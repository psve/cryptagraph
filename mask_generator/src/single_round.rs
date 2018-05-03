use smallvec::SmallVec;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

use cipher::Cipher;
use property::{Property, PropertyType, PropertyFilter, PropertyMap};

/** 
An internal representation of a partial S-box pattern. An S-box pattern describes a
truncated property, but where the value is specified for each S-box.

pattern             The partial pattern. Any S-box that has not been specified yet is None.
determined_length   The number of S-boxes determined so far.
value               Value of the partial pattern.
num_active          The number of active S-boxes so far.
 */
#[derive(Clone)]
struct InternalSboxPattern {
    pattern: Vec<Option<i16>>,
    determined_length: usize,
    value: f64,
    num_active: usize
}

impl InternalSboxPattern {
    /** 
    Returns true if the are no None values in the pattern 
    */
    fn is_complete(&self) -> bool {
        self.pattern[self.pattern.len() - 1].is_some()
    }

    /** Extends the current pattern to at most two "neighbouring" patterns

    property_values     A list of property values for the S-box in descending order.
                        Is assumed to contain the value of the trivial property.
     */
    fn extend(&self, 
              property_values: &[i16], 
              property_type: PropertyType) 
              -> (Option<InternalSboxPattern>, Option<InternalSboxPattern>) {
        // Value of the trivial property
        let trivial = *property_values.first().expect("No values found.") as f64;

        // We generate at most two new patterns
        let mut extended_patterns = (None, None);

        // The first pattern extends the current pattern to the right with the trivial value
        // If the current pattern is complete, we cannot extend in this way
        if !self.is_complete() {
            let mut new_pattern = self.clone();
            new_pattern.pattern[self.determined_length] = Some(trivial as i16);
            new_pattern.determined_length += 1;

            // Note that the value doesn't change when extended by the trivial pattern            
            extended_patterns.0 = Some(new_pattern);
        }

        // The second pattern replaces the last determined value with the
        // next value in property_values
        let mut new_pattern = self.clone();
        let current_value = self.pattern[self.determined_length - 1].unwrap();
        let corr_idx = property_values.binary_search_by(|a| a.cmp(&current_value).reverse());

        // This check fails if the current value was the last on the list
        // In this case, this pattern isn't generated
        match corr_idx {
            Ok(x) => {
                if x+1 < property_values.len() {
                    new_pattern.pattern[self.determined_length - 1] = Some(property_values[x+1]);
                    new_pattern.num_active += (x == 0) as usize;

                    match property_type {
                        PropertyType::Linear => {
                            new_pattern.value /= (property_values[x] as f64 / trivial).powi(2);
                            new_pattern.value *= (property_values[x+1] as f64 / trivial).powi(2);
                        },
                        PropertyType::Differential => {
                            new_pattern.value /= property_values[x] as f64 / trivial;
                            new_pattern.value *= property_values[x+1] as f64 / trivial;
                        }
                    }

                    extended_patterns.1 = Some(new_pattern);
                }
            },
            Err(_) => {}
        };

        extended_patterns
    }
}

/** 
Ordering traits of the partial S-box patterns. Required for BinaryHeap<InternalSboxPattern> 
*/
impl Ord for InternalSboxPattern {
    fn cmp(&self, other: &InternalSboxPattern) -> Ordering {
        self.partial_cmp(&other).unwrap()
    }
}

impl PartialOrd for InternalSboxPattern {
    fn partial_cmp(&self, other: &InternalSboxPattern) -> Option<Ordering> {
        let val_ord = self.value.log2().partial_cmp(&other.value.log2()).unwrap();
        let active_ord = self.num_active.cmp(&other.num_active).reverse();
        let len_ord = self.determined_length.cmp(&other.determined_length);

        if val_ord != Ordering::Equal {
            return Some(val_ord);
        }

        if active_ord != Ordering::Equal {
            return Some(active_ord);
        }

        if len_ord != Ordering::Equal {
            return Some(len_ord);
        }

        return Some(Ordering::Equal);
    }
}

impl PartialEq for InternalSboxPattern {
    #[allow(unused_variables)]
    fn eq(&self, other: &InternalSboxPattern) -> bool {
        // This is bad - only works because we never compare equal patterns
        false
    }
}

impl Eq for InternalSboxPattern {}

/***********************************************************************************************/

/**
Enum representing the status of the current pattern

New     The pattern has not been initialised yet.
Old     The pattern has been initialised.
Empty   There are no properties left in the pattern.
*/
#[derive(Clone, PartialEq, Eq)]
enum PatternStatus {
    New,
    Old,
    Empty
}

/** 
An external interface to InternalSboxPattern. The pattern only stores the active S-box positions.

pattern     A vector describing the S-box index and its property value.
property    Type of property represented by the pattern.
mask        A bit mask corresponding to a single S-box.
counter     A vector of counters keep track of the current property in each S-box.
status      The patterns current status. 
*/
#[derive(Clone)]
pub struct SboxPattern {
    pattern: Vec<(usize, i16)>,
    property: Property,
    mask: u64,
    counter: Vec<usize>,
    status: PatternStatus,
}

impl SboxPattern {
    /** 
    Converts an InternalSboxPattern to an SboxPattern.
    
    cipher                  The cipher the pattern belongs to.
    internal_sbox_pattern   A complete internal S-box pattern.
    property_type           The type of property represented by the pattern.
    */
    fn new (cipher: &Cipher,
            internal_sbox_pattern: &InternalSboxPattern,
            property_type: PropertyType) 
            -> SboxPattern {
        // Get the value of an inactive S-box 
        let non_property = match property_type {
            PropertyType::Linear => cipher.sbox().linear_balance(),
            PropertyType::Differential => cipher.sbox().differential_zero(),
        };

        // Collect active S-box positions
        // This fails of the pattern wasn't complete
        let pattern: Vec<_> = internal_sbox_pattern.pattern.iter()
                                   .map(|x| x.expect("Tried to convert incomplete pattern."))
                                   .enumerate()
                                   .filter(|&(_,x)| x != non_property)
                                   .map(|(i,x)| (i*cipher.sbox().size, x))
                                   .collect();

        let counter = vec![0; pattern.len()];
        let property = Property::new(0, 0, internal_sbox_pattern.value, 1);

        SboxPattern {
            pattern: pattern, 
            property: property,
            mask: ((1 << cipher.sbox().size) - 1) as u64,
            counter: counter,
            status: PatternStatus::New
        }
    }

    /**
    Generates the next property matching the S-box pattern. 

    property_map        A map from S-box values to inputs/outputs.
    property_filter     A filter determining whether to produce full properties, or only
                        inputs/outputs.
    */
    fn next(&mut self, 
            property_map: &PropertyMap,
            property_filter: &PropertyFilter) 
            -> Option<Property> {
        // If there are no active S-boxes in the pattern, it is already empty
        if self.counter.len() == 0 {
            self.status = PatternStatus::Empty;
        }

        // Stop if there are no more properties to generate
        if self.status == PatternStatus::Empty {
            return None;
        }

        // Initialise and return first property if the pattern is new
        if self.status == PatternStatus::New {
            for &(i, x) in &self.pattern {
                let sbox_property = match property_filter {
                    PropertyFilter::All   => property_map.get(&x).unwrap()[0],
                    PropertyFilter::Input => property_map.get_input(&x).unwrap()[0],
                    PropertyFilter::Output  => property_map.get_output(&x).unwrap()[0]
                };

                let input = sbox_property.input;
                let output = sbox_property.output;

                self.property.input ^= input << i;
                self.property.output ^= output << i;
            }

            self.status = PatternStatus::Old;
        }
        
        let result = self.property;

        // Generate next property
        for i in 0..self.counter.len() {
            // We can consider counter as a mixed radix number. We simply increment the value of
            // this number. 
            let idx = self.pattern[i].0;
            let val = self.pattern[i].1;
            let modulus = match property_filter {
                PropertyFilter::All    => property_map.len_of(val),
                PropertyFilter::Input  => property_map.len_of_input(val),
                PropertyFilter::Output => property_map.len_of_output(val)
            };

            self.counter[i] = (self.counter[i] + 1) % modulus;

            // If the counter rolls over, there are no more properties
            if i+1 == self.counter.len() && self.counter[i] == 0 {
                self.status = PatternStatus::Empty;
                return Some(result);
            }

            // Update current position
            let app = match property_filter {
                PropertyFilter::All    => property_map.get(&val).unwrap()[self.counter[i]],
                PropertyFilter::Input  => property_map.get_input(&val).unwrap()[self.counter[i]],
                PropertyFilter::Output => property_map.get_output(&val).unwrap()[self.counter[i]]
            };

            self.property.input = 
                (self.property.input & !(self.mask << idx)) ^ (app.input << idx);
            self.property.output = 
                (self.property.output & !(self.mask << idx)) ^ (app.output << idx);

            // Continue only if current "digit" rolls over
            if self.counter[i] != 0 {
                break;
            }
        }
        
        Some(result)
    }

    /** 
    Returns the number of properties described by this pattern 
    */
    fn num_app(&self, property_map: &PropertyMap) -> usize {
        self.pattern.iter().fold(1, |acc, &(_, x)| acc * property_map.len_of(x))
    }

    /** 
    Returns the number of inputs described by this pattern 
    */
    fn num_input(&self, property_map: &PropertyMap) -> usize {
        self.pattern.iter().fold(1, |acc, &(_, x)| acc * property_map.len_of_input(x))
    }

    /** 
    Returns the number of outputs described by this pattern 
    */
    fn num_output(&self, property_map: &PropertyMap) -> usize {
        self.pattern.iter().fold(1, |acc, &(_, x)| acc * property_map.len_of_output(x))
    }
}

/***********************************************************************************************/

/** 
A struct that represents a list of single round properties of a cipher, sorted in
ascending order of their value. The actual properties are lazily
generated using the Iterator trait.

cipher                   The cipher whose round function we are considering.
property_map             The property map for the cipher's S-box.
sbox_patterns            A list of S-box patterns sorted by their property values.
property_type            The type of property the iterator generates. 
property_filter          What type of property an iterator will generate.
*/
#[derive(Clone)]
pub struct SortedProperties<'a> {
    pub cipher: &'a Cipher,
    pub property_map: PropertyMap,
    pub sbox_patterns: Vec<SboxPattern>,
    property_type: PropertyType,
    property_filter: PropertyFilter,
}

impl<'a> SortedProperties<'a> {
    /** 
    Returns a new SortedProperties struct ready to be used as an iterator.
    The function basically generates the patterns in sbox_patterns,
    using an approach inspired by the paper
    "Efficient Algorithms for Extracting the K Most Critical Paths in Timing Analysis"
    by Yen, Du, and Ghanta.
    
    cipher           The cipher whose round function we are considering.
    pattern_limit    The number of patterns we want to generate.
    property_type    What type of property to generate. 
    property_filter  What type of property an iterator will generate.
    */
    pub fn new(cipher: &Cipher, 
               pattern_limit: usize, 
               property_type: PropertyType,
               property_filter: PropertyFilter) 
               -> SortedProperties {
        // Generate property map and get S-box property values
        let property_map = PropertyMap::new(cipher, property_type);
        let mut property_values: SmallVec<[_; 128]> = property_map.map.keys().cloned().collect();

        // We need the values in descending order
        property_values.sort_by(|a, b| b.cmp(&a));

        // Start with a partial pattern where only the first value is determined
        let mut tmp = vec![None; cipher.num_sboxes()];
        tmp[0] = Some(*property_values.first().expect("No values found."));
        let current_pattern = InternalSboxPattern {
            pattern: tmp,
            determined_length: 1,
            value: 1.0,
            num_active: 0
        };

        // We maintain a heap of partial patterns sorted by their property value
        let mut sbox_patterns = vec![];
        let mut heap = BinaryHeap::new();
        heap.push(current_pattern);

        // While we haven't generated enough patterns
        while sbox_patterns.len() < pattern_limit {
            // We ran out of patterns, so we return what we have so far
            if heap.is_empty() {
                let sbox_patterns: Vec<SboxPattern>
                    = sbox_patterns.iter()
                                          .map(|x| SboxPattern::new(cipher, x, property_type))
                                          .collect();

                return SortedProperties{cipher: cipher.clone(),
                                            property_map: property_map.clone(),
                                            sbox_patterns: sbox_patterns,
                                            property_type: property_type,
                                            property_filter: property_filter}
            }

            // Extract the current best pattern
            let current_pattern = heap.pop().unwrap();

            // Extend best pattern and add the result to the heap
            let (pattern_1, pattern_2) = current_pattern.extend(&property_values[..], 
                                                                property_type);

            match pattern_1 {
                Some(pattern) => {
                    heap.push(pattern);
                },
                None => ()
            };

            match pattern_2 {
                Some(pattern) => {
                    heap.push(pattern);
                },
                None => ()
            };

            // Add current pattern if it was complete
            if current_pattern.is_complete() {
                sbox_patterns.push(current_pattern);
            }
        }

        // Convert all internal patterns to SboxPattern
        let sbox_patterns: Vec<SboxPattern>
            = sbox_patterns.iter()
                                  .map(|x| SboxPattern::new(cipher, x, property_type))
                                  .collect();

        return SortedProperties{cipher: cipher.clone(),
                                property_map: property_map.clone(),
                                sbox_patterns: sbox_patterns,
                                property_type: property_type,
                                property_filter: property_filter}
    }

    /** 
    Returns the number of properties which can be generated from the patterns. 
    */
    pub fn len(&self) -> usize {
        let mut len = 0;

        for pattern in &self.sbox_patterns {
            let combinations = match self.property_filter {
                PropertyFilter::All    => pattern.num_app(&self.property_map),
                PropertyFilter::Input  => pattern.num_input(&self.property_map),
                PropertyFilter::Output => pattern.num_output(&self.property_map),
            };

            len += combinations;
        }

        len
    }

    /** 
    Returns the number of patterns 
    */
    pub fn len_patterns(&self) -> usize {
        self.sbox_patterns.len()
    }

    /** 
    Sets the type field to all 
    */
    pub fn set_type_all(&mut self) {
        self.property_filter = PropertyFilter::All;
    }

    /** 
    Sets the type field to input 
    */
    pub fn set_type_input(&mut self) {
        self.property_filter = PropertyFilter::Input;
    }

    /** 
    Sets the type field to output 
    */
    pub fn set_type_output(&mut self) {
        self.property_filter = PropertyFilter::Output;
    }
}

impl<'a> IntoIterator for &'a SortedProperties<'a> {
    type Item = (Property, usize);
    type IntoIter = SortedPropertiesIterator<'a>;

    /**
    Get an iterator over all properties. 
    */
    fn into_iter(self) -> Self::IntoIter {
        SortedPropertiesIterator { 
            cipher: self.cipher,
            property_map: self.property_map.clone(),
            sbox_patterns: self.sbox_patterns.clone(),
            property_type: self.property_type.clone(),
            property_filter: self.property_filter.clone(),
            current_pattern: 0       
        }
    }
}

/** 
An iterator over properties represented by a SortedProperties struct.

cipher              The cipher considered.
sbox_patterns       A vector of patterns to generate properties from.
property_map        A map from S-box property values to property input/output.
property_type       The type of property the iterator generates. 
property_filter     Determines whether to generate full properties or just inputs/outputs.
current_pattern     Index of the current pattern used to generate properties.
 */
#[derive(Clone)]
pub struct SortedPropertiesIterator<'a> {
    cipher: &'a Cipher,
    pub sbox_patterns: Vec<SboxPattern>,
    property_map: PropertyMap,
    property_type: PropertyType,
    property_filter: PropertyFilter,
    current_pattern: usize
}

impl<'a> Iterator for SortedPropertiesIterator<'a> {
    type Item = (Property, usize);

    /**
    Generate the next property
    */
    fn next(&mut self) -> Option<Self::Item> {
        let max_length = self.sbox_patterns.len();
        
        // Stop if we have generated all possible properties
        if self.current_pattern >= max_length {
            return None;
        }

        // Generate next property by calling next on the current pattern. 
        // Repeat until we get a pattern or run out entirely
        let mut property = None;

        while property.is_none() {
            let pattern = &mut self.sbox_patterns[self.current_pattern];
            property = match pattern.next(&self.property_map, &self.property_filter) {
                Some(x) => Some(x),
                None => {
                    self.current_pattern += 1;

                    if self.current_pattern >= max_length {
                        return None;
                    }

                    None
                }
            }
        }
        
        let mut property = property.unwrap();
        let (input, output) = self.cipher
                                  .sbox_mask_transform(property.input, 
                                                       property.output,
                                                       self.property_type);
        property.input = input;
        property.output = output;

        Some((property, self.current_pattern))
    }
}