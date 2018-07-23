use crossbeam_utils;
use fnv::FnvHashSet;
use num_cpus;
use std::sync::mpsc;

use cipher::Cipher;
use property::{Property, PropertyType, PropertyFilter, ValueMap};
use search::patterns::{SboxPattern, get_sorted_patterns};
use utility::{ProgressBar, compress};

// The number of threads used for parallel calls is fixed
lazy_static! {
    static ref THREADS: usize = num_cpus::get();
}

/***********************************************************************************************/

/** 
A struct that represents a list of single round properties of a cipher, sorted in
ascending order of their value. The actual properties are lazily
generated using the Iterator trait.

cipher                   The cipher whose round function we are considering.
value_map                The property map for the cipher's S-box.
sbox_patterns            A list of S-box patterns sorted by their property values.
property_type            The type of property the iterator generates. 
property_filter          What type of property an iterator will generate.
*/
#[derive(Clone)]
pub struct SortedProperties<'a> {
    pub cipher: &'a Cipher,
    pub value_maps: Vec<ValueMap>,
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
    pub fn new(cipher: &dyn Cipher, 
               pattern_limit: usize, 
               property_type: PropertyType,
               property_filter: PropertyFilter) 
               -> SortedProperties {
        let (sbox_patterns, value_maps) = get_sorted_patterns(cipher, pattern_limit, property_type);

        SortedProperties{cipher,
                         value_maps,
                         sbox_patterns,
                         property_type,
                         property_filter}
    }

    /** 
    Returns the number of properties which can be generated from the patterns. 
    */
    pub fn len(&self) -> usize {
        let mut len = 0;

        for pattern in &self.sbox_patterns {
            let combinations = match self.property_filter {
                PropertyFilter::All    => pattern.num_prop(&self.value_maps),
                PropertyFilter::Input  => pattern.num_input(&self.value_maps),
                PropertyFilter::Output => pattern.num_output(&self.value_maps),
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

    /**
    Removes S-box patterns from a set of properties for which none of the resulting properties
    are allowed by the current filters. Note that the order of properties generated is not preserved.

    Filters         Filters to check.
    properties      Properties to remove patterns from.
    level           Compression level used for the filters.
    */
    pub fn remove_dead_patterns(&mut self,
                                filters: &[FnvHashSet<u128>], 
                                level: usize) {
        let (result_tx, result_rx) = mpsc::channel();
        
        // Start scoped worker threads
        crossbeam_utils::thread::scope(|scope| {
            for t in 0..*THREADS {
                let mut thread_properties = self.clone();
                let result_tx = result_tx.clone();

                scope.spawn(move || {
                    thread_properties.set_type_input();
                    
                    // Split the S-box patterns equally across threads
                    // Note that this does not equally split the number of properties across threads,
                    // but hopefully it is close enough
                    let tmp = thread_properties.sbox_patterns.iter()
                                                             .cloned()
                                                             .skip(t)
                                                             .step_by(*THREADS)
                                                             .collect();
                    thread_properties.sbox_patterns = tmp;

                    // Find patterns to keep
                    let mut good_patterns = vec![false; thread_properties.len_patterns()];
                    let mut progress_bar = ProgressBar::new(thread_properties.len());

                    for (property, pattern_idx) in &thread_properties {
                        // Skip if pattern is already marked good
                        if good_patterns[pattern_idx] {
                            if t == 0 {
                                progress_bar.increment();
                            }
                            continue;
                        }

                        let input = compress(property.input, level);
                        let mut good = false;

                        for f in filters {
                            if f.contains(&input) {
                                good = true;
                                break;
                            }
                        }

                        good_patterns[pattern_idx] |= good;
                        
                        if t == 0 {
                            progress_bar.increment();
                        }
                    }

                    // Keep only good patterns
                    let mut new_patterns = vec![];

                    for (i, keep) in good_patterns.iter().enumerate() {
                        if *keep {
                            new_patterns.push(thread_properties.sbox_patterns[i].clone());
                        }
                    }

                    result_tx.send(new_patterns).expect("Thread could not send result");
                });
            }
        });

        // Collect patterns from each thread and update properties
        let mut new_patterns = Vec::new();

        for _ in 0..*THREADS {
            let mut thread_result = result_rx.recv().expect("Main could not receive result");
            new_patterns.append(&mut thread_result);
        }

        self.sbox_patterns = new_patterns;
        self.set_type_all();
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
            value_maps: self.value_maps.clone(),
            sbox_patterns: self.sbox_patterns.clone(),
            property_type: self.property_type,
            property_filter: self.property_filter,
            current_pattern: 0       
        }
    }
}

/** 
An iterator over properties represented by a SortedProperties struct.

cipher              The cipher considered.
sbox_patterns       A vector of patterns to generate properties from.
value_maps          Map from each of the S-boxes property values to property input/output.
property_type       The type of property the iterator generates. 
property_filter     Determines whether to generate full properties or just inputs/outputs.
current_pattern     Index of the current pattern used to generate properties.
 */
#[derive(Clone)]
pub struct SortedPropertiesIterator<'a> {
    cipher: &'a Cipher,
    pub sbox_patterns: Vec<SboxPattern>,
    value_maps: Vec<ValueMap>,
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
            property = match pattern.next(&self.value_maps, self.property_filter) {
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