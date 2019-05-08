//! Types for representing property patterns for an S-box layer.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use crate::cipher::Cipher;
use crate::property::{Property, PropertyType, PropertyFilter, ValueMap};

/// An internal representation of a partial S-box pattern. An S-box pattern describes a
/// truncated property, but where the value is specified for each S-box.
#[derive(Clone)]
struct InternalSboxPattern {
    pattern: Vec<Option<i16>>,
    determined_length: usize,
    value: f64,
    num_active: usize
}

impl InternalSboxPattern {
    ///Returns true if the are no None values in the pattern 
    fn is_complete(&self) -> bool {
        self.pattern[self.pattern.len() - 1].is_some()
    }

    /// Extends the current pattern to at most two "neighbouring" patterns
    fn extend(&self, 
              property_values: &[Vec<i16>], 
              property_type: PropertyType) 
              -> (Option<InternalSboxPattern>, Option<InternalSboxPattern>) {
        // We generate at most two new patterns
        let mut extended_patterns = (None, None);

        // The first pattern extends the current pattern to the right with the trivial value
        // If the current pattern is complete, we cannot extend in this way
        if !self.is_complete() {
            // Value of the trivial property for the next S-box
            let trivial = f64::from(*property_values[self.determined_length]
                                    .first().expect("No values found."));

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
        let corr_idx = property_values[self.determined_length - 1]
                        .iter().enumerate().find(|(_, x)| **x == current_value).map(|(i,_)| i);

        // This check fails if the current value was the last on the list
        // In this case, this pattern isn't generated
        if let Some(x) = corr_idx {
            if x+1 < property_values[self.determined_length - 1].len() {
                // Value of the trivial property for the current S-box
                let trivial = f64::from(*property_values[self.determined_length - 1]
                                        .first().expect("No values found."));

                new_pattern.pattern[self.determined_length - 1] = 
                    Some(property_values[self.determined_length - 1][x+1]);
                new_pattern.num_active += (x == 0) as usize;

                match property_type {
                    PropertyType::Linear => {
                        new_pattern.value /= 
                            (f64::from(property_values[self.determined_length - 1][x]) / trivial).powi(2);
                        new_pattern.value *= 
                            (f64::from(property_values[self.determined_length - 1][x+1]) / trivial).powi(2);
                    },
                    PropertyType::Differential => {
                        new_pattern.value /= 
                            f64::from(property_values[self.determined_length - 1][x]) / trivial;
                        new_pattern.value *= 
                            f64::from(property_values[self.determined_length - 1][x+1]) / trivial;
                    }
                }

                extended_patterns.1 = Some(new_pattern);
            }
        };

        extended_patterns
    }
}

impl Ord for InternalSboxPattern {
    fn cmp(&self, other: &InternalSboxPattern) -> Ordering {
        self.partial_cmp(&other).unwrap()
    }
}

impl PartialOrd for InternalSboxPattern {
    fn partial_cmp(&self, other: &InternalSboxPattern) -> Option<Ordering> {
        let val_ord = self.value.abs().partial_cmp(&other.value.abs()).unwrap();
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

        Some(Ordering::Equal)
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

/// Status of a pattern.
#[derive(Clone, PartialEq, Eq)]
enum PatternStatus {
    New,
    Old,
    Empty
}

/// A pattern describing a set of properties of an S-box layer. All properties in the set have 
/// the same value and activate the same S-boxes. Internally, only active positions are stored. 
#[derive(Clone)]
pub struct SboxPattern {
    pattern: Vec<(usize, usize, usize, i16)>,
    property: Property,
    mask_in: u128,
    mask_out: u128,
    // sbox_size_in: usize,
    // sbox_size_out: usize,
    counter: Vec<usize>,
    status: PatternStatus,
}

impl SboxPattern {
    /// Converts an InternalSboxPattern to an SboxPattern.
    fn new(cipher: &dyn Cipher,
           internal_sbox_pattern: &InternalSboxPattern,
           property_type: PropertyType) 
           -> SboxPattern {
        // Get the value of an inactive S-box 
        let non_property = match property_type {
            PropertyType::Linear => cipher.sbox(0).linear_balance(),
            PropertyType::Differential => cipher.sbox(0).differential_trivial(),
        };

        // Collect active S-box positions
        // This fails if the pattern wasn't complete
        let pattern: Vec<_> = internal_sbox_pattern.pattern.iter()
                                   .map(|x| x.expect("Tried to convert incomplete pattern."))
                                   .enumerate()
                                   .filter(|&(_,x)| x != non_property)
                                   .map(|(i,x)| (cipher.sbox_pos_in(i), 
                                                 cipher.sbox_pos_out(i), 
                                                 i, x))
                                   .collect();

        let counter = vec![0; pattern.len()];
        let property = Property::new(0, 0, internal_sbox_pattern.value, 1);

        SboxPattern {
            pattern, 
            property,
            mask_in: cipher.sbox(0).mask_in() as u128,
            mask_out: cipher.sbox(0).mask_out() as u128,
            counter,
            status: PatternStatus::New
        }
    }

    /// Generate the next property matching the S-box pattern. 
    pub fn next(&mut self, 
                value_maps: &[ValueMap],
                property_filter: PropertyFilter) 
                -> Option<Property> {
        // If there are no active S-boxes in the pattern, it is already empty
        if self.counter.is_empty() {
            self.status = PatternStatus::Empty;
        }

        // Stop if there are no more properties to generate
        if self.status == PatternStatus::Empty {
            return None;
        }

        // Initialise and return first property if the pattern is new
        if self.status == PatternStatus::New {
            for &(i_in, i_out, j, x) in &self.pattern {
                let sbox_property = match property_filter {
                    PropertyFilter::All   => value_maps[j].get(x).unwrap()[0],
                    PropertyFilter::Input => value_maps[j].get_input(x).unwrap()[0],
                    PropertyFilter::Output  => value_maps[j].get_output(x).unwrap()[0]
                };

                let input = sbox_property.input;
                let output = sbox_property.output;

                self.property.input ^= input << i_in;
                self.property.output ^= output << i_out;
            }

            self.status = PatternStatus::Old;
        }
        
        let result = self.property;

        // Generate next property
        for i in 0..self.counter.len() {
            // We can consider counter as a mixed radix number. We simply increment the value of
            // this number. 
            let idx_in  = self.pattern[i].0;
            let idx_out = self.pattern[i].1;
            let sbox    = self.pattern[i].2;
            let val     = self.pattern[i].3;
            let modulus = match property_filter {
                PropertyFilter::All    => value_maps[sbox].len_of(val),
                PropertyFilter::Input  => value_maps[sbox].len_of_input(val),
                PropertyFilter::Output => value_maps[sbox].len_of_output(val)
            };

            self.counter[i] = (self.counter[i] + 1) % modulus;

            // If the counter rolls over, there are no more properties
            if i+1 == self.counter.len() && self.counter[i] == 0 {
                self.status = PatternStatus::Empty;
                return Some(result);
            }

            // Update current position
            let app = match property_filter {
                PropertyFilter::All    => value_maps[sbox].get(val).unwrap()[self.counter[i]],
                PropertyFilter::Input  => value_maps[sbox].get_input(val).unwrap()[self.counter[i]],
                PropertyFilter::Output => value_maps[sbox].get_output(val).unwrap()[self.counter[i]]
            };

            self.property.input = 
                (self.property.input & !(self.mask_in << idx_in)) ^ (app.input << idx_in);
            self.property.output = 
                (self.property.output & !(self.mask_out << idx_out)) ^ (app.output << idx_out);

            // Continue only if current "digit" rolls over
            if self.counter[i] != 0 {
                break;
            }
        }
        
        Some(result)
    }

    /// Returns the number of properties described by this pattern.
    pub fn num_prop(&self, value_maps: &[ValueMap]) -> usize {
        self.pattern.iter().fold(1, |acc, &(_, _, j, x)| acc * value_maps[j].len_of(x))
    }

    /// Returns the number of inputs described by this pattern.
    pub fn num_input(&self, value_maps: &[ValueMap]) -> usize {
        self.pattern.iter().fold(1, |acc, &(_, _, j, x)| acc * value_maps[j].len_of_input(x))
    }

    /// Returns the number of outputs described by this pattern.
    pub fn num_output(&self, value_maps: &[ValueMap]) -> usize {
        self.pattern.iter().fold(1, |acc, &(_, _, j, x)| acc * value_maps[j].len_of_output(x))
    }
}

/// Creates a vector of S-box patterns, sorted by their values. 
/// Also returns the associated `ValueMap`.
pub fn get_sorted_patterns(cipher: &dyn Cipher, 
                           pattern_limit: usize, 
                           property_type: PropertyType) -> 
                           (Vec<SboxPattern>, Vec<ValueMap>) {
    // Generate property map and get S-box property values
    let value_maps: Vec<_> = (0..cipher.num_sboxes()).map(|i| {
        ValueMap::new(cipher.sbox(i), property_type)
    }).collect();

    let mut property_values: Vec<Vec<_>> = value_maps.iter().map(|map| {
        map.keys().cloned().collect()
    }).collect();

    // We need the values in descending order
    for v in &mut property_values {
        v.sort_by(|a, b| b.abs().cmp(&a.abs()));
    }

    // Start with a partial pattern where only the first value is determined
    let mut tmp = vec![None; cipher.num_sboxes()];
    tmp[0] = Some(*property_values.first().expect("No values found.")
                                  .first().expect("No values found."));
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

            return (sbox_patterns, value_maps);
        }

        // Extract the current best pattern
        let current_pattern = heap.pop().unwrap();

        // Extend best pattern and add the result to the heap
        let (pattern_1, pattern_2) = current_pattern.extend(&property_values[..], 
                                                            property_type);

        if let Some(pattern) = pattern_1 {
            heap.push(pattern);
        };

        if let Some(pattern) = pattern_2 {
            heap.push(pattern);
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

    (sbox_patterns, value_maps)
}