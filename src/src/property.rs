//! Representations of various properties of a block cipher. 
//!
//! Currently only linear approximations and differentials are represented. 

use itertools::Itertools;
use std::str::FromStr;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use fnv::FnvHashMap;
use std::collections::hash_map::Keys;
use crate::sbox::Sbox;
use crate::cipher::Cipher;

/// Types of properties currently representable. 
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum PropertyType {
    /// Linear approximations.
    Linear,
    /// Differentials.
    Differential
}

impl FromStr for PropertyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "linear"       => Ok(PropertyType::Linear),
            "differential" => Ok(PropertyType::Differential),
            _              => Err(String::from("Unknown property type.")),
        }
    }
}

/// Indicates what part of a property to output.
#[derive(Copy, Clone)]
pub enum PropertyFilter {
    /// Output both input and output.
    All,
    /// Output only the input.
    Input,
    /// Output only the output.
    Output
}

/// A structure representing a property (e.g. a linear approximation or differential).
#[derive(Copy, Clone)]
pub struct Property {
    /// The input of the property.
    pub input: u128,
    /// The output of the property.
    pub output: u128,
    /// The value of the property.
    pub value: f64,
    /// The number of trains contaiend in the property.
    pub trails: u128,
}

impl Property {
    /// Creates a new property.
    pub fn new(input: u128, 
               output: u128, 
               value: f64, 
               trails: u128) 
               -> Property {
        Property {
            input, 
            output, 
            value,
            trails,
        }
    }
}

impl Ord for Property {
    fn cmp(&self, other: &Property) -> Ordering {
        if self.input == other.input {
            self.output.cmp(&other.output)
        } else {
            self.input.cmp(&other.input)
        }
    }
}

impl PartialOrd for Property {
    fn partial_cmp(&self, other: &Property) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Property {
    fn eq(&self, other: &Property) -> bool {
        (self.input == other.input) && (self.output == other.output)
    }
}

impl Eq for Property {}

impl Hash for Property {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.input.hash(state);
        self.output.hash(state);
    }
}

impl fmt::Debug for Property {
    /* Formats the property in a nice way for printing */
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({:032x},{:032x})", self.input, self.output)
    }
}

/// A structure that represents a property of an S-box as map from values to matching properties.
#[derive(Clone)]
pub struct ValueMap {
    /// Mapping from values to a vector of properties that have this value.
    map: FnvHashMap<i16, Vec<Property>>,
    /// Same as map, but where only the input of the property is kept.
    input_map: FnvHashMap<i16, Vec<Property>>,
    /// Same as map, but where only the output of the property is kept.
    output_map: FnvHashMap<i16, Vec<Property>>,
}

impl ValueMap {
    /// Create a new property map from an S-box.
    pub fn new(sbox: &Sbox, property_type: PropertyType) -> ValueMap {
        let mut map = FnvHashMap::default();
        let mut input_map = FnvHashMap::default();
        let mut output_map = FnvHashMap::default();

        // Value which is not interesting for the given property,
        // i.e. zero bias for linear and zero probability for differential
        let non_property = match property_type {
            PropertyType::Linear => sbox.linear_balance(),
            PropertyType::Differential => sbox.differential_zero(),
        };

        let value_map = match property_type {
            PropertyType::Linear => sbox.lat().clone(),
            PropertyType::Differential => sbox.ddt().clone(),
        };

        for (input, row) in value_map.iter().enumerate() {
            for (output, element) in row.iter().enumerate() {
                // If the property is not balanced, we add it to the map
                if *element as i16 != non_property {
                    // Absolute counter bias or probability
                    let key = ((*element as i16) - non_property).abs();

                    let entry = map.entry(key).or_insert_with(Vec::new);
                    entry.push(Property::new(input as u128, output as u128, 1.0, 1));

                    let entry = input_map.entry(key).or_insert_with(Vec::new);
                    entry.push(Property::new(input as u128, (output != 0) as u128, 1.0, 1));

                    let entry = output_map.entry(key).or_insert_with(Vec::new);
                    entry.push(Property::new((input != 0) as u128, output as u128, 1.0, 1));
                }
            }
        }

        // Remove duplicates
        for inputs in input_map.values_mut() {
            inputs.sort();
            inputs.dedup();
        }

        for outputs in output_map.values_mut() {
            outputs.sort();
            outputs.dedup();
        }

        ValueMap {
            map, 
            input_map, 
            output_map
        }
    }

    /// Reimplementation of `HashMap.keys`.
    pub fn keys(&self) -> Keys<i16, Vec<Property>> {
        self.map.keys()
    }

    /// Reimplementation of `HashMap.get`.
    pub fn get(&self, k: i16) -> Option<&Vec<Property>> {
        self.map.get(&k)
    }

    /// Reimplementation of `HashMap.keys`, but only returns property inputs.
    pub fn get_input(&self, k: i16) -> Option<&Vec<Property>> {
        self.input_map.get(&k)
    }

    /// Reimplementation of `HashMap.keys`, but only returns property outputs.
    pub fn get_output(&self, k: i16) -> Option<&Vec<Property>> {
        self.output_map.get(&k)
    }

    /// Returns the number of properties that has a certain value.
    pub fn len_of(&self, value: i16) -> usize {
        self.get(value).unwrap().len()
    }

    /// Returns the number of property inputs that has a certain value.
    pub fn len_of_input(&self, value: i16) -> usize {
        self.get_input(value).unwrap().len()
    }

    /// Returns the number of property outputs that has a certain value.
    pub fn len_of_output(&self, value: i16) -> usize {
        self.get_output(value).unwrap().len()
    }
}

/// A structure mapping inputs/outputs of properties of an S-box to corresponding outputs/inputs
/// and their associated values. The mapping is sorted in descending order by value.
///
/// This structure is mainly useful for its methods `get_best_inputs` and `get_best_outputs`.
#[derive(Clone)]
pub struct MaskMap {
    input_maps: Vec<FnvHashMap<u128, Vec<(u128, i16)>>>,
    output_maps: Vec<FnvHashMap<u128, Vec<(u128, i16)>>>,
    property_type: PropertyType,
}

impl MaskMap {
    /// Create a new mapping from a specific cipher.
    pub fn new(cipher: &dyn Cipher,
               property_type: PropertyType) 
               -> MaskMap {
        let non_property = match property_type {
            PropertyType::Linear => cipher.sbox(0).linear_balance(),
            PropertyType::Differential => cipher.sbox(0).differential_zero(),
        };

        let mut input_maps = Vec::new();
        let mut output_maps = Vec::new();

        for i in 0..cipher.num_sboxes() {
            // Get the corresponding property table
            let table = match property_type {
                PropertyType::Linear => cipher.sbox(i).lat(),
                PropertyType::Differential => cipher.sbox(i).ddt(),
            };

            // Collect data into two maps
            let mut input_map = FnvHashMap::default();
            let mut output_map = FnvHashMap::default();

            for (r, row) in table.iter().enumerate().skip(1) {
                for (c, &col) in row.iter().enumerate().skip(1) {
                    let x = ((col as i16) - non_property).abs();
                    if x != 0 {
                        let entry = input_map.entry(r as u128).or_insert_with(Vec::new);
                        entry.push((c as u128, x));

                        let entry = output_map.entry(c as u128).or_insert_with(Vec::new);
                        entry.push((r as u128, x));
                    }
                }
            }

            for v in input_map.values_mut() {
                v.sort_by(|x, y| y.1.cmp(&x.1));
            }

            for v in output_map.values_mut() {
                v.sort_by(|x, y| y.1.cmp(&x.1));
            }
            
            input_maps.push(input_map);
            output_maps.push(output_map);
        }


        MaskMap {
            input_maps,
            output_maps,
            property_type,
        }
    }

    /// Given the output value of a property over an S-box layer, returns the best input values,
    /// i.e. those with highest values. 
    pub fn get_best_inputs(&self,
                           cipher: &dyn Cipher,
                           output: u128,
                           limit: usize)
                           -> Vec<(u128, f64)> {
        let mask_out = cipher.sbox(0).mask_out();
        let size_out = cipher.sbox(0).size_out();
        let trivial = match self.property_type {
            PropertyType::Linear => f64::from(cipher.sbox(0).linear_balance()),
            PropertyType::Differential => f64::from(cipher.sbox(0).differential_trivial())
        };

        // Extract active positions and output values
        let mut active = Vec::new();

        for i in 0..cipher.num_sboxes() {
            let x = (output >> (i*size_out)) & mask_out;

            if x != 0 {
                active.push(((i*size_out), i, x));
            }
        }

        // Crate iterator over good inputs
        let mut good_inputs: Vec<Vec<_>> = Vec::new();

        for &(_, j, x) in &active {
            match self.output_maps[j].get(&x) {
                Some(ref v) => good_inputs.push(v.iter().take(2).cloned().collect()),
                None => return Vec::new()
            }
        }

        let mut inputs = Vec::new();

        for parts in good_inputs.iter().multi_cartesian_product().take(limit) {
            let mut input = 0;
            let mut value = 1.0;
            
            for (i, (sbox_idx, _, _)) in active.iter().enumerate() {
                input ^= parts[i].0 << sbox_idx;
                value *= f64::from(parts[i].1) / trivial;
            }

            if self.property_type == PropertyType::Linear {
                value = value.powi(2);
            }

            inputs.push((input, value));
        }

        inputs
    }

    /// Given the input value of a property over an S-box layer, returns the best output values,
    /// i.e. those with highest values. 
    pub fn get_best_outputs(&self,
                            cipher: &dyn Cipher,
                            input: u128,
                            limit: usize)
                            -> Vec<(u128, f64)> {
        let mask_in = cipher.sbox(0).mask_in();
        let size_in = cipher.sbox(0).size_in();
        let trivial = match self.property_type {
            PropertyType::Linear => f64::from(cipher.sbox(0).linear_balance()),
            PropertyType::Differential => f64::from(cipher.sbox(0).differential_trivial())
        };

        // Extract active positions and output values
        let mut active = Vec::new();

        for i in 0..cipher.num_sboxes() {
            let x = (input >> (i*size_in)) & mask_in;

            if x != 0 {
                active.push(((i*size_in), i, x));
            }
        }

        // Crate iterator over good outputs
        let mut good_outputs: Vec<Vec<_>> = Vec::new();

        for &(_, j, x) in &active {
            match self.input_maps[j].get(&x) {
                Some(ref v) => good_outputs.push(v.iter().take(2).cloned().collect()),
                None => return Vec::new()
            }
        }

        let mut outputs = Vec::new();

        for parts in good_outputs.iter().multi_cartesian_product().take(limit) {
            let mut output = 0;
            let mut value = 1.0;
            
            for (i, (sbox_idx, _, _)) in active.iter().enumerate() {
                output ^= parts[i].0 << sbox_idx;
                value *= f64::from(parts[i].1) / trivial;
            }

            if self.property_type == PropertyType::Linear {
                value = value.powi(2);
            }

            outputs.push((output, value));
        }

        outputs
    }
}