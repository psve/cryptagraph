use std::str::FromStr;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use fnv::FnvHashMap;
use cipher::Cipher;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum PropertyType {
    Linear,
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

#[derive(Clone)]
pub enum PropertyFilter {
    All,
    Input,
    Output
}

/* A structure representing a property (e.g. linear approximation or differential).
 *
 * input    The input value of the property.
 * output   The output value of the property.
 * value    The value of the property.
 */
#[derive(Copy, Clone)]
pub struct Property {
    pub input: u64,
    pub output: u64,
    pub value: f64,
    pub trails: usize,
}

impl Property {
    /* Generates a new property.
     *
     * input    The input mask.
     * output     The output mask.
     */
    pub fn new(
        input: u64, output: u64, 
        value: f64, trails: usize) -> Property {
        Property {
            input: input, 
            output: output, 
            value: value,
            trails: trails,
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
        write!(f, "({:016x},{:016x})", self.input, self.output)
    }
}



/* A structure that represents a property of an S-box as map from values to matching properties.
 *
 * map          The mapping from the values to a vector of properties that have this value.
 * input_map    Same as map, but where only the input of the property is kept.
 * output_map   Same as map, but where only the output of the property is kept.
 */
#[derive(Clone)]
pub struct PropertyMap {
    pub map: FnvHashMap<i16, Vec<Property>>,
    input_map: FnvHashMap<i16, Vec<Property>>,
    output_map: FnvHashMap<i16, Vec<Property>>,
}

impl PropertyMap {
    /* Generate a new property map from an S-box.
     *
     * sbox     The S-box used as the generator.
     */
    pub fn new(cipher: &Cipher, property_type: PropertyType) -> PropertyMap {
        let mut map = FnvHashMap::default();
        let mut input_map = FnvHashMap::default();
        let mut output_map = FnvHashMap::default();

        // Value which is not interesting for the given property,
        // i.e. zero bias for linear and zero probability for differential
        let non_property = match property_type {
            PropertyType::Linear => cipher.sbox().linear_balance(),
            PropertyType::Differential => cipher.sbox().differential_zero(),
        };

        let property_map = match property_type {
            PropertyType::Linear => cipher.sbox().lat.clone(),
            PropertyType::Differential => cipher.sbox().ddt.clone(),
        };

        for (input, row) in property_map.iter().enumerate() {
            for (output, element) in row.iter().enumerate() {
                // If the property is not balanced, we add it to the map
                if *element as i16 != non_property {
                    // Absolute counter bias or probability
                    let key = ((*element as i16) - non_property).abs();

                    let entry = map.entry(key).or_insert(vec![]);
                    entry.push(Property::new(input as u64, output as u64, 1.0, 1));

                    let entry = input_map.entry(key).or_insert(vec![]);
                    entry.push(Property::new(input as u64, (output != 0) as u64, 1.0, 1));

                    let entry = output_map.entry(key).or_insert(vec![]);
                    entry.push(Property::new((input != 0) as u64, output as u64, 1.0, 1));
                }
            }
        }

        // Remove dubplicates
        for inputs in input_map.values_mut() {
            inputs.sort();
            inputs.dedup();
        }

        for outputs in output_map.values_mut() {
            outputs.sort();
            outputs.dedup();
        }

        PropertyMap {
            map: map, 
            input_map: input_map, 
            output_map: output_map
        }
    }

    /* Getter to avoid unecessary syntax. Simply reimplements FnvHashMap::get */
    pub fn get(&self, k: &i16) -> Option<&Vec<Property>> {
        self.map.get(k)
    }

    /* Getter for the input map */
    pub fn get_input(&self, k: &i16) -> Option<&Vec<Property>> {
        self.input_map.get(k)
    }

    /* Getter for the output map */
    pub fn get_output(&self, k: &i16) -> Option<&Vec<Property>> {
        self.output_map.get(k)
    }

    /* Gets the number of properties that has a certain value.
     *
     * value    The target property value.
     */
    pub fn len_of(&self, value: i16) -> usize {
        self.get(&value).unwrap().len()
    }

    /* Gets the number of inputs that has a value.
     *
     * value    The target property value.
     */
    pub fn len_of_input(&self, value: i16) -> usize {
        self.get_input(&value).unwrap().len()
    }

    /* Gets the number of outputs that has a certain value.
     *
     * value    The target property value.
     */
    pub fn len_of_output(&self, value: i16) -> usize {
        self.get_output(&value).unwrap().len()
    }
}