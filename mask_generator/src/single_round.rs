use std::cmp::Ordering;
use std::collections::{HashMap, BinaryHeap};
use cipher::{Cipher, Sbox};
use approximation::{Approximation};

/* A structure that represents the LAT of an S-box as map from correlations to approximations.
 *
 * map  The mapping from the counter bias (abs(#pairs that hold - 2^(n-1))) to
        a vector of approximations that have that bias. 
 */
#[derive(Clone)]
struct LatMap {
    map: HashMap<i16, Vec<Approximation>>,
}

impl LatMap {
    /* Generate a new LAT map from an S-box.
     * 
     * sbox     The S-box used as the generator.
     */
    fn new(sbox: &Sbox) -> LatMap {
        let mut map = HashMap::new();
        let lat = sbox.lat();
        // The number of pairs the hold for a balanced approximation (i.e. 2^(n-1))
        let balance = (1 << (sbox.size - 1)) as i16;

        for (alpha, row) in lat.iter().enumerate() {
            for (beta, element) in row.iter().enumerate() {
                // If the approximation is not balanced, we add it to the map
                if *element as i16 != balance {
                    let abs_counter_bias = ((*element as i16) - balance).abs();
                    let entry = map.entry(abs_counter_bias).or_insert(vec![]);
                    entry.push(Approximation::new(alpha as u64, beta as u64, None))
                }
            }
        }

        LatMap{map: map}
    }

    /* Getter to avoid unecessary syntax. Simply reimplements HashMap::get */
    fn get(&self, k: &i16) -> Option<&Vec<Approximation>> {
        self.map.get(k)
    }

    /* Gets the number of approximations that has a certain counter bias.
     * 
     * value    The target counter bias.
     */
    fn len_of(&self, value: i16) -> usize {
        self.get(&value).unwrap().len()
    }
}

/***********************************************************************************************/


/* An internal representation of a partial S-box pattern. An S-box pattern describes a 
 * truncated approximation, but where the counter bias is specified for each S-box.
 *
 * pattern              The partial pattern. Any S-box that has not been specified yet is None.
 * determined_length    The number of S-boxes determined so far.
 * value                Squared correlation of the partial pattern.
 */
#[derive(Clone)]
struct InternalSboxPattern {
    pattern: Vec<Option<i16>>,
    determined_length: usize,
    value: f64 
}

impl InternalSboxPattern {
    /* Returns true if the are no None values in the pattern */
    fn is_complete(&self) -> bool {
        self.pattern[self.pattern.len() - 1].is_some()
    }

    /* Extends the current pattern to at most two "neighbouring" patterns
     * corr_values      A list counter biases for the S-box in descending order. 
                        Is assumed to contain the bias of the trivial approximation.
     */
    fn extend(&self, corr_values: &Vec<i16>) -> 
        (Option<InternalSboxPattern>, Option<InternalSboxPattern>) {
        // Counter bias of the trivial approximation
        let balance = corr_values[0] as f64;

        // We generate at most two new patterns
        let mut extended_patterns = (None, None);

        // The first pattern extends the current pattern to the left with the trivial bias
        // If the current pattern is complete, we cannot extend in this way
        if !self.is_complete() {
            let mut new_pattern = self.clone();
            new_pattern.pattern[self.determined_length] = Some(corr_values[0]);
            new_pattern.determined_length += 1;
            new_pattern.value *= (corr_values[0] as f64 / balance).powi(2);
            extended_patterns.0 = Some(new_pattern);
        }

        // The second pattern replaces the last determined counter bias with the 
        // next bias in the list 
        let mut new_pattern = self.clone();
        let current_value = self.pattern[self.determined_length - 1].unwrap();
        // This is kinda stupid. Could probably be improved?
        let corr_idx = corr_values.binary_search_by(|a| a.cmp(&current_value).reverse());
        
        // This check fails if the current bias was the last on the list
        // In this case, this pattern isn't generated
        match corr_idx {
            Ok(x) => {
                if x+1 < corr_values.len() {
                    new_pattern.pattern[self.determined_length - 1] = Some(corr_values[x+1]);
                    new_pattern.value /= (corr_values[x] as f64 / balance).powi(2);
                    new_pattern.value *= (corr_values[x+1] as f64 / balance).powi(2);
                    extended_patterns.1 = Some(new_pattern);
                }
            },
            Err(_) => {}
        };

        extended_patterns
    }
}

/* Ordering traits of the partial S-box patterns. Required for BinaryHeap<InternalSboxPattern> */
impl Ord for InternalSboxPattern {
    fn cmp(&self, other: &InternalSboxPattern) -> Ordering {
        // This is bad - only works because we never compare equal patters
        if self.value.log2() == other.value.log2() && 
           self.determined_length == other.determined_length {
            Ordering::Less
        } else if self.value.log2() != other.value.log2() {
            self.value.log2().partial_cmp(&other.value.log2()).expect("Float comparison failed.").reverse()
        } else {
            self.determined_length.cmp(&other.determined_length).reverse()
        }
    }
}

impl PartialOrd for InternalSboxPattern {
    fn partial_cmp(&self, other: &InternalSboxPattern) -> Option<Ordering> {
        // This is bad - only works because we never compare equal patters
        if self.value.log2() == other.value.log2() && 
           self.determined_length == other.determined_length {
            Some(Ordering::Less)
        } else if self.value.log2() != other.value.log2(){
            self.value.log2().partial_cmp(&other.value.log2())
        } else {
            Some(self.determined_length.cmp(&other.determined_length))
        }
    }
}

impl PartialEq for InternalSboxPattern {
    #[allow(unused_variables)]
    fn eq(&self, other: &InternalSboxPattern) -> bool {
        // This is bad - only works because we never compare equal patters
        false
    }
}

impl Eq for InternalSboxPattern {}

/***********************************************************************************************/


/* An external interface to InternalSboxPattern. These patterns are always complete.
 * 
 * Pattern      A vector describing the counter bias of each S-box.
 * Value        Squared correlation of the pattern.
 */
pub struct SboxPattern {
    pub pattern: Vec<i16>,
    pub value: f64
}

impl SboxPattern {
    /* Converts an InternalSboxPattern to an SboxPattern.
     * 
     * internal_sbox_pattern    A complete internal S-box pattern.
     */
    fn new(internal_sbox_pattern: &InternalSboxPattern) -> SboxPattern {
        // This fails of the pattern wasn't complete
        let pattern = internal_sbox_pattern.pattern.iter()
                                                   .map(|x| x.unwrap())
                                                   .collect();

        SboxPattern{pattern: pattern, value: internal_sbox_pattern.value}
    }
}

/***********************************************************************************************/


/* A struct that represents a list of single round approximations of a cipher, sorted in 
 * ascending order of their absolute correlation. The actual approximations are lazily 
 * generated using the Iterator trait. 
 *
 * cipher                   The cipher whose round function we are considering.
 * lat_map                  The LAT map for the cipher's S-box.
 * sorted_sbox_patterns     A list of S-box patterns sorted by their absolute correlation.
 * current_approximation    The last approximation generated.
 * current_pattern          The index of the current pattern considered in sorted_sbox_patterns.
 * current_app_index        Describes the indexing of lat_map for the current approximation.
 */
pub struct SortedApproximations<T: Cipher> {
    pub cipher: T,
    lat_map: LatMap,
    pub sorted_sbox_patterns: Vec<SboxPattern>,
    pub current_approximation: Approximation,
    current_pattern: usize,
    current_app_index: Vec<usize>
}

impl<T: Cipher + Clone> SortedApproximations<T> {
    /* Returns a new SortedApproximations struct ready to be used as an iterator.
     * The function basically generates the patterns in sorted_sbox_patterns, 
     * using an approach inspired by the paper
     * "Efficient Algorithms for Extracting the K Most Critical Paths in Timing Analysis"
     * by Yen, Du, and Ghanta. 
     *
     * cipher           The cipher whose round function we are considering. 
     * pattern_limit    The number of patterns we want to generate. 
     */
    pub fn new(cipher: T, pattern_limit: usize) -> SortedApproximations<T> {
        // Generate LAT map and get S-box counter bias values
        let lat_map: LatMap = LatMap::new(cipher.sbox());
        let mut corr_values = vec![];

        for (key, _) in &lat_map.map {
            corr_values.push(*key);
        }

        // We need the values in descending order
        corr_values.sort();
        corr_values.reverse();

        // Start with a partial pattern where only the first value is determined
        let mut tmp = vec![None; cipher.num_sboxes()];
        tmp[0] = Some(corr_values[0]);
        let current_pattern = InternalSboxPattern {
            pattern: tmp,
            determined_length: 1,
            value: 1.0
        };

        // We maintain a heap of partial patterns sorted by their correlation value
        let mut sorted_sbox_patterns = vec![];
        let mut heap = BinaryHeap::new();
        heap.push(current_pattern);

        // While we havn't generated enough patterns
        while sorted_sbox_patterns.len() < pattern_limit {
            // We ran out of patterns, so we return what we have so far
            if heap.is_empty() {
                let sorted_sbox_patterns = sorted_sbox_patterns.iter()
                                                       .map(|x| SboxPattern::new(x))
                                                       .collect();
                return SortedApproximations{cipher: cipher.clone(),
                                            lat_map: lat_map.clone(),
                                            sorted_sbox_patterns: sorted_sbox_patterns,
                                            current_approximation: Approximation::new(0, 0, None),
                                            current_pattern: 0,
                                            current_app_index: vec![0; cipher.num_sboxes()]}
            }

            // Extract the current best pattern
            let current_pattern = heap.pop().unwrap();

            // Extend best pattern and add the result to the heap
            let (pattern_1, pattern_2) = current_pattern.extend(&corr_values);

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
                sorted_sbox_patterns.push(current_pattern);
            }
        }

        let sorted_sbox_patterns = sorted_sbox_patterns.iter()
                                                       .map(|x| SboxPattern::new(x))
                                                       .collect();
        return SortedApproximations{cipher: cipher.clone(),
                                    lat_map: lat_map.clone(),
                                    sorted_sbox_patterns: sorted_sbox_patterns,
                                    current_approximation: Approximation::new(0, 0, None),
                                    current_pattern: 0,
                                    current_app_index: vec![0;  cipher.num_sboxes()]}
    }

    pub fn len(&self) -> usize {
        let mut len = 0;

        for pattern in &self.sorted_sbox_patterns {
            let mut combinations = 1;

            for &value in &pattern.pattern {
                combinations *= self.lat_map.len_of(value);
            }

            len += combinations;
        }

        len
    }
}

impl<T: Cipher + Clone> Iterator for SortedApproximations<T> {
    type Item = Approximation;
    
    /* Returns the next approximation in the sorted order */
    fn next(&mut self) -> Option<Approximation> {
        // Stop if we have generated all possible approximations
        if self.current_pattern >= self.sorted_sbox_patterns.len() {
            return None;
        }

        // Generate next approximation from the current S-box pattern and the LAT map
        let mut new_approximation = Approximation::new(0, 0, Some(self.sorted_sbox_patterns[self.current_pattern].value));
        let pattern = &self.sorted_sbox_patterns[self.current_pattern].pattern;

        for (i, &app_index) in self.current_app_index.iter().enumerate() {
            // Counter bias of the current S-box
            let value = pattern[i];

            // Get the current S-box approximation corresponding to the bias
            // This unwrap should never fail
            let sbox_app = &(*self.lat_map.get(&value).unwrap())[app_index];

            // Stitch together the full round approximation
            new_approximation.alpha ^= sbox_app.alpha << (self.cipher.sbox().size * i);
            new_approximation.beta ^= sbox_app.beta << (self.cipher.sbox().size * i);
        }

        new_approximation.beta = self.cipher.linear_layer(new_approximation.beta);
        self.current_approximation = new_approximation;

        // Advance approximation index
        let mut new_pattern = true;
        let mut i = 0;

        while i < self.current_app_index.len() {
            let value = pattern[i];

            if self.current_app_index[i]+1 < self.lat_map.len_of(value) {
                self.current_app_index[i] += 1;
                new_pattern = false;
                break;
            } else {
                self.current_app_index[i] = 0;
                i += 1;
            }
        }

        // Reset current approximation index if we reached a new pattern
        if new_pattern {
            self.current_pattern += 1;
            self.current_app_index = vec![0; self.current_app_index.len()];
        }

        Some(self.current_approximation.clone())
    }
}