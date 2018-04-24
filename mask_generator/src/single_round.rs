use approximation::{Approximation};
use cipher::Cipher;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use fnv::FnvHashMap;

/* A structure that represents the LAT of an S-box as map from correlations to approximations.
 *
 * map          The mapping from the counter bias (abs(#pairs that hold - 2^(n-1))) to
                a vector of approximations that have that bias.
 * alpha_map    Same as map, but where only the input of the approximations are kept.
 * alpha_map    Same as map, but where only the output of the approximations are kept.
 */
#[derive(Clone)]
pub struct LatMap {
    pub map: FnvHashMap<i16, Vec<Approximation>>,
    alpha_map: FnvHashMap<i16, Vec<Approximation>>,
    beta_map: FnvHashMap<i16, Vec<Approximation>>,
}

impl LatMap {
    /* Generate a new LAT map from an S-box.
     *
     * sbox     The S-box used as the generator.
     */
    pub fn new(cipher: &Cipher) -> LatMap {
        let mut map = FnvHashMap::default();
        let mut alpha_map = FnvHashMap::default();
        let mut beta_map = FnvHashMap::default();

        // The number of pairs the hold for a balanced approximation (i.e. 2^(n-1))
        let balance = cipher.sbox().balance();

        for (alpha, row) in cipher.sbox().lat.iter().enumerate() {
            for (beta, element) in row.iter().enumerate() {
                // If the approximation is not balanced, we add it to the map
                if *element as i16 != balance {
                    // Absolute counter bias
                    let key = ((*element as i16) - balance).abs();

                    let entry = map.entry(key).or_insert(vec![]);
                    entry.push(Approximation::new(alpha as u64, beta as u64, None));

                    let entry = alpha_map.entry(key).or_insert(vec![]);
                    entry.push(Approximation::new(alpha as u64, (beta != 0) as u64, None));

                    let entry = beta_map.entry(key).or_insert(vec![]);
                    entry.push(Approximation::new((alpha != 0) as u64, beta as u64, None));
                }
            }
        }

        // Remove dubplicates
        for alphas in alpha_map.values_mut() {
            alphas.sort();
            alphas.dedup();
        }

        for betas in beta_map.values_mut() {
            betas.sort();
            betas.dedup();
        }

        LatMap{
            map: map, 
            alpha_map: alpha_map, 
            beta_map: beta_map
        }
    }

    /* Getter to avoid unecessary syntax. Simply reimplements FnvHashMap::get */
    pub fn get(&self, k: &i16) -> Option<&Vec<Approximation>> {
        self.map.get(k)
    }

    /* Getter for the alpha map */
    pub fn get_alpha(&self, k: &i16) -> Option<&Vec<Approximation>> {
        self.alpha_map.get(k)
    }

    /* Getter for the beta map */
    pub fn get_beta(&self, k: &i16) -> Option<&Vec<Approximation>> {
        self.beta_map.get(k)
    }

    /* Gets the number of approximations that has a certain counter bias.
     *
     * value    The target counter bias.
     */
    pub fn len_of(&self, value: i16) -> usize {
        self.get(&value).unwrap().len()
    }

    /* Gets the number of input masks that has a certain counter bias.
     *
     * value    The target counter bias.
     */
    fn len_of_alpha(&self, value: i16) -> usize {
        self.get_alpha(&value).unwrap().len()
    }

    /* Gets the number of output masks that has a certain counter bias.
     *
     * value    The target counter bias.
     */
    fn len_of_beta(&self, value: i16) -> usize {
        self.get_beta(&value).unwrap().len()
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
pub struct InternalSboxPattern {
    pattern: Vec<Option<i16>>,
    determined_length: usize,
    value: f64,
    num_active: usize
}

impl InternalSboxPattern {
    /* Returns true if the are no None values in the pattern */
    fn is_complete(&self) -> bool {
        self.pattern[self.pattern.len() - 1].is_some()
    }

    /* Extends the current pattern to at most two "neighbouring" patterns
     * corr_values      A list of counter biases for the S-box in descending order.
                        Is assumed to contain the bias of the trivial approximation.
     */
    fn extend(&self, corr_values: &Vec<i16>) ->
        (Option<InternalSboxPattern>, Option<InternalSboxPattern>) {
        // Counter bias of the trivial approximation
        let balance = corr_values[0] as f64;

        // We generate at most two new patterns
        let mut extended_patterns = (None, None);

        // The first pattern extends the current pattern to the right with the trivial bias
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
                    new_pattern.num_active += (x == 0) as usize;
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

#[derive(Clone, Debug)]
enum PatternStatus {
    New,
    Old,
    Empty
}

/* An external interface to InternalSboxPattern. These patterns are always complete.
 *
 * Pattern      A vector describing the counter bias of each S-box.
 * Value        Squared correlation of the pattern.
 */
#[derive(Clone)]
pub struct SboxPattern {
    pub pattern: Vec<(usize, i16)>,
    // pub value: f64,
    pub approximation: Approximation,
    mask: u64,
    counter: Vec<usize>,
    status: PatternStatus,
}

impl SboxPattern {
    /* Converts an InternalSboxPattern to an SboxPattern.
     *
     * internal_sbox_pattern    A complete internal S-box pattern.
     */
    pub fn new(
        cipher: &Cipher,
        internal_sbox_pattern: &InternalSboxPattern) 
        -> SboxPattern {
        let balance = cipher.sbox().balance();

        // This fails of the pattern wasn't complete
        let pattern: Vec<_> = internal_sbox_pattern.pattern.iter()
                                                   .map(|x| x.unwrap())
                                                   .enumerate()
                                                   .filter(|&(_,x)| x != balance)
                                                   .map(|(i,x)| (i*cipher.sbox().size, x))
                                                   .collect();

        let counter = vec![0; pattern.len()];
        let approximation = Approximation::new(0, 0, Some(internal_sbox_pattern.value));

        SboxPattern {
            pattern: pattern, 
            approximation: approximation,
            mask: ((1 << cipher.sbox().size) - 1) as u64,
            counter: counter,
            status: PatternStatus::New
        }
    }

    pub fn next(&mut self, lat_map: &LatMap, app_type: &AppType) -> Option<Approximation> {
        let status = self.status.clone();
        match status {
            PatternStatus::New => {
                for &(i, x) in &self.pattern {
                    let sbox_app = match app_type {
                        AppType::All   => lat_map.get(&x).unwrap()[0],
                        AppType::Alpha => lat_map.get_alpha(&x).unwrap()[0],
                        AppType::Beta  => lat_map.get_beta(&x).unwrap()[0]
                    };
                    let alpha = sbox_app.alpha;
                    let beta = sbox_app.beta;

                    self.approximation.alpha ^= alpha << i;
                    self.approximation.beta ^= beta << i;
                }

                self.status = PatternStatus::Old;
                return self.next(lat_map, app_type);
            },
            PatternStatus::Old => {
                if self.counter.len() == 0 {
                    self.status = PatternStatus::Empty;
                }

                let result = self.approximation;

                for i in 0..self.counter.len() {
                    let idx = self.pattern[i].0;
                    let val = self.pattern[i].1;
                    let modulus = match app_type {
                        AppType::All   => lat_map.len_of(val),
                        AppType::Alpha => lat_map.len_of_alpha(val),
                        AppType::Beta  => lat_map.len_of_beta(val)
                    };

                    self.counter[i] = (self.counter[i] + 1) % modulus;

                    // No more approximations
                    if i+1 == self.counter.len() && self.counter[i] == 0 {
                        self.status = PatternStatus::Empty;
                        return Some(result);
                    }

                    // Update current position
                    let app = match app_type {
                        AppType::All   => lat_map.get(&val).unwrap()[self.counter[i]],
                        AppType::Alpha => lat_map.get_alpha(&val).unwrap()[self.counter[i]],
                        AppType::Beta  => lat_map.get_beta(&val).unwrap()[self.counter[i]]
                    };

                    self.approximation.alpha = 
                        (self.approximation.alpha & !(self.mask << idx)) ^ (app.alpha << idx);
                    self.approximation.beta = 
                        (self.approximation.beta & !(self.mask << idx)) ^ (app.beta << idx);

                    // Continue only if current counter rolls over
                    if self.counter[i] != 0 {
                        break;
                    }
                }
                
                return Some(result);
            },
            PatternStatus::Empty => {
                return None;
            }
        }
    }

    /* Returns the number of approximations described by this pattern */
    pub fn num_app(&self, lat_map: &LatMap) -> usize {
        self.pattern.iter().fold(1, |acc, &(_, x)| acc * lat_map.len_of(x))
    }

    /* Returns the number of input masks described by this pattern */
    pub fn num_alpha(&self, lat_map: &LatMap) -> usize {
        self.pattern.iter().fold(1, |acc, &(_, x)| acc * lat_map.len_of_alpha(x))
    }

    /* Returns the number of output masks described by this pattern */
    pub fn num_beta(&self, lat_map: &LatMap) -> usize {
        self.pattern.iter().fold(1, |acc, &(_, x)| acc * lat_map.len_of_beta(x))
    }
}

/***********************************************************************************************/

#[derive(Clone, Debug)]
pub enum AppType {
    All,
    Alpha,
    Beta
}

/* A struct that represents a list of single round approximations of a cipher, sorted in
 * ascending order of their absolute correlation. The actual approximations are lazily
 * generated using the Iterator trait.
 *
 * cipher                   The cipher whose round function we are considering.
 * lat_map                  The LAT map for the cipher's S-box.
 * sbox_patterns            A list of S-box patterns sorted by their absolute correlation.
 * app_type                 What type of approximation an iterator will generate.
 */
#[derive(Clone)]
pub struct SortedApproximations<'a> {
    pub cipher: &'a Cipher,
    pub lat_map: LatMap,
    pub sbox_patterns: Vec<SboxPattern>,
    app_type: AppType,
}

impl<'a> SortedApproximations<'a> {
    /* Returns a new SortedApproximations struct ready to be used as an iterator.
     * The function basically generates the patterns in sbox_patterns,
     * using an approach inspired by the paper
     * "Efficient Algorithms for Extracting the K Most Critical Paths in Timing Analysis"
     * by Yen, Du, and Ghanta.
     *
     * cipher           The cipher whose round function we are considering.
     * pattern_limit    The number of patterns we want to generate.
     */
    pub fn new(cipher: &Cipher, pattern_limit: usize, app_type: AppType) -> SortedApproximations {
        // Generate LAT map and get S-box counter bias values
        let lat_map = LatMap::new(cipher);
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
            value: 1.0,
            num_active: 0
        };

        // We maintain a heap of partial patterns sorted by their correlation value
        let mut sbox_patterns = vec![];
        let mut heap = BinaryHeap::new();
        heap.push(current_pattern);

        // While we havn't generated enough patterns
        while sbox_patterns.len() < pattern_limit {
            // We ran out of patterns, so we return what we have so far
            if heap.is_empty() {
                let sbox_patterns: Vec<SboxPattern>
                    = sbox_patterns.iter()
                                          .map(|x| SboxPattern::new(cipher, x))
                                          .collect();

                return SortedApproximations{cipher: cipher.clone(),
                                            lat_map: lat_map.clone(),
                                            sbox_patterns: sbox_patterns,
                                            app_type: app_type}
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
                sbox_patterns.push(current_pattern);
            }
        }

        let sbox_patterns: Vec<SboxPattern>
            = sbox_patterns.iter()
                                  .map(|x| SboxPattern::new(cipher, x))
                                  .collect();

        return SortedApproximations{cipher: cipher.clone(),
                                    lat_map: lat_map.clone(),
                                    sbox_patterns: sbox_patterns,
                                    app_type: app_type}
    }

    /* Returns the number of approximations which can be generated from the patterns. */
    pub fn len(&self) -> usize {
        let mut len = 0;

        for pattern in &self.sbox_patterns {
            let combinations = match self.app_type {
                AppType::All   => pattern.num_app(&self.lat_map),
                AppType::Alpha => pattern.num_alpha(&self.lat_map),
                AppType::Beta  => pattern.num_beta(&self.lat_map),
            };

            len += combinations;
        }

        len
    }

    /* Returns the number of patterns */
    pub fn len_patterns(&self) -> usize {
        self.sbox_patterns.len()
    }

    /* Sets the type field to all */
    pub fn set_type_all(&mut self) {
        self.app_type = AppType::All;
    }

    /* Sets the type field to alpha */
    pub fn set_type_alpha(&mut self) {
        self.app_type = AppType::Alpha;
    }

    /* Sets the type field to beta */
    pub fn set_type_beta(&mut self) {
        self.app_type = AppType::Beta;
    }
}

impl<'a> IntoIterator for &'a SortedApproximations<'a> {
    type Item = (Approximation, usize);
    type IntoIter = SortedApproximationsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SortedApproximationsIterator { 
            cipher: self.cipher,
            lat_map: self.lat_map.clone(),
            sbox_patterns: self.sbox_patterns.clone(),
            app_type: self.app_type.clone(),
            current_pattern: 0       
        }
    }
}

/* An iterator over approximations represented by a SortedApproximations struct.
 *
 * sorted_approximations    The struct to iterate over. 
 * current_approximation    The last approximation generated.
 * current_pattern          The index of the current pattern considered in sbox_patterns.
 * current_app_index        Describes the indexing of lat_map for the current approximation.
 */
#[derive(Clone)]
pub struct SortedApproximationsIterator<'a> {
    pub cipher: &'a Cipher,
    pub lat_map: LatMap,
    pub sbox_patterns: Vec<SboxPattern>,
    app_type: AppType,
    current_pattern: usize
}

impl<'a> Iterator for SortedApproximationsIterator<'a> {
    type Item = (Approximation, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let max_length = self.sbox_patterns.len();
        
        // Stop if we have generated all possible approximations
        if self.current_pattern >= max_length {
            return None;
        }

        // Generate next approximation from the current S-box pattern and the LAT map
        let mut approximation = None;

        while approximation.is_none() {
            let pattern = &mut self.sbox_patterns[self.current_pattern];
            approximation = match pattern.next(&self.lat_map, &self.app_type) {
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
        
        let mut approximation = approximation.unwrap();
        let (alpha, beta) = self.cipher
                                .sbox_mask_transform(approximation.alpha, 
                                                     approximation.beta);
        approximation.alpha = alpha;
        approximation.beta = beta;

        Some((approximation, self.current_pattern))
    }
}