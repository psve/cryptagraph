use approximation::{Approximation};
use cipher::Cipher;
use single_round::{SortedApproximations};
use std::collections::{HashMap,HashSet};
use time;
use utility::ProgressBar;
use bloom::BloomFilter;
use crossbeam_utils::scoped;
use std::sync::mpsc;
use num_cpus;

/* A struct representing a set of single round approximations.
 *
 * map      The map from alpha to a number of pairs (beta, squared correlation).
 * size     Number of approximations described by the map.
 */
#[derive(Clone)]
pub struct SingleRoundMap {
    pub map: HashMap<u64, Vec<(u64, f64)>>,
}

impl SingleRoundMap {
    /* Construct a new empty map */
    fn new() -> SingleRoundMap {
        SingleRoundMap{ map: HashMap::new() }
    }

    /* Inserts a new single round approximation into the map. 
     *
     * approximation    A single round approximation.
     */
    fn insert(&mut self, approximation: Approximation) {
        let entry = self.map.entry(approximation.alpha).or_insert(vec![]);
        (*entry).push((approximation.beta, approximation.value));
    }

    /* Reimplementation of HashMap::get */
    fn get(&self, alpha: &u64) -> Option<&Vec<(u64, f64)>> {
        self.map.get(alpha)
    }
}

/***********************************************************************************************/


/* A structure that maps approximations over a given number of rounds to an edge, 
 * which in turn represents a sub hull.
 *
 * map      The mapping from approximation to an edge 
 */
pub struct EdgeMap {
    pub map: HashMap<Approximation, (usize, f64)>
}

impl EdgeMap {
    /* Construct a new empty map */
    fn new() -> EdgeMap {
        EdgeMap{ map: HashMap::new() }
    }

    /* Reimplementation of HashMap::insert */
    fn insert(&mut self, approximation: Approximation, num_paths: usize, value: f64) {
        self.map.insert(approximation, (num_paths, value));
    }

    /* Construct an edge map mapping from alpha to all betas in a single round map.
     * 
     * single_round_map     A single round map.
     * alpha                The desired start mask.
     */
    fn from_single_round_map(single_round_map: &SingleRoundMap, alpha: u64) -> EdgeMap {
        match single_round_map.get(&alpha) {
            Some(betas) => {
                // If alpha was in the single round map, add all approximations starting
                // with alpha to the edge map
                let mut edge_map = EdgeMap::new();
                
                for &(beta, value) in betas {
                    let approximation = Approximation::new(alpha, beta, Some(value));
                    edge_map.insert(approximation, 1, value);
                }

                return edge_map;
            },
            None => {
                return EdgeMap::new();
            }
        };
}

    /* Reimplementation of HashMap::get_mut */
    fn get_mut(&mut self, approximation: &Approximation) -> Option<&mut (usize, f64)> {
        self.map.get_mut(approximation)
    }

    /* Reimplementation of HashMap::contains_key */
    fn contains_key(&self, approximation: &Approximation) -> bool {
        self.map.contains_key(approximation)
    }
}

/***********************************************************************************************/

/* Creates a bloom filter containing all input masks generated by a number of patterns.
 *
 * cipher           The cipher of interest.
 * pattern_limit    The maximum number of patterns to generate.
 */
fn create_alpha_filter(cipher: &Cipher, pattern_limit: usize, false_positive: f64) -> BloomFilter {
    let mut start = time::precise_time_s();

    // Generate alpha bloom filter
    let mut sorted_alphas = SortedApproximations::new(cipher, pattern_limit, true);
    let num_alphas = sorted_alphas.len();
    
    let mut stop = time::precise_time_s();
    println!("Alpha patterns generated. [{} s]", stop-start);
    println!("There are {} possible alpha values.\n", sorted_alphas.len());

    start = time::precise_time_s();
    let mut alpha_filter = BloomFilter::new(num_alphas, false_positive);
    let mut progress_bar = ProgressBar::new(num_alphas);

    loop {
        match sorted_alphas.next_with_pattern() {
            Some((approximation, _)) => {
                alpha_filter.insert(approximation.alpha);
                progress_bar.increment();
            }, 
            None => {
                break;
            }
        }
    }

    stop = time::precise_time_s();
    println!("\nAlpha filter generated. [{} s]", stop-start);

    alpha_filter
}

fn create_backward_filters
    (cipher: &Cipher, rounds: usize, pattern_limit: usize, false_positive: f64) -> 
    (Vec<BloomFilter>, Vec<SortedApproximations>){
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();

    let mut alpha_filters = vec![];
    let mut approximations = vec![];

    // The first alpha filter allows everything: false positive rate is 1
    let alpha_filter = BloomFilter::new(1, 1.0);
    alpha_filters.push(alpha_filter);

    // The next alpha filter is just all input masks in the last round
    let alpha_filter = create_alpha_filter(cipher, pattern_limit, false_positive);
    alpha_filters.push(alpha_filter);

    // The approximations in the last round are all approximations
    let approximation = SortedApproximations::new(cipher, pattern_limit, false);
    approximations.push(approximation);

    print!("\nProgressively narrowing alpha filter:");

    // We create new alpha filters by filtering based on the inputs to the next round
    for r in 1..rounds {
        println!("\nRound {} ({} approximations, {} inputs)", r, approximations[r-1].len()
                                                               , approximations[r-1].len_alpha());

        let copy = approximations[r-1].clone();
        approximations.push(copy);

        // Use scope since cipher contains a reference
        scoped::scope(|scope| {
            for t in 0..num_threads {
                let mut thread_approximations = approximations[r-1].clone();
                let mut thread_current_filter = alpha_filters[r].clone();
                let result_tx = result_tx.clone();

                scope.spawn(move || {
                    let mut thread_new_filter = 
                        BloomFilter::new(thread_approximations.len_alpha(), false_positive);
                    let mut thread_kept_patterns = 
                        vec![false; thread_approximations.sorted_sbox_patterns.len()];

                    let mut progress_bar = ProgressBar::new(thread_approximations.len());

                    thread_approximations.skip(t);

                    loop {
                        match thread_approximations.next_with_pattern() {
                            Some((approximation, pattern)) => {
                                // If an output was an input in the next round, keep its corresponding input
                                if thread_current_filter.contains(approximation.beta) {
                                    thread_kept_patterns[pattern] = true;
                                    thread_new_filter.insert(approximation.alpha);
                                }

                                progress_bar.increment();
                            }, 
                            None => {
                                break;
                            }
                        }

                        thread_approximations.skip(num_threads-1);
                    }

                    result_tx.send((thread_new_filter, thread_kept_patterns))
                             .expect("Thread could not send result");
                });
            }
        });


        let mut new_filter = BloomFilter::new(approximations[r-1].len_alpha(), false_positive);
        let mut kept_patterns = vec![false; approximations[r-1].sorted_sbox_patterns.len()];

        for _ in 0..num_threads {
            let thread_result = result_rx.recv().expect("Main could not receive result");
            
            // Find union of thread local filters and kept patterns
            new_filter.union(&thread_result.0);

            for i in 0..kept_patterns.len() {
                kept_patterns[i] |= thread_result.1[i];
            }
        }

        alpha_filters.push(new_filter);

        let retained_patterns = kept_patterns.iter()
                                             .zip(approximations[r-1].sorted_sbox_patterns.iter())
                                             .filter(|&(keep, _)| *keep)
                                             .map(|(_, pattern)| pattern.clone())
                                             .collect();
        approximations[r].sorted_sbox_patterns = retained_patterns;
    }
    
    // Reset the iteration of all approximations
    for p in approximations.iter_mut() {
        p.reset();
    }

    (alpha_filters, approximations)
}

fn create_hull_set
    (rounds: usize, false_positive: f64, 
     alpha_filters: &mut Vec<BloomFilter>, approximations: &mut Vec<SortedApproximations>) -> 
    (HashSet<Approximation>, HashSet<u64>) {
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();

    let mut hull_approximations = HashSet::new();
    let mut input_masks = HashSet::new();
    let mut current_beta_filter = alpha_filters[rounds].clone();

    print!("\n\nCreating beta filters:");

    // We maintain two beta filters corresponding to input and output in this round
    for r in 0..rounds {
        println!("\nRound {} ({} approximations)", r, approximations[rounds-r-1].len());

        // Use scope since cipher contains a reference
        scoped::scope(|scope| {
            for t in 0..num_threads {
                let mut thread_approximations = approximations[rounds-r-1].clone();
                let thread_alpha_filters = alpha_filters[rounds-r-1].clone();
                let thread_current_beta_filters = current_beta_filter.clone();
                let result_tx = result_tx.clone();

                scope.spawn(move || {
                    let mut thread_new_beta_filter = 
                        BloomFilter::new(thread_approximations.len(), false_positive);
                    let mut progress_bar = ProgressBar::new(thread_approximations.len());
                    let mut thread_hull_approximations = HashSet::new();
                    let mut thread_input_masks = HashSet::new();

                    thread_approximations.skip(t);

                    loop {
                        match thread_approximations.next_with_pattern() {
                            Some((approximation, _)) => {
                                // If an approximation exists in the input filter and the alpha
                                // filter of the next round, keep it and save that approximation
                                if thread_current_beta_filters.contains(approximation.alpha) &&
                                   thread_alpha_filters.contains(approximation.beta) {
                                    if r == 0 {
                                        thread_input_masks.insert(approximation.alpha);
                                    }

                                    thread_new_beta_filter.insert(approximation.beta);
                                    thread_hull_approximations.insert(approximation);
                                }

                                progress_bar.increment();
                            }, 
                            None => {
                                break;
                            }
                        }

                        thread_approximations.skip(num_threads-1);
                    }

                    result_tx.send((thread_new_beta_filter, thread_hull_approximations, thread_input_masks))
                              .expect("Thread could not send result");
                });
            }
        });

        let mut new_beta_filter = BloomFilter::new(approximations[rounds-r-1].len(), false_positive);

        for _ in 0..num_threads {
            let thread_result = result_rx.recv().expect("Main could not receive result");
            
            // Find union of thread local filters and approximations
            new_beta_filter.union(&thread_result.0);

            hull_approximations = hull_approximations.union(&thread_result.1).map(|x| x.clone()).collect();

            if r == 0 {
                input_masks = input_masks.union(&thread_result.2).map(|x| *x).collect();
            }
        }

        current_beta_filter = new_beta_filter;

        // Remove old alpha filter
        alpha_filters.remove(rounds-r-1);

        println!("\nCollected {} approximations.", hull_approximations.len());
    }

    (hull_approximations, input_masks)
}

/* Generates a single round map for a given cipher.  
 * 
 * cipher               The cipher of interest.
 * rounds               Number of rounds.
 * pattern_limit        The number of patterns to use when generating approximations.
 * false_positive       The false positive rate to use for Bloom filters
 */
pub fn generate_single_round_map
    (cipher: &Cipher, rounds: usize, pattern_limit: usize, false_positive: f64) -> 
    (SingleRoundMap, Vec<u64>) {
    let (mut alpha_filters, mut approximations) = 
        create_backward_filters(cipher, rounds, pattern_limit, false_positive);

    let (hull_approximations, input_masks) = 
        create_hull_set(rounds, false_positive, &mut alpha_filters, &mut approximations);

    println!("\n\nCreating single round map:");

    let mut single_round_map = SingleRoundMap::new();
    let mut progress_bar = ProgressBar::new(hull_approximations.len());

    for approximation in hull_approximations {
        single_round_map.insert(approximation);
        progress_bar.increment();
    }

    let input_masks: Vec<u64> = input_masks.iter().map(|x| *x).collect();

    (single_round_map, input_masks)
}


/* Find all linear subhulls which use a specific set of single round approximations 
 * starting with a parity alpha. 
 *
 * single_round_map     A map that describes the single round approximations included in the hull.
 * rounds               The number of rounds to consider.
 */
pub fn find_paths(single_round_map: &SingleRoundMap, rounds: usize, alpha: u64) -> EdgeMap {
    // Set up one round edge map
    let mut edge_map = EdgeMap::from_single_round_map(&single_round_map, alpha);

    // Extend edge map the desired number of rounds
    for _ in 1..rounds {
        let mut new_edge_map = EdgeMap::new();

        // Go through all edges (i.e. approximations (alpha, beta)) in the current map
        for (approximation, &(num_paths, value)) in &edge_map.map {
            let alpha = approximation.alpha;
            let beta = approximation.beta;
            
            // Look up beta in the single round map in order to extend one round
            match single_round_map.get(&beta) {
                Some(gammas) => {
                    // For each approximation of the type (beta, gamma)
                    for &(gamma, new_value) in gammas {
                        let new_approximation = Approximation::new(alpha, gamma, Some(new_value));

                        // Check of the approximation (alpha, gamma) is already in the new map
                        if new_edge_map.contains_key(&new_approximation) {
                            let existing_edge = new_edge_map.get_mut(&new_approximation)
                                                            .unwrap();
                            
                            // Update number of trails found and the squared correlation
                            existing_edge.0 += num_paths;
                            existing_edge.1 += value * new_value;
                        } else {
                            // Otherwise, extend the (alpha, beta) with (beta, gamma)
                            new_edge_map.insert(new_approximation, num_paths, value * new_value);
                        }
                    }
                },
                None => {}
            };
        }

        edge_map = new_edge_map;
    }

    edge_map
}