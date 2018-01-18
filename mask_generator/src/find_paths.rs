use approximation::{Approximation};
use bloom_filter::{BloomBuilder, Bloom};
use cipher::Cipher;
use single_round::{SortedApproximations};
use std::collections::{HashMap,HashSet};
use time;
use utility::ProgressBar;

/* A structure representing an edge in the compressed linear hull graph. 
 * 
 * approximation    The edge goes from node approximation.alpha to approximation.beta.
 * masks            All intermediate masks known to be part of the hull between alpha and beta.
 * num_paths        Number of paths contained in this edge.
 */
#[derive(Clone)]
pub struct Edge {
    pub approximation: Approximation,
    // pub masks: HashSet<u64>,
    pub num_paths: usize,
}

impl Edge {
    /* Generate a new edge from a single round approximation.
     *
     * single_round_app     An approximation over a single round
     */
    fn new(single_round_app: &Approximation) -> Edge {
        // let masks = [single_round_app.alpha, single_round_app.beta].iter().cloned().collect();

        Edge {approximation: single_round_app.clone(),
              // masks: masks,
              num_paths: 1}
    }

    /* Reimplementation of HashSet<u64>::insert */    
    /*fn insert(&mut self, value: u64) -> bool {
        self.masks.insert(value)
    }*/
}

/***********************************************************************************************/


/* A struct representing a set of single round approximations.
 *
 * map      The map from alpha to a number of pairs (beta, squared correlation).
 * size     Number of approximations described by the map.
 */
pub struct SingleRoundMap {
    pub map: HashMap<u64, Vec<(u64, f64)>>,
    pub size: usize
}

impl SingleRoundMap {
    /* Construct a new empty map */
    fn new() -> SingleRoundMap {
        SingleRoundMap{ map: HashMap::new(), size: 0 }
    }

    /* Inserts a new single round approximation into the map. 
     *
     * approximation    A single round approximation.
     */
    fn insert(&mut self, approximation: Approximation) {
        let entry = self.map.entry(approximation.alpha).or_insert(vec![]);
        (*entry).push((approximation.beta, approximation.value));
        self.size += 1;
    }

    /* Reimplementation of HashMap::get */
    fn get(&self, alpha: &u64) -> Option<&Vec<(u64, f64)>> {
        self.map.get(alpha)
    }

    /* Reimplementation of HashMap::len */
    fn len(&self) -> usize {
        self.size
    }
}

/***********************************************************************************************/


/* A structure that maps approximations over a given number of rounds to an edge, 
 * which in turn represents a sub hull.
 *
 * map      The mapping from approximation to an edge 
 */
pub struct EdgeMap {
    pub map: HashMap<Approximation, Edge>
}

impl EdgeMap {
    /* Construct a new empty map */
    fn new() -> EdgeMap {
        EdgeMap{ map: HashMap::new() }
    }

    /* Reimplementation of HashMap::insert */
    fn insert(&mut self, approximation: Approximation, edge: Edge) {
        self.map.insert(approximation, edge);
    }

    /* Construct an edge map mapping from alpha to all betas in a single round map.
     * 
     * single_round_map     A single round map.
     * alpha                The desired start mask.
     */
    fn from_single_round_map(single_round_map: &SingleRoundMap) -> EdgeMap {
        let mut edge_map = EdgeMap::new();

        for (&alpha, betas) in &single_round_map.map {              
            for &(beta, value) in betas {
                let approximation = Approximation::new(alpha, beta, Some(value));
                let edge = Edge::new(&approximation);
                edge_map.insert(approximation, edge);
            }
        }

        edge_map
    }

    /* Reimplementation of HashMap::get_mut */
    fn get_mut(&mut self, approximation: &Approximation) -> Option<&mut Edge> {
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
fn create_alpha_filter<T: Cipher + Clone>(cipher: &T, pattern_limit: usize, false_positive: f64) -> Bloom<u64> {
    let mut start = time::precise_time_s();

    // Generate alpha bloom filter
    let sorted_alphas = SortedApproximations::new(cipher.clone(), pattern_limit, true);
    let num_alphas = sorted_alphas.len();
    
    let mut stop = time::precise_time_s();
    println!("Alpha patterns generated. [{} s]", stop-start);
    println!("There are {} possible alpha values.\n", sorted_alphas.len());

    start = time::precise_time_s();
    let mut alpha_filter = BloomBuilder::new(num_alphas as u64).with_fpr(false_positive).finish().unwrap();
    let mut progress_bar = ProgressBar::new(num_alphas);

    for approximation in sorted_alphas {
        alpha_filter.insert(approximation.alpha);
        progress_bar.increment();
    }
    
    stop = time::precise_time_s();
    println!("\nAlpha filter generated. [{} s]", stop-start);

    alpha_filter
}


/* Generates a single round map for a given cipher.  
 * 
 * cipher               The cipher of interest.
 * rounds               Number of rounds.
 * pattern_limit        The number of patterns to use when generating approximations.
 */
pub fn generate_single_round_map<T: Cipher + Clone> 
    (cipher: &T, rounds: usize, pattern_limit: usize, false_positive: f64) -> SingleRoundMap {
    let mut alpha_filters = vec![];
    let mut approximations = vec![];

    // The first alpha filter allows everything: false positive rate is 1
    let alpha_filter = BloomBuilder::new(1).with_fpr(1.0).finish().unwrap();
    alpha_filters.push(alpha_filter);

    // The next alpha filter is just all input masks in the last round
    let alpha_filter = create_alpha_filter(cipher, pattern_limit, false_positive);
    alpha_filters.push(alpha_filter);

    // The approximations in the last round are all approximations
    let approximation = SortedApproximations::new(cipher.clone(), pattern_limit, false);
    approximations.push(approximation);

    print!("\nProgressively narrowing alpha filter:");

    for r in 1..rounds {
        println!("\nRound {} ({} approximations, {} inputs)", r, approximations[r-1].len()
                                                               , approximations[r-1].len_alpha());

        alpha_filters.push(BloomBuilder::new(approximations[r-1].len_alpha() as u64)
                                        .with_fpr(false_positive)
                                        .finish()
                                        .unwrap());
        let copy = approximations[r-1].clone();
        approximations.push(copy);

        let mut kept_patterns = vec![false; approximations[r-1].sorted_sbox_patterns.len()];
        let mut progress_bar = ProgressBar::new(approximations[r-1].len());

        loop {
            match approximations[r-1].next_with_pattern() {
                Some((approximation, pattern)) => {
                    if alpha_filters[r].lookup(approximation.beta) {
                        kept_patterns[pattern] = true;
                        alpha_filters[r+1].insert(approximation.alpha);
                    }

                    progress_bar.increment();
                }, 
                None => {
                    break;
                }
            }
        }

        let retained_patterns = kept_patterns.iter()
                                             .zip(approximations[r-1].sorted_sbox_patterns.iter())
                                             .filter(|&(keep, _)| *keep)
                                             .map(|(_, pattern)| pattern.clone())
                                             .collect();
        approximations[r].sorted_sbox_patterns = retained_patterns; 
    }
    
    for p in approximations.iter_mut() {
        p.reset();
    }

    let mut hull_approximations = HashSet::new();
    let mut current_beta_filter = alpha_filters[rounds].clone();

    print!("\n\nCreating beta filters:");

    for r in 0..rounds {
        println!("\nRound {} ({} approximations)", r, approximations[rounds-r-1].len());

        let mut new_beta_filter = BloomBuilder::new(approximations[rounds-r-1].len() as u64)
                                               .with_fpr(false_positive)
                                               .finish()
                                               .unwrap();

        let mut progress_bar = ProgressBar::new(approximations[rounds-r-1].len());

        loop {
            match approximations[rounds-r-1].next() {
                Some(approximation) => {
                    if current_beta_filter.lookup(approximation.alpha) &&
                       alpha_filters[rounds-r-1].lookup(approximation.beta) {
                        new_beta_filter.insert(approximation.beta);
                        hull_approximations.insert(approximation);
                    }

                    progress_bar.increment();
                }, 
                None => {
                    break;
                }
            }
        }

        current_beta_filter = new_beta_filter;

        // Remove old alpha filter
        alpha_filters.remove(rounds-r-1);

        println!("\nCollected {} approximations.", hull_approximations.len());
    }

    println!("\n\nCreating single round map:");

    let mut single_round_map = SingleRoundMap::new();
    let mut progress_bar = ProgressBar::new(hull_approximations.len());

    for approximation in hull_approximations {
        single_round_map.insert(approximation);
        progress_bar.increment();
    }

    single_round_map
}


/* Find all linear subhulls which use a specific set of single round approximations 
 * starting with a parity alpha. 
 *
 * single_round_map     A map that describes the single round approximations included in the hull.
 * rounds               The number of rounds to consider.
 * alpha                The parity to start from. 
 */
pub fn find_paths(single_round_map: &SingleRoundMap, rounds: usize) -> EdgeMap {
    // Set up one round edge map
    let mut edge_map = EdgeMap::from_single_round_map(&single_round_map);

    print!("\nFinding linear hulls:");

    // Extend edge map the desired number of rounds
    for r in 1..rounds {
        println!("\nRound {} ({} approximations)", r, edge_map.map.len());
        let mut progress_bar = ProgressBar::new(edge_map.map.len());

        let mut new_edge_map = EdgeMap::new();

        // Go through all edges (i.e. approximations (alpha, beta)) in the current map
        for (approximation, edge) in &edge_map.map {
            let alpha = approximation.alpha;
            let beta = approximation.beta;
            
            // Look up beta in the single round map in order to extend one round
            match single_round_map.get(&beta) {
                Some(gammas) => {
                    // For each approximation of the type (beta, gamma)
                    for &(gamma, value) in gammas {
                        let new_approximation = Approximation::new(alpha, gamma, Some(value));

                        // Check of the approximation (alpha, gamma) is already in the new map
                        if new_edge_map.contains_key(&new_approximation) {
                            let existing_edge = new_edge_map.get_mut(&new_approximation)
                                                            .unwrap();
                            
                            // Add the one round masks to the existing set
                            /*existing_edge.masks = existing_edge.masks.union(&edge.masks)
                                                                     .cloned()
                                                                     .collect();*/
                            
                            // Update number of trails found and the squared correlation
                            existing_edge.num_paths += edge.num_paths;
                            existing_edge.approximation.value += edge.approximation.value * value;
                        } else {
                            // Otherwise, extend the (alpha, beta) with (beta, gamma)
                            let mut new_edge = (*edge).clone();
                            new_edge.approximation = new_approximation.clone();
                            // new_edge.insert(gamma);
                            new_edge.approximation.value = edge.approximation.value * value;
                            new_edge_map.insert(new_approximation, new_edge);
                        }
                    }
                },
                None => {}
            };

            progress_bar.increment();
        }

        edge_map = new_edge_map;
    }

    edge_map
}