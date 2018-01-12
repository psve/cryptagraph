use approximation::{Approximation};
use single_round::{SortedApproximations, SboxPattern};
use cipher::Cipher;
use std::collections::{HashMap,HashSet};
use std::cmp;
use std::io::{self, Write};
use time;
use bloom::{ASMS, BloomFilter};

/* A structure representing an edge in the compressed linear hull graph. 
 * 
 * approximation    The edge goes from node approximation.alpha to approximation.beta.
 * masks            All intermediate masks known to be part of the hull between alpha and beta.
 * num_paths        Number of paths contained in this edge.
 */
#[derive(Clone)]
pub struct Edge {
    pub approximation: Approximation,
    pub masks: HashSet<u64>,
    pub num_paths: usize,
}

impl Edge {
    /* Generate a new edge from a single round approximation.
     *
     * single_round_app     An approximation over a single round
     */
    fn new(single_round_app: &Approximation) -> Edge {
        let masks = [single_round_app.alpha, single_round_app.beta].iter().cloned().collect();

        Edge {approximation: single_round_app.clone(),
              masks: masks,
              num_paths: 1}
    }

    /* Reimplementation of HashSet<u64>::insert */    
    fn insert(&mut self, value: u64) -> bool {
        self.masks.insert(value)
    }
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
    fn from_single_round_map(single_round_map: &SingleRoundMap, alpha: u64) -> EdgeMap {
        match single_round_map.get(&alpha) {
            Some(betas) => {
                // If alpha was in the single round map, add all approximations starting
                // with alpha to the edge map
                let mut edge_map = EdgeMap::new();
                
                for &(beta, value) in betas {
                    let approximation = Approximation::new(alpha, beta, Some(value));
                    let edge = Edge::new(&approximation);
                    edge_map.insert(approximation, edge);
                }

                return edge_map;
            },
            None => {
                return EdgeMap::new();
            }
        };
    }

    /* Reimplementation of HashMap::get_mut */
    fn get_mut(&mut self, approximation: &Approximation) -> Option<&mut Edge> {
        self.map.get_mut(approximation)
    }

    /* Reimplementation of HashMap::contains_key */
    fn contains_key(&self, approximation: &Approximation) -> bool {
        self.map.contains_key(approximation)
    }

    /* Reimplementation of HashMap::is_empty */
    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/***********************************************************************************************/

/* Creates a bloom filter containing all input masks generated by a number of patterns.
 *
 * cipher           The cipher of interest.
 * pattern_limit    The maximum number of patterns to generate.
 */
fn create_alpha_filter<T: Cipher + Clone>(cipher: &T, pattern_limit: usize) -> BloomFilter {
    let mut start = time::precise_time_s();

    // Generate alpha bloom filter
    let sorted_alphas = SortedApproximations::new(cipher.clone(), pattern_limit, true);
    let num_alphas = sorted_alphas.len();
    
    let mut stop = time::precise_time_s();
    println!("Alpha patterns generated. [{} s]", stop-start);
    println!("There are {} possible alpha values.\n", sorted_alphas.len());

    start = time::precise_time_s();
    let mut alpha_filter = BloomFilter::with_rate(0.01, num_alphas as u32);
    let mut progress = 0;
    let mut percentage = 0;

    for approximation in sorted_alphas {
        alpha_filter.insert(&approximation.alpha);

        // Lazy progress bar. Make nicer at some point
        if progress > (num_alphas / 100 * percentage) {
            print!("=");
            io::stdout().flush().ok().expect("Could not flush stdout");
            percentage += 1;
        }

        progress += 1;
    }
    
    stop = time::precise_time_s();
    println!("\nAlpha filter generated. [{} s]", stop-start);
    println!("Bits in alpha filter: {:?}", alpha_filter.num_bits());

    alpha_filter
}


/* Generates a single round map for a given cipher. The map is filter such that only 
 * approximations that can survive more than one round are kept. 
 * 
 * cipher               The cipher of interest.
 * pattern_limit        The number of patterns to use when generating approximations.
 * approximation_limit  Maximum number of approximations to generate.
 */
pub fn generate_single_round_map<T: Cipher + Clone>
    (cipher: &T, pattern_limit: usize, approximation_limit: usize) -> SingleRoundMap {
    let alpha_filter = create_alpha_filter(cipher, pattern_limit);

    let mut start = time::precise_time_s();

    // Generate single round approximations in sorted order
    let sorted_approximations = SortedApproximations::new(cipher.clone(), pattern_limit, false);
    
    let mut stop = time::precise_time_s();
    println!("\nSingle round approximation patterns generated. [{} s]", stop-start);
    println!("There are {} possible approximations.\n", sorted_approximations.len());

    start = time::precise_time_s();

    // Insert all single round approximations into a new map
    let mut single_round_map = SingleRoundMap::new();
    let mut last = Approximation::new(0, 0, None);
    let search_limit = cmp::min(approximation_limit, sorted_approximations.len());
    let mut progress = 0;
    let mut percentage = 0;

    for approximation in sorted_approximations {
        if alpha_filter.contains(&approximation.beta) {
            single_round_map.insert(approximation.clone());
            last = approximation;
        }

        progress += 1;

        // Lazy progress bar. Make nicer at some point
        if progress > (search_limit / 100 * percentage) {
            print!("=");
            io::stdout().flush().ok().expect("Could not flush stdout");
            percentage += 1;
        }

        if progress >= approximation_limit {
            break;
        }
    }
    
    stop = time::precise_time_s();
    
    println!("\nSingle round approximations generated. [{} s]", stop-start);
    println!("Last approximation is: {:?} = {}", last, last.value.log2());
    println!("Size of single round map: {}\n", single_round_map.len());

    single_round_map
}

/* Generates a single round map for a given cipher. The map is not filtered, but approximations
 * that already exists in the supplied single round map are not added.  
 * 
 * cipher               The cipher of interest.
 * last_round_limit     The number of patterns to use when generating approximations.
 * approximation_limit  Maximum number of approximations to generate.
 * single_round_map     An existing map to check for duplicates.
 */
pub fn generate_last_round_map<T: Cipher + Clone>
    (cipher: &T, last_round_limit: usize, approximation_limit: usize, 
     single_round_map: &SingleRoundMap) -> SingleRoundMap {

    let mut start = time::precise_time_s();

    // Generate single round approximations in sorted order
    let sorted_approximations = SortedApproximations::new(cipher.clone(), last_round_limit, false);
    
    let mut stop = time::precise_time_s();
    println!("Last round approximation patterns generated. [{} s]", stop-start);
    println!("There are {} possible approximations.\n", sorted_approximations.len());

    start = time::precise_time_s();

    // Insert all single round approximations into a new map
    let mut last_round_map = SingleRoundMap::new();
    let mut last = Approximation::new(0, 0, None);
    let search_limit = cmp::min(approximation_limit, sorted_approximations.len());
    let mut progress = 0;
    let mut percentage = 0;

    for approximation in sorted_approximations {
        // Check if current approximation already exists in the single round map
        match single_round_map.get(&approximation.alpha) {
            Some(betas) => {
                let found = betas.iter()
                                 .fold(false, 
                                       |acc, &(beta, _)| acc | (approximation.beta == beta));
                
                if !found {
                    last_round_map.insert(approximation.clone());
                    last = approximation;
                }
            },
            None => {
                last_round_map.insert(approximation.clone());
                last = approximation;
            }
        }

        progress += 1;

        // Lazy progress bar. Make nicer at some point
        if progress > (search_limit / 100 * percentage) {
            print!("=");
            io::stdout().flush().ok().expect("Could not flush stdout");
            percentage += 1;
        }

        if progress >= approximation_limit {
            break;
        }
    }
    
    stop = time::precise_time_s();
    
    println!("\nLast round approximations generated. [{} s]", stop-start);
    println!("Last approximation is: {:?} = {}", last, last.value.log2());
    println!("Size of last round map: {}\n", last_round_map.len());

    last_round_map
}

/* Find all linear subhulls which use a specific set of single round approximations 
 * starting with a parity alpha. 
 *
 * single_round_map     A map that describes the single round approximations included in the hull.
 * rounds               The number of rounds to consider.
 * alpha                The parity to start from. 
 */
pub fn find_paths(single_round_map: &SingleRoundMap, rounds: usize, alpha: u64) -> EdgeMap {
    // Set up one round edge map
    let mut edge_map = EdgeMap::from_single_round_map(&single_round_map, alpha);

    if edge_map.is_empty() {
        return edge_map;
    }

    // Extend edge map the desired number of rounds
    for _ in 1..rounds {
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
                            existing_edge.masks = existing_edge.masks.union(&edge.masks)
                                                                     .cloned()
                                                                     .collect();
                            
                            // Update number of trails found and the squared correlation
                            existing_edge.num_paths += edge.num_paths;
                            existing_edge.approximation.value += edge.approximation.value * value;
                        } else {
                            // Otherwise, extend the (alpha, beta) with (beta, gamma)
                            let mut new_edge = (*edge).clone();
                            new_edge.approximation = new_approximation.clone();
                            new_edge.insert(gamma);
                            new_edge.approximation.value = edge.approximation.value * value;
                            new_edge_map.insert(new_approximation, new_edge);
                        }
                    }
                },
                None => { 
                    continue 
                }
            };
        }

        edge_map = new_edge_map;
    }

    edge_map
}

/* Extends an edge map a single round using two single round maps: one filtered, and one unfiltered.
 *
 * edge_map             The edge map to extend.
 * single_round_map     A filtered single round map.
 * last_round_map       An unfiltered single round map.
 */
pub fn last_round(edge_map: &EdgeMap, 
    single_round_map: &SingleRoundMap, last_round_map: &SingleRoundMap) -> EdgeMap {
    // Extend edge map the last round
    let mut new_edge_map = EdgeMap::new();

    // Go through all edges (i.e. approximations (alpha, beta)) in the current map
    for (approximation, edge) in &edge_map.map {
        let alpha = approximation.alpha;
        let beta = approximation.beta;

        let mut gammas = vec![];

        match single_round_map.get(&beta) {
            Some(x) => {
                let mut x = x.clone();
                gammas.append(&mut x.clone())
            },
            None => { }
        };

        match last_round_map.get(&beta) {
            Some(x) => {
                gammas.append(&mut x.clone())
            },
            None => { }
        };

        // For each approximation of the type (beta, gamma)
        for &(gamma, value) in &gammas {
            let new_approximation = Approximation::new(alpha, gamma, Some(value));

            // Check of the approximation (alpha, gamma) is already in the new map
            if new_edge_map.contains_key(&new_approximation) {
                let existing_edge = new_edge_map.get_mut(&new_approximation)
                                                .unwrap();
                
                // Add the one round masks to the existing set
                existing_edge.masks = existing_edge.masks.union(&edge.masks)
                                                         .cloned()
                                                         .collect();
                
                // Update number of trails found and the squared correlation
                existing_edge.num_paths += edge.num_paths;
                existing_edge.approximation.value += edge.approximation.value * value;
            } else {
                // Otherwise, extend the (alpha, beta) with (beta, gamma)
                let mut new_edge = (*edge).clone();
                new_edge.approximation = new_approximation.clone();
                new_edge.insert(gamma);
                new_edge.approximation.value = edge.approximation.value * value;
                new_edge_map.insert(new_approximation, new_edge);
            }
        }
    }

    new_edge_map
}