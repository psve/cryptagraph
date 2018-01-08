use approximation::{Approximation};
use single_round::{SortedApproximations};
use cipher::Cipher;
use std::collections::{HashMap,HashSet};
use time;

/* A structure representing an edge in the compressed linear hull graph. 
 * 
 * approximation    The edge goes from node approximation.alpha to approximation.beta.
 * masks            All intermediate masks known to be part of the hull between alpha and beta.
 * num_paths        Number of paths contained in this edge.
 * value            Squared correlation of the linear subhull represented by this edge.
 * length           The number of rounds the approximation stretches over.
 */
#[derive(Clone)]
pub struct Edge {
    pub approximation: Approximation,
    pub masks: HashSet<u64>,
    pub num_paths: usize,
    pub value: f64,
    pub length: usize,
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
              num_paths: 1,
              value: single_round_app.value,
              length: 1}
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
        // Check if alpha already has an entry in the map.
        if self.map.contains_key(&approximation.alpha) {
            let betas = self.map.get_mut(&approximation.alpha).unwrap();

            // Add new beta to the current list of betas
            betas.push((approximation.beta, approximation.value));
        // Otherwise create a new entry.
        } else {
            let betas = vec![(approximation.beta, approximation.value)];
            self.map.insert(approximation.alpha, betas);
        }

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
        let entry = single_round_map.get(&alpha);

        match entry {
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


/* Generates a single round map for a given cipher. 
 * 
 * cipher               The cipher of interest.
 * pattern_limit        The number of patterns to use when generating approximations.
 * approximation_limit  Maximum number of approximations to generate.
 */
pub fn generate_single_round_map<T: Cipher + Clone>
    (cipher: &T, pattern_limit: usize, approximation_limit: usize) -> SingleRoundMap {
    let mut start = time::precise_time_s();

    // Generate single round approximations in sorted order
    let sorted_approximations = SortedApproximations::new(cipher.clone(), pattern_limit);

    let mut stop = time::precise_time_s();
    println!("Patterns generated. [{} s]", stop-start);
    println!("There are {} possible approximations.", sorted_approximations.len());

    start = time::precise_time_s();

    // Insert all single round approximations into a new map
    // let mut single_round_map = SingleRoundMap::with_capacity(approximation_limit);
    let mut single_round_map = SingleRoundMap::new();
    let mut last = Approximation::new(0, 0, None);
    
    for approximation in sorted_approximations {
        single_round_map.insert(approximation.clone());
        last = approximation;

        if single_round_map.len() >= approximation_limit {
            break;
        }
    }
    
    stop = time::precise_time_s();
    
    println!("Single round approximations generated. [{} s]", stop-start);
    println!("Last approximation is: {:?} = {}\n", last, last.value.log2());

    // single_round_map.shrink_to_fit();
    single_round_map
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
        panic!("Alpha was not found in the initial set of approximations");
    }

    // Extend for edge map the desired number of rounds
    for _ in 1..rounds {
        // print!("Calculating round {}... ", i);
        // let start = time::precise_time_s();

        let mut new_edge_map = EdgeMap::new();

        // Go through all edges (i.e. approximations (alpha, beta)) in the current map
        for (approximation, edge) in &edge_map.map {
            let alpha = approximation.alpha;
            let beta = approximation.beta;
            
            // Look up beta in the single round map in order to extend one round
            let entry = single_round_map.get(&beta);

            match entry {
                Some(gammas) => {
                    // For each approximation of the type (beta, gamma)
                    for &(gamma, value) in gammas {
                        let new_approximation = Approximation::new(alpha, gamma, Some(value));

                        // Check of the approximation (alpha, gamma) is already in the new map
                        if new_edge_map.contains_key(&new_approximation) {
                            let existing_edge = new_edge_map.get_mut(&new_approximation)
                                                            .unwrap();
                            
                            // Add the one round masks to the existing set
                            let new_edge_set = existing_edge.masks.union(&edge.masks)
                                                                  .cloned()
                                                                  .collect();
                            existing_edge.masks = new_edge_set;
                            
                            // Update number of trails found and the squared correlation
                            existing_edge.num_paths += edge.num_paths;
                            existing_edge.value += edge.value * value;
                        } else {
                            // Otherwise, extend the (alpha, beta) with (beta, gamma)
                            let mut new_edge = (*edge).clone();
                            new_edge.approximation = new_approximation.clone();
                            new_edge.insert(gamma);
                            new_edge.value = edge.value * value;
                            new_edge.length += 1;
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

        // let stop = time::precise_time_s();       
        // println!("[{} s]", stop-start);
    }

    edge_map
}