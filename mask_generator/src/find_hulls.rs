use approximation::{Approximation};
use std::collections::{HashMap, HashSet};

/* A struct representing a set of single round approximations.
 *
 * map      The map from alpha to a number of pairs (beta, squared correlation).
 * size     Number of approximations described by the map.
 */
#[derive(Clone)]
pub struct SingleRoundMap {
    pub map: HashMap<u64, Vec<(u64, f64)>>
}

impl SingleRoundMap {
    /* Construct a new empty map */
    pub fn new() -> SingleRoundMap {
        SingleRoundMap{ map: HashMap::new() }
    }

    /* Inserts a new single round approximation into the map. 
     *
     * approximation    A single round approximation.
     */
    pub fn insert(&mut self, approximation: Approximation) {
        let entry = self.map.entry(approximation.alpha).or_insert(vec![]);
        (*entry).push((approximation.beta, approximation.value));
    }

    /* Reimplementation of HashMap::get */
    pub fn get(&self, alpha: &u64) -> Option<&Vec<(u64, f64)>> {
        self.map.get(alpha)
    }

    /* Returns the number of approximations stored in the map */
    pub fn len(&self) -> usize {
        let mut length = 0;

        for (_, v) in &self.map {
            length += v.len();
        }

        length
    }
}

/***********************************************************************************************/


/* A structure that maps approximations over a given number of rounds to an edge, 
 * which in turn represents a sub hull.
 *
 * map      The mapping from approximation to an edge 
 */
#[derive(Clone)]
pub struct EdgeMap {
    pub map: HashMap<Approximation, (usize, f64, HashSet<Approximation>)>
}

impl EdgeMap {
    /* Construct a new empty map */
    pub fn new() -> EdgeMap {
        EdgeMap{ map: HashMap::new() }
    }

    /* Reimplementation of HashMap::insert */
    pub fn insert(&mut self, approximation: Approximation, num_paths: usize, 
        value: f64, intermediate: HashSet<Approximation>) {
        self.map.insert(approximation, (num_paths, value, intermediate));
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
                    let intermediate = [approximation.clone()].iter().cloned().collect();
                    edge_map.insert(approximation, 1, value, intermediate);
                }

                return edge_map;
            },
            None => {
                return EdgeMap::new();
            }
        };
    }

    /* Reimplementation of HashMap::get_mut */
    pub fn get_mut(&mut self, approximation: &Approximation) 
        -> Option<&mut (usize, f64, HashSet<Approximation>)> {
        self.map.get_mut(approximation)
    }

    /* Reimplementation of HashMap::contains_key */
    pub fn contains_key(&self, approximation: &Approximation) -> bool {
        self.map.contains_key(approximation)
    }
}

/***********************************************************************************************/

/* Find all linear subhulls which use a specific set of single round approximations 
 * starting with a parity alpha. 
 *
 * single_round_map     A map that describes the single round approximations included in the hull.
 * rounds               The number of rounds to consider.
 */
pub fn find_hulls(single_round_map: &SingleRoundMap, rounds: usize, alpha: u64) -> EdgeMap {
    // Set up one round edge map
    let mut edge_map = EdgeMap::from_single_round_map(&single_round_map, alpha);

    // Extend edge map the desired number of rounds
    for _ in 1..rounds {
        let mut new_edge_map = EdgeMap::new();

        // Go through all edges (i.e. approximations (alpha, beta)) in the current map
        for (approximation, &(num_paths, value, ref intermediate)) in &edge_map.map {
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
                            // let mut new_intermediate = intermediate.clone();
                            // new_intermediate.insert(Approximation::new(beta, gamma, Some(new_value)));

                            // Update number of trails fo und and the squared correlation
                            existing_edge.0 += num_paths;
                            existing_edge.1 += value * new_value;
                            // existing_edge.2 = &existing_edge.2 | &new_intermediate;
                        } else {
                            // Otherwise, extend the (alpha, beta) with (beta, gamma)
                            let mut new_intermediate = intermediate.clone();
                            // new_intermediate.insert(Approximation::new(beta, gamma, Some(new_value)));
                            new_edge_map.insert(new_approximation, 
                                                num_paths, 
                                                value * new_value,
                                                new_intermediate);
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