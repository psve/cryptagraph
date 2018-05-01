use property::{Property};
use fnv::{FnvHashMap, FnvHashSet};
use graph::MultistageGraph;
use time;
use std::sync::mpsc;
use num_cpus;
use utility::ProgressBar;
use crossbeam_utils::scoped;

/***********************************************************************************************/

/* Find all linear subhulls which use a specific set of single round properties 
 * starting with a parity input. 
 *
 * single_round_map     A map that describes the single round properties included in the hull.
 * rounds               The number of rounds to consider.
 */
fn find_hulls(
    graph: &MultistageGraph, 
    rounds: usize, 
    input: u64) 
    -> Vec<Property> {
    let start_property = Property::new(input, input, 1.0, 1);
    let mut edge_map = FnvHashMap::default();
    edge_map.insert(input, start_property);

    // Extend edge map the desired number of rounds
    for r in 0..rounds {
        let mut new_edge_map = FnvHashMap::default();

        // Go through all edges (i.e. properties (input, output)) in the current map
        for (output, &property) in &edge_map {
            // Look up output in the single round map in order to extend one round
            match graph.get_vertex(r, *output as usize) {
                Some(vertex_ref) => {
                    for (&new_output, &length) in &vertex_ref.successors {
                        let new_value = 2.0f64.powf(-length);
                        let entry = new_edge_map.entry(new_output as u64)
                                                .or_insert(Property::new(property.input,
                                                                         new_output as u64,
                                                                         0.0, 0));

                        (*entry).trails += property.trails;
                        (*entry).value += property.value * new_value;
                    }
                },
                None => {}
            }
        }

        edge_map = new_edge_map;
    }

    edge_map.values().map(|x| *x).collect()
}

pub fn parallel_find_hulls (
    graph: &MultistageGraph,
    rounds: usize,
    input_masks: &FnvHashSet<u64>,
    input_allowed: &FnvHashSet<u64>,
    output_allowed: &FnvHashSet<u64>,
    num_keep: usize) 
    -> Vec<Property> {
    println!("Finding linear hulls ({} input masks, {} approximations):", 
             input_masks.len(), graph.num_edges());

    let start = time::precise_time_s();
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();

    scoped::scope(|scope| {
        for t in 0..num_threads {
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                let mut result = vec![];
                let mut progress_bar = ProgressBar::new(input_masks.len());
                let mut min_value = 1.0_f64;
                let mut num_found = 0;
                let mut paths = 0;

                for &input in input_masks.iter().skip(t).step_by(num_threads) {
                    let hulls = find_hulls(&graph, rounds, input);
                    num_found += hulls.len();
                    
                    for property in &hulls {
                        if (input_allowed.len() == 0 || input_allowed.contains(&property.input)) &&
                           (output_allowed.len() == 0 || output_allowed.contains(&property.output)) {
                            paths += property.trails;
                            result.push(*property);
                        }
                    }
                    
                    result.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap());
                    match result.last() {
                        Some(property) => {
                            min_value = min_value.min(property.value);
                        },
                        None => { }
                    }
                    result.truncate(num_keep);
                    progress_bar.increment();
                }

                result_tx.send((result, min_value, num_found, paths)).expect("Thread could not send result");
            });
        }
    });

    let mut paths = 0;
    let mut num_found = 0;
    let mut min_value = 1.0_f64;;
    let mut result = vec![];

    for _ in 0..num_threads {
        let mut thread_result = result_rx.recv().expect("Main could not receive result");
        
        result.append(&mut thread_result.0);
        min_value = min_value.min(thread_result.1);
        num_found += thread_result.2;
        paths += thread_result.3;
    }

    println!("");

    result.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap());
    result.truncate(num_keep);

    println!("\nFound {} approximations. [{} s]", num_found, time::precise_time_s()-start);

    if result.len() > 0 {
        println!("Smallest squared correlation: {}", min_value.log2());
        println!("Largest squared correlation:  {}\n", result[0].value.log2());
        println!("Total number of trails:  {}\n", paths);
    }

    result
}