use crossbeam_utils::scoped;
use fnv::FnvHashSet;
use indexmap::IndexMap;
use num_cpus;
use std::sync::mpsc;
use time;

use graph::MultistageGraph;
use property::{Property};
use utility::ProgressBar;

/***********************************************************************************************/

/**
Find all properties for a given graph starting with a specific input value. 

graph       The graph to search through.
input       The input value to start the search from.
*/
fn find_properties(graph: &MultistageGraph, 
                   input: u64) 
                   -> IndexMap<u64, Property> {
    let rounds = graph.stages()-1;
    let start_property = Property::new(input, input, 1.0, 1);
    
    // The edge map maps output values to properties over a number of rounds
    // It first contains an "empty" property
    let mut edge_map = IndexMap::new();
    edge_map.insert(input, start_property);

    // Extend the edge map the desired number of rounds
    for r in 0..rounds {
        let mut new_edge_map = IndexMap::new();

        // Go through all edges (i.e. properties (input, output)) in the current map
        for (output, &property) in &edge_map {
            // Look up output in the single round map in order to extend one round
            match graph.get_vertex(r, *output as usize) {
                Some(vertex_ref) => {
                    for (&new_output, &length) in &vertex_ref.successors {
                        // Either add the new path to the current property or create a new one
                        let new_value = length.powi(2);
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

    edge_map
}

/**
Find all properties for a given graph in parallel. 

graph               The graph to search through.
input_allowed       A set of allowed input values. Other inputs are ignored.
output_allowed      A set of allowed output values. Other outputs are ignored.
num_keep            The number of properties to keep. The best <num_keep> properties are kept.
*/
pub fn parallel_find_properties(graph: &MultistageGraph,
                                input_allowed: &FnvHashSet<u64>,
                                output_allowed: &FnvHashSet<u64>,
                                num_keep: usize) 
                                -> Vec<Property> {
    let input_len = graph.get_stage(0).unwrap().len();
    println!("Finding properties ({} input values, {} edges):", 
             input_len, graph.num_edges());

    let start = time::precise_time_s();
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    scoped::scope(|scope| {
        for t in 0..num_threads {
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                let mut progress_bar = ProgressBar::new(input_len);
                let mut result = vec![];
                let mut min_value = 1.0_f64;
                let mut num_found = 0;
                let mut paths = 0;

                // Split input values between threads and call find_properties
                for &input in graph.get_stage(0).unwrap().keys().skip(t).step_by(num_threads) {
                    let properties = find_properties(&graph, input as u64);
                    num_found += properties.len();
                    
                    for property in properties.values() {
                        if (input_allowed.len() == 0 || input_allowed.contains(&property.input)) &&
                           (output_allowed.len() == 0 || output_allowed.contains(&property.output)) {
                            paths += property.trails;
                            result.push(*property);
                        }
                    }
                    
                    // Only keep best <num_keep> properties
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

    // Collect results from all threads
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

    println!("\nFound {} properties. [{} s]", num_found, time::precise_time_s()-start);

    if result.len() > 0 {
        println!("Smallest value: {}", min_value.log2());
        println!("Largest value:  {}\n", result[0].value.log2());
        println!("Total number of trails:  {}\n", paths);
    }

    result
}