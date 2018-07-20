use crossbeam_utils::scoped;
use fnv::FnvHashSet;
use indexmap::IndexMap;
use num_cpus;
use std::f64;
use std::sync::mpsc;
use time;

use search::graph::MultistageGraph;
use property::{Property, PropertyType};
use utility::ProgressBar;

/***********************************************************************************************/

/**
Find all properties for a given graph starting with a specific input value. 

graph           The graph to search through.
property_type   The type of peroperty to find.
input           The input value to start the search from.
*/
fn find_properties(graph: &MultistageGraph, 
                   property_type: PropertyType,
                   input: u128,
                   start: usize,
                   stop: usize) 
                   -> IndexMap<u128, Property> {
    let start_property = Property::new(input, input, 1.0, 1);
    
    // The edge map maps output values to properties over a number of rounds
    // It first contains an "empty" property
    let mut edge_map = IndexMap::new();
    edge_map.insert(input, start_property);

    // Extend the edge map the desired number of rounds
    for r in start..stop {
        let mut new_edge_map = IndexMap::new();

        // Go through all edges (i.e. properties (input, output)) in the current map
        for (output, &property) in &edge_map {
            // Look up output in the single round map in order to extend one round
            if let Some(vertex_ref) = graph.get_vertex(r, *output) {
                for (&new_output, &length) in &vertex_ref.successors {
                    // Either add the new path to the current property or create a new one
                    let new_value = match property_type {
                        PropertyType::Linear => length,
                        PropertyType::Differential => length,
                    };

                    let entry = new_edge_map.entry(new_output as u128)
                                            .or_insert(Property::new(property.input,
                                                                     new_output as u128,
                                                                     0.0, 0));

                    (*entry).trails += property.trails;
                    (*entry).value += property.value * new_value;
                }
            }
        }

        edge_map = new_edge_map;
    }

    edge_map
}

/**
Find all properties for a given graph in parallel. 

graph               The graph to search through.
property_type       The type of peroperty to find.
allowed       A set of allowed input/output values. Other input/output pairs are ignored.
num_keep            The number of properties to keep. The best <num_keep> properties are kept.
*/
pub fn parallel_find_properties(graph: &MultistageGraph,
                                property_type: PropertyType,
                                allowed: &FnvHashSet<(u128, u128)>,
                                num_keep: usize) 
                                -> (Vec<Property>, f64, u128) {
    println!("Finding properties ({} input values, {} edges):", 
             graph.get_stage(0).unwrap().len(), graph.num_edges());

    let start = time::precise_time_s();
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    scoped::scope(|scope| {
        for t in 0..num_threads {
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                let mut progress_bar = ProgressBar::new(graph.get_stage(0).unwrap()
                                                             .keys().skip(t)
                                                             .step_by(num_threads).len());
                let rounds = graph.stages()-1;
                let mut result = vec![];
                let mut min_value = 1.0_f64;
                let mut num_found = 0;
                let mut paths = 0;

                // Split input values between threads and call find_properties
                for &input in graph.get_stage(0).unwrap().keys().skip(t).step_by(num_threads) {
                    let properties = find_properties(&graph, property_type, input as u128, 0, rounds);
                    num_found += properties.len();
                    
                    for property in properties.values() {
                        if allowed.is_empty() || 
                           allowed.contains(&(property.input, property.output)) {
                            paths += property.trails;
                            result.push(*property);
                        }
                    }
                    
                    // Only keep best <num_keep> properties
                    result.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap());
                    
                    if let Some(property) = result.last() {
                        min_value = min_value.min(property.value);
                    }

                    result.truncate(num_keep);

                    if t == 0 {
                        progress_bar.increment();
                    }
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

    result.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap());
    result.truncate(num_keep);

    println!("\nFound {} properties. [{} s]", num_found, time::precise_time_s()-start);

    (result, min_value, paths)
}