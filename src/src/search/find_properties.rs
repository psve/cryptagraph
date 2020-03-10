//! Functions for searching for properties once a graph has been generated.

use crossbeam_utils;
use fnv::FnvHashSet;
use indexmap::IndexMap;
use num_cpus;
use std::f64;
use std::sync::mpsc;

use std::time::Instant;

use crate::cipher::{Cipher, CipherStructure};
use crate::search::graph::MultistageGraph;
use crate::property::{Property, PropertyType};
use crate::utility::ProgressBar;

// The number of threads used for parallel calls is fixed
lazy_static! {
    static ref THREADS: usize = num_cpus::get();
}

/// Find all properties for a given graph starting with a specific input value.
fn find_properties(cipher: &dyn Cipher,
                   graph: &MultistageGraph,
                   property_type: PropertyType,
                   input: u128)
                   -> IndexMap<u128, Property> {
    let start_property = Property::new(input, input, 1.0, 1);

    // The edge map maps output values to properties over a number of rounds
    // It first contains an "empty" property
    let mut edge_map = IndexMap::new();
    edge_map.insert(input, start_property);

    // Extend the edge map the desired number of rounds
    for r in 0..graph.stages() {
        let mut new_edge_map = IndexMap::new();

        // Go through all edges (i.e. properties (input, output)) in the current map
        for (output, &property) in &edge_map {
            // Look up output in the single round map in order to extend one round
            if let Some(inputs) = graph.forward_edges().get(output) {
                for (&new_output, &(stages, length)) in inputs.iter() {
                    if ((stages >> r) & 0x1) != 1 {
                        continue;
                    }

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

    // In case of Prince type cipher, go back through the graph as well
    if cipher.structure() == CipherStructure::Prince {
        // First apply reflection layer
        edge_map = edge_map.iter().map(|(&k, &v)| (cipher.reflection_layer(k), v)).collect();

        // Extend the edge map the desired number of rounds backwards
        for r in 0..graph.stages() {
            let mut new_edge_map = IndexMap::new();

            // Go through all backward edges (i.e. properties (input, output)) in the current map
            for (output, &property) in &edge_map {
                // Look up output in the single round map in order to extend one round
                if let Some(inputs) = graph.backward_edges().get(output) {
                    for (&new_output, &(stages, length)) in inputs.iter() {
                        if ((stages >> (graph.stages()-1-r)) & 0x1) != 1 {
                            continue;
                        }

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
    }

    edge_map
}

/// Find all properties for a given graph in a parallelised way.
///
/// # Parameters
/// * `cipher`: The cipher we are analysing.
/// * `graph`: A graph generated with `generate_graph`.
/// * `property_type': The type of property the graph represents.
/// * `allowed`: A set of allowed input-output pairs. Properties not matching these are filtered.
/// * `num_keep`: Only the best `num_keep` properties are returned.
pub fn parallel_find_properties(cipher: &dyn Cipher,
                                graph: &MultistageGraph,
                                property_type: PropertyType,
                                allowed: &FnvHashSet<(u128, u128)>,
                                num_keep: usize)
                                -> (Vec<Property>, f64, u128) {
    println!("Finding properties ({} input values, {} edges):",
             graph.num_vertices(0), graph.num_edges());

    let start = Instant::now();
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    crossbeam_utils::thread::scope(|scope| {
        for t in 0..*THREADS {
            let result_tx = result_tx.clone();

            scope.spawn(move |_| {
                let mut progress_bar = ProgressBar::new((0..graph.num_vertices(0))
                                                        .skip(t).step_by(*THREADS).len());
                let mut result = vec![];
                let mut min_value = 1.0_f64;
                let mut num_found = 0;
                let mut paths = 0;

                // Split input values between threads and call find_properties
                for &input in graph.get_vertices_outgoing(0).iter().skip(t).step_by(*THREADS) {
                    let properties = find_properties(cipher, &graph, property_type, input as u128);
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
    }).expect("Threads failed to join.");

    // Collect results from all threads
    let mut paths = 0;
    let mut num_found = 0;
    let mut min_value = 1.0_f64;
    let mut result = vec![];

    for _ in 0..*THREADS {
        let mut thread_result = result_rx.recv().expect("Main could not receive result");

        result.append(&mut thread_result.0);
        min_value = min_value.min(thread_result.1);
        num_found += thread_result.2;
        paths += thread_result.3;
    }

    result.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap());
    result.truncate(num_keep);

    println!("\nFound {} properties. [{:?} s]", num_found, start.elapsed());

    (result, min_value, paths)
}
