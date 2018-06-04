use crossbeam_utils::scoped;
use fnv::{FnvHashSet, FnvHashMap};
use indexmap::{IndexMap, IndexSet};
use num_cpus;
use std::f64;
use std::sync::mpsc;
use time;

use graph::MultistageGraph;
use property::{Property, PropertyType};
use utility::ProgressBar;

/**
Finds the number of paths between to stages of a graph. 

graph       Graph to analyse.
start       The first stage.
stop        The last stage.
*/
fn num_paths(graph: &MultistageGraph, 
             start: usize, 
             stop: usize) 
             -> usize {
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    scoped::scope(|scope| {
        for t in 0..num_threads {
            let result_tx = result_tx.clone();
            
            scope.spawn(move || {
                let mut progress_bar = ProgressBar::new(graph.get_stage(start).unwrap()
                                                             .keys().skip(t)
                                                             .step_by(num_threads).len());
                let mut num_paths = 0;

                for input in graph.get_stage(start).unwrap().keys().skip(t).step_by(num_threads) {
                    // The edge map maps output values to properties over a number of rounds
                    // It first contains an "empty" property
                    let mut edge_map = IndexSet::new();
                    edge_map.insert(input);

                    // Extend the edge map the desired number of rounds
                    for r in start..stop {
                        let mut new_edge_map = IndexSet::new();

                        // Go through all edges (i.e. properties (input, output)) in the current map
                        for &output in &edge_map {
                            // Look up output in the single round map in order to extend one round
                            match graph.get_vertex(r, *output) {
                                Some(vertex_ref) => {
                                    for new_output in vertex_ref.successors.keys() {
                                        new_edge_map.insert(new_output);
                                    }
                                },
                                None => {}
                            }
                        }

                        edge_map = new_edge_map;
                    }

                    num_paths += edge_map.len();

                    if t == 0 {
                        progress_bar.increment();
                    }
                }
                
                result_tx.send(num_paths).expect("Thread could not send result");
            });
        }
    });

    // Collect results from all threads
    let mut num_paths = 0;

    for _ in 0..num_threads {
        let mut thread_result = result_rx.recv().expect("Main could not receive result");
        num_paths += thread_result;
    }

    num_paths
}

/**
Find properties over a part of a graph. The properties are sorted while taking into accout the
best possible transitions in the two adjacent stages. 

graph               Graph to search.
property_type       Type of property to search for.
start               The first stage.
stop                The last stage.
num_keep            Number of properties to return.
*/
pub fn find_middle_properties(graph: &MultistageGraph, 
                              property_type: PropertyType,
                              start: usize, 
                              stop: usize,
                              num_keep: usize)
                              -> Vec<Property> {
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();
    
    // Calculate best transitions for each vertex in the stage before start and after stop
    let mut best_forward = FnvHashMap::default();
    let mut best_backward = FnvHashMap::default();

    for (&label, vertex) in graph.get_stage(start).unwrap() {
        let mut max_value = 0.0_f64;
        
        for &predecessor_val in vertex.predecessors.values() {
            max_value = max_value.max(predecessor_val);
        }

        best_forward.insert(label, max_value);
    }

    for (&label, vertex) in graph.get_stage(stop).unwrap() {
        let mut max_value = 0.0_f64;
        
        for &successor_val in vertex.successors.values() {
            max_value = max_value.max(successor_val);
        }

        best_backward.insert(label, max_value);
    }

    // Start scoped worker threads
    scoped::scope(|scope| {
        for t in 0..num_threads {
            let result_tx = result_tx.clone();
            let best_forward = best_forward.clone();
            let best_backward = best_backward.clone();

            scope.spawn(move || {
                let mut progress_bar = ProgressBar::new(graph.get_stage(start).unwrap()
                                                             .keys().skip(t)
                                                             .step_by(num_threads).len());
                let mut result = vec![];

                // Split input values between threads and call find_properties
                for &input in graph.get_stage(start).unwrap().keys().skip(t).step_by(num_threads) {
                    let properties = find_properties(&graph, property_type, input as u128, start, stop);
                    
                    for property in properties.values() {
                        result.push(*property);
                    }
                    
                    // Only keep best <num_keep> properties modified with outer transitions
                    result.sort_by(|&x, &y| {
                        let x_value = x.value * best_forward.get(&(x.input)).unwrap() 
                                              * best_backward.get(&(x.output)).unwrap();
                        let y_value = y.value * best_forward.get(&(y.input)).unwrap() 
                                              * best_backward.get(&(y.output)).unwrap();
                        y_value.partial_cmp(&x_value).unwrap()
                    });
                    result.truncate(num_keep);

                    if t == 0 {
                        progress_bar.increment();
                    }
                }

                result_tx.send(result).expect("Thread could not send result");
            });
        }
    });

    // Collect results from all threads
    let mut result = vec![];

    for _ in 0..num_threads {
        let mut thread_result = result_rx.recv().expect("Main could not receive result");
        
        result.append(&mut thread_result);
    }

    result.sort_by(|x, y| {
        let x_value = x.value * best_forward.get(&(x.input)).unwrap() 
                              * best_backward.get(&(x.output)).unwrap();
        let y_value = y.value * best_forward.get(&(y.input)).unwrap() 
                              * best_backward.get(&(y.output)).unwrap();
        y_value.partial_cmp(&x_value).unwrap()
    });
    result.truncate(num_keep);

    result
}

/**
Calculates the restriction of a graph, in the sense that the stages in the given range
are converted to one stage, and only the best edges in this stage are kept. 

graph           The base graph.
property_type   Type of property described by the graph.
percentage      The percent of best edges to keept in the restricted stage.
start           The layer to restrict from.
stop            The layer to restrict to. 
*/
pub fn restricted_graph(graph: &MultistageGraph,
                        property_type: PropertyType,
                        percentage: f64,
                        start: usize,
                        stop: usize) 
                        -> MultistageGraph {
    let timer = time::precise_time_s();
    if start-stop < 2 {
        return graph.clone();
    }

    // Find the number of edges to keep, then find those edges
    let num_paths = num_paths(&graph, start+1, stop-1);
    let num_keep = (num_paths as f64 * percentage).ceil() as usize;
    let middle_edges = find_middle_properties(&graph, property_type, start+1, stop-1, num_keep);

    // Create restricted graph
    let stages = graph.stages();
    let mut new_graph = MultistageGraph::new(stages - (stop-start+1) + 4);

    for (i, stage) in graph.vertices.iter().take(start+2).enumerate() {
        new_graph.vertices[i] = stage.clone();
    }

    for (i, stage) in graph.vertices.iter().skip(stop-1).take(stages-stop+1).enumerate() {
        new_graph.vertices[i+start+2] = stage.clone();
    }

    for vertex in new_graph.vertices[start+1].values_mut() {
        vertex.successors.clear();
    }

    for vertex in new_graph.vertices[start+2].values_mut() {
        vertex.predecessors.clear();
    }

    for p in middle_edges.iter() {
        new_graph.add_edge(start+1, p.input, p.output, p.value);
    }
    
    new_graph.prune(0, stages - (stop-start+1) + 4);
    println!("Restricted graph has {} vertices and {} edges. [{} s]", 
        new_graph.num_vertices(), new_graph.num_edges(),
        time::precise_time_s() - timer);

    new_graph
}


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
            match graph.get_vertex(r, *output) {
                Some(vertex_ref) => {
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
property_type       The type of peroperty to find.
input_allowed       A set of allowed input values. Other inputs are ignored.
output_allowed      A set of allowed output values. Other outputs are ignored.
num_keep            The number of properties to keep. The best <num_keep> properties are kept.
*/
pub fn parallel_find_properties(graph: &MultistageGraph,
                                property_type: PropertyType,
                                input_allowed: &FnvHashSet<u128>,
                                output_allowed: &FnvHashSet<u128>,
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