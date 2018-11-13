//! Functions for generating a graph representing a set of properties over multiple 
//! rounds of a cipher.

use crossbeam_utils;
use fnv::{FnvHashSet, FnvHashMap};
use indexmap::IndexMap;
use itertools::interleave;
use num_cpus;
use std::cmp;
use std::sync::mpsc;
use time;

use crate::cipher::*;
use crate::property::{PropertyType, PropertyFilter, MaskMap};
use crate::search::graph::MultistageGraph;
use crate::search::prince_extra::prince_pruning_new;
use crate::search::single_round::SortedProperties;
use crate::utility::{ProgressBar, compress};

// The number of threads used for parallel calls is fixed
lazy_static! {
    static ref THREADS: usize = num_cpus::get();
}

/// Finds the set of all vertices that have both an input and an output.
fn get_vertex_set(properties: &SortedProperties,
                  previous: Option<&FnvHashSet<u128>>,
                  level: usize)
                  -> FnvHashSet<u128> {
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    crossbeam_utils::thread::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                // Split the S-box patterns equally across threads
                // Note that this does not equally split the number of properties across threads,
                // but hopefully it is close enough
                let tmp: Vec<_> = thread_properties.patterns().iter()
                                                              .cloned()
                                                              .skip(t)
                                                              .step_by(*THREADS)
                                                              .collect();
                thread_properties.set_patterns(&tmp);
                
                // First, collect all input values
                let mut input_set = FnvHashSet::default();
                
                thread_properties.set_type_input();
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in &thread_properties {
                    if let Some(previous) = previous {
                        let old = compress(property.input, level-1);

                        if !previous.contains(&old) {
                            if t == 0 {
                                progress_bar.increment();
                            }

                            continue
                        }
                    }

                    let new = compress(property.input, level);
                    input_set.insert(new);

                    if t == 0 {
                        progress_bar.increment();
                    }
                }
                
                result_tx.send(input_set).expect("Thread could not send result");
            });
        }
    });
    
    // Collect input sets from all threads
    let mut input_set: FnvHashSet<u128> = FnvHashSet::default();
    
    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        
        // Get union of different thread sets
        input_set.extend(thread_result.iter());
    }

    // Start scoped worker threads
    crossbeam_utils::thread::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();
            let input_set = &input_set;

            scope.spawn(move || {
                // Split the S-box patterns equally across threads
                // Note that this does not equally split the number of properties across threads,
                // but hopefully it is close enough
                let tmp: Vec<_> = thread_properties.patterns().iter()
                                                              .cloned()
                                                              .skip(t)
                                                              .step_by(*THREADS)
                                                              .collect();
                thread_properties.set_patterns(&tmp);
                
                // Second, collect all output values that are also in the input set
                let mut union_set = FnvHashSet::default();
                
                thread_properties.set_type_output();
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in &thread_properties {
                    let new = compress(property.output, level);
                    if input_set.contains(&new) {
                        union_set.insert(new);
                    }

                    if t == 0 {
                        progress_bar.increment();
                    }
                }
                
                result_tx.send(union_set).expect("Thread could not send result");
            });
        }
    });

    // Last, collect union sets from all threads
    let mut vertex_set: FnvHashSet<u128> = FnvHashSet::default();
    
    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        vertex_set.extend(thread_result.iter());
    }

    vertex_set
}

/// Generates a graph according to a set of properties and a stage pattern.
fn gen_with_stages(properties: &SortedProperties,
                   rounds: usize,
                   stages: u64,
                   level: usize,
                   vertex_set: Option<&FnvHashSet<u128>>,
                   previous_graph: Option<&MultistageGraph>)
                   -> MultistageGraph {
    // Block size of the compression
    let block = 1 << (3-level);
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    crossbeam_utils::thread::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                // For SPN ciphers, we can exploit the structure when the compressiond is 
                // sufficiently coarse and not generate all properties explicitly 
                let max_sbox_size = cmp::max(thread_properties.cipher().sbox(0).size_in(),
                                             thread_properties.cipher().sbox(0).size_out());
                if block >= max_sbox_size  && 
                   thread_properties.cipher().structure() == CipherStructure::Spn {
                    thread_properties.set_type_output();
                } else {
                    thread_properties.set_type_all();
                }

                // Split the S-box patterns equally across threads
                // Note that this does not equally split the number of properties across threads,
                // but hopefully it is close enough
                let tmp: Vec<_> = thread_properties.patterns().iter()
                                                              .cloned()
                                                              .skip(t)
                                                              .step_by(*THREADS)
                                                              .collect();
                thread_properties.set_patterns(&tmp);

                // Generate graph
                let mut graph = MultistageGraph::new(rounds);
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in &thread_properties {
                    let mut previous_mask = (1 << rounds) - 1;

                    // Filter based on edges in the previous graph
                    if let Some(previous_graph) = previous_graph {
                        let old_input = compress(property.input, level-1);
                        let old_output = compress(property.output, level-1);

                        previous_mask = previous_graph.get_edge(old_input, old_output);

                        if previous_mask == 0 {
                            if t == 0 {
                                progress_bar.increment();
                            }

                            continue;
                        }
                    }
                    
                    let input = compress(property.input, level);
                    let output = compress(property.output, level);
                    let length = if level != 3 {
                        0.0
                    } else {
                        property.value
                    };

                    // Filter based on the vertex set
                    match vertex_set {
                        Some(vertex_set) => {
                            // Construct stage pattern to match vertex set constraints
                            let input_mask = vertex_set.contains(&input);
                            let input_mask = (!1 * (input_mask as u64)) ^ 1;
                            let output_mask = vertex_set.contains(&output);
                            let output_mask = (((1 << (rounds-1)) - 1) * (output_mask as u64)) ^ (1 << (rounds-1));
                            let mask = input_mask & output_mask;

                            graph.add_edges(input, output, stages & mask & previous_mask, length);
                        },
                        None => graph.add_edges(input, output, stages & previous_mask, length)
                    }

                    if t == 0 {
                        progress_bar.increment();
                    }
                }

                result_tx.send(graph).expect("Thread could not send result");
            });
        }
    });

    let mut graph = MultistageGraph::new(rounds);

    // Find union of thread graphs
    for _ in 0..*THREADS {
        let mut thread_result = result_rx.recv().expect("Main could not receive result");
        graph.union(&mut thread_result);
    }

    graph
}

/// Adds edges in the first and last stage of the graph. The edges are only added if they connect 
/// to an existing vertex. 
fn extend(graph: &mut MultistageGraph,
          properties: &SortedProperties,
          rounds: usize,
          level: usize,
          input_allowed: Option<&FnvHashSet<u128>>,
          output_allowed: Option<&FnvHashSet<u128>>) {
    // Block size of the compression
    let block = 1 << (3-level);
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    crossbeam_utils::thread::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();
            let graph = &(*graph);

            scope.spawn(move || {
                // For SPN ciphers, we can exploit the structure when the compressiond is 
                // sufficiently coarse and not generate all properties explicitly 
                let max_sbox_size = cmp::max(thread_properties.cipher().sbox(0).size_in(),
                                             thread_properties.cipher().sbox(0).size_out());
                if block >= max_sbox_size  && 
                   thread_properties.cipher().structure() == CipherStructure::Spn {
                    thread_properties.set_type_output();
                } else {
                    thread_properties.set_type_all();
                }

                // Split the S-box patterns equally across threads
                // Note that this does not equally split the number of properties across threads,
                // but hopefully it is close enough
                let tmp: Vec<_> = thread_properties.patterns().iter()
                                                              .cloned()
                                                              .skip(t)
                                                              .step_by(*THREADS)
                                                              .collect();
                thread_properties.set_patterns(&tmp);

                // Collect all edges that have corresponding output/input vertices in the 
                // second/second to last stage
                let mut edges = IndexMap::new();
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in &thread_properties {
                    let input = compress(property.input, level);
                    let output = compress(property.output, level);
                    let mut stages = 0;

                    // Generate appropriate stage pattern
                    if let Some(input_allowed) = input_allowed {
                        if input_allowed.contains(&input) {
                            stages ^= graph.has_vertex_outgoing(output, 1) as u64;
                        }
                    } else {
                        stages ^= graph.has_vertex_outgoing(output, 1) as u64;
                    }

                    if let Some(output_allowed) = output_allowed {
                        if output_allowed.contains(&output) {
                            stages ^= (graph.has_vertex_incoming(input, rounds-1) as u64) << (rounds-1);
                        }
                    } else {
                        stages ^= (graph.has_vertex_incoming(input, rounds-1) as u64) << (rounds-1);
                    }                    

                    if stages != 0 {
                        let length = if level != 3 {
                            0.0
                        } else {
                            property.value
                        };

                        edges.insert((input, output), (stages, length));
                    }

                    if t == 0 {
                        progress_bar.increment();
                    }
                }
                
                result_tx.send(edges).expect("Thread could not send result");
            });
        }
    });

    // Add edges from each thread
    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        
        for ((tail, head), (stages, length)) in thread_result {
            graph.add_edges(tail, head, stages, length);
        }
    }
}

/// Adds good edges from to/from each vertex in the second/second to last layer.
fn anchor_ends(cipher: &dyn Cipher,
               property_type: PropertyType,
               graph: &mut MultistageGraph,
               anchors: Option<usize>,
               input_allowed: Option<&FnvHashSet<u128>>,
               output_allowed: Option<&FnvHashSet<u128>>) {
    let (result_tx, result_rx) = mpsc::channel();
    let mask_map = MaskMap::new(cipher, property_type);
    let rounds = graph.stages();

    // Collect vertices in the second/second to last layer.
    let start_labels: Vec<_> = graph.get_vertices_outgoing(1).iter().map(|&x| (x, 0)).collect();
    let end_labels: Vec<_> = graph.get_vertices_incoming(rounds-1).iter().map(|&x| (x, rounds-1)).collect();

    // Determine number of anchors to add
    let num_labels = start_labels.len() + end_labels.len();
    let max_anchors = match anchors {
        Some(x) => 1 << x,
        None    => 1 << 17
    };
    let limit = 0.max(max_anchors - (graph.num_vertices(0) + graph.num_vertices(rounds)) as i64);
    let num_anchor = (limit as f64 / num_labels as f64).ceil() as usize;
    println!("Adding {:?} anchors.", limit);
    
    // Start scoped worker threads
    crossbeam_utils::thread::scope(|scope| {
        for t in 0..*THREADS {
            let result_tx = result_tx.clone();
            let mask_map = mask_map.clone();
            let start_labels = start_labels.clone();
            let end_labels = end_labels.clone();

            scope.spawn(move || {
                let mut progress_bar = ProgressBar::new(start_labels.iter().skip(t)
                                                                    .step_by(*THREADS).len() + 
                                                        end_labels.iter().skip(t)
                                                                  .step_by(*THREADS).len());
                let mut edges = IndexMap::new();
                

                for (label, stage) in interleave(start_labels, end_labels).take(limit as usize)
                                        .skip(t).step_by(*THREADS) {
                    if stage == 0 {
                        // Invert input to get output
                        let output = cipher.linear_layer_inv(label as u128);
                        let inputs = mask_map.get_best_inputs(cipher, output, num_anchor);

                        for (input, value) in inputs {
                            if let Some(input_allowed) = input_allowed {
                                if input_allowed.contains(&input) {
                                    edges.insert((input, label, stage), value);
                                }
                            } else {
                                edges.insert((input, label, stage), value);
                            }
                        }
                    } else {
                        let input = label as u128;
                        let outputs = mask_map.get_best_outputs(cipher, input, num_anchor);

                        for (output, value) in outputs {
                            let output = cipher.linear_layer(output);

                            if let Some(output_allowed) = output_allowed {
                                if output_allowed.contains(&output) {
                                    edges.insert((label, output, stage), value);
                                }
                            } else {
                                edges.insert((label, output, stage), value);
                            }
                        }
                    }
                    
                    if t == 0 {
                        progress_bar.increment();
                    }
                }

                result_tx.send(edges).expect("Thread could not send result");
            });
        }
    });

    // Add edges from each thread
    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        
        for ((tail, head, stage), length) in thread_result {
            graph.add_edges(tail, head, 1 << stage, length);
        }
    }
}

/// Patches the graph, i.e. adds any missing edges between already existing vertices. 
fn patch(cipher: &dyn Cipher,
         property_type: PropertyType,
         graph: &mut MultistageGraph) 
         -> usize {
    // TODO: Find a way to handle this case
    if cipher.sbox(0).size_in() != cipher.sbox(0).size_out() {
        println!("Aborting patching due to S-box truncating/expanding S-box");
        return 0;
    }

    // Get LATs/DDTs
    let mut tables = Vec::new();

    for i in 0..cipher.num_sboxes() {
        match property_type {
            PropertyType::Linear       => tables.push(cipher.sbox(i).lat().clone()),
            PropertyType::Differential => tables.push(cipher.sbox(i).ddt().clone()),
        }
    }
    
    // Set mask and level to match S-box size
    let mask_in = (1 << cipher.sbox(0).size_in()) - 1;
    let mask_out = (1 << cipher.sbox(0).size_out()) - 1;
    // NOTE: This wouldn't work for truncating/expanding S-boxes
    let level = 3 - (cipher.sbox(0).size_in() as f32).log2()  as usize;
    
    let num_vertices = (0..=graph.stages()).fold(0, |num, x| num + graph.num_vertices(x));
    let mut progress_bar = ProgressBar::new(num_vertices);
    let mut num_added = 0;
    
    // Initialise maps for first stage
    let stages = graph.stages();
    let mut input_map = FnvHashMap::default();
    let mut input_map_tmp = FnvHashMap::default();

    let vertices = graph.get_vertices_outgoing(0);

    for &input in &vertices{
        let input_c = compress(input, level);
        let entry = input_map.entry(input_c).or_insert_with(Vec::new);
        entry.push(input);
        progress_bar.increment();
    }    

    for s in 0..stages {
        let vertices = if s+1 == graph.stages() {
            graph.get_vertices_incoming(s+1)
        } else {
            graph.get_vertices_outgoing(s+1)
        };

        for &output in &vertices {
            // Build map for next stage
            let input_c = compress(output, level);
            let entry = input_map_tmp.entry(input_c).or_insert_with(Vec::new);
            entry.push(output);

            // Check if the output has non-zero correlation with any input
            let out_inv = cipher.linear_layer_inv(output);

            if let Some(inputs) = input_map.get(&compress(out_inv, level)) {
                for &input in inputs {
                    if ((graph.get_edge(input, output) >> s) & 0x1) == 1 {
                        continue;
                    }

                    // Calculate length
                    let mut value = 1.0;

                    for (i, table) in tables.iter().enumerate() {
                        let a = (input  >> (i * cipher.sbox(i).size_in())) & mask_in;
                        let b = (out_inv >> (i * cipher.sbox(i).size_out())) & mask_out;

                        let v = table[a as usize][b as usize];

                        if v == 0 {
                            value = 0.0;
                            break;
                        }

                        match property_type {
                            PropertyType::Linear => {
                                value *= (2.0 * v as f64 / tables[i][0][0] as f64 - 1.0).powi(2);
                            },
                            PropertyType::Differential => {
                                value *= v as f64 / tables[i][0][0] as f64;  
                            }
                        }
                    }

                    if value != 0.0 {
                        graph.add_edges(input, output, 1 << s, value);
                        num_added += 1;
                    }
                }
            }

            progress_bar.increment();
        }

        input_map = input_map_tmp.clone();
        input_map_tmp.clear();
    }

    num_added
}

/// Creates a graph that represents a set of properties over a number of rounds for a 
/// given cipher. 

/// # Parameters
/// * `cipher`: The cipher which the graph represents.
/// * `property_type`: The type of the property the graph represents.
/// * `rounds`: The number of cipher rounds. For Prince-like ciphers, this is the number of forward rounds.
/// * `patterns`: Tje number of patterns to generate. 
/// * `anchors`: The number of anchors added in the input and output stages.
/// * `allowed`: A set of allowed input-output pairs. Properties not matching these are filtered. 
pub fn generate_graph(cipher: &dyn Cipher, 
                      property_type: PropertyType,
                      rounds: usize, 
                      patterns: usize,
                      anchors: Option<usize>,
                      allowed: &FnvHashSet<(u128, u128)>) 
                      -> MultistageGraph {
    // Generate the set of properties to consider
    let mut properties = SortedProperties::new(
        cipher, patterns, property_type, PropertyFilter::All);
    let mut graph = MultistageGraph::new(rounds);

    properties.set_type_all();
    let num_prop = properties.len();
    properties.set_type_input();
    let num_input = properties.len();
    properties.set_type_output();
    let num_output = properties.len();

    // Change allowed inputs/outputs for Prince-like ciphers
    let mut input_allowed: FnvHashSet<_>  = allowed.iter().map(|(a,_)| *a).collect();
    let mut output_allowed: FnvHashSet<_> = allowed.iter().map(|(_,b)| *b).collect();
    if cipher.structure() == CipherStructure::Prince {
        input_allowed = input_allowed.union(&output_allowed).cloned().collect();
        output_allowed = FnvHashSet::default();
    }

    let input_allowed = if input_allowed.is_empty() {
        None
    } else {
        Some(&input_allowed)
    };

    let output_allowed = if output_allowed.is_empty() {
        None
    } else {
        Some(&output_allowed)
    };

    // Rounds 1 to 4 are treated specially
    if rounds == 1 || rounds == 3 {
        let start = time::precise_time_s();
        println!("Generating graph: {} properties ({} input, {} output).", 
            num_prop, num_input, num_output);
        graph = gen_with_stages(&properties, 1, 0b1, 3, None, None);
        println!("Graph has {} edges [{} s]\n", 
            graph.num_edges(), time::precise_time_s()-start);
    } else {
        if rounds == 2 {
            let start = time::precise_time_s();
            println!("Generating graph.");
            graph = gen_with_stages(&properties, 2, 0b11, 3, None, None);
            println!("Graph has {} edges [{} s]\n", 
                graph.num_edges(), time::precise_time_s()-start);
        }

        if rounds == 4 {
            println!("Finding vertex set: {} properties ({} input, {} output).", 
                num_prop, num_input, num_output);
            let start = time::precise_time_s();
            let vertex_set = get_vertex_set(&properties, None, 3);
            println!("{} vertices in set [{} s]\n", 
                    vertex_set.len(), time::precise_time_s()-start);

            let start = time::precise_time_s();
            println!("Generating graph.");
            graph = gen_with_stages(&properties, 2, 0b11, 3, Some(&vertex_set), None);
            println!("Graph has {} edges [{} s]\n", 
                graph.num_edges(), time::precise_time_s()-start);
        }

        if rounds > 4 {
            // First generate the inner rounds
            let rounds = rounds - 2;
            graph = MultistageGraph::new(rounds);
            let mut vertex_set = FnvHashSet::default();

            // Iteratively generate graphs with finer compression functions
            for level in 1..4 {
                // Get total number of properties considered
                properties.set_type_all();
                let num_prop = properties.len();
                properties.set_type_input();
                let num_input = properties.len();
                properties.set_type_output();
                let num_output = properties.len();

                println!("#### Level {}: {} properties ({} input, {} output). ####\n", 
                    level, num_prop, num_input, num_output);

                // We take the previous graph into account when generating the new one
                let old_graph = if level != 1 {
                    Some(&graph)
                } else {
                    None
                };

                let start = time::precise_time_s();
                println!("Finding vertex set.");
                // Take the old vertex set into account if it exists
                vertex_set = if level == 1 {
                    get_vertex_set(&properties, None, level)
                } else {
                    get_vertex_set(&properties, Some(&vertex_set), level)
                };
                println!("{} vertices in set [{} s]\n", 
                        vertex_set.len(), time::precise_time_s()-start);

                // All but the first and last stage
                let stages = ((1 << (rounds-1)) - 1) ^ 1;
                
                let start = time::precise_time_s();
                println!("Generating graph.");
                graph = gen_with_stages(&properties, rounds, stages, level, Some(&vertex_set), old_graph);
                println!("Graph has {} edges [{} s]", 
                    graph.num_edges(), time::precise_time_s()-start);

                let start = time::precise_time_s();
                graph.prune(1, rounds-1);
                println!("Pruned graph has {} edges [{} s]\n", 
                        graph.num_edges(), time::precise_time_s()-start);

                let start = time::precise_time_s();
                println!("Extending graph.");
                extend(&mut graph, &properties, rounds, level, None, None);
                println!("Extended graph has {} edges [{} s]", 
                        graph.num_edges(), time::precise_time_s()-start);

                let start = time::precise_time_s();
                if cipher.structure() == CipherStructure::Prince {
                    prince_pruning_new(cipher, &mut graph);
                } else {
                    graph.prune(0, rounds);
                }
                println!("Pruned graph has {} edges [{} s]", 
                        graph.num_edges(), time::precise_time_s()-start);

                // Update filters and remove dead patterns if we havn't generated the final graph
                if level != 3 {
                    let start = time::precise_time_s();
                    println!("\nRemoving dead patterns.");
                    let patterns_before = properties.len_patterns();
                    properties.remove_dead_patterns(&graph, level);
                    let patterns_after = properties.len_patterns();
                    println!("Removed {} dead patterns [{} s]", 
                        patterns_before - patterns_after, time::precise_time_s()-start);
                }

                println!();
            }
        }
    }

    println!("#### Final steps: {} properties ({} input, {} output). ####\n", 
        num_prop, num_input, num_output);

    // Extending
    if rounds > 2 {
        graph.insert_stage_before();
        graph.insert_stage_after();

        let start = time::precise_time_s();
        println!("Extending final graph.");
        extend(&mut graph, &properties, rounds, 3, input_allowed, output_allowed);
        println!("Extended graph has {} edges [{} s]\n", 
                 graph.num_edges(), time::precise_time_s()-start);
    }

    // Anchoring
    if rounds > 1 && cipher.structure() != CipherStructure::Feistel {
        let start = time::precise_time_s();
        print!("Anchoring final graph: ");
        anchor_ends(cipher, property_type, &mut graph, anchors, input_allowed, output_allowed);
        println!("Anchored graph has {} edges [{} s]", 
                 graph.num_edges(), time::precise_time_s()-start);
    }

    let start = time::precise_time_s();
    if cipher.structure() == CipherStructure::Prince {
        prince_pruning_new(cipher, &mut graph);
    } else {
        graph.prune(0, rounds);
    }
    println!("Pruned graph has {} edges [{} s]\n", 
            graph.num_edges(), time::precise_time_s()-start);

    // Patch graph
    if cipher.structure() != CipherStructure::Feistel {
        let start = time::precise_time_s();
        println!("Patching graph.");
        let added = patch(cipher, property_type, &mut graph);
        println!("Added {} edges [{} s]\n", 
            added, time::precise_time_s()-start);
    }
    
    println!("Final graph has {} edges\n", graph.num_edges());

    graph
}