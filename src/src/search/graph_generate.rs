use crossbeam_utils::scoped;
use fnv::{FnvHashSet, FnvHashMap};
use indexmap::{IndexMap, IndexSet};
use itertools::interleave;
use num_cpus;
use smallvec::SmallVec;
use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use time;

use cipher::*;
use search::graph::MultistageGraph;
use search::prince_extra::{prince_pruning, prince_modification};
use property::{PropertyType, PropertyFilter, MaskMap};
use search::single_round::SortedProperties;
use utility::{ProgressBar, compress};

// The number of threads used for parallel calls is fixed
lazy_static! {
    static ref THREADS: usize = num_cpus::get();
}

/**
Generates a graph with only a single round.

properties      Properties representing the edges of the graph.
*/
fn one_round(properties: &mut SortedProperties) 
             -> MultistageGraph {
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    scoped::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                // Split the S-box patterns equally across threads
                // Note that this does not equally split the number of properties across threads,
                // but hopefully it is close enough
                thread_properties.set_type_all();
                let tmp = thread_properties.sbox_patterns.iter()
                                                         .cloned()
                                                         .skip(t)
                                                         .step_by(*THREADS)
                                                         .collect();
                thread_properties.sbox_patterns = tmp;

                // Collect all possible edges in the graph
                let mut edges = IndexMap::new();
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in thread_properties.into_iter() {
                    let input = property.input;
                    let output = property.output;
                    let length = property.value;
                    edges.insert((0, input, output), length);

                    if t == 0 {
                        progress_bar.increment();
                    }
                }
                
                result_tx.send(edges).expect("Thread could not send result");
            });
        }
    });

    let mut graph = MultistageGraph::new(2);

    // Add edges from each thread
    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        graph.add_edges_and_vertices(&thread_result);
    }

    graph
}

/**
Generates a graph with only a single stage, i.e. only vertices are added.

properties      Properties representing the vertices of the graph.
*/
fn two_rounds(properties: &mut SortedProperties) 
              -> MultistageGraph {
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    scoped::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                // Split the S-box patterns equally across threads
                // Note that this does not equally split the number of properties across threads,
                // but hopefully it is close enough
                let tmp = thread_properties.sbox_patterns.iter()
                                                         .cloned()
                                                         .skip(t)
                                                         .step_by(*THREADS)
                                                         .collect();
                thread_properties.sbox_patterns = tmp;

                // Collect all vertices corresponding to property inputs and outputs
                let mut vertices = IndexSet::new();
                {
                thread_properties.set_type_input();
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in thread_properties.into_iter() {
                    let input = property.input;
                    vertices.insert(input);

                    if t == 0 {
                        progress_bar.increment();
                    }
                }   
                }

                {
                thread_properties.set_type_output();
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in thread_properties.into_iter() {
                    let output = property.output;
                    vertices.insert(output);

                    if t == 0 {
                        progress_bar.increment();
                    }
                }   
                }
                
                result_tx.send(vertices).expect("Thread could not send result");
            });
        }
    });

    let mut graph = MultistageGraph::new(1);

    // Add vertices from each thread
    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        
        for vertex in thread_result {
            graph.add_vertex(0, vertex)
        }
    }

    graph
}

/**
Generates a graph only with vertices. The vertices are generated from the input properties in such
a way that a vertex only exists in a round if there exists a property with that vertex as input as 
well as a (maybe different) property with the vertex as output. Additionally, the values of the
vertices are filtered, and input/output vertices are not added. 

properties      The properties considered when generating vertices.
rounds          The number of rounds, i.e. one less than the number of stages in the graph.
filters         Filters used to restrict the vertices in each round.
level           Compression level to use for vertex values. 
*/
fn get_middle_vertices (properties: &SortedProperties, 
                        rounds: usize, 
                        filters: &[FnvHashSet<u128>],
                        level: usize) 
                        -> MultistageGraph {
    let barrier = Arc::new(Barrier::new(*THREADS));
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    scoped::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let barrier = barrier.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                // Split the S-box patterns equally across threads
                // Note that this does not equally split the number of properties across threads,
                // but hopefully it is close enough
                let tmp = thread_properties.sbox_patterns.iter()
                                                         .cloned()
                                                         .skip(t)
                                                         .step_by(*THREADS)
                                                         .collect();
                thread_properties.sbox_patterns = tmp;
                
                // First, collect all input values allowed by the filters
                // Store them in a hash set for each round
                let mut input_sets: SmallVec<[_; 256]> = smallvec![FnvHashSet::default(); rounds-1];
                {
                thread_properties.set_type_input();
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in thread_properties.into_iter() {
                    // Get old value for filter look up
                    let old = compress(property.input, level - 1);

                    // Ignore input and output stages
                    for (r, f) in filters.iter().skip(1).take(rounds-1).enumerate() {
                        if f.contains(&old) {
                            let new = compress(property.input, level);
                            input_sets[r].insert(new);
                        }
                    }

                    if t == 0 {
                        progress_bar.increment();
                    }
                }

                // Synchronise threads for proper progress bar printing
                barrier.wait();
                }

                // Second, collect all output values allowed by the filters
                // Store them in a hash set for each round
                let mut output_sets: SmallVec<[_; 256]> = smallvec![FnvHashSet::default(); rounds-1];
                {
                thread_properties.set_type_output();
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in thread_properties.into_iter() {
                    // Get old value for filter look up
                    let old = compress(property.output, level - 1);

                    // Ignore input and output stages
                    for (r, f) in filters.iter().skip(1).take(rounds-1).enumerate() {
                        if f.contains(&old) {
                            let new = compress(property.output, level);
                            output_sets[r].insert(new);
                        }
                    }
                    
                    if t == 0 {
                        progress_bar.increment();
                    }
                }   
                }
                
                result_tx.send((input_sets, output_sets)).expect("Thread could not send result");
            });
        }
    });
    
    // Last, collect sets from all threads and create graph
    let mut graph = MultistageGraph::new(rounds+1);
    let mut input_sets: SmallVec<[FnvHashSet<u128>; 256]> = smallvec![FnvHashSet::default(); rounds-1];
    let mut output_sets: SmallVec<[FnvHashSet<u128>; 256]> = smallvec![FnvHashSet::default(); rounds-1];

    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        
        // Get union of different thread sets
        for i in 0..thread_result.0.len() {
            input_sets[i].extend(thread_result.0[i].iter());
            output_sets[i].extend(thread_result.1[i].iter());   
        }
    }

    // Add vertices that are in the intersections of input and output sets 
    for i in 0..rounds-1 {
        for &label in input_sets[i].intersection(&output_sets[i]) {
            graph.add_vertex(i+1, label);
        }
    }
    
    graph
}

/**
Add edges to a graph generated by get_middle_vertices. Edges represent properties, and are only 
added if there are matching vertices in two adjacent stages. Input and output edges are ignored.

graph           Graph to add edges to.
properties      The properties consideres when adding edges. 
rounds          The number of rounds, i.e. one less than the number of stages in the graph.
level           Compression level to use for vertex values. 
*/
fn add_middle_edges(graph: &MultistageGraph,
                    properties: &SortedProperties, 
                    rounds: usize, 
                    level: usize)
                    -> MultistageGraph {
    // Block size of the compression
    let block = 1 << (3-level);
    let (result_tx, result_rx) = mpsc::channel();
    let mut base_graph = graph.clone();
    
    // Start scoped worker threads
    scoped::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                // For SPN ciphers, we can exploit the structure when the compressiond is 
                // sufficiently coarse and not generate all properties explicitly 
                if block >= thread_properties.cipher.sbox(0).size  && 
                   thread_properties.cipher.structure() == CipherStructure::Spn {
                    thread_properties.set_type_output();
                } else {
                    thread_properties.set_type_all();
                }

                
                // Split the S-box patterns equally across threads
                // Note that this does not equally split the number of properties across threads,
                // but hopefully it is close enough
                let tmp = thread_properties.sbox_patterns.iter()
                                                         .cloned()
                                                         .skip(t)
                                                         .step_by(*THREADS)
                                                         .collect();
                thread_properties.sbox_patterns = tmp;

                // Collect all edges that have corresponding vertices in the graph
                let mut edges = IndexMap::new();
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in thread_properties.into_iter() {
                    let input = compress(property.input, level);
                    let output = compress(property.output, level);
                    let length = property.value;
                    
                    for r in 1..rounds-1 {
                        if graph.has_vertex(r, input) && 
                           graph.has_vertex(r+1, output) {
                            edges.insert((r, input, output), length);
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
        base_graph.add_edges(&thread_result);
    }

    base_graph
}

/**
Add input/output edges to a graph generated by get_middle_vertices as well as any missing vertices
in the first/last stage. Vertices in other stages are respected such that edges are not added if 
they don't have a matching output/input vertex. 

graph           Graph to add edges to.
properties      The properties consideres when adding edges. 
rounds          The number of rounds, i.e. one less than the number of stages in the graph.
level           Compression level to use for vertex values. 
input_allowed   A set of allowed input values. Other inputs are ignored.
output_allowed  A set of allowed output values. Other outputs are ignored.
*/
fn add_outer_edges (graph: &MultistageGraph,
                    properties: &SortedProperties, 
                    rounds: usize, 
                    level: usize,
                    input_allowed: &FnvHashSet<u128>,
                    output_allowed: &FnvHashSet<u128>) 
                    -> MultistageGraph {
    // Block size of the compression
    let block = 1 << (3-level);
    let (result_tx, result_rx) = mpsc::channel();
    let mut base_graph = graph.clone();
    
    // Start scoped worker threads
    scoped::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                // For SPN ciphers, we can exploit the structure when the compressiond is 
                // sufficiently coarse and not generate all properties explicitly 
                if block >= thread_properties.cipher.sbox(0).size  && 
                   thread_properties.cipher.structure() == CipherStructure::Spn {
                    thread_properties.set_type_output();
                } else {
                    thread_properties.set_type_all();
                }

                
                // Split the S-box patterns equally across threads
                // Note that this does not equally split the number of properties across threads,
                // but hopefully it is close enough
                let tmp = thread_properties.sbox_patterns.iter()
                                                         .cloned()
                                                         .skip(t)
                                                         .step_by(*THREADS)
                                                         .collect();
                thread_properties.sbox_patterns = tmp;

                // Collect all edges that have corresponding output/input vertices in the 
                // second/second to last stage
                let mut edges = IndexMap::new();
                let mut progress_bar = ProgressBar::new(thread_properties.len());

                for (property, _) in thread_properties.into_iter() {
                    let input = compress(property.input, level);
                    let output = compress(property.output, level);
                    let length = property.value;

                    // First round        
                    if input_allowed.len() == 0 || input_allowed.contains(&(input as u128)) {
                        match graph.get_vertex(1, output) {
                            Some(vertex_ref) => {
                                // Only insert if the output vertex has an outgoing edge,
                                // unless there are only two rounds
                                if rounds == 2 || vertex_ref.successors.len() != 0 {
                                    edges.insert((0, input, output), length);
                                }
                            },
                            None => {}
                        }
                    }

                    // Last round
                    if output_allowed.len() == 0 || output_allowed.contains(&(output as u128)) {
                        match graph.get_vertex(rounds-1, input) {
                            Some(vertex_ref) => {
                                // Only insert if the input vertex has an incoming edge,
                                // unless there are only two rounds
                                if rounds == 2 || vertex_ref.predecessors.len() != 0 {
                                    edges.insert((rounds-1, input, output), length);
                                }
                            },
                            None => {}
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

    // Add edges and vertices from each thread
    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        base_graph.add_edges_and_vertices(&thread_result);
    }

    base_graph
}

/**
Adds good edges from to/from each vertex in the second/second to last layer.

cipher          The cipher being analysed.
property_type   The type of property being analysed.
graph           The graph to modify.
*/
fn anchor_ends(cipher: &Cipher,
               property_type: PropertyType,
               graph: &mut MultistageGraph,
               anchors: Option<usize>,
               input_allowed: &FnvHashSet<u128>,
               output_allowed: &FnvHashSet<u128>) {
    let (result_tx, result_rx) = mpsc::channel();
    let mask_map = MaskMap::new(cipher, property_type);
    let stages = graph.stages();
    let start_labels: Vec<_> = graph.get_stage(1).unwrap().keys()
                                    .map(|&x| (x, 0)).collect();
    let end_labels: Vec<_> = graph.get_stage(stages-2).unwrap().keys()
                                  .map(|&x| (x, stages-2)).collect();

    // Determine number of anchors to add
    let num_labels = start_labels.len() + end_labels.len();
    let max_anchors = match anchors {
        Some(x) => 1 << x,
        None    => 1 << 17
    };
    let limit = 0.max(max_anchors
        - (graph.get_stage(0).unwrap().len() 
         + graph.get_stage(stages-1).unwrap().len()) as i64);
    let num_anchor = (limit as f64 / num_labels as f64).ceil() as usize;
    println!("Adding {:?} anchors.", limit);

    // Start scoped worker threads
    scoped::scope(|scope| {
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
                            if input_allowed.len() == 0 || input_allowed.contains(&input) {
                                edges.insert((0, input, label), value);
                            }
                        }
                    } else {
                        let input = label as u128;
                        let outputs = mask_map.get_best_outputs(cipher, input, num_anchor);

                        for (output, value) in outputs {
                            let output = cipher.linear_layer(output);

                            if output_allowed.len() == 0 || output_allowed.contains(&output) {
                                edges.insert((stages-2, label, output), value);
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

    // Add edges and vertices from each thread
    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        graph.add_edges_and_vertices(&thread_result);
    }
}

/**
Initialise filters. The resulting filters allow all values with a block size of 8.

rounds      One less than the number of filters to generate.
*/
fn init_filter(rounds: usize) 
               -> SmallVec<[FnvHashSet<u128>; 65536]> {
    let mut sequence = FnvHashSet::default();

    // Generate all 128-bit values where the first bit of each byte is either zero or one
    for i in 1..65536 {
        let x = (((i >>  0) & 0x1) << 0)
              ^ (((i >>  1) & 0x1) << 8)
              ^ (((i >>  2) & 0x1) << 16)
              ^ (((i >>  3) & 0x1) << 24)
              ^ (((i >>  4) & 0x1) << 32)
              ^ (((i >>  5) & 0x1) << 40)
              ^ (((i >>  6) & 0x1) << 48)
              ^ (((i >>  7) & 0x1) << 56)
              ^ (((i >>  8) & 0x1) << 64)
              ^ (((i >>  9) & 0x1) << 72)
              ^ (((i >> 10) & 0x1) << 80)
              ^ (((i >> 11) & 0x1) << 88)
              ^ (((i >> 12) & 0x1) << 96)
              ^ (((i >> 13) & 0x1) << 104)
              ^ (((i >> 14) & 0x1) << 112)
              ^ (((i >> 15) & 0x1) << 120);

        sequence.insert(x);
    }

    // Using smallvec here assuming most ciphers don't have a large number of rounds
    let output: SmallVec<[_; 65536]> = smallvec![sequence ; rounds+1];
    output
}

/**
Update all filters with new allowed values given by the current vertices in the graph. 
Returns number of vertices in the graph which were inserted into the filter. 

filters         Filters to update.
graph           Graph to update from.
*/
fn update_filters(
    filters: &mut [FnvHashSet<u128>], 
    graph: &MultistageGraph)
    -> usize {
    let mut good_vertices = 0;

    for (i, f) in filters.iter_mut().enumerate() {
        f.clear();
        f.extend(graph.get_stage(i).unwrap()
                                   .iter()
                                   .map(|(input, _)| *input as u128));
        good_vertices += f.len();
    }

    good_vertices
}

/** 
Creates a graph that represents the set of characteristics over a number of rounds for a 
given cipher and set of properties. 

cipher              The cipher to consider.
property_type       The property type to consider.
rounds              The number of rounds.
patterns            The number of S-box patterns to generate.
allowed             A set of allowed input/output values for the properties. 
                    If empty, all values are allowed.
*/
pub fn generate_graph(cipher: Box<Cipher>, 
                      property_type: PropertyType,
                      rounds: usize, 
                      patterns: usize,
                      anchors: Option<usize>,
                      allowed: &FnvHashSet<(u128, u128)>) 
                      -> MultistageGraph {
    // Generate the set of properties to consider
    let mut properties = SortedProperties::new(cipher.as_ref(), patterns, 
                                               property_type, PropertyFilter::All);
    let mut graph = MultistageGraph::new(0);
    
    // Change allowed inputs/outputs for Prince-like ciphers
    let mut input_allowed: FnvHashSet<_>  = allowed.iter().map(|(a,_)| *a).collect();
    let mut output_allowed: FnvHashSet<_> = allowed.iter().map(|(_,b)| *b).collect();
    if cipher.structure() == CipherStructure::Prince {
        input_allowed = input_allowed.union(&output_allowed).cloned().collect();
        output_allowed = FnvHashSet::default();
    }

    if rounds == 1 {
        let start = time::precise_time_s();
        graph = one_round(&mut properties);
        println!("Graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), graph.num_edges(), time::precise_time_s()-start);
    }

    if rounds == 2 {
        let start = time::precise_time_s();
        graph = two_rounds(&mut properties);
        println!("Graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), graph.num_edges(), time::precise_time_s()-start);
    }

    if rounds == 3 {
        let start = time::precise_time_s();
        graph = one_round(&mut properties);
        println!("Graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), graph.num_edges(), time::precise_time_s()-start);
    }

    if rounds >= 4 {
        let rounds = rounds - 2;
        let mut filters = init_filter(rounds);

        // Iteratively generate graphs with finer compression functions
        for level in 1..4 {
            // Get total number of properties considered
            properties.set_type_all();
            let num_prop = properties.len();
            properties.set_type_input();
            let num_input = properties.len();
            properties.set_type_output();
            let num_output = properties.len();

            println!("Level {}.", level);
            println!("{} properties ({} input, {} output).", num_prop, num_input, num_output);

            let start = time::precise_time_s();
            graph = get_middle_vertices(&properties, rounds, &filters[..], level);
            println!("Added vertices [{} s]", time::precise_time_s()-start);
            
            // Don't add middle edges if there are only two rounds
            if rounds > 2 {
                let start = time::precise_time_s();
                graph = add_middle_edges(&graph, &properties, rounds, level);
                println!("Graph has {} vertices and {} edges [{} s]", 
                    graph.num_vertices(), graph.num_edges(), time::precise_time_s()-start);

                let start = time::precise_time_s();
                graph.prune(1, rounds);
                println!("Pruned graph has {} vertices and {} edges [{} s]", 
                    graph.num_vertices(), graph.num_edges(), time::precise_time_s()-start);                
            }

            let start = time::precise_time_s();

            graph = add_outer_edges(&mut graph, &properties, rounds, level, 
                                    &FnvHashSet::default(), &FnvHashSet::default());
            println!("Graph has {} vertices and {} edges [{} s]", 
                graph.num_vertices(), graph.num_edges(), time::precise_time_s()-start);

            // Remove any dead vertices
            let start = time::precise_time_s();
            if cipher.structure() == CipherStructure::Prince {
                prince_pruning(cipher.as_ref(), &mut graph);
            } else {
                graph.prune(0, rounds+1);
            }
            println!("Pruned graph has {} vertices and {} edges [{} s]", 
                graph.num_vertices(), graph.num_edges(), time::precise_time_s()-start);

            // Update filters and remove dead patterns if we havn't generated the final graph
            if level != 3 {
                let start = time::precise_time_s();
                let good_vertices = update_filters(&mut filters[..], &graph);
                println!("Number of good vertices: {} [{} s]", 
                    good_vertices, time::precise_time_s()-start);

                let start = time::precise_time_s();
                let patterns_before = properties.len_patterns();
                properties.remove_dead_patterns(&filters[..], level);
                let patterns_after = properties.len_patterns();
                println!("Removed {} dead patterns [{} s]", 
                    patterns_before - patterns_after, time::precise_time_s()-start);
            }

            println!("");
        }
    }

    // Extending and anchoring
    if rounds != 1 {
        graph.vertices.insert(0, FnvHashMap::default());
        graph.vertices.push(FnvHashMap::default());

        let start = time::precise_time_s();
        graph = add_outer_edges(&mut graph, &properties, rounds, 3,
                                &input_allowed, &output_allowed);
        println!("Extended graph has {} vertices and {} edges [{} s]\n", 
                graph.num_vertices(), graph.num_edges(), time::precise_time_s()-start);

        let start = time::precise_time_s();
        anchor_ends(cipher.as_ref(), property_type, &mut graph, anchors,
                    &input_allowed, &output_allowed);
        println!("Anchored graph has {} vertices and {} edges [{} s]\n", 
                graph.num_vertices(), graph.num_edges(), time::precise_time_s()-start);

        graph.prune(0, rounds+1);
        println!("Final graph has {} vertices and {} edges", 
                graph.num_vertices(), graph.num_edges());
    }

    // Reflecting in case of Prince type ciphers
    if cipher.structure() == CipherStructure::Prince {
        let start = time::precise_time_s();
        graph = prince_modification(cipher.as_ref(), &mut graph);
        println!("Reflected graph has {} vertices and {} edges [{} s]\n", 
            graph.num_vertices(), graph.num_edges(), time::precise_time_s()-start);
    }
    
    graph
}