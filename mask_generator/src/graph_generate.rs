use crossbeam_utils::scoped;
use num_cpus;
use fnv::FnvHashSet;
use indexmap::IndexMap;
use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use time;
use smallvec::SmallVec;

use cipher::*;
use graph::MultistageGraph;
use single_round::SortedProperties;
use property::{PropertyType, PropertyFilter};
use utility::ProgressBar;

lazy_static! {
    static ref THREADS: usize = num_cpus::get();
}

#[inline(always)]
pub fn compress(x: u64, level: usize) -> u64 {
    match level {
        0 => {
             (x & 0x0101010101010101) |
            ((x & 0x0202020202020202) >> 1) |
            ((x & 0x0404040404040404) >> 2) |
            ((x & 0x0808080808080808) >> 3) |
            ((x & 0x1010101010101010) >> 4) |
            ((x & 0x2020202020202020) >> 5) |
            ((x & 0x4040404040404040) >> 6) |
            ((x & 0x8080808080808080) >> 7)
        }
        1 => {
             (x & 0x1111111111111111) |
            ((x & 0x2222222222222222) >> 1) |
            ((x & 0x4444444444444444) >> 2) |
            ((x & 0x8888888888888888) >> 3)
        },
        2 => {
             (x & 0x5555555555555555) |
            ((x & 0xaaaaaaaaaaaaaaaa) >> 1)
        },
        3 => {
            x
        },
        _ => panic!("Compression level out of range.")
    }
}

fn get_vertices (
    properties: &SortedProperties, 
    rounds: usize, 
    filters: &[FnvHashSet<u64>],
    level: usize) 
    -> MultistageGraph {
    let barrier = Arc::new(Barrier::new(*THREADS));
    let (result_tx, result_rx) = mpsc::channel();

    scoped::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let barrier = barrier.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                thread_properties.set_type_input();
                let num_input = properties.len();
                thread_properties.set_type_output();
                let num_output = properties.len();

                // Annoying solution, hopefully okay
                let tmp = thread_properties.sbox_patterns.iter()
                                                         .cloned()
                                                         .skip(t)
                                                         .step_by(*THREADS)
                                                         .collect();
                thread_properties.sbox_patterns = tmp;

                // Collect all input values allowed by filters
                let mut input_sets: SmallVec<[_; 256]> = smallvec![FnvHashSet::default(); rounds-1];
                let mut progress_bar = ProgressBar::new(num_input);
                thread_properties.set_type_input();

                for (property, _) in thread_properties.into_iter() {
                    let input = if property.input == 0 {
                        continue
                    } else {
                        property.input
                    };

                    let old = compress(input, level - 1);
                    let new = compress(input, level);

                    for (r, f) in filters.iter().skip(1).take(rounds-1).enumerate() {
                        if f.contains(&old) {
                            input_sets[r].insert(new);
                        }
                    }

                    progress_bar.increment();
                }

                barrier.wait();
                if t == 0 {
                    println!("");
                }

                // For the last round, collect all output values
                let mut output_sets: SmallVec<[_; 256]> = smallvec![FnvHashSet::default(); rounds-1];
                let mut progress_bar = ProgressBar::new(num_output);
                thread_properties.set_type_output();

                for (property, _) in thread_properties.into_iter() {
                    let output = if property.output == 0 {
                        continue
                    } else {
                        property.output
                    };

                    let old = compress(output, level - 1);
                    let new = compress(output, level);

                    for (r, f) in filters.iter().skip(1).take(rounds-1).enumerate() {
                        if f.contains(&old) {
                            output_sets[r].insert(new);
                        }
                    }
                    
                    progress_bar.increment();
                }
                
                result_tx.send((input_sets, output_sets)).expect("Thread could not send result");
            });
        }
    });
    println!("");
    
    // Create graph from vertex sets
    let mut graph = MultistageGraph::new(rounds+1);
    let mut input_sets: SmallVec<[FnvHashSet<u64>; 256]> = smallvec![FnvHashSet::default(); rounds-1];
    let mut output_sets: SmallVec<[FnvHashSet<u64>; 256]> = smallvec![FnvHashSet::default(); rounds-1];

    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        
        for i in 0..thread_result.0.len() {
            input_sets[i].extend(thread_result.0[i].iter());
            output_sets[i].extend(thread_result.1[i].iter());   
        }
    }

    for i in 0..rounds-1 {
        for &label in input_sets[i].intersection(&output_sets[i]) {
            graph.add_vertex(i+1, label as usize);
        }
    }
    
    graph
}

fn add_middle_edges(
    graph: &MultistageGraph,
    properties: &SortedProperties, 
    rounds: usize, 
    level: usize)
    -> MultistageGraph {
    let block = 1 << (3-level);
    
    // Collect edges in parallel
    let (result_tx, result_rx) = mpsc::channel();
    let mut base_graph = graph.clone();
    
    scoped::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                if block < thread_properties.cipher.sbox().size  || 
                   thread_properties.cipher.structure() == CipherStructure::Feistel {
                    thread_properties.set_type_all();
                } else {
                    thread_properties.set_type_output();
                }

                let mut progress_bar = ProgressBar::new(thread_properties.len());
                
                // Annoying solution, hopefully okay
                let tmp = thread_properties.sbox_patterns.iter()
                                                             .cloned()
                                                             .skip(t)
                                                             .step_by(*THREADS)
                                                             .collect();
                thread_properties.sbox_patterns = tmp;

                // Collect edges
                let mut edges = IndexMap::new();

                for (property, _) in thread_properties.into_iter() {    
                    let input = compress(property.input, level) as usize;
                    let output = compress(property.output, level) as usize;
                    let length = -property.value.log2();
                    
                    for r in 1..rounds-1 {
                        if graph.has_vertex(r, input) && 
                           graph.has_vertex(r+1, output) {
                            edges.insert((r, input, output), length);
                        }
                    }

                    progress_bar.increment();
                }
                
                result_tx.send(edges).expect("Thread could not send result");
            });
        }
    });

    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        base_graph.add_edges(&thread_result);
    }

    println!("");
    base_graph
}

/* Creates a linear hull graph, compressing the properties with the specified level. 
 *
 * properties   Approximations to use.
 * rounds           Number of rounds.
 * level       Block size of the compression.
 * vertex_maps      Map of the allowed mask values.
 */ 
fn add_outer_edges (
    graph: &MultistageGraph,
    properties: &SortedProperties, 
    rounds: usize, 
    level: usize,
    input_allowed: &FnvHashSet<u64>,
    output_allowed: &FnvHashSet<u64>) 
    -> MultistageGraph {
    let block = 1 << (3-level);

    // Create graph in parallel
    let (result_tx, result_rx) = mpsc::channel();
    let mut base_graph = graph.clone();
    
    scoped::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                if block < thread_properties.cipher.sbox().size  || 
                   thread_properties.cipher.structure() == CipherStructure::Feistel {
                    thread_properties.set_type_all();
                } else {
                    thread_properties.set_type_output();
                }

                let mut progress_bar = ProgressBar::new(thread_properties.len());
                
                // Annoying solution, hopefully okay
                let tmp = thread_properties.sbox_patterns.iter()
                                                             .cloned()
                                                             .skip(t)
                                                             .step_by(*THREADS)
                                                             .collect();
                thread_properties.sbox_patterns = tmp;

                // Add edges
                let mut edges = IndexMap::new();

                for (property, _) in thread_properties.into_iter() {
                    let input = compress(property.input, level) as usize;
                    let output = compress(property.output, level) as usize;
                    let length = -property.value.log2();

                    // First round                    
                    if input_allowed.len() == 0 || input_allowed.contains(&(input as u64)) {
                        match graph.get_vertex(1, output) {
                            Some(vertex_ref) => {
                                if rounds == 2 || vertex_ref.successors.len() != 0 {
                                    edges.insert((0, input, output), length);
                                }
                            },
                            None => {}
                        }
                        
                    }

                    // Last round
                    if output_allowed.len() == 0 || output_allowed.contains(&(output as u64)) {
                        match graph.get_vertex(rounds-1, input) {
                            Some(vertex_ref) => {
                                if rounds == 2 || vertex_ref.predecessors.len() != 0 {
                                    edges.insert((rounds-1, input, output), length);
                                }
                            },
                            None => {}
                        }
                    }

                    progress_bar.increment();
                }

                result_tx.send(edges).expect("Thread could not send result");
            });
        }
    });

    for _ in 0..*THREADS {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        base_graph.add_edges_and_vertices(&thread_result);
    }

    println!("");
    base_graph
}

/* Update all filters with new allowed values. Returns number of vertices in the graph which
 * were inserted into the filter. 
 *
 * filters      Filters to update.
 * graph        Graph to update from.
 * vertex_maps  Map of vertex indices to values.
 */
fn update_filters(
    filters: &mut [FnvHashSet<u64>], 
    graph: &MultistageGraph)
    -> usize {
    let mut good_vertices = 0;

    for (i, f) in filters.iter_mut().enumerate() {
        f.clear();
        f.extend(graph.get_stage(i).unwrap()
                                   .iter()
                                   .filter(|(_, vertex_ref)| 
                                        vertex_ref.successors.len() != 0 || 
                                        vertex_ref.predecessors.len() != 0)
                                   .map(|(input, _)| *input as u64));

        good_vertices += f.len();
    }

    good_vertices
}

/* Removes patterns from a SortedProperties which a not allowed by a set of filters.
 *
 * Filters          Filters to check.
 * properties   Approximations to remove patterns from.
 */
fn remove_dead_patterns(
    filters: &[FnvHashSet<u64>], 
    properties: &mut SortedProperties,
    level: usize) {
    let (result_tx, result_rx) = mpsc::channel();
    
    scoped::scope(|scope| {
        for t in 0..*THREADS {
            let mut thread_properties = properties.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                thread_properties.set_type_input();
                let mut progress_bar = ProgressBar::new(thread_properties.len());
                
                // Annoying solution, hopefully okay
                let tmp = thread_properties.sbox_patterns.iter()
                                                             .cloned()
                                                             .skip(t)
                                                             .step_by(*THREADS)
                                                             .collect();
                thread_properties.sbox_patterns = tmp;

                let mut good_patterns = vec![false; thread_properties.len_patterns()];

                for (property, pattern_idx) in thread_properties.into_iter() {
                    if good_patterns[pattern_idx] {
                        progress_bar.increment();
                        continue;
                    }

                    let input = compress(property.input, level);
                    let mut good = false;

                    for f in filters {
                        if f.contains(&input) {
                            good = true;
                            break;
                        }
                    }

                    good_patterns[pattern_idx] |= good;
                    progress_bar.increment();
                }

                // Keep only good patterns
                let mut new_patterns = vec![];

                for (i, keep) in good_patterns.iter().enumerate() {
                    if *keep {
                        new_patterns.push(thread_properties.sbox_patterns[i].clone());
                    }
                }

                result_tx.send(new_patterns).expect("Thread could not send result");
            });
        }
    });

    let mut new_patterns = Vec::new();

    for _ in 0..*THREADS {
        let mut thread_result = result_rx.recv().expect("Main could not receive result");
        new_patterns.append(&mut thread_result);
    }
    println!("");

    properties.sbox_patterns = new_patterns;
    properties.set_type_all();
}

fn init_filter(rounds: usize) -> SmallVec<[FnvHashSet<u64>; 256]> {
    let mut sequence = FnvHashSet::default();

    for i in 0..256 {
        let x = (((i >> 0) & 0x1) << 0)
              ^ (((i >> 1) & 0x1) << 8)
              ^ (((i >> 2) & 0x1) << 16)
              ^ (((i >> 3) & 0x1) << 24)
              ^ (((i >> 4) & 0x1) << 32)
              ^ (((i >> 5) & 0x1) << 40)
              ^ (((i >> 6) & 0x1) << 48)
              ^ (((i >> 7) & 0x1) << 56);

        sequence.insert(x);
    }

    // Using smallvec here assuming most ciphers don't have a large number of rounds
    let output: SmallVec<[_; 256]> = smallvec![sequence ; rounds+1];
    output
}

/* Creates a graph that represents the linear hull over a number of rounds for a given cipher and 
 * set of properties. 
 * 
 * cipher       Cipher to consider.
 * rounds       Number of rounds.
 * patterns     Number of patterns to generate for properties.
 */
pub fn generate_graph(
    cipher: Box<Cipher>, 
    property_type: PropertyType,
    rounds: usize, 
    patterns: usize,
    input_allowed: &FnvHashSet<u64>,
    output_allowed: &FnvHashSet<u64>) 
    -> MultistageGraph {
    let mut properties = SortedProperties::new(cipher.as_ref(), patterns, 
                                               property_type, 
                                               PropertyFilter::All);
    let mut filters = init_filter(rounds);
    let mut graph = MultistageGraph::new(0);

    for level in 1..4 {
        properties.set_type_all();
        let num_app = properties.len();
        properties.set_type_input();
        let num_input = properties.len();
        properties.set_type_output();
        let num_output = properties.len();

        println!("Level {}.", level);
        println!("{} properties ({} input, {} output).", num_app, num_input, num_output);

        let start = time::precise_time_s();
        graph = get_vertices(&properties, rounds, &filters[..], level);
        println!("Added vertices [{} s]", time::precise_time_s()-start);

        let start = time::precise_time_s();
        graph = add_middle_edges(&graph, &properties, rounds, level);
        println!("Graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), 
            graph.num_edges(),
            time::precise_time_s()-start);

        if rounds > 2 {
            let start = time::precise_time_s();
            graph.prune_graph(1, rounds);
            println!("Pruned graph has {} vertices and {} edges [{} s]", 
                graph.num_vertices(), 
                graph.num_edges(), 
                time::precise_time_s()-start);
        }

        let start = time::precise_time_s();
        let input_allowed_comp = input_allowed.iter().map(|&x| compress(x, level)).collect();
        let output_allowed_comp = output_allowed.iter().map(|&x| compress(x, level)).collect();

        graph = add_outer_edges(&mut graph, &properties, rounds, level, 
                                &input_allowed_comp, &output_allowed_comp);
        println!("Graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), 
            graph.num_edges(),
            time::precise_time_s()-start);

        let start = time::precise_time_s();
        graph.prune_graph(0, rounds+1);
        println!("Pruned graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), 
            graph.num_edges(), 
            time::precise_time_s()-start);

        if level != 3 {
            let start = time::precise_time_s();
            let good_vertices = update_filters(&mut filters[..], &graph);
            println!("Number of good vertices: {} [{} s]", 
                good_vertices,
                time::precise_time_s()-start);

            let start = time::precise_time_s();
            let patterns_before = properties.len_patterns();
            remove_dead_patterns(&filters[..], &mut properties, level);
            let patterns_after = properties.len_patterns();
            println!("Removed {} dead patterns [{} s]", 
                patterns_before - patterns_after, 
                time::precise_time_s()-start);
        }

        println!("");
    }
    
    graph
}