use crossbeam_utils::scoped;
use num_cpus;
use std::collections::{HashSet, HashMap};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use time;
use std::cmp;

use cipher::*;
use graph_search::MultistageGraph;
use single_round::{SortedApproximations, AppType};
use utility::ProgressBar;

lazy_static! {
    static ref COMPRESS: Vec<Vec<usize>> = vec![
        vec![16, 16, 16, 16],
        // vec![8, 8, 16, 8, 8, 16],
        vec![8, 8, 8, 8, 8, 8, 8, 8],
        // vec![4, 4, 8, 4, 4, 8, 4, 4, 8, 4, 4, 8],
        vec![4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4],
        vec![2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
        vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    ];
}

pub fn compress(x: u64, level: usize) -> u64 {
    let mut out = 0;
    let mut tmp = x;

    for (i, block) in COMPRESS[level].iter().enumerate() {
        let mask = ((1 << block) - 1) as u64;

        if tmp & mask != 0 {
            out ^= 1 << i;
        }

        tmp >>= block;
    }

    out
}

fn get_vertices (
    approximations: &mut SortedApproximations, 
    rounds: usize, 
    filters: &Vec<HashSet<u64>>,
    level: usize) 
    -> MultistageGraph {
    let num_threads = num_cpus::get();
    let barrier = Arc::new(Barrier::new(num_threads));
    let (result_tx, result_rx) = mpsc::channel();
    approximations.set_type_alpha();
    let num_alpha = approximations.len();
    approximations.set_type_beta();
    let num_beta = approximations.len();

    scoped::scope(|scope| {
        for t in 0..num_threads {
            let mut thread_approximations = approximations.clone();
            let barrier = barrier.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                // Annoying solution, hopefully okay
                let tmp = thread_approximations.sbox_patterns.iter()
                                                             .cloned()
                                                             .skip(t)
                                                             .step_by(num_threads)
                                                             .collect();
                thread_approximations.sbox_patterns = tmp;

                // Collect all alpha values allowed by filters
                let mut alpha_sets = vec![HashSet::new(); rounds-1];
                let mut progress_bar = ProgressBar::new(num_alpha);
                thread_approximations.set_type_alpha();

                for (approximation, _) in thread_approximations.into_iter() {
                    let alpha = if approximation.alpha == 0 {
                        continue
                    } else {
                        approximation.alpha
                    };

                    let old = compress(alpha, level - 1);
                    let new = compress(alpha, level);

                    for r in 0..rounds-1 {
                        if filters[r+1].contains(&old) {
                            alpha_sets[r].insert(new);
                        }
                    }

                    progress_bar.increment();
                }

                barrier.wait();
                if t == 0 {
                    println!("");
                }

                // For the last round, collect all beta values
                let mut beta_sets = vec![HashSet::new(); rounds-1];
                let mut progress_bar = ProgressBar::new(num_beta);
                thread_approximations.set_type_beta();

                for (approximation, _) in thread_approximations.into_iter() {
                    let beta = if approximation.beta == 0 {
                        continue
                    } else {
                        approximation.beta
                    };

                    let old = compress(beta, level - 1);
                    let new = compress(beta, level);

                    for r in 0..rounds-1 {
                        if filters[r+1].contains(&old) {
                            beta_sets[r].insert(new);
                        }
                    }
                    
                    progress_bar.increment();
                }
                
                result_tx.send((alpha_sets, beta_sets)).expect("Thread could not send result");
            });
        }
    });
    println!("");

    let mut vertex_sets = vec![HashSet::new(); rounds-1];
    {
        let mut alpha_sets = vec![HashSet::new(); rounds-1];
        let mut beta_sets = vec![HashSet::new(); rounds-1];

        for _ in 0..num_threads {
            let thread_result = result_rx.recv().expect("Main could not receive result");
            
            for (i, set) in thread_result.0.iter().enumerate() {
                alpha_sets[i] = alpha_sets[i].union(&set).cloned().collect();
            }

            for (i, set) in thread_result.1.iter().enumerate() {
                beta_sets[i] = beta_sets[i].union(&set).cloned().collect();
            }
        }

        for i in 0..rounds-1 {
            vertex_sets[i] = alpha_sets[i].intersection(&beta_sets[i]).cloned().collect();
        }
    }

    // Create graph from vertex sets
    let mut graph = MultistageGraph::new(rounds+1);

    for i in 0..rounds-1 {
        for &label in &vertex_sets[i] {
            graph.add_vertex(i+1, label as usize);
        }

        vertex_sets[i].clear();
    }

    approximations.set_type_all();
    graph
}

fn add_edges(graph: &mut MultistageGraph, edges: &HashMap<(usize, usize, usize), f64>) {
    for (&(stage, from, to), &length) in edges {
        graph.add_edge(stage, from, to, length);
    }
}

fn add_edges_and_vertices(graph: &mut MultistageGraph, edges: &HashMap<(usize, usize, usize), f64>) {
    for (&(stage, from, to), &length) in edges {
        if stage == 0 {
            graph.add_vertex(0, from);
        } else {
            graph.add_vertex(stage+1, to);
        }
        graph.add_edge(stage, from, to, length);
    }
}

fn add_middle_edges(
    graph: &MultistageGraph,
    approximations: &mut SortedApproximations, 
    rounds: usize, 
    level: usize)
    -> MultistageGraph {
    let min_block = COMPRESS[level].iter()
                                   .fold(approximations.cipher.size(), |acc, &x| cmp::min(x, acc));

    if min_block < approximations.cipher.sbox().size {
        approximations.set_type_all();
    } else {
        approximations.set_type_beta();
    }
    
    // Collect edges in parallel
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();
    let mut base_graph = graph.clone();
    
    scoped::scope(|scope| {
        for t in 0..num_threads {
            let mut thread_approximations = approximations.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                let mut progress_bar = ProgressBar::new(thread_approximations.len());
                
                // Annoying solution, hopefully okay
                let tmp = thread_approximations.sbox_patterns.iter()
                                                             .cloned()
                                                             .skip(t)
                                                             .step_by(num_threads)
                                                             .collect();
                thread_approximations.sbox_patterns = tmp;

                // Collect edges
                let mut edges = HashMap::new();

                for (approximation, _) in thread_approximations.into_iter() {    
                    let alpha = compress(approximation.alpha, level) as usize;
                    let beta = compress(approximation.beta, level) as usize;
                    let length = -approximation.value.log2();
                    
                    for r in 1..rounds-1 {
                        if graph.get_vertex(r, alpha).is_some() && 
                           graph.get_vertex(r+1, beta).is_some() {
                            edges.insert((r, alpha, beta), length);
                        }
                    }

                    progress_bar.increment();
                }
                
                result_tx.send(edges).expect("Thread could not send result");
            });
        }
    });

    for _ in 0..num_threads {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        add_edges(&mut base_graph, &thread_result);
    }

    println!("");
    base_graph
}

/* Creates a linear hull graph, compressing the approximations with the specified level. 
 *
 * approximations   Approximations to use.
 * rounds           Number of rounds.
 * level       Block size of the compression.
 * vertex_maps      Map of the allowed mask values.
 */ 
fn add_outer_edges (
    graph: &MultistageGraph,
    approximations: &mut SortedApproximations, 
    rounds: usize, 
    level: usize) 
    -> MultistageGraph {
    let min_block = COMPRESS[level].iter()
                                   .fold(approximations.cipher.size(), |acc, &x| cmp::min(x, acc));

    if min_block < approximations.cipher.sbox().size {
        approximations.set_type_all();
    } else {
        approximations.set_type_beta();
    }

    // Create graph in parallel
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();
    let mut base_graph = graph.clone();
    
    scoped::scope(|scope| {
        for t in 0..num_threads {
            let mut thread_approximations = approximations.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                let mut progress_bar = ProgressBar::new(thread_approximations.len());
                
                // Annoying solution, hopefully okay
                let tmp = thread_approximations.sbox_patterns.iter()
                                                             .cloned()
                                                             .skip(t)
                                                             .step_by(num_threads)
                                                             .collect();
                thread_approximations.sbox_patterns = tmp;

                // Add edges
                let mut edges = HashMap::new();

                for (approximation, _) in thread_approximations.into_iter() {    
                    let alpha = compress(approximation.alpha, level) as usize;
                    let beta = compress(approximation.beta, level) as usize;
                    let length = -approximation.value.log2();

                    // First round                    
                    if /*graph.get_vertex(0, alpha).is_some() && */
                       graph.get_vertex(1, beta).is_some() {
                        let vertex_ref = graph.get_vertex(1, beta).unwrap();

                        if rounds == 2 || vertex_ref.successors.len() != 0 {
                            edges.insert((0, alpha, beta), length);
                        }
                    }

                    // Last round
                    if graph.get_vertex(rounds-1, alpha).is_some() /*&& 
                       graph.get_vertex(rounds, beta).is_some()*/ {
                        let vertex_ref = graph.get_vertex(rounds-1, alpha).unwrap();

                        if rounds == 2 || vertex_ref.predecessors.len() != 0 {
                            edges.insert((rounds-1, alpha, beta), length);
                        }
                    }

                    progress_bar.increment();
                }

                result_tx.send(edges).expect("Thread could not send result");
            });
        }
    });

    for _ in 0..num_threads {
        let thread_result = result_rx.recv().expect("Main could not receive result");
        add_edges_and_vertices(&mut base_graph, &thread_result);
    }

    println!("");
    base_graph
}

/* Remove any edges that aren't part of a path from source to sink. 
 *
 * graph    Graph to prune.
 */
fn prune_graph(graph: &mut MultistageGraph, start: usize, stop: usize) {
    let mut pruned = true;

    while pruned {
        pruned = false;

        for stage in start..stop {
            let mut remove = Vec::new();

            for (&label, vertex) in graph.get_stage(stage).unwrap() {
                if stage == start && vertex.successors.len() == 0 {
                    remove.push(label);
                } else if stage == stop-1 && vertex.predecessors.len() == 0 {
                    remove.push(label);
                } else if (stage != start && stage != stop-1) && (vertex.successors.len() == 0 ||
                    vertex.predecessors.len() == 0) {
                    remove.push(label);
                }
            }

            for label in remove {
                graph.remove_vertex(stage, label);
                pruned = true;
            }
        }
    }
}

/* Update all filters with new allowed values. Returns number of vertices in the graph which
 * were inserted into the filter. 
 *
 * filters      Filters to update.
 * graph        Graph to update from.
 * vertex_maps  Map of vertex indices to values.
 */
fn update_filters(
    filters: &mut Vec<HashSet<u64>>, 
    graph: &MultistageGraph)
    -> usize {
    let stages = graph.stages();
    let mut good_vertices = 0;

    for stage in 0..stages {
        filters[stage].clear();

        for (alpha, vertex_ref) in graph.get_stage(stage).unwrap() {                    
            if vertex_ref.successors.len() != 0 || vertex_ref.predecessors.len() != 0 {
                filters[stage].insert(*alpha as u64);
                good_vertices += 1;
            }
        }
    }

    good_vertices
}

/* Removes patterns from a SortedApproximations which a not allowed by a set of filters.
 *
 * Filters          Filters to check.
 * approximations   Approximations to remove patterns from.
 */
fn remove_dead_patterns(
    filters: &Vec<HashSet<u64>>, 
    approximations: &mut SortedApproximations,
    level: usize) {
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();
    
    scoped::scope(|scope| {
        for t in 0..num_threads {
            let mut thread_approximations = approximations.clone();
            let result_tx = result_tx.clone();

            scope.spawn(move || {
                thread_approximations.set_type_alpha();
                let mut progress_bar = ProgressBar::new(thread_approximations.len());
                
                // Annoying solution, hopefully okay
                let tmp = thread_approximations.sbox_patterns.iter()
                                                             .cloned()
                                                             .skip(t)
                                                             .step_by(num_threads)
                                                             .collect();
                thread_approximations.sbox_patterns = tmp;

                let mut good_patterns = vec![false; thread_approximations.len_patterns()];

                for (approximation, pattern_idx) in thread_approximations.into_iter() {
                    let alpha = approximation.alpha;
                    let good = filters.iter()
                                      .fold(false, 
                                            |acc, ref x| acc | x.contains(&compress(alpha, level)));
                    good_patterns[pattern_idx] |= good;
                    progress_bar.increment();
                }

                // Keep only good patterns
                let mut new_patterns = vec![];

                for (i, keep) in good_patterns.iter().enumerate() {
                    if *keep {
                        new_patterns.push(thread_approximations.sbox_patterns[i].clone());
                    }
                }

                result_tx.send(new_patterns).expect("Thread could not send result");
            });
        }
    });

    let mut new_patterns = Vec::new();

    for _ in 0..num_threads {
        let mut thread_result = result_rx.recv().expect("Main could not receive result");
        new_patterns.append(&mut thread_result);
    }
    println!("");

    approximations.sbox_patterns = new_patterns;
    approximations.set_type_all();
}

/* Creates a graph that represents the linear hull over a number of rounds for a given cipher and 
 * set of approximations. 
 * 
 * cipher       Cipher to consider.
 * rounds       Number of rounds.
 * patterns     Number of patterns to generate for approximations.
 */
pub fn generate_graph(
    cipher: &Cipher, 
    rounds: usize, 
    patterns: usize) 
    -> MultistageGraph {
    let mut approximations = SortedApproximations::new(cipher, patterns, AppType::All);
    let mut filters = vec![(0..(1 << (cipher.size() / 16))).collect() ; rounds+1];
    let mut graph = MultistageGraph::new(0);

    for level in 1..COMPRESS.len() {
        approximations.set_type_all();
        let num_app = approximations.len();
        approximations.set_type_alpha();
        let num_alpha = approximations.len();
        approximations.set_type_beta();
        let num_beta = approximations.len();

        println!("Level {}.", level);
        println!("{} approximations ({} alpha, {} beta).", num_app, num_alpha, num_beta);

        let start = time::precise_time_s();
        graph = get_vertices(&mut approximations, rounds, &filters, level);
        println!("Added vertices [{} s]", time::precise_time_s()-start);

        let start = time::precise_time_s();
        graph = add_middle_edges(&graph, &mut approximations, rounds, level);
        println!("Graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), 
            graph.num_edges(),
            time::precise_time_s()-start);

        let mut name = String::from("test_step1");
        name.push_str(&level.to_string());
        print_to_graph_tool(&graph, &name);

        let start = time::precise_time_s();
        if rounds > 2 {
            prune_graph(&mut graph, 1, rounds);
        }
        println!("Pruned graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), 
            graph.num_edges(), 
            time::precise_time_s()-start);

        let mut name = String::from("test_step2");
        name.push_str(&level.to_string());
        print_to_graph_tool(&graph, &name);

        let start = time::precise_time_s();
        graph = add_outer_edges(&mut graph, &mut approximations, rounds, level);
        println!("Graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), 
            graph.num_edges(),
            time::precise_time_s()-start);

        let mut name = String::from("test_step3");
        name.push_str(&level.to_string());
        print_to_graph_tool(&graph, &name);

        if level != COMPRESS.len() - 1 {
            let start = time::precise_time_s();
            let good_vertices = update_filters(&mut filters, &graph);
            println!("Number of good vertices: {} [{} s]", 
                good_vertices,
                time::precise_time_s()-start);

            let start = time::precise_time_s();
            let patterns_before = approximations.len_patterns();
            remove_dead_patterns(&filters, &mut approximations, level);
            let patterns_after = approximations.len_patterns();
            println!("Removed {} dead patterns [{} s]", 
                patterns_before - patterns_after, 
                time::precise_time_s()-start);
        }

        println!("");
    }
    
    graph
}

/* Prints a graph for plotting with python graph-tool */
pub fn print_to_graph_tool(
    graph: &MultistageGraph,
    path: &String) {
    let mut path = path.clone();
    path.push_str(".graph");
    let mut file = OpenOptions::new()
                               .write(true)
                               .truncate(true)
                               .create(true)
                               .open(path)
                               .expect("Could not open file.");

    let stages = graph.stages();

    for i in 0..stages {
        for (j, _) in graph.get_stage(i).unwrap() {
            write!(file, "{},{}\n", i, j).expect("Write error");
        }
    }        

    for i in 0..stages-1 {
        for (j, vertex_ref) in graph.get_stage(i).unwrap() {
            for (k, _) in &vertex_ref.successors {
                write!(file, "{},{},{},{}\n", i, j, i+1, k).expect("Write error");       
            }
        }
    }   
}