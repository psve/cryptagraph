use crossbeam_utils::scoped;
use bimap::BiMap;
use num_cpus;
use std::collections::{HashSet, HashMap};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::mpsc;
use std::thread;
use std::sync::{Arc, Barrier};
use time;

use cipher::*;
use filter::*;
use graph_search::MultistageGraph;
use single_round::{SortedApproximations, AppType};
use utility::ProgressBar;


fn get_vertices (
    approximations: &mut SortedApproximations, 
    rounds: usize, 
    filters: &Vec<Filter>) 
    -> MultistageGraph {
    // Block size is half of that described by current filter
    let block_size = filters[0].block_size() / 2;
    
    // Just generate all possible values
    /*if approximations.cipher.size() / block_size <= 16 {
        let size = 1 << (approximations.cipher.size() / block_size);
        return vec![(0..size).map(|x| (x as u64, x)).collect(); rounds+1];
    }*/

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
                let tmp = thread_approximations.sbox_patterns.iter().cloned().skip(t).step_by(num_threads).collect();
                thread_approximations.sbox_patterns = tmp;

                // Collect all alpha values allowed by filters
                let mut alpha_sets = vec![HashSet::new(); rounds];
                let mut progress_bar = ProgressBar::new(num_alpha);
                thread_approximations.set_type_alpha();

                for (approximation, _) in thread_approximations.into_iter() {
                    let alpha = if approximation.alpha == 0 {
                        continue
                    } else {
                        approximation.alpha
                    };

                    for r in 0..rounds {
                        if filters[r].check(alpha) {
                            alpha_sets[r].insert(compress(alpha, block_size));
                        }
                    }

                    progress_bar.increment();
                }

                barrier.wait();
                if t == 0 {
                    println!("");
                }

                // For the last round, collect all beta values
                let mut beta_sets = vec![HashSet::new(); rounds];
                let mut progress_bar = ProgressBar::new(num_beta);
                thread_approximations.set_type_beta();

                for (approximation, _) in thread_approximations.into_iter() {
                    let beta = if approximation.beta == 0 {
                        continue
                    } else {
                        approximation.beta
                    };

                    for r in 0..rounds {
                        if filters[r+1].check(beta) {
                            beta_sets[r].insert(compress(beta, block_size));
                        }
                    }
                    
                    progress_bar.increment();
                }
                
                result_tx.send((alpha_sets, beta_sets)).expect("Thread could not send result");
            });
        }
    });
    println!("");

    let mut vertex_sets = vec![HashSet::new(); rounds+1];
    {
        let mut alpha_sets = vec![HashSet::new(); rounds+1];
        let mut beta_sets = vec![HashSet::new(); rounds+1];

        for _ in 0..num_threads {
            let thread_result = result_rx.recv().expect("Main could not receive result");
            
            for (i, set) in thread_result.0.iter().enumerate() {
                alpha_sets[i] = alpha_sets[i].union(&set).cloned().collect();
            }

            for (i, set) in thread_result.1.iter().enumerate() {
                beta_sets[i] = beta_sets[i].union(&set).cloned().collect();
            }
        }

        vertex_sets[0] = alpha_sets[0].clone();
        vertex_sets[rounds] = beta_sets[rounds-1].clone();

        for i in 1..rounds {
            vertex_sets[i] = alpha_sets[i].intersection(&beta_sets[i-1]).cloned().collect();
        }
    }

    // Create graph from vertex sets
    let mut graph = MultistageGraph::new(rounds+1);

    for i in 0..rounds+1 {
        for &label in &vertex_sets[i] {
            graph.add_vertex(i, label as usize);
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

fn add_middle_edges(
    graph: &MultistageGraph,
    approximations: &mut SortedApproximations, 
    rounds: usize, 
    block_size: usize)
    -> MultistageGraph {
    if block_size < approximations.cipher.sbox().size {
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
                let tmp = thread_approximations.sbox_patterns.iter().cloned().skip(t).step_by(num_threads).collect();
                thread_approximations.sbox_patterns = tmp;

                // Collect edges
                let mut edges = HashMap::new();

                for (approximation, _) in thread_approximations.into_iter() {    
                    let alpha = compress(approximation.alpha, block_size) as usize;
                    let beta = compress(approximation.beta, block_size) as usize;
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

/* Creates a linear hull graph, compressing the approximations with the specified block_size. 
 *
 * approximations   Approximations to use.
 * rounds           Number of rounds.
 * block_size       Block size of the compression.
 * vertex_maps      Map of the allowed mask values.
 */ 
fn add_outer_edges (
    graph: &MultistageGraph,
    approximations: &mut SortedApproximations, 
    rounds: usize, 
    block_size: usize) 
    -> MultistageGraph {
    if block_size < approximations.cipher.sbox().size {
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
                let tmp = thread_approximations.sbox_patterns.iter().cloned().skip(t).step_by(num_threads).collect();
                thread_approximations.sbox_patterns = tmp;

                // Add edges
                let mut edges = HashMap::new();

                for (approximation, _) in thread_approximations.into_iter() {    
                    let alpha = compress(approximation.alpha, block_size) as usize;
                    let beta = compress(approximation.beta, block_size) as usize;
                    let length = -approximation.value.log2();

                    // First round                    
                    if graph.get_vertex(0, alpha).is_some() && 
                       graph.get_vertex(1, beta).is_some() {
                        let vertex_ref = graph.get_vertex(1, beta).unwrap();

                        if rounds == 2 || vertex_ref.successors.len() != 0 {
                            edges.insert((0, alpha, beta), length);
                        }
                    }

                    // Last round
                    if graph.get_vertex(rounds-1, alpha).is_some() && 
                       graph.get_vertex(rounds, beta).is_some() {
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
        add_edges(&mut base_graph, &thread_result);
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
    filters: &mut Vec<Filter>, 
    graph: &MultistageGraph) 
    -> usize {
    let stages = graph.stages();
    let mut good_vertices = 0;

    for stage in 0..stages {
        filters[stage].add_layer();
        let stage_len = graph.stage_len(stage);

        for (alpha, vertex_ref) in graph.get_stage(stage).unwrap() {
            // let vertex_ref = graph.get_vertex(stage, vertex).unwrap();
                    
            if vertex_ref.successors.len() != 0 || vertex_ref.predecessors.len() != 0 {
                // let alpha = *vertex_maps[stage].get_by_right(&vertex).unwrap();
                filters[stage].add_plain_value(*alpha as u64);
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
    filters: &Vec<Filter>, 
    approximations: &mut SortedApproximations) {
    let mut good_patterns = vec![false; approximations.len_patterns()];
    approximations.set_type_alpha();
    let block_size = filters[0].block_size();

    // If the block size is less than the pattern resolution, we need to iterate
    // over the alpha values
    if block_size < approximations.cipher.sbox().size {
        for (approximation, pattern_idx) in approximations.into_iter() {
            let alpha = approximation.alpha;
            let good = filters.iter().fold(false, |acc, ref x| acc | x.check(alpha));
            good_patterns[pattern_idx] |= good;
        }
    // Otherwise we convert each pattern to a value
    } else {
        let sbox_size = approximations.cipher.sbox().size;
        let balance = (1 << (sbox_size - 1)) as i16;
        
        for (pattern_idx, pattern) in approximations.sbox_patterns.iter().enumerate() {
            let mut activity = 0;

            for (i, &(bias, _)) in pattern.pattern.iter().enumerate() {
                if bias != balance {
                    activity ^= 1 << (i*sbox_size);
                }
            }

            let good = filters.iter().fold(false, |acc, ref x| acc | x.check(activity));
            good_patterns[pattern_idx] |= good;
        }
    }

    // Keep only good patterns
    let mut new_patterns = vec![];

    for (i, keep) in good_patterns.iter().enumerate() {
        if *keep {
            new_patterns.push(approximations.sbox_patterns[i].clone());
        }
    }

    approximations.sbox_patterns = new_patterns;
    approximations.set_type_all();
}

fn get_graph_stats(graph: &MultistageGraph) {
    let stages = graph.stages();

    for i in 0..stages {
        let stage_len = graph.stage_len(i);
        let mut edges = 0;

        for j in 0..stage_len {
            edges += graph.get_vertex(i,j).unwrap().successors.len();
        }

        println!("Stage {} has {} vertices and {} edges", i, stage_len, edges);
    }
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
    let start_block_size = 16;
    let mut filters = vec![Filter::new(start_block_size); rounds+1];
    let mut graph = MultistageGraph::new(0);
    let levels = (start_block_size as f64).log2() as usize; 

    for r in 0..levels {
        let block_size = filters[0].block_size() / 2;

        approximations.set_type_all();
        let num_app = approximations.len();
        approximations.set_type_alpha();
        let num_alpha = approximations.len();
        approximations.set_type_beta();
        let num_beta = approximations.len();

        println!("{} approximations ({} alpha, {} beta).", num_app, num_alpha, num_beta);
        println!("Block size: {} bits.", block_size);

        let start = time::precise_time_s();
        graph = get_vertices(&mut approximations, rounds, &filters);
        println!("Added vertices [{} s]", time::precise_time_s()-start);

        let start = time::precise_time_s();
        graph = add_middle_edges(&graph, &mut approximations, rounds, block_size);
        println!("Graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), 
            graph.num_edges(),
            time::precise_time_s()-start);

        // get_graph_stats(&graph);

        let start = time::precise_time_s();
        if rounds > 2 {
            prune_graph(&mut graph, 1, rounds);
        }
        println!("Pruned graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), 
            graph.num_edges(), 
            time::precise_time_s()-start);

        // get_graph_stats(&graph);
        /*let mut name = String::from("test_before");
        name.push_str(&r.to_string());
        print_to_graph_tool(&graph, &name);*/

        let start = time::precise_time_s();
        graph = add_outer_edges(&mut graph, &mut approximations, rounds, block_size);
        println!("Graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), 
            graph.num_edges(),
            time::precise_time_s()-start);

        // get_graph_stats(&graph);
        /*let mut name = String::from("test_after");
        name.push_str(&r.to_string());
        print_to_graph_tool(&graph, &name);*/

        let start = time::precise_time_s();
        prune_graph(&mut graph, 0, rounds+1);
        println!("Pruned graph has {} vertices and {} edges [{} s]", 
            graph.num_vertices(), 
            graph.num_edges(), 
            time::precise_time_s()-start);
        // get_graph_stats(&graph);

        if r != levels - 1 {
            let start = time::precise_time_s();
            let good_vertices = update_filters(&mut filters, &graph);
            println!("Number of good vertices: {} [{} s]", 
                good_vertices,
                time::precise_time_s()-start);

            let start = time::precise_time_s();
            let patterns_before = approximations.len_patterns();
            remove_dead_patterns(&filters, &mut approximations);
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
        let stage_len = graph.stage_len(i);

        for (j, _) in graph.get_stage(i).unwrap() {
            write!(file, "{},{}\n", i, j);
        }
    }        

    for i in 0..stages-1 {
        for (j, vertex_ref) in graph.get_stage(i).unwrap() {
            for (k, _) in &vertex_ref.successors {
                write!(file, "{},{},{},{}\n", i, j, i+1, k);       
            }
        }
    }   
}