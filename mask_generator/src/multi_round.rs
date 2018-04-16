use num_cpus;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::mpsc;
use std::thread;
use time;
use utility::ProgressBar;
use bimap::BiMap;

use cipher::Cipher;
use find_hulls::{find_hulls, SingleRoundMap};
use graph_generate::{generate_graph, print_to_graph_tool};
use approximation::Approximation;
use graph_search::MultistageGraph;

fn find_trails (
    cipher: &Cipher, 
    rounds: usize, 
    patterns: usize,
    file_name_graph: Option<String>) 
    -> (SingleRoundMap, HashSet<u64>) {
    let graph = generate_graph(cipher, rounds, patterns);
    
    match file_name_graph {
        Some(path) => {
            print_to_graph_tool(&graph, &path);
        },
        None => {}
    }
    
    let mut single_round_map = SingleRoundMap::new();
    let input_masks = graph.get_stage(0).unwrap().keys().map(|x| *x as u64).collect();
    let stages = graph.stages();

    for stage in 0..stages-1 {
        for (alpha, vertex_ref) in graph.get_stage(stage).unwrap() {
            for (beta, length) in &vertex_ref.successors {
                let app = Approximation::new(*alpha as u64, *beta as u64, Some(2.0f64.powf(-length)));
                single_round_map.insert(app);
            }
        }

        for (_, v) in single_round_map.map.iter_mut() {
            v.sort_by(|a, b| a.0.cmp(&b.0));
            v.dedup();
        }
    }
    
    (single_round_map, input_masks)
}

pub fn find_approximations(
    cipher: &Cipher, 
    rounds: usize, 
    patterns: usize,
    file_name_mask: Option<String>,
    file_name_graph: Option<String>) {
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();
    let start = time::precise_time_s();
    let mut result = vec![];
    let num_keep = 50;
    let mut min_correlation = 1.0_f64;
    let mut num_found = 0;
    let (single_round_map, input_masks) = find_trails (cipher, rounds, patterns, file_name_graph);

    // Dump union of all hull sets if path is specified
    match file_name_mask {
        Some(path) => {
            let mut file_app_path = path.clone();
            file_app_path.push_str(".app");
            let mut file_set_path = path.clone();
            file_set_path.push_str(".set");

            let mut file = OpenOptions::new()
                                       .write(true)
                                       .append(false)
                                       .create(true)
                                       .open(file_app_path)
                                       .expect("Could not open file.");

            let mut total_set = HashSet::new();

            for (alpha, betas) in &single_round_map.map {
                total_set.insert(*alpha);

                for &(beta, _) in betas {
                    total_set.insert(beta);

                    write!(file, "{:016x}, {:016x}\n", alpha, beta).expect("Could not write to file.");
                }
            }

            let mut file = OpenOptions::new()
                                       .write(true)
                                       .append(false)
                                       .create(true)
                                       .open(file_set_path)
                                       .expect("Could not open file.");
            
            for mask in &total_set {
                write!(file, "{:016x}\n", mask).expect("Could not write to file.");
            }
        },
        None => { }
    }
    
    println!("Finding linear hulls ({} input masks, {} approximations):", 
        input_masks.len(), single_round_map.len());
    let hull_start = time::precise_time_s();

    for t in 0..num_threads {
        let input_masks = input_masks.clone();
        let single_round_map = single_round_map.clone();
        let result_tx = result_tx.clone();

        thread::spawn(move || {
            let mut result = vec![];
            let mut progress_bar = ProgressBar::new(input_masks.len());

            for &alpha in input_masks.iter().skip(t).step_by(num_threads) {
                let edge_map = find_hulls(&single_round_map, rounds, alpha);
                num_found += edge_map.map.len();

                for (a, b) in &edge_map.map {
                    result.push((a.clone(), b.0, b.1));
                }

                result.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
                if result.len() > 0 {
                    min_correlation = min_correlation.min(result[result.len()-1].2);
                }
                result.truncate(num_keep);
                progress_bar.increment();
            }

            result_tx.send((result, min_correlation, num_found)).expect("Thread could not send result");
        });
    }

    for _ in 0..num_threads {
        let mut thread_result = result_rx.recv().expect("Main could not receive result");
        
        result.append(&mut thread_result.0);
        min_correlation = min_correlation.min(thread_result.1);
        num_found += thread_result.2;
    }

    println!("");

    result.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    result.truncate(num_keep);
    
    println!("\nFound {} approximations. [{} s]", num_found, time::precise_time_s()-hull_start);
    println!("Smallest squared correlation: {}", min_correlation.log2());
    println!("Largest squared correlation:  {}\n", result[0].2.log2());
    println!("Search finished. [{} s]", time::precise_time_s()-start);

    for &(ref approximation, num_paths, value) in &result {
        if approximation.alpha == 0 && approximation.beta == 0 {
            continue
        }

        print!("Approximation:   {:?} ", approximation);
        println!("[{}, {}]", num_paths, value.log2());
    }
}
