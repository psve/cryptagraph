#![feature(iterator_step_by)]

extern crate time;
extern crate structopt;
#[macro_use] extern crate structopt_derive;
extern crate rand;
extern crate num_cpus;
extern crate crossbeam_utils;
extern crate min_max_heap;

mod cipher;
mod utility;
mod single_round;
mod approximation;
mod find_paths;
mod options;
mod bloom;

use cipher::*;
use single_round::{SortedApproximations, AppType};
use options::CliArgs;
use structopt::StructOpt;
use std::io::Write;
use std::fs::OpenOptions;
use std::collections::HashSet;
use utility::ProgressBar;
use std::thread;
use std::sync::mpsc;

/* Lists the number ranges of patterns with different correlation values. 
 *
 * cipher   The cipher to investigate.
 */
fn list_pattern_ranges(cipher: &(Cipher + Sync)) {
    let patterns = SortedApproximations::new(cipher.clone(), usize::max_value(), AppType::All);
    let mut output: Vec<(f64, (usize, usize))> = patterns.range_map.iter()
                                       .map(|(&k, &v)| (f64::from_bits(k).log2(), v))
                                       .collect();
    output.sort_by(|&(a, _), &(b, _)| (b.floor() as i64).cmp(&(a.floor() as i64)));

    for (k,v) in output {
        println!("{:?}: {:?}", k, v);
    }
}

/* Performs the hull set search. 
 *
 * cipher                   The cipher to investigate.
 * rounds                   The number of rounds.
 * pattern_add              The number of single round S-box patterns to add in each pruning round.
 * pruning_rounds           Number of rounds to perform pruning. 
 * false_positive           The false positive rate to use for Bloom filters.
 * file_name                File name prefix to use for output. 
 */
fn run_search
    (cipher: &(Cipher + Sync), rounds: usize, pattern_add: usize, pruning_rounds: usize,
     false_positive: f64, file_name: Option<String>) {
    println!("Searching through hulls with varying input mask.");
    println!("\tCipher: {}.", cipher.name());
    println!("\tRounds: {}.", rounds);
    println!("\tAdding at most {} S-box patterns.", pattern_add);
    println!("\tPruning over {} rounds.", pruning_rounds);
    println!("\tUsing {} false positive rate.", false_positive);

    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();

    let start = time::precise_time_s();
    let (single_round_map, input_masks) = 
        find_paths::generate_single_round_map(cipher, rounds, pattern_add, 
                                              pruning_rounds, false_positive);
    
    // Dump union of all hull sets if path is specified
    match file_name {
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
    
    let mut result = vec![];
    let num_keep = 100;
    let mut min_correlation = 1.0_f64;
    let mut num_found = 0;
    
    println!("\nFinding linear hulls ({} input masks):", input_masks.len());

    for t in 0..num_threads {
        let input_masks = input_masks.clone();
        let single_round_map = single_round_map.clone();
        let result_tx = result_tx.clone();

        thread::spawn(move || {
            let mut result = vec![];
            let mut progress_bar = ProgressBar::new(input_masks.len());

            for &alpha in input_masks.iter().skip(t).step_by(num_threads) {
                let edge_map = find_paths::find_paths(&single_round_map, rounds, alpha);
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

    result.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    result.truncate(num_keep);
    result.remove(0);

    let stop = time::precise_time_s();

    println!("\n\nSearch finished. [{} s]", stop-start);
    println!("Found {} approximations.", num_found);
    println!("Smallest squared correlation: {}", min_correlation.log2());
    println!("Largest squared correlation:  {}\n", result[0].2.log2());

    for &(ref approximation, num_paths, value) in &result {
        if approximation.alpha == 0 && approximation.beta == 0 {
            continue
        }

        print!("Approximation:   {:?} ", approximation);
        println!("[{}, {}]", num_paths, value.log2());
    }
}

fn main() {
    let options = CliArgs::from_args();

    match options.mode.as_ref() {
        "probe" => {
            let cipher = match name_to_cipher(options.cipher.as_ref()) {
                Some(c) => c,
                None    => panic!("Cipher must be one of: present, gift, twine, puffin, skinny, midori, led, rectangle, mibs")
            };

            list_pattern_ranges(cipher.as_ref());
        },
        "search" => {
            let rounds = options.rounds.expect("Number of rounds must be specified in this mode.");
            let pattern_add = options.pattern_add.expect("Pattern add must be specified in this mode.");
            let pruning_rounds = options.pruning_rounds.expect("Number of pruning rounds must be specified in this mode.");
            let false_positive = options.false_positive.expect("False positive rate must be specified in this mode.");
            let file_name = options.file_path;

            let cipher = match name_to_cipher(options.cipher.as_ref()) {
                Some(c) => c,
                None    => panic!("Cipher must be one of: present, gift, twine, puffin, skinny, midori, led, rectangle, mibs")
            };

            run_search(cipher.as_ref(), rounds, pattern_add, pruning_rounds, 
                       false_positive, file_name);
        },
        _ => {
            println!("Mode must be one of: search, probe");
        },
    }
}
    
