extern crate time;
extern crate structopt;
#[macro_use] extern crate structopt_derive;
extern crate rand;

mod cipher;
mod utility;
mod single_round;
mod approximation;
mod find_paths;
mod options;
mod bloom;

use cipher::*;
use single_round::SortedApproximations;
use options::CliArgs;
use structopt::StructOpt;
use std::io::Write;
use std::fs::OpenOptions;
use std::collections::HashSet;
use utility::ProgressBar;

/* Lists the number ranges of patterns with different correlation values. 
 *
 * cipher   The cipher to investigate.
 */
fn list_pattern_ranges(cipher: &Cipher) {
    let patterns = SortedApproximations::new(cipher.clone(), usize::max_value(), false);
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
 * pattern_limit            The maximum number of single round S-box patterns to generate.
 */
fn run_search(cipher: &Cipher, rounds: usize, pattern_limit: usize, false_positive: f64, file_name: Option<String>) {
    println!("Searching through hulls with varying input mask.");
    println!("\tCipher: {}.", cipher.name());
    println!("\tRounds: {}.", rounds);
    println!("\tGenerating at most {} S-box patterns.\n", pattern_limit);

    let start = time::precise_time_s();
    let (single_round_map, input_masks) 
        = find_paths::generate_single_round_map(cipher, rounds, pattern_limit, false_positive);
    
    // Dump union of all hull sets if path is specified
    match file_name {
        Some(path) => {
            let mut total_set = HashSet::new();

            for (alpha, betas) in &single_round_map.map {
                total_set.insert(*alpha);

                for &(beta, _) in betas {
                    total_set.insert(beta);
                }
            }

            let mut file = OpenOptions::new()
                                       .write(true)
                                       .append(false)
                                       .create(true)
                                       .open(path)
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
    let mut progress_bar = ProgressBar::new(input_masks.len());

    for alpha in input_masks {
        let edge_map = find_paths::find_paths(&single_round_map, rounds, alpha);
        num_found += edge_map.map.len();

        for (a, b) in edge_map.map {
            result.push((a, b.0, b.1));
        }

        result.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
        min_correlation = min_correlation.min(result[result.len()-1].2);
        result.truncate(num_keep);

        progress_bar.increment();
    }
    let stop = time::precise_time_s();

    result.remove(0);

    println!("\n\nSearch finished. [{} s]", stop-start);
    println!("Found {} approximations.", num_found);
    println!("Smallest squared correlation: {}", min_correlation.log2());
    println!("Largest squared correlation:  {}\n", result[0].2.log2());

    for &(ref approximation, num_paths, value) in &result {
        if approximation.alpha == 0 && approximation.beta == 0 {
            continue
        }

        print!("Approximation:   {:?} ", approximation);
        println!("[{}, {}]\n", num_paths, value.log2());
    }
}

fn main() {
    let options = CliArgs::from_args();

    match options.mode.as_ref() {
        "probe" => {
            let cipher = match name_to_cipher(options.cipher.as_ref()) {
                Some(c) => c,
                None    => panic!("Cipher must be one of: present, gift, twine, puffin, skinny, midori, led, rectangle")
            };

            list_pattern_ranges(cipher.as_ref());
        },
        "search" => {
            let rounds = options.rounds.expect("Number of rounds must be specified in this mode.");
            let pattern_limit = options.pattern_limit.expect("Pattern limit must be specified in this mode.");
            let false_positive = options.false_positive.expect("False positive rate must be specified in this mode.");
            let file_name = options.file_path;

            let cipher = match name_to_cipher(options.cipher.as_ref()) {
                Some(c) => c,
                None    => panic!("Cipher must be one of: present, gift, twine, puffin, skinny, midori, led, rectangle")
            };

            run_search(cipher.as_ref(), rounds, pattern_limit, false_positive, file_name);
        },
        _ => {
            println!("Mode must be one of: search, probe");
        },
    }
}
    
