extern crate time;
extern crate structopt;
#[macro_use] extern crate structopt_derive;
extern crate bloom;

mod cipher;
mod utility;
mod single_round;
mod approximation;
mod find_paths;
mod options;

use cipher::*;
use single_round::SortedApproximations;
use options::CliArgs;
use structopt::StructOpt;
use std::collections::HashSet;
use std::io::{self, Write};
use std::fs::OpenOptions;
use std::cmp;

/* Performs the hull set search for multiple input masks. The masks are searched in descending
 * order of their possible correlations over one round. 
 *
 * cipher                   The cipher to investigate.
 * rounds                   The number of rounds.
 * pattern_limit            The maximum number of single round S-box patterns to generate.
 * approximation_limit      The maximum number of single round approximations to generate.
 * last_round_limit         The maximum number of patterns to generate for the last round.
 * search_limit             The maximum number of approximations to search.
 */
fn run_search<T: Cipher + Clone>
    (cipher: T, rounds: usize, 
     pattern_limit: usize, approximation_limit: usize, last_round_limit: usize,
     search_limit: usize) {
    println!("Searching through hulls with varying input mask.");
    println!("\tCipher: {}.", cipher.name());
    println!("\tRounds: {}.", rounds);
    println!("\tGenerating at most {} S-box patterns.", pattern_limit);
    println!("\tConsidering at most {} single round approximations.", approximation_limit);
    println!("\tUsing at most {} last round patterns.", last_round_limit);
    println!("\tSearching at most {} input masks.\n", search_limit);

    let sorted_alphas = SortedApproximations::new(cipher.clone(), pattern_limit, true);
    let mut results = vec![];

    let single_round_map = 
        find_paths::generate_single_round_map(&cipher, pattern_limit, approximation_limit);
    let last_round_map = 
        find_paths::generate_last_round_map(&cipher, last_round_limit, approximation_limit, &single_round_map);
    let mut progress = 0;
    let mut percentage = 0;
    let search_limit = cmp::min(search_limit, sorted_alphas.len());

    let start = time::precise_time_s();
    for approximation in sorted_alphas {
        progress += 1;

        // Lazy progress bar. Make nicer at some point
        if progress > (search_limit / 100 * percentage) {
            print!("=");
            io::stdout().flush().ok().expect("Could not flush stdout");
            percentage += 1;
        }

        if progress >= search_limit {
            break
        }

        let alpha = approximation.alpha;
        let edge_map = find_paths::find_paths(&single_round_map, rounds-1, alpha);
        let edge_map = find_paths::last_round(&edge_map, &last_round_map, &single_round_map);
        let mut min_correlation = 1.0_f64;
        let mut max_correlation = 0.0_f64;

        if edge_map.map.len() > 0 {
            for (_, edge) in &edge_map.map {
                min_correlation = min_correlation.min(edge.approximation.value);
                max_correlation = max_correlation.max(edge.approximation.value);
            }

            results.push((alpha, max_correlation));
        }
    }
    let stop = time::precise_time_s();

    println!("\n\nSearch finished. [{} s]", stop-start);
    println!("Found approximations for {} input masks. Showing best correlation for each.\n", results.len());

    results.sort_by(|a, b| (b.1).partial_cmp(&a.1).unwrap());

    for i in 0..results.len() {
        println!("{:016x}: {}", results[i].0, results[i].1.log2());
    }
}

/* Finds the hull sets for a given input mask. 
 *
 * cipher                   The cipher to investigate.
 * rounds                   The number of rounds.
 * alpha                    The input mask to the first round.
 * pattern_limit            The maximum number of single round S-box patterns to generate.
 * approximation_limit      The maximum number of single round approximations to generate.
 * last_round_limit         The maximum number of patterns to generate for the last round.
 * file_name                If supplied, dumps the union of all hull sets to disk. 
 */
fn run_single<T: Cipher + Clone>
    (cipher: T, rounds: usize, alpha: u64, 
     pattern_limit: usize, approximation_limit: usize, last_round_limit: usize,
     file_name: Option<String>) {
    println!("Searching for hulls starting from a single input mask.");
    println!("\tCipher: {}.", cipher.name());
    println!("\tRounds: {}.", rounds);
    println!("\tInput mask: {:016x}.", alpha);
    println!("\tGenerating at most {} S-box patterns.", pattern_limit);
    println!("\tConsidering at most {} single round approximations.", approximation_limit);
    println!("\tUsing at most {} last round patterns.\n", last_round_limit);

    let single_round_map = 
        find_paths::generate_single_round_map(&cipher, pattern_limit, approximation_limit);
    let last_round_map = 
        find_paths::generate_last_round_map(&cipher, last_round_limit, approximation_limit, &single_round_map);
    let edge_map = find_paths::find_paths(&single_round_map, rounds-1, alpha);
    let edge_map = find_paths::last_round(&edge_map, &last_round_map, &single_round_map);
    
    let mut min_correlation = 1.0_f64;
    let mut max_correlation = 0.0_f64;
    let mut total_set = HashSet::new();

    if edge_map.map.len() > 0 {
        println!("Found {} approximations:\n", edge_map.map.len());

        for (approximation, edge) in &edge_map.map {
            min_correlation = min_correlation.min(edge.approximation.value);
            max_correlation = max_correlation.max(edge.approximation.value);

            println!("Approximation:   {:?}", approximation);
            print!("Linear hull set: {{");

            let mut sorted_set: Vec<u64> = edge.masks.iter().map(|x| *x).collect();
            sorted_set.sort();
            
            for &mask in &sorted_set {
                print!("{:016x} ", mask);

                if file_name.is_some() {
                    total_set.insert(mask);
                }
            }
            println!("}} [{}, {}]\n", edge.num_paths, edge.approximation.value.log2());
        }

        println!("Smallest squared correlation: {}", min_correlation.log2());
        println!("Largest squared correlation:  {}", max_correlation.log2());
    }

    // Dump union of all hull sets if path is specified
    match file_name {
        Some(path) => {
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
}

/* Lists the number ranges of patterns with different correlation values. 
 *
 * cipher   The cipher to investigate.
 */
fn list_pattern_ranges<T: Cipher + Clone>(cipher: T) {
    let patterns = SortedApproximations::new(cipher.clone(), usize::max_value(), false);
    let mut output: Vec<(f64, (usize, usize))> = patterns.range_map.iter()
                                       .map(|(&k, &v)| (f64::from_bits(k).log2(), v))
                                       .collect();
    output.sort_by(|&(a, _), &(b, _)| (b.floor() as i64).cmp(&(a.floor() as i64)));

    for (k,v) in output {
        println!("{:?}: {:?}", k, v);
    }
}

fn main() {
    let options = CliArgs::from_args();

    match options.mode.as_ref() {
        "probe" => {
            match options.cipher.as_ref() {
                "present" => {
                    let cipher = Present::new();
                    list_pattern_ranges(cipher);
                },
                "gift"    => {
                    let cipher = Gift::new();
                    list_pattern_ranges(cipher);
                },
                "twine"   => {
                    let cipher = Twine::new();
                    list_pattern_ranges(cipher);
                },
                "puffin"  => {
                    let cipher = Puffin::new();
                    list_pattern_ranges(cipher);
                },
                "skinny"  => {
                    let cipher = Skinny::new();
                    list_pattern_ranges(cipher);
                },
                "midori"  => {
                    let cipher = Midori::new();
                    list_pattern_ranges(cipher);
                },
                _ => {
                    println!("Cipher must be one of: present, gift, twine, puffin");
                }
            };
        },
        "single" => {
            let alpha = options.alpha.expect("Alpha must be specified in single mode!");
            let rounds = options.rounds.expect("Number of rounds must be specified in this mode.");
            let pattern_limit = options.pattern_limit.expect("Pattern limit must be specified in this mode.");;
            let approximation_limit = options.approximation_limit.expect("Approximation limit must be specified in this mode.");;
            let last_round_limit = options.last_round_limit.expect("Last round limit must be specified in this mode.");;
            let file_path = options.file_path;

            match options.cipher.as_ref() {
                "present" => {
                    let cipher = Present::new();
                    run_single(cipher, rounds, alpha, 
                               pattern_limit, approximation_limit, last_round_limit, 
                               file_path);
                },
                "gift"    => {
                    let cipher = Gift::new();
                    run_single(cipher, rounds, alpha, 
                               pattern_limit, approximation_limit, last_round_limit,
                               file_path);
                },
                "twine"   => {
                    let cipher = Twine::new();
                    run_single(cipher, rounds, alpha, 
                               pattern_limit, approximation_limit, last_round_limit,
                               file_path);
                },
                "puffin"  => {
                    let cipher = Puffin::new();
                    run_single(cipher, rounds, alpha, 
                               pattern_limit, approximation_limit, last_round_limit,
                               file_path);
                },
                "skinny"  => {
                    let cipher = Skinny::new();
                    run_single(cipher, rounds, alpha, 
                               pattern_limit, approximation_limit, last_round_limit,
                               file_path);
                },
                "midori"  => {
                    let cipher = Midori::new();
                    run_single(cipher, rounds, alpha, 
                               pattern_limit, approximation_limit, last_round_limit,
                               file_path);
                },
                _ => {
                    println!("Cipher must be one of: present, gift, twine, puffin");
                }
            };
        },
        "search" => {
            let rounds = options.rounds.expect("Number of rounds must be specified in this mode.");
            let pattern_limit = options.pattern_limit.expect("Pattern limit must be specified in this mode.");;
            let approximation_limit = options.approximation_limit.expect("Approximation limit must be specified in this mode.");;
            let last_round_limit = options.last_round_limit.expect("Last round limit must be specified in this mode.");;
            let search_limit = options.search_limit.expect("Search limit t be specified in this mode.");

            match options.cipher.as_ref() {
                "present" => {
                    let cipher = Present::new();
                    run_search(cipher, rounds, 
                               pattern_limit, approximation_limit, last_round_limit,
                               search_limit);
                },
                "gift"    => {
                    let cipher = Gift::new();
                    run_search(cipher, rounds, 
                               pattern_limit, approximation_limit, last_round_limit,
                               search_limit);
                },
                "twine"   => {
                    let cipher = Twine::new();
                    run_search(cipher, rounds, 
                               pattern_limit, approximation_limit, last_round_limit,
                               search_limit);
                },
                "puffin"  => {
                    let cipher = Puffin::new();
                    run_search(cipher, rounds, 
                               pattern_limit, approximation_limit, last_round_limit,
                               search_limit);
                },
                "skinny"  => {
                    let cipher = Skinny::new();
                    run_search(cipher, rounds, 
                               pattern_limit, approximation_limit, last_round_limit,
                               search_limit);
                },
                "midori"  => {
                    let cipher = Midori::new();
                    run_search(cipher, rounds, 
                               pattern_limit, approximation_limit, last_round_limit,
                               search_limit);
                },
                _ => {
                    println!("Cipher must be one of: present, gift, twine, puffin");
                }
            };
        },
        _ => {
            println!("Mode must be one of: single, search");
        },
    }
}
    
