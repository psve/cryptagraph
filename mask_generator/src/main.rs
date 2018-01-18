extern crate time;
extern crate structopt;
#[macro_use] extern crate structopt_derive;
extern crate bloom_filter;

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
use std::io::Write;
use std::fs::OpenOptions;
use std::collections::HashSet;

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

/* Performs the hull set search. 
 *
 * cipher                   The cipher to investigate.
 * rounds                   The number of rounds.
 * pattern_limit            The maximum number of single round S-box patterns to generate.
 */
fn run_search<T: Cipher + Clone>
    (cipher: T, rounds: usize, pattern_limit: usize, false_positive: f64, file_name: Option<String>) {
    println!("Searching through hulls with varying input mask.");
    println!("\tCipher: {}.", cipher.name());
    println!("\tRounds: {}.", rounds);
    println!("\tGenerating at most {} S-box patterns.\n", pattern_limit);

    let start = time::precise_time_s();
    let single_round_map = find_paths::generate_single_round_map(&cipher, rounds, pattern_limit, false_positive);
    let edge_map = find_paths::find_paths(&single_round_map, rounds);
    let stop = time::precise_time_s();

    let mut result: Vec<_> = edge_map.map.iter().collect();
    result.sort_by(|a, b| b.1.approximation.value.partial_cmp(&a.1.approximation.value).unwrap());
    result.remove(0);

    println!("\n\nSearch finished. [{} s]", stop-start);
    println!("Found {} approximations.", edge_map.map.len());
    println!("Smallest squared correlation: {}", result[result.len()-1].1.approximation.value.log2());
    println!("Largest squared correlation:  {}\n", result[0].1.approximation.value.log2());


    for &(approximation, edge) in result.iter().take(100) {
        if approximation.alpha == 0 && approximation.beta == 0 {
            continue
        }

        println!("Approximation:   {:?}", approximation);
        /*print!("Linear hull set: {{");

        let mut sorted_set: Vec<u64> = edge.masks.iter().map(|x| *x).collect();
        sorted_set.sort();
        
        for &mask in &sorted_set {
            print!("{:016x} ", mask);
        }
        println!("}} [{}, {}]\n", edge.num_paths, edge.approximation.value.log2());*/
        println!("[{}, {}]\n", edge.num_paths, edge.approximation.value.log2());
    }

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
                "led"  => {
                    let cipher = Led::new();
                    list_pattern_ranges(cipher);
                },
                "rectangle"  => {
                    let cipher = Rectangle::new();
                    list_pattern_ranges(cipher);
                },
                _ => {
                    println!("Cipher must be one of: present, gift, twine, puffin, skinny, midori, led, rectangle");
                }
            };
        },
        "search" => {
            let rounds = options.rounds.expect("Number of rounds must be specified in this mode.");
            let pattern_limit = options.pattern_limit.expect("Pattern limit must be specified in this mode.");
            let false_positive = options.false_positive.expect("False positive rate must be specified in this mode.");
            let file_name = options.file_path;

            match options.cipher.as_ref() {
                "present" => {
                    let cipher = Present::new();
                    run_search(cipher, rounds, pattern_limit, false_positive, file_name);
                },
                "gift"    => {
                    let cipher = Gift::new();
                    run_search(cipher, rounds, pattern_limit, false_positive, file_name);
                },
                "twine"   => {
                    let cipher = Twine::new();
                    run_search(cipher, rounds, pattern_limit, false_positive, file_name);
                },
                "puffin"  => {
                    let cipher = Puffin::new();
                    run_search(cipher, rounds, pattern_limit, false_positive, file_name);
                },
                "skinny"  => {
                    let cipher = Skinny::new();
                    run_search(cipher, rounds, pattern_limit, false_positive, file_name);
                },
                "midori"  => {
                    let cipher = Midori::new();
                    run_search(cipher, rounds, pattern_limit, false_positive, file_name);
                },
                "led"  => {
                    let cipher = Led::new();
                    run_search(cipher, rounds, pattern_limit, false_positive, file_name);
                },
                "rectangle"  => {
                    let cipher = Rectangle::new();
                    run_search(cipher, rounds, pattern_limit, false_positive, file_name);
                },
                _ => {
                    println!("Cipher must be one of: present, gift, twine, puffin, skinny, midori, led, rectangle");
                }
            };
        },
        _ => {
            println!("Mode must be one of: search, probe");
        },
    }
}
    
