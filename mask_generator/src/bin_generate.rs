#![feature(iterator_step_by)]

extern crate time;
extern crate structopt;
#[macro_use] extern crate structopt_derive;
extern crate rand;
extern crate num_cpus;
extern crate crossbeam_utils;

mod cipher;
mod utility;
mod single_round;
mod multi_round;
mod approximation;
mod find_hulls;
mod options;
mod graph_search;
mod graph_generate;

use cipher::*;
use options::CliArgs;
use structopt::StructOpt;

/* Performs the hull set search. 
 *
 * cipher                   The cipher to investigate.
 * rounds                   The number of rounds.
 * pattern_add              The number of single round S-box patterns to add in each pruning round.
 * pruning_rounds           Number of rounds to perform pruning. 
 * false_positive           The false positive rate to use for Bloom filters.
 * file_name                File name prefix to use for output. 
 */
fn run_search(
    cipher: &Cipher, 
    rounds: usize, 
    num_patterns: usize, 
    file_name_mask: Option<String>,
    file_name_graph: Option<String>) {
    println!("\tCipher: {}.", cipher.name());
    println!("\tRounds: {}.", rounds);
    println!("\tS-box patterns: {}\n", num_patterns);

    multi_round::find_approximations(cipher, rounds, num_patterns, file_name_mask, file_name_graph);
}

fn main() {
    let options = CliArgs::from_args();

    let rounds = options.rounds.expect("Number of rounds must be specified in this mode.");
    let num_patterns = options.num_patterns.expect("Number of patterns must be specified in this mode.");
    let file_name_mask = options.file_name_mask;
    let file_name_graph = options.file_name_graph;

    let cipher = match name_to_cipher(options.cipher.as_ref()) {
        Some(c) => c,
        None    => panic!("Cipher must be one of: present, gift, twine, puffin, skinny, midori, led, rectangle, mibs")
    };

    run_search(cipher.as_ref(), rounds, num_patterns, file_name_mask, file_name_graph);
}
    
