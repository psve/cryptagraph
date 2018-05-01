#![feature(iterator_step_by)]

#[macro_use] extern crate lazy_static;
extern crate time;
extern crate structopt;
#[macro_use] extern crate structopt_derive;
extern crate rand;
extern crate num_cpus;
extern crate crossbeam_utils;
extern crate fnv;

mod cipher;
mod utility;
mod single_round;
mod multi_round;
mod property;
mod find_hulls;
mod options;
mod graph;
mod graph_generate;

use cipher::*;
use options::CliArgs;
use structopt::StructOpt;
use property::PropertyType;

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
    property_type: PropertyType,
    rounds: usize, 
    num_patterns: usize, 
    file_mask_in: Option<String>,
    file_mask_out: Option<String>,
    file_graph: Option<String>) {
    println!("\tCipher: {}.", cipher.name());
    println!("\tRounds: {}.", rounds);
    println!("\tS-box patterns: {}\n", num_patterns);

    multi_round::find_approximations(cipher, property_type, rounds, num_patterns, 
                                     file_mask_in, file_mask_out, file_graph);
}

fn main() {
    let options = CliArgs::from_args();

    let rounds = options.rounds;
    let property_type = options.property_type;
    let num_patterns = options.num_patterns;
    let file_mask_in = options.file_mask_in;
    let file_mask_out = options.file_mask_out;
    let file_graph = options.file_graph;

    let cipher = match name_to_cipher(options.cipher.as_ref()) {
        Some(c) => c,
        None    => panic!("Cipher must be one of: present, gift, twine, puffin, skinny, midori, led, rectangle, mibs")
    };

    run_search(cipher.as_ref(), property_type, rounds, num_patterns, 
               file_mask_in, file_mask_out, file_graph);
}
    
