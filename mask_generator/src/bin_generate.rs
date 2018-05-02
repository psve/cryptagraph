#![feature(iterator_step_by)]

#[macro_use] extern crate lazy_static;
#[macro_use] extern crate smallvec;
#[macro_use] extern crate structopt_derive;

extern crate crossbeam_utils;
extern crate fnv;
extern crate indexmap;
extern crate num_cpus;
extern crate rand;
extern crate structopt;
extern crate time;

mod cipher;
mod find_hulls;
mod graph;
mod graph_generate;
mod multi_round;
mod options;
mod property;
mod single_round;
mod utility;

use cipher::*;
use options::CliArgs;
use structopt::StructOpt;

fn main() {
    let options = CliArgs::from_args();

    let cipher = match name_to_cipher(options.cipher.as_ref()) {
        Some(c) => c,
        None    => {
            println!("Cipher not supported. Check --help for supported ciphers.");
            return;
        }
    };

    let property_type = options.property_type;
    let rounds = options.rounds;
    let num_patterns = options.num_patterns;
    let file_mask_in = options.file_mask_in;
    let file_mask_out = options.file_mask_out;
    let file_graph = options.file_graph;


    println!("\tCipher: {}.", cipher.name());
    println!("\tRounds: {}.", rounds);
    println!("\tS-box patterns: {}\n", num_patterns);

    multi_round::find_approximations(cipher, property_type, rounds, num_patterns, 
                                     file_mask_in, file_mask_out, file_graph);
}
    
