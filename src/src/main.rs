#![feature(iterator_step_by)]

#[macro_use] extern crate lazy_static;
#[macro_use] extern crate smallvec;
#[macro_use] extern crate structopt_derive;

extern crate crossbeam_utils;
extern crate fnv;
extern crate indexmap;
extern crate itertools;
extern crate num_cpus;
extern crate rand;
extern crate structopt;
extern crate time;

mod cipher;
mod options;
mod property;
mod utility;
mod search;
mod dist;

use options::CryptagraphOptions;
use structopt::StructOpt;
use cipher::*;

fn main() {
    match CryptagraphOptions::from_args() {
        CryptagraphOptions::Search {cipher, 
                                    property_type, 
                                    rounds, 
                                    num_patterns, 
                                    anchors, 
                                    file_mask_in, 
                                    file_mask_out, 
                                    file_graph} => {
            
            let cipher = match name_to_cipher(cipher.as_ref()) {
                Some(c) => c,
                None    => {
                    println!("Cipher not supported. Check --help for supported ciphers.");
                    return;
                }
            };

            search::search::find_properties(cipher, property_type, rounds, num_patterns, anchors,
                                            file_mask_in, file_mask_out, file_graph);
        },
        CryptagraphOptions::Dist {cipher,
                                  file_mask_in,
                                  rounds,
                                  keys,
                                  masks,
                                  output} => {
            
            let cipher = match name_to_cipher(cipher.as_ref()) {
                Some(c) => c,
                None    => {
                    println!("Cipher not supported. Check --help for supported ciphers.");
                    return;
                }
            };

            dist::dist::get_distributions(cipher, file_mask_in, rounds, keys, masks, output);
        }
    }
}
    
