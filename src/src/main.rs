//! Cryptagraph is a tool for finding linear approximations and differentials of block ciphers. 

#[macro_use] extern crate lazy_static;
#[macro_use] extern crate structopt_derive;

extern crate crossbeam_utils;
extern crate fnv;
extern crate indexmap;
extern crate itertools;
extern crate num_cpus;
extern crate rand;
extern crate structopt;
extern crate time;

mod options;
pub mod cipher;
pub mod dist;
pub mod property;
pub mod sbox;
pub mod search;
pub mod utility;

use crate::options::CryptagraphOptions;
use structopt::StructOpt;
use crate::cipher::*;

fn main() {
    match CryptagraphOptions::from_args() {
        CryptagraphOptions::Search {cipher, 
                                    property_type, 
                                    rounds, 
                                    num_patterns, 
                                    anchors, 
                                    file_mask_in, 
                                    file_mask_out, 
                                    num_keep,
                                    file_graph} => {
            
            let cipher = match name_to_cipher(cipher.as_ref()) {
                Some(c) => c,
                None    => {
                    println!("Cipher not supported. Check --help for supported ciphers.");
                    return;
                }
            };

            search::search_properties::search_properties(
                cipher.as_ref(), 
                property_type, 
                rounds, 
                num_patterns, 
                anchors,
                file_mask_in, 
                file_mask_out, 
                num_keep, 
                file_graph);
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

            dist::distributions::get_distributions(
                cipher.as_ref(), 
                &file_mask_in, 
                rounds, 
                keys, 
                &masks, 
                &output);
        }
    }
}
    
