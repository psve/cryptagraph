#![feature(iterator_step_by)]

#[macro_use] extern crate lazy_static;
#[macro_use] extern crate smallvec;
#[macro_use] extern crate structopt_derive;

extern crate structopt;
extern crate rand;
extern crate fnv;
extern crate crossbeam_utils;
extern crate indexmap;
extern crate num_cpus;
extern crate time;

macro_rules! debug {
    ($($arg:tt)*) => (if cfg!(debug_assertions) { println!($($arg)*) })
}

mod pool;
mod cipher;
mod utility;
mod analysis;
mod approximation;
mod find_properties;
mod graph;
mod graph_generate;
mod multi_round;
mod options;
mod property;
mod single_round;

use rand::{OsRng, Rng};
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use structopt::StructOpt;
use cipher::*;
use pool::MaskPool;

#[derive(Clone, StructOpt)]
#[structopt(name = "Hull Enumeration")]
pub struct CliArgs {
    #[structopt(short = "c", long = "cipher", help = "Name of cipher to analyse.")]
    pub cipher: String,

    #[structopt(short = "i", long = "input", help = "Input mask / parity (hex)")]
    pub input: String,

    #[structopt(short = "o", long = "output", help = "Output mask / parity (hex)")]
    pub output: String,

    #[structopt(short = "r", long = "rounds", help = "Number of rounds to enumerate")]
    pub rounds: usize,

    #[structopt(short = "k", long = "keys", help = "Number of keys to enumerate")]
    pub keys: usize,

    #[structopt(short = "m", long = "masks", help = "Path to file of masks")]
    pub masks: String,
}


fn load_masks(path : &str) -> Option<Vec<u64>> {
    let file      = File::open(path).unwrap();
    let reader    = BufReader::new(&file);
    let mut masks = vec![];
    for line in reader.lines() {
        let line = line.unwrap();
        let mask = match u64::from_str_radix(&line, 16) {
            Ok(m)  => m,
            Err(_) => return None,
        };
        masks.push(mask);
    };
    Some(masks)
}

fn main() {

    // parse options

    let options    = CliArgs::from_args();

    // read mask files

    let masks = match load_masks(&options.masks) {
        Some(m) => m,
        None => panic!("failed to load mask set")
    };

    let alphas = match load_masks(&options.input) {
        Some(m) => m,
        None => panic!("failed to load mask set")
    };

    let betas = match load_masks(&options.output) {
        Some(m) => m,
        None => panic!("failed to load mask set")
    };

    // resolve cipher name

    let cipher = match name_to_cipher(options.cipher.as_ref()) {
        Some(c) => c,
        None    => panic!("unsupported cipher")
    };

    // calculate LAT for masks between rounds (cipher dependent)

    println!("> calculating approximation table");

    let lat = analysis::MaskLAT::new(cipher.as_ref(), &masks);

    // construct pools

    let mut pool_old = MaskPool::new();
    let mut pool_new = MaskPool::new();

    println!("> enumerating keys");

    let mut rng = OsRng::new().unwrap();
    let mut key = vec![0; cipher.key_size() / 8];

    for _ in 0..options.keys {

        // generate rounds keys

        rng.fill_bytes(&mut key);
        let keys = cipher.key_schedule(options.rounds, &key);

        for key in &keys {
            debug!("Round-Key {:016x}", key);
        }

        // initalize pool with chosen alpha

        pool_old.clear();
        for alpha in &alphas {
            pool_old.add(*alpha);
        }

        for rkey in keys.iter() {

            // "clock" all patterns one round

            pool::step(&lat, &mut pool_new, &pool_old, *rkey);

            // check for early termination

            if pool_new.masks.len() == 0 {
                println!("pool empty :(");
                return;
            }

            // swap pools

            debug!("# {} {}", pool_old.size(), pool_new.size());

            {
                let tmp  = pool_old;
                pool_old = pool_new;
                pool_new = tmp;
                pool_new.clear();
            }

            debug!("# {} {}", pool_old.size(), pool_new.size());
        }

        for beta in &betas {
            match pool_old.masks.get(&beta) {
                Some(c) => println!("{:x} : {:}", beta, *c),
                None    => ()
            };

            debug!("> paths[{:x}] = {:}", beta, match pool_old.paths.get(&beta) {
                Some(c) => *c,
                None    => 0
            });
        }
    }
}
