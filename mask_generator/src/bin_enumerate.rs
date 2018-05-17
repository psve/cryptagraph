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
use std::io::{BufRead, BufReader, Write};
use structopt::StructOpt;
use cipher::*;
use pool::MaskPool;
use utility::{parity, ProgressBar};

#[derive(Clone, StructOpt)]
#[structopt(name = "Hull Enumeration")]
pub struct CliArgs {
    #[structopt(short = "c", long = "cipher", help = "Name of cipher to analyse.")]
    pub cipher: String,

    #[structopt(short = "a", long = "alpha", help = "Input mask / parity (hex)")]
    pub alpha: String,

    #[structopt(short = "b", long = "beta", help = "Output masks (file path)")]
    pub beta: String,

    #[structopt(short = "r", long = "rounds", help = "Number of rounds to enumerate")]
    pub rounds: usize,

    #[structopt(short = "k", long = "keys", help = "Number of keys to enumerate")]
    pub keys: usize,

    #[structopt(short = "m", long = "masks", help = "Path to file of masks")]
    pub masks: String,

    #[structopt(short = "o", long = "output", help = "Pattern to save correlations: save.cipher.keys.input.output.corrs")]
    pub output: Option<String>,
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

    let alpha = u64::from_str_radix(&options.alpha, 16).unwrap();

    let betas = match load_masks(&options.beta) {
        Some(m) => m,
        None => panic!("failed to load mask set")
    };

    // resolve cipher name

    let cipher = match name_to_cipher(options.cipher.as_ref()) {
        Some(c) => c,
        None    => panic!("unsupported cipher")
    };

    println!("Target cipher: {}", cipher.name());

    match &options.output {
        Some(prefix) => println!("Saving results to {}.xyz.corr", prefix),
        None => println!("Results will not be saved!")
    };

    // calculate LAT for masks between rounds (cipher dependent)

    println!("Calculating full approximation table");

    let lat = analysis::MaskLAT::new(cipher.as_ref(), &masks);

    println!("{}");

    // construct pools

    let mut pool_old = MaskPool::new();
    let mut pool_new = MaskPool::new();

    println!("Enumerating keys");

    let mut rng = OsRng::new().unwrap();
    let mut key = vec![0; cipher.key_size() / 8];

    // open output files

    let mut outputs = vec![];
    for beta in &betas {
        outputs.push(
            File::create(
                match &options.output {
                    Some(prefix) => format!(
                        "{}.{}.{}.{:x}.{:x}.corrs",
                        prefix,
                        options.cipher,
                        options.keys,
                        alpha,
                        beta
                    ),
                    None => String::from("/dev/null")
                }
            ).unwrap()
        )
    }

    let round_keys = if cipher.whitening() {
        options.rounds + 1
    } else {
        options.rounds
    };

    let mut bar = ProgressBar::new(options.keys);

    for _ in 0..options.keys {

        bar.increment();

        // generate rounds keys

        rng.fill_bytes(&mut key);
        let keys = cipher.key_schedule(round_keys, &key);

        // initalize pool with chosen alpha

        pool_old.clear();
        pool_old.add(alpha);

        for round in 1..options.rounds {

            // "clock" all patterns one round

            pool::step(&lat, &mut pool_new, &pool_old, keys[round]);

            // check for early termination

            if pool_new.masks.len() == 0 {
                println!("pool empty :(");
                return;
            }

            // swap pools

            {
                let tmp  = pool_old;
                pool_old = pool_new;
                pool_new = tmp;
                pool_new.clear();
            }
        }


        for (i, beta) in betas.iter().enumerate() {

            let corr = match pool_old.masks.get(&beta) {
                Some(c) =>
                    if cipher.whitening() && parity(beta & keys[options.rounds]) == 1  {
                        - (*c)
                    } else {
                        *c
                    },
                None    => 0.0
            };

            outputs[i].write_fmt(format_args!("{:}\n", corr)).unwrap();
        }
    }
}
