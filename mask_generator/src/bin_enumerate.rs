extern crate structopt;
extern crate rand;

#[macro_use]
extern crate structopt_derive;

mod pool;
mod cipher;
mod utility;
mod analysis;
mod approximation;
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

fn main() {

    // parse options

    let options    = CliArgs::from_args();

    // read mask file

    let file      = File::open(options.masks).unwrap();
    let reader    = BufReader::new(&file);
    let mut masks = vec![];

    for line in reader.lines() {
        let line = line.unwrap();
        let mask = match u64::from_str_radix(&line, 16) {
            Ok(m)  => m,
            Err(e) => panic!("failed to parse mask")
        };
        masks.push(mask);
    }

    let alpha  = u64::from_str_radix(&options.input, 16).unwrap();
    let beta   = u64::from_str_radix(&options.output, 16).unwrap();

    let cipher = match name_to_cipher(options.cipher.as_ref()) {
        Some(c) => c,
        None    => panic!("unsupported cipher")
    };

    println!("{:x} {:x}", alpha, beta);
    println!("> calculating approximation table");

    let lat = analysis::MaskLAT::new(cipher.as_ref(), &masks);

    // construct pools

    let mut pool_old = MaskPool::new();
    let mut pool_new = MaskPool::new();

    println!("> enumerating keys");

    let mut rng = OsRng::new().unwrap();
    let mut key = vec![0; cipher.key_size() / 8];

    for k in 0..options.keys {

        // generate rounds keys

        rng.fill_bytes(&mut key);
        let keys = cipher.key_schedule(options.rounds, &key);

        // initalize pool with chosen alpha

        pool_old.init(alpha);

        for rkey in keys.iter() {

            // "clock" all patterns one round

            pool::step(&lat, &mut pool_new, &pool_old, *rkey);

            // swap pools

            {
                let tmp  = pool_old;
                pool_old = pool_new;
                pool_new = tmp;
            }

            // check for early termination

            if pool_old.masks.len() == 0 {
                println!("pool empty :(");
                return;
            }
        }

        println!("{:}", match pool_old.masks.get(&beta) {
            Some(c) => *c,
            None    => 0.0
        });
    }

    /*
    for (k, v) in pool_old.masks.iter() {
        println!("{:x} {:}", k, v);
    }
    */
}
