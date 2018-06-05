use rand::{OsRng, RngCore};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use cipher::*;
use dist::pool::{MaskPool, step};
use dist::analysis::MaskLat;
use utility::{parity, ProgressBar};

fn load_masks(path : &str) -> Option<Vec<u128>> {
    let file      = File::open(path).unwrap();
    let reader    = BufReader::new(&file);
    let mut masks = vec![];
    for line in reader.lines() {
        let line = line.unwrap();
        let mask = match u128::from_str_radix(&line, 16) {
            Ok(m)  => m,
            Err(_) => return None,
        };
        masks.push(mask);
    };
    Some(masks)
}

pub fn get_distributions(cipher: Box<Cipher>,
                         alpha: String,
                         beta: String,
                         rounds: usize,
                         keys: usize,
                         masks: String,
                         output: Option<String>) {
    
    // parse options

    // let options    = CliArgs::from_args();

    // read mask files

    let masks = match load_masks(&masks) {
        Some(m) => m,
        None => panic!("failed to load mask set")
    };

    let alpha = u128::from_str_radix(&alpha, 16).unwrap();

    let betas = match load_masks(&beta) {
        Some(m) => m,
        None => panic!("failed to load mask set")
    };

    println!("Target cipher: {}", cipher.name());

    match &output {
        Some(prefix) => println!("Saving results to {}.xyz.corr", prefix),
        None => println!("Results will not be saved!")
    };

    // calculate LAT for masks between rounds (cipher dependent)

    println!("Calculating full approximation table");

    let lat = MaskLat::new(cipher.as_ref(), &masks);

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
                match &output {
                    Some(prefix) => format!(
                        "{}.{}.{}.{:x}.{:x}.corrs",
                        prefix,
                        cipher.name(),
                        keys,
                        alpha,
                        beta
                    ),
                    None => String::from("/dev/null")
                }
            ).unwrap()
        )
    }

    let mut bar = ProgressBar::new(keys);

    for _ in 0..keys {

        bar.increment();

        // generate rounds keys

        rng.fill_bytes(&mut key);
        let keys = cipher.key_schedule(rounds, &key);

        // initalize pool with chosen alpha

        pool_old.clear();
        pool_old.add(alpha);

        for round in 0..rounds {
            // "clock" all patterns one round

            step(&lat, &mut pool_new, &pool_old, keys[round]);

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
                    if cipher.whitening() && parity(beta & keys[rounds]) == 1  {
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
