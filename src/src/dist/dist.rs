use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use fnv::FnvHashMap;
use time;

use cipher::*;
use dist::correlations::get_correlations;

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

fn dump_correlations(correlations: &FnvHashMap<(u128, u128), Vec<f64>>,
                     path: &str) {
    let mut file = OpenOptions::new()
                               .write(true)
                               .truncate(true)
                               .create(true)
                               .open(path)
                               .expect("Could not open file.");

    let mut values = Vec::new();

    let mut line = String::new();
    for ((alpha, beta), corrs) in correlations.iter() {
        line.push_str(&format!("{:032x}_{:032x},", alpha, beta));
        values.push(corrs);
    }
    line.pop();
    write!(file, "{}\n", line).expect("Could not write to file.");

    for j in 0..values.first().expect("Empty data set.").len() {
        let mut line = String::new();
        
        for i in 0..values.len() {
            line.push_str(&format!("{},", values[i][j]));
        }
        line.pop();
        write!(file, "{}\n", line).expect("Could not write to file.");
    }
}

pub fn get_distributions(cipher: Box<Cipher>,
                         alpha: String,
                         beta: String,
                         rounds: usize,
                         keys: usize,
                         masks: String,
                         output: String) {
    let start = time::precise_time_s();
    
    // read mask files
    let masks = match load_masks(&masks) {
        Some(m) => m,
        None => panic!("failed to load mask set")
    };

    let alphas = match load_masks(&alpha) {
        Some(m) => m,
        None => panic!("failed to load mask set")
    };

    let betas = match load_masks(&beta) {
        Some(m) => m,
        None => panic!("failed to load mask set")
    };
    
    println!("Cipher: {}", cipher.name());
    println!("Input masks: {}", alphas.len());
    println!("Output masks: {}", betas.len());
    println!("Intermediate masks: {}", masks.len());

    let mut correlations = get_correlations(cipher.as_ref(), &alphas, &betas, rounds, keys, &masks);

    // Remove approximations with zero correlation
    correlations.retain(|_, v| v.iter().fold(false, |acc, &x| acc | (x != 0.0)));

    let path = format!("{}_r{}_{}.corrs", cipher.name(), rounds, output);
    dump_correlations(&correlations, &path);

    println!("Generation finished. [{} s]", time::precise_time_s()-start);
}
