use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use fnv::FnvHashMap;
use time;

use cipher::*;
use dist::correlations::get_correlations;

/**
Reads a file of allowed input and output values and stores them in a hash set. 
The values in the files are assumed to be in hexadecimals, without the '0x' prefix, and
input/output masks should be separated by a comma. 

file_mask_in        Path of the input file used.
*/
fn read_allowed(file_mask_in: &str) -> Vec<(u128, u128)> {
    let file = File::open(file_mask_in).expect("Could not open file.");
    let mut allowed = Vec::new();

    for line in BufReader::new(file).lines() {
        let s = line.expect("Error reading file");
        let split: Vec<_> = s.split(',').collect();
        let alpha = u128::from_str_radix(split.get(0).expect("Could not read input data"), 16)
                        .expect("Could not parse integer. Is it in hexadecimals?");
        let beta  = u128::from_str_radix(split.get(1).expect("Could not read input data"), 16)
                        .expect("Could not parse integer. Is it in hexadecimals?");
        allowed.push((alpha, beta));
    }

    allowed
}

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
    writeln!(file, "{}", line).expect("Could not write to file.");

    for j in 0..values.first().expect("Empty data set.").len() {
        let mut line = String::new();
        
        for v in &values {
            line.push_str(&format!("{},", v[j]));
        }
        line.pop();
        writeln!(file, "{}", line).expect("Could not write to file.");
    }
}

pub fn get_distributions(cipher: &dyn Cipher,
                         file_mask_in: &str,
                         rounds: usize,
                         keys: usize,
                         masks: &str,
                         output: &str) {
    let start = time::precise_time_s();
    
    // read mask files
    let masks = match load_masks(&masks) {
        Some(m) => m,
        None => panic!("failed to load mask set")
    };

    let allowed = read_allowed(file_mask_in);
    
    println!("Cipher: {}", cipher.name());
    println!("Properties masks: {}", allowed.len());
    println!("Intermediate masks: {}", masks.len());

    let mut correlations = get_correlations(cipher, &allowed, rounds, keys, &masks);

    // Remove approximations with zero correlation
    correlations.retain(|_, v| v.iter().fold(false, |acc, &x| acc | (x != 0.0)));

    let path = format!("{}.corrs", output);
    dump_correlations(&correlations, &path);

    println!("Generation finished. [{} s]", time::precise_time_s()-start);
}
