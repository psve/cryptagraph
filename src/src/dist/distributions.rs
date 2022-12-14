//! Main functions for generating correlations distributions.

use fnv::FnvHashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::time::Instant;

use crate::cipher::*;
use crate::dist::correlations::get_correlations;

/// Reads a file of allowed input and output values and stores them in a hash set.  The values in
/// the files are assumed to be in hexadecimals, without the '0x' prefix, and input/output masks
/// should be separated by a comma.
fn read_allowed(file_mask_in: &str) -> Vec<(u128, u128)> {
    let file = File::open(file_mask_in).expect("Could not open file.");
    let mut allowed = Vec::new();

    for line in BufReader::new(file).lines() {
        let s = line.expect("Error reading file");
        let split: Vec<_> = s.split(',').collect();
        let alpha = u128::from_str_radix(split.get(0).expect("Could not read input data"), 16)
            .expect("Could not parse integer. Is it in hexadecimals?");
        let beta = u128::from_str_radix(split.get(1).expect("Could not read input data"), 16)
            .expect("Could not parse integer. Is it in hexadecimals?");
        allowed.push((alpha, beta));
    }

    allowed
}

/// Loads a set of intermediate masks from file. The values in the files are assumed to be in
/// hexadecimals, without the '0x' prefix.
fn load_masks(path: &str) -> Option<Vec<u128>> {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(&file);
    let mut masks = vec![];
    for line in reader.lines() {
        let line = line.unwrap();
        let mask = match u128::from_str_radix(&line, 16) {
            Ok(m) => m,
            Err(_) => return None,
        };
        masks.push(mask);
    }
    Some(masks)
}

/// Saves a set of correlations in a file. The file format is csv, and the headers have the form
/// `input_output`.
fn dump_correlations(correlations: &FnvHashMap<(u128, u128), Vec<f64>>, path: &str) {
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

/// Generates correlation distributions for a given cipher. The correlations are saved in a csv file
/// with the suffix '.corrs'. The headers have the form `input_output`.
///
/// # Parameters
/// * `cipher`: The cipher to calculate correlations for.
/// * `file_mask_in`: Path to a file containing allowed input-output masks.
/// * `rounds`: Number of rounds to calculate correlations for.
/// * `keys`: Number of master keys to generation correlations for.
/// * `masks`: Path to a file containing a set of intermediate masks used when generating trails.
/// * `output`: Prefix of the output file.
pub fn get_distributions(
    cipher: &dyn Cipher,
    file_mask_in: &str,
    rounds: usize,
    keys: usize,
    masks: &str,
    output: &str,
) {
    let start = Instant::now();

    // read mask files
    let masks = match load_masks(&masks) {
        Some(m) => m,
        None => panic!("failed to load mask set"),
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

    println!("Generation finished. [{:?} s]", start.elapsed().as_secs());
}
