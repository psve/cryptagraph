//! Types and functions for calculating linear correlations.

use crossbeam_utils;
use fnv::FnvHashMap;
use num_cpus;
use std::sync::mpsc;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::cipher::{Cipher, CipherStructure};
use crate::property::Property;
use crate::utility::{parity, ProgressBar};

/// Part of a linear approximation table for an entire round function of a cipher.
#[derive(Clone)]
struct MaskLat {
    map_input: FnvHashMap<u128, Vec<Property>>,
}

impl MaskLat {
    /// Takes an LAT of a component function and computes the correlation of parities over the
    /// bricklayer function.
    #[inline(always)]
    fn correlation(cipher: &dyn Cipher, input: u128, output: u128) -> f64 {
        let mut value = 1.0;
        let mut input = input;
        let mut output = output;

        let w_in = cipher.sbox(0).size_in();
        let w_out = cipher.sbox(0).size_out();
        let m_in = (1 << w_in) - 1;
        let m_out = (1 << w_out) - 1;
        let values = f64::from(1 << cipher.sbox(0).size_in());

        for i in 0..cipher.num_sboxes() {
            let hits = cipher.sbox(i).lat()[(input & m_in) as usize][(output & m_out) as usize];
            let c = 2.0 * ((hits as f64) / values) - 1.0;
            value *= c;

            output >>= w_out;
            input >>= w_in;
        }

        debug_assert_eq!(output, 0);
        debug_assert_eq!(input, 0);

        value
    }

    /// Constructs a Lat over the bricklayer function for the particular set of parities.
    fn new(cipher: &dyn Cipher, masks: &[u128]) -> MaskLat {
        /* Assuming SPN; compute possible "outputs" for input set
         *
         * Alpha ^ Key Addition -> Substitution -> Linear
         *
         * We move backwards to obtain:
         *
         * Alpha ^ Key Addition -> Substitution ^ Beta <- Linear <- Alpha
         */
        let mut outputs = vec![];

        for input in masks {
            let output = cipher.linear_layer_inv(*input);
            assert_eq!(cipher.linear_layer(output), *input);
            outputs.push(output);
        }

        // construct full mask lat
        let mut mlat = MaskLat {
            map_input: FnvHashMap::default(),
        };

        for input in masks {
            mlat.map_input.insert(*input, vec![]);
        }

        let mut progress_bar = ProgressBar::new(masks.len());

        for &input in masks {
            progress_bar.increment();
            for &output in &outputs {
                let value = MaskLat::correlation(cipher, input, output);

                if value * value > 0.0 {
                    let vector = mlat.map_input.get_mut(&input).expect("Error 1");
                    /* NOTE:
                     *   Applies linear layer to output
                     *   to speed up computation of
                     *   new maskset (subset of Alpha)
                     */
                    let output = cipher.linear_layer(output);
                    vector.push(Property {
                        input,
                        output,
                        value,
                        trails: 1,
                    });
                }
            }
        }

        mlat
    }

    /// Inverts the current LAT
    fn invert(&mut self) {
        let mut inverse = FnvHashMap::default();

        for v in self.map_input.values() {
            for p in v {
                let inverse_property = Property {
                    input: p.output,
                    output: p.input,
                    value: p.value,
                    trails: p.trails,
                };

                let entry = inverse
                    .entry(inverse_property.input)
                    .or_insert_with(Vec::new);
                entry.push(inverse_property);
            }
        }

        self.map_input = inverse;
    }

    /// Gets any outputs matching a specific input.
    fn lookup_input(&self, a: u128) -> Option<&Vec<Property>> {
        self.map_input.get(&a)
    }
}

/// A collection of approximations over a number of rounds as well as their correlation.
#[derive(Clone)]
struct MaskPool {
    masks: FnvHashMap<(u128, u128), f64>,
}

impl MaskPool {
    /// Create a new empty pool.
    fn new() -> MaskPool {
        MaskPool {
            masks: FnvHashMap::default(),
        }
    }

    /// Add a new approximation over "zero" rounds.
    fn add(&mut self, mask: u128) {
        self.masks.insert((mask, mask), 1.0);
    }

    /// Extend the current set by one round given an LAT and a round key.
    fn step(&mut self, lat: &MaskLat, key: u128) {
        let mut pool_new = FnvHashMap::default();

        // propergate mask set
        for ((input, output), value) in &self.masks {
            if let Some(approximations) = lat.lookup_input(*output) {
                for approx in approximations {
                    let sign = if parity(approx.output & key) == 1 {
                        -1.0
                    } else {
                        1.0
                    };
                    let delta = sign * (approx.value * value);

                    // add relation to accumulator
                    let acc = match pool_new.get(&(*input, approx.output)) {
                        None => delta,
                        Some(c) => delta + c,
                    };

                    // write back to pool
                    pool_new.insert((*input, approx.output), acc);
                }
            }
        }

        self.masks = pool_new;
    }
}

/// Calculates key dependent correlations for a set of intermediate masks and keys.
///
/// # Parameters
/// * `cipher`: The cipher to calculate correlations for.
/// * `allowed`: A set of allowed input-output pairs. All other approximations are ignored.
/// * `rounds`: Number of rounds to calculate correlations for.
/// * `num_keys`: Number of master keys to generation correlations for.
/// * `masks`: A set of intermediate masks to use when generating trails.
pub fn get_correlations(
    cipher: &dyn Cipher,
    allowed: &[(u128, u128)],
    rounds: usize,
    num_keys: usize,
    masks: &[u128],
) -> FnvHashMap<(u128, u128), Vec<f64>> {
    // calculate LAT for masks between rounds (cipher dependent)
    println!("Calculating full approximation table.");
    let lat = MaskLat::new(cipher, masks);

    // Calculate the inverse LAT in case of Prince-like ciphers
    let mut lat_inv = lat.clone();
    lat_inv.invert();

    println!("Generating correlations.");

    // Generate keys
    let mut keys = vec![vec![0; cipher.key_size() / 8]; num_keys];

    for mut k in &mut keys {
        OsRng.fill_bytes(&mut k);
    }

    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    crossbeam_utils::thread::scope(|scope| {
        for t in 0..num_threads {
            let result_tx = result_tx.clone();
            let keys = keys.clone();
            let lat = lat.clone();
            let lat_inv = lat_inv.clone();

            scope.spawn(move |_| {
                let mut pool = MaskPool::new();
                let mut thread_result = FnvHashMap::default();
                let mut progress_bar =
                    ProgressBar::new((0..num_keys).skip(t).step_by(num_threads).len());

                let rounds = if cipher.structure() == CipherStructure::Prince {
                    rounds - 1
                } else {
                    rounds
                };

                for k in (0..num_keys).skip(t).step_by(num_threads) {
                    // generate rounds keys
                    let mut round_keys = if cipher.structure() == CipherStructure::Prince {
                        cipher.key_schedule(rounds * 2, &keys[k])
                    } else {
                        cipher.key_schedule(rounds, &keys[k])
                    };

                    let whitening_key = if cipher.whitening() {
                        round_keys.remove(0)
                    } else {
                        0
                    };

                    for (alpha, _) in allowed {
                        // initalize pool with chosen alpha
                        pool.add(*alpha);
                    }

                    for &round_key in round_keys.iter().take(rounds) {
                        // for round in 0..rounds {
                        // "clock" all patterns one round
                        // pool.step(&lat, round_keys[round]);
                        pool.step(&lat, round_key);

                        // check for early termination
                        if pool.masks.is_empty() {
                            panic!("1: pool empty :(");
                        }
                    }

                    if cipher.structure() == CipherStructure::Prince {
                        // Handle reflection layer
                        pool.step(&lat, 0);

                        let mut pool_new = pool.clone();

                        for (k, &v) in &pool.masks {
                            let k_new = (k.0, cipher.reflection_layer(k.1));
                            pool_new.masks.insert(k_new, v);
                        }

                        pool.step(&lat_inv, round_keys[rounds]);

                        // Do remaining rounds
                        for &round_key in round_keys.iter().skip(rounds + 1) {
                            // for round in 0..rounds {
                            // "clock" all patterns one round
                            // pool.step(&lat_inv, round_keys[rounds+1+round]);
                            pool.step(&lat_inv, round_key);

                            // check for early termination
                            if pool.masks.is_empty() {
                                panic!("2: pool empty :(");
                            }
                        }
                    }

                    for (alpha, beta) in allowed {
                        let corr = match pool.masks.get(&(*alpha, *beta)) {
                            Some(c) => {
                                if cipher.whitening() && parity(*alpha & whitening_key) == 1 {
                                    -(*c)
                                } else {
                                    *c
                                }
                            }
                            None => 0.0,
                        };

                        let entry = thread_result
                            .entry((*alpha, *beta))
                            .or_insert_with(Vec::new);
                        entry.push(corr);
                    }

                    if t == 0 {
                        progress_bar.increment();
                    }
                }

                result_tx
                    .send(thread_result)
                    .expect("Thread could not send result");
            });
        }
    })
    .expect("Threads failed to join.");

    let mut result = FnvHashMap::default();

    for _ in 0..num_threads {
        let mut thread_result = result_rx.recv().expect("Main could not receive result");

        for (k, mut v) in &mut thread_result {
            let entry = result.entry(*k).or_insert_with(Vec::new);
            entry.append(&mut v);
        }
    }

    result
}
