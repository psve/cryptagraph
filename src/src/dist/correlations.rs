use crossbeam_utils;
use rand::{OsRng, RngCore};
use fnv::FnvHashMap;
use num_cpus;
use std::sync::mpsc;

use cipher::{Cipher, CipherStructure};
use property::Property;
use utility::{ProgressBar, parity};

/* Linear Approximation Table for entire round permutation
 *
 * The linear layer has been applied to the { output } set.
 */
#[derive(Clone)]
struct MaskLat {
    map_input: FnvHashMap<u128, Vec<Property>>,
}

impl MaskLat {
    /* Takes an LAT of a component function and
     * computes the correlation of parities over the bricklayer function.
     */
    #[inline(always)]
    fn correlation(cipher : &Cipher,
                   input  : u128,
                   output : u128) 
                   -> f64 {
        let mut value = 1.0;
        let mut input = input;
        let mut output = output;

        let w = cipher.sbox(0).size;
        let m = (1 << w) - 1;
        let values  = f64::from(1 << cipher.sbox(0).size);

        for i in 0..cipher.num_sboxes() {
            let hits = cipher.sbox(i).lat[(input & m) as usize][(output & m) as usize];
            let c = 2.0 * ((hits as f64) / values) - 1.0;
            value *= c;

            output  >>= w;
            input >>= w;
        }

        debug_assert_eq!(output, 0);
        debug_assert_eq!(input, 0);

        value
    }

    /* Constructs a Lat over the bricklayer function
     * for the particular set of parities
     */
    fn new(cipher : &Cipher, masks : &[u128]) -> MaskLat {
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
            map_input : FnvHashMap::default(),
        };

        for input in masks {
            mlat.map_input.insert(*input, vec![]);
        }

        let mut progress_bar = ProgressBar::new(masks.len());

        for &input in masks {
            progress_bar.increment();
            for &output in &outputs {
                let value = MaskLat::correlation(cipher, input, output);
                
                if value*value > 0.0 {
                    let vector = mlat.map_input.get_mut(&input).expect("Error 1");
                    /* NOTE:
                     *   Applies linear layer to output
                     *   to speed up computation of
                     *   new maskset (subset of Alpha)
                     */
                    let output = cipher.linear_layer(output);
                    vector.push(Property{
                        input,
                        output,
                        value,
                        trails : 1
                    });
                }
            }
        }

        mlat
    }

    fn invert(&mut self) {
        let mut inverse = FnvHashMap::default();

        for v in self.map_input.values() {
            for p in v {
                let inverse_property = Property {
                    input  : p.output,
                    output : p.input,
                    value  : p.value,
                    trails : p.trails
                };

                let entry = inverse.entry(inverse_property.input).or_insert_with(Vec::new);
                entry.push(inverse_property);
            }
        }

        self.map_input = inverse;
    }

    fn lookup_input(&self, a : u128) -> Option<&Vec<Property>> {
        self.map_input.get(&a)
    }
}


#[derive(Clone)]
struct MaskPool {
    masks: FnvHashMap<(u128, u128), f64>,
}

impl MaskPool {
    fn new() -> MaskPool {
        MaskPool{
            masks: FnvHashMap::default(),
        }
    }

    fn add(&mut self, mask: u128) {
        self.masks.insert((mask, mask), 1.0);
    }
    
    fn step(&mut self,
            lat: &MaskLat,
            key: u128) {
        let mut pool_new = FnvHashMap::default();

        // propergate mask set
        for ((input, output), value) in &self.masks {
            if let Some(approximations) = lat.lookup_input(*output) {
                for approx in approximations {
                    let sign   = if parity(approx.output & key) == 1 { -1.0 } else { 1.0 };
                    let delta = sign * (approx.value * value);

                    // add relation to accumulator
                    let acc  = match pool_new.get(&(*input, approx.output)) {
                        None    => delta,
                        Some(c) => delta + c
                    };

                    // write back to pool
                    pool_new.insert((*input, approx.output), acc);
                }
            }
        }

        self.masks = pool_new;
    }
}

pub fn get_correlations(cipher: &Cipher,
                        allowed: &[(u128, u128)],
                        rounds: usize,
                        num_keys: usize,
                        masks: &[u128])
                        -> FnvHashMap<(u128, u128), Vec<f64>> {
    // calculate LAT for masks between rounds (cipher dependent)
    println!("Calculating full approximation table.");
    let lat = MaskLat::new(cipher, masks);

    // Calculate the inverse LAT in case of Prince-like ciphers
    let mut lat_inv = lat.clone();
    lat_inv.invert();

    println!("Generating correlations.");
        
    // Generate keys
    let mut rng = OsRng::new().unwrap();
    let mut keys = vec![vec![0; cipher.key_size() / 8]; num_keys];

    for mut k in &mut keys {
        rng.fill_bytes(&mut k);
    }
    
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    crossbeam_utils::thread::scope(|scope| {
        for t in 0..num_threads {
            let result_tx = result_tx.clone();
            let keys = keys.clone();
            let mut lat = lat.clone();
            let mut lat_inv = lat_inv.clone();

            scope.spawn(move || {
                let mut pool = MaskPool::new();
                let mut thread_result = FnvHashMap::default();
                let mut progress_bar = ProgressBar::new((0..num_keys).skip(t).step_by(num_threads).len());
                
                let rounds = if cipher.structure() == CipherStructure::Prince {
                    rounds - 1
                } else {
                    rounds
                };

                for k in (0..num_keys).skip(t).step_by(num_threads) {

                    // generate rounds keys
                    let mut round_keys = if cipher.structure() == CipherStructure::Prince {
                        cipher.key_schedule(rounds*2, &keys[k])
                    } else {
                        cipher.key_schedule(rounds, &keys[k])
                    };

                    let whitening_key = if cipher.whitening() { round_keys.remove(0) } else { 0 };

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
                        for &round_key in round_keys.iter().skip(rounds+1) {
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
                            Some(c) =>
                                if cipher.whitening() && parity(*alpha & whitening_key) == 1  {
                                    - (*c)
                                } else {
                                    *c
                                },
                            None    => 0.0
                        };

                        let entry = thread_result.entry((*alpha, *beta)).or_insert_with(Vec::new);
                        entry.push(corr);
                    }

                    if t == 0 {
                        progress_bar.increment();
                    }
                }

                result_tx.send(thread_result).expect("Thread could not send result");
            });
        }
    });

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