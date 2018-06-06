use crossbeam_utils::scoped;
use rand::{OsRng, RngCore};
use fnv::FnvHashMap;
use num_cpus;
use std::sync::mpsc;

use cipher::Cipher;
use property::Property;
use utility::{ProgressBar, parity};

/* Linear Approximation Table for entire round permutation
 *
 * The linear layer has been applied to the { output } set.
 */
#[derive(Clone)]
pub struct MaskLat {
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

        debug_assert_eq!(cipher.sbox(0).size * cipher.num_sboxes(), cipher.size());

        let w = cipher.sbox(0).size;
        let m = (1 << w) - 1;
        let values  = (1 << cipher.sbox(0).size) as f64;

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
    pub fn new(cipher : &Cipher, masks : &Vec<u128>) -> MaskLat {
        /* Assuming SPN; compute possible "outputs" for input set
         *
         * Alpha ^ Key Addition -> Substitution -> Linear
         *
         * We move backwards to obtain:
         *
         * Alpha ^ Key Addition -> Substitution ^ Beta <- Linear <- Alpha
         */
        let mut outputs = vec![];

        for input in masks.iter() {
            let output = cipher.linear_layer_inv(*input);
            assert_eq!(cipher.linear_layer(output), *input);
            outputs.push(output);
        }

        // construct full mask lat
        let mut mlat = MaskLat {
            map_input : FnvHashMap::default(),
        };

        for input in masks.iter() {
            mlat.map_input.insert(*input, vec![]);
        }

        let mut bar = ProgressBar::new(masks.len());

        for input in masks.iter() {
            bar.increment();
            for output in outputs.iter() {
                let value = MaskLat::correlation(cipher, *input, *output);
                
                if value*value > 0.0 {
                    let vector = mlat.map_input.get_mut(input).expect("Error 1");
                    /* NOTE:
                     *   Applies linear layer to output
                     *   to speed up computation of
                     *   new maskset (subset of Alpha)
                     */
                    let ninput = cipher.linear_layer(*output);
                    vector.push(Property{
                        input  : *input,
                        output : ninput,
                        value  : value,
                        trails : 1
                    });
                }
            }
        }

        mlat
    }

    pub fn lookup_input(&self, a : u128) -> Option<&Vec<Property>> {
        self.map_input.get(&a)
    }
}


#[derive(Clone)]
pub struct MaskPool {
    pub masks: FnvHashMap<(u128, u128), f64>,
}

impl MaskPool {
    pub fn new() -> MaskPool {
        MaskPool{
            masks: FnvHashMap::default(),
        }
    }

    pub fn add(&mut self, mask: u128) {
        self.masks.insert((mask, mask), 1.0);
    }
    
    pub fn step(&mut self,
                lat: &MaskLat,
                key: u128) {
        let mut pool_new = FnvHashMap::default();

        // propergate mask set
        for ((input, output), value) in &self.masks {
            let sign   = if parity(*output & key) == 1 { -1.0 } else { 1.0 };

            match lat.lookup_input(*output) {
                Some(approximations) => {
                    for approx in approximations {
                        debug_assert_eq!(approx.output, *output);

                        let delta = sign * (approx.value * value);

                        // add relation to accumulator
                        let acc  = match pool_new.get(&(*input, approx.output)) {
                            None    => delta,
                            Some(c) => delta + c
                        };

                        // write back to pool
                        pool_new.insert((*input, approx.output), acc);
                    }
                },
                None => {}
            }
        }

        self.masks = pool_new;
    }
}

pub fn get_correlations(cipher: &Cipher,
                        alphas: &Vec<u128>,
                        betas: &Vec<u128>,
                        rounds: usize,
                        num_keys: usize,
                        masks: &Vec<u128>)
                        -> FnvHashMap<(u128, u128), Vec<f64>> {
    // calculate LAT for masks between rounds (cipher dependent)
    println!("Calculating full approximation table.");
    let lat = MaskLat::new(cipher, &masks);

    println!("Generating correlations.");
        
    // Generate keys
    let mut rng = OsRng::new().unwrap();
    let mut keys = vec![vec![0; cipher.key_size() / 8]; num_keys];

    for mut k in keys.iter_mut() {
        rng.fill_bytes(&mut k);
    }
    
    let num_threads = num_cpus::get();
    let (result_tx, result_rx) = mpsc::channel();

    // Start scoped worker threads
    scoped::scope(|scope| {
        for t in 0..num_threads {
            let result_tx = result_tx.clone();
            let keys = keys.clone();
            let lat = lat.clone();

            scope.spawn(move || {
                let mut pool = MaskPool::new();
                let mut thread_result = FnvHashMap::default();
                let mut progress_bar = ProgressBar::new((0..num_keys).skip(t).step_by(num_threads).len());

                for k in (0..num_keys).skip(t).step_by(num_threads) {
                    // generate rounds keys
                    let round_keys = cipher.key_schedule(rounds, &keys[k]);

                    for alpha in alphas {
                        // initalize pool with chosen alpha
                        pool.add(*alpha);
                    }

                    for round in 0..rounds {
                        // "clock" all patterns one round
                        pool.step(&lat, round_keys[round]);

                        // check for early termination
                        if pool.masks.len() == 0 {
                            panic!("pool empty :(");
                        }
                    }

                    for alpha in alphas {
                        for beta in betas {
                            let corr = match pool.masks.get(&(*alpha, *beta)) {
                                Some(c) =>
                                    if cipher.whitening() && parity(*beta & round_keys[rounds]) == 1  {
                                        - (*c)
                                    } else {
                                        *c
                                    },
                                None    => 0.0
                            };

                            let entry = thread_result.entry((*alpha, *beta)).or_insert(vec![]);
                            entry.push(corr);
                        }
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

        for (k, mut v) in thread_result.iter_mut() {
            let entry = result.entry(*k).or_insert(vec![]);
            entry.append(&mut v);
        }
    }

    result
}