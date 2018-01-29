/*
 *
 */

use cipher::{Cipher, Sbox};
use std::collections::{HashMap};
use approximation::{Approximation};

pub struct LAT {
    lat       : Vec<Vec<Option<f64>>>,
    map_alpha : Vec<Vec<Approximation>>,
    map_beta  : Vec<Vec<Approximation>>
}

pub struct MaskApproximation {
    pub corr  : f64,
    pub alpha : u64,
    pub beta  : u64, // permuted, -> new alpha
}

pub struct MaskLAT {
    map_alpha: HashMap<u64, Vec<MaskApproximation>>,
}

impl LAT {
    pub fn new(sbox: &Sbox) -> LAT {

        let mut lat = LAT {
            lat       : vec![],
            map_alpha : vec![],
            map_beta  : vec![]
        };

        let balance = (1 << (sbox.size - 1)) as usize;
        let values  = 1 << sbox.size;

        for _i in 0..values {
            lat.map_alpha.push(vec![]);
            lat.map_beta.push(vec![]);
            lat.lat.push(vec![]);
        }

        for (alpha, row) in sbox.lat.iter().enumerate() {
            for (beta, hits) in row.iter().enumerate() {

                // handle balanced

                let corr = 2.0 * ((*hits as f64) / (values as f64)) - 1.0;

                {
                    let entry = lat.lat.get_mut(alpha).unwrap();
                    if *hits == balance {
                        entry.push(None);
                        continue;
                    }
                    entry.push(Some(corr));
                }

                // add to alpha map

                {
                    let entry = lat.map_alpha.get_mut(alpha).unwrap();
                    entry.push(Approximation::new(alpha as u64, beta as u64, None));
                }

                // add to beta map

                {
                    let entry = lat.map_beta.get_mut(beta).unwrap();
                    entry.push(Approximation::new(alpha as u64, beta as u64, None));
                }
            }

            // assert lat filled

            assert!({
                let entry = lat.lat.get_mut(alpha).unwrap();
                entry.len() == values
            })
        }
        lat
    }

    pub fn lookup(&self, a : u64, b : u64) -> Option<f64> {
        match self.lat.get(a as usize) {
            None      => None,
            Some(vec) => {
                match vec.get(b as usize) {
                    None    => None,
                    Some(f) => *f
                }
            }
        }
    }

    pub fn lookup_alpha(&self, a : u64) -> &Vec<Approximation> {
        self.map_alpha.get(a as usize).unwrap()
    }
}

impl MaskLAT {

    fn correlation(
        cipher : &Cipher,
        lat    : &LAT,
        alpha  : u64,
        beta   : u64
    ) -> Option<f64> {
        let mut corr : f64 = 1.0;
        let mut alpha      = alpha;
        let mut beta       = beta;

        let w = cipher.sbox().size;
        let m = (1 << w) - 1;

        for i in 0..cipher.num_sboxes() {

            match lat.lookup(alpha & m, beta & m) {
                None    => { return None; }
                Some(c) => {
                    corr *= c;
                }
            }

            beta  >>= w;
            alpha >>= w;
        }

        assert!(beta == 0);
        assert!(alpha == 0);

        return Some(corr);
    }

    pub fn new(cipher : &Cipher, alphas : &Vec<u64>) -> MaskLAT {

        // construct lat for single sbox instance

        let lat = LAT::new(cipher.sbox());

        // compute possible "betas" for alpha set

        let mut betas = vec![];

        for alpha in alphas.iter() {
            betas.push(cipher.linear_layer_inv(*alpha));
        }

        // construct full mask lat

        let mut mlat = MaskLAT {
            map_alpha : HashMap::new(),
        };

        for alpha in alphas.iter() {
            mlat.map_alpha.insert(*alpha, vec![]);
        }

        for alpha in alphas.iter() {
            for beta in betas.iter() {
                match MaskLAT::correlation(cipher, &lat, *alpha, *beta) {
                    None => (),
                    Some(corr) => {
                        let vector = mlat.map_alpha.get_mut(alpha).unwrap();
                        vector.push(MaskApproximation{
                            alpha : *alpha,
                            beta  : cipher.linear_layer(*beta),
                            corr  : corr
                        });
                    }
                }
            }
        }

        mlat
    }

    pub fn lookup_alpha(&self, a : u64) -> &Vec<MaskApproximation> {
        self.map_alpha.get(&a).unwrap()
    }
}
