/*
 *
 */

use cipher::{Cipher, Sbox};
use approximation::{Approximation};

pub struct LAT {
    lat       : Vec<Vec<Option<f64>>>,
    map_alpha : Vec<Vec<Approximation>>,
    map_beta  : Vec<Vec<Approximation>>
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
