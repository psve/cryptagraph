/*
 *
 */

use cipher::{Cipher, Sbox};
use approximation::{Approximation};

pub struct LAT {
    map_alpha : Vec<Vec<Approximation>>,
    map_beta  : Vec<Vec<Approximation>>
}

impl LAT {
    pub fn new(sbox: &Sbox) -> LAT {

        let mut lat = LAT {
            map_alpha : vec![],
            map_beta  : vec![]
        };

        let balance = (1 << (sbox.size - 1)) as usize;
        let values  = 1 << sbox.size;

        for _i in 0..values {
            lat.map_alpha.push(vec![]);
            lat.map_beta.push(vec![]);
        }

        for (alpha, row) in sbox.lat.iter().enumerate() {
            for (beta, hits) in row.iter().enumerate() {
                if *hits == balance { continue; }

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
        }
        lat
    }

    pub fn lookup_alpha(&self, a : u64) -> &Vec<Approximation> {
        self.map_alpha.get(a as usize).unwrap()
    }
}
