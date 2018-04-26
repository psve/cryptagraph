use analysis::MaskLAT;
use std::collections::HashMap;
use utility::parity;

#[derive(Clone)]
pub struct MaskPool {
    pub masks: HashMap<u64, f64>,
    pub paths: HashMap<u64, usize>,
}

impl MaskPool {
    pub fn new() -> MaskPool {
        MaskPool{
            masks: HashMap::new(),
            paths: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.masks.clear();
        self.paths.clear();
    }

    pub fn add(&mut self, mask: u64) {
        self.masks.insert(mask, 1.0);
        self.paths.insert(mask, 1);
    }

    pub fn size(&self) -> usize {
        self.masks.len()
    }
}

pub fn step(
    lat      : &MaskLAT,
    pool_new : &mut MaskPool,
    pool_old : &MaskPool,
    key      : u64,
) {
    pool_new.clear();
    for (alpha, corr) in &pool_old.masks {

        let sign  = if parity(*alpha ^ key) == 1 { -1.0 } else { 1.0 };
        let apaths = pool_old.paths.get(alpha).unwrap();

        //// println!("ALPHA : {:} {:x} {:x}", sign, *alpha, key);

        for approx in lat.lookup_alpha(*alpha).iter() {
            assert!(approx.alpha == *alpha);

            let delta = corr * sign * approx.corr;

            //// println!("APPROX : {:x} -> {:x}, delta {:}", approx.alpha, approx.beta, delta);

            // add relation to accumulator

            let acc  = match pool_new.masks.get(&approx.beta) {
                None    => delta,
                Some(c) => {
                    //// println!("LOAD : <- {:}", c);
                    c + delta
                }
            };

            if acc * acc < 0.000000000000000000000000000001 {
                continue;
            }

            let paths = match pool_new.paths.get(&approx.beta) {
                None => 0,
                Some(c) => *c
            };

            //// println!("POST : {:} {:}", acc, delta);

            // write back to pool

            pool_new.masks.insert(
                approx.beta,
                acc
            );

            pool_new.paths.insert(
                approx.beta,
                paths + apaths,
            );
        };
    };
}
