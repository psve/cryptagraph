use analysis::MaskLAT;
use std::collections::HashMap;
use utility::parity;

#[derive(Clone)]
pub struct MaskPool {
    pub masks: HashMap<u64, f64>,
}

impl MaskPool {
    pub fn new() -> MaskPool {
        MaskPool{
            masks: HashMap::new(),
        }
    }

    pub fn init(&mut self, masks: &Vec<u64>, input: u64) {
        self.masks.clear();
        for alpha in masks {
            self.masks.insert(
                *alpha,
                if *alpha == input { 1.0 } else { 0.0 }
            );
        }
    }

    fn clear(&mut self) {
        self.masks.clear();
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
        for approx in lat.lookup_alpha(*alpha).iter() {
            assert!(approx.alpha == *alpha);

            let keyed = if parity(*alpha ^ key) == 1 { - approx.corr } else { approx.corr };
            let delta = corr * keyed;

            // add relation to accumulator

            let acc  = match pool_new.masks.get(&approx.beta) {
                None    => delta,
                Some(c) => c + delta
            };

            // write back to pool

            pool_new.masks.insert(
                approx.beta,
                acc
            );
        };
    };
}
