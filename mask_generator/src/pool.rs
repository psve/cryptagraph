use analysis::MaskLAT;
use std::collections::HashMap;
use utility::parity;

static FLOAT_TINY : f64 = 0.00000000000000000000000000000000001;

#[derive(Clone)]
pub struct MaskPool {
    pub masks: HashMap<u64, f64>,
    // pub paths: HashMap<u64, usize>,
}

impl MaskPool {
    pub fn new() -> MaskPool {
        MaskPool{
            masks: HashMap::new(),
            // paths: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.masks.clear();
    }

    pub fn add(&mut self, mask: u64) {
        self.masks.insert(mask, 1.0);
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

    // propergate mask set

    for (alpha, corr) in &pool_old.masks {

        // filter zero correlation

        /*if (*corr) * (*corr) < FLOAT_TINY {
            continue;
        }*/

        let sign   = if parity(*alpha & key) == 1 { -1.0 } else { 1.0 };

        // let apaths = *pool_old.paths.get(alpha).unwrap();
        // debug_assert!(apaths > 0);

        for approx in lat.lookup_alpha(*alpha).iter() {
            debug_assert_eq!(approx.alpha, *alpha);

            let delta = sign * (approx.corr * corr);

            // add relation to accumulator

            let acc  = match pool_new.masks.get(&approx.beta) {
                None    => delta,
                Some(c) => delta + c
            };

            /*
            let paths = match pool_new.paths.get(&approx.beta) {
                None    => apaths,
                Some(c) => *c + apaths
            };
            */

            // write back to pool

            pool_new.masks.insert(
                approx.beta,
                acc
            );

            /*
            pool_new.paths.insert(
                approx.beta,
                paths
            );
            */
        };
    };
}
