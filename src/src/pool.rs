use analysis::MaskLAT;
use fnv::FnvHashMap;
use utility::parity;

#[derive(Clone)]
pub struct MaskPool {
    pub masks: FnvHashMap<u64, f64>,
}

impl MaskPool {
    pub fn new() -> MaskPool {
        MaskPool{
            masks: FnvHashMap::default(),
        }
    }

    pub fn clear(&mut self) {
        self.masks.clear();
    }

    pub fn add(&mut self, mask: u64) {
        self.masks.insert(mask, 1.0);
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

        let sign   = if parity(*alpha & key) == 1 { -1.0 } else { 1.0 };

        for approx in lat.lookup_alpha(*alpha).iter() {
            debug_assert_eq!(approx.alpha, *alpha);

            let delta = sign * (approx.corr * corr);

            // add relation to accumulator

            let acc  = match pool_new.masks.get(&approx.beta) {
                None    => delta,
                Some(c) => delta + c
            };

            // write back to pool

            pool_new.masks.insert(
                approx.beta,
                acc
            );
        };
    };
}
