use cipher::{Cipher, Sbox};
use fnv::FnvHashMap;
use property::Property;
use utility::{ProgressBar};

macro_rules! debug {
    ($($arg:tt)*) => (if cfg!(debug_assertions) { println!($($arg)*) })
}


static FLOAT_TINY : f64 = 0.00000000000000000000000000000000001;

/* Linear Approximation Table over some component.
 *
 * Maps (alpha, beta) -> correlation
 */
pub struct Lat {
    lat       : Vec<Vec<Option<f64>>>,
    map_alpha : Vec<Vec<Property>>,
    map_beta  : Vec<Vec<Property>>
}

/* Approximation over a full domain (up to 64-bit)
 */
pub struct MaskApproximation {
    pub corr  : f64,
    pub alpha : u128,
    pub beta  : u128, // permuted, -> new alpha
}

/* Linear Approximation Table for entire round permutation
 *
 * The linear layer has been applied to the { beta } set.
 */
pub struct MaskLat {
    map_alpha: FnvHashMap<u128, Vec<MaskApproximation>>,
}

impl Lat {
    pub fn new(sbox: &Sbox) -> Lat {

        let mut lat = Lat {
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
                        continue; // do not add to enumeration maps (below)
                    }
                    entry.push(Some(corr));
                }

                // add to alpha map

                {
                    let entry = lat.map_alpha.get_mut(alpha).unwrap();
                    entry.push(Property::new(alpha as u128, beta as u128, corr, 1));
                }

                // add to beta map

                {
                    let entry = lat.map_beta.get_mut(beta).unwrap();
                    entry.push(Property::new(alpha as u128, beta as u128, corr, 1));
                }
            }

            // assert lat filled

            debug_assert!({
                let entry = lat.lat.get_mut(alpha).unwrap();
                entry.len() == values
            })
        }
        lat
    }

    #[inline(always)]
    pub fn lookup(&self, a : u128, b : u128) -> Option<f64> {
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
}

impl MaskLat {

    /* Takes an LAT of a component function and
     * computes the correlation of parities over the bricklayer function.
     */
    #[inline(always)]
    fn correlation(
        cipher : &Cipher,
        lat    : &Lat,
        alpha  : u128,
        beta   : u128
    ) -> Option<f64> {
        let mut corr : f64 = 1.0;
        let mut alpha      = alpha;
        let mut beta       = beta;

        debug_assert_eq!(cipher.sbox().size * cipher.num_sboxes(), 64);

        let w = cipher.sbox().size;
        let m = (1 << w) - 1;

        for _ in 0..cipher.num_sboxes() {
            match lat.lookup(alpha & m, beta & m) {
                None    => { return None; }
                Some(c) => {
                    debug_assert!(c*c > 0.0);
                    corr *= c;
                }
            }
            beta  >>= w;
            alpha >>= w;
        }

        debug_assert_eq!(beta, 0);
        debug_assert_eq!(alpha, 0);

        if corr * corr < FLOAT_TINY {
            None
        } else {
            Some(corr)
        }
    }

    /* Constructs a Lat over the bricklayer function
     * for the particular set of parities
     */
    pub fn new(cipher : &Cipher, masks : &Vec<u128>) -> MaskLat {

        // construct lat for single sbox instance

        let lat = Lat::new(cipher.sbox());

        /* Assuming SPN; compute possible "betas" for alpha set
         *
         * Alpha ^ Key Addition -> Substitution -> Linear
         *
         * We move backwards to obtain:
         *
         * Alpha ^ Key Addition -> Substitution ^ Beta <- Linear <- Alpha
         */
        let mut betas = vec![];

        for alpha in masks.iter() {
            let beta = cipher.linear_layer_inv(*alpha);
            assert_eq!(cipher.linear_layer(beta), *alpha);
            betas.push(beta);
        }

        // construct full mask lat

        let mut mlat = MaskLat {
            map_alpha : FnvHashMap::default(),
        };

        for alpha in masks.iter() {
            mlat.map_alpha.insert(*alpha, vec![]);
        }

        let mut bar = ProgressBar::new(masks.len());

        for alpha in masks.iter() {
            bar.increment();
            for beta in betas.iter() {
                match MaskLat::correlation(cipher, &lat, *alpha, *beta) {
                    None       => (), // zero correlation
                    Some(corr) => {
                        debug_assert!(corr*corr > 0.0);
                        let vector = mlat.map_alpha.get_mut(alpha).unwrap();
                        /* NOTE:
                         *   Applies linear layer to beta
                         *   to speed up computation of
                         *   new maskset (subset of Alpha)
                         */
                        let nalpha = cipher.linear_layer(*beta);
                        vector.push(MaskApproximation{
                            alpha : *alpha,
                            beta  : nalpha,
                            corr  : corr
                        });
                        debug!("Full-Approximation: {:016x} <-> {:016x} : {}", *alpha, nalpha, corr);
                    }
                }
            }
        }

        mlat
    }

    pub fn lookup_alpha(&self, a : u128) -> &Vec<MaskApproximation> {
        self.map_alpha.get(&a).unwrap()
    }
}
