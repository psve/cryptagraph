use analysis::{LAT};
use cipher::{Cipher};
use std::collections::{HashMap, HashSet};
use utility::parity;

#[derive(Clone)]
pub struct MaskPool {
    pub masks: HashMap<u64, f64>,
}

#[derive(Clone)]
pub struct MaskTree {
    size : usize,
    root : MaskNode
}

#[derive(Clone)]
struct MaskNode {
    mask     : u64,
    offset   : u64,
    bits     : u64,
    children : Vec<Option<Box<MaskNode>>>
}

#[derive(Clone)]
struct MaskApproximation {
    corr  : f64,
    alpha : u64,
    beta  : u64
}

#[derive(Clone)]
struct MaskLAT {
    map_alpha: HashMap<u64, Vec<MaskApproximation>>,
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

    pub fn new(cipher : &Cipher, alphas : Vec<u64>) -> MaskLAT {

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
                            beta  : *beta,
                            corr  : corr
                        });
                    }
                }
            }
        }

        mlat
    }
}

impl MaskTree {
    pub fn new(bits : u64) -> MaskTree {
        MaskTree {
            size : 0,
            root : MaskNode::new_with_offset(bits, 0)
        }
    }

    pub fn add(&mut self, value : u64) {
        self.root.add(value);
        self.size += 1;
    }

    pub fn len(&mut self) -> usize {
        self.size
    }

    pub fn contains(&self, value : u64) -> bool {
        let mut node = &self.root;
        let mut step = 0;
        while step < 64 {
            step = step + node.bits;
            node = match node.step(value) {
                None    => { return false; },
                Some(n) => n
            };
        }
        assert!(match node.step(value) {
            None    => true,
            Some(_) => false
        });
        return true;
    }
}

impl MaskNode {
    fn new(bits : u64) -> MaskNode {
        MaskNode::new_with_offset(bits, 0)
    }

    fn new_with_offset(bits : u64, offset : u64) -> MaskNode {
        let fanout   = 1 << bits;
        let mut node = MaskNode{
            mask     : (1 << bits) - 1,
            bits     : bits,
            offset   : offset,
            children : Vec::new()
        };
        for _i in 0..fanout {
            node.children.push(None);
        };
        node
    }

    fn step(&self, value : u64) -> Option<&MaskNode> {
        if self.offset == 64 { return None; }

        let v = (value >> self.offset) & self.mask;

        match self.children.get(v as usize).unwrap() {
            &None => None,
            &Some(ref node) => Some(node)
        }
    }

    fn add(&mut self, value : u64) {
        if self.offset == 64 { return; }

        let v = (value >> self.offset) & self.mask;
        let child = self.children.get_mut(v as usize).unwrap();

        match child {
            &mut None => {
                let mut node = Box::new(
                    MaskNode::new_with_offset(
                        self.bits,
                        self.offset + self.bits,
                    )
                );
                node.add(value);
                *child = Some(node);
            },
            &mut Some(ref mut node) => {
                node.add(value);
            }
        };
    }
}

impl MaskPool {
    pub fn new() -> MaskPool {
        MaskPool{
            masks: HashMap::new(),
        }
    }

    pub fn init(&mut self, masks: &HashSet<u64>, input: u64) {
        assert!(masks.contains(&input));
        for alpha in masks {
            self.masks.insert(*alpha,
                if *alpha == input { 1.0 } else { 0.0 }
            );
        }
    }

    fn clear(&mut self) {
        self.masks.clear();
    }
}



pub fn step(
    cipher   : &Cipher,
    lat      : &LAT,
    hull     : &MaskTree,
    pool_new : &mut MaskPool,
    pool_old : &MaskPool,
    key      : u64,
) {
    pool_new.clear();
    for (alpha, corr) in &pool_old.masks {
        step_mask(
            cipher,
            lat,
            hull,
            pool_new,
            key,
            *alpha,
            *corr
        );
    };
}

fn step_mask(
    cipher : &Cipher,
    lat    : &LAT,
    hull   : &MaskTree,
    pool   : &mut MaskPool,
    key    : u64,
    alpha  : u64,
    corr   : f64
) {
    println!("{:x}", alpha);
    fn fill(
        cipher : &Cipher,
        lat    : &LAT,
        node   : &MaskNode,
        pool   : &mut MaskPool,
        key    : u64,
        alpha  : u64,
        beta   : u64,
        corr   : f64,
        index  : usize
    ) {

        let mut node = node;

        // prepare sbox domain mask

        let w = cipher.sbox().size;
        let m = (1 << w) - 1;

        for i in index..cipher.num_sboxes() {

            let shift = i * w;

            // fetch input parity of sbox

            let a = (alpha >> shift) & m;
            if  a == 0 {
                match node.step(0) {
                    None    => { return; }
                    Some(n) => { node = n; }
                }
                continue;
            }

            // enumerate possible output parities

            for approx in lat.lookup_alpha(a) {
                assert!(approx.alpha == a as u64);
                match node.step(approx.beta) {
                    None => { continue; }
                    Some(node) => {
                        fill(
                            cipher,
                            lat,
                            node,
                            pool,
                            key,
                            alpha,
                            beta | approx.beta << shift,
                            corr * approx.value,
                            i + 1
                        );
                    }
                }
            }

            return;
        }

        // apply permutation

        let beta_p = cipher.linear_layer(beta);

        // key approximation / correlation

        let corr = if parity(beta_p ^ key) == 1 {- corr } else { corr };

        // add to pool

        let acc = match pool.masks.get(&beta_p) {
            None    => corr,
            Some(c) => c + corr
        };

        pool.masks.insert(
            beta_p,
            acc
        );
    }

    fill(cipher, lat, &hull.root, pool, key, alpha, 0, corr, 0)
}
