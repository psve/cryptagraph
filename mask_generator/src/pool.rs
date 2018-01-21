use cipher::{Cipher};
use single_round::{LatMap};
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
pub struct MaskPool {
    masks: HashMap<u64, f64>,
}

// rust has surprisingly weak generics

#[derive(Clone)]
pub struct MaskNode {
    mask     : u64,
    offset   : u64,
    bits     : u64,
    children : Vec<Option<Box<MaskNode>>>
}

impl MaskNode {
    pub fn new(bits : u64) -> MaskNode {
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

    pub fn step(&self, value : u64) -> Option<&MaskNode> {
        if self.offset == 64 { return None; }

        let v = (value >> self.offset) & self.mask;

        match self.children.get(v as usize).unwrap() {
            &None => None,
            &Some(ref node) => Some(node)
        }
    }

    pub fn add(&mut self, value : u64) {
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

fn parity(x : u64) -> u64 {
    let x = x ^ (x >> 32);
    let x = x ^ (x >> 16);
    let x = x ^ (x >> 8);
    let x = x ^ (x >> 4);
    let x = x ^ (x >> 2);
    let x = x ^ (x >> 1);
    x & 1
}

pub fn step(
    cipher   : &Cipher,
    lat      : &LatMap,
    hull     : &HashSet<u64>,
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
    lat    : &LatMap,
    hull   : &HashSet<u64>,
    pool   : &mut MaskPool,
    key    : u64,
    alpha  : u64,
    corr   : f64
) {
    fn fill(
        cipher : &Cipher,
        lat    : &LatMap,
        hull   : &HashSet<u64>,
        pool   : &mut MaskPool,
        key    : u64,
        alpha  : u64,
        beta   : u64,
        corr   : f64,
        index  : usize
    ) {

        // prepare sbox domain mask

        let w = cipher.sbox().size;
        let m = (1 << w) - 1;

        for i in index..cipher.num_sboxes() {

            let shift = i * 4;

            // fetch input parity of sbox

            let a = ((alpha >> shift) & m) as i16;
            if  a == 0 { continue }

            // enumerate possible output parities

            match lat.get(&a) {
                None => {return ();}
                Some(approximations) => {
                    for approx in approximations {
                        fill(
                            cipher,
                            lat,
                            hull,
                            pool,
                            key,
                            alpha,
                            beta | approx.beta << shift,
                            corr * approx.value,
                            i + 1
                        )
                    }
                }
            }

            return;
        }

        println!("{:x}", beta);

        // apply permutation

        let beta_p = cipher.linear_layer(beta);

        // check mask-set membership

        if !hull.contains(&beta_p) { return; }

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

    fill(cipher, lat, hull, pool, key, alpha, 0, corr, 0)
}
