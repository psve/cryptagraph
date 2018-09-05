//! Implementation of PRIDE.

use sbox::Sbox;
use cipher::{CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            PRIDE
******************************************************************/

/// A structure representing the PRIDE cipher.
#[derive(Clone)]
pub struct Pride {
    size     : usize,
    key_size : usize,
    sbox     : Sbox,
    perm     : [[u128; 256]; 8],
    iperm    : [[u128; 256]; 8],
}

impl Pride {
    /// Create a new instance of the cipher.
    pub fn new() -> Pride {
        let table = vec![0x0,0x4,0x8,0xf,0x1,0x5,0xe,0x9,0x2,0x7,0xa,0xc,0xb,0xd,0x6,0x3];
        let perm = include!("data/pride.perm");
        let iperm = include!("data/pride.inv.perm");

        Pride {
            size: 64, 
            key_size: 128, 
            sbox: Sbox::new(4, 4, table),
            perm,
            iperm
        }
    }
}

// Code mostly borrowed from https://github.com/camilstaps/pypride
fn swap(x: u128) -> u128 {
    ((x & 0xf0) >> 4) | ((x & 0x0f) << 4)
}

fn rol(x: u128) -> u128 {
    ((x << 1) | (x >> 7)) & 0xff
}

fn ror(x: u128) -> u128 {
    (x >> 1) | ((x & 0x01) << 7)
}

fn apply_l0(x: u128) -> u128 {
    let s0 = x >> 8;
    let s1 = x & 0x00ff;
    let temp = swap(s1 ^ s0);
    ((s1 ^ temp) << 8) | (s0 ^ temp)
}

fn apply_l1(x: u128) -> u128 {
    let s2 = x >> 8;
    let s3 = swap(x & 0x00ff);
    let temp = s2 ^ ror(s3);
    ((rol(s2) ^ temp) << 8) | (s3 ^ temp)
}

fn apply_l1_inv(x: u128) -> u128 {
    let s2 = ror(x >> 8);
    let s3 = x & 0x00ff;
    let temp = s2 ^ ror(s3);
    ((ror(temp) ^ s2) << 8) | swap(temp ^ s3)
}

fn apply_l2(x: u128) -> u128 {
    let s4 = swap(x >> 8);
    let s5 = x & 0x00ff;
    let temp = s4 ^ ror(s5);
    ((temp ^ rol(s4)) << 8) | (temp ^ s5)
}

fn apply_l2_inv(x: u128) -> u128 {
    let s4 = ror(x >> 8);
    let s5 = x & 0x00ff;
    let temp = s4 ^ ror(s5);
    (swap(s4 ^ ror(temp)) << 8) | (s5 ^ temp)
}

fn apply_l3(x: u128) -> u128 {
    let s6 = x >> 8;
    let s7 = x & 0x00ff;
    let temp = swap(s6 ^ s7);
    ((s6 ^ temp) << 8) | (s7 ^ temp)
}

impl Cipher for Pride {
    fn structure(&self) -> CipherStructure {
        CipherStructure::Spn
    }
    
    fn size(&self) -> usize {
        self.size
    }

    fn key_size(&self) -> usize {
        self.key_size
    }

    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size_in()
    }

    fn sbox(&self, _i: usize) -> &Sbox {
        &self.sbox
    }

    fn linear_layer(&self, input: u128) -> u128{
        let mut output = 0;
        
        // Apply P
        for i in 0..8 {
            output ^= self.perm[i][((input >> (i*8)) & 0xff) as usize];
        }

        // Apply L0, L1, L2, L3
        output = (apply_l0((output >> 48) & 0xffff) << 48) 
               ^ (apply_l1((output >> 32) & 0xffff) << 32) 
               ^ (apply_l2((output >> 16) & 0xffff) << 16) 
               ^ (apply_l3(output & 0xffff));

        // Apply P^(-1)
        let mut tmp = 0;
        
        for i in 0..8 {
            tmp ^= self.iperm[i][((output >> (i*8)) & 0xff) as usize];
        }

        tmp
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;
        
        // Apply P
        for i in 0..8 {
            output ^= self.perm[i][((input >> (i*8)) & 0xff) as usize];
        }

        // Apply L0, L1^(-1), L2^(-1), L3
        output = (apply_l0((output >> 48) & 0xffff) << 48) 
               ^ (apply_l1_inv((output >> 32) & 0xffff) << 32) 
               ^ (apply_l2_inv((output >> 16) & 0xffff) << 16) 
               ^ (apply_l3(output & 0xffff));

        // Apply P^(-1)
        let mut tmp = 0;
        
        for i in 0..8 {
            tmp ^= self.iperm[i][((output >> (i*8)) & 0xff) as usize];
        }

        tmp
    }

    fn reflection_layer(&self, _input: u128) -> u128 {
        panic!("Not implemented for this type of cipher")
    }

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u128> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut k0 = 0;
        let mut k1 = 0;

        for i in 0..8 {
            k1 <<= 8;
            k0 <<= 8;
            k1 |= u128::from(key[i+8]);
            k0 |= u128::from(key[i]);
        }

        keys.push(k0);

        for r in 0..(rounds+1) {
            let mut roundkey = 0;

            roundkey ^= k1 & 0xff00ff00ff00ff00;
            roundkey ^= ((((k1 >> 48) & 0xff) + 193*(r as u128 + 1)) % 256) << 48;
            roundkey ^= ((((k1 >> 32) & 0xff) + 165*(r as u128 + 1)) % 256) << 32;
            roundkey ^= ((((k1 >> 16) & 0xff) +  81*(r as u128 + 1)) % 256) << 16;
            roundkey ^=  (((k1      ) & 0xff) + 197*(r as u128 + 1)) % 256;

            let mut tmp = 0;
        
            // Permutation
            for i in 0..8 {
                tmp ^= self.iperm[i][((roundkey >> (i*8)) & 0xff) as usize];
            }

            keys.push(tmp);
        }
        
        keys.push(k0);
        keys[1] ^= keys[0];
        keys.remove(0);

        keys   
    }

    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = 0;
        
        // Initial permutation
        for i in 0..8 {
            output ^= self.iperm[i][((input >> (i*8)) & 0xff) as usize];
        }

        for round_key in round_keys.iter().take(19) {
            // Add round key
            output ^= round_key;

            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.sbox.apply((output >> (4*j)) & 0xf)) << (4*j);
            }

            // Linear layer
            output = self.linear_layer(tmp);
        }

        // Add round key
        output ^= round_keys[19];

        // Apply S-box
        let mut tmp = 0;

        for j in 0..16 {
            tmp ^= u128::from(self.sbox.apply((output >> (4*j)) & 0xf)) << (4*j);
        }

        // Whitening key
        output = tmp ^ round_keys[20];

        // Final permutation
        let mut tmp = 0;

        for i in 0..8 {
            tmp ^= self.perm[i][((output >> (i*8)) & 0xff) as usize];
        }

        tmp        
    }

    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = 0;
        
        // Initial permutation
        for i in 0..8 {
            output ^= self.iperm[i][((input >> (i*8)) & 0xff) as usize];
        }

        // Whitening key
        output ^= round_keys[20];

        // Apply S-box
        let mut tmp = 0;

        for j in 0..16 {
            tmp ^= u128::from(self.sbox.apply((output >> (4*j)) & 0xf)) << (4*j);
        }
        
        // Add round key
        output = tmp ^ round_keys[19];

        for i in 0..19 {
            // Linear layer
            output = self.linear_layer_inv(output);

            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.sbox.apply((output >> (4*j)) & 0xf)) << (4*j);
            }

            // Add round key
            output = tmp ^ round_keys[18-i];
        }

        // Final permutation
        let mut tmp = 0;

        for i in 0..8 {
            tmp ^= self.perm[i][((output >> (i*8)) & 0xff) as usize];
        }

        tmp     
    }

    fn name(&self) -> String {
        String::from("PRIDE")
    }

    fn sbox_mask_transform(&self, 
                           input: u128, 
                           output: u128, 
                           _property_type: PropertyType) 
                           -> (u128, u128) {
        (input, self.linear_layer(output))
    }

    #[inline(always)]
    fn whitening(&self) -> bool {
        true
    }
}


#[cfg(test)]
mod tests {
    use cipher; 

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("pride").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x82b4109fcc70bd1f;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0xd70e60680a17b956;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x28f19f97f5e846a9;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0xd123ebaf368fce62;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = 0xd1372929712d336e;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("pride").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x82b4109fcc70bd1f;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0xd70e60680a17b956;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x28f19f97f5e846a9;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0xd123ebaf368fce62;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = 0xd1372929712d336e;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("pride").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(19, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}