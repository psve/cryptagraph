//! Implementation of TWINE.

use crate::sbox::Sbox;
use crate::cipher::{CipherStructure, Cipher};
use crate::property::PropertyType;

/*****************************************************************
                            TWINE
******************************************************************/

/// A structure representing the TWINE cipher.
#[derive(Clone)]
pub struct Twine {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    permutation: [u128; 16],
    inverse: [u128; 16],
    constants: [u128; 35],
}

impl Twine {
    /// Create a new instance of the cipher.
    pub fn new() -> Twine {
        let table = vec![0xc, 0x0, 0xf, 0xa, 0x2, 0xb, 0x9, 0x5, 0x8, 0x3, 0xd, 0x7, 0x1, 0xe, 0x6, 0x4];
        let permutation = [1, 4, 5, 0, 13, 6, 9, 2, 7, 12, 3, 8, 11, 14, 15, 10];
        let inverse     = [3, 0, 7, 10, 1, 2, 5, 8, 11, 6, 15, 12, 9, 4, 13, 14];
        let constants = [0x01,0x02,0x04,0x08,0x10,0x20,0x03,0x06,0x0c,0x18,0x30,0x23,0x05,0x0a,0x14,
                        0x28,0x13,0x26,0x0f,0x1e,0x3c,0x3b,0x35,0x29,0x11,0x22,0x07,0x0e,0x1c,0x38,
                        0x33,0x25,0x09,0x12,0x24];

        Twine{size: 64, 
              key_size: 80,
              sbox: Sbox::new(4, 4, table), 
              permutation, 
              inverse,
              constants}
    }
}

impl Cipher for Twine {
    fn structure(&self) -> CipherStructure {
        CipherStructure::Feistel
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

    fn sbox_pos_in(&self, i: usize) -> usize {
        i*self.sbox(i).size_in()
    }

    fn sbox_pos_out(&self, i: usize) -> usize {
        i*self.sbox(i).size_out()
    }

    fn linear_layer(&self, input: u128) -> u128{
        let mut output = 0;
        
        output ^= ((input as u64      ) & 0xf) << (self.permutation[ 0]*4);
        output ^= ((input as u64 >>  4) & 0xf) << (self.permutation[ 1]*4);
        output ^= ((input as u64 >>  8) & 0xf) << (self.permutation[ 2]*4);
        output ^= ((input as u64 >> 12) & 0xf) << (self.permutation[ 3]*4);
        output ^= ((input as u64 >> 16) & 0xf) << (self.permutation[ 4]*4);
        output ^= ((input as u64 >> 20) & 0xf) << (self.permutation[ 5]*4);
        output ^= ((input as u64 >> 24) & 0xf) << (self.permutation[ 6]*4);
        output ^= ((input as u64 >> 28) & 0xf) << (self.permutation[ 7]*4);
        output ^= ((input as u64 >> 32) & 0xf) << (self.permutation[ 8]*4);
        output ^= ((input as u64 >> 36) & 0xf) << (self.permutation[ 9]*4);
        output ^= ((input as u64 >> 40) & 0xf) << (self.permutation[10]*4);
        output ^= ((input as u64 >> 44) & 0xf) << (self.permutation[11]*4);
        output ^= ((input as u64 >> 48) & 0xf) << (self.permutation[12]*4);
        output ^= ((input as u64 >> 52) & 0xf) << (self.permutation[13]*4);
        output ^= ((input as u64 >> 56) & 0xf) << (self.permutation[14]*4);
        output ^= ((input as u64 >> 60) & 0xf) << (self.permutation[15]*4);

        u128::from(output)
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;

        output ^= ((input as u64      ) & 0xf) << (self.inverse[ 0]*4);
        output ^= ((input as u64 >>  4) & 0xf) << (self.inverse[ 1]*4);
        output ^= ((input as u64 >>  8) & 0xf) << (self.inverse[ 2]*4);
        output ^= ((input as u64 >> 12) & 0xf) << (self.inverse[ 3]*4);
        output ^= ((input as u64 >> 16) & 0xf) << (self.inverse[ 4]*4);
        output ^= ((input as u64 >> 20) & 0xf) << (self.inverse[ 5]*4);
        output ^= ((input as u64 >> 24) & 0xf) << (self.inverse[ 6]*4);
        output ^= ((input as u64 >> 28) & 0xf) << (self.inverse[ 7]*4);
        output ^= ((input as u64 >> 32) & 0xf) << (self.inverse[ 8]*4);
        output ^= ((input as u64 >> 36) & 0xf) << (self.inverse[ 9]*4);
        output ^= ((input as u64 >> 40) & 0xf) << (self.inverse[10]*4);
        output ^= ((input as u64 >> 44) & 0xf) << (self.inverse[11]*4);
        output ^= ((input as u64 >> 48) & 0xf) << (self.inverse[12]*4);
        output ^= ((input as u64 >> 52) & 0xf) << (self.inverse[13]*4);
        output ^= ((input as u64 >> 56) & 0xf) << (self.inverse[14]*4);
        output ^= ((input as u64 >> 60) & 0xf) << (self.inverse[15]*4);

        u128::from(output)
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

        k1 |= u64::from(key[0]);
        k1 <<= 8;
        k1 |= u64::from(key[1]);

        for &k in key.iter().take(10).skip(2) {
            k0 <<= 8;
            k0 |= u64::from(k);
        }

        let idx_0 = [12, 16, 20, 24, 52, 60];
        let idx_1 = [0, 8];

        for r in 0..rounds {
            // Extract
            let mut roundkey = 0;

            for (i, &idx) in idx_0.iter().enumerate() {
                roundkey ^= ((k0 >> idx) & 0xf) << (8*i+4);
            }

            for (i, &idx) in idx_1.iter().enumerate() {
                roundkey ^= ((k1 >> idx) & 0xf) << (8*(i+6)+4);
            }

            keys.push(roundkey);

            // Update
            k0 ^= self.constants[r] as u64 & 0x7;
            k0 ^= (self.constants[r] as u64 >> 3) << 48;
            k0 ^= u64::from(self.sbox.apply((k0 >> 12) & 0xf)) << 60;
            k1 ^= u64::from(self.sbox.apply((k1 >> 12) & 0xf)) << 8;
            k1 = (k1 >> 12) ^ ((k1 << 4) & 0xfff0);
            let t = k1;
            k1 = k0 >> 48;
            k0 <<= 16;
            k0 ^= t;
        }

        // Extract
        let mut roundkey = 0;

        for (i, &idx) in idx_0.iter().enumerate() {
            roundkey ^= ((k0 >> idx) & 0xf) << (8*i+4);
        }

        for (i, &idx) in idx_1.iter().enumerate() {
            roundkey ^= ((k1 >> idx) & 0xf) << (8*(i+6)+4);
        }

        keys.push(roundkey);

        keys.iter().map(|&x| u128::from(x)).collect()
    }

    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        for round_key in round_keys.iter().take(35) {
            let x = (output & 0xf0f0f0f0f0f0f0f0) ^ round_key;
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= u128::from(self.sbox.apply((x >> (8*j+4)) & 0xf)) << (8*j+4);
            }

            output ^= tmp >> 4;
            output = self.linear_layer(output);
        }

        let x = (output & 0xf0f0f0f0f0f0f0f0) ^ round_keys[35];
        let mut tmp = 0;

        for j in 0..8 {
            tmp ^= u128::from(self.sbox.apply((x >> (8*j+4)) & 0xf)) << (8*j+4);
        }

        output ^= tmp >> 4;
        output
    }

    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        for i in 0..35 {
            let x = (output & 0xf0f0f0f0f0f0f0f0) ^ round_keys[35-i];
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= u128::from(self.sbox.apply((x >> (8*j+4)) & 0xf)) << (8*j+4);
            }

            output ^= tmp >> 4;
            output = self.linear_layer_inv(output);
        }

        let x = (output & 0xf0f0f0f0f0f0f0f0) ^ round_keys[0];
        let mut tmp = 0;

        for j in 0..8 {
            tmp ^= u128::from(self.sbox.apply((x >> (8*j+4)) & 0xf)) << (8*j+4);
        }

        output ^= tmp >> 4;
        output
    }

    fn name(&self) -> String {
        String::from("TWINE")
    }

    fn sbox_mask_transform(&self, 
                           input: u128, 
                           output: u128, 
                           property_type: PropertyType) 
                           -> (u128, u128) {
        match property_type {
            PropertyType::Linear => {
                let input = input as u64;
                let output = output as u64;

                let mut alpha = 0;
                let mut tmp = 0;

                for i in 0..8 {
                    alpha ^= ((output >> (4*i)) & 0xf) << (i*8);
                    alpha ^= ((input >> (4*i)) & 0xf) << (i*8+4);
                    tmp ^= ((output >> (4*i+32)) & 0xf) << (i*8);
                }

                tmp = self.linear_layer_inv(u128::from(tmp)) as u64;
                alpha ^= tmp;

                let mut beta = 0;
                tmp = 0;

                for i in 0..8 {
                    beta ^= ((output >> (4*i+32)) & 0xf) << (i*8);
                    beta ^= ((input >> (4*i+32)) & 0xf) << (i*8+4);
                    tmp ^= ((output >> (4*i)) & 0xf) << (i*8);
                }

                tmp = self.linear_layer(u128::from(tmp)) as u64;
                beta ^= tmp;
                beta = self.linear_layer(u128::from(beta)) as u64;       

                (u128::from(alpha), u128::from(beta))
            },
            PropertyType::Differential => {
                let input = input as u64;
                let output = output as u64;

                let mut delta = 0;
                let mut tmp = 0;

                for i in 0..8 {
                    delta ^= ((output >> (4*i)) & 0xf) << (i*8);
                    delta ^= ((input >> (4*i)) & 0xf) << (i*8+4);
                    tmp ^= ((input >> (4*i+32)) & 0xf) << (i*8+4);
                }

                tmp = self.linear_layer_inv(u128::from(tmp)) as u64;
                delta ^= tmp;

                let mut nabla = 0;
                tmp = 0;

                for i in 0..8 {
                    nabla ^= ((output >> (4*i+32)) & 0xf) << (i*8);
                    nabla ^= ((input >> (4*i+32)) & 0xf) << (i*8+4);
                    tmp ^= ((input >> (4*i)) & 0xf) << (i*8+4);
                }

                tmp = self.linear_layer(u128::from(tmp)) as u64;
                nabla ^= tmp;
                nabla = self.linear_layer(u128::from(nabla)) as u64;       

                (u128::from(delta), u128::from(nabla))
            }
        }
    }

    #[inline(always)]
    fn whitening(&self) -> bool { 
        false 
    }
}

impl Default for Twine {
    fn default() -> Self {
        Twine::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher;
    
    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("twine").unwrap();
        let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let round_keys = cipher.key_schedule(35, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = 0x7c1f0f80b1df9c28;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("twine").unwrap();
        let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let round_keys = cipher.key_schedule(35, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = 0x7c1f0f80b1df9c28;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("twine").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(35, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(35, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}