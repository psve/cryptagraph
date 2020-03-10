//! Implementation of GIFT-64.

use crate::sbox::Sbox;
use crate::cipher::{CipherStructure, Cipher};
use crate::property::PropertyType;

/*****************************************************************
                            GIFT64
******************************************************************/

/// A structure representing the GIFT64 cipher.
#[derive(Clone)]
pub struct Gift64 {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox,
    constants: [u128; 48],
}

impl Gift64 {
    const PERMUTATION     : [[u128 ; 0x100] ; 8] = include!("data/gift.perm");
    const PERMUTATION_INV : [[u128 ; 0x100] ; 8] = include!("data/gift.perm.inv");
    
    /// Create a new instance of the cipher.
    pub fn new() -> Gift64 {
        let table = vec![0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
                         0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe];
        let itable = vec![0xd, 0x0, 0x8, 0x6, 0x2, 0xc, 0x4, 0xb, 
                          0xe, 0x7, 0x1, 0xa, 0x3, 0x9, 0xf, 0x5];
        let constants = [0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,0x27,
                         0x0e,0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b,0x17,0x2e,
                         0x1c,0x38,0x31,0x23,0x06,0x0d,0x1b,0x36,0x2d,0x1a,0x34,0x29,0x12,0x24,0x08,
                         0x11,0x22,0x04];

        Gift64{size: 64, 
             key_size: 128,
             sbox: Sbox::new(4, 4, table), 
             isbox: Sbox::new(4, 4, itable),
             constants}
    }
}


impl Cipher for Gift64 {
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

    fn sbox_pos_in(&self, i: usize) -> usize {
        i*self.sbox(i).size_in()
    }

    fn sbox_pos_out(&self, i: usize) -> usize {
        i*self.sbox(i).size_out()
    }

    fn linear_layer(&self, input: u128) -> u128{
        let mut output = 0;
        output ^= Gift64::PERMUTATION[0][((input      ) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[1][((input >>  8) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[2][((input >> 16) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[3][((input >> 24) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[4][((input >> 32) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[5][((input >> 40) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[6][((input >> 48) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[7][((input >> 56) & 0xff) as usize];

        output
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;
        output ^= Gift64::PERMUTATION_INV[0][((input      ) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[1][((input >>  8) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[2][((input >> 16) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[3][((input >> 24) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[4][((input >> 32) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[5][((input >> 40) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[6][((input >> 48) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[7][((input >> 56) & 0xff) as usize];

        output
    }

    fn reflection_layer(&self, _input: u128) -> u128 {
        panic!("Not implemented for this type of cipher")
    }

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u128> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut k1 = 0;
        let mut k0 = 0;

        // Load key into 128-bit state (k1 || k0)
        for i in 0..8 {
            k1 <<= 8;
            k0 <<= 8;
            k1 |= u128::from(key[i]);
            k0 |= u128::from(key[i+8]);
        }

        for r in 0..rounds {
            let mut round_key = 0;

            for i in 0..16 {
                round_key ^= ((k0 >> i) & 0x1) << (4*i);
                round_key ^= ((k0 >> (i+16)) & 0x1) << (4*i+1);
            }

            round_key ^= 1 << 63;
            round_key ^= (self.constants[r] & 0x1) << 3;
            round_key ^= ((self.constants[r] >> 1) & 0x1) << 7;
            round_key ^= ((self.constants[r] >> 2) & 0x1) << 11;
            round_key ^= ((self.constants[r] >> 3) & 0x1) << 15;
            round_key ^= ((self.constants[r] >> 4) & 0x1) << 19;
            round_key ^= ((self.constants[r] >> 5) & 0x1) << 23;

            keys.push(round_key);

            let t0 = k0;
            let t1 = k1;

            k0 = (t0 >> 32) & 0xffffffffffffffff;
            k0 ^= (t1 << 32) & 0xffffffffffffffff;
            k1 = (t1 >> 32) & 0xffffffffffffffff;
            k1 ^= ((((t0 & 0xffff) >> 12) ^ ((t0 & 0xffff) << 4)) & 0xffff) << 32;
            k1 ^= ((((t0 & 0xffff0000) >> 2) ^ ((t0 & 0xffff0000) << 14)) & 0xffff0000) << 32;
        }

        keys
    }

    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        for round_key in round_keys.iter().take(28) {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.sbox.apply((output >> (4*j)) & 0xf)) << (4*j);
            }

            // Apply linear layer
            output = self.linear_layer(tmp);

            // Add round key
            output ^= round_key;
        }

        output
    }

    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        for i in 0..28 {
            // Add round key
            output ^= round_keys[27-i];

            // Apply linear layer
            output = self.linear_layer_inv(output);
            
            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.isbox.apply((output >> (4*j)) & 0xf)) << (4*j);
            }

            output = tmp;
        }

        output
    }

    fn name(&self) -> String {
        String::from("GIFT64")
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
        false 
    }
}

impl Default for Gift64 {
    fn default() -> Self {
        Gift64::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher; 
    
    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("gift64").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(28, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(28, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}
