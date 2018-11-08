//! Implementation of GIFT-128.

use crate::sbox::Sbox;
use crate::cipher::{CipherStructure, Cipher};
use crate::property::PropertyType;

/*****************************************************************
                            GIFT128
******************************************************************/

/// A structure representing the GIFT128 cipher.
#[derive(Clone)]
pub struct Gift128 {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox,
    constants: [u128; 48],
    perm: [u128; 128],
    iperm: [u128; 128]
}

impl Gift128 {
    /// Create a new instance of the cipher.
    pub fn new() -> Gift128 {
        let table = vec![0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
                         0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe];
        let itable = vec![0xd, 0x0, 0x8, 0x6, 0x2, 0xc, 0x4, 0xb, 
                          0xe, 0x7, 0x1, 0xa, 0x3, 0x9, 0xf, 0x5];
        let constants = [0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,0x27,
                         0x0e,0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b,0x17,0x2e,
                         0x1c,0x38,0x31,0x23,0x06,0x0d,0x1b,0x36,0x2d,0x1a,0x34,0x29,0x12,0x24,0x08,
                         0x11,0x22,0x04];
        let perm = [0,33,66,99,96,1,34,67,64,97,2,35,32,65,98,3,
                    4,37,70,103,100,5,38,71,68,101,6,39,36,69,102,7,
                    8,41,74,107,104,9,42,75,72,105,10,43,40,73,106,11,
                    12,45,78,111,108,13,46,79,76,109,14,47,44,77,110,15,
                    16,49,82,115,112,17,50,83,80,113,18,51,48,81,114,19,
                    20,53,86,119,116,21,54,87,84,117,22,55,52,85,118,23,
                    24,57,90,123,120,25,58,91,88,121,26,59,56,89,122,27,
                    28,61,94,127,124,29,62,95,92,125,30,63,60,93,126,31];
        let iperm = [0,5,10,15,16,21,26,31,32,37,42,47,48,53,58,63,64,69,
                     74,79,80,85,90,95,96,101,106,111,112,117,122,127,12,
                     1,6,11,28,17,22,27,44,33,38,43,60,49,54,59,76,65,70,
                     75,92,81,86,91,108,97,102,107,124,113,118,123,8,13,
                     2,7,24,29,18,23,40,45,34,39,56,61,50,55,72,77,66,71,
                     88,93,82,87,104,109,98,103,120,125,114,119,4,9,14,3,
                     20,25,30,19,36,41,46,35,52,57,62,51,68,73,78,67,84,89,
                     94,83,100,105,110,99,116,121,126,115];

        Gift128{size: 128, 
                key_size: 128,
                sbox: Sbox::new(4, 4, table), 
                isbox: Sbox::new(4, 4, itable),
                constants,
                perm,
                iperm
         }
    }
}

impl Cipher for Gift128 {
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
        
        for i in 0..128 {
            output ^= ((input >> i) & 0x1) << self.perm[i];
        }

        output
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;
        
        for i in 0..128 {
            output ^= ((input >> i) & 0x1) << self.iperm[i];
        }

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

            for i in 0..32 {
                round_key ^= ((k0 >> i) & 0x1) << (4*i+1);
                round_key ^= ((k0 >> (i+32)) & 0x1) << (4*i+2);
            }

            round_key ^= 1 << 127;
            round_key ^= (self.constants[r] & 0x1) << 3;
            round_key ^= ((self.constants[r] >> 1) & 0x1) << 7;
            round_key ^= ((self.constants[r] >> 2) & 0x1) << 11;
            round_key ^= ((self.constants[r] >> 3) & 0x1) << 15;
            round_key ^= ((self.constants[r] >> 4) & 0x1) << 19;
            round_key ^= ((self.constants[r] >> 5) & 0x1) << 23;

            keys.push(round_key);

            let t0 = k0;
            let t1 = k1;

            k0 = t0 >> 32;
            k0 ^= t1 << 32;
            k1 = t1 >> 32;
            k1 ^= ((((t0 & 0xffff) >> 12) ^ ((t0 & 0xffff) << 4)) & 0xffff) << 32;
            k1 ^= ((((t0 & 0xffff0000) >> 2) ^ ((t0 & 0xffff0000) << 14)) & 0xffff0000) << 32;
        }

        keys
    }

    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        for round_key in round_keys.iter().take(40) {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..32 {
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

        for i in 0..40 {
            // Add round key
            output ^= round_keys[39-i];

            // Apply linear layer
            output = self.linear_layer_inv(output);
            
            // Apply S-box
            let mut tmp = 0;

            for j in 0..32 {
                tmp ^= u128::from(self.isbox.apply((output >> (4*j)) & 0xf)) << (4*j);
            }

            output = tmp;
        }

        output
    }

    fn name(&self) -> String {
        String::from("GIFT128")
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

impl Default for Gift128 {
    fn default() -> Self {
        Gift128::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher; 
    
    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("gift128").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(40, &key);
        let plaintext = 0x00112233445566778899aabbccddeeff;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(40, &key);
        let plaintext = 0x00112233445566778899aabbccddeeff;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}