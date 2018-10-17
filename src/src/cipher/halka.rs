//! Implementation of Halka.

use crate::sbox::Sbox;
use crate::cipher::{CipherStructure, Cipher};
use crate::property::PropertyType;

/*****************************************************************
                            Halka
******************************************************************/

/// A structure representing the Halka cipher.
#[derive(Clone)]
pub struct Halka {
    size     : usize,
    key_size : usize,
    sbox     : Sbox,
    isbox    : Sbox,
    perm     : [usize; 64],
    iperm    : [usize; 64]
}

impl Halka {
    /// Create a new instance of the cipher.
    pub fn new() -> Halka {
        let table = vec![0x24,0x2c,0x20,0xdc,0x26,0x73,0xd8,0x91,0x25,0xb7,0x8f,0x9c,0xda,0x1f,0xfe,0xe9,
                         0x9f,0xa4,0xd5,0x6d,0xc3,0x71,0x32,0x78,0x96,0xdb,0x55,0xb9,0x4c,0x49,0x6e,0x42,
                         0x9a,0xf9,0x1d,0x64,0x03,0x5c,0xa0,0x00,0x4a,0xd7,0xe3,0x8e,0x75,0xaf,0x0b,0x0a,
                         0x7d,0x4d,0x5b,0x1a,0x1c,0xe7,0x6a,0x74,0x10,0x06,0x92,0x29,0x81,0x79,0x17,0x40,
                         0x07,0x7b,0x69,0xca,0xc8,0xb8,0xef,0x84,0xc2,0x37,0x3a,0x98,0xdf,0x66,0x12,0xb6,
                         0x13,0x08,0x5d,0xfc,0x47,0x31,0xf1,0x21,0x8c,0x14,0xe1,0x51,0x33,0x19,0xb3,0x65,
                         0x88,0x4e,0x90,0x70,0x1b,0xa8,0x3b,0xcc,0x38,0x15,0x45,0xa7,0x83,0x39,0x0c,0xde,
                         0xa1,0x3e,0xc1,0xb5,0xeb,0x7f,0xac,0xa2,0x01,0x76,0x9b,0x8a,0xb4,0xbd,0x99,0x16,
                         0x35,0xd4,0x8b,0x4f,0x02,0x54,0x53,0xbe,0x52,0xc7,0xea,0x09,0x41,0xc6,0xf4,0xb1,
                         0x58,0x57,0x6b,0x2d,0xf8,0xab,0x87,0x7a,0xf6,0x59,0xa3,0x85,0x61,0x3f,0x9e,0xed,
                         0x63,0xbf,0xfd,0xb2,0xe8,0x18,0xd2,0x48,0x7c,0x95,0x0f,0x2e,0x44,0xce,0x5f,0xa6,
                         0xf0,0x8d,0x3c,0xf5,0x46,0x23,0x1e,0xd0,0x2f,0xee,0xba,0x34,0x6f,0x5a,0x04,0x5e,
                         0xc5,0xf2,0xc4,0x11,0xe2,0x7e,0xe0,0x0e,0xdd,0xbb,0x9d,0x62,0x80,0x2b,0xae,0x50,
                         0xaa,0x97,0xbc,0xc9,0x94,0x72,0xe5,0xd3,0x77,0x86,0x2a,0xcd,0xb0,0x05,0xd9,0xd1,
                         0xe6,0xe4,0xa9,0xad,0xd6,0x56,0x6c,0x30,0x43,0xff,0x89,0xcb,0x60,0xf7,0x67,0xcf,
                         0xa5,0x36,0xc0,0x0d,0x93,0xfb,0x82,0xf3,0x27,0xec,0x4b,0x68,0x22,0xfa,0x28,0x3d];
        let itable = vec![0x27,0x78,0x84,0x24,0xbe,0xdd,0x39,0x40,0x51,0x8b,0x2f,0x2e,0x6e,0xf3,0xc7,0xaa,
                          0x38,0xc3,0x4e,0x50,0x59,0x69,0x7f,0x3e,0xa5,0x5d,0x33,0x64,0x34,0x22,0xb6,0x0d,
                          0x02,0x57,0xfc,0xb5,0x00,0x08,0x04,0xf8,0xfe,0x3b,0xda,0xcd,0x01,0x93,0xab,0xb8,
                          0xe7,0x55,0x16,0x5c,0xbb,0x80,0xf1,0x49,0x68,0x6d,0x4a,0x66,0xb2,0xff,0x71,0x9d,
                          0x3f,0x8c,0x1f,0xe8,0xac,0x6a,0xb4,0x54,0xa7,0x1d,0x28,0xfa,0x1c,0x31,0x61,0x83,
                          0xcf,0x5b,0x88,0x86,0x85,0x1a,0xe5,0x91,0x90,0x99,0xbd,0x32,0x25,0x52,0xbf,0xae,
                          0xec,0x9c,0xcb,0xa0,0x23,0x5f,0x4d,0xee,0xfb,0x42,0x36,0x92,0xe6,0x13,0x1e,0xbc,
                          0x63,0x15,0xd5,0x05,0x37,0x2c,0x79,0xd8,0x17,0x3d,0x97,0x41,0xa8,0x30,0xc5,0x75,
                          0xcc,0x3c,0xf6,0x6c,0x47,0x9b,0xd9,0x96,0x60,0xea,0x7b,0x82,0x58,0xb1,0x2b,0x0a,
                          0x62,0x07,0x3a,0xf4,0xd4,0xa9,0x18,0xd1,0x4b,0x7e,0x20,0x7a,0x0b,0xca,0x9e,0x10,
                          0x26,0x70,0x77,0x9a,0x11,0xf0,0xaf,0x6b,0x65,0xe2,0xd0,0x95,0x76,0xe3,0xce,0x2d,
                          0xdc,0x8f,0xa3,0x5e,0x7c,0x73,0x4f,0x09,0x45,0x1b,0xba,0xc9,0xd2,0x7d,0x87,0xa1,
                          0xf2,0x72,0x48,0x14,0xc2,0xc0,0x8d,0x89,0x44,0xd3,0x43,0xeb,0x67,0xdb,0xad,0xef,
                          0xb7,0xdf,0xa6,0xd7,0x81,0x12,0xe4,0x29,0x06,0xde,0x0c,0x19,0x03,0xc8,0x6f,0x4c,
                          0xc6,0x5a,0xc4,0x2a,0xe1,0xd6,0xe0,0x35,0xa4,0x0f,0x8a,0x74,0xf9,0x9f,0xb9,0x46,
                          0xb0,0x56,0xc1,0xf7,0x8e,0xb3,0x98,0xed,0x94,0x21,0xfd,0xf5,0x53,0xa2,0x0e,0xe9];
        let perm = [10,21,28,38,44,48,59,1,51,15,41,2,60,34,24,20,56,6,17,31,36,53,12,46,30,52,11,4,23,35,40,63,8,39,3,43,57,49,16,25,37,42,61,50,0,9,18,26,58,55,7,19,29,14,47,32,33,5,62,45,13,54,22,27];
        let iperm = [44,7,11,34,27,57,17,50,32,45,0,26,22,60,53,9,38,18,46,51,15,1,62,28,14,39,47,63,2,52,24,19,55,56,13,29,20,40,3,33,30,10,41,35,4,59,23,54,5,37,43,8,25,21,61,49,16,36,48,6,12,42,58,31];

        Halka { size: 64,
                key_size: 80,
                sbox: Sbox::new(8, 8, table),
                isbox: Sbox::new(8, 8, itable),
                perm,
                iperm
        }
    }
}

impl Cipher for Halka {
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

        for i in 0..64 {
            output ^= ((input >> i) & 0x1) << self.perm[i];
        }

        output
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;

        for i in 0..64 {
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
        let mut s : u128 = 0;

        // load key into 80-bit state
        for &k in key.iter().take(10) {
            s <<= 8;
            s |= u128::from(k);
        }

        for r in 0..(rounds+1) {
            keys.push((s >> 16) & 0xffffffffffffffff);

            s = ((s << 57) & 0xffffffffffffffffffff) ^  ((s >> 23) & 0xffffffffffffffffffff);

            let tmp = (s >> 72) & 0xff;
            s = s & 0x00ffffffffffffffffff;
            s ^= u128::from(self.sbox.apply(tmp)) << 72;

            let rnd = ((r+1) & 0b11111) as u128;
            s ^= rnd << 15;
        }

        keys
    }

    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        output ^= round_keys[0];

        for round_key in round_keys.iter().take(25).skip(1) {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= u128::from(self.sbox.apply((output >> (8*j)) & 0xff)) << (8*j);
            }

            // Apply linear layer
            output = self.linear_layer(tmp);

            // Add round key
            output ^= round_key
        }

        output
    }

    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        output ^= round_keys[24];

        for i in 1..25 {
            // Apply linear layer
            output = self.linear_layer_inv(output);

            // Apply S-box
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= u128::from(self.isbox.apply((output >> (8*j)) & 0xff)) << (8*j);
            }

            // Add round key
            output = tmp ^ round_keys[24-i]
        }

        output
    }

    fn name(&self) -> String {
        String::from("Halka")
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
    fn linear_test() {
        let cipher = cipher::name_to_cipher("halka").unwrap();
        let x = 0x0123456789abcdef;

        assert_eq!(x, cipher.linear_layer_inv(cipher.linear_layer(x)));
    }

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("halka").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(24, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x0136ff2b22fdaed5;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(24, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0xca6f36922252f05a;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("halka").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(24, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x0136ff2b22fdaed5;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(24, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0xca6f36922252f05a;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("halka").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(24, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(24, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}