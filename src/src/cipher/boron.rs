//! Implementation of BORON with an 80-bit key.

use crate::sbox::Sbox;
use crate::cipher::{CipherStructure, Cipher};
use crate::property::PropertyType;

/*****************************************************************
                            BORON
******************************************************************/

/// A structure representing the BORON cipher.
#[derive(Clone)]
pub struct Boron {
    size     : usize,
    key_size : usize,
    sbox     : Sbox,
    isbox    : Sbox,
}

impl Boron {
    /// Create a new instance of the cipher.
    pub fn new() -> Boron {
        let table = vec![0xe,0x4,0xb,0x1,0x7,0x9,0xc,0xa,0xd,0x2,0x0,0xf,0x8,0x5,0x3,0x6];
        let itable = vec![0xa,0x3,0x9,0xe,0x1,0xd,0xf,0x4,0xc,0x5,0x7,0x2,0x6,0x8,0x0,0xb];

        Boron{size: 64,
              key_size: 80,
              sbox: Sbox::new(4, 4, table),
              isbox: Sbox::new(4, 4, itable)}
    }
}

impl Cipher for Boron {
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

        // Block shuffle
        output ^= (input & 0xff00ff00ff00ff00) >> 8;
        output ^= (input & 0x00ff00ff00ff00ff) << 8;

        // Permutation
        let tmp = output;
        output = 0;

        output ^= ((tmp << 1) & 0xfffe) ^ ((tmp >> 15) & 0x0001);
        output ^= ((tmp << 4) & 0xfff00000) ^ ((tmp >> 12) & 0x000f0000);
        output ^= ((tmp << 7) & 0xff8000000000) ^ ((tmp >> 9) & 0x007f00000000);
        output ^= ((tmp << 9) & 0xfe00000000000000) ^ ((tmp >> 7) & 0x01ff000000000000);

        // XOR
        output ^= (output & 0xffff) << 32;
        output ^= (output & 0xffff000000000000) >> 32;
        output ^= (output & 0xffff0000) >> 16;
        output ^= (output & 0xffff00000000) << 16;

        output
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = input;
        
        // XOR
        output ^= (output & 0xffff00000000) << 16;
        output ^= (output & 0xffff0000) >> 16;
        output ^= (output & 0xffff000000000000) >> 32;
        output ^= (output & 0xffff) << 32;

        // Permutation
        let tmp = output;
        output = 0;

        output ^= ((tmp & 0x0001) << 15) ^ ((tmp & 0xfffe) >> 1);
        output ^= ((tmp & 0x000f0000) << 12) ^ ((tmp & 0xfff00000) >> 4);
        output ^= ((tmp & 0x007f00000000) << 9) ^ ((tmp & 0xff8000000000) >> 7);
        output ^= ((tmp & 0x01ff000000000000) << 7) ^ ((tmp & 0xfe00000000000000) >> 9);

        // Block shuffle
        let tmp = output;
        output = 0;

        output ^= (tmp & 0xff00ff00ff00ff00) >> 8;
        output ^= (tmp & 0x00ff00ff00ff00ff) << 8;

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

        for r in 0..=rounds {
            keys.push(s & 0xffffffffffffffff);

            s = ((s << 13) & 0xffffffffffffffffffff) ^  ((s >> 67) & 0xffffffffffffffffffff);

            let tmp = s & 0xf;
            s &= 0xfffffffffffffffffff0;
            s ^= u128::from(self.sbox.apply(tmp));

            let rnd = (r & 0b11111) as u128;
            s ^= rnd << 59;
        }

        keys
    }

    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        output ^= round_keys[0];

        for round_key in round_keys.iter().take(26).skip(1) {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.sbox.apply((output >> (4*j)) & 0xf)) << (4*j);
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

        output ^= round_keys[25];

        for i in 1..26 {
            // Apply linear layer
            output = self.linear_layer_inv(output);

            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.isbox.apply((output >> (4*j)) & 0xf)) << (4*j);
            }

            // Add round key
            output = tmp ^ round_keys[25-i]
        }

        output
    }

    fn name(&self) -> String {
        String::from("BORON")
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

impl Default for Boron {
    fn default() -> Self {
        Boron::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher;

    #[test]
    fn linear_test() {
        let cipher = cipher::name_to_cipher("boron").unwrap();
        let x = 0x0123456789abcdef;

        assert_eq!(x, cipher.linear_layer_inv(cipher.linear_layer(x)));
    }

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("boron").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x3cf72a8b7518e6f7;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = 0x5a664928b961c619;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("boron").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x3cf72a8b7518e6f7;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = 0x5a664928b961c619;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("boron").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}
