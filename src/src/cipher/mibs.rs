//! Implementation of MIBS.

use crate::cipher::{Cipher, CipherStructure};
use crate::property::PropertyType;
use crate::sbox::Sbox;

/*****************************************************************
                            MIBS
******************************************************************/

/// A structure representing the MIBS cipher.
#[derive(Clone)]
pub struct Mibs {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox,
}

impl Mibs {
    const PERMUTATION: [usize; 8] = [3, 4, 1, 2, 5, 7, 0, 6];
    const IPERMUTATION: [usize; 8] = [6, 2, 3, 0, 1, 4, 7, 5];

    /// Create a new instance of the cipher.
    pub fn new() -> Mibs {
        let table = vec![4, 15, 3, 8, 13, 10, 12, 0, 11, 5, 7, 14, 2, 6, 1, 9];
        let itable = vec![7, 14, 12, 2, 0, 9, 13, 10, 3, 15, 5, 8, 6, 4, 11, 1];
        Mibs {
            size: 64,
            key_size: 64,
            sbox: Sbox::new(4, 4, table),
            isbox: Sbox::new(4, 4, itable),
        }
    }
}

impl Cipher for Mibs {
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
        i * self.sbox(i).size_in()
    }

    fn sbox_pos_out(&self, i: usize) -> usize {
        i * self.sbox(i).size_out()
    }

    fn linear_layer(&self, input: u128) -> u128 {
        let mut x = input as u64;
        x ^= (x & (0xf << 16)) >> 16;
        x ^= (x & (0xf << 20)) >> 16;
        x ^= (x & (0xf << 24)) >> 16;
        x ^= (x & (0xf << 28)) >> 16;
        x ^= (x & (0xf)) << 24;
        x ^= (x & (0xf << 4)) << 24;
        x ^= (x & (0xf << 8)) << 8;
        x ^= (x & (0xf << 12)) << 8;
        x ^= (x & (0xf << 16)) >> 4;
        x ^= (x & (0xf << 20)) >> 20;
        x ^= (x & (0xf << 24)) >> 20;
        x ^= (x & (0xf << 28)) >> 20;
        x ^= (x & (0xf)) << 16;
        x ^= (x & (0xf << 4)) << 16;
        x ^= (x & (0xf << 8)) << 16;
        x ^= (x & (0xf << 12)) << 16;

        let mut output = 0;

        output ^= ((x) & 0xf) << (Mibs::PERMUTATION[0] * 4);
        output ^= ((x >> 4) & 0xf) << (Mibs::PERMUTATION[1] * 4);
        output ^= ((x >> 8) & 0xf) << (Mibs::PERMUTATION[2] * 4);
        output ^= ((x >> 12) & 0xf) << (Mibs::PERMUTATION[3] * 4);
        output ^= ((x >> 16) & 0xf) << (Mibs::PERMUTATION[4] * 4);
        output ^= ((x >> 20) & 0xf) << (Mibs::PERMUTATION[5] * 4);
        output ^= ((x >> 24) & 0xf) << (Mibs::PERMUTATION[6] * 4);
        output ^= ((x >> 28) & 0xf) << (Mibs::PERMUTATION[7] * 4);

        u128::from(output)
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;

        output ^= ((input as u64) & 0xf) << (Mibs::IPERMUTATION[0] * 4);
        output ^= ((input as u64 >> 4) & 0xf) << (Mibs::IPERMUTATION[1] * 4);
        output ^= ((input as u64 >> 8) & 0xf) << (Mibs::IPERMUTATION[2] * 4);
        output ^= ((input as u64 >> 12) & 0xf) << (Mibs::IPERMUTATION[3] * 4);
        output ^= ((input as u64 >> 16) & 0xf) << (Mibs::IPERMUTATION[4] * 4);
        output ^= ((input as u64 >> 20) & 0xf) << (Mibs::IPERMUTATION[5] * 4);
        output ^= ((input as u64 >> 24) & 0xf) << (Mibs::IPERMUTATION[6] * 4);
        output ^= ((input as u64 >> 28) & 0xf) << (Mibs::IPERMUTATION[7] * 4);

        let mut x = output;

        x ^= (x & (0xf << 12)) << 16;
        x ^= (x & (0xf << 8)) << 16;
        x ^= (x & (0xf << 4)) << 16;
        x ^= (x & (0xf)) << 16;
        x ^= (x & (0xf << 28)) >> 20;
        x ^= (x & (0xf << 24)) >> 20;
        x ^= (x & (0xf << 20)) >> 20;
        x ^= (x & (0xf << 16)) >> 4;
        x ^= (x & (0xf << 12)) << 8;
        x ^= (x & (0xf << 8)) << 8;
        x ^= (x & (0xf << 4)) << 24;
        x ^= (x & (0xf)) << 24;
        x ^= (x & (0xf << 28)) >> 16;
        x ^= (x & (0xf << 24)) >> 16;
        x ^= (x & (0xf << 20)) >> 16;
        x ^= (x & (0xf << 16)) >> 16;

        u128::from(x)
    }

    fn reflection_layer(&self, _input: u128) -> u128 {
        panic!("Not implemented for this type of cipher")
    }

    fn key_schedule(&self, rounds: usize, key: &[u8]) -> Vec<u128> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut s = 0;

        // load key into 63-bit state
        for &k in key.iter().take(8) {
            s <<= 8;
            s |= u64::from(k);
        }

        for r in 0..rounds {
            s = (s >> 15) ^ (s << (64 - 15));
            s = (s & 0x0fffffffffffffff) ^ (u64::from(self.sbox.apply(s >> 60)) << 60);
            s ^= ((r + 1) as u64) << 11;
            keys.push(s >> 32);
        }

        keys.iter().map(|&x| u128::from(x)).collect()
    }

    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input as u64;

        for &round_key in round_keys.iter().take(32) {
            let mut left = output >> 32;
            let right = output & 0xffffffff;
            output = left;

            // Add round key
            left ^= round_key as u64;

            // Sbox
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= u128::from(self.sbox.apply((left >> (4 * j)) & 0xf)) << (4 * j);
            }

            // Linear layer
            left = self.linear_layer(tmp) as u64;

            output ^= (right ^ left) << 32;
        }

        output = (output >> 32) ^ (output << 32);
        u128::from(output)
    }

    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input as u64;

        for i in 0..32 {
            let mut left = output >> 32;
            let right = output & 0xffffffff;
            output = left;

            // Add round key
            left ^= round_keys[31 - i] as u64;

            // Sbox
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= u128::from(self.sbox.apply((left >> (4 * j)) & 0xf)) << (4 * j);
            }

            // Linear layer
            left = self.linear_layer(tmp) as u64;

            output ^= (right ^ left) << 32;
        }

        u128::from((output >> 32) ^ (output << 32))
    }

    fn name(&self) -> String {
        String::from("MIBS")
    }

    fn sbox_mask_transform(
        &self,
        input: u128,
        output: u128,
        property_type: PropertyType,
    ) -> (u128, u128) {
        match property_type {
            PropertyType::Linear => {
                let input = input as u64;
                let output = self.linear_layer(output & 0xffffffff) as u64
                    ^ ((self.linear_layer(output >> 32) as u64) << 32);
                let mut alpha = output;
                alpha ^= input << 32;

                let mut beta = output;
                beta ^= input >> 32;

                (u128::from(alpha), u128::from(beta))
            }
            PropertyType::Differential => {
                let input = input as u64;
                let output = self.linear_layer(output & 0xffffffff) as u64
                    ^ ((self.linear_layer(output >> 32) as u64) << 32);
                let mut delta = (input >> 32) ^ (input << 32);
                delta ^= output & 0xffffffff;

                let mut nabla = (input >> 32) ^ (input << 32);
                nabla ^= output & 0xffffffff00000000;

                (u128::from(delta), u128::from(nabla))
            }
        }
    }

    #[inline(always)]
    fn whitening(&self) -> bool {
        false
    }
}

impl Default for Mibs {
    fn default() -> Self {
        Mibs::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher;

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("mibs").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x6d1d3722e19613d2;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x595263b93ffe6e18;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("mibs").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x6d1d3722e19613d2;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x595263b93ffe6e18;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("mibs").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}
