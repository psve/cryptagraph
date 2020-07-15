//! Implementation of EPCBC-48.

use crate::cipher::{Cipher, CipherStructure};
use crate::property::PropertyType;
use crate::sbox::Sbox;
use std::mem;

/*****************************************************************
                            EPCBC48
******************************************************************/

//// A structure representing the EPCBC48 cipher.
#[derive(Clone)]
pub struct Epcbc48 {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox,
}

impl Epcbc48 {
    const SBOX: [u8; 16] = [
        0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2,
    ];
    const ISBOX: [u8; 16] = [
        0x5, 0xe, 0xf, 0x8, 0xc, 0x1, 0x2, 0xd, 0xb, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xa,
    ];

    /// Create a new instance of the cipher.
    pub fn new() -> Epcbc48 {
        let table: Vec<_> = From::from(&Epcbc48::SBOX[0..]);
        let itable: Vec<_> = From::from(&Epcbc48::ISBOX[0..]);
        Epcbc48 {
            size: 48,
            key_size: 96,
            sbox: Sbox::new(4, 4, table),
            isbox: Sbox::new(4, 4, itable),
        }
    }
}

impl Cipher for Epcbc48 {
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
        i * self.sbox(i).size_in()
    }

    fn sbox_pos_out(&self, i: usize) -> usize {
        i * self.sbox(i).size_out()
    }

    fn linear_layer(&self, input: u128) -> u128 {
        let mut output = 0;

        for i in 0..self.size - 1 {
            output ^= ((input >> i) & 0x1) << ((i * self.size / 4) % (self.size - 1));
        }
        output ^= ((input >> (self.size - 1)) & 0x1) << (self.size - 1);

        output
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;

        for i in 0..self.size - 1 {
            output ^= ((input >> ((i * self.size / 4) % (self.size - 1))) & 0x1) << i;
        }
        output ^= ((input >> (self.size - 1)) & 0x1) << (self.size - 1);

        output
    }

    fn reflection_layer(&self, _input: u128) -> u128 {
        panic!("Not implemented for this type of cipher")
    }

    fn key_schedule(&self, rounds: usize, key: &[u8]) -> Vec<u128> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut l = 0;
        let mut r = 0;

        // load key into 80-bit state (s0 || s1)
        for i in 0..6 {
            l <<= 8;
            l |= u128::from(key[i]);

            r <<= 8;
            r |= u128::from(key[i + 6]);
        }

        keys.push(l);
        l ^= r;

        for i in 0..rounds {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..12 {
                tmp ^= u128::from(self.sbox.apply((r >> (4 * j)) & 0xf)) << (4 * j);
            }

            // Apply linear layer
            r = self.linear_layer(tmp);

            // Apply round constant
            r ^= i as u128;

            keys.push(r);

            if (i + 1) % 4 == 0 {
                mem::swap(&mut l, &mut r);
                l ^= r;
            }
        }

        keys
    }

    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        output ^= round_keys[0];

        for round_key in round_keys.iter().take(33).skip(1) {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..12 {
                tmp ^= u128::from(self.sbox.apply((output >> (4 * j)) & 0xf)) << (4 * j);
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

        output ^= round_keys[32];

        for i in 1..33 {
            // Apply linear layer
            output = self.linear_layer_inv(output);

            // Apply S-box
            let mut tmp = 0;

            for j in 0..12 {
                tmp ^= u128::from(self.isbox.apply((output >> (4 * j)) & 0xf)) << (4 * j);
            }

            // Add round key
            output = tmp ^ round_keys[32 - i]
        }

        output
    }

    fn name(&self) -> String {
        String::from("EPCBC48")
    }

    fn sbox_mask_transform(
        &self,
        input: u128,
        output: u128,
        _property_type: PropertyType,
    ) -> (u128, u128) {
        (input, self.linear_layer(output))
    }

    #[inline(always)]
    fn whitening(&self) -> bool {
        true
    }
}

impl Default for Epcbc48 {
    fn default() -> Self {
        Epcbc48::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher;

    #[test]
    fn linear() {
        let cipher = cipher::name_to_cipher("epcbc48").unwrap();
        let x = 0x0123456789ab;

        assert_eq!(x, cipher.linear_layer_inv(cipher.linear_layer(x)));
    }

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("epcbc48").unwrap();
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        ];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0123456789AB;
        let ciphertext = 0x0B46B67143DC;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("epcbc48").unwrap();
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        ];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0123456789AB;
        let ciphertext = 0x0B46B67143DC;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("epcbc48").unwrap();
        let key = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x000000000000;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xff;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}
