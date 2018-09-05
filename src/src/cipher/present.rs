//! Implementation of PRESENT with an 80-bit key.

use sbox::Sbox;
use cipher::{CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            PRESENT
******************************************************************/

/// A structure representing the PRESENT cipher.
#[derive(Clone)]
pub struct Present {
    size     : usize,
    key_size : usize,
    sbox     : Sbox,
    isbox    : Sbox,
}

impl Present {
    const PERMUTATION_INV : [[u128 ; 0x100] ; 8] = include!("data/present.inv.perm");
    const PERMUTATION     : [[u128 ; 0x100] ; 8] = include!("data/present.perm");
    const SBOX : [u8 ; 16] = [0xc, 0x5, 0x6, 0xb,
                              0x9, 0x0, 0xa, 0xd,
                              0x3, 0xe, 0xf, 0x8,
                              0x4, 0x7, 0x1, 0x2];
    const ISBOX : [u8 ; 16] = [0x5, 0xe, 0xf, 0x8,
                               0xc, 0x1, 0x2, 0xd,
                               0xb, 0x4, 0x6, 0x3,
                               0x0, 0x7, 0x9, 0xa];
    
    /// Create a new instance of the cipher.
    pub fn new() -> Present {
        let table: Vec<_> = From::from(&Present::SBOX[0..]);
        let itable: Vec<_> = From::from(&Present::ISBOX[0..]);
        Present{size: 64,
                key_size: 80,
                sbox: Sbox::new(4, 4, table),
                isbox: Sbox::new(4, 4, itable)}
    }
}

impl Cipher for Present {
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
        output ^= Present::PERMUTATION[0][((input as u64      ) & 0xff) as usize];
        output ^= Present::PERMUTATION[1][((input as u64 >>  8) & 0xff) as usize];
        output ^= Present::PERMUTATION[2][((input as u64 >> 16) & 0xff) as usize];
        output ^= Present::PERMUTATION[3][((input as u64 >> 24) & 0xff) as usize];
        output ^= Present::PERMUTATION[4][((input as u64 >> 32) & 0xff) as usize];
        output ^= Present::PERMUTATION[5][((input as u64 >> 40) & 0xff) as usize];
        output ^= Present::PERMUTATION[6][((input as u64 >> 48) & 0xff) as usize];
        output ^= Present::PERMUTATION[7][((input as u64 >> 56) & 0xff) as usize];

        output as u128
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;
        output ^= Present::PERMUTATION_INV[0][((input as u64      ) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[1][((input as u64 >>  8) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[2][((input as u64 >> 16) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[3][((input as u64 >> 24) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[4][((input as u64 >> 32) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[5][((input as u64 >> 40) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[6][((input as u64 >> 48) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[7][((input as u64 >> 56) & 0xff) as usize];

        output as u128
    }

    fn reflection_layer(&self, _input: u128) -> u128 {
        panic!("Not implemented for this type of cipher")
    }

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u128> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut s0 : u64 = 0;
        let mut s1 : u64 = 0;

        // load key into 80-bit state (s0 || s1)
        for &k in key.iter().take(8) {
            s0 <<= 8;
            s0 |= u64::from(k);
        }

        s1 |= u64::from(key[8]);
        s1 <<= 8;
        s1 |= u64::from(key[9]);

        for r in 0..(rounds+1) {
            // extract round key
            keys.push(s0);

            // rotate 61-bits left
            assert!(s1 >> 16 == 0);

            {
                let mut t0 : u64 = 0;
                t0 |= s0 << 61;
                t0 |= s1 << (64 - (3 + 16));
                t0 |= s0 >> 19;

                s1 = (s0 >> 3) & 0xffff;
                s0 = t0;
            }

            // apply sbox to 4 MSBs
            {
                let x = s0 >> 60;
                let y = u64::from(Present::SBOX[x as usize]);
                s0 &= 0x0fffffffffffffff;
                s0 |= y << 60;
            }

            // add round constant
            let rnd = ((r+1) & 0b11111) as u64;
            s0 ^= rnd >> 1;
            s1 ^= (rnd & 1) << 15;
        }

        keys.iter().map(|&x| u128::from(x)).collect()
    }

    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        output ^= round_keys[0];

        for round_key in round_keys.iter().take(32).skip(1) {
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

        output ^= round_keys[31];

        for i in 1..32 {
            // Apply linear layer
            output = self.linear_layer_inv(output);

            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.isbox.apply((output >> (4*j)) & 0xf)) << (4*j);
            }

            // Add round key
            output = tmp ^ round_keys[31-i]
        }

        output
    }

    fn name(&self) -> String {
        String::from("PRESENT")
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
        let cipher = cipher::name_to_cipher("present").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(31, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x5579c1387b228445;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(31, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x3333dcd3213210d2;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("present").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(31, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x5579c1387b228445;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(31, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x3333dcd3213210d2;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("present").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(31, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(31, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}
