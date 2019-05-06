//! Implementation of KLEIN.

use crate::sbox::Sbox;
use crate::cipher::{CipherStructure, Cipher};
use crate::property::PropertyType;
use std::mem;

/*****************************************************************
                            KLEIN
******************************************************************/

/// A structure representing the KLEIN cipher.
#[derive(Clone)]
pub struct Klein {
    size     : usize,
    key_size : usize,
    sbox     : Sbox,
}

impl Klein {
    /// Create a new instance of the cipher.
    pub fn new() -> Klein {
        let table = vec![0x7,0x4,0xa,0x9,0x1,0xf,0xb,0x0,0xc,0x3,0x2,0x6,0x8,0xe,0xd,0x5];
        Klein{
            size: 64, 
            key_size: 64, 
            sbox: Sbox::new(4, 4, table)
        }
    }
}

/**
Calculate y*02 in the Rijndael finite field
*/
fn mult_02(y: u8) -> u8{
    let t = y << 1;
    let u = 0xff * ((y >> 7) & 0x1);
    (u & 0x1b) ^ t
}

/**
Calculate y*04 in the Rijndael finite field
*/
fn mult_04(y: u8) -> u8{
    mult_02(mult_02(y))
}

/**
Calculate y*08 in the Rijndael finite field
*/
fn mult_08(y: u8) -> u8{
    mult_02(mult_04(y))
}

impl Cipher for Klein {
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
        let mut output = input as u64;

        // RotateNibbles
        output = (output << 16) ^ (output >> 48);

        // MixNibbles
        for i in 0..2 {
            let mut x = [((output >> (i*32+24)) & 0xff) as u8,
                         ((output >> (i*32+16)) & 0xff) as u8,
                         ((output >> (i*32+ 8)) & 0xff) as u8, 
                         ((output >> (i*32   )) & 0xff) as u8];

            let t = x[0] ^ x[1] ^ x[2] ^ x[3];
            let u = x[3] ^ x[0];
            
            for j in 0..3 {
                x[j] = x[j] ^ mult_02(x[j]^x[j+1]) ^ t;
            }
            x[3] = x[3] ^ mult_02(u) ^ t;

            output &= !(0xffffffff << (i*32));
            output ^= u64::from(x[0]) << (i*32+24);
            output ^= u64::from(x[1]) << (i*32+16);
            output ^= u64::from(x[2]) << (i*32+8);
            output ^= u64::from(x[3]) << (i*32);
        }

        u128::from(output)
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = input as u64; 

        // MixNibbles inverse
        for i in 0..2 {
            let x = [((output >> (i*32+24)) & 0xff) as u8,
                     ((output >> (i*32+16)) & 0xff) as u8,
                     ((output >> (i*32+ 8)) & 0xff) as u8, 
                     ((output >> (i*32   )) & 0xff) as u8];

            let mut y = [0, 0, 0, 0];

            y[0] = mult_08(x[0]^x[1]^x[2]^x[3]) ^
                   mult_04(x[0]^x[2]) ^ mult_02(x[0]^x[1]) ^
                   x[1] ^ x[2] ^ x[3];
            y[1] = mult_08(x[1]^x[2]^x[3]^x[0]) ^
                   mult_04(x[1]^x[3]) ^ mult_02(x[1]^x[2]) ^
                   x[2] ^ x[3] ^ x[0];
            y[2] = mult_08(x[2]^x[3]^x[0]^x[1]) ^
                   mult_04(x[2]^x[0]) ^ mult_02(x[2]^x[3]) ^
                   x[3] ^ x[0] ^ x[1];
            y[3] = mult_08(x[3]^x[0]^x[1]^x[2]) ^
                   mult_04(x[3]^x[1]) ^ mult_02(x[3]^x[0]) ^
                   x[0] ^ x[1] ^ x[2];

            output &= !(0xffffffff << (i*32));
            output ^= u64::from(y[0]) << (i*32+24);
            output ^= u64::from(y[1]) << (i*32+16);
            output ^= u64::from(y[2]) << (i*32+8);
            output ^= u64::from(y[3]) << (i*32);
        }

        // RotateNibbles inverse
        output = (output >> 16) ^ (output << 48);

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

        for i in 0..4 {
            k1 <<= 8;
            k0 <<= 8;
            k1 |= u128::from(key[i]);
            k0 |= u128::from(key[i+4]);
        }

        for r in 0..=rounds {
            keys.push(k0 ^ (k1 << 32));

            k0 = ((k0 << 8) & 0xffffff00) ^ ((k0 >> 24) & 0x000000ff);
            k1 = ((k1 << 8) & 0xffffff00) ^ ((k1 >> 24) & 0x000000ff);
            k1 ^= k0;
            mem::swap(&mut k0, &mut k1);

            for i in 2..6 {
                k0 = (k0 & !(0xf << (4*i))) ^ (u128::from(self.sbox.apply((k0 >> (4*i)) & 0xf)) << (4*i));
            }

            k1 ^= ((r + 1) as u128) << 8;
        }

        keys
    }

    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        for &round_key in round_keys.iter().take(12) {
            // Add key
            output ^= round_key;

            // SubNibbles
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.sbox.apply((output >> (4*j)) & 0xf)) << (4*j);
            }

            // Linear layer
            output = self.linear_layer(tmp);
        }

        output ^= round_keys[12];
        output
    }

    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        for i in 0..12 {
            // Add key
            output ^= round_keys[12-i];

            // Linear layer
            output = self.linear_layer_inv(output);
            
            // SubNibbles
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.sbox.apply((output >> (4*j)) & 0xf)) << (4*j);
            }

            output = tmp;
        }

        output ^= round_keys[0];
        output
    }

    fn name(&self) -> String {
        String::from("KLEIN")
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

impl Default for Klein {
    fn default() -> Self {
        Klein::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher; 

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("klein").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0xcdc0b51f14722bbe;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x6456764e8602e154;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x592356c4997176c8;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0x1234567890abcdef;
        let ciphertext = 0x629f9d6dff95800e;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("klein").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0xcdc0b51f14722bbe;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x6456764e8602e154;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x592356c4997176c8;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0x1234567890abcdef;
        let ciphertext = 0x629f9d6dff95800e;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("klein").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}