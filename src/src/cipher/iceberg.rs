//! Implementation of ICEBERG.

use crate::sbox::Sbox;
use crate::cipher::{CipherStructure, Cipher};
use crate::property::PropertyType;

/*****************************************************************
                            ICEBERG
******************************************************************/

/// A structure representing the ICEBERG cipher.
#[derive(Clone)]
pub struct Iceberg {
    size: usize,
    key_size: usize,
    sbox_8: Sbox,
    sbox_4: Sbox,
    table_64: [usize; 64],
    table_d:  [u128; 16],
    table_4:  [u128; 16],
    table_128: [usize; 128]
}

impl Iceberg {
    /// Create a new instance of the cipher.
    pub fn new() -> Iceberg {
        let sbox_8 = vec![
            0x24, 0xc1, 0x38, 0x30, 0xe7, 0x57, 0xdf, 0x20, 0x3e, 0x99, 0x1a, 0x34, 0xca, 0xd6, 0x52, 0xfd,
            0x40, 0x6c, 0xd3, 0x3d, 0x4a, 0x59, 0xf8, 0x77, 0xfb, 0x61, 0x0a, 0x56, 0xb9, 0xd2, 0xfc, 0xf1,
            0x07, 0xf5, 0x93, 0xcd, 0x00, 0xb6, 0x62, 0xa7, 0x63, 0xfe, 0x44, 0xbd, 0x5f, 0x92, 0x6b, 0x68,
            0x03, 0x4e, 0xa2, 0x97, 0x0b, 0x60, 0x83, 0xa3, 0x02, 0xe5, 0x45, 0x67, 0xf4, 0x13, 0x08, 0x8b,
            0x10, 0xce, 0xbe, 0xb4, 0x2a, 0x3a, 0x96, 0x84, 0xc8, 0x9f, 0x14, 0xc0, 0xc4, 0x6f, 0x31, 0xd9,
            0xab, 0xae, 0x0e, 0x64, 0x7c, 0xda, 0x1b, 0x05, 0xa8, 0x15, 0xa5, 0x90, 0x94, 0x85, 0x71, 0x2c,
            0x35, 0x19, 0x26, 0x28, 0x53, 0xe2, 0x7f, 0x3b, 0x2f, 0xa9, 0xcc, 0x2e, 0x11, 0x76, 0xed, 0x4d,
            0x87, 0x5e, 0xc2, 0xc7, 0x80, 0xb0, 0x6d, 0x17, 0xb2, 0xff, 0xe4, 0xb7, 0x54, 0x9d, 0xb8, 0x66,
            0x74, 0x9c, 0xdb, 0x36, 0x47, 0x5d, 0xde, 0x70, 0xd5, 0x91, 0xaa, 0x3f, 0xc9, 0xd8, 0xf3, 0xf2,
            0x5b, 0x89, 0x2d, 0x22, 0x5c, 0xe1, 0x46, 0x33, 0xe6, 0x09, 0xbc, 0xe8, 0x81, 0x7d, 0xe9, 0x49,
            0xe0, 0xb1, 0x32, 0x37, 0xea, 0x5a, 0xf6, 0x27, 0x58, 0x69, 0x8a, 0x50, 0xba, 0xdd, 0x51, 0xf9,
            0x75, 0xa1, 0x78, 0xd0, 0x43, 0xf7, 0x25, 0x7b, 0x7e, 0x1c, 0xac, 0xd4, 0x9a, 0x2b, 0x42, 0xe3,
            0x4b, 0x01, 0x72, 0xd7, 0x4c, 0xfa, 0xeb, 0x73, 0x48, 0x8c, 0x0c, 0xf0, 0x6a, 0x23, 0x41, 0xec,
            0xb3, 0xef, 0x1d, 0x12, 0xbb, 0x88, 0x0d, 0xc3, 0x8d, 0x4f, 0x55, 0x82, 0xee, 0xad, 0x86, 0x06,
            0xa0, 0x95, 0x65, 0xbf, 0x7a, 0x39, 0x98, 0x04, 0x9b, 0x9e, 0xa4, 0xc6, 0xcf, 0x6e, 0xdc, 0xd1,
            0xcb, 0x1f, 0x8f, 0x8e, 0x3c, 0x21, 0xa6, 0xb5, 0x16, 0xaf, 0xc5, 0x18, 0x1e, 0x0f, 0x29, 0x79
        ];

        let sbox_4 = vec![0xd, 0x7, 0x3, 0x2, 0x9, 0xa, 0xc, 0x1, 0xf, 0x4, 0x5, 0xe, 0x6, 0x0, 0xb, 0x8];
        let table_64 = [0,12,23,25,38,42,53,59,22,9,26,32,1,47,51,61,24,37,18,41,55,58,8,2,16,3,10,27,
                        33,46,48,62,11,28,60,49,36,17,4,43,50,19,5,39,56,45,29,13,30,35,40,14,57,6,54,
                        20,44,52,21,7,34,15,31,63];
        let table_d = [0x0, 0xe, 0xd, 0x3, 0xb, 0x5, 0x6, 0x8, 0x7, 0x9, 0xa, 0x4, 0xc, 0x2, 0x1, 0xf];
        let table_4 = [0b0000,0b0010,0b0001,0b0011,0b1000,0b1010,0b1001,0b1011,
                       0b0100,0b0110,0b0101,0b0111,0b1100,0b1110,0b1101,0b1111,];
        let table_128 = [76,110,83,127,67,114,92,97,98,65,121,106,78,112,91,82,71,101,89,126,72,107,81,
                         118,90,124,73,88,64,104,100,85,109,87,75,113,120,66,103,115,122,108,95,69,74,
                         116,80,102,84,96,125,68,93,105,119,79,123,86,70,117,111,77,99,94,28,9,37,4,51,
                         43,58,16,20,26,44,34,0,61,12,55,46,22,15,2,48,31,57,33,27,18,24,14,6,52,63,42,
                         49,7,8,62,30,17,47,38,29,53,11,21,41,32,1,60,13,35,5,39,45,59,23,54,36,10,40,
                         56,25,50,19,3];

        Iceberg{size: 64, 
                key_size: 128,
                sbox_8: Sbox::new(8, 8, sbox_8),
                sbox_4: Sbox::new(4, 4, sbox_4),
                table_64,
                table_d,
                table_4,
                table_128
        }
    }
}

impl Cipher for Iceberg {
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
        self.size / self.sbox_8.size_in()
    }

    fn sbox(&self, _i: usize) -> &Sbox {
        &self.sbox_8
    }

    fn linear_layer(&self, input: u128) -> u128{
        let mut output = 0;

        // Apply 64-bit permutation
        for i in 0..64 {
            output ^= ((input >> self.table_64[i]) & 0x1) << i;
        }

        // Apply matrix multiplication
        let tmp = output;
        output = 0;

        for i in 0..16 {
            output ^= self.table_d[((tmp >> (4*i)) & 0xf) as usize] << (4*i);
        }

        // Apply 4-bit permutation
        let tmp = output;
        output = 0;

        for i in 0..16 {
            output ^= self.table_4[((tmp >> (4*i)) & 0xf) as usize] << (4*i);
        }

        // Apply 64-bit permutation again
        let tmp = output;
        output = 0;

        for i in 0..64 {
            output ^= ((tmp >> self.table_64[i]) & 0x1) << i;
        }

        output
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;

        // Apply 64-bit permutation
        for i in 0..64 {
            output ^= ((input >> self.table_64[i]) & 0x1) << i;
        }

        // Apply 4-bit permutation
        let tmp = output;
        output = 0;

        for i in 0..16 {
            output ^= self.table_4[((tmp >> (4*i)) & 0xf) as usize] << (4*i);
        }

        // Apply matrix multiplication
        let tmp = output;
        output = 0;

        for i in 0..16 {
            output ^= self.table_d[((tmp >> (4*i)) & 0xf) as usize] << (4*i);
        }

        // Apply 64-bit permutation again
        let tmp = output;
        output = 0;

        for i in 0..64 {
            output ^= ((tmp >> self.table_64[i]) & 0x1) << i;
        }

        output
    }

    fn reflection_layer(&self, _input: u128) -> u128 {
        panic!("Not implemented for this type of cipher")
    }

    fn key_schedule(&self, _rounds : usize, key: &[u8]) -> Vec<u128> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        panic!("Not implemented!")
    }

    fn encrypt(&self, _input: u128, _round_keys: &[u128]) -> u128 {
        panic!("Not implemented!")
    }

    fn decrypt(&self, _input: u128, _round_keys: &[u128]) -> u128 {
        panic!("Not implemented!")
    }

    fn name(&self) -> String {
        String::from("ICEBERG")
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
        let cipher = cipher::name_to_cipher("iceberg").unwrap();
        let x = 0x0123456789abcdef;

        assert_eq!(x, cipher.linear_layer_inv(cipher.linear_layer(x)));
    }

    /*#[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("mcrypton").unwrap();
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
    }*/
}