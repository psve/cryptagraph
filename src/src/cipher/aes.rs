use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            AES
******************************************************************/

/** 
A structure representing the AES cipher.

size                Size of the cipher in bits. This is fixed to 64.
key_size            Size of cipher key in bits. This is fixed to 64.
sbox                The AES S-box.
isbox               The inverse AES S-box.
shift_rows_table    Table for AES ShiftRows.
ishift_rows_table   Table for inverse AES ShiftRows.
constants           Round constants.
*/
#[derive(Clone)]
pub struct Aes {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox,
    shift_rows_table: [usize; 16],
    ishift_rows_table: [usize; 16],
}

pub fn new() -> Aes {
    let table = vec![0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                     0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                     0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                     0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                     0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                     0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                     0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                     0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                     0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                     0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                     0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                     0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                     0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                     0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                     0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                     0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];
    let itable = vec![0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                      0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                      0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                      0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                      0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                      0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                      0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                      0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                      0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                      0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                      0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                      0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                      0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                      0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                      0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                      0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D];
    let shift_rows_table = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];
    let ishift_rows_table = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

    Aes{size: 128,
        key_size: 128,
        sbox: Sbox::new(8, table), 
        isbox: Sbox::new(8, itable), 
        shift_rows_table,
        ishift_rows_table
    }
}

/**
Performs multiplication by two in the AES field
*/
fn aes_times2(x: u128) -> u128 {
    ((x << 1) & 0xff) ^ (((x >> 7) & 0x1) * 0x1b)
}

impl Cipher for Aes {
    /** 
    Returns the design type of the cipher. 
    */
    fn structure(&self) -> CipherStructure {
        CipherStructure::Spn
    }
    
    /** 
    Returns the size of the cipher input in bits. 
    */
    fn size(&self) -> usize {
        self.size
    }

    /** 
    Returns key-size in bits 
    */
    fn key_size(&self) -> usize {
        self.key_size
    }

    /** 
    Returns the number of S-boxes in the non-linear layer. 
    */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /** 
    Returns the i'th S-box of the cipher. 
    */
    fn sbox(&self, _i: usize) -> &Sbox {
        &self.sbox
    }

    /** 
    Applies the linear layer of the cipher.
    
    input   The input to the linear layer.
    */
    fn linear_layer(&self, input: u128) -> u128{
        let mut x = 0;

        // Apply ShiftRows
        for i in 0..16 {
            x ^= ((input >> (i*8)) & 0xff) << (self.shift_rows_table[i]*8);
        }

        // Apply MixColumns
        let mut y = 0;
        for i in 0..4 {
            let t = ((x >> (   32*i)) & 0xff) 
                  ^ ((x >> ( 8+32*i)) & 0xff) 
                  ^ ((x >> (16+32*i)) & 0xff) 
                  ^ ((x >> (24+32*i)) & 0xff);
            let u = (x >> (32*i)) & 0xff;
            
            y ^= (((x >> (32*i)) & 0xff) 
              ^ aes_times2(((x >> (   32*i)) & 0xff)^((x >> ( 8+32*i)) & 0xff)) 
              ^ t) << (   32*i);
            y ^= (((x >> (8+32*i)) & 0xff) 
              ^ aes_times2(((x >> ( 8+32*i)) & 0xff)^((x >> (16+32*i)) & 0xff)) 
              ^ t) << ( 8+32*i);
            y ^= (((x >> (16+32*i)) & 0xff) 
              ^ aes_times2(((x >> (16+32*i)) & 0xff)^((x >> (24+32*i)) & 0xff)) 
              ^ t) << (16+32*i);
            y ^= (((x >> (24+32*i)) & 0xff) 
              ^ aes_times2(((x >> (24+32*i)) & 0xff)^u) 
              ^ t) << (24+32*i);
        }
        
        y
    }

    /** 
    Applies the inverse linear layer of the cipher.
    
    input   The input to the inverse linear layer. 
    */
    fn linear_layer_inv(&self, input: u128) -> u128 {
        // Apply MixColumnsInv
        let x = input;
        let mut y = 0;

        for i in 0..4 {
            let u = aes_times2(aes_times2(((x >> (32*i)) & 0xff) ^ ((x >> (16+32*i)) & 0xff)));
    
            y ^= (((x >> (   32*i)) & 0xff) ^ u) << (   32*i);
            y ^= (((x >> (16+32*i)) & 0xff) ^ u) << (16+32*i);
            
            let u = aes_times2(aes_times2(((x >> (8+32*i)) & 0xff) ^ ((x >> (24+32*i)) & 0xff)));
            
            y ^= (((x >> (8+32*i)) & 0xff) ^ u) << (8+32*i);
            y ^= (((x >> (24+32*i)) & 0xff) ^ u) << (24+32*i);
        }

        let x = y;
        let mut y = 0;
        for i in 0..4 {
            let t = ((x >> (  32*i)) & 0xff) 
                  ^ ((x >> (8+32*i)) & 0xff) 
                  ^ ((x >> (16+32*i)) & 0xff) 
                  ^ ((x >> (24+32*i)) & 0xff);
            let u = (x >> (32*i)) & 0xff;
            
            y ^= (((x >> (32*i)) & 0xff) 
              ^ aes_times2(((x >> (   32*i)) & 0xff)^((x >> ( 8+32*i)) & 0xff)) 
              ^ t) << (  32*i);
            y ^= (((x >> (8+32*i)) & 0xff) 
              ^ aes_times2(((x >> ( 8+32*i)) & 0xff)^((x >> (16+32*i)) & 0xff)) 
              ^ t) << (8+32*i);
            y ^= (((x >> (16+32*i)) & 0xff) 
              ^ aes_times2(((x >> (16+32*i)) & 0xff)^((x >> (24+32*i)) & 0xff)) 
              ^ t) << (16+32*i);
            y ^= (((x >> (24+32*i)) & 0xff) 
              ^ aes_times2(((x >> (24+32*i)) & 0xff)^u) 
              ^ t) << (24+32*i);
        }

        // Apply ShiftRowsInv
        let mut x = 0;

        for i in 0..16 {
            x ^= ((y >> (i*8)) & 0xff) << (self.ishift_rows_table[i]*8);
        }

        x
    }

    /**
    Applies the reflection layer for Prince like ciphers. 
    For all other cipher types, this can remain unimplemented. 

    input   The input to the reflection layer.
    */
    #[allow(unused_variables)]
    fn reflection_layer(&self, input: u128) -> u128 {
        panic!("Not implemented for this type of cipher")
    }

    /** 
    Computes a vector of round key from a cipher key.

    rounds      Number of rounds to generate keys for.
    key         The master key to expand.
    */
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u128> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = Vec::new();
        let mut k = 0;

        for &x in key.iter().take(16) {
            k <<= 8;
            k |= u128::from(x);
        }

        keys.push(k);
        let mut r_const = 0x01;

        for _ in 0..rounds {
            let mut tmp = k >> 96;
            tmp = ((tmp >> 8) ^ (tmp << 24)) & 0xffffffff;
            
            for j in 0..4 {
                k ^= u128::from(self.sbox.table[((tmp >> (8*j)) & 0xff) as usize]) << (8*j);
            }

            k ^= r_const;


            for j in 1..4 {
                k ^= (k & (0xffffffff << (32*(j-1)))) << 32;
            }

            keys.push(k);
            r_const = aes_times2(r_const);
        }

        keys
    }

    /** 
    Performs encryption with the cipher. 
    
    input       Plaintext to be encrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        // AddRoundKey 
        output ^= round_keys[0];

        for i in 0..9 {
            // SubBytes
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.sbox.table[((output >> (j*8)) & 0xff) as usize]) << (j*8);
            }

            // ShiftRows + MixColumns
            output = self.linear_layer(tmp);

            // AddRoundKey
            output ^= round_keys[i+1]
        }

        // SubBytes
        let mut tmp = 0;

        for j in 0..16 {
            tmp ^= u128::from(self.sbox.table[((output >> (j*8)) & 0xff) as usize]) << (j*8);
        }

        // ShiftRows
        output = 0;

        for i in 0..16 {
            output ^= ((tmp >> (i*8)) & 0xff) << (self.shift_rows_table[i]*8);
        }

        // AddRoundKey
        output ^= round_keys[10];

        output
    }

    /** 
    Performs decryption with the cipher. 
    
    input       Ciphertext to be decrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        // AddRoundKey
        output ^= round_keys[10];

        // InvShiftRows
        let mut tmp = 0;

        for i in 0..16 {
            tmp ^= ((output >> (i*8)) & 0xff) << (self.ishift_rows_table[i]*8);
        }

        // InvSubBytes
        output = 0;

        for j in 0..16 {
            output ^= u128::from(self.isbox.table[((tmp >> (j*8)) & 0xff) as usize]) << (j*8);
        }

        for i in 0..9 {
            // AddRoundKey
            output ^= round_keys[9-i];

            // InvShiftRows + InvMixColumns
            let tmp = self.linear_layer_inv(output);

            // InvSubBytes
            output = 0;

            for j in 0..16 {
                output ^= u128::from(self.isbox.table[((tmp >> (j*8)) & 0xff) as usize]) << (j*8);
            }
        }

        output ^= round_keys[0];

        output
    }

    /** 
    Returns the name of the cipher. 
    */
    fn name(&self) -> String {
        String::from("AES")
    }

    /** 
    Transforms the input and output mask of the S-box layer to an
    input and output mask of a round.
    
    input    Input mask to the S-box layer.
    output   Output mask to the S-box layer.
    */
    #[allow(unused_variables)]
    fn sbox_mask_transform(&self, 
                           input: u128, 
                           output: u128, 
                           property_type: PropertyType) 
                           -> (u128, u128) {
        (input, self.linear_layer(output))
    }

    /**
    Specifies if a pre-whitening key is used. In this case, the key-schedule returns 
    rounds+1 round keys. 
    */
    #[inline(always)]
    fn whitening(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use cipher;

    #[test]
    fn linear() {
        let cipher = cipher::name_to_cipher("aes").unwrap();
        let x = 0x00112233445566778899aabbccddeeff;

        assert_eq!(x, cipher.linear_layer_inv(cipher.linear_layer(x)));
    }

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("aes").unwrap();
        let key = [0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,  
                   0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0xffeeddccbbaa99887766554433221100;
        let ciphertext = 0x5ac5b47080b7cdd830047b6ad8e0c469;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0x00000000000000f8ffffffffffffffff;
        let ciphertext = 0x11b57e6e49d55493602bb7d633404066;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    
    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("aes").unwrap();
        let key = [0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,  
                   0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0xffeeddccbbaa99887766554433221100;
        let ciphertext = 0x5ac5b47080b7cdd830047b6ad8e0c469;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0x00000000000000f8ffffffffffffffff;
        let ciphertext = 0x11b57e6e49d55493602bb7d633404066;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("aes").unwrap();
        let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                   0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0x00112233445566778899aabbccddeeff;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0xffffffffffffffffffffffffffffffff;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}