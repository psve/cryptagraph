use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            SKINNY
******************************************************************/

/** 
A structure representing the SKINNY cipher.

size                Size of the cipher in bits. This is fixed to 64.
key_size            Size of the cipher key in bits. This is fixed to 64.
sbox                The SKINNY S-box.
isbox               The inverse SKINNY S-box.
shift_rows_table    Permutation used for ShiftRows.
ishift_rows_table   Permutation used for inverse ShiftRows.
key_permute         Permutation used for key-schedule.
constants           Round constants. 
*/
#[derive(Clone)]
pub struct Skinny128 {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox,
    shift_rows_table: [usize; 16],
    ishift_rows_table: [usize; 16],
    key_permute: [usize; 16],
    constants: [u128; 48]
}

pub fn new() -> Skinny128 {
    let table = vec![
        0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
        0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
        0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
        0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
        0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
        0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
        0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
        0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
        0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
        0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
        0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
        0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
        0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
        0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
        0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
        0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff
    ];
    let itable = vec![
        0xac, 0xe8, 0x68, 0x3c, 0x6c, 0x38, 0xa8, 0xec, 0xaa, 0xae, 0x3a, 0x3e, 0x6a, 0x6e, 0xea, 0xee,
        0xa6, 0xa3, 0x33, 0x36, 0x66, 0x63, 0xe3, 0xe6, 0xe1, 0xa4, 0x61, 0x34, 0x31, 0x64, 0xa1, 0xe4,
        0x8d, 0xc9, 0x49, 0x1d, 0x4d, 0x19, 0x89, 0xcd, 0x8b, 0x8f, 0x1b, 0x1f, 0x4b, 0x4f, 0xcb, 0xcf,
        0x85, 0xc0, 0x40, 0x15, 0x45, 0x10, 0x80, 0xc5, 0x82, 0x87, 0x12, 0x17, 0x42, 0x47, 0xc2, 0xc7,
        0x96, 0x93, 0x03, 0x06, 0x56, 0x53, 0xd3, 0xd6, 0xd1, 0x94, 0x51, 0x04, 0x01, 0x54, 0x91, 0xd4,
        0x9c, 0xd8, 0x58, 0x0c, 0x5c, 0x08, 0x98, 0xdc, 0x9a, 0x9e, 0x0a, 0x0e, 0x5a, 0x5e, 0xda, 0xde,
        0x95, 0xd0, 0x50, 0x05, 0x55, 0x00, 0x90, 0xd5, 0x92, 0x97, 0x02, 0x07, 0x52, 0x57, 0xd2, 0xd7,
        0x9d, 0xd9, 0x59, 0x0d, 0x5d, 0x09, 0x99, 0xdd, 0x9b, 0x9f, 0x0b, 0x0f, 0x5b, 0x5f, 0xdb, 0xdf,
        0x16, 0x13, 0x83, 0x86, 0x46, 0x43, 0xc3, 0xc6, 0x41, 0x14, 0xc1, 0x84, 0x11, 0x44, 0x81, 0xc4,
        0x1c, 0x48, 0xc8, 0x8c, 0x4c, 0x18, 0x88, 0xcc, 0x1a, 0x1e, 0x8a, 0x8e, 0x4a, 0x4e, 0xca, 0xce,
        0x35, 0x60, 0xe0, 0xa5, 0x65, 0x30, 0xa0, 0xe5, 0x32, 0x37, 0xa2, 0xa7, 0x62, 0x67, 0xe2, 0xe7,
        0x3d, 0x69, 0xe9, 0xad, 0x6d, 0x39, 0xa9, 0xed, 0x3b, 0x3f, 0xab, 0xaf, 0x6b, 0x6f, 0xeb, 0xef,
        0x26, 0x23, 0xb3, 0xb6, 0x76, 0x73, 0xf3, 0xf6, 0x71, 0x24, 0xf1, 0xb4, 0x21, 0x74, 0xb1, 0xf4,
        0x2c, 0x78, 0xf8, 0xbc, 0x7c, 0x28, 0xb8, 0xfc, 0x2a, 0x2e, 0xba, 0xbe, 0x7a, 0x7e, 0xfa, 0xfe,
        0x25, 0x70, 0xf0, 0xb5, 0x75, 0x20, 0xb0, 0xf5, 0x22, 0x27, 0xb2, 0xb7, 0x72, 0x77, 0xf2, 0xf7,
        0x2d, 0x79, 0xf9, 0xbd, 0x7d, 0x29, 0xb9, 0xfd, 0x2b, 0x2f, 0xbb, 0xbf, 0x7b, 0x7f, 0xfb, 0xff
    ];
    let shift_rows_table = [0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14];
    let ishift_rows_table = [0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12];
    let key_permute = [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1];
    let constants = [0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,0x27,
                     0x0e,0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b,0x17,0x2e,
                     0x1c,0x38,0x31,0x23,0x06,0x0d,0x1b,0x36,0x2d,0x1a,0x34,0x29,0x12,0x24,0x08,
                     0x11,0x22,0x04];
    Skinny128{size: 128, 
           key_size: 128,
           sbox: Sbox::new(8, table), 
           isbox: Sbox::new(8, itable), 
           shift_rows_table: shift_rows_table,
           ishift_rows_table: ishift_rows_table,
           key_permute: key_permute,
           constants: constants}
}

impl Cipher for Skinny128 {
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
        let mut output = 0;

        // Apply ShiftRows
        for i in 0..16 {
            output ^= ((input >> (i*8)) & 0xff) << (self.shift_rows_table[i]*8);
        }

        println!("{:032x}", output);

        // Apply MixColumns
        output ^= (output & 0xffffffff0000000000000000) >> 32;
        output ^= (output & 0xffffffff) << 64;
        output ^= (output & 0xffffffff0000000000000000) << 32;
        output = (output << 32) ^ (output >> 96);

        output
    }

    /** 
    Applies the inverse linear layer of the cipher.
    
    input   The input to the inverse linear layer. 
    */
    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = input;

        // Apply MixColumns
        output = (output >> 32) ^ (output << 96);
        output ^= (output & 0xffffffff0000000000000000) << 32;
        output ^= (output & 0xffffffff) << 64;
        output ^= (output & 0xffffffff0000000000000000) >> 32;

        // Apply ShiftRows
        let mut tmp = 0;

        for i in 0..16 {
            tmp ^= ((output >> (i*8)) & 0xff) << (self.ishift_rows_table[i]*8);
        }

        tmp  
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

        let mut keys = vec![];
        let mut k = 0;

        for i in 0..16 {
            k <<= 8;
            k |= key[i] as u128;
        }


        for _ in 0..rounds {
            let round_key = self.linear_layer(k & 0xffffffffffffffff);
            keys.push(round_key);

            let mut tmp = 0;

            // Apply permutation
            for i in 0..16 {
                tmp ^= ((k >> (i*8)) & 0xff) << (self.key_permute[i]*8);
            }

            k = tmp;
        }

        keys
    }

    /** 
    Performs encryption with the cipher. 
    
    input       Plaintext to be encrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn encrypt(&self, input: u128, round_keys: &Vec<u128>) -> u128 {
        let mut output = input;

        for i in 0..40 {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.sbox.table[((output >> (8*j)) & 0xff) as usize] as u128) << (8*j);
            }

            // Add constants
            output = tmp;
            output ^= self.constants[i] & 0xf;
            output ^= (self.constants[i] >> 4) << 32;
            output ^= 0x2 << 64;

            // Shift + MixColumns
            output = self.linear_layer(output);

            // Add round key
            output ^= round_keys[i];
        }

        output
    }

    /** 
    Performs decryption with the cipher. 
    
    input       Ciphertext to be decrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn decrypt(&self, input: u128, round_keys: &Vec<u128>) -> u128 {
        let mut output = input;

        for i in 0..40 {
            // Add round key
            output ^= round_keys[39-i];

            // Shift + MixColumns
            output = self.linear_layer_inv(output);
            
            // Add constants
            output ^= self.constants[39-i] & 0xf;
            output ^= (self.constants[39-i] >> 4) << 32;
            output ^= 0x2 << 64;

            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.isbox.table[((output >> (8*j)) & 0xff) as usize] as u128) << (8*j);
            }

            output = tmp;
        }

        output   
    }

    /** 
    Returns the name of the cipher. 
    */
    fn name(&self) -> String {
        String::from("SKINNY128")
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
     * Pre-whiteing key used?
     * (rounds + 1) round keys
     *
     * This is the case for most ciphers
     */
    #[inline(always)]
    fn whitening(&self) -> bool { 
        false 
    }
}

#[cfg(test)]
mod tests {
    use cipher;
    
    #[test]
    fn linear() {
        let cipher = cipher::name_to_cipher("skinny128").unwrap();
        let x = 0x00112233445566778899aabbccddeeff;
        assert_eq!(x, cipher.linear_layer(cipher.linear_layer_inv(x)));
    }

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("skinny128").unwrap();
        let key = [0x93, 0x3e, 0x07, 0x37, 0x5f, 0xc1, 0x92, 0xfd, 
                   0x52, 0xac, 0x0c, 0x52, 0xb0, 0xcf, 0x55, 0x4f];
        let round_keys = cipher.key_schedule(40, &key);
        let plaintext = 0x14daadf0d1ee2e3b8a648bb00edb0af2;
        let ciphertext = 0x745b67336e475be4d762ea98d430ff22;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xc8, 0x9e, 0x97, 0xaa, 0x40, 0xc6, 0x8d, 0x2a, 
                   0xad, 0xe5, 0x89, 0x50, 0x22, 0xb7, 0x2b, 0x1c];
        let round_keys = cipher.key_schedule(40, &key);
        let plaintext = 0x074ba8738667f9c59da069e3ae498d1e;
        let ciphertext = 0x8c22cf896a6c6de08d79e869e76c8b46;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("skinny128").unwrap();
        let key = [0x93, 0x3e, 0x07, 0x37, 0x5f, 0xc1, 0x92, 0xfd, 
                   0x52, 0xac, 0x0c, 0x52, 0xb0, 0xcf, 0x55, 0x4f];
        let round_keys = cipher.key_schedule(40, &key);
        let plaintext = 0x14daadf0d1ee2e3b8a648bb00edb0af2;
        let ciphertext = 0x745b67336e475be4d762ea98d430ff22;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xc8, 0x9e, 0x97, 0xaa, 0x40, 0xc6, 0x8d, 0x2a, 
                   0xad, 0xe5, 0x89, 0x50, 0x22, 0xb7, 0x2b, 0x1c];
        let round_keys = cipher.key_schedule(40, &key);
        let plaintext = 0x074ba8738667f9c59da069e3ae498d1e;
        let ciphertext = 0x8c22cf896a6c6de08d79e869e76c8b46;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("skinny128").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(40, &key);
        let plaintext = 0x0123456789abcdef0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(40, &key);
        let plaintext = 0x0123456789abcdef0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}