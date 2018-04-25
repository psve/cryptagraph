use cipher::{Sbox, CipherStructure, Cipher};

/*****************************************************************
                            SKINNY
******************************************************************/

/* A structure representing the SKINNY cipher.
 *
 * size                 Size of the cipher in bits. This is fixed to 64.
 * sbox                 The SKINNY S-box.
 * shift_rows_table     Permutation used for ShiftRows.
 */
#[derive(Clone)]
pub struct Skinny {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox,
    shift_rows_table: [usize; 16],
    ishift_rows_table: [usize; 16],
    key_permute: [usize; 16],
    constants: [u64; 48]
}

pub fn new() -> Skinny {
    let table = vec![0xc, 0x6, 0x9, 0x0, 0x1, 0xa, 0x2, 0xb, 0x3, 0x8, 0x5, 0xd, 0x4, 0xe, 0x7, 0xf];
    let itable = vec![0x3, 0x4, 0x6, 0x8, 0xc, 0xa, 0x1, 0xe, 0x9, 0x2, 0x5, 0x7, 0x0, 0xb, 0xd, 0xf];
    let shift_rows_table = [0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14];
    let ishift_rows_table = [0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12];
    let key_permute = [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1];
    let constants = [0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,0x27,
                     0x0e,0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b,0x17,0x2e,
                     0x1c,0x38,0x31,0x23,0x06,0x0d,0x1b,0x36,0x2d,0x1a,0x34,0x29,0x12,0x24,0x08,
                     0x11,0x22,0x04];
    Skinny{size: 64, 
           key_size: 64,
           sbox: Sbox::new(4, table), 
           isbox: Sbox::new(4, itable), 
           shift_rows_table: shift_rows_table,
           ishift_rows_table: ishift_rows_table,
           key_permute: key_permute,
           constants: constants}
}

impl Cipher for Skinny {
    /* Returns the design type of the cipher */
    fn structure(&self) -> CipherStructure {
        CipherStructure::Spn
    }
    
    /* Returns the size of the input to SKINNY. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }
    /* Returns key-size in bits */
    fn key_size(&self) -> usize {
        self.key_size
    }

    /* Returns the number of S-boxes in SKINNY. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the SKINNY S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the ShiftRows and MixColumns steps of SKINNY to the input.
     *
     * input    Input to be transformed.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;

        // Apply ShiftRows
        for i in 0..16 {
            output ^= ((input >> (i*4)) & 0xf) << (self.shift_rows_table[i]*4);
        }

        // Apply MixColumns
        output ^= (output & 0xffff00000000) >> 16;
        output ^= (output & 0xffff) << 32;
        output ^= (output & 0xffff00000000) << 16;
        output = (output << 16) ^ (output >> 48);

        output
    }

    #[allow(unused_variables)]
    fn linear_layer_inv(&self, input: u64) -> u64 {
        let mut output = input;

        // Apply MixColumns
        output = (output >> 16) ^ (output << 48);
        output ^= (output & 0xffff00000000) << 16;
        output ^= (output & 0xffff) << 32;
        output ^= (output & 0xffff00000000) >> 16;

        // Apply ShiftRows
        let mut tmp = 0;

        for i in 0..16 {
            tmp ^= ((output >> (i*4)) & 0xf) << (self.ishift_rows_table[i]*4);
        }

        tmp  
    }

    #[allow(unused_variables)]
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut k = 0;

        for i in 0..8 {
            k <<= 8;
            k |= key[i] as u64;
        }


        for r in 0..rounds {
            keys.push(k & 0xffffffff);

            let mut tmp = 0;

            // Apply permutation
            for i in 0..16 {
                tmp ^= ((k >> (i*4)) & 0xf) << (self.key_permute[i]*4);
            }

            k = tmp;
        }

        keys
    }

    /* Performs encryption */
    fn encrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        for i in 0..32 {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }

            // Add constants
            output = tmp;
            output ^= self.constants[i] & 0xf;
            output ^= (self.constants[i] >> 4) << 16;
            output ^= 0x2 << 32;

            // Add round key
            output ^= round_keys[i];

            // Shift + MixColumns
            output = self.linear_layer(output);
        }

        output
    }

    /* Performs decryption */
    fn decrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        for i in 0..32 {
            // Shift + MixColumns
            output = self.linear_layer_inv(output);
            
            // Add round key
            output ^= round_keys[31-i];

            // Add constants
            output ^= self.constants[31-i] & 0xf;
            output ^= (self.constants[31-i] >> 4) << 16;
            output ^= 0x2 << 32;

            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.isbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }

            output = tmp;
        }

        output   
    }

    /* Returns the string "SKINNY". */
    fn name(&self) -> String {
        String::from("SKINNY")
    }

    /* Transforms the input and output mask of the S-box layer to an
     * input and output mask of a round.
     *
     * input    Input mask to the S-box layer.
     * output   Output mask to the S-box layer.
     */
    fn sbox_mask_transform(& self, input: u64, output: u64) -> (u64, u64) {
        (input, self.linear_layer(output))
    }
}

#[cfg(test)]
mod tests {
    use cipher;
    
    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("skinny").unwrap();
        let key = [0x45, 0x84, 0xf9, 0xd7, 0x08, 0x97, 0x76, 0x4d];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x74aba08aa527f88a;
        let ciphertext = 0xfa2848282ab1f696;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x83, 0x21, 0x86, 0xcf, 0x62, 0x89, 0x62, 0x5f];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xd91d427759f43060;
        let ciphertext = 0x7ca8b9242bfd93bb;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("skinny").unwrap();
        let key = [0x45, 0x84, 0xf9, 0xd7, 0x08, 0x97, 0x76, 0x4d];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x74aba08aa527f88a;
        let ciphertext = 0xfa2848282ab1f696;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x83, 0x21, 0x86, 0xcf, 0x62, 0x89, 0x62, 0x5f];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xd91d427759f43060;
        let ciphertext = 0x7ca8b9242bfd93bb;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("skinny").unwrap();
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