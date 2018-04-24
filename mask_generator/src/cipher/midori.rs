use cipher::Sbox;
use cipher::Cipher;

/*****************************************************************
                            Midori
******************************************************************/

/* A structure representing the Midori cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The Midori S-box.
 */
#[derive(Clone)]
pub struct Midori {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    shuffle_cell_table: [usize; 16],
    ishuffle_cell_table: [usize; 16],
    constants: [u64; 15],
}

pub fn new() -> Midori {
    let table = vec![0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6];
    let shuffle_cell_table = [00, 07, 14, 09, 05, 02, 11, 12, 15, 08, 01, 06, 10, 13, 04, 03];
    let ishuffle_cell_table = [00, 10, 05, 15, 14, 04, 11, 01, 09, 03, 12, 06, 07, 13, 02, 08];
    let constants = [0x0001010110110011,
                     0x0111100011000000,
                     0x1010010000110101,
                     0x0110001000010011,
                     0x0001000001001111,
                     0x1101000101110000,
                     0x0000001001100110,
                     0x0000101111001100,
                     0x1001010010000001,
                     0x0100000010111000,
                     0x0111000110010111,
                     0x0010001010001110,
                     0x0101000100110000,
                     0x1111100011001010,
                     0x1101111110010000];
    Midori{size: 64, 
           key_size: 128,
           sbox: Sbox::new(4, table), 
           shuffle_cell_table: shuffle_cell_table,
           ishuffle_cell_table: ishuffle_cell_table,
           constants: constants}
}

impl Cipher for Midori {
    /* Returns the size of the input to Midori. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }
    /* Returns key-size in bits */
    fn key_size(&self) -> usize {
        self.key_size
    }

    /* Returns the number of S-boxes in Midori. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the Midori S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the ShuffleCell and MixColumn steps of Midori to the input.
     *
     * input    Input to be transformed.
     */
    fn linear_layer(&self, input: u64) -> u64 {
        let mut x = 0;

        // Apply ShuffleCell
        for i in 0..16 {
            x ^= ((input >> ((15-i)*4)) & 0xf) << ((15-self.shuffle_cell_table[i])*4);
        }

        // Apply MixColumn
        let mut output = 0;
        output ^= (x & 0x00f000f000f000f0) >> 4
                ^ (x & 0x0f000f000f000f00) >> 8
                ^ (x & 0xf000f000f000f000) >> 12;

        output ^= (x & 0x000f000f000f000f) << 4
                ^ (x & 0x0f000f000f000f00) >> 4
                ^ (x & 0xf000f000f000f000) >> 8;

        output ^= (x & 0x000f000f000f000f) << 8
                ^ (x & 0x00f000f000f000f0) << 4
                ^ (x & 0xf000f000f000f000) >> 4;

        output ^= (x & 0x000f000f000f000f) << 12
                ^ (x & 0x00f000f000f000f0) << 8
                ^ (x & 0x0f000f000f000f00) << 4;

        output
    }

    #[allow(unused_variables)]
    fn linear_layer_inv(&self, input: u64) -> u64 {
        let mut x = input;

        // Apply MixColumn
        let mut output = 0;
        output ^= (x & 0x00f000f000f000f0) >> 4
                ^ (x & 0x0f000f000f000f00) >> 8
                ^ (x & 0xf000f000f000f000) >> 12;

        output ^= (x & 0x000f000f000f000f) << 4
                ^ (x & 0x0f000f000f000f00) >> 4
                ^ (x & 0xf000f000f000f000) >> 8;

        output ^= (x & 0x000f000f000f000f) << 8
                ^ (x & 0x00f000f000f000f0) << 4
                ^ (x & 0xf000f000f000f000) >> 4;

        output ^= (x & 0x000f000f000f000f) << 12
                ^ (x & 0x00f000f000f000f0) << 8
                ^ (x & 0x0f000f000f000f00) << 4;

        // Apply ShuffleCell
        x = 0;

        for i in 0..16 {
            x ^= ((output >> ((15-i)*4)) & 0xf) << ((15-self.ishuffle_cell_table[i])*4);
        }
        
        x
    }

    #[allow(unused_variables)]
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut k0 = 0;
        let mut k1 = 0;

        for i in 0..8 {
            k0 <<= 8;
            k0 |= key[i] as u64;
            k1 <<= 8;
            k1 |= key[i+8] as u64;
        }

        keys.push(k0 ^ k1);

        for i in 0..(rounds/2-1) {
            keys.push(k0);
            keys.push(k1);
        }
        
        keys.push(k0);
        keys.push(k0 ^ k1);

        keys
    }

    /* Performs encryption */
    fn encrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;
        output ^= round_keys[0];

        for i in 0..15 {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }

            // ShuffleCell + MixColumns
            output = self.linear_layer(tmp);

            // Add key and constant
            output ^= round_keys[i+1];
            output ^= self.constants[i];
        }

        // Apply S-box
        let mut tmp = 0;

        for j in 0..16 {
            tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
        }

        tmp ^ round_keys[16]        
    }

    /* Performs decryption */
    fn decrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;
        output ^= round_keys[16];

        // Apply S-box
        let mut tmp = 0;

        for j in 0..16 {
            tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
        }

        for i in 0..15 {
            // Add key and constant
            output = tmp ^ round_keys[16-(i+1)];
            output ^= self.constants[14-i];

            // ShuffleCell + MixColumns
            output = self.linear_layer_inv(output);

            // Apply S-box
            tmp = 0;

            for j in 0..16 {
                tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }
        }

        tmp ^ round_keys[0]
    }

    /* Returns the string "Midori". */
    fn name(&self) -> String {
        String::from("Midori")
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
    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("midori").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(16, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x3c9cceda2bbd449a;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x68, 0x7d, 0xed, 0x3b, 0x3c, 0x85, 0xb3, 0xf3, 
                   0x5b, 0x10, 0x09, 0x86, 0x3e, 0x2a, 0x8c, 0xbf];
        let round_keys = cipher.key_schedule(16, &key);
        let plaintext = 0x42c20fd3b586879e;
        let ciphertext = 0x66bcdc6270d901cd;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("midori").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(16, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x3c9cceda2bbd449a;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x68, 0x7d, 0xed, 0x3b, 0x3c, 0x85, 0xb3, 0xf3, 
                   0x5b, 0x10, 0x09, 0x86, 0x3e, 0x2a, 0x8c, 0xbf];
        let round_keys = cipher.key_schedule(16, &key);
        let plaintext = 0x42c20fd3b586879e;
        let ciphertext = 0x66bcdc6270d901cd;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("midori").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(16, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x68, 0x7d, 0xed, 0x3b, 0x3c, 0x85, 0xb3, 0xf3, 
                   0x5b, 0x10, 0x09, 0x86, 0x3e, 0x2a, 0x8c, 0xbf];
        let round_keys = cipher.key_schedule(16, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}