use cipher::{Sbox, CipherStructure, Cipher};

/*****************************************************************
                            Khazad
******************************************************************/

/* A structure representing the Khazad cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The Khazad S-box.
 * key_size     Size of cipher key in bits. This is (currently) fixed to 80.
 */
#[derive(Clone)]
pub struct Khazad {
    size     : usize,
    key_size : usize,
    sbox     : Sbox,
}

impl Khazad {
    const PERMUTATION     : [[u64 ; 0x100] ; 8] = include!("khazad.perm");
    const SBOX : [u8 ; 256] = [0xba,0x54,0x2f,0x74,0x53,0xd3,0xd2,0x4d,0x50,0xac,0x8d,0xbf,0x70,0x52,0x9a,0x4c,
                               0xea,0xd5,0x97,0xd1,0x33,0x51,0x5b,0xa6,0xde,0x48,0xa8,0x99,0xdb,0x32,0xb7,0xfc,
                               0xe3,0x9e,0x91,0x9b,0xe2,0xbb,0x41,0x6e,0xa5,0xcb,0x6b,0x95,0xa1,0xf3,0xb1,0x02,
                               0xcc,0xc4,0x1d,0x14,0xc3,0x63,0xda,0x5d,0x5f,0xdc,0x7d,0xcd,0x7f,0x5a,0x6c,0x5c,
                               0xf7,0x26,0xff,0xed,0xe8,0x9d,0x6f,0x8e,0x19,0xa0,0xf0,0x89,0x0f,0x07,0xaf,0xfb,
                               0x08,0x15,0x0d,0x04,0x01,0x64,0xdf,0x76,0x79,0xdd,0x3d,0x16,0x3f,0x37,0x6d,0x38,
                               0xb9,0x73,0xe9,0x35,0x55,0x71,0x7b,0x8c,0x72,0x88,0xf6,0x2a,0x3e,0x5e,0x27,0x46,
                               0x0c,0x65,0x68,0x61,0x03,0xc1,0x57,0xd6,0xd9,0x58,0xd8,0x66,0xd7,0x3a,0xc8,0x3c,
                               0xfa,0x96,0xa7,0x98,0xec,0xb8,0xc7,0xae,0x69,0x4b,0xab,0xa9,0x67,0x0a,0x47,0xf2,
                               0xb5,0x22,0xe5,0xee,0xbe,0x2b,0x81,0x12,0x83,0x1b,0x0e,0x23,0xf5,0x45,0x21,0xce,
                               0x49,0x2c,0xf9,0xe6,0xb6,0x28,0x17,0x82,0x1a,0x8b,0xfe,0x8a,0x09,0xc9,0x87,0x4e,
                               0xe1,0x2e,0xe4,0xe0,0xeb,0x90,0xa4,0x1e,0x85,0x60,0x00,0x25,0xf4,0xf1,0x94,0x0b,
                               0xe7,0x75,0xef,0x34,0x31,0xd4,0xd0,0x86,0x7e,0xad,0xfd,0x29,0x30,0x3b,0x9f,0xf8,
                               0xc6,0x13,0x06,0x05,0xc5,0x11,0x77,0x7c,0x7a,0x78,0x36,0x1c,0x39,0x59,0x18,0x56,
                               0xb3,0xb0,0x24,0x20,0xb2,0x92,0xa3,0xc0,0x44,0x62,0x10,0xb4,0x84,0x43,0x93,0xc2,
                               0x4a,0xbd,0x8f,0x2d,0xbc,0x9c,0x6a,0x40,0xcf,0xa2,0x80,0x4f,0x1f,0xca,0xaa,0x42];
}

pub fn new() -> Khazad {
    let table: Vec<_> = From::from(&Khazad::SBOX[0..]);

    Khazad{size: 64, 
            key_size: 128, 
            sbox: Sbox::new(8, table)}
}

impl Cipher for Khazad {
    /* Returns the design type of the cipher */
    fn structure(&self) -> CipherStructure {
        CipherStructure::Spn
    }

    /* Returns the size of the input to Khazad. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }
    /* Returns key-size in bits */
    fn key_size(&self) -> usize {
        return self.key_size;
    }

    /* Returns the number of S-boxes in Khazad. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the Khazad S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the bit permutation of Khazad to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;
        output ^= Khazad::PERMUTATION[0][((input >>  0) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[1][((input >>  8) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[2][((input >> 16) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[3][((input >> 24) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[4][((input >> 32) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[5][((input >> 40) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[6][((input >> 48) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[7][((input >> 56) & 0xff) as usize];

        output
    }

    /* Applies the inverse linear layer, st.
     *
     * I = linear_layer_inv o linear_layer
     */
    fn linear_layer_inv(&self, input: u64) -> u64 {
        let mut output = 0;
        output ^= Khazad::PERMUTATION[0][((input >>  0) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[1][((input >>  8) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[2][((input >> 16) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[3][((input >> 24) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[4][((input >> 32) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[5][((input >> 40) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[6][((input >> 48) & 0xff) as usize];
        output ^= Khazad::PERMUTATION[7][((input >> 56) & 0xff) as usize];
        
        output
    }

    /* Computes a vector of round key from a cipher key*/    
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut k0 : u64 = 0;
        let mut k1 : u64 = 0;

        for i in 0..8 {
            k1 <<= 8;
            k1 |= key[i] as u64;
            k0 <<= 8;
            k0 |= key[i+8] as u64;
        }

        keys.push(k0);
        keys.push(k1);

        for r in 0..rounds {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= (self.sbox.table[((keys[r+1] >> (8*j)) & 0xff) as usize] as u64) << (8*j);
            }

            // Apply linear layer
            tmp = self.linear_layer(tmp);

            // Add round constant
            for j in 0..8 {
                tmp ^= (self.sbox.table[8*r+j] as u64) << 8*j;
            }

            // Add round key
            tmp ^= keys[r];
            keys.push(tmp);
        }

        keys
    }

    /* Performs encryption */
    fn encrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;
        output ^= round_keys[2];

        for i in 1..8 {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= (self.sbox.table[((output >> (8*j)) & 0xff) as usize] as u64) << (8*j);
            }

            // Apply linear layer
            output = self.linear_layer(tmp);

            // Add round key
            output ^= round_keys[i+2];
        }

        // Apply S-box
        let mut tmp = 0;

        for j in 0..8 {
            tmp ^= (self.sbox.table[((output >> (8*j)) & 0xff) as usize] as u64) << (8*j);
        }

        // Add round key
        output = tmp ^ round_keys[10];
        output
    }

    /* Performs decryption */
    fn decrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;
        output ^= round_keys[10];

        for i in 1..8 {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= (self.sbox.table[((output >> (8*j)) & 0xff) as usize] as u64) << (8*j);
            }

            // Apply linear layer
            output = self.linear_layer(tmp);

            // Add round key
            output ^= self.linear_layer(round_keys[10-i]);
        }

        // Apply S-box
        let mut tmp = 0;

        for j in 0..8 {
            tmp ^= (self.sbox.table[((output >> (8*j)) & 0xff) as usize] as u64) << (8*j);
        }

        // Add round key
        output = tmp ^ round_keys[2];
        output
    }

    /* Returns the string "Khazad". */
    fn name(&self) -> String {
        String::from("Khazad")
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
        let cipher = cipher::name_to_cipher("khazad").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
        let round_keys = cipher.key_schedule(9, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x3f0e19ac32cea449 ;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40];
        let round_keys = cipher.key_schedule(9, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0xd14a8b12c12622bd;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(9, &key);
        let plaintext = 0x0400000000000000; 
        let ciphertext = 0x7e15dcf0d2759f84;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("khazad").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
        let round_keys = cipher.key_schedule(9, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x3f0e19ac32cea449 ;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40];
        let round_keys = cipher.key_schedule(9, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0xd14a8b12c12622bd;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(9, &key);
        let plaintext = 0x0400000000000000; 
        let ciphertext = 0x7e15dcf0d2759f84;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("khazad").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(9, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(9, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}