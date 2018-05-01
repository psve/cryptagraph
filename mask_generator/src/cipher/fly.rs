use cipher::{Sbox, CipherStructure, Cipher};

/*****************************************************************
                            Fly
******************************************************************/

/* A structure representing the Fly cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The Fly S-box.
 * key_size     Size of cipher key in bits. This is (currently) fixed to 80.
 */
#[derive(Clone)]
pub struct Fly {
    size     : usize,
    key_size : usize,
    sbox     : Sbox,
}

impl Fly {
    const PERMUTATION     : [[u64 ; 0x100] ; 8] = include!("fly.perm");
    const PERMUTATION_INV : [[u64 ; 0x100] ; 8] = include!("fly.inv.perm");
    const SBOX : [u8 ; 256] = [0x00,0x9b,0xc2,0x15,0x5d,0x84,0x4c,0xd1,
                               0x67,0x38,0xef,0xb0,0x7e,0x2b,0xf6,0xa3,
                               0xb9,0xaa,0x36,0x78,0x2f,0x6e,0xe3,0xf7,
                               0x12,0x5c,0x9a,0xd4,0x89,0xcd,0x01,0x45,
                               0x2c,0x63,0x44,0xde,0x02,0x96,0x39,0x70,
                               0xba,0xe4,0x18,0x57,0xa1,0xf5,0x8b,0xce,
                               0x51,0x87,0xed,0xff,0xb5,0xa8,0xca,0x1b,
                               0xdf,0x90,0x6c,0x32,0x46,0x03,0x7d,0x29,
                               0xd5,0xf2,0x20,0x5b,0xcc,0x31,0x04,0xbd,
                               0xa6,0x41,0x8e,0x79,0xea,0x9f,0x68,0x1c,
                               0x48,0xe6,0x69,0x8a,0x13,0x77,0x9e,0xaf,
                               0xf3,0x05,0xcb,0x2d,0xb4,0xd0,0x37,0x52,
                               0xc4,0x3e,0x93,0xac,0x40,0xe9,0x22,0x56,
                               0x7b,0x8d,0xf1,0x06,0x17,0x62,0xbf,0xda,
                               0x1d,0x7f,0x07,0xb1,0xdb,0xfa,0x65,0x88,
                               0x2e,0xc9,0xa5,0x43,0x58,0x3c,0xe0,0x94,
                               0x76,0x21,0xab,0xfd,0x6a,0x3f,0xb7,0xe2,
                               0xdd,0x4f,0x53,0x8c,0xc0,0x19,0x95,0x08,
                               0x83,0xc5,0x4e,0x09,0x14,0x50,0xd8,0x9c,
                               0xf4,0xee,0x27,0x61,0x3b,0x7a,0xa2,0xb6,
                               0xfe,0xa9,0x81,0xc6,0xe8,0xbc,0x1f,0x5a,
                               0x35,0x72,0x99,0x0a,0xd3,0x47,0x24,0x6d,
                               0x0b,0x4d,0x75,0x23,0x97,0xd2,0x60,0x34,
                               0xc8,0x16,0xa0,0xbb,0xfc,0xe1,0x5e,0x8f,
                               0xe7,0x98,0x1a,0x64,0xae,0x4b,0x71,0x85,
                               0x0c,0xb3,0x3d,0xcf,0x55,0x28,0xd9,0xf0,
                               0xb2,0xdc,0x5f,0x30,0xf9,0x0d,0x26,0xc3,
                               0x91,0xa7,0x74,0x1e,0x82,0x66,0x4a,0xeb,
                               0x6f,0x10,0xb8,0xd7,0x86,0x73,0xfb,0x0e,
                               0x59,0x2a,0x42,0xe5,0x9d,0xa4,0x33,0xc7,
                               0x3a,0x54,0xec,0x92,0xc1,0x25,0xad,0x49,
                               0x80,0x6b,0xd6,0xf8,0x0f,0xbe,0x7c,0x11];
    const CONSTANTS : [u64; 25] = [
        0x0000000000000000,
        0x8000808000000080,
        0x0080008080000000,
        0x8000008080800080,
        0x0080000080808000,
        0x8000008000808000,
        0x8080808080008000,
        0x8080000080800000,
        0x8080008000808080,
        0x0080800080008080,
        0x0000808000800080,
        0x0000008080008000,
        0x8000808080800000,
        0x8080800080808080,
        0x0080808000808080,
        0x0000808080008080,
        0x0000008080800080,
        0x0000000080808000,
        0x8000808000808000,
        0x8080800080008000,
        0x8080000000800000,
        0x8080008000008080,
        0x0080800080000080,
        0x0000808000800000,
        0x8000800080008080
    ];
}

pub fn new() -> Fly {
    let table: Vec<_> = From::from(&Fly::SBOX[0..]);
    Fly {size: 64, 
         key_size: 128, 
         sbox: Sbox::new(8, table)}
}

impl Cipher for Fly {
    /* Returns the design type of the cipher */
    fn structure(&self) -> CipherStructure {
        CipherStructure::Spn
    }

    /* Returns the size of the input to Fly. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }
    /* Returns key-size in bits */
    fn key_size(&self) -> usize {
        return self.key_size;
    }

    /* Returns the number of S-boxes in Fly. This is always 8. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the Fly S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the bit permutation of Fly to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;
        for i in 0..8 {
            output ^= Fly::PERMUTATION[i][((input >> (i*8)) & 0xff) as usize];
        }
        output
    }

    /* Applies the inverse linear layer, st.
     *
     * I = linear_layer_inv o linear_layer
     */
    fn linear_layer_inv(&self, input: u64) -> u64 {
        let mut output = 0;
        for i in 0..8 {
            output ^= Fly::PERMUTATION_INV[i][((input >> (i*8)) & 0xff) as usize];
        }
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
            k0 <<= 8;
            k0 |= key[i] as u64;
            k1 <<= 8;
            k1 |= key[i+8] as u64;
        }

        for r in 0..rounds {
            if r % 2 == 0 {
                keys.push(k0)
            } else {
                keys.push(k0 ^ k1)
            }
        }

        keys
    }

    /* Performs encryption */
    fn encrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        for i in 0..20 {
            // Add round key
            output ^= round_keys[i];

            // Appply constants
            output ^= 0x4444444444444444;
            output ^= Fly::CONSTANTS[i];

            // Apply S-box
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= (self.sbox.table[((output >> (8*j)) & 0xff) as usize] as u64) << (8*j);
            }

            // Apply linear layer
            output = self.linear_layer(tmp);
        }

        output ^= round_keys[20];

        // Appply constants
        output ^= 0x4444444444444444;
        output ^= Fly::CONSTANTS[20];

        output
    }

    /* Performs decryption */
    fn decrypt(&self, _input: u64, _round_keys: &Vec<u64>) -> u64 {
        panic!("Not implemented")
    }

    /* Returns the string "Fly". */
    fn name(&self) -> String {
        String::from("Fly")
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

/*
#[cfg(test)]
mod tests {
    use cipher;

    fn translate(x: u64) -> u64 {
        let mut y = 0;

        for i in 0..8 {
            let z  = (x >> (8*i)) & 0xff;

            for j in 0..8 {
                y ^= ((z >> j) & 0x1) << (8*j+i);
            }
        }

        y
    }

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("fly").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(21, &key);
        let plaintext = 0x0000000000000000;
        // let ciphertext = 0x242730FBD342A940;
        let ciphertext = 0x40A942D3FB302724;
        let ciphertext = translate(ciphertext);
        println!("{:016x}", ciphertext);

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        // let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        // let round_keys = cipher.key_schedule(32, &key);
        // let plaintext = 0xffffffffffffffff;
        // let ciphertext = 0x3333dcd3213210d2;

        // assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("fly").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x5579c1387b228445;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x3333dcd3213210d2;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("fly").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}
*/