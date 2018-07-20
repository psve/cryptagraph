use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            PUFFIN
******************************************************************/

/** 
A structure representing the PUFFIN cipher.

size        Size of the cipher in bits. This is fixed to 64.
key_size    Size of the cipher key in bits. This is fixed to 128.
sbox        The PUFFIN S-box.
 */
#[derive(Clone)]
pub struct Puffin {
    size: usize,
    key_size: usize,
    sbox: Sbox
}

impl Puffin {
    const PERMUTATION : [[u128 ; 0x100] ; 8] = include!("data/puffin.perm");
    const KEY_PERMUTATION : [u128; 128] = [22,121,126,110,79,81,116,55,
                                          113,21,29,20,56,76,41,112,
                                          45,109,95,87,94,44,68,8,
                                          115,69,6,75,83,5,54,70,
                                          23,61,106,103,85,124,111,52,
                                          119,32,100,17,15,34,128,91,
                                          58,99,120,67,31,98,53,71,
                                          92,25,38,93,65,2,37,28,
                                          24,82,88,14,96,118,1,9,
                                          125,27,127,18,4,10,102,7,
                                          35,105,48,63,30,77,72,50,
                                          108,73,12,19,107,11,26,84,
                                          47,97,117,49,46,33,16,42,
                                          39,57,114,62,123,101,80,13,
                                          51,122,64,89,43,60,40,3,
                                          86,90,59,74,78,104,36,66];
    const KEY_SELECTION : [u128; 64] = [3,123,15,58,89,36,98,52,57,63,100,70,46,71,94,51,83,14,4,
                                       22,32,114,84,101,12,23,31,65,41,96,120,50,45,54,112,122,29,
                                       81,30,121,97,55,26,64,24,117,19,9,111,18,44,86,16,95,42,72,
                                       2,91,118,124,38,48,43,39];
}

pub fn new() -> Puffin {
    let table = vec![0xd, 0x7, 0x3, 0x2, 0x9, 0xa, 0xc, 0x1, 0xf, 0x4, 0x5, 0xe, 0x6, 0x0, 0xb, 0x8];
    Puffin{size: 64, 
           key_size: 128,
           sbox: Sbox::new(4, table)}
}

impl Cipher for Puffin {
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

        output ^= Puffin::PERMUTATION[0][((input      ) & 0xff) as usize];
        output ^= Puffin::PERMUTATION[1][((input >>  8) & 0xff) as usize];
        output ^= Puffin::PERMUTATION[2][((input >> 16) & 0xff) as usize];
        output ^= Puffin::PERMUTATION[3][((input >> 24) & 0xff) as usize];
        output ^= Puffin::PERMUTATION[4][((input >> 32) & 0xff) as usize];
        output ^= Puffin::PERMUTATION[5][((input >> 40) & 0xff) as usize];
        output ^= Puffin::PERMUTATION[6][((input >> 48) & 0xff) as usize];
        output ^= Puffin::PERMUTATION[7][((input >> 56) & 0xff) as usize];

        output
    }

    /** 
    Applies the inverse linear layer of the cipher.
    
    input   The input to the inverse linear layer. 
    */
    fn linear_layer_inv(&self, input: u128) -> u128 {
        self.linear_layer(input)
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
        let mut k1 = 0;
        let mut k0 = 0;

        // Load key into 128-bit state (k1 || k0)
        for i in 0..8 {
            k1 <<= 8;
            k0 <<= 8;
            k1 |= u128::from(key[i+8]);
            k0 |= u128::from(key[i]);
        }

        for r in 0..rounds {
            let mut t0 = 0;
            let mut t1 = 0;
            for i in 0..64 {
                if Puffin::KEY_PERMUTATION[i] > 64 {
                    t1 ^= ((k0 >> i) & 0x1) << (Puffin::KEY_PERMUTATION[i] - 1 - 64);
                } else {
                    t0 ^= ((k0 >> i) & 0x1) << (Puffin::KEY_PERMUTATION[i] - 1);
                }

                if Puffin::KEY_PERMUTATION[i+64] > 64 {
                    t1 ^= ((k1 >> i) & 0x1) << (Puffin::KEY_PERMUTATION[i+64] - 1 - 64);
                } else {
                    t0 ^= ((k1 >> i) & 0x1) << (Puffin::KEY_PERMUTATION[i+64] - 1);
                }
            }

            k0 = t0;
            k1 = t1;

            if r != 2 || r != 5 || r != 6 || r != 8 {
                k0 ^= 0b10111;
            }

            let mut key = 0;

            for i in 0..64 {
                if Puffin::KEY_SELECTION[i] > 64 {
                    key ^= ((k1 >> (Puffin::KEY_SELECTION[i] - 1 - 64)) & 0x1) << i;
                } else {
                    key ^= ((k0 >> (Puffin::KEY_SELECTION[i] - 1)) & 0x1) << i;
                }
            }

            keys.push(key);
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

        for &round_key in round_keys.iter().take(33) {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.sbox.table[((output >> (4*j)) & 0xf) as usize]) << (4*j);
            }

            // Apply linear layer
            output = self.linear_layer(tmp);

            // Add round key
            output ^= round_key;
        }

        output
    }

    /** 
    Performs decryption with the cipher. 
    
    input       Ciphertext to be decrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        for i in 0..33 {
            // Add round key
            output ^= round_keys[32-i];

            // Apply linear layer
            output = self.linear_layer(output);
            
            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.sbox.table[((output >> (4*j)) & 0xf) as usize]) << (4*j);
            }

            output = tmp;
        }

        output
    }

    /** 
    Returns the name of the cipher. 
    */
    fn name(&self) -> String {
        String::from("PUFFIN")
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
    
    /* No test vectors provided in specification
    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("puffin").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x5579c1387b228445;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x3333dcd3213210d2;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("puffin").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x5579c1387b228445;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x3333dcd3213210d2;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }*/

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("puffin").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(33, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(33, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}