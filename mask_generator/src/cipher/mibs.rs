use cipher::{Sbox, CipherStructure, Cipher};

/*****************************************************************
                            MIBS
******************************************************************/

/* A structure representing the MIBS cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The MIBS S-box.
 * permutation  The MIBS bit permutation.
 */
#[derive(Clone)]
pub struct Mibs {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox
}

impl Mibs {
    const PERMUTATION : [usize ; 8] = [3, 4, 1, 2, 5, 7, 0, 6];
    const IPERMUTATION : [usize ; 8] = [6, 2, 3, 0, 1, 4, 7, 5];
}

pub fn new() -> Mibs {
    let table = vec![4, 15, 3, 8, 13, 10, 12, 0, 11, 5, 7, 14, 2, 6, 1, 9];
    let itable = vec![7, 14, 12, 2, 0, 9, 13, 10, 3, 15, 5, 8, 6, 4, 11, 1];
    Mibs{size: 64,
         key_size: 64, 
         sbox: Sbox::new(4, table),
         isbox: Sbox::new(4, itable)}
}

impl Cipher for Mibs {
    /* Returns the design type of the cipher */
    fn structure(&self) -> CipherStructure {
        CipherStructure::Feistel
    }

    /* Returns the size of the input to MIBS. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }
    /* Returns key-size in bits */
    fn key_size(&self) -> usize {
        self.key_size
    }

    /* Returns the number of S-boxes in MIBS. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the MIBS S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the bit permutation of MIBS to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut x = input;
        x ^= (x & (0xf << 16)) >> 16;
        x ^= (x & (0xf << 20)) >> 16;
        x ^= (x & (0xf << 24)) >> 16;
        x ^= (x & (0xf << 28)) >> 16;
        x ^= (x & (0xf << 0)) << 24;
        x ^= (x & (0xf << 4)) << 24;
        x ^= (x & (0xf << 8)) << 8;
        x ^= (x & (0xf << 12)) << 8;
        x ^= (x & (0xf << 16)) >> 4;
        x ^= (x & (0xf << 20)) >> 20;
        x ^= (x & (0xf << 24)) >> 20;
        x ^= (x & (0xf << 28)) >> 20;
        x ^= (x & (0xf << 0)) << 16;
        x ^= (x & (0xf << 4)) << 16;
        x ^= (x & (0xf << 8)) << 16;
        x ^= (x & (0xf << 12)) << 16;

        let mut output = 0;
        
        for i in 0..8 {
            output ^= ((x >> (4*i)) & 0xf) << (Mibs::PERMUTATION[i] * 4);
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
            output ^= ((input >> (4*i)) & 0xf) << (Mibs::IPERMUTATION[i] * 4);
        }
        
        let mut x = output;

        x ^= (x & (0xf << 12)) << 16;
        x ^= (x & (0xf << 8)) << 16;
        x ^= (x & (0xf << 4)) << 16;
        x ^= (x & (0xf << 0)) << 16;
        x ^= (x & (0xf << 28)) >> 20;
        x ^= (x & (0xf << 24)) >> 20;
        x ^= (x & (0xf << 20)) >> 20;
        x ^= (x & (0xf << 16)) >> 4;
        x ^= (x & (0xf << 12)) << 8;
        x ^= (x & (0xf << 8)) << 8;
        x ^= (x & (0xf << 4)) << 24;
        x ^= (x & (0xf << 0)) << 24;
        x ^= (x & (0xf << 28)) >> 16;
        x ^= (x & (0xf << 24)) >> 16;
        x ^= (x & (0xf << 20)) >> 16;
        x ^= (x & (0xf << 16)) >> 16;

        x
    }

    /* Computes a vector of round key from a cipher key*/    
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut s = 0;

        // load key into 63-bit state
        for i in 0..8 {
            s <<= 8;
            s |= key[i] as u64;
        }

        for r in 0..rounds {
            s = (s >> 15) ^ (s << (64-15));
            s = (s & 0x0fffffffffffffff) ^ ((self.sbox.table[(s >> 60) as usize] as u64) << 60);
            s ^= ((r+1) as u64) << 11;
            keys.push(s >> 32);
        }

        keys
    }

    /* Performs encryption */
    fn encrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        for i in 0..32 {
            let mut left = output >> 32;
            let right = output & 0xffffffff;
            output = left;

            // Add round key
            left ^= round_keys[i];

            // Sbox
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= (self.sbox.table[((left >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }

            // Linear layer
            left = self.linear_layer(tmp);

            output ^= (right ^ left) << 32;
        }

        output = (output >> 32) ^ (output << 32);
        output
    }

    /* Performs decryption */
    fn decrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        for i in 0..32 {
            let mut left = output >> 32;
            let right = output & 0xffffffff;
            output = left;

            // Add round key
            left ^= round_keys[31-i];

            // Sbox
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= (self.sbox.table[((left >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }

            // Linear layer
            left = self.linear_layer(tmp);

            output ^= (right ^ left) << 32;
        }

        (output >> 32) ^ (output << 32)
    }

    /* Returns the string "MIBS". */
    fn name(&self) -> String {
        String::from("MIBS")
    }
    
    /* Transforms the input and output mask of the S-box layer to an
     * input and output mask of a round.
     *
     * input    Input mask to the S-box layer.
     * output   Output mask to the S-box layer.
     */

    fn sbox_mask_transform(& self, input: u64, output: u64) -> (u64, u64) {
        let output = self.linear_layer(output & 0xffffffff)
                   ^ (self.linear_layer(output >> 32) << 32);
        let mut alpha = output;
        alpha ^= input << 32;

        let mut beta = output;
        beta ^= input >> 32;        

        (alpha, beta)
    }
}


#[cfg(test)]
mod tests {
    use cipher;
    
    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("mibs").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x6d1d3722e19613d2;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x595263b93ffe6e18;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("mibs").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x6d1d3722e19613d2;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x595263b93ffe6e18;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
    

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("mibs").unwrap();
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