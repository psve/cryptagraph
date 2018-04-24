use cipher::Sbox;
use cipher::Cipher;

#[derive(Clone)]
pub struct Twine {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    permutation: [u64; 16],
    inverse: [u64; 16],
    constants: [u64; 35],
}

pub fn new() -> Twine {
    let table = vec![0xc, 0x0, 0xf, 0xa, 0x2, 0xb, 0x9, 0x5, 0x8, 0x3, 0xd, 0x7, 0x1, 0xe, 0x6, 0x4];
    let permutation = [1, 4, 5, 0, 13, 6, 9, 2, 7, 12, 3, 8, 11, 14, 15, 10];
    let inverse     = [3, 0, 7, 10, 1, 2, 5, 8, 11, 6, 15, 12, 9, 4, 13, 14];
    let constants = [0x01,0x02,0x04,0x08,0x10,0x20,0x03,0x06,0x0c,0x18,0x30,0x23,0x05,0x0a,0x14,
                    0x28,0x13,0x26,0x0f,0x1e,0x3c,0x3b,0x35,0x29,0x11,0x22,0x07,0x0e,0x1c,0x38,
                    0x33,0x25,0x09,0x12,0x24];

    Twine{size: 64, 
          key_size: 80,
          sbox: Sbox::new(4, table), 
          permutation: permutation, 
          inverse: inverse,
          constants: constants}
}

impl Twine {
    /* Applies the inverse nibble permutation of TWINE to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer_inverse(&self, input: u64) -> u64{
        let mut output = 0;

        for i in 0..16 {
            output ^= ((input >> (i*4)) & 0xf) << (self.inverse[i]*4);
        }

        output
    }
}

impl Cipher for Twine {
    /* Returns the size of the input to TWINE. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }
    /* Returns key-size in bits */
    fn key_size(&self) -> usize {
        self.key_size
    }

    /* Returns the number of S-boxes in TWINE. This is always 8. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns Feistel function of TWINE represented as an S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the nibble permutation of TWINE to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;

        for i in 0..16 {
            output ^= ((input >> (i*4)) & 0xf) << (self.permutation[i]*4);
        }

        output
    }
    
    fn linear_layer_inv(&self, input: u64) -> u64 {
        let mut output = 0;

        for i in 0..16 {
            output ^= ((input >> (i*4)) & 0xf) << (self.inverse[i]*4);
        }

        output
    }

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut k0 = 0;
        let mut k1 = 0;

        k1 |= key[0] as u64;
        k1 <<= 8;
        k1 |= key[1] as u64;

        for i in 2..10 {
            k0 <<= 8;
            k0 |= key[i] as u64;
        }

        let idx_0 = [12, 16, 20, 24, 52, 60];
        let idx_1 = [0, 8];

        for r in 0..rounds {
            // Extract
            let mut roundkey = 0;

            for i in 0..6 {
                roundkey ^= ((k0 >> idx_0[i]) & 0xf) << (8*i+4);
            }

            for i in 0..2 {
                roundkey ^= ((k1 >> idx_1[i]) & 0xf) << (8*(i+6)+4);
            }

            keys.push(roundkey);

            // Update
            k0 ^= self.constants[r] & 0x7;
            k0 ^= (self.constants[r] >> 3) << 48;
            k0 ^= (self.sbox.table[((k0 >> 12) & 0xf) as usize] as u64) << 60;
            k1 ^= (self.sbox.table[((k1 >> 12) & 0xf) as usize] as u64) << 8;
            k1 = (k1 >> 12) ^ ((k1 << 4) & 0xfff0);
            let t = k1;
            k1 = k0 >> 48;
            k0 <<= 16;
            k0 ^= t;
        }

        // Extract
        let mut roundkey = 0;

        for i in 0..6 {
            roundkey ^= ((k0 >> idx_0[i]) & 0xf) << (8*i+4);
        }

        for i in 0..2 {
            roundkey ^= ((k1 >> idx_1[i]) & 0xf) << (8*(i+6)+4);
        }

        keys.push(roundkey);

        keys
    }

    /* Performs encryption */
    fn encrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        for i in 0..35 {
            let x = (output & 0xf0f0f0f0f0f0f0f0) ^ round_keys[i];
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= (self.sbox.table[((x >> (8*j+4)) & 0xf) as usize] as u64) << (8*j+4);
            }

            output ^= tmp >> 4;
            output = self.linear_layer(output);
        }

        let x = (output & 0xf0f0f0f0f0f0f0f0) ^ round_keys[35];
        let mut tmp = 0;

        for j in 0..8 {
            tmp ^= (self.sbox.table[((x >> (8*j+4)) & 0xf) as usize] as u64) << (8*j+4);
        }

        output ^= tmp >> 4;
        output
    }

    /* Performs decryption */
    fn decrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        for i in 0..35 {
            let x = (output & 0xf0f0f0f0f0f0f0f0) ^ round_keys[35-i];
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= (self.sbox.table[((x >> (8*j+4)) & 0xf) as usize] as u64) << (8*j+4);
            }

            output ^= tmp >> 4;
            output = self.linear_layer_inv(output);
        }

        let x = (output & 0xf0f0f0f0f0f0f0f0) ^ round_keys[0];
        let mut tmp = 0;

        for j in 0..8 {
            tmp ^= (self.sbox.table[((x >> (8*j+4)) & 0xf) as usize] as u64) << (8*j+4);
        }

        output ^= tmp >> 4;
        output
    }

    fn name(&self) -> String {
        String::from("TWINE")
    }

    /* Transforms the input and output mask of the S-box layer to an
     * input and output mask of a round.
     *
     * input    Input mask to the S-box layer.
     * output   Output mask to the S-box layer.
     */
    fn sbox_mask_transform(& self, input: u64, output: u64) -> (u64, u64) {
        let mut alpha = 0;

        alpha ^= (input & 0xf) << 4;
        alpha ^= (input & 0xf0) << 8;
        alpha ^= (input & 0xf00) << 12;
        alpha ^= (input & 0xf000) << 16;
        alpha ^= (input & 0xf0000) << 20;
        alpha ^= (input & 0xf00000) << 24;
        alpha ^= (input & 0xf000000) << 28;
        alpha ^= (input & 0xf0000000) << 32;

        alpha ^= (output & 0xf) << 0;
        alpha ^= (output & 0xf0) << 4;
        alpha ^= (output & 0xf00) << 8;
        alpha ^= (output & 0xf000) << 12;
        alpha ^= (output & 0xf0000) << 16;
        alpha ^= (output & 0xf00000) << 20;
        alpha ^= (output & 0xf000000) << 24;
        alpha ^= (output & 0xf0000000) << 28;

        let mut beta = 0;

        beta ^= ((input & 0xf00000000) >> 32) << 4;
        beta ^= ((input & 0xf000000000) >> 32) << 8;
        beta ^= ((input & 0xf0000000000) >> 32) << 12;
        beta ^= ((input & 0xf00000000000) >> 32) << 16;
        beta ^= ((input & 0xf000000000000) >> 32) << 20;
        beta ^= ((input & 0xf0000000000000) >> 32) << 24;
        beta ^= ((input & 0xf00000000000000) >> 32) << 28;
        beta ^= ((input & 0xf000000000000000) >> 32) << 32;

        alpha ^= self.linear_layer_inverse(beta);

        beta ^= ((output & 0xf00000000) >> 32) << 0;
        beta ^= ((output & 0xf000000000) >> 32) << 4;
        beta ^= ((output & 0xf0000000000) >> 32) << 8;
        beta ^= ((output & 0xf00000000000) >> 32) << 12;
        beta ^= ((output & 0xf000000000000) >> 32) << 16;
        beta ^= ((output & 0xf0000000000000) >> 32) << 20;
        beta ^= ((output & 0xf00000000000000) >> 32) << 24;
        beta ^= ((output & 0xf000000000000000) >> 32) << 28;

        beta ^= self.linear_layer(alpha & 0xf0f0f0f0f0f0f0f0);

        beta = self.linear_layer(beta);

        (alpha, beta)
    }

    /* Function that defines how values of input mask, output mask, and bias 
     * are categorised for an LatMap. 
     *
     * alpha    Input mask.
     * beta     Output mask.
     * bias     Absolute counter bias.
     */
    fn lat_diversify(&self, _alpha: u64, _beta: u64, bias: i16) -> (i16, u16) {
        (bias, 0)
    }
}


mod tests {
    use cipher;


    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("twine").unwrap();
        let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let round_keys = cipher.key_schedule(35, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = 0x7c1f0f80b1df9c28;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("twine").unwrap();
        let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let round_keys = cipher.key_schedule(35, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = 0x7c1f0f80b1df9c28;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("twine").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(35, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(35, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}