use cipher::{Sbox, CipherStructure, Cipher};

/*****************************************************************
                            KLEIN
******************************************************************/

/* A structure representing the KLEIN cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The KLEIN S-box.
 * key_size     Size of cipher key in bits. This is (currently) fixed to 80.
 */
#[derive(Clone)]
pub struct Klein {
    size     : usize,
    key_size : usize,
    sbox     : Sbox,
}

pub fn new() -> Klein {
    let table = vec![0x7,0x4,0xa,0x9,0x1,0xf,0xb,0x0,0xc,0x3,0x2,0x6,0x8,0xe,0xd,0x5];
    Klein{
        size: 64, 
        key_size: 64, 
        sbox: Sbox::new(4, table)
    }
}

// Calculate y*02 in the Rijndael finite field
fn mult_02(y: u8) -> u8{
    let t = (y << 1) & 0xff;
    let u = 0xff * ((y >> 7) & 0x1);
    (u & 0x1b) ^ t
}

fn mult_04(y: u8) -> u8{
    mult_02(mult_02(y))
}

fn mult_08(y: u8) -> u8{
    mult_02(mult_04(y))
}

impl Cipher for Klein {
    /* Returns the design type of the cipher */
    fn structure(&self) -> CipherStructure {
        CipherStructure::Spn
    }
    
    /* Returns the size of the input to KLEIN. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }
    /* Returns key-size in bits */
    fn key_size(&self) -> usize {
        return self.key_size;
    }

    /* Returns the number of S-boxes in KLEIN. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the KLEIN S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the bit permutation of KLEIN to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = input;

        // RotateNibbles
        output = (output << 16) ^ (output >> 48);

        // MixNibbles
        for i in 0..2 {
            let mut x = [((output >> (i*32+24)) & 0xff) as u8,
                         ((output >> (i*32+16)) & 0xff) as u8,
                         ((output >> (i*32+8)) & 0xff) as u8, 
                         ((output >> i*32) & 0xff) as u8];

            let t = x[0] ^ x[1] ^ x[2] ^ x[3];
            let u = x[3] ^ x[0];
            
            for j in 0..3 {
                x[j] = x[j] ^ mult_02(x[j]^x[j+1]) ^ t;
            }
            x[3] = x[3] ^ mult_02(u) ^ t;

            output &= !(0xffffffff << (i*32));
            output ^= (x[0] as u64) << (i*32+24);
            output ^= (x[1] as u64) << (i*32+16);
            output ^= (x[2] as u64) << (i*32+8);
            output ^= (x[3] as u64) << (i*32);
        }

        output
    }

    /* Applies the inverse linear layer, st.
     *
     * I = linear_layer_inv o linear_layer
     */
    fn linear_layer_inv(&self, input: u64) -> u64 {
        let mut output = input; 

        // MixNibbles inverse
        for i in 0..2 {
            let x = [((output >> (i*32+24)) & 0xff) as u8,
                     ((output >> (i*32+16)) & 0xff) as u8,
                     ((output >> (i*32+8)) & 0xff) as u8, 
                     ((output >> i*32) & 0xff) as u8];

            let mut y = [0, 0, 0, 0];

            y[0] = mult_08(x[0]^x[1]^x[2]^x[3]) ^
                   mult_04(x[0]^x[2]) ^ mult_02(x[0]^x[1]) ^
                   x[1] ^ x[2] ^ x[3];
            y[1] = mult_08(x[1]^x[2]^x[3]^x[0]) ^
                   mult_04(x[1]^x[3]) ^ mult_02(x[1]^x[2]) ^
                   x[2] ^ x[3] ^ x[0];
            y[2] = mult_08(x[2]^x[3]^x[0]^x[1]) ^
                   mult_04(x[2]^x[0]) ^ mult_02(x[2]^x[3]) ^
                   x[3] ^ x[0] ^ x[1];
            y[3] = mult_08(x[3]^x[0]^x[1]^x[2]) ^
                   mult_04(x[3]^x[1]) ^ mult_02(x[3]^x[0]) ^
                   x[0] ^ x[1] ^ x[2];

            output &= !(0xffffffff << (i*32));
            output ^= (y[0] as u64) << (i*32+24);
            output ^= (y[1] as u64) << (i*32+16);
            output ^= (y[2] as u64) << (i*32+8);
            output ^= (y[3] as u64) << (i*32);
        }

        // RotateNibbles inverse
        output = (output >> 16) ^ (output << 48);

        output
    }

    /* Computes a vector of round key from a cipher key*/    
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut k0 = 0;
        let mut k1 = 0;

        for i in 0..4 {
            k1 <<= 8;
            k0 <<= 8;
            k1 |= key[i] as u64;
            k0 |= key[i+4] as u64;
        }

        for r in 0..rounds {
            keys.push(k0 ^ (k1 << 32));

            k0 = ((k0 << 8) & 0xffffff00) ^ ((k0 >> 24) & 0x000000ff);
            k1 = ((k1 << 8) & 0xffffff00) ^ ((k1 >> 24) & 0x000000ff);
            k1 ^= k0;
            let t = k0;
            k0 = k1;
            k1 = t;

            for i in 2..6 {
                k0 = (k0 & !(0xf << 4*i)) ^ ((self.sbox.table[((k0 >> (4*i)) & 0xf) as usize] as u64) << (4*i));
            }

            k1 ^= ((r + 1) as u64) << 8;
        }

        keys
    }

    /* Performs encryption */
    fn encrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        for i in 0..12 {
            // Add key
            output ^= round_keys[i];

            // SubNibbles
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }

            // Linear layer
            output = self.linear_layer(tmp);
        }

        output ^= round_keys[12];
        output
    }

    /* Performs decryption */
    fn decrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        for i in 0..12 {
            // Add key
            output ^= round_keys[12-i];

            // Linear layer
            output = self.linear_layer_inv(output);
            
            // SubNibbles
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }

            output = tmp;
        }

        output ^= round_keys[0];
        output
    }

    /* Returns the string "KLEIN". */
    fn name(&self) -> String {
        String::from("KLEIN")
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
        let cipher = cipher::name_to_cipher("klein").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(13, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0xcdc0b51f14722bbe;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(13, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x6456764e8602e154;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let round_keys = cipher.key_schedule(13, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x592356c4997176c8;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(13, &key);
        let plaintext = 0x1234567890abcdef;
        let ciphertext = 0x629f9d6dff95800e;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("klein").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(13, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0xcdc0b51f14722bbe;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(13, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x6456764e8602e154;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let round_keys = cipher.key_schedule(13, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x592356c4997176c8;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(13, &key);
        let plaintext = 0x1234567890abcdef;
        let ciphertext = 0x629f9d6dff95800e;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("klein").unwrap();
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