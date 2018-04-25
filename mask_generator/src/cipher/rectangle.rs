use cipher::{Sbox, CipherStructure, Cipher};

/*****************************************************************
                            RECTANGLE
******************************************************************/

/* A structure representing the RECTANGLE cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The RECTANGLE S-box.
 * permutation  The RECTANGLE bit permutation.
 */
#[derive(Clone)]
pub struct Rectangle {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox,
    constants: [u64; 25],
}

impl Rectangle {
    const PERMUTATION : [[u64 ; 0x100] ; 8] = include!("rectangle.perm");
    const IPERMUTATION : [[u64 ; 0x100] ; 8] = include!("rectangle.inv.perm");
}

pub fn new() -> Rectangle {
    let table = vec![0x6, 0x5, 0xc, 0xa, 0x1, 0xe, 0x7, 0x9, 0xb, 0x0, 0x3, 0xd, 0x8, 0xf, 0x4, 0x2];
    let itable = vec![0x9, 0x4, 0xf, 0xa, 0xe, 0x1, 0x0, 0x6, 0xc, 0x7, 0x3, 0x8, 0x2, 0xb, 0x5, 0xd];
    let constants = [0x01,0x02,0x04,0x09,0x12,0x05,0x0b,0x16,0x0c,0x19,0x13,0x07,0x0f,0x1f,
                     0x1e,0x1c,0x18,0x11,0x03,0x06,0x0d,0x1b,0x17,0x0e,0x1d];
    Rectangle{size: 64, 
              key_size: 80,
              sbox: Sbox::new(4, table),
              isbox: Sbox::new(4, itable),
              constants: constants}
}

impl Cipher for Rectangle {
    /* Returns the design type of the cipher */
    fn structure(&self) -> CipherStructure {
        CipherStructure::Spn
    }
    
    /* Returns the size of the input to RECTANGLE. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }
    /* Returns key-size in bits */
    fn key_size(&self) -> usize {
        self.key_size
    }

    /* Returns the number of S-boxes in RECTANGLE. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the RECTANGLE S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the bit permutation of RECTANGLE to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;

        for i in 0..8 {
            output ^= Rectangle::PERMUTATION[i][((input >> (i*8)) & 0xff) as usize];
        }

        output
    }

    fn linear_layer_inv(&self, input: u64) -> u64 {
        let mut output = 0;

        for i in 0..8 {
            output ^= Rectangle::IPERMUTATION[i][((input >> (i*8)) & 0xff) as usize];
        }

        output
    }

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut r0 = 0;
        let mut r1 = 0;
        let mut r2 = 0;
        let mut r3 = 0;
        let mut r4 = 0;

        for i in 0..2 {
            r4 <<= 8;
            r4 |= key[i] as u64;
            r3 <<= 8;
            r3 |= key[i+2] as u64;
            r2 <<= 8;
            r2 |= key[i+4] as u64;
            r1 <<= 8;
            r1 |= key[i+6] as u64;
            r0 <<= 8;
            r0 |= key[i+8] as u64;
        }

        for r in 0..rounds {
            // Extract
            let mut roundkey = 0;

            for i in 0..16 {
                roundkey ^= ((r0 >> i) & 0x1) << (4*i);
                roundkey ^= ((r1 >> i) & 0x1) << (4*i+1);
                roundkey ^= ((r2 >> i) & 0x1) << (4*i+2);
                roundkey ^= ((r3 >> i) & 0x1) << (4*i+3);
            }

            keys.push(roundkey);

            // Update
            for i in 0..4 {
                let mut s = 0;
                s ^= (r0 >> i) & 0x1;
                s ^= ((r1 >> i) & 0x1) << 1;
                s ^= ((r2 >> i) & 0x1) << 2;
                s ^= ((r3 >> i) & 0x1) << 3;
                s = self.sbox.table[s as usize] as u64;
                
                r0 = (r0 & !(0x1 << i)) ^ ((s & 0x1) << i);
                r1 = (r1 & !(0x1 << i)) ^ (((s >> 1) & 0x1) << i);
                r2 = (r2 & !(0x1 << i)) ^ (((s >> 2) & 0x1) << i);
                r3 = (r3 & !(0x1 << i)) ^ (((s >> 3) & 0x1) << i);
            }

            let t = r0;
            r0 = ((r0 << 8) & 0xffff) ^ ((r0 >> 8) & 0xffff) ^ r1;
            r1 = r2;
            r2 = r3;
            r3 = ((r3 << 12) & 0xffff) ^ ((r3 >> 4) & 0xffff) ^ r4;
            r4 = t;

            r0 ^= self.constants[r];
        }

        // Extract
        let mut roundkey = 0;

        for i in 0..16 {
            roundkey ^= ((r0 >> i) & 0x1) << (4*i);
            roundkey ^= ((r1 >> i) & 0x1) << (4*i+1);
            roundkey ^= ((r2 >> i) & 0x1) << (4*i+2);
            roundkey ^= ((r3 >> i) & 0x1) << (4*i+3);
        }

        keys.push(roundkey);

        keys
    }

    /* Performs encryption */
    fn encrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        // Transpose text
        let mut output = 0;

        for i in 0..16 {
            output ^= ((input >> i) & 0x1) << 4*i;
            output ^= ((input >> (i+16)) & 0x1) << (4*i+1);
            output ^= ((input >> (i+32)) & 0x1) << (4*i+2);
            output ^= ((input >> (i+48)) & 0x1) << (4*i+3);
        }

        for i in 0..25 {
            // Add round key
            output ^= round_keys[i];

            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }

            // Shift rows
            output = self.linear_layer(tmp);
        }

        output ^= round_keys[25];

        // Transpose text
        let mut tmp = 0;

        for i in 0..16 {
            tmp ^= ((output >> 4*i) & 0x1) << i;
            tmp ^= ((output >> (4*i+1)) & 0x1) << (i+16);
            tmp ^= ((output >> (4*i+2)) & 0x1) << (i+32);
            tmp ^= ((output >> (4*i+3)) & 0x1) << (i+48);
        }

        tmp
    }

    /* Performs decryption */
    fn decrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = 0;

        for i in 0..16 {
            output ^= ((input >> i) & 0x1) << 4*i;
            output ^= ((input >> (i+16)) & 0x1) << (4*i+1);
            output ^= ((input >> (i+32)) & 0x1) << (4*i+2);
            output ^= ((input >> (i+48)) & 0x1) << (4*i+3);
        }
        
        output ^= round_keys[25];

        for i in 0..25 {
            // Shift rows
            output = self.linear_layer_inv(output);

            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.isbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }

            // Add round key
            output = tmp ^ round_keys[24-i];
        }

        // Transpose text
        let mut tmp = 0;

        for i in 0..16 {
            tmp ^= ((output >> 4*i) & 0x1) << i;
            tmp ^= ((output >> (4*i+1)) & 0x1) << (i+16);
            tmp ^= ((output >> (4*i+2)) & 0x1) << (i+32);
            tmp ^= ((output >> (4*i+3)) & 0x1) << (i+48);
        }

        tmp
    }

    fn name(&self) -> String {
        String::from("RECTANGLE")
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
        let cipher = cipher::name_to_cipher("rectangle").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0b0000100001110100111010001011000111100011010101000010110110010110;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0b0000000100010010101011100011110110101010001101001001100101000101;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("rectangle").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0b0000100001110100111010001011000111100011010101000010110110010110;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0b0000000100010010101011100011110110101010001101001001100101000101;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("rectangle").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(25, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}