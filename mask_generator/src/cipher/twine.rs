use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            TWINE
******************************************************************/

/** 
A structure representing the TWINE cipher.

size                Size of the cipher in bits. This is fixed to 64.
key_size            Size of the cipher key in bits. This is fixed to 80.
sbox                The TWINE S-box.
permutation         The TWINE permutation.
inverse             The inverse TWINE permutation.
constants           Round constants. 
*/
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

impl Cipher for Twine {
    /** 
    Returns the design type of the cipher. 
    */
    fn structure(&self) -> CipherStructure {
        CipherStructure::Feistel
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
    Returns the S-box of the cipher. 
    */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /** 
    Applies the linear layer of the cipher.
    
    input   The input to the linear layer.
    */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;
        
        output ^= ((input >> ( 0*4)) & 0xf) << (self.permutation[ 0]*4);
        output ^= ((input >> ( 1*4)) & 0xf) << (self.permutation[ 1]*4);
        output ^= ((input >> ( 2*4)) & 0xf) << (self.permutation[ 2]*4);
        output ^= ((input >> ( 3*4)) & 0xf) << (self.permutation[ 3]*4);
        output ^= ((input >> ( 4*4)) & 0xf) << (self.permutation[ 4]*4);
        output ^= ((input >> ( 5*4)) & 0xf) << (self.permutation[ 5]*4);
        output ^= ((input >> ( 6*4)) & 0xf) << (self.permutation[ 6]*4);
        output ^= ((input >> ( 7*4)) & 0xf) << (self.permutation[ 7]*4);
        output ^= ((input >> ( 8*4)) & 0xf) << (self.permutation[ 8]*4);
        output ^= ((input >> ( 9*4)) & 0xf) << (self.permutation[ 9]*4);
        output ^= ((input >> (10*4)) & 0xf) << (self.permutation[10]*4);
        output ^= ((input >> (11*4)) & 0xf) << (self.permutation[11]*4);
        output ^= ((input >> (12*4)) & 0xf) << (self.permutation[12]*4);
        output ^= ((input >> (13*4)) & 0xf) << (self.permutation[13]*4);
        output ^= ((input >> (14*4)) & 0xf) << (self.permutation[14]*4);
        output ^= ((input >> (15*4)) & 0xf) << (self.permutation[15]*4);

        output
    }

    /** 
    Applies the inverse linear layer of the cipher.
    
    input   The the input to the inverse linear layer. 
    */
    fn linear_layer_inv(&self, input: u64) -> u64 {
        let mut output = 0;

        output ^= ((input >> ( 0*4)) & 0xf) << (self.inverse[ 0]*4);
        output ^= ((input >> ( 1*4)) & 0xf) << (self.inverse[ 1]*4);
        output ^= ((input >> ( 2*4)) & 0xf) << (self.inverse[ 2]*4);
        output ^= ((input >> ( 3*4)) & 0xf) << (self.inverse[ 3]*4);
        output ^= ((input >> ( 4*4)) & 0xf) << (self.inverse[ 4]*4);
        output ^= ((input >> ( 5*4)) & 0xf) << (self.inverse[ 5]*4);
        output ^= ((input >> ( 6*4)) & 0xf) << (self.inverse[ 6]*4);
        output ^= ((input >> ( 7*4)) & 0xf) << (self.inverse[ 7]*4);
        output ^= ((input >> ( 8*4)) & 0xf) << (self.inverse[ 8]*4);
        output ^= ((input >> ( 9*4)) & 0xf) << (self.inverse[ 9]*4);
        output ^= ((input >> (10*4)) & 0xf) << (self.inverse[10]*4);
        output ^= ((input >> (11*4)) & 0xf) << (self.inverse[11]*4);
        output ^= ((input >> (12*4)) & 0xf) << (self.inverse[12]*4);
        output ^= ((input >> (13*4)) & 0xf) << (self.inverse[13]*4);
        output ^= ((input >> (14*4)) & 0xf) << (self.inverse[14]*4);
        output ^= ((input >> (15*4)) & 0xf) << (self.inverse[15]*4);

        output
    }

    /** 
    Computes a vector of round key from a cipher key.

    rounds      Number of rounds to generate keys for.
    key         The master key to expand.
    */
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

    /** 
    Performs encryption with the cipher. 
    
    input       Plaintext to be encrypted.
    round_keys  Round keys generated by the key-schedule.
    */
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

    /** 
    Performs decryption with the cipher. 
    
    input       Ciphertext to be decrypted.
    round_keys  Round keys generated by the key-schedule.
    */
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

    /** 
    Returns the name of the cipher. 
    */
    fn name(&self) -> String {
        String::from("TWINE")
    }

    /** 
    Transforms the input and output mask of the S-box layer to an
    input and output mask of a round.
    
    input    Input mask to the S-box layer.
    output   Output mask to the S-box layer.
    */
    #[allow(unused_variables)]
    fn sbox_mask_transform(&self, 
                           input: u64, 
                           output: u64, 
                           property_type: PropertyType) 
                           -> (u64, u64) {
        match property_type {
            PropertyType::Linear => {
                let mut alpha = 0;
                let mut tmp = 0;

                for i in 0..8 {
                    alpha ^= ((output >> 4*i) & 0xf) << (i*8);
                    alpha ^= ((input >> 4*i) & 0xf) << (i*8+4);
                    tmp ^= ((output >> (4*i+32)) & 0xf) << (i*8);
                }

                tmp = self.linear_layer_inv(tmp);
                alpha ^= tmp;

                let mut beta = 0;
                tmp = 0;

                for i in 0..8 {
                    beta ^= ((output >> (4*i+32)) & 0xf) << (i*8);
                    beta ^= ((input >> (4*i+32)) & 0xf) << (i*8+4);
                    tmp ^= ((output >> 4*i) & 0xf) << (i*8);
                }

                tmp = self.linear_layer(tmp);
                beta ^= tmp;
                beta = self.linear_layer(beta);       

                (alpha, beta)
            },
            PropertyType::Differential => {
                let mut delta = 0;
                let mut tmp = 0;

                for i in 0..8 {
                    delta ^= ((output >> 4*i) & 0xf) << (i*8);
                    delta ^= ((input >> 4*i) & 0xf) << (i*8+4);
                    tmp ^= ((input >> (4*i+32)) & 0xf) << (i*8+4);
                }

                tmp = self.linear_layer_inv(tmp);
                delta ^= tmp;

                let mut nabla = 0;
                tmp = 0;

                for i in 0..8 {
                    nabla ^= ((output >> (4*i+32)) & 0xf) << (i*8);
                    nabla ^= ((input >> (4*i+32)) & 0xf) << (i*8+4);
                    tmp ^= ((input >> 4*i) & 0xf) << (i*8+4);
                }

                tmp = self.linear_layer(tmp);
                nabla ^= tmp;
                nabla = self.linear_layer(nabla);       

                (delta, nabla)
            }
        }
    }
}

#[cfg(test)]
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