use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            mCrypton
******************************************************************/

/** 
A structure representing the mCrypton cipher.

size                Size of the cipher in bits. This is fixed to 64.
key_size            Size of the cipher key in bits. This is fixed to 64.
sbox0               The first mCrypton S-box.
sbox1               The second mCrypton S-box.
sbox2               The thrid mCrypton S-box.
sbox3               The fourht mCrypton S-box.
constants           Round constants. 
*/
#[derive(Clone)]
pub struct Mcrypton {
    size: usize,
    key_size: usize,
    sbox0: Sbox,
    sbox1: Sbox,
    sbox2: Sbox,
    sbox3: Sbox,
    constants: [u128; 13]
}

pub fn new() -> Mcrypton {
    let table0 = vec![4, 15, 3, 8, 13, 10, 12, 0, 11, 5, 7, 14, 2, 6, 1, 9];
    let table1 = vec![1, 12, 7, 10, 6, 13, 5, 3, 15, 11, 2, 0, 8, 4, 9, 14];
    let table2 = vec![7, 14, 12, 2, 0, 9, 13, 10, 3, 15, 5, 8, 6, 4, 11, 1];
    let table3 = vec![11, 0, 10, 7, 13, 6, 4, 2, 12, 14, 3, 9, 1, 5, 15, 8];
    
    let constants = [0x1111, 0x2222, 0x4444, 0x8888, 0x3333, 0x6666, 
                     0xcccc, 0xbbbb, 0x5555, 0xaaaa, 0x7777, 0xeeee, 0xffff];
    Mcrypton{size: 64, 
           key_size: 64,
           sbox0: Sbox::new(4, table0), 
           sbox1: Sbox::new(4, table1), 
           sbox2: Sbox::new(4, table2), 
           sbox3: Sbox::new(4, table3), 
           constants}
}

impl Cipher for Mcrypton {
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
        self.size / self.sbox0.size
    }

    /** 
    Returns the i'th S-box of the cipher. 
    */
    fn sbox(&self, i: usize) -> &Sbox {
        let j = ((i / 4) + (i % 4)) % 4;

        match j {
             0 => &self.sbox0,
             1 => &self.sbox1,
             2 => &self.sbox2,
             3 => &self.sbox3,
            _ => unreachable!(),
        }
    }

    /** 
    Applies the linear layer of the cipher.
    
    input   The input to the linear layer.
    */
    fn linear_layer(&self, input: u128) -> u128{
        let mut output = 0;

        // Apply pi
        let masks = [0b1110, 0b1101, 0b1011, 0b0111];

        for c in 0..4 {
            for r in 0..4 {
                let mut m =  
                       masks[(c+r)   % 4]
                    ^ (masks[(c+r+1) % 4] << 16)
                    ^ (masks[(c+r+2) % 4] << 32)
                    ^ (masks[(c+r+3) % 4] << 48);
                m <<= 4*c;

                let x = (input & m) >> 4*c;
                let y =  (x & 0xf)
                      ^ ((x >> 16) & 0xf)
                      ^ ((x >> 32) & 0xf)
                      ^ ((x >> 48) & 0xf);

                output ^= y << (4*c + 16*r);
            }
        }

        // Apply tau
        let tmp = output;
        output = 0;

        for c in 0..4 {
            for r in 0..4 {
                output ^= ((tmp >> (4*c + 16*r)) & 0xf) << (4*r + 16*c);
            }
        }

        output
    }

    /** 
    Applies the inverse linear layer of the cipher.
    
    input   The input to the inverse linear layer. 
    */
    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;

        // Apply tau
        let tmp = input;

        for c in 0..4 {
            for r in 0..4 {
                output ^= ((tmp >> (4*c + 16*r)) & 0xf) << (4*r + 16*c);
            }
        }

        // Apply pi
        let tmp = output;
        output = 0;
        let masks = [0b1110, 0b1101, 0b1011, 0b0111];

        for c in 0..4 {
            for r in 0..4 {
                let mut m =  
                       masks[(c+r)   % 4]
                    ^ (masks[(c+r+1) % 4] << 16)
                    ^ (masks[(c+r+2) % 4] << 32)
                    ^ (masks[(c+r+3) % 4] << 48);
                m <<= 4*c;

                let x = (tmp & m) >> 4*c;
                let y =  (x & 0xf)
                      ^ ((x >> 16) & 0xf)
                      ^ ((x >> 32) & 0xf)
                      ^ ((x >> 48) & 0xf);

                output ^= y << (4*c + 16*r);
            }
        }

        output
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
    fn key_schedule(&self, _rounds : usize, key: &[u8]) -> Vec<u128> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        panic!("Not implemented!")
    }

    /** 
    Performs encryption with the cipher. 
    
    input       Plaintext to be encrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn encrypt(&self, _input: u128, _round_keys: &[u128]) -> u128 {
        panic!("Not implemented!")
    }

    /** 
    Performs decryption with the cipher. 
    
    input       Ciphertext to be decrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn decrypt(&self, _input: u128, _round_keys: &[u128]) -> u128 {
        panic!("Not implemented!")
    }

    /** 
    Returns the name of the cipher. 
    */
    fn name(&self) -> String {
        String::from("mCrypton")
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
        true 
    }
}

#[cfg(test)]
mod tests {
    use cipher;

    #[test]
    fn linear_test() {
        let cipher = cipher::name_to_cipher("mcrypton").unwrap();
        let x = 0x0123456789abcdef;

        assert_eq!(x, cipher.linear_layer_inv(cipher.linear_layer(x)));
    }

    /*#[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("mcrypton").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }*/
}