use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            MIBS
******************************************************************/

/** 
A structure representing the MIBS cipher.

size        Size of the cipher in bits. This is fixed to 64.
key_size    Size of the cipher key in bits. This is fixed to 64.
sbox        The MIBS S-box.
isbox       The inverse MIBS S-box.
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
    fn linear_layer(&self, input: u128) -> u128{
        let mut x = input as u64;
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
        
        output ^= ((x >> (4*0)) & 0xf) << (Mibs::PERMUTATION[0] * 4);
        output ^= ((x >> (4*1)) & 0xf) << (Mibs::PERMUTATION[1] * 4);
        output ^= ((x >> (4*2)) & 0xf) << (Mibs::PERMUTATION[2] * 4);
        output ^= ((x >> (4*3)) & 0xf) << (Mibs::PERMUTATION[3] * 4);
        output ^= ((x >> (4*4)) & 0xf) << (Mibs::PERMUTATION[4] * 4);
        output ^= ((x >> (4*5)) & 0xf) << (Mibs::PERMUTATION[5] * 4);
        output ^= ((x >> (4*6)) & 0xf) << (Mibs::PERMUTATION[6] * 4);
        output ^= ((x >> (4*7)) & 0xf) << (Mibs::PERMUTATION[7] * 4);

        output as u128
    }

    /** 
    Applies the inverse linear layer of the cipher.
    
    input   The input to the inverse linear layer. 
    */
    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;
        
        output ^= ((input as u64 >> (4*0)) & 0xf) << (Mibs::IPERMUTATION[0] * 4);
        output ^= ((input as u64 >> (4*1)) & 0xf) << (Mibs::IPERMUTATION[1] * 4);
        output ^= ((input as u64 >> (4*2)) & 0xf) << (Mibs::IPERMUTATION[2] * 4);
        output ^= ((input as u64 >> (4*3)) & 0xf) << (Mibs::IPERMUTATION[3] * 4);
        output ^= ((input as u64 >> (4*4)) & 0xf) << (Mibs::IPERMUTATION[4] * 4);
        output ^= ((input as u64 >> (4*5)) & 0xf) << (Mibs::IPERMUTATION[5] * 4);
        output ^= ((input as u64 >> (4*6)) & 0xf) << (Mibs::IPERMUTATION[6] * 4);
        output ^= ((input as u64 >> (4*7)) & 0xf) << (Mibs::IPERMUTATION[7] * 4);
        
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

        x as u128
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

        keys.iter().map(|&x| x as u128).collect()
    }

    /** 
    Performs encryption with the cipher. 
    
    input       Plaintext to be encrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn encrypt(&self, input: u128, round_keys: &Vec<u128>) -> u128 {
        let mut output = input as u64;

        for i in 0..32 {
            let mut left = output >> 32;
            let right = output & 0xffffffff;
            output = left;

            // Add round key
            left ^= round_keys[i] as u64;

            // Sbox
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= (self.sbox.table[((left >> (4*j)) & 0xf) as usize] as u128) << (4*j);
            }

            // Linear layer
            left = self.linear_layer(tmp) as u64;

            output ^= (right ^ left) << 32;
        }

        output = (output >> 32) ^ (output << 32);
        output as u128
    }

    /** 
    Performs decryption with the cipher. 
    
    input       Ciphertext to be decrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn decrypt(&self, input: u128, round_keys: &Vec<u128>) -> u128 {
        let mut output = input as u64;

        for i in 0..32 {
            let mut left = output >> 32;
            let right = output & 0xffffffff;
            output = left;

            // Add round key
            left ^= round_keys[31-i] as u64;

            // Sbox
            let mut tmp = 0;

            for j in 0..8 {
                tmp ^= (self.sbox.table[((left >> (4*j)) & 0xf) as usize] as u128) << (4*j);
            }

            // Linear layer
            left = self.linear_layer(tmp) as u64;

            output ^= (right ^ left) << 32;
        }

        ((output >> 32) ^ (output << 32)) as u128
    }

    /** 
    Returns the name of the cipher. 
    */
    fn name(&self) -> String {
        String::from("MIBS")
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
        match property_type {
            PropertyType::Linear => {
                let input = input as u64;
                let output = self.linear_layer(output & 0xffffffff) as u64
                           ^ ((self.linear_layer(output >> 32) as u64) << 32);
                let mut alpha = output;
                alpha ^= input << 32;

                let mut beta = output;
                beta ^= input >> 32;

                (alpha as u128, beta as u128)
            },
            PropertyType::Differential => {
                let input = input as u64;
                let output = self.linear_layer(output & 0xffffffff) as u64
                           ^ ((self.linear_layer(output >> 32) as u64) << 32);
                let mut delta = (input >> 32) ^ (input << 32);
                delta ^= output & 0xffffffff;

                let mut nabla = (input >> 32) ^ (input << 32);
                nabla ^= output & 0xffffffff00000000;

                (delta as u128, nabla as u128)
            }
        }
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