use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            GIFT64
******************************************************************/

/** 
A structure representing the GIFT64 cipher.
 
size            Size of the cipher in bits. This is fixed to 64.
key_size        Size of cipher key in bits. This is fixed to 128.
sbox            The GIFT S-box.
isbox           The inverse GIFT S-box.
constants       Round constants.
*/
#[derive(Clone)]
pub struct Gift64 {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox,
    constants: [u128; 48],
}

impl Gift64 {
    const PERMUTATION     : [[u128 ; 0x100] ; 8] = include!("data/gift.perm");
    const PERMUTATION_INV : [[u128 ; 0x100] ; 8] = include!("data/gift.perm.inv");
}

pub fn new() -> Gift64 {
    let table = vec![0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
                     0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe];
    let itable = vec![0xd, 0x0, 0x8, 0x6, 0x2, 0xc, 0x4, 0xb, 
                      0xe, 0x7, 0x1, 0xa, 0x3, 0x9, 0xf, 0x5];
    let constants = [0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,0x27,
                     0x0e,0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b,0x17,0x2e,
                     0x1c,0x38,0x31,0x23,0x06,0x0d,0x1b,0x36,0x2d,0x1a,0x34,0x29,0x12,0x24,0x08,
                     0x11,0x22,0x04];

    Gift64{size: 64, 
         key_size: 128,
         sbox: Sbox::new(4, table), 
         isbox: Sbox::new(4, itable),
         constants}
}

impl Cipher for Gift64 {
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
        output ^= Gift64::PERMUTATION[0][((input      ) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[1][((input >>  8) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[2][((input >> 16) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[3][((input >> 24) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[4][((input >> 32) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[5][((input >> 40) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[6][((input >> 48) & 0xff) as usize];
        output ^= Gift64::PERMUTATION[7][((input >> 56) & 0xff) as usize];

        output
    }

    /** 
    Applies the inverse linear layer of the cipher.
    
    input   The input to the inverse linear layer. 
    */
    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;
        output ^= Gift64::PERMUTATION_INV[0][((input      ) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[1][((input >>  8) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[2][((input >> 16) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[3][((input >> 24) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[4][((input >> 32) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[5][((input >> 40) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[6][((input >> 48) & 0xff) as usize];
        output ^= Gift64::PERMUTATION_INV[7][((input >> 56) & 0xff) as usize];

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
            k1 |= u128::from(key[i]);
            k0 |= u128::from(key[i+8]);
        }

        for r in 0..rounds {
            let mut round_key = 0;

            for i in 0..16 {
                round_key ^= ((k0 >> i) & 0x1) << (4*i);
                round_key ^= ((k0 >> (i+16)) & 0x1) << (4*i+1);
            }

            round_key ^= 1 << 63;
            round_key ^= (self.constants[r] & 0x1) << 3;
            round_key ^= ((self.constants[r] >> 1) & 0x1) << 7;
            round_key ^= ((self.constants[r] >> 2) & 0x1) << 11;
            round_key ^= ((self.constants[r] >> 3) & 0x1) << 15;
            round_key ^= ((self.constants[r] >> 4) & 0x1) << 19;
            round_key ^= ((self.constants[r] >> 5) & 0x1) << 23;

            keys.push(round_key);

            let t0 = k0;
            let t1 = k1;

            k0 = (t0 >> 32) & 0xffffffffffffffff;
            k0 ^= (t1 << 32) & 0xffffffffffffffff;
            k1 = (t1 >> 32) & 0xffffffffffffffff;;
            k1 ^= ((((t0 & 0xffff) >> 12) ^ ((t0 & 0xffff) << 4)) & 0xffff) << 32;
            k1 ^= ((((t0 & 0xffff0000) >> 2) ^ ((t0 & 0xffff0000) << 14)) & 0xffff0000) << 32;
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

        for round_key in round_keys.iter().take(28) {
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

        for i in 0..28 {
            // Add round key
            output ^= round_keys[27-i];

            // Apply linear layer
            output = self.linear_layer_inv(output);
            
            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.isbox.table[((output >> (4*j)) & 0xf) as usize]) << (4*j);
            }

            output = tmp;
        }

        output
    }

    /** 
    Returns the name of the cipher. 
    */
    fn name(&self) -> String {
        String::from("GIFT64")
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
    
    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("gift64").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(28, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(28, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}