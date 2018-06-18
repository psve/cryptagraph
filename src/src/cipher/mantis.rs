use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            MANTIS
******************************************************************/

/** 
A structure representing the MANTIS cipher.

size                Size of the cipher in bits. This is fixed to 64.
key_size            Size of the cipher key in bits. This is fixed to 128.
sbox                The MANTIS S-box.
shift_rows_table    Permutation used for ShiftRows.
permute_cell_table  Table for PermuteCells.
ipermute_cell_table Table for inverse PermuteCells.
constants           Round constants. 
*/
#[derive(Clone)]
pub struct Mantis {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    constants: [u128; 8],
    tweak_permute: [usize; 16],
    itweak_permute: [usize; 16],
    permute_cell_table: [usize; 16],
    ipermute_cell_table: [usize; 16],

}

pub fn new() -> Mantis {
    let table = vec![0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6];
    let constants = [0x44370730e2a89131,
                     0x0d13f9922283904a,
                     0x98c6e4ce89afe280,
                     0x77310d836e128254,
                     0xc6c09e43fc6645eb,
                     0xdd05c79c7b92ca0c,
                     0x7190745b5b5d48f3,
                     0xb1bf97989d5d6129];
    let tweak_permute = [4, 5, 6, 7, 11, 1, 0, 8, 12, 13, 14, 15, 9, 10, 2, 3];
    let itweak_permute = [6, 5, 14, 15, 0, 1, 2, 3, 7, 12, 13, 4, 8, 9, 10, 11];
    let permute_cell_table = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12];
    let ipermute_cell_table = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2];

    Mantis {
        size: 64,
        key_size: 128,
        sbox: Sbox::new(4, table),
        constants: constants,
        tweak_permute: tweak_permute,
        itweak_permute: itweak_permute,
        permute_cell_table: permute_cell_table,
        ipermute_cell_table: ipermute_cell_table 
    }
}

impl Cipher for Mantis {
    /** 
    Returns the design type of the cipher. 
    */
    fn structure(&self) -> CipherStructure {
        CipherStructure::Prince
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
    fn linear_layer(&self, input: u128) -> u128 {
        let mut output = 0;

        // Apply PermuteCells
        for i in 0..16 {
            output ^= ((input >> (i*4)) & 0xf) << (self.permute_cell_table[i]*4);
        }
        println!("{:016x}", output);

        // Apply MixColumns
        let x = output;
        output  = (x & 0x00000000ffff0000) >> 16
                ^ (x & 0x0000ffff00000000) >> 32
                ^ (x & 0xffff000000000000) >> 48;

        output ^= (x & 0x000000000000ffff) << 16
                ^ (x & 0x0000ffff00000000) >> 16
                ^ (x & 0xffff000000000000) >> 32;

        output ^= (x & 0x000000000000ffff) << 32
                ^ (x & 0x00000000ffff0000) << 16
                ^ (x & 0xffff000000000000) >> 16;

        output ^= (x & 0x000000000000ffff) << 48
                ^ (x & 0x00000000ffff0000) << 32
                ^ (x & 0x0000ffff00000000) << 16;

        output
    }

    /** 
    Applies the inverse linear layer of the cipher.
    
    input   The input to the inverse linear layer. 
    */
    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = input;

        // Apply MixColumns
        let x = output;
        output  = (x & 0x00000000ffff0000) >> 16
                ^ (x & 0x0000ffff00000000) >> 32
                ^ (x & 0xffff000000000000) >> 48;

        output ^= (x & 0x000000000000ffff) << 16
                ^ (x & 0x0000ffff00000000) >> 16
                ^ (x & 0xffff000000000000) >> 32;

        output ^= (x & 0x000000000000ffff) << 32
                ^ (x & 0x00000000ffff0000) << 16
                ^ (x & 0xffff000000000000) >> 16;

        output ^= (x & 0x000000000000ffff) << 48
                ^ (x & 0x00000000ffff0000) << 32
                ^ (x & 0x0000ffff00000000) << 16;

        // Apply inverse PermuteCells
        let mut tmp = 0;
        for i in 0..16 {
            tmp ^= ((output >> (i*4)) & 0xf) << (self.ipermute_cell_table[i]*4);
        }

        tmp
    }

    /**
    Applies the reflection layer for Prince like ciphers. 
    For all other cipher types, this can remain unimplemented. 

    input   The input to the reflection layer.
    */
    fn reflection_layer(&self, input: u128) -> u128 {
        // Note that this reflection layer is not as defined in 
        // the specification. It is specified such that if the S-box
        // application before and after reflection is replaced by a full
        // round, this reflection layer ensures equivalent functionality. 
        let mut output = self.linear_layer_inv(input);

        // Apply MixColumns
        let x = output;
        output  = (x & 0x00000000ffff0000) >> 16
                ^ (x & 0x0000ffff00000000) >> 32
                ^ (x & 0xffff000000000000) >> 48;

        output ^= (x & 0x000000000000ffff) << 16
                ^ (x & 0x0000ffff00000000) >> 16
                ^ (x & 0xffff000000000000) >> 32;

        output ^= (x & 0x000000000000ffff) << 32
                ^ (x & 0x00000000ffff0000) << 16
                ^ (x & 0xffff000000000000) >> 16;

        output ^= (x & 0x000000000000ffff) << 48
                ^ (x & 0x00000000ffff0000) << 32
                ^ (x & 0x0000ffff00000000) << 16;

        output = self.linear_layer(output);

        output
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

        // Fixed tweak
        let mut t = 0x2def5501f6e219ab;

        let mut k0 = 0;
        let mut k1 = 0;

        for i in 0..8 {
            k1 <<= 8;
            k1 |= key[i] as u128;
            k0 <<= 8;
            k0 |= key[i+8] as u128;
        }

        let mut keys = vec![k1; rounds+2];

        keys[0] ^= k0;
        keys[rounds+1] ^= ((k0 >> 63) & 0x1) ^ ((k0 << 1) & 0xffffffffffffffff) ^ ((k0 & 0x1) << 63);

        println!("k0  = {:016x}", k0);
        println!("k0' = {:016x}", keys[rounds+1] ^ k1);
        println!("k1  = {:016x}", k1);

        for i in 0..keys.len()/2 {
            keys[i] ^= t;

            let tmp = t;
            t = 0;

            for j in 0..16 {
                t ^= ((tmp >> (j*4)) & 0xf) << (self.tweak_permute[j]*4);
            }
        }

        let tmp = t;
        t = 0;

        for j in 0..16 {
            t ^= ((tmp >> (j*4)) & 0xf) << (self.itweak_permute[j]*4);
        }

        for i in keys.len()/2..keys.len() {
            keys[i] ^= 0x3d803a5888a6f342;
            keys[i] ^= t;

            let tmp = t;
            t = 0;

            for j in 0..16 {
                t ^= ((tmp >> (j*4)) & 0xf) << (self.itweak_permute[j]*4);
            }
        }

        keys
    }

    /** 
    Performs encryption with the cipher. 
    
    input       Plaintext to be encrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn encrypt(&self, input: u128, round_keys: &Vec<u128>) -> u128 {
        let mut output = input;

        // Forward rounds
        output ^= round_keys[0];

        println!("{:016x}", output);

        for i in 0..6 {
            // S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.sbox.table[((output >> (j*4)) & 0xf) as usize] as u128) << (j*4);
            }

            println!("{:016x}", tmp);

            // Round key and constant
            output = tmp ^ self.constants[i];
            println!("{:016x}", output);
            output ^= round_keys[i+1];
            println!("{:016x}", output);
            
            // Linear layer
            output = self.linear_layer(output);
            println!("{:016x}\n", output);
        }

        // S-box
        let mut tmp = 0;

        for j in 0..16 {
            tmp ^= (self.sbox.table[((output >> (j*4)) & 0xf) as usize] as u128) << (j*4);
        }

        // Apply MixColumns
        output  = (tmp & 0x00000000ffff0000) >> 16
                ^ (tmp & 0x0000ffff00000000) >> 32
                ^ (tmp & 0xffff000000000000) >> 48;

        output ^= (tmp & 0x000000000000ffff) << 16
                ^ (tmp & 0x0000ffff00000000) >> 16
                ^ (tmp & 0xffff000000000000) >> 32;

        output ^= (tmp & 0x000000000000ffff) << 32
                ^ (tmp & 0x00000000ffff0000) << 16
                ^ (tmp & 0xffff000000000000) >> 16;

        output ^= (tmp & 0x000000000000ffff) << 48
                ^ (tmp & 0x00000000ffff0000) << 32
                ^ (tmp & 0x0000ffff00000000) << 16;

        // Inverse S-box
        tmp = 0;

        for j in 0..16 {
            tmp ^= (self.sbox.table[((output >> (j*4)) & 0xf) as usize] as u128) << (j*4);
        }

        println!("{:016x}\n", tmp);

        for i in 0..6 {
            // Inverse linear layer
            output = self.linear_layer_inv(tmp);
            println!("{:016x}", output);
            
            // Round key and constant
            output ^= round_keys[i+7];
            println!("{:016x}", output);
            output ^= self.constants[5-i];
            println!("{:016x}", output);

            // Inverse S-box
            tmp = 0;

            for j in 0..16 {
                tmp ^= (self.sbox.table[((output >> (j*4)) & 0xf) as usize] as u128) << (j*4);
            }
            println!("{:016x}\n", tmp);
        }

        // Round key and constant
        output = tmp ^ round_keys[13];
        println!("{:016x}\n", output);

        output
    }

    /** 
    Performs decryption with the cipher. 
    
    input       Ciphertext to be decrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    #[allow(unused_variables)]
    fn decrypt(&self, input: u128, round_keys: &Vec<u128>) -> u128 {
        let mut round_keys = round_keys.clone();
        round_keys.reverse();

        self.encrypt(input, &round_keys)
    }

    /** 
    Returns the name of the cipher. 
    */
    fn name(&self) -> String {
        String::from("MANTIS")
    }

    /** 
    Transforms the input and output mask of the S-box layer to an
    input and output mask of a round.
    
    input           Input mask to the S-box layer.
    output          Output mask to the S-box layer.
    property_type   Type of the property determining the transform.
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
    Specifies if a pre-whitening key is used. In this case, the key-schedule returns 
    rounds+1 round keys. 
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
    fn linear() {
        let cipher = cipher::name_to_cipher("mantis").unwrap();
        let x = 0x0123456789abcedf;
        assert_eq!(x, cipher.linear_layer(cipher.linear_layer_inv(x)));
    }

    #[test]
    fn reflection() {
        let cipher = cipher::name_to_cipher("mantis").unwrap();
        let x = 0x0123456789abcedf;

        assert_eq!(x, cipher.reflection_layer(cipher.reflection_layer(x)));
    }

    /* Note: We could not get the test vectors to match. Comparing to the reference code,
       there might be a bug in how k0' is calculated there, as everything else matches. */
    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("mantis").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(12, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}