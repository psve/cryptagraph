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
    permute_cell_table: [usize; 16],
    ipermute_cell_table: [usize; 16],

}

pub fn new() -> Mantis {
    let table = vec![0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6];
    let constants = [0x13198a2e03707344,
                     0xa4093822299f31d0,
                     0x082efa98ec4e6c89,
                     0x452821e638d01377,
                     0xbe5466cf34e90c6c,
                     0xc0ac29b7c97c50dd,
                     0x3f84d5b5b5470917,
                     0x9216d5d98979fb1b];
    let permute_cell_table = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12];
    let ipermute_cell_table = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2];

    Mantis {
        size: 64,
        key_size: 128,
        sbox: Sbox::new(4, table),
        constants: constants,
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
    Returns the S-box of the cipher. 
    */
    fn sbox(&self) -> &Sbox {
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

        // Apply MixColumns
        let x = output;
        output  = (x & 0x00f000f000f000f0) >> 4
                ^ (x & 0x0f000f000f000f00) >> 8
                ^ (x & 0xf000f000f000f000) >> 12;

        output ^= (x & 0x000f000f000f000f) << 4
                ^ (x & 0x0f000f000f000f00) >> 4
                ^ (x & 0xf000f000f000f000) >> 8;

        output ^= (x & 0x000f000f000f000f) << 8
                ^ (x & 0x00f000f000f000f0) << 4
                ^ (x & 0xf000f000f000f000) >> 4;

        output ^= (x & 0x000f000f000f000f) << 12
                ^ (x & 0x00f000f000f000f0) << 8
                ^ (x & 0x0f000f000f000f00) << 4;

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
        output  = (x & 0x00f000f000f000f0) >> 4
                ^ (x & 0x0f000f000f000f00) >> 8
                ^ (x & 0xf000f000f000f000) >> 12;

        output ^= (x & 0x000f000f000f000f) << 4
                ^ (x & 0x0f000f000f000f00) >> 4
                ^ (x & 0xf000f000f000f000) >> 8;

        output ^= (x & 0x000f000f000f000f) << 8
                ^ (x & 0x00f000f000f000f0) << 4
                ^ (x & 0xf000f000f000f000) >> 4;

        output ^= (x & 0x000f000f000f000f) << 12
                ^ (x & 0x00f000f000f000f0) << 8
                ^ (x & 0x0f000f000f000f00) << 4;

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
        output  = (x & 0x00f000f000f000f0) >> 4
                ^ (x & 0x0f000f000f000f00) >> 8
                ^ (x & 0xf000f000f000f000) >> 12;

        output ^= (x & 0x000f000f000f000f) << 4
                ^ (x & 0x0f000f000f000f00) >> 4
                ^ (x & 0xf000f000f000f000) >> 8;

        output ^= (x & 0x000f000f000f000f) << 8
                ^ (x & 0x00f000f000f000f0) << 4
                ^ (x & 0xf000f000f000f000) >> 4;

        output ^= (x & 0x000f000f000f000f) << 12
                ^ (x & 0x00f000f000f000f0) << 8
                ^ (x & 0x0f000f000f000f00) << 4;

        output = self.linear_layer(output);

        output
    }

    /** 
    Computes a vector of round key from a cipher key.

    rounds      Number of rounds to generate keys for.
    key         The master key to expand.
    */
    #[allow(unused_variables)]
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u128> {
        panic!("Not implemented")
    }

    /** 
    Performs encryption with the cipher. 
    
    input       Plaintext to be encrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    #[allow(unused_variables)]
    fn encrypt(&self, input: u128, round_keys: &Vec<u128>) -> u128 {
        panic!("Not implemented")
    }

    /** 
    Performs decryption with the cipher. 
    
    input       Ciphertext to be decrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    #[allow(unused_variables)]
    fn decrypt(&self, input: u128, round_keys: &Vec<u128>) -> u128 {
        panic!("Not implemented")
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
}