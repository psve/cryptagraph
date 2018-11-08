//! Implementation of QARMA.

use crate::sbox::Sbox;
use crate::cipher::{CipherStructure, Cipher};
use crate::property::PropertyType;

/*****************************************************************
                            QARMA
******************************************************************/

// A structure representing the QARMA cipher. 
#[derive(Clone)]
pub struct Qarma {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    constants: [u128; 8],
    permute_cell_table: [usize; 16],
    ipermute_cell_table: [usize; 16],

}

impl Qarma {
    /// Create a new instance of the cipher.
    pub fn new() -> Qarma {
        let table = vec![0, 14, 2, 10, 9, 15, 8, 11, 6, 4, 3, 7, 13, 12, 1, 5];
        let constants = [0x0000000000000000,
                         0x13198A2E03707344,
                         0xA4093822299F31D0,
                         0x082EFA98EC4E6C89,
                         0x452821E638D01377,
                         0xBE5466CF34E90C6C,
                         0x3F84D5B5B5470917,
                         0x9216D5D98979FB1B];
        let permute_cell_table = [0, 5, 15, 10, 13, 8, 2, 7, 11, 14, 4, 1, 6, 3, 9, 12];
        let ipermute_cell_table = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2];

        Qarma {
            size: 64,
            key_size: 128,
            sbox: Sbox::new(4, 4, table),
            constants,
            permute_cell_table,
            ipermute_cell_table 
        }
    }
}

impl Qarma {
    fn mix_columns(&self, x: u128) -> u128 {
        let mut output = 0;
        output ^= ((((x << 1) & 0xeeee0000)         | ((x >> 3) & 0x11110000)) >> 16)
                ^ ((((x << 2) & 0xcccc00000000)     | ((x >> 2) & 0x333300000000)) >> 32)
                ^ ((((x << 1) & 0xeeee000000000000) | ((x >> 3) & 0x1111000000000000)) >> 48);

        output ^= ((((x << 1) & 0xeeee)             | ((x >> 3) & 0x1111)) << 16)
                ^ ((((x << 1) & 0xeeee00000000)     | ((x >> 3) & 0x111100000000)) >> 16)
                ^ ((((x << 2) & 0xcccc000000000000) | ((x >> 2) & 0x3333000000000000)) >> 32);

        output ^= ((((x << 2) & 0xcccc)             | ((x >> 2) & 0x3333)) << 32)
                ^ ((((x << 1) & 0xeeee0000)         | ((x >> 3) & 0x11110000)) << 16)
                ^ ((((x << 1) & 0xeeee000000000000) | ((x >> 3) & 0x1111000000000000)) >> 16);

        output ^= ((((x << 1) & 0xeeee)             | ((x >> 3) & 0x1111)) << 48)
                ^ ((((x << 2) & 0xcccc0000)         | ((x >> 2) & 0x33330000)) << 32)
                ^ ((((x << 1) & 0xeeee00000000)     | ((x >> 3) & 0x111100000000)) << 16);

        output
    }
}

impl Cipher for Qarma {
    fn structure(&self) -> CipherStructure {
        CipherStructure::Prince
    }

    fn size(&self) -> usize {
        self.size
    }

    fn key_size(&self) -> usize {
        self.key_size
    }

    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size_in()
    }

    fn sbox(&self, _i: usize) -> &Sbox {
        &self.sbox
    }

    fn linear_layer(&self, input: u128) -> u128 {
        let mut output = 0;

        // Apply PermuteCells
        for i in 0..16 {
            output ^= ((input >> (i*4)) & 0xf) << (self.permute_cell_table[i]*4);
        }

        // Apply MixColumns
        output = self.mix_columns(output);

        output
    }

    fn linear_layer_inv(&self, input: u128) -> u128 {
        // Apply MixColumns
        let output = self.mix_columns(input);

        // Apply inverse PermuteCells
        let mut tmp = 0;
        for i in 0..16 {
            tmp ^= ((output >> (i*4)) & 0xf) << (self.ipermute_cell_table[i]*4);
        }

        tmp
    }

    fn reflection_layer(&self, input: u128) -> u128 {
        // Note that this reflection layer is not as defined in 
        // the specification. It is specified such that if the S-box
        // application before and after reflection is replaced by a full
        // round, this reflection layer ensures equivalent functionality. 
        let mut output = self.mix_columns(input);
        output = self.mix_columns(output);
        output = self.mix_columns(output);

        output
    }

    #[allow(unused_variables)]
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u128> {
        panic!("Not implemented")
    }

    #[allow(unused_variables)]
    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        panic!("Not implemented")
    }

    #[allow(unused_variables)]
    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        panic!("Not implemented")
    }

    fn name(&self) -> String {
        String::from("QARMA")
    }

    fn sbox_mask_transform(&self, 
                           input: u128, 
                           output: u128, 
                           _property_type: PropertyType) 
                           -> (u128, u128) {
        (input, self.linear_layer(output))
    }

    #[inline(always)]
    fn whitening(&self) -> bool {
        true
    }
}

impl Default for Qarma {
    fn default() -> Self {
        Qarma::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher;

    #[test]
    fn linear() {
        let cipher = cipher::name_to_cipher("qarma").unwrap();
        let x = 0x0123456789abcedf;
        assert_eq!(x, cipher.linear_layer(cipher.linear_layer_inv(x)));
    }

    #[test]
    fn reflection() {
        let cipher = cipher::name_to_cipher("qarma").unwrap();
        let x = 0x0123456789abcedf;

        assert_eq!(x, cipher.reflection_layer(cipher.reflection_layer(x)));
    }
}