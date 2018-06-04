use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            PRINCE
******************************************************************/

/** 
A structure representing the PRINCE cipher.

size                Size of the cipher in bits. This is fixed to 64.
key_size            Size of the cipher key in bits. This is fixed to 128.
sbox                The PRINCE S-box.
shift_rows_table    Permutation used for ShiftRows.
shift_rows_table  Table for PermuteCells.
ishift_rows_table Table for inverse PermuteCells.
constants           Round constants. 
*/
#[derive(Clone)]
pub struct Prince {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    constants: [u128; 12],
    shift_rows_table: [usize; 16],
    ishift_rows_table: [usize; 16],
    m0: [u128; 16],
    m1: [u128; 16],
}

pub fn new() -> Prince {
    let table = vec![0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4];
    let constants = [0x0000000000000000,
                     0x13198a2e03707344,
                     0xa4093822299f31d0,
                     0x082efa98ec4e6c89,
                     0x452821e638d01377,
                     0xbe5466cf34e90c6c,
                     0x7ef84f78fd955cb1,
                     0x85840851f1ac43aa,
                     0xc882d32f25323c54,
                     0x64a51195e0e3610d,
                     0xd3b5a399ca0c2399,
                     0xc0ac29b7c97c50dd];
    let shift_rows_table = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
    let ishift_rows_table = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];
    let m0 = [0x0111,0x2220,0x4404,0x8088,0x1011,0x0222,0x4440,0x8808,0x1101,0x2022,0x0444,0x8880,0x1110,0x2202,0x4044,0x0888];
    let m1 = [0x1110,0x2202,0x4044,0x0888,0x0111,0x2220,0x4404,0x8088,0x1011,0x0222,0x4440,0x8808,0x1101,0x2022,0x0444,0x8880];

    Prince {
        size: 64,
        key_size: 128,
        sbox: Sbox::new(4, table),
        constants: constants,
        shift_rows_table: shift_rows_table,
        ishift_rows_table: ishift_rows_table,
        m0: m0,
        m1: m1
    }
}

impl Prince {
    fn gf2_mat_mult16(x: u128, m: [u128; 16]) -> u128 {
        let mut out = 0;

        for i in 0..16 {
            if (x >> i) & 0x1 == 1 {
                out ^= m[i];
            }
        }

        out
    }

    fn m_prime(&self, x: u128) -> u128 {
        let chunk0 = Prince::gf2_mat_mult16(x >> (0*16), self.m0);
        let chunk1 = Prince::gf2_mat_mult16(x >> (1*16), self.m1);
        let chunk2 = Prince::gf2_mat_mult16(x >> (2*16), self.m1);
        let chunk3 = Prince::gf2_mat_mult16(x >> (3*16), self.m0);
        
        let out = (chunk3 << (3*16)) 
                | (chunk2 << (2*16)) 
                | (chunk1 << (1*16)) 
                | (chunk0 << (0*16));
        out
    }
}

impl Cipher for Prince {
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
        // Apply MixColumns
        let output = self.m_prime(input);
       
        // Apply ShiftRows
        let mut tmp = 0;        
        for i in 0..16 {
            tmp ^= ((output >> (i*4)) & 0xf) << (self.shift_rows_table[i]*4);
        }

        tmp
    }

    /** 
    Applies the inverse linear layer of the cipher.
    
    input   The input to the inverse linear layer. 
    */
    fn linear_layer_inv(&self, input: u128) -> u128 {
        // Apply inverse ShiftRows
        let mut tmp = 0;        
        for i in 0..16 {
            tmp ^= ((input >> (i*4)) & 0xf) << (self.ishift_rows_table[i]*4);
        }

        // Apply MixColumns
        let output = self.m_prime(tmp);
       
        output
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
        let output = self.linear_layer_inv(input);

        // Apply MixColumns
        let mut output = self.m_prime(output);

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
        String::from("PRINCE")
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
        let cipher = cipher::name_to_cipher("prince").unwrap();
        let x = 0x0123456789abcedf;
        assert_eq!(x, cipher.linear_layer(cipher.linear_layer_inv(x)));
    }

    #[test]
    fn reflection() {
        let cipher = cipher::name_to_cipher("prince").unwrap();
        let x = 0x0123456789abcedf;

        assert_eq!(x, cipher.reflection_layer(cipher.reflection_layer(x)));
    }
}