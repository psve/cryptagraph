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
    isbox: Sbox,
    constants: [u128; 12],
    shift_rows_table: [usize; 16],
    ishift_rows_table: [usize; 16],
    m0: [u128; 16],
    m1: [u128; 16],
}

pub fn new() -> Prince {
    let table = vec![0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4];
    let itable = vec![0xb, 0x7, 0x3, 0x2, 0xf, 0xd, 0x8, 0x9, 0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1];
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
    let shift_rows_table = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];
    let ishift_rows_table = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
    let m0 = [0x0111,0x2220,0x4404,0x8088,0x1011,0x0222,0x4440,0x8808,0x1101,0x2022,0x0444,0x8880,0x1110,0x2202,0x4044,0x0888];
    let m1 = [0x1110,0x2202,0x4044,0x0888,0x0111,0x2220,0x4404,0x8088,0x1011,0x0222,0x4440,0x8808,0x1101,0x2022,0x0444,0x8880];

    Prince {
        size: 64,
        key_size: 128,
        sbox: Sbox::new(4, table),
        isbox: Sbox::new(4, itable),
        constants,
        shift_rows_table,
        ishift_rows_table,
        m0,
        m1
    }
}

impl Prince {
    fn gf2_mat_mult16(x: u128, m: [u128; 16]) -> u128 {
        let mut out = 0;

        for (i, a) in m.iter().enumerate() {
            if (x >> i) & 0x1 == 1 {
                out ^= a;
            }
        }

        out
    }

    fn m_prime(&self, x: u128) -> u128 {
        let chunk0 = Prince::gf2_mat_mult16(x      , self.m0);
        let chunk1 = Prince::gf2_mat_mult16(x >> 16, self.m1);
        let chunk2 = Prince::gf2_mat_mult16(x >> 32, self.m1);
        let chunk3 = Prince::gf2_mat_mult16(x >> 48, self.m0);
        
          (chunk3 << 48) 
        | (chunk2 << 32) 
        | (chunk1 << 16) 
        | chunk0
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
        // Apply MixColumns
        let output = self.m_prime(input);
       
        // Apply ShiftRows
        let mut tmp = 0;        
        for i in 0..16 {
            tmp ^= ((output >> ((15-i)*4)) & 0xf) << ((15-self.shift_rows_table[i])*4);
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
            tmp ^= ((input >> ((15-i)*4)) & 0xf) << ((15-self.ishift_rows_table[i])*4);
        }

        // Apply MixColumns
        self.m_prime(tmp)
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
        let output = self.m_prime(output);

        self.linear_layer(output)
    }

    /** 
    Computes a vector of round key from a cipher key.

    rounds      Number of rounds to generate keys for.
    key         The master key to expand.
    */
    #[allow(unused_variables)]
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u128> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut k0 = 0;
        let mut k1 = 0;

        for i in 0..8 {
            k1 <<= 8;
            k1 |= u128::from(key[i]);
            k0 <<= 8;
            k0 |= u128::from(key[i+8]);
        }

        let mut keys = vec![k1; rounds+2];

        keys[0] ^= k0;
        keys[rounds+1] ^= ((k0 >> 1) & 0xffffffffffffffff) ^ ((k0 & 1) << 63) ^ ((k0 >> 63) & 1);

        keys
    }

    /** 
    Performs encryption with the cipher. 
    
    input       Plaintext to be encrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut output = input;

        // Forward rounds
        output ^= round_keys[0];
        output ^= self.constants[0];

        for i in 0..5 {
            // S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.sbox.table[((output >> (j*4)) & 0xf) as usize]) << (j*4);
            }

            // Linear layer
            output = self.linear_layer(tmp);

            // Round key and constant
            output ^= round_keys[i+1];
            output ^= self.constants[i+1];
        }


        // S-box
        let mut tmp = 0;

        for j in 0..16 {
            tmp ^= u128::from(self.sbox.table[((output >> (j*4)) & 0xf) as usize]) << (j*4);
        }

        // Reflection 
        output = self.m_prime(tmp);

        // Inverse S-box
        tmp = 0;

        for j in 0..16 {
            tmp ^= u128::from(self.isbox.table[((output >> (j*4)) & 0xf) as usize]) << (j*4);
        }

        for i in 0..5 {
            // Round key and constant
            output = tmp ^ round_keys[i+6];
            output ^= self.constants[i+6];

            // Inverse linear layer
            output = self.linear_layer_inv(output);

            // Inverse S-box
            tmp = 0;

            for j in 0..16 {
                tmp ^= u128::from(self.isbox.table[((output >> (j*4)) & 0xf) as usize]) << (j*4);
            }
        }

        // Round key and constant
        output = tmp ^ round_keys[11];
        output ^= self.constants[11];

        output
    }

    /** 
    Performs decryption with the cipher. 
    
    input       Ciphertext to be decrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    #[allow(unused_variables)]
    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128 {
        let mut round_keys = round_keys.to_vec();
        round_keys.swap(0, 11);

        for x in &mut round_keys {
            *x ^= 0xc0ac29b7c97c50dd;
        }

        self.encrypt(input, &round_keys)
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

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("prince").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x818665aa0d02dfda;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = 0xae25ad3ca8fa9ccf;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("prince").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x818665aa0d02dfda;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = 0xae25ad3ca8fa9ccf;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("prince").unwrap();
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                   0x08, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                   0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let round_keys = cipher.key_schedule(10, &key);
        let plaintext = 0x010a0b0c0d0e0f02;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}