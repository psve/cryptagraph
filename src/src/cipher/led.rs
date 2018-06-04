use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            LED
******************************************************************/

/** 
A structure representing the LED cipher.

size                Size of the cipher in bits. This is fixed to 64.
key_size            Size of cipher key in bits. This is fixed to 64.
sbox                The LED S-box.
isbox               The inverse LED S-box.
shift_rows_table    Table for LED ShiftRows.
ishift_rows_table   Table for inverse LED ShiftRows.
constants           Round constants.
*/
#[derive(Clone)]
pub struct Led {
    size: usize,
    key_size: usize,
    sbox: Sbox,
    isbox: Sbox,
    shift_rows_table: [usize; 16],
    ishift_rows_table: [usize; 16],
    constants: [u128; 48]
}

pub fn new() -> Led {
    let table = vec![0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2];
    let itable = vec![0x5, 0xe, 0xf, 0x8, 0xc, 0x1, 0x2, 0xd, 0xb, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xa];
    let shift_rows_table = [0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12];
    let ishift_rows_table = [0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14];
    let constants = [0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3b,0x37,0x2f,0x1e,0x3c,0x39,0x33,0x27,
                     0x0e,0x1d,0x3a,0x35,0x2b,0x16,0x2c,0x18,0x30,0x21,0x02,0x05,0x0b,0x17,0x2e,
                     0x1c,0x38,0x31,0x23,0x06,0x0d,0x1b,0x36,0x2d,0x1a,0x34,0x29,0x12,0x24,0x08,
                     0x11,0x22,0x04];
    Led{size: 64,
        key_size: 64,
        sbox: Sbox::new(4, table), 
        isbox: Sbox::new(4, itable), 
        shift_rows_table: shift_rows_table,
        ishift_rows_table: ishift_rows_table,
        constants: constants }
}

/**
Performs multiplication by two in the LED field
*/
fn led_times2(x: u128) -> u128 {
    ((x & 0x7777) << 1) ^ ((x & 0x8888) >> 3) ^ ((x & 0x8888) >> 2)
}

impl Cipher for Led {
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
        let mut x = 0;

        // Apply ShiftRows
        for i in 0..16 {
            x ^= ((input >> (i*4)) & 0xf) << (self.shift_rows_table[i]*4);
        }

        // Apply MixColumnsSerial
        let mut y;

        for _ in 0..4 {
            y = x >> 16;
            // Times 4
            y ^= led_times2(led_times2(x & 0xffff)) << 48;
            // Times 1
            y ^= (x & 0xffff0000) << 32;
            // Times 2
            y ^= led_times2((x & 0xffff00000000) >> 32) << 48;
            // Times 2
            y ^= led_times2((x & 0xffff000000000000) >> 48) << 48;
            x = y;
        }

        x
    }

    /** 
    Applies the inverse linear layer of the cipher.
    
    input   The input to the inverse linear layer. 
    */
    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut x = input;

        // Apply inverse MixColumnsSerial
        let mut y;

        for _ in 0..4 {
            y = x << 16;
            // Times 13             
            y ^= led_times2(led_times2(led_times2(x & 0xffff)));
            y ^= led_times2(led_times2(x & 0xffff));
            y ^= x & 0xffff;
            // Times 9
            y ^= led_times2(led_times2(led_times2((x & 0xffff0000) >> 16)));
            y ^= (x & 0xffff0000) >> 16;
            // Times 9
            y ^= led_times2(led_times2(led_times2((x & 0xffff00000000) >> 32)));
            y ^= (x & 0xffff00000000) >> 32;
            // Times 13             
            y ^= led_times2(led_times2(led_times2((x & 0xffff000000000000) >> 48)));
            y ^= led_times2(led_times2((x & 0xffff000000000000) >> 48));
            y ^= (x & 0xffff000000000000) >> 48;
            x = y;
        }

        // Apply inverse ShiftRows
        let mut y = 0;

        for i in 0..16 {
            y ^= ((x >> (i*4)) & 0xf) << (self.ishift_rows_table[i]*4);
        }

        y
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

        let mut k = 0;

        // Load key into 64-bit state 
        for i in 0..8 {
            k <<= 8;
            k |= key[i] as u128;
        }

        // All keys are identical
        vec![k; rounds+1]
    }

    /** 
    Performs encryption with the cipher. 
    
    input       Plaintext to be encrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn encrypt(&self, input: u128, round_keys: &Vec<u128>) -> u128 {
        let mut output = input;

        output ^= round_keys[0];

        for s in 0..8 {
            for i in 0..4 {
                // Add constant
                let mut constant = 0x0003000200050004;
                constant ^= (self.constants[4*s+i] >> 3) << 4;
                constant ^= (self.constants[4*s+i] & 0b111) << (4+16);
                constant ^= (self.constants[4*s+i] >> 3) << (4+32);
                constant ^= (self.constants[4*s+i] & 0b111) << (4+48);
                
                output ^= constant;

                // SubCells
                let mut tmp = 0;

                for j in 0..16 {
                    tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u128) << (4*j);
                }

                // ShiftRows + MixColumns
                output = self.linear_layer(tmp);
            }

            output ^= round_keys[s+1];
        }

        output
    }

    /** 
    Performs decryption with the cipher. 
    
    input       Ciphertext to be decrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn decrypt(&self, input: u128, round_keys: &Vec<u128>) -> u128 {
        let mut output = input;

        output ^= round_keys[8];

        for s in 0..8 {
            for i in 0..4 {
                // InvShiftRows + InvMixColumns
                output = self.linear_layer_inv(output);
                
                // SubCells
                let mut tmp = 0;

                for j in 0..16 {
                    tmp ^= (self.isbox.table[((output >> (4*j)) & 0xf) as usize] as u128) << (4*j);
                }

                // Add constant
                let mut constant = 0x0003000200050004;
                constant ^= (self.constants[31-(4*s+i)] >> 3) << 4;
                constant ^= (self.constants[31-(4*s+i)] & 0b111) << (4+16);
                constant ^= (self.constants[31-(4*s+i)] >> 3) << (4+32);
                constant ^= (self.constants[31-(4*s+i)] & 0b111) << (4+48);
                
                output = tmp ^ constant;
            }

            output ^= round_keys[7-s];
        }

        output
    }

    /** 
    Returns the name of the cipher. 
    */
    fn name(&self) -> String {
        String::from("LED")
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
}

#[cfg(test)]
mod tests {
    use cipher;
    
    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("led").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(8, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x897c0a3001042c93;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let round_keys = cipher.key_schedule(8, &key);
        let plaintext = 0xfedcba9876543210;
        let ciphertext = 0x85cf3983e155300a;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("led").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(8, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x897c0a3001042c93;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let round_keys = cipher.key_schedule(8, &key);
        let plaintext = 0xfedcba9876543210;
        let ciphertext = 0x85cf3983e155300a;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("led").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(8, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(8, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}