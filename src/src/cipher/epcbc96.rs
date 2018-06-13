use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            EPCBC96
******************************************************************/

/**
A structure representing the EPCBC96 cipher.

size        Size of the cipher in bits. This is fixed to 64.
key_size    Size of cipher key in bits. This is fixed to 80.
sbox        The EPCBC96 S-box.
isbox       The inverse EPCBC96 S-box.
 */
#[derive(Clone)]
pub struct Epcbc96 {
    size     : usize,
    key_size : usize,
    sbox     : Sbox,
    isbox    : Sbox,
}

impl Epcbc96 {
    const SBOX : [u8 ; 16] = [0xc, 0x5, 0x6, 0xb,
                              0x9, 0x0, 0xa, 0xd,
                              0x3, 0xe, 0xf, 0x8,
                              0x4, 0x7, 0x1, 0x2];
    const ISBOX : [u8 ; 16] = [0x5, 0xe, 0xf, 0x8,
                               0xc, 0x1, 0x2, 0xd,
                               0xb, 0x4, 0x6, 0x3,
                               0x0, 0x7, 0x9, 0xa];
}

pub fn new() -> Epcbc96 {
    let table: Vec<_> = From::from(&Epcbc96::SBOX[0..]);
    let itable: Vec<_> = From::from(&Epcbc96::ISBOX[0..]);
    Epcbc96{size: 96,
            key_size: 96,
            sbox: Sbox::new(4, table),
            isbox: Sbox::new(4, itable)}
}

impl Cipher for Epcbc96 {
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
        return self.key_size;
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
        
        for i in 0..self.size-1 {
            output ^= ((input >> i) & 0x1) << ((i*self.size/4) % (self.size-1));
        }
        output ^= ((input >> (self.size-1)) & 0x1) << (self.size-1);

        output
    }

    /**
    Applies the inverse linear layer of the cipher.

    input   The input to the inverse linear layer.
    */
    fn linear_layer_inv(&self, input: u128) -> u128 {
        let mut output = 0;
        
        for i in 0..self.size-1 {
            output ^= ((input >> ((i*self.size/4) % (self.size-1))) & 0x1) << i;
        }
        output ^= ((input >> (self.size-1)) & 0x1) << (self.size-1);

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
        let mut k = 0;

        // load key into 80-bit state (s0 || s1)
        for i in 0..12 {
            k <<= 8;
            k |= key[i] as u128;
        }

        keys.push(k);

        for i in 0..rounds {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..24 {
                tmp ^= (self.sbox.table[((k >> (4*j)) & 0xf) as usize] as u128) << (4*j);
            }

            // Apply linear layer
            k = self.linear_layer(tmp);

            // Apply round constant
            k ^= i as u128;

            keys.push(k);
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

        output ^= round_keys[0];

        for i in 1..33 {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..24 {
                tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u128) << (4*j);
            }

            // Apply linear layer
            output = self.linear_layer(tmp);

            // Add round key
            output ^= round_keys[i]
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

        output ^= round_keys[32];

        for i in 1..33 {
            // Apply linear layer
            output = self.linear_layer_inv(output);

            // Apply S-box
            let mut tmp = 0;

            for j in 0..24 {
                tmp ^= (self.isbox.table[((output >> (4*j)) & 0xf) as usize] as u128) << (4*j);
            }

            // Add round key
            output = tmp ^ round_keys[32-i]
        }

        output
    }

    /**
    Returns the name of the cipher.
    */
    fn name(&self) -> String {
        String::from("EPCBC96")
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
        let cipher = cipher::name_to_cipher("epcbc96").unwrap();
        let x = 0x0123456789ab;

        assert_eq!(x, cipher.linear_layer_inv(cipher.linear_layer(x)));
    }

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("epcbc96").unwrap();
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0123456789ABCDEF01234567;
        let ciphertext = 0x408C65649781E6A5C9757244;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("epcbc96").unwrap();
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0123456789ABCDEF01234567;
        let ciphertext = 0x408C65649781E6A5C9757244;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("epcbc96").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x000000000000;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xff;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}
