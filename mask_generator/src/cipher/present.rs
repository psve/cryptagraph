use cipher::{Sbox, CipherStructure, Cipher};
use property::PropertyType;

/*****************************************************************
                            PRESENT
******************************************************************/

/**
A structure representing the PRESENT cipher.

size        Size of the cipher in bits. This is fixed to 64.
key_size    Size of cipher key in bits. This is fixed to 80.
sbox        The PRESENT S-box.
isbox       The inverse PRESENT S-box.
 */
#[derive(Clone)]
pub struct Present {
    size     : usize,
    key_size : usize,
    sbox     : Sbox,
    isbox    : Sbox,
}

impl Present {
    const PERMUTATION_INV : [[u64 ; 0x100] ; 8] = include!("present.inv.perm");
    const PERMUTATION     : [[u64 ; 0x100] ; 8] = include!("present.perm");
    const SBOX : [u8 ; 16] = [0xc, 0x5, 0x6, 0xb,
                              0x9, 0x0, 0xa, 0xd,
                              0x3, 0xe, 0xf, 0x8,
                              0x4, 0x7, 0x1, 0x2];
    const ISBOX : [u8 ; 16] = [0x5, 0xe, 0xf, 0x8,
                               0xc, 0x1, 0x2, 0xd,
                               0xb, 0x4, 0x6, 0x3,
                               0x0, 0x7, 0x9, 0xa];
}

pub fn new() -> Present {
    let table: Vec<_> = From::from(&Present::SBOX[0..]);
    let itable: Vec<_> = From::from(&Present::ISBOX[0..]);
    Present{size: 64,
            key_size: 80,
            sbox: Sbox::new(4, table),
            isbox: Sbox::new(4, itable)}
}

impl Cipher for Present {
    /**
    Returns the design type of the cipher.
    */
    fn structure(&self) -> CipherStructure {
        CipherStructure::Spn
    }

    fn whitening(&self) -> bool { false }

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
    Returns the S-box of the cipher.
    */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /**
    Applies the linear layer of the cipher.

    input   The input to the linear layer.
    */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;
        output ^= Present::PERMUTATION[0][((input >>  0) & 0xff) as usize];
        output ^= Present::PERMUTATION[1][((input >>  8) & 0xff) as usize];
        output ^= Present::PERMUTATION[2][((input >> 16) & 0xff) as usize];
        output ^= Present::PERMUTATION[3][((input >> 24) & 0xff) as usize];
        output ^= Present::PERMUTATION[4][((input >> 32) & 0xff) as usize];
        output ^= Present::PERMUTATION[5][((input >> 40) & 0xff) as usize];
        output ^= Present::PERMUTATION[6][((input >> 48) & 0xff) as usize];
        output ^= Present::PERMUTATION[7][((input >> 56) & 0xff) as usize];

        output
    }

    /**
    Applies the inverse linear layer of the cipher.

    input   The input to the inverse linear layer.
    */
    fn linear_layer_inv(&self, input: u64) -> u64 {
        let mut output = 0;
        output ^= Present::PERMUTATION_INV[0][((input >>  0) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[1][((input >>  8) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[2][((input >> 16) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[3][((input >> 24) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[4][((input >> 32) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[5][((input >> 40) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[6][((input >> 48) & 0xff) as usize];
        output ^= Present::PERMUTATION_INV[7][((input >> 56) & 0xff) as usize];

        output
    }

    /**
    Applies the reflection layer for Prince like ciphers.
    For all other cipher types, this can remain unimplemented.

    input   The input to the reflection layer.
    */
    #[allow(unused_variables)]
    fn reflection_layer(&self, input: u64) -> u64 {
        panic!("Not implemented for this type of cipher")
    }

    /**
    Computes a vector of round key from a cipher key.

    rounds      Number of rounds to generate keys for.
    key         The master key to expand.
    */
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        if key.len() * 8 != self.key_size {
            panic!("invalid key-length");
        }

        let mut keys = vec![];
        let mut s0 : u64 = 0;
        let mut s1 : u64 = 0;

        // load key into 80-bit state (s0 || s1)
        for i in 0..8 {
            s0 <<= 8;
            s0 |= key[i] as u64;
        }

        s1 |= key[8] as u64;
        s1 <<= 8;
        s1 |= key[9] as u64;

        for r in 0..rounds {
            // extract round key
            keys.push(s0);

            // rotate 61-bits left
            assert!(s1 >> 16 == 0);

            {
                let mut t0 : u64 = 0;
                t0 |= s0 << 61;
                t0 |= s1 << (64 - (3 + 16));
                t0 |= s0 >> 19;

                s1 = (s0 >> 3) & 0xffff;
                s0 = t0;
            }

            // apply sbox to 4 MSBs
            {
                let x = s0 >> 60;
                let y = Present::SBOX[x as usize] as u64;
                s0 &= 0x0fffffffffffffff;
                s0 |= y << 60;
            }

            // add round constant
            let rnd = ((r+1) & 0b11111) as u64;
            s0 ^= rnd >> 1;
            s1 ^= (rnd & 1) << 15;
        }

        keys
    }

    /**
    Performs encryption with the cipher.

    input       Plaintext to be encrypted.
    round_keys  Round keys generated by the key-schedule.
    */
    fn encrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        output ^= round_keys[0];

        for i in 1..32 {
            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.sbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
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
    fn decrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64 {
        let mut output = input;

        output ^= round_keys[31];

        for i in 1..32 {
            // Apply linear layer
            output = self.linear_layer_inv(output);

            // Apply S-box
            let mut tmp = 0;

            for j in 0..16 {
                tmp ^= (self.isbox.table[((output >> (4*j)) & 0xf) as usize] as u64) << (4*j);
            }

            // Add round key
            output = tmp ^ round_keys[31-i]
        }

        output
    }

    /**
    Returns the name of the cipher.
    */
    fn name(&self) -> String {
        String::from("PRESENT")
    }

    /**
    Transforms the input and output mask of the S-box layer to an
    input and output mask of a round.

    input    Input mask to the S-box layer.
    output   Output mask to the S-box layer.
    */
    #[allow(unused_variables)]
    fn sbox_mask_transform(&self,
                           input: u64,
                           output: u64,
                           property_type: PropertyType)
                           -> (u64, u64) {
        (input, self.linear_layer(output))
    }
}


#[cfg(test)]
mod tests {
    use cipher;

    #[test]
    fn encryption_test() {
        let cipher = cipher::name_to_cipher("present").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x5579c1387b228445;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x3333dcd3213210d2;

        assert_eq!(ciphertext, cipher.encrypt(plaintext, &round_keys));
    }

    #[test]
    fn decryption_test() {
        let cipher = cipher::name_to_cipher("present").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0000000000000000;
        let ciphertext = 0x5579c1387b228445;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0xffffffffffffffff;
        let ciphertext = 0x3333dcd3213210d2;

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }

    #[test]
    fn encryption_decryption_test() {
        let cipher = cipher::name_to_cipher("present").unwrap();
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));

        let key = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let round_keys = cipher.key_schedule(32, &key);
        let plaintext = 0x0123456789abcdef;
        let ciphertext = cipher.encrypt(plaintext, &round_keys);

        assert_eq!(plaintext, cipher.decrypt(ciphertext, &round_keys));
    }
}
