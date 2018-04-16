use cipher::Sbox;
use cipher::Cipher;

/*****************************************************************
                            PRESENT
******************************************************************/

/* A structure representing the PRESENT cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The PRESENT S-box.
 * key_size     Size of cipher key in bits. This is (currently) fixed to 80.
 */
#[derive(Clone)]
pub struct Present {
    size     : usize,
    key_size : usize,
    sbox     : Sbox
}

impl Present {
    const PERMUTATION_INV : [[u64 ; 0x100] ; 8] = include!("present.inv.perm");
    const PERMUTATION     : [[u64 ; 0x100] ; 8] = include!("present.perm");
    const SBOX : [u8 ; 16] = [0xc, 0x5, 0x6, 0xb,
                              0x9, 0x0, 0xa, 0xd,
                              0x3, 0xe, 0xf, 0x8,
                              0x4, 0x7, 0x1, 0x2];
}

pub fn new() -> Present {
    let table: Vec<_> = From::from(&Present::SBOX[0..]);
    Present{size: 64, key_size: 80, sbox: Sbox::new(4, table)}
}

impl Cipher for Present {

    /* Returns the size of the input to PRESENT. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }

    fn key_size(&self) -> usize {
        return self.key_size;
    }

    /* Returns the number of S-boxes in PRESENT. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the PRESENT S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the bit permutation of PRESENT to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;
        for i in 0..8 {
            output ^= Present::PERMUTATION[i][((input >> (i*8)) & 0xff) as usize];
        }
        output
    }

    fn linear_layer_inv(&self, input: u64) -> u64 {
        let mut output = 0;
        for i in 0..8 {
            output ^= Present::PERMUTATION_INV[i][((input >> (i*8)) & 0xff) as usize];
        }
        output
    }

    /* Transforms the input and output mask of the S-box layer to an
     * input and output mask of a round.
     *
     * input    Input mask to the S-box layer.
     * output   Output mask to the S-box layer.
     */
    fn sbox_mask_transform(& self, input: u64, output: u64) -> (u64, u64) {
        (input, self.linear_layer(output))
    }

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

            let rnd = (r & 0b11111) as u64;
            s0 ^= rnd >> 1;
            s1 ^= (rnd & 1) << 15;
        }

        keys
    }

    /* Returns the string "PRESENT". */
    fn name(&self) -> String {
        String::from("PRESENT")
    }

    /* Function that defines how values of input mask, output mask, and bias 
     * are categorised for an LatMap. 
     *
     * alpha    Input mask.
     * beta     Output mask.
     * bias     Absolute counter bias.
     */
    fn lat_diversify(&self, _alpha: u64, _beta: u64, bias: i16) -> (i16, u16) {
        (bias, 0)
    }
}
