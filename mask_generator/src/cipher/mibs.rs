use cipher::Sbox;
use cipher::Cipher;

/*****************************************************************
                            MIBS
******************************************************************/

/* A structure representing the MIBS cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The MIBS S-box.
 * permutation  The MIBS bit permutation.
 */
#[derive(Clone)]
pub struct Mibs {
    size: usize,
    sbox: Sbox
}

impl Mibs {
    const PERMUTATION : [usize ; 8] = [1, 7, 0, 2, 5, 6, 3, 4];
}

pub fn new() -> Mibs {
    let table = vec![4, 15, 3, 8, 13, 10, 12, 0, 11, 5, 7, 14, 2, 6, 1, 9];
    Mibs{size: 64, sbox: Sbox::new(4, table)}
}

impl Cipher for Mibs {
    /* Returns the size of the input to MIBS. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }

    fn key_size(&self) -> usize {
        panic!("not implemented");
    }

    /* Returns the number of S-boxes in MIBS. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the MIBS S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the bit permutation of MIBS to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut x = input;

        x ^= (x & (0xf << 12)) << 16;
        x ^= (x & (0xf << 8)) << 16;
        x ^= (x & (0xf << 4)) << 16;
        x ^= (x & (0xf << 0)) << 16;
        x ^= (x & (0xf << 28)) >> 24;
        x ^= (x & (0xf << 24)) >> 24;
        x ^= (x & (0xf << 20)) >> 8;
        x ^= (x & (0xf << 16)) >> 8;
        x ^= (x & (0xf << 12)) << 4;
        x ^= (x & (0xf << 8)) << 20;
        x ^= (x & (0xf << 4)) << 20;
        x ^= (x & (0xf << 0)) << 20;
        x ^= (x & (0xf << 28)) >> 16;
        x ^= (x & (0xf << 24)) >> 16;
        x ^= (x & (0xf << 20)) >> 16;
        x ^= (x & (0xf << 16)) >> 16;

        let mut output = 0;

        for i in 0..8 {
            output ^= ((x >> (4*i)) & 0xf) << (Mibs::PERMUTATION[i] * 4);
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
        let output = self.linear_layer(output & 0xffffffff)
                   ^ (self.linear_layer(output >> 32) << 32);
        let mut alpha = 0;

        alpha ^= input << 32;
        alpha ^= output & 0xffffffff;
        alpha ^= input >> 32;

        let mut beta = 0;

        beta ^= input >> 32;
        beta ^= output & 0xffffffff00000000;
        beta ^= input << 32;

        (alpha, beta)
    }

    #[allow(unused_variables)]
    fn linear_layer_inv(&self, input: u64) -> u64 {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        panic!("not implemented");
    }

    /* Returns the string "MIBS". */
    fn name(&self) -> String {
        String::from("MIBS")
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

