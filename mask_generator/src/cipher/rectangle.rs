use cipher::Sbox;
use cipher::Cipher;

/*****************************************************************
                            RECTANGLE
******************************************************************/

/* A structure representing the RECTANGLE cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The RECTANGLE S-box.
 * permutation  The RECTANGLE bit permutation.
 */
#[derive(Clone)]
pub struct Rectangle {
    size: usize,
    sbox: Sbox,
}

impl Rectangle {
    const PERMUTATION : [usize ; 64] =  [
         0,  5, 50, 55,  4,  9, 54, 59,
         8, 13, 58, 63, 12, 17, 62,  3,
        16, 21,  2,  7, 20, 25,  6, 11,
        24, 29, 10, 15, 28, 33, 14, 19,
        32, 37, 18, 23, 36, 41, 22, 27,
        40, 45, 26, 31, 44, 49, 30, 35,
        48, 53, 34, 39, 52, 57, 38, 43,
        56, 61, 42, 47, 60,  1, 46, 51
    ];
}

pub fn new() -> Rectangle {
    let table = vec![0x6, 0x5, 0xc, 0xa, 0x1, 0xe, 0x7, 0x9, 0xb, 0x0, 0x3, 0xd, 0x8, 0xf, 0x4, 0x2];
    Rectangle{size: 64, sbox: Sbox::new(4, table)}
}

impl Cipher for Rectangle {
    /* Returns the size of the input to RECTANGLE. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }

    fn key_size(&self) -> usize {
        panic!("not implemented");
    }

    /* Returns the number of S-boxes in RECTANGLE. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the RECTANGLE S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the bit permutation of RECTANGLE to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;

        for i in 0..64 {
            output ^= ((input >> i) & 0x1) << Rectangle::PERMUTATION[i];
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

    #[allow(unused_variables)]
    fn linear_layer_inv(&self, input: u64) -> u64 {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        panic!("not implemented");
    }

    fn name(&self) -> String {
        String::from("RECTANGLE")
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

