use cipher::Sbox;
use cipher::Cipher;

#[derive(Clone)]
pub struct Twine {
    size: usize,
    sbox: Sbox,
    permutation: [u64; 16],
    inverse: [u64; 16],
}

pub fn new() -> Twine {
    let table = vec![0xc, 0x0, 0xf, 0xa, 0x2, 0xb, 0x9, 0x5, 0x8, 0x3, 0xd, 0x7, 0x1, 0xe, 0x6, 0x4];

    let permutation = [1, 4, 5, 0, 13, 6, 9, 2, 7, 12, 3, 8, 11, 14, 15, 10];
    let inverse     = [3, 0, 7, 10, 1, 2, 5, 8, 11, 6, 15, 12, 9, 4, 13, 14];

    Twine{size: 64, sbox: Sbox::new(4, table), permutation: permutation, inverse: inverse}
}

impl Twine {
    /* Applies the inverse nibble permutation of TWINE to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer_inverse(&self, input: u64) -> u64{
        let mut output = 0;

        for i in 0..16 {
            output ^= ((input >> (i*4)) & 0xf) << (self.inverse[i]*4);
        }

        output
    }
}

impl Cipher for Twine {
    /* Returns the size of the input to TWINE. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }

    fn key_size(&self) -> usize {
        panic!("not implemented");
    }

    /* Returns the number of S-boxes in TWINE. This is always 8. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns Feistel function of TWINE represented as an S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the nibble permutation of TWINE to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;

        for i in 0..16 {
            output ^= ((input >> (i*4)) & 0xf) << (self.permutation[i]*4);
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
        let mut alpha = 0;

        alpha ^= (input & 0xf) << 4;
        alpha ^= (input & 0xf0) << 8;
        alpha ^= (input & 0xf00) << 12;
        alpha ^= (input & 0xf000) << 16;
        alpha ^= (input & 0xf0000) << 20;
        alpha ^= (input & 0xf00000) << 24;
        alpha ^= (input & 0xf000000) << 28;
        alpha ^= (input & 0xf0000000) << 32;

        alpha ^= (output & 0xf) << 0;
        alpha ^= (output & 0xf0) << 4;
        alpha ^= (output & 0xf00) << 8;
        alpha ^= (output & 0xf000) << 12;
        alpha ^= (output & 0xf0000) << 16;
        alpha ^= (output & 0xf00000) << 20;
        alpha ^= (output & 0xf000000) << 24;
        alpha ^= (output & 0xf0000000) << 28;

        let mut beta = 0;

        beta ^= ((input & 0xf00000000) >> 32) << 4;
        beta ^= ((input & 0xf000000000) >> 32) << 8;
        beta ^= ((input & 0xf0000000000) >> 32) << 12;
        beta ^= ((input & 0xf00000000000) >> 32) << 16;
        beta ^= ((input & 0xf000000000000) >> 32) << 20;
        beta ^= ((input & 0xf0000000000000) >> 32) << 24;
        beta ^= ((input & 0xf00000000000000) >> 32) << 28;
        beta ^= ((input & 0xf000000000000000) >> 32) << 32;

        alpha ^= self.linear_layer_inverse(beta);

        beta ^= ((output & 0xf00000000) >> 32) << 0;
        beta ^= ((output & 0xf000000000) >> 32) << 4;
        beta ^= ((output & 0xf0000000000) >> 32) << 8;
        beta ^= ((output & 0xf00000000000) >> 32) << 12;
        beta ^= ((output & 0xf000000000000) >> 32) << 16;
        beta ^= ((output & 0xf0000000000000) >> 32) << 20;
        beta ^= ((output & 0xf00000000000000) >> 32) << 24;
        beta ^= ((output & 0xf000000000000000) >> 32) << 28;

        beta ^= self.linear_layer(alpha & 0xf0f0f0f0f0f0f0f0);

        beta = self.linear_layer(beta);

        (alpha, beta)
    }

    fn linear_layer_inv(&self, input: u64) -> u64 {
        panic!("not implemented");
    }

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        panic!("not implemented");
    }

    fn name(&self) -> String {
        String::from("TWINE")
    }
}
