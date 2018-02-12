use cipher::Sbox;
use cipher::Cipher;

#[derive(Clone)]
pub struct Gift {
    size: usize,
    sbox: Sbox
}

impl Gift {
    const PERMUTATION : [[u64 ; 0x100] ; 8] = include!("gift.perm");
}

pub fn new() -> Gift {
    let table = vec![0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
                     0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe];
    Gift{size: 64, sbox: Sbox::new(4, table)}
}

impl Cipher for Gift {
    /* Returns the size of the input to GIFT. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }

    fn key_size(&self) -> usize {
        panic!("not implemented");
    }

    /* Returns the number of S-boxes in GIFT. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the GIFT S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the bit permutation of GIFT to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;

        for i in 0..8 {
            output ^= Gift::PERMUTATION[i][((input >> (i*8)) & 0xff) as usize];
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

    fn linear_layer_inv(&self, input: u64) -> u64 {
        panic!("not implemented");
    }

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        panic!("not implemented");
    }

    /* Returns the string "GIFT". */
    fn name(&self) -> String {
        String::from("GIFT")
    }

}




