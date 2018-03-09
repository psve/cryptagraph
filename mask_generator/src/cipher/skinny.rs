use cipher::Sbox;
use cipher::Cipher;

/*****************************************************************
                            SKINNY
******************************************************************/

/* A structure representing the SKINNY cipher.
 *
 * size                 Size of the cipher in bits. This is fixed to 64.
 * sbox                 The SKINNY S-box.
 * shift_rows_table     Permutation used for ShiftRows.
 */
#[derive(Clone)]
pub struct Skinny {
    size: usize,
    sbox: Sbox,
    shift_rows_table: [usize; 16]
}

pub fn new() -> Skinny {
    let table = vec![0xc, 0x6, 0x9, 0x0, 0x1, 0xa, 0x2, 0xb, 0x3, 0x8, 0x5, 0xd, 0x4, 0xe, 0x7, 0xf];
    let shift_rows_table = [0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12];
    Skinny{size: 64, sbox: Sbox::new(4, table), shift_rows_table: shift_rows_table}
}

impl Cipher for Skinny {
    /* Returns the size of the input to SKINNY. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }

    fn key_size(&self) -> usize {
        panic!("not implemented");
    }

    /* Returns the number of S-boxes in SKINNY. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the SKINNY S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the ShiftRows and MixColumns steps of SKINNY to the input.
     *
     * input    Input to be transformed.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;

        // Apply ShiftRows
        for i in 0..16 {
            output ^= ((input >> (i*4)) & 0xf) << (self.shift_rows_table[i]*4);
        }

        // Apply MixColumns
        output ^= (output & 0xffff00000000) >> 16;
        output ^= (output & 0xffff) << 32;
        output ^= (output & 0xffff00000000) << 16;
        output = (output << 16) ^ (output >> 48);

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

    /* Returns the string "SKINNY". */
    fn name(&self) -> String {
        String::from("SKINNY")
    }
}
