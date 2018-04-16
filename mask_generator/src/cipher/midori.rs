use cipher::Sbox;
use cipher::Cipher;

/*****************************************************************
                            Midori
******************************************************************/

/* A structure representing the Midori cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The Midori S-box.
 */
#[derive(Clone)]
pub struct Midori {
    size: usize,
    sbox: Sbox,
    shuffle_cell_table: [usize; 16]
}

pub fn new() -> Midori {
    let table = vec![0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6];
    let shuffle_cell_table = [00, 07, 14, 09, 05, 02, 11, 12, 15, 08, 01, 06, 10, 13, 04, 03];
    Midori{size: 64, sbox: Sbox::new(4, table), shuffle_cell_table: shuffle_cell_table}
}

impl Cipher for Midori {
    /* Returns the size of the input to Midori. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }

    fn key_size(&self) -> usize {
        panic!("not implemented");
    }

    /* Returns the number of S-boxes in Midori. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the Midori S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the ShuffleCell and MixColumn steps of Midori to the input.
     *
     * input    Input to be transformed.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut x = 0;

        // Apply ShuffleCell
        for i in 0..16 {
            x ^= ((input >> (i*4)) & 0xf) << (self.shuffle_cell_table[i]*4);
        }

        // Apply MixColumn
        let mut output = 0;

        output ^= (x & 0x00f000f000f000f0) >> 4
                ^ (x & 0x0f000f000f000f00) >> 8
                ^ (x & 0xf000f000f000f000) >> 12;

        output ^= (x & 0x000f000f000f000f) << 4
                ^ (x & 0x0f000f000f000f00) >> 4
                ^ (x & 0xf000f000f000f000) >> 8;

        output ^= (x & 0x000f000f000f000f) << 8
                ^ (x & 0x00f000f000f000f0) << 4
                ^ (x & 0xf000f000f000f000) >> 4;

        output ^= (x & 0x000f000f000f000f) << 12
                ^ (x & 0x00f000f000f000f0) << 8
                ^ (x & 0x0f000f000f000f00) << 4;

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

    /* Returns the string "Midori". */
    fn name(&self) -> String {
        String::from("Midori")
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
