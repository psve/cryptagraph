use cipher::Sbox;
use cipher::Cipher;

/*****************************************************************
                            LED
******************************************************************/

/* A structure representing the LED cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The LED S-box.
 */
#[derive(Clone)]
pub struct Led {
    size: usize,
    sbox: Sbox,
    shift_rows_table: [usize; 16]
}

pub fn new() -> Led {
    let table = vec![0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2];
    let shift_rows_table = [0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12];
    Led{size: 64, sbox: Sbox::new(4, table), shift_rows_table: shift_rows_table}
}

fn led_times2(x: u64) -> u64 {
    ((x & 0x7777) << 1) ^ ((x & 0x8888) >> 3) ^ ((x & 0x8888) >> 2)
}

impl Cipher for Led {
    /* Returns the size of the input to LED. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }

    fn key_size(&self) -> usize {
        panic!("not implemented");
    }

    /* Returns the number of S-boxes in LED. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the LED S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the ShuffleCell and MixColumn steps of LED to the input.
     *
     * input    Input to be transformed.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut x = 0;

        // Apply ShiftRows
        for i in 0..16 {
            x ^= ((input >> (i*4)) & 0xf) << (self.shift_rows_table[i]*4);
        }

        // Apply MixColumnsSerial
        let mut y;

        for _ in 0..4 {
            y = x >> 16;
            y ^= led_times2(led_times2(x & 0xffff)) << 48;
            y ^= (x & 0xffff0000) << 32;
            y ^= led_times2((x & 0xffff00000000) >> 32) << 48;
            y ^= led_times2((x & 0xffff000000000000) >> 48) << 48;
            x = y;
        }

        x
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

    /* Returns the string "LED". */
    fn name(&self) -> String {
        String::from("LED")
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
