use std::cmp;
use utility;

/* A structure that represents an S-box.
 *
 * size     Size of the S-box input in number of bits.
 * table    The table that describes the S-box.
 */
#[derive(Clone, Debug)]
pub struct Sbox {
    pub size: usize,
    table: Vec<u8>,
    pub lat: Vec<Vec<usize>>,
    pub min_max_corr: Vec<(f64, f64)>,
}

impl Sbox {
    /* Generates a new S-box from a table.
     *
     * table    A table discribing the S-box transformation.
     */
    fn new(size: usize, table: Vec<u8>) -> Sbox {
        let lat = Sbox::generate_lat(&table, size);
        let min_max_corr = Sbox::generate_min_max_corr(&lat, size);
        Sbox{size: size, table: table, lat: lat, min_max_corr: min_max_corr}
    }

    /* Generates the LAT associated with the S-box. */
    fn generate_lat(table: &Vec<u8>, sbox_size: usize) -> Vec<Vec<usize>> {
        let lat_size = 1 << sbox_size;
        let mut lat = vec![vec![0; lat_size]; lat_size];

        for plaintext in 0..lat_size {
            let ciphertext = table[plaintext];

            for alpha in 0..lat_size {
                for beta in 0..lat_size {
                    let parity = utility::parity_masks(plaintext as u64,
                                                       ciphertext as u64,
                                                       alpha as u64,
                                                       beta as u64);

                    lat[alpha as usize][beta as usize] += (1 - parity) as usize;
                }
            }
        }

        lat
    }

    fn generate_min_max_corr(lat: &Vec<Vec<usize>>, sbox_size: usize) -> Vec<(f64, f64)> {
        let balance = (1 << (sbox_size - 1)) as i16;
        let mut min_max_corr = vec![(0.0, 1.0); 1 << sbox_size];

        for (i, row) in lat.iter().enumerate() {
            let (min, max) = row.iter()
                                .filter(|&x| *x as i16 != balance)
                                .fold((i16::max_value(), 0),
                                      |acc, &x|
                                      (cmp::min(acc.0, (x as i16 - balance).abs()),
                                       cmp::max(acc.1, (x as i16 - balance).abs())));
            let (min_corr, max_corr) = ((min as f64 / balance as f64).powi(2),
                                        (max as f64 / balance as f64).powi(2));
            min_max_corr[i] = (min_corr, max_corr);
        }

        min_max_corr
    }
}

/* A trait defining an SPN cipher */
pub trait Cipher: Send + Sync {
    /* Returns the size of the cipher input in bits. */
    fn size(&self) -> usize;

    /* Returns the number of S-boxes in the non-linear layer. */
    fn num_sboxes(&self) -> usize;

    /* Returns the S-box of the cipher */
    fn sbox(&self) -> &Sbox;

    /* Applies the linear layer of the cipher.
     *
     * input    The input to the linear layer.
     */
    fn linear_layer(&self, input: u64) -> u64;

    /* Transforms the input and output mask of the S-box layer to an
     * input and output mask of a round.
     *
     * input    Input mask to the S-box layer.
     * output   Output mask to the S-box layer.
     */
    fn sbox_mask_transform(& self, input: u64, output: u64) -> (u64, u64);

    /* Applies the inverse linear layer, st.
     *
     * I = linear_layer_inv o linear_layer
     */
    fn linear_layer_inv(&self, input: u64) -> u64;

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64>;

    /* Returns the name of the cipher. */
    fn name(&self) -> String;
}

pub fn name_to_cipher(name : &str) -> Option<Box<(Cipher + Sync)>> {
    match name {
        "present"   => Some(Box::new(Present::new())),
        "gift"      => Some(Box::new(Gift::new())),
        "twine"     => Some(Box::new(Twine::new())),
        "puffin"    => Some(Box::new(Puffin::new())),
        "skinny"    => Some(Box::new(Skinny::new())),
        "midori"    => Some(Box::new(Midori::new())),
        "led"       => Some(Box::new(Led::new())),
        "rectangle" => Some(Box::new(Rectangle::new())),
        "mibs"      => Some(Box::new(Mibs::new())),
        _ => None
    }
}

/*****************************************************************
                            PRESENT
******************************************************************/

/* A structure representing the PRESENT cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The PRESENT S-box.
 * permutation  The PRESENT bit permutation.
 */
#[derive(Clone)]
pub struct Present {
    size: usize,
    sbox: Sbox
}

impl Present {
    const PERMUTATION_INV : [[u64 ; 0x100] ; 8] = include!("present.inv.perm");
    const PERMUTATION     : [[u64 ; 0x100] ; 8] = include!("present.perm");

    /* Generates a new instance of the PRESENT cipher */
    pub fn new() -> Present {
        let table = vec![0xc, 0x5, 0x6, 0xb,
                         0x9, 0x0, 0xa, 0xd,
                         0x3, 0xe, 0xf, 0x8,
                         0x4, 0x7, 0x1, 0x2];
        Present{size: 64, sbox: Sbox::new(4, table)}
    }
}

impl Cipher for Present {

    /* Returns the size of the input to PRESENT. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
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
        panic!("not implemented");
    }

    /* Returns the string "PRESENT". */
    fn name(&self) -> String {
        String::from("PRESENT")
    }
}


/*****************************************************************
                            GIFT
******************************************************************/

/* A structure representing the GIFT cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The GIFT S-box.
 * permutation  The GIFT bit permutation.
 */
#[derive(Clone)]
pub struct Gift {
    size: usize,
    sbox: Sbox
}

impl Gift {
    const PERMUTATION : [[u64 ; 0x100] ; 8] = include!("gift.perm");

    /* Generates a new instance of the GIFT cipher */
    pub fn new() -> Gift {
        let table = vec![0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
                         0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe];
        Gift{size: 64, sbox: Sbox::new(4, table)}
    }
}

impl Cipher for Gift {
    /* Returns the size of the input to GIFT. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
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



/*****************************************************************
                            TWINE
******************************************************************/

/* A structure representing the TWINE cipher. Due to the Feistel structure, one round is actually
 * two rounds of TWINE.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The Feistel function of TWINE represented as an S-box. Key addition ignored.
 * permutation  The TWINE nibble permutation.
 */
#[derive(Clone)]
pub struct Twine {
    size: usize,
    sbox: Sbox,
    permutation: [u64; 16],
    inverse: [u64; 16],
}

impl Twine {
    /* Generates a new instance of the TWINE cipher */
    pub fn new() -> Twine {
        let table = vec![0xc, 0x0, 0xf, 0xa, 0x2, 0xb, 0x9, 0x5, 0x8, 0x3, 0xd, 0x7, 0x1, 0xe, 0x6, 0x4];

        let permutation = [1, 4, 5, 0, 13, 6, 9, 2, 7, 12, 3, 8, 11, 14, 15, 10];
        let inverse     = [3, 0, 7, 10, 1, 2, 5, 8, 11, 6, 15, 12, 9, 4, 13, 14];

        Twine{size: 64, sbox: Sbox::new(4, table), permutation: permutation, inverse: inverse}
    }

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

    /* Returns the string "TWINE". */
    fn name(&self) -> String {
        String::from("TWINE")
    }
}



/*****************************************************************
                            PUFFIN
******************************************************************/

/* A structure representing the PUFFIN cipher.
 *
 * size         Size of the cipher in bits. This is fixed to 64.
 * sbox         The PUFFIN S-box.
 * permutation  The PUFFIN bit permutation.
 */
#[derive(Clone)]
pub struct Puffin {
    size: usize,
    sbox: Sbox
}

impl Puffin {
    const PERMUTATION : [[u64 ; 0x100] ; 8] = include!("puffin.perm");

    /* Generates a new instance of the PUFFIN cipher */
    pub fn new() -> Puffin {
        let table = vec![0xd, 0x7, 0x3, 0x2, 0x9, 0xa, 0xc, 0x1, 0xf, 0x4, 0x5, 0xe, 0x6, 0x0, 0xb, 0x8];
        Puffin{size: 64, sbox: Sbox::new(4, table)}
    }
}

impl Cipher for Puffin {
    /* Returns the size of the input to PUFFIN. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
    }

    /* Returns the number of S-boxes in PUFFIN. This is always 16. */
    fn num_sboxes(&self) -> usize {
        self.size / self.sbox.size
    }

    /* Returns the PUFFIN S-box */
    fn sbox(&self) -> &Sbox {
        &self.sbox
    }

    /* Applies the bit permutation of PUFFIN to the input.
     *
     * input    Input to be permuted.
     */
    fn linear_layer(&self, input: u64) -> u64{
        let mut output = 0;

        for i in 0..8 {
            output ^= Puffin::PERMUTATION[i][((input >> (i*8)) & 0xff) as usize];
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

    /* Returns the string "PUFFIN". */
    fn name(&self) -> String {
        String::from("PUFFIN")
    }
}



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

impl Skinny {
    /* Generates a new instance of the SKINNY cipher */
    pub fn new() -> Skinny {
        let table = vec![0xc, 0x6, 0x9, 0x0, 0x1, 0xa, 0x2, 0xb, 0x3, 0x8, 0x5, 0xd, 0x4, 0xe, 0x7, 0xf];
        let shift_rows_table = [0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12];
        Skinny{size: 64, sbox: Sbox::new(4, table), shift_rows_table: shift_rows_table}
    }
}

impl Cipher for Skinny {
    /* Returns the size of the input to SKINNY. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
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

impl Midori {
    /* Generates a new instance of the Midori cipher */
    pub fn new() -> Midori {
        let table = vec![0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6];
        let shuffle_cell_table = [00, 07, 14, 09, 05, 02, 11, 12, 15, 08, 01, 06, 10, 13, 04, 03];
        Midori{size: 64, sbox: Sbox::new(4, table), shuffle_cell_table: shuffle_cell_table}
    }
}

impl Cipher for Midori {
    /* Returns the size of the input to Midori. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
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

    fn linear_layer_inv(&self, input: u64) -> u64 {
        panic!("not implemented");
    }

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        panic!("not implemented");
    }

    /* Returns the string "Midori". */
    fn name(&self) -> String {
        String::from("Midori")
    }
}

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

impl Led {
    /* Generates a new instance of the LED cipher */
    pub fn new() -> Led {
        let table = vec![0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2];
        let shift_rows_table = [0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12];
        Led{size: 64, sbox: Sbox::new(4, table), shift_rows_table: shift_rows_table}
    }
}

fn led_times2(x: u64) -> u64 {
    ((x & 0x7777) << 1) ^ ((x & 0x8888) >> 3) ^ ((x & 0x8888) >> 2)
}

impl Cipher for Led {
    /* Returns the size of the input to LED. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
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
        let mut y = 0;

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

    fn linear_layer_inv(&self, input: u64) -> u64 {
        panic!("not implemented");
    }

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        panic!("not implemented");
    }

    /* Returns the string "LED". */
    fn name(&self) -> String {
        String::from("LED")
    }
}

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
    permutation: [u64; 64]
}

impl Rectangle {
    /* Generates a new instance of the RECTANGLE cipher */
    pub fn new() -> Rectangle {
        let table = vec![0x6, 0x5, 0xc, 0xa, 0x1, 0xe, 0x7, 0x9, 0xb, 0x0, 0x3, 0xd, 0x8, 0xf, 0x4, 0x2];

        let permutation = [ 0,  5, 50, 55,
                            4,  9, 54, 59,
                            8, 13, 58, 63,
                           12, 17, 62,  3,
                           16, 21,  2,  7,
                           20, 25,  6, 11,
                           24, 29, 10, 15,
                           28, 33, 14, 19,
                           32, 37, 18, 23,
                           36, 41, 22, 27,
                           40, 45, 26, 31,
                           44, 49, 30, 35,
                           48, 53, 34, 39,
                           52, 57, 38, 43,
                           56, 61, 42, 47,
                           60,  1, 46, 51];

        Rectangle{size: 64, sbox: Sbox::new(4, table), permutation: permutation}
    }
}

impl Cipher for Rectangle {
    /* Returns the size of the input to RECTANGLE. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
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
            output ^= ((input >> i) & 0x1) << self.permutation[i];
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

    /* Returns the string "RECTANGLE". */
    fn name(&self) -> String {
        String::from("RECTANGLE")
    }
}


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
    sbox: Sbox,
    permutation: [u64; 8]
}

impl Mibs {
    /* Generates a new instance of the MIBS cipher */
    pub fn new() -> Mibs {
        let table = vec![4, 15, 3, 8, 13, 10, 12, 0, 11, 5, 7, 14, 2, 6, 1, 9];

        let permutation = [1, 7, 0, 2, 5, 6, 3, 4];

        Mibs{size: 64, sbox: Sbox::new(4, table), permutation: permutation}
    }
}

impl Cipher for Mibs {
    /* Returns the size of the input to MIBS. This is always 64 bits. */
    fn size(&self) -> usize {
        self.size
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
            output ^= ((x >> (4*i)) & 0xf) << (self.permutation[i] * 4);
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

    fn linear_layer_inv(&self, input: u64) -> u64 {
        panic!("not implemented");
    }

    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64> {
        panic!("not implemented");
    }

    /* Returns the string "MIBS". */
    fn name(&self) -> String {
        String::from("MIBS")
    }
}
