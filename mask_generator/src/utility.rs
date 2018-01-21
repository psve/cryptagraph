use std::io::{self, Write};

/* Finds the parity of <input, alpha> ^ <outout, beta>, where <_,_> is the inner product
 * over F_2. 
 * Taken from http://www.graphics.stanford.edu/~seander/bithacks.html#ParityMultiply
 */
pub fn parity_masks(input: u64, output: u64, alpha: u64, beta: u64) -> u64 {
    let mut y = (input & alpha) | ((output & beta) << 32);

    y ^= y >> 1;
    y ^= y >> 2;
    y = (y & 0x1111111111111111).wrapping_mul(0x1111111111111111);
    (y >> 60) & 1
}

pub fn parity(input: u64) -> u64 {
    let mut y = input;

    y ^= y >> 1;
    y ^= y >> 2;
    y = (y & 0x1111111111111111).wrapping_mul(0x1111111111111111);
    (y >> 60) & 1
}

pub struct ProgressBar {
    num_items: usize,
    pub progress: usize,
    percentage: usize,
}

impl ProgressBar {
    pub fn new(num_items: usize) -> ProgressBar {
        ProgressBar{num_items: num_items, progress: 0, percentage: 1}
    }

    pub fn increment(&mut self) {
        self.progress += 1;

        if self.progress > (self.num_items / 100 * self.percentage) {
            print!("=");
            io::stdout().flush().ok().expect("Could not flush stdout");
            self.percentage += 1;
        }
    }
}