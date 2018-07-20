use std::io::{self, Write};

/**
Finds the parity of <input, alpha> ^ <outout, beta>, where <_,_> is the inner product
over F_2. Taken from http://www.graphics.stanford.edu/~seander/bithacks.html#ParityMultiply

input   Input value.
output  Output value.
alpha   Input mask.
beta    Output mask.
*/
pub fn parity_masks(input: u128,
                    output: u128,
                    alpha: u128,
                    beta: u128)
                    -> u128 {
    let mut y = (input & alpha) | ((output & beta) << 64);

    y ^= y >> 1;
    y ^= y >> 2;
    y = (y & 0x11111111111111111111111111111111).wrapping_mul(0x11111111111111111111111111111111);
    (y >> 124) & 1
}

#[allow(dead_code)]
pub fn parity(input: u128) -> u128 {
    let mut y = input;

    y ^= y >> 1;
    y ^= y >> 2;
    y = (y & 0x11111111111111111111111111111111).wrapping_mul(0x11111111111111111111111111111111);
    (y >> 124) & 1
}


static COMP_PATTERN: [u128; 4] = [
    0x01010101010101010101010101010101, 
    0x11111111111111111111111111111111, 
    0x55555555555555555555555555555555, 
    0xffffffffffffffffffffffffffffffff
]; 

/**
"Compresses" a 64-bit value such that if a block of 2^(3-level) bits is non-zero, than that 
block is set to the value 1.

x       The value to compress
level   The compression level to use.
*/
#[inline(always)]
pub fn compress(x: u128, 
                level: usize) 
                -> u128 {
    // We use bit patterns to reduce the amount of work done
    let mut y = x;
    for i in 0..(3-level) {
        y = y | (y >> (1<<i));
    }

    y & COMP_PATTERN[level]
}

/**
A struct representing a progress bar for progress printing on the command line.

num_items       Number of items to count the progress for.
progress        The current progress.
percentage      The current progress in percent.
*/
pub struct ProgressBar {
    current_items: f64,
    item_size: f64,
    used: bool,
}

impl ProgressBar {
    /**
    Crate a new progress bar.

    num_items       Number of items to count the progress for.
    */
    pub fn new(num_items: usize) -> ProgressBar {
        let item_size = 100.0 / (num_items as f64);

        ProgressBar {
            current_items: 0.0,
            item_size,
            used: false,
        }
    }

    /**
    Increment the current progress of the progress bar. The progress bar prints if
    a new step was reached.
    */
    #[inline(always)]
    pub fn increment(&mut self) {
        self.current_items += self.item_size;

        while self.current_items >= 1.0 {
            print!("=");
            io::stdout().flush().expect("Could not flush stdout");
            self.current_items -= 1.0;
        }

        self.used = true;
    }
}

impl Drop for ProgressBar {
    fn drop(&mut self) {
        if self.used {
            println!();
        }
    }
}