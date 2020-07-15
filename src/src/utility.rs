//! A collection of utility functions used throughout the library.

use std::io::{self, Write};

/// Finds the parity of `<input, alpha> ^ <outout, beta>`, where `<_,_>` is the inner product
/// over GF(2). Taken from
/// [here](http://www.graphics.stanford.edu/~seander/bithacks.html#ParityMultiply).
pub fn parity_masks(input: u128, output: u128, alpha: u128, beta: u128) -> u128 {
    let mut y = (input & alpha) | ((output & beta) << 64);

    y ^= y >> 1;
    y ^= y >> 2;
    y = (y & 0x1111_1111_1111_1111_1111_1111_1111_1111)
        .wrapping_mul(0x1111_1111_1111_1111_1111_1111_1111_1111);
    (y >> 124) & 1
}

/// Calculates the modulo 2 sum of the bits in the input.
pub fn parity(input: u128) -> u128 {
    let mut y = input;

    y ^= y >> 1;
    y ^= y >> 2;
    y = (y & 0x1111_1111_1111_1111_1111_1111_1111_1111)
        .wrapping_mul(0x1111_1111_1111_1111_1111_1111_1111_1111);
    (y >> 124) & 1
}

static COMP_PATTERN: [u128; 4] = [
    0x0101_0101_0101_0101_0101_0101_0101_0101,
    0x1111_1111_1111_1111_1111_1111_1111_1111,
    0x5555_5555_5555_5555_5555_5555_5555_5555,
    0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
];

/// Compresses `x` such that if a block of 2<sup>(3-`level`)</sup> bits is non-zero, then that
/// block is set to the value 1 in the output.
#[inline(always)]
pub fn compress(x: u128, level: usize) -> u128 {
    // We use bit patterns to reduce the amount of work done
    let mut y = x;
    for i in 0..(3 - level) {
        y = y | (y >> (1 << i));
    }

    y & COMP_PATTERN[level]
}

/// A struct representing a progress bar for progress printing on the command line.
pub struct ProgressBar {
    current_items: f64,
    item_size: f64,
    used: bool,
}

impl ProgressBar {
    /// Creates a new progress for tracking progress of `num_items` steps.
    pub fn new(num_items: usize) -> ProgressBar {
        let item_size = 100.0 / (num_items as f64);

        ProgressBar {
            current_items: 0.0,
            item_size,
            used: false,
        }
    }

    /// Increment the current progress of the bar. The progress bar prints if
    /// a new step was reached.
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
