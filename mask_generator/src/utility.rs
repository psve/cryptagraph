use std::io::{self, Write};

/** 
Finds the parity of <input, alpha> ^ <outout, beta>, where <_,_> is the inner product
over F_2. Taken from http://www.graphics.stanford.edu/~seander/bithacks.html#ParityMultiply

input   Input value.
output  Output value.
alpha   Input mask.
beta    Output mask.
*/
pub fn parity_masks(input: u64, 
                    output: u64, 
                    alpha: u64, 
                    beta: u64) 
                    -> u64 {
    let mut y = (input & alpha) | ((output & beta) << 32);

    y ^= y >> 1;
    y ^= y >> 2;
    y = (y & 0x1111111111111111).wrapping_mul(0x1111111111111111);
    (y >> 60) & 1
}

#[allow(dead_code)]
pub fn parity(input: u64) -> u64 {
    let mut y = input;

    y ^= y >> 1;
    y ^= y >> 2;
    y = (y & 0x1111111111111111).wrapping_mul(0x1111111111111111);
    (y >> 60) & 1
}

/**
A struct representing a progress bar for progress printing on the command line.

num_items       Number of items to count the progress for.
progress        The current progress.
percentage      The current progress in percent.
*/
pub struct ProgressBar {
    current_items: f64,
    item_size: f64
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
            item_size: item_size
        }
    }

    /**
    Increment the current progress of the progress bar. The progress bar prints if
    a new step was reached.
    */
    pub fn increment(&mut self) {
        self.current_items += self.item_size;
        
        while self.current_items >= 1.0 {
            print!("=");
            io::stdout().flush().ok().expect("Could not flush stdout");
            self.current_items -= 1.0;
        }
    }
}