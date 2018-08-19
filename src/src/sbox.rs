//! Type representing an S-box. 

use utility::parity_masks;
use std::convert::TryInto;

/// A structure that represents an S-box.
#[derive(Clone, Debug)]
pub struct Sbox {
    size: usize,
    table: Vec<u8>,
    lat: Vec<Vec<usize>>,
    ddt: Vec<Vec<usize>>,
}

impl Sbox {
    /// Creates a new S-box from its table description. `size` is the bit size of the S-box.
    ///
    /// # Panics
    /// The function panics if the length of `table` is not equal to 2<\sup>`size`<\sup>.
    pub fn new(size: usize, table: Vec<u8>) -> Sbox {
        assert_eq!(1 << size, table.len());

        let lat = Sbox::generate_lat(&table[..], size);
        let ddt = Sbox::generate_ddt(&table[..], size);

        Sbox {
            size,
            table,
            lat,
            ddt
         }
    }

    /// Generates the LAT associated with the S-box.
    fn generate_lat(table: &[u8], sbox_size: usize) -> Vec<Vec<usize>> {
        let lat_size = 1 << sbox_size;
        let mut lat = vec![vec![0; lat_size]; lat_size];

        for (plaintext, &ciphertext) in table.iter().enumerate().take(lat_size) {
            for alpha in 0..lat_size {
                for beta in 0..lat_size {
                    let parity = parity_masks(plaintext as u128,
                                              u128::from(ciphertext),
                                              alpha as u128,
                                              beta as u128);

                    lat[alpha as usize][beta as usize] += (1 - parity) as usize;
                }
            }
        }

        lat
    }

    /// Generates the DDT associated with the S-box.
    fn generate_ddt(table: &[u8], sbox_size: usize) -> Vec<Vec<usize>> {
        let ddt_size = 1 << sbox_size;
        let mut ddt = vec![vec![0; ddt_size]; ddt_size];

        for plaintext_0 in 0..ddt_size {
            let ciphertext_0 = table[plaintext_0];

            for (in_diff, ddt_row) in ddt.iter_mut().enumerate().take(ddt_size) {
                let plaintext_1 = plaintext_0 ^ in_diff;
                let ciphertext_1 = table[plaintext_1];

                ddt_row[(ciphertext_0 ^ ciphertext_1) as usize] += 1;
            }
        }

        ddt
    }

    /// Applies the S-box to the input.
    pub fn apply<T: TryInto<usize>>(&self, x: T) -> u8 {
        let x = match x.try_into() {
            Ok(x) => x,
            Err(_) => panic!("Conversion error"),
        };

        self.table[x]
    }

    /// Returns the value of a balanced linear approximation of the S-box.
    pub fn linear_balance(&self) -> i16 {
        (1 << (self.size - 1)) as i16
    }

    /// Returns the probability of an impossible differential of the S-box.
    pub fn differential_zero(&self) -> i16 {
        0
    }

    /// Returns a bitmask that corresponds to the S-box size.
    pub fn mask(&self) -> u128 {
        (1 << self.size) - 1
    }

    /// Returns the size of the S-box in bits.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns a reference to the LAT of the S-box.
    pub fn lat(&self) -> &Vec<Vec<usize>> {
        &self.lat
    }

    /// Returns a reference to the DDT of the S-box.
    pub fn ddt(&self) -> &Vec<Vec<usize>> {
        &self.ddt
    }
}