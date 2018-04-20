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
    // pub min_max_corr: Vec<(f64, f64)>,
}


impl Sbox {
    /* Generates a new S-box from a table.
     *
     * table    A table discribing the S-box transformation.
     */
    fn new(size: usize, table: Vec<u8>) -> Sbox {
        let lat = Sbox::generate_lat(&table, size);
        // let min_max_corr = Sbox::generate_min_max_corr(&lat, size);
        Sbox{size: size, table: table, lat: lat/*, min_max_corr: min_max_corr*/}
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

    /*fn generate_min_max_corr(lat: &Vec<Vec<usize>>, sbox_size: usize) -> Vec<(f64, f64)> {
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
    }*/
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

    /* Applies the inverse linear layer, st.
     *
     * I = linear_layer_inv o linear_layer
     */
    fn linear_layer_inv(&self, input: u64) -> u64;

    /* Computes a vector of round key from a cipher key*/
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u64>;

    /* Returns key-size in bits */
    fn key_size(&self) -> usize;

    /* Returns the name of the cipher. */
    fn name(&self) -> String;

    /* Transforms the input and output mask of the S-box layer to an
     * input and output mask of a round.
     *
     * input    Input mask to the S-box layer.
     * output   Output mask to the S-box layer.
     */
    fn sbox_mask_transform(&self, input: u64, output: u64) -> (u64, u64);

    /* Function that defines how values of input mask, output mask, and bias 
     * are categorised for an LatMap. 
     *
     * alpha    Input mask.
     * beta     Output mask.
     * bias     Absolute counter bias.
     */
    fn lat_diversify(&self, alpha: u64, beta: u64, bias: i16) -> (i16, u16);
}

mod present;
mod gift;
mod twine;
mod puffin;
mod skinny;
mod midori;
mod led;
mod rectangle;
mod mibs;

pub fn name_to_cipher(name : &str) -> Option<Box<(Cipher + Sync)>> {
    match name {
        "present"   => Some(Box::new(present::new())),
        "gift"      => Some(Box::new(gift::new())),
        "twine"     => Some(Box::new(twine::new())),
        "puffin"    => Some(Box::new(puffin::new())),
        "skinny"    => Some(Box::new(skinny::new())),
        "midori"    => Some(Box::new(midori::new())),
        "led"       => Some(Box::new(led::new())),
        "rectangle" => Some(Box::new(rectangle::new())),
        "mibs"      => Some(Box::new(mibs::new())),
        _ => None
    }
}

mod tests;