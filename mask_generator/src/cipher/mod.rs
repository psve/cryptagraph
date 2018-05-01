use utility;

/* A structure that represents an S-box.
 *
 * size     Size of the S-box input in number of bits.
 * table    The table that describes the S-box.
 */
#[derive(Clone, Debug)]
pub struct Sbox {
    pub size: usize,
    pub table: Vec<u8>,
    pub lat: Vec<Vec<usize>>,
    pub ddt: Vec<Vec<usize>>,
}

impl Sbox {
    /* Generates a new S-box from a table.
     *
     * table    A table discribing the S-box transformation.
     */
    fn new(size: usize, table: Vec<u8>) -> Sbox {
        let lat = Sbox::generate_lat(&table, size);
        let ddt = Sbox::generate_ddt(&table, size);

        Sbox {
            size: size, 
            table: table, 
            lat: lat,
            ddt: ddt
         }
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

    /* Generates the DDT associated with the S-box. */
    fn generate_ddt(table: &Vec<u8>, sbox_size: usize) -> Vec<Vec<usize>> {
        let ddt_size = 1 << sbox_size;
        let mut ddt = vec![vec![0; ddt_size]; ddt_size];

        for plaintext_0 in 0..ddt_size {
            let ciphertext_0 = table[plaintext_0];

            for in_diff in 0..ddt_size {
                let plaintext_1 = plaintext_0 ^ in_diff;
                let ciphertext_1 = table[plaintext_1];

                ddt[in_diff][(ciphertext_0 ^ ciphertext_1) as usize] += 1;
            }
        }

        ddt
    }

    pub fn linear_balance(&self) -> i16 {
        (1 << (self.size - 1)) as i16
    }

    pub fn differential_zero(&self) -> i16 {
        0
    }
}

#[derive(PartialEq, Eq)]
pub enum CipherStructure {
    Spn,
    Feistel
}

/* A trait defining an SPN cipher */
pub trait Cipher: Send + Sync {
    /* Returns the design type of the cipher */
    fn structure(&self) -> CipherStructure;

    /* Returns the size of the cipher input in bits. */
    fn size(&self) -> usize;

    /* Returns key-size in bits */
    fn key_size(&self) -> usize;

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

    /* Performs encryption */
    fn encrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64;

    /* Performs decryption */
    fn decrypt(&self, input: u64, round_keys: &Vec<u64>) -> u64;

    /* Returns the name of the cipher. */
    fn name(&self) -> String;

    /* Transforms the input and output mask of the S-box layer to an
     * input and output mask of a round.
     *
     * input    Input mask to the S-box layer.
     * output   Output mask to the S-box layer.
     */
    fn sbox_mask_transform(&self, input: u64, output: u64) -> (u64, u64);
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
mod klein;
mod pride;
mod khazad;
mod fly;

pub fn name_to_cipher(name : &str) -> Option<Box<(Cipher + Send)>> {
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
        "klein"     => Some(Box::new(klein::new())),
        "pride"     => Some(Box::new(pride::new())),
        "khazad"    => Some(Box::new(khazad::new())),
        "fly"       => Some(Box::new(fly::new())),
        _ => None
    }
}