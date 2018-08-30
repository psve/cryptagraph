//! A trait for representing ciphers as well as several cipher implementations.

use sbox::Sbox;
use property::PropertyType;

/// Different type of ciphers.
#[derive(PartialEq, Eq)]
pub enum CipherStructure {
    /// A regular SPN cipher.
    Spn,
    /// A Feistel cipher.
    Feistel,
    /// A cipher with a reflective structure similar to PRINCE.
    Prince
}

/// A trait defining a cipher.
pub trait Cipher: Sync {
    /// Returns the type of the cipher.
    fn structure(&self) -> CipherStructure;

    /// Returns the block size of the cipher in bits.
    fn size(&self) -> usize;

    /// Returns key size in bits.
    fn key_size(&self) -> usize;

    /// Returns the number of S-boxes in the non-linear layer.
    fn num_sboxes(&self) -> usize;

    /// Returns the i'th S-box of the cipher.
    fn sbox(&self, i: usize) -> &Sbox;
    
    /// Applies the linear layer of the cipher to the input.
    fn linear_layer(&self, input: u128) -> u128;

    /// Applies the inverse linear layer of the cipher to the input.
    fn linear_layer_inv(&self, input: u128) -> u128;

    /// Applies the reflection layer for Prince like ciphers.
    /// For all other cipher types, this can remain unimplemented.
    #[allow(unused_variables)]
    fn reflection_layer(&self, input: u128) -> u128;

    /// Computes a vector of round key from a cipher key. Note that the length of the output
    /// is not necessarily equal to `rounds`. See the `whitening` function.
    fn key_schedule(&self, rounds : usize, key: &[u8]) -> Vec<u128>;

    /// Performs encryption with the cipher.
    fn encrypt(&self, input: u128, round_keys: &[u128]) -> u128;

    /// Performs decryption with the cipher.
    fn decrypt(&self, input: u128, round_keys: &[u128]) -> u128;

    /// Returns the name of the cipher.
    fn name(&self) -> String;

    /// Transforms the input and output mask of the S-box layer to an input and output mask 
    /// of a round. Note that this transformation can depend on the property type. 
    #[allow(unused_variables)]
    fn sbox_mask_transform(&self,
                           input: u128,
                           output: u128,
                           property_type: PropertyType)
                           -> (u128, u128);

    /// Specifies if the cipher uses a pre-whitening key. In this case, the key-schedule returns 
    /// rounds+1 round keys. 
    fn whitening(&self) -> bool;
}

pub mod aes;
pub mod boron;
pub mod epcbc48;
pub mod epcbc96;
pub mod fly;
pub mod gift64;
pub mod gift128;
pub mod iceberg;
pub mod khazad;
pub mod klein;
pub mod led;
pub mod mantis;
pub mod mcrypton;
pub mod mibs;
pub mod midori;
pub mod present;
pub mod pride;
pub mod prince;
pub mod puffin;
pub mod qarma;
pub mod rectangle;
pub mod skinny64;
pub mod skinny128;
pub mod twine;

/// Converts the name of a cipher to an instance of that cipher.
pub fn name_to_cipher(name : &str) -> Option<Box<dyn Cipher>> {
    match name {
        "aes"       => Some(Box::new(aes::Aes::new())),
        "boron"     => Some(Box::new(boron::Boron::new())),
        "epcbc48"   => Some(Box::new(epcbc48::Epcbc48::new())),
        "epcbc96"   => Some(Box::new(epcbc96::Epcbc96::new())),
        "fly"       => Some(Box::new(fly::Fly::new())),
        "gift64"    => Some(Box::new(gift64::Gift64::new())),
        "gift128"   => Some(Box::new(gift128::Gift128::new())),
        "iceberg"   => Some(Box::new(iceberg::Iceberg::new())),
        "khazad"    => Some(Box::new(khazad::Khazad::new())),
        "klein"     => Some(Box::new(klein::Klein::new())),
        "led"       => Some(Box::new(led::Led::new())),
        "mantis"    => Some(Box::new(mantis::Mantis::new())),
        "mcrypton"  => Some(Box::new(mcrypton::Mcrypton::new())),
        "mibs"      => Some(Box::new(mibs::Mibs::new())),
        "midori"    => Some(Box::new(midori::Midori::new())),
        "present"   => Some(Box::new(present::Present::new())),
        "pride"     => Some(Box::new(pride::Pride::new())),
        "prince"    => Some(Box::new(prince::Prince::new())),
        "puffin"    => Some(Box::new(puffin::Puffin::new())),
        "qarma"     => Some(Box::new(qarma::Qarma::new())),
        "rectangle" => Some(Box::new(rectangle::Rectangle::new())),
        "skinny64"  => Some(Box::new(skinny64::Skinny64::new())),
        "skinny128" => Some(Box::new(skinny128::Skinny128::new())),
        "twine"     => Some(Box::new(twine::Twine::new())),
        _ => None
    }
}
