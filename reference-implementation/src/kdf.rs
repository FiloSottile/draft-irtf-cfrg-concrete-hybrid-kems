//! SHA3-256 KDF implementation

use crate::hybrid::Kdf;
use sha3::{Digest, Sha3_256};

/// SHA3-256 based KDF
pub struct Sha3_256Kdf;

// Implementation of the bis::Kdf trait
impl Kdf for Sha3_256Kdf {
    const OUTPUT_SIZE: usize = 32;

    fn compute(input: impl Iterator<Item = u8>) -> crate::hybrid::Output {
        let input: Vec<u8> = input.collect();
        let mut hasher = Sha3_256::new();
        hasher.update(&input);
        hasher.finalize().to_vec()
    }
}
