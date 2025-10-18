//! SHA3-256 KDF implementation

use crate::generic::traits::Kdf as GenericKdf;
use sha3::{Digest, Sha3_256};

/// SHA3-256 based KDF
pub struct Sha3_256Kdf;

impl GenericKdf for Sha3_256Kdf {
    const INPUT_LENGTH: usize = 32; // Can be any length, but we'll use 32 for simplicity
    const OUTPUT_LENGTH: usize = 32;

    fn kdf(input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }
}

// Implementation of the new bis::Kdf trait
impl crate::bis::Kdf for Sha3_256Kdf {
    const OUTPUT_SIZE: usize = 32;

    fn compute(input: impl Iterator<Item = u8>) -> crate::bis::Output {
        let mut hasher = Sha3_256::new();
        for byte in input {
            hasher.update(&[byte]);
        }
        let result = hasher.finalize();
        result.to_vec()
    }
}
