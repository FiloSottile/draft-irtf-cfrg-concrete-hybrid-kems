//! SHA3-256 KDF implementation

use sha3::{Digest, Sha3_256};

/// SHA3-256 based KDF
pub struct Sha3_256Kdf;

// Implementation of the bis::Kdf trait
impl crate::hybrid::Kdf for Sha3_256Kdf {
    const OUTPUT_SIZE: usize = 32;

    fn compute(input: impl Iterator<Item = u8>) -> crate::hybrid::Output {
        let mut hasher = Sha3_256::new();
        for byte in input {
            hasher.update(&[byte]);
        }
        let result = hasher.finalize();
        result.to_vec()
    }
}
