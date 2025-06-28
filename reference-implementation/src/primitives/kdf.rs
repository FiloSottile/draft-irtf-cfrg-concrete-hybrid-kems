//! SHA3-256 KDF implementation

use hybrid_kem_ref::traits::Kdf;
use sha3::{Digest, Sha3_256};

/// SHA3-256 based KDF
pub struct Sha3_256Kdf;

impl Kdf for Sha3_256Kdf {
    const INPUT_LENGTH: usize = 32; // Can be any length, but we'll use 32 for simplicity
    const OUTPUT_LENGTH: usize = 32;

    fn kdf(input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }
}
