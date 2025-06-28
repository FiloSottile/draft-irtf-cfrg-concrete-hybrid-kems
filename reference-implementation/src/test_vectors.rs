//! Test vector data structures for serialization

use serde::{Deserialize, Serialize};

/// Test vector for a hybrid KEM instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKemTestVector {
    #[serde(with = "hex::serde")]
    pub seed: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub randomness: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub encapsulation_key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub decapsulation_key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub shared_secret: Vec<u8>,
}

/// Complete test vector collection for all hybrid KEM instances
#[derive(Debug, Serialize, Deserialize)]
pub struct TestVectors {
    pub qsf_p256_mlkem768_shake256_sha3256: Vec<HybridKemTestVector>,
    pub qsf_x25519_mlkem768_shake256_sha3256: Vec<HybridKemTestVector>,
    pub qsf_p384_mlkem1024_shake256_sha3256: Vec<HybridKemTestVector>,
}
