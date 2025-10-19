//! Concrete Hybrid KEM Reference Implementation
//!
//! This crate provides reference implementations of concrete hybrid Key Encapsulation
//! Mechanisms (KEMs) as described in draft-irtf-cfrg-concrete-hybrid-kems.

/// Nominal groups
pub mod group;

/// KEMs
pub mod kem;

/// KDFs
pub mod kdf;

/// PRGs
pub mod prg;

/// Definition of test vector formats, generation, and validation
pub mod test_vectors;

/// The hybrid KEM frameworks
pub mod hybrid;

// MLKEM768-P256
pub struct MlKem768P256Constants;

impl kem::SeedSize for MlKem768P256Constants {
    const SEED_SIZE: usize = 32;
}

impl kem::SharedSecretSize for MlKem768P256Constants {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl hybrid::HybridKemConstants for MlKem768P256Constants {
    const LABEL: &'static [u8] = b"|-()-|";
}

pub type MlKem768P256 =
    hybrid::GC<kem::MlKem768, group::P256, prg::Shake256, kdf::Sha3_256, MlKem768P256Constants>;

// MLKEM768-X25519
pub struct MlKem768X25519Constants;

impl kem::SeedSize for MlKem768X25519Constants {
    const SEED_SIZE: usize = 32;
}

impl kem::SharedSecretSize for MlKem768X25519Constants {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl hybrid::HybridKemConstants for MlKem768X25519Constants {
    const LABEL: &'static [u8] = b"\\.//^\\";
}

pub type MlKem768X25519 =
    hybrid::GC<kem::MlKem768, group::X25519, prg::Shake256, kdf::Sha3_256, MlKem768X25519Constants>;

// MLKEM1024-P384
pub struct MlKem1024P384Constants;

impl kem::SeedSize for MlKem1024P384Constants {
    const SEED_SIZE: usize = 32;
}

impl kem::SharedSecretSize for MlKem1024P384Constants {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl hybrid::HybridKemConstants for MlKem1024P384Constants {
    const LABEL: &'static [u8] = b" | /-\\";
}

pub type MlKem1024P384 =
    hybrid::GC<kem::MlKem1024, group::P384, prg::Shake256, kdf::Sha3_256, MlKem1024P384Constants>;

#[cfg(test)]
mod test {
    use super::*;
    use kem::test::test_all;

    #[test]
    fn mlkem768_p256() {
        test_all::<MlKem768P256>();
    }

    #[test]
    fn mlkem768_x25519() {
        test_all::<MlKem768X25519>();
    }

    #[test]
    fn mlkem1024_p384() {
        test_all::<MlKem1024P384>();
    }
}
