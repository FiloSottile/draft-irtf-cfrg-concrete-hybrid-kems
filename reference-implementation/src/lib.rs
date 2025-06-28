//! Concrete Hybrid KEM Reference Implementation
//!
//! This crate provides reference implementations of concrete hybrid Key Encapsulation
//! Mechanisms (KEMs) as described in draft-irtf-cfrg-concrete-hybrid-kems.
//!
//! It builds on the generic hybrid KEM framework to provide specific instantiations
//! with well-defined cryptographic primitives.

pub mod groups;
pub mod instantiations;
pub mod kems;
pub mod primitives;
pub mod test_vectors;

#[cfg(test)]
mod tests;

// Re-export the generic hybrid KEM traits and types
pub use hybrid_kem_ref::{
    error::KemError,
    qsf::QsfHybridKem,
    traits::{AsBytes, EncapsDerand, HybridKemLabel, Kdf, Kem, NominalGroup, Prg},
    utils::HybridValue,
};

// Re-export our concrete implementations
pub use groups::{P256Group, P384Group, X25519Group};
pub use instantiations::{
    QsfP256MlKem768Shake256Sha3256, QsfP384MlKem1024Shake256Sha3256,
    QsfX25519MlKem768Shake256Sha3256,
};
pub use kems::{MlKem768Kem, MlKem1024};
pub use primitives::{Sha3_256Kdf, Shake256Prg};
