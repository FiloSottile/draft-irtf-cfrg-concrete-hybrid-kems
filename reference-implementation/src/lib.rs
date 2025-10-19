//! Concrete Hybrid KEM Reference Implementation
//!
//! This crate provides reference implementations of concrete hybrid Key Encapsulation
//! Mechanisms (KEMs) as described in draft-irtf-cfrg-concrete-hybrid-kems.
//!
//! It uses the bis module which provides a simple Vec<u8>-based API for all operations.

pub mod bis;
pub mod groups;
pub mod kems;
pub mod primitives;
pub mod test_vectors;
pub mod utils;

#[cfg(test)]
mod tests;

// Re-export our concrete implementations
pub use groups::{P256Group, P384Group, X25519Group};
pub use kems::{MlKem1024Kem, MlKem512Kem, MlKem768Kem};
pub use primitives::{Sha3_256Kdf, Shake256Prg};
