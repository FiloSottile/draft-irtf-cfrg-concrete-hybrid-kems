//! Concrete Hybrid KEM Reference Implementation
//!
//! This crate provides reference implementations of concrete hybrid Key Encapsulation
//! Mechanisms (KEMs) as described in draft-irtf-cfrg-concrete-hybrid-kems.

/// Core types and traits that are used across all of the algorithms
pub mod core;

/// Implementations of nominal groups
mod groups;

/// Implementations of KEMs
mod kems;

/// Implementations of KDFs
mod kdf;

/// Implementations of PRGs
mod prg;

/// Definition of test vector formats, generation, and validation
pub mod test_vectors;

/// The hybrid KEMs
pub mod hybrid;

#[cfg(test)]
mod tests;

// Re-export our concrete implementations
pub use groups::{P256Group, P384Group, X25519Group};
pub use kdf::Sha3_256Kdf;
pub use kems::{MlKem1024, MlKem512, MlKem768};
pub use prg::Shake256Prg;
