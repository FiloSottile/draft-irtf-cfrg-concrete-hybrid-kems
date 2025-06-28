//! Cryptographic primitives (KDF and PRG)

pub mod kdf;
pub mod prg;

pub use kdf::Sha3_256Kdf;
pub use prg::Shake256Prg;

#[cfg(test)]
mod tests;
