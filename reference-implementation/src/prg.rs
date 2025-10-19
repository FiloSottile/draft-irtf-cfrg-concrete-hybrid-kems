//! SHAKE256 PRG implementation

use crate::hybrid::Prg;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// SHAKE256 based PRG with generic output length
pub struct Shake256Prg;

// Implementation of the bis::Prg trait
impl Prg for Shake256Prg {
    fn generate(seed: &[u8], output: &mut [u8]) {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        hasher.finalize_xof().read(output);
    }
}
