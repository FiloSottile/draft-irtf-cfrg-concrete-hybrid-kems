//! SHAKE256 PRG implementation

use crate::generic::traits::Prg as GenericPrg;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// SHAKE256 based PRG with generic output length
pub struct Shake256Prg<const OUTPUT_LEN: usize>;

impl<const OUTPUT_LEN: usize> GenericPrg for Shake256Prg<OUTPUT_LEN> {
    const INPUT_LENGTH: usize = 32;
    const OUTPUT_LENGTH: usize = OUTPUT_LEN;

    fn prg(seed: &[u8]) -> Vec<u8> {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        let mut output = vec![0u8; OUTPUT_LEN];
        hasher.finalize_xof().read(&mut output);
        output
    }
}

// Implementation of the new bis::Prg trait
impl<const OUTPUT_LEN: usize> crate::bis::Prg for Shake256Prg<OUTPUT_LEN> {
    fn generate<N: hybrid_array::ArraySize>(seed: &[u8]) -> hybrid_array::Array<u8, N> {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        let mut output = hybrid_array::Array::<u8, N>::default();
        hasher.finalize_xof().read(&mut output);
        output
    }
}
