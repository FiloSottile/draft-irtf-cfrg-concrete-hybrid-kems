//! SHAKE256 PRG implementation

use crate::generic::traits::Prg;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// SHAKE256 based PRG with generic output length
pub struct Shake256Prg<const OUTPUT_LEN: usize>;

impl<const OUTPUT_LEN: usize> Prg for Shake256Prg<OUTPUT_LEN> {
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
