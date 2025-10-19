//! SHAKE256 PRG implementation

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// SHAKE256 based PRG with generic output length
pub struct Shake256Prg<const OUTPUT_LEN: usize>;

// Implementation of the bis::Prg trait
impl<const OUTPUT_LEN: usize> crate::hybrid::Prg for Shake256Prg<OUTPUT_LEN> {
    fn generate(seed: &[u8], output_len: usize) -> Vec<u8> {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        let mut output = vec![0u8; output_len];
        hasher.finalize_xof().read(&mut output);
        output
    }
}
