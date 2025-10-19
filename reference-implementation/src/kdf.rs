use sha3::Digest;

pub type Output = Vec<u8>;

pub trait Kdf {
    const OUTPUT_SIZE: usize;

    fn compute(input: impl Iterator<Item = u8>) -> Output;
}

/// SHA3-256 based KDF
pub struct Sha3_256;

// Implementation of the bis::Kdf trait
impl Kdf for Sha3_256 {
    const OUTPUT_SIZE: usize = 32;

    fn compute(input: impl Iterator<Item = u8>) -> Output {
        let input: Vec<u8> = input.collect();
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(&input);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    pub fn test_kdf_basic<K: Kdf>() {
        // Create test input
        let input: Vec<u8> = (0..100)
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(42))
            .collect();

        // Test output length
        let output = K::compute(input.iter().cloned());
        assert_eq!(output.len(), K::OUTPUT_SIZE, "KDF output length mismatch");

        // Test determinism
        let output2 = K::compute(input.iter().cloned());
        assert_eq!(output, output2, "KDF should be deterministic");

        // Test different inputs produce different outputs
        let mut input2 = input.clone();
        input2[0] = input2[0].wrapping_add(1);
        let output3 = K::compute(input2.iter().cloned());
        assert_ne!(
            output, output3,
            "Different inputs should produce different outputs"
        );
    }

    #[test]
    fn sha3_256() {
        test_kdf_basic::<Sha3_256>();
    }
}
