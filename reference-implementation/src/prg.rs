use sha3::digest::{ExtendableOutput, Update, XofReader};

pub trait Prg {
    fn generate(seed: &[u8], output: &mut [u8]);
}

/// SHAKE256 based PRG with generic output length
pub struct Shake256;

// Implementation of the bis::Prg trait
impl Prg for Shake256 {
    fn generate(seed: &[u8], output: &mut [u8]) {
        let mut hasher = sha3::Shake256::default();
        hasher.update(seed);
        hasher.finalize_xof().read(output);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    pub fn test_all<P: Prg>() {
        // Create test seed
        let seed: Vec<u8> = (0..32)
            .map(|i| (i as u8).wrapping_mul(23).wrapping_add(77))
            .collect();

        // Test that the whole output is filled
        let canary = 0xA0;
        let mut output = [canary; 128];
        P::generate(&seed, &mut output);
        let count = output.iter().filter(|x| **x == canary).count();
        assert!(count < 2, "PRG incomplete fill");

        // Test determinism
        let mut output2 = [0; 128];
        P::generate(&seed, &mut output2);
        assert_eq!(output, output2, "PRG should be deterministic");

        // Test different seeds produce different outputs
        let mut seed2 = seed.clone();
        seed2[0] = seed2[0].wrapping_add(1);
        P::generate(&seed2, &mut output2);
        assert_ne!(
            output, output2,
            "Different seeds should produce different outputs"
        );
    }

    #[test]
    fn shake256() {
        test_all::<Shake256>();
    }
}
