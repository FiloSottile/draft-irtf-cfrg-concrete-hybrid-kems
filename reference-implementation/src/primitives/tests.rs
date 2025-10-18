//! Tests for cryptographic primitives

#[cfg(test)]
mod tests {
    use crate::generic::test_utils::{test_kdf_all, test_prg_all};
    use crate::primitives::{Sha3_256Kdf, Shake256Prg};

    #[test]
    fn test_sha3_256_kdf() {
        test_kdf_all::<Sha3_256Kdf>();
    }

    #[test]
    fn test_shake256_prg() {
        // Test with output length of 64 bytes (common case)
        test_prg_all::<Shake256Prg<64>>();
    }

    // Cross-compatibility tests between old (generic) and new (bis) trait implementations

    #[test]
    fn test_kdf_cross_compatibility() {
        use crate::bis::Kdf as BisKdf;
        use crate::generic::traits::Kdf as GenericKdf;

        // Test with various inputs
        let test_inputs = vec![
            vec![0u8; 32],
            vec![0xFF; 32],
            (0..32).collect::<Vec<u8>>(),
            vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
        ];

        for input in test_inputs {
            // Call old implementation
            let old_output = Sha3_256Kdf::kdf(&input);

            // Call new implementation
            let new_output = Sha3_256Kdf::compute(input.iter().cloned());

            // Verify outputs match
            assert_eq!(
                old_output,
                new_output.as_slice(),
                "KDF outputs should match for input: {:?}",
                input
            );
        }
    }

    #[test]
    fn test_prg_cross_compatibility() {
        use crate::bis::Prg as BisPrg;
        use crate::generic::traits::Prg as GenericPrg;
        use hybrid_array::typenum::U64;

        // Test with various seeds
        let test_seeds = vec![
            vec![0u8; 32],
            vec![0xFF; 32],
            (0..32).collect::<Vec<u8>>(),
            vec![
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab, 0xcd, 0xef,
            ],
        ];

        for seed in test_seeds {
            // Call old implementation
            let old_output = Shake256Prg::<64>::prg(&seed);

            // Call new implementation
            let new_output: hybrid_array::Array<u8, U64> = Shake256Prg::<64>::generate(&seed);

            // Verify outputs match
            assert_eq!(
                old_output.as_slice(),
                new_output.as_slice(),
                "PRG outputs should match for seed: {:?}",
                seed
            );
        }
    }
}
