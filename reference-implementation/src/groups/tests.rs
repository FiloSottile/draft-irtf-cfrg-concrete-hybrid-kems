//! Tests for nominal group implementations

#[cfg(test)]
mod tests {
    use crate::generic::test_utils::test_group_all;
    use crate::groups::{P256Group, P384Group, X25519Group};

    #[test]
    fn test_p256_group() {
        test_group_all::<P256Group>();
    }

    #[test]
    fn test_p384_group() {
        test_group_all::<P384Group>();
    }

    #[test]
    fn test_x25519_group() {
        test_group_all::<X25519Group>();
    }

    // Cross-compatibility tests between old (generic) and new (bis) trait implementations

    #[test]
    fn test_p256_group_cross_compatibility() {
        use crate::bis::NominalGroup as BisGroup;
        use crate::generic::traits::{AsBytes, NominalGroup as GenericGroup};

        // Test 1: Generator should be the same
        let old_gen = <P256Group as GenericGroup>::generator();
        let new_gen = <P256Group as BisGroup>::G;
        assert_eq!(
            old_gen.as_bytes(),
            new_gen.as_slice(),
            "Generators should be identical"
        );

        // Test 2: Same seed should produce same scalar
        let test_seeds = vec![
            vec![0u8; 48],
            vec![0xFF; 48],
            (0..48).collect::<Vec<u8>>(),
        ];

        for seed in test_seeds {
            let old_scalar = <P256Group as GenericGroup>::random_scalar(&seed).unwrap();
            let new_scalar = <P256Group as BisGroup>::random_scalar(
                seed.as_slice().try_into().expect("Invalid seed length"),
            );
            assert_eq!(
                old_scalar.as_bytes(),
                new_scalar.as_slice(),
                "Scalars should match for seed: {:?}",
                seed
            );
        }

        // Test 3: Same scalar and element should produce same exponentiation result
        let seed = vec![0x42; 48];
        let old_scalar = <P256Group as GenericGroup>::random_scalar(&seed).unwrap();
        let new_scalar = <P256Group as BisGroup>::random_scalar(
            seed.as_slice().try_into().expect("Invalid seed length"),
        );

        let old_gen = <P256Group as GenericGroup>::generator();
        let new_gen = <P256Group as BisGroup>::G;

        let old_result = <P256Group as GenericGroup>::exp(&old_gen, &old_scalar);
        let new_result = <P256Group as BisGroup>::exp(&new_gen, &new_scalar);

        assert_eq!(
            old_result.as_bytes(),
            new_result.as_slice(),
            "Exponentiation results should match"
        );

        // Test 4: Same element should produce same shared secret
        let old_ss = <P256Group as GenericGroup>::element_to_shared_secret(&old_result);
        let new_ss = <P256Group as BisGroup>::element_to_shared_secret(new_result);

        assert_eq!(
            old_ss.as_slice(),
            new_ss.as_slice(),
            "Shared secrets should match"
        );
    }

    #[test]
    fn test_p384_group_cross_compatibility() {
        use crate::bis::NominalGroup as BisGroup;
        use crate::generic::traits::{AsBytes, NominalGroup as GenericGroup};

        // Test 1: Generator should be the same
        let old_gen = <P384Group as GenericGroup>::generator();
        let new_gen = <P384Group as BisGroup>::G;
        assert_eq!(
            old_gen.as_bytes(),
            new_gen.as_slice(),
            "Generators should be identical"
        );

        // Test 2: Same seed should produce same scalar
        let test_seeds = vec![
            vec![0u8; 72],
            vec![0xFF; 72],
            (0..72).collect::<Vec<u8>>(),
        ];

        for seed in test_seeds {
            let old_scalar = <P384Group as GenericGroup>::random_scalar(&seed).unwrap();
            let new_scalar = <P384Group as BisGroup>::random_scalar(
                seed.as_slice().try_into().expect("Invalid seed length"),
            );
            assert_eq!(
                old_scalar.as_bytes(),
                new_scalar.as_slice(),
                "Scalars should match for seed: {:?}",
                seed
            );
        }

        // Test 3: Same scalar and element should produce same exponentiation result
        let seed = vec![0x42; 72];
        let old_scalar = <P384Group as GenericGroup>::random_scalar(&seed).unwrap();
        let new_scalar = <P384Group as BisGroup>::random_scalar(
            seed.as_slice().try_into().expect("Invalid seed length"),
        );

        let old_gen = <P384Group as GenericGroup>::generator();
        let new_gen = <P384Group as BisGroup>::G;

        let old_result = <P384Group as GenericGroup>::exp(&old_gen, &old_scalar);
        let new_result = <P384Group as BisGroup>::exp(&new_gen, &new_scalar);

        assert_eq!(
            old_result.as_bytes(),
            new_result.as_slice(),
            "Exponentiation results should match"
        );

        // Test 4: Same element should produce same shared secret
        let old_ss = <P384Group as GenericGroup>::element_to_shared_secret(&old_result);
        let new_ss = <P384Group as BisGroup>::element_to_shared_secret(new_result);

        assert_eq!(
            old_ss.as_slice(),
            new_ss.as_slice(),
            "Shared secrets should match"
        );
    }

    #[test]
    fn test_x25519_group_cross_compatibility() {
        use crate::bis::NominalGroup as BisGroup;
        use crate::generic::traits::{AsBytes, NominalGroup as GenericGroup};

        // Test 1: Generator should be the same
        let old_gen = <X25519Group as GenericGroup>::generator();
        let new_gen = <X25519Group as BisGroup>::G;
        assert_eq!(
            old_gen.as_bytes(),
            new_gen.as_slice(),
            "Generators should be identical"
        );

        // Test 2: Same seed should produce same scalar
        let test_seeds = vec![
            vec![0u8; 32],
            vec![0xFF; 32],
            (0..32).collect::<Vec<u8>>(),
        ];

        for seed in test_seeds {
            let old_scalar = <X25519Group as GenericGroup>::random_scalar(&seed).unwrap();
            let new_scalar = <X25519Group as BisGroup>::random_scalar(
                seed.as_slice().try_into().expect("Invalid seed length"),
            );
            assert_eq!(
                old_scalar.as_bytes(),
                new_scalar.as_slice(),
                "Scalars should match for seed: {:?}",
                seed
            );
        }

        // Test 3: Same scalar and element should produce same exponentiation result
        let seed = vec![0x42; 32];
        let old_scalar = <X25519Group as GenericGroup>::random_scalar(&seed).unwrap();
        let new_scalar = <X25519Group as BisGroup>::random_scalar(
            seed.as_slice().try_into().expect("Invalid seed length"),
        );

        let old_gen = <X25519Group as GenericGroup>::generator();
        let new_gen = <X25519Group as BisGroup>::G;

        let old_result = <X25519Group as GenericGroup>::exp(&old_gen, &old_scalar);
        let new_result = <X25519Group as BisGroup>::exp(&new_gen, &new_scalar);

        assert_eq!(
            old_result.as_bytes(),
            new_result.as_slice(),
            "Exponentiation results should match"
        );

        // Test 4: Same element should produce same shared secret
        let old_ss = <X25519Group as GenericGroup>::element_to_shared_secret(&old_result);
        let new_ss = <X25519Group as BisGroup>::element_to_shared_secret(new_result);

        assert_eq!(
            old_ss.as_slice(),
            new_ss.as_slice(),
            "Shared secrets should match"
        );
    }
}
