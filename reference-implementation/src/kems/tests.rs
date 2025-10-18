//! Tests for KEM implementations

#[cfg(test)]
mod tests {
    use crate::generic::test_utils::test_kem_all;
    use crate::kems::{MlKem1024Kem, MlKem512Kem, MlKem768Kem};

    #[test]
    fn test_ml_kem_512() {
        let mut rng = rand::rng();
        test_kem_all::<MlKem512Kem, _>(&mut rng);
    }

    #[test]
    fn test_ml_kem_768() {
        let mut rng = rand::rng();
        test_kem_all::<MlKem768Kem, _>(&mut rng);
    }

    #[test]
    fn test_ml_kem_1024() {
        let mut rng = rand::rng();
        test_kem_all::<MlKem1024Kem, _>(&mut rng);
    }

    // Cross-compatibility tests between old (generic) and new (bis) trait implementations

    #[test]
    fn test_ml_kem_512_cross_compatibility() {
        use crate::bis::Kem as BisKem;
        use crate::generic::traits::{AsBytes, EncapsDerand, Kem as GenericKem};

        let test_seeds = vec![
            vec![0u8; 64],
            vec![0xFF; 64],
            (0..64).collect::<Vec<u8>>(),
        ];

        for seed in test_seeds {
            // Test 1: Same seed should produce same encapsulation key
            let (old_ek, old_dk) = <MlKem512Kem as GenericKem>::derive_key_pair(&seed).unwrap();
            let (new_dk, new_ek) = <MlKem512Kem as BisKem>::derive_key_pair(
                seed.as_slice().try_into().expect("Invalid seed length"),
            );

            assert_eq!(
                old_ek.as_bytes(),
                new_ek.as_slice(),
                "Encapsulation keys should match for seed: {:?}",
                &seed[..8]
            );

            // Test 2: Old ciphertext can be decapped by new implementation
            let randomness = vec![0x42; 32];
            let (old_ct, old_ss) = MlKem512Kem::encaps_derand(&old_ek, &randomness).unwrap();

            let new_ct_bytes: &[u8] = old_ct.as_bytes();
            let new_ct = new_ct_bytes.try_into().expect("Invalid ciphertext size");
            let new_ss = <MlKem512Kem as BisKem>::decaps(&new_dk, &new_ct);

            assert_eq!(
                old_ss.as_bytes(),
                new_ss.as_slice(),
                "Shared secrets should match (old CT -> new decaps)"
            );

            // Test 3: New ciphertext can be decapped by old implementation
            // Use deterministic encapsulation for reproducibility
            let mut rng = crate::utils::FixedRng::new(&randomness);
            let (new_ss2, new_ct2) = <MlKem512Kem as BisKem>::encaps(&new_ek, &mut rng);

            // Convert new ciphertext to old format
            let old_ct2 = crate::kems::ml_kem_512::MlKem512Ciphertext::from(new_ct2.as_slice());
            let old_ss2 = <MlKem512Kem as GenericKem>::decaps(&old_dk, &old_ct2).unwrap();

            assert_eq!(
                new_ss2.as_slice(),
                old_ss2.as_bytes(),
                "Shared secrets should match (new CT -> old decaps)"
            );

            // Test 4: Verify bidirectional compatibility
            assert_eq!(
                old_ss.as_bytes(),
                new_ss2.as_slice(),
                "All shared secrets should match"
            );
        }
    }

    #[test]
    fn test_ml_kem_768_cross_compatibility() {
        use crate::bis::Kem as BisKem;
        use crate::generic::traits::{AsBytes, EncapsDerand, Kem as GenericKem};

        let test_seeds = vec![
            vec![0u8; 64],
            vec![0xFF; 64],
            (0..64).collect::<Vec<u8>>(),
        ];

        for seed in test_seeds {
            // Test 1: Same seed should produce same encapsulation key
            let (old_ek, old_dk) = <MlKem768Kem as GenericKem>::derive_key_pair(&seed).unwrap();
            let (new_dk, new_ek) = <MlKem768Kem as BisKem>::derive_key_pair(
                seed.as_slice().try_into().expect("Invalid seed length"),
            );

            assert_eq!(
                old_ek.as_bytes(),
                new_ek.as_slice(),
                "Encapsulation keys should match for seed: {:?}",
                &seed[..8]
            );

            // Test 2: Old ciphertext can be decapped by new implementation
            let randomness = vec![0x42; 32];
            let (old_ct, old_ss) = MlKem768Kem::encaps_derand(&old_ek, &randomness).unwrap();

            let new_ct_bytes: &[u8] = old_ct.as_bytes();
            let new_ct = new_ct_bytes.try_into().expect("Invalid ciphertext size");
            let new_ss = <MlKem768Kem as BisKem>::decaps(&new_dk, &new_ct);

            assert_eq!(
                old_ss.as_bytes(),
                new_ss.as_slice(),
                "Shared secrets should match (old CT -> new decaps)"
            );

            // Test 3: New ciphertext can be decapped by old implementation
            let mut rng = crate::utils::FixedRng::new(&randomness);
            let (new_ss2, new_ct2) = <MlKem768Kem as BisKem>::encaps(&new_ek, &mut rng);

            let old_ct2 = crate::kems::ml_kem_768::MlKem768Ciphertext::from(new_ct2.as_slice());
            let old_ss2 = <MlKem768Kem as GenericKem>::decaps(&old_dk, &old_ct2).unwrap();

            assert_eq!(
                new_ss2.as_slice(),
                old_ss2.as_bytes(),
                "Shared secrets should match (new CT -> old decaps)"
            );

            // Test 4: Verify bidirectional compatibility
            assert_eq!(
                old_ss.as_bytes(),
                new_ss2.as_slice(),
                "All shared secrets should match"
            );
        }
    }

    #[test]
    fn test_ml_kem_1024_cross_compatibility() {
        use crate::bis::Kem as BisKem;
        use crate::generic::traits::{AsBytes, EncapsDerand, Kem as GenericKem};

        let test_seeds = vec![
            vec![0u8; 64],
            vec![0xFF; 64],
            (0..64).collect::<Vec<u8>>(),
        ];

        for seed in test_seeds {
            // Test 1: Same seed should produce same encapsulation key
            let (old_ek, old_dk) = <MlKem1024Kem as GenericKem>::derive_key_pair(&seed).unwrap();
            let (new_dk, new_ek) = <MlKem1024Kem as BisKem>::derive_key_pair(
                seed.as_slice().try_into().expect("Invalid seed length"),
            );

            assert_eq!(
                old_ek.as_bytes(),
                new_ek.as_slice(),
                "Encapsulation keys should match for seed: {:?}",
                &seed[..8]
            );

            // Test 2: Old ciphertext can be decapped by new implementation
            let randomness = vec![0x42; 32];
            let (old_ct, old_ss) = MlKem1024Kem::encaps_derand(&old_ek, &randomness).unwrap();

            let new_ct_bytes: &[u8] = old_ct.as_bytes();
            let new_ct = new_ct_bytes.try_into().expect("Invalid ciphertext size");
            let new_ss = <MlKem1024Kem as BisKem>::decaps(&new_dk, &new_ct);

            assert_eq!(
                old_ss.as_bytes(),
                new_ss.as_slice(),
                "Shared secrets should match (old CT -> new decaps)"
            );

            // Test 3: New ciphertext can be decapped by old implementation
            let mut rng = crate::utils::FixedRng::new(&randomness);
            let (new_ss2, new_ct2) = <MlKem1024Kem as BisKem>::encaps(&new_ek, &mut rng);

            let old_ct2 = crate::kems::ml_kem_1024::MlKem1024Ciphertext::from(new_ct2.as_slice());
            let old_ss2 = <MlKem1024Kem as GenericKem>::decaps(&old_dk, &old_ct2).unwrap();

            assert_eq!(
                new_ss2.as_slice(),
                old_ss2.as_bytes(),
                "Shared secrets should match (new CT -> old decaps)"
            );

            // Test 4: Verify bidirectional compatibility
            assert_eq!(
                old_ss.as_bytes(),
                new_ss2.as_slice(),
                "All shared secrets should match"
            );
        }
    }
}
