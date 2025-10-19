//! Integration tests for hybrid KEM instantiations

#[cfg(test)]
mod tests {
    use crate::generic::test_utils::test_kem_all;
    use crate::generic::traits::AsBytes;
    use crate::instantiations::{
        QsfP256MlKem768Shake256Sha3256, QsfP384MlKem1024Shake256Sha3256,
        QsfX25519MlKem768Shake256Sha3256,
    };

    #[test]
    fn test_qsf_p256_mlkem768() {
        let mut rng = rand::rng();
        test_kem_all::<QsfP256MlKem768Shake256Sha3256, _>(&mut rng);
    }

    #[test]
    fn test_qsf_x25519_mlkem768() {
        let mut rng = rand::rng();
        test_kem_all::<QsfX25519MlKem768Shake256Sha3256, _>(&mut rng);
    }

    #[test]
    fn test_qsf_p384_mlkem1024() {
        let mut rng = rand::rng();
        test_kem_all::<QsfP384MlKem1024Shake256Sha3256, _>(&mut rng);
    }

    // Tests for bis module instantiations

    #[test]
    fn test_bis_mlkem768_p256() {
        use crate::bis::{Kem, MlKem768P256};

        let mut rng = rand::rng();

        // Generate key pair from random seed
        let seed = vec![0x42u8; 32];
        let (dk, ek) = <MlKem768P256 as Kem>::derive_key_pair(&seed);

        // Verify sizes
        assert_eq!(dk.len(), <MlKem768P256 as Kem>::DECAPSULATION_KEY_SIZE);
        assert_eq!(ek.len(), <MlKem768P256 as Kem>::ENCAPSULATION_KEY_SIZE);

        // Encapsulate
        let (ss1, ct) = <MlKem768P256 as Kem>::encaps(&ek, &mut rng);

        // Verify sizes
        assert_eq!(ss1.len(), 32); // SHARED_SECRET_SIZE
        assert_eq!(ct.len(), <MlKem768P256 as Kem>::CIPHERTEXT_SIZE);

        // Decapsulate
        let ss2 = <MlKem768P256 as Kem>::decaps(&dk, &ct);

        // Verify size and equality
        assert_eq!(ss2.len(), 32);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_bis_mlkem768_x25519() {
        use crate::bis::{Kem, MlKem768X25519};

        let mut rng = rand::rng();

        // Generate key pair from random seed
        let seed = vec![0x42u8; 32];
        let (dk, ek) = <MlKem768X25519 as Kem>::derive_key_pair(&seed);

        // Verify sizes
        assert_eq!(dk.len(), <MlKem768X25519 as Kem>::DECAPSULATION_KEY_SIZE);
        assert_eq!(ek.len(), <MlKem768X25519 as Kem>::ENCAPSULATION_KEY_SIZE);

        // Encapsulate
        let (ss1, ct) = <MlKem768X25519 as Kem>::encaps(&ek, &mut rng);

        // Verify sizes
        assert_eq!(ss1.len(), 32); // SHARED_SECRET_SIZE
        assert_eq!(ct.len(), <MlKem768X25519 as Kem>::CIPHERTEXT_SIZE);

        // Decapsulate
        let ss2 = <MlKem768X25519 as Kem>::decaps(&dk, &ct);

        // Verify size and equality
        assert_eq!(ss2.len(), 32);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_bis_mlkem1024_p384() {
        use crate::bis::{Kem, MlKem1024P384};

        let mut rng = rand::rng();

        // Generate key pair from random seed
        let seed = vec![0x42u8; 32];
        let (dk, ek) = <MlKem1024P384 as Kem>::derive_key_pair(&seed);

        // Verify sizes
        assert_eq!(dk.len(), <MlKem1024P384 as Kem>::DECAPSULATION_KEY_SIZE);
        assert_eq!(ek.len(), <MlKem1024P384 as Kem>::ENCAPSULATION_KEY_SIZE);

        // Encapsulate
        let (ss1, ct) = <MlKem1024P384 as Kem>::encaps(&ek, &mut rng);

        // Verify sizes
        assert_eq!(ss1.len(), 32); // SHARED_SECRET_SIZE
        assert_eq!(ct.len(), <MlKem1024P384 as Kem>::CIPHERTEXT_SIZE);

        // Decapsulate
        let ss2 = <MlKem1024P384 as Kem>::decaps(&dk, &ct);

        // Verify size and equality
        assert_eq!(ss2.len(), 32);
        assert_eq!(ss1, ss2);
    }

    // Derandomized encapsulation tests

    #[test]
    fn test_bis_mlkem768_p256_encaps_derand() {
        use crate::bis::{EncapsDerand, Kem, MlKem768P256};

        // Generate key pair from random seed
        let seed = vec![0x42u8; 32];
        let (dk, ek) = <MlKem768P256 as Kem>::derive_key_pair(&seed);

        // Use deterministic randomness
        let randomness = vec![0x13u8; <MlKem768P256 as EncapsDerand>::RANDOMNESS_SIZE];

        // Encapsulate deterministically twice
        let (ct1, ss1) = <MlKem768P256 as EncapsDerand>::encaps_derand(&ek, &randomness);
        let (ct2, ss2) = <MlKem768P256 as EncapsDerand>::encaps_derand(&ek, &randomness);

        // Should produce identical results
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);

        // Verify sizes
        assert_eq!(ss1.len(), 32);
        assert_eq!(ct1.len(), <MlKem768P256 as Kem>::CIPHERTEXT_SIZE);

        // Decapsulate should recover the same shared secret
        let ss3 = <MlKem768P256 as Kem>::decaps(&dk, &ct1);
        assert_eq!(ss1, ss3);
    }

    #[test]
    fn test_bis_mlkem768_x25519_encaps_derand() {
        use crate::bis::{EncapsDerand, Kem, MlKem768X25519};

        // Generate key pair from random seed
        let seed = vec![0x42u8; 32];
        let (dk, ek) = <MlKem768X25519 as Kem>::derive_key_pair(&seed);

        // Use deterministic randomness
        let randomness = vec![0x13u8; <MlKem768X25519 as EncapsDerand>::RANDOMNESS_SIZE];

        // Encapsulate deterministically twice
        let (ct1, ss1) = <MlKem768X25519 as EncapsDerand>::encaps_derand(&ek, &randomness);
        let (ct2, ss2) = <MlKem768X25519 as EncapsDerand>::encaps_derand(&ek, &randomness);

        // Should produce identical results
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);

        // Verify sizes
        assert_eq!(ss1.len(), 32);
        assert_eq!(ct1.len(), <MlKem768X25519 as Kem>::CIPHERTEXT_SIZE);

        // Decapsulate should recover the same shared secret
        let ss3 = <MlKem768X25519 as Kem>::decaps(&dk, &ct1);
        assert_eq!(ss1, ss3);
    }

    #[test]
    fn test_bis_mlkem1024_p384_encaps_derand() {
        use crate::bis::{EncapsDerand, Kem, MlKem1024P384};

        // Generate key pair from random seed
        let seed = vec![0x42u8; 32];
        let (dk, ek) = <MlKem1024P384 as Kem>::derive_key_pair(&seed);

        // Use deterministic randomness
        let randomness = vec![0x13u8; <MlKem1024P384 as EncapsDerand>::RANDOMNESS_SIZE];

        // Encapsulate deterministically twice
        let (ct1, ss1) = <MlKem1024P384 as EncapsDerand>::encaps_derand(&ek, &randomness);
        let (ct2, ss2) = <MlKem1024P384 as EncapsDerand>::encaps_derand(&ek, &randomness);

        // Should produce identical results
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);

        // Verify sizes
        assert_eq!(ss1.len(), 32);
        assert_eq!(ct1.len(), <MlKem1024P384 as Kem>::CIPHERTEXT_SIZE);

        // Decapsulate should recover the same shared secret
        let ss3 = <MlKem1024P384 as Kem>::decaps(&dk, &ct1);
        assert_eq!(ss1, ss3);
    }

    #[test]
    fn test_bis_encaps_derand_randomness_sizes() {
        use crate::bis::{EncapsDerand, MlKem1024P384, MlKem768P256, MlKem768X25519};

        // Verify expected randomness sizes: PQ (32) + Group seed size
        assert_eq!(<MlKem768P256 as EncapsDerand>::RANDOMNESS_SIZE, 32 + 48); // P256 seed = 48
        assert_eq!(<MlKem768X25519 as EncapsDerand>::RANDOMNESS_SIZE, 32 + 32); // X25519 seed = 32
        assert_eq!(<MlKem1024P384 as EncapsDerand>::RANDOMNESS_SIZE, 32 + 72); // P384 seed = 72
    }

    // Comprehensive tests using test_utils

    #[test]
    fn test_bis_kdf_all() {
        use crate::bis::test_utils::test_kdf_all;
        use crate::primitives::Sha3_256Kdf;

        test_kdf_all::<Sha3_256Kdf>();
    }

    #[test]
    fn test_bis_prg_all() {
        use crate::bis::test_utils::test_prg_all;
        use crate::primitives::{Shake256Prg};

        test_prg_all::<Shake256Prg<96>>();
        test_prg_all::<Shake256Prg<112>>();
        test_prg_all::<Shake256Prg<136>>();
    }

    #[test]
    fn test_bis_group_p256_all() {
        use crate::bis::test_utils::test_group_all;
        use crate::groups::P256Group;

        test_group_all::<P256Group>();
    }

    #[test]
    fn test_bis_group_p384_all() {
        use crate::bis::test_utils::test_group_all;
        use crate::groups::P384Group;

        test_group_all::<P384Group>();
    }

    #[test]
    fn test_bis_group_x25519_all() {
        use crate::bis::test_utils::test_group_all;
        use crate::groups::X25519Group;

        test_group_all::<X25519Group>();
    }

    #[test]
    fn test_bis_kem_mlkem512_all() {
        use crate::bis::test_utils::test_kem_all;
        use crate::kems::MlKem512Kem;

        let mut rng = rand::rng();
        test_kem_all::<MlKem512Kem, _>(&mut rng);
    }

    #[test]
    fn test_bis_kem_mlkem768_all() {
        use crate::bis::test_utils::test_kem_all;
        use crate::kems::MlKem768Kem;

        let mut rng = rand::rng();
        test_kem_all::<MlKem768Kem, _>(&mut rng);
    }

    #[test]
    fn test_bis_kem_mlkem1024_all() {
        use crate::bis::test_utils::test_kem_all;
        use crate::kems::MlKem1024Kem;

        let mut rng = rand::rng();
        test_kem_all::<MlKem1024Kem, _>(&mut rng);
    }

    #[test]
    fn test_bis_hybrid_mlkem768_p256_all() {
        use crate::bis::test_utils::test_kem_all;
        use crate::bis::MlKem768P256;

        let mut rng = rand::rng();
        test_kem_all::<MlKem768P256, _>(&mut rng);
    }

    #[test]
    fn test_bis_hybrid_mlkem768_x25519_all() {
        use crate::bis::test_utils::test_kem_all;
        use crate::bis::MlKem768X25519;

        let mut rng = rand::rng();
        test_kem_all::<MlKem768X25519, _>(&mut rng);
    }

    #[test]
    fn test_bis_hybrid_mlkem1024_p384_all() {
        use crate::bis::test_utils::test_kem_all;
        use crate::bis::MlKem1024P384;

        let mut rng = rand::rng();
        test_kem_all::<MlKem1024P384, _>(&mut rng);
    }

    // Cross-compatibility tests between generic and bis implementations

    /// Helper function to test cross-compatibility between generic and bis hybrid KEM implementations
    fn test_hybrid_cross_compatibility<
        GenericKem: crate::generic::traits::Kem,
        BisKem: crate::bis::Kem + crate::bis::SeedSize + crate::bis::SharedSecretSize,
    >()
    where
        GenericKem::EncapsulationKey: crate::generic::traits::AsBytes,
        GenericKem::DecapsulationKey: crate::generic::traits::AsBytes,
        GenericKem::Ciphertext: crate::generic::traits::AsBytes + for<'a> From<&'a [u8]>,
        GenericKem::SharedSecret: crate::generic::traits::AsBytes,
    {
        let mut rng = rand::rng();

        // Generate a seed
        let seed = vec![0x42u8; BisKem::SEED_SIZE];

        println!("\n=== Testing Cross-Compatibility ===");
        println!("Seed: {}", hex::encode(&seed));

        // Test 1: Key derivation should produce identical keys
        println!("\n--- Test 1: Key Derivation Compatibility ---");
        let (generic_ek, generic_dk) =
            GenericKem::derive_key_pair(&seed).expect("Generic key derivation failed");
        let (bis_dk, bis_ek) = BisKem::derive_key_pair(&seed);

        let generic_ek_bytes = generic_ek.as_bytes();
        let generic_dk_bytes = generic_dk.as_bytes();

        println!("Generic EK: {}", hex::encode(generic_ek_bytes));
        println!("Bis EK:     {}", hex::encode(&bis_ek));
        println!("Generic DK: {}", hex::encode(generic_dk_bytes));
        println!("Bis DK:     {}", hex::encode(&bis_dk));

        assert_eq!(
            generic_ek_bytes,
            bis_ek.as_slice(),
            "Encapsulation keys should be identical"
        );
        assert_eq!(
            generic_dk_bytes,
            bis_dk.as_slice(),
            "Decapsulation keys should be identical"
        );

        // Test 2: Generic encaps -> Bis decaps
        println!("\n--- Test 2: Generic Encaps -> Bis Decaps ---");
        let (generic_ct, generic_ss) =
            GenericKem::encaps(&generic_ek, &mut rng).expect("Generic encapsulation failed");

        let generic_ct_bytes = generic_ct.as_bytes();
        let generic_ss_bytes = generic_ss.as_bytes();

        println!("Generic CT: {}", hex::encode(generic_ct_bytes));
        println!("Generic SS: {}", hex::encode(generic_ss_bytes));

        let generic_ct_vec = generic_ct_bytes.to_vec();
        let bis_ss = BisKem::decaps(&bis_dk, &generic_ct_vec);

        println!("Bis SS:     {}", hex::encode(&bis_ss));

        assert_eq!(
            generic_ss_bytes,
            bis_ss.as_slice(),
            "Shared secret from generic encaps should match bis decaps"
        );

        // Test 3: Bis encaps -> Generic decaps
        println!("\n--- Test 3: Bis Encaps -> Generic Decaps ---");
        let (bis_ss2, bis_ct) = BisKem::encaps(&bis_ek, &mut rng);

        println!("Bis CT: {}", hex::encode(&bis_ct));
        println!("Bis SS: {}", hex::encode(&bis_ss2));

        let generic_ct2 = GenericKem::Ciphertext::from(bis_ct.as_slice());
        let generic_ss2 = GenericKem::decaps(&generic_dk, &generic_ct2)
            .expect("Generic decapsulation failed");

        let generic_ss2_bytes = generic_ss2.as_bytes();

        println!("Generic SS: {}", hex::encode(generic_ss2_bytes));

        assert_eq!(
            bis_ss2.as_slice(),
            generic_ss2_bytes,
            "Shared secret from bis encaps should match generic decaps"
        );

        // Test 4: Verify sizes match
        println!("\n--- Test 4: Size Verification ---");
        assert_eq!(
            GenericKem::ENCAPSULATION_KEY_LENGTH,
            BisKem::ENCAPSULATION_KEY_SIZE,
            "Encapsulation key sizes should match"
        );
        assert_eq!(
            GenericKem::DECAPSULATION_KEY_LENGTH,
            BisKem::DECAPSULATION_KEY_SIZE,
            "Decapsulation key sizes should match"
        );
        assert_eq!(
            GenericKem::CIPHERTEXT_LENGTH,
            BisKem::CIPHERTEXT_SIZE,
            "Ciphertext sizes should match"
        );
        assert_eq!(
            GenericKem::SHARED_SECRET_LENGTH,
            BisKem::SHARED_SECRET_SIZE,
            "Shared secret sizes should match"
        );

        println!("\n=== All Cross-Compatibility Tests Passed ===\n");
    }

    #[test]
    fn test_hybrid_mlkem768_p256_cross_compatibility() {
        use crate::bis::MlKem768P256;
        use crate::instantiations::QsfP256MlKem768Shake256Sha3256;

        test_hybrid_cross_compatibility::<QsfP256MlKem768Shake256Sha3256, MlKem768P256>();
    }

    #[test]
    fn test_hybrid_mlkem768_x25519_cross_compatibility() {
        use crate::bis::MlKem768X25519;
        use crate::instantiations::QsfX25519MlKem768Shake256Sha3256;

        test_hybrid_cross_compatibility::<QsfX25519MlKem768Shake256Sha3256, MlKem768X25519>();
    }

    #[test]
    fn test_hybrid_mlkem1024_p384_cross_compatibility() {
        use crate::bis::MlKem1024P384;
        use crate::instantiations::QsfP384MlKem1024Shake256Sha3256;

        test_hybrid_cross_compatibility::<QsfP384MlKem1024Shake256Sha3256, MlKem1024P384>();
    }
}
