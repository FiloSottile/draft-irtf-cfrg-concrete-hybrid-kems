//! Integration tests for hybrid KEM instantiations

#[cfg(test)]
mod tests {
    // Tests for bis module instantiations

    #[test]
    fn test_mlkem768_p256() {
        use crate::hybrid::{Kem, MlKem768P256};

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
    fn test_mlkem768_x25519() {
        use crate::hybrid::{Kem, MlKem768X25519};

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
    fn test_mlkem1024_p384() {
        use crate::hybrid::{Kem, MlKem1024P384};

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
    fn test_mlkem768_p256_encaps_derand() {
        use crate::hybrid::{EncapsDerand, Kem, MlKem768P256};

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
    fn test_mlkem768_x25519_encaps_derand() {
        use crate::hybrid::{EncapsDerand, Kem, MlKem768X25519};

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
    fn test_mlkem1024_p384_encaps_derand() {
        use crate::hybrid::{EncapsDerand, Kem, MlKem1024P384};

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
    fn test_encaps_derand_randomness_sizes() {
        use crate::hybrid::{EncapsDerand, MlKem1024P384, MlKem768P256, MlKem768X25519};

        // Verify expected randomness sizes: PQ (32) + Group seed size
        assert_eq!(<MlKem768P256 as EncapsDerand>::RANDOMNESS_SIZE, 32 + 32); // P256 seed = 48
        assert_eq!(<MlKem768X25519 as EncapsDerand>::RANDOMNESS_SIZE, 32 + 32); // X25519 seed = 32
        assert_eq!(<MlKem1024P384 as EncapsDerand>::RANDOMNESS_SIZE, 32 + 48); // P384 seed = 72
    }

    // Comprehensive tests using test_utils

    #[test]
    fn test_kdf_all() {
        use crate::hybrid::test_utils::test_kdf_all;
        use crate::primitives::Sha3_256Kdf;

        test_kdf_all::<Sha3_256Kdf>();
    }

    #[test]
    fn test_prg_all() {
        use crate::hybrid::test_utils::test_prg_all;
        use crate::primitives::Shake256Prg;

        test_prg_all::<Shake256Prg<96>>();
        test_prg_all::<Shake256Prg<112>>();
        test_prg_all::<Shake256Prg<136>>();
    }

    #[test]
    fn test_group_p256_all() {
        use crate::groups::P256Group;
        use crate::hybrid::test_utils::test_group_all;

        test_group_all::<P256Group>();
    }

    #[test]
    fn test_group_p384_all() {
        use crate::groups::P384Group;
        use crate::hybrid::test_utils::test_group_all;

        test_group_all::<P384Group>();
    }

    #[test]
    fn test_group_x25519_all() {
        use crate::groups::X25519Group;
        use crate::hybrid::test_utils::test_group_all;

        test_group_all::<X25519Group>();
    }

    #[test]
    fn test_kem_mlkem512_all() {
        use crate::hybrid::test_utils::test_kem_all;
        use crate::kems::MlKem512;

        let mut rng = rand::rng();
        test_kem_all::<MlKem512, _>(&mut rng);
    }

    #[test]
    fn test_kem_mlkem768_all() {
        use crate::hybrid::test_utils::test_kem_all;
        use crate::kems::MlKem768;

        let mut rng = rand::rng();
        test_kem_all::<MlKem768, _>(&mut rng);
    }

    #[test]
    fn test_kem_mlkem1024_all() {
        use crate::hybrid::test_utils::test_kem_all;
        use crate::kems::MlKem1024;

        let mut rng = rand::rng();
        test_kem_all::<MlKem1024, _>(&mut rng);
    }

    #[test]
    fn test_hybrid_mlkem768_p256_all() {
        use crate::hybrid::test_utils::test_kem_all;
        use crate::hybrid::MlKem768P256;

        let mut rng = rand::rng();
        test_kem_all::<MlKem768P256, _>(&mut rng);
    }

    #[test]
    fn test_hybrid_mlkem768_x25519_all() {
        use crate::hybrid::test_utils::test_kem_all;
        use crate::hybrid::MlKem768X25519;

        let mut rng = rand::rng();
        test_kem_all::<MlKem768X25519, _>(&mut rng);
    }

    #[test]
    fn test_hybrid_mlkem1024_p384_all() {
        use crate::hybrid::test_utils::test_kem_all;
        use crate::hybrid::MlKem1024P384;

        let mut rng = rand::rng();
        test_kem_all::<MlKem1024P384, _>(&mut rng);
    }
}
