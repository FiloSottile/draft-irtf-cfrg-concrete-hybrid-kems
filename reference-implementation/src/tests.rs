//! Integration tests for hybrid KEM instantiations

#[cfg(test)]
mod tests {
    use crate::generic::test_utils::test_kem_all;
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

    // Deterministic tests with fixed seeds

    #[test]
    fn test_bis_mlkem768_p256_sizes() {
        use crate::bis::{Kem, MlKem768P256, SeedSize, SharedSecretSize};

        // Verify expected sizes
        assert_eq!(<MlKem768P256 as SeedSize>::SEED_SIZE, 32);
        assert_eq!(<MlKem768P256 as SharedSecretSize>::SHARED_SECRET_SIZE, 32);
        assert_eq!(<MlKem768P256 as Kem>::DECAPSULATION_KEY_SIZE, 32);
        assert_eq!(<MlKem768P256 as Kem>::ENCAPSULATION_KEY_SIZE, 1184 + 65); // ML-KEM-768 + P256
        assert_eq!(<MlKem768P256 as Kem>::CIPHERTEXT_SIZE, 1088 + 65); // ML-KEM-768 + P256
    }

    #[test]
    fn test_bis_mlkem768_x25519_sizes() {
        use crate::bis::{Kem, MlKem768X25519, SeedSize, SharedSecretSize};

        // Verify expected sizes
        assert_eq!(<MlKem768X25519 as SeedSize>::SEED_SIZE, 32);
        assert_eq!(<MlKem768X25519 as SharedSecretSize>::SHARED_SECRET_SIZE, 32);
        assert_eq!(<MlKem768X25519 as Kem>::DECAPSULATION_KEY_SIZE, 32);
        assert_eq!(<MlKem768X25519 as Kem>::ENCAPSULATION_KEY_SIZE, 1184 + 32); // ML-KEM-768 + X25519
        assert_eq!(<MlKem768X25519 as Kem>::CIPHERTEXT_SIZE, 1088 + 32); // ML-KEM-768 + X25519
    }

    #[test]
    fn test_bis_mlkem1024_p384_sizes() {
        use crate::bis::{Kem, MlKem1024P384, SeedSize, SharedSecretSize};

        // Verify expected sizes
        assert_eq!(<MlKem1024P384 as SeedSize>::SEED_SIZE, 32);
        assert_eq!(<MlKem1024P384 as SharedSecretSize>::SHARED_SECRET_SIZE, 32);
        assert_eq!(<MlKem1024P384 as Kem>::DECAPSULATION_KEY_SIZE, 32);
        assert_eq!(<MlKem1024P384 as Kem>::ENCAPSULATION_KEY_SIZE, 1568 + 97); // ML-KEM-1024 + P384
        assert_eq!(<MlKem1024P384 as Kem>::CIPHERTEXT_SIZE, 1568 + 97); // ML-KEM-1024 + P384
    }
}
