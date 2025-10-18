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
        use crate::bis::{Kem, MlKem768P256, Seed};
        use rand::Rng;

        let mut rng = rand::rng();

        // Generate key pair from random seed
        let mut seed = Seed::<MlKem768P256>::default();
        rng.fill(seed.as_mut_slice());

        let (dk, ek) = <MlKem768P256 as Kem>::derive_key_pair(seed);

        // Encapsulate
        let (ss1, ct) = <MlKem768P256 as Kem>::encaps(&ek, &mut rng);

        // Decapsulate
        let ss2 = <MlKem768P256 as Kem>::decaps(&dk, &ct);

        // Verify shared secrets match
        assert_eq!(ss1.as_slice(), ss2.as_slice());
    }

    #[test]
    fn test_bis_mlkem768_x25519() {
        use crate::bis::{Kem, MlKem768X25519, Seed};
        use rand::Rng;

        let mut rng = rand::rng();

        // Generate key pair from random seed
        let mut seed = Seed::<MlKem768X25519>::default();
        rng.fill(seed.as_mut_slice());

        let (dk, ek) = <MlKem768X25519 as Kem>::derive_key_pair(seed);

        // Encapsulate
        let (ss1, ct) = <MlKem768X25519 as Kem>::encaps(&ek, &mut rng);

        // Decapsulate
        let ss2 = <MlKem768X25519 as Kem>::decaps(&dk, &ct);

        // Verify shared secrets match
        assert_eq!(ss1.as_slice(), ss2.as_slice());
    }

    #[test]
    fn test_bis_mlkem1024_p384() {
        use crate::bis::{Kem, MlKem1024P384, Seed};
        use rand::Rng;

        let mut rng = rand::rng();

        // Generate key pair from random seed
        let mut seed = Seed::<MlKem1024P384>::default();
        rng.fill(seed.as_mut_slice());

        let (dk, ek) = <MlKem1024P384 as Kem>::derive_key_pair(seed);

        // Encapsulate
        let (ss1, ct) = <MlKem1024P384 as Kem>::encaps(&ek, &mut rng);

        // Decapsulate
        let ss2 = <MlKem1024P384 as Kem>::decaps(&dk, &ct);

        // Verify shared secrets match
        assert_eq!(ss1.as_slice(), ss2.as_slice());
    }

    // Deterministic tests with fixed seeds

    #[test]
    fn test_bis_mlkem768_p256_deterministic() {
        use crate::bis::{Kem, MlKem768P256, Seed};

        // Use a fixed seed
        let seed = Seed::<MlKem768P256>::from([0x42u8; 32]);

        // Derive key pair twice and verify they're identical
        let (dk1, ek1) = <MlKem768P256 as Kem>::derive_key_pair(seed);
        let (dk2, ek2) = <MlKem768P256 as Kem>::derive_key_pair(seed);

        assert_eq!(dk1.as_slice(), dk2.as_slice());
        assert_eq!(ek1.as_slice(), ek2.as_slice());
    }

    #[test]
    fn test_bis_mlkem768_x25519_deterministic() {
        use crate::bis::{Kem, MlKem768X25519, Seed};

        // Use a fixed seed
        let seed = Seed::<MlKem768X25519>::from([0x42u8; 32]);

        // Derive key pair twice and verify they're identical
        let (dk1, ek1) = <MlKem768X25519 as Kem>::derive_key_pair(seed);
        let (dk2, ek2) = <MlKem768X25519 as Kem>::derive_key_pair(seed);

        assert_eq!(dk1.as_slice(), dk2.as_slice());
        assert_eq!(ek1.as_slice(), ek2.as_slice());
    }

    #[test]
    fn test_bis_mlkem1024_p384_deterministic() {
        use crate::bis::{Kem, MlKem1024P384, Seed};

        // Use a fixed seed
        let seed = Seed::<MlKem1024P384>::from([0x42u8; 32]);

        // Derive key pair twice and verify they're identical
        let (dk1, ek1) = <MlKem1024P384 as Kem>::derive_key_pair(seed);
        let (dk2, ek2) = <MlKem1024P384 as Kem>::derive_key_pair(seed);

        assert_eq!(dk1.as_slice(), dk2.as_slice());
        assert_eq!(ek1.as_slice(), ek2.as_slice());
    }
}
