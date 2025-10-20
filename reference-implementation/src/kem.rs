use hybrid_array::typenum::Unsigned;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore,
};
use rand::{CryptoRng, Rng};

pub type Seed = Vec<u8>;
pub type EncapsulationKey = Vec<u8>;
pub type DecapsulationKey = Vec<u8>;
pub type Ciphertext = Vec<u8>;
pub type SharedSecret = Vec<u8>;

pub trait SeedSize {
    const SEED_SIZE: usize;
}

pub trait SharedSecretSize {
    const SHARED_SECRET_SIZE: usize;
}

pub trait Kem: SeedSize + SharedSecretSize {
    const ENCAPS_RANDOMNESS_SIZE: usize;
    const ENCAPSULATION_KEY_SIZE: usize;
    const DECAPSULATION_KEY_SIZE: usize;
    const CIPHERTEXT_SIZE: usize;

    // Additional information about derived keys (e.g., subkeys)
    type KeyInfo;

    fn generate_key_pair(
        rng: &mut impl CryptoRng,
    ) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo);
    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext);
    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret;
}

/// Marker trait for traditional KEMs
pub trait TKem: Kem {}

/// Marker trait for post-quantum KEMs
pub trait PqKem: Kem {}

/// RNG wrapper to bridge between rand_core versions
pub(crate) struct RngWrapper<'a, R: rand::CryptoRng>(pub &'a mut R);

impl<'a, R> old_rand_core::RngCore for RngWrapper<'a, R>
where
    R: rand::CryptoRng,
{
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), old_rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<'a, R> old_rand_core::CryptoRng for RngWrapper<'a, R> where R: rand::CryptoRng {}

macro_rules! define_ml_kem {
    ($mlkem:ident, $params:ty) => {
        pub struct $mlkem;

        // Implementation of the bis traits
        impl SeedSize for $mlkem {
            const SEED_SIZE: usize = 64;
        }

        impl SharedSecretSize for $mlkem {
            const SHARED_SECRET_SIZE: usize = 32;
        }

        impl Kem for $mlkem {
            const ENCAPS_RANDOMNESS_SIZE: usize = 32;
            const ENCAPSULATION_KEY_SIZE: usize =
                <<ml_kem::$mlkem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize::USIZE;
            const DECAPSULATION_KEY_SIZE: usize = 64;
            const CIPHERTEXT_SIZE: usize = <ml_kem::$mlkem as KemCore>::CiphertextSize::USIZE;

            type KeyInfo = ();

            fn generate_key_pair(
                rng: &mut impl CryptoRng,
            ) -> (
                DecapsulationKey,
                EncapsulationKey,
                Self::KeyInfo,
            ) {
                use ml_kem::$mlkem;

                let mut d = ml_kem::B32::default();
                let mut z = ml_kem::B32::default();

                rng.fill(d.as_mut_slice());
                rng.fill(z.as_mut_slice());
                let (_dk_inner, ek_inner) = $mlkem::generate_deterministic(&d, &z);

                let dk = d.concat(z).to_vec();
                let ek = ek_inner.as_bytes().as_slice().to_vec();
                (dk, ek, ())
            }

            fn encaps(
                ek: &EncapsulationKey,
                rng: &mut impl rand::CryptoRng,
            ) -> (SharedSecret, Ciphertext) {
                assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
                let ek_inner: ml_kem::kem::EncapsulationKey<$params> =
                    ml_kem::kem::EncapsulationKey::from_bytes(ek.as_slice().try_into().expect("Invalid EK size"));
                let (ct_inner, ss_inner) = ek_inner
                    .encapsulate(&mut RngWrapper(rng))
                    .expect("Encapsulation failed");

                let ss = ss_inner.as_slice().to_vec();
                let ct = ct_inner.as_slice().to_vec();

                (ss, ct)
            }

            fn decaps(
                dk: &DecapsulationKey,
                ct: &Ciphertext,
            ) -> SharedSecret {
                use ml_kem::$mlkem;

                assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
                assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
                let d = ml_kem::B32::try_from(&dk[..32]).expect("Invalid DK slice");
                let z = ml_kem::B32::try_from(&dk[32..]).expect("Invalid DK slice");
                let (dk_inner, _ek_inner) = $mlkem::generate_deterministic(&d, &z);

                let ct_inner = ml_kem::Ciphertext::<$mlkem>::try_from(ct.as_slice()).expect("Invalid CT");
                let ss_inner = dk_inner
                    .decapsulate(&ct_inner)
                    .expect("Decapsulation failed");

                ss_inner.as_slice().to_vec()
            }
        }

        impl PqKem for $mlkem {}
    }
}

define_ml_kem! { MlKem512, ml_kem::MlKem512Params }
define_ml_kem! { MlKem768, ml_kem::MlKem768Params }
define_ml_kem! { MlKem1024, ml_kem::MlKem1024Params }

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::prg::AsTrivialPrg;

    fn test_deterministic_derivation<K: Kem>() {
        // Create test seed
        let seed: Vec<u8> = (0..K::SEED_SIZE)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(13))
            .collect();

        // Test deterministic key derivation
        let (dk1, ek1, _) = K::generate_key_pair(&mut seed.as_trivial_prg());
        let (dk2, ek2, _) = K::generate_key_pair(&mut seed.as_trivial_prg());

        assert_eq!(
            ek1, ek2,
            "Deterministic key derivation should produce same encapsulation key"
        );
        assert_eq!(
            dk1, dk2,
            "Deterministic key derivation should produce same decapsulation key"
        );

        // Test key sizes
        assert_eq!(
            dk1.len(),
            K::DECAPSULATION_KEY_SIZE,
            "Decapsulation key size mismatch"
        );
        assert_eq!(
            ek1.len(),
            K::ENCAPSULATION_KEY_SIZE,
            "Encapsulation key size mismatch"
        );
    }

    fn test_roundtrip<K: Kem>() {
        let mut rng = rand::rng();

        // Generate key pair
        let (dk, ek, _) = K::generate_key_pair(&mut rng);

        // Test encapsulation
        let (ss1, ct) = K::encaps(&ek, &mut rng);

        // Test sizes
        assert_eq!(ct.len(), K::CIPHERTEXT_SIZE, "Ciphertext size mismatch");
        assert_eq!(
            ss1.len(),
            K::SHARED_SECRET_SIZE,
            "Shared secret size mismatch"
        );

        // Test decapsulation
        let ss2 = K::decaps(&dk, &ct);

        assert_eq!(
            ss1, ss2,
            "Encapsulation and decapsulation should produce same shared secret"
        );

        // Test that different encapsulations produce different ciphertexts (with very high probability)
        let (_ss3, ct3) = K::encaps(&ek, &mut rng);
        let (_ss4, ct4) = K::encaps(&ek, &mut rng);

        // With proper randomness, ciphertexts should be different
        assert_ne!(
            ct3, ct4,
            "Different encapsulations should produce different ciphertexts"
        );
    }

    pub fn test_deterministic_encaps<K: Kem>() {
        // Generate key pair
        let mut rng = rand::rng();
        let (dk, ek, _) = K::generate_key_pair(&mut rng);

        // Create deterministic randomness
        let randomness = vec![42u8; K::ENCAPS_RANDOMNESS_SIZE];

        // Test deterministic encapsulation
        let (ss1, ct1) = K::encaps(&ek, &mut randomness.as_trivial_prg());
        let (ss2, ct2) = K::encaps(&ek, &mut randomness.as_trivial_prg());

        assert_eq!(
            ct1, ct2,
            "Deterministic encapsulation should produce same ciphertext"
        );
        assert_eq!(
            ss1, ss2,
            "Deterministic encapsulation should produce same shared secret"
        );

        // Test sizes
        assert_eq!(ct1.len(), K::CIPHERTEXT_SIZE, "Ciphertext size mismatch");
        assert_eq!(
            ss1.len(),
            K::SHARED_SECRET_SIZE,
            "Shared secret size mismatch"
        );

        // Test that it decapsulates correctly
        let ss3 = K::decaps(&dk, &ct1);

        assert_eq!(
            ss1, ss3,
            "Deterministic encapsulation should be compatible with decapsulation"
        );

        // Test that different randomness produces different outputs
        let randomness2 = vec![43u8; K::ENCAPS_RANDOMNESS_SIZE];
        let (ct4, ss4) = K::encaps(&ek, &mut randomness2.as_trivial_prg());

        assert_ne!(
            ct1, ct4,
            "Different randomness should produce different ciphertext"
        );
        assert_ne!(
            ss1, ss4,
            "Different randomness should produce different shared secret"
        );
    }

    pub fn test_all<K: Kem>() {
        test_deterministic_derivation::<K>();
        test_roundtrip::<K>();
        test_deterministic_encaps::<K>();
    }

    #[test]
    fn mlkem512() {
        test_all::<MlKem512>();
    }

    #[test]
    fn mlkem768() {
        test_all::<MlKem768>();
    }

    #[test]
    fn mlkem1024() {
        test_all::<MlKem1024>();
    }
}
