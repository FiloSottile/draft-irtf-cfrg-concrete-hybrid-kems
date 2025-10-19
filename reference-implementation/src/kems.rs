//! KEM implementations for ML-KEM

use crate::hybrid::{
    Ciphertext, DecapsulationKey, EncapsDerand, EncapsulationKey, Kem, PqKem, SeedSize,
    SharedSecret, SharedSecretSize,
};
use hybrid_array::typenum::Unsigned;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncapsulateDeterministic, EncodedSizeUser, KemCore,
};

/// RNG wrapper to bridge between rand_core versions
pub struct RngWrapper<'a, R: rand::CryptoRng>(pub &'a mut R);

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
            const ENCAPSULATION_KEY_SIZE: usize =
                <<ml_kem::$mlkem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize::USIZE;
            const DECAPSULATION_KEY_SIZE: usize = 64;
            const CIPHERTEXT_SIZE: usize = <ml_kem::$mlkem as KemCore>::CiphertextSize::USIZE;

            fn derive_key_pair(
                seed: &[u8],
            ) -> (
                DecapsulationKey,
                EncapsulationKey,
            ) {
                use ml_kem::$mlkem;

                assert_eq!(seed.len(), Self::SEED_SIZE);
                let d = ml_kem::B32::try_from(&seed[..32]).expect("Invalid seed slice");
                let z = ml_kem::B32::try_from(&seed[32..]).expect("Invalid seed slice");
                let (_dk_inner, ek_inner) = $mlkem::generate_deterministic(&d, &z);

                let ek = ek_inner.as_bytes().as_slice().to_vec();
                (seed.to_vec(), ek)
            }

            fn encaps(
                ek: &EncapsulationKey,
                rng: &mut impl rand::CryptoRng,
            ) -> (SharedSecret, crate::hybrid::Ciphertext) {
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

        impl EncapsDerand for $mlkem {
            const RANDOMNESS_SIZE: usize = 32;

            fn encaps_derand(
                ek: &EncapsulationKey,
                randomness: &[u8],
            ) -> (Ciphertext, crate::hybrid::SharedSecret) {
                assert_eq!(
                    ek.len(),
                    <Self as Kem>::ENCAPSULATION_KEY_SIZE
                );
                assert_eq!(randomness.len(), Self::RANDOMNESS_SIZE);

                let m = ml_kem::B32::try_from(randomness).expect("Invalid randomness length");

                let ek_inner: ml_kem::kem::EncapsulationKey<$params> =
                    ml_kem::kem::EncapsulationKey::from_bytes(
                        ek.as_slice().try_into().expect("Invalid EK size"),
                    );
                let (ct_inner, ss_inner) = ek_inner
                    .encapsulate_deterministic(&m)
                    .expect("Deterministic encapsulation failed");

                let ct = ct_inner.as_slice().to_vec();
                let ss = ss_inner.as_slice().to_vec();

                (ct, ss)
            }
        }
    }
}

define_ml_kem! { MlKem512, ml_kem::MlKem512Params }
define_ml_kem! { MlKem768, ml_kem::MlKem768Params }
define_ml_kem! { MlKem1024, ml_kem::MlKem1024Params }
