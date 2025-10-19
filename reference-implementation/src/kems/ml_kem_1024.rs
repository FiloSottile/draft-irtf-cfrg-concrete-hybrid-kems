//! ML-KEM-1024 implementation

use crate::bis::SeedSize;
use crate::utils::RngWrapper;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, EncapsulationKey},
    Ciphertext, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};

/// ML-KEM-1024 KEM implementation
pub struct MlKem1024Kem;

// Implementation of the bis traits
impl crate::bis::SeedSize for MlKem1024Kem {
    const SEED_SIZE: usize = 64;
}

impl crate::bis::SharedSecretSize for MlKem1024Kem {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl crate::bis::Kem for MlKem1024Kem {
    const ENCAPSULATION_KEY_SIZE: usize = 1568;
    const DECAPSULATION_KEY_SIZE: usize = 64;
    const CIPHERTEXT_SIZE: usize = 1568;

    fn derive_key_pair(
        seed: &[u8],
    ) -> (crate::bis::DecapsulationKey, crate::bis::EncapsulationKey) {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        let d = ml_kem::B32::try_from(&seed[..32]).expect("Invalid seed slice");
        let z = ml_kem::B32::try_from(&seed[32..]).expect("Invalid seed slice");
        let (_dk_inner, ek_inner) = MlKem1024::generate_deterministic(&d, &z);

        let ek = ek_inner.as_bytes().as_slice().to_vec();
        (seed.to_vec(), ek)
    }

    fn encaps(
        ek: &crate::bis::EncapsulationKey,
        rng: &mut impl rand::CryptoRng,
    ) -> (crate::bis::SharedSecret, crate::bis::Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        let ek_inner: EncapsulationKey<MlKem1024Params> =
            EncapsulationKey::from_bytes(ek.as_slice().try_into().expect("Invalid EK size"));
        let (ct_inner, ss_inner) = ek_inner
            .encapsulate(&mut RngWrapper(rng))
            .expect("Encapsulation failed");

        let ss = ss_inner.as_slice().to_vec();
        let ct = ct_inner.as_slice().to_vec();

        (ss, ct)
    }

    fn decaps(
        dk: &crate::bis::DecapsulationKey,
        ct: &crate::bis::Ciphertext,
    ) -> crate::bis::SharedSecret {
        assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
        assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
        let d = ml_kem::B32::try_from(&dk[..32]).expect("Invalid DK slice");
        let z = ml_kem::B32::try_from(&dk[32..]).expect("Invalid DK slice");
        let (dk_inner, _ek_inner) = MlKem1024::generate_deterministic(&d, &z);

        let ct_inner = Ciphertext::<MlKem1024>::try_from(ct.as_slice()).expect("Invalid CT");
        let ss_inner = dk_inner
            .decapsulate(&ct_inner)
            .expect("Decapsulation failed");

        ss_inner.as_slice().to_vec()
    }
}

impl crate::bis::PqKem for MlKem1024Kem {}

impl crate::bis::EncapsDerand for MlKem1024Kem {
    const RANDOMNESS_SIZE: usize = 32;

    fn encaps_derand(
        ek: &crate::bis::EncapsulationKey,
        randomness: &[u8],
    ) -> (crate::bis::Ciphertext, crate::bis::SharedSecret) {
        assert_eq!(ek.len(), <Self as crate::bis::Kem>::ENCAPSULATION_KEY_SIZE);
        assert_eq!(randomness.len(), Self::RANDOMNESS_SIZE);

        let m = ml_kem::B32::try_from(randomness).expect("Invalid randomness length");

        let ek_inner: ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params> =
            ml_kem::kem::EncapsulationKey::from_bytes(ek.as_slice().try_into().expect("Invalid EK size"));
        let (ct_inner, ss_inner) = ek_inner
            .encapsulate_deterministic(&m)
            .expect("Deterministic encapsulation failed");

        let ct = ct_inner.as_slice().to_vec();
        let ss = ss_inner.as_slice().to_vec();

        (ct, ss)
    }
}
