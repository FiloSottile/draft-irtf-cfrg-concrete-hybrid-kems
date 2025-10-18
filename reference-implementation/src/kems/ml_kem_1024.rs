//! ML-KEM-1024 implementation

use crate::bis::SeedSize;
use crate::generic::{
    error::KemError,
    traits::{AsBytes, EncapsDerand, Kem},
};
use crate::utils::RngWrapper;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, EncapsulationKey},
    Ciphertext, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};

/// ML-KEM-1024 KEM implementation
pub struct MlKem1024Kem;

/// Wrapper for ML-KEM-1024 encapsulation key
pub struct MlKem1024EncapsulationKey {
    bytes: Vec<u8>,
}

/// Wrapper for ML-KEM-1024 decapsulation key  
pub struct MlKem1024DecapsulationKey {
    seed: Vec<u8>,
}

/// Wrapper for ML-KEM-1024 ciphertext
pub struct MlKem1024Ciphertext {
    bytes: Vec<u8>,
}

/// Wrapper for ML-KEM-1024 shared secret
pub struct MlKem1024SharedSecret {
    bytes: Vec<u8>,
}

impl AsBytes for MlKem1024EncapsulationKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for MlKem1024EncapsulationKey {
    fn from(bytes: &[u8]) -> Self {
        MlKem1024EncapsulationKey {
            bytes: bytes.to_vec(),
        }
    }
}

impl AsBytes for MlKem1024DecapsulationKey {
    fn as_bytes(&self) -> &[u8] {
        &self.seed
    }
}

impl From<&[u8]> for MlKem1024DecapsulationKey {
    fn from(seed: &[u8]) -> Self {
        MlKem1024DecapsulationKey {
            seed: seed.to_vec(),
        }
    }
}

impl MlKem1024DecapsulationKey {
    fn generate_keys_from_seed(
        &self,
    ) -> (
        ml_kem::kem::DecapsulationKey<MlKem1024Params>,
        ml_kem::kem::EncapsulationKey<MlKem1024Params>,
    ) {
        let d = ml_kem::B32::try_from(&self.seed[..32]).unwrap();
        let z = ml_kem::B32::try_from(&self.seed[32..]).unwrap();
        MlKem1024::generate_deterministic(&d, &z)
    }

    fn decapsulation_key(&self) -> ml_kem::kem::DecapsulationKey<MlKem1024Params> {
        self.generate_keys_from_seed().0
    }

    fn encapsulation_key(&self) -> ml_kem::kem::EncapsulationKey<MlKem1024Params> {
        self.generate_keys_from_seed().1
    }
}

impl AsBytes for MlKem1024Ciphertext {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for MlKem1024Ciphertext {
    fn from(bytes: &[u8]) -> Self {
        MlKem1024Ciphertext {
            bytes: bytes.to_vec(),
        }
    }
}

impl AsBytes for MlKem1024SharedSecret {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Kem for MlKem1024Kem {
    const SEED_LENGTH: usize = 64;
    const ENCAPSULATION_KEY_LENGTH: usize = 1568;
    const DECAPSULATION_KEY_LENGTH: usize = 64;
    const CIPHERTEXT_LENGTH: usize = 1568;
    const SHARED_SECRET_LENGTH: usize = 32;

    type EncapsulationKey = MlKem1024EncapsulationKey;
    type DecapsulationKey = MlKem1024DecapsulationKey;
    type Ciphertext = MlKem1024Ciphertext;
    type SharedSecret = MlKem1024SharedSecret;

    fn generate_key_pair<R: rand::CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError> {
        let mut seed = [0u8; 64];
        rand::RngCore::fill_bytes(rng, &mut seed);
        Self::derive_key_pair(&seed)
    }

    fn derive_key_pair(
        seed: &[u8],
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError> {
        if seed.len() != Self::SEED_LENGTH {
            return Err(KemError::InvalidInputLength);
        }

        let dk = MlKem1024DecapsulationKey {
            seed: seed.to_vec(),
        };
        let ek_inner = dk.encapsulation_key();

        Ok((
            MlKem1024EncapsulationKey {
                bytes: ek_inner.as_bytes().to_vec(),
            },
            dk,
        ))
    }

    fn encaps<R: rand::CryptoRng>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        let ek_inner: EncapsulationKey<MlKem1024Params> =
            EncapsulationKey::from_bytes(ek.bytes.as_slice().try_into().unwrap());
        let (ct, ss) = ek_inner
            .encapsulate(&mut RngWrapper(rng))
            .map_err(|_| KemError::PostQuantum)?;
        Ok((
            MlKem1024Ciphertext { bytes: ct.to_vec() },
            MlKem1024SharedSecret { bytes: ss.to_vec() },
        ))
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, KemError> {
        let dk_inner = dk.decapsulation_key();
        let ct_array = ct.bytes.as_slice();
        let ct_inner = Ciphertext::<MlKem1024>::try_from(ct_array).unwrap();
        let ss = dk_inner
            .decapsulate(&ct_inner)
            .map_err(|_| KemError::PostQuantum)?;
        Ok(MlKem1024SharedSecret { bytes: ss.to_vec() })
    }

    fn to_encapsulation_key(
        dk: &Self::DecapsulationKey,
    ) -> Result<Self::EncapsulationKey, KemError> {
        let ek_inner = dk.encapsulation_key();
        Ok(MlKem1024EncapsulationKey {
            bytes: ek_inner.as_bytes().to_vec(),
        })
    }
}

impl EncapsDerand for MlKem1024Kem {
    const RANDOMNESS_LENGTH: usize = 32;

    fn encaps_derand(
        ek: &Self::EncapsulationKey,
        randomness: &[u8],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        if randomness.len() != Self::RANDOMNESS_LENGTH {
            return Err(KemError::InvalidInputLength);
        }

        let m = ml_kem::B32::try_from(randomness).unwrap();

        let ek_inner: EncapsulationKey<MlKem1024Params> =
            EncapsulationKey::from_bytes(ek.bytes.as_slice().try_into().unwrap());
        let (ct, ss) = ek_inner
            .encapsulate_deterministic(&m)
            .map_err(|_| KemError::PostQuantum)?;
        Ok((
            MlKem1024Ciphertext { bytes: ct.to_vec() },
            MlKem1024SharedSecret { bytes: ss.to_vec() },
        ))
    }
}

// Implementation of the new bis traits
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
