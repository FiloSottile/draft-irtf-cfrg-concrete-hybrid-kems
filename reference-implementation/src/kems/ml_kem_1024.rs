//! ML-KEM-1024 implementation

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
    fn generate_keys_from_seed(&self) -> (ml_kem::kem::DecapsulationKey<MlKem1024Params>, ml_kem::kem::EncapsulationKey<MlKem1024Params>) {
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
