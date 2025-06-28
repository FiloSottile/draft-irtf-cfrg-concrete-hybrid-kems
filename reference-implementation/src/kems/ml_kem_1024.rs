//! ML-KEM-1024 implementation

use hybrid_kem_ref::{
    error::KemError,
    traits::{AsBytes, EncapsDerand, Kem},
};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    Ciphertext, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};
use crate::utils::RngWrapper;

/// ML-KEM-1024 KEM implementation
pub struct MlKem1024Kem;

/// Wrapper for ML-KEM-1024 encapsulation key
pub struct MlKem1024EncapsulationKey {
    bytes: Vec<u8>,
}

/// Wrapper for ML-KEM-1024 decapsulation key  
pub struct MlKem1024DecapsulationKey {
    bytes: Vec<u8>,
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
        &self.bytes
    }
}

impl From<&[u8]> for MlKem1024DecapsulationKey {
    fn from(bytes: &[u8]) -> Self {
        MlKem1024DecapsulationKey {
            bytes: bytes.to_vec(),
        }
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
    const DECAPSULATION_KEY_LENGTH: usize = 3168;
    const CIPHERTEXT_LENGTH: usize = 1568;
    const SHARED_SECRET_LENGTH: usize = 32;

    type EncapsulationKey = MlKem1024EncapsulationKey;
    type DecapsulationKey = MlKem1024DecapsulationKey;
    type Ciphertext = MlKem1024Ciphertext;
    type SharedSecret = MlKem1024SharedSecret;

    fn generate_key_pair<R: rand::CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError> {
        let (dk, ek) = MlKem1024::generate(&mut RngWrapper(rng));
        Ok((
            MlKem1024EncapsulationKey {
                bytes: ek.as_bytes().to_vec(),
            },
            MlKem1024DecapsulationKey {
                bytes: dk.as_bytes().to_vec(),
            },
        ))
    }

    fn derive_key_pair(
        seed: &[u8],
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError> {
        if seed.len() != Self::SEED_LENGTH {
            return Err(KemError::InvalidInputLength);
        }

        let d = ml_kem::B32::try_from(&seed[..32]).unwrap();
        let z = ml_kem::B32::try_from(&seed[32..]).unwrap();
        let (dk, ek) = MlKem1024::generate_deterministic(&d, &z);

        Ok((
            MlKem1024EncapsulationKey {
                bytes: ek.as_bytes().to_vec(),
            },
            MlKem1024DecapsulationKey {
                bytes: dk.as_bytes().to_vec(),
            },
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
        let dk_inner: DecapsulationKey<MlKem1024Params> =
            DecapsulationKey::from_bytes(dk.bytes.as_slice().try_into().unwrap());
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
        let dk_inner: DecapsulationKey<MlKem1024Params> =
            DecapsulationKey::from_bytes(dk.bytes.as_slice().try_into().unwrap());
        let ek_inner = dk_inner.encapsulation_key();
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
