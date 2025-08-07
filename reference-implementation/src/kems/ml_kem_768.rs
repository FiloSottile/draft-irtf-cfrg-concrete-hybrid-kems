//! ML-KEM-768 implementation

use crate::generic::{
    error::KemError,
    traits::{AsBytes, EncapsDerand, Kem},
};
use crate::utils::RngWrapper;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    Ciphertext, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};

/// ML-KEM-768 KEM implementation
pub struct MlKem768Kem;

/// Wrapper for ML-KEM-768 encapsulation key
pub struct MlKem768EncapsulationKey {
    bytes: Vec<u8>,
}

/// Wrapper for ML-KEM-768 decapsulation key  
pub struct MlKem768DecapsulationKey {
    bytes: Vec<u8>,
}

/// Wrapper for ML-KEM-768 ciphertext
pub struct MlKem768Ciphertext {
    bytes: Vec<u8>,
}

/// Wrapper for ML-KEM-768 shared secret
pub struct MlKem768SharedSecret {
    bytes: Vec<u8>,
}

impl AsBytes for MlKem768EncapsulationKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for MlKem768EncapsulationKey {
    fn from(bytes: &[u8]) -> Self {
        MlKem768EncapsulationKey {
            bytes: bytes.to_vec(),
        }
    }
}

impl AsBytes for MlKem768DecapsulationKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for MlKem768DecapsulationKey {
    fn from(bytes: &[u8]) -> Self {
        MlKem768DecapsulationKey {
            bytes: bytes.to_vec(),
        }
    }
}

impl AsBytes for MlKem768Ciphertext {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for MlKem768Ciphertext {
    fn from(bytes: &[u8]) -> Self {
        MlKem768Ciphertext {
            bytes: bytes.to_vec(),
        }
    }
}

impl AsBytes for MlKem768SharedSecret {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PartialEq<Vec<u8>> for MlKem768SharedSecret {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_bytes() == other.as_slice()
    }
}

impl Kem for MlKem768Kem {
    const SEED_LENGTH: usize = 64;
    const ENCAPSULATION_KEY_LENGTH: usize = 1184;
    const DECAPSULATION_KEY_LENGTH: usize = 2400;
    const CIPHERTEXT_LENGTH: usize = 1088;
    const SHARED_SECRET_LENGTH: usize = 32;

    type EncapsulationKey = MlKem768EncapsulationKey;
    type DecapsulationKey = MlKem768DecapsulationKey;
    type Ciphertext = MlKem768Ciphertext;
    type SharedSecret = MlKem768SharedSecret;

    fn generate_key_pair<R: rand::CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError> {
        let (dk, ek) = MlKem768::generate(&mut RngWrapper(rng));
        Ok((
            MlKem768EncapsulationKey {
                bytes: ek.as_bytes().to_vec(),
            },
            MlKem768DecapsulationKey {
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
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);

        Ok((
            MlKem768EncapsulationKey {
                bytes: ek.as_bytes().to_vec(),
            },
            MlKem768DecapsulationKey {
                bytes: dk.as_bytes().to_vec(),
            },
        ))
    }

    fn encaps<R: rand::CryptoRng>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        let ek_inner: EncapsulationKey<MlKem768Params> =
            EncapsulationKey::from_bytes(ek.bytes.as_slice().try_into().unwrap());
        let (ct, ss) = ek_inner
            .encapsulate(&mut RngWrapper(rng))
            .map_err(|_| KemError::PostQuantum)?;
        Ok((
            MlKem768Ciphertext { bytes: ct.to_vec() },
            MlKem768SharedSecret { bytes: ss.to_vec() },
        ))
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, KemError> {
        let dk_inner: DecapsulationKey<MlKem768Params> =
            DecapsulationKey::from_bytes(dk.bytes.as_slice().try_into().unwrap());
        let ct_array = ct.bytes.as_slice();
        let ct_inner = Ciphertext::<MlKem768>::try_from(ct_array).unwrap();
        let ss = dk_inner
            .decapsulate(&ct_inner)
            .map_err(|_| KemError::PostQuantum)?;
        Ok(MlKem768SharedSecret { bytes: ss.to_vec() })
    }

    fn to_encapsulation_key(
        dk: &Self::DecapsulationKey,
    ) -> Result<Self::EncapsulationKey, KemError> {
        let dk_inner: DecapsulationKey<MlKem768Params> =
            DecapsulationKey::from_bytes(dk.bytes.as_slice().try_into().unwrap());
        let ek_inner = dk_inner.encapsulation_key();
        Ok(MlKem768EncapsulationKey {
            bytes: ek_inner.as_bytes().to_vec(),
        })
    }
}

impl EncapsDerand for MlKem768Kem {
    const RANDOMNESS_LENGTH: usize = 32;

    fn encaps_derand(
        ek: &Self::EncapsulationKey,
        randomness: &[u8],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        if randomness.len() != Self::RANDOMNESS_LENGTH {
            return Err(KemError::InvalidInputLength);
        }

        let m = ml_kem::B32::try_from(randomness).unwrap();

        let ek_inner: EncapsulationKey<MlKem768Params> =
            EncapsulationKey::from_bytes(ek.bytes.as_slice().try_into().unwrap());
        let (ct, ss) = ek_inner
            .encapsulate_deterministic(&m)
            .map_err(|_| KemError::PostQuantum)?;
        Ok((
            MlKem768Ciphertext { bytes: ct.to_vec() },
            MlKem768SharedSecret { bytes: ss.to_vec() },
        ))
    }
}
