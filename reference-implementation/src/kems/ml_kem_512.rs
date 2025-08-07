//! ML-KEM-512 implementation

use crate::generic::{
    error::KemError,
    traits::{AsBytes, EncapsDerand, Kem},
};
use crate::utils::RngWrapper;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    Ciphertext, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem512, MlKem512Params,
};

/// ML-KEM-512 KEM implementation
pub struct MlKem512Kem;

/// Wrapper for ML-KEM-512 encapsulation key
pub struct MlKem512EncapsulationKey {
    bytes: Vec<u8>,
}

/// Wrapper for ML-KEM-512 decapsulation key  
pub struct MlKem512DecapsulationKey {
    bytes: Vec<u8>,
}

/// Wrapper for ML-KEM-512 ciphertext
pub struct MlKem512Ciphertext {
    bytes: Vec<u8>,
}

/// Wrapper for ML-KEM-512 shared secret
pub struct MlKem512SharedSecret {
    bytes: Vec<u8>,
}

impl AsBytes for MlKem512EncapsulationKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for MlKem512EncapsulationKey {
    fn from(bytes: &[u8]) -> Self {
        MlKem512EncapsulationKey {
            bytes: bytes.to_vec(),
        }
    }
}

impl AsBytes for MlKem512DecapsulationKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for MlKem512DecapsulationKey {
    fn from(bytes: &[u8]) -> Self {
        MlKem512DecapsulationKey {
            bytes: bytes.to_vec(),
        }
    }
}

impl AsBytes for MlKem512Ciphertext {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for MlKem512Ciphertext {
    fn from(bytes: &[u8]) -> Self {
        MlKem512Ciphertext {
            bytes: bytes.to_vec(),
        }
    }
}

impl AsBytes for MlKem512SharedSecret {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PartialEq<Vec<u8>> for MlKem512SharedSecret {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_bytes() == other.as_slice()
    }
}

impl Kem for MlKem512Kem {
    const SEED_LENGTH: usize = 64;
    const ENCAPSULATION_KEY_LENGTH: usize = 800;
    const DECAPSULATION_KEY_LENGTH: usize = 1632;
    const CIPHERTEXT_LENGTH: usize = 768;
    const SHARED_SECRET_LENGTH: usize = 32;

    type EncapsulationKey = MlKem512EncapsulationKey;
    type DecapsulationKey = MlKem512DecapsulationKey;
    type Ciphertext = MlKem512Ciphertext;
    type SharedSecret = MlKem512SharedSecret;

    fn generate_key_pair<R: rand::CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError> {
        let (dk, ek) = MlKem512::generate(&mut RngWrapper(rng));
        Ok((
            MlKem512EncapsulationKey {
                bytes: ek.as_bytes().to_vec(),
            },
            MlKem512DecapsulationKey {
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
        let (dk, ek) = MlKem512::generate_deterministic(&d, &z);

        Ok((
            MlKem512EncapsulationKey {
                bytes: ek.as_bytes().to_vec(),
            },
            MlKem512DecapsulationKey {
                bytes: dk.as_bytes().to_vec(),
            },
        ))
    }

    fn encaps<R: rand::CryptoRng>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        let ek_inner: EncapsulationKey<MlKem512Params> =
            EncapsulationKey::from_bytes(ek.bytes.as_slice().try_into().unwrap());
        let (ct, ss) = ek_inner
            .encapsulate(&mut RngWrapper(rng))
            .map_err(|_| KemError::PostQuantum)?;
        Ok((
            MlKem512Ciphertext { bytes: ct.to_vec() },
            MlKem512SharedSecret { bytes: ss.to_vec() },
        ))
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, KemError> {
        let dk_inner: DecapsulationKey<MlKem512Params> =
            DecapsulationKey::from_bytes(dk.bytes.as_slice().try_into().unwrap());
        let ct_array = ct.bytes.as_slice();
        let ct_inner = Ciphertext::<MlKem512>::try_from(ct_array).unwrap();
        let ss = dk_inner
            .decapsulate(&ct_inner)
            .map_err(|_| KemError::PostQuantum)?;
        Ok(MlKem512SharedSecret { bytes: ss.to_vec() })
    }

    fn to_encapsulation_key(
        dk: &Self::DecapsulationKey,
    ) -> Result<Self::EncapsulationKey, KemError> {
        let dk_inner: DecapsulationKey<MlKem512Params> =
            DecapsulationKey::from_bytes(dk.bytes.as_slice().try_into().unwrap());
        let ek_inner = dk_inner.encapsulation_key();
        Ok(MlKem512EncapsulationKey {
            bytes: ek_inner.as_bytes().to_vec(),
        })
    }
}

impl EncapsDerand for MlKem512Kem {
    const RANDOMNESS_LENGTH: usize = 32;

    fn encaps_derand(
        ek: &Self::EncapsulationKey,
        randomness: &[u8],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        if randomness.len() != Self::RANDOMNESS_LENGTH {
            return Err(KemError::InvalidInputLength);
        }

        let m = ml_kem::B32::try_from(randomness).unwrap();

        let ek_inner: EncapsulationKey<MlKem512Params> =
            EncapsulationKey::from_bytes(ek.bytes.as_slice().try_into().unwrap());
        let (ct, ss) = ek_inner
            .encapsulate_deterministic(&m)
            .map_err(|_| KemError::PostQuantum)?;
        Ok((
            MlKem512Ciphertext { bytes: ct.to_vec() },
            MlKem512SharedSecret { bytes: ss.to_vec() },
        ))
    }
}
