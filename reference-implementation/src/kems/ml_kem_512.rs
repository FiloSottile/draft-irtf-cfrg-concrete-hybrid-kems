//! ML-KEM-512 implementation

use crate::generic::{
    error::KemError,
    traits::{AsBytes, EncapsDerand, Kem},
};
use crate::utils::RngWrapper;
use hybrid_array::typenum::{U32, U64};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, EncapsulationKey},
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
    seed: Vec<u8>,
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
        &self.seed
    }
}

impl From<&[u8]> for MlKem512DecapsulationKey {
    fn from(seed: &[u8]) -> Self {
        MlKem512DecapsulationKey {
            seed: seed.to_vec(),
        }
    }
}

impl MlKem512DecapsulationKey {
    fn generate_keys_from_seed(&self) -> (ml_kem::kem::DecapsulationKey<MlKem512Params>, ml_kem::kem::EncapsulationKey<MlKem512Params>) {
        let d = ml_kem::B32::try_from(&self.seed[..32]).unwrap();
        let z = ml_kem::B32::try_from(&self.seed[32..]).unwrap();
        MlKem512::generate_deterministic(&d, &z)
    }

    fn decapsulation_key(&self) -> ml_kem::kem::DecapsulationKey<MlKem512Params> {
        self.generate_keys_from_seed().0
    }

    fn encapsulation_key(&self) -> ml_kem::kem::EncapsulationKey<MlKem512Params> {
        self.generate_keys_from_seed().1
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
    const DECAPSULATION_KEY_LENGTH: usize = 64;
    const CIPHERTEXT_LENGTH: usize = 768;
    const SHARED_SECRET_LENGTH: usize = 32;

    type EncapsulationKey = MlKem512EncapsulationKey;
    type DecapsulationKey = MlKem512DecapsulationKey;
    type Ciphertext = MlKem512Ciphertext;
    type SharedSecret = MlKem512SharedSecret;

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

        let dk = MlKem512DecapsulationKey {
            seed: seed.to_vec(),
        };
        let ek_inner = dk.encapsulation_key();

        Ok((
            MlKem512EncapsulationKey {
                bytes: ek_inner.as_bytes().to_vec(),
            },
            dk,
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
        let dk_inner = dk.decapsulation_key();
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
        let ek_inner = dk.encapsulation_key();
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

// Implementation of the new bis traits
impl crate::bis::SeedSize for MlKem512Kem {
    type SeedSize = U64;
}

impl crate::bis::SharedSecretSize for MlKem512Kem {
    type SharedSecretSize = U32;
}

impl crate::bis::Kem for MlKem512Kem {
    type EncapsulationKeySize =
        <ml_kem::kem::EncapsulationKey<MlKem512Params> as EncodedSizeUser>::EncodedSize;
    type DecapsulationKeySize = U64;
    type CiphertextSize = <MlKem512 as KemCore>::CiphertextSize;

    fn derive_key_pair(
        seed: crate::bis::Seed<Self>,
    ) -> (
        crate::bis::DecapsulationKey<Self>,
        crate::bis::EncapsulationKey<Self>,
    ) {
        let d = ml_kem::B32::try_from(&seed[..32]).expect("Invalid seed slice");
        let z = ml_kem::B32::try_from(&seed[32..]).expect("Invalid seed slice");
        let (_dk_inner, ek_inner) = MlKem512::generate_deterministic(&d, &z);

        let ek = crate::bis::EncapsulationKey::<Self>::try_from(ek_inner.as_bytes().as_slice())
            .expect("Size mismatch");

        (seed, ek)
    }

    fn encaps(
        ek: &crate::bis::EncapsulationKey<Self>,
        rng: &mut impl rand::CryptoRng,
    ) -> (crate::bis::SharedSecret<Self>, crate::bis::Ciphertext<Self>) {
        let ek_inner: EncapsulationKey<MlKem512Params> =
            EncapsulationKey::from_bytes(ek.as_slice().try_into().expect("Invalid EK size"));
        let (ct_inner, ss_inner) = ek_inner
            .encapsulate(&mut RngWrapper(rng))
            .expect("Encapsulation failed");

        let ss = crate::bis::SharedSecret::<Self>::try_from(ss_inner.as_slice())
            .expect("Size mismatch");
        let ct = crate::bis::Ciphertext::<Self>::try_from(ct_inner.as_slice())
            .expect("Size mismatch");

        (ss, ct)
    }

    fn decaps(
        dk: &crate::bis::DecapsulationKey<Self>,
        ct: &crate::bis::Ciphertext<Self>,
    ) -> crate::bis::SharedSecret<Self> {
        let d = ml_kem::B32::try_from(&dk[..32]).expect("Invalid DK slice");
        let z = ml_kem::B32::try_from(&dk[32..]).expect("Invalid DK slice");
        let (dk_inner, _ek_inner) = MlKem512::generate_deterministic(&d, &z);

        let ct_inner = Ciphertext::<MlKem512>::try_from(ct.as_slice()).expect("Invalid CT");
        let ss_inner = dk_inner.decapsulate(&ct_inner).expect("Decapsulation failed");

        crate::bis::SharedSecret::<Self>::try_from(ss_inner.as_slice()).expect("Size mismatch")
    }
}

impl crate::bis::PqKem for MlKem512Kem {}
