//! Test vector data structures for serialization

use crate::hybrid::HybridKem;
use crate::prg::{Prg, TrivialPrg};
use serde::{Deserialize, Serialize};

/// An enumeration of the ways test vector validation can fail
pub enum VerifyError {
    EncapsulationKey(Vec<u8>, Vec<u8>),
    DecapsulationKey(Vec<u8>, Vec<u8>),
    Ciphertext(Vec<u8>, Vec<u8>),
    SharedSecretEncaps(Vec<u8>, Vec<u8>),
    SharedSecretDecaps(Vec<u8>, Vec<u8>),
}

/// Test vector for a hybrid KEM instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKemTestVector {
    #[serde(with = "hex::serde")]
    pub seed: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub randomness: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub encapsulation_key: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub decapsulation_key: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub decapsulation_key_pq: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub decapsulation_key_t: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub ciphertext: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub shared_secret: Vec<u8>,
}

impl HybridKemTestVector {
    pub fn generate<K: HybridKem>(index: u8) -> Self {
        let seed = vec![index; K::SEED_SIZE];
        let randomness = vec![index.wrapping_add(100); K::RANDOMNESS_SIZE];

        let mut prg = TrivialPrg::new(&seed);
        let (dk, ek, info) = K::generate_key_pair(&mut prg);
        let (ct, ss) = K::encaps_derand(&ek, &randomness);

        HybridKemTestVector {
            seed,
            randomness,
            encapsulation_key: ek,
            decapsulation_key: dk,
            decapsulation_key_pq: info.dk_pq,
            decapsulation_key_t: info.dk_t,
            ciphertext: ct,
            shared_secret: ss,
        }
    }

    pub fn verify<K: HybridKem>(&self) -> Result<(), VerifyError> {
        // Verify deterministic key generation
        let mut prg = TrivialPrg::new(&self.seed);
        let (dk, ek, _) = K::generate_key_pair(&mut prg);

        if dk != self.decapsulation_key {
            return Err(VerifyError::DecapsulationKey(
                dk,
                self.decapsulation_key.clone(),
            ));
        }

        if ek != self.encapsulation_key {
            return Err(VerifyError::DecapsulationKey(
                dk,
                self.decapsulation_key.clone(),
            ));
        }

        // Verify deterministic encapsulation
        let (ct, ss) = K::encaps_derand(&ek, &self.randomness);

        if ct != self.ciphertext {
            return Err(VerifyError::Ciphertext(ct, self.ciphertext.clone()));
        }

        if ss != self.shared_secret {
            return Err(VerifyError::SharedSecretEncaps(
                ss,
                self.shared_secret.clone(),
            ));
        }

        // Verify decapsulation consistency
        let ss = K::decaps(&dk, &ct);

        if ss != self.shared_secret {
            return Err(VerifyError::SharedSecretDecaps(
                ss,
                self.shared_secret.clone(),
            ));
        }

        Ok(())
    }
}

/// Complete test vector collection for all hybrid KEM instances
#[derive(Debug, Serialize, Deserialize)]
pub struct TestVectors {
    pub mlkem768_p256: Vec<HybridKemTestVector>,
    pub mlkem768_x25519: Vec<HybridKemTestVector>,
    pub mlkem1024_p384: Vec<HybridKemTestVector>,
}
