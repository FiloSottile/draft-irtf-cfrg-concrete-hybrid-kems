//! X25519 nominal group implementation

use hybrid_kem_ref::{
    error::KemError,
    traits::{AsBytes, NominalGroup},
};
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 nominal group
pub struct X25519Group;

/// Wrapper for X25519 scalar with serialized form
pub struct X25519Scalar {
    secret: StaticSecret,
    bytes: Vec<u8>,
}

/// Wrapper for X25519 group element with serialized form
pub struct X25519Element {
    public: PublicKey,
    bytes: Vec<u8>,
}

impl AsBytes for X25519Scalar {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for X25519Scalar {
    fn from(bytes: &[u8]) -> Self {
        // Take the first 32 bytes
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&bytes[..32]);

        let secret = StaticSecret::from(scalar_bytes);
        let bytes = scalar_bytes.to_vec();

        X25519Scalar { secret, bytes }
    }
}

impl AsBytes for X25519Element {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for X25519Element {
    fn from(bytes: &[u8]) -> Self {
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(&bytes[..32]);

        let public = PublicKey::from(public_bytes);

        X25519Element {
            public,
            bytes: bytes.to_vec(),
        }
    }
}

impl NominalGroup for X25519Group {
    const SEED_LENGTH: usize = 32;
    const SCALAR_LENGTH: usize = 32;
    const ELEMENT_LENGTH: usize = 32;
    const SHARED_SECRET_LENGTH: usize = 32;

    type Scalar = X25519Scalar;
    type Element = X25519Element;

    fn generator() -> Self::Element {
        // X25519 generator is defined as 9
        let generator_bytes = [
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let public = PublicKey::from(generator_bytes);
        let bytes = generator_bytes.to_vec();

        X25519Element { public, bytes }
    }

    fn exp(p: &Self::Element, x: &Self::Scalar) -> Self::Element {
        // Compute the shared secret using X25519
        let shared_secret = x.secret.diffie_hellman(&p.public);
        let result_bytes = shared_secret.as_bytes();

        X25519Element {
            public: PublicKey::from(*result_bytes),
            bytes: result_bytes.to_vec(),
        }
    }

    fn random_scalar(seed: &[u8]) -> Result<Self::Scalar, KemError> {
        if seed.len() != Self::SEED_LENGTH {
            return Err(KemError::InvalidInputLength);
        }

        // Convert seed directly to scalar
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(seed);

        let secret = StaticSecret::from(scalar_bytes);
        let bytes = scalar_bytes.to_vec();

        Ok(X25519Scalar { secret, bytes })
    }

    fn element_to_shared_secret(p: &Self::Element) -> Vec<u8> {
        // For X25519, the element itself is the shared secret
        p.bytes.clone()
    }
}
