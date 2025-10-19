//! X25519 nominal group implementation

use crate::hybrid::SeedSize;
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 nominal group
pub struct X25519Group;

// Implementation of the bis traits
impl crate::hybrid::SeedSize for X25519Group {
    const SEED_SIZE: usize = 32;
}

impl crate::hybrid::SharedSecretSize for X25519Group {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl crate::hybrid::NominalGroup for X25519Group {
    const SCALAR_SIZE: usize = 32;
    const ELEMENT_SIZE: usize = 32;

    fn generator() -> crate::hybrid::Element {
        // X25519 generator is 9
        vec![
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]
    }

    fn random_scalar(seed: &[u8]) -> crate::hybrid::Scalar {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        // For X25519, seed is directly used as scalar
        seed.to_vec()
    }

    fn exp(element: &crate::hybrid::Element, scalar: &crate::hybrid::Scalar) -> crate::hybrid::Element {
        assert_eq!(element.len(), Self::ELEMENT_SIZE);
        assert_eq!(scalar.len(), Self::SCALAR_SIZE);

        let mut element_bytes = [0u8; 32];
        element_bytes.copy_from_slice(element);
        let public = PublicKey::from(element_bytes);

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(scalar);
        let secret = StaticSecret::from(scalar_bytes);

        // Compute the Diffie-Hellman operation
        let shared_secret = secret.diffie_hellman(&public);
        shared_secret.as_bytes().to_vec()
    }

    fn element_to_shared_secret(element: &crate::hybrid::Element) -> crate::hybrid::SharedSecret {
        assert_eq!(element.len(), Self::ELEMENT_SIZE);
        // For X25519, the element itself is the shared secret
        element.to_vec()
    }
}
