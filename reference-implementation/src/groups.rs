//! Nominal group implementations for elliptic curves

use crate::hybrid::{Element, NominalGroup, Scalar, SeedSize, SharedSecret, SharedSecretSize};
use elliptic_curve::Curve;
use hex_literal::hex;
use hybrid_array::typenum::Unsigned;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct X25519Group;

// Implementation of the bis traits
impl SeedSize for X25519Group {
    const SEED_SIZE: usize = 32;
}

impl SharedSecretSize for X25519Group {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl NominalGroup for X25519Group {
    const SCALAR_SIZE: usize = 32;
    const ELEMENT_SIZE: usize = 32;

    fn generator() -> Element {
        // X25519 generator is 9
        hex!("0900000000000000000000000000000000000000000000000000000000000000").to_vec()
    }

    fn random_scalar(seed: &[u8]) -> Scalar {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        seed.to_vec()
    }

    fn exp(element: &Element, scalar: &Scalar) -> Element {
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

    fn element_to_shared_secret(element: &Element) -> SharedSecret {
        assert_eq!(element.len(), Self::ELEMENT_SIZE);
        element.clone()
    }
}

macro_rules! define_nist_group {
    ($group:ident, $mod:ident, $curve:ident) => {
        pub struct $group;

        impl $group {
            fn bytes_to_scalar(bytes: &[u8]) -> $mod::Scalar {
                use $mod::{elliptic_curve::ops::Reduce, FieldBytes, Scalar};
                Scalar::reduce_bytes(FieldBytes::from_slice(bytes))
            }
        }

        impl SeedSize for $group {
            // XXX: This doesn't match the spec, but I think it's the spec that's wrong
            const SEED_SIZE: usize = Self::SCALAR_SIZE;
        }

        impl SharedSecretSize for $group {
            const SHARED_SECRET_SIZE: usize = Self::SCALAR_SIZE;
        }

        impl NominalGroup for $group {
            const SCALAR_SIZE: usize = <$mod::$curve as Curve>::FieldBytesSize::USIZE;
            const ELEMENT_SIZE: usize = 1 + 2 * Self::SCALAR_SIZE;

            fn generator() -> Element {
                use $mod::{
                    elliptic_curve::sec1::ToEncodedPoint, elliptic_curve::Group, AffinePoint,
                    ProjectivePoint,
                };

                let gen_aff: AffinePoint = ProjectivePoint::generator().into();
                gen_aff.to_encoded_point(false).as_bytes().to_vec()
            }

            fn random_scalar(seed: &[u8]) -> Scalar {
                assert_eq!(seed.len(), Self::SEED_SIZE);
                Self::bytes_to_scalar(seed).to_bytes().to_vec()
            }

            fn exp(element: &Element, scalar: &Scalar) -> Element {
                use $mod::{
                    elliptic_curve::ops::Reduce,
                    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
                    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
                };

                assert_eq!(element.len(), Self::ELEMENT_SIZE);
                assert_eq!(scalar.len(), Self::SCALAR_SIZE);

                let encoded_point =
                    EncodedPoint::from_bytes(element).expect("Invalid point encoding");
                let point = AffinePoint::from_encoded_point(&encoded_point).expect("Invalid point");
                let scalar_value = Scalar::reduce_bytes(FieldBytes::from_slice(scalar));

                // Convert to projective and back for scalar multiplication
                let proj_point = ProjectivePoint::from(point);
                let result_proj = proj_point * scalar_value;
                let result_aff: AffinePoint = result_proj.into();

                // Encode in uncompressed form
                result_aff.to_encoded_point(false).as_bytes().to_vec()
            }

            fn element_to_shared_secret(element: &Element) -> SharedSecret {
                use $mod::EncodedPoint;

                assert_eq!(element.len(), Self::ELEMENT_SIZE);
                let encoded = EncodedPoint::from_bytes(element).expect("Invalid point encoding");
                let x_bytes = encoded.x().expect("Point at infinity");
                x_bytes.to_vec()
            }
        }
    };
}

define_nist_group! { P256Group, p256, NistP256 }
define_nist_group! { P384Group, p384, NistP384 }
