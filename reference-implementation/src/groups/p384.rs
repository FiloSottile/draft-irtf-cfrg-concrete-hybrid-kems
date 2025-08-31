//! P-384 nominal group implementation

use crate::generic::{
    error::KemError,
    traits::{AsBytes, NominalGroup},
};
use hex_literal::hex;
use num_bigint::BigUint;
use p384::{
    elliptic_curve::{
        group::prime::PrimeCurveAffine,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};

/// P-384 nominal group
pub struct P384Group;

/// Wrapper for P-384 scalar with serialized form
pub struct P384Scalar {
    scalar: Scalar,
    bytes: Vec<u8>,
}

/// Wrapper for P-384 group element with serialized form
pub struct P384Element {
    point: AffinePoint,
    bytes: Vec<u8>,
}

impl AsBytes for P384Scalar {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for P384Scalar {
    fn from(bytes: &[u8]) -> Self {
        // Manually reduce mod n
        const MOD: &[u8] = &hex!("ffffffffffffffffffffffffffffffffffffffffffffffff"
            "c7634d81f4372ddf581a0db248b0a77aecec196accc52973");
        let q = BigUint::from_bytes_be(MOD);
        let p = BigUint::from_bytes_be(bytes) % &q;

        // Use reduce_bytes for modular reduction
        // XXX(RLB) This will fail if `p` is not large enough to render into 32 bytes
        let bytes = p.to_bytes_be();
        let scalar = Scalar::reduce_bytes(FieldBytes::from_slice(&bytes));
        let bytes = scalar.to_bytes().to_vec();

        P384Scalar { scalar, bytes }
    }
}

impl AsBytes for P384Element {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for P384Element {
    fn from(bytes: &[u8]) -> Self {
        let encoded = EncodedPoint::from_bytes(bytes).expect("Invalid point encoding");
        let point = AffinePoint::from_encoded_point(&encoded).expect("Invalid point");

        P384Element {
            point,
            bytes: bytes.to_vec(),
        }
    }
}

impl NominalGroup for P384Group {
    const SEED_LENGTH: usize = 72;
    const SCALAR_LENGTH: usize = 48;
    const ELEMENT_LENGTH: usize = 97;
    const SHARED_SECRET_LENGTH: usize = 48;

    type Scalar = P384Scalar;
    type Element = P384Element;

    fn generator() -> Self::Element {
        let point = AffinePoint::generator();
        let encoded = point.to_encoded_point(false);
        let bytes = encoded.as_bytes().to_vec();

        P384Element { point, bytes }
    }

    fn exp(p: &Self::Element, x: &Self::Scalar) -> Self::Element {
        // Convert to projective for scalar multiplication
        let proj_point = ProjectivePoint::from(p.point);
        let result_proj = proj_point * x.scalar;
        let result_affine: AffinePoint = result_proj.into();

        // Encode in uncompressed form
        let encoded = result_affine.to_encoded_point(false);
        let bytes = encoded.as_bytes().to_vec();

        P384Element {
            point: result_affine,
            bytes,
        }
    }

    fn random_scalar(seed: &[u8]) -> Result<Self::Scalar, KemError> {
        if seed.len() != Self::SEED_LENGTH {
            return Err(KemError::InvalidInputLength);
        }

        Ok(P384Scalar::from(seed))
    }

    fn element_to_shared_secret(p: &Self::Element) -> Vec<u8> {
        // Extract X coordinate as the shared secret
        let encoded = p.point.to_encoded_point(false);
        let x_bytes = encoded.x().expect("Point at infinity");
        x_bytes.to_vec()
    }
}
