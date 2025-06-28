//! P-256 nominal group implementation

use hybrid_kem_ref::{
    error::KemError,
    traits::{AsBytes, NominalGroup},
};
use p256::{
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        ops::Reduce,
        group::prime::PrimeCurveAffine,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};

/// P-256 nominal group
pub struct P256Group;

/// Wrapper for P-256 scalar with serialized form
pub struct P256Scalar {
    scalar: Scalar,
    bytes: Vec<u8>,
}

/// Wrapper for P-256 group element with serialized form
pub struct P256Element {
    point: AffinePoint,
    bytes: Vec<u8>,
}

impl AsBytes for P256Scalar {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for P256Scalar {
    fn from(bytes: &[u8]) -> Self {
        // Take the first 32 bytes
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&bytes[..32]);

        // Use reduce_bytes for modular reduction
        let scalar = Scalar::reduce_bytes(&scalar_bytes.into());
        let bytes = scalar.to_bytes().to_vec();

        P256Scalar { scalar, bytes }
    }
}

impl AsBytes for P256Element {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&[u8]> for P256Element {
    fn from(bytes: &[u8]) -> Self {
        let encoded = EncodedPoint::from_bytes(bytes).expect("Invalid point encoding");
        let point = AffinePoint::from_encoded_point(&encoded).expect("Invalid point");

        P256Element {
            point,
            bytes: bytes.to_vec(),
        }
    }
}

impl NominalGroup for P256Group {
    const SEED_LENGTH: usize = 48;
    const SCALAR_LENGTH: usize = 32;
    const ELEMENT_LENGTH: usize = 33;
    const SHARED_SECRET_LENGTH: usize = 32;

    type Scalar = P256Scalar;
    type Element = P256Element;

    fn generator() -> Self::Element {
        let point = AffinePoint::generator();
        let encoded = point.to_encoded_point(true);
        let bytes = encoded.as_bytes().to_vec();

        P256Element { point, bytes }
    }

    fn exp(p: &Self::Element, x: &Self::Scalar) -> Self::Element {
        // Convert to projective for scalar multiplication
        let proj_point = ProjectivePoint::from(p.point);
        let result_proj = proj_point * x.scalar;
        let result_affine: AffinePoint = result_proj.into();

        // Encode in compressed form
        let encoded = result_affine.to_encoded_point(true);
        let bytes = encoded.as_bytes().to_vec();

        P256Element {
            point: result_affine,
            bytes,
        }
    }

    fn random_scalar(seed: &[u8]) -> Result<Self::Scalar, KemError> {
        if seed.len() != Self::SEED_LENGTH {
            return Err(KemError::InvalidInputLength);
        }

        // Convert seed to scalar by reducing modulo the group order
        // Using the first 32 bytes and reducing
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&seed[..32]);

        // Use reduce_bytes for modular reduction
        let scalar = Scalar::reduce_bytes(&scalar_bytes.into());
        let bytes = scalar.to_bytes().to_vec();

        Ok(P256Scalar { scalar, bytes })
    }

    fn element_to_shared_secret(p: &Self::Element) -> Vec<u8> {
        // Extract X coordinate as the shared secret
        let encoded = p.point.to_encoded_point(false);
        let x_bytes = encoded.x().expect("Point at infinity");
        x_bytes.to_vec()
    }
}
