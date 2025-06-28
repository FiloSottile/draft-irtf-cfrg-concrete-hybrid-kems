//! P-384 nominal group implementation

use hybrid_kem_ref::{
    error::KemError,
    traits::{AsBytes, NominalGroup},
};
use p384::{
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        ops::Reduce,
        group::prime::PrimeCurveAffine,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
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
        // Take the first 48 bytes
        let mut scalar_bytes = [0u8; 48];
        scalar_bytes.copy_from_slice(&bytes[..48]);

        // Use reduce_bytes for modular reduction
        let scalar = Scalar::reduce_bytes(&scalar_bytes.into());
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
    const ELEMENT_LENGTH: usize = 49;
    const SHARED_SECRET_LENGTH: usize = 48;

    type Scalar = P384Scalar;
    type Element = P384Element;

    fn generator() -> Self::Element {
        let point = AffinePoint::generator();
        let encoded = point.to_encoded_point(true);
        let bytes = encoded.as_bytes().to_vec();

        P384Element { point, bytes }
    }

    fn exp(p: &Self::Element, x: &Self::Scalar) -> Self::Element {
        // Convert to projective for scalar multiplication
        let proj_point = ProjectivePoint::from(p.point);
        let result_proj = proj_point * x.scalar;
        let result_affine: AffinePoint = result_proj.into();

        // Encode in compressed form
        let encoded = result_affine.to_encoded_point(true);
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

        // Convert seed to scalar by reducing modulo the group order
        // Using the first 48 bytes and reducing
        let mut scalar_bytes = [0u8; 48];
        scalar_bytes.copy_from_slice(&seed[..48]);

        // Use reduce_bytes for modular reduction
        let scalar = Scalar::reduce_bytes(&scalar_bytes.into());
        let bytes = scalar.to_bytes().to_vec();

        Ok(P384Scalar { scalar, bytes })
    }

    fn element_to_shared_secret(p: &Self::Element) -> Vec<u8> {
        // Extract X coordinate as the shared secret
        let encoded = p.point.to_encoded_point(false);
        let x_bytes = encoded.x().expect("Point at infinity");
        x_bytes.to_vec()
    }
}