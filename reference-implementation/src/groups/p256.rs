//! P-256 nominal group implementation

use crate::generic::{
    error::KemError,
    traits::{AsBytes, NominalGroup},
};
use hex_literal::hex;
use hybrid_array::typenum::{U32, U48, U65};
use num_bigint::BigUint;
use p256::{
    elliptic_curve::{
        group::prime::PrimeCurveAffine,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
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
        // Manually reduce mod n
        const MOD: &[u8] = &hex!("ffffffff00000000ffffffffffffffff"
            "bce6faada7179e84f3b9cac2fc632551");
        let q = BigUint::from_bytes_be(MOD);
        let p = BigUint::from_bytes_be(bytes) % &q;

        // Convert to bytes and pad to 32 bytes
        let mut bytes_be = p.to_bytes_be();
        // Pad with leading zeros if necessary
        while bytes_be.len() < 32 {
            bytes_be.insert(0, 0);
        }
        let scalar = Scalar::reduce_bytes(FieldBytes::from_slice(&bytes_be));
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
    const ELEMENT_LENGTH: usize = 65;
    const SHARED_SECRET_LENGTH: usize = 32;

    type Scalar = P256Scalar;
    type Element = P256Element;

    fn generator() -> Self::Element {
        let point = AffinePoint::generator();
        let encoded = point.to_encoded_point(false);
        let bytes = encoded.as_bytes().to_vec();

        P256Element { point, bytes }
    }

    fn exp(p: &Self::Element, x: &Self::Scalar) -> Self::Element {
        // Convert to projective for scalar multiplication
        let proj_point = ProjectivePoint::from(p.point);
        let result_proj = proj_point * x.scalar;
        let result_affine: AffinePoint = result_proj.into();

        // Encode in uncompressed form
        let encoded = result_affine.to_encoded_point(false);
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

        Ok(P256Scalar::from(seed))
    }

    fn element_to_shared_secret(p: &Self::Element) -> Vec<u8> {
        // Extract X coordinate as the shared secret
        let encoded = p.point.to_encoded_point(false);
        let x_bytes = encoded.x().expect("Point at infinity");
        x_bytes.to_vec()
    }
}

// Implementation of the new bis traits
impl crate::bis::SeedSize for P256Group {
    type SeedSize = U48;
}

impl crate::bis::SharedSecretSize for P256Group {
    type SharedSecretSize = U32;
}

impl crate::bis::NominalGroup for P256Group {
    type ScalarSize = U32;
    type ElementSize = U65;

    const G: crate::bis::Element<Self> = {
        // P-256 generator in uncompressed form (0x04 || x || y)
        hybrid_array::Array(*b"\x04\x6b\x17\xd1\xf2\xe1\x2c\x42\x47\xf8\xbc\xe6\xe5\x63\xa4\x40\xf2\x77\x03\x7d\x81\x2d\xeb\x33\xa0\xf4\xa1\x39\x45\xd8\x98\xc2\x96\x4f\xe3\x42\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xeb\x4a\x7c\x0f\x9e\x16\x2b\xce\x33\x57\x6b\x31\x5e\xce\xcb\xb6\x40\x68\x37\xbf\x51\xf5")
    };

    fn random_scalar(seed: crate::bis::Seed<Self>) -> crate::bis::Scalar<Self> {
        let scalar_wrapper = P256Scalar::from(seed.as_slice());
        let mut result = crate::bis::Scalar::<Self>::default();
        result.copy_from_slice(scalar_wrapper.as_bytes());
        result
    }

    fn exp(
        element: &crate::bis::Element<Self>,
        scalar: &crate::bis::Scalar<Self>,
    ) -> crate::bis::Element<Self> {
        let element_wrapper = P256Element::from(element.as_slice());
        let scalar_wrapper = P256Scalar::from(scalar.as_slice());

        // Convert to projective for scalar multiplication
        let proj_point = ProjectivePoint::from(element_wrapper.point);
        let result_proj = proj_point * scalar_wrapper.scalar;
        let result_affine: AffinePoint = result_proj.into();

        // Encode in uncompressed form
        let encoded = result_affine.to_encoded_point(false);
        let mut result = crate::bis::Element::<Self>::default();
        result.copy_from_slice(encoded.as_bytes());
        result
    }

    fn element_to_shared_secret(
        element: crate::bis::Element<Self>,
    ) -> crate::bis::SharedSecret<Self> {
        let encoded = EncodedPoint::from_bytes(&element).expect("Invalid point encoding");
        let x_bytes = encoded.x().expect("Point at infinity");
        let mut result = crate::bis::SharedSecret::<Self>::default();
        result.copy_from_slice(x_bytes);
        result
    }
}
