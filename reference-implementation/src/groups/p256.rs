//! P-256 nominal group implementation

use crate::bis::SeedSize;
use hex_literal::hex;
use num_bigint::BigUint;
use p256::{
    elliptic_curve::{
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};

/// P-256 nominal group
pub struct P256Group;

// Internal helper function to convert bytes to P-256 scalar
fn bytes_to_scalar(bytes: &[u8]) -> Scalar {
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
    Scalar::reduce_bytes(FieldBytes::from_slice(&bytes_be))
}

// Implementation of the bis traits
impl crate::bis::SeedSize for P256Group {
    const SEED_SIZE: usize = 48;
}

impl crate::bis::SharedSecretSize for P256Group {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl crate::bis::NominalGroup for P256Group {
    const SCALAR_SIZE: usize = 32;
    const ELEMENT_SIZE: usize = 65;

    fn generator() -> crate::bis::Element {
        // P-256 generator in uncompressed form (0x04 || x || y)
        b"\x04\x6b\x17\xd1\xf2\xe1\x2c\x42\x47\xf8\xbc\xe6\xe5\x63\xa4\x40\xf2\x77\x03\x7d\x81\x2d\xeb\x33\xa0\xf4\xa1\x39\x45\xd8\x98\xc2\x96\x4f\xe3\x42\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xeb\x4a\x7c\x0f\x9e\x16\x2b\xce\x33\x57\x6b\x31\x5e\xce\xcb\xb6\x40\x68\x37\xbf\x51\xf5".to_vec()
    }

    fn random_scalar(seed: &[u8]) -> crate::bis::Scalar {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        let scalar = bytes_to_scalar(seed);
        scalar.to_bytes().to_vec()
    }

    fn exp(element: &crate::bis::Element, scalar: &crate::bis::Scalar) -> crate::bis::Element {
        assert_eq!(element.len(), Self::ELEMENT_SIZE);
        assert_eq!(scalar.len(), Self::SCALAR_SIZE);

        let encoded_point = EncodedPoint::from_bytes(element).expect("Invalid point encoding");
        let point = AffinePoint::from_encoded_point(&encoded_point).expect("Invalid point");
        let scalar_value = bytes_to_scalar(scalar);

        // Convert to projective for scalar multiplication
        let proj_point = ProjectivePoint::from(point);
        let result_proj = proj_point * scalar_value;
        let result_affine: AffinePoint = result_proj.into();

        // Encode in uncompressed form
        let encoded = result_affine.to_encoded_point(false);
        encoded.as_bytes().to_vec()
    }

    fn element_to_shared_secret(element: &crate::bis::Element) -> crate::bis::SharedSecret {
        assert_eq!(element.len(), Self::ELEMENT_SIZE);
        let encoded = EncodedPoint::from_bytes(element).expect("Invalid point encoding");
        let x_bytes = encoded.x().expect("Point at infinity");
        x_bytes.to_vec()
    }
}
