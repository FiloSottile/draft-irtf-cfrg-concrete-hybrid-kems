//! P-384 nominal group implementation

use crate::bis::SeedSize;
use hex_literal::hex;
use num_bigint::BigUint;
use p384::{
    elliptic_curve::{
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};

/// P-384 nominal group
pub struct P384Group;

// Internal helper function to convert bytes to P-384 scalar
fn bytes_to_scalar(bytes: &[u8]) -> Scalar {
    // Manually reduce mod n
    const MOD: &[u8] = &hex!("ffffffffffffffffffffffffffffffffffffffffffffffff"
        "c7634d81f4372ddf581a0db248b0a77aecec196accc52973");
    let q = BigUint::from_bytes_be(MOD);
    let p = BigUint::from_bytes_be(bytes) % &q;

    // Convert to bytes and pad to 48 bytes
    let mut bytes_be = p.to_bytes_be();
    // Pad with leading zeros if necessary
    while bytes_be.len() < 48 {
        bytes_be.insert(0, 0);
    }
    Scalar::reduce_bytes(FieldBytes::from_slice(&bytes_be))
}

// Implementation of the bis traits
impl crate::bis::SeedSize for P384Group {
    const SEED_SIZE: usize = 72;
}

impl crate::bis::SharedSecretSize for P384Group {
    const SHARED_SECRET_SIZE: usize = 48;
}

impl crate::bis::NominalGroup for P384Group {
    const SCALAR_SIZE: usize = 48;
    const ELEMENT_SIZE: usize = 97;

    fn generator() -> crate::bis::Element {
        // P-384 generator in uncompressed form (0x04 || x || y)
        b"\x04\xaa\x87\xca\x22\xbe\x8b\x05\x37\x8e\xb1\xc7\x1e\xf3\x20\xad\x74\x6e\x1d\x3b\x62\x8b\xa7\x9b\x98\x59\xf7\x41\xe0\x82\x54\x2a\x38\x55\x02\xf2\x5d\xbf\x55\x29\x6c\x3a\x54\x5e\x38\x72\x76\x0a\xb7\x36\x17\xde\x4a\x96\x26\x2c\x6f\x5d\x9e\x98\xbf\x92\x92\xdc\x29\xf8\xf4\x1d\xbd\x28\x9a\x14\x7c\xe9\xda\x31\x13\xb5\xf0\xb8\xc0\x0a\x60\xb1\xce\x1d\x7e\x81\x9d\x7a\x43\x1d\x7c\x90\xea\x0e\x5f".to_vec()
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
