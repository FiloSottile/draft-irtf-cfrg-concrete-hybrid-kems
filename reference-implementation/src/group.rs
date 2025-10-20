use crate::kem::{RngWrapper, SeedSize, SharedSecret, SharedSecretSize};
use elliptic_curve::Curve;
use hex_literal::hex;
use hybrid_array::typenum::Unsigned;
use rand::CryptoRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub type Scalar = Vec<u8>;
pub type Element = Vec<u8>;

pub trait NominalGroup: SeedSize + SharedSecretSize {
    const SCALAR_SIZE: usize;
    const ELEMENT_SIZE: usize;

    fn generator() -> Element;
    fn random_scalar(seed: &mut impl CryptoRng) -> Scalar;
    fn exp(element: &Element, scalar: &Scalar) -> Element;
    fn element_to_shared_secret(element: &Element) -> SharedSecret;
}

pub struct X25519;

// Implementation of the bis traits
impl SeedSize for X25519 {
    const SEED_SIZE: usize = 32;
}

impl SharedSecretSize for X25519 {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl NominalGroup for X25519 {
    const SCALAR_SIZE: usize = 32;
    const ELEMENT_SIZE: usize = 32;

    fn generator() -> Element {
        // X25519 generator is 9
        hex!("0900000000000000000000000000000000000000000000000000000000000000").to_vec()
    }

    fn random_scalar(prg: &mut impl CryptoRng) -> Scalar {
        use rand::Rng;
        let mut seed = [0u8; Self::SEED_SIZE];
        prg.fill(&mut seed);
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

        impl SeedSize for $group {
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

            fn random_scalar(prg: &mut impl CryptoRng) -> Scalar {
                // Coincidentally, NonZeroScalar::random implements exactly the rejection sampling
                // loop we need here.
                $mod::NonZeroScalar::random(&mut RngWrapper(prg))
                    .to_bytes()
                    .to_vec()
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

define_nist_group! { P256, p256, NistP256 }
define_nist_group! { P384, p384, NistP384 }

#[cfg(test)]
mod test {
    use super::*;
    use crate::prg::AsTrivialPrg;
    use rand::Rng;

    pub fn test_basic_ops<G: NominalGroup>() {
        // Test generator
        let generator = G::generator();
        assert_eq!(generator.len(), G::ELEMENT_SIZE, "Generator size mismatch");

        // Test scalar generation
        let mut rng = rand::rng();
        let scalar = G::random_scalar(&mut rng);
        assert_eq!(scalar.len(), G::SCALAR_SIZE, "Scalar size mismatch");

        // Test exponentiation
        let element = G::exp(&generator, &scalar);
        assert_eq!(element.len(), G::ELEMENT_SIZE, "Element size mismatch");

        // Test shared secret extraction
        let shared_secret = G::element_to_shared_secret(&element);
        assert_eq!(
            shared_secret.len(),
            G::SHARED_SECRET_SIZE,
            "Shared secret size mismatch"
        );
    }

    pub fn test_diffie_hellman<G: NominalGroup>() {
        let generator = G::generator();

        // Generate two scalars
        let mut rng = rand::rng();
        let mut seed = vec![0u8; G::SEED_SIZE];
        rng.fill(seed.as_mut_slice());

        let scalar_a = G::random_scalar(&mut seed.as_trivial_prg());
        let scalar_b = G::random_scalar(&mut rng);

        // Compute public keys
        let public_a = G::exp(&generator, &scalar_a);
        let public_b = G::exp(&generator, &scalar_b);

        // Compute shared secrets (should be equal due to DH property)
        let shared_ab = G::exp(&public_b, &scalar_a);
        let shared_ba = G::exp(&public_a, &scalar_b);

        let secret_ab = G::element_to_shared_secret(&shared_ab);
        let secret_ba = G::element_to_shared_secret(&shared_ba);

        assert_eq!(
            secret_ab, secret_ba,
            "Diffie-Hellman shared secrets should be equal"
        );

        // Test deterministic scalar generation
        let scalar_a2 = G::random_scalar(&mut seed.as_trivial_prg());

        assert_eq!(
            scalar_a, scalar_a2,
            "Scalar generation should be deterministic"
        );
    }

    pub fn test_determinism<G: NominalGroup + SeedSize>() {
        // Test generator determinism
        let gen1 = G::generator();
        let gen2 = G::generator();
        assert_eq!(gen1, gen2, "Generator should be deterministic");

        // Test scalar generation determinism
        let seed = vec![42u8; G::SEED_SIZE];
        let scalar1 = G::random_scalar(&mut seed.as_trivial_prg());
        let scalar2 = G::random_scalar(&mut seed.as_trivial_prg());
        assert_eq!(
            scalar1, scalar2,
            "Scalar generation should be deterministic"
        );

        // Test exponentiation determinism
        let elem1 = G::exp(&gen1, &scalar1);
        let elem2 = G::exp(&gen2, &scalar2);
        assert_eq!(elem1, elem2, "Exponentiation should be deterministic");
    }

    fn test_all<G: NominalGroup>() {
        test_basic_ops::<G>();
        test_diffie_hellman::<G>();
        test_determinism::<G>();
    }

    #[test]
    fn p256() {
        test_all::<P256>();
    }

    #[test]
    fn p384() {
        test_all::<P384>();
    }

    #[test]
    fn x25519() {
        test_all::<X25519>();
    }
}
