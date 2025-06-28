//! Integration tests for hybrid KEM instantiations

#[cfg(test)]
mod tests {
    use crate::instantiations::{
        QsfP256MlKem768Shake256Sha3256, QsfP384MlKem1024Shake256Sha3256,
        QsfX25519MlKem768Shake256Sha3256,
    };
    use hybrid_kem_ref::test_utils::test_kem_all;

    #[test]
    fn test_qsf_p256_mlkem768() {
        let mut rng = rand::rng();
        test_kem_all::<QsfP256MlKem768Shake256Sha3256, _>(&mut rng);
    }

    #[test]
    fn test_qsf_x25519_mlkem768() {
        let mut rng = rand::rng();
        test_kem_all::<QsfX25519MlKem768Shake256Sha3256, _>(&mut rng);
    }

    #[test]
    fn test_qsf_p384_mlkem1024() {
        let mut rng = rand::rng();
        test_kem_all::<QsfP384MlKem1024Shake256Sha3256, _>(&mut rng);
    }
}
