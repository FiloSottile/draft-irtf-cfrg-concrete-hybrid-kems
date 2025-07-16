//! Tests for KEM implementations

#[cfg(test)]
mod tests {
    use crate::generic::test_utils::test_kem_all;
    use crate::kems::{MlKem1024Kem, MlKem512Kem, MlKem768Kem};

    #[test]
    fn test_ml_kem_512() {
        let mut rng = rand::rng();
        test_kem_all::<MlKem512Kem, _>(&mut rng);
    }

    #[test]
    fn test_ml_kem_768() {
        let mut rng = rand::rng();
        test_kem_all::<MlKem768Kem, _>(&mut rng);
    }

    #[test]
    fn test_ml_kem_1024() {
        let mut rng = rand::rng();
        test_kem_all::<MlKem1024Kem, _>(&mut rng);
    }
}
