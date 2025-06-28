//! Tests for KEM implementations

#[cfg(test)]
mod tests {
    use crate::kems::{MlKem768Kem, MlKem1024};
    use hybrid_kem_ref::test_utils::test_kem_all;

    #[test]
    fn test_ml_kem_768() {
        let mut rng = rand::rng();
        test_kem_all::<MlKem768Kem, _>(&mut rng);
    }

    #[test]
    fn test_ml_kem_1024() {
        let mut rng = rand::rng();
        test_kem_all::<MlKem1024, _>(&mut rng);
    }
}
