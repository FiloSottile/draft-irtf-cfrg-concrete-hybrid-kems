//! Tests for cryptographic primitives

#[cfg(test)]
mod tests {
    use crate::primitives::{Sha3_256Kdf, Shake256Prg};
    use hybrid_kem_ref::test_utils::{test_kdf_all, test_prg_all};

    #[test]
    fn test_sha3_256_kdf() {
        test_kdf_all::<Sha3_256Kdf>();
    }

    #[test]
    fn test_shake256_prg() {
        // Test with output length of 64 bytes (common case)
        test_prg_all::<Shake256Prg<64>>();
    }
}
