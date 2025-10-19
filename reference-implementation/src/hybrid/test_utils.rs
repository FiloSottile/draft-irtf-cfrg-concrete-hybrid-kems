//! Generic test utilities for bis trait implementations
//!
//! This module provides reusable test functions that can be used to verify
//! any implementation of the bis KEM, KDF, PRG, and NominalGroup traits.

use super::{EncapsDerand, Kdf, Kem, NominalGroup, Prg, SeedSize, SharedSecretSize};
use rand::{CryptoRng, Rng};

/// Generic test for KDF determinism and output length
pub fn test_kdf_basic<K: Kdf>() {
    // Create test input
    let input: Vec<u8> = (0..100).map(|i| (i as u8).wrapping_mul(17).wrapping_add(42)).collect();

    // Test output length
    let output = K::compute(input.iter().cloned());
    assert_eq!(output.len(), K::OUTPUT_SIZE, "KDF output length mismatch");

    // Test determinism
    let output2 = K::compute(input.iter().cloned());
    assert_eq!(output, output2, "KDF should be deterministic");

    // Test different inputs produce different outputs
    let mut input2 = input.clone();
    input2[0] = input2[0].wrapping_add(1);
    let output3 = K::compute(input2.iter().cloned());
    assert_ne!(
        output, output3,
        "Different inputs should produce different outputs"
    );
}

/// Generic test for PRG determinism, output length, and expansion
pub fn test_prg_basic<P: Prg>() {
    // Create test seed
    let seed: Vec<u8> = (0..32).map(|i| (i as u8).wrapping_mul(23).wrapping_add(77)).collect();

    // Test output length
    let output_len = 128;
    let output = P::generate(&seed, output_len);
    assert_eq!(output.len(), output_len, "PRG output length mismatch");

    // Test determinism
    let output2 = P::generate(&seed, output_len);
    assert_eq!(output, output2, "PRG should be deterministic");

    // Test different seeds produce different outputs
    let mut seed2 = seed.clone();
    seed2[0] = seed2[0].wrapping_add(1);
    let output3 = P::generate(&seed2, output_len);
    assert_ne!(
        output, output3,
        "Different seeds should produce different outputs"
    );

    // Test different output lengths work
    let output4 = P::generate(&seed, output_len * 2);
    assert_eq!(output4.len(), output_len * 2, "PRG should support different output lengths");
}

/// Generic test for KEM deterministic key derivation
pub fn test_kem_deterministic_derivation<K: Kem + SeedSize>() {
    // Create test seed
    let seed: Vec<u8> = (0..K::SEED_SIZE).map(|i| (i as u8).wrapping_mul(31).wrapping_add(13)).collect();

    // Test deterministic key derivation
    let (dk1, ek1) = K::derive_key_pair(&seed);
    let (dk2, ek2) = K::derive_key_pair(&seed);

    assert_eq!(
        ek1, ek2,
        "Deterministic key derivation should produce same encapsulation key"
    );
    assert_eq!(
        dk1, dk2,
        "Deterministic key derivation should produce same decapsulation key"
    );

    // Test key sizes
    assert_eq!(
        dk1.len(),
        K::DECAPSULATION_KEY_SIZE,
        "Decapsulation key size mismatch"
    );
    assert_eq!(
        ek1.len(),
        K::ENCAPSULATION_KEY_SIZE,
        "Encapsulation key size mismatch"
    );
}

/// Generic test for KEM encapsulation/decapsulation roundtrip
pub fn test_kem_roundtrip<K: Kem + SeedSize + SharedSecretSize, R: CryptoRng>(rng: &mut R) {
    // Generate key pair
    let mut seed = vec![0u8; K::SEED_SIZE];
    rng.fill(seed.as_mut_slice());
    let (dk, ek) = K::derive_key_pair(&seed);

    // Test encapsulation
    let (ss1, ct) = K::encaps(&ek, rng);

    // Test sizes
    assert_eq!(
        ct.len(),
        K::CIPHERTEXT_SIZE,
        "Ciphertext size mismatch"
    );
    assert_eq!(
        ss1.len(),
        K::SHARED_SECRET_SIZE,
        "Shared secret size mismatch"
    );

    // Test decapsulation
    let ss2 = K::decaps(&dk, &ct);

    assert_eq!(
        ss1, ss2,
        "Encapsulation and decapsulation should produce same shared secret"
    );

    // Test that different encapsulations produce different ciphertexts (with very high probability)
    let (_ss3, ct3) = K::encaps(&ek, rng);
    let (_ss4, ct4) = K::encaps(&ek, rng);

    // With proper randomness, ciphertexts should be different
    assert_ne!(ct3, ct4, "Different encapsulations should produce different ciphertexts");
}

/// Generic test for KEM deterministic encapsulation
pub fn test_kem_deterministic_encaps<K: Kem + EncapsDerand + SeedSize + SharedSecretSize, R: CryptoRng>(rng: &mut R) {
    // Generate key pair
    let mut seed = vec![0u8; K::SEED_SIZE];
    rng.fill(seed.as_mut_slice());
    let (dk, ek) = K::derive_key_pair(&seed);

    // Create deterministic randomness
    let randomness = vec![42u8; K::RANDOMNESS_SIZE];

    // Test deterministic encapsulation
    let (ct1, ss1) = K::encaps_derand(&ek, &randomness);
    let (ct2, ss2) = K::encaps_derand(&ek, &randomness);

    assert_eq!(
        ct1, ct2,
        "Deterministic encapsulation should produce same ciphertext"
    );
    assert_eq!(
        ss1, ss2,
        "Deterministic encapsulation should produce same shared secret"
    );

    // Test sizes
    assert_eq!(ct1.len(), K::CIPHERTEXT_SIZE, "Ciphertext size mismatch");
    assert_eq!(ss1.len(), K::SHARED_SECRET_SIZE, "Shared secret size mismatch");

    // Test that it decapsulates correctly
    let ss3 = K::decaps(&dk, &ct1);

    assert_eq!(
        ss1, ss3,
        "Deterministic encapsulation should be compatible with decapsulation"
    );

    // Test that different randomness produces different outputs
    let randomness2 = vec![43u8; K::RANDOMNESS_SIZE];
    let (ct4, ss4) = K::encaps_derand(&ek, &randomness2);

    assert_ne!(ct1, ct4, "Different randomness should produce different ciphertext");
    assert_ne!(ss1, ss4, "Different randomness should produce different shared secret");
}

/// Generic test for NominalGroup basic operations
pub fn test_group_basic_operations<G: NominalGroup + SeedSize + SharedSecretSize>() {
    // Test generator
    let generator = G::generator();
    assert_eq!(
        generator.len(),
        G::ELEMENT_SIZE,
        "Generator size mismatch"
    );

    // Test scalar generation
    let seed: Vec<u8> = (0..G::SEED_SIZE).map(|i| (i as u8).wrapping_mul(41).wrapping_add(29)).collect();

    let scalar = G::random_scalar(&seed);
    assert_eq!(
        scalar.len(),
        G::SCALAR_SIZE,
        "Scalar size mismatch"
    );

    // Test exponentiation
    let element = G::exp(&generator, &scalar);
    assert_eq!(
        element.len(),
        G::ELEMENT_SIZE,
        "Element size mismatch"
    );

    // Test shared secret extraction
    let shared_secret = G::element_to_shared_secret(&element);
    assert_eq!(
        shared_secret.len(),
        G::SHARED_SECRET_SIZE,
        "Shared secret size mismatch"
    );
}

/// Generic test for NominalGroup Diffie-Hellman properties
pub fn test_group_diffie_hellman<G: NominalGroup + SeedSize + SharedSecretSize>() {
    let generator = G::generator();

    // Generate two scalars
    let seed_a = vec![1u8; G::SEED_SIZE];
    let seed_b = vec![2u8; G::SEED_SIZE];

    let scalar_a = G::random_scalar(&seed_a);
    let scalar_b = G::random_scalar(&seed_b);

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
    let scalar_a2 = G::random_scalar(&seed_a);

    assert_eq!(
        scalar_a, scalar_a2,
        "Scalar generation should be deterministic"
    );
}

/// Generic test for NominalGroup determinism
pub fn test_group_determinism<G: NominalGroup + SeedSize>() {
    // Test generator determinism
    let gen1 = G::generator();
    let gen2 = G::generator();
    assert_eq!(gen1, gen2, "Generator should be deterministic");

    // Test scalar generation determinism
    let seed = vec![42u8; G::SEED_SIZE];
    let scalar1 = G::random_scalar(&seed);
    let scalar2 = G::random_scalar(&seed);
    assert_eq!(scalar1, scalar2, "Scalar generation should be deterministic");

    // Test exponentiation determinism
    let elem1 = G::exp(&gen1, &scalar1);
    let elem2 = G::exp(&gen2, &scalar2);
    assert_eq!(elem1, elem2, "Exponentiation should be deterministic");
}

/// Run all KDF tests for a given implementation
pub fn test_kdf_all<K: Kdf>() {
    test_kdf_basic::<K>();
}

/// Run all PRG tests for a given implementation
pub fn test_prg_all<P: Prg>() {
    test_prg_basic::<P>();
}

/// Run all KEM tests for a given implementation
pub fn test_kem_all<K: Kem + EncapsDerand + SeedSize + SharedSecretSize, R: CryptoRng>(rng: &mut R) {
    test_kem_deterministic_derivation::<K>();
    test_kem_roundtrip::<K, R>(rng);
    test_kem_deterministic_encaps::<K, R>(rng);
}

/// Run all NominalGroup tests for a given implementation
pub fn test_group_all<G: NominalGroup + SeedSize + SharedSecretSize>() {
    test_group_basic_operations::<G>();
    test_group_diffie_hellman::<G>();
    test_group_determinism::<G>();
}
