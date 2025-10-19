//! Test vector generation binary

use concrete_hybrid_kem::{
    hybrid::{EncapsDerand, Kem, MlKem1024P384, MlKem768P256, MlKem768X25519, SeedSize},
    test_vectors::{HybridKemTestVector, TestVectors},
};

fn main() {
    eprintln!("Generating test vectors for concrete hybrid KEMs...");
    eprintln!("Using bis module implementation");

    // Generate 10 test vectors for QSF-P256-MLKEM768-SHAKE256-SHA3256
    let mut qsf_p256_vectors = Vec::new();
    for i in 0..10 {
        let seed = vec![i + 1; MlKem768P256::SEED_SIZE];
        let randomness = vec![i + 100; MlKem768P256::RANDOMNESS_SIZE];
        let (dk, ek) = MlKem768P256::derive_key_pair(&seed);
        let (ct, ss) = MlKem768P256::encaps_derand(&ek, &randomness);

        qsf_p256_vectors.push(HybridKemTestVector {
            seed,
            randomness,
            encapsulation_key: ek,
            decapsulation_key: dk,
            ciphertext: ct,
            shared_secret: ss,
        });
    }

    // Generate 10 test vectors for QSF-X25519-MLKEM768-SHAKE256-SHA3256
    let mut qsf_x25519_vectors = Vec::new();
    for i in 0..10 {
        let seed = vec![i + 11; MlKem768X25519::SEED_SIZE];
        let randomness = vec![i + 111; MlKem768X25519::RANDOMNESS_SIZE];
        let (dk, ek) = MlKem768X25519::derive_key_pair(&seed);
        let (ct, ss) = MlKem768X25519::encaps_derand(&ek, &randomness);

        qsf_x25519_vectors.push(HybridKemTestVector {
            seed,
            randomness,
            encapsulation_key: ek,
            decapsulation_key: dk,
            ciphertext: ct,
            shared_secret: ss,
        });
    }

    // Generate 10 test vectors for QSF-P384-MLKEM1024-SHAKE256-SHA3256
    let mut qsf_p384_vectors = Vec::new();
    for i in 0..10 {
        let seed = vec![i + 21; MlKem1024P384::SEED_SIZE];
        let randomness = vec![i + 121; MlKem1024P384::RANDOMNESS_SIZE];
        let (dk, ek) = MlKem1024P384::derive_key_pair(&seed);
        let (ct, ss) = MlKem1024P384::encaps_derand(&ek, &randomness);

        qsf_p384_vectors.push(HybridKemTestVector {
            seed,
            randomness,
            encapsulation_key: ek,
            decapsulation_key: dk,
            ciphertext: ct,
            shared_secret: ss,
        });
    }

    let test_vectors = TestVectors {
        qsf_p256_mlkem768_shake256_sha3256: qsf_p256_vectors,
        qsf_x25519_mlkem768_shake256_sha3256: qsf_x25519_vectors,
        qsf_p384_mlkem1024_shake256_sha3256: qsf_p384_vectors,
    };

    // Output as JSON
    println!("{}", serde_json::to_string_pretty(&test_vectors).unwrap());
}
