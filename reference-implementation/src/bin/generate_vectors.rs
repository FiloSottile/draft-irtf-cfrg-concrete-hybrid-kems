//! Test vector generation binary

use concrete_hybrid_kem::{
    generic::traits::{AsBytes, EncapsDerand, Kem},
    instantiations::{
        QsfP256MlKem768Shake256Sha3256, QsfP384MlKem1024Shake256Sha3256,
        QsfX25519MlKem768Shake256Sha3256,
    },
    test_vectors::{HybridKemTestVector, TestVectors},
};

fn main() {
    eprintln!("Generating test vectors for concrete hybrid KEMs...");

    // Generate 10 test vectors for QSF-P256-MLKEM768-SHAKE256-SHA3256
    let mut qsf_p256_vectors = Vec::new();
    for i in 0..10 {
        let seed = vec![i + 1; QsfP256MlKem768Shake256Sha3256::SEED_LENGTH];
        let randomness = vec![i + 100; QsfP256MlKem768Shake256Sha3256::RANDOMNESS_LENGTH];
        let (ek, dk) = QsfP256MlKem768Shake256Sha3256::derive_key_pair(&seed).unwrap();
        let (ct, ss) = QsfP256MlKem768Shake256Sha3256::encaps_derand(&ek, &randomness).unwrap();

        qsf_p256_vectors.push(HybridKemTestVector {
            seed,
            randomness,
            encapsulation_key: ek.as_bytes().to_vec(),
            decapsulation_key: dk.as_bytes().to_vec(),
            ciphertext: ct.as_bytes().to_vec(),
            shared_secret: ss,
        });
    }

    // Generate 10 test vectors for QSF-X25519-MLKEM768-SHAKE256-SHA3256
    let mut qsf_x25519_vectors = Vec::new();
    for i in 0..10 {
        let seed = vec![i + 11; QsfX25519MlKem768Shake256Sha3256::SEED_LENGTH];
        let randomness = vec![i + 111; QsfX25519MlKem768Shake256Sha3256::RANDOMNESS_LENGTH];
        let (ek, dk) = QsfX25519MlKem768Shake256Sha3256::derive_key_pair(&seed).unwrap();
        let (ct, ss) = QsfX25519MlKem768Shake256Sha3256::encaps_derand(&ek, &randomness).unwrap();

        qsf_x25519_vectors.push(HybridKemTestVector {
            seed,
            randomness,
            encapsulation_key: ek.as_bytes().to_vec(),
            decapsulation_key: dk.as_bytes().to_vec(),
            ciphertext: ct.as_bytes().to_vec(),
            shared_secret: ss,
        });
    }

    // Generate 10 test vectors for QSF-P384-MLKEM1024-SHAKE256-SHA3256
    let mut qsf_p384_vectors = Vec::new();
    for i in 0..10 {
        let seed = vec![i + 21; QsfP384MlKem1024Shake256Sha3256::SEED_LENGTH];
        let randomness = vec![i + 121; QsfP384MlKem1024Shake256Sha3256::RANDOMNESS_LENGTH];
        let (ek, dk) = QsfP384MlKem1024Shake256Sha3256::derive_key_pair(&seed).unwrap();
        let (ct, ss) = QsfP384MlKem1024Shake256Sha3256::encaps_derand(&ek, &randomness).unwrap();

        qsf_p384_vectors.push(HybridKemTestVector {
            seed,
            randomness,
            encapsulation_key: ek.as_bytes().to_vec(),
            decapsulation_key: dk.as_bytes().to_vec(),
            ciphertext: ct.as_bytes().to_vec(),
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
