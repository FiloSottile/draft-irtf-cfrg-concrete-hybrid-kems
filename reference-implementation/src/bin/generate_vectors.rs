//! Test vector generation binary

use concrete_hybrid_kem::{
    test_vectors::{HybridKemTestVector, TestVectors},
    MlKem1024P384, MlKem768P256, MlKem768X25519,
};

fn main() {
    eprintln!("Generating test vectors for concrete hybrid KEMs...");

    // Generate 10 test vectors for each hybrid KEM
    const N_VECTORS: u8 = 10;

    let mlkem768_p256 = (0..N_VECTORS)
        .map(|i| HybridKemTestVector::generate::<MlKem768P256>(i))
        .collect();

    let mlkem768_x25519 = (0..N_VECTORS)
        .map(|i| HybridKemTestVector::generate::<MlKem768X25519>(i))
        .collect();

    let mlkem1024_p384 = (0..N_VECTORS)
        .map(|i| HybridKemTestVector::generate::<MlKem1024P384>(i))
        .collect();

    let test_vectors = TestVectors {
        mlkem768_p256,
        mlkem768_x25519,
        mlkem1024_p384,
    };

    // Output as JSON
    println!("{}", serde_json::to_string_pretty(&test_vectors).unwrap());
}
