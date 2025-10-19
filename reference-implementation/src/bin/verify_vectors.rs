//! Test vector verification binary

use concrete_hybrid_kem::{
    hybrid::HybridKem,
    test_vectors::{HybridKemTestVector, TestVectors, VerifyError},
    MlKem1024P384, MlKem768P256, MlKem768X25519,
};
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <test_vectors.json>", args[0]);
        process::exit(1);
    }

    let filename = &args[1];
    let content = match fs::read_to_string(filename) {
        Ok(content) => content,
        Err(err) => {
            eprintln!("Error reading file {}: {}", filename, err);
            process::exit(1);
        }
    };

    let test_vectors: TestVectors = match serde_json::from_str(&content) {
        Ok(vectors) => vectors,
        Err(err) => {
            eprintln!("Error parsing JSON: {}", err);
            process::exit(1);
        }
    };

    println!("Verifying test vectors from {}...", filename);

    let mlkem768_p256 =
        verify_hybrid_kem_vectors::<MlKem768P256>("MLKEM768-P256", &test_vectors.mlkem768_p256);

    let mlkem768_x25519 = verify_hybrid_kem_vectors::<MlKem768X25519>(
        "MLKEM768-X25519",
        &test_vectors.mlkem768_x25519,
    );

    let mlkem1024_p384 =
        verify_hybrid_kem_vectors::<MlKem1024P384>("MLKEM1024-P384", &test_vectors.mlkem1024_p384);

    if mlkem768_p256 && mlkem768_x25519 && mlkem1024_p384 {
        println!("✅ All test vectors verified successfully!");
    } else {
        println!("❌ Some test vectors failed verification");
        process::exit(1);
    }
}

fn verify_hybrid_kem_vectors<K: HybridKem>(name: &str, vectors: &[HybridKemTestVector]) -> bool {
    println!("Verifying {} hybrid KEM...", name);

    let error_count = vectors
        .iter()
        .map(|v| v.verify::<K>())
        .enumerate()
        .filter_map(|(i, rv)| rv.err().map(|rv| (i, rv)))
        .map(|(i, err)| print_failure(name, i, err))
        .count();

    error_count == 0
}

fn print_failure(name: &str, index: usize, err: VerifyError) {
    println!("Error in vector #{} for {}", index, name);
    match err {
        VerifyError::EncapsulationKey(my, vec) => println!(
            "EncapsulationKey my={} vec={}",
            hex::encode(my),
            hex::encode(vec)
        ),

        VerifyError::DecapsulationKey(my, vec) => println!(
            "DecapsulationKey my={} vec={}",
            hex::encode(my),
            hex::encode(vec)
        ),

        VerifyError::Ciphertext(my, vec) => {
            println!("Ciphertext my={} vec={}", hex::encode(my), hex::encode(vec))
        }

        VerifyError::SharedSecretEncaps(my, vec) => println!(
            "SharedSecretEncaps my={} vec={}",
            hex::encode(my),
            hex::encode(vec)
        ),

        VerifyError::SharedSecretDecaps(my, vec) => println!(
            "SharedSecretDecaps my={} vec={}",
            hex::encode(my),
            hex::encode(vec)
        ),
    }
}
