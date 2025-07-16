//! Test vector verification binary

use concrete_hybrid_kem::{
    generic::traits::{AsBytes, EncapsDerand, Kem},
    instantiations::{
        QsfP256MlKem768Shake256Sha3256, QsfP384MlKem1024Shake256Sha3256,
        QsfX25519MlKem768Shake256Sha3256,
    },
    test_vectors::{HybridKemTestVector, TestVectors},
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

    let mut success = true;

    // Verify QSF-P256-MLKEM768-SHAKE256-SHA3256 hybrid KEM
    success &= verify_hybrid_kem_vectors::<QsfP256MlKem768Shake256Sha3256>(
        "QSF_P256_MLKEM768_SHAKE256_SHA3256",
        &test_vectors.qsf_p256_mlkem768_shake256_sha3256,
    );

    // Verify QSF-X25519-MLKEM768-SHAKE256-SHA3256 hybrid KEM
    success &= verify_hybrid_kem_vectors::<QsfX25519MlKem768Shake256Sha3256>(
        "QSF_X25519_MLKEM768_SHAKE256_SHA3256",
        &test_vectors.qsf_x25519_mlkem768_shake256_sha3256,
    );

    // Verify QSF-P384-MLKEM1024-SHAKE256-SHA3256 hybrid KEM
    success &= verify_hybrid_kem_vectors::<QsfP384MlKem1024Shake256Sha3256>(
        "QSF_P384_MLKEM1024_SHAKE256_SHA3256",
        &test_vectors.qsf_p384_mlkem1024_shake256_sha3256,
    );

    if success {
        println!("✅ All test vectors verified successfully!");
    } else {
        println!("❌ Some test vectors failed verification");
        process::exit(1);
    }
}

fn verify_hybrid_kem_vectors<T>(name: &str, vectors: &[HybridKemTestVector]) -> bool
where
    T: Kem + EncapsDerand,
    T::SharedSecret: PartialEq<Vec<u8>>,
{
    println!("Verifying {} hybrid KEM...", name);
    let mut local_success = true;

    for (i, test_vector) in vectors.iter().enumerate() {
        if !verify_hybrid_kem::<T>(test_vector) {
            println!("  ❌ Test vector {} failed", i);
            local_success = false;
        }
    }

    if local_success {
        println!("  ✅ All {} test vectors passed", vectors.len());
    }

    local_success
}

fn verify_hybrid_kem<T>(data: &HybridKemTestVector) -> bool
where
    T: Kem + EncapsDerand,
    T::SharedSecret: PartialEq<Vec<u8>>,
{
    // Verify deterministic key generation
    let (ek_regenerated, dk_regenerated) = T::derive_key_pair(&data.seed).unwrap();
    if ek_regenerated.as_bytes() != data.encapsulation_key
        || dk_regenerated.as_bytes() != data.decapsulation_key
    {
        return false;
    }

    // Verify deterministic encapsulation
    let (ct_regenerated, ss_regenerated) =
        T::encaps_derand(&ek_regenerated, &data.randomness).unwrap();
    if ct_regenerated.as_bytes() != data.ciphertext || ss_regenerated != data.shared_secret {
        return false;
    }

    // Verify decapsulation consistency
    let dk = T::DecapsulationKey::from(data.decapsulation_key.as_slice());
    let ct = T::Ciphertext::from(data.ciphertext.as_slice());
    let ss = T::decaps(&dk, &ct).unwrap();

    ss == data.shared_secret
}
