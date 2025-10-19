//! Test vector verification binary

use concrete_hybrid_kem::{
    hybrid::{EncapsDerand, Kem, MlKem1024P384, MlKem768P256, MlKem768X25519, SeedSize},
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
    println!("Using bis module implementation");

    let mut success = true;

    // Verify QSF-P256-MLKEM768-SHAKE256-SHA3256 hybrid KEM using bis::MlKem768P256
    success &= verify_hybrid_kem_vectors::<MlKem768P256>(
        "QSF_P256_MLKEM768_SHAKE256_SHA3256 (bis::MlKem768P256)",
        &test_vectors.qsf_p256_mlkem768_shake256_sha3256,
    );

    // Verify QSF-X25519-MLKEM768-SHAKE256-SHA3256 hybrid KEM using bis::MlKem768X25519
    success &= verify_hybrid_kem_vectors::<MlKem768X25519>(
        "QSF_X25519_MLKEM768_SHAKE256_SHA3256 (bis::MlKem768X25519)",
        &test_vectors.qsf_x25519_mlkem768_shake256_sha3256,
    );

    // Verify QSF-P384-MLKEM1024-SHAKE256-SHA3256 hybrid KEM using bis::MlKem1024P384
    success &= verify_hybrid_kem_vectors::<MlKem1024P384>(
        "QSF_P384_MLKEM1024_SHAKE256_SHA3256 (bis::MlKem1024P384)",
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
    T: Kem + EncapsDerand + SeedSize,
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
    T: Kem + EncapsDerand + SeedSize,
{
    // Verify deterministic key generation
    let (dk_regenerated, ek_regenerated) = T::derive_key_pair(&data.seed);
    if ek_regenerated != data.encapsulation_key || dk_regenerated != data.decapsulation_key {
        eprintln!("  Key derivation mismatch");
        eprintln!("    Expected EK: {}", hex::encode(&data.encapsulation_key));
        eprintln!("    Got EK:      {}", hex::encode(&ek_regenerated));
        eprintln!("    Expected DK: {}", hex::encode(&data.decapsulation_key));
        eprintln!("    Got DK:      {}", hex::encode(&dk_regenerated));
        return false;
    }

    // Verify deterministic encapsulation
    let (ct_regenerated, ss_regenerated) = T::encaps_derand(&ek_regenerated, &data.randomness);
    if ct_regenerated != data.ciphertext || ss_regenerated != data.shared_secret {
        eprintln!("  Encapsulation mismatch");
        eprintln!("    Expected CT: {}", hex::encode(&data.ciphertext));
        eprintln!("    Got CT:      {}", hex::encode(&ct_regenerated));
        eprintln!("    Expected SS: {}", hex::encode(&data.shared_secret));
        eprintln!("    Got SS:      {}", hex::encode(&ss_regenerated));
        return false;
    }

    // Verify decapsulation consistency
    let ss = T::decaps(&dk_regenerated, &ct_regenerated);

    if ss != data.shared_secret {
        eprintln!("  Decapsulation mismatch");
        eprintln!("    Expected SS: {}", hex::encode(&data.shared_secret));
        eprintln!("    Got SS:      {}", hex::encode(&ss));
        return false;
    }

    true
}
