//! Test vector generation binary

use concrete_hybrid_kem::{
    groups::{P256Group, P384Group, X25519Group},
    instantiations::{
        QsfP256MlKem768Shake256Sha3256, QsfP384MlKem1024Shake256Sha3256,
        QsfX25519MlKem768Shake256Sha3256,
    },
    kems::{MlKem768Kem, MlKem1024},
    primitives::{Sha3_256Kdf, Shake256Prg},
};
use hybrid_kem_ref::traits::{AsBytes, Kdf, Kem, NominalGroup, Prg};
use serde_json::{json, Value};
use std::collections::HashMap;

fn main() {
    eprintln!("Generating test vectors for concrete hybrid KEM components...");
    
    let mut test_vectors = HashMap::new();
    
    // Generate test vectors for nominal groups
    test_vectors.insert("nominal_groups", generate_group_test_vectors());
    
    // Generate test vectors for KEMs
    test_vectors.insert("kems", generate_kem_test_vectors());
    
    // Generate test vectors for hybrid KEMs
    test_vectors.insert("hybrid_kems", generate_hybrid_kem_test_vectors());
    
    // Generate test vectors for primitives
    test_vectors.insert("primitives", generate_primitive_test_vectors());
    
    // Output as JSON
    let output = json!({
        "test_vectors": test_vectors,
        "metadata": {
            "version": "1.0",
            "specification": "draft-irtf-cfrg-concrete-hybrid-kems",
            "description": "Test vectors for concrete hybrid KEM components"
        }
    });
    
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn generate_group_test_vectors() -> Value {
    let mut groups = HashMap::new();
    
    // P-256 test vectors
    let p256_seed = vec![1u8; P256Group::SEED_LENGTH];
    let p256_scalar = P256Group::random_scalar(&p256_seed).unwrap();
    let p256_generator = P256Group::generator();
    let p256_element = P256Group::exp(&p256_generator, &p256_scalar);
    let p256_shared_secret = P256Group::element_to_shared_secret(&p256_element);
    
    groups.insert("P256", json!({
        "seed": hex::encode(&p256_seed),
        "scalar": hex::encode(p256_scalar.as_bytes()),
        "generator": hex::encode(p256_generator.as_bytes()),
        "element": hex::encode(p256_element.as_bytes()),
        "shared_secret": hex::encode(&p256_shared_secret),
        "constants": {
            "seed_length": P256Group::SEED_LENGTH,
            "scalar_length": P256Group::SCALAR_LENGTH,
            "element_length": P256Group::ELEMENT_LENGTH,
            "shared_secret_length": P256Group::SHARED_SECRET_LENGTH
        }
    }));
    
    // P-384 test vectors
    let p384_seed = vec![2u8; P384Group::SEED_LENGTH];
    let p384_scalar = P384Group::random_scalar(&p384_seed).unwrap();
    let p384_generator = P384Group::generator();
    let p384_element = P384Group::exp(&p384_generator, &p384_scalar);
    let p384_shared_secret = P384Group::element_to_shared_secret(&p384_element);
    
    groups.insert("P384", json!({
        "seed": hex::encode(&p384_seed),
        "scalar": hex::encode(p384_scalar.as_bytes()),
        "generator": hex::encode(p384_generator.as_bytes()),
        "element": hex::encode(p384_element.as_bytes()),
        "shared_secret": hex::encode(&p384_shared_secret),
        "constants": {
            "seed_length": P384Group::SEED_LENGTH,
            "scalar_length": P384Group::SCALAR_LENGTH,
            "element_length": P384Group::ELEMENT_LENGTH,
            "shared_secret_length": P384Group::SHARED_SECRET_LENGTH
        }
    }));
    
    // X25519 test vectors
    let x25519_seed = vec![3u8; X25519Group::SEED_LENGTH];
    let x25519_scalar = X25519Group::random_scalar(&x25519_seed).unwrap();
    let x25519_generator = X25519Group::generator();
    let x25519_element = X25519Group::exp(&x25519_generator, &x25519_scalar);
    let x25519_shared_secret = X25519Group::element_to_shared_secret(&x25519_element);
    
    groups.insert("X25519", json!({
        "seed": hex::encode(&x25519_seed),
        "scalar": hex::encode(x25519_scalar.as_bytes()),
        "generator": hex::encode(x25519_generator.as_bytes()),
        "element": hex::encode(x25519_element.as_bytes()),
        "shared_secret": hex::encode(&x25519_shared_secret),
        "constants": {
            "seed_length": X25519Group::SEED_LENGTH,
            "scalar_length": X25519Group::SCALAR_LENGTH,
            "element_length": X25519Group::ELEMENT_LENGTH,
            "shared_secret_length": X25519Group::SHARED_SECRET_LENGTH
        }
    }));
    
    json!(groups)
}

fn generate_kem_test_vectors() -> Value {
    let mut kems = HashMap::new();
    let mut rng = rand::rng();
    
    // ML-KEM-768 test vectors
    let (ek768, dk768) = MlKem768Kem::generate_key_pair(&mut rng).unwrap();
    let (ct768, ss768) = MlKem768Kem::encaps(&ek768, &mut rng).unwrap();
    let ss768_recovered = MlKem768Kem::decaps(&dk768, &ct768).unwrap();
    
    kems.insert("MlKem768", json!({
        "encapsulation_key": hex::encode(ek768.as_bytes()),
        "decapsulation_key": hex::encode(dk768.as_bytes()),
        "ciphertext": hex::encode(ct768.as_bytes()),
        "shared_secret": hex::encode(ss768.as_bytes()),
        "shared_secret_recovered": hex::encode(ss768_recovered.as_bytes()),
        "constants": {
            "seed_length": MlKem768Kem::SEED_LENGTH,
            "encapsulation_key_length": MlKem768Kem::ENCAPSULATION_KEY_LENGTH,
            "decapsulation_key_length": MlKem768Kem::DECAPSULATION_KEY_LENGTH,
            "ciphertext_length": MlKem768Kem::CIPHERTEXT_LENGTH,
            "shared_secret_length": MlKem768Kem::SHARED_SECRET_LENGTH
        }
    }));
    
    // ML-KEM-1024 test vectors
    let (ek1024, dk1024) = MlKem1024::generate_key_pair(&mut rng).unwrap();
    let (ct1024, ss1024) = MlKem1024::encaps(&ek1024, &mut rng).unwrap();
    let ss1024_recovered = MlKem1024::decaps(&dk1024, &ct1024).unwrap();
    
    kems.insert("MlKem1024", json!({
        "encapsulation_key": hex::encode(ek1024.as_bytes()),
        "decapsulation_key": hex::encode(dk1024.as_bytes()),
        "ciphertext": hex::encode(ct1024.as_bytes()),
        "shared_secret": hex::encode(ss1024.as_bytes()),
        "shared_secret_recovered": hex::encode(ss1024_recovered.as_bytes()),
        "constants": {
            "seed_length": MlKem1024::SEED_LENGTH,
            "encapsulation_key_length": MlKem1024::ENCAPSULATION_KEY_LENGTH,
            "decapsulation_key_length": MlKem1024::DECAPSULATION_KEY_LENGTH,
            "ciphertext_length": MlKem1024::CIPHERTEXT_LENGTH,
            "shared_secret_length": MlKem1024::SHARED_SECRET_LENGTH
        }
    }));
    
    json!(kems)
}

fn generate_primitive_test_vectors() -> Value {
    let mut primitives = HashMap::new();
    
    // SHA3-256 KDF test vectors
    let kdf_input = vec![42u8; 32];
    let kdf_output = Sha3_256Kdf::kdf(&kdf_input);
    
    primitives.insert("SHA3_256_KDF", json!({
        "input": hex::encode(&kdf_input),
        "output": hex::encode(&kdf_output),
        "constants": {
            "input_length": Sha3_256Kdf::INPUT_LENGTH,
            "output_length": Sha3_256Kdf::OUTPUT_LENGTH
        }
    }));
    
    // SHAKE256 PRG test vectors (64-byte output)
    let prg_seed = vec![24u8; 32];
    let prg_output = Shake256Prg::<64>::prg(&prg_seed);
    
    primitives.insert("SHAKE256_PRG", json!({
        "seed": hex::encode(&prg_seed),
        "output": hex::encode(&prg_output),
        "constants": {
            "input_length": Shake256Prg::<64>::INPUT_LENGTH,
            "output_length": Shake256Prg::<64>::OUTPUT_LENGTH
        }
    }));
    
    json!(primitives)
}

fn generate_hybrid_kem_test_vectors() -> Value {
    let mut hybrid_kems = HashMap::new();
    let mut rng = rand::rng();
    
    // QSF-P256-MLKEM768-SHAKE256-SHA3256 test vectors
    let (ek_p256, dk_p256) = QsfP256MlKem768Shake256Sha3256::generate_key_pair(&mut rng).unwrap();
    let (ct_p256, ss_p256) = QsfP256MlKem768Shake256Sha3256::encaps(&ek_p256, &mut rng).unwrap();
    let ss_p256_recovered = QsfP256MlKem768Shake256Sha3256::decaps(&dk_p256, &ct_p256).unwrap();
    
    hybrid_kems.insert("QSF_P256_MLKEM768_SHAKE256_SHA3256", json!({
        "encapsulation_key": hex::encode(ek_p256.as_bytes()),
        "decapsulation_key": hex::encode(dk_p256.as_bytes()),
        "ciphertext": hex::encode(ct_p256.as_bytes()),
        "shared_secret": hex::encode(&ss_p256),
        "shared_secret_recovered": hex::encode(&ss_p256_recovered),
        "constants": {
            "seed_length": QsfP256MlKem768Shake256Sha3256::SEED_LENGTH,
            "encapsulation_key_length": QsfP256MlKem768Shake256Sha3256::ENCAPSULATION_KEY_LENGTH,
            "decapsulation_key_length": QsfP256MlKem768Shake256Sha3256::DECAPSULATION_KEY_LENGTH,
            "ciphertext_length": QsfP256MlKem768Shake256Sha3256::CIPHERTEXT_LENGTH,
            "shared_secret_length": QsfP256MlKem768Shake256Sha3256::SHARED_SECRET_LENGTH
        }
    }));
    
    // QSF-X25519-MLKEM768-SHAKE256-SHA3256 test vectors (X-Wing)
    let (ek_x25519, dk_x25519) = QsfX25519MlKem768Shake256Sha3256::generate_key_pair(&mut rng).unwrap();
    let (ct_x25519, ss_x25519) = QsfX25519MlKem768Shake256Sha3256::encaps(&ek_x25519, &mut rng).unwrap();
    let ss_x25519_recovered = QsfX25519MlKem768Shake256Sha3256::decaps(&dk_x25519, &ct_x25519).unwrap();
    
    hybrid_kems.insert("QSF_X25519_MLKEM768_SHAKE256_SHA3256", json!({
        "encapsulation_key": hex::encode(ek_x25519.as_bytes()),
        "decapsulation_key": hex::encode(dk_x25519.as_bytes()),
        "ciphertext": hex::encode(ct_x25519.as_bytes()),
        "shared_secret": hex::encode(&ss_x25519),
        "shared_secret_recovered": hex::encode(&ss_x25519_recovered),
        "constants": {
            "seed_length": QsfX25519MlKem768Shake256Sha3256::SEED_LENGTH,
            "encapsulation_key_length": QsfX25519MlKem768Shake256Sha3256::ENCAPSULATION_KEY_LENGTH,
            "decapsulation_key_length": QsfX25519MlKem768Shake256Sha3256::DECAPSULATION_KEY_LENGTH,
            "ciphertext_length": QsfX25519MlKem768Shake256Sha3256::CIPHERTEXT_LENGTH,
            "shared_secret_length": QsfX25519MlKem768Shake256Sha3256::SHARED_SECRET_LENGTH
        }
    }));
    
    // QSF-P384-MLKEM1024-SHAKE256-SHA3256 test vectors
    let (ek_p384, dk_p384) = QsfP384MlKem1024Shake256Sha3256::generate_key_pair(&mut rng).unwrap();
    let (ct_p384, ss_p384) = QsfP384MlKem1024Shake256Sha3256::encaps(&ek_p384, &mut rng).unwrap();
    let ss_p384_recovered = QsfP384MlKem1024Shake256Sha3256::decaps(&dk_p384, &ct_p384).unwrap();
    
    hybrid_kems.insert("QSF_P384_MLKEM1024_SHAKE256_SHA3256", json!({
        "encapsulation_key": hex::encode(ek_p384.as_bytes()),
        "decapsulation_key": hex::encode(dk_p384.as_bytes()),
        "ciphertext": hex::encode(ct_p384.as_bytes()),
        "shared_secret": hex::encode(&ss_p384),
        "shared_secret_recovered": hex::encode(&ss_p384_recovered),
        "constants": {
            "seed_length": QsfP384MlKem1024Shake256Sha3256::SEED_LENGTH,
            "encapsulation_key_length": QsfP384MlKem1024Shake256Sha3256::ENCAPSULATION_KEY_LENGTH,
            "decapsulation_key_length": QsfP384MlKem1024Shake256Sha3256::DECAPSULATION_KEY_LENGTH,
            "ciphertext_length": QsfP384MlKem1024Shake256Sha3256::CIPHERTEXT_LENGTH,
            "shared_secret_length": QsfP384MlKem1024Shake256Sha3256::SHARED_SECRET_LENGTH
        }
    }));
    
    json!(hybrid_kems)
}