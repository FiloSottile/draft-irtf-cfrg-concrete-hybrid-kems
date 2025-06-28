//! Test vector verification binary

use concrete_hybrid_kem::{
    groups::{P256Group, P384Group, X25519Group},
    kems::{MlKem768Kem, MlKem1024},
    primitives::{Sha3_256Kdf, Shake256Prg},
};
use hybrid_kem_ref::traits::{AsBytes, Kdf, Kem, NominalGroup, Prg};
use serde_json::Value;
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
    
    let test_vectors: Value = match serde_json::from_str(&content) {
        Ok(vectors) => vectors,
        Err(err) => {
            eprintln!("Error parsing JSON: {}", err);
            process::exit(1);
        }
    };
    
    println!("Verifying test vectors from {}...", filename);
    
    let mut success = true;
    
    // Verify nominal groups
    if let Some(groups) = test_vectors["test_vectors"]["nominal_groups"].as_object() {
        success &= verify_groups(groups);
    } else {
        eprintln!("Warning: No nominal group test vectors found");
    }
    
    // Verify KEMs
    if let Some(kems) = test_vectors["test_vectors"]["kems"].as_object() {
        success &= verify_kems(kems);
    } else {
        eprintln!("Warning: No KEM test vectors found");
    }
    
    // Verify primitives
    if let Some(primitives) = test_vectors["test_vectors"]["primitives"].as_object() {
        success &= verify_primitives(primitives);
    } else {
        eprintln!("Warning: No primitive test vectors found");
    }
    
    if success {
        println!("✅ All test vectors verified successfully!");
    } else {
        println!("❌ Some test vectors failed verification");
        process::exit(1);
    }
}

fn verify_groups(groups: &serde_json::Map<String, Value>) -> bool {
    let mut success = true;
    
    for (group_name, group_data) in groups {
        println!("Verifying {} group...", group_name);
        
        let result = match group_name.as_str() {
            "P256" => verify_p256_group(group_data),
            "P384" => verify_p384_group(group_data),
            "X25519" => verify_x25519_group(group_data),
            _ => {
                eprintln!("  Unknown group: {}", group_name);
                false
            }
        };
        
        if result {
            println!("  ✅ {} verification passed", group_name);
        } else {
            println!("  ❌ {} verification failed", group_name);
            success = false;
        }
    }
    
    success
}

fn verify_p256_group(data: &Value) -> bool {
    let seed_hex = data["seed"].as_str().unwrap();
    let expected_scalar_hex = data["scalar"].as_str().unwrap();
    let expected_element_hex = data["element"].as_str().unwrap();
    let expected_shared_secret_hex = data["shared_secret"].as_str().unwrap();
    
    let seed = hex::decode(seed_hex).unwrap();
    let scalar = P256Group::random_scalar(&seed).unwrap();
    let generator = P256Group::generator();
    let element = P256Group::exp(&generator, &scalar);
    let shared_secret = P256Group::element_to_shared_secret(&element);
    
    let scalar_matches = hex::encode(scalar.as_bytes()) == expected_scalar_hex;
    let element_matches = hex::encode(element.as_bytes()) == expected_element_hex;
    let shared_secret_matches = hex::encode(&shared_secret) == expected_shared_secret_hex;
    
    scalar_matches && element_matches && shared_secret_matches
}

fn verify_p384_group(data: &Value) -> bool {
    let seed_hex = data["seed"].as_str().unwrap();
    let expected_scalar_hex = data["scalar"].as_str().unwrap();
    let expected_element_hex = data["element"].as_str().unwrap();
    let expected_shared_secret_hex = data["shared_secret"].as_str().unwrap();
    
    let seed = hex::decode(seed_hex).unwrap();
    let scalar = P384Group::random_scalar(&seed).unwrap();
    let generator = P384Group::generator();
    let element = P384Group::exp(&generator, &scalar);
    let shared_secret = P384Group::element_to_shared_secret(&element);
    
    let scalar_matches = hex::encode(scalar.as_bytes()) == expected_scalar_hex;
    let element_matches = hex::encode(element.as_bytes()) == expected_element_hex;
    let shared_secret_matches = hex::encode(&shared_secret) == expected_shared_secret_hex;
    
    scalar_matches && element_matches && shared_secret_matches
}

fn verify_x25519_group(data: &Value) -> bool {
    let seed_hex = data["seed"].as_str().unwrap();
    let expected_scalar_hex = data["scalar"].as_str().unwrap();
    let expected_element_hex = data["element"].as_str().unwrap();
    let expected_shared_secret_hex = data["shared_secret"].as_str().unwrap();
    
    let seed = hex::decode(seed_hex).unwrap();
    let scalar = X25519Group::random_scalar(&seed).unwrap();
    let generator = X25519Group::generator();
    let element = X25519Group::exp(&generator, &scalar);
    let shared_secret = X25519Group::element_to_shared_secret(&element);
    
    let scalar_matches = hex::encode(scalar.as_bytes()) == expected_scalar_hex;
    let element_matches = hex::encode(element.as_bytes()) == expected_element_hex;
    let shared_secret_matches = hex::encode(&shared_secret) == expected_shared_secret_hex;
    
    scalar_matches && element_matches && shared_secret_matches
}

fn verify_kems(kems: &serde_json::Map<String, Value>) -> bool {
    let mut success = true;
    
    for (kem_name, kem_data) in kems {
        println!("Verifying {} KEM...", kem_name);
        
        let result = match kem_name.as_str() {
            "MlKem768" => verify_mlkem768(kem_data),
            "MlKem1024" => verify_mlkem1024(kem_data),
            _ => {
                eprintln!("  Unknown KEM: {}", kem_name);
                false
            }
        };
        
        if result {
            println!("  ✅ {} verification passed", kem_name);
        } else {
            println!("  ❌ {} verification failed", kem_name);
            success = false;
        }
    }
    
    success
}

fn verify_mlkem768(data: &Value) -> bool {
    let ek_hex = data["encapsulation_key"].as_str().unwrap();
    let dk_hex = data["decapsulation_key"].as_str().unwrap();
    let ct_hex = data["ciphertext"].as_str().unwrap();
    let expected_ss_hex = data["shared_secret_recovered"].as_str().unwrap();
    
    let ek_bytes = hex::decode(ek_hex).unwrap();
    let dk_bytes = hex::decode(dk_hex).unwrap();
    let ct_bytes = hex::decode(ct_hex).unwrap();
    
    let _ek = <MlKem768Kem as Kem>::EncapsulationKey::from(ek_bytes.as_slice());
    let dk = <MlKem768Kem as Kem>::DecapsulationKey::from(dk_bytes.as_slice());
    let ct = <MlKem768Kem as Kem>::Ciphertext::from(ct_bytes.as_slice());
    
    let ss = MlKem768Kem::decaps(&dk, &ct).unwrap();
    let ss_hex = hex::encode(ss.as_bytes());
    
    ss_hex == expected_ss_hex
}

fn verify_mlkem1024(data: &Value) -> bool {
    let ek_hex = data["encapsulation_key"].as_str().unwrap();
    let dk_hex = data["decapsulation_key"].as_str().unwrap();
    let ct_hex = data["ciphertext"].as_str().unwrap();
    let expected_ss_hex = data["shared_secret_recovered"].as_str().unwrap();
    
    let ek_bytes = hex::decode(ek_hex).unwrap();
    let dk_bytes = hex::decode(dk_hex).unwrap();
    let ct_bytes = hex::decode(ct_hex).unwrap();
    
    let _ek = <MlKem1024 as Kem>::EncapsulationKey::from(ek_bytes.as_slice());
    let dk = <MlKem1024 as Kem>::DecapsulationKey::from(dk_bytes.as_slice());
    let ct = <MlKem1024 as Kem>::Ciphertext::from(ct_bytes.as_slice());
    
    let ss = MlKem1024::decaps(&dk, &ct).unwrap();
    let ss_hex = hex::encode(ss.as_bytes());
    
    ss_hex == expected_ss_hex
}

fn verify_primitives(primitives: &serde_json::Map<String, Value>) -> bool {
    let mut success = true;
    
    for (primitive_name, primitive_data) in primitives {
        println!("Verifying {} primitive...", primitive_name);
        
        let result = match primitive_name.as_str() {
            "SHA3_256_KDF" => verify_sha3_256_kdf(primitive_data),
            "SHAKE256_PRG" => verify_shake256_prg(primitive_data),
            _ => {
                eprintln!("  Unknown primitive: {}", primitive_name);
                false
            }
        };
        
        if result {
            println!("  ✅ {} verification passed", primitive_name);
        } else {
            println!("  ❌ {} verification failed", primitive_name);
            success = false;
        }
    }
    
    success
}

fn verify_sha3_256_kdf(data: &Value) -> bool {
    let input_hex = data["input"].as_str().unwrap();
    let expected_output_hex = data["output"].as_str().unwrap();
    
    let input = hex::decode(input_hex).unwrap();
    let output = Sha3_256Kdf::kdf(&input);
    let output_hex = hex::encode(&output);
    
    output_hex == expected_output_hex
}

fn verify_shake256_prg(data: &Value) -> bool {
    let seed_hex = data["seed"].as_str().unwrap();
    let expected_output_hex = data["output"].as_str().unwrap();
    
    let seed = hex::decode(seed_hex).unwrap();
    let output = Shake256Prg::<64>::prg(&seed);
    let output_hex = hex::encode(&output);
    
    output_hex == expected_output_hex
}