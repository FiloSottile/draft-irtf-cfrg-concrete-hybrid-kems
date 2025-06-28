//! Test vector to Markdown converter binary

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
    
    eprintln!("Converting test vectors from {} to Markdown...", filename);
    
    // Generate the Markdown content
    println!("# Test Vectors");
    println!();
    
    if let Some(metadata) = test_vectors["metadata"].as_object() {
        if let Some(spec) = metadata["specification"].as_str() {
            println!("Test vectors for {}.", spec);
        }
        if let Some(description) = metadata["description"].as_str() {
            println!("{}", description);
        }
        if let Some(version) = metadata["version"].as_str() {
            println!("Version: {}", version);
        }
        println!();
    }
    
    // Convert nominal groups
    if let Some(groups) = test_vectors["test_vectors"]["nominal_groups"].as_object() {
        println!("## Nominal Groups");
        println!();
        
        for (group_name, group_data) in groups {
            println!("### {}", group_name);
            println!();
            
            if let Some(constants) = group_data["constants"].as_object() {
                println!("Constants:");
                println!();
                for (key, value) in constants {
                    println!("- `{}`: {}", key, value);
                }
                println!();
            }
            
            println!("Test Vector:");
            println!();
            println!("```");
            if let Some(seed) = group_data["seed"].as_str() {
                println!("seed = {}", seed);
            }
            if let Some(scalar) = group_data["scalar"].as_str() {
                println!("scalar = {}", scalar);
            }
            if let Some(generator) = group_data["generator"].as_str() {
                println!("generator = {}", generator);
            }
            if let Some(element) = group_data["element"].as_str() {
                println!("element = {}", element);
            }
            if let Some(shared_secret) = group_data["shared_secret"].as_str() {
                println!("shared_secret = {}", shared_secret);
            }
            println!("```");
            println!();
        }
    }
    
    // Convert KEMs
    if let Some(kems) = test_vectors["test_vectors"]["kems"].as_object() {
        println!("## Key Encapsulation Mechanisms");
        println!();
        
        for (kem_name, kem_data) in kems {
            println!("### {}", kem_name);
            println!();
            
            if let Some(constants) = kem_data["constants"].as_object() {
                println!("Constants:");
                println!();
                for (key, value) in constants {
                    println!("- `{}`: {}", key, value);
                }
                println!();
            }
            
            println!("Test Vector:");
            println!();
            println!("```");
            if let Some(ek) = kem_data["encapsulation_key"].as_str() {
                println!("encapsulation_key = {}", truncate_hex(ek, 64));
            }
            if let Some(dk) = kem_data["decapsulation_key"].as_str() {
                println!("decapsulation_key = {}", dk);
            }
            if let Some(ct) = kem_data["ciphertext"].as_str() {
                println!("ciphertext = {}", truncate_hex(ct, 64));
            }
            if let Some(ss) = kem_data["shared_secret"].as_str() {
                println!("shared_secret = {}", ss);
            }
            if let Some(ss_recovered) = kem_data["shared_secret_recovered"].as_str() {
                println!("shared_secret_recovered = {}", ss_recovered);
            }
            println!("```");
            println!();
        }
    }
    
    // Convert primitives
    if let Some(primitives) = test_vectors["test_vectors"]["primitives"].as_object() {
        println!("## Cryptographic Primitives");
        println!();
        
        for (primitive_name, primitive_data) in primitives {
            println!("### {}", primitive_name);
            println!();
            
            if let Some(constants) = primitive_data["constants"].as_object() {
                println!("Constants:");
                println!();
                for (key, value) in constants {
                    println!("- `{}`: {}", key, value);
                }
                println!();
            }
            
            println!("Test Vector:");
            println!();
            println!("```");
            if let Some(input) = primitive_data["input"].as_str() {
                println!("input = {}", input);
            }
            if let Some(seed) = primitive_data["seed"].as_str() {
                println!("seed = {}", seed);
            }
            if let Some(output) = primitive_data["output"].as_str() {
                println!("output = {}", output);
            }
            println!("```");
            println!();
        }
    }
    
    eprintln!("Markdown conversion completed successfully!");
}

fn truncate_hex(hex_str: &str, max_len: usize) -> String {
    if hex_str.len() <= max_len {
        hex_str.to_string()
    } else {
        format!("{}...", &hex_str[..max_len])
    }
}