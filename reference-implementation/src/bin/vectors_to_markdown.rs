//! Test vector to Markdown converter binary

use concrete_hybrid_kem::test_vectors::{HybridKemTestVector, TestVectors};
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

    eprintln!("Converting test vectors from {} to Markdown...", filename);

    // Convert MLKEM768-P256
    println!("## MLKEM768-P256");
    println!();
    convert_hybrid_kem_vectors(&test_vectors.mlkem768_p256);

    // Convert MLKEM768-X25519
    println!("## MLKEM768-X25519");
    println!();
    convert_hybrid_kem_vectors(&test_vectors.mlkem768_x25519);

    // Convert MLKEM1024-P384
    println!("## MLKEM1024-P384");
    println!();
    convert_hybrid_kem_vectors(&test_vectors.mlkem1024_p384);

    eprintln!("Markdown conversion completed successfully!");
}

fn convert_hybrid_kem_vectors(vectors: &[HybridKemTestVector]) {
    for vector in vectors {
        println!("~~~");
        println!("{}", format_hex_field("seed", &hex::encode(&vector.seed)));
        println!(
            "{}",
            format_hex_field("randomness", &hex::encode(&vector.randomness))
        );
        println!(
            "{}",
            format_hex_field("encapsulation_key", &hex::encode(&vector.encapsulation_key))
        );
        println!(
            "{}",
            format_hex_field("decapsulation_key", &hex::encode(&vector.decapsulation_key))
        );
        println!(
            "{}",
            format_hex_field(
                "decapsulation_key_pq",
                &hex::encode(&vector.decapsulation_key_pq)
            )
        );
        println!(
            "{}",
            format_hex_field(
                "decapsulation_key_t",
                &hex::encode(&vector.decapsulation_key_t)
            )
        );
        println!(
            "{}",
            format_hex_field("ciphertext", &hex::encode(&vector.ciphertext))
        );
        println!(
            "{}",
            format_hex_field("shared_secret", &hex::encode(&vector.shared_secret))
        );
        println!("~~~");
        println!();
    }
}

fn format_hex_field(label: &str, hex_str: &str) -> String {
    let prefix = format!("{} = ", label);
    let indent = " ".repeat(prefix.len());

    if hex_str.len() + prefix.len() <= 64 {
        // Fits on one line
        format!("{}{}", prefix, hex_str)
    } else {
        // Need to wrap
        let mut result = prefix;
        let mut remaining = hex_str;
        let first_line_len = 64 - result.len();

        // First line
        result.push_str(&remaining[..first_line_len]);
        remaining = &remaining[first_line_len..];

        // Subsequent lines
        while !remaining.is_empty() {
            result.push('\n');
            result.push_str(&indent);
            let line_len = std::cmp::min(remaining.len(), 64 - indent.len());
            result.push_str(&remaining[..line_len]);
            remaining = &remaining[line_len..];
        }

        result
    }
}
