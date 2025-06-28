# Concrete Hybrid KEM Reference Implementation

This crate provides reference implementations of concrete hybrid Key Encapsulation Mechanisms (KEMs) as described in [draft-irtf-cfrg-concrete-hybrid-kems](https://github.com/cfrg/draft-irtf-cfrg-concrete-hybrid-kems).

## Overview

Hybrid KEMs combine classical and post-quantum cryptographic algorithms to provide both current security and future-proofing against quantum attacks. This implementation provides three concrete instantiations:

- **QSF-P256-MLKEM768-SHAKE256-SHA3256**: P-256 elliptic curve + ML-KEM-768
- **QSF-X25519-MLKEM768-SHAKE256-SHA3256**: X25519 + ML-KEM-768 (X-Wing compatible)
- **QSF-P384-MLKEM1024-SHAKE256-SHA3256**: P-384 elliptic curve + ML-KEM-1024

## Features

- **Post-quantum security**: Combines classical elliptic curve cryptography with ML-KEM (NIST's standardized post-quantum KEM)
- **Standards compliant**: Implements the draft IETF specification
- **Multiple curves**: Supports P-256, P-384, and X25519 elliptic curves
- **Test vectors**: Includes utilities for generating and verifying test vectors
- **X-Wing compatibility**: The X25519+ML-KEM-768 instantiation is compatible with X-Wing

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
concrete-hybrid-kem = "0.1.0"
```

### Basic Example

```rust
use concrete_hybrid_kem::{QsfX25519MlKem768Shake256Sha3256, Kem};
use rand::rngs::OsRng;

// Generate a keypair
let mut rng = OsRng;
let (private_key, public_key) = QsfX25519MlKem768Shake256Sha3256::keygen(&mut rng)?;

// Encapsulate to generate a shared secret
let (ciphertext, shared_secret_sender) = QsfX25519MlKem768Shake256Sha3256::encaps(&public_key, &mut rng)?;

// Decapsulate to recover the shared secret
let shared_secret_receiver = QsfX25519MlKem768Shake256Sha3256::decaps(&private_key, &ciphertext)?;

assert_eq!(shared_secret_sender, shared_secret_receiver);
```

## Binary Tools

This crate includes several binary utilities:

### Generate Test Vectors
```bash
cargo run --bin generate_vectors
```

### Verify Test Vectors
```bash
cargo run --bin verify_vectors
```

### Convert Vectors to Markdown
```bash
cargo run --bin vectors_to_markdown
```

## Testing

Run the test suite:

```bash
cargo test
```

## Dependencies

- **Elliptic Curves**: `p256`, `p384`, `x25519-dalek`
- **Post-Quantum**: `ml-kem`
- **Hash Functions**: `sha3` (for SHAKE256 and SHA3-256)
- **Utilities**: `rand`, `hex`, `serde`

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

This is a reference implementation for an IETF draft. Contributions should align with the specification requirements.

## Authors

- Deirdre Connolly <durumcrustulum@gmail.com>
- Richard Barnes <rlb@ipv.sx>