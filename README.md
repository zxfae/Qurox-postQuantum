# qurox-pq

[![Crates.io](https://img.shields.io/crates/v/qurox-pq.svg)](https://crates.io/crates/qurox-pq)
[![Documentation](https://docs.rs/qurox-pq/badge.svg)](https://docs.rs/qurox-pq)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> **Alpha — not audited. Do not use in production.**

Post-quantum cryptography library for Rust. Implements the NIST FIPS 203/204/205 standards alongside classical ECDSA, with a hybrid mode for gradual migration.

Built as the cryptographic core of [Qubex Protocol](https://github.com/Qubex-Protocol/Qubex-Protocol), a quantum-safe infrastructure project on Internet Computer Protocol that reached the European pool finals at WCHL 2025.

## Quick Start

```toml
[dependencies]
qurox-pq = "0.1.0"
```

```rust
use qurox_pq::qurox::{QuantumSigner, HybridSigner, QuantumEncryptor};

// ML-DSA-44 (FIPS 204)
let signer = QuantumSigner::new()?;
let sig = signer.sign(b"hello")?;
assert!(signer.verify(b"hello", &sig)?);

// Classical + post-quantum simultaneously
let hybrid = HybridSigner::new()?;
let sig = hybrid.sign(b"hello")?;
assert!(hybrid.verify(b"hello", &sig)?);

// ML-KEM-768 key encapsulation (FIPS 203)
let enc = QuantumEncryptor::new()?;
let (ciphertext, shared_secret) = enc.encapsulate()?;
let recovered = enc.decapsulate(&ciphertext)?;
assert_eq!(shared_secret, recovered);
```

## Algorithms

| Algorithm | Type | Standard |
|-----------|------|----------|
| ML-DSA-44 | Signature | NIST FIPS 204 |
| SLH-DSA-SHA2-128f | Signature | NIST FIPS 205 |
| ML-KEM-768 | Key encapsulation | NIST FIPS 203 |
| ECDSA secp256k1 | Signature | — |
| ECDSA P-256 | Signature | NIST |
| Schnorr | Signature | — |

## Hybrid mode

ML-DSA-44 signatures are ~2.4 KB. The hybrid mode signs with both ECDSA and ML-DSA simultaneously — verification requires both to pass. This lets you deploy post-quantum support incrementally without dropping classical compatibility.

```rust
use qurox_pq::{QuroxCrypto, HybridPolicy, SecurityLevel, TransitionMode};

let policy = HybridPolicy {
    security_level: SecurityLevel::Hybrid,
    transition_mode: TransitionMode::HybridRequired,
    compression_enabled: true,
    ..Default::default()
};

let hybrid = HybridSigner::with_policy(policy)?;
let sig = hybrid.sign_compact(b"hello")?; // zstd-compressed, 60-80% smaller
```

## Advanced API

```rust
use qurox_pq::{QuroxCrypto, EcdsaCurve};

let kp = QuroxCrypto::generate_mldsa_keypair()?;
let sig = QuroxCrypto::sign(&kp.private_key, b"message")?;
assert!(QuroxCrypto::verify(&kp.public_key, b"message", &sig)?);
```

## Architecture

```
src/
├── algorithms/    # ECDSA, Schnorr, ML-DSA, SLH-DSA, ML-KEM, hybrid
├── bridge.rs      # Trait abstractions over individual algorithms
├── compression.rs # zstd/lz4 compression for hybrid signatures
├── errors.rs
├── types.rs
├── simple.rs      # High-level API (QuantumSigner, HybridSigner, QuantumEncryptor)
└── lib.rs
```

## Building

```bash
cargo build
cargo test
cargo test --all-features  # includes compression
```

## Security notes

This library has **not been audited**. The algorithms themselves (ML-DSA, ML-KEM, SLH-DSA) are NIST-approved, but the implementation here has not been reviewed for side-channel resistance, constant-time correctness, or misuse resistance.

Private keys are zeroized on drop.

## License

Apache 2.0 — see [LICENSE](LICENSE).

Copyright 2025 Philippe Lecrosnier.
