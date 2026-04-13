# qurox-pq

![version](https://img.shields.io/badge/v0.1.0-blue)
[![Crates.io](https://img.shields.io/crates/v/qurox-pq.svg)](https://crates.io/crates/qurox-pq)
[![Docs](https://docs.rs/qurox-pq/badge.svg)](https://docs.rs/qurox-pq)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![FIPS 203](https://img.shields.io/badge/FIPS-203-brightgreen)
![FIPS 204](https://img.shields.io/badge/FIPS-204-brightgreen)
![FIPS 205](https://img.shields.io/badge/FIPS-205-brightgreen)
![status](https://img.shields.io/badge/Alpha-not%20audited-red)

> Post-quantum cryptography library for Rust.
> Implements NIST FIPS 203 / 204 / 205 alongside classical ECDSA and Schnorr,
> with a hybrid mode designed for gradual migration of existing systems.

---

## Table of contents

1. [Why hybrid?](#1--why-hybrid)
2. [Algorithms](#2--algorithms)
3. [Key & signature sizes](#3--key--signature-sizes)
4. [Quick start](#4--quick-start)
5. [Hybrid mode](#5--hybrid-mode)
6. [Policy configuration](#6--policy-configuration)
7. [Advanced API](#7--advanced-api)
8. [Architecture](#8--architecture)
9. [Security notes](#9--security-notes)
10. [License](#10--license)

---

## 1 — Why hybrid?

Classical algorithms (ECDSA, Schnorr) rely on the hardness of the discrete
logarithm problem. A sufficiently powerful quantum computer running **Shor's
algorithm** breaks them retroactively — including transactions already recorded
on public blockchains today.

The threat is not theoretical: adversaries can **harvest now, decrypt later**,
recording encrypted traffic today to decrypt it once quantum hardware matures.

Hybrid mode counters this by requiring **both** a classical and a post-quantum
signature to pass verification. An attacker who compromises only the classical
key — via Shor's or any other means — cannot forge a valid hybrid signature:

```
Alice signs with:   ECDSA (K256)  +  ML-DSA-44
Attacker breaks:    ECDSA only    →  hybrid verify FAILS
Attacker needs:     both keys     →  not feasible
```

`HybridRequired` enforces this. `ClassicalOnly` remains available for systems
that cannot yet accept post-quantum key sizes, with explicit acknowledgement
of the trade-off.

---

## 2 — Algorithms

| Algorithm | Type | Standard | Security level |
|---|---|---|---|
| **ML-DSA-44** | Signature | NIST FIPS 204 | NIST Level 2 |
| **SLH-DSA-SHA2-128f** | Signature | NIST FIPS 205 | NIST Level 1 |
| **ML-KEM-768** | Key encapsulation | NIST FIPS 203 | NIST Level 3 |
| ECDSA secp256k1 | Signature | SEC2 | Classical |
| ECDSA P-256 | Signature | NIST | Classical |
| Schnorr (secp256k1) | Signature | BIP-340 | Classical |

All post-quantum algorithms are NIST-approved (2024). The classical algorithms
are provided for hybrid use and backward compatibility.

---

## 3 — Key & signature sizes

| Algorithm | Public key | Private key | Signature |
|---|---|---|---|
| ECDSA secp256k1 | 65 B | 32 B | 64 B |
| Schnorr | 32 B | 32 B | 64 B |
| **ML-DSA-44** | **1 312 B** | **2 528 B** | **2 420 B** |
| **SLH-DSA-SHA2-128f** | **32 B** | **64 B** | **17 088 B** |
| **ML-KEM-768** | **1 184 B** | **2 400 B** | *(ciphertext: 1 088 B)* |

Hybrid signatures combine ECDSA + ML-DSA — roughly **~2.5 KB** uncompressed.
The built-in zstd / lz4 compression reduces this by **60–80%** in practice.

---

## 4 — Quick start

```toml
[dependencies]
qurox-pq = "0.1.0"
```

```rust
use qurox_pq::qurox;

// ML-DSA-44 — post-quantum signing (FIPS 204)
let signer = qurox::quantum_signer()?;
let sig = signer.sign(b"hello")?;
assert!(signer.verify(b"hello", &sig)?);

// ECDSA + ML-DSA simultaneously — hybrid signing
let hybrid = qurox::hybrid_signer()?;
let sig = hybrid.sign(b"hello")?;
assert!(hybrid.verify(b"hello", &sig)?);

// ML-KEM-768 — key encapsulation (FIPS 203)
let enc = qurox::quantum_encryptor()?;
let (ciphertext, shared_secret) = enc.encapsulate()?;
let recovered = enc.decapsulate(&ciphertext)?;
assert_eq!(shared_secret, recovered);
```

---

## 5 — Hybrid mode

Two presets are available for common use cases:

```rust
use qurox_pq::qurox;

// Both signatures must verify — maximum security
let signer = qurox::secure_signer()?;
let sig = signer.sign(b"message")?;
assert!(signer.verify(b"message", &sig)?);

// Compressed hybrid — minimize bandwidth
let signer = qurox::compact_signer()?;
let sig = signer.sign_compact(b"message")?;   // zstd-compressed
assert!(signer.verify_compact(b"message", &sig)?);
```

---

## 6 — Policy configuration

Full control over algorithm selection and verification policy:

```rust
use qurox_pq::{
    HybridSigner, HybridPolicy, SecurityLevel, TransitionMode,
    ClassicalAlgorithm, PostQuantumAlgorithm,
};

// Schnorr (Taproot-compatible) + SLH-DSA (hash-based, conservative assumptions)
let policy = HybridPolicy {
    security_level: SecurityLevel::Hybrid,
    transition_mode: TransitionMode::HybridRequired,
    classical_algorithm: ClassicalAlgorithm::Schnorr,
    post_quantum_algorithm: PostQuantumAlgorithm::SlhDsaSha2128f,
    compression_enabled: false,
    compression_config: None,
};

let signer = HybridSigner::with_policy(policy)?;
```

| `TransitionMode` | Behaviour |
|---|---|
| `ClassicalOnly` | Only the classical signature is verified |
| `HybridOptional` | Both are produced; one passing is sufficient |
| `HybridRequired` | Both must pass — recommended for new systems |
| `QuantumOnly` | Only the post-quantum signature is verified |

---

## 7 — Advanced API

```rust
use qurox_pq::{QuroxCrypto, EcdsaCurve};

// Generate and use keypairs directly
let kp = QuroxCrypto::generate_mldsa_keypair()?;
let sig = QuroxCrypto::sign(&kp.private_key, b"message")?;
assert!(QuroxCrypto::verify(&kp.public_key, b"message", &sig)?);

// ML-KEM key encapsulation
let kp = QuroxCrypto::generate_mlkem_keypair()?;
let enc = QuroxCrypto::encapsulate(&kp.public_key)?;
let secret = QuroxCrypto::decapsulate(&kp.private_key, &enc.ciphertext)?;
assert_eq!(enc.shared_secret, secret);
```

---

## 8 — Architecture

```
src/
├── bridge.rs           # CryptographyBridge / KeyEncapsulationBridge traits (ports)
├── algorithms/
│   ├── ecdsa.rs        # EcdsaK256, EcdsaP256, EcdsaCrypto
│   ├── schnorr.rs      # Schnorr, SchnorrCrypto
│   ├── mldsa.rs        # MlDsa44, MlDsaCrypto     (FIPS 204)
│   ├── slh_dsa.rs      # SlhDsaSha2128f, SlhDsaCrypto (FIPS 205)
│   ├── mlkem.rs        # MlKem768, MlKemCrypto    (FIPS 203)
│   └── hybrid.rs       # HybridCrypto — orchestrates classical + PQ
├── compression.rs      # zstd / lz4 compression for hybrid signatures
├── simple.rs           # High-level API: QuantumSigner, HybridSigner, QuantumEncryptor
├── types.rs            # Shared types: KeyPair, HybridPolicy, Algorithm…
├── errors.rs
└── lib.rs              # QuroxCrypto facade
```

Each algorithm exposes two layers:

- **Bridge struct** (`MlDsa44`, `Schnorr`, …) — implements the trait, works with native FIPS types
- **Crypto struct** (`MlDsaCrypto`, `SchnorrCrypto`, …) — byte-oriented adapter, delegates to the bridge

---

## 9 — Security notes

![not audited](https://img.shields.io/badge/Not%20audited-red)

This library has **not been independently audited**. Do not use in production
without a dedicated security review.

| Property | Status |
|---|---|
| NIST-approved algorithms | ✓ FIPS 203 / 204 / 205 |
| Private key zeroization on drop | ✓ via `zeroize` |
| Side-channel resistance | ✗ not evaluated |
| Constant-time correctness | ✗ not evaluated |
| Misuse resistance | ✗ not evaluated |

---

## 10 — License

Apache 2.0 — see [LICENSE](LICENSE).

Copyright 2025 Philippe Lecrosnier.
