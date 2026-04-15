# Benchmarks

Measured on an AMD Ryzen 9 / Linux x86_64, debug build disabled, `cargo bench`.
All times are wall-clock medians over 100 samples. Results will vary by hardware.

---

## Key generation

| Algorithm | Time |
|---|---|
| ECDSA secp256k1 | 181 µs |
| ML-KEM-768 | 270 µs |
| Schnorr | 343 µs |
| ECDSA P-256 | 449 µs |
| ML-DSA-44 | 739 µs |
| **SLH-DSA-SHA2-128f** | **8.5 ms** |

SLH-DSA key generation is ~49x slower than ECDSA K256. Acceptable for
one-time setup, not for high-frequency key rotation.

---

## Sign

| Algorithm | Time |
|---|---|
| ECDSA secp256k1 | 350 µs |
| Schnorr | 694 µs |
| ECDSA P-256 | 950 µs |
| ML-DSA-44 | 1.89 ms |
| **SLH-DSA-SHA2-128f** | **200 ms** |

ML-DSA-44 at 1.89ms is usable in any context where you're not signing thousands
of messages per second. SLH-DSA at 200ms is not suitable for real-time use —
reserve it for offline signing or cases where hash-based security assumptions
are a hard requirement.

---

## Verify

| Algorithm | Time |
|---|---|
| ECDSA secp256k1 | 295 µs |
| Schnorr | 279 µs |
| ML-DSA-44 | 401 µs |
| ECDSA P-256 | 851 µs |
| **SLH-DSA-SHA2-128f** | **11.3 ms** |

ML-DSA-44 verify (401 µs) is faster than ECDSA P-256. That's a useful
property for validators that verify far more than they sign.

---

## Hybrid (K256 + ML-DSA-44)

| Operation | Time |
|---|---|
| Keygen | 724 µs |
| Sign | 1.68 ms |
| Verify | 658 µs |
| Sign compact (lz4) | 2.07 ms |
| Verify compact | 950 µs |

For reference, Ethereum produces a block every ~12 seconds, Bitcoin every ~10
minutes. A 1.68ms hybrid sign has negligible impact on throughput in either
context.

The K256 + SLH-DSA combination clocks in at **162ms per sign** — not viable
for anything latency-sensitive.

---

## ML-KEM-768 (key encapsulation)

| Operation | Time |
|---|---|
| Encapsulate | 183 µs |
| Decapsulate | 242 µs |

Fast enough for TLS-like handshakes.

---

## Compression

Measured on a real hybrid signature (~2.5 KB uncompressed).

| Algorithm | Compress | Decompress |
|---|---|---|
| LZ4 fast | **77 µs** | **21 µs** |
| Zstd fast | 216 µs | 41 µs |
| Zstd balanced | 530 µs | 41 µs |
| Zstd maximum | 85 ms | 41 µs |

**LZ4** is the clear winner for online use: 3x faster compression than Zstd
fast, near-identical decompression. The decompression cost (35 µs) is
negligible relative to the signature verification it precedes.

**Zstd maximum** adds ~85ms of compression overhead with marginal size
reduction over balanced. Do not use it in production.

The library defaults to **LZ4 fast**. It is 7x faster than Zstd balanced
with near-identical decompression. Use Zstd balanced only when storing
signatures long-term and byte count matters more than latency.

---

## Summary

| Use case | Recommendation |
|---|---|
| General post-quantum signing | ML-DSA-44 |
| Hybrid migration (recommended) | K256 + ML-DSA-44, `HybridRequired` |
| Maximum security, offline only | K256 + SLH-DSA |
| Key exchange / shared secret | ML-KEM-768 |
| Compression for bandwidth | LZ4 fast |
| Compression for storage | Zstd balanced |
| **Never in production** | Zstd maximum |
