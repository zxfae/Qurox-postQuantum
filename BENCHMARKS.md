# Benchmarks

Measured on an AMD Ryzen 9 / Linux x86_64, debug build disabled, `cargo bench`.
All times are wall-clock medians over 100 samples. Results will vary by hardware.

---

## Key generation

| Algorithm | Time |
|---|---|
| ECDSA secp256k1 | 187 µs |
| ML-KEM-768 | 231 µs |
| Schnorr | 369 µs |
| ECDSA P-256 | 463 µs |
| ML-DSA-44 | 762 µs |
| **SLH-DSA-SHA2-128f** | **9.3 ms** |

SLH-DSA key generation is ~49x slower than ECDSA K256. Acceptable for
one-time setup, not for high-frequency key rotation.

---

## Sign

| Algorithm | Time |
|---|---|
| ECDSA secp256k1 | 367 µs |
| Schnorr | 742 µs |
| ECDSA P-256 | 1.0 ms |
| ML-DSA-44 | 1.8 ms |
| **SLH-DSA-SHA2-128f** | **210 ms** |

ML-DSA-44 at 1.8ms is usable in any context where you're not signing thousands
of messages per second. SLH-DSA at 210ms is not suitable for real-time use —
reserve it for offline signing or cases where hash-based security assumptions
are a hard requirement.

---

## Verify

| Algorithm | Time |
|---|---|
| ECDSA secp256k1 | 291 µs |
| Schnorr | 307 µs |
| ML-DSA-44 | 443 µs |
| ECDSA P-256 | 915 µs |
| **SLH-DSA-SHA2-128f** | **12 ms** |

ML-DSA-44 verify (443 µs) is faster than ECDSA P-256. That's a useful
property for validators that verify far more than they sign.

---

## Hybrid (K256 + ML-DSA-44)

| Operation | Time |
|---|---|
| Keygen | 992 µs |
| Sign | 2.27 ms |
| Verify | 986 µs |
| Sign compact (zstd) | 3.30 ms |
| Verify compact | 1.13 ms |

For reference, Ethereum produces a block every ~12 seconds, Bitcoin every ~10
minutes. A 2.27ms hybrid sign has negligible impact on throughput in either
context.

The K256 + SLH-DSA combination clocks in at **218ms per sign** — not viable
for anything latency-sensitive.

---

## ML-KEM-768 (key encapsulation)

| Operation | Time |
|---|---|
| Encapsulate | 232 µs |
| Decapsulate | 326 µs |

Fast enough for TLS-like handshakes.

---

## Compression

Measured on a real hybrid signature (~2.5 KB uncompressed).

| Algorithm | Compress | Decompress |
|---|---|---|
| LZ4 fast | **100 µs** | **35 µs** |
| Zstd fast | 321 µs | 52 µs |
| Zstd balanced | 705 µs | 52 µs |
| Zstd maximum | 105 ms | 52 µs |

**LZ4** is the clear winner for online use: 3x faster compression than Zstd
fast, near-identical decompression. The decompression cost (35 µs) is
negligible relative to the signature verification it precedes.

**Zstd maximum** adds ~105ms of compression overhead with marginal size
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
