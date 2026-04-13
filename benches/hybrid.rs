use criterion::{criterion_group, criterion_main, Criterion};
use qurox_pq::{
    ClassicalAlgorithm, HybridPolicy, HybridSigner, PostQuantumAlgorithm, QuroxCrypto,
    SecurityLevel, TransitionMode,
};

fn bench_hybrid_sign(c: &mut Criterion) {
    let mut g = c.benchmark_group("hybrid_sign");
    let message = b"benchmark message for hybrid signing";

    let signer_default = HybridSigner::new().unwrap();
    g.bench_function("k256_mldsa44", |b| {
        b.iter(|| signer_default.sign(message).unwrap())
    });

    let signer_schnorr = HybridSigner::with_policy(HybridPolicy {
        security_level: SecurityLevel::Hybrid,
        transition_mode: TransitionMode::HybridRequired,
        classical_algorithm: ClassicalAlgorithm::Schnorr,
        post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
        compression_enabled: false,
        compression_config: None,
    })
    .unwrap();
    g.bench_function("schnorr_mldsa44", |b| {
        b.iter(|| signer_schnorr.sign(message).unwrap())
    });

    let signer_slhdsa = HybridSigner::with_policy(HybridPolicy {
        security_level: SecurityLevel::Hybrid,
        transition_mode: TransitionMode::HybridRequired,
        classical_algorithm: ClassicalAlgorithm::EcdsaK256,
        post_quantum_algorithm: PostQuantumAlgorithm::SlhDsaSha2128f,
        compression_enabled: false,
        compression_config: None,
    })
    .unwrap();
    g.bench_function("k256_slhdsa", |b| {
        b.iter(|| signer_slhdsa.sign(message).unwrap())
    });

    g.finish();
}

fn bench_hybrid_verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("hybrid_verify");
    let message = b"benchmark message for hybrid verification";

    let signer = HybridSigner::new().unwrap();
    let sig = signer.sign(message).unwrap();
    g.bench_function("k256_mldsa44", |b| {
        b.iter(|| signer.verify(message, &sig).unwrap())
    });

    g.finish();
}

fn bench_hybrid_compressed(c: &mut Criterion) {
    let mut g = c.benchmark_group("hybrid_compressed");
    let message = b"benchmark message for compressed hybrid signing";

    let signer = HybridSigner::new().unwrap();

    g.bench_function("sign_compact", |b| {
        b.iter(|| signer.sign_compact(message).unwrap())
    });

    let compact_sig = signer.sign_compact(message).unwrap();
    g.bench_function("verify_compact", |b| {
        b.iter(|| signer.verify_compact(message, &compact_sig).unwrap())
    });

    g.finish();
}

fn bench_hybrid_keypair(c: &mut Criterion) {
    let mut g = c.benchmark_group("hybrid_keygen");

    let hybrid = QuroxCrypto::create_hybrid_crypto_default();
    g.bench_function("k256_mldsa44", |b| {
        b.iter(|| QuroxCrypto::generate_hybrid_keypair(&hybrid).unwrap())
    });

    g.finish();
}

criterion_group!(
    benches,
    bench_hybrid_sign,
    bench_hybrid_verify,
    bench_hybrid_compressed,
    bench_hybrid_keypair
);
criterion_main!(benches);
