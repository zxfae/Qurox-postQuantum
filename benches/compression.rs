use criterion::{criterion_group, criterion_main, Criterion};
use qurox_pq::{
    compression::{CompressionAlgorithm, CompressionConfig, CompressionEngine, CompressionLevel},
    HybridSigner,
};

fn bench_compression_zstd(c: &mut Criterion) {
    let mut g = c.benchmark_group("compression_zstd");
    let signer = HybridSigner::new().unwrap();
    let sig = signer.sign(b"benchmark").unwrap();

    let engine_fast = CompressionEngine::new(CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: CompressionLevel::Fast,
        enabled: true,
        threshold_bytes: 0,
    });
    g.bench_function("fast", |b| {
        b.iter(|| engine_fast.compress_data(&sig).unwrap())
    });

    let engine_balanced = CompressionEngine::new(CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: CompressionLevel::Balanced,
        enabled: true,
        threshold_bytes: 0,
    });
    g.bench_function("balanced", |b| {
        b.iter(|| engine_balanced.compress_data(&sig).unwrap())
    });

    let engine_max = CompressionEngine::new(CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: CompressionLevel::Maximum,
        enabled: true,
        threshold_bytes: 0,
    });
    g.bench_function("maximum", |b| {
        b.iter(|| engine_max.compress_data(&sig).unwrap())
    });

    g.finish();
}

fn bench_compression_lz4(c: &mut Criterion) {
    let mut g = c.benchmark_group("compression_lz4");
    let signer = HybridSigner::new().unwrap();
    let sig = signer.sign(b"benchmark").unwrap();

    let engine = CompressionEngine::new(CompressionConfig {
        algorithm: CompressionAlgorithm::Lz4,
        level: CompressionLevel::Fast,
        enabled: true,
        threshold_bytes: 0,
    });
    g.bench_function("fast", |b| b.iter(|| engine.compress_data(&sig).unwrap()));

    g.finish();
}

fn bench_decompression(c: &mut Criterion) {
    let mut g = c.benchmark_group("decompression");
    let signer = HybridSigner::new().unwrap();
    let sig = signer.sign(b"benchmark").unwrap();

    let engine_zstd = CompressionEngine::new(CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: CompressionLevel::Balanced,
        enabled: true,
        threshold_bytes: 0,
    });
    let compressed_zstd = engine_zstd.compress_data(&sig).unwrap();
    g.bench_function("zstd", |b| {
        b.iter(|| engine_zstd.decompress_data(&compressed_zstd).unwrap())
    });

    let engine_lz4 = CompressionEngine::new(CompressionConfig {
        algorithm: CompressionAlgorithm::Lz4,
        level: CompressionLevel::Fast,
        enabled: true,
        threshold_bytes: 0,
    });
    let compressed_lz4 = engine_lz4.compress_data(&sig).unwrap();
    g.bench_function("lz4", |b| {
        b.iter(|| engine_lz4.decompress_data(&compressed_lz4).unwrap())
    });

    g.finish();
}

criterion_group!(
    benches,
    bench_compression_zstd,
    bench_compression_lz4,
    bench_decompression
);
criterion_main!(benches);
