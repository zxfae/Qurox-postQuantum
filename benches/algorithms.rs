use criterion::{criterion_group, criterion_main, Criterion};
use qurox_pq::QuroxCrypto;
use qurox_pq::EcdsaCurve;

fn bench_keygen(c: &mut Criterion) {
    let mut g = c.benchmark_group("keygen");

    g.bench_function("ecdsa_k256", |b| {
        b.iter(|| QuroxCrypto::generate_ecdsa_keypair(EcdsaCurve::K256).unwrap())
    });

    g.bench_function("ecdsa_p256", |b| {
        b.iter(|| QuroxCrypto::generate_ecdsa_keypair(EcdsaCurve::P256).unwrap())
    });

    g.bench_function("schnorr", |b| {
        b.iter(|| QuroxCrypto::generate_schnorr_keypair().unwrap())
    });

    g.bench_function("ml_dsa_44", |b| {
        b.iter(|| QuroxCrypto::generate_mldsa_keypair().unwrap())
    });

    g.bench_function("slh_dsa_sha2_128f", |b| {
        b.iter(|| QuroxCrypto::generate_slh_dsa_keypair().unwrap())
    });

    g.bench_function("ml_kem_768", |b| {
        b.iter(|| QuroxCrypto::generate_mlkem_keypair().unwrap())
    });

    g.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut g = c.benchmark_group("sign");
    let message = b"benchmark message for signing";

    let kp_k256 = QuroxCrypto::generate_ecdsa_keypair(EcdsaCurve::K256).unwrap();
    g.bench_function("ecdsa_k256", |b| {
        b.iter(|| QuroxCrypto::sign(&kp_k256.private_key, message).unwrap())
    });

    let kp_p256 = QuroxCrypto::generate_ecdsa_keypair(EcdsaCurve::P256).unwrap();
    g.bench_function("ecdsa_p256", |b| {
        b.iter(|| QuroxCrypto::sign(&kp_p256.private_key, message).unwrap())
    });

    let kp_schnorr = QuroxCrypto::generate_schnorr_keypair().unwrap();
    g.bench_function("schnorr", |b| {
        b.iter(|| QuroxCrypto::sign(&kp_schnorr.private_key, message).unwrap())
    });

    let kp_mldsa = QuroxCrypto::generate_mldsa_keypair().unwrap();
    g.bench_function("ml_dsa_44", |b| {
        b.iter(|| QuroxCrypto::sign(&kp_mldsa.private_key, message).unwrap())
    });

    let kp_slhdsa = QuroxCrypto::generate_slh_dsa_keypair().unwrap();
    g.bench_function("slh_dsa_sha2_128f", |b| {
        b.iter(|| QuroxCrypto::sign(&kp_slhdsa.private_key, message).unwrap())
    });

    g.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("verify");
    let message = b"benchmark message for verification";

    let kp_k256 = QuroxCrypto::generate_ecdsa_keypair(EcdsaCurve::K256).unwrap();
    let sig_k256 = QuroxCrypto::sign(&kp_k256.private_key, message).unwrap();
    g.bench_function("ecdsa_k256", |b| {
        b.iter(|| QuroxCrypto::verify(&kp_k256.public_key, message, &sig_k256).unwrap())
    });

    let kp_p256 = QuroxCrypto::generate_ecdsa_keypair(EcdsaCurve::P256).unwrap();
    let sig_p256 = QuroxCrypto::sign(&kp_p256.private_key, message).unwrap();
    g.bench_function("ecdsa_p256", |b| {
        b.iter(|| QuroxCrypto::verify(&kp_p256.public_key, message, &sig_p256).unwrap())
    });

    let kp_schnorr = QuroxCrypto::generate_schnorr_keypair().unwrap();
    let sig_schnorr = QuroxCrypto::sign(&kp_schnorr.private_key, message).unwrap();
    g.bench_function("schnorr", |b| {
        b.iter(|| QuroxCrypto::verify(&kp_schnorr.public_key, message, &sig_schnorr).unwrap())
    });

    let kp_mldsa = QuroxCrypto::generate_mldsa_keypair().unwrap();
    let sig_mldsa = QuroxCrypto::sign(&kp_mldsa.private_key, message).unwrap();
    g.bench_function("ml_dsa_44", |b| {
        b.iter(|| QuroxCrypto::verify(&kp_mldsa.public_key, message, &sig_mldsa).unwrap())
    });

    let kp_slhdsa = QuroxCrypto::generate_slh_dsa_keypair().unwrap();
    let sig_slhdsa = QuroxCrypto::sign(&kp_slhdsa.private_key, message).unwrap();
    g.bench_function("slh_dsa_sha2_128f", |b| {
        b.iter(|| QuroxCrypto::verify(&kp_slhdsa.public_key, message, &sig_slhdsa).unwrap())
    });

    g.finish();
}

fn bench_mlkem(c: &mut Criterion) {
    let mut g = c.benchmark_group("ml_kem_768");

    let kp = QuroxCrypto::generate_mlkem_keypair().unwrap();

    g.bench_function("encapsulate", |b| {
        b.iter(|| QuroxCrypto::encapsulate(&kp.public_key).unwrap())
    });

    let enc = QuroxCrypto::encapsulate(&kp.public_key).unwrap();
    g.bench_function("decapsulate", |b| {
        b.iter(|| QuroxCrypto::decapsulate(&kp.private_key, &enc.ciphertext).unwrap())
    });

    g.finish();
}

criterion_group!(benches, bench_keygen, bench_sign, bench_verify, bench_mlkem);
criterion_main!(benches);
