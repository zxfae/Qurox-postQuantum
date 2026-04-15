// Copyright 2025 Philippe Lecrosnier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Post-quantum cryptography library. Implements NIST FIPS 203/204/205 alongside
//! classical ECDSA, with hybrid mode for gradual migration.
//!
//! Start with [`simple::qurox`] for the high-level API, or use [`QuroxCrypto`]
//! directly if you need access to raw keypairs and signatures.

pub mod algorithms;
pub mod bridge;
pub mod compression;
pub mod errors;
pub mod simple;
pub mod types;

pub use bridge::*;
pub use errors::*;
pub use types::*;

pub use simple::qurox;
pub use simple::{HybridSigner, HybridVerifier, QuantumEncryptor, QuantumSigner, QuantumVerifier};
pub use algorithms::ecdsa::EcdsaCurve;

use algorithms::*;
use compression::*;

pub struct QuroxCrypto;

impl QuroxCrypto {
    pub fn generate_ecdsa_keypair(curve: EcdsaCurve) -> Result<KeyPair> {
        EcdsaCrypto::generate_keypair(curve)
    }

    pub fn generate_schnorr_keypair() -> Result<KeyPair> {
        SchnorrCrypto::generate_keypair()
    }

    pub fn generate_mldsa_keypair() -> Result<KeyPair> {
        MlDsaCrypto::generate_keypair()
    }

    pub fn generate_slh_dsa_keypair() -> Result<KeyPair> {
        SlhDsaCrypto::generate_keypair()
    }

    pub fn generate_mlkem_keypair() -> Result<KeyPair> {
        MlKemCrypto::generate_keypair()
    }

    pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature> {
        match private_key.algorithm {
            Algorithm::EcdsaK256 | Algorithm::EcdsaP256 => EcdsaCrypto::sign(private_key, message),
            Algorithm::Schnorr => SchnorrCrypto::sign(private_key, message),
            Algorithm::MlDsa44 => MlDsaCrypto::sign(private_key, message),
            Algorithm::SlhDsaSha2128f => SlhDsaCrypto::sign(private_key, message),
            Algorithm::MlKem768 => Err(CryptoError::Generic(
                "ML-KEM is for encryption, not signing".to_string(),
            )),
            Algorithm::Hybrid => Err(CryptoError::Generic(
                "Use sign_hybrid for hybrid signatures".to_string(),
            )),
        }
    }

    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
        match public_key.algorithm {
            Algorithm::EcdsaK256 | Algorithm::EcdsaP256 => {
                EcdsaCrypto::verify(public_key, message, signature)
            }
            Algorithm::Schnorr => SchnorrCrypto::verify(public_key, message, signature),
            Algorithm::MlDsa44 => MlDsaCrypto::verify(public_key, message, signature),
            Algorithm::SlhDsaSha2128f => SlhDsaCrypto::verify(public_key, message, signature),
            Algorithm::MlKem768 => Err(CryptoError::Generic(
                "ML-KEM is for encryption, not signing".to_string(),
            )),
            Algorithm::Hybrid => Err(CryptoError::Generic(
                "Use verify_hybrid for hybrid signatures".to_string(),
            )),
        }
    }

    pub fn encapsulate(public_key: &PublicKey) -> Result<EncryptionResult> {
        match public_key.algorithm {
            Algorithm::MlKem768 => MlKemCrypto::encapsulate(public_key),
            _ => Err(CryptoError::Generic(
                "Algorithm does not support encapsulation".to_string(),
            )),
        }
    }

    pub fn decapsulate(
        private_key: &PrivateKey,
        ciphertext: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        match private_key.algorithm {
            Algorithm::MlKem768 => MlKemCrypto::decapsulate(private_key, ciphertext),
            _ => Err(CryptoError::Generic(
                "Algorithm does not support decapsulation".to_string(),
            )),
        }
    }

    pub fn create_hybrid_crypto(policy: HybridPolicy) -> HybridCrypto {
        HybridCrypto::new(policy)
    }

    pub fn create_hybrid_crypto_default() -> HybridCrypto {
        HybridCrypto::new_default()
    }

    pub fn generate_hybrid_keypair(hybrid_crypto: &HybridCrypto) -> Result<HybridKeyPair> {
        hybrid_crypto.generate_hybrid_keypair()
    }

    pub fn sign_hybrid(
        hybrid_crypto: &HybridCrypto,
        hybrid_keypair: &HybridKeyPair,
        message: &[u8],
    ) -> Result<HybridSignature> {
        hybrid_crypto.sign_hybrid(hybrid_keypair, message)
    }

    pub fn verify_hybrid(
        hybrid_crypto: &HybridCrypto,
        hybrid_keypair: &HybridKeyPair,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool> {
        hybrid_crypto.verify_hybrid(hybrid_keypair, message, signature)
    }

    pub fn create_compression_engine(config: CompressionConfig) -> CompressionEngine {
        CompressionEngine::new(config)
    }

    pub fn create_compression_engine_default() -> CompressionEngine {
        CompressionEngine::new_default()
    }

    pub fn compress_hybrid_signature(
        hybrid_crypto: &HybridCrypto,
        signature: &HybridSignature,
    ) -> Result<CompressedHybridSignature> {
        hybrid_crypto.compress_signature(signature)
    }

    pub fn decompress_hybrid_signature(
        hybrid_crypto: &HybridCrypto,
        compressed: &CompressedHybridSignature,
    ) -> Result<HybridSignature> {
        hybrid_crypto.decompress_signature(compressed)
    }

    pub fn sign_hybrid_compressed(
        hybrid_crypto: &HybridCrypto,
        hybrid_keypair: &HybridKeyPair,
        message: &[u8],
    ) -> Result<CompressedHybridSignature> {
        hybrid_crypto.sign_hybrid_compressed(hybrid_keypair, message)
    }

    pub fn verify_hybrid_compressed(
        hybrid_crypto: &HybridCrypto,
        hybrid_keypair: &HybridKeyPair,
        message: &[u8],
        compressed_signature: &CompressedHybridSignature,
    ) -> Result<bool> {
        hybrid_crypto.verify_hybrid_compressed(hybrid_keypair, message, compressed_signature)
    }

    pub fn compress_signature_with_metrics(
        hybrid_crypto: &HybridCrypto,
        signature: &HybridSignature,
    ) -> Result<(CompressedHybridSignature, CompressionMetrics)> {
        hybrid_crypto.compress_signature_with_metrics(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_api_ecdsa_k256() {
        let keypair = QuroxCrypto::generate_ecdsa_keypair(EcdsaCurve::K256).unwrap();
        let message = b"test message";

        let signature = QuroxCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = QuroxCrypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_api_ecdsa_p256() {
        let keypair = QuroxCrypto::generate_ecdsa_keypair(EcdsaCurve::P256).unwrap();
        let message = b"test message";

        let signature = QuroxCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = QuroxCrypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_api_schnorr() {
        let keypair = QuroxCrypto::generate_schnorr_keypair().unwrap();
        let message = b"test message";

        let signature = QuroxCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = QuroxCrypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_api_mldsa() {
        let keypair = QuroxCrypto::generate_mldsa_keypair().unwrap();
        let message = b"post-quantum test";

        let signature = QuroxCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = QuroxCrypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_api_slh_dsa() {
        let keypair = QuroxCrypto::generate_slh_dsa_keypair().unwrap();
        let message = b"stateless hash test";

        let signature = QuroxCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = QuroxCrypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_api_mlkem() {
        let keypair = QuroxCrypto::generate_mlkem_keypair().unwrap();

        let encryption_result = QuroxCrypto::encapsulate(&keypair.public_key).unwrap();
        let decrypted_secret =
            QuroxCrypto::decapsulate(&keypair.private_key, &encryption_result.ciphertext).unwrap();

        assert_eq!(encryption_result.shared_secret.as_slice(), decrypted_secret.as_slice());
    }

    #[test]
    fn test_hybrid_crypto_api() {
        let hybrid_crypto = QuroxCrypto::create_hybrid_crypto_default();
        let hybrid_keypair = QuroxCrypto::generate_hybrid_keypair(&hybrid_crypto).unwrap();
        let message = b"hybrid crypto test";

        let signature = QuroxCrypto::sign_hybrid(&hybrid_crypto, &hybrid_keypair, message).unwrap();
        let is_valid =
            QuroxCrypto::verify_hybrid(&hybrid_crypto, &hybrid_keypair, message, &signature)
                .unwrap();

        assert!(is_valid);
        assert_eq!(signature.metadata.security_level, SecurityLevel::Hybrid);
    }

    #[test]
    fn test_compression_api() {
        let hybrid_crypto = QuroxCrypto::create_hybrid_crypto_default();
        let hybrid_keypair = QuroxCrypto::generate_hybrid_keypair(&hybrid_crypto).unwrap();
        let message = b"compression api test";

        let compressed_signature =
            QuroxCrypto::sign_hybrid_compressed(&hybrid_crypto, &hybrid_keypair, message).unwrap();
        let is_valid = QuroxCrypto::verify_hybrid_compressed(
            &hybrid_crypto,
            &hybrid_keypair,
            message,
            &compressed_signature,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_compression_engine_api() {
        let compression_engine = QuroxCrypto::create_compression_engine_default();
        let test_data = b"compression engine test data".repeat(10);

        let compressed = compression_engine.compress_data(&test_data).unwrap();
        let decompressed = compression_engine.decompress_data(&compressed).unwrap();

        assert_eq!(test_data, decompressed);
    }
}
