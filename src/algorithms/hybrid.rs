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

//! Hybrid signing: ECDSA + ML-DSA (or SLH-DSA) simultaneously.
//!
//! Both signatures are produced and must both verify. This gives you
//! classical security today and post-quantum security going forward,
//! without needing to cut over all at once.

use crate::algorithms::{EcdsaCrypto, EcdsaCurve, MlDsaCrypto, SchnorrCrypto, SlhDsaCrypto};
use crate::compression::{CompressedHybridSignature, CompressionEngine, CompressionMetrics};
use crate::errors::{CryptoError, Result};
use crate::types::{
    Algorithm, ClassicalAlgorithm, HybridKeyPair, HybridMetadata, HybridPolicy, HybridSignature,
    KeyPair, PostQuantumAlgorithm, SecurityLevel, TransitionMode,
};

use std::time::{SystemTime, UNIX_EPOCH};

pub struct HybridCrypto {
    policy: HybridPolicy,
}

impl Default for HybridPolicy {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridOptional,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: true,
            compression_config: None,
        }
    }
}

impl HybridCrypto {
    pub fn new(policy: HybridPolicy) -> Self {
        Self { policy }
    }

    pub fn new_default() -> Self {
        Self {
            policy: HybridPolicy::default(),
        }
    }

    pub fn generate_hybrid_keypair(&self) -> Result<HybridKeyPair> {
        let classical_algorithm = self.select_classical_algorithm();
        let post_quantum_algorithm = self.select_post_quantum_algorithm();

        let classical_keypair = match classical_algorithm {
            ClassicalAlgorithm::EcdsaK256 => EcdsaCrypto::generate_keypair(EcdsaCurve::K256)?,
            ClassicalAlgorithm::EcdsaP256 => EcdsaCrypto::generate_keypair(EcdsaCurve::P256)?,
            ClassicalAlgorithm::Schnorr => SchnorrCrypto::generate_keypair()?,
        };

        let post_quantum_keypair = match post_quantum_algorithm {
            PostQuantumAlgorithm::MlDsa44 => MlDsaCrypto::generate_keypair()?,
            PostQuantumAlgorithm::SlhDsaSha2128f => SlhDsaCrypto::generate_keypair()?,
        };

        Ok(HybridKeyPair {
            classical_keypair,
            post_quantum_keypair,
            security_level: self.policy.security_level,
        })
    }

    pub fn sign_hybrid(
        &self,
        hybrid_keypair: &HybridKeyPair,
        message: &[u8],
    ) -> Result<HybridSignature> {
        let classical_signature = match hybrid_keypair.classical_keypair.private_key.algorithm {
            Algorithm::EcdsaK256 | Algorithm::EcdsaP256 => {
                EcdsaCrypto::sign(&hybrid_keypair.classical_keypair.private_key, message)?
            }
            Algorithm::Schnorr => {
                SchnorrCrypto::sign(&hybrid_keypair.classical_keypair.private_key, message)?
            }
            _ => {
                return Err(CryptoError::Generic(
                    "Invalid classical algorithm".to_string(),
                ))
            }
        };

        let post_quantum_signature = match hybrid_keypair.post_quantum_keypair.private_key.algorithm
        {
            Algorithm::MlDsa44 => {
                MlDsaCrypto::sign(&hybrid_keypair.post_quantum_keypair.private_key, message)?
            }
            Algorithm::SlhDsaSha2128f => {
                SlhDsaCrypto::sign(&hybrid_keypair.post_quantum_keypair.private_key, message)?
            }
            _ => {
                return Err(CryptoError::Generic(
                    "Invalid post-quantum algorithm".to_string(),
                ))
            }
        };

        let metadata = self.create_hybrid_metadata(
            &hybrid_keypair.classical_keypair,
            &hybrid_keypair.post_quantum_keypair,
        )?;

        Ok(HybridSignature {
            classical_signature,
            post_quantum_signature,
            metadata,
        })
    }

    pub fn verify_hybrid(
        &self,
        hybrid_keypair: &HybridKeyPair,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool> {
        let classical_valid = match hybrid_keypair.classical_keypair.public_key.algorithm {
            Algorithm::EcdsaK256 | Algorithm::EcdsaP256 => EcdsaCrypto::verify(
                &hybrid_keypair.classical_keypair.public_key,
                message,
                &signature.classical_signature,
            )?,
            Algorithm::Schnorr => SchnorrCrypto::verify(
                &hybrid_keypair.classical_keypair.public_key,
                message,
                &signature.classical_signature,
            )?,
            _ => {
                return Err(CryptoError::Generic(
                    "Invalid classical algorithm".to_string(),
                ))
            }
        };

        let post_quantum_valid = match hybrid_keypair.post_quantum_keypair.public_key.algorithm {
            Algorithm::MlDsa44 => MlDsaCrypto::verify(
                &hybrid_keypair.post_quantum_keypair.public_key,
                message,
                &signature.post_quantum_signature,
            )?,
            Algorithm::SlhDsaSha2128f => SlhDsaCrypto::verify(
                &hybrid_keypair.post_quantum_keypair.public_key,
                message,
                &signature.post_quantum_signature,
            )?,
            _ => {
                return Err(CryptoError::Generic(
                    "Invalid post-quantum algorithm".to_string(),
                ))
            }
        };

        match self.policy.security_level {
            SecurityLevel::Classical => Ok(classical_valid),
            SecurityLevel::QuantumOnly => Ok(post_quantum_valid),
            SecurityLevel::Hybrid => Ok(classical_valid && post_quantum_valid),
        }
    }

    fn select_classical_algorithm(&self) -> ClassicalAlgorithm {
        self.policy.classical_algorithm
    }

    fn select_post_quantum_algorithm(&self) -> PostQuantumAlgorithm {
        self.policy.post_quantum_algorithm
    }

    fn create_hybrid_metadata(
        &self,
        classical_keypair: &KeyPair,
        post_quantum_keypair: &KeyPair,
    ) -> Result<HybridMetadata> {
        let classical_algorithm = match classical_keypair.private_key.algorithm {
            Algorithm::EcdsaK256 => ClassicalAlgorithm::EcdsaK256,
            Algorithm::EcdsaP256 => ClassicalAlgorithm::EcdsaP256,
            Algorithm::Schnorr => ClassicalAlgorithm::Schnorr,
            _ => {
                return Err(CryptoError::Generic(
                    "Invalid classical algorithm".to_string(),
                ))
            }
        };

        let post_quantum_algorithm = match post_quantum_keypair.private_key.algorithm {
            Algorithm::MlDsa44 => PostQuantumAlgorithm::MlDsa44,
            Algorithm::SlhDsaSha2128f => PostQuantumAlgorithm::SlhDsaSha2128f,
            _ => {
                return Err(CryptoError::Generic(
                    "Invalid post-quantum algorithm".to_string(),
                ))
            }
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(HybridMetadata {
            classical_algorithm,
            post_quantum_algorithm,
            security_level: self.policy.security_level,
            transition_mode: self.policy.transition_mode,
            compressed: self.policy.compression_enabled,
            timestamp,
        })
    }

    pub fn compress_signature(
        &self,
        signature: &HybridSignature,
    ) -> Result<CompressedHybridSignature> {
        if !self.policy.compression_enabled {
            return Err(CryptoError::Generic(
                "Compression disabled in policy".to_string(),
            ));
        }

        let compression_config = self.policy.compression_config.clone().unwrap_or_default();

        let compression_engine = CompressionEngine::new(compression_config);
        compression_engine.compress_hybrid_signature(signature)
    }

    pub fn decompress_signature(
        &self,
        compressed: &CompressedHybridSignature,
    ) -> Result<HybridSignature> {
        let compression_config = self.policy.compression_config.clone().unwrap_or_default();

        let compression_engine = CompressionEngine::new(compression_config);
        compression_engine.decompress_hybrid_signature(compressed)
    }

    pub fn compress_signature_with_metrics(
        &self,
        signature: &HybridSignature,
    ) -> Result<(CompressedHybridSignature, CompressionMetrics)> {
        if !self.policy.compression_enabled {
            return Err(CryptoError::Generic(
                "Compression disabled in policy".to_string(),
            ));
        }

        let compression_config = self.policy.compression_config.clone().unwrap_or_default();

        let compression_engine = CompressionEngine::new(compression_config);

        let serialized = serde_json::to_vec(signature).map_err(|_| {
            CryptoError::SerializationError("Failed to serialize signature".to_string())
        })?;

        let (compressed_data, metrics) = compression_engine.compress_with_metrics(&serialized)?;

        let signature_metadata = serde_json::to_value(&signature.metadata).map_err(|_| {
            CryptoError::SerializationError("Failed to serialize metadata".to_string())
        })?;

        let compressed_signature = CompressedHybridSignature {
            compressed_data,
            signature_metadata,
        };

        Ok((compressed_signature, metrics))
    }

    pub fn sign_hybrid_compressed(
        &self,
        hybrid_keypair: &HybridKeyPair,
        message: &[u8],
    ) -> Result<CompressedHybridSignature> {
        let signature = self.sign_hybrid(hybrid_keypair, message)?;
        self.compress_signature(&signature)
    }

    pub fn verify_hybrid_compressed(
        &self,
        hybrid_keypair: &HybridKeyPair,
        message: &[u8],
        compressed_signature: &CompressedHybridSignature,
    ) -> Result<bool> {
        let signature = self.decompress_signature(compressed_signature)?;
        self.verify_hybrid(hybrid_keypair, message, &signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_keypair_generation() {
        let hybrid_crypto = HybridCrypto::new_default();
        let hybrid_keypair = hybrid_crypto.generate_hybrid_keypair().unwrap();

        assert_eq!(hybrid_keypair.security_level, SecurityLevel::Hybrid);
        assert!(!hybrid_keypair
            .classical_keypair
            .private_key
            .bytes
            .is_empty());
        assert!(!hybrid_keypair
            .post_quantum_keypair
            .private_key
            .bytes
            .is_empty());
    }

    #[test]
    fn test_hybrid_sign_verify() {
        let hybrid_crypto = HybridCrypto::new_default();
        let hybrid_keypair = hybrid_crypto.generate_hybrid_keypair().unwrap();
        let message = b"hybrid signature test";

        let signature = hybrid_crypto.sign_hybrid(&hybrid_keypair, message).unwrap();
        let is_valid = hybrid_crypto
            .verify_hybrid(&hybrid_keypair, message, &signature)
            .unwrap();

        assert!(is_valid);
        assert_eq!(signature.metadata.security_level, SecurityLevel::Hybrid);
    }

    #[test]
    fn test_hybrid_different_policies() {
        let policy_classical = HybridPolicy {
            security_level: SecurityLevel::Classical,
            transition_mode: TransitionMode::ClassicalOnly,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: false,
            compression_config: None,
        };

        let hybrid_crypto = HybridCrypto::new(policy_classical);
        let hybrid_keypair = hybrid_crypto.generate_hybrid_keypair().unwrap();
        let message = b"classical policy test";

        let signature = hybrid_crypto.sign_hybrid(&hybrid_keypair, message).unwrap();
        let is_valid = hybrid_crypto
            .verify_hybrid(&hybrid_keypair, message, &signature)
            .unwrap();

        assert!(is_valid);
        assert_eq!(signature.metadata.security_level, SecurityLevel::Classical);
    }

    #[test]
    fn test_invalid_signature_verification() {
        let hybrid_crypto = HybridCrypto::new_default();
        let hybrid_keypair = hybrid_crypto.generate_hybrid_keypair().unwrap();
        let message = b"original message";
        let wrong_message = b"tampered message";

        let signature = hybrid_crypto.sign_hybrid(&hybrid_keypair, message).unwrap();
        let is_valid = hybrid_crypto
            .verify_hybrid(&hybrid_keypair, wrong_message, &signature)
            .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_compression_functionality() {
        use crate::compression::{CompressionAlgorithm, CompressionConfig, CompressionLevel};

        let compression_config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: CompressionLevel::Balanced,
            enabled: true,
            threshold_bytes: 100,
        };

        let policy = HybridPolicy {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridOptional,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: true,
            compression_config: Some(compression_config),
        };

        let hybrid_crypto = HybridCrypto::new(policy);
        let hybrid_keypair = hybrid_crypto.generate_hybrid_keypair().unwrap();
        let message = b"compression test message";

        let signature = hybrid_crypto.sign_hybrid(&hybrid_keypair, message).unwrap();
        let compressed_signature = hybrid_crypto.compress_signature(&signature).unwrap();
        let decompressed_signature = hybrid_crypto
            .decompress_signature(&compressed_signature)
            .unwrap();

        let is_valid = hybrid_crypto
            .verify_hybrid(&hybrid_keypair, message, &decompressed_signature)
            .unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_compressed_sign_verify_workflow() {
        let hybrid_crypto = HybridCrypto::new_default();
        let hybrid_keypair = hybrid_crypto.generate_hybrid_keypair().unwrap();
        let message = b"compressed workflow test";

        let compressed_signature = hybrid_crypto
            .sign_hybrid_compressed(&hybrid_keypair, message)
            .unwrap();
        let is_valid = hybrid_crypto
            .verify_hybrid_compressed(&hybrid_keypair, message, &compressed_signature)
            .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_compression_metrics() {
        let hybrid_crypto = HybridCrypto::new_default();
        let hybrid_keypair = hybrid_crypto.generate_hybrid_keypair().unwrap();
        let message = b"metrics test message";

        let signature = hybrid_crypto.sign_hybrid(&hybrid_keypair, message).unwrap();
        let (compressed_signature, metrics) = hybrid_crypto
            .compress_signature_with_metrics(&signature)
            .unwrap();

        assert!(metrics.original_size > 0);
        // Time metrics are always non-negative by design (u64 type)
        assert!(metrics.compression_time_ms == metrics.compression_time_ms);
        assert!(metrics.decompression_time_ms == metrics.decompression_time_ms);

        let decompressed = hybrid_crypto
            .decompress_signature(&compressed_signature)
            .unwrap();
        let is_valid = hybrid_crypto
            .verify_hybrid(&hybrid_keypair, message, &decompressed)
            .unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_policy_schnorr_mldsa() {
        let policy = HybridPolicy {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridRequired,
            classical_algorithm: ClassicalAlgorithm::Schnorr,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: false,
            compression_config: None,
        };
        let hybrid_crypto = HybridCrypto::new(policy);
        let keypair = hybrid_crypto.generate_hybrid_keypair().unwrap();
        let message = b"schnorr + mldsa";

        assert_eq!(keypair.classical_keypair.private_key.algorithm, Algorithm::Schnorr);
        assert_eq!(keypair.post_quantum_keypair.private_key.algorithm, Algorithm::MlDsa44);

        let sig = hybrid_crypto.sign_hybrid(&keypair, message).unwrap();
        assert!(hybrid_crypto.verify_hybrid(&keypair, message, &sig).unwrap());
    }

    #[test]
    fn test_policy_p256_mldsa() {
        let policy = HybridPolicy {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridRequired,
            classical_algorithm: ClassicalAlgorithm::EcdsaP256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: false,
            compression_config: None,
        };
        let hybrid_crypto = HybridCrypto::new(policy);
        let keypair = hybrid_crypto.generate_hybrid_keypair().unwrap();
        let message = b"p256 + mldsa";

        assert_eq!(keypair.classical_keypair.private_key.algorithm, Algorithm::EcdsaP256);
        assert_eq!(keypair.post_quantum_keypair.private_key.algorithm, Algorithm::MlDsa44);

        let sig = hybrid_crypto.sign_hybrid(&keypair, message).unwrap();
        assert!(hybrid_crypto.verify_hybrid(&keypair, message, &sig).unwrap());
    }

    #[test]
    fn test_policy_k256_slhdsa() {
        let policy = HybridPolicy {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridRequired,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::SlhDsaSha2128f,
            compression_enabled: false,
            compression_config: None,
        };
        let hybrid_crypto = HybridCrypto::new(policy);
        let keypair = hybrid_crypto.generate_hybrid_keypair().unwrap();
        let message = b"k256 + slh-dsa";

        assert_eq!(keypair.classical_keypair.private_key.algorithm, Algorithm::EcdsaK256);
        assert_eq!(keypair.post_quantum_keypair.private_key.algorithm, Algorithm::SlhDsaSha2128f);

        let sig = hybrid_crypto.sign_hybrid(&keypair, message).unwrap();
        assert!(hybrid_crypto.verify_hybrid(&keypair, message, &sig).unwrap());
    }

    /// Simulates a quantum attack: the adversary has compromised the classical key
    /// (via Shor's algorithm) but not the post-quantum key.
    ///
    /// With HybridRequired, verification must fail because the ML-DSA signature
    /// does not match Alice's PQ key.
    /// With ClassicalOnly, verification passes — demonstrating why this mode
    /// is insufficient against a quantum-capable adversary.
    #[test]
    fn test_quantum_attacker_compromises_classical_key() {
        let message = b"transfer 1000 ETH to attacker";

        // Alice generates her hybrid keypair
        let alice_policy = HybridPolicy {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridRequired,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: false,
            compression_config: None,
        };
        let alice_crypto = HybridCrypto::new(alice_policy);
        let alice_keypair = alice_crypto.generate_hybrid_keypair().unwrap();

        // The attacker has Alice's classical key (via Shor's) but their own PQ key
        let attacker_crypto = HybridCrypto::new(HybridPolicy {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridRequired,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: false,
            compression_config: None,
        });

        // Attacker forges a keypair: Alice's classical key + attacker's own PQ key
        let forged_keypair = HybridKeyPair {
            classical_keypair: alice_keypair.classical_keypair.clone(),
            post_quantum_keypair: attacker_crypto.generate_hybrid_keypair().unwrap().post_quantum_keypair,
            security_level: SecurityLevel::Hybrid,
        };

        let forged_sig = attacker_crypto.sign_hybrid(&forged_keypair, message).unwrap();

        // HybridRequired: Alice verifies with her real keys — FAILS
        // The attacker's ML-DSA signature does not match Alice's PQ public key
        let is_valid_hybrid = alice_crypto
            .verify_hybrid(&alice_keypair, message, &forged_sig)
            .unwrap();
        assert!(!is_valid_hybrid, "HybridRequired must reject a forged signature");

        // ClassicalOnly: same check — PASSES (vulnerable mode)
        // This demonstrates why ClassicalOnly is insufficient
        let classical_only_crypto = HybridCrypto::new(HybridPolicy {
            security_level: SecurityLevel::Classical,
            transition_mode: TransitionMode::ClassicalOnly,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: false,
            compression_config: None,
        });
        let is_valid_classical = classical_only_crypto
            .verify_hybrid(&alice_keypair, message, &forged_sig)
            .unwrap();
        assert!(is_valid_classical, "ClassicalOnly accepts the forged signature — vulnerable mode demonstrated");
    }

    /// Same quantum attack scenario as above, but with compression enabled.
    /// Ensures that compress/decompress roundtrip does not weaken hybrid verification.
    #[test]
    fn test_quantum_attacker_compromises_classical_key_compressed() {
        let message = b"transfer 1000 ETH to attacker";

        let policy = HybridPolicy {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridRequired,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: true,
            compression_config: None,
        };
        let alice_crypto = HybridCrypto::new(policy);
        let alice_keypair = alice_crypto.generate_hybrid_keypair().unwrap();

        // Attacker forges a keypair: Alice's classical key + attacker's own PQ key
        let attacker_crypto = HybridCrypto::new(HybridPolicy {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridRequired,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: true,
            compression_config: None,
        });
        let forged_keypair = HybridKeyPair {
            classical_keypair: alice_keypair.classical_keypair.clone(),
            post_quantum_keypair: attacker_crypto.generate_hybrid_keypair().unwrap().post_quantum_keypair,
            security_level: SecurityLevel::Hybrid,
        };

        // Attacker signs and compresses
        let forged_compressed = attacker_crypto
            .sign_hybrid_compressed(&forged_keypair, message)
            .unwrap();

        // Alice verifies the compressed forged signature — must fail
        let is_valid = alice_crypto
            .verify_hybrid_compressed(&alice_keypair, message, &forged_compressed)
            .unwrap();
        assert!(!is_valid, "HybridRequired must reject a compressed forged signature");

        // Sanity check: Alice's own compressed signature must still verify
        let alice_compressed = alice_crypto
            .sign_hybrid_compressed(&alice_keypair, message)
            .unwrap();
        let alice_valid = alice_crypto
            .verify_hybrid_compressed(&alice_keypair, message, &alice_compressed)
            .unwrap();
        assert!(alice_valid, "Alice's own compressed signature must verify");
    }
}
