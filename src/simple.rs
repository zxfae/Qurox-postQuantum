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

//! Simplified Qurox Crypto API
//!
//! This module provides a clean, simple API that uses the CryptographyBridge pattern
//! internally while exposing an ergonomic interface for post-quantum cryptography.

use crate::algorithms::{HybridCrypto, MlDsa44, MlKem768};
use crate::bridge::{CryptographyBridge, KeyEncapsulationBridge};
use crate::errors::{CryptoError, Result};
use crate::types::{ClassicalAlgorithm, HybridKeyPair, HybridPolicy, PostQuantumAlgorithm, SecurityLevel, TransitionMode};

/// Quantum-safe signer using ML-DSA-44
pub struct QuantumSigner {
    bridge: MlDsa44,
    public_key: <MlDsa44 as CryptographyBridge>::PublicKey,
    secret_key: <MlDsa44 as CryptographyBridge>::SecretKey,
}

impl QuantumSigner {
    /// Create a new quantum-safe signer
    pub fn new() -> Result<Self> {
        let bridge = MlDsa44;
        let (public_key, secret_key) = bridge.key_generator()?;
        Ok(Self {
            bridge,
            public_key,
            secret_key,
        })
    }

    /// Sign a message using post-quantum cryptography
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature = self.bridge.sign(&self.secret_key, message)?;
        Ok(self.bridge.signature_to_bytes(&signature))
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        // For ML-DSA, signature bytes are stored directly as Vec<u8>
        let sig_vec = signature.to_vec();
        self.bridge.verify(&self.public_key, message, &sig_vec)
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.bridge.public_key_to_bytes(&self.public_key)
    }
}

/// Hybrid signer combining classical and post-quantum cryptography
pub struct HybridSigner {
    hybrid_crypto: HybridCrypto,
    hybrid_keypair: HybridKeyPair,
}

impl HybridSigner {
    /// Create a new hybrid signer with default policy
    pub fn new() -> Result<Self> {
        let hybrid_crypto = HybridCrypto::new_default();
        let hybrid_keypair = hybrid_crypto.generate_hybrid_keypair()?;
        Ok(Self {
            hybrid_crypto,
            hybrid_keypair,
        })
    }

    /// Create a hybrid signer with custom policy
    pub fn with_policy(policy: HybridPolicy) -> Result<Self> {
        let hybrid_crypto = HybridCrypto::new(policy);
        let hybrid_keypair = hybrid_crypto.generate_hybrid_keypair()?;
        Ok(Self {
            hybrid_crypto,
            hybrid_keypair,
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature = self
            .hybrid_crypto
            .sign_hybrid(&self.hybrid_keypair, message)?;
        serde_json::to_vec(&signature).map_err(|_| {
            CryptoError::SerializationError("Failed to serialize signature".to_string())
        })
    }

    /// Sign and compress. Useful when bandwidth matters — hybrid signatures
    /// combine ECDSA and ML-DSA, which adds up to ~2.4 KB before compression.
    pub fn sign_compact(&self, message: &[u8]) -> Result<Vec<u8>> {
        let compressed_sig = self
            .hybrid_crypto
            .sign_hybrid_compressed(&self.hybrid_keypair, message)?;
        serde_json::to_vec(&compressed_sig).map_err(|_| {
            CryptoError::SerializationError("Failed to serialize compressed signature".to_string())
        })
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = serde_json::from_slice(signature).map_err(|_| {
            CryptoError::SerializationError("Failed to deserialize signature".to_string())
        })?;
        self.hybrid_crypto
            .verify_hybrid(&self.hybrid_keypair, message, &sig)
    }

    pub fn verify_compact(&self, message: &[u8], compressed_signature: &[u8]) -> Result<bool> {
        let compressed_sig = serde_json::from_slice(compressed_signature).map_err(|_| {
            CryptoError::SerializationError(
                "Failed to deserialize compressed signature".to_string(),
            )
        })?;
        self.hybrid_crypto
            .verify_hybrid_compressed(&self.hybrid_keypair, message, &compressed_sig)
    }

    /// Sign with only the classical (ECDSA secp256k1) half of the stored keypair.
    pub fn classical_signature(&self, message: &[u8]) -> Result<Vec<u8>> {
        use crate::algorithms::EcdsaCrypto;
        let sig = EcdsaCrypto::sign(&self.hybrid_keypair.classical_keypair.private_key, message)?;
        Ok(sig.bytes)
    }

    /// The ECDSA public key corresponding to `classical_signature`.
    /// Needed by the verifier if they only check the classical half.
    pub fn classical_public_key(&self) -> Vec<u8> {
        self.hybrid_keypair
            .classical_keypair
            .public_key
            .bytes
            .clone()
    }

    /// Both public keys — classical and post-quantum.
    /// Use this when sharing your hybrid public key with a peer.
    pub fn public_keys(&self) -> (&[u8], &[u8]) {
        (
            &self.hybrid_keypair.classical_keypair.public_key.bytes,
            &self.hybrid_keypair.post_quantum_keypair.public_key.bytes,
        )
    }
}

/// Key encapsulation via ML-KEM-768 (FIPS 203).
/// Used to establish a shared secret over an untrusted channel.
pub struct QuantumEncryptor {
    bridge: MlKem768,
    public_key: <MlKem768 as KeyEncapsulationBridge>::PublicKey,
    secret_key: <MlKem768 as KeyEncapsulationBridge>::SecretKey,
}

impl QuantumEncryptor {
    pub fn new() -> Result<Self> {
        let bridge = MlKem768;
        let (public_key, secret_key) = bridge.kem_keygen()?;
        Ok(Self {
            bridge,
            public_key,
            secret_key,
        })
    }

    /// Returns `(ciphertext, shared_secret)`. Send the ciphertext to the other party;
    /// they call `decapsulate` to recover the same shared secret.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (ciphertext, shared_secret) = self.bridge.encapsulate(&self.public_key)?;
        use fips203::traits::SerDes;
        Ok((ciphertext.into_bytes().to_vec(), shared_secret))
    }

    pub fn decapsulate(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>> {
        use fips203::ml_kem_768::{CipherText, CT_LEN};
        use fips203::traits::SerDes;

        let ct_array: [u8; CT_LEN] = ciphertext_bytes
            .try_into()
            .map_err(|_| CryptoError::Generic("Invalid ciphertext size".to_string()))?;
        let ciphertext = CipherText::try_from_bytes(ct_array)
            .map_err(|_| CryptoError::Generic("Invalid ciphertext".to_string()))?;

        let shared_secret = self.bridge.decapsulate(&self.secret_key, &ciphertext)?;
        Ok(shared_secret)
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.bridge.kem_public_key_to_bytes(&self.public_key)
    }
}

pub mod qurox {
    use super::*;

    pub fn quantum_signer() -> Result<QuantumSigner> {
        QuantumSigner::new()
    }

    pub fn hybrid_signer() -> Result<HybridSigner> {
        HybridSigner::new()
    }

    pub fn quantum_encryptor() -> Result<QuantumEncryptor> {
        QuantumEncryptor::new()
    }

    /// Hybrid with `HybridRequired` — both signatures must verify.
    pub fn secure_signer() -> Result<HybridSigner> {
        let policy = HybridPolicy {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridRequired,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: true,
            compression_config: None,
        };
        HybridSigner::with_policy(policy)
    }

    /// Hybrid with compression enabled. Use `sign_compact` / `verify_compact`.
    pub fn compact_signer() -> Result<HybridSigner> {
        let policy = HybridPolicy {
            security_level: SecurityLevel::Hybrid,
            transition_mode: TransitionMode::HybridOptional,
            classical_algorithm: ClassicalAlgorithm::EcdsaK256,
            post_quantum_algorithm: PostQuantumAlgorithm::MlDsa44,
            compression_enabled: true,
            compression_config: None,
        };
        HybridSigner::with_policy(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_signer() {
        let signer = QuantumSigner::new().unwrap();
        let message = b"quantum test message";

        let signature = signer.sign(message).unwrap();
        let is_valid = signer.verify(message, &signature).unwrap();

        assert!(is_valid);
        assert!(!signature.is_empty());
        assert!(!signer.public_key_bytes().is_empty());
    }

    #[test]
    fn test_hybrid_signer() {
        let signer = HybridSigner::new().unwrap();
        let message = b"hybrid test message";

        let signature = signer.sign(message).unwrap();
        let is_valid = signer.verify(message, &signature).unwrap();

        assert!(is_valid);
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_compact_signing() {
        let signer = HybridSigner::new().unwrap();
        let message = b"compact test message";

        let compact_sig = signer.sign_compact(message).unwrap();
        let is_valid = signer.verify_compact(message, &compact_sig).unwrap();

        assert!(is_valid);
        assert!(!compact_sig.is_empty());
    }

    #[test]
    fn test_quantum_encryptor() {
        let encryptor = QuantumEncryptor::new().unwrap();

        let (ciphertext, shared_secret1) = encryptor.encapsulate().unwrap();
        let shared_secret2 = encryptor.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert!(!ciphertext.is_empty());
        assert!(!shared_secret1.is_empty());
    }

    #[test]
    fn test_qurox_api() {
        // Test simple API
        let quantum = qurox::quantum_signer().unwrap();
        let hybrid = qurox::hybrid_signer().unwrap();
        let encryptor = qurox::quantum_encryptor().unwrap();
        let secure = qurox::secure_signer().unwrap();
        let compact = qurox::compact_signer().unwrap();

        let message = b"qurox api test";

        // Quantum signing
        let q_sig = quantum.sign(message).unwrap();
        assert!(quantum.verify(message, &q_sig).unwrap());

        // Hybrid signing
        let h_sig = hybrid.sign(message).unwrap();
        assert!(hybrid.verify(message, &h_sig).unwrap());

        // Secure signer
        let s_sig = secure.sign(message).unwrap();
        assert!(secure.verify(message, &s_sig).unwrap());

        // Compact signing
        let c_sig = compact.sign_compact(message).unwrap();
        assert!(compact.verify_compact(message, &c_sig).unwrap());

        // Quantum encryption
        let (ct, ss1) = encryptor.encapsulate().unwrap();
        let ss2 = encryptor.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }
}
