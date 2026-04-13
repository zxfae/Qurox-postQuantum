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

//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) implementation.

use crate::bridge::CryptographyBridge;
use crate::errors::{CryptoError, Result};
use crate::types::{Algorithm, KeyPair, PrivateKey, PublicKey, Signature};

use fips204::{
    ml_dsa_44::{self, PK_LEN, SIG_LEN, SK_LEN},
    traits::{SerDes, Signer, Verifier},
};
use rand::rngs::OsRng;

#[derive(Debug, Clone)]
pub struct MlDsa44;

impl CryptographyBridge for MlDsa44 {
    type PublicKey = ml_dsa_44::PublicKey;
    type SecretKey = ml_dsa_44::PrivateKey;
    type SignedMessage = Vec<u8>; // ML-DSA signatures are variable length

    fn key_generator(&self) -> Result<(Self::PublicKey, Self::SecretKey)> {
        let (public_key, secret_key) = ml_dsa_44::try_keygen_with_rng(&mut OsRng)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok((public_key, secret_key))
    }

    fn sign(&self, secret_key: &Self::SecretKey, message: &[u8]) -> Result<Self::SignedMessage> {
        let signature = secret_key
            .try_sign_with_rng(&mut OsRng, message, &[])
            .map_err(|_| CryptoError::Generic("ML-DSA signing failed".to_string()))?;
        Ok(signature.to_vec())
    }

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::SignedMessage,
    ) -> Result<bool> {
        let sig_array: [u8; SIG_LEN] = signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;

        // ML-DSA verify returns bool directly, not Result
        Ok(public_key.verify(message, &sig_array, &[]))
    }

    fn public_key_to_bytes(&self, public_key: &Self::PublicKey) -> Vec<u8> {
        use fips204::traits::SerDes;
        public_key.clone().into_bytes().to_vec()
    }

    fn secret_key_to_bytes(&self, secret_key: &Self::SecretKey) -> Vec<u8> {
        use fips204::traits::SerDes;
        secret_key.clone().into_bytes().to_vec()
    }

    fn signature_to_bytes(&self, signature: &Self::SignedMessage) -> Vec<u8> {
        signature.clone()
    }
}

// Byte-oriented API used by QuroxCrypto and HybridCrypto.
// Delegates to MlDsa44 bridge — single implementation of the FIPS logic.
pub struct MlDsaCrypto;

impl MlDsaCrypto {
    pub fn generate_keypair() -> Result<KeyPair> {
        let bridge = MlDsa44;
        let (pk, sk) = bridge.key_generator()?;
        Ok(KeyPair {
            private_key: PrivateKey {
                bytes: bridge.secret_key_to_bytes(&sk),
                algorithm: Algorithm::MlDsa44,
            },
            public_key: PublicKey {
                bytes: bridge.public_key_to_bytes(&pk),
                algorithm: Algorithm::MlDsa44,
            },
        })
    }

    pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature> {
        if private_key.algorithm != Algorithm::MlDsa44 {
            return Err(CryptoError::Generic(
                "Invalid algorithm for ML-DSA signing".to_string(),
            ));
        }
        let sk_array: [u8; SK_LEN] = private_key
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk_array)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = MlDsa44.sign(&sk, message)?;
        Ok(Signature {
            bytes: MlDsa44.signature_to_bytes(&sig),
            algorithm: Algorithm::MlDsa44,
        })
    }

    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
        if public_key.algorithm != Algorithm::MlDsa44 {
            return Err(CryptoError::Generic(
                "Invalid algorithm for ML-DSA verification".to_string(),
            ));
        }
        let pk_array: [u8; PK_LEN] = public_key
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_array)
            .map_err(|_| CryptoError::InvalidKey)?;
        MlDsa44.verify(&pk, message, &signature.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_keypair_generation() {
        let keypair = MlDsaCrypto::generate_keypair().unwrap();
        assert_eq!(keypair.private_key.algorithm, Algorithm::MlDsa44);
        assert_eq!(keypair.public_key.algorithm, Algorithm::MlDsa44);
        assert!(!keypair.private_key.bytes.is_empty());
        assert!(!keypair.public_key.bytes.is_empty());
    }

    #[test]
    fn test_mldsa_sign_verify() {
        let keypair = MlDsaCrypto::generate_keypair().unwrap();
        let message = b"post-quantum test message";

        let signature = MlDsaCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = MlDsaCrypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
        assert_eq!(signature.algorithm, Algorithm::MlDsa44);
    }

    #[test]
    fn test_mldsa_invalid_signature() {
        let keypair = MlDsaCrypto::generate_keypair().unwrap();
        let message = b"original message";
        let wrong_message = b"tampered message";

        let signature = MlDsaCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = MlDsaCrypto::verify(&keypair.public_key, wrong_message, &signature).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_mldsa_key_sizes() {
        let keypair = MlDsaCrypto::generate_keypair().unwrap();

        // ML-DSA-44 expected sizes
        assert_eq!(keypair.public_key.bytes.len(), PK_LEN); // ML-DSA-44 public key size
        assert_eq!(keypair.private_key.bytes.len(), SK_LEN); // ML-DSA-44 private key size
    }
}
