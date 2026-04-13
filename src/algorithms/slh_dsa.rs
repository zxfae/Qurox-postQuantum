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

//! SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) implementation.

use crate::bridge::CryptographyBridge;
use crate::errors::{CryptoError, Result};
use crate::types::{Algorithm, KeyPair, PrivateKey, PublicKey, Signature};

use fips205::{
    slh_dsa_sha2_128f::{self, PK_LEN, SIG_LEN, SK_LEN},
    traits::{SerDes, Signer, Verifier},
};
use rand::rngs::OsRng;

#[derive(Debug, Clone)]
pub struct SlhDsaSha2128f;

impl CryptographyBridge for SlhDsaSha2128f {
    type PublicKey = slh_dsa_sha2_128f::PublicKey;
    type SecretKey = slh_dsa_sha2_128f::PrivateKey;
    type SignedMessage = Vec<u8>;

    fn key_generator(&self) -> Result<(Self::PublicKey, Self::SecretKey)> {
        slh_dsa_sha2_128f::try_keygen_with_rng(&mut OsRng)
            .map_err(|_| CryptoError::RandomGenerationFailed)
    }

    fn sign(&self, secret_key: &Self::SecretKey, message: &[u8]) -> Result<Self::SignedMessage> {
        let sig = secret_key
            .try_sign_with_rng(&mut OsRng, message, &[], false)
            .map_err(|_| CryptoError::Generic("SLH-DSA signing failed".to_string()))?;
        Ok(sig.to_vec())
    }

    fn verify(&self, public_key: &Self::PublicKey, message: &[u8], signature: &Self::SignedMessage) -> Result<bool> {
        let sig_array: [u8; SIG_LEN] = signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(public_key.verify(message, &sig_array, &[]))
    }

    fn public_key_to_bytes(&self, public_key: &Self::PublicKey) -> Vec<u8> {
        public_key.clone().into_bytes().to_vec()
    }

    fn secret_key_to_bytes(&self, secret_key: &Self::SecretKey) -> Vec<u8> {
        secret_key.clone().into_bytes().to_vec()
    }

    fn signature_to_bytes(&self, signature: &Self::SignedMessage) -> Vec<u8> {
        signature.clone()
    }
}

// Byte-oriented API used by QuroxCrypto and HybridCrypto.
// Delegates to SlhDsaSha2128f bridge — single implementation of the signing logic.
pub struct SlhDsaCrypto;

impl SlhDsaCrypto {
    pub fn generate_keypair() -> Result<KeyPair> {
        let (pk, sk) = SlhDsaSha2128f.key_generator()?;
        Ok(KeyPair {
            private_key: PrivateKey { bytes: SlhDsaSha2128f.secret_key_to_bytes(&sk), algorithm: Algorithm::SlhDsaSha2128f },
            public_key: PublicKey { bytes: SlhDsaSha2128f.public_key_to_bytes(&pk), algorithm: Algorithm::SlhDsaSha2128f },
        })
    }

    pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature> {
        if private_key.algorithm != Algorithm::SlhDsaSha2128f {
            return Err(CryptoError::Generic("Invalid algorithm for SLH-DSA signing".to_string()));
        }
        let sk_array: [u8; SK_LEN] = private_key.bytes.as_slice()
            .try_into().map_err(|_| CryptoError::InvalidKey)?;
        let sk = slh_dsa_sha2_128f::PrivateKey::try_from_bytes(&sk_array)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = SlhDsaSha2128f.sign(&sk, message)?;
        Ok(Signature { bytes: SlhDsaSha2128f.signature_to_bytes(&sig), algorithm: Algorithm::SlhDsaSha2128f })
    }

    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
        if public_key.algorithm != Algorithm::SlhDsaSha2128f {
            return Err(CryptoError::Generic("Invalid algorithm for SLH-DSA verification".to_string()));
        }
        let pk_array: [u8; PK_LEN] = public_key.bytes.as_slice()
            .try_into().map_err(|_| CryptoError::InvalidKey)?;
        let pk = slh_dsa_sha2_128f::PublicKey::try_from_bytes(&pk_array)
            .map_err(|_| CryptoError::InvalidKey)?;
        SlhDsaSha2128f.verify(&pk, message, &signature.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slh_dsa_keypair_generation() {
        let keypair = SlhDsaCrypto::generate_keypair().unwrap();
        assert_eq!(keypair.private_key.algorithm, Algorithm::SlhDsaSha2128f);
        assert_eq!(keypair.public_key.algorithm, Algorithm::SlhDsaSha2128f);
        assert!(!keypair.private_key.bytes.is_empty());
        assert!(!keypair.public_key.bytes.is_empty());
    }

    #[test]
    fn test_slh_dsa_sign_verify() {
        let keypair = SlhDsaCrypto::generate_keypair().unwrap();
        let message = b"stateless hash-based signature test";

        let signature = SlhDsaCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = SlhDsaCrypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
        assert_eq!(signature.algorithm, Algorithm::SlhDsaSha2128f);
    }

    #[test]
    fn test_slh_dsa_invalid_signature() {
        let keypair = SlhDsaCrypto::generate_keypair().unwrap();
        let message = b"original message";
        let wrong_message = b"modified message";

        let signature = SlhDsaCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid =
            SlhDsaCrypto::verify(&keypair.public_key, wrong_message, &signature).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_slh_dsa_key_sizes() {
        let keypair = SlhDsaCrypto::generate_keypair().unwrap();

        // SLH-DSA-SHA2-128f expected sizes
        assert_eq!(keypair.public_key.bytes.len(), PK_LEN); // SLH-DSA-SHA2-128f public key size
        assert_eq!(keypair.private_key.bytes.len(), SK_LEN); // SLH-DSA-SHA2-128f private key size
    }

    #[test]
    fn test_slh_dsa_signature_size() {
        let keypair = SlhDsaCrypto::generate_keypair().unwrap();
        let message = b"signature size test";

        let signature = SlhDsaCrypto::sign(&keypair.private_key, message).unwrap();

        // SLH-DSA-SHA2-128f signature size
        assert_eq!(signature.bytes.len(), SIG_LEN);
    }
}
