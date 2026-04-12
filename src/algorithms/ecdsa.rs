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

//! ECDSA signature implementations for secp256k1 and P-256 curves.

use crate::bridge::CryptographyBridge;
use crate::errors::{CryptoError, Result};
use crate::types::{Algorithm, KeyPair, PrivateKey, PublicKey, Signature};

use k256::{
    ecdsa::signature::Signer, ecdsa::signature::Verifier, ecdsa::SigningKey as K256SigningKey,
    ecdsa::VerifyingKey as K256VerifyingKey,
};
use p256::{ecdsa::SigningKey as P256SigningKey, ecdsa::VerifyingKey as P256VerifyingKey};
use rand::rngs::OsRng;

#[derive(Debug, Clone)]
pub struct EcdsaK256;

#[derive(Debug, Clone)]
pub struct EcdsaP256;

// Bridge implementation for K256
impl CryptographyBridge for EcdsaK256 {
    type PublicKey = K256VerifyingKey;
    type SecretKey = K256SigningKey;
    type SignedMessage = k256::ecdsa::Signature;

    fn key_generator(&self) -> Result<(Self::PublicKey, Self::SecretKey)> {
        let secret_key = K256SigningKey::random(&mut OsRng);
        let public_key = *secret_key.verifying_key();
        Ok((public_key, secret_key))
    }

    fn sign(&self, secret_key: &Self::SecretKey, message: &[u8]) -> Result<Self::SignedMessage> {
        Ok(secret_key.sign(message))
    }

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::SignedMessage,
    ) -> Result<bool> {
        Ok(public_key.verify(message, signature).is_ok())
    }

    fn public_key_to_bytes(&self, public_key: &Self::PublicKey) -> Vec<u8> {
        public_key.to_encoded_point(false).as_bytes().to_vec()
    }

    fn secret_key_to_bytes(&self, secret_key: &Self::SecretKey) -> Vec<u8> {
        secret_key.to_bytes().to_vec()
    }

    fn signature_to_bytes(&self, signature: &Self::SignedMessage) -> Vec<u8> {
        signature.to_bytes().to_vec()
    }
}

// Bridge implementation for P256
impl CryptographyBridge for EcdsaP256 {
    type PublicKey = P256VerifyingKey;
    type SecretKey = P256SigningKey;
    type SignedMessage = p256::ecdsa::Signature;

    fn key_generator(&self) -> Result<(Self::PublicKey, Self::SecretKey)> {
        let secret_key = P256SigningKey::random(&mut OsRng);
        let public_key = *secret_key.verifying_key();
        Ok((public_key, secret_key))
    }

    fn sign(&self, secret_key: &Self::SecretKey, message: &[u8]) -> Result<Self::SignedMessage> {
        Ok(secret_key.sign(message))
    }

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::SignedMessage,
    ) -> Result<bool> {
        Ok(public_key.verify(message, signature).is_ok())
    }

    fn public_key_to_bytes(&self, public_key: &Self::PublicKey) -> Vec<u8> {
        public_key.to_encoded_point(false).as_bytes().to_vec()
    }

    fn secret_key_to_bytes(&self, secret_key: &Self::SecretKey) -> Vec<u8> {
        secret_key.to_bytes().to_vec()
    }

    fn signature_to_bytes(&self, signature: &Self::SignedMessage) -> Vec<u8> {
        signature.to_bytes().to_vec()
    }
}

// Legacy wrapper maintaining backward compatibility
pub struct EcdsaCrypto;

impl EcdsaCrypto {
    pub fn generate_keypair(curve: EcdsaCurve) -> Result<KeyPair> {
        match curve {
            EcdsaCurve::K256 => Self::generate_k256_keypair(),
            EcdsaCurve::P256 => Self::generate_p256_keypair(),
        }
    }

    pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature> {
        match private_key.algorithm {
            Algorithm::EcdsaK256 => Self::sign_k256(&private_key.bytes, message),
            Algorithm::EcdsaP256 => Self::sign_p256(&private_key.bytes, message),
            _ => Err(CryptoError::Generic(
                "Invalid algorithm for ECDSA signing".to_string(),
            )),
        }
    }

    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
        match public_key.algorithm {
            Algorithm::EcdsaK256 => Self::verify_k256(&public_key.bytes, message, &signature.bytes),
            Algorithm::EcdsaP256 => Self::verify_p256(&public_key.bytes, message, &signature.bytes),
            _ => Err(CryptoError::Generic(
                "Invalid algorithm for ECDSA verification".to_string(),
            )),
        }
    }

    fn generate_k256_keypair() -> Result<KeyPair> {
        let signing_key = K256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let private_key = PrivateKey {
            bytes: signing_key.to_bytes().to_vec(),
            algorithm: Algorithm::EcdsaK256,
        };

        let public_key = PublicKey {
            bytes: verifying_key.to_encoded_point(false).as_bytes().to_vec(),
            algorithm: Algorithm::EcdsaK256,
        };

        Ok(KeyPair {
            private_key,
            public_key,
        })
    }

    fn generate_p256_keypair() -> Result<KeyPair> {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let private_key = PrivateKey {
            bytes: signing_key.to_bytes().to_vec(),
            algorithm: Algorithm::EcdsaP256,
        };

        let public_key = PublicKey {
            bytes: verifying_key.to_encoded_point(false).as_bytes().to_vec(),
            algorithm: Algorithm::EcdsaP256,
        };

        Ok(KeyPair {
            private_key,
            public_key,
        })
    }

    fn sign_k256(private_key_bytes: &[u8], message: &[u8]) -> Result<Signature> {
        let signing_key =
            K256SigningKey::from_slice(private_key_bytes).map_err(|_| CryptoError::InvalidKey)?;

        let signature: k256::ecdsa::Signature = signing_key.sign(message);

        Ok(Signature {
            bytes: signature.to_bytes().to_vec(),
            algorithm: Algorithm::EcdsaK256,
        })
    }

    fn sign_p256(private_key_bytes: &[u8], message: &[u8]) -> Result<Signature> {
        let signing_key =
            P256SigningKey::from_slice(private_key_bytes).map_err(|_| CryptoError::InvalidKey)?;

        let signature: p256::ecdsa::Signature = signing_key.sign(message);

        Ok(Signature {
            bytes: signature.to_bytes().to_vec(),
            algorithm: Algorithm::EcdsaP256,
        })
    }

    fn verify_k256(
        public_key_bytes: &[u8],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool> {
        let verifying_key = K256VerifyingKey::from_sec1_bytes(public_key_bytes)
            .map_err(|_| CryptoError::InvalidKey)?;

        let signature = k256::ecdsa::Signature::from_slice(signature_bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;

        Ok(verifying_key.verify(message, &signature).is_ok())
    }

    fn verify_p256(
        public_key_bytes: &[u8],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool> {
        let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key_bytes)
            .map_err(|_| CryptoError::InvalidKey)?;

        let signature = p256::ecdsa::Signature::from_slice(signature_bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;

        Ok(verifying_key.verify(message, &signature).is_ok())
    }
}

#[derive(Debug, Clone)]
pub enum EcdsaCurve {
    K256,
    P256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k256_keypair_generation() {
        let keypair = EcdsaCrypto::generate_keypair(EcdsaCurve::K256).unwrap();
        assert_eq!(keypair.private_key.algorithm, Algorithm::EcdsaK256);
        assert_eq!(keypair.public_key.algorithm, Algorithm::EcdsaK256);
    }

    #[test]
    fn test_p256_keypair_generation() {
        let keypair = EcdsaCrypto::generate_keypair(EcdsaCurve::P256).unwrap();
        assert_eq!(keypair.private_key.algorithm, Algorithm::EcdsaP256);
        assert_eq!(keypair.public_key.algorithm, Algorithm::EcdsaP256);
    }

    #[test]
    fn test_k256_sign_verify() {
        let keypair = EcdsaCrypto::generate_keypair(EcdsaCurve::K256).unwrap();
        let message = b"test message";

        let signature = EcdsaCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = EcdsaCrypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_p256_sign_verify() {
        let keypair = EcdsaCrypto::generate_keypair(EcdsaCurve::P256).unwrap();
        let message = b"test message";

        let signature = EcdsaCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = EcdsaCrypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
    }
}
