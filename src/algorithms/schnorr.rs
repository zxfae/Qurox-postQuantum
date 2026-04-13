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

//! Schnorr signature implementation for secp256k1 curve.

use crate::bridge::CryptographyBridge;
use crate::errors::{CryptoError, Result};
use crate::types::{Algorithm, KeyPair, PrivateKey, PublicKey, Signature};

use k256::{
    schnorr::signature::Signer, schnorr::signature::Verifier, schnorr::SigningKey,
    schnorr::VerifyingKey,
};
use rand::rngs::OsRng;

#[derive(Debug, Clone)]
pub struct Schnorr;

impl CryptographyBridge for Schnorr {
    type PublicKey = VerifyingKey;
    type SecretKey = SigningKey;
    type SignedMessage = k256::schnorr::Signature;

    fn key_generator(&self) -> Result<(Self::PublicKey, Self::SecretKey)> {
        let sk = SigningKey::random(&mut OsRng);
        let pk = *sk.verifying_key();
        Ok((pk, sk))
    }

    fn sign(&self, secret_key: &Self::SecretKey, message: &[u8]) -> Result<Self::SignedMessage> {
        Ok(secret_key.sign(message))
    }

    fn verify(&self, public_key: &Self::PublicKey, message: &[u8], signature: &Self::SignedMessage) -> Result<bool> {
        Ok(public_key.verify(message, signature).is_ok())
    }

    fn public_key_to_bytes(&self, public_key: &Self::PublicKey) -> Vec<u8> {
        public_key.to_bytes().to_vec()
    }

    fn secret_key_to_bytes(&self, secret_key: &Self::SecretKey) -> Vec<u8> {
        secret_key.to_bytes().to_vec()
    }

    fn signature_to_bytes(&self, signature: &Self::SignedMessage) -> Vec<u8> {
        signature.to_bytes().to_vec()
    }
}

// Byte-oriented API used by QuroxCrypto and HybridCrypto.
// Delegates to Schnorr bridge — single implementation of the signing logic.
pub struct SchnorrCrypto;

impl SchnorrCrypto {
    pub fn generate_keypair() -> Result<KeyPair> {
        let (pk, sk) = Schnorr.key_generator()?;
        Ok(KeyPair {
            private_key: PrivateKey { bytes: Schnorr.secret_key_to_bytes(&sk), algorithm: Algorithm::Schnorr },
            public_key: PublicKey { bytes: Schnorr.public_key_to_bytes(&pk), algorithm: Algorithm::Schnorr },
        })
    }

    pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature> {
        if private_key.algorithm != Algorithm::Schnorr {
            return Err(CryptoError::Generic("Invalid algorithm for Schnorr signing".to_string()));
        }
        let sk = SigningKey::from_bytes(&private_key.bytes).map_err(|_| CryptoError::InvalidKey)?;
        let sig = Schnorr.sign(&sk, message)?;
        Ok(Signature { bytes: Schnorr.signature_to_bytes(&sig), algorithm: Algorithm::Schnorr })
    }

    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
        if public_key.algorithm != Algorithm::Schnorr {
            return Err(CryptoError::Generic("Invalid algorithm for Schnorr verification".to_string()));
        }
        let pk = VerifyingKey::from_bytes(&public_key.bytes).map_err(|_| CryptoError::InvalidKey)?;
        let sig = k256::schnorr::Signature::try_from(&signature.bytes[..])
            .map_err(|_| CryptoError::InvalidSignature)?;
        Schnorr.verify(&pk, message, &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_keypair_generation() {
        let keypair = SchnorrCrypto::generate_keypair().unwrap();
        assert_eq!(keypair.private_key.algorithm, Algorithm::Schnorr);
        assert_eq!(keypair.public_key.algorithm, Algorithm::Schnorr);
    }

    #[test]
    fn test_schnorr_sign_verify() {
        let keypair = SchnorrCrypto::generate_keypair().unwrap();
        let message = b"test message";

        let signature = SchnorrCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = SchnorrCrypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_schnorr_invalid_signature() {
        let keypair = SchnorrCrypto::generate_keypair().unwrap();
        let message = b"test message";
        let wrong_message = b"wrong message";

        let signature = SchnorrCrypto::sign(&keypair.private_key, message).unwrap();
        let is_valid =
            SchnorrCrypto::verify(&keypair.public_key, wrong_message, &signature).unwrap();

        assert!(!is_valid);
    }
}
