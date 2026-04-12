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

use crate::errors::{CryptoError, Result};
use crate::types::{Algorithm, KeyPair, PrivateKey, PublicKey, Signature};

use k256::{
    schnorr::signature::Signer, schnorr::signature::Verifier, schnorr::SigningKey,
    schnorr::VerifyingKey,
};
use rand::rngs::OsRng;

pub struct SchnorrCrypto;

impl SchnorrCrypto {
    pub fn generate_keypair() -> Result<KeyPair> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let private_key = PrivateKey {
            bytes: signing_key.to_bytes().to_vec(),
            algorithm: Algorithm::Schnorr,
        };

        let public_key = PublicKey {
            bytes: verifying_key.to_bytes().to_vec(),
            algorithm: Algorithm::Schnorr,
        };

        Ok(KeyPair {
            private_key,
            public_key,
        })
    }

    pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature> {
        if private_key.algorithm != Algorithm::Schnorr {
            return Err(CryptoError::Generic(
                "Invalid algorithm for Schnorr signing".to_string(),
            ));
        }

        let signing_key =
            SigningKey::from_bytes(&private_key.bytes).map_err(|_| CryptoError::InvalidKey)?;

        let signature: k256::schnorr::Signature = signing_key.sign(message);

        Ok(Signature {
            bytes: signature.to_bytes().to_vec(),
            algorithm: Algorithm::Schnorr,
        })
    }

    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
        if public_key.algorithm != Algorithm::Schnorr {
            return Err(CryptoError::Generic(
                "Invalid algorithm for Schnorr verification".to_string(),
            ));
        }

        let verifying_key =
            VerifyingKey::from_bytes(&public_key.bytes).map_err(|_| CryptoError::InvalidKey)?;

        let signature = k256::schnorr::Signature::try_from(&signature.bytes[..])
            .map_err(|_| CryptoError::InvalidSignature)?;

        Ok(verifying_key.verify(message, &signature).is_ok())
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
