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

//! ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) implementation.

use crate::bridge::KeyEncapsulationBridge;
use crate::errors::{CryptoError, Result};
use crate::types::{Algorithm, KeyPair, PrivateKey, PublicKey};

use zeroize::{Zeroize, Zeroizing};

use fips203::{
    ml_kem_768::{self, CT_LEN, DK_LEN, EK_LEN},
    traits::{Decaps, Encaps, KeyGen, SerDes},
};
use rand::rngs::OsRng;

#[derive(Debug, Clone)]
pub struct MlKem768;

impl KeyEncapsulationBridge for MlKem768 {
    type PublicKey = ml_kem_768::EncapsKey;
    type SecretKey = ml_kem_768::DecapsKey;
    type Ciphertext = ml_kem_768::CipherText;
    type SharedSecret = Vec<u8>; // Use Vec<u8> for shared secret to avoid private type issues

    fn kem_keygen(&self) -> Result<(Self::PublicKey, Self::SecretKey)> {
        let (public_key, secret_key) = ml_kem_768::KG::try_keygen_with_rng(&mut OsRng)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok((public_key, secret_key))
    }

    fn encapsulate(
        &self,
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        let (shared_secret, ciphertext) = public_key
            .try_encaps_with_rng(&mut OsRng)
            .map_err(|_| CryptoError::Generic("ML-KEM encapsulation failed".to_string()))?;
        use fips203::traits::SerDes;
        Ok((ciphertext, shared_secret.into_bytes().to_vec()))
    }

    fn decapsulate(
        &self,
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret> {
        let shared_secret = secret_key
            .try_decaps(ciphertext)
            .map_err(|_| CryptoError::Generic("ML-KEM decapsulation failed".to_string()))?;
        use fips203::traits::SerDes;
        Ok(shared_secret.into_bytes().to_vec())
    }

    fn kem_public_key_to_bytes(&self, public_key: &Self::PublicKey) -> Vec<u8> {
        use fips203::traits::SerDes;
        public_key.clone().into_bytes().to_vec()
    }
}

// Byte-oriented API used by QuroxCrypto.
// Delegates to MlKem768 bridge — single implementation of the KEM logic.
pub struct MlKemCrypto;

#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl Drop for EncryptionResult {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl Zeroize for EncryptionResult {
    fn zeroize(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl MlKemCrypto {
    pub fn generate_keypair() -> Result<KeyPair> {
        let (ek, dk) = MlKem768.kem_keygen()?;
        Ok(KeyPair {
            private_key: PrivateKey {
                bytes: dk.into_bytes().to_vec(),
                algorithm: Algorithm::MlKem768,
            },
            public_key: PublicKey {
                bytes: MlKem768.kem_public_key_to_bytes(&ek),
                algorithm: Algorithm::MlKem768,
            },
        })
    }

    pub fn encapsulate(public_key: &PublicKey) -> Result<EncryptionResult> {
        if public_key.algorithm != Algorithm::MlKem768 {
            return Err(CryptoError::Generic(
                "Invalid algorithm for ML-KEM encapsulation".to_string(),
            ));
        }
        let ek_array: [u8; EK_LEN] = public_key.bytes.as_slice()
            .try_into().map_err(|_| CryptoError::InvalidKey)?;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_array)
            .map_err(|_| CryptoError::InvalidKey)?;
        let (ct, shared_secret) = MlKem768.encapsulate(&ek)?;
        Ok(EncryptionResult {
            ciphertext: ct.into_bytes().to_vec(),
            shared_secret,
        })
    }

    pub fn decapsulate(private_key: &PrivateKey, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if private_key.algorithm != Algorithm::MlKem768 {
            return Err(CryptoError::Generic(
                "Invalid algorithm for ML-KEM decapsulation".to_string(),
            ));
        }
        let dk_array: [u8; DK_LEN] = private_key.bytes.as_slice()
            .try_into().map_err(|_| CryptoError::InvalidKey)?;
        let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_array)
            .map_err(|_| CryptoError::InvalidKey)?;
        let ct_array: [u8; CT_LEN] = ciphertext
            .try_into().map_err(|_| CryptoError::Generic("Invalid ciphertext size".to_string()))?;
        let ct = ml_kem_768::CipherText::try_from_bytes(ct_array)
            .map_err(|_| CryptoError::Generic("Invalid ciphertext".to_string()))?;
        Ok(Zeroizing::new(MlKem768.decapsulate(&dk, &ct)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem_keypair_generation() {
        let keypair = MlKemCrypto::generate_keypair().unwrap();
        assert_eq!(keypair.private_key.algorithm, Algorithm::MlKem768);
        assert_eq!(keypair.public_key.algorithm, Algorithm::MlKem768);
        assert!(!keypair.private_key.bytes.is_empty());
        assert!(!keypair.public_key.bytes.is_empty());
    }

    #[test]
    fn test_mlkem_encaps_decaps() {
        let keypair = MlKemCrypto::generate_keypair().unwrap();

        let encryption_result = MlKemCrypto::encapsulate(&keypair.public_key).unwrap();
        let decrypted_secret =
            MlKemCrypto::decapsulate(&keypair.private_key, &encryption_result.ciphertext).unwrap();

        assert_eq!(encryption_result.shared_secret.as_slice(), decrypted_secret.as_slice());
        assert!(!encryption_result.ciphertext.is_empty());
        assert!(!encryption_result.shared_secret.is_empty());
    }

    #[test]
    fn test_mlkem_key_sizes() {
        let keypair = MlKemCrypto::generate_keypair().unwrap();

        println!(
            "Public key len: {}, expected EK_LEN: {}",
            keypair.public_key.bytes.len(),
            EK_LEN
        );
        println!(
            "Private key len: {}, expected DK_LEN: {}",
            keypair.private_key.bytes.len(),
            DK_LEN
        );

        // ML-KEM-768 expected sizes
        assert_eq!(keypair.public_key.bytes.len(), EK_LEN); // ML-KEM-768 public key size
        assert_eq!(keypair.private_key.bytes.len(), DK_LEN); // ML-KEM-768 private key size
    }

    #[test]
    fn test_mlkem_ciphertext_size() {
        let keypair = MlKemCrypto::generate_keypair().unwrap();
        let encryption_result = MlKemCrypto::encapsulate(&keypair.public_key).unwrap();

        // ML-KEM-768 expected sizes
        assert_eq!(encryption_result.ciphertext.len(), CT_LEN); // ML-KEM-768 ciphertext size
        assert_eq!(encryption_result.shared_secret.len(), 32); // ML-KEM-768 shared secret size
    }

    #[test]
    fn test_mlkem_wrong_private_key() {
        let keypair1 = MlKemCrypto::generate_keypair().unwrap();
        let keypair2 = MlKemCrypto::generate_keypair().unwrap();

        let encryption_result = MlKemCrypto::encapsulate(&keypair1.public_key).unwrap();
        let decrypted_secret =
            MlKemCrypto::decapsulate(&keypair2.private_key, &encryption_result.ciphertext).unwrap();

        // Wrong key should produce different shared secret
        assert_ne!(encryption_result.shared_secret.as_slice(), decrypted_secret.as_slice());
    }
}
