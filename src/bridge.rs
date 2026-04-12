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

//! Trait abstractions shared by all algorithm implementations.

use crate::errors::Result;

/// Implemented by every signature algorithm (ECDSA, Schnorr, ML-DSA, SLH-DSA).
pub trait CryptographyBridge: Clone {
    type PublicKey: Clone;
    type SecretKey: Clone;
    type SignedMessage: Clone + std::fmt::Debug;

    fn key_generator(&self) -> Result<(Self::PublicKey, Self::SecretKey)>;
    fn sign(&self, secret_key: &Self::SecretKey, message: &[u8]) -> Result<Self::SignedMessage>;
    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::SignedMessage,
    ) -> Result<bool>;
    fn public_key_to_bytes(&self, public_key: &Self::PublicKey) -> Vec<u8>;
    fn secret_key_to_bytes(&self, secret_key: &Self::SecretKey) -> Vec<u8>;
    fn signature_to_bytes(&self, signature: &Self::SignedMessage) -> Vec<u8>;
}

/// Implemented by KEM algorithms (currently ML-KEM-768).
///
/// KEM is not signing — it establishes a shared secret between two parties.
/// The sender encapsulates, the receiver decapsulates; both end up with the same secret.
pub trait KeyEncapsulationBridge: Clone {
    type PublicKey: Clone;
    type SecretKey: Clone;
    type Ciphertext: Clone;
    type SharedSecret: Clone;

    fn kem_keygen(&self) -> Result<(Self::PublicKey, Self::SecretKey)>;
    fn encapsulate(
        &self,
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)>;
    fn decapsulate(
        &self,
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret>;
    fn kem_public_key_to_bytes(&self, public_key: &Self::PublicKey) -> Vec<u8>;
}
