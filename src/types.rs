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

//! Shared types — keys, signatures, algorithms, policies.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Algorithm {
    EcdsaK256,
    EcdsaP256,
    Schnorr,
    MlDsa44,
    SlhDsaSha2128f,
    MlKem768,
    Hybrid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ClassicalAlgorithm {
    EcdsaK256,
    EcdsaP256,
    Schnorr,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PostQuantumAlgorithm {
    MlDsa44,
    SlhDsaSha2128f,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SecurityLevel {
    Classical,
    Hybrid,
    QuantumOnly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum TransitionMode {
    ClassicalOnly,
    HybridOptional,
    HybridRequired,
    QuantumOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    pub bytes: Vec<u8>,
    pub algorithm: Algorithm,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub bytes: Vec<u8>,
    pub algorithm: Algorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub bytes: Vec<u8>,
    pub algorithm: Algorithm,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKeyPair {
    pub classical_keypair: KeyPair,
    pub post_quantum_keypair: KeyPair,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub classical_signature: Signature,
    pub post_quantum_signature: Signature,
    pub metadata: HybridMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridMetadata {
    pub classical_algorithm: ClassicalAlgorithm,
    pub post_quantum_algorithm: PostQuantumAlgorithm,
    pub security_level: SecurityLevel,
    pub transition_mode: TransitionMode,
    pub compressed: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPolicy {
    pub security_level: SecurityLevel,
    pub transition_mode: TransitionMode,
    pub compression_enabled: bool,
    pub compression_config: Option<crate::compression::CompressionConfig>,
}
