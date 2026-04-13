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

//! Cryptographic algorithm implementations for classical and post-quantum cryptography.

pub mod ecdsa;
pub mod hybrid;
pub mod mldsa;
pub mod mlkem;
pub mod schnorr;
pub mod slh_dsa;

pub use ecdsa::{EcdsaCrypto, EcdsaCurve, EcdsaK256, EcdsaP256};
pub use hybrid::*;
pub use mldsa::{MlDsa44, MlDsaCrypto};
pub use mlkem::{EncryptionResult, MlKem768, MlKemCrypto};
pub use schnorr::{Schnorr, SchnorrCrypto};
pub use slh_dsa::{SlhDsaCrypto, SlhDsaSha2128f};
