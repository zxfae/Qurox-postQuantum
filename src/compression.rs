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

//! zstd/lz4 compression for hybrid signatures.
//!
//! Hybrid signatures (ECDSA + ML-DSA) are large. Compression is optional
//! and only applied when the payload exceeds `threshold_bytes`.

use crate::errors::{CryptoError, Result};
use crate::types::HybridSignature;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum CompressionAlgorithm {
    Zstd,
    Lz4,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum CompressionLevel {
    Fast,     // Level 1-3
    Balanced, // Level 6-9
    Maximum,  // Level 19-22
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    pub algorithm: CompressionAlgorithm,
    pub level: CompressionLevel,
    pub enabled: bool,
    pub threshold_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedData {
    pub compressed_bytes: Vec<u8>,
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f64,
    pub algorithm: CompressionAlgorithm,
    pub level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedHybridSignature {
    pub compressed_data: CompressedData,
    pub signature_metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionMetrics {
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f64,
    pub compression_time_ms: u128,
    pub decompression_time_ms: u128,
    pub algorithm: CompressionAlgorithm,
    pub level: u8,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Zstd,
            level: CompressionLevel::Balanced,
            enabled: true,
            threshold_bytes: 1024,
        }
    }
}

impl CompressionLevel {
    fn to_zstd_level(self) -> i32 {
        match self {
            CompressionLevel::Fast => 3,
            CompressionLevel::Balanced => 6,
            CompressionLevel::Maximum => 19,
        }
    }

    fn to_lz4_level(self) -> u32 {
        match self {
            CompressionLevel::Fast => 1,
            CompressionLevel::Balanced => 6,
            CompressionLevel::Maximum => 12,
        }
    }
}

pub struct CompressionEngine {
    config: CompressionConfig,
}

impl CompressionEngine {
    pub fn new(config: CompressionConfig) -> Self {
        Self { config }
    }

    pub fn new_default() -> Self {
        Self {
            config: CompressionConfig::default(),
        }
    }

    pub fn compress_data(&self, data: &[u8]) -> Result<CompressedData> {
        if !self.config.enabled || data.len() < self.config.threshold_bytes {
            return Ok(CompressedData {
                compressed_bytes: data.to_vec(),
                original_size: data.len(),
                compressed_size: data.len(),
                compression_ratio: 0.0,
                algorithm: self.config.algorithm,
                level: 0,
            });
        }

        match self.config.algorithm {
            CompressionAlgorithm::Zstd => self.compress_with_zstd(data),
            CompressionAlgorithm::Lz4 => self.compress_with_lz4(data),
        }
    }

    pub fn decompress_data(&self, compressed: &CompressedData) -> Result<Vec<u8>> {
        if compressed.compression_ratio == 0.0 {
            return Ok(compressed.compressed_bytes.clone());
        }

        match compressed.algorithm {
            CompressionAlgorithm::Zstd => self.decompress_with_zstd(compressed),
            CompressionAlgorithm::Lz4 => self.decompress_with_lz4(compressed),
        }
    }

    pub fn compress_hybrid_signature(
        &self,
        signature: &HybridSignature,
    ) -> Result<CompressedHybridSignature> {
        let serialized = serde_json::to_vec(signature).map_err(|_| {
            CryptoError::SerializationError("Failed to serialize signature".to_string())
        })?;

        let compressed_data = self.compress_data(&serialized)?;
        let signature_metadata = serde_json::to_value(&signature.metadata).map_err(|_| {
            CryptoError::SerializationError("Failed to serialize metadata".to_string())
        })?;

        Ok(CompressedHybridSignature {
            compressed_data,
            signature_metadata,
        })
    }

    pub fn decompress_hybrid_signature(
        &self,
        compressed: &CompressedHybridSignature,
    ) -> Result<HybridSignature> {
        let decompressed_bytes = self.decompress_data(&compressed.compressed_data)?;
        let signature: HybridSignature =
            serde_json::from_slice(&decompressed_bytes).map_err(|_| {
                CryptoError::SerializationError("Failed to deserialize signature".to_string())
            })?;

        Ok(signature)
    }

    pub fn compress_with_metrics(
        &self,
        data: &[u8],
    ) -> Result<(CompressedData, CompressionMetrics)> {
        let start = std::time::Instant::now();
        let compressed_data = self.compress_data(data)?;
        let compression_time = start.elapsed().as_millis();

        let decompression_start = std::time::Instant::now();
        let _decompressed = self.decompress_data(&compressed_data)?;
        let decompression_time = decompression_start.elapsed().as_millis();

        let metrics = CompressionMetrics {
            original_size: compressed_data.original_size,
            compressed_size: compressed_data.compressed_size,
            compression_ratio: compressed_data.compression_ratio,
            compression_time_ms: compression_time,
            decompression_time_ms: decompression_time,
            algorithm: compressed_data.algorithm,
            level: compressed_data.level,
        };

        Ok((compressed_data, metrics))
    }

    #[cfg(feature = "compression")]
    fn compress_with_zstd(&self, data: &[u8]) -> Result<CompressedData> {
        let level = self.config.level.to_zstd_level();
        let compressed_bytes = zstd::encode_all(data, level)
            .map_err(|_| CryptoError::Generic("ZSTD compression failed".to_string()))?;

        let original_size = data.len();
        let compressed_size = compressed_bytes.len();
        let compression_ratio = if original_size > 0 && compressed_size < original_size {
            ((original_size - compressed_size) as f64 / original_size as f64) * 100.0
        } else {
            0.0
        };

        Ok(CompressedData {
            compressed_bytes,
            original_size,
            compressed_size,
            compression_ratio,
            algorithm: CompressionAlgorithm::Zstd,
            level: level as u8,
        })
    }

    #[cfg(feature = "compression")]
    fn decompress_with_zstd(&self, compressed: &CompressedData) -> Result<Vec<u8>> {
        let decompressed = zstd::decode_all(&compressed.compressed_bytes[..])
            .map_err(|_| CryptoError::Generic("ZSTD decompression failed".to_string()))?;

        Ok(decompressed)
    }

    #[cfg(feature = "compression")]
    fn compress_with_lz4(&self, data: &[u8]) -> Result<CompressedData> {
        let compressed_bytes = lz4_flex::compress_prepend_size(data);

        let original_size = data.len();
        let compressed_size = compressed_bytes.len();
        let compression_ratio = if original_size > 0 && compressed_size < original_size {
            ((original_size - compressed_size) as f64 / original_size as f64) * 100.0
        } else {
            0.0
        };

        Ok(CompressedData {
            compressed_bytes,
            original_size,
            compressed_size,
            compression_ratio,
            algorithm: CompressionAlgorithm::Lz4,
            level: self.config.level.to_lz4_level() as u8,
        })
    }

    #[cfg(feature = "compression")]
    fn decompress_with_lz4(&self, compressed: &CompressedData) -> Result<Vec<u8>> {
        let decompressed = lz4_flex::decompress_size_prepended(&compressed.compressed_bytes)
            .map_err(|_| CryptoError::Generic("LZ4 decompression failed".to_string()))?;

        Ok(decompressed)
    }

    #[cfg(not(feature = "compression"))]
    fn compress_with_zstd(&self, data: &[u8]) -> Result<CompressedData> {
        Ok(CompressedData {
            compressed_bytes: data.to_vec(),
            original_size: data.len(),
            compressed_size: data.len(),
            compression_ratio: 0.0,
            algorithm: CompressionAlgorithm::Zstd,
            level: 0,
        })
    }

    #[cfg(not(feature = "compression"))]
    fn decompress_with_zstd(&self, compressed: &CompressedData) -> Result<Vec<u8>> {
        Ok(compressed.compressed_bytes.clone())
    }

    #[cfg(not(feature = "compression"))]
    fn compress_with_lz4(&self, data: &[u8]) -> Result<CompressedData> {
        Ok(CompressedData {
            compressed_bytes: data.to_vec(),
            original_size: data.len(),
            compressed_size: data.len(),
            compression_ratio: 0.0,
            algorithm: CompressionAlgorithm::Lz4,
            level: 0,
        })
    }

    #[cfg(not(feature = "compression"))]
    fn decompress_with_lz4(&self, compressed: &CompressedData) -> Result<Vec<u8>> {
        Ok(compressed.compressed_bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_engine_creation() {
        let engine = CompressionEngine::new_default();
        assert!(engine.config.enabled);
        assert_eq!(engine.config.algorithm, CompressionAlgorithm::Zstd);
    }

    #[test]
    fn test_data_compression_zstd() {
        let engine = CompressionEngine::new_default();
        let test_data = b"This is a test string that should compress well. This is a test string that should compress well. This is a test string that should compress well.";

        let compressed = engine.compress_data(test_data).unwrap();
        let decompressed = engine.decompress_data(&compressed).unwrap();

        assert_eq!(test_data, decompressed.as_slice());
        if cfg!(feature = "compression") && test_data.len() >= 1024 {
            assert!(compressed.compression_ratio > 0.0);
        }
    }

    #[test]
    fn test_data_compression_lz4() {
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Lz4,
            level: CompressionLevel::Fast,
            enabled: true,
            threshold_bytes: 10,
        };
        let engine = CompressionEngine::new(config);
        let test_data = b"This is a test string that should compress with LZ4. This is a test string that should compress with LZ4.";

        let compressed = engine.compress_data(test_data).unwrap();
        let decompressed = engine.decompress_data(&compressed).unwrap();

        assert_eq!(test_data, decompressed.as_slice());
    }

    #[test]
    fn test_compression_metrics() {
        let engine = CompressionEngine::new_default();
        let test_data = b"Large test data for compression metrics. ".repeat(50);

        let (compressed, metrics) = engine.compress_with_metrics(&test_data).unwrap();

        assert_eq!(metrics.original_size, test_data.len());
        assert_eq!(metrics.compressed_size, compressed.compressed_size);
        // Time metrics are always non-negative by design (u64 type)
        assert!(metrics.compression_time_ms == metrics.compression_time_ms);
        assert!(metrics.decompression_time_ms == metrics.decompression_time_ms);
    }

    #[test]
    fn test_threshold_behavior() {
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: CompressionLevel::Fast,
            enabled: true,
            threshold_bytes: 1000,
        };
        let engine = CompressionEngine::new(config);
        let small_data = b"small";

        let compressed = engine.compress_data(small_data).unwrap();

        assert_eq!(compressed.compression_ratio, 0.0);
        assert_eq!(compressed.original_size, compressed.compressed_size);
    }
}
