//! Replayability attestation tuple emitted for onchain petal runs.
//!
//! An attestation is the public summary of an onchain run that someone
//! else can use to *verify* the run by re-executing the named petal
//! against the named input and checking the output hash matches. Block
//! pinning is captured so a verifier knows the historical context.

use serde::{Deserialize, Serialize};

/// BLAKE3 of arbitrary bytes, hex-encoded.
pub fn blake3_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PetalAttestation {
    /// Content hash of the petal wasm.
    pub petal_hash: String,
    /// BLAKE3 of the stdin bytes passed to the run.
    pub input_hash: String,
    /// BLAKE3 of the stdout bytes captured from the run.
    pub output_hash: String,
    /// Highest block number observed in any `chain_read_at` call, or
    /// `None` if the petal made no chain reads.
    pub block_pin: Option<u64>,
    /// Wasmtime version used to execute the run. Diagnostic only.
    pub wasmtime_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_hex_matches_known_vector() {
        // BLAKE3 of empty input is a known constant.
        assert_eq!(
            blake3_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn attestation_serde_roundtrip() {
        let a = PetalAttestation {
            petal_hash: "p".into(),
            input_hash: "i".into(),
            output_hash: "o".into(),
            block_pin: Some(42),
            wasmtime_version: "26.0.0".into(),
        };
        let s = serde_json::to_string(&a).unwrap();
        let a2: PetalAttestation = serde_json::from_str(&s).unwrap();
        assert_eq!(a, a2);
    }
}
