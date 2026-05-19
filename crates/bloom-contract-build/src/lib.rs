//! Build orchestration for `bloom contract build`.
//!
//! The build crate is responsible for:
//!
//! 1. Driving `cargo build --target wasm32-unknown-unknown --release` against
//!    a contract crate (Phase 6).
//! 2. Validating the resulting wasm module against the deterministic-profile
//!    rules (no floating point, only `chain.*` imports, memory/code limits).
//! 3. Lifting the embedded manifest data segment out of the wasm, merging in
//!    the computed `wasm_hash` + `source_hash`, and emitting `<name>.wasm`
//!    plus `<name>.manifest.json`.
//! 4. Verifying that a published manifest matches a published wasm.
//!
//! Phase 1 ships the public types + error enum only; the real implementations
//! land in Phase 6.

use bloom_contract_metadata::Manifest;
use thiserror::Error;

/// Output of a successful build.
#[derive(Clone, Debug)]
pub struct ArtifactSet {
    pub wasm: Vec<u8>,
    pub manifest: Manifest,
    pub wasm_hash: [u8; 32],
    pub source_hash: [u8; 32],
}

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("cargo build failed: {0}")]
    Cargo(String),
    #[error("wasm validation failed: {0}")]
    Validation(String),
    #[error("manifest extraction failed: {0}")]
    Manifest(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Compute the canonical wasm hash (`blake3` of the module bytes).
pub fn wasm_hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_hash_is_blake3() {
        let bytes = b"hello";
        let expected = *blake3::hash(bytes).as_bytes();
        assert_eq!(wasm_hash(bytes), expected);
    }
}
