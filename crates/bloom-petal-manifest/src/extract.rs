//! Wasm custom-section extractor for the canonical petal manifest.
//!
//! Walks a wasm binary looking for the `bloom_petal_manifest_v0` custom
//! section emitted by `#[bloom::petal]` (spec §8.1, §11.1). On hit,
//! decodes the bytes via [`crate::codec::decode`] and returns the
//! [`crate::types::PetalManifestV0`]. Missing section or malformed
//! bytes yield `None` — the caller decides whether absence is a hard
//! error (the chain's `load_manifest` treats it as "no manifest, no
//! Move dispatch" by surfacing `PetalNotFound`).

use wasmparser::{Parser, Payload};

use crate::codec;
use crate::types::{MANIFEST_CUSTOM_SECTION, PetalManifestV0};

/// Extract and canonical-decode the `bloom_petal_manifest_v0` custom
/// section from `wasm`. Returns `None` if either:
/// - the section is absent (legacy petals, hand-written wasm, …), or
/// - the wasm parses but the section bytes do not round-trip through
///   [`crate::codec::decode`] (corruption / version skew).
///
/// In both cases the chain falls back to "no manifest" and the validator
/// rejects any `Command::Move` against this petal with `PetalNotFound`
/// (which is the conservative, fail-closed behaviour we want).
pub fn extract_petal_manifest_v0(wasm: &[u8]) -> Option<PetalManifestV0> {
    let bytes = extract_petal_manifest_v0_bytes(wasm)?;
    codec::decode(&bytes).ok()
}

/// Extract the raw bytes of the `bloom_petal_manifest_v0` custom
/// section without decoding. Useful for tooling that wants to compute a
/// content hash over the section, or for callers that already trust the
/// bytes and want to skip the round-trip overhead.
pub fn extract_petal_manifest_v0_bytes(wasm: &[u8]) -> Option<Vec<u8>> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm) {
        let payload = payload.ok()?;
        if let Payload::CustomSection(reader) = payload
            && reader.name() == MANIFEST_CUSTOM_SECTION
        {
            return Some(reader.data().to_vec());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;
    use crate::types::{PetalManifestV0, SemVer};

    /// Build a minimal wasm with one custom section.
    /// We hand-emit the wasm preamble + a single CustomSection payload.
    /// Format reference:
    ///   `\0asm` magic + `0x01 0x00 0x00 0x00` version, then
    ///   one custom section: section id 0, LEB-encoded length, LEB
    ///   encoded name length, name bytes, payload bytes.
    fn wasm_with_custom(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\0asm");
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // Custom section: section id 0
        out.push(0x00);
        // Body = name_len (LEB) + name_bytes + payload_bytes
        let mut body = Vec::new();
        leb128(&mut body, name.len() as u64);
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(payload);
        leb128(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
        out
    }

    fn leb128(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            } else {
                out.push(b | 0x80);
            }
        }
    }

    fn sample_manifest() -> PetalManifestV0 {
        PetalManifestV0 {
            schema_version: crate::types::SCHEMA_VERSION,
            module_path: "/bloom/test/x".into(),
            framework_version: SemVer::new(0, 1, 0),
            ..Default::default()
        }
    }

    #[test]
    fn extracts_canonical_section() {
        let m = sample_manifest();
        let encoded = codec::encode(&m).unwrap();
        let wasm = wasm_with_custom(MANIFEST_CUSTOM_SECTION, &encoded);
        let back = extract_petal_manifest_v0(&wasm).expect("section must decode");
        assert_eq!(back, m);
    }

    #[test]
    fn returns_none_when_section_missing() {
        // Wasm with a *different* custom section name.
        let wasm = wasm_with_custom("not_the_manifest", &[1, 2, 3]);
        assert!(extract_petal_manifest_v0(&wasm).is_none());
    }

    #[test]
    fn returns_none_on_malformed_payload() {
        // Right section name, garbage payload.
        let wasm = wasm_with_custom(MANIFEST_CUSTOM_SECTION, &[0xFF, 0xFF, 0xFF]);
        assert!(extract_petal_manifest_v0(&wasm).is_none());
    }

    #[test]
    fn returns_none_on_non_wasm_input() {
        let garbage = vec![0u8; 16];
        assert!(extract_petal_manifest_v0(&garbage).is_none());
    }

    #[test]
    fn raw_bytes_round_trip() {
        let m = sample_manifest();
        let encoded = codec::encode(&m).unwrap();
        let wasm = wasm_with_custom(MANIFEST_CUSTOM_SECTION, &encoded);
        let raw = extract_petal_manifest_v0_bytes(&wasm).unwrap();
        assert_eq!(raw, encoded);
    }
}
