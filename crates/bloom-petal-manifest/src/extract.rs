//! Wasm custom-section extractor for petal manifests.
//!
//! Walks a wasm binary looking for the `bloom_petal_manifest` custom
//! section emitted by `#[bloom::petal]` (spec §8.1, §11.1). On hit,
//! decodes the bytes via [`crate::codec::decode`] and returns the
//! [`crate::types::PetalManifest`]. Missing section or malformed
//! bytes yield `None` — the caller decides whether absence is a hard
//! error (the chain's `load_manifest` treats it as "no manifest, no
//! Move dispatch" by surfacing `PetalNotFound`).

use wasmparser::{Parser, Payload};

use crate::codec;
use crate::local::{
    LocalCapability, LocalManifestError, LocalPetalManifest, local_capability_for_import,
    parse_local_manifest_toml, parse_local_manifest_toml_with_mounts,
};
use crate::types::{MANIFEST_CUSTOM_SECTION, PetalManifest};

/// Extract and canonical-decode the `bloom_petal_manifest` custom
/// section from `wasm`. Returns `None` if either:
/// - the section is absent (legacy petals, hand-written wasm, …), or
/// - the wasm parses but the section bytes do not round-trip through
///   [`crate::codec::decode`] (corruption / version skew).
///
/// In both cases the chain falls back to "no manifest" and the validator
/// rejects any `Command::Move` against this petal with `PetalNotFound`
/// (which is the conservative, fail-closed behaviour we want).
pub fn extract_petal_manifest(wasm: &[u8]) -> Option<PetalManifest> {
    let bytes = extract_petal_manifest_bytes(wasm)?;
    codec::decode(&bytes).ok()
}

/// Extract the raw bytes of the `bloom_petal_manifest` custom
/// section without decoding. Useful for tooling that wants to compute a
/// content hash over the section, or for callers that already trust the
/// bytes and want to skip the round-trip overhead.
pub fn extract_petal_manifest_bytes(wasm: &[u8]) -> Option<Vec<u8>> {
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

/// Strictly extract and validate a local handler-petal TOML manifest.
///
/// Unlike [`extract_petal_manifest`], this is an install-time API: absence,
/// malformed wasm, duplicate sections, non-UTF8 payloads, TOML errors, and
/// validation failures are hard errors. Callers must pass the currently
/// occupied local mounts so install-time collision checks cannot be skipped.
pub fn extract_local_petal_manifest<'a>(
    wasm: &[u8],
    occupied_mounts: impl IntoIterator<Item = &'a str>,
) -> Result<LocalPetalManifest, LocalManifestError> {
    let bytes = extract_single_manifest_section(wasm)?;
    let manifest = parse_local_manifest_toml_with_mounts(&bytes, occupied_mounts)?;
    validate_local_wasm_imports(wasm, &manifest)?;
    Ok(manifest)
}

/// Append a local manifest custom section to a wasm module.
///
/// The TOML bytes are parsed and validated before embedding so build tooling
/// fails before producing a content-addressed artifact. Existing manifest
/// sections are rejected to avoid ambiguity about which policy is installed.
pub fn embed_local_manifest_section(
    wasm: &[u8],
    petal_toml: &[u8],
) -> Result<Vec<u8>, LocalManifestError> {
    parse_local_manifest_toml(petal_toml)?;
    ensure_valid_wasm_without_manifest(wasm)?;

    let mut out = wasm.to_vec();
    out.push(0x00);
    let mut body = Vec::new();
    write_leb128(&mut body, MANIFEST_CUSTOM_SECTION.len() as u64);
    body.extend_from_slice(MANIFEST_CUSTOM_SECTION.as_bytes());
    body.extend_from_slice(petal_toml);
    write_leb128(&mut out, body.len() as u64);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Validate that Bloom host imports and declared capabilities match exactly.
pub fn validate_local_wasm_imports(
    wasm: &[u8],
    manifest: &LocalPetalManifest,
) -> Result<(), LocalManifestError> {
    let required = local_import_capabilities(wasm)?;
    let declared = manifest.cap_set();
    if let Some(cap) = required.difference(&declared).next() {
        return Err(LocalManifestError::Invalid(format!(
            "wasm imports host capability {cap} but manifest does not declare it"
        )));
    }
    if let Some(cap) = declared.difference(&required).next() {
        return Err(LocalManifestError::Invalid(format!(
            "manifest declares capability {cap} but wasm does not import it"
        )));
    }
    Ok(())
}

/// Scan local Bloom host imports and return the capabilities they require.
pub fn local_import_capabilities(
    wasm: &[u8],
) -> Result<std::collections::BTreeSet<LocalCapability>, LocalManifestError> {
    let mut caps = std::collections::BTreeSet::new();
    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm) {
        let payload = payload.map_err(|e| LocalManifestError::InvalidWasm(e.to_string()))?;
        if let Payload::ImportSection(imports) = payload {
            for import in imports {
                let import = import.map_err(|e| LocalManifestError::InvalidWasm(e.to_string()))?;
                if let Some(cap) = local_capability_for_import(import.module, import.name)? {
                    caps.insert(cap);
                }
            }
        }
    }
    Ok(caps)
}

fn extract_single_manifest_section(wasm: &[u8]) -> Result<Vec<u8>, LocalManifestError> {
    let mut found = None;
    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm) {
        let payload = payload.map_err(|e| LocalManifestError::InvalidWasm(e.to_string()))?;
        if let Payload::CustomSection(reader) = payload
            && reader.name() == MANIFEST_CUSTOM_SECTION
        {
            if found.is_some() {
                return Err(LocalManifestError::Duplicate);
            }
            found = Some(reader.data().to_vec());
        }
    }
    found.ok_or(LocalManifestError::Missing)
}

fn ensure_valid_wasm_without_manifest(wasm: &[u8]) -> Result<(), LocalManifestError> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm) {
        let payload = payload.map_err(|e| LocalManifestError::InvalidWasm(e.to_string()))?;
        if let Payload::CustomSection(reader) = payload
            && reader.name() == MANIFEST_CUSTOM_SECTION
        {
            return Err(LocalManifestError::Duplicate);
        }
    }
    Ok(())
}

fn write_leb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;
    use crate::types::{PetalManifest, SemVer};

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

    fn sample_manifest() -> PetalManifest {
        PetalManifest {
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
        let back = extract_petal_manifest(&wasm).expect("section must decode");
        assert_eq!(back, m);
    }

    #[test]
    fn returns_none_when_section_missing() {
        // Wasm with a *different* custom section name.
        let wasm = wasm_with_custom("not_the_manifest", &[1, 2, 3]);
        assert!(extract_petal_manifest(&wasm).is_none());
    }

    #[test]
    fn returns_none_on_malformed_payload() {
        // Right section name, garbage payload.
        let wasm = wasm_with_custom(MANIFEST_CUSTOM_SECTION, &[0xFF, 0xFF, 0xFF]);
        assert!(extract_petal_manifest(&wasm).is_none());
    }

    #[test]
    fn returns_none_on_non_wasm_input() {
        let garbage = vec![0u8; 16];
        assert!(extract_petal_manifest(&garbage).is_none());
    }

    #[test]
    fn raw_bytes_round_trip() {
        let m = sample_manifest();
        let encoded = codec::encode(&m).unwrap();
        let wasm = wasm_with_custom(MANIFEST_CUSTOM_SECTION, &encoded);
        let raw = extract_petal_manifest_bytes(&wasm).unwrap();
        assert_eq!(raw, encoded);
    }

    fn valid_local_toml() -> &'static [u8] {
        br#"
schema = "bloom.petal.local.v1"
name = "echo"

[provides]
kind = "vfs"
mount = "echo"
caps = []
"#
    }

    fn local_toml_with_caps(caps: &str) -> Vec<u8> {
        format!(
            r#"
schema = "bloom.petal.local.v1"
name = "echo"

[provides]
kind = "vfs"
mount = "echo"
caps = [{caps}]
"#
        )
        .into_bytes()
    }

    fn wasm_with_import_and_custom(module: &str, name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\0asm");
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        // Type section: one nullary function type returning i32.
        out.push(0x01);
        let mut types = Vec::new();
        leb128(&mut types, 1);
        types.push(0x60);
        leb128(&mut types, 0);
        leb128(&mut types, 1);
        types.push(0x7f);
        leb128(&mut out, types.len() as u64);
        out.extend_from_slice(&types);

        // Import section: one function import using type index 0.
        out.push(0x02);
        let mut imports = Vec::new();
        leb128(&mut imports, 1);
        leb128(&mut imports, module.len() as u64);
        imports.extend_from_slice(module.as_bytes());
        leb128(&mut imports, name.len() as u64);
        imports.extend_from_slice(name.as_bytes());
        imports.push(0x00);
        leb128(&mut imports, 0);
        leb128(&mut out, imports.len() as u64);
        out.extend_from_slice(&imports);

        out.push(0x00);
        let mut body = Vec::new();
        leb128(&mut body, MANIFEST_CUSTOM_SECTION.len() as u64);
        body.extend_from_slice(MANIFEST_CUSTOM_SECTION.as_bytes());
        body.extend_from_slice(payload);
        leb128(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn embeds_and_extracts_local_toml_manifest() {
        let wasm = wasm_with_custom("not_the_manifest", b"x");
        let embedded = embed_local_manifest_section(&wasm, valid_local_toml()).unwrap();
        let local = extract_local_petal_manifest(&embedded, std::iter::empty::<&str>()).unwrap();
        assert_eq!(local.name, "echo");
        assert_eq!(local.provides.mount, "echo");
        assert_eq!(
            extract_petal_manifest_bytes(&embedded).unwrap(),
            valid_local_toml()
        );
        assert!(
            extract_petal_manifest(&embedded).is_none(),
            "chain decoder must not silently accept local TOML manifests"
        );
    }

    #[test]
    fn local_extract_errors_on_missing_or_malformed_section() {
        let wasm = wasm_with_custom("not_the_manifest", b"x");
        assert!(matches!(
            extract_local_petal_manifest(&wasm, std::iter::empty::<&str>()),
            Err(LocalManifestError::Missing)
        ));

        let malformed = wasm_with_custom(MANIFEST_CUSTOM_SECTION, b"not = [toml");
        assert!(matches!(
            extract_local_petal_manifest(&malformed, std::iter::empty::<&str>()),
            Err(LocalManifestError::Toml(_))
        ));
    }

    #[test]
    fn local_embed_rejects_duplicate_manifest_sections() {
        let wasm = wasm_with_custom(MANIFEST_CUSTOM_SECTION, valid_local_toml());
        assert!(matches!(
            embed_local_manifest_section(&wasm, valid_local_toml()),
            Err(LocalManifestError::Duplicate)
        ));
    }

    #[test]
    fn local_extract_rejects_mount_collision() {
        let wasm = wasm_with_custom(MANIFEST_CUSTOM_SECTION, valid_local_toml());
        assert!(matches!(
            extract_local_petal_manifest(&wasm, ["echo"]),
            Err(LocalManifestError::Invalid(_))
        ));
    }

    #[test]
    fn local_extract_rejects_undeclared_or_unused_host_caps() {
        let no_caps = valid_local_toml();
        let wasm = wasm_with_import_and_custom("bloom.v1", "sign_hash", no_caps);
        assert!(matches!(
            extract_local_petal_manifest(&wasm, std::iter::empty::<&str>()),
            Err(LocalManifestError::Invalid(_))
        ));

        let sign_cap = local_toml_with_caps(r#""sign""#);
        let wasm = wasm_with_import_and_custom("bloom.v1", "sign_hash", &sign_cap);
        let local = extract_local_petal_manifest(&wasm, std::iter::empty::<&str>()).unwrap();
        assert!(local.cap_set().contains(&LocalCapability::Sign));

        let declared_but_unused = wasm_with_custom(MANIFEST_CUSTOM_SECTION, &sign_cap);
        assert!(matches!(
            extract_local_petal_manifest(&declared_but_unused, std::iter::empty::<&str>()),
            Err(LocalManifestError::Invalid(_))
        ));
    }
}
