//! Build orchestration for `bloom contract build`.
//!
//! Drives a contract crate from source to a paired `(.wasm, .manifest.json)`
//! deliverable. The orchestration is deliberately linear:
//!
//! 1. Run `cargo build --target wasm32-unknown-unknown --release` (or
//!    `--profile dev`) inside the crate directory.
//! 2. Locate the freshly-built `<crate-name-snake>.wasm` (cdylib output)
//!    under `target/wasm32-unknown-unknown/<profile>/`.
//! 3. Validate the module against the deterministic-execution profile:
//!    no floating-point ops, only `chain.*` imports, function exports
//!    restricted to `init`/`call`, memory ≤ 256 pages, wasm size ≤ 256
//!    KiB. Out-of-policy modules abort the build.
//! 4. Extract the `bloom_manifest` custom section the macro emitted,
//!    decode its JSON skeleton, fill in `wasm_hash` / `source_hash` /
//!    `imports` (the live set of `chain.*` host imports the module
//!    actually links).
//! 5. Write `<out_dir>/<name>.wasm` and `<out_dir>/<name>.manifest.json`.
//!
//! `verify_manifest_against_wasm` performs the inverse — given a manifest
//! JSON and a wasm, check that `wasm_hash` matches and the import set is
//! a subset of the chain's policy. It's the same primitive a block
//! explorer would use to confirm a deployed wasm matches a published
//! manifest.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use bloom_contract_metadata::{Limits, Manifest};
use thiserror::Error;
use wasmparser::{ExternalKind, Parser, Payload};

/// Output of a successful build.
#[derive(Clone, Debug)]
pub struct ArtifactSet {
    /// Final wasm bytes (post-validation). Identical to whatever ends up
    /// at `<out_dir>/<name>.wasm`.
    pub wasm: Vec<u8>,
    /// Manifest with hashes + imports populated.
    pub manifest: Manifest,
    /// `blake3(wasm)`, lowercase hex — also stored on the manifest.
    pub wasm_hash: String,
    /// `blake3` of the canonical src/ tree, lowercase hex — also stored
    /// on the manifest.
    pub source_hash: String,
    /// `blake3` of the canonical (compact serde_json) manifest bytes,
    /// lowercase hex. This is the value users pass to
    /// `bloom chain deploy --manifest-hash` so the on-chain
    /// `Account.manifest_hash` anchor matches.
    pub manifest_hash: String,
    /// On-disk paths the build emitted.
    pub wasm_path: PathBuf,
    pub manifest_path: PathBuf,
}

/// Cargo build profile the wasm is compiled under.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Profile {
    Dev,
    #[default]
    Release,
}

impl Profile {
    fn cargo_dir_name(self) -> &'static str {
        match self {
            Profile::Dev => "debug",
            Profile::Release => "release",
        }
    }

    fn cargo_arg(self) -> Option<&'static str> {
        match self {
            Profile::Dev => None,
            Profile::Release => Some("--release"),
        }
    }
}

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("cargo build failed: {0}")]
    Cargo(String),
    #[error("wasm validation failed: {0}")]
    Validation(String),
    #[error("manifest extraction failed: {0}")]
    Manifest(String),
    #[error("crate metadata error: {0}")]
    CrateMeta(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Compute the canonical wasm hash (`blake3` of the module bytes).
pub fn wasm_hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Compute the canonical `manifest_hash` — `blake3(serde_json::to_vec(manifest))`.
///
/// This is the on-chain anchor a user passes to
/// `bloom chain deploy --manifest-hash` so a deployed account's
/// `Account.manifest_hash` (Phase 8) can be verified against a published
/// `.manifest.json` byte-for-byte.
///
/// Stability: `serde_json::to_vec` emits struct fields in declaration order
/// (no whitespace, no key reordering), so the byte form of any given
/// `Manifest` is deterministic across builds.
pub fn manifest_hash(manifest: &Manifest) -> [u8; 32] {
    let bytes = serde_json::to_vec(manifest).expect("Manifest serializes");
    *blake3::hash(&bytes).as_bytes()
}

/// Compute the canonical source hash for a crate at `crate_dir`.
///
/// Walks `src/` in lexical order, feeding `(rel_path, content)` pairs into
/// a single blake3 hasher. The output is stable across machines provided
/// the source tree's bytes are byte-identical — that's the property the
/// `bloom contract verify` step relies on for "this wasm was built from
/// this source".
pub fn source_hash(crate_dir: &Path) -> Result<[u8; 32], BuildError> {
    let src = crate_dir.join("src");
    let mut entries: Vec<PathBuf> = Vec::new();
    collect_rs_files(&src, &mut entries)?;
    entries.sort();

    let mut hasher = blake3::Hasher::new();
    for path in &entries {
        let rel = path
            .strip_prefix(&src)
            .map_err(|e| BuildError::CrateMeta(format!("strip prefix {}: {e}", path.display())))?;
        let rel_str = rel.to_string_lossy();
        // Length-prefix path + content so concatenation is unambiguous.
        let path_bytes = rel_str.as_bytes();
        hasher.update(&(path_bytes.len() as u64).to_le_bytes());
        hasher.update(path_bytes);
        let body = fs::read(path)?;
        hasher.update(&(body.len() as u64).to_le_bytes());
        hasher.update(&body);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            collect_rs_files(&p, out)?;
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
    Ok(())
}

// ===========================================================================
// Wasm validation + section/import extraction
// ===========================================================================

/// Outcome of `validate_wasm` — the live import list plus any policy
/// violations. Used by the build pipeline to enforce determinism rules
/// and by `verify_manifest_against_wasm` to spot-check a published
/// artifact.
#[derive(Clone, Debug)]
pub struct WasmInspection {
    /// `<module>.<name>` for every wasm import the module declares.
    pub imports: Vec<String>,
}

/// Hard caps for the deterministic profile (spec §10 + §11).
pub const MAX_MEMORY_PAGES: u32 = 256;
pub const MAX_WASM_BYTES: usize = 262_144;

/// Validate a contract wasm against the deterministic-execution profile.
///
/// Rejects: floating-point instructions, non-`chain.*` imports, function
/// exports outside `{init, call}`, memory > 256 pages, wasm > 256 KiB.
/// Non-function exports (globals, tables, the `memory` export itself)
/// are tolerated — they aren't host entry points, and rustc's wasm32
/// backend emits a handful of them by default (`__heap_base`,
/// `__data_end`, ...).
pub fn validate_wasm(bytes: &[u8]) -> Result<WasmInspection, BuildError> {
    if bytes.len() > MAX_WASM_BYTES {
        return Err(BuildError::Validation(format!(
            "wasm size {} exceeds {MAX_WASM_BYTES}-byte cap",
            bytes.len()
        )));
    }
    let mut imports: Vec<String> = Vec::new();
    let parser = Parser::new(0);
    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| BuildError::Validation(e.to_string()))?;
        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| BuildError::Validation(e.to_string()))?;
                    if import.module != "chain" {
                        return Err(BuildError::Validation(format!(
                            "disallowed import: '{}.{}' (only `chain.*` host imports are permitted)",
                            import.module, import.name
                        )));
                    }
                    imports.push(format!("{}.{}", import.module, import.name));
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| BuildError::Validation(e.to_string()))?;
                    if let ExternalKind::Func = export.kind {
                        match export.name {
                            "init" | "call" => {}
                            other => {
                                return Err(BuildError::Validation(format!(
                                    "disallowed function export: '{other}' (only `init` and `call` may be exported)"
                                )));
                            }
                        }
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem = mem.map_err(|e| BuildError::Validation(e.to_string()))?;
                    if mem.initial > u64::from(MAX_MEMORY_PAGES) {
                        return Err(BuildError::Validation(format!(
                            "memory min pages {} exceeds cap of {MAX_MEMORY_PAGES}",
                            mem.initial
                        )));
                    }
                    if let Some(max) = mem.maximum {
                        if max > u64::from(MAX_MEMORY_PAGES) {
                            return Err(BuildError::Validation(format!(
                                "memory max pages {max} exceeds cap of {MAX_MEMORY_PAGES}"
                            )));
                        }
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut reader = body
                    .get_operators_reader()
                    .map_err(|e| BuildError::Validation(e.to_string()))?;
                while !reader.eof() {
                    let op = reader.read().map_err(|e| BuildError::Validation(e.to_string()))?;
                    if is_floating_point_op(&op) {
                        return Err(BuildError::Validation(format!(
                            "floating-point op disallowed: {:?}",
                            op
                        )));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(WasmInspection { imports })
}

/// Wasmparser's `Operator` enum carries one variant per opcode; the
/// floating-point ones share a `F32`/`F64` prefix on the variant name.
/// Rather than enumerate dozens, we check the debug representation —
/// stable across wasmparser minor releases since the variant names are
/// part of the public surface.
fn is_floating_point_op(op: &wasmparser::Operator) -> bool {
    let dbg = format!("{op:?}");
    // Discriminator name comes first, e.g. `F32Add { .. }` or `F64Load`.
    dbg.starts_with("F32") || dbg.starts_with("F64")
}

/// Extract the bytes of the `bloom_manifest` custom wasm section embedded
/// by `#[bloom::contract]`. Returns `None` if no such section exists —
/// the caller decides whether that's an error.
pub fn extract_manifest_section(bytes: &[u8]) -> Result<Option<Vec<u8>>, BuildError> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| BuildError::Manifest(e.to_string()))?;
        if let Payload::CustomSection(reader) = payload {
            if reader.name() == "bloom_manifest" {
                return Ok(Some(reader.data().to_vec()));
            }
        }
    }
    Ok(None)
}

// ===========================================================================
// Manifest finalisation
// ===========================================================================

/// Decode the embedded manifest skeleton and fold in the runtime-derived
/// fields (`wasm_hash`, `source_hash`, `imports`, `limits`).
pub fn finalise_manifest(
    skeleton: &[u8],
    wasm_hash_hex: String,
    source_hash_hex: String,
    imports: Vec<String>,
) -> Result<Manifest, BuildError> {
    // The skeleton carries extra keys the on-disk schema doesn't model
    // yet (e.g. `interfaces`, `signature` on events/errors). Decode via
    // `serde_json::Value` first so unknown keys round-trip without
    // exploding when the schema grows.
    let mut value: serde_json::Value = serde_json::from_slice(skeleton)
        .map_err(|e| BuildError::Manifest(format!("skeleton JSON: {e}")))?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| BuildError::Manifest("skeleton root is not an object".into()))?;
    obj.insert("wasm_hash".into(), serde_json::Value::String(wasm_hash_hex));
    obj.insert("source_hash".into(), serde_json::Value::String(source_hash_hex));
    obj.insert(
        "imports".into(),
        serde_json::Value::Array(imports.into_iter().map(serde_json::Value::String).collect()),
    );
    // Limits aren't user-configurable yet; force the on-disk default.
    let limits = Limits::default();
    obj.insert(
        "limits".into(),
        serde_json::to_value(limits).expect("Limits serializes"),
    );

    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|e| BuildError::Manifest(format!("decode finalised manifest: {e}")))?;
    Ok(manifest)
}

/// Verify a published manifest matches a wasm: hashes line up and the
/// import policy holds. The wasm itself must already satisfy
/// `validate_wasm`; this function additionally confirms the imports in
/// the wasm are a subset of the manifest's declared `imports` array (a
/// drift here means the manifest is out of date).
pub fn verify_manifest_against_wasm(manifest: &Manifest, wasm: &[u8]) -> Result<(), BuildError> {
    let actual_hash = hex_encode(&wasm_hash(wasm));
    if manifest.wasm_hash != actual_hash {
        return Err(BuildError::Manifest(format!(
            "wasm_hash mismatch: manifest={} actual={}",
            manifest.wasm_hash, actual_hash
        )));
    }
    let insp = validate_wasm(wasm)?;
    for live in &insp.imports {
        if !manifest.imports.iter().any(|m| m == live) {
            return Err(BuildError::Manifest(format!(
                "wasm imports `{live}` but manifest does not declare it"
            )));
        }
    }
    Ok(())
}

// ===========================================================================
// Cargo driver
// ===========================================================================

/// Run `cargo build --target wasm32-unknown-unknown` inside `crate_dir`
/// and return the resulting wasm bytes.
///
/// `crate_dir` must point at a directory containing `Cargo.toml`. The
/// expected output path is
/// `<crate_dir>/target/wasm32-unknown-unknown/<profile>/<snake_name>.wasm`.
/// Workspace members built from a parent root land their wasm at
/// `<workspace>/target/...` — that case is handled by also searching the
/// `cargo locate-project`-derived workspace root.
pub fn build_crate(crate_dir: &Path, profile: Profile) -> Result<Vec<u8>, BuildError> {
    let crate_name = read_crate_name(crate_dir)?;
    let wasm_name = format!("{}.wasm", crate_name.replace('-', "_"));

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--target")
        .arg("wasm32-unknown-unknown");
    if let Some(rel) = profile.cargo_arg() {
        cmd.arg(rel);
    }
    cmd.arg("--manifest-path").arg(crate_dir.join("Cargo.toml"));
    cmd.env("CARGO_TERM_COLOR", "never");
    let output = cmd.output().map_err(|e| BuildError::Cargo(format!("spawn cargo: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(BuildError::Cargo(format!(
            "cargo build failed (status {}):\n{}",
            output.status, stderr
        )));
    }

    let candidates = wasm_candidates(crate_dir, profile, &wasm_name)?;
    for path in &candidates {
        if path.is_file() {
            return Ok(fs::read(path)?);
        }
    }
    Err(BuildError::Cargo(format!(
        "wasm artifact not found; looked at: {}",
        candidates.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
    )))
}

fn read_crate_name(crate_dir: &Path) -> Result<String, BuildError> {
    let toml_path = crate_dir.join("Cargo.toml");
    let body = fs::read_to_string(&toml_path)?;
    // Lightweight parse — we only need `package.name`. Avoids pulling in
    // a TOML dep at the macro/build layer.
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("name") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                let unquoted = rest.trim_matches('"').trim_matches('\'');
                if !unquoted.is_empty() {
                    return Ok(unquoted.to_string());
                }
            }
        }
    }
    Err(BuildError::CrateMeta(format!(
        "could not find `name = ...` in {}",
        toml_path.display()
    )))
}

fn wasm_candidates(crate_dir: &Path, profile: Profile, wasm_name: &str) -> Result<Vec<PathBuf>, BuildError> {
    let subpath = format!("target/wasm32-unknown-unknown/{}/{}", profile.cargo_dir_name(), wasm_name);
    let mut out = vec![crate_dir.join(&subpath)];

    // If the crate is a workspace member, the target dir is at the
    // workspace root. Walk parents looking for a Cargo.toml that contains
    // a `[workspace]` table — that's the workspace root.
    let mut cur = crate_dir.parent();
    while let Some(p) = cur {
        let candidate_toml = p.join("Cargo.toml");
        if candidate_toml.is_file() {
            if let Ok(body) = fs::read_to_string(&candidate_toml) {
                if body.contains("[workspace]") {
                    out.push(p.join(&subpath));
                }
            }
        }
        cur = p.parent();
    }
    Ok(out)
}

// ===========================================================================
// End-to-end orchestration
// ===========================================================================

/// Build a contract crate end-to-end: compile, validate, extract +
/// finalise the manifest, write artifacts to `out_dir`.
pub fn emit_artifacts(crate_dir: &Path, out_dir: &Path, profile: Profile) -> Result<ArtifactSet, BuildError> {
    fs::create_dir_all(out_dir)?;

    let wasm = build_crate(crate_dir, profile)?;
    let inspection = validate_wasm(&wasm)?;
    let skeleton = extract_manifest_section(&wasm)?
        .ok_or_else(|| BuildError::Manifest("bloom_manifest custom section missing".into()))?;

    let wasm_hash_bytes = wasm_hash(&wasm);
    let source_hash_bytes = source_hash(crate_dir)?;
    let wasm_hash_hex = hex_encode(&wasm_hash_bytes);
    let source_hash_hex = hex_encode(&source_hash_bytes);

    let manifest = finalise_manifest(
        &skeleton,
        wasm_hash_hex.clone(),
        source_hash_hex.clone(),
        inspection.imports,
    )?;

    let name = manifest.contract.name.replace('-', "_");
    let wasm_path = out_dir.join(format!("{}.wasm", name));
    let manifest_path = out_dir.join(format!("{}.manifest.json", name));
    fs::write(&wasm_path, &wasm)?;
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| BuildError::Manifest(format!("serialize manifest: {e}")))?;
    fs::write(&manifest_path, manifest_json)?;

    let manifest_hash_hex = hex_encode(&manifest_hash(&manifest));

    Ok(ArtifactSet {
        wasm,
        manifest,
        wasm_hash: wasm_hash_hex,
        source_hash: source_hash_hex,
        manifest_hash: manifest_hash_hex,
        wasm_path,
        manifest_path,
    })
}

// ===========================================================================
// Helpers
// ===========================================================================

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(NIBBLE[(*byte >> 4) as usize] as char);
        s.push(NIBBLE[(*byte & 0x0f) as usize] as char);
    }
    s
}
const NIBBLE: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_hash_is_blake3() {
        let bytes = b"hello";
        let expected = *blake3::hash(bytes).as_bytes();
        assert_eq!(wasm_hash(bytes), expected);
    }

    #[test]
    fn hex_encode_is_lowercase() {
        let h = wasm_hash(b"x");
        let s = hex_encode(&h);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn source_hash_walks_src_tree() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("lib.rs"), b"pub fn a() {}").unwrap();
        fs::write(src.join("util.rs"), b"pub fn b() {}").unwrap();
        let h1 = source_hash(dir.path()).unwrap();
        // Same content + paths → identical hash.
        let h2 = source_hash(dir.path()).unwrap();
        assert_eq!(h1, h2);
        // Mutating content changes the hash.
        fs::write(src.join("lib.rs"), b"pub fn a() { /* edit */ }").unwrap();
        let h3 = source_hash(dir.path()).unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn validate_wasm_accepts_minimal_module() {
        // Empty module: header + version, no sections.
        let bytes = wat::parse_str("(module)").unwrap();
        let insp = validate_wasm(&bytes).unwrap();
        assert!(insp.imports.is_empty());
    }

    #[test]
    fn validate_wasm_rejects_non_chain_imports() {
        let bytes = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32))))"#,
        )
        .unwrap();
        let err = validate_wasm(&bytes).unwrap_err();
        assert!(matches!(err, BuildError::Validation(_)));
    }

    #[test]
    fn validate_wasm_accepts_chain_imports() {
        let bytes = wat::parse_str(
            r#"(module
                (import "chain" "state_read" (func (param i32 i32 i32))))"#,
        )
        .unwrap();
        let insp = validate_wasm(&bytes).unwrap();
        assert_eq!(insp.imports, vec!["chain.state_read".to_string()]);
    }

    #[test]
    fn validate_wasm_rejects_floating_point_ops() {
        let bytes = wat::parse_str(
            r#"(module
                (func (export "call")
                    f32.const 1.0
                    drop))"#,
        )
        .unwrap();
        let err = validate_wasm(&bytes).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("floating-point"), "got: {msg}");
    }

    #[test]
    fn validate_wasm_rejects_disallowed_function_export() {
        let bytes = wat::parse_str(
            r#"(module
                (func (export "evil") nop))"#,
        )
        .unwrap();
        let err = validate_wasm(&bytes).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("evil"));
    }

    #[test]
    fn extract_manifest_section_reads_custom_section() {
        // Construct a tiny wasm with a `bloom_manifest` custom section.
        let bytes = wat::parse_str(
            r#"(module (@custom "bloom_manifest" "{\"hello\":\"world\"}"))"#,
        )
        .unwrap();
        let section = extract_manifest_section(&bytes).unwrap().unwrap();
        assert_eq!(section, b"{\"hello\":\"world\"}");
    }

    #[test]
    fn extract_manifest_section_returns_none_when_absent() {
        let bytes = wat::parse_str("(module)").unwrap();
        let section = extract_manifest_section(&bytes).unwrap();
        assert!(section.is_none());
    }

    #[test]
    fn finalise_manifest_round_trips_through_serde() {
        // Construct a minimal skeleton with the fields the macro emits.
        let skeleton = serde_json::json!({
            "schema_version": 1,
            "contract": { "name": "demo", "domain": "demo", "version": "0.1.0" },
            "abi": { "methods": [] },
            "storage": { "fields": [] },
            "events": [],
            "errors": [],
            "interfaces": [],
            "imports": [],
            "limits": { "max_memory_pages": 0, "max_wasm_bytes": 0 },
            "wasm_hash": "",
            "source_hash": "",
        });
        let bytes = serde_json::to_vec(&skeleton).unwrap();
        let m = finalise_manifest(
            &bytes,
            "aa".repeat(32),
            "bb".repeat(32),
            vec!["chain.state_read".into(), "chain.state_write".into()],
        )
        .unwrap();
        assert_eq!(m.contract.name, "demo");
        assert_eq!(m.wasm_hash, "aa".repeat(32));
        assert_eq!(m.source_hash, "bb".repeat(32));
        assert_eq!(
            m.imports,
            vec!["chain.state_read".to_string(), "chain.state_write".to_string()]
        );
        assert_eq!(m.limits.max_memory_pages, 256);
        assert_eq!(m.limits.max_wasm_bytes, 262_144);
    }

    #[test]
    fn verify_manifest_rejects_mismatched_hash() {
        let wasm = wat::parse_str("(module)").unwrap();
        let manifest = Manifest {
            schema_version: 1,
            contract: bloom_contract_metadata::ContractMeta {
                name: "demo".into(),
                domain: "demo".into(),
                version: "0.1.0".into(),
            },
            abi: Default::default(),
            storage: Default::default(),
            events: vec![],
            errors: vec![],
            imports: vec![],
            limits: Limits::default(),
            wasm_hash: "00".repeat(32),
            source_hash: "11".repeat(32),
        };
        let err = verify_manifest_against_wasm(&manifest, &wasm).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("wasm_hash mismatch"), "got: {msg}");
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let m = Manifest {
            schema_version: 1,
            contract: bloom_contract_metadata::ContractMeta {
                name: "demo".into(),
                domain: "demo".into(),
                version: "0.1.0".into(),
            },
            abi: Default::default(),
            storage: Default::default(),
            events: vec![],
            errors: vec![],
            imports: vec!["chain.state.read".into()],
            limits: Limits::default(),
            wasm_hash: "aa".repeat(32),
            source_hash: "bb".repeat(32),
        };
        let h1 = manifest_hash(&m);
        let h2 = manifest_hash(&m);
        assert_eq!(h1, h2);

        // Changing any field changes the hash.
        let mut m2 = m.clone();
        m2.wasm_hash = "cc".repeat(32);
        assert_ne!(manifest_hash(&m), manifest_hash(&m2));
    }

    #[test]
    fn verify_manifest_accepts_matching_hash() {
        let wasm = wat::parse_str("(module)").unwrap();
        let manifest = Manifest {
            schema_version: 1,
            contract: bloom_contract_metadata::ContractMeta {
                name: "demo".into(),
                domain: "demo".into(),
                version: "0.1.0".into(),
            },
            abi: Default::default(),
            storage: Default::default(),
            events: vec![],
            errors: vec![],
            imports: vec![],
            limits: Limits::default(),
            wasm_hash: hex_encode(&wasm_hash(&wasm)),
            source_hash: "11".repeat(32),
        };
        verify_manifest_against_wasm(&manifest, &wasm).unwrap();
    }
}
