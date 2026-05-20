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

use bloom_contract_metadata::{
    CompilerInfo, ImportEntry, InterfaceManifest, Limits, Manifest, SCHEMA_VERSION, SlotAlgo,
};
use thiserror::Error;
use wasmparser::{ExternalKind, Parser, Payload, TypeRef, ValType};

pub mod petals_lock;

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
    /// Structured imports: `(module, name, signature)`. Signature is the
    /// wasm function type formatted as `"(param tys) -> (result tys)"`,
    /// or `None` for non-function imports (memories, tables, globals).
    pub imports: Vec<ImportEntry>,
    /// Interface metadata records extracted from the `bloom_interfaces`
    /// custom section, if any. Each `#[bloom::interface]` declaration
    /// emits one record there at link time so the build crate can
    /// preserve the full method list in the manifest without re-running
    /// the macro.
    pub interface_records: Vec<InterfaceManifest>,
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
    let mut types: Vec<String> = Vec::new();
    let mut imports: Vec<ImportEntry> = Vec::new();
    let mut interface_records: Vec<InterfaceManifest> = Vec::new();
    let parser = Parser::new(0);
    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| BuildError::Validation(e.to_string()))?;
        match payload {
            Payload::TypeSection(reader) => {
                for rec in reader.into_iter_err_on_gc_types() {
                    let func = rec.map_err(|e| BuildError::Validation(e.to_string()))?;
                    types.push(format_func_type(&func));
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| BuildError::Validation(e.to_string()))?;
                    if import.module != "chain" {
                        return Err(BuildError::Validation(format!(
                            "disallowed import: '{}.{}' (only `chain.*` host imports are permitted)",
                            import.module, import.name
                        )));
                    }
                    let signature = match import.ty {
                        TypeRef::Func(idx) => types.get(idx as usize).cloned(),
                        _ => None,
                    };
                    imports.push(ImportEntry {
                        module: import.module.into(),
                        name: import.name.into(),
                        signature,
                    });
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
            Payload::CustomSection(reader) if reader.name() == "bloom_interfaces" => {
                interface_records = parse_interface_records(reader.data())
                    .map_err(|e| BuildError::Manifest(format!("bloom_interfaces: {e}")))?;
            }
            _ => {}
        }
    }
    Ok(WasmInspection { imports, interface_records })
}

/// Render a wasm function type as `"(param_tys) -> (result_tys)"`.
fn format_func_type(ft: &wasmparser::FuncType) -> String {
    let mut s = String::new();
    s.push('(');
    let mut first = true;
    for p in ft.params() {
        if !first {
            s.push(' ');
        }
        first = false;
        s.push_str(val_type_str(p));
    }
    s.push_str(") -> (");
    let mut first = true;
    for r in ft.results() {
        if !first {
            s.push(' ');
        }
        first = false;
        s.push_str(val_type_str(r));
    }
    s.push(')');
    s
}

fn val_type_str(v: &ValType) -> &'static str {
    match v {
        ValType::I32 => "i32",
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
        ValType::V128 => "v128",
        ValType::Ref(_) => "ref",
    }
}

/// Decode a length-prefixed list of JSON `InterfaceManifest` records.
///
/// Wire form per record: `<u16-le len>` followed by `len` JSON bytes.
/// `#[bloom::interface]` emits one such record per trait declaration via
/// a `#[link_section = "bloom_interfaces"]` static; multiple records get
/// concatenated by the linker.
fn parse_interface_records(data: &[u8]) -> Result<Vec<InterfaceManifest>, String> {
    let mut out: Vec<InterfaceManifest> = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if i + 2 > data.len() {
            return Err(format!("truncated length prefix at offset {i}"));
        }
        let len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        i += 2;
        if i + len > data.len() {
            return Err(format!(
                "truncated record at offset {} (len {}, remaining {})",
                i - 2,
                len,
                data.len() - i
            ));
        }
        let rec_bytes = &data[i..i + len];
        let rec: InterfaceManifest =
            serde_json::from_slice(rec_bytes).map_err(|e| format!("decode record: {e}"))?;
        out.push(rec);
        i += len;
    }
    Ok(out)
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

/// Read every `InterfaceManifest` record embedded in `bloom_interfaces`.
///
/// Unlike [`validate_wasm`], this performs no determinism checks — just
/// walks the wasm for the one custom section. Client-codegen tooling
/// runs in less-constrained host contexts where the binary may already
/// have been validated upstream.
pub fn extract_interface_records(bytes: &[u8]) -> Result<Vec<InterfaceManifest>, BuildError> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| BuildError::Manifest(e.to_string()))?;
        if let Payload::CustomSection(reader) = payload {
            if reader.name() == "bloom_interfaces" {
                return parse_interface_records(reader.data())
                    .map_err(|e| BuildError::Manifest(format!("bloom_interfaces: {e}")));
            }
        }
    }
    Ok(Vec::new())
}

// ===========================================================================
// Manifest finalisation
// ===========================================================================

/// Decode the embedded manifest skeleton and fold in the runtime-derived
/// fields:
///
/// - `wasm_hash` / `source_hash` come from the freshly-built artifact.
/// - `imports` is the structured `(module, name, signature)` triple the
///   wasm actually links — exact import verification means the build
///   crate, not the macro, owns this field.
/// - `interfaces` are the records the `#[bloom::interface]` macro embeds
///   in the `bloom_interfaces` custom section; the contract macro emits
///   only their names in the skeleton, and we resolve them to full
///   `InterfaceManifest` records here so the manifest carries the
///   complete method list.
/// - `compiler` is `rustc --version` + framework version + target triple
///   gathered by `emit_artifacts`.
///
/// Schema-version is forced to the current `SCHEMA_VERSION` so older
/// macro skeletons (still emitting v1) are normalised on the way out.
pub fn finalise_manifest(
    skeleton: &[u8],
    wasm_hash_hex: String,
    source_hash_hex: String,
    imports: Vec<ImportEntry>,
    interface_records: Vec<InterfaceManifest>,
    compiler: CompilerInfo,
) -> Result<Manifest, BuildError> {
    // The skeleton carries extra keys the on-disk schema doesn't model
    // (`signature` on events/errors, `kind` object on storage fields).
    // Decode via `serde_json::Value` first so we can normalise before
    // handing to `serde_json::from_value`.
    let mut value: serde_json::Value = serde_json::from_slice(skeleton)
        .map_err(|e| BuildError::Manifest(format!("skeleton JSON: {e}")))?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| BuildError::Manifest("skeleton root is not an object".into()))?;

    obj.insert(
        "schema_version".into(),
        serde_json::Value::Number(SCHEMA_VERSION.into()),
    );
    obj.insert("wasm_hash".into(), serde_json::Value::String(wasm_hash_hex));
    obj.insert("source_hash".into(), serde_json::Value::String(source_hash_hex));
    obj.insert(
        "imports".into(),
        serde_json::to_value(&imports).map_err(|e| BuildError::Manifest(e.to_string()))?,
    );
    obj.insert(
        "compiler".into(),
        serde_json::to_value(&compiler).map_err(|e| BuildError::Manifest(e.to_string()))?,
    );

    // Resolve declared interface names to the full records emitted by
    // `#[bloom::interface]` (carrying domain + method descriptors). The
    // skeleton lists only names — the build crate is the only stage that
    // sees the wasm custom section.
    let declared_names = take_interface_names(obj);
    let resolved = resolve_interfaces(&declared_names, &interface_records)?;
    obj.insert(
        "interfaces".into(),
        serde_json::to_value(&resolved).map_err(|e| BuildError::Manifest(e.to_string()))?,
    );

    if let Some(storage) = obj.get_mut("storage").and_then(|v| v.as_object_mut()) {
        if let Some(fields) = storage.get_mut("fields").and_then(|v| v.as_array_mut()) {
            for entry in fields {
                normalise_storage_field(entry)?;
            }
        }
    }

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

/// Extract the skeleton's `interfaces: [name, ...]` array, leaving the
/// key absent so the structured replacement can be inserted by the
/// caller. Tolerates missing/empty/non-string entries — anything the
/// macro can't supply at expansion time is simply skipped.
fn take_interface_names(obj: &mut serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let raw = obj.remove("interfaces");
    let arr = match raw {
        Some(serde_json::Value::Array(a)) => a,
        _ => return Vec::new(),
    };
    arr.into_iter()
        .filter_map(|v| match v {
            serde_json::Value::String(s) => Some(s),
            _ => None,
        })
        .collect()
}

/// Match the contract's declared interfaces against the records the
/// `#[bloom::interface]` macro embedded in the wasm. Order follows the
/// declaration order; missing records are an error — the build crate
/// can't synthesise method descriptors on its own.
fn resolve_interfaces(
    declared: &[String],
    records: &[InterfaceManifest],
) -> Result<Vec<InterfaceManifest>, BuildError> {
    let mut out = Vec::with_capacity(declared.len());
    for name in declared {
        let rec = records.iter().find(|r| &r.name == name).ok_or_else(|| {
            BuildError::Manifest(format!(
                "interface `{name}` declared by contract but no `bloom_interfaces` record found"
            ))
        })?;
        out.push(rec.clone());
    }
    Ok(out)
}

/// Convert macro-emitted storage entries (`kind: {kind, ty, key_ty, ...}`)
/// to the on-disk shape (`ty: "<canonical>"`, `slot_algorithm: SlotAlgo`).
///
/// We compute `slot_algorithm` from the macro-emitted hints when present
/// (`kind.kind == "map"` ⇒ `blake3-map-v1`, `compat_tag` ⇒
/// `blake3-compat-v1`, etc.) and default the rest to `blake3-storage-v1`.
fn normalise_storage_field(entry: &mut serde_json::Value) -> Result<(), BuildError> {
    let obj = entry.as_object_mut().ok_or_else(|| {
        BuildError::Manifest("storage field entry is not an object".into())
    })?;

    let has_compat = obj.contains_key("compat_tag");
    let kind = obj.remove("kind");

    let (ty_string, algo) = match kind {
        Some(serde_json::Value::Object(k)) => {
            let kind_tag = k.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let algo = match (kind_tag, has_compat) {
                ("map", true) => SlotAlgo::MAP_COMPAT_V1,
                ("map", false) => SlotAlgo::MAP_V1,
                ("vec", _) => SlotAlgo::VEC_V1,
                (_, true) => SlotAlgo::COMPAT_V1,
                _ => SlotAlgo::STORAGE_V1,
            };
            let ty = match kind_tag {
                "scalar" => k
                    .get("ty")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                "map" => format!(
                    "map<{},{}>",
                    k.get("key_ty").and_then(|v| v.as_str()).unwrap_or("?"),
                    k.get("value_ty").and_then(|v| v.as_str()).unwrap_or("?"),
                ),
                "vec" => format!(
                    "vec<{}>",
                    k.get("ty").and_then(|v| v.as_str()).unwrap_or("?"),
                ),
                _ => k
                    .get("ty")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
            };
            (ty, algo)
        }
        // Macro already emitted the canonical shape (`ty: String`).
        _ => {
            let existing = obj
                .get("ty")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let algo = if has_compat { SlotAlgo::COMPAT_V1 } else { SlotAlgo::STORAGE_V1 };
            (existing, algo)
        }
    };

    obj.insert("ty".into(), serde_json::Value::String(ty_string));
    if !obj.contains_key("slot_algorithm") {
        obj.insert(
            "slot_algorithm".into(),
            serde_json::json!({ "version": 1, "rule": algo }),
        );
    }
    Ok(())
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
        let declared = manifest
            .imports
            .iter()
            .find(|m| m.module == live.module && m.name == live.name);
        let declared = match declared {
            Some(d) => d,
            None => {
                return Err(BuildError::Manifest(format!(
                    "wasm imports `{}.{}` but manifest does not declare it",
                    live.module, live.name
                )));
            }
        };
        // If the manifest pins a signature, the wasm must match it. A
        // missing signature on either side is treated as a wildcard — older
        // (v1) manifests didn't capture this field at all.
        if let (Some(want), Some(got)) = (&declared.signature, &live.signature) {
            if want != got {
                return Err(BuildError::Manifest(format!(
                    "import `{}.{}` signature mismatch: manifest={} wasm={}",
                    live.module, live.name, want, got
                )));
            }
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
        inspection.interface_records,
        detect_compiler_info(),
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
// Compiler provenance
// ===========================================================================

/// Gather build-time provenance for the manifest's `compiler` block.
///
/// `rustc` is detected by running `rustc --version` (trimmed); failure
/// falls back to an empty string rather than aborting the build — the
/// build can succeed without provenance, the manifest just records less.
/// `framework_version` is this crate's `CARGO_PKG_VERSION`, which moves
/// in lockstep with `bloom-contract` since they share a workspace
/// `[package].version`. `target` is fixed at `wasm32-unknown-unknown`
/// because the build pipeline only emits petals.
fn detect_compiler_info() -> CompilerInfo {
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    CompilerInfo {
        rustc,
        framework_version: env!("CARGO_PKG_VERSION").to_string(),
        target: "wasm32-unknown-unknown".to_string(),
    }
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
        assert_eq!(insp.imports.len(), 1);
        assert_eq!(insp.imports[0].module, "chain");
        assert_eq!(insp.imports[0].name, "state_read");
        // Function signature is recorded so the manifest can verify it.
        assert_eq!(
            insp.imports[0].signature.as_deref(),
            Some("(i32 i32 i32) -> ()"),
        );
    }

    #[test]
    fn validate_wasm_extracts_interface_records() {
        // Wire form: <u16-le len><JSON> per record, concatenated.
        let rec1 =
            r#"{"name":"Erc20","domain":"erc20","methods":[]}"#;
        let mut blob = Vec::new();
        blob.extend_from_slice(&(rec1.len() as u16).to_le_bytes());
        blob.extend_from_slice(rec1.as_bytes());
        // `(@custom)` in wat doesn't take binary, but it does take a
        // string with escapes — encode raw bytes via \xx escapes.
        let mut wat = String::from("(module (@custom \"bloom_interfaces\" \"");
        for b in &blob {
            wat.push_str(&format!("\\{:02x}", b));
        }
        wat.push_str("\"))");
        let bytes = wat::parse_str(&wat).unwrap();
        let insp = validate_wasm(&bytes).unwrap();
        assert_eq!(insp.interface_records.len(), 1);
        assert_eq!(insp.interface_records[0].name, "Erc20");
        assert_eq!(insp.interface_records[0].domain, "erc20");
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
        // Skeleton mirrors what `#[bloom::contract]` emits — note the
        // legacy storage `kind: {kind, ty}` shape; `finalise_manifest`
        // normalises it to the on-disk `ty: String` form.
        let skeleton = serde_json::json!({
            "schema_version": 1,
            "contract": { "name": "demo", "domain": "demo", "version": "0.1.0" },
            "abi": { "methods": [] },
            "storage": {
                "fields": [
                    { "name": "owner", "kind": { "kind": "scalar", "ty": "address" }, "slot": "00".repeat(32) },
                    {
                        "name": "balances",
                        "kind": { "kind": "map", "key_ty": "address", "value_ty": "u256" },
                        "slot": "00".repeat(32),
                    },
                ]
            },
            "events": [],
            "errors": [],
            "interfaces": ["Erc20"],
            "imports": [],
            "limits": { "max_memory_pages": 0, "max_wasm_bytes": 0 },
            "wasm_hash": "",
            "source_hash": "",
        });
        let bytes = serde_json::to_vec(&skeleton).unwrap();
        let imports = vec![
            ImportEntry {
                module: "chain".into(),
                name: "state_read".into(),
                signature: Some("(i32 i32) -> (i32)".into()),
            },
            ImportEntry {
                module: "chain".into(),
                name: "state_write".into(),
                signature: None,
            },
        ];
        let records = vec![InterfaceManifest {
            name: "Erc20".into(),
            domain: "erc20".into(),
            methods: vec![],
        }];
        let compiler = CompilerInfo {
            rustc: "rustc test".into(),
            framework_version: "0.1.0".into(),
            target: "wasm32-unknown-unknown".into(),
        };
        let m = finalise_manifest(
            &bytes,
            "aa".repeat(32),
            "bb".repeat(32),
            imports.clone(),
            records.clone(),
            compiler.clone(),
        )
        .unwrap();
        assert_eq!(m.schema_version, SCHEMA_VERSION);
        assert_eq!(m.contract.name, "demo");
        assert_eq!(m.wasm_hash, "aa".repeat(32));
        assert_eq!(m.source_hash, "bb".repeat(32));
        assert_eq!(m.imports, imports);
        assert_eq!(m.interfaces, records);
        assert_eq!(m.compiler, compiler);
        // Storage normalisation: scalar → ty, map → ty + map-v1 algo.
        assert_eq!(m.storage.fields[0].ty, "address");
        assert_eq!(m.storage.fields[0].slot_algorithm.rule, SlotAlgo::STORAGE_V1);
        assert_eq!(m.storage.fields[1].ty, "map<address,u256>");
        assert_eq!(m.storage.fields[1].slot_algorithm.rule, SlotAlgo::MAP_V1);
        assert_eq!(m.limits.max_memory_pages, 256);
        assert_eq!(m.limits.max_wasm_bytes, 262_144);
    }

    #[test]
    fn finalise_manifest_errors_on_unresolved_interface() {
        let skeleton = serde_json::json!({
            "schema_version": 1,
            "contract": { "name": "demo", "domain": "demo", "version": "0.1.0" },
            "abi": { "methods": [] },
            "storage": { "fields": [] },
            "events": [],
            "errors": [],
            "interfaces": ["Erc20"],
            "imports": [],
            "limits": { "max_memory_pages": 0, "max_wasm_bytes": 0 },
            "wasm_hash": "",
            "source_hash": "",
        });
        let bytes = serde_json::to_vec(&skeleton).unwrap();
        let err = finalise_manifest(
            &bytes,
            "aa".repeat(32),
            "bb".repeat(32),
            vec![],
            vec![],
            CompilerInfo::default(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Erc20"), "got: {msg}");
    }

    #[test]
    fn verify_manifest_rejects_mismatched_hash() {
        let wasm = wat::parse_str("(module)").unwrap();
        let manifest = demo_manifest("00".repeat(32), "11".repeat(32));
        let err = verify_manifest_against_wasm(&manifest, &wasm).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("wasm_hash mismatch"), "got: {msg}");
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let mut m = demo_manifest("aa".repeat(32), "bb".repeat(32));
        m.imports = vec![ImportEntry {
            module: "chain".into(),
            name: "state_read".into(),
            signature: None,
        }];
        let h1 = manifest_hash(&m);
        let h2 = manifest_hash(&m);
        assert_eq!(h1, h2);

        let mut m2 = m.clone();
        m2.wasm_hash = "cc".repeat(32);
        assert_ne!(manifest_hash(&m), manifest_hash(&m2));
    }

    #[test]
    fn verify_manifest_accepts_matching_hash() {
        let wasm = wat::parse_str("(module)").unwrap();
        let manifest = demo_manifest(hex_encode(&wasm_hash(&wasm)), "11".repeat(32));
        verify_manifest_against_wasm(&manifest, &wasm).unwrap();
    }

    #[test]
    fn verify_manifest_flags_signature_drift() {
        let wasm = wat::parse_str(
            r#"(module
                (import "chain" "state_read" (func (param i32 i32 i32))))"#,
        )
        .unwrap();
        let mut manifest = demo_manifest(hex_encode(&wasm_hash(&wasm)), "11".repeat(32));
        manifest.imports = vec![ImportEntry {
            module: "chain".into(),
            name: "state_read".into(),
            // Drift: wasm has 3-arg signature, manifest claims 2-arg.
            signature: Some("(i32 i32) -> (i32)".into()),
        }];
        let err = verify_manifest_against_wasm(&manifest, &wasm).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("signature mismatch"), "got: {msg}");
    }

    fn demo_manifest(wasm_hash_hex: String, source_hash_hex: String) -> Manifest {
        Manifest {
            schema_version: SCHEMA_VERSION,
            contract: bloom_contract_metadata::ContractMeta {
                name: "demo".into(),
                domain: "demo".into(),
                version: "0.1.0".into(),
            },
            compiler: CompilerInfo::default(),
            abi: Default::default(),
            storage: Default::default(),
            events: vec![],
            errors: vec![],
            interfaces: vec![],
            imports: vec![],
            limits: Limits::default(),
            wasm_hash: wasm_hash_hex,
            source_hash: source_hash_hex,
        }
    }
}
