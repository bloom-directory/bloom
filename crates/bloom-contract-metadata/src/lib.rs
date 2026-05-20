//! Contract manifest schema.
//!
//! The manifest is the JSON sibling of every compiled contract `.wasm`. It
//! captures the ABI, storage layout, events, errors, host-import allowlist,
//! and resource limits — everything an indexer or block explorer needs to
//! understand a deployed contract without re-running its build.
//!
//! Phase 1 ships the schema skeleton + the version constant; field types are
//! filled in across Phases 2-6 alongside the runtime support that produces
//! them.

use serde::{Deserialize, Serialize};

/// Current manifest schema version. v2 added compiler provenance,
/// preserved interfaces, slot-algorithm metadata per storage field, and
/// signed imports (`ImportEntry` rather than raw `String`).
pub const SCHEMA_VERSION: u32 = 2;

/// Top-level manifest written next to each `<contract>.wasm`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub contract: ContractMeta,
    /// Build-time provenance — rustc version, framework version, target
    /// triple. Filled in by `bloom contract build`; reproducible builds
    /// rely on the same compiler producing the same fields here.
    #[serde(default)]
    pub compiler: CompilerInfo,
    pub abi: AbiManifest,
    pub storage: StorageManifest,
    pub events: Vec<EventManifest>,
    pub errors: Vec<ErrorManifest>,
    /// Cross-contract interfaces the contract claims to implement. Each
    /// entry carries the interface's domain plus the method descriptors
    /// (name, signature, selector) so an indexer can verify by selector
    /// without re-running the macro.
    #[serde(default)]
    pub interfaces: Vec<InterfaceManifest>,
    pub imports: Vec<ImportEntry>,
    pub limits: Limits,
    /// `blake3(wasm_bytes)`, lowercase hex.
    pub wasm_hash: String,
    /// `blake3(canonical concat of src/**/*.rs)`, lowercase hex.
    pub source_hash: String,
}

/// Compiler / framework provenance recorded at build time.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CompilerInfo {
    /// `rustc --version`-style string, e.g. `"rustc 1.85.0 (...)"`.
    pub rustc: String,
    /// `bloom-contract` framework crate version (its `CARGO_PKG_VERSION`).
    pub framework_version: String,
    /// Build target triple — `"wasm32-unknown-unknown"` for petals.
    pub target: String,
}

/// One declared interface preserved in the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceManifest {
    /// Trait identifier as written in the contract source.
    pub name: String,
    /// Canonical ABI domain (`"erc20"` etc.).
    pub domain: String,
    pub methods: Vec<InterfaceMethodEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceMethodEntry {
    pub name: String,
    /// `domain.method(types)`.
    pub signature: String,
    /// Lowercase hex of the 4-byte selector.
    pub selector: String,
}

/// One host import the contract is allowed to use.
///
/// Stored as a structured record so the build crate can verify the wasm's
/// import section exactly matches the manifest's declared signatures, not
/// just the module/name pairs. Signature uses wasm value-type abbreviations
/// (`"(i32 i32) -> (i32)"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportEntry {
    pub module: String,
    pub name: String,
    /// Wasm function signature as a printable string,
    /// e.g. `"(i32 i32 i32) -> (i32)"`. Optional because some entries are
    /// recorded by-name only and resolved against the runtime allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Slot-derivation algorithm version for one storage field. v1 is the
/// blake3 rule documented in the spec; bumping happens when the rule
/// changes (e.g. switching hash function or input ordering).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotAlgo {
    /// Numeric version (1 today).
    pub version: u32,
    /// Symbolic identifier — `"blake3-storage-v1"` for new-rule fields,
    /// `"blake3-compat-v1"` for legacy `compat_tag` fields, `"blake3-map-v1"`
    /// for mappings.
    pub rule: String,
}

impl SlotAlgo {
    pub const STORAGE_V1: &'static str = "blake3-storage-v1";
    pub const COMPAT_V1: &'static str = "blake3-compat-v1";
    pub const MAP_V1: &'static str = "blake3-map-v1";
    pub const MAP_COMPAT_V1: &'static str = "blake3-map-compat-v1";
    pub const VEC_V1: &'static str = "blake3-vec-v1";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractMeta {
    pub name: String,
    pub domain: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AbiManifest {
    pub methods: Vec<MethodManifest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodManifest {
    pub name: String,
    /// Lowercase hex of the 4-byte selector.
    pub selector: String,
    pub inputs: Vec<NamedType>,
    pub outputs: Vec<NamedType>,
    #[serde(default)]
    pub mutability: Mutability,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mutability {
    #[default]
    Mutating,
    View,
    Payable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedType {
    pub name: String,
    pub ty: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StorageManifest {
    pub fields: Vec<StorageField>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageField {
    pub name: String,
    pub ty: String,
    /// Lowercase hex of the 32-byte slot.
    pub slot: String,
    /// `Some("erc20.balance:")` if this field uses the legacy derivation
    /// rule. `None` for new-rule fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compat_tag: Option<String>,
    /// Slot-derivation algorithm for this field. Lets readers handle
    /// future rule bumps explicitly; today every entry is v1.
    #[serde(default = "default_slot_algo")]
    pub slot_algorithm: SlotAlgo,
}

fn default_slot_algo() -> SlotAlgo {
    SlotAlgo { version: 1, rule: SlotAlgo::STORAGE_V1.into() }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventManifest {
    pub name: String,
    /// Lowercase hex of the 32-byte topic-0 (v2) or 4-byte prefix (v1).
    pub topic0: String,
    pub fields: Vec<EventField>,
    /// Per-event metadata version: 1 = 4-byte-padded topic, 2 = 32-byte topic.
    #[serde(default = "default_event_version")]
    pub version: u32,
}

fn default_event_version() -> u32 {
    1
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventField {
    pub name: String,
    pub ty: String,
    #[serde(default)]
    pub indexed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorManifest {
    pub name: String,
    /// Lowercase hex of the 4-byte selector.
    pub selector: String,
    pub payload: Vec<NamedType>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_memory_pages: u32,
    pub max_wasm_bytes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_memory_pages: 256, max_wasm_bytes: 262_144 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_v2() {
        assert_eq!(SCHEMA_VERSION, 2);
    }

    #[test]
    fn default_limits_match_spec() {
        let l = Limits::default();
        assert_eq!(l.max_memory_pages, 256);
        assert_eq!(l.max_wasm_bytes, 262_144);
    }

    #[test]
    fn manifest_roundtrips_json() {
        let m = Manifest {
            schema_version: SCHEMA_VERSION,
            contract: ContractMeta {
                name: "Erc20".into(),
                domain: "erc20".into(),
                version: "0.1.0".into(),
            },
            compiler: CompilerInfo {
                rustc: "rustc 1.85.0 (test)".into(),
                framework_version: "0.1.0".into(),
                target: "wasm32-unknown-unknown".into(),
            },
            abi: AbiManifest::default(),
            storage: StorageManifest::default(),
            events: vec![],
            errors: vec![],
            interfaces: vec![InterfaceManifest {
                name: "Erc20".into(),
                domain: "erc20".into(),
                methods: vec![InterfaceMethodEntry {
                    name: "balance_of".into(),
                    signature: "erc20.balance_of(address)".into(),
                    selector: "deadbeef".into(),
                }],
            }],
            imports: vec![ImportEntry {
                module: "chain.state".into(),
                name: "read".into(),
                signature: Some("(i32 i32) -> (i32)".into()),
            }],
            limits: Limits::default(),
            wasm_hash: "00".repeat(32),
            source_hash: "11".repeat(32),
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn v1_manifest_decodes_with_defaults() {
        // Old-shape manifest without compiler/interfaces/slot_algorithm/
        // structured imports must still parse — serde defaults fill the
        // gaps and importers keep working across the v1→v2 cutover.
        let raw = r#"{
            "schema_version": 1,
            "contract": { "name": "Old", "domain": "old", "version": "0.1.0" },
            "abi": { "methods": [] },
            "storage": { "fields": [] },
            "events": [],
            "errors": [],
            "imports": [],
            "limits": { "max_memory_pages": 256, "max_wasm_bytes": 262144 },
            "wasm_hash": "",
            "source_hash": ""
        }"#;
        let m: Manifest = serde_json::from_str(raw).expect("v1 manifest parses");
        assert_eq!(m.compiler, CompilerInfo::default());
        assert!(m.interfaces.is_empty());
    }
}
