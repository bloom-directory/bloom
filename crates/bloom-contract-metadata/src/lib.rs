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

/// Current manifest schema version. Bump only when adding fields that break
/// backwards compatibility with v1 readers.
pub const SCHEMA_VERSION: u32 = 1;

/// Top-level manifest written next to each `<contract>.wasm`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub contract: ContractMeta,
    pub abi: AbiManifest,
    pub storage: StorageManifest,
    pub events: Vec<EventManifest>,
    pub errors: Vec<ErrorManifest>,
    pub imports: Vec<String>,
    pub limits: Limits,
    /// `blake3(wasm_bytes)`, lowercase hex.
    pub wasm_hash: String,
    /// `blake3(canonical concat of src/**/*.rs)`, lowercase hex.
    pub source_hash: String,
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
    fn schema_version_is_v1() {
        assert_eq!(SCHEMA_VERSION, 1);
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
            abi: AbiManifest::default(),
            storage: StorageManifest::default(),
            events: vec![],
            errors: vec![],
            imports: vec!["chain.state.read".into()],
            limits: Limits::default(),
            wasm_hash: "00".repeat(32),
            source_hash: "11".repeat(32),
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }
}
