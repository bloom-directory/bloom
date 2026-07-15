//! Per-petal metadata persisted next to the object.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Capabilities a petal can request. Default is deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// May call `vfs_read`.
    #[serde(rename = "vfs.read")]
    VfsRead,
    /// May call `vfs_write`.
    #[serde(rename = "vfs.write")]
    VfsWrite,
    /// May call `http_fetch`.
    #[serde(rename = "net.fetch")]
    NetFetch,
    /// May call `sign_hash`.
    #[serde(rename = "sign")]
    Sign,
    /// May call `store_*`.
    #[serde(rename = "store")]
    Store,
    /// May perform mediated chain reads.
    #[serde(rename = "chain")]
    Chain,
    /// May stage and confirm generic EVM outbox entries.
    #[serde(rename = "tx.outbox")]
    TxOutbox,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::VfsRead => "vfs.read",
            Capability::VfsWrite => "vfs.write",
            Capability::NetFetch => "net.fetch",
            Capability::Sign => "sign",
            Capability::Store => "store",
            Capability::Chain => "chain",
            Capability::TxOutbox => "tx.outbox",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "vfs.read" => Some(Capability::VfsRead),
            "vfs.write" => Some(Capability::VfsWrite),
            "net.fetch" => Some(Capability::NetFetch),
            "sign" => Some(Capability::Sign),
            "store" => Some(Capability::Store),
            "chain" => Some(Capability::Chain),
            "tx.outbox" => Some(Capability::TxOutbox),
            _ => None,
        }
    }
}

/// What execution surface a petal targets. Drives which host imports
/// the VM links and which WASI capabilities the ctx exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PetalMode {
    #[default]
    Local,
}

impl PetalMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PetalMode::Local => "local",
        }
    }
}

impl std::fmt::Display for PetalMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetalMeta {
    pub hash: String,
    pub size: u64,
    pub installed_at_ms: u64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub caps: BTreeSet<Capability>,
    #[serde(default)]
    pub mode: PetalMode,
    #[serde(default)]
    pub petal: Option<PetalPackageMeta>,
    #[serde(default)]
    pub source: Option<PetalSourceProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetalPackageMeta {
    pub name: String,
    pub petal_root: String,
    pub route_index_schema: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetalSourceProvenance {
    pub source_kind: String,
    pub url: String,
    pub owner: String,
    pub repo: String,
    pub requested_ref: String,
    pub resolved_commit: String,
    #[serde(default)]
    pub selected_tag: Option<String>,
    pub package_hash: String,
}

impl PetalMeta {
    pub fn has_cap(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }

    pub fn mode_str(&self) -> &'static str {
        self.mode.as_str()
    }
}

/// Validate that a (mode, caps) pair is allowed at install time.
///
/// - `Local` may declare `{vfs.read, vfs.write, net.fetch, sign, store, chain}`.
///
/// Returns `Err` on the first offending capability; the remaining caps
/// are not inspected.
pub fn validate_mode_caps(
    mode: PetalMode,
    caps: &BTreeSet<Capability>,
) -> Result<(), crate::error::PetalError> {
    for cap in caps {
        let ok = matches!(
            (mode, *cap),
            (
                PetalMode::Local,
                Capability::VfsRead
                    | Capability::VfsWrite
                    | Capability::NetFetch
                    | Capability::Sign
                    | Capability::Store
                    | Capability::Chain
                    | Capability::TxOutbox
            )
        );
        if !ok {
            return Err(crate::error::PetalError::ModeCapMismatch {
                mode,
                cap: cap.as_str().to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_string_roundtrip() {
        assert_eq!(Capability::VfsRead.as_str(), "vfs.read");
        assert_eq!(Capability::VfsWrite.as_str(), "vfs.write");
        assert_eq!(Capability::NetFetch.as_str(), "net.fetch");
        assert_eq!(Capability::Sign.as_str(), "sign");
        assert_eq!(Capability::Store.as_str(), "store");
        assert_eq!(Capability::Chain.as_str(), "chain");
        assert_eq!(Capability::TxOutbox.as_str(), "tx.outbox");
        assert_eq!(Capability::parse("vfs.read"), Some(Capability::VfsRead));
        assert_eq!(Capability::parse("vfs.write"), Some(Capability::VfsWrite));
        assert_eq!(Capability::parse("net.fetch"), Some(Capability::NetFetch));
        assert_eq!(Capability::parse("sign"), Some(Capability::Sign));
        assert_eq!(Capability::parse("store"), Some(Capability::Store));
        assert_eq!(Capability::parse("chain"), Some(Capability::Chain));
        assert_eq!(Capability::parse("tx.outbox"), Some(Capability::TxOutbox));
        assert_eq!(Capability::parse("nope"), None);
    }

    #[test]
    fn meta_serde_roundtrip_with_caps() {
        let mut caps = BTreeSet::new();
        caps.insert(Capability::VfsRead);
        let m = PetalMeta {
            hash: "abc".into(),
            size: 42,
            installed_at_ms: 1_000,
            name: Some("hello".into()),
            caps,
            mode: PetalMode::default(),
            petal: None,
            source: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        let m2: PetalMeta = serde_json::from_str(&s).unwrap();
        assert_eq!(m2.hash, "abc");
        assert_eq!(m2.size, 42);
        assert_eq!(m2.name.as_deref(), Some("hello"));
        assert!(
            m2.has_cap(Capability::VfsRead),
            "VfsRead cap should survive roundtrip"
        );
        assert!(
            !m2.has_cap(Capability::VfsWrite),
            "VfsWrite should not be present"
        );
        assert_eq!(
            m2.mode,
            PetalMode::Local,
            "default mode should roundtrip as Local"
        );
    }

    #[test]
    fn meta_serde_defaults_empty_caps_and_no_name() {
        let s = r#"{"hash":"x","size":1,"installed_at_ms":2}"#;
        let m: PetalMeta = serde_json::from_str(s).unwrap();
        assert!(m.name.is_none(), "name should default to None");
        assert!(m.caps.is_empty(), "caps should default to empty");
    }

    #[test]
    fn petal_mode_serde_roundtrips_as_lowercase() {
        assert_eq!(
            serde_json::to_string(&PetalMode::Local).unwrap(),
            "\"local\""
        );
        let m: PetalMode = serde_json::from_str("\"local\"").unwrap();
        assert_eq!(m, PetalMode::Local);
    }

    #[test]
    fn meta_serde_defaults_mode_to_local_when_missing() {
        let s = r#"{"hash":"x","size":1,"installed_at_ms":2}"#;
        let m: PetalMeta = serde_json::from_str(s).unwrap();
        assert_eq!(m.mode, PetalMode::Local);
    }

    #[test]
    fn validate_mode_caps_matrix() {
        let empty = BTreeSet::new();
        assert!(
            validate_mode_caps(PetalMode::Local, &empty).is_ok(),
            "Local + {{}} should be ok"
        );

        let mut vfs_read = BTreeSet::new();
        vfs_read.insert(Capability::VfsRead);
        assert!(
            validate_mode_caps(PetalMode::Local, &vfs_read).is_ok(),
            "Local + {{vfs.read}} should be ok"
        );

        let mut chain = BTreeSet::new();
        chain.insert(Capability::Chain);
        assert!(
            validate_mode_caps(PetalMode::Local, &chain).is_ok(),
            "Local + {{chain}} should be ok"
        );

        let mut tx_outbox = BTreeSet::new();
        tx_outbox.insert(Capability::TxOutbox);
        assert!(
            validate_mode_caps(PetalMode::Local, &tx_outbox).is_ok(),
            "Local + {{tx.outbox}} should be ok"
        );
    }
}
