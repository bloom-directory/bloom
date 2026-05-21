//! `petals.lock` — Cargo.lock-shaped pin file for cross-petal type
//! references (spec §13.2).
//!
//! # Phase 1 surface
//!
//! Phase 1 of the Bloom-native contracts framework introduces the data
//! types and load/write/resolve plumbing for `petals.lock` but does not
//! yet hook them into the existing `emit_artifacts` pipeline (the
//! legacy `bloom-contract*` macros do not emit `external_type_refs`).
//! Phase 2 calls into [`resolve_external_type_refs`] from the
//! new-framework manifest pipeline to substitute placeholder content
//! hashes before the manifest section is written.
//!
//! # File format (spec §13.2)
//!
//! ```toml
//! [[petal]]
//! path = "/bloom/core/fungible"
//! content_hash = "blake3:abcd...1234"
//! manifest_blake3 = "blake3:ef01...beef"
//! emitted_by = "bloom-petal-fungible 0.1.0"
//!
//! [[petal]]
//! path = "/bloom/dex/pool"
//! content_hash = "..."
//! depends_on = ["/bloom/core/fungible", "/bloom/core/cap"]
//! ```
//!
//! Hashes are stored in human-friendly `"blake3:<hex>"` form on disk
//! and decoded into 32-byte arrays by [`PetalsLockEntry`].
//!
//! # Fail-closed semantics
//!
//! Per spec §17 verification item #13, `bloom contract build` must fail
//! when a cross-petal type reference is missing from the lock.
//! [`resolve_external_type_refs`] enforces this by returning
//! `Err(PetalsLockError::Unresolved(path))` for any unknown petal path.
//! Callers must propagate this error instead of degrading silently.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Canonical file name of the lock at the workspace root.
pub const PETALS_LOCK_FILE_NAME: &str = "petals.lock";

/// Prefix for the on-disk `content_hash` / `manifest_blake3` strings.
///
/// `"blake3:"` keeps the format self-describing in case a future version
/// of the framework wants to add additional hash kinds; for now blake3
/// is the only accepted algorithm.
pub const HASH_PREFIX: &str = "blake3:";

#[derive(Debug, thiserror::Error)]
pub enum PetalsLockError {
    #[error("io error reading petals.lock: {0}")]
    Io(#[from] std::io::Error),
    #[error("petals.lock parse error: {0}")]
    Parse(String),
    #[error("petals.lock serialize error: {0}")]
    Serialize(String),
    #[error(
        "cross-petal type reference for `{0}` could not be resolved against petals.lock \
         (fail-closed; see spec §13.2)"
    )]
    Unresolved(String),
    #[error("duplicate petal path in lock: {0}")]
    Duplicate(String),
    #[error("malformed hash field for petal `{path}`: {msg}")]
    BadHash { path: String, msg: String },
}

// ---------------------------------------------------------------------------
// On-disk model
// ---------------------------------------------------------------------------

/// A single pinned petal entry on disk.
///
/// `content_hash` / `manifest_blake3` are serialised in the
/// `"blake3:<64 hex chars>"` form for readability. Use
/// [`PetalsLockEntry::content_hash_bytes`] /
/// [`PetalsLockEntry::manifest_hash_bytes`] to obtain the 32-byte raw
/// arrays used downstream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetalsLockEntry {
    /// Canonical petal path in the registry, e.g. `/bloom/core/fungible`.
    /// Used as the primary key; spec §13.2 calls this `path`.
    pub path: String,
    /// `blake3:<hex>` content hash of the petal's canonical wasm bytes.
    /// This is the value substituted into a referring petal's manifest
    /// when its `external_type_refs` are resolved.
    pub content_hash: String,
    /// `blake3:<hex>` manifest hash. Optional only for backward
    /// compatibility with hand-edited lock files; the build tool always
    /// fills it in on `write`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_blake3: Option<String>,
    /// Human-readable `crate-name version` string that produced this
    /// entry. Informational only — the build pipeline does not
    /// authenticate this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emitted_by: Option<String>,
    /// Other petals this one references via `external_type_refs`.
    ///
    /// Stored so a future `bloom contract update` can do topo-order
    /// rebuilds. Phase 1 only reads it for round-trip integrity tests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

impl PetalsLockEntry {
    /// Decode the `content_hash` field as a 32-byte BLAKE3 digest.
    pub fn content_hash_bytes(&self) -> Result<[u8; 32], PetalsLockError> {
        decode_blake3_field(&self.path, "content_hash", &self.content_hash)
    }

    /// Decode the `manifest_blake3` field as a 32-byte BLAKE3 digest.
    /// Returns `Ok(None)` if the field is absent (older hand-edited
    /// locks may omit it; the build tool always writes it).
    pub fn manifest_hash_bytes(&self) -> Result<Option<[u8; 32]>, PetalsLockError> {
        match &self.manifest_blake3 {
            Some(s) => Ok(Some(decode_blake3_field(&self.path, "manifest_blake3", s)?)),
            None => Ok(None),
        }
    }
}

/// In-memory representation of the entire lock file.
///
/// The on-disk TOML uses the array-of-tables shape `[[petal]] ... `,
/// so the wire format is a wrapper around `Vec<PetalsLockEntry>` with
/// field name `petal`. The in-memory form additionally indexes entries
/// by path for `O(log n)` lookups.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PetalsLockFile {
    /// Entries keyed by petal path. Insertion-ordered serialisation
    /// would require an extra container; `BTreeMap` keeps writes
    /// deterministic across builds (BTreeMap ordering is stable).
    pub entries: BTreeMap<String, PetalsLockEntry>,
}

impl PetalsLockFile {
    /// Construct an empty lock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an entry. Returns `Err(Duplicate)` if `path` was already
    /// present.
    pub fn insert(&mut self, entry: PetalsLockEntry) -> Result<(), PetalsLockError> {
        let path = entry.path.clone();
        if self.entries.contains_key(&path) {
            return Err(PetalsLockError::Duplicate(path));
        }
        self.entries.insert(path, entry);
        Ok(())
    }

    /// Look up an entry by canonical petal path.
    pub fn get(&self, path: &str) -> Option<&PetalsLockEntry> {
        self.entries.get(path)
    }

    /// Iterate over entries in deterministic (path-sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = &PetalsLockEntry> {
        self.entries.values()
    }

    /// Parse a `petals.lock` TOML body.
    pub fn from_toml_str(text: &str) -> Result<Self, PetalsLockError> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            petal: Vec<PetalsLockEntry>,
        }
        let wire: Wire = toml::from_str(text).map_err(|e| PetalsLockError::Parse(e.to_string()))?;
        let mut file = PetalsLockFile::new();
        for entry in wire.petal {
            file.insert(entry)?;
        }
        Ok(file)
    }

    /// Serialise to a deterministic TOML body.
    ///
    /// Entries are emitted in path-sorted order so a build that doesn't
    /// change the dep graph produces a byte-identical lock file.
    pub fn to_toml_string(&self) -> Result<String, PetalsLockError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            petal: Vec<&'a PetalsLockEntry>,
        }
        let wire = Wire {
            petal: self.entries.values().collect(),
        };
        toml::to_string(&wire).map_err(|e| PetalsLockError::Serialize(e.to_string()))
    }

    /// Load `petals.lock` from the workspace root.
    ///
    /// Returns an empty lock if the file does not exist — Phase 1 is
    /// tolerant of missing locks (no new-framework petals are built
    /// yet). [`resolve_external_type_refs`] re-imposes fail-closed
    /// semantics when an actual reference cannot be resolved.
    pub fn load(workspace_root: &Path) -> Result<Self, PetalsLockError> {
        let path = workspace_root.join(PETALS_LOCK_FILE_NAME);
        if !path.is_file() {
            return Ok(PetalsLockFile::new());
        }
        let body = std::fs::read_to_string(&path)?;
        Self::from_toml_str(&body)
    }

    /// Atomically write the lock to `<workspace_root>/petals.lock`.
    pub fn write(&self, workspace_root: &Path) -> Result<PathBuf, PetalsLockError> {
        let path = workspace_root.join(PETALS_LOCK_FILE_NAME);
        let body = self.to_toml_string()?;
        // Write to a temp neighbour file and rename for atomicity.
        let tmp = workspace_root.join(format!("{PETALS_LOCK_FILE_NAME}.tmp"));
        std::fs::write(&tmp, body.as_bytes())?;
        std::fs::rename(&tmp, &path)?;
        Ok(path)
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Resolution outcome for a single `external_type_refs` placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTypeRef {
    /// Canonical petal path the macro requested.
    pub path: String,
    /// 32-byte content hash to substitute in the referring petal's
    /// manifest (extracted from the lock entry's `content_hash` field).
    pub content_hash: [u8; 32],
}

/// Resolve a list of `external_type_refs` placeholders against a loaded
/// `petals.lock`. Fail-closed: any unknown path aborts with
/// `PetalsLockError::Unresolved`.
///
/// Spec §13.2 + §17 verification item 13.
pub fn resolve_external_type_refs(
    lock: &PetalsLockFile,
    refs: &[String],
) -> Result<Vec<ResolvedTypeRef>, PetalsLockError> {
    let mut out = Vec::with_capacity(refs.len());
    for path in refs {
        let entry = lock
            .get(path)
            .ok_or_else(|| PetalsLockError::Unresolved(path.clone()))?;
        let content_hash = entry.content_hash_bytes()?;
        out.push(ResolvedTypeRef {
            path: path.clone(),
            content_hash,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode_blake3_field(
    petal_path: &str,
    field: &str,
    raw: &str,
) -> Result<[u8; 32], PetalsLockError> {
    let stripped = raw
        .strip_prefix(HASH_PREFIX)
        .ok_or_else(|| PetalsLockError::BadHash {
            path: petal_path.into(),
            msg: format!("{field}: missing `{HASH_PREFIX}` prefix in `{raw}`"),
        })?;
    if stripped.len() != 64 {
        return Err(PetalsLockError::BadHash {
            path: petal_path.into(),
            msg: format!(
                "{field}: expected 64 hex chars after prefix, got {} (`{raw}`)",
                stripped.len()
            ),
        });
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(stripped, &mut out).map_err(|e| PetalsLockError::BadHash {
        path: petal_path.into(),
        msg: format!("{field}: hex decode failed: {e}"),
    })?;
    Ok(out)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_entry(path: &str, content_byte: u8) -> PetalsLockEntry {
        PetalsLockEntry {
            path: path.into(),
            content_hash: format!("{HASH_PREFIX}{}", hex::encode([content_byte; 32])),
            manifest_blake3: Some(format!("{HASH_PREFIX}{}", hex::encode([0xfe; 32]))),
            emitted_by: Some("test 0.0.0".into()),
            depends_on: vec![],
        }
    }

    #[test]
    fn empty_lock_round_trips_through_toml() {
        let lock = PetalsLockFile::new();
        let body = lock.to_toml_string().unwrap();
        let decoded = PetalsLockFile::from_toml_str(&body).unwrap();
        assert_eq!(lock, decoded);
    }

    #[test]
    fn single_entry_round_trips() {
        let mut lock = PetalsLockFile::new();
        lock.insert(mk_entry("/bloom/core/fungible", 0xab)).unwrap();
        let body = lock.to_toml_string().unwrap();
        let decoded = PetalsLockFile::from_toml_str(&body).unwrap();
        assert_eq!(lock, decoded);
    }

    #[test]
    fn round_trip_preserves_byte_equality() {
        // Re-encoding a parsed lock must produce identical bytes —
        // this is what makes the file safe to commit to a repo.
        let mut lock = PetalsLockFile::new();
        lock.insert(mk_entry("/bloom/core/cap", 0x01)).unwrap();
        let mut e = mk_entry("/bloom/core/fungible", 0x02);
        e.depends_on = vec!["/bloom/core/cap".into()];
        lock.insert(e).unwrap();

        let body1 = lock.to_toml_string().unwrap();
        let parsed = PetalsLockFile::from_toml_str(&body1).unwrap();
        let body2 = parsed.to_toml_string().unwrap();
        assert_eq!(body1, body2, "TOML round-trip must be byte-stable");
    }

    #[test]
    fn duplicate_path_is_rejected() {
        let mut lock = PetalsLockFile::new();
        lock.insert(mk_entry("/bloom/core/fungible", 0xab)).unwrap();
        let err = lock
            .insert(mk_entry("/bloom/core/fungible", 0xab))
            .unwrap_err();
        assert!(matches!(err, PetalsLockError::Duplicate(_)));
    }

    #[test]
    fn entries_serialise_in_sorted_order() {
        let mut lock = PetalsLockFile::new();
        lock.insert(mk_entry("/z", 0x01)).unwrap();
        lock.insert(mk_entry("/a", 0x02)).unwrap();
        lock.insert(mk_entry("/m", 0x03)).unwrap();
        let body = lock.to_toml_string().unwrap();
        let a = body.find("/a").unwrap();
        let m = body.find("/m").unwrap();
        let z = body.find("/z").unwrap();
        assert!(a < m && m < z, "expected sorted; got: {body}");
    }

    #[test]
    fn content_hash_decodes_to_32_bytes() {
        let entry = mk_entry("/bloom/core/fungible", 0xab);
        let h = entry.content_hash_bytes().unwrap();
        assert_eq!(h, [0xab; 32]);
    }

    #[test]
    fn rejects_hash_missing_prefix() {
        let entry = PetalsLockEntry {
            path: "/x".into(),
            content_hash: hex::encode([0xab; 32]),
            manifest_blake3: None,
            emitted_by: None,
            depends_on: vec![],
        };
        let err = entry.content_hash_bytes().unwrap_err();
        assert!(matches!(err, PetalsLockError::BadHash { .. }));
    }

    #[test]
    fn rejects_hash_with_wrong_length() {
        let entry = PetalsLockEntry {
            path: "/x".into(),
            content_hash: format!("{HASH_PREFIX}aabbcc"),
            manifest_blake3: None,
            emitted_by: None,
            depends_on: vec![],
        };
        let err = entry.content_hash_bytes().unwrap_err();
        assert!(matches!(err, PetalsLockError::BadHash { .. }));
    }

    #[test]
    fn resolve_fails_closed_for_unknown_path() {
        // Spec §17, verification item 13: build must fail closed.
        let lock = PetalsLockFile::new();
        let refs = vec!["/bloom/core/missing".to_string()];
        let err = resolve_external_type_refs(&lock, &refs).unwrap_err();
        match err {
            PetalsLockError::Unresolved(p) => assert_eq!(p, "/bloom/core/missing"),
            other => panic!("expected Unresolved, got {other:?}"),
        }
    }

    #[test]
    fn resolve_succeeds_with_full_coverage() {
        let mut lock = PetalsLockFile::new();
        lock.insert(mk_entry("/bloom/core/fungible", 0xab)).unwrap();
        lock.insert(mk_entry("/bloom/core/cap", 0xcd)).unwrap();

        let refs = vec![
            "/bloom/core/fungible".to_string(),
            "/bloom/core/cap".to_string(),
        ];
        let resolved = resolve_external_type_refs(&lock, &refs).unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].path, "/bloom/core/fungible");
        assert_eq!(resolved[0].content_hash, [0xab; 32]);
        assert_eq!(resolved[1].path, "/bloom/core/cap");
        assert_eq!(resolved[1].content_hash, [0xcd; 32]);
    }

    #[test]
    fn resolve_preserves_input_order() {
        // Output order matches input order, NOT the lock's storage order
        // — the macro emits placeholders in source order.
        let mut lock = PetalsLockFile::new();
        lock.insert(mk_entry("/a", 0x01)).unwrap();
        lock.insert(mk_entry("/b", 0x02)).unwrap();

        let refs = vec!["/b".to_string(), "/a".to_string()];
        let resolved = resolve_external_type_refs(&lock, &refs).unwrap();
        assert_eq!(resolved[0].path, "/b");
        assert_eq!(resolved[1].path, "/a");
    }

    #[test]
    fn load_missing_file_returns_empty_lock() {
        let dir = tempfile::tempdir().unwrap();
        let lock = PetalsLockFile::load(dir.path()).unwrap();
        assert!(lock.entries.is_empty());
    }

    #[test]
    fn write_then_load_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut lock = PetalsLockFile::new();
        lock.insert(mk_entry("/bloom/core/fungible", 0xab)).unwrap();
        let written_path = lock.write(dir.path()).unwrap();
        assert_eq!(written_path.file_name().unwrap(), PETALS_LOCK_FILE_NAME);
        assert!(written_path.is_file());

        let reloaded = PetalsLockFile::load(dir.path()).unwrap();
        assert_eq!(lock, reloaded);
    }

    #[test]
    fn write_is_atomic_no_leftover_tmp() {
        // After a successful `write`, no `.tmp` neighbour should remain.
        let dir = tempfile::tempdir().unwrap();
        let mut lock = PetalsLockFile::new();
        lock.insert(mk_entry("/bloom/x", 0x01)).unwrap();
        lock.write(dir.path()).unwrap();
        let tmp = dir.path().join(format!("{PETALS_LOCK_FILE_NAME}.tmp"));
        assert!(!tmp.exists(), "atomic-rename should leave no .tmp behind");
    }
}
