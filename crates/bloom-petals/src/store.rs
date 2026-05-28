//! Content-addressed object store for petal wasm.
//!
//! Layout on disk (rooted at `<base>`):
//!
//! ```text
//! <base>/objects/<hash>      — raw wasm bytes
//! <base>/meta/<hash>.json    — PetalMeta (size, installed_at, name, caps)
//! ```
//!
//! Hash is hex-encoded BLAKE3 of the wasm bytes. Writes are atomic
//! (write-to-tempfile + rename); reads are unbuffered. The store does
//! not validate that the bytes are valid wasm — that's the VM's job.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::PetalError;
use crate::meta::{Capability, PetalMeta, PetalMode};

const OBJECTS: &str = "objects";
const META: &str = "meta";

/// Filesystem-backed petal object store.
#[derive(Debug, Clone)]
pub struct PetalStore {
    base: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallResult {
    pub hash: String,
    pub size: u64,
    /// True if this hash already existed in the store; false if newly
    /// written. Either way `meta` reflects the on-disk record after
    /// installation (which may have been updated to add a name / caps).
    pub already_present: bool,
}

impl PetalStore {
    /// Open (or create) a store rooted at `base`. Creates the
    /// `objects/` and `meta/` subdirectories if missing.
    pub fn open(base: impl Into<PathBuf>) -> Result<Self, PetalError> {
        let base = base.into();
        std::fs::create_dir_all(base.join(OBJECTS))?;
        std::fs::create_dir_all(base.join(META))?;
        Ok(Self { base })
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    fn object_path(&self, hash: &str) -> PathBuf {
        self.base.join(OBJECTS).join(hash)
    }

    fn meta_path(&self, hash: &str) -> PathBuf {
        self.base.join(META).join(format!("{hash}.json"))
    }

    /// Install raw wasm bytes. The store assigns the content hash.
    /// If a petal with the same hash is already present, its metadata
    /// is updated only when the requested mode and caps match the
    /// existing install.
    pub fn install(
        &self,
        wasm: &[u8],
        name: Option<&str>,
        caps: &BTreeSet<Capability>,
        mode: PetalMode,
    ) -> Result<(InstallResult, PetalMeta), PetalError> {
        let hash = hex::encode(blake3::hash(wasm).as_bytes());
        let obj_path = self.object_path(&hash);
        let already_present = obj_path.exists();

        // Check the mode constraint before writing — a cross-mode reinstall
        // should fail without touching the object dir.
        let mut meta = match self.load_meta(&hash) {
            Ok(existing) => {
                if existing.mode != mode {
                    return Err(PetalError::ModeConflict {
                        existing: existing.mode,
                    });
                }
                if existing.caps != *caps {
                    return Err(PetalError::CapMismatch);
                }
                existing
            }
            Err(PetalError::NotFound(_)) => PetalMeta {
                hash: hash.clone(),
                size: wasm.len() as u64,
                installed_at_ms: now_ms(),
                name: None,
                caps: BTreeSet::new(),
                mode,
            },
            Err(e) => return Err(e),
        };

        if !already_present {
            atomic_write(&obj_path, wasm)?;
        }
        if let Some(n) = name {
            meta.name = Some(n.to_string());
        }
        meta.caps = caps.clone();
        meta.size = wasm.len() as u64;
        self.write_meta(&meta)?;

        Ok((
            InstallResult {
                hash: hash.clone(),
                size: wasm.len() as u64,
                already_present,
            },
            meta,
        ))
    }

    /// Read raw wasm bytes for a petal.
    pub fn read_wasm(&self, hash: &str) -> Result<Vec<u8>, PetalError> {
        let path = self.object_path(hash);
        match std::fs::read(&path) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(PetalError::NotFound(hash.to_string()))
            }
            Err(e) => Err(PetalError::Io(e)),
        }
    }

    /// Load metadata for a petal.
    pub fn load_meta(&self, hash: &str) -> Result<PetalMeta, PetalError> {
        let path = self.meta_path(hash);
        match std::fs::read(&path) {
            Ok(b) => {
                let m: PetalMeta = serde_json::from_slice(&b)?;
                Ok(m)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(PetalError::NotFound(hash.to_string()))
            }
            Err(e) => Err(PetalError::Io(e)),
        }
    }

    fn write_meta(&self, meta: &PetalMeta) -> Result<(), PetalError> {
        let body = serde_json::to_vec_pretty(meta)?;
        atomic_write(&self.meta_path(&meta.hash), &body)?;
        Ok(())
    }

    /// Whether the store has this hash on disk.
    pub fn contains(&self, hash: &str) -> bool {
        self.object_path(hash).exists()
    }

    /// List every installed petal hash (unordered).
    pub fn list_hashes(&self) -> Result<Vec<String>, PetalError> {
        let dir = self.base.join(OBJECTS);
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(PetalError::Io(e)),
        };
        for entry in rd {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str()
                && is_valid_hex_hash(name)
            {
                out.push(name.to_string());
            }
        }
        Ok(out)
    }

    /// Remove an installed petal's object and metadata. Returns `true`
    /// if anything was removed, `false` if the hash was not installed.
    /// The caller is responsible for clearing any registry entries that
    /// point at this hash.
    ///
    /// Not safe under concurrent mutation: the `had` snapshot is taken
    /// before the removes, and a non-NotFound IO error between the two
    /// unlinks can leave the store with only one of the two files.
    pub fn uninstall(&self, hash: &str) -> Result<bool, PetalError> {
        let obj_path = self.object_path(hash);
        let meta_path = self.meta_path(hash);
        let had = obj_path.exists() || meta_path.exists();
        for p in [&obj_path, &meta_path] {
            match std::fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(PetalError::Io(e)),
            }
        }
        Ok(had)
    }

    /// List hashes whose meta records have the given mode. Ignores
    /// objects with missing metadata (which would be a corruption).
    pub fn list_hashes_by_mode(&self, mode: PetalMode) -> Result<Vec<String>, PetalError> {
        let mut out = Vec::new();
        for hash in self.list_hashes()? {
            match self.load_meta(&hash) {
                Ok(m) if m.mode == mode => out.push(hash),
                Ok(_) => {}
                Err(PetalError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("path has no parent"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("path has no file name"))?;
    let mut tmp = dir.to_path_buf();
    tmp.push(format!(".{}.tmp", file_name.to_string_lossy()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A valid BLAKE3 hex hash: exactly 64 lowercase hex chars.
pub fn is_valid_hex_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::PetalMode;
    use tempfile::TempDir;

    fn store() -> (TempDir, PetalStore) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn install_writes_object_and_meta() {
        let (_d, store) = store();
        let mut caps = BTreeSet::new();
        caps.insert(Capability::VfsRead);
        let (r, m) = store
            .install(b"hello-wasm", Some("greet"), &caps, PetalMode::Local)
            .unwrap();
        assert_eq!(r.size, 10);
        assert!(!r.already_present);
        assert!(store.contains(&r.hash));
        assert_eq!(m.name.as_deref(), Some("greet"));
        assert!(m.has_cap(Capability::VfsRead));
    }

    #[test]
    fn install_is_idempotent_on_hash_when_caps_match() {
        let (_d, store) = store();
        let mut caps_a = BTreeSet::new();
        caps_a.insert(Capability::VfsRead);
        let (r1, _) = store
            .install(b"x", Some("a"), &caps_a, PetalMode::Local)
            .unwrap();
        let (r2, m) = store
            .install(b"x", Some("b"), &caps_a, PetalMode::Local)
            .unwrap();
        assert_eq!(r1.hash, r2.hash);
        assert!(r2.already_present);
        // Name overwritten on second install.
        assert_eq!(m.name.as_deref(), Some("b"));
        assert!(m.has_cap(Capability::VfsRead));
        assert!(!m.has_cap(Capability::VfsWrite));
    }

    #[test]
    fn reinstall_same_hash_same_mode_with_different_caps_is_cap_mismatch() {
        let (_d, store) = store();
        let mut caps_a = BTreeSet::new();
        caps_a.insert(Capability::VfsRead);
        let (r1, m1) = store
            .install(b"x", Some("a"), &caps_a, PetalMode::Local)
            .unwrap();

        let mut caps_b = BTreeSet::new();
        caps_b.insert(Capability::VfsWrite);
        let err = store
            .install(b"x", Some("b"), &caps_b, PetalMode::Local)
            .unwrap_err();

        assert!(matches!(err, PetalError::CapMismatch));
        let m2 = store.load_meta(&r1.hash).unwrap();
        assert_eq!(m2.name, m1.name);
        assert_eq!(m2.caps, caps_a);
    }

    #[test]
    fn read_unknown_hash_is_not_found() {
        let (_d, store) = store();
        let err = store.read_wasm("00".repeat(32).as_str()).unwrap_err();
        assert!(matches!(err, PetalError::NotFound(_)));
    }

    #[test]
    fn list_hashes_filters_non_hash_entries() {
        let (d, store) = store();
        let (r, _) = store
            .install(b"abc", None, &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        // Drop a stray file that does NOT look like a hash.
        std::fs::write(d.path().join(OBJECTS).join("README"), b"junk").unwrap();
        let hashes = store.list_hashes().unwrap();
        assert_eq!(hashes, vec![r.hash]);
    }

    #[test]
    fn is_valid_hex_hash_rejects_wrong_length_and_uppercase() {
        assert!(is_valid_hex_hash(&"a".repeat(64)));
        assert!(!is_valid_hex_hash(&"a".repeat(63)));
        assert!(!is_valid_hex_hash(&"a".repeat(65)));
        assert!(!is_valid_hex_hash(&"A".repeat(64)));
        assert!(!is_valid_hex_hash(&"g".repeat(64)));
    }

    #[test]
    fn install_records_mode() {
        let (_d, store) = store();
        let (_r, m) = store
            .install(b"abc", Some("a"), &BTreeSet::new(), PetalMode::Chain)
            .unwrap();
        assert_eq!(m.mode, PetalMode::Chain);
    }

    #[test]
    fn install_same_hash_different_mode_returns_mode_conflict() {
        let (_d, store) = store();
        let (_r, _m) = store
            .install(b"xyz", None, &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        let err = store
            .install(b"xyz", None, &BTreeSet::new(), PetalMode::Chain)
            .unwrap_err();
        assert!(
            matches!(err, PetalError::ModeConflict { existing } if existing == PetalMode::Local),
            "{err:?}"
        );
    }

    #[test]
    fn install_same_hash_same_mode_is_idempotent() {
        let (_d, store) = store();
        let (r1, _) = store
            .install(b"qqq", Some("a"), &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        let (r2, m) = store
            .install(b"qqq", Some("b"), &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        assert_eq!(r1.hash, r2.hash);
        assert!(r2.already_present);
        assert_eq!(m.name.as_deref(), Some("b"));
        assert_eq!(m.mode, PetalMode::Local);
    }

    #[test]
    fn uninstall_removes_object_and_meta() {
        let (_d, store) = store();
        let (r, _) = store
            .install(b"toremove", None, &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        assert!(store.contains(&r.hash));
        let removed = store.uninstall(&r.hash).unwrap();
        assert!(removed);
        assert!(!store.contains(&r.hash));
        assert!(matches!(
            store.load_meta(&r.hash),
            Err(PetalError::NotFound(_))
        ));
    }

    #[test]
    fn uninstall_missing_returns_false() {
        let (_d, store) = store();
        let absent = "0".repeat(64);
        assert!(!store.uninstall(&absent).unwrap());
    }

    #[test]
    fn list_hashes_by_mode_filters_correctly() {
        let (_d, store) = store();
        let (rl, _) = store
            .install(b"local-bytes", None, &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        let (rc, _) = store
            .install(b"chain-bytes", None, &BTreeSet::new(), PetalMode::Chain)
            .unwrap();
        let locals = store.list_hashes_by_mode(PetalMode::Local).unwrap();
        let chain = store.list_hashes_by_mode(PetalMode::Chain).unwrap();
        assert_eq!(locals, vec![rl.hash]);
        assert_eq!(chain, vec![rc.hash]);
    }
}
