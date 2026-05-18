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
use crate::meta::{Capability, PetalMeta};

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

    /// Install raw wasm bytes. The store assigns the content hash;
    /// `name` and `caps` are merged into the on-disk metadata. If a
    /// petal with the same hash is already present, its metadata is
    /// updated (name overwritten if `Some`, caps unioned).
    pub fn install(
        &self,
        wasm: &[u8],
        name: Option<&str>,
        caps: &BTreeSet<Capability>,
    ) -> Result<(InstallResult, PetalMeta), PetalError> {
        let hash = hex::encode(blake3::hash(wasm).as_bytes());
        let obj_path = self.object_path(&hash);
        let already_present = obj_path.exists();

        if !already_present {
            atomic_write(&obj_path, wasm)?;
        }

        // Merge metadata.
        let mut meta = match self.load_meta(&hash) {
            Ok(m) => m,
            Err(PetalError::NotFound(_)) => PetalMeta {
                hash: hash.clone(),
                size: wasm.len() as u64,
                installed_at_ms: now_ms(),
                name: None,
                caps: BTreeSet::new(),
                mode: Default::default(),
            },
            Err(e) => return Err(e),
        };
        if let Some(n) = name {
            meta.name = Some(n.to_string());
        }
        meta.caps.extend(caps.iter().copied());
        // Size is authoritative from the bytes we just hashed.
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
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
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
            .install(b"hello-wasm", Some("greet"), &caps)
            .unwrap();
        assert_eq!(r.size, 10);
        assert!(!r.already_present);
        assert!(store.contains(&r.hash));
        assert_eq!(m.name.as_deref(), Some("greet"));
        assert!(m.has_cap(Capability::VfsRead));
    }

    #[test]
    fn install_is_idempotent_on_hash_and_unions_caps() {
        let (_d, store) = store();
        let mut caps_a = BTreeSet::new();
        caps_a.insert(Capability::VfsRead);
        let (r1, _) = store.install(b"x", Some("a"), &caps_a).unwrap();
        let mut caps_b = BTreeSet::new();
        caps_b.insert(Capability::VfsWrite);
        let (r2, m) = store.install(b"x", Some("b"), &caps_b).unwrap();
        assert_eq!(r1.hash, r2.hash);
        assert!(r2.already_present);
        // Name overwritten on second install.
        assert_eq!(m.name.as_deref(), Some("b"));
        // Caps unioned.
        assert!(m.has_cap(Capability::VfsRead));
        assert!(m.has_cap(Capability::VfsWrite));
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
        let (r, _) = store.install(b"abc", None, &BTreeSet::new()).unwrap();
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
}
