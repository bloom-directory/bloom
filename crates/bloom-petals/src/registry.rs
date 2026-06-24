//! Petname → content-hash registry, persisted as TOML.
//!
//! ```toml
//! [names]
//! greet = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
//! hello = "..."
//! ```
//!
//! Single-user; the v1 beth daemon never serves multiple identities.
//! Edits are atomic (tempfile + rename) and the whole file is rewritten
//! on each change — fine for the small N we expect (hundreds at most).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::PetalError;
use crate::store::is_valid_hex_hash;

const FILE_NAME: &str = "names.toml";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OnDisk {
    #[serde(default)]
    names: BTreeMap<String, String>,
}

/// Reserved top-level names that must NOT be usable as petal names —
/// otherwise legacy name bindings could collide with handler-managed children.
const RESERVED_NAMES: &[&str] = &["names"];

#[derive(Debug)]
pub struct NameRegistry {
    path: PathBuf,
    inner: RwLock<OnDisk>,
}

impl NameRegistry {
    pub fn open(base: impl Into<PathBuf>) -> Result<Self, PetalError> {
        let mut path = base.into();
        std::fs::create_dir_all(&path)?;
        path.push(FILE_NAME);
        let inner = match std::fs::read_to_string(&path) {
            Ok(s) => toml::from_str::<OnDisk>(&s).map_err(PetalError::from)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => OnDisk::default(),
            Err(e) => return Err(PetalError::Io(e)),
        };
        Ok(Self {
            path,
            inner: RwLock::new(inner),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Snapshot of `name → hash`.
    pub fn snapshot(&self) -> BTreeMap<String, String> {
        self.inner.read().names.clone()
    }

    pub fn lookup(&self, name: &str) -> Option<String> {
        self.inner.read().names.get(name).cloned()
    }

    pub fn set(&self, name: &str, hash: &str) -> Result<(), PetalError> {
        validate_name(name)?;
        if !is_valid_hex_hash(hash) {
            return Err(PetalError::InvalidHash(hash.to_string()));
        }
        let mut g = self.inner.write();
        g.names.insert(name.to_string(), hash.to_string());
        persist(&self.path, &g)
    }

    pub fn unset(&self, name: &str) -> Result<bool, PetalError> {
        validate_name(name)?;
        let mut g = self.inner.write();
        let removed = g.names.remove(name).is_some();
        if removed {
            persist(&self.path, &g)?;
        }
        Ok(removed)
    }
}

fn persist(path: &Path, on_disk: &OnDisk) -> Result<(), PetalError> {
    let body = toml::to_string_pretty(on_disk)?;
    let dir = path
        .parent()
        .ok_or_else(|| PetalError::Io(std::io::Error::other("registry path has no parent")))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| PetalError::Io(std::io::Error::other("registry path has no file name")))?;
    let mut tmp = dir.to_path_buf();
    tmp.push(format!(".{}.tmp", file_name.to_string_lossy()));
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Names must be non-empty, ≤ 64 chars, contain no path separators or
/// control characters, not start with a dot, and not collide with a
/// reserved child of `public/`.
pub fn validate_name(name: &str) -> Result<(), PetalError> {
    if name.is_empty() {
        return Err(PetalError::InvalidName("empty".into()));
    }
    if name.len() > 64 {
        return Err(PetalError::InvalidName(format!("too long: {name}")));
    }
    if name.starts_with('.') {
        return Err(PetalError::InvalidName(format!("leading dot: {name}")));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(PetalError::InvalidName(format!("reserved: {name}")));
    }
    for c in name.chars() {
        if c == '/' || c == '\\' || c.is_control() {
            return Err(PetalError::InvalidName(format!(
                "disallowed character in {name:?}"
            )));
        }
    }
    // A bare hex hash would be confusing alongside `public/<hash>`. Ban
    // any name that *looks like* a hash.
    if is_valid_hex_hash(name) {
        return Err(PetalError::InvalidName(format!(
            "looks like a hash: {name}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn registry() -> (TempDir, NameRegistry) {
        let dir = TempDir::new().unwrap();
        let reg = NameRegistry::open(dir.path()).unwrap();
        (dir, reg)
    }

    #[test]
    fn set_lookup_persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let h = "a".repeat(64);
        {
            let reg = NameRegistry::open(dir.path()).unwrap();
            reg.set("greet", &h).unwrap();
        }
        let reg2 = NameRegistry::open(dir.path()).unwrap();
        assert_eq!(reg2.lookup("greet"), Some(h));
    }

    #[test]
    fn unset_removes_entry() {
        let (_d, reg) = registry();
        reg.set("greet", &"b".repeat(64)).unwrap();
        assert!(reg.unset("greet").unwrap());
        assert!(reg.lookup("greet").is_none());
        // unsetting again is a no-op (Ok(false)).
        assert!(!reg.unset("greet").unwrap());
    }

    #[test]
    fn invalid_hash_is_rejected() {
        let (_d, reg) = registry();
        let err = reg.set("greet", "not-a-hash").unwrap_err();
        assert!(matches!(err, PetalError::InvalidHash(_)));
    }

    #[test]
    fn validate_name_rules() {
        validate_name("ok").unwrap();
        validate_name("with-dash_and_under").unwrap();
        assert!(validate_name("").is_err());
        assert!(validate_name(".hidden").is_err());
        assert!(validate_name("with/slash").is_err());
        assert!(validate_name("with\\back").is_err());
        assert!(validate_name("names").is_err(), "reserved");
        let too_long = "a".repeat(65);
        assert!(validate_name(&too_long).is_err());
        let hash_like = "f".repeat(64);
        assert!(validate_name(&hash_like).is_err());
    }
}
