//! VFS handler for the `public/` subtree.
//!
//! Path layout (relative to the handler — i.e. the strings below omit
//! the `public/` prefix):
//!
//! ```text
//! .                  → directory listing of installed petals
//!                      (hash dirs + name symlinks + the `names/` dir)
//! <hash>/            → directory
//! <hash>/wasm        → file, read-only, raw wasm bytes
//! <hash>/meta.json   → file, read-only, PetalMeta as JSON
//! <name>             → symlink → <hash>
//! names/             → directory
//! names/<name>       → file, *writable*; body is the target hash
//! ```
//!
//! Petal *execution* is not exposed via the VFS in v0 — invoke via
//! the IPC method `petals.run` or `bloom petals run`.

use std::sync::Arc;

use async_trait::async_trait;

use bloom_vfs::handler::{Entry, Handler, HandlerError};
use bloom_vfs::path::VfsPath;

use crate::error::PetalError;
use crate::registry::{NameRegistry, validate_name};
use crate::store::{PetalStore, is_valid_hex_hash};

/// Reserved child of `public/` that exposes the name → hash registry.
const NAMES_DIR: &str = "names";

pub struct PetalsHandler {
    store: PetalStore,
    registry: Arc<NameRegistry>,
}

impl PetalsHandler {
    pub fn new(store: PetalStore, registry: Arc<NameRegistry>) -> Self {
        Self { store, registry }
    }

    pub fn store(&self) -> &PetalStore {
        &self.store
    }

    pub fn registry(&self) -> &Arc<NameRegistry> {
        &self.registry
    }
}

#[async_trait]
impl Handler for PetalsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        match path.segments() {
            // Root of `public/`.
            [] => Ok(Entry::dir("")),
            // `public/names`.
            [seg] if seg == NAMES_DIR => Ok(Entry::dir(NAMES_DIR)),
            // `public/names/<name>` — writable file holding the target hash.
            [first, rest @ ..] if first == NAMES_DIR => match rest {
                [name] => {
                    validate_name(name).map_err(map_err)?;
                    let entry = match self.registry.lookup(name) {
                        Some(_) => {
                            let mut e = Entry::writable_file(name);
                            // Show the hash length so `ls -l` reports the right size.
                            e.size = 64;
                            e
                        }
                        None => {
                            // Pre-existing-but-unset: still writable so a
                            // caller can create it. `lookup` is called by
                            // NFS before a write, so returning a
                            // writable_file here is correct even if the
                            // name isn't registered yet.
                            Entry::writable_file(name)
                        }
                    };
                    Ok(entry)
                }
                _ => Err(HandlerError::NotFound(path.to_string_path())),
            },
            // `public/<first>` — either a hash (directory) or a name (symlink).
            [first] => {
                if is_valid_hex_hash(first) {
                    if self.store.contains(first) {
                        Ok(Entry::dir(first))
                    } else {
                        Err(HandlerError::NotFound(path.to_string_path()))
                    }
                } else if let Some(target_hash) = self.registry.lookup(first) {
                    Ok(Entry::symlink(first, &target_hash))
                } else {
                    Err(HandlerError::NotFound(path.to_string_path()))
                }
            }
            // `public/<hash>/wasm` or `<hash>/meta.json`.
            [hash, rest @ ..] if is_valid_hex_hash(hash) => {
                if !self.store.contains(hash) {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                match rest {
                    [child] if child == "wasm" => {
                        let meta = self.store.load_meta(hash).map_err(map_err)?;
                        let mut e = Entry::read_only_file("wasm");
                        e.size = meta.size;
                        Ok(e)
                    }
                    [child] if child == "meta.json" => {
                        let meta = self.store.load_meta(hash).map_err(map_err)?;
                        let body = serde_json::to_vec_pretty(&meta)
                            .map_err(|e| HandlerError::Backend(e.to_string()))?;
                        let mut e = Entry::read_only_file("meta.json");
                        e.size = body.len() as u64;
                        Ok(e)
                    }
                    _ => Err(HandlerError::NotFound(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        match path.segments() {
            [first, rest @ ..] if first == NAMES_DIR => match rest {
                [name] => {
                    validate_name(name).map_err(map_err)?;
                    match self.registry.lookup(name) {
                        Some(hash) => {
                            let mut out = hash.into_bytes();
                            out.push(b'\n');
                            Ok(out)
                        }
                        None => Err(HandlerError::NotFound(path.to_string_path())),
                    }
                }
                _ => Err(HandlerError::NotAFile(path.to_string_path())),
            },
            [hash, child] if is_valid_hex_hash(hash) => {
                if !self.store.contains(hash) {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                match child.as_str() {
                    "wasm" => self.store.read_wasm(hash).map_err(map_err),
                    "meta.json" => {
                        let meta = self.store.load_meta(hash).map_err(map_err)?;
                        serde_json::to_vec_pretty(&meta)
                            .map(|mut v| {
                                v.push(b'\n');
                                v
                            })
                            .map_err(|e| HandlerError::Backend(e.to_string()))
                    }
                    _ => Err(HandlerError::NotFound(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        match path.segments() {
            [first, rest @ ..] if first == NAMES_DIR => match rest {
                [name] => {
                    validate_name(name).map_err(map_err)?;
                    let body = std::str::from_utf8(data)
                        .map_err(|_| HandlerError::invalid("name body not utf-8"))?
                        .trim();
                    if body.is_empty() {
                        self.registry.unset(name).map_err(map_err)?;
                        return Ok(());
                    }
                    if !is_valid_hex_hash(body) {
                        return Err(HandlerError::invalid(format!(
                            "expected 64-char hex hash, got {body:?}"
                        )));
                    }
                    if !self.store.contains(body) {
                        return Err(HandlerError::NotFound(format!("petal {body}")));
                    }
                    self.registry.set(name, body).map_err(map_err)
                }
                _ => Err(HandlerError::PermissionDenied),
            },
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        match path.segments() {
            [] => {
                let mut out = Vec::new();
                out.push(Entry::dir(NAMES_DIR));
                for hash in self.store.list_hashes().map_err(map_err)? {
                    out.push(Entry::dir(&hash));
                }
                for (name, hash) in self.registry.snapshot() {
                    out.push(Entry::symlink(&name, &hash));
                }
                Ok(out)
            }
            [seg] if seg == NAMES_DIR => {
                let mut out = Vec::new();
                for (name, _hash) in self.registry.snapshot() {
                    let mut e = Entry::writable_file(&name);
                    e.size = 64;
                    out.push(e);
                }
                Ok(out)
            }
            [hash] if is_valid_hex_hash(hash) => {
                if !self.store.contains(hash) {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                let meta = self.store.load_meta(hash).map_err(map_err)?;
                let mut wasm = Entry::read_only_file("wasm");
                wasm.size = meta.size;
                let meta_body = serde_json::to_vec_pretty(&meta)
                    .map_err(|e| HandlerError::Backend(e.to_string()))?;
                let mut meta_entry = Entry::read_only_file("meta.json");
                meta_entry.size = (meta_body.len() + 1) as u64;
                Ok(vec![wasm, meta_entry])
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

fn map_err(e: PetalError) -> HandlerError {
    match e {
        PetalError::NotFound(s) => HandlerError::NotFound(s),
        PetalError::InvalidHash(s) => HandlerError::invalid(format!("hash: {s}")),
        PetalError::InvalidName(s) => HandlerError::invalid(format!("name: {s}")),
        PetalError::InvalidWasm(s) => HandlerError::invalid(format!("wasm: {s}")),
        PetalError::CapabilityDenied { petal, cap } => HandlerError::Backend(format!(
            "capability denied: petal={petal} cap={cap}"
        )),
        PetalError::Vm(s) => HandlerError::Backend(format!("vm: {s}")),
        PetalError::Io(e) => HandlerError::Io(e),
        PetalError::Serde(s) => HandlerError::Backend(format!("serde: {s}")),
        PetalError::ModeCapMismatch { mode, cap } => {
            HandlerError::invalid(format!("mode/cap mismatch: mode={mode:?} disallows cap={cap}"))
        }
        PetalError::ModeConflict { existing } => {
            HandlerError::invalid(format!("mode conflict: existing={existing}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::Capability;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    fn setup() -> (TempDir, PetalsHandler, String) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path().join("store")).unwrap();
        let reg = Arc::new(NameRegistry::open(dir.path().join("reg")).unwrap());
        let mut caps = BTreeSet::new();
        caps.insert(Capability::VfsRead);
        let (r, _) = store.install(b"\x00asm\x01\x00\x00\x00", Some("greet"), &caps, crate::meta::PetalMode::Local).unwrap();
        let h = PetalsHandler::new(store, reg.clone());
        reg.set("greet", &r.hash).unwrap();
        (dir, h, r.hash)
    }

    #[tokio::test]
    async fn lookup_root_is_directory() {
        let (_d, h, _) = setup();
        let e = h.lookup(&VfsPath::parse("/").unwrap()).await.unwrap();
        assert_eq!(e.kind, bloom_vfs::handler::EntryKind::Dir);
    }

    #[tokio::test]
    async fn lookup_hash_is_directory() {
        let (_d, h, hash) = setup();
        let p = VfsPath::parse(&format!("/{hash}")).unwrap();
        let e = h.lookup(&p).await.unwrap();
        assert_eq!(e.kind, bloom_vfs::handler::EntryKind::Dir);
        assert_eq!(e.name, hash);
    }

    #[tokio::test]
    async fn lookup_name_is_symlink_to_hash() {
        let (_d, h, hash) = setup();
        let p = VfsPath::parse("/greet").unwrap();
        let e = h.lookup(&p).await.unwrap();
        assert_eq!(e.kind, bloom_vfs::handler::EntryKind::Symlink);
        assert_eq!(e.link_target.as_deref(), Some(hash.as_str()));
    }

    #[tokio::test]
    async fn read_wasm_returns_bytes() {
        let (_d, h, hash) = setup();
        let p = VfsPath::parse(&format!("/{hash}/wasm")).unwrap();
        let body = h.read(&p).await.unwrap();
        assert_eq!(body, b"\x00asm\x01\x00\x00\x00");
    }

    #[tokio::test]
    async fn read_meta_returns_json() {
        let (_d, h, hash) = setup();
        let p = VfsPath::parse(&format!("/{hash}/meta.json")).unwrap();
        let body = h.read(&p).await.unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("\"hash\""));
        assert!(s.contains("\"caps\""));
    }

    #[tokio::test]
    async fn write_to_names_sets_registry() {
        let (_d, h, hash) = setup();
        let p = VfsPath::parse("/names/hello").unwrap();
        h.write(&p, hash.as_bytes()).await.unwrap();
        assert_eq!(h.registry().lookup("hello"), Some(hash));
    }

    #[tokio::test]
    async fn write_to_names_with_empty_body_unsets() {
        let (_d, h, hash) = setup();
        let p = VfsPath::parse("/names/greet").unwrap();
        h.write(&p, b"").await.unwrap();
        assert!(h.registry().lookup("greet").is_none());
        let _ = hash;
    }

    #[tokio::test]
    async fn write_to_names_rejects_unknown_hash() {
        let (_d, h, _) = setup();
        let p = VfsPath::parse("/names/x").unwrap();
        let bad_hash = "9".repeat(64);
        let err = h.write(&p, bad_hash.as_bytes()).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn list_root_includes_hash_dir_and_name_symlink_and_names_dir() {
        let (_d, h, hash) = setup();
        let entries = h.list(&VfsPath::parse("/").unwrap()).await.unwrap();
        let hash_dir = entries
            .iter()
            .find(|e| e.name == hash && e.kind == bloom_vfs::handler::EntryKind::Dir);
        let name_link = entries
            .iter()
            .find(|e| e.name == "greet" && e.kind == bloom_vfs::handler::EntryKind::Symlink);
        let names_dir = entries
            .iter()
            .find(|e| e.name == NAMES_DIR && e.kind == bloom_vfs::handler::EntryKind::Dir);
        assert!(hash_dir.is_some(), "missing hash dir; got {entries:#?}");
        assert!(name_link.is_some(), "missing name symlink; got {entries:#?}");
        assert!(names_dir.is_some(), "missing names dir; got {entries:#?}");
    }
}
