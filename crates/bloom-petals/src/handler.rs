//! VFS handler for the `public/` subtree.
//!
//! Path layout (relative to the handler — i.e. the strings below omit
//! the `public/` prefix):
//!
//! ```text
//! .                          → directory listing: { local/, names/ }
//! local/                     → directory of installed local petals
//! local/<hash>/              → directory
//! local/<hash>/wasm          → file, read-only, raw wasm bytes
//! local/<hash>/meta.json     → file, read-only, PetalMeta as JSON
//! local/<name>               → symlink → <hash> (only if meta.mode == Local)
//! names/                     → directory
//! names/<name>               → file, *writable*; body is the target hash
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
const LOCAL_DIR: &str = "local";

use crate::meta::PetalMode;

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
            [] => Ok(Entry::dir("")),
            [seg] if seg == NAMES_DIR => Ok(Entry::dir(NAMES_DIR)),
            [seg] if seg == LOCAL_DIR => Ok(Entry::dir(LOCAL_DIR)),
            [first, name] if first == NAMES_DIR => {
                validate_name(name).map_err(map_err)?;
                let entry = match self.registry.lookup(name) {
                    Some(_) => {
                        let mut e = Entry::writable_file(name);
                        e.size = 64;
                        e
                    }
                    None => Entry::writable_file(name),
                };
                Ok(entry)
            }
            [mode_seg, hash, rest @ ..] if is_mode_dir(mode_seg) && is_valid_hex_hash(hash) => {
                let expected_mode = mode_for_seg(mode_seg);
                let meta = self.store.load_meta(hash).map_err(map_err)?;
                if meta.mode != expected_mode {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                match rest {
                    [] => Ok(Entry::dir(hash)),
                    [child] if child == "wasm" => {
                        let mut e = Entry::read_only_file("wasm");
                        e.size = meta.size;
                        Ok(e)
                    }
                    [child] if child == "meta.json" => {
                        let body = serde_json::to_vec_pretty(&meta)
                            .map_err(|e| HandlerError::Backend(e.to_string()))?;
                        let mut e = Entry::read_only_file("meta.json");
                        e.size = body.len() as u64;
                        Ok(e)
                    }
                    _ => Err(HandlerError::NotFound(path.to_string_path())),
                }
            }
            [mode_seg, name] if is_mode_dir(mode_seg) => {
                let expected_mode = mode_for_seg(mode_seg);
                let Some(hash) = self.registry.lookup(name) else {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                };
                let meta = self.store.load_meta(&hash).map_err(map_err)?;
                if meta.mode != expected_mode {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                Ok(Entry::symlink(name, &hash))
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        match path.segments() {
            [first, name] if first == NAMES_DIR => {
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
            [mode_seg, hash, child] if is_mode_dir(mode_seg) && is_valid_hex_hash(hash) => {
                let expected_mode = mode_for_seg(mode_seg);
                let meta = self.store.load_meta(hash).map_err(map_err)?;
                if meta.mode != expected_mode {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                match child.as_str() {
                    "wasm" => self.store.read_wasm(hash).map_err(map_err),
                    "meta.json" => serde_json::to_vec_pretty(&meta)
                        .map(|mut v| {
                            v.push(b'\n');
                            v
                        })
                        .map_err(|e| HandlerError::Backend(e.to_string())),
                    _ => Err(HandlerError::NotFound(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        match path.segments() {
            [first, name] if first == NAMES_DIR => {
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
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        match path.segments() {
            [] => Ok(vec![Entry::dir(LOCAL_DIR), Entry::dir(NAMES_DIR)]),
            [seg] if seg == NAMES_DIR => {
                let mut out = Vec::new();
                for (name, _hash) in self.registry.snapshot() {
                    let mut e = Entry::writable_file(&name);
                    e.size = 64;
                    out.push(e);
                }
                Ok(out)
            }
            [seg] if is_mode_dir(seg) => {
                let mode = mode_for_seg(seg);
                let mut out = Vec::new();
                for hash in self.store.list_hashes_by_mode(mode).map_err(map_err)? {
                    out.push(Entry::dir(&hash));
                }
                for (name, hash) in self.registry.snapshot() {
                    if let Ok(meta) = self.store.load_meta(&hash)
                        && meta.mode == mode
                    {
                        out.push(Entry::symlink(&name, &hash));
                    }
                }
                Ok(out)
            }
            [mode_seg, hash] if is_mode_dir(mode_seg) && is_valid_hex_hash(hash) => {
                let expected_mode = mode_for_seg(mode_seg);
                let meta = self.store.load_meta(hash).map_err(map_err)?;
                if meta.mode != expected_mode {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
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

fn is_mode_dir(s: &str) -> bool {
    s == LOCAL_DIR
}

fn mode_for_seg(_s: &str) -> PetalMode {
    PetalMode::Local
}

fn map_err(e: PetalError) -> HandlerError {
    match e {
        PetalError::NotFound(s) => HandlerError::NotFound(s),
        PetalError::InvalidHash(s) => HandlerError::invalid(format!("hash: {s}")),
        PetalError::InvalidName(s) => HandlerError::invalid(format!("name: {s}")),
        PetalError::InvalidWasm(s) => HandlerError::invalid(format!("wasm: {s}")),
        PetalError::CapabilityDenied { petal, cap } => {
            HandlerError::Backend(format!("capability denied: petal={petal} cap={cap}"))
        }
        PetalError::Vm(s) => HandlerError::Backend(format!("vm: {s}")),
        PetalError::Io(e) => HandlerError::Io(e),
        PetalError::Serde(s) => HandlerError::Backend(format!("serde: {s}")),
        PetalError::ModeCapMismatch { mode, cap } => HandlerError::invalid(format!(
            "mode/cap mismatch: mode={mode:?} disallows cap={cap}"
        )),
        PetalError::CapMismatch => HandlerError::invalid(
            "cap mismatch: petal already installed with different capabilities".to_string(),
        ),
        PetalError::ModeConflict { existing } => {
            HandlerError::invalid(format!("mode conflict: existing={existing}"))
        }
        PetalError::ModeUnsupported(s) => HandlerError::invalid(format!("mode unsupported: {s}")),
        PetalError::ChainCall(s) => HandlerError::Backend(format!("chain call: {s}")),
        PetalError::ChainCallTrap { detail, fuel_used } => HandlerError::Backend(format!(
            "chain call trapped after {fuel_used} fuel: {detail}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{Capability, PetalMode};
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    fn setup_with_local() -> (TempDir, PetalsHandler, String) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path().join("store")).unwrap();
        let reg = Arc::new(NameRegistry::open(dir.path().join("reg")).unwrap());
        let mut local_caps = BTreeSet::new();
        local_caps.insert(Capability::VfsRead);
        let (rl, _) = store
            .install(
                b"\x00asm\x01\x00\x00\x00local",
                Some("greet"),
                &local_caps,
                PetalMode::Local,
            )
            .unwrap();
        reg.set("greet", &rl.hash).unwrap();
        let h = PetalsHandler::new(store, reg);
        (dir, h, rl.hash)
    }

    #[tokio::test]
    async fn root_lists_local_and_names() {
        let (_d, h, _) = setup_with_local();
        let entries = h.list(&VfsPath::parse("/").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"local"));
        assert!(names.contains(&"names"));
    }

    #[tokio::test]
    async fn local_subtree_lists_only_local_petals() {
        let (_d, h, local_hash) = setup_with_local();
        let entries = h.list(&VfsPath::parse("/local").unwrap()).await.unwrap();
        let hashes: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            hashes.contains(&local_hash.as_str()),
            "missing local: {hashes:?}"
        );
    }

    #[tokio::test]
    async fn read_wasm_under_correct_mode_subtree() {
        let (_d, h, local_hash) = setup_with_local();
        let p = VfsPath::parse(&format!("/local/{local_hash}/wasm")).unwrap();
        let body = h.read(&p).await.unwrap();
        assert_eq!(body, b"\x00asm\x01\x00\x00\x00local");
    }

    #[tokio::test]
    async fn write_to_names_sets_registry() {
        let (_d, h, local_hash) = setup_with_local();
        let p = VfsPath::parse("/names/anothername").unwrap();
        h.write(&p, local_hash.as_bytes()).await.unwrap();
        assert_eq!(h.registry().lookup("anothername"), Some(local_hash));
    }
}
