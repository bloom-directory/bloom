//! High-level petal install / run, gluing the store, registry, and VM.
//!
//! The runner is the only place that bridges a [`PetalVm`] to a
//! surrounding [`bloom_vfs::Vfs`] — petals reach VFS paths via the
//! host imports we install on the runner's VM.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use bloom_vfs::handler::HandlerError;
use bloom_vfs::path::VfsPath;
use bloom_vfs::{Handler, Vfs};

use crate::error::PetalError;
use crate::host::{HostError, PetalHost};
use crate::meta::{Capability, PetalMeta};
use crate::registry::NameRegistry;
use crate::store::{InstallResult, PetalStore};
use crate::vm::{PetalVm, RunOptions, RunOutput};

/// Wraps an `Arc<Vfs>` so a petal's `bloom.vfs_read`/`vfs_write` calls
/// land on the live VFS (and therefore on the same daemon state the
/// rest of the bloom CLI sees).
pub struct VfsHost {
    vfs: Arc<Vfs>,
}

impl VfsHost {
    pub fn new(vfs: Arc<Vfs>) -> Self {
        Self { vfs }
    }
}

#[async_trait]
impl PetalHost for VfsHost {
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        let path = VfsPath::parse(path).map_err(|e| HostError::Invalid(format!("path: {e}")))?;
        self.vfs.read(&path).await.map_err(host_from_handler)
    }

    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        let path = VfsPath::parse(path).map_err(|e| HostError::Invalid(format!("path: {e}")))?;
        self.vfs
            .write(&path, bytes)
            .await
            .map_err(host_from_handler)
    }
}

fn host_from_handler(e: HandlerError) -> HostError {
    match e {
        HandlerError::NotFound(s) => HostError::NotFound(s),
        HandlerError::NotADir(s) | HandlerError::NotAFile(s) => HostError::Invalid(s),
        HandlerError::PermissionDenied | HandlerError::OperationNotPermitted => {
            HostError::Denied("vfs".into())
        }
        HandlerError::Invalid(s) => HostError::Invalid(s),
        HandlerError::Unsupported(s) => HostError::Backend(format!("unsupported: {s}")),
        HandlerError::Backend(s) => HostError::Backend(s),
        HandlerError::Io(e) => HostError::Backend(format!("io: {e}")),
    }
}

/// Single source of truth for installing and running petals.
#[derive(Clone)]
pub struct PetalRunner {
    store: PetalStore,
    registry: Arc<NameRegistry>,
    vm: PetalVm,
}

impl PetalRunner {
    pub fn new(store: PetalStore, registry: Arc<NameRegistry>, vm: PetalVm) -> Self {
        Self {
            store,
            registry,
            vm,
        }
    }

    pub fn store(&self) -> &PetalStore {
        &self.store
    }

    pub fn registry(&self) -> &Arc<NameRegistry> {
        &self.registry
    }

    /// Install a petal from raw bytes. Accepts either a wasm binary
    /// (starting with `\0asm`) or WAT source — WAT is compiled in
    /// memory before hashing, so the on-disk hash is always the
    /// canonical wasm.
    ///
    /// `(mode, caps)` is validated against [`validate_mode_caps`] before
    /// any bytes are parsed. Re-installing the same hash under a different
    /// mode is rejected with `ModeConflict` by the store.
    pub fn install(
        &self,
        bytes: &[u8],
        name: Option<&str>,
        caps: &BTreeSet<Capability>,
        mode: crate::meta::PetalMode,
    ) -> Result<(InstallResult, PetalMeta), PetalError> {
        crate::meta::validate_mode_caps(mode, caps)?;
        let wasm = if bytes.starts_with(b"\0asm") {
            bytes.to_vec()
        } else {
            // Try WAT.
            let s = std::str::from_utf8(bytes)
                .map_err(|_| PetalError::InvalidWasm("not wasm and not utf-8 WAT".into()))?;
            wat::parse_str(s).map_err(|e| PetalError::InvalidWasm(format!("wat: {e}")))?
        };
        let (result, meta) = self.store.install(&wasm, name, caps, mode)?;
        if let Some(n) = name {
            self.registry.set(n, &result.hash)?;
        }
        Ok((result, meta))
    }

    /// Remove an installed petal and any petname pointing at it.
    /// Returns true if anything was removed.
    pub fn uninstall(&self, hash: &str) -> Result<bool, PetalError> {
        let to_unset: Vec<String> = self
            .registry
            .snapshot()
            .into_iter()
            .filter_map(|(n, h)| if h == hash { Some(n) } else { None })
            .collect();
        let removed = self.store.uninstall(hash)?;
        for n in to_unset {
            self.registry.unset(&n)?;
        }
        Ok(removed)
    }

    /// Resolve a `name_or_hash` to a content hash. Hashes win — if a
    /// caller passes a 64-char hex that happens to be a name, the
    /// hash interpretation is used.
    pub fn resolve(&self, name_or_hash: &str) -> Result<String, PetalError> {
        if crate::store::is_valid_hex_hash(name_or_hash) && self.store.contains(name_or_hash) {
            return Ok(name_or_hash.to_string());
        }
        self.registry
            .lookup(name_or_hash)
            .ok_or_else(|| PetalError::NotFound(name_or_hash.to_string()))
    }

    /// Run a petal by name or hash. The caps used at runtime are the
    /// petal's declared caps, intersected with `cap_mask` if provided
    /// (`None` means "use the petal's declared caps"). Callers that
    /// want to *further restrict* what a petal can do can pass a
    /// narrower mask; they cannot grant capabilities the petal didn't
    /// declare.
    pub async fn run(
        &self,
        name_or_hash: &str,
        stdin: Vec<u8>,
        host: Arc<dyn PetalHost>,
        cap_mask: Option<BTreeSet<Capability>>,
        opts: RunOptions,
    ) -> Result<RunOutput, PetalError> {
        let hash = self.resolve(name_or_hash)?;
        let wasm = self.store.read_wasm(&hash)?;
        let meta = self.store.load_meta(&hash)?;
        let caps = match cap_mask {
            Some(mask) => meta.caps.intersection(&mask).copied().collect(),
            None => meta.caps.clone(),
        };
        self.vm
            .run(&wasm, stdin, caps, host, &hash, meta.mode, opts)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn runner() -> (TempDir, PetalRunner) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path().join("store")).unwrap();
        let reg = Arc::new(NameRegistry::open(dir.path().join("reg")).unwrap());
        let vm = PetalVm::new().unwrap();
        (dir, PetalRunner::new(store, reg, vm))
    }

    const HELLO_WAT: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "hi from petal\n")
          (data (i32.const 32) "\00\00\00\00\0e\00\00\00")
          (func (export "_start")
            (call $fd_write (i32.const 1) (i32.const 32) (i32.const 1) (i32.const 48))
            drop
            (call $exit (i32.const 0)))
        )
    "#;

    #[tokio::test]
    async fn install_from_wat_then_run_by_name() {
        let (_d, r) = runner();
        let (res, _meta) = r
            .install(
                HELLO_WAT.as_bytes(),
                Some("hello"),
                &BTreeSet::new(),
                crate::meta::PetalMode::Local,
            )
            .unwrap();
        // Registry now maps `hello` to the installed hash.
        assert_eq!(r.registry().lookup("hello"), Some(res.hash.clone()));
        let out = r
            .run(
                "hello",
                Vec::new(),
                Arc::new(crate::host::DenyHost),
                None,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, b"hi from petal\n");
    }

    #[tokio::test]
    async fn resolve_prefers_hash_then_name() {
        let (_d, r) = runner();
        let (res, _) = r
            .install(
                HELLO_WAT.as_bytes(),
                Some("aname"),
                &BTreeSet::new(),
                crate::meta::PetalMode::Local,
            )
            .unwrap();
        assert_eq!(r.resolve(&res.hash).unwrap(), res.hash);
        assert_eq!(r.resolve("aname").unwrap(), res.hash);
        assert!(matches!(
            r.resolve("nope").unwrap_err(),
            PetalError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn uninstall_removes_object_meta_and_petname() {
        let (_d, r) = runner();
        let (res, _) = r
            .install(
                HELLO_WAT.as_bytes(),
                Some("byename"),
                &BTreeSet::new(),
                crate::meta::PetalMode::Local,
            )
            .unwrap();
        assert!(r.store().contains(&res.hash));
        assert_eq!(r.registry().lookup("byename"), Some(res.hash.clone()));
        let removed = r.uninstall(&res.hash).unwrap();
        assert!(removed);
        assert!(!r.store().contains(&res.hash));
        assert!(r.registry().lookup("byename").is_none());
    }
}
