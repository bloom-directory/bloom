//! Top-level path router. Owns the per-prefix handlers and dispatches.
//!
//! The router optionally wires two cross-cutting concerns:
//!
//! 1. A service-signed audit log ([`AuditLog`]). Security-effecting reads and
//!    every write persist an exact intent before handler dispatch and a result
//!    afterward. Audit failure is fail-closed and latched; pure reads remain
//!    available.
//! 2. A per-path TTL cache ([`PathCache`]) — handlers opt in via
//!    [`Handler::cache_ttl`]. Reads consult the cache first; writes
//!    invalidate the exact path and the whole top-level prefix.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use bloom_proto::audit::{AuditLog, AuditRecord};

use crate::cache::PathCache;
use crate::handler::{Entry, EntryKind, Handler, HandlerError};
use crate::path::VfsPath;

// This source document is exposed only through the two mount-root aliases below.
const AGENT_GUIDANCE: &[u8] = include_bytes!("docs/agent-guidance.md");
const AGENT_GUIDANCE_FILES: [&str; 2] = ["AGENTS.md", "CLAUDE.md"];

/// Audit `kind` discriminants. Keep these in sync with `docs/AUDIT.md`.
const AUDIT_KIND_WRITE: &str = "vfs.write";
const AUDIT_KIND_READ: &str = "vfs.read";
/// Default actor recorded for in-process callers. The transport layer
/// (NFS / IPC) doesn't yet thread an authenticated identity through;
/// when it does, plumb it via a request-scoped extension.
const AUDIT_ACTOR_LOCAL: &str = "local";

/// The VFS facade. The daemon constructs one [`Vfs`] and registers a
/// handler for each top-level segment.
#[derive(Clone)]
pub struct Vfs {
    handlers: Arc<BTreeMap<String, Arc<dyn Handler>>>,
    audit: Option<Arc<AuditLog>>,
    audit_effect_lock: Arc<tokio::sync::Mutex<()>>,
    cache: Option<Arc<PathCache>>,
    root_dynamic: Arc<BTreeMap<String, Arc<RootContentRenderer>>>,
}

type RootContentFuture = Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'static>>;
type RootContentRenderer = dyn Fn() -> RootContentFuture + Send + Sync;

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(BTreeMap::new()),
            audit: None,
            audit_effect_lock: Arc::new(tokio::sync::Mutex::new(())),
            cache: None,
            root_dynamic: Arc::new(BTreeMap::new()),
        }
    }

    pub fn builder() -> VfsBuilder {
        VfsBuilder::default()
    }

    pub fn handler(&self, name: &str) -> Option<&Arc<dyn Handler>> {
        self.handlers.get(name)
    }

    pub fn top_segments(&self) -> Vec<String> {
        self.handlers.keys().cloned().collect()
    }

    /// Whether an audit log is wired into this router.
    pub fn has_audit(&self) -> bool {
        self.audit.is_some()
    }

    /// Whether a router-level path cache is wired.
    pub fn has_cache(&self) -> bool {
        self.cache.is_some()
    }

    /// Whether reading `path` would have externally-visible side
    /// effects (signing, broadcasting, mutating state). Returns
    /// `false` for paths that fall outside any registered handler —
    /// the safe default.
    ///
    /// The mount adapter consults this from `getattr` to decide
    /// whether it's safe to render content at stat time. A `true`
    /// here means "do NOT render speculatively; let the user's
    /// explicit read trigger the side effect."
    pub fn is_read_side_effecting(&self, path: &VfsPath) -> bool {
        let Some(head) = path.first() else {
            return false;
        };
        let Some(h) = self.handlers.get(head) else {
            return false;
        };
        let rest = path.shift();
        h.is_read_side_effecting(&rest)
    }

    /// Whether `path` is a small asynchronous command sink. Returns false for
    /// unknown paths and ordinary writable files.
    pub fn is_async_write_command(&self, path: &VfsPath) -> bool {
        let Some(head) = path.first() else {
            return false;
        };
        let Some(h) = self.handlers.get(head) else {
            return false;
        };
        h.is_async_write_command(&path.shift())
    }

    fn audit_record(
        &self,
        kind: &str,
        path: &VfsPath,
        data: serde_json::Value,
    ) -> Result<(), HandlerError> {
        let log = self.audit.as_ref().ok_or_else(|| {
            HandlerError::backend("Machine security effect has no configured audit journal")
        })?;
        let record = AuditRecord {
            ts_ms: 0, // overwritten by AuditLog::append
            kind: kind.to_string(),
            wallet: None,
            chain: None,
            data: serde_json::json!({
                "path": path.to_string_path(),
                "actor": AUDIT_ACTOR_LOCAL,
                "details": data,
            }),
            prev: String::new(),
            digest: String::new(),
        };
        log.append(record)
            .map(|_| ())
            .map_err(|error| HandlerError::backend(format!("Machine audit unavailable: {error}")))
    }

    fn begin_effect(
        &self,
        operation: &str,
        path: &VfsPath,
        payload: &[u8],
    ) -> Result<Option<String>, HandlerError> {
        if self.audit.is_none() {
            // Explicit builder-level unit/developer seam. Production Daemon
            // always installs its signed journal.
            return Ok(None);
        }
        let payload_digest = bloom_tools::sha256_hex(payload);
        let operation_id = bloom_tools::sha256_hex(
            format!(
                "bloom-machine-effect/v1\0{operation}\0{}\0{payload_digest}\0{}",
                path.to_string_path(),
                payload.len()
            )
            .as_bytes(),
        );
        let sequence = self
            .audit
            .as_ref()
            .map(|audit| audit.sequence() + 1)
            .unwrap_or(0);
        let correlation_id = format!("{operation_id}:{sequence}");
        self.audit_record(
            "machine.effect.intent",
            path,
            serde_json::json!({
                "operation": operation,
                "operation_id": operation_id,
                "correlation_id": correlation_id,
                "payload_sha256": payload_digest,
                "payload_size": payload.len(),
            }),
        )?;
        Ok(Some(correlation_id))
    }

    fn finish_effect(
        &self,
        operation: &str,
        path: &VfsPath,
        correlation_id: Option<&str>,
        outcome: &str,
        result: serde_json::Value,
    ) -> Result<(), HandlerError> {
        let Some(correlation_id) = correlation_id else {
            return Ok(());
        };
        self.audit_record(
            "machine.effect.result",
            path,
            serde_json::json!({
                "operation": operation,
                "correlation_id": correlation_id,
                "outcome": outcome,
                "result": result,
            }),
        )
    }

    /// Read `path` pinned to a historical block. This bypasses the router-level
    /// latest-state cache and only succeeds for handlers that explicitly
    /// implement historical reads.
    pub async fn read_at_block(&self, path: &VfsPath, block: u64) -> Result<Vec<u8>, HandlerError> {
        let head = path
            .first()
            .ok_or_else(|| HandlerError::NotAFile(path.to_string_path()))?;
        let h = self
            .handlers
            .get(head)
            .ok_or_else(|| HandlerError::NotFound(path.to_string_path()))?;
        let rest = path.shift();
        h.read_at_block(&rest, block).await
    }

    async fn write_under_mutation_gate(
        &self,
        path: &VfsPath,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        let head = path.first().ok_or(HandlerError::PermissionDenied)?;
        let h = self
            .handlers
            .get(head)
            .ok_or_else(|| HandlerError::NotFound(path.to_string_path()))?;
        let rest = path.shift();
        let correlation = self.begin_effect(AUDIT_KIND_WRITE, path, data)?;
        let write_result = h.write(&rest, data).await;
        match &write_result {
            Ok(()) => self.finish_effect(
                AUDIT_KIND_WRITE,
                path,
                correlation.as_deref(),
                "ok",
                serde_json::json!({}),
            )?,
            Err(error) => self.finish_effect(
                AUDIT_KIND_WRITE,
                path,
                correlation.as_deref(),
                "error",
                serde_json::json!({"error": error.to_string()}),
            )?,
        }
        write_result?;
        if let Some(cache) = &self.cache {
            cache.invalidate(&path_to_cache_key(path));
        }
        Ok(())
    }

    /// Write and capture its identity projection while excluding every other
    /// write through this VFS, including mounted and IPC writes.
    pub async fn write_then_lookup(
        &self,
        write_path: &VfsPath,
        data: &[u8],
        projection_path: &VfsPath,
    ) -> Result<Entry, HandlerError> {
        let _mutation_guard = self.audit_effect_lock.lock().await;
        self.write_under_mutation_gate(write_path, data).await?;
        Handler::lookup(self, projection_path).await
    }
}

fn root_agent_guidance_entry(path: &VfsPath) -> Option<&'static str> {
    match path.segments() {
        [name] => AGENT_GUIDANCE_FILES
            .iter()
            .copied()
            .find(|candidate| candidate == &name.as_str()),
        _ => None,
    }
}

fn root_dynamic_entry<'a>(
    path: &VfsPath,
    map: &'a BTreeMap<String, Arc<RootContentRenderer>>,
) -> Option<&'a str> {
    match path.segments() {
        [name] => map.get_key_value(name).map(|(k, _)| k.as_str()),
        _ => None,
    }
}

fn root_dynamic_renderer<'a>(
    path: &VfsPath,
    map: &'a BTreeMap<String, Arc<RootContentRenderer>>,
) -> Option<&'a Arc<RootContentRenderer>> {
    match path.segments() {
        [name] => map.get(name),
        _ => None,
    }
}

#[async_trait]
impl Handler for Vfs {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        if path.is_root() {
            return Ok(Entry::dir(""));
        }
        if let Some(name) = root_agent_guidance_entry(path) {
            let mut entry = Entry::file(name);
            entry.size = AGENT_GUIDANCE.len() as u64;
            return Ok(entry);
        }
        if let Some(name) = root_dynamic_entry(path, &self.root_dynamic) {
            return Ok(Entry::file(name));
        }
        let head = path.first().unwrap();
        let h = self
            .handlers
            .get(head)
            .ok_or_else(|| HandlerError::NotFound(path.to_string_path()))?;
        let rest = path.shift();
        if rest.is_root() {
            return Ok(Entry::dir(head));
        }
        h.lookup(&rest).await
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        if root_agent_guidance_entry(path).is_some() {
            return Ok(AGENT_GUIDANCE.to_vec());
        }
        if let Some(renderer) = root_dynamic_renderer(path, &self.root_dynamic) {
            return Ok(renderer().await);
        }
        let head = path
            .first()
            .ok_or_else(|| HandlerError::NotAFile(path.to_string_path()))?;
        let h = self
            .handlers
            .get(head)
            .ok_or_else(|| HandlerError::NotFound(path.to_string_path()))?;
        let rest = path.shift();

        // Cache fast path. We key on the *full* VFS path (including the
        // top segment) so collisions across handlers are impossible.
        let key = path_to_cache_key(path);
        if let Some(cache) = &self.cache
            && let Some(bytes) = cache.get(&key)
        {
            return Ok(bytes);
        }

        let side_effecting = h.is_read_side_effecting(&rest);
        let _audit_guard = if side_effecting {
            Some(self.audit_effect_lock.lock().await)
        } else {
            None
        };
        let correlation = if side_effecting {
            self.begin_effect(AUDIT_KIND_READ, path, &[])?
        } else {
            None
        };
        let read_result = h.read(&rest).await;
        if correlation.is_some() {
            match &read_result {
                Ok(bytes) => self.finish_effect(
                    AUDIT_KIND_READ,
                    path,
                    correlation.as_deref(),
                    "ok",
                    serde_json::json!({
                        "sha256": bloom_tools::sha256_hex(bytes),
                        "size": bytes.len(),
                    }),
                )?,
                Err(error) => self.finish_effect(
                    AUDIT_KIND_READ,
                    path,
                    correlation.as_deref(),
                    "error",
                    serde_json::json!({"error": error.to_string()}),
                )?,
            }
        }
        let bytes = read_result?;

        // Populate cache if the handler declares a TTL for this path.
        if let (Some(cache), Some(ttl)) = (&self.cache, h.cache_ttl(&rest))
            && !ttl.is_zero()
        {
            cache.put(&key, bytes.clone(), ttl);
        }

        Ok(bytes)
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let _mutation_guard = self.audit_effect_lock.lock().await;
        self.write_under_mutation_gate(path, data).await
    }

    async fn prepare_write_open(&self, path: &VfsPath) -> Result<(), HandlerError> {
        let head = path.first().ok_or(HandlerError::PermissionDenied)?;
        let h = self
            .handlers
            .get(head)
            .ok_or_else(|| HandlerError::NotFound(path.to_string_path()))?;
        let rest = path.shift();
        h.prepare_write_open(&rest).await
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if path.is_root() {
            let mut out = Vec::new();
            for name in AGENT_GUIDANCE_FILES {
                let mut entry = Entry::file(name);
                entry.size = AGENT_GUIDANCE.len() as u64;
                out.push(entry);
            }
            for name in self.handlers.keys() {
                out.push(Entry::dir(name));
            }
            for name in self.root_dynamic.keys() {
                out.push(Entry::file(name));
            }
            return Ok(out);
        }
        let head = path.first().unwrap();
        let h = self
            .handlers
            .get(head)
            .ok_or_else(|| HandlerError::NotFound(path.to_string_path()))?;
        let rest = path.shift();
        let entries = h.list(&rest).await?;
        Ok(entries)
    }
}

#[derive(Default)]
pub struct VfsBuilder {
    handlers: BTreeMap<String, Arc<dyn Handler>>,
    audit: Option<Arc<AuditLog>>,
    audit_effect_lock: Arc<tokio::sync::Mutex<()>>,
    cache: Option<Arc<PathCache>>,
    root_dynamic: BTreeMap<String, Arc<RootContentRenderer>>,
}

impl VfsBuilder {
    pub fn mount(mut self, prefix: &str, handler: Arc<dyn Handler>) -> Self {
        self.handlers.insert(prefix.into(), handler);
        self
    }

    /// Wire a hash-chained audit log into the router. Without this,
    /// writes and side-effecting reads run unaudited (back-compat for
    /// tests that don't care).
    pub fn with_audit(mut self, audit: Arc<AuditLog>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Wire a router-level path cache. Without this, every read goes
    /// straight to the handler (the original behaviour).
    pub fn with_cache(mut self, cache: Arc<PathCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_root_dynamic(
        self,
        name: &str,
        renderer: Arc<dyn Fn() -> Vec<u8> + Send + Sync>,
    ) -> Self {
        self.with_root_dynamic_async(name, move || std::future::ready(renderer()))
    }

    pub fn with_root_dynamic_async<F, Fut>(mut self, name: &str, renderer: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Vec<u8>> + Send + 'static,
    {
        self.root_dynamic
            .insert(name.into(), Arc::new(move || Box::pin(renderer())));
        self
    }

    pub fn build(self) -> Vfs {
        Vfs {
            handlers: Arc::new(self.handlers),
            audit: self.audit,
            audit_effect_lock: self.audit_effect_lock,
            cache: self.cache,
            root_dynamic: Arc::new(self.root_dynamic),
        }
    }
}

/// Build a stable cache key from a [`VfsPath`]. We strip the leading
/// `/` so keys agree with `path.segments().join("/")`; that makes the
/// `PathCache::invalidate` prefix-match logic correct.
fn path_to_cache_key(path: &VfsPath) -> String {
    path.segments().join("/")
}

/// Convenience: render a value as an `ls -l`-style metadata line.
pub fn entry_size(e: &Entry) -> u64 {
    e.size
}

/// Convenience: classify entry as dir.
pub fn is_dir(e: &Entry) -> bool {
    e.kind == EntryKind::Dir
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::Entry;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::{Mutex, Notify};

    struct EchoHandler;

    #[async_trait]
    impl Handler for EchoHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            if p.is_root() {
                Ok(Entry::dir(""))
            } else if p.segments().last().map(|s| s.as_str()) == Some("hello") {
                Ok(Entry::file("hello"))
            } else {
                Err(HandlerError::NotFound(p.to_string_path()))
            }
        }
        async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            Ok(b"world\n".to_vec())
        }
        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![Entry::file("hello")])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
    }

    struct AtomicProjectionHandler {
        latest: Mutex<String>,
        lookup_started: Notify,
        release_lookup: Notify,
    }

    #[async_trait]
    impl Handler for AtomicProjectionHandler {
        async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
            if path.to_string_path() != "/latest" {
                return Err(HandlerError::NotFound(path.to_string_path()));
            }
            self.lookup_started.notify_one();
            self.release_lookup.notified().await;
            let latest = self.latest.lock().await.clone();
            Ok(Entry::symlink("latest", &latest))
        }

        async fn write(&self, _path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
            *self.latest.lock().await = String::from_utf8(data.to_vec()).unwrap();
            Ok(())
        }
    }

    #[tokio::test]
    async fn write_then_lookup_excludes_direct_vfs_writes_until_identity_is_captured() {
        let handler = Arc::new(AtomicProjectionHandler {
            latest: Mutex::new(String::new()),
            lookup_started: Notify::new(),
            release_lookup: Notify::new(),
        });
        let vfs = Vfs::builder().mount("ids", handler.clone()).build();
        let atomic_vfs = vfs.clone();
        let atomic = tokio::spawn(async move {
            atomic_vfs
                .write_then_lookup(
                    &VfsPath::parse("/ids/new").unwrap(),
                    b"atomic",
                    &VfsPath::parse("/ids/latest").unwrap(),
                )
                .await
                .unwrap()
        });

        handler.lookup_started.notified().await;
        let ordinary_vfs = vfs.clone();
        let ordinary = tokio::spawn(async move {
            ordinary_vfs
                .write(&VfsPath::parse("/ids/new").unwrap(), b"ordinary")
                .await
                .unwrap();
        });
        tokio::task::yield_now().await;
        handler.release_lookup.notify_one();

        let identity = atomic.await.unwrap();
        ordinary.await.unwrap();
        assert_eq!(identity.link_target.as_deref(), Some("atomic"));
        assert_eq!(&*handler.latest.lock().await, "ordinary");
    }

    #[tokio::test]
    async fn dispatches_to_handler() {
        let vfs = Vfs::builder().mount("echo", Arc::new(EchoHandler)).build();
        let p = VfsPath::parse("/echo/hello").unwrap();
        let e = vfs.lookup(&p).await.unwrap();
        assert_eq!(e.kind, EntryKind::File);
        let body = vfs.read(&p).await.unwrap();
        assert_eq!(body, b"world\n");
    }

    #[tokio::test]
    async fn root_lists_top_segments() {
        let vfs = Vfs::builder().mount("echo", Arc::new(EchoHandler)).build();
        let entries = vfs.list(&VfsPath::root()).await.unwrap();
        assert!(
            entries
                .iter()
                .any(|e| e.name == "echo" && e.kind == EntryKind::Dir),
            "entries={entries:?}"
        );
    }

    #[tokio::test]
    async fn root_lists_agent_guidance_files() {
        let vfs = Vfs::builder().mount("echo", Arc::new(EchoHandler)).build();
        let entries = vfs.list(&VfsPath::root()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();

        assert!(names.contains(&"AGENTS.md"), "names={names:?}");
        assert!(names.contains(&"CLAUDE.md"), "names={names:?}");

        for name in ["AGENTS.md", "CLAUDE.md"] {
            let entry = entries.iter().find(|e| e.name == name).unwrap();
            assert_eq!(entry.kind, EntryKind::File);
            assert_eq!(entry.mode, 0o444);
        }
    }

    #[tokio::test]
    async fn root_agent_guidance_files_are_identical_to_markdown_source() {
        let vfs = Vfs::builder().mount("echo", Arc::new(EchoHandler)).build();
        let expected_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/docs/agent-guidance.md");
        let expected = std::fs::read(&expected_path).expect("raw agent guidance markdown exists");

        let agents = vfs
            .read(&VfsPath::parse("/AGENTS.md").unwrap())
            .await
            .unwrap();
        let claude = vfs
            .read(&VfsPath::parse("/CLAUDE.md").unwrap())
            .await
            .unwrap();

        assert_eq!(agents, expected);
        assert_eq!(claude, expected);
        let text = std::str::from_utf8(&agents).expect("guidance is utf-8");
        assert!(
            text.contains("cat docs/README.md"),
            "guidance should use mounted filesystem examples"
        );
        assert!(
            !text.contains("bloom vfs"),
            "guidance should not mention the bloom vfs CLI"
        );
        // Documentation assertion (plan:
        // docs/plans/2026-07-21-async-vfs-passkey-registration.md): agent
        // guidance must describe asynchronous passkey registration.
        assert!(
            text.contains("wallets/registrations/") && text.contains("status.json"),
            "guidance must document wallets/registrations/<name>/status.json"
        );
        assert!(
            text.contains("does not create a local wallet")
                || text.contains("does NOT create a local wallet"),
            "guidance must explicitly say a plain /wallets/new write does not create a local wallet"
        );
        assert!(
            text.contains("wallets/<wallet>/policy.json")
                && text.contains("policy.validate_update")
                && text.contains("policy.commit_update")
                && text.contains("exact same proposed bytes"),
            "guidance must document the canonical mounted triad policy-update flow"
        );
        for stale in ["policy.toml", "host signer", "the grant", "a grant"] {
            assert!(
                !text.contains(stale),
                "guidance retains stale Machine-authority vocabulary {stale:?}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_prefix_not_found() {
        let vfs = Vfs::builder().mount("echo", Arc::new(EchoHandler)).build();
        let r = vfs.lookup(&VfsPath::parse("/nope").unwrap()).await;
        assert!(matches!(r, Err(HandlerError::NotFound(_))));
    }

    #[tokio::test]
    async fn root_dynamic_renderer_preserves_synchronous_builder_api() {
        let renderer: Arc<dyn Fn() -> Vec<u8> + Send + Sync> =
            Arc::new(|| b"synchronous root content".to_vec());
        let vfs = Vfs::builder()
            .with_root_dynamic("dynamic.md", renderer)
            .build();

        let body = vfs
            .read(&VfsPath::parse("/dynamic.md").unwrap())
            .await
            .unwrap();

        assert_eq!(body, b"synchronous root content");
    }

    #[tokio::test]
    async fn root_dynamic_renderer_awaits_async_content() {
        let rendered = Arc::new(AtomicUsize::new(0));
        let rendered_by_source = rendered.clone();
        let vfs = Vfs::builder()
            .with_root_dynamic_async("dynamic.md", move || {
                let rendered = rendered_by_source.clone();
                async move {
                    tokio::task::yield_now().await;
                    rendered.fetch_add(1, Ordering::SeqCst);
                    b"async root content".to_vec()
                }
            })
            .build();

        let body = vfs
            .read(&VfsPath::parse("/dynamic.md").unwrap())
            .await
            .unwrap();

        assert_eq!(body, b"async root content");
        assert_eq!(rendered.load(Ordering::SeqCst), 1);
    }

    /// Handler that counts calls so we can prove the cache is short-
    /// circuiting reads, and supports a writable file at `/wkv/<key>`.
    struct CountingHandler {
        ttl: Option<Duration>,
        side_effecting_read: bool,
        reads: AtomicUsize,
        writes: AtomicUsize,
    }

    impl CountingHandler {
        fn new(ttl: Option<Duration>) -> Self {
            Self {
                ttl,
                side_effecting_read: false,
                reads: AtomicUsize::new(0),
                writes: AtomicUsize::new(0),
            }
        }
        fn with_side_effecting_read(mut self) -> Self {
            self.side_effecting_read = true;
            self
        }
    }

    #[async_trait]
    impl Handler for CountingHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            Ok(Entry::writable_file(
                p.segments().last().map(|s| s.as_str()).unwrap_or(""),
            ))
        }
        async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            let n = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(format!("body-{n}").into_bytes())
        }
        async fn write(&self, _p: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn cache_ttl(&self, _p: &VfsPath) -> Option<Duration> {
            self.ttl
        }
        fn is_read_side_effecting(&self, _p: &VfsPath) -> bool {
            self.side_effecting_read
        }
    }

    #[tokio::test]
    async fn cache_hit_returns_cached_value_within_ttl() {
        let h = Arc::new(CountingHandler::new(Some(Duration::from_secs(60))));
        let cache = Arc::new(PathCache::new());
        let vfs = Vfs::builder()
            .mount("k", h.clone())
            .with_cache(cache.clone())
            .build();
        let p = VfsPath::parse("/k/x").unwrap();
        let a = vfs.read(&p).await.unwrap();
        let b = vfs.read(&p).await.unwrap();
        assert_eq!(a, b, "cache should return identical body");
        assert_eq!(
            h.reads.load(Ordering::SeqCst),
            1,
            "second read must hit cache"
        );
    }

    #[tokio::test]
    async fn cache_expiry_refetches() {
        let h = Arc::new(CountingHandler::new(Some(Duration::from_millis(30))));
        let cache = Arc::new(PathCache::new());
        let vfs = Vfs::builder()
            .mount("k", h.clone())
            .with_cache(cache)
            .build();
        let p = VfsPath::parse("/k/x").unwrap();
        let _ = vfs.read(&p).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let _ = vfs.read(&p).await.unwrap();
        assert_eq!(h.reads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn write_invalidates_same_prefix() {
        let h = Arc::new(CountingHandler::new(Some(Duration::from_secs(60))));
        let cache = Arc::new(PathCache::new());
        let vfs = Vfs::builder()
            .mount("k", h.clone())
            .with_cache(cache)
            .build();
        let pa = VfsPath::parse("/k/a").unwrap();
        let pb = VfsPath::parse("/k/b").unwrap();
        let _ = vfs.read(&pa).await.unwrap();
        let _ = vfs.read(&pb).await.unwrap();
        assert_eq!(h.reads.load(Ordering::SeqCst), 2);

        // Both `a` and `b` are now cached. Writing to `b` should also
        // invalidate `a` because they share the `k` top-level prefix.
        vfs.write(&pb, b"new").await.unwrap();
        let _ = vfs.read(&pa).await.unwrap();
        assert_eq!(
            h.reads.load(Ordering::SeqCst),
            3,
            "write should evict siblings"
        );
    }

    #[tokio::test]
    async fn write_appends_audit_record() {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let h = Arc::new(CountingHandler::new(None));
        let vfs = Vfs::builder().mount("k", h).with_audit(log.clone()).build();
        let p = VfsPath::parse("/k/x").unwrap();
        vfs.write(&p, b"hello").await.unwrap();
        let tail = log.tail(10).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].kind, "machine.effect.intent");
        assert_eq!(tail[1].kind, "machine.effect.result");
        let details = tail[0].data.get("details").unwrap();
        assert_eq!(details["operation"], AUDIT_KIND_WRITE);
        let sha = details.get("payload_sha256").unwrap().as_str().unwrap();
        assert!(sha.starts_with("0x") && sha.len() == 66, "sha = {sha}");
        assert_eq!(details.get("payload_size").unwrap().as_u64().unwrap(), 5);
        assert_eq!(tail[0].data.get("path").unwrap().as_str().unwrap(), "/k/x");
        assert_eq!(
            tail[0].data["details"]["correlation_id"],
            tail[1].data["details"]["correlation_id"]
        );
    }

    #[tokio::test]
    async fn pure_read_does_not_audit_but_side_effecting_does() {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let pure = Arc::new(CountingHandler::new(None));
        let signing = Arc::new(CountingHandler::new(None).with_side_effecting_read());
        let vfs = Vfs::builder()
            .mount("pure", pure)
            .mount("sign", signing)
            .with_audit(log.clone())
            .build();
        vfs.read(&VfsPath::parse("/pure/x").unwrap()).await.unwrap();
        assert_eq!(log.count().unwrap(), 0, "pure read must not audit");
        vfs.read(&VfsPath::parse("/sign/x").unwrap()).await.unwrap();
        assert_eq!(log.count().unwrap(), 2, "side-effecting read must audit");
        let tail = log.tail(2).unwrap();
        assert_eq!(tail[0].kind, "machine.effect.intent");
        assert_eq!(tail[0].data["details"]["operation"], AUDIT_KIND_READ);
        assert_eq!(
            tail[0].data.get("path").unwrap().as_str().unwrap(),
            "/sign/x"
        );
    }

    #[tokio::test]
    async fn audit_chain_detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = Arc::new(AuditLog::open(&path).unwrap());
        let h = Arc::new(CountingHandler::new(None));
        let vfs = Vfs::builder().mount("k", h).with_audit(log).build();
        for body in ["a", "b", "c"] {
            vfs.write(&VfsPath::parse("/k/x").unwrap(), body.as_bytes())
                .await
                .unwrap();
        }
        AuditLog::verify(&path).expect("clean chain verifies");
        // Now tamper with line 1.
        let s = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = s.lines().collect();
        let mut rec: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        rec.kind = "evil".into();
        let new_first = serde_json::to_string(&rec).unwrap();
        lines[0] = &new_first;
        let body = lines.join("\n") + "\n";
        std::fs::write(&path, body).unwrap();
        assert!(AuditLog::verify(&path).is_err());
    }

    #[tokio::test]
    async fn failed_write_records_intent_and_error_result() {
        struct Failing;
        #[async_trait]
        impl Handler for Failing {
            async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
                Ok(Entry::writable_file(p.to_string_path().as_str()))
            }
            async fn write(&self, _p: &VfsPath, _d: &[u8]) -> Result<(), HandlerError> {
                Err(HandlerError::PermissionDenied)
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let vfs = Vfs::builder()
            .mount("k", Arc::new(Failing))
            .with_audit(log.clone())
            .build();
        let _ = vfs
            .write(&VfsPath::parse("/k/x").unwrap(), b"oops")
            .await
            .unwrap_err();
        assert_eq!(log.count().unwrap(), 2);
        let tail = log.tail(2).unwrap();
        assert_eq!(tail[1].data["details"]["outcome"], "error");
    }

    #[tokio::test]
    async fn audit_intent_failure_prevents_handler_dispatch_and_latches() {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let handler = Arc::new(CountingHandler::new(None));
        let vfs = Vfs::builder()
            .mount("k", handler.clone())
            .with_audit(log.clone())
            .build();
        log.fail_next_write_for_test();
        let error = vfs
            .write(&VfsPath::parse("/k/x").unwrap(), b"must-not-dispatch")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("audit"));
        assert_eq!(handler.writes.load(Ordering::SeqCst), 0);
        assert_eq!(log.count().unwrap(), 0);
        assert!(log.mutation_degradation().is_some());
    }

    #[tokio::test]
    async fn concurrent_vfs_and_petal_network_effects_do_not_self_latch() {
        struct PausingHandler {
            entered: Arc<tokio::sync::Notify>,
            release: Arc<tokio::sync::Notify>,
        }
        #[async_trait]
        impl Handler for PausingHandler {
            async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
                Ok(Entry::writable_file(path.to_string_path().as_str()))
            }
            async fn write(&self, _path: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let vfs = Vfs::builder()
            .mount(
                "k",
                Arc::new(PausingHandler {
                    entered: entered.clone(),
                    release: release.clone(),
                }),
            )
            .with_audit(log.clone())
            .build();
        let write = tokio::spawn(async move {
            vfs.write(&VfsPath::parse("/k/x").unwrap(), b"vfs-effect")
                .await
        });
        entered.notified().await;

        log.append(AuditRecord {
            ts_ms: 0,
            kind: "machine.effect.intent".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({
                "operation":"petal.http_fetch",
                "correlation_id":"petal-network:1"
            }),
            prev: String::new(),
            digest: String::new(),
        })
        .unwrap();
        log.append(AuditRecord {
            ts_ms: 0,
            kind: "machine.effect.result".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({
                "operation":"petal.http_fetch",
                "correlation_id":"petal-network:1",
                "outcome":"ok"
            }),
            prev: String::new(),
            digest: String::new(),
        })
        .unwrap();
        release.notify_one();
        write.await.unwrap().unwrap();
        assert!(log.mutation_degradation().is_none());
        assert!(log.pending_effect_correlations().unwrap().is_empty());
        assert_eq!(log.count().unwrap(), 4);
    }
}
