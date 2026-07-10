//! Top-level path router. Owns the per-prefix handlers and dispatches.
//!
//! The router optionally wires two cross-cutting concerns:
//!
//! 1. A hash-chained audit log ([`AuditLog`]) — every successful write
//!    appends an `vfs.write` record (with sha256 of the body); every
//!    successful read of a *side-effecting* path (handler-declared via
//!    [`Handler::is_read_side_effecting`]) appends an `vfs.read` record.
//!    Failures are not logged; we err on the side of *fewer* entries to
//!    keep the chain useful.
//! 2. A per-path TTL cache ([`PathCache`]) — handlers opt in via
//!    [`Handler::cache_ttl`]. Reads consult the cache first; writes
//!    invalidate the exact path and the whole top-level prefix.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use bloom_proto::audit::{AuditLog, AuditRecord};

use crate::cache::PathCache;
use crate::handler::{Entry, EntryKind, Handler, HandlerError};
use crate::path::VfsPath;

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
    cache: Option<Arc<PathCache>>,
    root_dynamic: Arc<BTreeMap<String, Arc<RootContentRenderer>>>,
}

type RootContentRenderer = dyn Fn() -> Vec<u8> + Send + Sync;

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

    /// Best-effort audit append. Errors are logged at WARN and dropped —
    /// audit failures must not break user-visible operations.
    fn audit_record(&self, kind: &str, path: &VfsPath, data: serde_json::Value) {
        let Some(log) = &self.audit else {
            return;
        };
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
        if let Err(e) = log.append(record) {
            tracing::warn!(target: "bloom_vfs::audit", error = %e, "audit append failed");
        }
    }

    fn audit_write(&self, path: &VfsPath, body: &[u8]) {
        let sha = bloom_tools::sha256_hex(body);
        self.audit_record(
            AUDIT_KIND_WRITE,
            path,
            serde_json::json!({
                "sha256": sha,
                "size": body.len(),
            }),
        );
    }

    fn audit_side_effecting_read(&self, path: &VfsPath) {
        self.audit_record(AUDIT_KIND_READ, path, serde_json::json!({}));
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
            return Ok(renderer());
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

        let bytes = h.read(&rest).await?;

        // Populate cache if the handler declares a TTL for this path.
        if let (Some(cache), Some(ttl)) = (&self.cache, h.cache_ttl(&rest))
            && !ttl.is_zero()
        {
            cache.put(&key, bytes.clone(), ttl);
        }

        // Side-effecting reads (signing, broadcast triggers, etc) get
        // an audit entry — only on success.
        if h.is_read_side_effecting(&rest) {
            self.audit_side_effecting_read(path);
        }

        Ok(bytes)
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let head = path.first().ok_or(HandlerError::PermissionDenied)?;
        let h = self
            .handlers
            .get(head)
            .ok_or_else(|| HandlerError::NotFound(path.to_string_path()))?;
        let rest = path.shift();
        h.write(&rest, data).await?;

        // Successful write — invalidate cache, then audit. Cache
        // invalidation goes first so a concurrent reader can't observe
        // a stale value with the audit entry already present.
        if let Some(cache) = &self.cache {
            cache.invalidate(&path_to_cache_key(path));
        }
        self.audit_write(path, data);
        Ok(())
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

    pub fn with_root_dynamic(mut self, name: &str, renderer: Arc<RootContentRenderer>) -> Self {
        self.root_dynamic.insert(name.into(), renderer);
        self
    }

    pub fn build(self) -> Vfs {
        Vfs {
            handlers: Arc::new(self.handlers),
            audit: self.audit,
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
        assert!(text.contains("/docs"), "guidance should call out /docs");
        assert!(
            text.contains("bloom vfs"),
            "guidance should mention the bloom vfs CLI"
        );
    }

    #[tokio::test]
    async fn unknown_prefix_not_found() {
        let vfs = Vfs::builder().mount("echo", Arc::new(EchoHandler)).build();
        let r = vfs.lookup(&VfsPath::parse("/nope").unwrap()).await;
        assert!(matches!(r, Err(HandlerError::NotFound(_))));
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
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].kind, AUDIT_KIND_WRITE);
        let details = tail[0].data.get("details").unwrap();
        let sha = details.get("sha256").unwrap().as_str().unwrap();
        assert!(sha.starts_with("0x") && sha.len() == 66, "sha = {sha}");
        assert_eq!(details.get("size").unwrap().as_u64().unwrap(), 5);
        assert_eq!(tail[0].data.get("path").unwrap().as_str().unwrap(), "/k/x");
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
        assert_eq!(log.count().unwrap(), 1, "side-effecting read must audit");
        let tail = log.tail(1).unwrap();
        assert_eq!(tail[0].kind, AUDIT_KIND_READ);
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
    async fn failed_write_does_not_audit() {
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
        assert_eq!(log.count().unwrap(), 0);
    }
}
