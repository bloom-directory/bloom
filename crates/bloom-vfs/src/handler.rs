//! The Handler trait — every top-level subtree implements it.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use thiserror::Error;

use crate::path::VfsPath;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File,
    Symlink,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    /// File size hint (best-effort; may be 0 for synthetic files).
    pub size: u64,
    /// Posix mode bits (just informational; the mount layer decides
    /// the real mode).
    pub mode: u32,
    /// For symlinks, the target.
    pub link_target: Option<String>,
    /// Optional artifact modification time. Mount adapters surface this as
    /// mtime/ctime/atime when a handler knows the backing artifact time.
    pub modified: Option<SystemTime>,
}

impl Entry {
    pub fn dir(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::Dir,
            size: 0,
            mode: 0o755,
            link_target: None,
            modified: None,
        }
    }
    /// Build a read-only file entry (mode 0o444). This is the right
    /// default for almost everything in the bloom tree — chain
    /// views, status, tools output, prices, docs, audit views, wallet
    /// metadata files, watch outputs. Per the v1 spec only a small set
    /// of injection points (wallets/new, sign/*, outbox writes,
    /// watch/new, defi intents new+confirm, policy.json) are writable;
    /// those should use [`Entry::writable_file`].
    pub fn file(name: &str) -> Self {
        Self::read_only_file(name)
    }
    /// Explicit read-only constructor. Equivalent to [`Entry::file`];
    /// prefer this name in handlers that mix read-only and writable
    /// entries side-by-side so the intent is loud at the call site.
    pub fn read_only_file(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::File,
            size: 0,
            mode: 0o444,
            link_target: None,
            modified: None,
        }
    }
    /// Build a writable file entry (mode 0o644). Use for the small set
    /// of NFS-injectable inputs the daemon accepts.
    pub fn writable_file(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::File,
            size: 0,
            mode: 0o644,
            link_target: None,
            modified: None,
        }
    }
    /// Build an executable read-only file entry (mode 0o555). This is used
    /// for command shims whose content is readable but whose primary affordance
    /// is `execve`.
    pub fn executable_file(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::File,
            size: 0,
            mode: 0o555,
            link_target: None,
            modified: None,
        }
    }
    pub fn symlink(name: &str, target: &str) -> Self {
        Self {
            name: name.into(),
            kind: EntryKind::Symlink,
            size: 0,
            mode: 0o777,
            link_target: Some(target.into()),
            modified: None,
        }
    }

    pub fn with_modified(mut self, modified: SystemTime) -> Self {
        self.modified = Some(modified);
        self
    }

    pub fn with_size(mut self, size: u64) -> Self {
        if self.kind == EntryKind::File {
            self.size = size;
        }
        self
    }

    pub fn with_modified_ms(self, modified_ms: u128) -> Self {
        if modified_ms > u64::MAX as u128 {
            return self;
        }
        self.with_modified(SystemTime::UNIX_EPOCH + Duration::from_millis(modified_ms as u64))
    }

    pub fn with_fs_metadata(mut self, metadata: &fs::Metadata) -> Self {
        if self.kind == EntryKind::File {
            self.size = metadata.len();
        }
        if let Ok(modified) = metadata.modified() {
            self.modified = Some(modified);
        }
        self
    }
}

pub fn entry_from_fs_metadata(name: &str, kind: EntryKind, metadata: &fs::Metadata) -> Entry {
    match kind {
        EntryKind::Dir => Entry::dir(name),
        EntryKind::File => Entry::file(name),
        EntryKind::Symlink => Entry::symlink(name, ""),
    }
    .with_fs_metadata(metadata)
}

pub fn entry_for_fs_path(
    path: impl AsRef<Path>,
    name: &str,
    kind: EntryKind,
) -> Result<Entry, HandlerError> {
    // A missing backing artifact must surface as NotFound (ENOENT on
    // mounts), not Io (EIO): clients treat EIO as a server fault.
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(HandlerError::NotFound(name.to_string()));
        }
        Err(err) => return Err(err.into()),
    };
    Ok(entry_from_fs_metadata(name, kind, &metadata))
}

pub fn entry_from_fs_dir_entry(
    dir_entry: &fs::DirEntry,
    name: &str,
    kind: EntryKind,
) -> Result<Entry, HandlerError> {
    let metadata = dir_entry.metadata()?;
    Ok(entry_from_fs_metadata(name, kind, &metadata))
}

pub fn fs_path_modified(path: impl AsRef<Path>) -> Result<Option<SystemTime>, HandlerError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.modified().ok()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("not a directory: {0}")]
    NotADir(String),
    #[error("not a file: {0}")]
    NotAFile(String),
    #[error("permission denied")]
    PermissionDenied,
    #[error("operation not permitted")]
    OperationNotPermitted,
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("backend: {0}")]
    Backend(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl HandlerError {
    pub fn invalid(s: impl Into<String>) -> Self {
        HandlerError::Invalid(s.into())
    }
    pub fn backend(s: impl Into<String>) -> Self {
        HandlerError::Backend(s.into())
    }
    pub fn not_found(s: impl Into<String>) -> Self {
        HandlerError::NotFound(s.into())
    }
}

/// One handler per top-level subtree (`chains/`, `wallets/`, etc).
///
/// Path semantics: the `path` passed in is the *suffix* under the
/// handler's mount segment, e.g. for `chains/ethereum/head/number` the
/// `chains` handler receives `ethereum/head/number`.
#[async_trait]
pub trait Handler: Send + Sync {
    /// Return the kind / metadata for this path (or NotFound).
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError>;

    /// Return the bytes for a regular file. Default: NotAFile.
    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        Err(HandlerError::NotAFile(path.to_string_path()))
    }

    /// Return bytes for a regular file pinned to `block`.
    ///
    /// Only handlers with an explicit historical backend should override this.
    /// The default is intentionally unsupported rather than delegating to
    /// `read`, so callers that need a pinned view do not silently read latest
    /// state.
    async fn read_at_block(&self, path: &VfsPath, block: u64) -> Result<Vec<u8>, HandlerError> {
        let _ = block;
        Err(HandlerError::Unsupported(path.to_string_path()))
    }

    /// Handle a write to a writable file. Default: read-only.
    async fn write(&self, path: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
        let _ = path;
        Err(HandlerError::PermissionDenied)
    }

    /// Prepare for a write-open before any bytes are accepted by the mount.
    ///
    /// Handlers that need user-visible failures for shell redirects should
    /// perform path-derived authorization here and return `PermissionDenied`
    /// after staging any challenge artifacts. The default allows the open and
    /// leaves enforcement to `write`.
    async fn prepare_write_open(&self, path: &VfsPath) -> Result<(), HandlerError> {
        let _ = path;
        Ok(())
    }

    /// List directory children. Default: NotADir.
    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        Err(HandlerError::NotADir(path.to_string_path()))
    }

    /// Optional per-path TTL for the router-level read cache. `None`
    /// (default) means "never cache at the router". Handlers backing
    /// volatile or RPC-heavy paths should return a small `Duration`
    /// here (e.g. 1s for chain head, 30s for etherscan-backed reads).
    fn cache_ttl(&self, path: &VfsPath) -> Option<Duration> {
        let _ = path;
        None
    }

    /// Whether a successful read of `path` has externally-visible side
    /// effects worth recording in the audit log (signing, broadcast,
    /// etc). Default: pure-data reads, no audit entry. Handlers that
    /// emit signatures, perform broadcasts, or otherwise mutate state
    /// in response to reads should override this and return `true`.
    fn is_read_side_effecting(&self, path: &VfsPath) -> bool {
        let _ = path;
        false
    }

    /// Whether `path` is a small asynchronous command sink whose payload is
    /// submitted as one complete write. The mount adapter accepts the NFS write
    /// immediately and runs the command away from the request path; callers
    /// observe its outcome through status projections.
    fn is_async_write_command(&self, path: &VfsPath) -> bool {
        let _ = path;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_constructor_defaults() {
        let e = Entry::dir("chains");
        assert_eq!(e.name, "chains");
        assert_eq!(e.kind, EntryKind::Dir);
        assert_eq!(e.size, 0);
        assert_eq!(e.mode, 0o755);
        assert!(e.link_target.is_none());
        assert!(e.modified.is_none());
    }

    #[test]
    fn file_is_read_only_alias() {
        let a = Entry::file("README.md");
        let b = Entry::read_only_file("README.md");
        assert_eq!(a.name, b.name);
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.mode, b.mode);
        assert_eq!(a.size, b.size);
        assert_eq!(a.link_target, b.link_target);
        assert_eq!(a.modified, b.modified);
    }

    #[test]
    fn read_only_file_defaults() {
        let e = Entry::read_only_file("status.json");
        assert_eq!(e.name, "status.json");
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size, 0);
        assert_eq!(e.mode, 0o444);
        assert!(e.link_target.is_none());
        assert!(e.modified.is_none());
    }

    #[test]
    fn writable_file_defaults() {
        let e = Entry::writable_file("policy.json");
        assert_eq!(e.name, "policy.json");
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size, 0);
        assert_eq!(e.mode, 0o644);
        assert!(e.link_target.is_none());
        assert!(e.modified.is_none());
    }

    #[test]
    fn executable_file_defaults() {
        let e = Entry::executable_file("quote");
        assert_eq!(e.name, "quote");
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size, 0);
        assert_eq!(e.mode, 0o555);
        assert!(e.link_target.is_none());
        assert!(e.modified.is_none());
    }

    #[test]
    fn symlink_records_target() {
        let e = Entry::symlink("default", "../ethereum");
        assert_eq!(e.name, "default");
        assert_eq!(e.kind, EntryKind::Symlink);
        assert_eq!(e.size, 0);
        assert_eq!(e.mode, 0o777);
        assert_eq!(e.link_target.as_deref(), Some("../ethereum"));
        assert!(e.modified.is_none());
    }

    #[test]
    fn with_modified_records_artifact_time() {
        let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(123);
        let e = Entry::file("artifact.json").with_modified(modified);
        assert_eq!(e.modified, Some(modified));
    }

    #[test]
    fn with_size_records_file_hint_but_not_directory_hint() {
        assert_eq!(Entry::file("status.json").with_size(410).size, 410);
        assert_eq!(Entry::dir("wallets").with_size(410).size, 0);
    }

    #[test]
    fn with_modified_ms_records_epoch_milliseconds() {
        let e = Entry::dir("req").with_modified_ms(1_700_000_000_123);
        assert_eq!(
            e.modified,
            Some(SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123))
        );
    }

    #[test]
    fn with_fs_metadata_records_file_size_and_modified_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact.json");
        std::fs::write(&path, b"hello").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();

        let entry = Entry::file("artifact.json").with_fs_metadata(&metadata);

        assert_eq!(entry.size, 5);
        assert_eq!(entry.modified, metadata.modified().ok());
    }

    #[test]
    fn entry_for_fs_path_maps_missing_path_to_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            entry_for_fs_path(dir.path().join("missing"), "missing", EntryKind::File).unwrap_err();
        assert!(
            matches!(err, HandlerError::NotFound(_)),
            "missing artifact must be NotFound (ENOENT), got: {err:?}"
        );
    }

    #[test]
    fn handler_error_constructors_match_variants() {
        match HandlerError::not_found("a/b") {
            HandlerError::NotFound(s) => assert_eq!(s, "a/b"),
            other => panic!("expected NotFound, got {other:?}"),
        }
        match HandlerError::invalid("bad") {
            HandlerError::Invalid(s) => assert_eq!(s, "bad"),
            other => panic!("expected Invalid, got {other:?}"),
        }
        match HandlerError::backend("upstream") {
            HandlerError::Backend(s) => assert_eq!(s, "upstream"),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn handler_error_display_strings() {
        assert_eq!(
            HandlerError::NotFound("x".into()).to_string(),
            "not found: x"
        );
        assert_eq!(
            HandlerError::NotADir("x".into()).to_string(),
            "not a directory: x"
        );
        assert_eq!(
            HandlerError::NotAFile("x".into()).to_string(),
            "not a file: x"
        );
        assert_eq!(
            HandlerError::PermissionDenied.to_string(),
            "permission denied"
        );
        assert_eq!(
            HandlerError::Invalid("y".into()).to_string(),
            "invalid input: y"
        );
        assert_eq!(
            HandlerError::Unsupported("z".into()).to_string(),
            "unsupported: z"
        );
        assert_eq!(
            HandlerError::Backend("oops".into()).to_string(),
            "backend: oops"
        );
    }

    #[test]
    fn handler_error_from_io_error_preserves_message() {
        let io = std::io::Error::other("boom");
        let e: HandlerError = io.into();
        match e {
            HandlerError::Io(inner) => assert!(inner.to_string().contains("boom")),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    /// A trivial Handler impl so we can exercise the trait defaults
    /// (`read`/`write`/`list`/`cache_ttl`/`is_read_side_effecting`).
    struct NoopHandler;

    #[async_trait]
    impl Handler for NoopHandler {
        async fn lookup(&self, _path: &VfsPath) -> Result<Entry, HandlerError> {
            Ok(Entry::dir(""))
        }
    }

    #[tokio::test]
    async fn default_read_returns_not_a_file() {
        let h = NoopHandler;
        let p = VfsPath::parse("/foo").unwrap();
        let err = h.read(&p).await.unwrap_err();
        match err {
            HandlerError::NotAFile(s) => assert_eq!(s, "/foo"),
            other => panic!("expected NotAFile, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn default_write_returns_permission_denied() {
        let h = NoopHandler;
        let p = VfsPath::parse("/foo").unwrap();
        let err = h.write(&p, b"x").await.unwrap_err();
        assert!(matches!(err, HandlerError::PermissionDenied));
    }

    #[tokio::test]
    async fn default_list_returns_not_a_dir() {
        let h = NoopHandler;
        let p = VfsPath::parse("/foo").unwrap();
        let err = h.list(&p).await.unwrap_err();
        match err {
            HandlerError::NotADir(s) => assert_eq!(s, "/foo"),
            other => panic!("expected NotADir, got {other:?}"),
        }
    }

    #[test]
    fn default_cache_ttl_is_none_and_no_side_effects() {
        let h = NoopHandler;
        let p = VfsPath::parse("/foo").unwrap();
        assert!(h.cache_ttl(&p).is_none());
        assert!(!h.is_read_side_effecting(&p));
    }
}
