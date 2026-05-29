//! NFS mount adapter for bloom.
//!
//! This crate exposes a [`bloom_vfs::Vfs`] over NFSv4.1 by spinning up an
//! in-process [`embednfs`] server bound to a localhost port and then
//! shelling out to the platform mount command (`mount.nfs4` on Linux,
//! `mount_nfs` on macOS) to attach it as a real filesystem mount.
//!
//! # Feature gating
//!
//! The actual server lives behind the `mount` cargo feature so default
//! builds stay portable — embednfs is a git dependency and the platform
//! mount tooling is not present everywhere. Without `--features mount`
//! the crate still exposes the [`MountConfig`] / [`MountHandle`] /
//! [`MountError`] surface plus the OS helpers ([`detect_mount_command`],
//! [`build_mount_args`]) so the daemon and CLI compile uniformly. The
//! stub [`mount`] entry returns [`MountError::NotEnabled`].
//!
//! With `--features mount`, the additional entry point [`serve_nfs`]
//! starts the server, issues the platform mount, and hands back a
//! [`NfsMountHandle`] whose `Drop` runs `umount`.

#![forbid(unsafe_code)]

use std::any::Any;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(feature = "mount")]
pub mod adapter;
#[cfg(feature = "mount")]
mod server;

#[cfg(feature = "mount")]
pub use server::{NfsMountHandle, serve_nfs};

/// Configuration for mounting a bloom VFS over NFS.
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// Filesystem path where the NFS export should be attached.
    /// Callers must expand `~` and resolve relative paths before
    /// constructing this — the adapter takes the value as-is.
    pub mount_path: PathBuf,
    /// Address the embedded NFS server should listen on.
    /// `127.0.0.1:0` selects an ephemeral port.
    pub nfs_listen: SocketAddr,
    /// Mount the export read-only.
    pub readonly: bool,
}

impl MountConfig {
    /// Build a config that picks an ephemeral port on loopback and
    /// mounts read-write at `mount_path`.
    pub fn ephemeral(mount_path: impl Into<PathBuf>) -> Self {
        Self {
            mount_path: mount_path.into(),
            nfs_listen: "127.0.0.1:0".parse().expect("static loopback addr"),
            readonly: false,
        }
    }
}

/// Errors produced by the mount adapter.
#[derive(thiserror::Error, Debug)]
pub enum MountError {
    #[error("nfs feature not enabled")]
    NotEnabled,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("mount system call failed: {0}")]
    Mount(String),
    #[error("invalid config: {0}")]
    Config(String),
}

/// Handle to a live mount. Dropping the handle does *not* unmount —
/// callers must invoke [`MountHandle::unmount`] explicitly to ensure
/// the underlying syscall is awaited.
#[async_trait::async_trait]
pub trait MountHandle: Send + Sync {
    /// Tear down the mount and stop the embedded server.
    async fn unmount(&self) -> Result<(), MountError>;
    /// Filesystem path where the export is attached.
    fn mount_path(&self) -> &Path;
    /// Address the embedded NFS server is listening on.
    fn nfs_addr(&self) -> SocketAddr;
}

/// Stub mount entry point used by callers that haven't migrated to
/// [`serve_nfs`] yet. Always returns [`MountError::NotEnabled`].
///
/// The `_vfs` argument is opaque so callers without `--features mount`
/// can still program against this surface. With the feature enabled
/// you should call [`serve_nfs`] directly with a typed `Vfs`.
pub async fn mount(
    _cfg: MountConfig,
    _vfs: Arc<dyn Any + Send + Sync>,
) -> Result<Box<dyn MountHandle>, MountError> {
    #[cfg(feature = "mount")]
    {
        tracing::warn!("mount.placeholder_called: use serve_nfs with a typed Vfs instead");
        Err(MountError::NotEnabled)
    }
    #[cfg(not(feature = "mount"))]
    {
        tracing::debug!("mount.feature_disabled: build without 'mount' cargo feature");
        Err(MountError::NotEnabled)
    }
}

/// Test/utility handle that satisfies [`MountHandle`] without doing any
/// real I/O. Useful for daemon-level tests that only need to pretend a
/// mount exists.
pub struct NoopHandle {
    mount_path: PathBuf,
    nfs_addr: SocketAddr,
}

impl NoopHandle {
    pub fn new(mount_path: PathBuf, nfs_addr: SocketAddr) -> Self {
        Self {
            mount_path,
            nfs_addr,
        }
    }
}

#[async_trait::async_trait]
impl MountHandle for NoopHandle {
    async fn unmount(&self) -> Result<(), MountError> {
        Ok(())
    }
    fn mount_path(&self) -> &Path {
        &self.mount_path
    }
    fn nfs_addr(&self) -> SocketAddr {
        self.nfs_addr
    }
}

/// Returns the platform-appropriate userspace mount command name.
///
/// Linux ships `mount.nfs4` from `nfs-utils`; macOS ships `mount_nfs`.
/// Other platforms fall back to `mount` so callers at least produce a
/// recognisable error rather than panicking.
pub fn detect_mount_command() -> &'static str {
    if cfg!(target_os = "linux") {
        "mount.nfs4"
    } else if cfg!(target_os = "macos") {
        "mount_nfs"
    } else {
        "mount"
    }
}

/// Build the `-o` option string and trailing positional arguments for
/// the platform mount command, targeting the embedded NFSv4.1 server at
/// `server`.
///
/// The shared options are `vers=4.1,proto=tcp`, explicit `port` so we
/// can target the auto-assigned ephemeral port, generous `rsize`/`wsize`
/// so most JSON/TOML payloads fit in a single op (the adapter buffers
/// multi-block writes anyway but a single op stays simpler for the
/// common case), and `timeo=10` for snappy failure on a wedged server.
///
/// Caching options diverge per-platform because the kernels expose
/// different knobs:
///
/// * **Linux** (`mount.nfs4`): `actimeo=0` disables attribute caching
///   without relying on `lookupcache=none`, which is rejected by some
///   minimal CI images.
/// * **macOS** (`mount_nfs`): `actimeo=0` zeros the attribute-cache
///   timeouts. The Linux-only `lookupcache=none`, `nocallback`, and
///   `nonegnamecache` knobs are *not* recognised by macOS and would
///   cause the mount to be rejected. `nolocks` is NFSv2/v3-only per
///   `mount_nfs(8)` and triggers `EINVAL` on a v4 mount; NFSv4 has
///   built-in locking so the option is meaningless anyway. `mountport=`
///   targets the v2/v3 mountd which doesn't exist for v4 — `port=` is
///   sufficient to reach the embedded server.
/// * **Other Unix**: mirrored from macOS as a portable default; mount
///   tooling that doesn't grok `actimeo=0` will surface its own error.
pub fn build_mount_args(cfg: &MountConfig, server: SocketAddr) -> Vec<String> {
    let port = server.port();
    let mut opts = build_mount_opts(port);
    if cfg.readonly {
        opts.push_str(",ro");
    }
    vec![
        "-o".to_string(),
        opts,
        format!("{}:/", server.ip()),
        cfg.mount_path.display().to_string(),
    ]
}

#[cfg(target_os = "linux")]
fn build_mount_opts(port: u16) -> String {
    format!("actimeo=0,vers=4.1,proto=tcp,port={port},rsize=65536,wsize=65536,timeo=10")
}

#[cfg(target_os = "macos")]
fn build_mount_opts(port: u16) -> String {
    format!("actimeo=0,vers=4.1,proto=tcp,port={port},rsize=65536,wsize=65536,timeo=10")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn build_mount_opts(port: u16) -> String {
    format!(
        "actimeo=0,vers=4.1,proto=tcp,nolocks,mountport={port},port={port},rsize=65536,wsize=65536,timeo=10"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_mount_command_matches_platform() {
        let got = detect_mount_command();
        if cfg!(target_os = "linux") {
            assert_eq!(got, "mount.nfs4");
        } else if cfg!(target_os = "macos") {
            assert_eq!(got, "mount_nfs");
        } else {
            assert_eq!(got, "mount");
        }
    }

    #[test]
    fn build_mount_args_includes_version_and_port() {
        let cfg = MountConfig {
            mount_path: PathBuf::from("/tmp/bloom"),
            nfs_listen: "127.0.0.1:0".parse().unwrap(),
            readonly: false,
        };
        let server: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let args = build_mount_args(&cfg, server);
        let joined = args.join(" ");
        assert!(joined.contains("vers=4.1"), "missing vers=4.1 in {joined}");
        assert!(
            joined.contains("port=54321"),
            "missing port=54321 in {joined}"
        );
        if cfg!(target_os = "linux") {
            assert!(
                !joined.contains("mountport="),
                "linux nfs4 mount must not include mountport=: {joined}"
            );
        } else if cfg!(target_os = "macos") {
            assert!(
                !joined.contains("mountport="),
                "macos mount_nfs must not include mountport=: {joined}"
            );
        }
        assert!(args.last().unwrap().ends_with("/tmp/bloom"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_mount_args_linux_uses_portable_cache_options() {
        let cfg = MountConfig {
            mount_path: PathBuf::from("/tmp/bloom"),
            nfs_listen: "127.0.0.1:0".parse().unwrap(),
            readonly: false,
        };
        let server: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let args = build_mount_args(&cfg, server);
        let joined = args.join(" ");
        assert!(
            joined.contains("actimeo=0"),
            "linux opts must include actimeo=0: {joined}"
        );
        assert!(
            !joined.contains("lookupcache="),
            "linux opts must avoid lookupcache= because some mount.nfs4 builds reject it: {joined}"
        );
        assert!(
            !joined.contains("nolocks"),
            "linux opts must avoid nolocks on nfs4: {joined}"
        );
        assert!(
            !joined.contains("mountport="),
            "linux opts must avoid nfs2/nfs3 mountport= on nfs4: {joined}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn build_mount_args_macos_uses_actimeo_only() {
        let cfg = MountConfig {
            mount_path: PathBuf::from("/tmp/bloom"),
            nfs_listen: "127.0.0.1:0".parse().unwrap(),
            readonly: false,
        };
        let server: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let args = build_mount_args(&cfg, server);
        let joined = args.join(" ");
        assert!(
            joined.contains("actimeo=0"),
            "macos opts must include actimeo=0: {joined}"
        );
        // Linux-only knobs that mount_nfs doesn't recognise.
        assert!(
            !joined.contains("noac"),
            "macos opts must not include noac: {joined}"
        );
        assert!(
            !joined.contains("lookupcache="),
            "macos opts must not include lookupcache=: {joined}"
        );
        assert!(
            !joined.contains("nocallback"),
            "macos opts must not include nocallback: {joined}"
        );
        assert!(
            !joined.contains("nonegnamecache"),
            "macos opts must not include nonegnamecache: {joined}"
        );
        assert!(
            !joined.contains("nolocks"),
            "macos opts must not include nolocks (v2/v3-only, EINVAL on v4): {joined}"
        );
        assert!(
            !joined.contains("mountport="),
            "macos opts must not include mountport= (v2/v3 mountd-only): {joined}"
        );
    }

    #[test]
    fn build_mount_args_readonly_appends_ro() {
        let cfg = MountConfig {
            mount_path: PathBuf::from("/tmp/bloom"),
            nfs_listen: "127.0.0.1:0".parse().unwrap(),
            readonly: true,
        };
        let server: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let args = build_mount_args(&cfg, server);
        let joined = args.join(" ");
        assert!(
            joined.contains(",ro"),
            "readonly mount must append ,ro: {joined}"
        );
    }

    #[tokio::test]
    async fn mount_returns_not_enabled_by_default() {
        let cfg = MountConfig {
            mount_path: PathBuf::from("/tmp/bloom"),
            nfs_listen: "127.0.0.1:0".parse().unwrap(),
            readonly: false,
        };
        let vfs: Arc<dyn Any + Send + Sync> = Arc::new(());
        match mount(cfg, vfs).await {
            Ok(_) => panic!("expected MountError::NotEnabled, got Ok"),
            Err(MountError::NotEnabled) => {}
            Err(other) => panic!("expected NotEnabled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn noop_handle_round_trips() {
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let h = NoopHandle::new(PathBuf::from("/tmp/x"), addr);
        assert_eq!(h.mount_path(), Path::new("/tmp/x"));
        assert_eq!(h.nfs_addr(), addr);
        h.unmount().await.unwrap();
    }
}
