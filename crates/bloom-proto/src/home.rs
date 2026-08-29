//! Machine-owned on-disk layout under `~/.bloom/`.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HomeError {
    #[error("could not determine home directory; set BLOOM_HOME or --home")]
    NoHome,
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Bloom home is already open for writing (lock={path})")]
    WriteLockHeld { path: PathBuf },
}

/// Resolves and creates the key-free Machine home directory tree.
///
/// Layout:
/// ```text
/// ~/.bloom/
/// ├── config.toml
/// ├── audit.jsonl
/// ├── bloom.sock           # admin socket
/// ├── events.sock         # streaming events socket
/// ├── cache/
/// │   └── cache.db
/// ├── blobs/
/// ├── outbox/             # daemon's persisted outbox state
/// │   └── <wallet>/<chain>/{pending,sent,failed}/<id>/...
/// ├── watch/
/// └── logs/
/// ```
#[derive(Debug, Clone)]
pub struct HomeDir {
    root: PathBuf,
}

impl HomeDir {
    /// Resolve `raw` (`~/.bloom` style) into a concrete path.
    pub fn resolve(raw: &str) -> Result<Self, HomeError> {
        let root = if raw == "~/.bloom" {
            let home = dirs::home_dir().ok_or(HomeError::NoHome)?;
            home.join(".bloom")
        } else {
            PathBuf::from(shellexpand_local(raw))
        };
        Ok(Self { root })
    }

    /// Use a pre-resolved path (mostly for tests).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Create the on-disk subdirectories. Idempotent.
    pub fn ensure(&self) -> Result<(), HomeError> {
        let dirs = [
            self.root.clone(),
            self.cache_dir(),
            self.blobs_dir(),
            self.outbox_dir(),
            self.solana_outbox_dir(),
            self.watch_dir(),
            self.logs_dir(),
        ];
        for d in dirs {
            std::fs::create_dir_all(&d).map_err(|source| HomeError::Io {
                path: d.clone(),
                source,
            })?;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.toml")
    }
    pub fn audit_path(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }
    pub fn admin_socket(&self) -> PathBuf {
        self.root.join("bloom.sock")
    }
    pub fn events_socket(&self) -> PathBuf {
        self.root.join("events.sock")
    }
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }
    pub fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }
    pub fn outbox_dir(&self) -> PathBuf {
        self.root.join("outbox")
    }
    /// Dedicated Solana outbox root. This is deliberately a reserved sibling
    /// of `outbox/`: putting it below `outbox/solana` would collide with a
    /// user wallet named `solana` in the legacy `<wallet>/<chain>` layout.
    pub fn solana_outbox_dir(&self) -> PathBuf {
        self.root.join(".solana-outbox")
    }
    pub fn watch_dir(&self) -> PathBuf {
        self.root.join("watch")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }
    pub fn canonical_root(&self) -> Result<PathBuf, HomeError> {
        std::fs::canonicalize(&self.root).map_err(|source| HomeError::Io {
            path: self.root.clone(),
            source,
        })
    }
}

#[derive(Debug)]
pub struct HomeWritePermit {
    home: PathBuf,
    path: PathBuf,
    _file: File,
}

impl HomeWritePermit {
    pub fn acquire(home: &HomeDir) -> Result<Self, HomeError> {
        fs::create_dir_all(home.root()).map_err(|source| HomeError::Io {
            path: home.root().to_path_buf(),
            source,
        })?;
        let canonical_home = home.canonical_root()?;
        let run_dir = canonical_home.join("run");
        fs::create_dir_all(&run_dir).map_err(|source| HomeError::Io {
            path: run_dir.clone(),
            source,
        })?;
        let path = run_dir.join(".daemon.lock");
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| HomeError::Io {
                path: path.clone(),
                source,
            })?;
        file.try_lock_exclusive()
            .map_err(|_| HomeError::WriteLockHeld { path: path.clone() })?;
        file.set_len(0).map_err(|source| HomeError::Io {
            path: path.clone(),
            source,
        })?;
        write!(file, "{}", std::process::id()).map_err(|source| HomeError::Io {
            path: path.clone(),
            source,
        })?;
        file.flush().map_err(|source| HomeError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(Self {
            home: canonical_home,
            path,
            _file: file,
        })
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn shellexpand_local(raw: &str) -> String {
    if let Some(stripped) = raw.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(stripped).to_string_lossy().into_owned();
    }
    raw.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn at_constructs_all_child_paths() {
        let td = tempdir().unwrap();
        let home = HomeDir::at(td.path());
        assert_eq!(home.root(), td.path());
        assert_eq!(home.config_path(), td.path().join("config.toml"));
        assert_eq!(home.audit_path(), td.path().join("audit.jsonl"));
        assert_eq!(home.admin_socket(), td.path().join("bloom.sock"));
        assert_eq!(home.events_socket(), td.path().join("events.sock"));
        assert_eq!(home.cache_dir(), td.path().join("cache"));
        assert_eq!(home.blobs_dir(), td.path().join("blobs"));
        assert_eq!(home.outbox_dir(), td.path().join("outbox"));
        assert_eq!(home.solana_outbox_dir(), td.path().join(".solana-outbox"));
        assert_eq!(home.watch_dir(), td.path().join("watch"));
        assert_eq!(home.logs_dir(), td.path().join("logs"));
    }

    #[test]
    fn ensure_creates_all_subdirs_idempotently() {
        let td = tempdir().unwrap();
        let home = HomeDir::at(td.path().join("nested"));
        assert!(!home.root().exists());

        home.ensure().unwrap();
        for d in [
            home.root().to_path_buf(),
            home.cache_dir(),
            home.blobs_dir(),
            home.outbox_dir(),
            home.solana_outbox_dir(),
            home.watch_dir(),
            home.logs_dir(),
        ] {
            assert!(d.is_dir(), "expected dir to exist: {}", d.display());
        }

        // ensure() is idempotent — second call should not error.
        home.ensure().unwrap();
    }

    #[test]
    fn ensure_does_not_create_files_only_dirs() {
        let td = tempdir().unwrap();
        let home = HomeDir::at(td.path());
        home.ensure().unwrap();
        // Files like config.toml / audit.jsonl / sockets should NOT exist
        // just because we ensured the dir tree.
        assert!(!home.config_path().exists());
        assert!(!home.audit_path().exists());
        assert!(!home.admin_socket().exists());
        assert!(!home.events_socket().exists());
        assert!(
            !home.root().join("keystore").exists(),
            "ensuring a clean Machine home must not create the legacy keystore"
        );
    }

    #[test]
    fn resolve_with_explicit_path_does_not_touch_home() {
        // A non-tilde, non-default path should be used as-is.
        let raw = "/tmp/bloom-test-resolve";
        let home = HomeDir::resolve(raw).unwrap();
        assert_eq!(home.root(), Path::new(raw));
    }

    #[test]
    fn resolve_default_uses_home_dir() {
        // The documented sentinel "~/.bloom" expands via dirs::home_dir.
        // dirs::home_dir() returning None on a CI box is rare, but tolerate it.
        if let Some(real_home) = dirs::home_dir() {
            let home = HomeDir::resolve("~/.bloom").unwrap();
            assert_eq!(home.root(), real_home.join(".bloom"));
        }
    }

    #[test]
    fn resolve_expands_tilde_prefix() {
        if let Some(real_home) = dirs::home_dir() {
            let home = HomeDir::resolve("~/foo/bar").unwrap();
            assert_eq!(home.root(), real_home.join("foo").join("bar"));
        }
    }

    #[test]
    fn write_permit_excludes_second_holder() {
        let td = tempdir().unwrap();
        let home = HomeDir::at(td.path());
        let first = HomeWritePermit::acquire(&home).unwrap();
        let second = HomeWritePermit::acquire(&home);
        assert!(matches!(second, Err(HomeError::WriteLockHeld { .. })));
        drop(first);
        let third = HomeWritePermit::acquire(&home).unwrap();
        assert!(third.path().ends_with("run/.daemon.lock"));
    }

    #[test]
    fn write_permit_canonicalizes_home() {
        let td = tempdir().unwrap();
        let home = HomeDir::at(td.path().join(".").join(""));
        let permit = HomeWritePermit::acquire(&home).unwrap();
        assert_eq!(permit.home(), td.path().canonicalize().unwrap());
    }
}
