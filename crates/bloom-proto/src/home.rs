//! On-disk layout under `~/.bloom/`.

use std::path::{Path, PathBuf};

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
}

/// Resolves and creates the bloom home directory tree.
///
/// Layout:
/// ```text
/// ~/.bloom/
/// ├── config.toml
/// ├── audit.jsonl
/// ├── bloom.sock           # admin socket
/// ├── events.sock         # streaming events socket
/// ├── keystore/
/// │   └── <wallet>/
/// │       ├── address
/// │       ├── pubkey
/// │       ├── kind
/// │       ├── encrypted.key
/// │       └── policy.toml
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
            self.keystore_dir(),
            self.cache_dir(),
            self.blobs_dir(),
            self.outbox_dir(),
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
    pub fn keystore_dir(&self) -> PathBuf {
        self.root.join("keystore")
    }
    pub fn wallet_dir(&self, name: &str) -> PathBuf {
        self.keystore_dir().join(name)
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
    pub fn watch_dir(&self) -> PathBuf {
        self.root.join("watch")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
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
        assert_eq!(home.keystore_dir(), td.path().join("keystore"));
        assert_eq!(home.cache_dir(), td.path().join("cache"));
        assert_eq!(home.blobs_dir(), td.path().join("blobs"));
        assert_eq!(home.outbox_dir(), td.path().join("outbox"));
        assert_eq!(home.watch_dir(), td.path().join("watch"));
        assert_eq!(home.logs_dir(), td.path().join("logs"));
    }

    #[test]
    fn wallet_dir_joins_under_keystore() {
        let td = tempdir().unwrap();
        let home = HomeDir::at(td.path());
        assert_eq!(
            home.wallet_dir("alice"),
            td.path().join("keystore").join("alice")
        );
    }

    #[test]
    fn ensure_creates_all_subdirs_idempotently() {
        let td = tempdir().unwrap();
        let home = HomeDir::at(td.path().join("nested"));
        assert!(!home.root().exists());

        home.ensure().unwrap();
        for d in [
            home.root().to_path_buf(),
            home.keystore_dir(),
            home.cache_dir(),
            home.blobs_dir(),
            home.outbox_dir(),
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
}
