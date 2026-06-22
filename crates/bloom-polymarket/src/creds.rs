//! Credential storage for CLOB L2 secrets — home-dir-agnostic.
//!
//! [`CredentialStore`] persists [`Credentials`] (apiKey/secret/passphrase/nonce)
//! under a caller-supplied directory as `<dir>/<wallet>/creds.json` at mode
//! `0o600`. The crate stays decoupled from the bloom home dir: the VFS handler
//! (PR-4b) constructs the store with `~/.bloom/polymarket`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::types::Credentials;
use crate::{PolymarketError, Result};

/// File-backed store for per-wallet CLOB credentials.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    dir: PathBuf,
}

impl CredentialStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn wallet_dir(&self, wallet: &str) -> PathBuf {
        self.dir.join(wallet)
    }
    fn creds_path(&self, wallet: &str) -> PathBuf {
        self.wallet_dir(wallet).join("creds.json")
    }

    /// Persist `creds` for `wallet` at mode `0o600` (dir `0o700`).
    pub fn save(&self, wallet: &str, creds: &Credentials) -> Result<()> {
        crate::validate_wallet_name(wallet)?;
        let dir = self.wallet_dir(wallet);
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        let path = self.creds_path(wallet);
        let body = serde_json::to_vec_pretty(creds)?;
        fs::write(&path, &body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load `wallet`'s credentials, or `None` if not yet stored.
    pub fn load(&self, wallet: &str) -> Result<Option<Credentials>> {
        crate::validate_wallet_name(wallet)?;
        let path = self.creds_path(wallet);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PolymarketError::from(e)),
        }
    }

    /// Whether credentials exist for `wallet`. A malformed wallet name can never
    /// have stored credentials (and must not escape the store dir), so it reads
    /// as `false` rather than touching the filesystem with an unchecked path.
    pub fn exists(&self, wallet: &str) -> bool {
        if crate::validate_wallet_name(wallet).is_err() {
            return false;
        }
        Path::new(&self.creds_path(wallet)).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Credentials {
        Credentials {
            key: "11111111-2222-3333-4444-555555555555".into(),
            secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            passphrase: "pass-12345".into(),
            nonce: 7,
        }
    }

    #[test]
    fn round_trip_and_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let store = CredentialStore::new(dir.path());
        assert!(store.load("alice").unwrap().is_none());
        assert!(!store.exists("alice"));

        store.save("alice", &sample()).unwrap();
        assert!(store.exists("alice"));
        let loaded = store.load("alice").unwrap().unwrap();
        assert_eq!(loaded.key, sample().key);
        assert_eq!(loaded.secret, sample().secret);
        assert_eq!(loaded.nonce, 7);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("alice/creds.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "creds.json must be 0600, got {:o}",
                mode & 0o777
            );
        }
    }

    #[test]
    fn rejects_unsafe_wallet_names() {
        let dir = tempfile::tempdir().unwrap();
        let store = CredentialStore::new(dir.path());
        for bad in ["../evil", "a/b", ""] {
            assert!(
                store.save(bad, &sample()).is_err(),
                "save must reject {bad:?}"
            );
            assert!(store.load(bad).is_err(), "load must reject {bad:?}");
            assert!(!store.exists(bad), "exists must be false for {bad:?}");
        }
    }
}
