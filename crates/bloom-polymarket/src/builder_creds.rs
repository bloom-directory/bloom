//! Builder API credentials — relayer **submission** auth, not wallet authority.
//!
//! A builder API key is created via CLOB L2 auth (`POST /auth/builder-api-key`)
//! and authenticates requests to the Polymarket relayer with `POLY_BUILDER_*`
//! HMAC headers. It cannot move funds: every deposit-wallet operation it
//! submits still carries the owner's EIP-712 signature, and orders carry the
//! owner's POLY_1271 signature. Treat it as a revocable service credential
//! (`DELETE /auth/builder-api-key`).
//!
//! Stored at `<dir>/<wallet>/builder_creds.json`, mode 0600, separate from the
//! CLOB credentials. Never logged; `Debug` redacts the secret and passphrase.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{PolymarketError, Result};

/// Builder API key credentials (`POST /auth/builder-api-key` response).
#[derive(Clone, Serialize, Deserialize)]
pub struct BuilderCredentials {
    /// Key id (UUID). Non-secret; this is what `list`/`revoke` reference.
    #[serde(rename = "apiKey", alias = "key")]
    pub key: String,
    /// Base64 HMAC secret (SENSITIVE).
    pub secret: String,
    /// Passphrase header value (SENSITIVE).
    pub passphrase: String,
    #[serde(default)]
    pub created_at_ms: u128,
    /// Provenance of the credential (e.g. "clob_l2_auth").
    #[serde(default)]
    pub source: String,
}

impl std::fmt::Debug for BuilderCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuilderCredentials")
            .field("key", &self.key)
            .field("secret", &"<redacted>")
            .field("passphrase", &"<redacted>")
            .field("created_at_ms", &self.created_at_ms)
            .field("source", &self.source)
            .finish()
    }
}

/// One entry of `GET /auth/builder-api-key`. The CLOB has returned both bare
/// UUID strings and `{key, created_at, revoked_at}` objects across versions;
/// [`BuilderApiKeyInfo::from_value`] accepts either.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuilderApiKeyInfo {
    #[serde(alias = "apiKey")]
    pub key: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
}

impl BuilderApiKeyInfo {
    pub fn from_value(v: &serde_json::Value) -> Option<Self> {
        if let Some(s) = v.as_str() {
            return Some(Self {
                key: s.to_string(),
                created_at: None,
                revoked_at: None,
            });
        }
        serde_json::from_value(v.clone()).ok()
    }
}

/// File-backed store, mirroring [`crate::CredentialStore`] (0700 dir, 0600
/// file).
#[derive(Debug, Clone)]
pub struct BuilderCredentialStore {
    dir: PathBuf,
}

impl BuilderCredentialStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn wallet_dir(&self, wallet: &str) -> PathBuf {
        self.dir.join(wallet)
    }
    fn creds_path(&self, wallet: &str) -> PathBuf {
        self.wallet_dir(wallet).join("builder_creds.json")
    }

    pub fn exists(&self, wallet: &str) -> bool {
        Path::new(&self.creds_path(wallet)).exists()
    }

    pub fn save(&self, wallet: &str, creds: &BuilderCredentials) -> Result<()> {
        crate::validate_wallet_name(wallet)?;
        let dir = self.wallet_dir(wallet);
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        let path = self.creds_path(wallet);
        fs::write(&path, serde_json::to_vec_pretty(creds)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load(&self, wallet: &str) -> Result<Option<BuilderCredentials>> {
        crate::validate_wallet_name(wallet)?;
        match fs::read(self.creds_path(wallet)) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PolymarketError::from(e)),
        }
    }

    pub fn delete(&self, wallet: &str) -> Result<()> {
        crate::validate_wallet_name(wallet)?;
        match fs::remove_file(self.creds_path(wallet)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PolymarketError::from(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn creds() -> BuilderCredentials {
        BuilderCredentials {
            key: "0198-uuid".into(),
            secret: "c2VjcmV0LXNlY3JldC1zZWNyZXQ=".into(),
            passphrase: "tops3cret-pp".into(),
            created_at_ms: 1,
            source: "clob_l2_auth".into(),
        }
    }

    #[test]
    fn round_trip_and_delete() {
        let tmp = TempDir::new().unwrap();
        let store = BuilderCredentialStore::new(tmp.path());
        assert!(!store.exists("w"));
        store.save("w", &creds()).unwrap();
        assert!(store.exists("w"));
        let loaded = store.load("w").unwrap().unwrap();
        assert_eq!(loaded.key, "0198-uuid");
        assert_eq!(loaded.secret, creds().secret);
        store.delete("w").unwrap();
        assert!(store.load("w").unwrap().is_none());
        store.delete("w").unwrap(); // idempotent
    }

    #[cfg(unix)]
    #[test]
    fn file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let store = BuilderCredentialStore::new(tmp.path());
        store.save("w", &creds()).unwrap();
        let mode = std::fs::metadata(tmp.path().join("w/builder_creds.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "builder creds must be 0600");
    }

    #[test]
    fn debug_redacts_secrets() {
        let s = format!("{:?}", creds());
        assert!(s.contains("0198-uuid"));
        assert!(!s.contains("c2VjcmV0"), "secret leaked in Debug: {s}");
        assert!(
            !s.contains("tops3cret-pp"),
            "passphrase leaked in Debug: {s}"
        );
        assert!(s.contains("<redacted>"));
    }

    #[test]
    fn create_response_shape_parses() {
        // The CLOB returns the same shape as CLOB creds: apiKey/secret/passphrase.
        let v: BuilderCredentials =
            serde_json::from_str(r#"{"apiKey":"u-1","secret":"s","passphrase":"p"}"#).unwrap();
        assert_eq!(v.key, "u-1");
        // and the stored form round-trips through the rename
        let second: BuilderCredentials =
            serde_json::from_slice(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(second.key, "u-1");
    }
}
