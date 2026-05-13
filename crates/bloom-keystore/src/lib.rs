//! Encrypted local keystore for bloom.
//!
//! ## Layout
//!
//! ```text
//! ~/.bloom/keystore/<wallet>/
//! ├── address           # 0x-prefixed checksum
//! ├── pubkey            # uncompressed secp256k1, hex
//! ├── kind              # "local" | "watch"
//! ├── encrypted.key     # CBOR blob with kdf+cipher params + ciphertext
//! └── policy.toml
//! ```
//!
//! ## Crypto
//!
//! - KDF: argon2id, parameters chosen for ~250ms on a modern laptop.
//! - Cipher: chacha20-poly1305 with a per-key random nonce.
//! - Plaintext: 32-byte secp256k1 private key, zeroized on drop.
//!
//! Private keys never leave the daemon process. Only the public address +
//! pubkey are exposed via the FS.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use bloom_proto::{Policy, checksum_address};

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("argon2 error: {0}")]
    Argon2(String),
    #[error("aead error: {0}")]
    Aead(String),
    #[error("malformed key file: {0}")]
    Malformed(String),
    #[error("wallet '{0}' not found")]
    NotFound(String),
    #[error("wallet '{0}' already exists")]
    AlreadyExists(String),
    #[error("wallet '{0}' is locked")]
    Locked(String),
    #[error("invalid wallet name '{0}'")]
    InvalidName(String),
    #[error("alloy signer error: {0}")]
    Signer(String),
    #[error("policy parse error: {0}")]
    Policy(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletKind {
    Local,
    Watch,
}

impl std::fmt::Display for WalletKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletKind::Local => f.write_str("local"),
            WalletKind::Watch => f.write_str("watch"),
        }
    }
}

/// Public-side wallet metadata.
#[derive(Debug, Clone)]
pub struct WalletInfo {
    pub name: String,
    pub address: Address,
    pub pubkey_hex: String,
    pub kind: WalletKind,
    pub policy: Policy,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFile {
    /// Format version.
    v: u8,
    /// Hex-encoded 32-byte salt for argon2.
    salt_hex: String,
    /// Hex-encoded 12-byte nonce for chacha20-poly1305.
    nonce_hex: String,
    /// Argon2id `m_cost` (KiB).
    m_cost: u32,
    /// Argon2id `t_cost` (iterations).
    t_cost: u32,
    /// Argon2id `p_cost` (parallelism).
    p_cost: u32,
    /// Hex ciphertext (key bytes encrypted under derived key).
    ciphertext_hex: String,
}

const KEYSTORE_VERSION: u8 = 1;
const ARGON2_M_COST: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

#[derive(Clone)]
pub struct Keystore {
    inner: Arc<KeystoreInner>,
}

struct KeystoreInner {
    root: PathBuf,
    unlocked: RwLock<std::collections::HashMap<String, Arc<PrivateKeySigner>>>,
}

impl Keystore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, KeystoreError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|source| KeystoreError::Io {
            path: root.clone(),
            source,
        })?;
        Ok(Self {
            inner: Arc::new(KeystoreInner {
                root,
                unlocked: RwLock::new(Default::default()),
            }),
        })
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    fn wallet_path(&self, name: &str) -> PathBuf {
        self.inner.root.join(name)
    }

    fn validate_name(name: &str) -> Result<(), KeystoreError> {
        if name.is_empty() || name.len() > 64 {
            return Err(KeystoreError::InvalidName(name.into()));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(KeystoreError::InvalidName(name.into()));
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<WalletInfo>, KeystoreError> {
        let mut out = Vec::new();
        if !self.inner.root.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&self.inner.root).map_err(|source| KeystoreError::Io {
            path: self.inner.root.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| KeystoreError::Io {
                path: self.inner.root.clone(),
                source,
            })?;
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    match self.info(name) {
                        Ok(info) => out.push(info),
                        Err(e) => {
                            tracing::debug!(
                                wallet = name,
                                error = %e,
                                "keystore.list_skipped"
                            );
                        }
                    }
                } else {
                    tracing::debug!(
                        file_name = ?entry.file_name(),
                        "keystore.list_non_utf8_skipped"
                    );
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub fn info(&self, name: &str) -> Result<WalletInfo, KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if !dir.exists() {
            return Err(KeystoreError::NotFound(name.into()));
        }
        let address_path = dir.join("address");
        let pub_path = dir.join("pubkey");
        let kind_path = dir.join("kind");
        let policy_path = dir.join("policy.toml");

        let addr_str = read_trim(&address_path)?;
        let address = addr_str
            .parse::<Address>()
            .map_err(|e| KeystoreError::Malformed(format!("address: {e}")))?;
        let pubkey_hex = read_trim(&pub_path)?;
        let kind: WalletKind = match read_trim(&kind_path)?.as_str() {
            "local" => WalletKind::Local,
            "watch" => WalletKind::Watch,
            other => return Err(KeystoreError::Malformed(format!("kind: {other}"))),
        };
        let policy = if policy_path.exists() {
            let s = fs::read_to_string(&policy_path).map_err(|source| KeystoreError::Io {
                path: policy_path.clone(),
                source,
            })?;
            toml::from_str::<Policy>(&s).map_err(|e| KeystoreError::Policy(e.to_string()))?
        } else {
            Policy::default()
        };
        Ok(WalletInfo {
            name: name.into(),
            address,
            pubkey_hex,
            kind,
            policy,
        })
    }

    pub fn create_local(&self, name: &str, passphrase: &str) -> Result<WalletInfo, KeystoreError> {
        let signer = PrivateKeySigner::random();
        self.import_local(name, &signer, passphrase)
    }

    pub fn import_hex(
        &self,
        name: &str,
        private_key_hex: &str,
        passphrase: &str,
    ) -> Result<WalletInfo, KeystoreError> {
        let bytes = decode_priv_hex(private_key_hex)
            .map_err(|e| KeystoreError::Malformed(format!("private key: {e}")))?;
        let signer = PrivateKeySigner::from_bytes(&bytes.into())
            .map_err(|e| KeystoreError::Signer(e.to_string()))?;
        self.import_local(name, &signer, passphrase)
    }

    pub fn add_watch(&self, name: &str, address: Address) -> Result<WalletInfo, KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if dir.exists() {
            return Err(KeystoreError::AlreadyExists(name.into()));
        }
        fs::create_dir_all(&dir).map_err(|source| KeystoreError::Io {
            path: dir.clone(),
            source,
        })?;
        write_atomic(&dir.join("address"), checksum_address(&address).as_bytes())?;
        write_atomic(&dir.join("kind"), b"watch")?;
        write_atomic(&dir.join("pubkey"), b"")?;
        Ok(WalletInfo {
            name: name.into(),
            address,
            pubkey_hex: String::new(),
            kind: WalletKind::Watch,
            policy: Policy::default(),
        })
    }

    fn import_local(
        &self,
        name: &str,
        signer: &PrivateKeySigner,
        passphrase: &str,
    ) -> Result<WalletInfo, KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if dir.exists() {
            return Err(KeystoreError::AlreadyExists(name.into()));
        }
        fs::create_dir_all(&dir).map_err(|source| KeystoreError::Io {
            path: dir.clone(),
            source,
        })?;

        let key_bytes = signer.to_bytes();
        let encrypted = encrypt_key(key_bytes.as_slice(), passphrase)?;
        let blob =
            serde_json::to_vec(&encrypted).map_err(|e| KeystoreError::Malformed(e.to_string()))?;
        write_atomic(&dir.join("encrypted.key"), &blob)?;

        let address = signer.address();
        let pub_hex = hex::encode(
            signer
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        write_atomic(&dir.join("address"), checksum_address(&address).as_bytes())?;
        write_atomic(&dir.join("pubkey"), pub_hex.as_bytes())?;
        write_atomic(&dir.join("kind"), b"local")?;
        let default_policy = Policy::default();
        write_atomic(
            &dir.join("policy.toml"),
            toml::to_string_pretty(&default_policy)
                .map_err(|e| KeystoreError::Policy(e.to_string()))?
                .as_bytes(),
        )?;

        Ok(WalletInfo {
            name: name.into(),
            address,
            pubkey_hex: pub_hex,
            kind: WalletKind::Local,
            policy: default_policy,
        })
    }

    pub fn unlock(&self, name: &str, passphrase: &str) -> Result<(), KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if !dir.exists() {
            tracing::debug!(wallet = name, "keystore.unlock_not_found");
            return Err(KeystoreError::NotFound(name.into()));
        }
        let kind: WalletKind = match read_trim(&dir.join("kind"))?.as_str() {
            "local" => WalletKind::Local,
            "watch" => {
                tracing::debug!(wallet = name, "keystore.unlock_watch_only");
                return Err(KeystoreError::Locked(name.into()));
            }
            other => {
                tracing::debug!(
                    wallet = name,
                    kind = other,
                    "keystore.unlock_malformed_kind"
                );
                return Err(KeystoreError::Malformed(format!("kind: {other}")));
            }
        };
        let _ = kind;
        let blob = fs::read(dir.join("encrypted.key")).map_err(|source| {
            tracing::debug!(
                wallet = name,
                error = %source,
                "keystore.unlock_read_failed"
            );
            KeystoreError::Io {
                path: dir.join("encrypted.key"),
                source,
            }
        })?;
        let enc: EncryptedFile = serde_json::from_slice(&blob).map_err(|e| {
            tracing::debug!(
                wallet = name,
                error = %e,
                "keystore.unlock_blob_malformed"
            );
            KeystoreError::Malformed(e.to_string())
        })?;
        let key_bytes = decrypt_key(&enc, passphrase).inspect_err(|e| {
            tracing::debug!(
                wallet = name,
                error = %e,
                "keystore.unlock_decrypt_failed"
            );
        })?;
        let signer = PrivateKeySigner::from_bytes(&key_bytes.into()).map_err(|e| {
            tracing::debug!(
                wallet = name,
                error = %e,
                "keystore.unlock_signer_failed"
            );
            KeystoreError::Signer(e.to_string())
        })?;
        self.inner
            .unlocked
            .write()
            .insert(name.to_string(), Arc::new(signer));
        tracing::debug!(wallet = name, "keystore.unlocked");
        Ok(())
    }

    pub fn lock(&self, name: &str) {
        self.inner.unlocked.write().remove(name);
    }

    pub fn is_unlocked(&self, name: &str) -> bool {
        self.inner.unlocked.read().contains_key(name)
    }

    pub fn signer(&self, name: &str) -> Result<Arc<PrivateKeySigner>, KeystoreError> {
        match self.inner.unlocked.read().get(name).cloned() {
            Some(s) => Ok(s),
            None => {
                tracing::debug!(wallet = name, "keystore.signer_locked");
                Err(KeystoreError::Locked(name.into()))
            }
        }
    }

    pub fn delete(&self, name: &str) -> Result<(), KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if !dir.exists() {
            tracing::debug!(wallet = name, "keystore.delete_not_found");
            return Err(KeystoreError::NotFound(name.into()));
        }
        fs::remove_dir_all(&dir).map_err(|source| KeystoreError::Io {
            path: dir.clone(),
            source,
        })?;
        self.inner.unlocked.write().remove(name);
        tracing::debug!(wallet = name, "keystore.deleted");
        Ok(())
    }
}

fn read_trim(path: &Path) -> Result<String, KeystoreError> {
    let s = fs::read_to_string(path).map_err(|source| KeystoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(s.trim().to_string())
}

fn write_atomic(path: &Path, body: &[u8]) -> Result<(), KeystoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("write")
    ));
    fs::write(&tmp, body).map_err(|source| KeystoreError::Io {
        path: tmp.clone(),
        source,
    })?;
    fs::rename(&tmp, path).map_err(|source| KeystoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn decode_priv_hex(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let v = hex::decode(s).map_err(|e| e.to_string())?;
    if v.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", v.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    params: &EncryptedFile,
) -> Result<[u8; 32], KeystoreError> {
    let argon = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
            .map_err(|e| KeystoreError::Argon2(e.to_string()))?,
    );
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| KeystoreError::Argon2(e.to_string()))?;
    Ok(key)
}

fn encrypt_key(plaintext: &[u8], passphrase: &str) -> Result<EncryptedFile, KeystoreError> {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let params = EncryptedFile {
        v: KEYSTORE_VERSION,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce_bytes),
        m_cost: ARGON2_M_COST,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
        ciphertext_hex: String::new(),
    };
    let mut key = derive_key(passphrase, &salt, &params)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: b"bloom-keystore-v1",
            },
        )
        .map_err(|e| KeystoreError::Aead(e.to_string()))?;
    key.zeroize();
    Ok(EncryptedFile {
        ciphertext_hex: hex::encode(&ciphertext),
        ..params
    })
}

fn decrypt_key(enc: &EncryptedFile, passphrase: &str) -> Result<[u8; 32], KeystoreError> {
    if enc.v != KEYSTORE_VERSION {
        return Err(KeystoreError::Malformed(format!(
            "unknown version {}",
            enc.v
        )));
    }
    let salt =
        hex::decode(&enc.salt_hex).map_err(|e| KeystoreError::Malformed(format!("salt: {e}")))?;
    let nonce_b =
        hex::decode(&enc.nonce_hex).map_err(|e| KeystoreError::Malformed(format!("nonce: {e}")))?;
    if nonce_b.len() != 12 {
        return Err(KeystoreError::Malformed("nonce length".into()));
    }
    let ct = hex::decode(&enc.ciphertext_hex)
        .map_err(|e| KeystoreError::Malformed(format!("ciphertext: {e}")))?;
    let mut key = derive_key(passphrase, &salt, enc)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_b);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: b"bloom-keystore-v1",
            },
        )
        .map_err(|e| KeystoreError::Aead(e.to_string()))?;
    key.zeroize();
    if pt.len() != 32 {
        return Err(KeystoreError::Malformed(format!(
            "plaintext len {} != 32",
            pt.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, Keystore) {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path()).unwrap();
        (dir, ks)
    }

    #[test]
    fn create_unlock_round_trip() {
        let (_dir, ks) = temp_store();
        let info = ks.create_local("alice", "secret").unwrap();
        assert_eq!(info.kind, WalletKind::Local);
        assert!(info.pubkey_hex.len() >= 64);
        assert!(!ks.is_unlocked("alice"));
        ks.unlock("alice", "secret").unwrap();
        assert!(ks.is_unlocked("alice"));
        let s = ks.signer("alice").unwrap();
        assert_eq!(s.address(), info.address);
        ks.lock("alice");
        assert!(!ks.is_unlocked("alice"));
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let (_dir, ks) = temp_store();
        ks.create_local("bob", "right").unwrap();
        assert!(ks.unlock("bob", "wrong").is_err());
    }

    #[test]
    fn list_returns_metadata() {
        let (_dir, ks) = temp_store();
        ks.create_local("alice", "p").unwrap();
        let pk = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        ks.import_hex("carol", pk, "p").unwrap();
        let l = ks.list().unwrap();
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn watch_only_can_be_added() {
        let (_dir, ks) = temp_store();
        let addr: Address = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
            .parse()
            .unwrap();
        let info = ks.add_watch("vitalik", addr).unwrap();
        assert_eq!(info.kind, WalletKind::Watch);
        assert!(ks.unlock("vitalik", "anything").is_err());
    }

    #[test]
    fn private_key_never_appears_on_disk() {
        let (dir, ks) = temp_store();
        let pk = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        ks.import_hex("dave", pk, "p").unwrap();
        for ent in walkdir(dir.path()) {
            if let Ok(s) = fs::read_to_string(&ent) {
                assert!(!s.contains(pk.trim_start_matches("0x")));
                assert!(!s.contains(pk));
            }
        }
    }

    fn walkdir(p: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if p.is_dir() {
            for e in fs::read_dir(p).unwrap() {
                let e = e.unwrap();
                let path = e.path();
                if path.is_dir() {
                    out.extend(walkdir(&path));
                } else {
                    out.push(path);
                }
            }
        }
        out
    }
}
