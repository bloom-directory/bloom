//! Encrypted local keystore for bloom.
//!
//! ## Layout
//!
//! ```text
//! ~/.bloom/keystore/<wallet>/
//! ├── address           # 0x-prefixed checksum
//! ├── pubkey            # uncompressed secp256k1, hex
//! ├── kind              # "local" | "watch" | "passkey"
//! ├── encrypted.key     # JSON blob with cipher params + ciphertext
//! ├── prf.salt          # (passkey only) 64 hex chars, public — input to PRF
//! ├── passkey.json      # (passkey only) serialised webauthn_rs::Passkey
//! └── policy.toml
//! ```
//!
//! ## Crypto
//!
//! - KDF: argon2id, parameters chosen for ~250ms on a modern laptop (Local).
//! - Cipher: chacha20-poly1305 with a per-key random nonce.
//! - Plaintext: 32-byte secp256k1 private key, zeroized on drop.
//! - Passkey wallets use WebAuthn PRF: `wrap_key = blake3::derive_key(
//!   "bloom passkey wrap key", prf_output)` where `prf_output` is a
//!   32-byte value derived from the authenticator's internal secret and
//!   `prf.salt`. PRF output is never stored on disk.
//!
//! Private keys never leave the daemon process. Only the public address +
//! pubkey are exposed via the FS.

#![forbid(unsafe_code)]

pub mod ephemeral;
pub(crate) mod passkey;
pub use passkey::{
    FinalizedPasskeyWallet, PreparedPasskeyWallet, SealedCeremonyChallenge, bind_local,
    client_data_challenge_b64, default_passkey_policy_toml, finalize_passkey_wallet,
    finish_registration, finish_registration_fallback_assertion, foreground_registration_ceremony,
    launch_browser, prepare_passkey_wallet, start_registration_challenge,
    start_registration_fallback_assertion,
};
pub use webauthn_rs::prelude::{
    AuthenticationResult, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential,
};
pub mod petal_host;
pub mod xdsa;
#[cfg(test)]
mod xdsa_tests;

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
use zeroize::{Zeroize, Zeroizing};

use bloom_auth_api::{
    ApprovalSignatureVerifier, AuthApiError, UnsignedApproval, WebAuthnAssertionRecord,
};
use bloom_proto::{Policy, checksum_address};

// ── errors ────────────────────────────────────────────────────────────────────

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
    #[error("passkey ceremony failed: {0}")]
    PasskeyCeremony(String),
    #[error("passkey credential invalid: {0}")]
    PasskeyCredential(String),
}

/// Signing algorithm for a wallet.
///
/// New wallets default to `Xdsa` (bloom-evm native).  Existing wallets
/// without an `algorithm` field in their envelope default to `Secp256k1`
/// for backward compatibility.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// secp256k1 / ECDSA — Ethereum-interop wallets.
    #[default]
    Secp256k1,
    /// Composite ML-DSA-65 + Ed25519 — bloom-evm native wallets.
    Xdsa,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Secp256k1 => f.write_str("secp256k1"),
            Algorithm::Xdsa => f.write_str("xdsa"),
        }
    }
}

/// An on-disk address that distinguishes the two key types.
///
/// Ethereum wallets carry a 20-byte `Address`; bloom-evm xDSA wallets
/// carry a 32-byte BLAKE3 digest derived from the composite public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletAddress {
    /// 20-byte Ethereum-style address (secp256k1 wallets).
    Ethereum(Address),
    /// 32-byte bloom-evm address (xDSA wallets).
    BloomEvm([u8; 32]),
}

impl std::fmt::Display for WalletAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletAddress::Ethereum(a) => write!(f, "{}", checksum_address(a)),
            WalletAddress::BloomEvm(b) => write!(f, "{}", hex::encode(b)),
        }
    }
}

// ─── xDSA on-disk keystore helpers ───────────────────────────────────────────
//
// xDSA wallets use the same directory layout as secp256k1 wallets, with two
// differences:
//
//   • `encrypted.key` envelope: the `algorithm` field (added in v2) is set
//     to "xdsa".  Old envelopes without the field default to "secp256k1".
//   • Plaintext of the encrypted blob: 64 bytes (`mldsa_seed || ed25519_seed`)
//     instead of 32 bytes.
//   • `address` file: 64 hex chars (32-byte BLAKE3 digest) instead of 42 chars.
//   • `pubkey` file: hex-encoded 1984-byte composite public key.

/// On-disk envelope for an encrypted private key (v2 adds `algorithm`).
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFileV2 {
    /// Format version.  1 = secp256k1-only (legacy).  2 = algorithm-tagged.
    v: u8,
    /// Algorithm.  Absent in v=1 files; defaults to secp256k1 on load.
    #[serde(default, skip_serializing_if = "is_secp256k1")]
    algorithm: Algorithm,
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
    /// Hex ciphertext.
    ciphertext_hex: String,
}

fn is_secp256k1(a: &Algorithm) -> bool {
    *a == Algorithm::Secp256k1
}

/// Argon2id parameters for xDSA keystore.
const XDSA_ARGON2_M_COST: u32 = 65536; // 64 MiB
const XDSA_ARGON2_T_COST: u32 = 3;
const XDSA_ARGON2_P_COST: u32 = 4;

const XDSA_KEYSTORE_AAD: &[u8] = b"bloom-keystore-xdsa-v2";

fn derive_key_v2(
    passphrase: &str,
    salt: &[u8],
    enc: &EncryptedFileV2,
) -> Result<[u8; 32], KeystoreError> {
    let argon = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(enc.m_cost, enc.t_cost, enc.p_cost, Some(32))
            .map_err(|e| KeystoreError::Argon2(e.to_string()))?,
    );
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| KeystoreError::Argon2(e.to_string()))?;
    Ok(key)
}

fn encrypt_xdsa_key(
    secret_bytes: &[u8],
    passphrase: &str,
) -> Result<EncryptedFileV2, KeystoreError> {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let enc = EncryptedFileV2 {
        v: 2,
        algorithm: Algorithm::Xdsa,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce_bytes),
        m_cost: XDSA_ARGON2_M_COST,
        t_cost: XDSA_ARGON2_T_COST,
        p_cost: XDSA_ARGON2_P_COST,
        ciphertext_hex: String::new(),
    };
    let mut key = derive_key_v2(passphrase, &salt, &enc)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: secret_bytes,
                aad: XDSA_KEYSTORE_AAD,
            },
        )
        .map_err(|e| KeystoreError::Aead(e.to_string()))?;
    key.zeroize();
    Ok(EncryptedFileV2 {
        ciphertext_hex: hex::encode(&ciphertext),
        ..enc
    })
}

fn decrypt_xdsa_key(enc: &EncryptedFileV2, passphrase: &str) -> Result<Vec<u8>, KeystoreError> {
    let salt = hex::decode(&enc.salt_hex)
        .map_err(|e| KeystoreError::Malformed(format!("xdsa salt: {e}")))?;
    let nonce_b = hex::decode(&enc.nonce_hex)
        .map_err(|e| KeystoreError::Malformed(format!("xdsa nonce: {e}")))?;
    if nonce_b.len() != 12 {
        return Err(KeystoreError::Malformed("xdsa nonce length".into()));
    }
    let ct = hex::decode(&enc.ciphertext_hex)
        .map_err(|e| KeystoreError::Malformed(format!("xdsa ciphertext: {e}")))?;
    let mut key = derive_key_v2(passphrase, &salt, enc)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_b);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: XDSA_KEYSTORE_AAD,
            },
        )
        .map_err(|e| KeystoreError::Aead(e.to_string()))?;
    key.zeroize();
    Ok(pt)
}

// ─── XdsaWallet: algorithm-tagged xDSA wallet operations ─────────────────────

/// A loaded and decrypted xDSA wallet (secret key in memory).
pub struct XdsaWallet {
    pub name: String,
    pub address: WalletAddress,
    pub public_key: xdsa::XdsaPublicKey,
    secret: xdsa::XdsaSecretKey,
}

impl XdsaWallet {
    /// Sign a message with the xDSA secret key.
    pub fn sign(&self, msg: &[u8]) -> xdsa::XdsaSignature {
        self.secret.sign(msg)
    }

    /// The wallet's 32-byte bloom-evm address bytes.
    pub fn address_bytes(&self) -> [u8; 32] {
        match &self.address {
            WalletAddress::BloomEvm(b) => *b,
            _ => unreachable!("xDSA wallet always has a bloom-evm address"),
        }
    }
}

/// Create a new xDSA wallet on disk and return its info.
///
/// Layout under `dir/<name>/`:
/// - `encrypted.key` — JSON `EncryptedFileV2` with algorithm = "xdsa"
/// - `pubkey`        — hex-encoded 1984-byte composite public key
/// - `address`       — hex-encoded 32-byte BLAKE3 address
/// - `kind`          — "local"
/// - `algorithm`     — "xdsa"
/// - `policy.toml`   — default policy
pub fn create_xdsa_wallet(
    keystore_root: &Path,
    name: &str,
    passphrase: &str,
) -> Result<(WalletAddress, xdsa::XdsaPublicKey), KeystoreError> {
    Keystore::validate_name(name)?;
    let dir = keystore_root.join(name);
    if dir.exists() {
        return Err(KeystoreError::AlreadyExists(name.into()));
    }
    fs::create_dir_all(&dir).map_err(|source| KeystoreError::Io {
        path: dir.clone(),
        source,
    })?;

    let (sk, pk) = xdsa::XdsaSecretKey::generate();
    let secret_bytes = sk.to_bytes();
    let encrypted = encrypt_xdsa_key(secret_bytes.as_slice(), passphrase)?;
    let blob =
        serde_json::to_vec(&encrypted).map_err(|e| KeystoreError::Malformed(e.to_string()))?;
    write_atomic(&dir.join("encrypted.key"), &blob)?;

    let addr_bytes = xdsa::derive_address(&pk);
    let addr_hex = hex::encode(addr_bytes);
    let pk_hex = hex::encode(&pk.0);

    write_atomic(&dir.join("address"), addr_hex.as_bytes())?;
    write_atomic(&dir.join("pubkey"), pk_hex.as_bytes())?;
    write_atomic(&dir.join("kind"), b"local")?;
    write_atomic(&dir.join("algorithm"), b"xdsa")?;
    let default_policy = Policy::default();
    write_atomic(
        &dir.join("policy.toml"),
        toml::to_string_pretty(&default_policy)
            .map_err(|e| KeystoreError::Policy(e.to_string()))?
            .as_bytes(),
    )?;

    Ok((WalletAddress::BloomEvm(addr_bytes), pk))
}

/// Load and decrypt an xDSA wallet from disk.
pub fn load_xdsa_wallet(
    keystore_root: &Path,
    name: &str,
    passphrase: &str,
) -> Result<XdsaWallet, KeystoreError> {
    Keystore::validate_name(name)?;
    let dir = keystore_root.join(name);
    if !dir.exists() {
        return Err(KeystoreError::NotFound(name.into()));
    }

    let blob = fs::read(dir.join("encrypted.key")).map_err(|source| KeystoreError::Io {
        path: dir.join("encrypted.key"),
        source,
    })?;
    let enc: EncryptedFileV2 =
        serde_json::from_slice(&blob).map_err(|e| KeystoreError::Malformed(e.to_string()))?;

    let secret_bytes = decrypt_xdsa_key(&enc, passphrase)?;
    let sk = xdsa::XdsaSecretKey::from_bytes(&secret_bytes)?;
    let pk = sk.public_key();
    let addr_bytes = xdsa::derive_address(&pk);

    Ok(XdsaWallet {
        name: name.into(),
        address: WalletAddress::BloomEvm(addr_bytes),
        public_key: pk,
        secret: sk,
    })
}

// ── wallet kind ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletKind {
    Local,
    Watch,
    /// secp256k1 key encrypted under a PRF-derived wrap key; a WebAuthn
    /// ceremony (with PRF extension) is required before the daemon will
    /// decrypt the key.
    #[serde(rename = "passkey")]
    PasskeyGated,
}

impl std::fmt::Display for WalletKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletKind::Local => f.write_str("local"),
            WalletKind::Watch => f.write_str("watch"),
            WalletKind::PasskeyGated => f.write_str("passkey"),
        }
    }
}

/// Signature state of a wallet's `policy.toml`, for display surfaces.
/// Unlike [`Keystore::info`], reading this never fails on an unsigned or
/// stale policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    /// PasskeyGated wallet with a policy whose signature matches.
    Signed,
    /// PasskeyGated wallet has policy content but no `policy.toml.sig`.
    Unsigned,
    /// PasskeyGated wallet's signature does not match the current policy.
    Stale,
    /// Wallet kind does not require a signed policy, or has no policy.
    NotApplicable,
}

// ── public types ──────────────────────────────────────────────────────────────

/// Public-side wallet metadata.
#[derive(Debug, Clone)]
pub struct WalletInfo {
    pub name: String,
    pub address: Address,
    pub pubkey_hex: String,
    pub kind: WalletKind,
    pub policy: Policy,
    /// Raw hex private key, present exactly once: immediately after a new
    /// passkey wallet is created. `None` for all other operations.
    /// The caller must display this and treat it like a seed phrase.
    /// Uses `Zeroizing` so the heap copy is cleared when WalletInfo is dropped.
    pub recovery_key: Option<Zeroizing<String>>,
}

// ── on-disk formats ───────────────────────────────────────────────────────────

/// v=1 encrypted key: argon2id KDF + chacha20poly1305. Used by Local wallets.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFile {
    v: u8,
    salt_hex: String,
    nonce_hex: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    ciphertext_hex: String,
}

/// PRF-based encrypted key: wrap_key derived from authenticator PRF output.
/// `wrap_key = blake3::derive_key("bloom passkey wrap key", prf_output)`.
/// PRF output is never stored on disk — it is derived at each ceremony.
#[derive(Debug, Serialize, Deserialize)]
struct PasskeyEncrypted {
    v: u8,
    nonce_hex: String,
    ciphertext_hex: String,
}

// ── constants ─────────────────────────────────────────────────────────────────

const KEYSTORE_VERSION: u8 = 1;
const ARGON2_M_COST: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const KEYSTORE_AAD: &[u8] = b"bloom-keystore-v1";
const LEGACY_BETH_KEYSTORE_AAD: &[u8] = b"beth-keystore-v1";

// ── keystore ──────────────────────────────────────────────────────────────────

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

    /// Validate a wallet name: non-empty, at most 64 bytes, and restricted to
    /// `[A-Za-z0-9_-]` — no path separators, `..`, or other characters that
    /// could escape the keystore root once the name is joined into a
    /// filesystem path. `pub` so callers that stage a wallet without going
    /// through a `Keystore` method first (e.g. the daemon's asynchronous
    /// passkey registration coordinator) can apply the identical rule before
    /// the name ever reaches a `Path::join`.
    pub fn validate_name(name: &str) -> Result<(), KeystoreError> {
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

    // ── list / info ───────────────────────────────────────────────────────────

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
                    // Listings use the unverified read so a passkey wallet with
                    // an unsigned/stale policy stays visible — hiding it is what
                    // led an agent to mistake a deposit wallet for the owner.
                    match self.info_unverified(name) {
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

    /// Raw `policy.toml` content + wallet kind, **without** signature
    /// verification. For displaying what `sign_policy` is about to sign:
    /// the only time re-signing is needed is precisely when the file is
    /// modified-but-unsigned, so verification here would make `sign-policy`
    /// unusable for its purpose. The authorization is the unlock ceremony
    /// that follows, with this content shown first.
    pub fn raw_policy(&self, name: &str) -> Result<(String, WalletKind), KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if !dir.exists() {
            return Err(KeystoreError::NotFound(name.into()));
        }
        let kind: WalletKind = match read_trim(&dir.join("kind"))?.as_str() {
            "local" => WalletKind::Local,
            "watch" => WalletKind::Watch,
            "passkey" => WalletKind::PasskeyGated,
            other => return Err(KeystoreError::Malformed(format!("kind: {other}"))),
        };
        let policy_path = dir.join("policy.toml");
        let content = if policy_path.exists() {
            fs::read_to_string(&policy_path).map_err(|source| KeystoreError::Io {
                path: policy_path,
                source,
            })?
        } else {
            String::new()
        };
        Ok((content, kind))
    }

    /// Wallet identity + parsed policy **without** verifying the passkey
    /// policy signature. Read-only surfaces (address, balances, listings) use
    /// this so an unsigned/stale `policy.toml` never blocks a read — the
    /// signature is a write-time authorization control, enforced by [`info`].
    pub fn info_unverified(&self, name: &str) -> Result<WalletInfo, KeystoreError> {
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
            "passkey" => WalletKind::PasskeyGated,
            other => return Err(KeystoreError::Malformed(format!("kind: {other}"))),
        };

        let policy_content = if policy_path.exists() {
            fs::read_to_string(&policy_path).map_err(|source| KeystoreError::Io {
                path: policy_path.clone(),
                source,
            })?
        } else {
            String::new()
        };
        let policy = if policy_content.is_empty() {
            Policy::default()
        } else {
            toml::from_str::<Policy>(&policy_content)
                .map_err(|e| KeystoreError::Policy(e.to_string()))?
        };

        Ok(WalletInfo {
            name: name.into(),
            address,
            pubkey_hex,
            kind,
            policy,
            recovery_key: None,
        })
    }

    /// Wallet identity + parsed policy, **verifying** the passkey policy
    /// signature. Write/sign/broadcast paths use this: a `PasskeyGated` wallet
    /// whose `policy.toml` is unsigned or modified-since-signed is rejected,
    /// so a tampered policy cannot authorize a mutation.
    pub fn info(&self, name: &str) -> Result<WalletInfo, KeystoreError> {
        let info = self.info_unverified(name)?;
        // Phase 2: verify policy.toml.sig for PasskeyGated wallets.
        if info.kind == WalletKind::PasskeyGated {
            let dir = self.wallet_path(name);
            let policy_path = dir.join("policy.toml");
            let policy_content = if policy_path.exists() {
                fs::read_to_string(&policy_path).map_err(|source| KeystoreError::Io {
                    path: policy_path.clone(),
                    source,
                })?
            } else {
                String::new()
            };
            if !policy_content.is_empty() {
                let sig_path = dir.join("policy.toml.sig");
                if sig_path.exists() {
                    passkey::verify_policy_sig(name, &policy_content, &info.address, &sig_path)?;
                } else {
                    return Err(KeystoreError::Policy(
                        "passkey wallet policy.toml is missing policy.toml.sig".into(),
                    ));
                }
            }
        }
        Ok(info)
    }

    /// Signature state of a wallet's `policy.toml`, for *display*. Never errors
    /// on an unsigned/stale policy (unlike [`info`]); local/watch wallets and
    /// passkey wallets with no policy report [`PolicyStatus::NotApplicable`].
    pub fn policy_status(&self, name: &str) -> Result<PolicyStatus, KeystoreError> {
        let info = self.info_unverified(name)?;
        if info.kind != WalletKind::PasskeyGated {
            return Ok(PolicyStatus::NotApplicable);
        }
        let dir = self.wallet_path(name);
        let policy_path = dir.join("policy.toml");
        let policy_content = if policy_path.exists() {
            fs::read_to_string(&policy_path).map_err(|source| KeystoreError::Io {
                path: policy_path.clone(),
                source,
            })?
        } else {
            String::new()
        };
        if policy_content.is_empty() {
            return Ok(PolicyStatus::NotApplicable);
        }
        let sig_path = dir.join("policy.toml.sig");
        if !sig_path.exists() {
            return Ok(PolicyStatus::Unsigned);
        }
        match passkey::verify_policy_sig(name, &policy_content, &info.address, &sig_path) {
            Ok(()) => Ok(PolicyStatus::Signed),
            Err(_) => Ok(PolicyStatus::Stale),
        }
    }

    // ── create / import ───────────────────────────────────────────────────────

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
            recovery_key: None,
        })
    }

    // ── unlock ────────────────────────────────────────────────────────────────

    pub fn unlock(&self, name: &str, passphrase: &str) -> Result<(), KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if !dir.exists() {
            tracing::debug!(wallet = name, "keystore.unlock_not_found");
            return Err(KeystoreError::NotFound(name.into()));
        }
        match read_trim(&dir.join("kind"))?.as_str() {
            "local" => {}
            "passkey" => {
                return Err(KeystoreError::Locked(format!(
                    "{name}: passkey wallet — use unlock_passkey instead"
                )));
            }
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
        }
        let blob = fs::read(dir.join("encrypted.key")).map_err(|source| {
            tracing::debug!(wallet = name, error = %source, "keystore.unlock_read_failed");
            KeystoreError::Io {
                path: dir.join("encrypted.key"),
                source,
            }
        })?;
        let enc: EncryptedFile = serde_json::from_slice(&blob).map_err(|e| {
            tracing::debug!(wallet = name, error = %e, "keystore.unlock_blob_malformed");
            KeystoreError::Malformed(e.to_string())
        })?;
        let key_bytes = decrypt_key(&enc, passphrase).inspect_err(|e| {
            tracing::debug!(wallet = name, error = %e, "keystore.unlock_decrypt_failed");
        })?;
        let signer = PrivateKeySigner::from_bytes(&key_bytes.into()).map_err(|e| {
            tracing::debug!(wallet = name, error = %e, "keystore.unlock_signer_failed");
            KeystoreError::Signer(e.to_string())
        })?;
        self.inner
            .unlocked
            .write()
            .insert(name.to_string(), Arc::new(signer));
        tracing::debug!(wallet = name, "keystore.unlocked");
        Ok(())
    }

    /// Write new policy content for `name` and, for PasskeyGated wallets,
    /// immediately re-sign it. Returns `Locked` without touching disk if the
    /// wallet is a passkey wallet that has not been unlocked yet.
    pub fn write_policy(&self, name: &str, toml_bytes: &[u8]) -> Result<(), KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if !dir.exists() {
            return Err(KeystoreError::NotFound(name.into()));
        }
        let content = std::str::from_utf8(toml_bytes)
            .map_err(|e| KeystoreError::Policy(format!("policy must be UTF-8: {e}")))?;
        // Validate TOML is parseable before touching disk.
        toml::from_str::<Policy>(content)
            .map_err(|e| KeystoreError::Policy(format!("invalid policy TOML: {e}")))?;

        let kind_str = read_trim(&dir.join("kind"))?;

        // For passkey wallets check the signer is available BEFORE writing
        // anything, so disk stays consistent if the wallet is locked.
        if kind_str == "passkey" {
            let _ = self.cached_signer(name)?;
        }

        write_atomic(&dir.join("policy.toml"), toml_bytes)?;

        if kind_str == "passkey" {
            self.sign_policy(name)?;
        }
        tracing::debug!(wallet = name, "keystore.policy_written");
        Ok(())
    }

    // ── lock / signer / delete ────────────────────────────────────────────────

    pub fn lock(&self, name: &str) {
        self.inner.unlocked.write().remove(name);
    }

    pub fn is_unlocked(&self, name: &str) -> bool {
        self.inner.unlocked.read().contains_key(name)
    }

    /// Install a recovered signer into the in-memory cache for an explicit
    /// local debug session. The signer must control the wallet's persisted
    /// address. Nothing is written to disk.
    #[cfg(feature = "unsafe-debug-signer")]
    pub fn install_unsafe_debug_signer(
        &self,
        name: &str,
        signer: Arc<PrivateKeySigner>,
    ) -> Result<(), KeystoreError> {
        let expected = self.info_unverified(name)?.address;
        if signer.address() != expected {
            return Err(KeystoreError::Signer(format!(
                "debug signer address {} does not match wallet address {expected}",
                signer.address()
            )));
        }
        self.inner.unlocked.write().insert(name.to_string(), signer);
        tracing::warn!(wallet = name, "keystore.unsafe_debug_signer_installed");
        Ok(())
    }

    pub fn signer(&self, name: &str) -> Result<Arc<PrivateKeySigner>, KeystoreError> {
        let info = self.info_unverified(name)?;
        if info.kind == WalletKind::PasskeyGated {
            return Err(KeystoreError::Signer(
                "passkey wallet signing requires a Sealed Approval grant via PetalHost::sign_hash"
                    .into(),
            ));
        }
        self.cached_signer(name)
    }

    pub(crate) fn cached_signer(&self, name: &str) -> Result<Arc<PrivateKeySigner>, KeystoreError> {
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

    // ── local wallet internals ────────────────────────────────────────────────

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

        let mut key_bytes = signer.to_bytes();
        let encrypted = encrypt_key(key_bytes.as_slice(), passphrase)?;
        key_bytes.zeroize();
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
            recovery_key: None,
        })
    }
}

#[derive(Clone)]
pub struct KeystoreApprovalSignatureVerifier {
    keystore: Keystore,
}

impl KeystoreApprovalSignatureVerifier {
    pub fn new(keystore: Keystore) -> Self {
        Self { keystore }
    }
}

#[async_trait::async_trait]
impl ApprovalSignatureVerifier for KeystoreApprovalSignatureVerifier {
    async fn verify_signature(
        &self,
        unsigned: &UnsignedApproval,
        webauthn_assertion: &WebAuthnAssertionRecord,
        _now_ms: u64,
    ) -> Result<(), AuthApiError> {
        match self
            .keystore
            .verify_approval_signature_with_passkey(unsigned, webauthn_assertion)
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => Err(AuthApiError::Denied(e.to_string())),
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

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

/// Decode a `0x`-prefixed or bare hex-encoded 32-byte private key.
pub fn decode_priv_hex(s: &str) -> Result<[u8; 32], String> {
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

// ── v=1 crypto (Local wallets, argon2id + chacha20poly1305) ──────────────────

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
                aad: KEYSTORE_AAD,
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
    let pt = decrypt_with_aad(&cipher, nonce, &ct, KEYSTORE_AAD).or_else(|_| {
        // Pre-rename live keystores were written by `beth` with the legacy AAD.
        // Keep reads backward-compatible; suggest re-encrypting.
        tracing::warn!("decrypting with legacy beth AAD — re-create wallet to upgrade");
        decrypt_with_aad(&cipher, nonce, &ct, LEGACY_BETH_KEYSTORE_AAD)
    })?;
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

fn decrypt_with_aad(
    cipher: &ChaCha20Poly1305,
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| KeystoreError::Aead(e.to_string()))
}

// ── tests ──────────────────────────────────────────────────────────────────────

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
    fn public_signer_rejects_passkey_wallet_even_when_cached() {
        let (dir, ks) = temp_store();
        let (_wallet_dir, _) = setup_passkey_dir(dir.path(), "pk-cached");
        ks.inner
            .unlocked
            .write()
            .insert("pk-cached".into(), Arc::new(PrivateKeySigner::random()));

        let err = ks.signer("pk-cached").unwrap_err();
        assert!(
            matches!(err, KeystoreError::Signer(_)),
            "expected passkey signer migration error, got: {err}"
        );
        assert!(
            err.to_string().contains("PetalHost::sign_hash"),
            "error should point to grant-backed host signing: {err}"
        );
        assert!(
            ks.cached_signer("pk-cached").is_ok(),
            "internal sealed/passkey paths can still use the cached signer"
        );
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let (_dir, ks) = temp_store();
        ks.create_local("bob", "right").unwrap();
        assert!(ks.unlock("bob", "wrong").is_err());
    }

    #[test]
    fn decrypt_accepts_legacy_beth_aad() {
        let mut salt = [0u8; 32];
        salt[0] = 1;
        let nonce_bytes = [2u8; 12];
        let mut enc = EncryptedFile {
            v: KEYSTORE_VERSION,
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce_bytes),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
            ciphertext_hex: String::new(),
        };
        let mut key = derive_key("legacy-pass", &salt, &enc).unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = [7u8; 32];
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: LEGACY_BETH_KEYSTORE_AAD,
                },
            )
            .unwrap();
        key.zeroize();
        enc.ciphertext_hex = hex::encode(ciphertext);
        assert_eq!(decrypt_key(&enc, "legacy-pass").unwrap(), plaintext);
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

    #[test]
    fn prf_key_encryption_round_trip() {
        let plaintext = [42u8; 32];
        let mut prf_output = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_output);
        let enc = passkey::encrypt_passkey_key(&plaintext, &prf_output).unwrap();
        let decrypted = passkey::decrypt_passkey_key(&enc, &prf_output).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn prf_key_wrong_prf_rejected() {
        let plaintext = [42u8; 32];
        let mut prf_output = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_output);
        let enc = passkey::encrypt_passkey_key(&plaintext, &prf_output).unwrap();
        let mut bad_prf = prf_output;
        bad_prf[0] ^= 0xff;
        assert!(passkey::decrypt_passkey_key(&enc, &bad_prf).is_err());
    }

    // ── policy-sig tests ──────────────────────────────────────────────────────

    /// Helper: create a local wallet, unlock it (signer in memory), then
    /// overwrite `kind` to "passkey" so sign_policy accepts it.  This lets
    /// us test the sign/verify cycle without a real WebAuthn ceremony.
    ///
    /// NOTE: this wallet uses V1 crypto (argon2id), not PRF-based passkey
    /// crypto. It only tests the secp256k1 sign/verify path, NOT the passkey
    /// ceremony gating.  Use `passkey_kind_round_trip` for tests that
    /// exercise the real PasskeyGated directory layout.
    fn make_unlocked_passkey_wallet(ks: &Keystore, root: &Path, name: &str) {
        ks.create_local(name, "p").unwrap();
        ks.unlock(name, "p").unwrap();
        // Overwrite kind so sign_policy accepts this wallet.
        let kind_path = root.join(name).join("kind");
        fs::write(&kind_path, b"passkey").unwrap();
    }

    /// sign_policy + verify_policy_sig: happy path round-trip.
    #[test]
    fn policy_signing_round_trip() {
        let (dir, ks) = temp_store();
        make_unlocked_passkey_wallet(&ks, dir.path(), "alice");

        ks.sign_policy("alice").unwrap();

        let wallet_dir = dir.path().join("alice");
        let policy_content = fs::read_to_string(wallet_dir.join("policy.toml")).unwrap();
        // Re-read address from disk (info() warns on missing sig, which is fine here
        // since we haven't signed via the keystore flow yet, but we just wrote the sig).
        let addr_str = read_trim(&wallet_dir.join("address")).unwrap();
        let address = addr_str.parse::<Address>().unwrap();
        let sig_path = wallet_dir.join("policy.toml.sig");
        // Must exist
        assert!(sig_path.exists(), "policy.toml.sig was not written");
        // Must verify cleanly against the correct address
        passkey::verify_policy_sig("alice", &policy_content, &address, &sig_path).unwrap();
    }

    /// Tampering with policy content is detected at verification time.
    #[test]
    fn policy_sig_tamper_detected() {
        let (dir, ks) = temp_store();
        make_unlocked_passkey_wallet(&ks, dir.path(), "alice");
        ks.sign_policy("alice").unwrap();

        let wallet_dir = dir.path().join("alice");
        let addr_str = read_trim(&wallet_dir.join("address")).unwrap();
        let address = addr_str.parse::<Address>().unwrap();
        let sig_path = wallet_dir.join("policy.toml.sig");
        let tampered = "# tampered content\n[caps]\nallow_all = true\n";
        let err = passkey::verify_policy_sig("alice", tampered, &address, &sig_path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("modified") || msg.contains("hash"),
            "unexpected error: {msg}"
        );
    }

    /// A signature from a different wallet address is rejected.
    #[test]
    fn policy_sig_wrong_address_rejected() {
        let (dir, ks) = temp_store();
        make_unlocked_passkey_wallet(&ks, dir.path(), "alice");
        ks.sign_policy("alice").unwrap();

        let wallet_dir = dir.path().join("alice");
        let policy_content = fs::read_to_string(wallet_dir.join("policy.toml")).unwrap();
        let sig_path = wallet_dir.join("policy.toml.sig");
        let wrong_address: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        let err = passkey::verify_policy_sig("alice", &policy_content, &wrong_address, &sig_path)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not match") || msg.contains("address"),
            "unexpected error: {msg}"
        );
    }

    /// A malformed sig file (missing required JSON fields) is rejected.
    #[test]
    fn policy_sig_missing_fields_rejected() {
        let (dir, ks) = temp_store();
        ks.create_local("alice", "p").unwrap();
        let info = ks.info("alice").unwrap();
        let wallet_dir = dir.path().join("alice");
        let sig_path = wallet_dir.join("policy.toml.sig");
        // Write a JSON object missing both required fields.
        fs::write(&sig_path, r#"{"something_else": "value"}"#).unwrap();
        let policy_content = fs::read_to_string(wallet_dir.join("policy.toml")).unwrap();
        let err = passkey::verify_policy_sig("alice", &policy_content, &info.address, &sig_path)
            .unwrap_err();
        assert!(
            matches!(err, KeystoreError::Policy(_)),
            "expected Policy error, got: {err}"
        );
    }

    // ── passkey wallet directory tests ────────────────────────────────────────

    /// Shared test helper: create a skeleton passkey wallet directory
    /// (address + pubkey + kind). Returns the directory path and parsed Address.
    fn setup_passkey_dir(root: &Path, name: &str) -> (PathBuf, Address) {
        let wallet_dir = root.join(name);
        fs::create_dir_all(&wallet_dir).unwrap();
        let addr: Address = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
            .parse()
            .unwrap();
        write_atomic(
            &wallet_dir.join("address"),
            bloom_proto::checksum_address(&addr).as_bytes(),
        )
        .unwrap();
        write_atomic(&wallet_dir.join("pubkey"), b"").unwrap();
        write_atomic(&wallet_dir.join("kind"), b"passkey").unwrap();
        (wallet_dir, addr)
    }

    /// Passkey wallet info() should error when policy.toml.sig is tampered.
    #[test]
    fn passkey_info_rejects_tampered_policy_sig() {
        let (dir, ks) = temp_store();
        let (wallet_dir, _addr) = setup_passkey_dir(dir.path(), "tamper-gate");
        let policy_toml = toml::to_string_pretty(&bloom_proto::Policy::default()).unwrap();
        write_atomic(&wallet_dir.join("policy.toml"), policy_toml.as_bytes()).unwrap();

        // Create a separate wallet, unlock it, and overwrite kind so
        // sign_policy produces a valid signature from a *different* key.
        make_unlocked_passkey_wallet(&ks, dir.path(), "signer-wallet");
        ks.sign_policy("signer-wallet").unwrap();
        let other_sig =
            std::fs::read_to_string(dir.path().join("signer-wallet").join("policy.toml.sig"))
                .unwrap();
        std::fs::write(wallet_dir.join("policy.toml.sig"), other_sig).unwrap();

        let err = ks.info("tamper-gate").unwrap_err();
        assert!(
            matches!(err, KeystoreError::Policy(_)),
            "expected Policy error, got: {err}"
        );
    }

    #[test]
    fn passkey_info_rejects_missing_policy_sig() {
        let (dir, ks) = temp_store();
        let (wallet_dir, _addr) = setup_passkey_dir(dir.path(), "unsigned-policy");
        let policy_toml = toml::to_string_pretty(&bloom_proto::Policy::default()).unwrap();
        write_atomic(&wallet_dir.join("policy.toml"), policy_toml.as_bytes()).unwrap();

        let err = ks.info("unsigned-policy").unwrap_err();
        assert!(
            matches!(err, KeystoreError::Policy(_)),
            "expected Policy error, got: {err}"
        );
        assert!(
            err.to_string().contains("policy.toml.sig"),
            "error should mention missing signature: {err}"
        );
    }

    /// Read-only path: an unsigned passkey policy blocks `info()` but
    /// `info_unverified()` still returns identity, and the wallet reports
    /// `Unsigned` rather than vanishing.
    #[test]
    fn passkey_info_unverified_tolerates_unsigned_policy() {
        let (dir, ks) = temp_store();
        let (wallet_dir, addr) = setup_passkey_dir(dir.path(), "readable-unsigned");
        let policy_toml = toml::to_string_pretty(&bloom_proto::Policy::default()).unwrap();
        write_atomic(&wallet_dir.join("policy.toml"), policy_toml.as_bytes()).unwrap();

        assert!(
            ks.info("readable-unsigned").is_err(),
            "verified info must reject"
        );
        let info = ks
            .info_unverified("readable-unsigned")
            .expect("unverified read must succeed");
        assert_eq!(info.address, addr);
        assert_eq!(
            ks.policy_status("readable-unsigned").unwrap(),
            PolicyStatus::Unsigned
        );
    }

    /// A passkey wallet with an unsigned/stale policy must remain visible in
    /// `list()` — hiding it is what led an agent to mistake a deposit wallet
    /// for the owner.
    #[test]
    fn list_includes_unsigned_passkey_wallet() {
        let (dir, ks) = temp_store();
        let (wallet_dir, _addr) = setup_passkey_dir(dir.path(), "listed-unsigned");
        let policy_toml = toml::to_string_pretty(&bloom_proto::Policy::default()).unwrap();
        write_atomic(&wallet_dir.join("policy.toml"), policy_toml.as_bytes()).unwrap();

        let names: Vec<String> = ks.list().unwrap().into_iter().map(|i| i.name).collect();
        assert!(
            names.iter().any(|n| n == "listed-unsigned"),
            "unsigned passkey wallet must still be listed, got: {names:?}"
        );
    }

    /// `policy_status` distinguishes a signed policy, a tampered (stale) one,
    /// and a non-passkey wallet.
    #[test]
    fn policy_status_reports_signed_stale_and_not_applicable() {
        let (dir, ks) = temp_store();

        // Signed: unlock + sign produces a matching signature.
        make_unlocked_passkey_wallet(&ks, dir.path(), "signed-w");
        ks.sign_policy("signed-w").unwrap();
        assert_eq!(ks.policy_status("signed-w").unwrap(), PolicyStatus::Signed);

        // Stale: transplant a signature from a different key.
        let (victim_dir, _addr) = setup_passkey_dir(dir.path(), "stale-w");
        let policy_toml = toml::to_string_pretty(&bloom_proto::Policy::default()).unwrap();
        write_atomic(&victim_dir.join("policy.toml"), policy_toml.as_bytes()).unwrap();
        let other_sig =
            std::fs::read_to_string(dir.path().join("signed-w").join("policy.toml.sig")).unwrap();
        std::fs::write(victim_dir.join("policy.toml.sig"), other_sig).unwrap();
        assert_eq!(ks.policy_status("stale-w").unwrap(), PolicyStatus::Stale);

        // Not applicable: a local wallet never requires a signed policy.
        ks.create_local("local-w", "p").unwrap();
        assert_eq!(
            ks.policy_status("local-w").unwrap(),
            PolicyStatus::NotApplicable
        );
    }

    #[test]
    fn passkey_kind_round_trip() {
        let (dir, ks) = temp_store();
        let (_wallet_dir, addr) = setup_passkey_dir(dir.path(), "passkey-test");
        // No policy.toml, passkey.json, or prf.salt — just kind="passkey".
        let info = ks.info("passkey-test").unwrap();
        assert_eq!(info.kind, WalletKind::PasskeyGated);
        assert_eq!(info.address, addr);
    }

    /// Calling unlock() (not unlock_passkey) on a passkey wallet returns a
    /// helpful error directing the user to use unlock_passkey instead.
    #[test]
    fn unlock_on_passkey_wallet_returns_helpful_error() {
        let (dir, ks) = temp_store();
        setup_passkey_dir(dir.path(), "passkey-test");
        let err = ks.unlock("passkey-test", "anything").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unlock_passkey") || msg.contains("passkey"),
            "expected helpful error, got: {msg}"
        );
        assert!(
            matches!(err, KeystoreError::Locked(_)),
            "expected Locked, got: {err}"
        );
    }

    /// unlock_passkey() called on a passkey wallet that is missing
    /// passkey.json must return an Io error before opening the browser.
    #[tokio::test]
    async fn unlock_passkey_missing_passkey_json() {
        let (dir, ks) = temp_store();
        setup_passkey_dir(dir.path(), "no-passkey");
        // No passkey.json — should fail before attempting any PRF ceremony.
        let err = ks.unlock_passkey("no-passkey").await.unwrap_err();
        assert!(
            matches!(err, KeystoreError::Io { .. }),
            "expected Io error, got: {err}"
        );
        assert!(
            err.to_string().contains("passkey.json"),
            "error should mention passkey.json: {err}"
        );
    }

    /// unlock_passkey() with a malformed passkey.json must return a
    /// PasskeyCredential error before opening the browser.
    #[tokio::test]
    async fn unlock_passkey_malformed_passkey_json() {
        let (dir, ks) = temp_store();
        let (wallet_dir, _) = setup_passkey_dir(dir.path(), "bad-passkey");
        write_atomic(&wallet_dir.join("passkey.json"), b"not valid json").unwrap();
        let err = ks.unlock_passkey("bad-passkey").await.unwrap_err();
        assert!(
            matches!(err, KeystoreError::PasskeyCredential(_)),
            "expected PasskeyCredential error, got: {err}"
        );
    }

    /// sign_policy on a Watch wallet returns a clear error (not Locked).
    #[test]
    fn sign_policy_kind_guard() {
        let (_dir, ks) = temp_store();
        let addr: Address = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
            .parse()
            .unwrap();
        ks.add_watch("watcher", addr).unwrap();
        let err = ks.sign_policy("watcher").unwrap_err();
        // Must not be Locked — must clearly indicate kind mismatch.
        assert!(
            matches!(err, KeystoreError::PasskeyCredential(_)),
            "expected PasskeyCredential error, got: {err}"
        );
        assert!(
            err.to_string().contains("passkey"),
            "error should mention passkey: {err}"
        );
    }

    /// sign_policy on a properly constructed PasskeyGated wallet that has
    /// never been unlocked must return Locked — the signer isn't cached.
    #[test]
    fn sign_policy_rejects_never_unlocked_passkey_wallet() {
        let (dir, ks) = temp_store();
        let (wallet_dir, _) = setup_passkey_dir(dir.path(), "cold-passkey");
        let policy = bloom_proto::Policy::default();
        write_atomic(
            &wallet_dir.join("policy.toml"),
            toml::to_string_pretty(&policy).unwrap().as_bytes(),
        )
        .unwrap();

        let err = ks.sign_policy("cold-passkey").unwrap_err();
        assert!(
            matches!(err, KeystoreError::Locked(_)),
            "expected Locked error (never unlocked), got: {err}"
        );
    }

    // ── write_policy tests ────────────────────────────────────────────────────

    /// write_policy on a Local wallet: writes content, no .sig file created.
    #[test]
    fn write_policy_local_happy_path() {
        let (_dir, ks) = temp_store();
        ks.create_local("local-w", "p").unwrap();
        let new_policy = "[caps]\nmax_value_eth = 1.0\n";
        ks.write_policy("local-w", new_policy.as_bytes()).unwrap();
        let info = ks.info("local-w").unwrap();
        assert_eq!(info.policy.caps.max_value_eth, Some(1.0));
    }

    /// write_policy on an unlocked passkey wallet: writes content and re-signs.
    #[test]
    fn write_policy_passkey_unlocked_resigns() {
        let (dir, ks) = temp_store();
        make_unlocked_passkey_wallet(&ks, dir.path(), "pk-w");
        // Initial sign so .sig exists.
        ks.sign_policy("pk-w").unwrap();
        // Write new policy — should re-sign automatically.
        let new_policy = "[caps]\nmax_value_eth = 2.0\n";
        ks.write_policy("pk-w", new_policy.as_bytes()).unwrap();
        // info() must not error (sig must match new content).
        let info = ks.info("pk-w").unwrap();
        assert_eq!(info.policy.caps.max_value_eth, Some(2.0));
    }

    /// write_policy on a locked passkey wallet returns Locked without touching disk.
    #[test]
    fn write_policy_passkey_locked_returns_locked_before_write() {
        let (dir, ks) = temp_store();
        let (wallet_dir, _) = setup_passkey_dir(dir.path(), "locked-pk");
        let orig = "[caps]\nmax_value_eth = 0.5\n";
        write_atomic(&wallet_dir.join("policy.toml"), orig.as_bytes()).unwrap();

        let new_policy = "[caps]\nmax_value_eth = 99.0\n";
        let err = ks
            .write_policy("locked-pk", new_policy.as_bytes())
            .unwrap_err();
        assert!(
            matches!(err, KeystoreError::Locked(_)),
            "expected Locked, got: {err}"
        );
        // Disk must be unchanged.
        let on_disk = fs::read_to_string(wallet_dir.join("policy.toml")).unwrap();
        assert_eq!(on_disk, orig, "policy.toml must not have been modified");
    }

    /// write_policy rejects invalid TOML before touching disk.
    #[test]
    fn write_policy_invalid_toml_rejected() {
        let (_dir, ks) = temp_store();
        ks.create_local("local-bad", "p").unwrap();
        let err = ks
            .write_policy("local-bad", b"not valid toml }{")
            .unwrap_err();
        assert!(
            matches!(err, KeystoreError::Policy(_)),
            "expected Policy error, got: {err}"
        );
    }

    /// Passkey wallet write path: private key never appears in any on-disk
    /// file (the encrypted.key blob must not contain the plaintext hex).
    #[test]
    fn prf_encrypted_key_does_not_contain_private_key() {
        let needle_hex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let needle_bytes = hex::decode(needle_hex).expect("valid hex");

        // Encrypt a known private key with a random PRF output.
        let mut prf_output = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_output);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&needle_bytes);
        let enc = passkey::encrypt_passkey_key(&key_bytes, &prf_output).unwrap();

        // The ciphertext (encrypted.key blob) must not contain the plaintext.
        let blob = serde_json::to_string(&enc).unwrap();
        assert!(
            !blob.contains(needle_hex),
            "plaintext hex appears in encrypted blob"
        );
        // The prf_output itself must not equal the private key.
        assert_ne!(
            &prf_output[..],
            &key_bytes[..],
            "prf_output must be independent of private key"
        );
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
