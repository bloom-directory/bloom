//! Asynchronous, daemon-owned wallet passkey registration (VFS-exposed).
//!
//! `ceremony_url` is an untrusted routing capability: any local process that
//! reads it from the VFS can create junk attempts or cause bounded denial of
//! service, but cannot mutate a policy attempt already bound to a WebAuthn
//! challenge, obtain a recovery key, or commit a wallet without presenting a
//! server-verified WebAuthn credential/assertion. See
//! `docs/plans/2026-07-21-async-vfs-passkey-registration.md` for the full
//! protocol and its numbered security invariants.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::AuthApiError;

/// Schema tag for `status.json`.
pub const WALLET_REGISTRATION_STATUS_SCHEMA_V1: &str = "bloom.wallet_registration_status.v1";

/// Domain separator for the registration challenge hash. See
/// [`RegistrationIntent::challenge_hash`].
const WALLET_REGISTRATION_CHALLENGE_DOMAIN: &[u8] = b"bloom.wallet_registration.v1";

/// Registration-protocol version exposed in daemon status so a newer CLI can
/// detect an older daemon that predates this protocol and ask the caller to
/// restart `bloom serve`.
pub const WALLET_REGISTRATION_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletRegistrationState {
    AwaitingUser,
    AwaitingRecoveryAck,
    Completed,
    Failed,
    Expired,
    Cancelled,
}

impl WalletRegistrationState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Expired | Self::Cancelled
        )
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::AwaitingUser | Self::AwaitingRecoveryAck)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingUser => "awaiting_user",
            Self::AwaitingRecoveryAck => "awaiting_recovery_ack",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "awaiting_user" => Self::AwaitingUser,
            "awaiting_recovery_ack" => Self::AwaitingRecoveryAck,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "expired" => Self::Expired,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }
}

/// Public projection of a wallet registration session. Never contains PRF
/// output, private keys, recovery keys, completion receipts, challenges, or
/// raw WebAuthn data (invariant 9 in the plan: only public metadata is
/// persisted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletRegistrationStatus {
    pub schema: String,
    pub wallet: String,
    pub state: WalletRegistrationState,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    /// `None` once the session is terminal — never retained as historical
    /// secret text (spec: "status may retain the URL as null").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl WalletRegistrationStatus {
    pub fn awaiting_user(
        wallet: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
        ceremony_url: impl Into<String>,
    ) -> Self {
        Self {
            schema: WALLET_REGISTRATION_STATUS_SCHEMA_V1.into(),
            wallet: wallet.into(),
            state: WalletRegistrationState::AwaitingUser,
            created_at_ms,
            expires_at_ms,
            ceremony_url: Some(ceremony_url.into()),
            address: None,
            error: None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

/// Canonical fields a registration attempt's WebAuthn challenge is bound to.
/// Changing any field changes the resulting challenge hash, so verification
/// against stale/mismatched state fails (spec §"HTTP protocol and state
/// machine" step 2).
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationIntent {
    pub session_id: String,
    pub attempt_id: String,
    pub wallet: String,
    pub policy_blake3: String,
    pub prf_salt_digest: String,
    pub expiry_ms: u64,
    pub server_nonce: String,
}

impl RegistrationIntent {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthApiError> {
        serde_json::to_vec(self).map_err(AuthApiError::Json)
    }

    /// `BLAKE3("bloom.wallet_registration.v1" || webauthn_random_challenge ||
    /// canonical(self))`. `webauthn_random_challenge` is the random challenge
    /// bytes `webauthn-rs` generated for this attempt.
    pub fn challenge_hash(
        &self,
        webauthn_random_challenge: &[u8],
    ) -> Result<[u8; 32], AuthApiError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(WALLET_REGISTRATION_CHALLENGE_DOMAIN);
        hasher.update(webauthn_random_challenge);
        hasher.update(&self.canonical_bytes()?);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Read-only session view served at `GET /wallet-registration/{token}/session.json`.
/// Contains no secrets — only what the registration page needs to render
/// before the user picks a passkey method.
#[derive(Debug, Clone, Serialize)]
pub struct WalletRegistrationSessionView {
    pub wallet: String,
    pub state: WalletRegistrationState,
    pub expires_at_ms: u64,
    pub default_policy_toml: String,
}

/// Response to `POST /wallet-registration/{token}/attempts`: a fresh,
/// immutable policy attempt plus WebAuthn creation options.
#[derive(Debug, Clone, Serialize)]
pub struct WalletRegistrationAttemptOptions {
    pub attempt_id: String,
    pub policy_toml: String,
    pub policy_blake3: String,
    /// Full `navigator.credentials.create()` options JSON (challenge + PRF ext).
    pub creation_options_json: serde_json::Value,
}

/// Response to `POST /wallet-registration/{token}/attempts/{attempt}/fallback-options`.
#[derive(Debug, Clone, Serialize)]
pub struct WalletRegistrationFallbackOptions {
    /// Full `navigator.credentials.get()` options JSON (challenge + PRF ext).
    pub request_options_json: serde_json::Value,
}

/// Body of `POST /wallet-registration/{token}/attempts/{attempt}/complete`.
/// `Registration` carries `create()`'s output when PRF arrived directly;
/// `Fallback` carries `get()`'s output for the two-ceremony PRF fallback.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WalletRegistrationCompleteBody {
    Registration {
        credential: serde_json::Value,
        prf_output_b64: String,
    },
    Fallback {
        credential: serde_json::Value,
        prf_output_b64: String,
    },
}

/// Success payload for `/complete`. `recovery_key` and `receipt` are the
/// *only* place either value is ever constructed outside browser page
/// memory — never persisted, logged, or returned by any other endpoint
/// (invariants 7, 8, 11).
pub struct WalletRegistrationCompleteOutcome {
    pub address: String,
    pub recovery_key: Zeroizing<String>,
    pub receipt: Zeroizing<String>,
}

/// Daemon-owned coordinator for asynchronous passkey registration.
///
/// Split by caller: the VFS-facing, wallet-keyed methods are called only by
/// `WalletsHandler` (never accept or expose a URL token as a capability
/// check bypass); the HTTP-facing, token-keyed methods are called only by
/// the loopback ceremony server and must never accept a wallet name from
/// the browser — the token is the sole capability.
///
/// Implementations own all in-memory secret state (signers, PRF salts,
/// WebAuthn verification state, prepared wallet files, recovery
/// keys/receipts) and persist only [`WalletRegistrationStatus`] rows via
/// [`crate::AuthStoreWriter::upsert_wallet_registration_status`].
#[async_trait]
pub trait WalletRegistrationCoordinator: Send + Sync {
    /// Arm the coordinator: called exactly once by the process that binds
    /// the shared loopback ceremony listener, immediately after the bind
    /// succeeds. Before this is called, [`Self::stage`] fails closed.
    fn mark_listener_bound(&self, base_url: &str);

    /// Restart reconciliation: mark every persisted, non-terminal
    /// registration session `failed` with `reason`. Must be called only by
    /// the process that just proved exclusive ownership of the shared
    /// ceremony listener (i.e. immediately before [`Self::mark_listener_bound`],
    /// after a successful bind) — a one-shot CLI command that merely
    /// constructs a coordinator without ever binding the listener has no
    /// basis for concluding any persisted session is actually dead, and
    /// calling this unconditionally would let it stomp on state a live
    /// `bloom serve` still owns in memory.
    async fn reconcile_after_restart(&self, reason: &str, now_ms: u64)
    -> Result<u64, AuthApiError>;

    // ── VFS-facing (wallet-keyed) ───────────────────────────────────────

    /// Create or idempotently return the one live registration session for
    /// `wallet`. Fails closed if not armed (no `bloom serve` reachable) or
    /// if the wallet already exists/has completed.
    async fn stage(
        &self,
        wallet: &str,
        now_ms: u64,
    ) -> Result<WalletRegistrationStatus, AuthApiError>;

    async fn status(&self, wallet: &str) -> Result<Option<WalletRegistrationStatus>, AuthApiError>;

    /// All wallet names with a known registration session (live or recent).
    async fn list_wallets(&self) -> Result<Vec<String>, AuthApiError>;

    async fn cancel(&self, wallet: &str, now_ms: u64) -> Result<(), AuthApiError>;

    // ── HTTP-facing (token-keyed) ───────────────────────────────────────

    async fn session_view(
        &self,
        token: &str,
        now_ms: u64,
    ) -> Result<WalletRegistrationSessionView, AuthApiError>;

    async fn create_attempt(
        &self,
        token: &str,
        policy_toml: String,
        now_ms: u64,
    ) -> Result<WalletRegistrationAttemptOptions, AuthApiError>;

    async fn fallback_options(
        &self,
        token: &str,
        attempt_id: &str,
        credential_json: serde_json::Value,
        now_ms: u64,
    ) -> Result<WalletRegistrationFallbackOptions, AuthApiError>;

    async fn complete(
        &self,
        token: &str,
        attempt_id: &str,
        body: WalletRegistrationCompleteBody,
        now_ms: u64,
    ) -> Result<WalletRegistrationCompleteOutcome, AuthApiError>;

    /// Requires the completion receipt returned by [`Self::complete`], not
    /// merely the VFS-visible URL token (invariant 8).
    async fn recovery_ack(
        &self,
        token: &str,
        receipt: &str,
        now_ms: u64,
    ) -> Result<String, AuthApiError>;

    async fn cancel_by_token(&self, token: &str, now_ms: u64) -> Result<(), AuthApiError>;

    // ── Maintenance ──────────────────────────────────────────────────────

    /// Expire timed-out sessions/attempts and remove their secret/temp
    /// state. Returns the number of sessions successfully reconciled to a
    /// persisted `Expired` status. A session whose persisted-status write
    /// fails is deliberately left in memory (not counted, and not removed)
    /// so the next sweep retries it — on retry-exhaustion-adjacent failure
    /// this returns `Err` so callers can surface it, mirroring
    /// `bloom_tx::Outbox::sweep_expired`'s `Ok(usize)`/`Err` shape.
    async fn sweep_expired(&self, now_ms: u64) -> Result<usize, AuthApiError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_intent() -> RegistrationIntent {
        RegistrationIntent {
            session_id: "sess-1".into(),
            attempt_id: "att-1".into(),
            wallet: "main".into(),
            policy_blake3: "policy-digest".into(),
            prf_salt_digest: "salt-digest".into(),
            expiry_ms: 1_000,
            server_nonce: "nonce-1".into(),
        }
    }

    #[test]
    fn challenge_hash_changes_with_any_bound_field() {
        let webauthn_challenge = b"webauthn-random-challenge";
        let base = base_intent()
            .challenge_hash(webauthn_challenge)
            .expect("base hash");

        let variants: Vec<RegistrationIntent> = vec![
            RegistrationIntent {
                wallet: "other".into(),
                ..base_intent()
            },
            RegistrationIntent {
                policy_blake3: "different-policy-digest".into(),
                ..base_intent()
            },
            RegistrationIntent {
                prf_salt_digest: "different-salt-digest".into(),
                ..base_intent()
            },
            RegistrationIntent {
                expiry_ms: 2_000,
                ..base_intent()
            },
            RegistrationIntent {
                attempt_id: "att-2".into(),
                ..base_intent()
            },
            RegistrationIntent {
                session_id: "sess-2".into(),
                ..base_intent()
            },
            RegistrationIntent {
                server_nonce: "nonce-2".into(),
                ..base_intent()
            },
        ];

        for variant in variants {
            let hash = variant
                .challenge_hash(webauthn_challenge)
                .expect("variant hash");
            assert_ne!(hash, base, "field change did not change the challenge hash");
        }

        // The webauthn-rs random challenge is itself part of the preimage:
        // reusing the same intent with a different underlying random
        // challenge must also change the hash.
        let different_random = base_intent()
            .challenge_hash(b"a-different-webauthn-random-challenge")
            .expect("different random hash");
        assert_ne!(different_random, base);

        // Same inputs are deterministic.
        let repeat = base_intent()
            .challenge_hash(webauthn_challenge)
            .expect("repeat hash");
        assert_eq!(repeat, base);
    }
}
