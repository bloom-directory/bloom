//! Shared types and narrow interfaces for daemon-owned passkey registration.

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

/// Persisted public projection; never contains credential or key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletRegistrationStatus {
    pub schema: String,
    pub wallet: String,
    pub state: WalletRegistrationState,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
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

/// Canonical fields bound into an attempt's WebAuthn challenge.
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

/// Public data needed to render the ceremony.
#[derive(Debug, Clone, Serialize)]
pub struct WalletRegistrationSessionView {
    pub wallet: String,
    pub state: WalletRegistrationState,
    pub expires_at_ms: u64,
    pub default_policy_toml: String,
}

/// Immutable policy attempt and WebAuthn creation options.
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

/// Direct registration or two-ceremony PRF-fallback completion.
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

/// One-time secret completion payload; never persisted or logged.
pub struct WalletRegistrationCompleteOutcome {
    pub address: String,
    pub recovery_key: Zeroizing<String>,
    pub receipt: Zeroizing<String>,
}

/// Persistence used only by wallet registration. Keeping this separate from
/// the sealed-approval store traits avoids coupling unrelated auth stores and
/// test doubles to the registration protocol.
#[async_trait]
pub trait WalletRegistrationStore: Send + Sync {
    async fn status_for_wallet(
        &self,
        wallet: &str,
    ) -> Result<Option<WalletRegistrationStatus>, AuthApiError>;
    async fn status_for_session(
        &self,
        session_id: &str,
    ) -> Result<Option<WalletRegistrationStatus>, AuthApiError>;
    async fn wallets(&self) -> Result<Vec<String>, AuthApiError>;
    async fn non_terminal(&self) -> Result<Vec<(String, WalletRegistrationStatus)>, AuthApiError>;
    async fn upsert(
        &self,
        session_id: &str,
        status: &WalletRegistrationStatus,
        now_ms: u64,
    ) -> Result<(), AuthApiError>;
}

#[async_trait]
pub trait WalletRegistrationLifecycle: Send + Sync {
    fn mark_listener_bound(&self, base_url: &str);
    fn mark_listener_unbound(&self);
    async fn reconcile_after_restart(&self, reason: &str, now_ms: u64)
    -> Result<u64, AuthApiError>;

    // ── VFS-facing (wallet-keyed) ───────────────────────────────────────
}

#[async_trait]
pub trait WalletRegistrationVfs: Send + Sync {
    async fn stage(
        &self,
        wallet: &str,
        now_ms: u64,
    ) -> Result<WalletRegistrationStatus, AuthApiError>;

    async fn status(&self, wallet: &str) -> Result<Option<WalletRegistrationStatus>, AuthApiError>;

    async fn list_wallets(&self) -> Result<Vec<String>, AuthApiError>;

    async fn cancel(&self, wallet: &str, now_ms: u64) -> Result<(), AuthApiError>;

    // ── HTTP-facing (token-keyed) ───────────────────────────────────────
}

#[async_trait]
pub trait WalletRegistrationCeremony: Send + Sync {
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

    async fn recovery_ack(
        &self,
        token: &str,
        receipt: &str,
        now_ms: u64,
    ) -> Result<String, AuthApiError>;

    async fn cancel_by_token(&self, token: &str, now_ms: u64) -> Result<(), AuthApiError>;

    // ── Maintenance ──────────────────────────────────────────────────────
}

#[async_trait]
pub trait WalletRegistrationMaintenance: Send + Sync {
    async fn sweep_expired(&self, now_ms: u64) -> Result<usize, AuthApiError>;
}

pub trait WalletRegistrationCoordinator:
    WalletRegistrationLifecycle
    + WalletRegistrationMaintenance
    + WalletRegistrationVfs
    + WalletRegistrationCeremony
{
}
impl<T> WalletRegistrationCoordinator for T where
    T: WalletRegistrationLifecycle
        + WalletRegistrationMaintenance
        + WalletRegistrationVfs
        + WalletRegistrationCeremony
{
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
