//! Daemon-owned coordinator for asynchronous, VFS-exposed passkey
//! registration. See `docs/plans/2026-07-21-async-vfs-passkey-registration.md`
//! for the full protocol and its numbered security invariants.
//!
//! All secret session/attempt state (signers, PRF salts, WebAuthn
//! verification state, prepared wallet files, recovery keys, completion
//! receipts) lives only in [`CoordinatorState`], guarded by one
//! [`parking_lot::Mutex`]. Only [`WalletRegistrationStatus`]'s public fields
//! are ever persisted, via [`AuthStoreWriter::upsert_wallet_registration_status`].
//!
//! Every state-mutating operation that must be atomic (attempt creation
//! bounds, winner selection, recovery-ack) runs its verification and its
//! state mutation inside one lock acquisition — no `.await` is ever held
//! across the lock, so a concurrent racer either sees the mutation applied
//! in full or not at all.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use base64::Engine as _;
use bloom_auth_api::{
    AuthApiError, AuthStoreView, AuthStoreWriter, RegistrationIntent,
    WalletRegistrationAttemptOptions, WalletRegistrationCompleteBody,
    WalletRegistrationCompleteOutcome, WalletRegistrationCoordinator,
    WalletRegistrationFallbackOptions, WalletRegistrationSessionView, WalletRegistrationState,
    WalletRegistrationStatus,
};
use bloom_keystore::{
    Keystore, Passkey, PasskeyAuthentication, PasskeyRegistration, PreparedPasskeyWallet,
    PublicKeyCredential, RegisterPublicKeyCredential, default_passkey_policy_toml,
    finalize_passkey_wallet, finish_registration, finish_registration_fallback_assertion,
    prepare_passkey_wallet, start_registration_challenge, start_registration_fallback_assertion,
};
use parking_lot::{Mutex, RwLock};
use rand::RngCore;
use zeroize::Zeroize;

/// Initial session TTL (spec: "Use a five-minute initial TTL unless product
/// requirements select another value").
const SESSION_TTL_MS: u64 = 5 * 60 * 1000;
/// Deadline for acknowledging recovery, counted from the moment `/complete`
/// installs a winner — deliberately separate from (and later than)
/// `SESSION_TTL_MS`, which bounds the WebAuthn ceremony itself. A completion
/// that lands close to the original session deadline must not leave the
/// human only seconds to read and save the recovery key.
const RECOVERY_ACK_TTL_MS: u64 = 5 * 60 * 1000;
/// Bound on attempts per session (spec: "Bound attempts per session (for
/// example, five)").
const MAX_ATTEMPTS: usize = 5;

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn gen_token() -> String {
    let mut t = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut t);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(t)
}

fn gen_id(prefix: &str) -> String {
    let mut t = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut t);
    format!(
        "{prefix}-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(t)
    )
}

/// One immutable policy attempt within a session. `reg_state`/`fallback` are
/// WebAuthn verification state — never serialized, never leave this process.
struct SecretAttempt {
    policy_toml: String,
    reg_state: PasskeyRegistration,
    used: bool,
    /// Set by `fallback_options` once the registration credential has been
    /// verified and consumed: the freshly-registered `Passkey` plus the
    /// authentication challenge state for the PRF-fallback assertion.
    fallback: Option<(Passkey, PasskeyAuthentication)>,
}

/// The winning attempt's prepared-but-uncommitted wallet, awaiting recovery
/// acknowledgment. Dropping this without [`finalize_passkey_wallet`] removes
/// the prepared wallet's temp directory (via `PreparedPasskeyWallet::Drop`).
struct WinnerState {
    prepared: PreparedPasskeyWallet,
    receipt: String,
    /// Identifies the exact `/complete` request that won, so an identical
    /// retry (e.g. after a dropped response) can be answered with the same
    /// outcome instead of erroring — the recovery key/receipt only ever
    /// existed in that one lost response.
    attempt_id: String,
    request_digest: [u8; 32],
    recovery_ack_expires_at_ms: u64,
}

/// Digest identifying a `/complete` request's content, for detecting an
/// exact client retry. Not a security boundary (the attempt/credential are
/// already consumed by this point) — only used to decide whether a second
/// `/complete` call is the same request replayed, not a genuinely new one.
fn complete_body_digest(attempt_id: &str, body: &WalletRegistrationCompleteBody) -> [u8; 32] {
    let (kind, credential, prf_output_b64) = match body {
        WalletRegistrationCompleteBody::Registration {
            credential,
            prf_output_b64,
        } => ("registration", credential, prf_output_b64),
        WalletRegistrationCompleteBody::Fallback {
            credential,
            prf_output_b64,
        } => ("fallback", credential, prf_output_b64),
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(attempt_id.as_bytes());
    hasher.update(kind.as_bytes());
    hasher.update(&serde_json::to_vec(credential).unwrap_or_default());
    hasher.update(prf_output_b64.as_bytes());
    *hasher.finalize().as_bytes()
}

struct SecretSession {
    wallet: String,
    signer: PrivateKeySigner,
    prf_salt: [u8; 32],
    server_nonce: String,
    created_at_ms: u64,
    expires_at_ms: u64,
    attempts: HashMap<String, SecretAttempt>,
    winner: Option<WinnerState>,
}

#[derive(Default)]
struct CoordinatorState {
    /// token -> session.
    sessions: HashMap<String, SecretSession>,
    /// wallet -> live session token.
    by_wallet: HashMap<String, String>,
}

pub struct RegistrationCoordinator {
    keystore: Keystore,
    store: Arc<dyn AuthStoreView>,
    writer: Arc<dyn AuthStoreWriter>,
    keystore_root: PathBuf,
    /// Set exactly once, by the process that binds the shared loopback
    /// ceremony listener. `stage()` fails closed while this is `None`.
    listener_base_url: RwLock<Option<String>>,
    state: Mutex<CoordinatorState>,
}

impl RegistrationCoordinator {
    pub fn new(
        keystore: Keystore,
        store: Arc<dyn AuthStoreView>,
        writer: Arc<dyn AuthStoreWriter>,
        keystore_root: PathBuf,
    ) -> Self {
        Self {
            keystore,
            store,
            writer,
            keystore_root,
            listener_base_url: RwLock::new(None),
            state: Mutex::new(CoordinatorState::default()),
        }
    }

    fn base_url(&self) -> Result<String, AuthApiError> {
        self.listener_base_url.read().clone().ok_or_else(|| {
            AuthApiError::Denied(
                "wallet registration requires a running `bloom serve` daemon that owns the \
                 loopback ceremony listener; start it with `bloom serve` and retry"
                    .into(),
            )
        })
    }

    fn ceremony_url(base: &str, token: &str) -> String {
        format!("{base}/wallet-registration/{token}")
    }

    /// Insert a fresh session for `wallet` under a new token. Caller must
    /// already hold `state`'s lock.
    fn insert_fresh_session(
        state: &mut CoordinatorState,
        wallet: &str,
        now_ms: u64,
    ) -> (String, u64, u64) {
        let mut prf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_salt);
        let token = gen_token();
        let created_at_ms = now_ms;
        let expires_at_ms = now_ms + SESSION_TTL_MS;
        state.sessions.insert(
            token.clone(),
            SecretSession {
                wallet: wallet.to_string(),
                signer: PrivateKeySigner::random(),
                prf_salt,
                server_nonce: gen_id("nonce"),
                created_at_ms,
                expires_at_ms,
                attempts: HashMap::new(),
                winner: None,
            },
        );
        state.by_wallet.insert(wallet.to_string(), token.clone());
        (token, created_at_ms, expires_at_ms)
    }
}

#[async_trait]
impl WalletRegistrationCoordinator for RegistrationCoordinator {
    fn mark_listener_bound(&self, base_url: &str) {
        *self.listener_base_url.write() = Some(base_url.to_string());
    }

    async fn reconcile_after_restart(
        &self,
        reason: &str,
        now_ms: u64,
    ) -> Result<u64, AuthApiError> {
        self.writer
            .mark_unfinished_wallet_registrations_failed(reason, now_ms)
            .await
    }

    async fn stage(
        &self,
        wallet: &str,
        now_ms: u64,
    ) -> Result<WalletRegistrationStatus, AuthApiError> {
        // Defense in depth: `wallet` is joined into a filesystem path below
        // and, on a successful ceremony, again in `recovery_ack`'s
        // `finalize_passkey_wallet` rename target. Reject anything that
        // could escape `keystore_root` even if a future caller stages
        // sessions without going through `WalletsHandler`'s own check.
        Keystore::validate_name(wallet).map_err(|e| AuthApiError::Denied(e.to_string()))?;

        let base = self.base_url()?;

        if self.keystore_root.join(wallet).exists() {
            return Err(AuthApiError::Denied(format!(
                "wallet '{wallet}' already exists"
            )));
        }
        if let Some(persisted) = self.store.wallet_registration_status(wallet).await?
            && persisted.state == WalletRegistrationState::Completed
        {
            return Err(AuthApiError::Denied(format!(
                "wallet '{wallet}' already exists"
            )));
        }

        let (token, created_at_ms, expires_at_ms) = {
            let mut state = self.state.lock();
            let live = state.by_wallet.get(wallet).cloned().and_then(|token| {
                state
                    .sessions
                    .get(&token)
                    .filter(|s| s.expires_at_ms > now_ms)
                    .map(|s| (token, s.created_at_ms, s.expires_at_ms))
            });
            match live {
                Some(triple) => triple,
                None => {
                    // Terminal/expired in-memory session for this wallet, if
                    // any: drop it before starting a fresh one.
                    if let Some(stale) = state.by_wallet.remove(wallet) {
                        state.sessions.remove(&stale);
                    }
                    Self::insert_fresh_session(&mut state, wallet, now_ms)
                }
            }
        };

        let url = Self::ceremony_url(&base, &token);
        let status =
            WalletRegistrationStatus::awaiting_user(wallet, created_at_ms, expires_at_ms, url);
        self.writer
            .upsert_wallet_registration_status(&token, &status, now_ms)
            .await?;
        Ok(status)
    }

    async fn status(&self, wallet: &str) -> Result<Option<WalletRegistrationStatus>, AuthApiError> {
        self.store.wallet_registration_status(wallet).await
    }

    async fn list_wallets(&self) -> Result<Vec<String>, AuthApiError> {
        self.store.wallet_registration_wallets().await
    }

    async fn cancel(&self, wallet: &str, now_ms: u64) -> Result<(), AuthApiError> {
        let token = {
            let mut state = self.state.lock();
            let token = state.by_wallet.remove(wallet);
            if let Some(t) = &token {
                state.sessions.remove(t);
            }
            token
        };
        let Some(token) = token else {
            return Err(AuthApiError::NotFound(format!(
                "no live registration session for wallet '{wallet}'"
            )));
        };
        let mut status = self
            .store
            .wallet_registration_status(wallet)
            .await?
            .ok_or_else(|| AuthApiError::Store("registration session status missing".into()))?;
        status.state = WalletRegistrationState::Cancelled;
        status.ceremony_url = None;
        self.writer
            .upsert_wallet_registration_status(&token, &status, now_ms)
            .await?;
        Ok(())
    }

    async fn session_view(
        &self,
        token: &str,
        now_ms: u64,
    ) -> Result<WalletRegistrationSessionView, AuthApiError> {
        let (wallet, expires_at_ms, awaiting_ack) = {
            let state = self.state.lock();
            let session = state
                .sessions
                .get(token)
                .filter(|s| s.expires_at_ms > now_ms)
                .ok_or_else(|| {
                    AuthApiError::NotFound("unknown or expired registration session".into())
                })?;
            (
                session.wallet.clone(),
                session.expires_at_ms,
                session.winner.is_some(),
            )
        };
        let default_policy_toml =
            default_passkey_policy_toml().map_err(|e| AuthApiError::Store(e.to_string()))?;
        Ok(WalletRegistrationSessionView {
            wallet,
            state: if awaiting_ack {
                WalletRegistrationState::AwaitingRecoveryAck
            } else {
                WalletRegistrationState::AwaitingUser
            },
            expires_at_ms,
            default_policy_toml,
        })
    }

    async fn create_attempt(
        &self,
        token: &str,
        policy_toml: String,
        now_ms: u64,
    ) -> Result<WalletRegistrationAttemptOptions, AuthApiError> {
        // Canonicalize and validate before binding it into a challenge —
        // must parse as `bloom_proto::Policy`, not just valid TOML.
        let policy: bloom_proto::Policy = toml::from_str(&policy_toml)
            .map_err(|e| AuthApiError::Denied(format!("invalid policy: {e}")))?;
        let canonical_policy_toml = toml::to_string_pretty(&policy)
            .map_err(|e| AuthApiError::Store(format!("policy re-serialize: {e}")))?;
        let policy_blake3 = hex::encode(blake3::hash(canonical_policy_toml.as_bytes()).as_bytes());

        let (wallet, prf_salt, server_nonce, expires_at_ms) = {
            let state = self.state.lock();
            let session = state
                .sessions
                .get(token)
                .filter(|s| s.expires_at_ms > now_ms)
                .ok_or_else(|| {
                    AuthApiError::NotFound("unknown or expired registration session".into())
                })?;
            if session.winner.is_some() {
                return Err(AuthApiError::Denied(
                    "registration already completed".into(),
                ));
            }
            if session.attempts.len() >= MAX_ATTEMPTS {
                return Err(AuthApiError::Denied(
                    "too many registration attempts for this session".into(),
                ));
            }
            (
                session.wallet.clone(),
                session.prf_salt,
                session.server_nonce.clone(),
                session.expires_at_ms,
            )
        };

        let attempt_id = gen_id("attempt");
        let mut attempt_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut attempt_nonce);
        let prf_salt_digest = hex::encode(blake3::hash(&prf_salt).as_bytes());
        let intent = RegistrationIntent {
            session_id: token.to_string(),
            attempt_id: attempt_id.clone(),
            wallet: wallet.clone(),
            policy_blake3: policy_blake3.clone(),
            prf_salt_digest,
            expiry_ms: expires_at_ms,
            server_nonce,
        };
        let challenge = intent
            .challenge_hash(&attempt_nonce)
            .map_err(|e| AuthApiError::Store(e.to_string()))?;

        let (creation_options_json, reg_state) =
            start_registration_challenge(&wallet, &prf_salt, &challenge)
                .map_err(AuthApiError::Denied)?;

        {
            let mut state = self.state.lock();
            let session = state.sessions.get_mut(token).ok_or_else(|| {
                AuthApiError::NotFound("unknown or expired registration session".into())
            })?;
            if session.winner.is_some() {
                return Err(AuthApiError::Denied(
                    "registration already completed".into(),
                ));
            }
            if session.attempts.len() >= MAX_ATTEMPTS {
                return Err(AuthApiError::Denied(
                    "too many registration attempts for this session".into(),
                ));
            }
            session.attempts.insert(
                attempt_id.clone(),
                SecretAttempt {
                    policy_toml: canonical_policy_toml.clone(),
                    reg_state,
                    used: false,
                    fallback: None,
                },
            );
        }

        Ok(WalletRegistrationAttemptOptions {
            attempt_id,
            policy_toml: canonical_policy_toml,
            policy_blake3,
            creation_options_json,
        })
    }

    async fn fallback_options(
        &self,
        token: &str,
        attempt_id: &str,
        credential_json: serde_json::Value,
        now_ms: u64,
    ) -> Result<WalletRegistrationFallbackOptions, AuthApiError> {
        let credential: RegisterPublicKeyCredential = serde_json::from_value(credential_json)
            .map_err(|e| AuthApiError::Denied(format!("invalid credential: {e}")))?;

        let (prf_salt, reg_state) = {
            let state = self.state.lock();
            let session = state
                .sessions
                .get(token)
                .filter(|s| s.expires_at_ms > now_ms)
                .ok_or_else(|| {
                    AuthApiError::NotFound("unknown or expired registration session".into())
                })?;
            let attempt = session
                .attempts
                .get(attempt_id)
                .ok_or_else(|| AuthApiError::NotFound("unknown registration attempt".into()))?;
            if attempt.used {
                return Err(AuthApiError::Denied("attempt already used".into()));
            }
            (session.prf_salt, attempt.reg_state.clone())
        };

        // Verify and consume the registration credential *before* issuing a
        // fallback assertion challenge — an invalid credential must not
        // poison this attempt or block the legitimate browser from retrying.
        let passkey = finish_registration(&credential, &reg_state).map_err(AuthApiError::Denied)?;

        let mut fallback_challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut fallback_challenge);
        let (request_options_json, auth_state) =
            start_registration_fallback_assertion(&passkey, &prf_salt, &fallback_challenge)
                .map_err(AuthApiError::Denied)?;

        {
            let mut state = self.state.lock();
            let session = state.sessions.get_mut(token).ok_or_else(|| {
                AuthApiError::NotFound("unknown or expired registration session".into())
            })?;
            let attempt = session
                .attempts
                .get_mut(attempt_id)
                .ok_or_else(|| AuthApiError::NotFound("unknown registration attempt".into()))?;
            if attempt.used {
                return Err(AuthApiError::Denied("attempt already used".into()));
            }
            attempt.fallback = Some((passkey, auth_state));
        }

        Ok(WalletRegistrationFallbackOptions {
            request_options_json,
        })
    }

    async fn complete(
        &self,
        token: &str,
        attempt_id: &str,
        body: WalletRegistrationCompleteBody,
        now_ms: u64,
    ) -> Result<WalletRegistrationCompleteOutcome, AuthApiError> {
        let (wallet, address, recovery_key, receipt) = {
            let mut state = self.state.lock();
            let session = state
                .sessions
                .get_mut(token)
                .filter(|s| s.expires_at_ms > now_ms)
                .ok_or_else(|| {
                    AuthApiError::NotFound("unknown or expired registration session".into())
                })?;
            if let Some(winner) = &session.winner {
                // Idempotent replay: the recovery key/receipt only ever
                // existed in the one HTTP response for the request that
                // won. If the browser lost that response (network drop)
                // and retries the exact same request, hand back the same
                // outcome instead of erroring into a state the user cannot
                // recover from.
                if winner.attempt_id == attempt_id
                    && winner.request_digest == complete_body_digest(attempt_id, &body)
                {
                    return Ok(WalletRegistrationCompleteOutcome {
                        address: bloom_proto::checksum_address(&winner.prepared.address),
                        recovery_key: winner.prepared.recovery_key.clone(),
                        receipt: winner.receipt.clone().into(),
                    });
                }
                return Err(AuthApiError::Denied(
                    "registration already completed".into(),
                ));
            }
            let wallet = session.wallet.clone();
            let prf_salt = session.prf_salt;
            let signer = session.signer.clone();

            let attempt = session
                .attempts
                .get_mut(attempt_id)
                .ok_or_else(|| AuthApiError::NotFound("unknown registration attempt".into()))?;
            if attempt.used {
                return Err(AuthApiError::Denied("attempt already used".into()));
            }

            // Verify the credential/assertion BEFORE touching the adjacent
            // PRF output (invariant 2, 4, 5).
            let (passkey, prf_output_b64): (Passkey, String) = match &body {
                WalletRegistrationCompleteBody::Registration {
                    credential,
                    prf_output_b64,
                } => {
                    let credential: RegisterPublicKeyCredential =
                        serde_json::from_value(credential.clone()).map_err(|e| {
                            AuthApiError::Denied(format!("invalid credential: {e}"))
                        })?;
                    let passkey = finish_registration(&credential, &attempt.reg_state)
                        .map_err(AuthApiError::Denied)?;
                    (passkey, prf_output_b64.clone())
                }
                WalletRegistrationCompleteBody::Fallback {
                    credential,
                    prf_output_b64,
                } => {
                    let credential: PublicKeyCredential =
                        serde_json::from_value(credential.clone()).map_err(|e| {
                            AuthApiError::Denied(format!("invalid credential: {e}"))
                        })?;
                    let (passkey, auth_state) = attempt.fallback.clone().ok_or_else(|| {
                        AuthApiError::Denied(
                            "no fallback attempt in progress for this attempt".into(),
                        )
                    })?;
                    finish_registration_fallback_assertion(&credential, &auth_state)
                        .map_err(AuthApiError::Denied)?;
                    (passkey, prf_output_b64.clone())
                }
            };

            let mut prf_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(prf_output_b64.trim())
                .map_err(|_| AuthApiError::Denied("prf_output_b64 is not valid base64".into()))?;
            if prf_bytes.len() != 32 {
                prf_bytes.zeroize();
                return Err(AuthApiError::Denied("prf_output must be 32 bytes".into()));
            }
            let mut prf_arr = [0u8; 32];
            prf_arr.copy_from_slice(&prf_bytes);
            prf_bytes.zeroize();

            // Atomically mark this attempt (and the session) as won before
            // preparing wallet files — a concurrent second /complete for
            // this session now observes `used`/`winner` and loses.
            attempt.used = true;
            let policy_toml = attempt.policy_toml.clone();
            let request_digest = complete_body_digest(attempt_id, &body);

            let temp_id = format!("{token}-{attempt_id}");
            let prepared = match prepare_passkey_wallet(
                &self.keystore_root,
                &temp_id,
                &wallet,
                &signer,
                &passkey,
                &prf_salt,
                prf_arr,
                &policy_toml,
            ) {
                Ok(p) => p,
                Err(e) => return Err(AuthApiError::Store(e.to_string())),
            };

            let receipt = gen_token();
            let address = bloom_proto::checksum_address(&prepared.address);
            let recovery_key = prepared.recovery_key.clone();
            session.winner = Some(WinnerState {
                prepared,
                receipt: receipt.clone(),
                attempt_id: attempt_id.to_string(),
                request_digest,
                recovery_ack_expires_at_ms: now_ms + RECOVERY_ACK_TTL_MS,
            });

            (wallet, address, recovery_key, receipt)
        };

        let mut status = self
            .store
            .wallet_registration_status(&wallet)
            .await?
            .ok_or_else(|| AuthApiError::Store("registration session status missing".into()))?;
        status.state = WalletRegistrationState::AwaitingRecoveryAck;
        status.address = None; // not committed until recovery is acknowledged
        self.writer
            .upsert_wallet_registration_status(token, &status, now_ms)
            .await?;

        Ok(WalletRegistrationCompleteOutcome {
            address,
            recovery_key,
            receipt: receipt.into(),
        })
    }

    async fn recovery_ack(
        &self,
        token: &str,
        receipt: &str,
        now_ms: u64,
    ) -> Result<String, AuthApiError> {
        let (wallet, finalize_result) = {
            let mut state = self.state.lock();
            let session = state.sessions.get_mut(token).ok_or_else(|| {
                AuthApiError::NotFound("unknown or expired registration session".into())
            })?;
            // Peek rather than `take()` first: every rejection below must
            // leave a valid pending winner exactly as it was, and checking
            // before removing means there is nothing to "put back" on any
            // failure path.
            let winner = session.winner.as_ref().ok_or_else(|| {
                AuthApiError::Denied("no completed registration attempt for this session".into())
            })?;
            if now_ms > winner.recovery_ack_expires_at_ms {
                // Same deadline `sweep_expired` uses for a winner-holding
                // session — don't let this race sweep's 60s cadence: a
                // request past the deadline is denied here regardless of
                // whether the sweeper has already run.
                return Err(AuthApiError::Denied(
                    "recovery acknowledgment window has expired".into(),
                ));
            }
            if winner.receipt != receipt {
                return Err(AuthApiError::Denied(
                    "invalid recovery acknowledgment receipt".into(),
                ));
            }
            let winner = session.winner.take().expect("checked Some above");
            let wallet = session.wallet.clone();
            let final_dir = self.keystore_root.join(&wallet);
            let finalize_result = match finalize_passkey_wallet(winner.prepared, &final_dir) {
                Ok(finalized) => Ok(finalized),
                Err((prepared, e)) => {
                    // Preserve the prepared wallet on a failed rename
                    // (disk full, cross-device, permissions) rather than
                    // losing the only copy of the recovery key over a
                    // transient error — a retried acknowledgment with the
                    // same receipt can still succeed.
                    session.winner = Some(WinnerState {
                        prepared: *prepared,
                        receipt: winner.receipt,
                        attempt_id: winner.attempt_id,
                        request_digest: winner.request_digest,
                        recovery_ack_expires_at_ms: winner.recovery_ack_expires_at_ms,
                    });
                    Err(e)
                }
            };
            (wallet, finalize_result)
        };

        let finalized = finalize_result.map_err(|e| AuthApiError::Store(e.to_string()))?;
        let address = bloom_proto::checksum_address(&finalized.address);

        {
            let mut state = self.state.lock();
            if let Some(session) = state.sessions.remove(token) {
                self.keystore.cache_unlocked_signer(&wallet, session.signer);
            }
            state.by_wallet.remove(&wallet);
        }

        let mut status = self
            .store
            .wallet_registration_status(&wallet)
            .await?
            .ok_or_else(|| AuthApiError::Store("registration session status missing".into()))?;
        status.state = WalletRegistrationState::Completed;
        status.ceremony_url = None;
        status.address = Some(address.clone());
        self.writer
            .upsert_wallet_registration_status(token, &status, now_ms)
            .await?;

        Ok(address)
    }

    async fn cancel_by_token(&self, token: &str, now_ms: u64) -> Result<(), AuthApiError> {
        let wallet = {
            let mut state = self.state.lock();
            // A session with an installed winner has already produced a
            // real WebAuthn credential and a recovery key the browser may
            // already hold — "cancelling" it here would silently destroy
            // that prepared wallet (via `PreparedPasskeyWallet::Drop`)
            // while `/complete` might still be finishing its own response,
            // or after the browser has already shown the recovery key.
            // There is nothing left to cancel at that point: the caller
            // must acknowledge recovery or let it expire.
            match state.sessions.get(token) {
                None => {
                    return Err(AuthApiError::NotFound(
                        "unknown or already-terminal registration session".into(),
                    ));
                }
                Some(session) if session.winner.is_some() => {
                    return Err(AuthApiError::Denied(
                        "registration already completed — acknowledge recovery or let it \
                         expire; it can no longer be cancelled"
                            .into(),
                    ));
                }
                Some(_) => {}
            }
            let session = state.sessions.remove(token).expect("checked Some above");
            state.by_wallet.remove(&session.wallet);
            session.wallet
        };
        let mut status = self
            .store
            .wallet_registration_status(&wallet)
            .await?
            .ok_or_else(|| AuthApiError::Store("registration session status missing".into()))?;
        status.state = WalletRegistrationState::Cancelled;
        status.ceremony_url = None;
        self.writer
            .upsert_wallet_registration_status(token, &status, now_ms)
            .await?;
        Ok(())
    }

    async fn sweep_expired(&self, now_ms: u64) -> Result<usize, AuthApiError> {
        let expired_tokens: Vec<String> = {
            let state = self.state.lock();
            state
                .sessions
                .iter()
                .filter(|(_, s)| {
                    // A session with an installed winner is judged against
                    // its own, later recovery-ack deadline instead of the
                    // original WebAuthn-ceremony deadline — otherwise a
                    // completion that lands close to `expires_at_ms` could
                    // be swept away (destroying the prepared wallet) before
                    // the human has any real chance to acknowledge it. Must
                    // stay consistent with `recovery_ack`'s own deadline
                    // check.
                    let deadline = s
                        .winner
                        .as_ref()
                        .map(|w| w.recovery_ack_expires_at_ms)
                        .unwrap_or(s.expires_at_ms);
                    deadline <= now_ms
                })
                .map(|(t, _)| t.clone())
                .collect()
        };

        // The in-memory session is deliberately NOT removed until its
        // persisted status has actually been written `Expired` — a session
        // removed first and then lost to a transient store error used to
        // leave a stale `awaiting_user`/`awaiting_recovery_ack` row with a
        // dead `ceremony_url` behind forever (nothing left in memory to
        // retry it with, and the persisted row can also block the unique
        // live-registration index for that wallet). Leaving it in memory on
        // failure means the next sweep tick (it is still past its deadline)
        // picks the same token back up and retries.
        let mut swept = 0usize;
        let mut failed = 0usize;
        for token in expired_tokens {
            let wallet = match self.state.lock().sessions.get(&token) {
                Some(s) => s.wallet.clone(),
                None => continue, // already reconciled concurrently (ack/cancel/a prior sweep tick)
            };

            let status = match self.store.wallet_registration_status(&wallet).await {
                Ok(Some(status)) => status,
                Ok(None) => {
                    tracing::warn!(
                        wallet = %wallet,
                        "wallet_registration.sweep_status_missing"
                    );
                    Self::remove_session_if_current(&mut self.state.lock(), &token, &wallet);
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        wallet = %wallet,
                        err = %e,
                        "wallet_registration.sweep_status_read_failed"
                    );
                    failed += 1;
                    continue;
                }
            };
            if status.state.is_terminal() {
                // Already terminal for some other reason (e.g. concurrently
                // cancelled/acknowledged) — just drop the dead session.
                Self::remove_session_if_current(&mut self.state.lock(), &token, &wallet);
                continue;
            }

            let mut status = status;
            status.state = WalletRegistrationState::Expired;
            status.ceremony_url = None;
            if let Err(e) = self
                .writer
                .upsert_wallet_registration_status(&token, &status, now_ms)
                .await
            {
                tracing::warn!(
                    wallet = %wallet,
                    err = %e,
                    "wallet_registration.sweep_status_write_failed"
                );
                failed += 1;
                continue;
            }
            Self::remove_session_if_current(&mut self.state.lock(), &token, &wallet);
            swept += 1;
        }

        if failed > 0 {
            return Err(AuthApiError::Store(format!(
                "wallet registration sweep: {failed} session(s) failed to persist as expired \
                 and will be retried next sweep"
            )));
        }
        Ok(swept)
    }
}

impl RegistrationCoordinator {
    /// Remove `token`'s session, and `wallet`'s `by_wallet` mapping only if
    /// it still points at `token` — a concurrent fresh `stage()` for the
    /// same wallet name may already have replaced it with a newer live
    /// token, which must not be clobbered here.
    fn remove_session_if_current(state: &mut CoordinatorState, token: &str, wallet: &str) {
        state.sessions.remove(token);
        if state.by_wallet.get(wallet).map(String::as_str) == Some(token) {
            state.by_wallet.remove(wallet);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_auth::{AuthStore, RejectingApprovalSignatureVerifier, StoreApprovalVerifier};

    fn coordinator() -> (RegistrationCoordinator, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(tmp.path().join("keystore")).unwrap();
        let store = AuthStore::open_in_memory_for_tests().unwrap();
        let verifier = Arc::new(StoreApprovalVerifier::new(
            store,
            RejectingApprovalSignatureVerifier,
        ));
        let view: Arc<dyn AuthStoreView> = verifier.clone();
        let writer: Arc<dyn AuthStoreWriter> = verifier;
        let coordinator =
            RegistrationCoordinator::new(keystore, view, writer, tmp.path().join("keystore"));
        (coordinator, tmp)
    }

    #[tokio::test]
    async fn stage_fails_closed_when_unarmed() {
        let (coordinator, _tmp) = coordinator();
        let err = coordinator.stage("alice", 1_000).await.unwrap_err();
        assert!(err.to_string().contains("bloom serve"));
    }

    #[tokio::test]
    async fn stage_is_idempotent_for_a_live_session() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");

        let first = coordinator.stage("alice", 1_000).await.unwrap();
        let second = coordinator.stage("alice", 1_050).await.unwrap();
        assert_eq!(first.ceremony_url, second.ceremony_url);
        assert_eq!(first.created_at_ms, second.created_at_ms);
    }

    #[tokio::test]
    async fn stage_rejects_wallet_that_already_exists_on_disk() {
        let (coordinator, tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        std::fs::create_dir_all(tmp.path().join("keystore").join("alice")).unwrap();

        let err = coordinator.stage("alice", 1_000).await.unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    /// Defense in depth alongside `WalletsHandler`'s own name validation:
    /// even a caller that reaches the coordinator directly cannot stage a
    /// name that would later escape `keystore_root` when joined into a path
    /// (used by both the initial existence check and, on completion,
    /// `recovery_ack`'s rename target).
    #[tokio::test]
    async fn stage_rejects_path_traversal_names() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        for name in ["../../escape", "a/b", "..", "/etc/passwd", ""] {
            let err = coordinator
                .stage(name, 1_000)
                .await
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("invalid wallet name") || err.contains("InvalidName"),
                "name={name:?} err={err}"
            );
        }
    }

    #[tokio::test]
    async fn a_url_holder_cannot_cancel_or_complete_an_unknown_token() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        coordinator.stage("alice", 1_000).await.unwrap();

        // Knowing *a* token format proves nothing without the actual value:
        // a guessed/unrelated token resolves to nothing.
        assert!(
            coordinator
                .cancel_by_token("not-a-real-token", 1_000)
                .await
                .is_err()
        );
        assert!(
            coordinator
                .session_view("not-a-real-token", 1_000)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn create_attempt_rejects_invalid_policy_without_touching_session() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let status = coordinator.stage("alice", 1_000).await.unwrap();
        let token = status
            .ceremony_url
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();

        let err = coordinator
            .create_attempt(&token, "not valid toml {{{".into(), 1_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid policy"));

        // Session is untouched and still resolvable.
        let view = coordinator.session_view(&token, 1_000).await.unwrap();
        assert_eq!(view.wallet, "alice");
    }

    #[tokio::test]
    async fn create_attempt_is_bounded() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let status = coordinator.stage("alice", 1_000).await.unwrap();
        let token = status
            .ceremony_url
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        let policy_toml = default_passkey_policy_toml().unwrap();

        for _ in 0..MAX_ATTEMPTS {
            coordinator
                .create_attempt(&token, policy_toml.clone(), 1_000)
                .await
                .unwrap();
        }
        let err = coordinator
            .create_attempt(&token, policy_toml, 1_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too many"));
    }

    #[tokio::test]
    async fn malformed_completion_does_not_advance_or_poison_the_session() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let status = coordinator.stage("alice", 1_000).await.unwrap();
        let token = status
            .ceremony_url
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        let policy_toml = default_passkey_policy_toml().unwrap();
        let opts = coordinator
            .create_attempt(&token, policy_toml, 1_000)
            .await
            .unwrap();

        let garbage_credential = serde_json::json!({
            "id": "garbage",
            "rawId": "AAAA",
            "type": "public-key",
            "response": {
                "attestationObject": "AAAA",
                "clientDataJSON": "AAAA",
            },
        });
        let body = bloom_auth_api::WalletRegistrationCompleteBody::Registration {
            credential: garbage_credential,
            prf_output_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
        };
        // `WalletRegistrationCompleteOutcome` intentionally does not derive
        // `Debug` (it carries the recovery key/receipt), so match instead of
        // `unwrap_err()`.
        let result = coordinator
            .complete(&token, &opts.attempt_id, body, 1_000)
            .await;
        match result {
            Err(AuthApiError::Denied(_)) => {}
            Err(other) => panic!("expected Denied, got {other}"),
            Ok(_) => panic!("garbage credential must not complete registration"),
        }

        // The session is still `awaiting_user`, not corrupted into a
        // half-completed state, and the attempt can still be retried.
        let after = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(after.state, WalletRegistrationState::AwaitingUser);
    }

    /// `cancel_by_token` must still work exactly as before when no winner
    /// has been installed — the new "reject once completed" guard must not
    /// affect the ordinary cancellation path.
    #[tokio::test]
    async fn cancel_by_token_still_works_before_any_completion() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let status = coordinator.stage("alice", 1_000).await.unwrap();
        let token = status
            .ceremony_url
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();

        coordinator.cancel_by_token(&token, 2_000).await.unwrap();
        let after = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(after.state, WalletRegistrationState::Cancelled);
    }

    /// `complete_body_digest` is the sole mechanism `complete()` uses to
    /// decide whether a second call for an already-won session is the exact
    /// same request replayed (answer with the cached outcome) or a
    /// genuinely different one (deny). It must be sensitive to every field
    /// that distinguishes one `/complete` request from another.
    #[test]
    fn complete_body_digest_is_stable_and_sensitive_to_every_field() {
        let cred_a = serde_json::json!({"id": "a"});
        let cred_b = serde_json::json!({"id": "b"});
        let reg_a = WalletRegistrationCompleteBody::Registration {
            credential: cred_a.clone(),
            prf_output_b64: "AAAA".into(),
        };
        let reg_a_again = WalletRegistrationCompleteBody::Registration {
            credential: cred_a.clone(),
            prf_output_b64: "AAAA".into(),
        };
        assert_eq!(
            complete_body_digest("att-1", &reg_a),
            complete_body_digest("att-1", &reg_a_again),
            "identical requests must digest identically"
        );

        let reg_b = WalletRegistrationCompleteBody::Registration {
            credential: cred_b,
            prf_output_b64: "AAAA".into(),
        };
        assert_ne!(
            complete_body_digest("att-1", &reg_a),
            complete_body_digest("att-1", &reg_b),
            "different credential must change the digest"
        );

        let reg_diff_prf = WalletRegistrationCompleteBody::Registration {
            credential: cred_a.clone(),
            prf_output_b64: "BBBB".into(),
        };
        assert_ne!(
            complete_body_digest("att-1", &reg_a),
            complete_body_digest("att-1", &reg_diff_prf),
            "different prf_output_b64 must change the digest"
        );

        assert_ne!(
            complete_body_digest("att-1", &reg_a),
            complete_body_digest("att-2", &reg_a),
            "different attempt_id must change the digest"
        );

        let fallback_a = WalletRegistrationCompleteBody::Fallback {
            credential: cred_a,
            prf_output_b64: "AAAA".into(),
        };
        assert_ne!(
            complete_body_digest("att-1", &reg_a),
            complete_body_digest("att-1", &fallback_a),
            "Registration vs Fallback with identical fields must still differ"
        );
    }

    #[tokio::test]
    async fn recovery_ack_requires_a_prior_completion() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let status = coordinator.stage("alice", 1_000).await.unwrap();
        let token = status
            .ceremony_url
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        let err = coordinator
            .recovery_ack(&token, "not-a-real-receipt", 1_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no completed registration"));
    }

    #[tokio::test]
    async fn cancel_removes_session_and_frees_the_wallet_for_a_fresh_stage() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let first = coordinator.stage("alice", 1_000).await.unwrap();

        coordinator.cancel("alice", 2_000).await.unwrap();
        let cancelled = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(cancelled.state, WalletRegistrationState::Cancelled);
        assert!(cancelled.ceremony_url.is_none());

        // Cancelling again fails — no live session left.
        assert!(coordinator.cancel("alice", 2_100).await.is_err());

        let fresh = coordinator.stage("alice", 3_000).await.unwrap();
        assert_ne!(fresh.ceremony_url, first.ceremony_url);
    }

    #[tokio::test]
    async fn sweep_expired_terminates_stale_sessions() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        coordinator.stage("alice", 1_000).await.unwrap();

        let swept = coordinator
            .sweep_expired(1_000 + SESSION_TTL_MS + 1)
            .await
            .unwrap();
        assert_eq!(swept, 1, "exactly the one stale session must be counted");
        let status = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(status.state, WalletRegistrationState::Expired);
        assert!(status.ceremony_url.is_none());

        // A fresh stage is possible again after expiry.
        let fresh = coordinator
            .stage("alice", 1_000 + SESSION_TTL_MS + 2)
            .await
            .unwrap();
        assert_eq!(fresh.state, WalletRegistrationState::AwaitingUser);

        // Nothing left to sweep — a repeat call is a harmless no-op.
        let swept_again = coordinator
            .sweep_expired(1_000 + SESSION_TTL_MS + 2)
            .await
            .unwrap();
        assert_eq!(swept_again, 0);
    }

    #[test]
    fn wallet_registration_status_json_never_contains_secret_fields() {
        // Structural guarantee: `WalletRegistrationStatus` has no field for
        // recovery keys, PRF output, private keys, or completion receipts —
        // it is impossible for `status()`/`status.json` to serialize them.
        let status = WalletRegistrationStatus::awaiting_user(
            "alice",
            1_000,
            2_000,
            "http://localhost:18734/wallet-registration/tok",
        );
        let json = serde_json::to_value(&status).unwrap();
        let obj = json.as_object().unwrap();
        for forbidden in [
            "recovery_key",
            "prf_output",
            "private_key",
            "receipt",
            "prf_salt",
        ] {
            assert!(
                !obj.contains_key(forbidden),
                "status.json leaked {forbidden}"
            );
        }
    }
}
