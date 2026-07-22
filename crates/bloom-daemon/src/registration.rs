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
}

/// A session's post-`/complete` phase. `recovery_ack`'s own rename can
/// itself fail or its persisted-status write can be lost after a
/// successful rename — `Finalized` is the phase in between: the wallet is
/// already durably on disk, but the coordinator hasn't yet confirmed that
/// in the persisted store. A retried acknowledgment in that phase must not
/// re-run finalize (`prepared` was already consumed) — just re-confirm the
/// receipt and retry the persist.
enum CompletionPhase {
    /// `prepare_passkey_wallet` succeeded; not yet renamed into place.
    Won(Box<WinnerState>),
    /// `finalize_passkey_wallet`'s rename succeeded.
    Finalized { address: String, receipt: String },
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
    completion: Option<CompletionPhase>,
    /// Set once `/complete` installs a winner (alongside `completion`);
    /// `None` beforehand. Independent of which `CompletionPhase` variant is
    /// active — the recovery-ack window starts at the moment of
    /// completion, not at finalization.
    recovery_ack_deadline: Option<u64>,
}

impl SecretSession {
    /// The deadline past which this session is considered dead: the later,
    /// separate recovery-ack deadline once a winner is installed, otherwise
    /// the original WebAuthn-ceremony deadline. Every place that gates a
    /// session lookup on expiry must use this, not `expires_at_ms` directly,
    /// so `stage`, `session_view`, `complete`'s replay handling, and
    /// `sweep_expired` all agree on how long an awaiting-ack session stays
    /// alive.
    fn effective_deadline(&self) -> u64 {
        self.recovery_ack_deadline.unwrap_or(self.expires_at_ms)
    }
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
                completion: None,
                recovery_ack_deadline: None,
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
        let rows = self
            .store
            .non_terminal_wallet_registration_sessions()
            .await?;
        let mut reconciled = 0u64;
        for (token, mut status) in rows {
            let dir = self.keystore_root.join(&status.wallet);
            if dir.exists() {
                // `recovery_ack`'s rename can succeed and then the process
                // can die before its persisted `Completed` write confirms.
                // A bulk "mark everything failed" can't see that — check
                // the keystore directly and reconcile to `Completed` with
                // the real address instead of misrepresenting a wallet
                // that genuinely exists as failed.
                let address = std::fs::read_to_string(dir.join("address"))
                    .ok()
                    .map(|s| s.trim().to_string());
                status.state = WalletRegistrationState::Completed;
                status.ceremony_url = None;
                status.address = address;
            } else {
                status.state = WalletRegistrationState::Failed;
                status.ceremony_url = None;
                status.error = Some(reason.to_string());
            }
            self.writer
                .upsert_wallet_registration_status(&token, &status, now_ms)
                .await?;
            reconciled += 1;
        }
        Ok(reconciled)
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

        // `is_fresh` distinguishes "found an existing live session" from
        // "inserted a new one" — only the fresh case should construct and
        // persist an `awaiting_user` status. Re-staging over an existing
        // live session (which may already be `awaiting_recovery_ack`, i.e.
        // a winner is installed) must not downgrade its persisted status
        // back to `awaiting_user`; it must also use the session's own
        // `effective_deadline()`, not just `expires_at_ms`, or a session
        // past the original ceremony deadline but still within its
        // recovery-ack window would look dead here and get dropped —
        // destroying an installed winner to start a fresh session.
        let (token, is_fresh, created_at_ms, expires_at_ms) = {
            let mut state = self.state.lock();
            let live = state.by_wallet.get(wallet).cloned().and_then(|token| {
                state
                    .sessions
                    .get(&token)
                    .filter(|s| s.effective_deadline() > now_ms)
                    .map(|s| (token, s.created_at_ms, s.expires_at_ms))
            });
            match live {
                Some((token, created_at_ms, expires_at_ms)) => {
                    (token, false, created_at_ms, expires_at_ms)
                }
                None => {
                    // Terminal/expired in-memory session for this wallet, if
                    // any: drop it before starting a fresh one.
                    if let Some(stale) = state.by_wallet.remove(wallet) {
                        state.sessions.remove(&stale);
                    }
                    let (token, created_at_ms, expires_at_ms) =
                        Self::insert_fresh_session(&mut state, wallet, now_ms);
                    (token, true, created_at_ms, expires_at_ms)
                }
            }
        };

        if !is_fresh {
            // Idempotently return the existing persisted status unchanged
            // — it already reflects whatever transition last touched it.
            return self
                .store
                .wallet_registration_status(wallet)
                .await?
                .ok_or_else(|| AuthApiError::Store("registration session status missing".into()));
        }

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
            let token = state.by_wallet.get(wallet).cloned().ok_or_else(|| {
                AuthApiError::NotFound(format!(
                    "no live registration session for wallet '{wallet}'"
                ))
            })?;
            // Mirrors `cancel_by_token`'s guard: a session with an
            // installed winner has already produced a real credential and
            // (once finalized) a durably-installed wallet — destroying it
            // here would either lose a prepared-but-not-yet-renamed wallet
            // or desync the persisted status from a wallet that already
            // exists on disk. Nothing left to cancel at that point.
            if let Some(session) = state.sessions.get(&token)
                && session.completion.is_some()
            {
                return Err(AuthApiError::Denied(
                    "registration already completed — acknowledge recovery or let it expire; \
                     it can no longer be cancelled"
                        .into(),
                ));
            }
            state.sessions.remove(&token);
            state.by_wallet.remove(wallet);
            token
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
                .filter(|s| s.effective_deadline() > now_ms)
                .ok_or_else(|| {
                    AuthApiError::NotFound("unknown or expired registration session".into())
                })?;
            (
                session.wallet.clone(),
                session.effective_deadline(),
                session.completion.is_some(),
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
            if session.completion.is_some() {
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
            if session.completion.is_some() {
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
                .filter(|s| s.effective_deadline() > now_ms)
                .ok_or_else(|| {
                    AuthApiError::NotFound("unknown or expired registration session".into())
                })?;
            match &session.completion {
                Some(CompletionPhase::Won(winner)) => {
                    // Idempotent replay: the recovery key/receipt only ever
                    // existed in the one HTTP response for the request that
                    // won. If the browser lost that response (network drop)
                    // and retries the exact same request, hand back the
                    // same outcome instead of erroring into a state the
                    // user cannot recover from.
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
                Some(CompletionPhase::Finalized { .. }) => {
                    // Already renamed into place by `recovery_ack` — no
                    // outcome to replay (the recovery key isn't retained
                    // past finalization) and nothing left for `/complete`
                    // to do.
                    return Err(AuthApiError::Denied(
                        "registration already completed".into(),
                    ));
                }
                None => {}
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
            session.completion = Some(CompletionPhase::Won(Box::new(WinnerState {
                prepared,
                receipt: receipt.clone(),
                attempt_id: attempt_id.to_string(),
                request_digest,
            })));
            session.recovery_ack_deadline = Some(now_ms + RECOVERY_ACK_TTL_MS);

            (wallet, address, recovery_key, receipt)
        };

        let mut status = self
            .store
            .wallet_registration_status(&wallet)
            .await?
            .ok_or_else(|| AuthApiError::Store("registration session status missing".into()))?;
        status.state = WalletRegistrationState::AwaitingRecoveryAck;
        status.address = None; // not committed until recovery is acknowledged
        // Extend the persisted deadline to match the in-memory
        // recovery-ack window — otherwise a poller reading the stale
        // original ceremony deadline (e.g. the CLI's own expiry-based
        // timeout) would conclude the registration is dead while the
        // server still considers it live and awaiting acknowledgment.
        status.expires_at_ms = now_ms + RECOVERY_ACK_TTL_MS;
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
        // Phase 1 (locked): validate, and either finalize a `Won` session
        // or re-confirm an already-`Finalized` one. Either way, produce the
        // address to persist — nothing here removes the session yet.
        let (wallet, address) = {
            let mut state = self.state.lock();
            let session = state.sessions.get_mut(token).ok_or_else(|| {
                AuthApiError::NotFound("unknown or expired registration session".into())
            })?;
            match session.completion.as_ref() {
                None => {
                    return Err(AuthApiError::Denied(
                        "no completed registration attempt for this session".into(),
                    ));
                }
                Some(CompletionPhase::Finalized {
                    address,
                    receipt: stored_receipt,
                }) => {
                    // The wallet is already durably on disk from a prior
                    // call whose persisted-status write never confirmed
                    // (crash, DB error, lost response). Don't re-run
                    // finalize — `prepared` was already consumed — just
                    // re-confirm the receipt and retry the persist below.
                    if stored_receipt != receipt {
                        return Err(AuthApiError::Denied(
                            "invalid recovery acknowledgment receipt".into(),
                        ));
                    }
                    (session.wallet.clone(), address.clone())
                }
                Some(CompletionPhase::Won(winner)) => {
                    if let Some(deadline) = session.recovery_ack_deadline
                        && now_ms > deadline
                    {
                        // Same deadline `sweep_expired` uses — don't let
                        // this race sweep's 60s cadence: a request past the
                        // deadline is denied here regardless of whether the
                        // sweeper has already run.
                        return Err(AuthApiError::Denied(
                            "recovery acknowledgment window has expired".into(),
                        ));
                    }
                    if winner.receipt != receipt {
                        return Err(AuthApiError::Denied(
                            "invalid recovery acknowledgment receipt".into(),
                        ));
                    }
                    let Some(CompletionPhase::Won(winner)) = session.completion.take() else {
                        unreachable!("just matched Won above")
                    };
                    let wallet = session.wallet.clone();
                    let final_dir = self.keystore_root.join(&wallet);
                    match finalize_passkey_wallet(winner.prepared, &final_dir) {
                        Ok(finalized) => {
                            let address = bloom_proto::checksum_address(&finalized.address);
                            // Durably on disk now — move to `Finalized` so a
                            // retried ack (if the persist below fails) can't
                            // re-attempt the rename.
                            session.completion = Some(CompletionPhase::Finalized {
                                address: address.clone(),
                                receipt: winner.receipt,
                            });
                            (wallet, address)
                        }
                        Err((prepared, e)) => {
                            // Preserve the prepared wallet on a failed
                            // rename (disk full, cross-device, permissions)
                            // rather than losing the only copy of the
                            // recovery key over a transient error — a
                            // retried acknowledgment with the same receipt
                            // can still succeed.
                            session.completion =
                                Some(CompletionPhase::Won(Box::new(WinnerState {
                                    prepared: *prepared,
                                    receipt: winner.receipt,
                                    attempt_id: winner.attempt_id,
                                    request_digest: winner.request_digest,
                                })));
                            return Err(AuthApiError::Store(e.to_string()));
                        }
                    }
                }
            }
        };

        // Phase 2 (unlocked): persist `Completed`. Only after this succeeds
        // is the in-memory session discarded — a failure here (crash, DB
        // error, lost response) leaves the session in `Finalized` phase so
        // a retried acknowledgment with the same receipt returns the same
        // address instead of the session simply vanishing (which used to
        // 404 a retry even though the wallet was already durably created).
        self.persist_completed(token, &wallet, &address, now_ms)
            .await?;

        {
            let mut state = self.state.lock();
            if let Some(session) = state.sessions.remove(token) {
                self.keystore.cache_unlocked_signer(&wallet, session.signer);
            }
            state.by_wallet.remove(&wallet);
        }

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
                Some(session) if session.completion.is_some() => {
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
                .filter(|(_, s)| s.effective_deadline() <= now_ms)
                .map(|(t, _)| t.clone())
                .collect()
        };

        // The in-memory session is deliberately NOT removed until its
        // persisted status has actually been written — a session removed
        // first and then lost to a transient store error used to leave a
        // stale row behind forever (nothing left in memory to retry it
        // with, and the persisted row can also block the unique
        // live-registration index for that wallet). Leaving it in memory on
        // failure means the next sweep tick (it is still past its deadline)
        // picks the same token back up and retries.
        let mut swept = 0usize;
        let mut failed = 0usize;
        for token in expired_tokens {
            let (wallet, finalized_address) = match self.state.lock().sessions.get(&token) {
                Some(s) => (
                    s.wallet.clone(),
                    match &s.completion {
                        Some(CompletionPhase::Finalized { address, .. }) => Some(address.clone()),
                        _ => None,
                    },
                ),
                None => continue, // already reconciled concurrently (ack/cancel/a prior sweep tick)
            };

            if let Some(address) = finalized_address {
                // The wallet is already durably on disk (a prior
                // `recovery_ack` call finalized it) but its persisted
                // status never confirmed `Completed` — same situation
                // `recovery_ack` itself retries on. Retry the same persist
                // here instead of marking it `Expired`, which would hide a
                // wallet that actually exists.
                match self
                    .persist_completed(&token, &wallet, &address, now_ms)
                    .await
                {
                    Ok(()) => {
                        Self::remove_session_if_current(&mut self.state.lock(), &token, &wallet);
                        swept += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            wallet = %wallet,
                            err = %e,
                            "wallet_registration.sweep_finalized_persist_failed"
                        );
                        failed += 1;
                    }
                }
                continue;
            }

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
                "wallet registration sweep: {failed} session(s) failed to persist \
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

    /// Persist a session's terminal `Completed` status. Shared by
    /// `recovery_ack` (the live request path) and `sweep_expired` (which
    /// retries the exact same persist for a session stuck in `Finalized`
    /// phase — its wallet is already on disk, so it must not be marked
    /// `Expired`).
    async fn persist_completed(
        &self,
        token: &str,
        wallet: &str,
        address: &str,
        now_ms: u64,
    ) -> Result<(), AuthApiError> {
        let mut status = self
            .store
            .wallet_registration_status(wallet)
            .await?
            .ok_or_else(|| AuthApiError::Store("registration session status missing".into()))?;
        status.state = WalletRegistrationState::Completed;
        status.ceremony_url = None;
        status.address = Some(address.to_string());
        self.writer
            .upsert_wallet_registration_status(token, &status, now_ms)
            .await
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

    /// Directly installs a `Finalized` completion phase on `wallet`'s live
    /// session, bypassing the WebAuthn/PRF ceremony entirely — no
    /// virtual-authenticator harness exists in this codebase to drive a
    /// real `/complete` to a winning credential. Everything the recent
    /// findings are about (stage/cancel/sweep/session_view/recovery_ack
    /// around an already-completed session) happens *after* a winner
    /// exists, so this is sufficient to exercise all of it without one.
    /// Mirrors what `complete()` itself does to the persisted status.
    async fn stage_and_finalize_directly(
        coordinator: &RegistrationCoordinator,
        wallet: &str,
        address: &str,
        receipt: &str,
        now_ms: u64,
        ack_ttl_ms: u64,
    ) -> String {
        let status = coordinator.stage(wallet, now_ms).await.unwrap();
        let token = status
            .ceremony_url
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        let recovery_ack_deadline = now_ms + ack_ttl_ms;
        {
            let mut state = coordinator.state.lock();
            let session = state.sessions.get_mut(&token).unwrap();
            session.completion = Some(CompletionPhase::Finalized {
                address: address.to_string(),
                receipt: receipt.to_string(),
            });
            session.recovery_ack_deadline = Some(recovery_ack_deadline);
        }
        let mut persisted = coordinator.status(wallet).await.unwrap().unwrap();
        persisted.state = WalletRegistrationState::AwaitingRecoveryAck;
        persisted.address = None;
        persisted.expires_at_ms = recovery_ack_deadline;
        coordinator
            .writer
            .upsert_wallet_registration_status(&token, &persisted, now_ms)
            .await
            .unwrap();
        token
    }

    #[tokio::test]
    async fn stage_does_not_downgrade_an_awaiting_recovery_ack_session() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        stage_and_finalize_directly(&coordinator, "alice", "0xabc", "receipt-1", 1_000, 300_000)
            .await;

        // Re-staging while a winner is installed must return the existing
        // `awaiting_recovery_ack` status unchanged, not reconstruct and
        // persist a fresh `awaiting_user` one.
        let status = coordinator.stage("alice", 1_500).await.unwrap();
        assert_eq!(status.state, WalletRegistrationState::AwaitingRecoveryAck);
    }

    #[tokio::test]
    async fn stage_treats_a_session_as_live_past_the_original_deadline_while_awaiting_ack() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        // recovery-ack deadline (300_000ms out) outlives the original
        // SESSION_TTL_MS (also 300_000ms in these tests) only if we push
        // "now" past the original expiry but before the ack deadline.
        stage_and_finalize_directly(&coordinator, "alice", "0xabc", "receipt-1", 1_000, 600_000)
            .await;

        // Past the original 5-minute ceremony deadline, but still within
        // the recovery-ack window: must NOT be treated as dead.
        let status = coordinator
            .stage("alice", 1_000 + SESSION_TTL_MS + 1)
            .await
            .unwrap();
        assert_eq!(status.state, WalletRegistrationState::AwaitingRecoveryAck);
    }

    #[tokio::test]
    async fn cancel_and_cancel_by_token_reject_once_finalized() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let token = stage_and_finalize_directly(
            &coordinator,
            "alice",
            "0xabc",
            "receipt-1",
            1_000,
            300_000,
        )
        .await;

        assert!(
            coordinator.cancel("alice", 1_500).await.is_err(),
            "cancel() must reject once a winner is installed, same as cancel_by_token()"
        );
        assert!(coordinator.cancel_by_token(&token, 1_500).await.is_err());

        // Neither attempt touched the persisted status.
        let status = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(status.state, WalletRegistrationState::AwaitingRecoveryAck);
    }

    #[tokio::test]
    async fn session_view_stays_resolvable_past_original_deadline_while_awaiting_ack() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let token = stage_and_finalize_directly(
            &coordinator,
            "alice",
            "0xabc",
            "receipt-1",
            1_000,
            600_000,
        )
        .await;

        let view = coordinator
            .session_view(&token, 1_000 + SESSION_TTL_MS + 1)
            .await
            .unwrap();
        assert_eq!(view.state, WalletRegistrationState::AwaitingRecoveryAck);
    }

    #[tokio::test]
    async fn recovery_ack_on_a_finalized_session_returns_the_address_and_persists_completed() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let token = stage_and_finalize_directly(
            &coordinator,
            "alice",
            "0xabc",
            "receipt-1",
            1_000,
            300_000,
        )
        .await;

        let address = coordinator
            .recovery_ack(&token, "receipt-1", 1_500)
            .await
            .unwrap();
        assert_eq!(address, "0xabc");
        let status = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(status.state, WalletRegistrationState::Completed);
        assert_eq!(status.address.as_deref(), Some("0xabc"));

        // The session is gone — a repeat with the same receipt now 404s,
        // same as any other terminal session (idempotent completion of the
        // *persisted* status, not of the in-memory session's lifetime).
        assert!(
            coordinator
                .recovery_ack(&token, "receipt-1", 1_600)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn recovery_ack_on_a_finalized_session_rejects_the_wrong_receipt() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let token = stage_and_finalize_directly(
            &coordinator,
            "alice",
            "0xabc",
            "receipt-1",
            1_000,
            300_000,
        )
        .await;

        let err = coordinator
            .recovery_ack(&token, "wrong-receipt", 1_500)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid recovery"));

        // Still resolvable and unchanged — a bad guess doesn't destroy it.
        let status = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(status.state, WalletRegistrationState::AwaitingRecoveryAck);
    }

    #[tokio::test]
    async fn sweep_expired_reconciles_a_finalized_session_to_completed_not_expired() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        stage_and_finalize_directly(&coordinator, "alice", "0xabc", "receipt-1", 1_000, 300_000)
            .await;

        // Past its recovery-ack deadline, but already finalized on disk —
        // must reconcile to `Completed`, not overwrite it to `Expired`.
        let swept = coordinator
            .sweep_expired(1_000 + 300_000 + 1)
            .await
            .unwrap();
        assert_eq!(swept, 1);
        let status = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(status.state, WalletRegistrationState::Completed);
        assert_eq!(status.address.as_deref(), Some("0xabc"));
    }

    #[tokio::test]
    async fn reconcile_after_restart_completes_an_already_installed_wallet() {
        let (coordinator, tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");

        // Simulate a wallet that `recovery_ack` successfully renamed into
        // place before the process died, whose persisted status never got
        // to `Completed`.
        let wallet_dir = tmp.path().join("keystore").join("alice");
        std::fs::create_dir_all(&wallet_dir).unwrap();
        std::fs::write(wallet_dir.join("address"), "0xabc\n").unwrap();
        let mut status = WalletRegistrationStatus::awaiting_user(
            "alice",
            1_000,
            1_000 + 300_000,
            "http://localhost:18734/wallet-registration/tok-installed",
        );
        status.state = WalletRegistrationState::AwaitingRecoveryAck;
        coordinator
            .writer
            .upsert_wallet_registration_status("tok-installed", &status, 1_000)
            .await
            .unwrap();

        // A second, truly-abandoned session with no directory on disk.
        let abandoned = WalletRegistrationStatus::awaiting_user(
            "bob",
            1_000,
            1_000 + 300_000,
            "http://localhost:18734/wallet-registration/tok-abandoned",
        );
        coordinator
            .writer
            .upsert_wallet_registration_status("tok-abandoned", &abandoned, 1_000)
            .await
            .unwrap();

        let reconciled = coordinator
            .reconcile_after_restart("daemon restarted", 9_000)
            .await
            .unwrap();
        assert_eq!(reconciled, 2);

        let alice = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(alice.state, WalletRegistrationState::Completed);
        assert_eq!(alice.address.as_deref(), Some("0xabc"));

        let bob = coordinator.status("bob").await.unwrap().unwrap();
        assert_eq!(bob.state, WalletRegistrationState::Failed);
        assert_eq!(bob.error.as_deref(), Some("daemon restarted"));
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
