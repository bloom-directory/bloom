//! Daemon-owned asynchronous passkey registration. Secret ceremony state is
//! memory-only; [`WalletRegistrationStore`] persists its public projection.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use base64::Engine as _;
use bloom_auth_api::{
    AuthApiError, RegistrationIntent, WalletRegistrationAttemptOptions, WalletRegistrationCeremony,
    WalletRegistrationCompleteBody, WalletRegistrationCompleteOutcome,
    WalletRegistrationFallbackOptions, WalletRegistrationLifecycle, WalletRegistrationMaintenance,
    WalletRegistrationSessionView, WalletRegistrationState, WalletRegistrationStatus,
    WalletRegistrationStore, WalletRegistrationVfs,
};
use bloom_keystore::{
    Keystore, Passkey, PasskeyAuthentication, PasskeyRegistration, PreparedPasskeyWallet,
    PublicKeyCredential, RegisterPublicKeyCredential, default_passkey_policy_toml,
    finalize_passkey_wallet, finish_registration, finish_registration_fallback_assertion,
    prepare_passkey_wallet, start_registration_challenge, start_registration_fallback_assertion,
};
use bloom_proto::{AuditLog, AuditRecord};
use parking_lot::{Mutex, RwLock};
use rand::RngCore;
use zeroize::Zeroize;

const SESSION_TTL_MS: u64 = 5 * 60 * 1000;
const RECOVERY_ACK_TTL_MS: u64 = 5 * 60 * 1000;
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

struct SecretAttempt {
    policy_toml: String,
    reg_state: PasskeyRegistration,
    busy: bool,
    fallback: Option<(Passkey, PasskeyAuthentication, serde_json::Value)>,
}

struct WinnerState {
    prepared: PreparedPasskeyWallet,
    receipt: String,
    attempt_id: String,
    request_digest: [u8; 32],
}

enum CompletionPhase {
    Won(Box<WinnerState>),
    Finalized { address: String, receipt: String },
}

enum CompleteWork {
    Replay {
        address: String,
        recovery_key: zeroize::Zeroizing<String>,
        receipt: String,
    },
    New(Box<CompleteNew>),
}

struct CompleteNew {
    wallet: String,
    signer: PrivateKeySigner,
    prf_salt: [u8; 32],
    policy_toml: String,
    reg_state: PasskeyRegistration,
    fallback: Option<(Passkey, PasskeyAuthentication)>,
}

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
    completing: bool,
    recovery_ack_deadline: Option<u64>,
}

impl SecretSession {
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
    store: Arc<dyn WalletRegistrationStore>,
    audit: Arc<AuditLog>,
    keystore_root: PathBuf,
    /// Set exactly once, by the process that binds the shared loopback
    /// ceremony listener. `stage()` fails closed while this is `None`.
    listener_base_url: RwLock<Option<String>>,
    state: Mutex<CoordinatorState>,
    transitions: tokio::sync::Mutex<()>,
}

impl RegistrationCoordinator {
    pub fn new(
        keystore: Keystore,
        store: Arc<dyn WalletRegistrationStore>,
        audit: Arc<AuditLog>,
        keystore_root: PathBuf,
    ) -> Self {
        Self {
            keystore,
            store,
            audit,
            keystore_root,
            listener_base_url: RwLock::new(None),
            state: Mutex::new(CoordinatorState::default()),
            transitions: tokio::sync::Mutex::new(()),
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

    async fn cancel_inner(
        &self,
        wallet: Option<&str>,
        token: Option<&str>,
        now_ms: u64,
    ) -> Result<(), AuthApiError> {
        let _transition = self.transitions.lock().await;
        let (token, wallet) = {
            let state = self.state.lock();
            let token = match (wallet, token) {
                (Some(wallet), None) => state.by_wallet.get(wallet).cloned(),
                (None, Some(token)) => Some(token.to_string()),
                _ => None,
            }
            .ok_or_else(|| AuthApiError::NotFound("no live registration session".into()))?;
            let session = state.sessions.get(&token).ok_or_else(|| {
                AuthApiError::NotFound("unknown or already-terminal registration session".into())
            })?;
            if session.completion.is_some() || session.completing {
                return Err(AuthApiError::Denied(
                    "registration is completing or completed; it cannot be cancelled".into(),
                ));
            }
            (token, session.wallet.clone())
        };
        let mut status = self
            .store
            .status_for_session(&token)
            .await?
            .ok_or_else(|| AuthApiError::Store("registration session status missing".into()))?;
        status.state = WalletRegistrationState::Cancelled;
        status.ceremony_url = None;
        self.store.upsert(&token, &status, now_ms).await?;
        Self::remove_session_if_current(&mut self.state.lock(), &token, &wallet);
        Ok(())
    }

    fn fresh_session(wallet: &str, now_ms: u64) -> (String, SecretSession) {
        let mut prf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_salt);
        let token = gen_token();
        let created_at_ms = now_ms;
        let expires_at_ms = now_ms + SESSION_TTL_MS;
        let session = SecretSession {
            wallet: wallet.to_string(),
            signer: PrivateKeySigner::random(),
            prf_salt,
            server_nonce: gen_id("nonce"),
            created_at_ms,
            expires_at_ms,
            attempts: HashMap::new(),
            completion: None,
            completing: false,
            recovery_ack_deadline: None,
        };
        (token, session)
    }

    fn release_completion(&self, token: &str, attempt_id: &str) {
        if let Some(session) = self.state.lock().sessions.get_mut(token) {
            session.completing = false;
            if let Some(attempt) = session.attempts.get_mut(attempt_id) {
                attempt.busy = false;
            }
        }
    }

    fn audit_wallet_created(&self, wallet: &str) {
        if let Err(error) = self.audit.append(AuditRecord {
            ts_ms: 0,
            kind: "wallet.created".into(),
            wallet: Some(wallet.into()),
            chain: None,
            data: serde_json::json!({"kind": "passkey", "source": "wallet_registration"}),
            prev: String::new(),
            digest: String::new(),
        }) {
            tracing::warn!(%error, %wallet, "wallet.created audit unavailable");
        }
    }
}

#[async_trait]
impl WalletRegistrationLifecycle for RegistrationCoordinator {
    fn mark_listener_bound(&self, base_url: &str) {
        *self.listener_base_url.write() = Some(base_url.to_string());
    }

    fn mark_listener_unbound(&self) {
        *self.listener_base_url.write() = None;
    }

    async fn reconcile_after_restart(
        &self,
        reason: &str,
        now_ms: u64,
    ) -> Result<u64, AuthApiError> {
        let rows = self.store.non_terminal().await?;
        let mut reconciled = 0u64;
        for (token, mut status) in rows {
            let installed = if let Ok(info) = self.keystore.info_unverified(&status.wallet) {
                status.state = WalletRegistrationState::Completed;
                status.ceremony_url = None;
                status.address = Some(bloom_proto::checksum_address(&info.address));
                true
            } else {
                status.state = WalletRegistrationState::Failed;
                status.ceremony_url = None;
                status.error = Some(reason.to_string());
                false
            };
            self.store.upsert(&token, &status, now_ms).await?;
            if installed {
                self.audit_wallet_created(&status.wallet);
            }
            reconciled += 1;
        }
        Ok(reconciled)
    }
}

#[async_trait]
impl WalletRegistrationVfs for RegistrationCoordinator {
    async fn stage(
        &self,
        wallet: &str,
        now_ms: u64,
    ) -> Result<WalletRegistrationStatus, AuthApiError> {
        Keystore::validate_name(wallet).map_err(|e| AuthApiError::Denied(e.to_string()))?;

        let base = self.base_url()?;
        let _transition = self.transitions.lock().await;

        if self.keystore_root.join(wallet).exists() {
            return Err(AuthApiError::Denied(format!(
                "wallet '{wallet}' already exists"
            )));
        }
        if let Some(persisted) = self.store.status_for_wallet(wallet).await?
            && persisted.state == WalletRegistrationState::Completed
        {
            return Err(AuthApiError::Denied(format!(
                "wallet '{wallet}' already exists"
            )));
        }

        let (live_token, stale_token) = {
            let state = self.state.lock();
            let token = state.by_wallet.get(wallet).cloned();
            match token.as_ref().and_then(|token| state.sessions.get(token)) {
                Some(session) if session.effective_deadline() > now_ms || session.completing => {
                    (token, None)
                }
                Some(_) => (None, token),
                None => (None, None),
            }
        };
        if let Some(token) = live_token {
            return self
                .store
                .status_for_session(&token)
                .await?
                .ok_or_else(|| AuthApiError::Store("registration session status missing".into()));
        }
        if let Some(token) = stale_token {
            let mut status = self
                .store
                .status_for_session(&token)
                .await?
                .ok_or_else(|| AuthApiError::Store("registration session status missing".into()))?;
            if !status.state.is_terminal() {
                status.state = WalletRegistrationState::Expired;
                status.ceremony_url = None;
                self.store.upsert(&token, &status, now_ms).await?;
            }
            Self::remove_session_if_current(&mut self.state.lock(), &token, wallet);
        }

        let (token, session) = Self::fresh_session(wallet, now_ms);
        let url = Self::ceremony_url(&base, &token);
        let status = WalletRegistrationStatus::awaiting_user(
            wallet,
            session.created_at_ms,
            session.expires_at_ms,
            url,
        );
        self.store.upsert(&token, &status, now_ms).await?;
        let mut state = self.state.lock();
        if let Some(stale) = state.by_wallet.insert(wallet.to_string(), token.clone()) {
            state.sessions.remove(&stale);
        }
        state.sessions.insert(token, session);
        Ok(status)
    }

    async fn status(&self, wallet: &str) -> Result<Option<WalletRegistrationStatus>, AuthApiError> {
        self.store.status_for_wallet(wallet).await
    }

    async fn list_wallets(&self) -> Result<Vec<String>, AuthApiError> {
        self.store.wallets().await
    }

    async fn cancel(&self, wallet: &str, now_ms: u64) -> Result<(), AuthApiError> {
        self.cancel_inner(Some(wallet), None, now_ms).await
    }
}

#[async_trait]
impl WalletRegistrationCeremony for RegistrationCoordinator {
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
            if session.expires_at_ms <= now_ms {
                return Err(AuthApiError::NotFound(
                    "unknown or expired registration session".into(),
                ));
            }
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
                    busy: false,
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
            let mut state = self.state.lock();
            let session = state
                .sessions
                .get_mut(token)
                .filter(|s| s.expires_at_ms > now_ms)
                .ok_or_else(|| AuthApiError::NotFound("unknown or expired session".into()))?;
            let attempt = session
                .attempts
                .get_mut(attempt_id)
                .ok_or_else(|| AuthApiError::NotFound("unknown registration attempt".into()))?;
            if let Some((_, _, options)) = &attempt.fallback {
                return Ok(WalletRegistrationFallbackOptions {
                    request_options_json: options.clone(),
                });
            }
            if attempt.busy {
                return Err(AuthApiError::Denied(
                    "attempt is already in progress".into(),
                ));
            }
            attempt.busy = true;
            (session.prf_salt, attempt.reg_state.clone())
        };

        let generated = (|| {
            let passkey =
                finish_registration(&credential, &reg_state).map_err(AuthApiError::Denied)?;
            let mut challenge = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut challenge);
            let (options, auth_state) =
                start_registration_fallback_assertion(&passkey, &prf_salt, &challenge)
                    .map_err(AuthApiError::Denied)?;
            Ok::<_, AuthApiError>((passkey, auth_state, options))
        })();

        let mut state = self.state.lock();
        let session = state
            .sessions
            .get_mut(token)
            .filter(|session| session.expires_at_ms > now_ms && session.completion.is_none())
            .ok_or_else(|| {
                AuthApiError::NotFound("registration session is no longer active".into())
            })?;
        let attempt = session
            .attempts
            .get_mut(attempt_id)
            .ok_or_else(|| AuthApiError::NotFound("registration attempt disappeared".into()))?;
        attempt.busy = false;
        let (passkey, auth_state, options) = generated?;
        attempt.fallback = Some((passkey, auth_state, options.clone()));
        Ok(WalletRegistrationFallbackOptions {
            request_options_json: options,
        })
    }

    async fn complete(
        &self,
        token: &str,
        attempt_id: &str,
        body: WalletRegistrationCompleteBody,
        now_ms: u64,
    ) -> Result<WalletRegistrationCompleteOutcome, AuthApiError> {
        let request_digest = complete_body_digest(attempt_id, &body);
        let work = {
            // Serialize the reservation with cancel/stage/sweep, then release
            // the lifecycle gate before WebAuthn and filesystem work.
            let _transition = self.transitions.lock().await;
            let mut state = self.state.lock();
            let session = state
                .sessions
                .get_mut(token)
                .filter(|s| s.effective_deadline() > now_ms)
                .ok_or_else(|| AuthApiError::NotFound("unknown or expired session".into()))?;
            match &session.completion {
                Some(CompletionPhase::Won(winner))
                    if winner.attempt_id == attempt_id
                        && winner.request_digest == request_digest =>
                {
                    CompleteWork::Replay {
                        address: bloom_proto::checksum_address(&winner.prepared.address),
                        recovery_key: winner.prepared.recovery_key.clone(),
                        receipt: winner.receipt.clone(),
                    }
                }
                Some(_) => {
                    return Err(AuthApiError::Denied(
                        "registration already completed".into(),
                    ));
                }
                None => {
                    if session.completing {
                        return Err(AuthApiError::Denied("another attempt is completing".into()));
                    }
                    let attempt = session.attempts.get_mut(attempt_id).ok_or_else(|| {
                        AuthApiError::NotFound("unknown registration attempt".into())
                    })?;
                    if attempt.busy {
                        return Err(AuthApiError::Denied(
                            "attempt is already in progress".into(),
                        ));
                    }
                    attempt.busy = true;
                    session.completing = true;
                    CompleteWork::New(Box::new(CompleteNew {
                        wallet: session.wallet.clone(),
                        signer: session.signer.clone(),
                        prf_salt: session.prf_salt,
                        policy_toml: attempt.policy_toml.clone(),
                        reg_state: attempt.reg_state.clone(),
                        fallback: attempt
                            .fallback
                            .as_ref()
                            .map(|(passkey, auth, _)| (passkey.clone(), auth.clone())),
                    }))
                }
            }
        };

        let (address, recovery_key, receipt) = match work {
            CompleteWork::Replay {
                address,
                recovery_key,
                receipt,
            } => (address, recovery_key, receipt),
            CompleteWork::New(work) => {
                let CompleteNew {
                    wallet,
                    signer,
                    prf_salt,
                    policy_toml,
                    reg_state,
                    fallback,
                } = *work;
                let prepared = (|| {
                    // WebAuthn verification and filesystem writes deliberately
                    // run outside the coordinator mutex.
                    let (passkey, prf_output_b64) = match &body {
                        WalletRegistrationCompleteBody::Registration {
                            credential,
                            prf_output_b64,
                        } => {
                            let credential: RegisterPublicKeyCredential =
                                serde_json::from_value(credential.clone()).map_err(|e| {
                                    AuthApiError::Denied(format!("invalid credential: {e}"))
                                })?;
                            (
                                finish_registration(&credential, &reg_state)
                                    .map_err(AuthApiError::Denied)?,
                                prf_output_b64,
                            )
                        }
                        WalletRegistrationCompleteBody::Fallback {
                            credential,
                            prf_output_b64,
                        } => {
                            let credential: PublicKeyCredential =
                                serde_json::from_value(credential.clone()).map_err(|e| {
                                    AuthApiError::Denied(format!("invalid credential: {e}"))
                                })?;
                            let (passkey, auth_state) = fallback.as_ref().ok_or_else(|| {
                                AuthApiError::Denied("no fallback attempt in progress".into())
                            })?;
                            finish_registration_fallback_assertion(&credential, auth_state)
                                .map_err(AuthApiError::Denied)?;
                            (passkey.clone(), prf_output_b64)
                        }
                    };
                    let mut bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(prf_output_b64.trim())
                        .map_err(|_| AuthApiError::Denied("invalid PRF output".into()))?;
                    if bytes.len() != 32 {
                        bytes.zeroize();
                        return Err(AuthApiError::Denied("PRF output must be 32 bytes".into()));
                    }
                    let mut prf = [0; 32];
                    prf.copy_from_slice(&bytes);
                    bytes.zeroize();
                    prepare_passkey_wallet(
                        &self.keystore_root,
                        &format!("{token}-{attempt_id}"),
                        &wallet,
                        &signer,
                        &passkey,
                        &prf_salt,
                        prf,
                        &policy_toml,
                    )
                    .map_err(|e| AuthApiError::Store(e.to_string()))
                })();

                let prepared = match prepared {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        self.release_completion(token, attempt_id);
                        return Err(error);
                    }
                };
                let address = bloom_proto::checksum_address(&prepared.address);
                let recovery_key = prepared.recovery_key.clone();
                let receipt = gen_token();
                let mut state = self.state.lock();
                let session = state.sessions.get_mut(token).ok_or_else(|| {
                    AuthApiError::NotFound("registration session disappeared".into())
                })?;
                if session.effective_deadline() <= now_ms || session.completion.is_some() {
                    session.completing = false;
                    if let Some(attempt) = session.attempts.get_mut(attempt_id) {
                        attempt.busy = false;
                    }
                    return Err(AuthApiError::Denied(
                        "registration session is no longer active".into(),
                    ));
                }
                let attempt = session.attempts.get_mut(attempt_id).ok_or_else(|| {
                    AuthApiError::NotFound("registration attempt disappeared".into())
                })?;
                attempt.busy = false;
                session.completing = false;
                session.completion = Some(CompletionPhase::Won(Box::new(WinnerState {
                    prepared,
                    receipt: receipt.clone(),
                    attempt_id: attempt_id.to_string(),
                    request_digest,
                })));
                session.recovery_ack_deadline = Some(now_ms + RECOVERY_ACK_TTL_MS);
                (address, recovery_key, receipt)
            }
        };

        // Replays retry this write too, repairing a prior response-path store
        // failure rather than returning early with stale public status.
        let mut status = self
            .store
            .status_for_session(token)
            .await?
            .ok_or_else(|| AuthApiError::Store("registration session status missing".into()))?;
        status.state = WalletRegistrationState::AwaitingRecoveryAck;
        status.address = None;
        status.expires_at_ms = now_ms + RECOVERY_ACK_TTL_MS;
        self.store.upsert(token, &status, now_ms).await?;

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
        let _transition = self.transitions.lock().await;
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
                            session.completion = Some(CompletionPhase::Finalized {
                                address: address.clone(),
                                receipt: winner.receipt,
                            });
                            (wallet, address)
                        }
                        Err((prepared, e)) => {
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

        // Retain `Finalized` until persistence succeeds so acknowledgment is retryable.
        self.persist_completed(token, &address, now_ms).await?;

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
        self.cancel_inner(None, Some(token), now_ms).await
    }
}

#[async_trait]
impl WalletRegistrationMaintenance for RegistrationCoordinator {
    async fn sweep_expired(&self, now_ms: u64) -> Result<usize, AuthApiError> {
        let _transition = self.transitions.lock().await;
        let expired_tokens: Vec<String> = {
            let state = self.state.lock();
            state
                .sessions
                .iter()
                .filter(|(_, s)| s.effective_deadline() <= now_ms && !s.completing)
                .map(|(t, _)| t.clone())
                .collect()
        };

        // Remove memory only after terminal status persists; failures retry next tick.
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
                match self.persist_completed(&token, &address, now_ms).await {
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

            let status = match self.store.status_for_session(&token).await {
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
            if let Err(e) = self.store.upsert(&token, &status, now_ms).await {
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
    fn remove_session_if_current(state: &mut CoordinatorState, token: &str, wallet: &str) {
        state.sessions.remove(token);
        if state.by_wallet.get(wallet).map(String::as_str) == Some(token) {
            state.by_wallet.remove(wallet);
        }
    }

    async fn persist_completed(
        &self,
        token: &str,
        address: &str,
        now_ms: u64,
    ) -> Result<(), AuthApiError> {
        let mut status = self
            .store
            .status_for_session(token)
            .await?
            .ok_or_else(|| AuthApiError::Store("registration session status missing".into()))?;
        status.state = WalletRegistrationState::Completed;
        status.ceremony_url = None;
        status.address = Some(address.to_string());
        self.store.upsert(token, &status, now_ms).await?;
        self.audit_wallet_created(&status.wallet);
        Ok(())
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
        let store: Arc<dyn WalletRegistrationStore> = verifier;
        let audit = Arc::new(AuditLog::open(tmp.path().join("audit.jsonl")).unwrap());
        let coordinator =
            RegistrationCoordinator::new(keystore, store, audit, tmp.path().join("keystore"));
        (coordinator, tmp)
    }

    fn wallet_created_records(coordinator: &RegistrationCoordinator) -> Vec<AuditRecord> {
        coordinator
            .audit
            .tail(10)
            .unwrap()
            .into_iter()
            .filter(|record| record.kind == "wallet.created")
            .collect()
    }

    async fn stage_token(
        coordinator: &RegistrationCoordinator,
        wallet: &str,
        now_ms: u64,
    ) -> String {
        coordinator
            .stage(wallet, now_ms)
            .await
            .unwrap()
            .ceremony_url
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn stage_fails_closed_when_unarmed() {
        let (coordinator, _tmp) = coordinator();
        let err = coordinator.stage("alice", 1_000).await.unwrap_err();
        assert!(err.to_string().contains("bloom serve"));
    }

    #[tokio::test]
    async fn stage_fails_closed_after_listener_stops() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        coordinator.mark_listener_unbound();
        assert!(coordinator.stage("alice", 1_000).await.is_err());
    }

    #[tokio::test]
    async fn failed_stage_does_not_publish_an_in_memory_session() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let mut blocker = WalletRegistrationStatus::awaiting_user(
            "alice",
            500,
            2_000,
            "http://localhost:18734/wallet-registration/blocker",
        );
        coordinator
            .store
            .upsert("blocker", &blocker, 500)
            .await
            .unwrap();

        assert!(coordinator.stage("alice", 1_000).await.is_err());
        assert!(coordinator.state.lock().sessions.is_empty());

        blocker.state = WalletRegistrationState::Cancelled;
        blocker.ceremony_url = None;
        coordinator
            .store
            .upsert("blocker", &blocker, 1_001)
            .await
            .unwrap();
        assert!(coordinator.stage("alice", 1_002).await.is_ok());
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
    async fn stage_replaces_an_expired_session_before_the_next_sweep() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");

        let first = coordinator.stage("alice", 1_000).await.unwrap();
        let fresh = coordinator
            .stage("alice", 1_000 + SESSION_TTL_MS + 1)
            .await
            .unwrap();

        assert_ne!(fresh.ceremony_url, first.ceremony_url);
        assert_eq!(fresh.state, WalletRegistrationState::AwaitingUser);
    }

    #[tokio::test]
    async fn stage_rejects_wallet_that_already_exists_on_disk() {
        let (coordinator, tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        std::fs::create_dir_all(tmp.path().join("keystore").join("alice")).unwrap();

        let err = coordinator.stage("alice", 1_000).await.unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

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
        let token = stage_token(&coordinator, "alice", 1_000).await;

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
        let token = stage_token(&coordinator, "alice", 1_000).await;
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
        let token = stage_token(&coordinator, "alice", 1_000).await;
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
        let state = coordinator.state.lock();
        let session = state.sessions.get(&token).unwrap();
        assert!(!session.completing);
        assert!(!session.attempts[&opts.attempt_id].busy);
    }

    #[tokio::test]
    async fn cancel_by_token_still_works_before_any_completion() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let token = stage_token(&coordinator, "alice", 1_000).await;

        coordinator.cancel_by_token(&token, 2_000).await.unwrap();
        let after = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(after.state, WalletRegistrationState::Cancelled);
    }

    #[tokio::test]
    async fn cancel_rejects_while_completion_is_reserved() {
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");
        let token = stage_token(&coordinator, "alice", 1_000).await;
        coordinator
            .state
            .lock()
            .sessions
            .get_mut(&token)
            .unwrap()
            .completing = true;
        assert!(coordinator.cancel("alice", 1_001).await.is_err());
        assert!(coordinator.cancel_by_token(&token, 1_001).await.is_err());
        assert_eq!(
            coordinator.status("alice").await.unwrap().unwrap().state,
            WalletRegistrationState::AwaitingUser
        );
    }

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
        let token = stage_token(&coordinator, "alice", 1_000).await;
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

    async fn stage_and_finalize_directly(
        coordinator: &RegistrationCoordinator,
        wallet: &str,
        address: &str,
        receipt: &str,
        now_ms: u64,
        ack_ttl_ms: u64,
    ) -> String {
        let token = stage_token(coordinator, wallet, now_ms).await;
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
            .store
            .upsert(&token, &persisted, now_ms)
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
        assert_eq!(wallet_created_records(&coordinator).len(), 1);

        // The session is gone — a repeat with the same receipt now 404s,
        // same as any other terminal session (idempotent completion of the
        // *persisted* status, not of the in-memory session's lifetime).
        assert!(
            coordinator
                .recovery_ack(&token, "receipt-1", 1_600)
                .await
                .is_err()
        );
        assert_eq!(wallet_created_records(&coordinator).len(), 1);
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
        let (coordinator, _tmp) = coordinator();
        coordinator.mark_listener_bound("http://localhost:18734");

        // Simulate a wallet that `recovery_ack` successfully renamed into
        // place before the process died, whose persisted status never got
        // to `Completed`.
        coordinator
            .keystore
            .add_watch(
                "alice",
                "0x0000000000000000000000000000000000000abc"
                    .parse()
                    .unwrap(),
            )
            .unwrap();
        let mut status = WalletRegistrationStatus::awaiting_user(
            "alice",
            1_000,
            1_000 + 300_000,
            "http://localhost:18734/wallet-registration/tok-installed",
        );
        status.state = WalletRegistrationState::AwaitingRecoveryAck;
        coordinator
            .store
            .upsert("tok-installed", &status, 1_000)
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
            .store
            .upsert("tok-abandoned", &abandoned, 1_000)
            .await
            .unwrap();

        let reconciled = coordinator
            .reconcile_after_restart("daemon restarted", 9_000)
            .await
            .unwrap();
        assert_eq!(reconciled, 2);

        let alice = coordinator.status("alice").await.unwrap().unwrap();
        assert_eq!(alice.state, WalletRegistrationState::Completed);
        assert_eq!(
            alice.address.as_deref(),
            Some("0x0000000000000000000000000000000000000aBc")
        );

        let bob = coordinator.status("bob").await.unwrap().unwrap();
        assert_eq!(bob.state, WalletRegistrationState::Failed);
        assert_eq!(bob.error.as_deref(), Some("daemon restarted"));

        let records = wallet_created_records(&coordinator);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].wallet.as_deref(), Some("alice"));
        assert_eq!(records[0].data["source"], "wallet_registration");
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
