//! The onboarding state machine — deploy → fund → approve → creds → sync.
//!
//! [`Onboarder::run`] drives a wallet through every incomplete onboarding
//! stage, **idempotently and resumably**: each stage probes real state (chain
//! code/balances/allowances, the creds file) before acting, so the persisted
//! [`OnboardState`] is a progress hint for humans, never the authority — a
//! daemon killed mid-run self-heals on the next run. State is persisted to
//! `<dir>/<wallet>/account.json` (no secrets) after every transition, and any
//! error is recorded in `last_error` before returning so a fire-and-forget
//! caller (the VFS `begin` write spawns this) always leaves an observable
//! trail.
//!
//! Side effects that move past the relayer or mint credentials are reported
//! through the [`OnboardEvent`] callback so the caller can append audit
//! records; events carry tx ids and the API-key id only — never the L2
//! `secret`/`passphrase`.
//!
//! Chain reads go through the narrow [`ChainReader`] trait so this crate stays
//! free of any RPC/client coupling (the daemon adapts its chain client; tests
//! use a mock).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use crate::clob::ClobClient;
use crate::creds::CredentialStore;
use crate::eip712::{
    CTF, CTF_COLLATERAL_ADAPTER, CTF_EXCHANGE_V2, NEG_RISK_CTF_COLLATERAL_ADAPTER,
    NEG_RISK_EXCHANGE_V2, PUSD, derive_deposit_wallet_address,
};
use crate::relayer::RelayerClient;
use crate::signer::OnboardSigner;
use crate::wallet::v2_approval_calls;
use crate::{PolymarketError, Result};

/// The four V2 spenders/operators the approval batch grants (order matters —
/// it mirrors `v2_approval_calls`).
const V2_SPENDERS: [Address; 4] = [
    CTF_EXCHANGE_V2,
    NEG_RISK_EXCHANGE_V2,
    CTF_COLLATERAL_ADAPTER,
    NEG_RISK_CTF_COLLATERAL_ADAPTER,
];

/// Allowance floor treated as "approved". `approve(MAX)` decays as it is
/// spent, so equality with `U256::MAX` would spuriously re-approve; anything
/// above 2^160 is unspendable in practice.
fn allowance_floor() -> U256 {
    U256::from(1) << 160
}

/// Validity window for the approval batch signature.
const BATCH_DEADLINE_SECS: u64 = 3600;

/// Narrow read-only chain access used by the idempotency probes. Implemented
/// over the daemon's chain client in bloom-vfs; mocked in tests.
#[async_trait::async_trait]
pub trait ChainReader: Send + Sync {
    /// Byte length of the code at `addr` (0 = not deployed).
    async fn code_len(&self, addr: Address) -> Result<usize>;
    async fn erc20_balance(&self, token: Address, holder: Address) -> Result<U256>;
    async fn erc20_allowance(
        &self,
        token: Address,
        owner: Address,
        spender: Address,
    ) -> Result<U256>;
    async fn is_approved_for_all(
        &self,
        token: Address,
        owner: Address,
        operator: Address,
    ) -> Result<bool>;
    /// The deposit-wallet address **as the live factory computes it**:
    /// `factory.predictWalletAddress(factory.implementation(), bytes32(owner))`
    /// via `eth_call`. Authoritative — the local CREATE2 port
    /// (`derive_deposit_wallet_address`) has disagreed with the live factory
    /// (owner `0x5c3d…` → factory says `0x3855…`, local said `0xAe87…`), and
    /// an on-chain read also survives factory implementation upgrades.
    async fn predict_deposit_wallet(&self, owner: Address) -> Result<Address>;
}

/// Which onboarding path a wallet is on. Bloom trades only via the gasless
/// deposit wallet (signatureType 3, POLY_1271) — this single-variant enum is
/// retained so persisted `account.json` (`"mode": "deposit_wallet"`) keeps
/// deserializing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnboardMode {
    /// Gasless deposit wallet, signatureType 3 (POLY_1271), via the relayer.
    #[default]
    DepositWallet,
}

impl OnboardMode {
    /// CLOB `signature_type` for the balance-allowance sync.
    fn sig_type(self) -> u8 {
        match self {
            OnboardMode::DepositWallet => 3,
        }
    }
}

/// Onboarding stages, in order. The persisted stage is the **next incomplete**
/// stage (`Complete` = done). `Derive` means "not started".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Derive,
    Deploy,
    Fund,
    Approve,
    Creds,
    Sync,
    Complete,
}

impl Stage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Stage::Derive => "derive",
            Stage::Deploy => "deploy",
            Stage::Fund => "fund",
            Stage::Approve => "approve",
            Stage::Creds => "creds",
            Stage::Sync => "sync",
            Stage::Complete => "complete",
        }
    }
}

/// Durable per-wallet onboarding state (`<dir>/<wallet>/account.json`).
/// Contains addresses, stage, and relayer tx ids — never secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardState {
    pub wallet: String,
    /// Owner EOA (checksummed) — the bloom keystore wallet address.
    pub owner: String,
    /// Deterministic CREATE2 deposit-wallet address (checksummed).
    pub deposit_wallet: String,
    /// Provenance for `deposit_wallet`: `owner_eoa`,
    /// `local_estimate_unverified`, `persisted_factory_resolved`, or
    /// `live_factory_resolved`.
    #[serde(default)]
    pub deposit_wallet_source: String,
    /// Whether callers may safely send pUSD to `deposit_wallet`.
    #[serde(default)]
    pub deposit_wallet_fundable: bool,
    /// Optional warning shown on VFS/status surfaces.
    #[serde(default)]
    pub deposit_wallet_warning: Option<String>,
    pub chain_id: u64,
    /// Next incomplete stage.
    pub stage: Stage,
    pub deploy_tx_id: Option<String>,
    pub approve_tx_id: Option<String>,
    /// Last observed pUSD balance at the deposit wallet (raw 6-dp units).
    pub pusd_balance: Option<String>,
    pub creds_present: bool,
    pub last_error: Option<String>,
    /// Unix millis of the last persisted transition.
    pub updated_ms: u128,
    /// Unix-ms deadline of an in-flight network stage (relayer/CLOB call +
    /// confirmation poll). Set and persisted *before* the call, cleared on
    /// success. A separate reader — or a post-mortem after the process is killed
    /// mid-call — can tell a live op (`now` < deadline) from a dead/stalled one
    /// (`now` > deadline), which the in-memory `running` flag cannot do across
    /// processes. `null` with `last_error == null` at a non-terminal stage means
    /// a run stopped between network regions (clean exit, or killed before an
    /// error could be persisted) — re-running `begin` is safe.
    #[serde(default)]
    pub in_flight_deadline_ms: Option<u128>,
    /// Which onboarding path this run is on. `#[serde(default)]` ⇒ legacy
    /// `account.json` (pre-EOA) loads as `DepositWallet`.
    #[serde(default)]
    pub mode: OnboardMode,
    /// How relayer operations are authenticated for this run:
    /// `"builder_key_auto"` (bloom-minted builder API key),
    /// `"relayer_key_manual"`, `"none"` (EOA), or `"disabled"`.
    #[serde(default)]
    pub relayer_auth: Option<String>,
}

impl OnboardState {
    fn fresh(
        wallet: &str,
        owner: Address,
        deposit_wallet: Address,
        chain_id: u64,
        mode: OnboardMode,
    ) -> Self {
        Self {
            wallet: wallet.to_string(),
            owner: owner.to_checksum(None),
            deposit_wallet: deposit_wallet.to_checksum(None),
            deposit_wallet_source: "local_estimate_unverified".to_string(),
            deposit_wallet_fundable: false,
            deposit_wallet_warning: Some(
                "local deposit-wallet estimate only; do not fund until onboarding resolves the live factory address".to_string(),
            ),
            chain_id,
            stage: Stage::Derive,
            deploy_tx_id: None,
            approve_tx_id: None,
            pusd_balance: None,
            creds_present: false,
            last_error: None,
            updated_ms: now_ms(),
            in_flight_deadline_ms: None,
            mode,
            relayer_auth: None,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.stage == Stage::Complete
    }

    /// Whether this account can actually place orders.
    pub fn tradeable(&self) -> bool {
        self.is_complete()
    }
}

/// File-backed store for [`OnboardState`] — the `CredentialStore` analogue,
/// sharing the same per-wallet directory layout.
#[derive(Debug, Clone)]
pub struct OnboardStore {
    dir: PathBuf,
}

impl OnboardStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn state_path(&self, wallet: &str) -> PathBuf {
        self.dir.join(wallet).join("account.json")
    }

    pub fn load(&self, wallet: &str) -> Result<Option<OnboardState>> {
        validate_wallet_name(wallet)?;
        match std::fs::read(self.state_path(wallet)) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PolymarketError::from(e)),
        }
    }

    pub fn save(&self, wallet: &str, state: &OnboardState) -> Result<()> {
        validate_wallet_name(wallet)?;
        let path = self.state_path(wallet);
        let dir = path.parent().expect("state path has parent");
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(std::fs::write(&path, serde_json::to_vec_pretty(state)?)?)
    }
}

/// Reject wallet names that could escape the per-wallet directory. The VFS
/// additionally requires the name to resolve in the keystore; this guard makes
/// the stores safe even for direct library callers.
pub fn validate_wallet_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(PolymarketError::invalid(format!(
            "invalid wallet name {name:?}: must be 1-128 chars of [A-Za-z0-9._-], not starting with '.'"
        )))
    }
}

/// A side effect worth auditing, reported as it happens. Carries identifiers
/// only — never the L2 secret/passphrase.
#[derive(Debug, Clone)]
pub enum OnboardEvent {
    /// A relayer tx was accepted (`kind`: `"deploy"` | `"approve"`).
    RelayerSubmitted {
        kind: &'static str,
        tx_id: String,
    },
    RelayerConfirmed {
        kind: &'static str,
        tx_id: String,
        tx_hash: Option<String>,
    },
    /// CLOB API credentials were minted/derived (API-key id only).
    CredsMinted {
        api_key: String,
    },
    /// An EOA-path on-chain approval tx was broadcast / confirmed (`kind`:
    /// `"approve"`). Carries the tx hash.
    OnchainSubmitted {
        kind: &'static str,
        tx_hash: String,
    },
    OnchainConfirmed {
        kind: &'static str,
        tx_hash: String,
    },
    /// Disclosure hook fired **before** bloom creates a builder API key on
    /// the user's Polymarket account. UIs should render: bloom is about to
    /// create a builder API key from this wallet's CLOB credentials; it
    /// authenticates relayer submission only, can never move funds, and is
    /// revocable with `bloom polymarket builder-keys revoke`.
    BuilderKeyCreating,
    /// A builder API key was created and persisted (key id only — no secret).
    BuilderKeyCreated {
        key: String,
    },
    StageDone(Stage),
}

/// Callback for [`OnboardEvent`]s.
pub type OnEvent = dyn Fn(OnboardEvent) + Send + Sync;

/// Default relayer/CLOB confirmation poll budget. Exposed so `status.json` can
/// surface the window an agent should expect a network-bound stage to take.
pub const DEFAULT_POLL_TIMEOUT_SECS: u64 = 180;

/// How the onboarder obtains relayer auth for deposit-wallet operations.
#[derive(Debug, Clone)]
pub enum RelayerAuthMode {
    /// Use the relayer client exactly as constructed (manual relayer key
    /// attached via `RelayerClient::with_api_key`, or none on the EOA path).
    Inherit,
    /// Self-provision a **builder API key** at first relayer use: ensure CLOB
    /// credentials exist (L1 mint is pure signing), then load or create the
    /// builder key via CLOB L2 and persist it. Fires
    /// [`OnboardEvent::BuilderKeyCreating`] before any creation.
    AutoBuilder,
    /// Refuse every relayer operation with this reason (config disabled the
    /// automatic path and no manual key exists).
    Disabled(String),
}

/// Orchestrates the onboarding stages for one configured chain.
pub struct Onboarder {
    chain: Arc<dyn ChainReader>,
    /// Base relayer client. With [`RelayerAuthMode::AutoBuilder`] this is the
    /// unauthenticated base that gets a builder key attached per use; with
    /// `Inherit` it is used exactly as constructed.
    relayer: RelayerClient,
    mode: OnboardMode,
    auth_mode: RelayerAuthMode,
    builder_store: Option<crate::builder_creds::BuilderCredentialStore>,
    clob: ClobClient,
    creds: CredentialStore,
    store: OnboardStore,
    chain_id: u64,
    poll_timeout: Duration,
}

impl Onboarder {
    /// Deposit-wallet (sigType 3, relayer) onboarder.
    pub fn new(
        chain: Arc<dyn ChainReader>,
        relayer: RelayerClient,
        clob: ClobClient,
        creds: CredentialStore,
        store: OnboardStore,
        chain_id: u64,
    ) -> Self {
        Self {
            chain,
            relayer,
            mode: OnboardMode::DepositWallet,
            auth_mode: RelayerAuthMode::Inherit,
            builder_store: None,
            clob,
            creds,
            store,
            chain_id,
            poll_timeout: Duration::from_secs(DEFAULT_POLL_TIMEOUT_SECS),
        }
    }

    /// Self-provision relayer auth via an auto-created builder API key,
    /// persisted in `store` (the bloom default when no manual relayer key is
    /// configured).
    pub fn with_builder_auth(
        mut self,
        store: crate::builder_creds::BuilderCredentialStore,
    ) -> Self {
        self.auth_mode = RelayerAuthMode::AutoBuilder;
        self.builder_store = Some(store);
        self
    }

    /// Refuse all relayer operations with `reason` (builder_key_mode =
    /// "manual" without a configured key, or "disabled").
    pub fn with_relayer_disabled(mut self, reason: impl Into<String>) -> Self {
        self.auth_mode = RelayerAuthMode::Disabled(reason.into());
        self
    }

    /// Human-readable relayer auth mode, recorded in onboarding state.
    fn relayer_auth_label(&self) -> &'static str {
        match &self.auth_mode {
            RelayerAuthMode::AutoBuilder => "builder_key_auto",
            RelayerAuthMode::Inherit => "relayer_key_manual",
            RelayerAuthMode::Disabled(_) => "disabled",
        }
    }

    /// A relayer client carrying live auth, per [`RelayerAuthMode`]. For
    /// `AutoBuilder` this ensures CLOB creds exist (pure L1 signing), then
    /// loads — or, after the disclosure event, creates and persists — the
    /// builder API key.
    pub async fn relayer_for(
        &self,
        wallet: &str,
        owner: Address,
        signer: &dyn OnboardSigner,
        on_event: &OnEvent,
    ) -> Result<RelayerClient> {
        match &self.auth_mode {
            RelayerAuthMode::Inherit => Ok(self.relayer.clone()),
            RelayerAuthMode::Disabled(reason) => Err(PolymarketError::invalid(reason.clone())),
            RelayerAuthMode::AutoBuilder => {
                let store = self
                    .builder_store
                    .as_ref()
                    .ok_or_else(|| PolymarketError::invalid("builder auth without a store"))?;
                if !self.creds.exists(wallet) {
                    let c = self.clob.mint_or_derive_credentials(signer, 0).await?;
                    self.creds.save(wallet, &c)?;
                    on_event(OnboardEvent::CredsMinted {
                        api_key: c.key.clone(),
                    });
                }
                if let Some(bc) = store.load(wallet)? {
                    return Ok(self.relayer.clone().with_builder_key(bc));
                }
                let creds = self
                    .creds
                    .load(wallet)?
                    .ok_or_else(|| PolymarketError::invalid("creds vanished"))?;
                on_event(OnboardEvent::BuilderKeyCreating);
                let bc = self.clob.create_builder_api_key(&creds, owner).await?;
                store.save(wallet, &bc)?;
                on_event(OnboardEvent::BuilderKeyCreated {
                    key: bc.key.clone(),
                });
                Ok(self.relayer.clone().with_builder_key(bc))
            }
        }
    }

    /// Bounded self-healing for stale stored builder creds: when a relayer
    /// call fails 401/403 under `AutoBuilder` and the stored key id is no
    /// longer listed by the CLOB, drop it and mint one fresh key. Returns a
    /// re-authed client at most once; `None` means the failure was not a
    /// stale-credential problem.
    async fn refresh_stale_builder_auth(
        &self,
        err: &PolymarketError,
        wallet: &str,
        owner: Address,
        _signer: &dyn OnboardSigner,
        on_event: &OnEvent,
    ) -> Result<Option<RelayerClient>> {
        if !matches!(self.auth_mode, RelayerAuthMode::AutoBuilder) {
            return Ok(None);
        }
        let PolymarketError::Api { status, .. } = err else {
            return Ok(None);
        };
        if *status != 401 && *status != 403 {
            return Ok(None);
        }
        let store = self
            .builder_store
            .as_ref()
            .ok_or_else(|| PolymarketError::invalid("builder auth without a store"))?;
        let Some(stored) = store.load(wallet)? else {
            return Ok(None);
        };
        let creds = self
            .creds
            .load(wallet)?
            .ok_or_else(|| PolymarketError::invalid("creds vanished"))?;
        let listed = self.clob.list_builder_api_keys(&creds, owner).await?;
        let still_active = listed
            .iter()
            .any(|k| k.key == stored.key && k.revoked_at.is_none());
        if still_active {
            return Ok(None); // key is fine; the 401 is something else
        }
        store.delete(wallet)?;
        on_event(OnboardEvent::BuilderKeyCreating);
        let bc = self.clob.create_builder_api_key(&creds, owner).await?;
        store.save(wallet, &bc)?;
        on_event(OnboardEvent::BuilderKeyCreated {
            key: bc.key.clone(),
        });
        Ok(Some(self.relayer.clone().with_builder_key(bc)))
    }

    /// Relayer confirmation poll budget (shrink in tests).
    pub fn with_poll_timeout(mut self, t: Duration) -> Self {
        self.poll_timeout = t;
        self
    }

    /// The configured confirmation poll budget, in seconds — surfaced in
    /// `status.json` so an agent can compute how long a network-bound stage may
    /// legitimately run before it should be treated as stalled.
    pub fn poll_timeout_secs(&self) -> u64 {
        self.poll_timeout.as_secs()
    }

    /// Current state: the persisted snapshot, or a fresh one for a wallet that
    /// never started. **Local only** — "derive" is the deterministic CREATE2
    /// deposit-wallet *address* derivation (a pure function of the owner; not
    /// to be confused with deriving CLOB credentials). Never touches the
    /// network.
    pub fn status(&self, wallet: &str, owner: Address) -> Result<OnboardState> {
        validate_wallet_name(wallet)?;
        // The "holder" of funds/allowances: the CREATE2 deposit wallet on the
        // deposit-wallet path, the owner EOA itself on the EOA path.
        let holder = derive_deposit_wallet_address(&owner, self.chain_id);
        match self.store.load(wallet)? {
            Some(mut st) => {
                // The persisted state must belong to this owner; a renamed or
                // re-imported keystore wallet must not inherit another key's
                // onboarding record.
                if st.owner.parse::<Address>().ok() != Some(owner) {
                    return Err(PolymarketError::invalid(format!(
                        "onboarding state for '{wallet}' belongs to owner {}, not {}",
                        st.owner,
                        owner.to_checksum(None)
                    )));
                }
                // The persisted address is authoritative — it was resolved from
                // the live factory at run time and the local CREATE2 estimate
                // must not clobber it.
                st.deposit_wallet_source = "persisted_factory_resolved".to_string();
                st.deposit_wallet_fundable = true;
                st.deposit_wallet_warning = None;
                st.creds_present = self.creds.exists(wallet);
                Ok(st)
            }
            None => {
                let mut st = OnboardState::fresh(wallet, owner, holder, self.chain_id, self.mode);
                // Creds can exist without persisted run state (e.g. state dir
                // pruned, or creds seeded externally) — the file is authoritative.
                st.creds_present = self.creds.exists(wallet);
                Ok(st)
            }
        }
    }

    /// The exact approval batch `run` would sign — rendered for
    /// `approvals.json`. Pure; no network, no signature.
    pub fn approval_preview(&self, owner: Address) -> serde_json::Value {
        let deposit = derive_deposit_wallet_address(&owner, self.chain_id);
        let calls: Vec<serde_json::Value> = v2_approval_calls()
            .iter()
            .zip(crate::wallet::V2_APPROVAL_LABELS)
            .map(|(c, label)| {
                serde_json::json!({
                    "label": label,
                    "target": format!("{:#x}", c.target),
                    "value": c.value.to_string(),
                    "data": format!("0x{}", hex::encode(&c.data)),
                })
            })
            .collect();
        serde_json::json!({
            "deposit_wallet": deposit.to_checksum(None),
            "deposit_wallet_source": "local_estimate_unverified",
            "deposit_wallet_fundable": false,
            "warning": "do not fund this locally derived estimate; run onboarding so the live factory address is persisted",
            "chain_id": self.chain_id,
            "eip712_domain": {
                "name": "DepositWallet",
                "version": "1",
                "chainId": self.chain_id,
                "verifyingContract": deposit.to_checksum(None),
            },
            "signature": "plain 65-byte EIP-712 by the owner EOA, submitted to the relayer as a WALLET batch",
            "calls": calls,
        })
    }

    /// Drive every incomplete stage to completion (or to the `Fund` resting
    /// state when the deposit wallet holds no pUSD). Idempotent and resumable;
    /// errors are persisted to `last_error` before returning.
    pub async fn run(
        &self,
        wallet: &str,
        signer: &dyn OnboardSigner,
        on_event: &OnEvent,
    ) -> Result<OnboardState> {
        let owner = signer.address();
        let mut st = self.status(wallet, owner)?;
        st.last_error = None;
        match self.run_stages(&mut st, wallet, signer, on_event).await {
            Ok(()) => {
                self.persist(wallet, &mut st)?;
                Ok(st)
            }
            Err(e) => {
                st.last_error = Some(e.to_string());
                // Best-effort: the run error is the primary failure to report.
                let _ = self.persist(wallet, &mut st);
                Err(e)
            }
        }
    }

    fn persist(&self, wallet: &str, st: &mut OnboardState) -> Result<()> {
        st.updated_ms = now_ms();
        self.store.save(wallet, st)
    }

    /// Persist a self-expiring deadline before a network-bound region so that a
    /// run killed mid-call leaves an observable, cross-process trace (see
    /// [`OnboardState::in_flight_deadline_ms`]).
    fn mark_in_flight(&self, wallet: &str, st: &mut OnboardState) -> Result<()> {
        st.in_flight_deadline_ms = Some(now_ms().saturating_add(self.poll_timeout.as_millis()));
        self.persist(wallet, st)
    }

    /// Clear the in-flight deadline after a network-bound region completes.
    fn clear_in_flight(&self, wallet: &str, st: &mut OnboardState) -> Result<()> {
        st.in_flight_deadline_ms = None;
        self.persist(wallet, st)
    }

    async fn run_stages(
        &self,
        st: &mut OnboardState,
        wallet: &str,
        signer: &dyn OnboardSigner,
        on_event: &OnEvent,
    ) -> Result<()> {
        let owner = signer.address();
        // The factory's own prediction is authoritative (the local CREATE2
        // estimate has disagreed with the live factory). Resolve once per run
        // and persist; downstream stages (fund target, approvals, CLOB funder)
        // all key off the corrected address.
        {
            let predicted = self.chain.predict_deposit_wallet(owner).await?;
            let checksummed = predicted.to_checksum(None);
            if st.deposit_wallet != checksummed {
                st.deposit_wallet = checksummed;
            }
            st.deposit_wallet_source = "live_factory_resolved".to_string();
            st.deposit_wallet_fundable = true;
            st.deposit_wallet_warning = None;
            self.persist(wallet, st)?;
        }
        let deposit: Address = st
            .deposit_wallet
            .parse()
            .map_err(|_| PolymarketError::invalid("corrupt deposit_wallet in onboarding state"))?;

        // ── derive: already verified by status(); record progress.
        if st.stage == Stage::Derive {
            st.stage = Stage::Deploy;
            self.persist(wallet, st)?;
            on_event(OnboardEvent::StageDone(Stage::Derive));
        }

        st.relayer_auth = Some(self.relayer_auth_label().to_string());

        // ── deploy: the chain is the authority, not the persisted stage.
        if self.chain.code_len(deposit).await? == 0 {
            self.mark_in_flight(wallet, st)?;
            let relayer = self.relayer_for(wallet, owner, signer, on_event).await?;
            let tx = match relayer.deploy_deposit_wallet(owner).await {
                Ok(tx) => tx,
                Err(e) => {
                    match self
                        .refresh_stale_builder_auth(&e, wallet, owner, signer, on_event)
                        .await?
                    {
                        Some(fresh) => fresh.deploy_deposit_wallet(owner).await?,
                        None => return Err(e),
                    }
                }
            };
            st.deploy_tx_id = Some(tx.id.clone());
            self.persist(wallet, st)?;
            on_event(OnboardEvent::RelayerSubmitted {
                kind: "deploy",
                tx_id: tx.id.clone(),
            });
            let done = relayer.poll_confirmed(&tx, self.poll_timeout).await?;
            on_event(OnboardEvent::RelayerConfirmed {
                kind: "deploy",
                tx_id: done.id,
                tx_hash: done.tx_hash,
            });
            if self.chain.code_len(deposit).await? == 0 {
                return Err(PolymarketError::invalid(
                    "relayer confirmed the deploy but no code exists at the deposit wallet",
                ));
            }
            self.clear_in_flight(wallet, st)?;
        }
        if st.stage < Stage::Fund {
            st.stage = Stage::Fund;
            self.persist(wallet, st)?;
            on_event(OnboardEvent::StageDone(Stage::Deploy));
        }

        // ── fund: the deposit wallet must hold pUSD as buying power. v1 never
        // moves funds: it rests here until the user funds it, then resumes.
        let balance = self.chain.erc20_balance(PUSD, deposit).await?;
        st.pusd_balance = Some(balance.to_string());
        if balance.is_zero() {
            st.stage = Stage::Fund;
            self.persist(wallet, st)?;
            return Ok(());
        }
        if st.stage < Stage::Approve {
            st.stage = Stage::Approve;
            self.persist(wallet, st)?;
            on_event(OnboardEvent::StageDone(Stage::Fund));
        }

        // ── approve: grant the V2 exchanges/adapters spending rights *from the
        // deposit wallet* via one gasless relayer batch (an EOA approve() does
        // nothing for it).
        if !self.approvals_in_place(deposit).await? {
            self.mark_in_flight(wallet, st)?;
            let relayer = self.relayer_for(wallet, owner, signer, on_event).await?;
            let nonce = relayer.wallet_nonce(owner).await?;
            let deadline = now_secs() + BATCH_DEADLINE_SECS;
            let tx = match relayer
                .submit_wallet_batch(owner, deposit, v2_approval_calls(), nonce, deadline, signer)
                .await
            {
                Ok(tx) => tx,
                Err(e) => match self
                    .refresh_stale_builder_auth(&e, wallet, owner, signer, on_event)
                    .await?
                {
                    Some(fresh) => {
                        fresh
                            .submit_wallet_batch(
                                owner,
                                deposit,
                                v2_approval_calls(),
                                nonce,
                                deadline,
                                signer,
                            )
                            .await?
                    }
                    None => return Err(e),
                },
            };
            st.approve_tx_id = Some(tx.id.clone());
            self.persist(wallet, st)?;
            on_event(OnboardEvent::RelayerSubmitted {
                kind: "approve",
                tx_id: tx.id.clone(),
            });
            let done = relayer.poll_confirmed(&tx, self.poll_timeout).await?;
            on_event(OnboardEvent::RelayerConfirmed {
                kind: "approve",
                tx_id: done.id,
                tx_hash: done.tx_hash,
            });
            if !self.approvals_in_place(deposit).await? {
                return Err(PolymarketError::invalid(
                    "approvals confirmed but on-chain allowances are still missing",
                ));
            }
            self.clear_in_flight(wallet, st)?;
        }
        if st.stage < Stage::Creds {
            st.stage = Stage::Creds;
            self.persist(wallet, st)?;
            on_event(OnboardEvent::StageDone(Stage::Approve));
        }

        // ── creds: mint (or re-derive) the CLOB L2 credentials.
        if !self.creds.exists(wallet) {
            self.mark_in_flight(wallet, st)?;
            let creds = self.clob.mint_or_derive_credentials(signer, 0).await?;
            self.creds.save(wallet, &creds)?;
            on_event(OnboardEvent::CredsMinted {
                api_key: creds.key.clone(),
            });
            self.clear_in_flight(wallet, st)?;
        }
        st.creds_present = true;
        if st.stage < Stage::Sync {
            st.stage = Stage::Sync;
            self.persist(wallet, st)?;
            on_event(OnboardEvent::StageDone(Stage::Creds));
        }

        // ── sync: make the CLOB recompute buying power for the deposit wallet.
        let creds = self
            .creds
            .load(wallet)?
            .ok_or_else(|| PolymarketError::invalid("credentials vanished before sync"))?;
        self.mark_in_flight(wallet, st)?;
        self.clob
            .update_balance_allowance(&creds, owner, "COLLATERAL", self.mode.sig_type())
            .await?;
        // Fold the clear into the terminal persist below.
        st.in_flight_deadline_ms = None;
        st.stage = Stage::Complete;
        self.persist(wallet, st)?;
        on_event(OnboardEvent::StageDone(Stage::Sync));
        Ok(())
    }

    /// Whether all eight V2 grants are live on-chain.
    async fn approvals_in_place(&self, deposit: Address) -> Result<bool> {
        let floor = allowance_floor();
        for spender in V2_SPENDERS {
            if self.chain.erc20_allowance(PUSD, deposit, spender).await? < floor {
                return Ok(false);
            }
        }
        for operator in V2_SPENDERS {
            if !self
                .chain
                .is_approved_for_all(CTF, deposit, operator)
                .await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeystoreSigner;
    use crate::testutil::{Rule, ScriptedServer};
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Mutex;
    use url::Url;

    /// The derivation regression vector (see eip712.rs): this owner's Polygon
    /// deposit wallet.
    const OWNER_KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    /// Mock chain with settable code/balances/allowances and a call log.
    #[derive(Default)]
    struct MockChain {
        code: Mutex<HashMap<Address, usize>>,
        balances: Mutex<HashMap<(Address, Address), U256>>,
        allowances: Mutex<HashMap<(Address, Address, Address), U256>>,
        operator_ok: Mutex<HashMap<(Address, Address, Address), bool>>,
    }

    impl MockChain {
        fn set_code(&self, addr: Address, len: usize) {
            self.code.lock().unwrap().insert(addr, len);
        }
        fn set_balance(&self, token: Address, holder: Address, v: U256) {
            self.balances.lock().unwrap().insert((token, holder), v);
        }
        fn approve_all(&self, deposit: Address) {
            for s in V2_SPENDERS {
                self.allowances
                    .lock()
                    .unwrap()
                    .insert((PUSD, deposit, s), U256::MAX);
                self.operator_ok
                    .lock()
                    .unwrap()
                    .insert((CTF, deposit, s), true);
            }
        }
    }

    #[async_trait::async_trait]
    impl ChainReader for MockChain {
        async fn code_len(&self, addr: Address) -> Result<usize> {
            Ok(*self.code.lock().unwrap().get(&addr).unwrap_or(&0))
        }
        async fn predict_deposit_wallet(&self, owner: Address) -> Result<Address> {
            // Tests mirror the local derivation so existing fixtures keep
            // their addresses; the live impl asks the factory on-chain.
            Ok(derive_deposit_wallet_address(&owner, crate::POLYGON))
        }
        async fn erc20_balance(&self, token: Address, holder: Address) -> Result<U256> {
            Ok(*self
                .balances
                .lock()
                .unwrap()
                .get(&(token, holder))
                .unwrap_or(&U256::ZERO))
        }
        async fn erc20_allowance(
            &self,
            token: Address,
            owner: Address,
            spender: Address,
        ) -> Result<U256> {
            Ok(*self
                .allowances
                .lock()
                .unwrap()
                .get(&(token, owner, spender))
                .unwrap_or(&U256::ZERO))
        }
        async fn is_approved_for_all(
            &self,
            token: Address,
            owner: Address,
            operator: Address,
        ) -> Result<bool> {
            Ok(*self
                .operator_ok
                .lock()
                .unwrap()
                .get(&(token, owner, operator))
                .unwrap_or(&false))
        }
    }

    struct Fixture {
        onboarder: Onboarder,
        chain: Arc<MockChain>,
        signer: KeystoreSigner,
        owner: Address,
        deposit: Address,
        _dir: tempfile::TempDir,
    }

    fn signer() -> KeystoreSigner {
        let pk = alloy::signers::local::PrivateKeySigner::from_str(OWNER_KEY).unwrap();
        KeystoreSigner::new(Arc::new(pk))
    }

    fn fixture(server_url: &str) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(MockChain::default());
        let s = signer();
        let owner = s.address();
        let deposit = derive_deposit_wallet_address(&owner, crate::POLYGON);
        let onboarder = Onboarder::new(
            chain.clone() as Arc<dyn ChainReader>,
            RelayerClient::new(crate::POLYGON).with_base_url(server_url),
            ClobClient::new(crate::POLYGON).with_base_url(Url::parse(server_url).unwrap()),
            CredentialStore::new(dir.path()),
            OnboardStore::new(dir.path()),
            crate::POLYGON,
        )
        .with_poll_timeout(Duration::from_secs(5));
        Fixture {
            onboarder,
            chain,
            signer: s,
            owner,
            deposit,
            _dir: dir,
        }
    }

    fn collect_events() -> (Arc<Mutex<Vec<OnboardEvent>>>, Box<OnEvent>) {
        let events: Arc<Mutex<Vec<OnboardEvent>>> = Arc::default();
        let sink = events.clone();
        (events, Box::new(move |e| sink.lock().unwrap().push(e)))
    }

    fn creds_body() -> String {
        r#"{"apiKey":"11111111-2222-3333-4444-555555555555","secret":"c2VjcmV0","passphrase":"pp"}"#
            .to_string()
    }

    #[tokio::test]
    async fn fresh_status_derives_deposit_wallet_locally() {
        let f = fixture("http://127.0.0.1:1"); // unreachable: status is local
        let st = f.onboarder.status("alice", f.owner).unwrap();
        assert_eq!(st.stage, Stage::Derive);
        assert_eq!(
            st.deposit_wallet.parse::<Address>().unwrap(),
            f.deposit,
            "status must derive the CREATE2 deposit wallet"
        );
        assert_eq!(st.deposit_wallet_source, "local_estimate_unverified");
        assert!(!st.deposit_wallet_fundable);
        assert!(st.deposit_wallet_warning.is_some());
        assert!(st.last_error.is_none() && !st.creds_present);
    }

    #[tokio::test]
    async fn status_rejects_state_owned_by_a_different_key() {
        let f = fixture("http://127.0.0.1:1");
        let mut st = OnboardState::fresh(
            "alice",
            f.owner,
            f.deposit,
            crate::POLYGON,
            OnboardMode::default(),
        );
        st.owner = Address::ZERO.to_checksum(None);
        f.onboarder.store.save("alice", &st).unwrap();
        let err = f.onboarder.status("alice", f.owner).unwrap_err();
        assert!(err.to_string().contains("belongs to owner"));
    }

    #[tokio::test]
    async fn wallet_name_validation_rejects_path_escapes() {
        for bad in [
            "",
            "..",
            "a/b",
            "a\\b",
            ".hidden",
            "a/../b",
            &"x".repeat(129),
        ] {
            assert!(
                validate_wallet_name(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        for good in ["alice", "my-wallet_2", "a.b"] {
            validate_wallet_name(good).unwrap();
        }
    }

    #[test]
    fn legacy_account_json_without_in_flight_field_deserializes() {
        // A pre-existing account.json (e.g. an older passkey wallet) predates
        // `in_flight_deadline_ms`. `#[serde(default)]` must let it load as None.
        let legacy = r#"{
            "wallet":"minnow","owner":"0x2000000000000000000000000000000000000002",
            "deposit_wallet":"0x3000000000000000000000000000000000000003","chain_id":137,
            "stage":"deploy","deploy_tx_id":null,"approve_tx_id":null,"pusd_balance":null,
            "creds_present":false,"last_error":null,"updated_ms":0
        }"#;
        let st: OnboardState = serde_json::from_str(legacy).unwrap();
        assert_eq!(st.stage, Stage::Deploy);
        assert!(
            st.in_flight_deadline_ms.is_none(),
            "missing field must default to None, not fail back-compat"
        );
        assert!(!st.deposit_wallet_fundable);
    }

    #[tokio::test]
    async fn deployed_unfunded_run_skips_deploy_and_rests_at_fund() {
        let server = ScriptedServer::start(vec![]).await; // any request = test failure (404)
        let f = fixture(&server.url());
        let (_, on_event) = collect_events();
        f.chain.set_code(f.deposit, 1); // already deployed

        let st = f
            .onboarder
            .run("alice", &f.signer, &on_event)
            .await
            .unwrap();

        assert_eq!(st.stage, Stage::Fund, "unfunded wallet rests at fund");
        assert!(st.last_error.is_none());
        assert_eq!(st.pusd_balance.as_deref(), Some("0"));
        // Deploy idempotency: code already on-chain → the relayer is never hit.
        assert!(server.seen().is_empty());
        // Resumable: persisted state reloads to the same stage.
        let reloaded = f.onboarder.status("alice", f.owner).unwrap();
        assert_eq!(reloaded.stage, Stage::Fund);
    }

    #[tokio::test]
    async fn deploy_runs_when_no_code_and_recheck_guards() {
        // Relayer confirms, but the chain never shows code → run must error
        // and persist last_error (the post-confirm re-check is the guard).
        let server = ScriptedServer::start(vec![
            Rule::post("/submit", r#"{"transactionID":"tx-d","state":"STATE_NEW"}"#),
            Rule::get("/transaction", r#"{"state":"STATE_CONFIRMED"}"#),
        ])
        .await;
        let f = fixture(&server.url());
        let (events, on_event) = collect_events();

        let err = f
            .onboarder
            .run("alice", &f.signer, &on_event)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no code exists"));

        let st = f.onboarder.status("alice", f.owner).unwrap();
        assert_eq!(st.deploy_tx_id.as_deref(), Some("tx-d"));
        assert!(
            st.in_flight_deadline_ms.is_some(),
            "a stage that died/errored mid-flight must leave the deadline set, so a \
             cross-process reader sees both it and last_error"
        );
        assert!(
            st.last_error.unwrap().contains("no code exists"),
            "run errors must be observable via persisted state"
        );
        let submits = server.seen_paths_containing("/submit");
        assert_eq!(submits.len(), 1);
        let body: serde_json::Value = serde_json::from_str(&submits[0].body).unwrap();
        assert_eq!(body["type"], "WALLET-CREATE");
        let ev = events.lock().unwrap();
        assert!(matches!(
            ev[1],
            OnboardEvent::RelayerSubmitted { kind: "deploy", .. }
        ));
    }

    #[tokio::test]
    async fn funded_run_approves_mints_creds_and_completes() {
        let server = ScriptedServer::start(vec![
            Rule::get("/nonce", "7"),
            Rule::post("/submit", r#"{"transactionID":"tx-a","state":"STATE_NEW"}"#),
            Rule::get(
                "/transaction",
                r#"{"state":"STATE_CONFIRMED","transactionHash":"0xfeed"}"#,
            ),
            Rule::post("/auth/api-key", creds_body()),
            Rule::get("/balance-allowance/update", r#"{"ok":true}"#),
        ])
        .await;
        let f = fixture(&server.url());
        f.chain.set_code(f.deposit, 1);
        f.chain
            .set_balance(PUSD, f.deposit, U256::from(25_000_000u64)); // 25 pUSD
        let (events, on_event) = collect_events();

        // The approval batch confirms but the mock chain doesn't change on its
        // own — pre-arm the post-confirm state so the re-verify passes while
        // the *initial* probe still sees missing approvals... it would also
        // skip the submit. So: arm approvals only for the re-verify by doing a
        // first run that fails re-verify, then arm and resume — exercising
        // both the submit and the resume path.
        let err = f
            .onboarder
            .run("alice", &f.signer, &on_event)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("allowances are still missing"));
        let submits = server.seen_paths_containing("/submit");
        assert_eq!(submits.len(), 1, "approval batch submitted exactly once");
        let body: serde_json::Value = serde_json::from_str(&submits[0].body).unwrap();
        assert_eq!(body["type"], "WALLET");
        assert_eq!(body["nonce"], "7");
        assert_eq!(
            body["depositWalletParams"]["calls"]
                .as_array()
                .unwrap()
                .len(),
            8
        );
        let sig = body["signature"].as_str().unwrap();
        assert!(
            sig.starts_with("0x") && sig.len() == 132,
            "65-byte sig, got {sig}"
        );

        // Approvals now live on-chain → the resumed run skips straight to
        // creds + sync without re-submitting.
        f.chain.approve_all(f.deposit);
        let st = f
            .onboarder
            .run("alice", &f.signer, &on_event)
            .await
            .unwrap();
        assert_eq!(st.stage, Stage::Complete);
        assert!(st.creds_present && st.last_error.is_none());
        assert!(
            st.in_flight_deadline_ms.is_none(),
            "a completed run clears the in-flight deadline"
        );
        assert_eq!(
            server.seen_paths_containing("/submit").len(),
            1,
            "no duplicate approval submit on resume"
        );
        assert_eq!(server.seen_paths_containing("/auth/api-key").len(), 1);
        assert_eq!(
            server
                .seen_paths_containing("/balance-allowance/update")
                .len(),
            1
        );

        // Creds were persisted 0600 and the minted event carries the key only.
        let saved = f.onboarder.creds.load("alice").unwrap().unwrap();
        assert_eq!(saved.key, "11111111-2222-3333-4444-555555555555");
        let minted: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                OnboardEvent::CredsMinted { api_key } => Some(api_key.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(minted, vec![saved.key.clone()]);

        // A third run is a no-op end-to-end except the always-run sync.
        let st = f
            .onboarder
            .run("alice", &f.signer, &on_event)
            .await
            .unwrap();
        assert_eq!(st.stage, Stage::Complete);
        assert_eq!(server.seen_paths_containing("/auth/api-key").len(), 1);
    }

    #[tokio::test]
    async fn existing_creds_are_never_reminted() {
        let server = ScriptedServer::start(vec![Rule::get(
            "/balance-allowance/update",
            r#"{"ok":true}"#,
        )])
        .await;
        let f = fixture(&server.url());
        f.chain.set_code(f.deposit, 1);
        f.chain.set_balance(PUSD, f.deposit, U256::from(1u64));
        f.chain.approve_all(f.deposit);
        f.onboarder
            .creds
            .save(
                "alice",
                &crate::types::Credentials {
                    key: "existing".into(),
                    secret: "cw==".into(),
                    passphrase: "p".into(),
                    nonce: 0,
                },
            )
            .unwrap();
        let (_, on_event) = collect_events();

        let st = f
            .onboarder
            .run("alice", &f.signer, &on_event)
            .await
            .unwrap();
        assert_eq!(st.stage, Stage::Complete);
        assert!(
            server.seen_paths_containing("/auth").is_empty(),
            "no credential mint when creds.json already exists"
        );
        assert_eq!(
            f.onboarder.creds.load("alice").unwrap().unwrap().key,
            "existing"
        );
    }

    #[test]
    fn approval_preview_is_pure_and_byte_exact() {
        let dir = tempfile::tempdir().unwrap();
        let onboarder = Onboarder::new(
            Arc::new(MockChain::default()),
            RelayerClient::new(crate::POLYGON).with_base_url("http://127.0.0.1:1"),
            ClobClient::new(crate::POLYGON),
            CredentialStore::new(dir.path()),
            OnboardStore::new(dir.path()),
            crate::POLYGON,
        );
        let owner = signer().address();
        let v = onboarder.approval_preview(owner);
        let calls = v["calls"].as_array().unwrap();
        assert_eq!(calls.len(), 8);
        let expected = v2_approval_calls();
        for (rendered, call) in calls.iter().zip(&expected) {
            assert_eq!(
                rendered["target"].as_str().unwrap().to_lowercase(),
                format!("{:#x}", call.target)
            );
            assert_eq!(
                rendered["data"].as_str().unwrap(),
                &format!("0x{}", hex::encode(&call.data))
            );
        }
        assert_eq!(v["eip712_domain"]["name"], "DepositWallet");
    }
}
