//! Tx engine: turn a parsed RawIntent into a StagedTx, simulate it,
//! then on confirm sign and broadcast. Also handles same-nonce
//! replacement / cancel txs and a legacy (non-1559) build path.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::Encodable2718;
use alloy::eips::eip2930::AccessList;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use alloy::rpc::types::eth::TransactionRequest;
#[cfg(feature = "unsafe-debug-signer")]
use alloy::signers::SignerSync;
#[cfg(any(test, feature = "unsafe-debug-signer"))]
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bloom_auth_api::petal_identity::{
    FIRST_PARTY_PETAL_VERSION_V0, PETAL_ID_EVM_WALLET, PLACEHOLDER_DIGEST_EVM_WALLET,
};
use bloom_auth_api::{
    ApprovalVerifier, AssuranceLevel, AuthEntryState, AuthStoreWriter, CanonicalEnvelope,
    DaemonGrantTerms, EVM_ERC20_TRANSFER_METHOD, EVM_OWNER_SESSION_USE_ACTION_KIND,
    EVM_SEALED_INTENT_SUBJECT_KIND, EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1, EVM_TX_SIGN_INTENT,
    EvmCallFact, EvmFeeFacts, EvmNonceIntent, EvmOriginalTxFact, EvmOwnerSessionUseFact,
    EvmOwnerSigningSessionScope, EvmOwnerSigningSessionUse, EvmSealedActionKind,
    EvmSealedIntentSubject, EvmTokenFact, EvmUnsignedEnvelopeFacts, EvmValueFact, GrantStore,
    NonceState, PetalHost, PetalPolicySnapshot, SealedAction, SignHashRequest, SignedApproval,
    SigningAttestation, StandingSessionRecord, ValuationPolicy,
};
use bloom_evm::{ChainClient, ChainError, IERC20, NftKind};

// Local NFT-write interfaces. `bloom-evm` declares the read shapes for
// ERC-721/1155; we add the write functions here so calldata encoding stays
// in bloom-tx without expanding the chain crate's read-only surface.
sol! {
    #[allow(missing_docs)]
    interface INftWrite721 {
        function approve(address to, uint256 tokenId) external;
        function setApprovalForAll(address operator, bool approved) external;
        function transferFrom(address from, address to, uint256 tokenId) external;
        function safeTransferFrom(address from, address to, uint256 tokenId) external;
    }

    #[allow(missing_docs)]
    interface INftWrite1155 {
        function safeTransferFrom(
            address from,
            address to,
            uint256 id,
            uint256 amount,
            bytes data
        ) external;
    }
}
use bloom_proto::plan::ExecutionOrigin;
use bloom_proto::{
    AddressBook, ChainSpec, HomeWritePermit, NftAction, NftRef, Policy, RawIntent, RawIntentBody,
    StagedTx, TokenRef, TxActionKind, TxStatus, format_units, parse_amount, parse_eth, parse_units,
};
use parking_lot::RwLock;
use thiserror::Error;
use tracing::{debug, info};

use crate::bump_scanner::MempoolIndexes;
use crate::intent_parser::ParseError;
use crate::outbox::{
    BroadcastAttempt, BroadcastAttemptKind, BroadcastTransport, Outbox, OutboxError, OutboxState,
    SameNonceAttemptQuery,
};
use crate::policy_engine;

/// Pluggable name resolver. Implemented by an ENS adapter outside the
/// engine to keep bloom-tx free of bloom-ens dependency.
#[async_trait::async_trait]
pub trait RecipientResolver: Send + Sync {
    async fn resolve_name(&self, name: &str) -> Result<Address, String>;
}

/// A recoverable request for the caller to complete a Sealed Approval ceremony.
///
/// This is deliberately structured: callers must route on this type, never on
/// the human-readable error text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequirement {
    pub action_id: String,
    pub ceremony_url: String,
    pub expires_ms: u64,
    pub reason: String,
}

impl std::fmt::Display for ApprovalRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "for action '{}': {}", self.action_id, self.reason)
    }
}

#[derive(Debug, Error)]
pub enum TxEngineError {
    #[error("parse: {0}")]
    Parse(#[from] ParseError),
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    #[error("rpc: {0}")]
    Rpc(#[from] bloom_rpc::BloomRpcError),
    #[error("outbox: {0}")]
    Outbox(#[from] OutboxError),
    #[error("address: {0}")]
    Address(String),
    #[error("amount: {0}")]
    Amount(String),
    #[error("invalid EIP-1559 fee override: {0}")]
    InvalidFeeOverride(String),
    #[error("policy denied")]
    PolicyDenied,
    #[error("broadcast disabled for chain '{0}' (set allow_broadcast=true)")]
    BroadcastDisabled(String),
    #[error("broadcast approval required {0}")]
    ApprovalRequired(ApprovalRequirement),
    #[error("approval service unavailable: {0}")]
    ApprovalServiceUnavailable(String),
    #[error("approval state error: {0}")]
    ApprovalState(String),
    #[error("approval construction error: {0}")]
    ApprovalConstruction(String),
    #[error("approval backend error: {0}")]
    ApprovalBackend(String),
    #[error("approval denied: {0}")]
    ApprovalDenied(String),
    #[error("valuation unavailable: {0}")]
    ValuationUnavailable(String),
    #[error("not yet implemented: {0}")]
    Unimplemented(String),
    #[error("signer: {0}")]
    Signer(String),
    #[error("token: {0}")]
    Token(String),
    #[error("private RPC provider {0} not configured")]
    PrivateProviderNotConfigured(String),
    #[error("private RPC not supported on chain {0}")]
    PrivateNotSupportedOnChain(String),
    #[error("private RPC broadcast failed: {0}")]
    PrivateBroadcast(String),
    #[error("private RPC provider {provider} does not support chain {chain_id}")]
    PrivateProviderChainMismatch { provider: String, chain_id: u64 },
    #[error("broadcast returned hash {returned}, expected signed tx hash {expected}")]
    BroadcastHashMismatch { expected: String, returned: String },
    #[error("broadcast attempt for tx '{id}' is ambiguous: {reason}")]
    BroadcastAttemptAmbiguous { id: String, reason: String },
    #[error("home write permit does not match tx outbox home (permit={permit}, outbox={outbox})")]
    HomeWritePermitMismatch { permit: String, outbox: String },
    #[error("home write permit check failed: {0}")]
    HomeWritePermit(String),
    #[error("tx '{id}' is in status {status}, expected pending or unmined sent")]
    InvalidTxStatus { id: String, status: String },
    #[error(
        "Enso quote is {age}s old (expires ~5 min) — re-run the intent for a fresh route, or write 'override' to broadcast anyway"
    )]
    EnsoQuoteStale { age: u64 },
    #[error("dependency '{dep_id}' not satisfied: {reason}")]
    DependencyNotSatisfied { dep_id: String, reason: String },
    #[error("pre-broadcast simulation reverted: {reason} — write 'override' to broadcast anyway")]
    SimulationReverted { reason: String },
    #[error(
        "nonce gap: tx for {from} uses nonce {staged} but the account's next on-chain nonce is {chain_next} — the node would queue it behind the missing nonce(s) and it could never mine. Broadcast nonce {chain_next} first, or restage with an explicit `nonce` to fill the gap deliberately."
    )]
    NonceGap {
        from: String,
        staged: u64,
        chain_next: u64,
    },
}

/// In-memory cache for ERC-20 metadata keyed by `(chain_id, address)`.
type TokenCache = Arc<RwLock<HashMap<(u64, Address), TokenMeta>>>;

/// Per-(chain_id, provider_id) map of configured private RPC providers
/// used by `broadcast` when `policy.private.enabled == true`.
type PrivateRpcs = Arc<RwLock<BTreeMap<(u64, String), Arc<dyn bloom_mempool::PrivateRpcProvider>>>>;

struct SignedRawTx {
    raw: Bytes,
    hash: B256,
}

enum UnsignedEvmTx {
    Legacy(TxLegacy),
    Eip1559(TxEip1559),
}

/// A complete, validated EIP-1559 fee override pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eip1559FeeOverrides {
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
}

impl Eip1559FeeOverrides {
    pub fn from_decimal_pair(
        max_fee_per_gas: Option<&str>,
        max_priority_fee_per_gas: Option<&str>,
        legacy_chain: bool,
    ) -> Result<Option<Self>, TxEngineError> {
        let (Some(max_fee), Some(priority_fee)) = (max_fee_per_gas, max_priority_fee_per_gas)
        else {
            if max_fee_per_gas.is_some() || max_priority_fee_per_gas.is_some() {
                return Err(TxEngineError::InvalidFeeOverride(
                    "max fee and max priority fee must be supplied together".into(),
                ));
            }
            return Ok(None);
        };
        if legacy_chain {
            return Err(TxEngineError::InvalidFeeOverride(
                "EIP-1559 overrides are not valid for a legacy transaction chain".into(),
            ));
        }
        let parse = |field: &str, value: &str| {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(TxEngineError::InvalidFeeOverride(format!(
                    "{field} must be an unsigned decimal integer"
                )));
            }
            value
                .parse::<u128>()
                .map_err(|_| TxEngineError::InvalidFeeOverride(format!("{field} exceeds u128")))
        };
        let max_fee_per_gas = parse("max-fee-per-gas", max_fee)?;
        let max_priority_fee_per_gas = parse("max-priority-fee-per-gas", priority_fee)?;
        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(TxEngineError::InvalidFeeOverride(
                "max priority fee exceeds max fee".into(),
            ));
        }
        Ok(Some(Self {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }))
    }
}

struct PreparedEvmTx {
    unsigned: UnsignedEvmTx,
    signing_hash: B256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvmOutboxActionKind {
    Confirm,
    Replace,
    Cancel,
}

impl EvmOutboxActionKind {
    fn action_kind(self) -> &'static str {
        match self {
            Self::Confirm => "evm_confirm",
            Self::Replace => "evm_replace",
            Self::Cancel => "evm_cancel",
        }
    }

    fn sealed_action_kind(self) -> EvmSealedActionKind {
        match self {
            Self::Confirm => EvmSealedActionKind::Confirm,
            Self::Replace => EvmSealedActionKind::Replace,
            Self::Cancel => EvmSealedActionKind::Cancel,
        }
    }

    fn broadcast_kind(self) -> BroadcastAttemptKind {
        match self {
            Self::Confirm => BroadcastAttemptKind::Confirm,
            Self::Replace => BroadcastAttemptKind::Replacement,
            Self::Cancel => BroadcastAttemptKind::CancelReplacement,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvmOwnerSessionExecution {
    pub tx_hash: B256,
    pub nonce: u64,
    pub signing_hash: B256,
}

#[derive(Debug, Clone)]
pub struct SealedActionExecution {
    pub action_id: String,
    pub petal_id: String,
    pub petal_digest: String,
    pub action_kind: String,
    pub tx_hash: B256,
    pub nonce: u64,
    pub signing_hash: B256,
}

struct EvmCentralResult<'a> {
    action_id: &'a str,
    state: OutboxState,
    outcome: &'a str,
    tx_hash: B256,
    nonce: u64,
    signing_hash: &'a B256,
    action_kind: &'a str,
}

struct EvmCentralFailure<'a> {
    action_id: &'a str,
    state: OutboxState,
    outcome: &'a str,
    reason: &'a str,
}

struct SubmitResult {
    transport: BroadcastTransport,
    returned_hash: Option<B256>,
}

/// Stub `QuoteOracle` for stage-time MEV heuristics. It holds a
/// `ChainClient` reference so a real implementation can `eth_call` a
/// quoter contract, but the current version always returns `None`
/// (the heuristic then degrades to the `amount_out_min == 0` check
/// only). Phase 4+ will wire this to a real quoter.
struct EthCallQuoteOracle<'a> {
    _chain: &'a ChainClient,
}

impl bloom_mempool::QuoteOracle for EthCallQuoteOracle<'_> {
    fn quote(&self, _amount_in: U256, _path: &[Address]) -> Option<U256> {
        None
    }
}

/// Build the `HeuristicConfig` from the active policy. Kept as a free
/// function so unit tests can exercise it without constructing a
/// `TxEngine`.
pub(crate) fn mev_cfg_from_policy(policy: &Policy) -> bloom_mempool::HeuristicConfig {
    bloom_mempool::HeuristicConfig {
        max_slippage_bps: policy.mev.max_slippage_bps,
        // Match `HeuristicConfig::default()` — 1e18 (one whole token /
        // ETH worth of input). The threshold only fires together with
        // `amountOutMin == 0`, so it's a sanity gate, not a primary
        // signal.
        zero_min_amount_in_threshold: U256::from(10u64).pow(U256::from(18u64)),
    }
}

/// Run the stage-time MEV/sandwich heuristic. The `ChainClient` is
/// held only by the (currently stub) quoter so the function stays
/// synchronous and safe to call without a live RPC.
pub(crate) fn evaluate_mev_risk(
    chain: &ChainClient,
    data_bytes: &[u8],
    value_wei: U256,
    policy: &Policy,
) -> bloom_mempool::MevRiskReport {
    let cfg = mev_cfg_from_policy(policy);
    let quoter = EthCallQuoteOracle { _chain: chain };
    bloom_mempool::heuristic::evaluate(
        &alloy::primitives::Bytes::copy_from_slice(data_bytes),
        value_wei,
        &cfg,
        &quoter,
    )
}

#[derive(Debug, Clone)]
struct TokenMeta {
    address: Address,
    symbol: String,
    decimals: u8,
}

/// Oracle input facts supplied by a trusted route handler, bound to the exact
/// executable transaction that the engine resolves and stages.
#[derive(Debug, Clone)]
pub struct BoundValuationTarget {
    pub asset_id: String,
    pub amount_base_units: String,
    pub asset_decimals: u8,
    pub expected_to: Address,
    pub expected_value_wei: U256,
    pub expected_calldata: Bytes,
}

#[derive(Debug, Clone)]
struct ValuationTarget {
    asset_id: String,
    amount_base_units: String,
    asset_decimals: u8,
}

fn classify_action_kind(
    body: &RawIntentBody,
    has_token: bool,
    destination_is_contract: bool,
) -> TxActionKind {
    match body {
        RawIntentBody::Send { .. } if has_token => TxActionKind::Erc20Transfer,
        RawIntentBody::Send { data, .. }
            if !destination_is_contract
                && data
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty() || value.trim() == "0x") =>
        {
            TxActionKind::NativeTransfer
        }
        RawIntentBody::Send { .. } => TxActionKind::ContractCall,
        RawIntentBody::Approve { .. }
        | RawIntentBody::NftApprove { .. }
        | RawIntentBody::NftApproveAll { .. } => TxActionKind::Approval,
        RawIntentBody::NftTransfer { .. } => TxActionKind::NftTransfer,
        RawIntentBody::Call { .. } | RawIntentBody::Raw { .. } | RawIntentBody::Enso { .. } => {
            TxActionKind::ContractCall
        }
    }
}

/// Per-(wallet, chain, from) stage-serialisation lock map.
/// Outer lock: `parking_lot` (held microseconds for HashMap lookup/insert).
/// Inner lock: `tokio` async mutex (held for the stage critical section).
type NonceLocks =
    Arc<parking_lot::Mutex<HashMap<(String, String, Address), Arc<tokio::sync::Mutex<()>>>>>;

const OUTBOX_APPROVAL_FILE: &str = "approval.json";
const OUTBOX_APPROVAL_CHALLENGE_FILE: &str = "approval_challenge.json";
const OUTBOX_APPROVAL_TTL_MS: u64 = 5 * 60 * 1000;

/// Stage / confirm the lifecycle.
#[derive(Clone)]
pub struct TxEngine {
    pub outbox: Outbox,
    /// Default stage TTL in ms.
    pub stage_ttl_ms: u128,
    token_cache: TokenCache,
    resolver: Option<Arc<dyn RecipientResolver>>,
    price_oracle: Option<crate::oracle::DynPriceOracle>,
    /// Per-chain pending-tx indexes for the nonce-conflict check at
    /// stage time. Populated externally (by the daemon, after the
    /// mempool subsystem starts) via [`Self::set_mempool_index`].
    mempool_indexes: MempoolIndexes,
    /// Per-(chain_id, provider_id) map of configured private RPC
    /// providers. Populated externally via
    /// [`Self::register_private_rpc`]; used by `broadcast` to route
    /// signed raw txs privately when `policy.private.enabled` is set
    /// (mainnet only — see `MAINNET_CHAIN_ID`).
    private_rpcs: PrivateRpcs,
    /// Per-(wallet, chain, from) async mutex that serialises the
    /// read-chain-nonce → check-pending → write-pending critical section
    /// in `stage()`. The outer `parking_lot::Mutex` is held for
    /// microseconds only (HashMap lookup/insert); the inner
    /// `tokio::sync::Mutex` is the actual per-sender stage lock.
    nonce_locks: NonceLocks,
    /// Bounded policy sessions: one ceremony authorizes many in-bounds
    /// confirms without a fresh per-tx review. See [`crate::session`].
    session_store: crate::session::SessionStore,
    approval_verifier: Option<Arc<dyn ApprovalVerifier>>,
    auth_writer: Option<Arc<dyn AuthStoreWriter>>,
    grant_store: Option<Arc<dyn GrantStore>>,
    petal_host: Option<Arc<dyn PetalHost>>,
    #[cfg(feature = "unsafe-debug-signer")]
    unsafe_debug_signer: Option<(String, Arc<PrivateKeySigner>)>,
}

impl TxEngine {
    pub fn new(outbox: Outbox, stage_ttl_ms: u128) -> Self {
        Self {
            outbox,
            stage_ttl_ms,
            token_cache: Arc::new(RwLock::new(HashMap::new())),
            resolver: None,
            price_oracle: None,
            mempool_indexes: Arc::new(RwLock::new(BTreeMap::new())),
            private_rpcs: Arc::new(RwLock::new(BTreeMap::new())),
            nonce_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            session_store: crate::session::SessionStore::new(),
            approval_verifier: None,
            auth_writer: None,
            grant_store: None,
            petal_host: None,
            #[cfg(feature = "unsafe-debug-signer")]
            unsafe_debug_signer: None,
        }
    }

    pub fn with_auth_services(
        mut self,
        approval_verifier: Arc<dyn ApprovalVerifier>,
        auth_writer: Arc<dyn AuthStoreWriter>,
    ) -> Self {
        self.approval_verifier = Some(approval_verifier);
        self.auth_writer = Some(auth_writer);
        self
    }

    pub fn with_host_signing_services(
        mut self,
        grant_store: Arc<dyn GrantStore>,
        petal_host: Arc<dyn PetalHost>,
    ) -> Self {
        self.grant_store = Some(grant_store);
        self.petal_host = Some(petal_host);
        self
    }

    /// Install an explicit local-only debug signer for one wallet. Policy
    /// evaluation and transaction simulation still run; only the interactive
    /// Sealed Approval ceremony is bypassed. Never enable this in production.
    #[cfg(feature = "unsafe-debug-signer")]
    pub fn with_unsafe_debug_signer(
        mut self,
        wallet: impl Into<String>,
        signer: Arc<PrivateKeySigner>,
    ) -> Self {
        self.unsafe_debug_signer = Some((wallet.into(), signer));
        self
    }

    #[cfg(feature = "unsafe-debug-signer")]
    fn unsafe_debug_signer(&self, wallet: &str) -> Option<&Arc<PrivateKeySigner>> {
        self.unsafe_debug_signer
            .as_ref()
            .filter(|(configured, _)| configured == wallet)
            .map(|(_, signer)| signer)
    }

    /// Access the bounded policy-session store (mint/revoke/list live here).
    pub fn session_store(&self) -> &crate::session::SessionStore {
        &self.session_store
    }

    /// Return (or create) the per-(wallet, chain, from) `tokio::sync::Mutex`
    /// used to serialise nonce assignment in `stage()`. The outer
    /// `parking_lot::Mutex` is held only for the HashMap lookup/insert
    /// (~microseconds); callers then `.lock().await` the returned
    /// `Arc<tokio::sync::Mutex<()>>` to cover the critical section.
    fn nonce_lock_for(
        &self,
        wallet: &str,
        chain: &str,
        from: Address,
    ) -> Arc<tokio::sync::Mutex<()>> {
        let key = (wallet.to_string(), chain.to_string(), from);
        self.nonce_locks
            .lock()
            .entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn assert_write_permit(&self, permit: &HomeWritePermit) -> Result<(), TxEngineError> {
        let outbox_home = self
            .outbox
            .root()
            .parent()
            .unwrap_or_else(|| self.outbox.root())
            .canonicalize()
            .map_err(|e| TxEngineError::HomeWritePermit(e.to_string()))?;
        if permit.home() != outbox_home {
            return Err(TxEngineError::HomeWritePermitMismatch {
                permit: permit.home().display().to_string(),
                outbox: outbox_home.display().to_string(),
            });
        }
        Ok(())
    }

    /// Register the `PendingTxIndex` for `chain`. Calling stage on this
    /// chain will then surface a `nonce_conflict.json` artefact if the
    /// staged `(from, nonce)` collides with an externally-observed
    /// pending tx.
    pub fn set_mempool_index(
        &self,
        chain: impl Into<String>,
        idx: Arc<bloom_mempool::PendingTxIndex>,
    ) {
        self.mempool_indexes.write().insert(chain.into(), idx);
    }

    /// Register a `PrivateRpcProvider` for `chain_id`. The provider's
    /// `id()` becomes the lookup key alongside `chain_id`, matching the
    /// `policy.private.provider` string written by the user.
    ///
    /// Returns `Err(PrivateProviderChainMismatch)` if `chain_id` is not
    /// listed in `provider.supported_chains()`, catching misconfiguration
    /// before any tx is submitted.
    pub fn register_private_rpc(
        &self,
        chain_id: u64,
        provider: Arc<dyn bloom_mempool::PrivateRpcProvider>,
    ) -> Result<(), TxEngineError> {
        if !provider.supported_chains().contains(&chain_id) {
            return Err(TxEngineError::PrivateProviderChainMismatch {
                provider: provider.id().to_string(),
                chain_id,
            });
        }
        self.private_rpcs
            .write()
            .insert((chain_id, provider.id().to_string()), provider);
        Ok(())
    }

    /// Submit a signed raw tx via the configured private RPC provider
    /// keyed by `(chain_id, provider_id)`. Returns the hash returned by
    /// the provider on success, or a typed error if the provider is not
    /// configured or the submission fails. Kept `pub(crate)` so unit
    /// tests can exercise it without going through the full broadcast
    /// path (which requires a live chain).
    pub(crate) async fn submit_via_private(
        &self,
        chain_id: u64,
        provider_id: &str,
        raw: &alloy::primitives::Bytes,
    ) -> Result<alloy::primitives::B256, TxEngineError> {
        // Take the lock, clone the Arc out, drop the guard before .await — no
        // lock is held across the network call.
        let provider = self
            .private_rpcs
            .read()
            .get(&(chain_id, provider_id.to_string()))
            .cloned()
            .ok_or_else(|| TxEngineError::PrivateProviderNotConfigured(provider_id.to_string()))?;
        provider
            .submit(raw)
            .await
            .map_err(|e| TxEngineError::PrivateBroadcast(e.to_string()))
    }

    /// Build the nonce-conflict JSON body if `(from, nonce)` collides
    /// with an externally observed pending tx on this chain. Returns
    /// `None` when no index is registered for the chain, or when no
    /// collision is found.
    pub(crate) fn build_nonce_conflict_body(
        &self,
        chain_name: &str,
        from: Address,
        nonce: u64,
    ) -> Option<serde_json::Value> {
        let rec = self
            .mempool_indexes
            .read()
            .get(chain_name)?
            .lookup_by_addr_nonce(from, nonce)?;
        let observed_at = rec
            .tx
            .observed_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let hex_hash = hex::encode(rec.tx.hash.as_slice());
        let hash_str = format!("0x{hex_hash}");
        Some(serde_json::json!({
            "conflict_nonce": nonce,
            "external_hash": &hash_str,
            "external_observed_at": observed_at,
            "advice": format!(
                "external tx {hash_str} is pending at this nonce; use a different nonce or wait for it to mine/drop"
            ),
        }))
    }

    /// Wire a name resolver (typically an ENS adapter) for recipients.
    pub fn with_resolver(mut self, resolver: Arc<dyn RecipientResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Wire a price oracle so policy USD caps are evaluated with real
    /// values instead of the no-data Warn fallback.
    pub fn with_price_oracle(mut self, oracle: crate::oracle::DynPriceOracle) -> Self {
        self.price_oracle = Some(oracle);
        self
    }

    /// Resolve recipient from an intent (`0xabc`, alias, or ENS name).
    async fn resolve_recipient_async(
        &self,
        to: &str,
        book: Option<&AddressBook>,
    ) -> Result<Address, TxEngineError> {
        if to.starts_with("0x") {
            return to
                .parse::<Address>()
                .map_err(|e| TxEngineError::Address(e.to_string()));
        }
        if let Some(b) = book
            && let Some(addr) = b.resolve(to)
        {
            return Ok(addr);
        }
        if to.ends_with(".eth") {
            if let Some(r) = &self.resolver {
                return r
                    .resolve_name(to)
                    .await
                    .map_err(|e| TxEngineError::Address(format!("ens '{to}': {e}")));
            }
            return Err(TxEngineError::Unimplemented(format!(
                "ENS resolution for '{}' (no resolver wired)",
                to
            )));
        }
        Err(TxEngineError::Address(format!(
            "unresolved recipient '{}'",
            to
        )))
    }

    /// Resolve a value+token string into wei (when token is the native
    /// asset). Returns `Ok(None)` when the token is non-native and the
    /// caller should route through the ERC-20 path.
    fn resolve_native_value(
        value: &str,
        token: &Option<String>,
    ) -> Result<Option<U256>, TxEngineError> {
        match token.as_deref() {
            Some(t) => match t.to_ascii_lowercase().as_str() {
                "eth" | "ether" | "wei" | "gwei" => Ok(Some(
                    parse_eth(value).map_err(|e| TxEngineError::Amount(e.to_string()))?,
                )),
                _ => Ok(None),
            },
            None => {
                if value.is_empty() {
                    Ok(Some(U256::ZERO))
                } else {
                    Ok(Some(
                        parse_eth(value).map_err(|e| TxEngineError::Amount(e.to_string()))?,
                    ))
                }
            }
        }
    }

    /// Resolve an ERC-20 token symbol or 0x address into a concrete
    /// contract address on the given chain.
    fn resolve_token_address(
        token: &str,
        chain_id: u64,
    ) -> Result<(Address, String), TxEngineError> {
        let t = token.trim();
        if t.starts_with("0x") || t.starts_with("0X") {
            let addr: Address = t
                .parse()
                .map_err(|e: alloy::hex::FromHexError| TxEngineError::Token(e.to_string()))?;
            return Ok((addr, t.to_string()));
        }
        let upper = t.to_ascii_uppercase();
        if let Some(addr_str) = lookup_known_token(chain_id, &upper) {
            let addr: Address = addr_str.parse().map_err(|_| {
                TxEngineError::Token(format!("invalid hardcoded token addr for {upper}"))
            })?;
            return Ok((addr, upper));
        }
        Err(TxEngineError::Token(format!(
            "unknown token '{token}' on chain id {chain_id}"
        )))
    }

    /// Read the ERC-20 metadata for `addr`, caching the result.
    async fn token_meta(
        &self,
        chain: &ChainClient,
        addr: Address,
        symbol_hint: &str,
    ) -> Result<TokenMeta, TxEngineError> {
        let chain_id = chain.chain_id().await?;
        let key = (chain_id, addr);
        if let Some(m) = self.token_cache.read().get(&key).cloned() {
            return Ok(m);
        }
        let decimals = chain.erc20_decimals(addr).await?.ok_or_else(|| {
            TxEngineError::Token(format!(
                "could not read decimals() from {} (not an ERC-20?)",
                bloom_proto::checksum_address(&addr)
            ))
        })?;
        let symbol = if symbol_hint.starts_with("0x") || symbol_hint.starts_with("0X") {
            short_addr_label(&addr)
        } else {
            symbol_hint.to_ascii_uppercase()
        };
        let meta = TokenMeta {
            address: addr,
            symbol,
            decimals,
        };
        self.token_cache.write().insert(key, meta.clone());
        Ok(meta)
    }

    /// Resolve a parsed intent body into the on-wire fields a staged tx
    /// needs: destination, value, calldata, and optional ERC-20 metadata
    /// for plan rendering. Shared by [`Self::stage`] and
    /// [`Self::replace_with_intent`] so the calldata-substitution path is
    /// guaranteed to encode identically to the original stage.
    async fn resolve_intent_body(
        &self,
        body: &RawIntentBody,
        chain: &ChainClient,
        chain_id: u64,
        address_book: Option<&AddressBook>,
        from: Address,
    ) -> Result<(Address, U256, String, Option<TokenRef>, Option<NftRef>), TxEngineError> {
        match body {
            RawIntentBody::Send {
                to,
                value,
                token,
                amount,
                data,
            } => {
                let to_addr = self.resolve_recipient_async(to, address_book).await?;
                if let Some(v) = Self::resolve_native_value(value, token)? {
                    if !amount.trim().is_empty() {
                        return Err(TxEngineError::Amount(
                            "native sends must use value; amount is only for token sends".into(),
                        ));
                    }
                    let data = data.clone().unwrap_or_else(|| "0x".into());
                    Ok((to_addr, v, data, None, None))
                } else {
                    if amount.trim().is_empty() {
                        return Err(TxEngineError::Amount(
                            "token sends require amount; value is only for native sends".into(),
                        ));
                    }
                    if !value.trim().is_empty() && value.trim() != "0" {
                        return Err(TxEngineError::Amount(
                            "token sends must use amount; value is reserved for native sends"
                                .into(),
                        ));
                    }
                    let token_str = token.as_deref().unwrap_or("");
                    let (token_addr, sym_hint) = Self::resolve_token_address(token_str, chain_id)?;
                    let meta = self.token_meta(chain, token_addr, &sym_hint).await?;
                    let parsed =
                        parse_amount(amount).map_err(|e| TxEngineError::Amount(e.to_string()))?;
                    // A native metric unit (wei/gwei/eth) on an ERC-20 amount is
                    // ambiguous — it would be silently rescaled by token
                    // decimals. Reject it and point at the unambiguous forms.
                    // A bare integer (explicit_unit == false) is still accepted
                    // as a human token amount.
                    if parsed.explicit_unit && parsed.is_native() {
                        return Err(TxEngineError::Amount(format!(
                            "'{amount}' uses a native unit ('{}') for an ERC-20 token; write a human \
                             amount like '10 {}' or raw base units like '10000000 base'",
                            parsed.unit, meta.symbol
                        )));
                    }
                    // `base` means the number is already in token base units —
                    // do not rescale by decimals.
                    let scale = if parsed.unit == "base" {
                        0
                    } else {
                        meta.decimals
                    };
                    let amount = parse_units(&parsed.number, scale)
                        .map_err(|e| TxEngineError::Amount(e.to_string()))?;
                    let call = IERC20::transferCall {
                        to: to_addr,
                        amount,
                    };
                    let calldata = format!("0x{}", hex::encode(call.abi_encode()));
                    let token_ref = TokenRef {
                        address: bloom_proto::checksum_address(&meta.address),
                        symbol: meta.symbol.clone(),
                        decimals: meta.decimals,
                        recipient: bloom_proto::checksum_address(&to_addr),
                        amount: parsed.number.clone(),
                        amount_base_units: Some(amount.to_string()),
                    };
                    Ok((token_addr, U256::ZERO, calldata, Some(token_ref), None))
                }
            }
            RawIntentBody::Raw { to, value, data } => {
                let to_addr = self.resolve_recipient_async(to, address_book).await?;
                let v = if value.is_empty() {
                    U256::ZERO
                } else {
                    parse_eth(value).map_err(|e| TxEngineError::Amount(e.to_string()))?
                };
                Ok((to_addr, v, data.clone(), None, None))
            }
            RawIntentBody::Call {
                contract,
                method,
                args,
                value,
            } => {
                let contract_addr = self.resolve_recipient_async(contract, address_book).await?;
                let v = if value.is_empty() {
                    U256::ZERO
                } else {
                    parse_eth(value).map_err(|e| TxEngineError::Amount(e.to_string()))?
                };
                let data = bloom_tools::encode_call(method, &serde_json::json!(args))
                    .map_err(|e| TxEngineError::Amount(format!("encode_call: {e}")))?;
                Ok((contract_addr, v, data, None, None))
            }
            RawIntentBody::Approve {
                token,
                spender,
                amount,
            } => {
                let token_addr = self.resolve_recipient_async(token, address_book).await?;
                let spender_addr = self.resolve_recipient_async(spender, address_book).await?;
                let amount_u = parse_approve_amount(amount)
                    .map_err(|e| TxEngineError::Amount(format!("approve amount: {e}")))?;
                let call = IERC20::approveCall {
                    spender: spender_addr,
                    amount: amount_u,
                };
                let calldata = format!("0x{}", hex::encode(call.abi_encode()));
                Ok((token_addr, U256::ZERO, calldata, None, None))
            }
            RawIntentBody::NftTransfer {
                contract,
                to,
                token_id,
                standard,
                amount,
                safe,
                data,
            } => {
                let contract_addr = self.resolve_recipient_async(contract, address_book).await?;
                let to_addr = self.resolve_recipient_async(to, address_book).await?;
                let token_id_u = parse_u256(token_id)
                    .map_err(|e| TxEngineError::Amount(format!("token_id: {e}")))?;
                let kind = self
                    .resolve_nft_kind(chain, contract_addr, standard.as_deref())
                    .await?;
                let calldata = match kind {
                    NftKind::Erc721 => {
                        if *safe {
                            let call = INftWrite721::safeTransferFromCall {
                                from,
                                to: to_addr,
                                tokenId: token_id_u,
                            };
                            format!("0x{}", hex::encode(call.abi_encode()))
                        } else {
                            let call = INftWrite721::transferFromCall {
                                from,
                                to: to_addr,
                                tokenId: token_id_u,
                            };
                            format!("0x{}", hex::encode(call.abi_encode()))
                        }
                    }
                    NftKind::Erc1155 => {
                        let amount_u = match amount.as_deref() {
                            Some(s) if !s.is_empty() => parse_u256(s)
                                .map_err(|e| TxEngineError::Amount(format!("amount: {e}")))?,
                            _ => U256::from(1u64),
                        };
                        let data_bytes = match data.as_deref() {
                            Some(s) if !s.is_empty() && s != "0x" => decode_data(s)?,
                            _ => Bytes::new(),
                        };
                        let call = INftWrite1155::safeTransferFromCall {
                            from,
                            to: to_addr,
                            id: token_id_u,
                            amount: amount_u,
                            data: data_bytes,
                        };
                        format!("0x{}", hex::encode(call.abi_encode()))
                    }
                    NftKind::Unknown => {
                        return Err(TxEngineError::Token(format!(
                            "{} is not an NFT contract (no ERC-721/1155 support)",
                            bloom_proto::checksum_address(&contract_addr)
                        )));
                    }
                };
                let nft_ref = NftRef {
                    action: NftAction::Transfer,
                    contract: bloom_proto::checksum_address(&contract_addr),
                    kind: nft_kind_label(kind),
                    symbol: best_effort_nft_symbol(chain, contract_addr).await,
                    token_id: token_id_u.to_string(),
                    counterparty: bloom_proto::checksum_address(&to_addr),
                    amount: match (kind, amount.as_deref()) {
                        (NftKind::Erc1155, Some(s)) if !s.is_empty() => s.to_string(),
                        (NftKind::Erc1155, _) => "1".to_string(),
                        _ => String::new(),
                    },
                    approved: None,
                };
                Ok((contract_addr, U256::ZERO, calldata, None, Some(nft_ref)))
            }
            RawIntentBody::NftApprove {
                contract,
                operator,
                token_id,
            } => {
                let contract_addr = self.resolve_recipient_async(contract, address_book).await?;
                let operator_addr = self.resolve_recipient_async(operator, address_book).await?;
                let token_id_u = parse_u256(token_id)
                    .map_err(|e| TxEngineError::Amount(format!("token_id: {e}")))?;
                // Per-token approve only exists on ERC-721. Detect first
                // so we don't ship calldata that targets the wrong ABI.
                let kind = self.resolve_nft_kind(chain, contract_addr, None).await?;
                match kind {
                    NftKind::Erc721 => {}
                    NftKind::Erc1155 => {
                        return Err(TxEngineError::Token(
                            "ERC-1155 has no per-token approval; use nft_approve_all".into(),
                        ));
                    }
                    NftKind::Unknown => {
                        return Err(TxEngineError::Token(format!(
                            "{} is not an NFT contract (no ERC-721/1155 support)",
                            bloom_proto::checksum_address(&contract_addr)
                        )));
                    }
                }
                let call = INftWrite721::approveCall {
                    to: operator_addr,
                    tokenId: token_id_u,
                };
                let calldata = format!("0x{}", hex::encode(call.abi_encode()));
                let nft_ref = NftRef {
                    action: NftAction::Approve,
                    contract: bloom_proto::checksum_address(&contract_addr),
                    kind: nft_kind_label(NftKind::Erc721),
                    symbol: best_effort_nft_symbol(chain, contract_addr).await,
                    token_id: token_id_u.to_string(),
                    counterparty: bloom_proto::checksum_address(&operator_addr),
                    amount: String::new(),
                    approved: None,
                };
                Ok((contract_addr, U256::ZERO, calldata, None, Some(nft_ref)))
            }
            RawIntentBody::NftApproveAll {
                contract,
                operator,
                approved,
            } => {
                let contract_addr = self.resolve_recipient_async(contract, address_book).await?;
                let operator_addr = self.resolve_recipient_async(operator, address_book).await?;
                let kind = self.resolve_nft_kind(chain, contract_addr, None).await?;
                if matches!(kind, NftKind::Unknown) {
                    return Err(TxEngineError::Token(format!(
                        "{} is not an NFT contract (no ERC-721/1155 support)",
                        bloom_proto::checksum_address(&contract_addr)
                    )));
                }
                let call = INftWrite721::setApprovalForAllCall {
                    operator: operator_addr,
                    approved: *approved,
                };
                let calldata = format!("0x{}", hex::encode(call.abi_encode()));
                let nft_ref = NftRef {
                    action: NftAction::SetApprovalForAll,
                    contract: bloom_proto::checksum_address(&contract_addr),
                    kind: nft_kind_label(kind),
                    symbol: best_effort_nft_symbol(chain, contract_addr).await,
                    token_id: String::new(),
                    counterparty: bloom_proto::checksum_address(&operator_addr),
                    amount: String::new(),
                    approved: Some(*approved),
                };
                Ok((contract_addr, U256::ZERO, calldata, None, Some(nft_ref)))
            }
            RawIntentBody::Enso { .. } => Err(TxEngineError::Unimplemented(
                "Enso intents flow through the enso petal (not in tx stage path)".into(),
            )),
        }
    }

    /// Resolve the NFT standard for `contract`. Honours an explicit
    /// `standard` hint (`"erc721"` / `"erc1155"`) without a network call.
    /// Auto-detects via ERC-165 otherwise.
    async fn resolve_nft_kind(
        &self,
        chain: &ChainClient,
        contract: Address,
        hint: Option<&str>,
    ) -> Result<NftKind, TxEngineError> {
        match hint.map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("erc721") => Ok(NftKind::Erc721),
            Some("erc1155") => Ok(NftKind::Erc1155),
            Some(other) => Err(TxEngineError::Token(format!(
                "unknown NFT standard '{other}'; use erc721 or erc1155"
            ))),
            None => Ok(chain.nft_detect(contract).await?),
        }
    }

    /// Stage a tx for a wallet on a chain. The caller is responsible for
    /// looking up the wallet's address.
    #[allow(clippy::too_many_arguments)]
    pub async fn stage(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        from: Address,
        intent: RawIntent,
        chain: &ChainClient,
        policy: &Policy,
        address_book: Option<&AddressBook>,
    ) -> Result<StagedTx, TxEngineError> {
        self.stage_with_execution_origin(
            permit,
            wallet,
            from,
            intent,
            chain,
            policy,
            address_book,
            None,
        )
        .await
    }

    /// Stage an EVM transaction with trusted Petal provenance supplied by the
    /// caller that owns the execution surface. Native wallet staging passes no
    /// origin and therefore retains the default `evm-wallet` identity.
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_with_execution_origin(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        from: Address,
        intent: RawIntent,
        chain: &ChainClient,
        policy: &Policy,
        address_book: Option<&AddressBook>,
        execution_origin: Option<ExecutionOrigin>,
    ) -> Result<StagedTx, TxEngineError> {
        self.stage_with_execution_origin_and_fee_overrides(
            permit,
            wallet,
            from,
            intent,
            chain,
            policy,
            address_book,
            execution_origin,
            None,
        )
        .await
    }

    /// Stage with trusted provenance and an optional complete EIP-1559 fee
    /// pair. The override is used for estimation, review, sealing, and signing.
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_with_execution_origin_and_fee_overrides(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        from: Address,
        intent: RawIntent,
        chain: &ChainClient,
        policy: &Policy,
        address_book: Option<&AddressBook>,
        execution_origin: Option<ExecutionOrigin>,
        fee_overrides: Option<Eip1559FeeOverrides>,
    ) -> Result<StagedTx, TxEngineError> {
        self.stage_with_execution_origin_and_fee_overrides_and_valuation_target(
            permit,
            wallet,
            from,
            intent,
            chain,
            policy,
            address_book,
            execution_origin,
            fee_overrides,
            None,
        )
        .await
    }

    /// Stage a trusted route transaction with an exact oracle binding. The
    /// caller supplies the encoded input asset and base-unit amount together
    /// with the expected executable transaction; the engine rejects any
    /// mismatch before obtaining or attaching a quote.
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_with_oracle_valuation_target(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        from: Address,
        intent: RawIntent,
        chain: &ChainClient,
        policy: &Policy,
        address_book: Option<&AddressBook>,
        valuation_target: BoundValuationTarget,
    ) -> Result<StagedTx, TxEngineError> {
        self.stage_with_execution_origin_and_fee_overrides_and_valuation_target(
            permit,
            wallet,
            from,
            intent,
            chain,
            policy,
            address_book,
            None,
            None,
            Some(valuation_target),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn stage_with_execution_origin_and_fee_overrides_and_valuation_target(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        from: Address,
        intent: RawIntent,
        chain: &ChainClient,
        policy: &Policy,
        address_book: Option<&AddressBook>,
        execution_origin: Option<ExecutionOrigin>,
        fee_overrides: Option<Eip1559FeeOverrides>,
        trusted_valuation_target: Option<BoundValuationTarget>,
    ) -> Result<StagedTx, TxEngineError> {
        if let Some(origin) = &execution_origin {
            origin
                .validate()
                .map_err(TxEngineError::ApprovalConstruction)?;
        }
        self.assert_write_permit(permit)?;
        let spec: &ChainSpec = chain.spec();
        if spec.legacy_tx && fee_overrides.is_some() {
            return Err(TxEngineError::InvalidFeeOverride(
                "EIP-1559 overrides are not valid for a legacy transaction chain".into(),
            ));
        }
        let chain_id = chain.chain_id().await?;

        // (to, value_wei, data_hex, optional token / nft metadata for plan)
        let (to, value_wei, data_hex, token_for_plan, nft_for_plan): (
            Address,
            U256,
            String,
            Option<TokenRef>,
            Option<NftRef>,
        ) = self
            .resolve_intent_body(&intent.body, chain, chain_id, address_book, from)
            .await?;

        // Build a request to estimate gas; choose 1559 vs legacy fields.
        let data_bytes = decode_data(&data_hex)?;
        if let Some(target) = &trusted_valuation_target
            && (target.expected_to != to
                || target.expected_value_wei != value_wei
                || target.expected_calldata.as_ref() != data_bytes.as_ref())
        {
            return Err(TxEngineError::ValuationUnavailable(
                "trusted valuation target does not match the executable transaction".into(),
            ));
        }

        // Stage-time MEV/sandwich heuristic. Computed up-front so that
        // when `policy.mev.fail_on_high_risk` is set we can deny before
        // any pending-dir write happens (high-risk denials don't leave
        // a partially-written stage on disk). The artefact write below
        // — after `write_pending` — only runs when we keep going.
        let mev_report = evaluate_mev_risk(chain, &data_bytes, value_wei, policy);
        if policy.mev.fail_on_high_risk && matches!(mev_report.risk, bloom_mempool::MevRisk::High) {
            debug!(
                wallet,
                chain = %spec.name,
                reason = "mev_high_risk",
                advice = %mev_report.advice,
                "tx.policy_denied"
            );
            return Err(TxEngineError::PolicyDenied);
        }

        // Open a pinned read session for the nonce + code reads so the
        // staging fanout sees a self-consistent block even when the
        // layered fallback transport rotates upstreams between calls.
        // Sessions are unconditional per the spec's Decisions Ratified
        // #2 — there is no opt-out. `gas_price` and `estimate_gas`
        // intentionally stay on the bare client because they target
        // pending-block semantics that don't fit the pinned model;
        // `chain_id` uses the cached value and doesn't need pinning.
        let session = chain.open_session().await?;
        if session.is_degraded() {
            tracing::warn!(
                chain = %spec.name,
                pinned_number = session.block_number(),
                "tx.staging.session_degraded"
            );
        }
        // Acquire a per-(wallet, chain, from) async mutex so concurrent
        // stage() calls for the same sender serialise here. The guard
        // lives until the end of stage(), covering write_pending, so two
        // callers can't both read nonce=0 and commit pending entries with
        // the same nonce.
        let nonce_mutex = self.nonce_lock_for(wallet, &spec.name, from);
        let _nonce_guard = nonce_mutex.lock().await;
        let now_ms = now_ms();
        let swept = self.outbox.sweep_expired(now_ms)?;
        if swept > 0 {
            tracing::info!(
                wallet,
                chain = %spec.name,
                swept,
                "tx.outbox_swept_expired_before_stage"
            );
        }
        let nonce = match intent.nonce {
            Some(n) => n,
            None => {
                let chain_nonce = session.nonce(from).await?;
                let pending_high = self
                    .outbox
                    .highest_pending_nonce(wallet, &spec.name, from)?;
                // If there are staged-but-unconfirmed txs, use the slot
                // after the highest pending nonce. After broadcast they
                // move to sent/ and the chain RPC returns the updated
                // next nonce — no stale-data risk once the queue drains.
                pending_high.map_or(chain_nonce, |h| chain_nonce.max(h + 1))
            }
        };
        // Check for an externally-observed pending tx at this (from, nonce).
        // Body is computed up-front but written only after write_pending
        // creates the pending dir.
        let conflict_body = self.build_nonce_conflict_body(&spec.name, from, nonce);
        let gas_price = match chain.gas_price().await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    chain = %spec.name,
                    fallback_wei = 1_000_000_000u128,
                    "tx.gas_price_fallback"
                );
                1_000_000_000
            }
        };
        let (max_fee, prio) = fee_overrides.map_or_else(
            || (gas_price.saturating_mul(2), (gas_price / 10).max(1)),
            |fees| (fees.max_fee_per_gas, fees.max_priority_fee_per_gas),
        );

        let mut req = TransactionRequest::default()
            .with_from(from)
            .with_to(to)
            .with_value(value_wei)
            .with_input(data_bytes.clone())
            .with_nonce(nonce)
            .with_chain_id(chain_id);
        if spec.legacy_tx {
            req = req.with_gas_price(gas_price);
        } else {
            req = req
                .with_max_fee_per_gas(max_fee)
                .with_max_priority_fee_per_gas(prio);
        }
        let gas_limit = match chain.estimate_gas(&req).await {
            Ok(g) => {
                // Add a 25% buffer; estimates can run short under load.
                let buffered = g.saturating_mul(125) / 100;
                buffered.max(21_000)
            }
            Err(e) => {
                // Use the hint from the external estimator (e.g. Enso) when
                // available, applying the same 25% buffer. Fall back to 500k
                // only if no hint was provided.
                let fallback = intent
                    .gas_limit_hint
                    .map(|h| (h.saturating_mul(125) / 100).min(30_000_000))
                    .unwrap_or(500_000);
                tracing::warn!(error = %e, fallback, "estimate_gas failed");
                fallback
            }
        };

        let (max_fee_field, prio_field, gas_price_field) = if spec.legacy_tx {
            (None, None, Some(gas_price.to_string()))
        } else {
            (Some(max_fee.to_string()), Some(prio.to_string()), None)
        };
        let funding_check = match session.balance(from).await {
            Ok(available) => insufficient_native_funds_check(
                &bloom_proto::checksum_address(&from),
                spec.display_name.as_deref().unwrap_or(&spec.name),
                &spec.native_symbol,
                spec.native_decimals,
                available,
                value_wei,
                gas_limit,
                if spec.legacy_tx { gas_price } else { max_fee },
            ),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    wallet,
                    chain = %spec.name,
                    account = %bloom_proto::checksum_address(&from),
                    "tx.native_funding_check_unavailable"
                );
                None
            }
        };

        // For policy evaluation, decide what addresses are involved:
        //   - native send: contract=None,    token=None,         recipient=to
        //   - erc20 send:  contract=token,   token=token,        recipient=token_for_plan.recipient
        //   - call/raw:    contract=to,      token=None,         recipient=to (best-effort)
        //
        // `destination_is_contract` drives the legacy `[contracts]` block
        // from the spec: a plain native send to an EOA bypasses those
        // checks. For native sends with a non-empty data field or where
        // the destination has bytecode we still flag it as a contract
        // call; the heuristic mirrors the spec's "code length > 0 OR data
        // is non-empty" rule.
        let mut policy_ctx = policy_engine::AddressContext::default();
        // Synthetic policy checks contributed by NFT-aware code paths
        // (e.g. operator-wide approvals) — appended after the rules engine
        // has produced its own checks so they all show up in plan.md.
        let mut staged_policy_extras: Vec<bloom_proto::PolicyCheck> = Vec::new();
        if let Some(check) = funding_check {
            staged_policy_extras.push(check);
        }
        let native_destination_is_contract = match &intent.body {
            RawIntentBody::Send { .. } if token_for_plan.is_none() => {
                // An unavailable code lookup is treated conservatively: a
                // native send must not become an autonomous transfer merely
                // because the RPC could not prove the destination is an EOA.
                !data_bytes.is_empty()
                    || session
                        .code(to)
                        .await
                        .map(|code| !code.is_empty())
                        .unwrap_or(true)
            }
            _ => false,
        };
        let action_kind = classify_action_kind(
            &intent.body,
            token_for_plan.is_some(),
            native_destination_is_contract,
        );
        match &intent.body {
            RawIntentBody::Send { .. } => {
                if let Some(t) = &token_for_plan {
                    policy_ctx.token = Some(to);
                    policy_ctx.contract = Some(to);
                    policy_ctx.destination_is_contract = true;
                    policy_ctx.token_symbol = Some(t.symbol.clone());
                    if let Ok(rec) = t.recipient.parse::<Address>() {
                        policy_ctx.recipient = Some(rec);
                    }
                } else {
                    policy_ctx.recipient = Some(to);
                    // Native send: if data is non-empty or the destination
                    // has bytecode, treat as contract call.
                    policy_ctx.destination_is_contract = native_destination_is_contract;
                    if policy_ctx.destination_is_contract {
                        policy_ctx.contract = Some(to);
                    }
                }
            }
            RawIntentBody::Call { .. } | RawIntentBody::Raw { .. } => {
                policy_ctx.contract = Some(to);
                policy_ctx.recipient = Some(to);
                policy_ctx.destination_is_contract = true;
            }
            RawIntentBody::Approve { .. } => {
                // contract = the ERC-20 (== `to`); recipient = the
                // spender, decoded out of the calldata so policies that
                // restrict who an allowance can be granted to still
                // have a meaningful target.
                policy_ctx.contract = Some(to);
                policy_ctx.token = Some(to);
                policy_ctx.destination_is_contract = true;
                if let Some(spender) = decode_approve_spender(&data_bytes) {
                    policy_ctx.recipient = Some(spender);
                }
            }
            RawIntentBody::NftTransfer { .. } => {
                // The on-wire `to` is the NFT contract; the human
                // recipient lives inside calldata. Surface both.
                policy_ctx.contract = Some(to);
                policy_ctx.destination_is_contract = true;
                if let Some(rec) = decode_nft_recipient(&data_bytes) {
                    policy_ctx.recipient = Some(rec);
                }
            }
            RawIntentBody::NftApprove { .. } => {
                // Single-token approval — moderate-risk write.
                policy_ctx.contract = Some(to);
                policy_ctx.destination_is_contract = true;
                if let Some(op) = decode_nft_approve_operator(&data_bytes) {
                    policy_ctx.recipient = Some(op);
                }
            }
            RawIntentBody::NftApproveAll {
                operator, approved, ..
            } => {
                // Operator-wide approval — the riskiest NFT write. Add a
                // warn-style policy line so plan.md highlights it.
                policy_ctx.contract = Some(to);
                policy_ctx.destination_is_contract = true;
                if let Ok(op) = operator.parse::<Address>() {
                    policy_ctx.recipient = Some(op);
                }
                let op_disp = bloom_proto::checksum_address(
                    &operator.parse::<Address>().unwrap_or(Address::ZERO),
                );
                let outcome = if *approved {
                    bloom_proto::PolicyOutcome::Warn
                } else {
                    bloom_proto::PolicyOutcome::Pass
                };
                staged_policy_extras.push(if *approved {
                    bloom_proto::PolicyCheck::soft(
                        "nft.approve_all",
                        outcome,
                        format!(
                            "operator-wide approval to {op_disp} — review carefully (write override token to confirm)"
                        ),
                    )
                } else {
                    bloom_proto::PolicyCheck::informational(
                        "nft.approve_all",
                        outcome,
                        format!("revoking operator-wide approval for {op_disp}"),
                    )
                });
            }
            RawIntentBody::Enso { .. } => {}
        }
        // USD valuation is authoritative only when produced by the oracle.
        // Caller-supplied hints are deliberately ignored: they are not bound
        // to the encoded asset, amount, or calldata and must never satisfy an
        // autonomous policy budget.
        let needs_usd = policy.caps.per_tx_usd.is_some()
            || policy.caps.require_confirm_above_usd.is_some()
            || policy.caps.per_day_usd.is_some()
            || matches!(
                policy.effective_agent_autonomy(),
                bloom_proto::AgentAutonomyMode::UnderPolicy
            );
        let valuation_target = trusted_valuation_target
            .as_ref()
            .map(|target| ValuationTarget {
                asset_id: target.asset_id.clone(),
                amount_base_units: target.amount_base_units.clone(),
                asset_decimals: target.asset_decimals,
            })
            .or_else(|| match action_kind {
                TxActionKind::NativeTransfer if value_wei > U256::ZERO => Some(ValuationTarget {
                    asset_id: format!("native:{}", spec.name),
                    amount_base_units: value_wei.to_string(),
                    asset_decimals: spec.native_decimals,
                }),
                TxActionKind::Erc20Transfer => token_for_plan.as_ref().and_then(|token| {
                    token
                        .amount_base_units
                        .clone()
                        .map(|amount| ValuationTarget {
                            asset_id: format!("{}:{}", spec.name, token.address),
                            amount_base_units: amount,
                            asset_decimals: token.decimals,
                        })
                }),
                _ => None,
            });
        let valuation = if needs_usd || trusted_valuation_target.is_some() {
            if let Some(target) = valuation_target.as_ref()
                && let Some(oracle) = &self.price_oracle
            {
                match oracle
                    .quote_usd(
                        &target.asset_id,
                        &target.amount_base_units,
                        target.asset_decimals,
                        now_ms as u64,
                    )
                    .await
                {
                    Ok(quote)
                        if quote.asset_id == target.asset_id
                            && quote.amount_base_units == target.amount_base_units
                            && (quote.usd_micro > 0
                                || target
                                    .amount_base_units
                                    .parse::<U256>()
                                    .is_ok_and(|v| v.is_zero()))
                            && quote
                                .validate_for_authorization(
                                    &ValuationPolicy::default(),
                                    now_ms as u64,
                                )
                                .is_ok() =>
                    {
                        Some(quote)
                    }
                    Ok(_) => {
                        tracing::warn!(
                            wallet,
                            chain = %spec.name,
                            "tx.valuation_oracle_returned_unbound_quote"
                        );
                        None
                    }
                    Err(error) => {
                        tracing::warn!(
                            wallet,
                            chain = %spec.name,
                            error = %error,
                            "tx.valuation_lookup_failed"
                        );
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        policy_ctx.usd_value = valuation
            .as_ref()
            .map(|quote| quote.usd_micro as f64 / 1_000_000.0);
        // Trailing 24h USD spend across all chains for this wallet.
        // Only consulted when the policy actually has a per_day cap;
        // we still set it whenever a USD rule fires so plan.md / audit
        // can show the running total (cheap — just walks intent.json).
        if needs_usd {
            const DAY_MS: u128 = 24 * 60 * 60 * 1000;
            let since = now_ms.saturating_sub(DAY_MS);
            policy_ctx.usd_spent_last_24h = self.outbox.sum_usd_since(wallet, since, None).ok();
        }

        let mut staged = StagedTx {
            id: self.outbox.allocate_id(),
            wallet: wallet.to_string(),
            chain: spec.name.clone(),
            chain_id,
            from: bloom_proto::checksum_address(&from),
            to: bloom_proto::checksum_address(&to),
            value_wei: value_wei.to_string(),
            data_hex: data_hex.clone(),
            gas_limit,
            max_fee_per_gas: max_fee_field,
            max_priority_fee_per_gas: prio_field,
            gas_price: gas_price_field,
            nonce,
            policy_checks: vec![],
            created_ms: now_ms,
            expires_ms: now_ms + self.stage_ttl_ms,
            status: TxStatus::Pending,
            action_kind,
            tx_hash: None,
            token: token_for_plan,
            nft: nft_for_plan,
            usd_value: policy_ctx.usd_value,
            valuation,
            depends_on: None,
            action_id: None,
            execution_origin,
        };
        staged.policy_checks = policy_engine::evaluate(
            policy,
            &spec.name,
            value_wei,
            spec.native_decimals,
            policy_ctx,
        );
        staged.policy_checks.extend(staged_policy_extras);

        let plan =
            bloom_proto::PlanRender::render(&staged, &spec.native_symbol, spec.native_decimals);
        self.outbox.write_pending(&staged, &plan)?;
        if let Some(body) = conflict_body {
            self.outbox
                .write_nonce_conflict(&staged.wallet, &staged.chain, &staged.id, &body)?;
        }
        self.outbox
            .write_mev_risk(&staged.wallet, &staged.chain, &staged.id, &mev_report)?;
        debug!(id=%staged.id, wallet=%staged.wallet, chain=%staged.chain, "tx.stage");
        Ok(staged)
    }

    /// Confirm and broadcast a staged tx. Caller decides whether the
    /// confirm content is "y" (normal) or the policy's override sentinel
    /// (bypass soft warns).
    ///
    /// Refuses any id that is not currently in `pending`: a stale path
    /// like `outbox/<wallet>/<chain>/pending/<sent-id>/confirm` cannot
    /// rebroadcast (fix #2). Refuses any pending entry whose `expires_ms`
    /// has passed (fix #3) — the caller should sweep expired and re-stage.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_confirm_write_open(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        chain_name: &str,
        id: &str,
        chain: &ChainClient,
        policy: &Policy,
        override_warnings: bool,
    ) -> Result<(), TxEngineError> {
        self.assert_write_permit(permit)?;
        let entry = self
            .outbox
            .read_in_state(wallet, chain_name, id, OutboxState::Pending)?;
        let mut staged = entry.staged.clone();

        if self
            .outbox
            .read_broadcast_attempt(&entry, BroadcastAttemptKind::Confirm)?
            .is_some()
        {
            return Ok(());
        }

        let now = now_ms();
        if staged.expires_ms != 0 && now >= staged.expires_ms {
            return Err(TxEngineError::Outbox(OutboxError::StagedExpired {
                id: staged.id.clone(),
                expired_at: staged.expires_ms,
                now,
            }));
        }

        if let Some(dep_id) = staged.depends_on.clone() {
            self.ensure_dependency_satisfied(wallet, chain_name, &dep_id)?;
        }

        let hard = policy_engine::has_hard_violation(&staged.policy_checks);
        if hard {
            staged.status = TxStatus::Failed;
            self.outbox
                .transition(&entry, crate::outbox::OutboxState::Failed)?;
            debug!(
                id = %staged.id,
                wallet,
                chain = %chain_name,
                reason = "hard",
                "tx.policy_denied"
            );
            return Err(TxEngineError::PolicyDenied);
        }
        let warn = policy_engine::has_warning(&staged.policy_checks);
        if warn && !override_warnings {
            debug!(
                id = %staged.id,
                wallet,
                chain = %chain_name,
                reason = "warn_no_override",
                "tx.policy_denied"
            );
            return Err(TxEngineError::PolicyDenied);
        }

        const ENSO_QUOTE_MAX_AGE_SECS: u64 = 300;
        let now_secs = (now_ms() / 1000) as u64;
        if let Some(age) = enso_quote_age_secs(&staged.data_hex, now_secs)
            && age > ENSO_QUOTE_MAX_AGE_SECS
            && !override_warnings
        {
            return Err(TxEngineError::EnsoQuoteStale { age });
        }

        let spec = chain.spec();
        if !spec.allow_broadcast {
            debug!(
                id = %staged.id,
                wallet,
                chain = %spec.name,
                allow_broadcast = spec.allow_broadcast,
                "tx.broadcast_disabled"
            );
            return Err(TxEngineError::BroadcastDisabled(spec.name.clone()));
        }
        if !override_warnings {
            self.simulate_or_reject(&staged, chain).await?;
        }

        let subject = self.authorization_subject(&staged);
        if self.session_store.covers(
            wallet,
            staged.chain_id,
            &staged.id,
            subject.total_value_usd_micro,
            crate::session::SessionActionFacts {
                value_moving: subject.value_moving,
                calldata_verified: subject.calldata_verified,
                authority_change: subject.authority_change,
            },
            now_ms(),
        ) {
            return Ok(());
        }

        let unsigned = self.build_unsigned_evm_tx(&staged, chain)?;
        let signing_hash = Self::unsigned_signing_hash(&unsigned);
        self.ensure_action_authorized(
            &entry,
            &staged,
            EvmOutboxActionKind::Confirm,
            &signing_hash,
            policy,
            bloom_proto::AuthorizationSurface::Cli,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn confirm(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        chain_name: &str,
        id: &str,
        chain: &ChainClient,
        policy: &Policy,
        confirm_text: &str,
    ) -> Result<StagedTx, TxEngineError> {
        let override_warnings = confirm_text
            .trim()
            .eq_ignore_ascii_case(policy.override_sentinel());
        self.confirm_with_warning_override(
            permit,
            wallet,
            chain_name,
            id,
            chain,
            policy,
            override_warnings,
        )
        .await
    }

    /// Confirm a staged transaction with an explicit warning-override decision.
    /// This avoids converting trusted boolean decisions into user-configurable
    /// sentinel text at internal call sites.
    #[allow(clippy::too_many_arguments)]
    pub async fn confirm_with_warning_override(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        chain_name: &str,
        id: &str,
        chain: &ChainClient,
        policy: &Policy,
        override_warnings: bool,
    ) -> Result<StagedTx, TxEngineError> {
        self.assert_write_permit(permit)?;
        let entry = self
            .outbox
            .read_in_state(wallet, chain_name, id, OutboxState::Pending)?;
        let mut staged = entry.staged.clone();

        if let Some(attempt) = self
            .outbox
            .read_broadcast_attempt(&entry, BroadcastAttemptKind::Confirm)?
        {
            return self
                .reconcile_confirm_attempt(&entry, attempt, chain, policy)
                .await;
        }

        // Expiry check: stage TTL is enforced regardless of whether the
        // sweeper has run yet. We use wall-clock here; sweep_expired is the
        // background mop-up that removes stale dirs.
        let now = now_ms();
        if staged.expires_ms != 0 && now >= staged.expires_ms {
            return Err(TxEngineError::Outbox(OutboxError::StagedExpired {
                id: staged.id.clone(),
                expired_at: staged.expires_ms,
                now,
            }));
        }

        // Same-chain dependency gate: a tx that depends on another (e.g. a
        // route that spends an approve) must not broadcast until that
        // predecessor has mined *successfully*. A reverted predecessor still
        // consumed its nonce, so this is an explicit refuse — never a reshuffle.
        if let Some(dep_id) = staged.depends_on.clone() {
            self.ensure_dependency_satisfied(wallet, chain_name, &dep_id)?;
        }

        // Policy gate.
        let hard = policy_engine::has_hard_violation(&staged.policy_checks);
        if hard {
            staged.status = TxStatus::Failed;
            self.outbox
                .transition(&entry, crate::outbox::OutboxState::Failed)?;
            debug!(
                id = %staged.id,
                wallet,
                chain = %chain_name,
                reason = "hard",
                "tx.policy_denied"
            );
            return Err(TxEngineError::PolicyDenied);
        }
        let warn = policy_engine::has_warning(&staged.policy_checks);
        if warn && !override_warnings {
            debug!(
                id = %staged.id,
                wallet,
                chain = %chain_name,
                reason = "warn_no_override",
                "tx.policy_denied"
            );
            return Err(TxEngineError::PolicyDenied);
        }

        // Enso quotes embed a ~5-minute deadline. Warn before wasting gas.
        const ENSO_QUOTE_MAX_AGE_SECS: u64 = 300;
        let now_secs = (now_ms() / 1000) as u64;
        if let Some(age) = enso_quote_age_secs(&staged.data_hex, now_secs)
            && age > ENSO_QUOTE_MAX_AGE_SECS
            && !override_warnings
        {
            return Err(TxEngineError::EnsoQuoteStale { age });
        }

        // Broadcast gate: honor the per-chain setting.
        let spec = chain.spec();
        if !spec.allow_broadcast {
            debug!(
                id = %staged.id,
                wallet,
                chain = %spec.name,
                allow_broadcast = spec.allow_broadcast,
                "tx.broadcast_disabled"
            );
            return Err(TxEngineError::BroadcastDisabled(spec.name.clone()));
        }
        // Pre-broadcast simulation first (no side effects): eth_call against
        // current state so a tx that would revert is caught here instead of
        // burning gas. The override sentinel forces it through.
        if !override_warnings {
            self.simulate_or_reject(&staged, chain).await?;
        }

        // Authorization. The policy gates above (hard deny / unoverridden warn)
        // have already passed, so a bounded policy session may authorize this
        // confirm without a fresh per-tx review; otherwise fall back to the
        // standard per-tx authorization. The session debit is atomic; we refund
        // it if the broadcast then fails.
        let subject = self.authorization_subject(&staged);
        let session_debit = self.session_store.authorize_and_debit(
            wallet,
            staged.chain_id,
            &staged.id,
            subject.total_value_usd_micro,
            crate::session::SessionActionFacts {
                value_moving: subject.value_moving,
                calldata_verified: subject.calldata_verified,
                authority_change: subject.authority_change,
            },
            now_ms(),
        );
        let unsigned = self.build_unsigned_evm_tx(&staged, chain)?;
        let prepared = PreparedEvmTx {
            signing_hash: Self::unsigned_signing_hash(&unsigned),
            unsigned,
        };
        let signing_hash = prepared.signing_hash;

        if let Some((ref sid, _)) = session_debit {
            debug!(id = %staged.id, session = %sid, "tx.authorized_by_session");
        } else {
            self.ensure_action_authorized(
                &entry,
                &staged,
                EvmOutboxActionKind::Confirm,
                &signing_hash,
                policy,
                bloom_proto::AuthorizationSurface::Cli,
            )
            .await?;
        }

        let tx_hash = match self
            .submit_with_marker(
                &entry,
                EvmOutboxActionKind::Confirm,
                &staged,
                chain,
                policy,
                prepared,
            )
            .await
        {
            Ok(h) => h,
            Err(e) => {
                if let Some((sid, amt)) = session_debit {
                    let attempted = self
                        .outbox
                        .read_broadcast_attempt(&entry, BroadcastAttemptKind::Confirm)?
                        .is_some();
                    if !attempted {
                        self.session_store.refund(&sid, amt);
                    }
                }
                return Err(e);
            }
        };
        info!(id=%staged.id, hash=%format!("{:#x}", tx_hash), "tx.broadcast");

        staged.status = TxStatus::Sent;
        staged.tx_hash = Some(format!("{:#x}", tx_hash));

        let new_dir = self
            .outbox
            .transition(&entry, crate::outbox::OutboxState::Sent)?;
        self.outbox.write_artefact(
            &new_dir,
            "intent.json",
            &serde_json::to_vec_pretty(&staged).unwrap(),
        )?;
        self.outbox.write_artefact(
            &new_dir,
            "tx_hash",
            staged.tx_hash.as_ref().unwrap().as_bytes(),
        )?;
        if let Some(action_id) = staged.action_id.as_deref() {
            self.write_central_evm_result(EvmCentralResult {
                action_id,
                state: OutboxState::Sent,
                outcome: "sent",
                tx_hash,
                nonce: staged.nonce,
                signing_hash: &signing_hash,
                action_kind: EvmOutboxActionKind::Confirm.action_kind(),
            })?;
        }

        Ok(staged)
    }

    async fn reconcile_confirm_attempt(
        &self,
        entry: &crate::outbox::OutboxEntry,
        attempt: BroadcastAttempt,
        chain: &ChainClient,
        policy: &Policy,
    ) -> Result<StagedTx, TxEngineError> {
        let tx_hash: B256 = attempt
            .tx_hash
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        if chain.tx_by_hash(tx_hash).await?.is_some() || chain.receipt(tx_hash).await?.is_some() {
            return self.finalize_sent(entry, tx_hash, chain);
        }

        let from: Address = attempt
            .from
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        let chain_nonce = chain.nonce(from).await?;
        if chain_nonce > attempt.nonce {
            self.write_reconcile_ambiguous(
                entry,
                format!(
                    "account nonce advanced to {chain_nonce}, but tx {} was not found",
                    attempt.tx_hash
                ),
            )?;
            return Err(TxEngineError::BroadcastAttemptAmbiguous {
                id: entry.staged.id.clone(),
                reason: "account nonce advanced but attempted tx hash is absent".into(),
            });
        }

        if let Some(body) = self.build_nonce_conflict_body(&entry.staged.chain, from, attempt.nonce)
        {
            self.write_reconcile_ambiguous(entry, body.to_string())?;
            return Err(TxEngineError::BroadcastAttemptAmbiguous {
                id: entry.staged.id.clone(),
                reason: "external pending tx already occupies this nonce".into(),
            });
        }
        let other_attempts = self
            .outbox
            .broadcast_attempts_for_nonce(SameNonceAttemptQuery {
                wallet: &entry.staged.wallet,
                chain: &entry.staged.chain,
                from: &attempt.from,
                chain_id: attempt.chain_id,
                nonce: attempt.nonce,
                excluding_id: &entry.staged.id,
                excluding_kind: BroadcastAttemptKind::Confirm,
            })?;
        if !other_attempts.is_empty() {
            self.write_reconcile_ambiguous(
                entry,
                format!("other same-nonce attempts exist: {}", other_attempts.len()),
            )?;
            return Err(TxEngineError::BroadcastAttemptAmbiguous {
                id: entry.staged.id.clone(),
                reason: "another known broadcast attempt occupies this nonce".into(),
            });
        }

        match attempt.transport {
            BroadcastTransport::PrivateRpc => {
                self.write_reconcile_ambiguous(
                    entry,
                    "private relay attempt absent from public RPC; refusing to leak to public mempool",
                )?;
                Err(TxEngineError::BroadcastAttemptAmbiguous {
                    id: entry.staged.id.clone(),
                    reason: "private relay attempt unresolved".into(),
                })
            }
            BroadcastTransport::PublicRpc => {
                let spec = chain.spec();
                if !spec.allow_broadcast {
                    return Err(TxEngineError::BroadcastDisabled(spec.name.clone()));
                }
                if policy.private.enabled {
                    self.write_reconcile_ambiguous(
                        entry,
                        "current policy requests private routing; refusing to replay old public attempt automatically",
                    )?;
                    return Err(TxEngineError::BroadcastAttemptAmbiguous {
                        id: entry.staged.id.clone(),
                        reason: "current policy changed to private routing".into(),
                    });
                }
                let unsigned = self.build_unsigned_evm_tx(&entry.staged, chain)?;
                let signing_hash = Self::unsigned_signing_hash(&unsigned);
                self.ensure_action_authorized(
                    entry,
                    &entry.staged,
                    EvmOutboxActionKind::Confirm,
                    &signing_hash,
                    policy,
                    bloom_proto::AuthorizationSurface::Cli,
                )
                .await?;
                let raw = self.outbox.read_broadcast_raw_tx(
                    entry,
                    BroadcastAttemptKind::Confirm,
                    &attempt,
                )?;
                let returned = chain.send_raw(Bytes::from(raw)).await.map_err(|e| {
                    let _ = self
                        .write_reconcile_ambiguous(entry, format!("public resubmit failed: {e}"));
                    TxEngineError::Chain(e)
                })?;
                if returned != tx_hash {
                    return Err(TxEngineError::BroadcastHashMismatch {
                        expected: format!("{:#x}", tx_hash),
                        returned: format!("{:#x}", returned),
                    });
                }
                self.finalize_sent(entry, tx_hash, chain)
            }
        }
    }

    fn finalize_sent(
        &self,
        entry: &crate::outbox::OutboxEntry,
        tx_hash: B256,
        chain: &ChainClient,
    ) -> Result<StagedTx, TxEngineError> {
        let mut staged = entry.staged.clone();
        staged.status = TxStatus::Sent;
        staged.tx_hash = Some(format!("{:#x}", tx_hash));
        let new_dir = self
            .outbox
            .transition(entry, crate::outbox::OutboxState::Sent)?;
        self.outbox.write_artefact(
            &new_dir,
            "intent.json",
            &serde_json::to_vec_pretty(&staged).unwrap(),
        )?;
        self.outbox.write_artefact(
            &new_dir,
            "tx_hash",
            staged.tx_hash.as_ref().unwrap().as_bytes(),
        )?;
        if let Some(action_id) = staged.action_id.as_deref() {
            let signing_hash = self
                .build_unsigned_evm_tx(&staged, chain)
                .map(|unsigned| Self::unsigned_signing_hash(&unsigned))?;
            self.write_central_evm_result(EvmCentralResult {
                action_id,
                state: OutboxState::Sent,
                outcome: "sent",
                tx_hash,
                nonce: staged.nonce,
                signing_hash: &signing_hash,
                action_kind: EvmOutboxActionKind::Confirm.action_kind(),
            })?;
        }
        Ok(staged)
    }

    fn write_central_evm_result(&self, central: EvmCentralResult<'_>) -> Result<(), TxEngineError> {
        let result = serde_json::json!({
            "schema": "bloom.evm_execution_result.v1",
            "action_id": central.action_id,
            "state": central.state.dirname(),
            "outcome": central.outcome,
            "action_kind": central.action_kind,
            "tx_hash": format!("{:#x}", central.tx_hash),
            "nonce": central.nonce,
            "signing_hash": format!("{:#x}", central.signing_hash),
            "created_ms": now_ms(),
        });
        let mut status = self.central_status_base(central.action_id, central.state)?;
        let status_obj = status.as_object_mut().expect("central status is object");
        status_obj.insert("outcome".into(), serde_json::json!(central.outcome));
        status_obj.insert(
            "tx_hash".into(),
            serde_json::json!(format!("{:#x}", central.tx_hash)),
        );
        status_obj.insert("action_kind".into(), serde_json::json!(central.action_kind));
        self.outbox.write_central_action_artifact(
            central.action_id,
            central.state,
            "result.json",
            &serde_json::to_vec_pretty(&result).unwrap(),
        )?;
        self.outbox.write_central_action_artifact(
            central.action_id,
            central.state,
            "status.json",
            &serde_json::to_vec_pretty(&status).unwrap(),
        )?;
        Ok(())
    }

    fn write_central_evm_failure_result(
        &self,
        central: EvmCentralFailure<'_>,
    ) -> Result<(), TxEngineError> {
        let result = serde_json::json!({
            "schema": "bloom.evm_execution_result.v1",
            "action_id": central.action_id,
            "state": central.state.dirname(),
            "outcome": central.outcome,
            "error": central.reason,
            "created_ms": now_ms(),
        });
        let mut status = self.central_status_base(central.action_id, central.state)?;
        let status_obj = status.as_object_mut().expect("central status is object");
        status_obj.insert("outcome".into(), serde_json::json!(central.outcome));
        status_obj.insert("error".into(), serde_json::json!(central.reason));
        self.outbox.write_central_action_artifact(
            central.action_id,
            central.state,
            "result.json",
            &serde_json::to_vec_pretty(&result).unwrap(),
        )?;
        self.outbox.write_central_action_artifact(
            central.action_id,
            central.state,
            "status.json",
            &serde_json::to_vec_pretty(&status).unwrap(),
        )?;
        Ok(())
    }

    fn central_status_base(
        &self,
        action_id: &str,
        state: OutboxState,
    ) -> Result<serde_json::Value, TxEngineError> {
        let mut status = self
            .outbox
            .read_central_action_artifact(action_id, state, "status.json")?
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .filter(|value| value.is_object())
            .unwrap_or_else(|| serde_json::json!({}));
        let status_obj = status.as_object_mut().expect("central status is object");
        status_obj.insert("action_id".into(), serde_json::json!(action_id));
        status_obj.insert("state".into(), serde_json::json!(state.dirname()));
        Ok(status)
    }

    fn write_reconcile_ambiguous(
        &self,
        entry: &crate::outbox::OutboxEntry,
        reason: impl Into<String>,
    ) -> Result<(), TxEngineError> {
        let body = serde_json::json!({
            "schema": "bloom.reconcile_ambiguous.v1",
            "id": entry.staged.id,
            "wallet": entry.staged.wallet,
            "chain": entry.staged.chain,
            "nonce": entry.staged.nonce,
            "reason": reason.into(),
            "created_ms": now_ms(),
        });
        self.outbox.write_artefact(
            &entry.dir,
            "reconcile_ambiguous.json",
            &serde_json::to_vec_pretty(&body).unwrap(),
        )?;
        Ok(())
    }

    /// Refuse to broadcast a tx whose nonce is ahead of the account's next
    /// on-chain nonce with nothing filling the gap.
    ///
    /// The auto-increment nonce default ([`Outbox::highest_pending_nonce`]) is
    /// optimistic: a pending entry reserves its slot before it broadcasts, so a
    /// staged-but-never-broadcast (or later-abandoned) entry can push a
    /// subsequent tx one nonce past a gap that never fills. The RPC accepts such
    /// a tx into its *queued* set and returns a hash — it looks broadcast — but
    /// it can never mine, silently stranding it. This is the broadcast-time
    /// backstop for that hazard.
    ///
    /// The `pending` nonce tag already reflects every tx the node has accepted,
    /// including our own in-flight ones, so a *strictly greater* staged nonce is
    /// a genuine gap. Bundles stay safe: a dependent's `depends_on` gate holds it
    /// until its predecessor mines, by which point the chain nonce has advanced
    /// to meet it. Callers that intend to queue ahead override the default with
    /// an explicit intent `nonce`.
    async fn assert_nonce_not_ahead_of_chain(
        &self,
        chain: &ChainClient,
        from: Address,
        nonce: u64,
    ) -> Result<(), TxEngineError> {
        // Only refuse on *positive* evidence of a gap. A failed nonce read (RPC
        // down, transient error) is not evidence the tx is ahead of the chain —
        // fail open and let the actual broadcast surface any real RPC error,
        // rather than blocking a broadcast on a flaky preflight.
        let chain_next = match chain.nonce(from).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    from = %bloom_proto::checksum_address(&from),
                    nonce,
                    "nonce_gap_guard: could not read chain nonce; proceeding with broadcast"
                );
                return Ok(());
            }
        };
        if nonce > chain_next {
            return Err(TxEngineError::NonceGap {
                from: bloom_proto::checksum_address(&from),
                staged: nonce,
                chain_next,
            });
        }
        Ok(())
    }

    /// Persist a machine-readable advisory beside a pending entry when its
    /// broadcast was refused by [`Self::assert_nonce_not_ahead_of_chain`], so an
    /// agent can see the exact gap and how to resolve it without re-deriving it.
    fn write_nonce_gap_advisory(
        &self,
        entry: &crate::outbox::OutboxEntry,
        staged: u64,
        chain_next: u64,
    ) -> Result<(), TxEngineError> {
        let body = serde_json::json!({
            "schema": "bloom.nonce_gap.v1",
            "id": entry.staged.id,
            "wallet": entry.staged.wallet,
            "chain": entry.staged.chain,
            "from": entry.staged.from,
            "staged_nonce": staged,
            "chain_next_nonce": chain_next,
            "advice": format!(
                "broadcast nonce {chain_next} first, or restage with an explicit `nonce` to fill the gap deliberately"
            ),
            "created_ms": now_ms(),
        });
        self.outbox.write_artefact(
            &entry.dir,
            "nonce_gap.json",
            &serde_json::to_vec_pretty(&body).unwrap(),
        )?;
        Ok(())
    }

    fn build_unsigned_evm_tx(
        &self,
        staged: &StagedTx,
        chain: &ChainClient,
    ) -> Result<UnsignedEvmTx, TxEngineError> {
        let _from: Address = staged
            .from
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        let to_addr: Address = staged
            .to
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        let value: U256 = staged
            .value_wei
            .parse()
            .map_err(|_| TxEngineError::Amount("value_wei".into()))?;
        let data = decode_data(&staged.data_hex)?;

        if chain.spec().legacy_tx {
            let gp: u128 = staged
                .gas_price
                .as_deref()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(1_000_000_000);
            Ok(UnsignedEvmTx::Legacy(TxLegacy {
                chain_id: Some(staged.chain_id),
                nonce: staged.nonce,
                gas_price: gp,
                gas_limit: staged.gas_limit,
                to: TxKind::Call(to_addr),
                value,
                input: data,
            }))
        } else {
            let max_fee: u128 = staged
                .max_fee_per_gas
                .as_deref()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(2_000_000_000);
            let prio: u128 = staged
                .max_priority_fee_per_gas
                .as_deref()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(1_000_000);
            Ok(UnsignedEvmTx::Eip1559(TxEip1559 {
                chain_id: staged.chain_id,
                nonce: staged.nonce,
                gas_limit: staged.gas_limit,
                max_fee_per_gas: max_fee,
                max_priority_fee_per_gas: prio,
                to: TxKind::Call(to_addr),
                value,
                access_list: AccessList::default(),
                input: data,
            }))
        }
    }

    fn unsigned_signing_hash(unsigned: &UnsignedEvmTx) -> B256 {
        match unsigned {
            UnsignedEvmTx::Legacy(tx) => tx.signature_hash(),
            UnsignedEvmTx::Eip1559(tx) => tx.signature_hash(),
        }
    }

    fn assemble_signed_raw_tx(
        &self,
        staged: &StagedTx,
        unsigned: UnsignedEvmTx,
        signature: Signature,
    ) -> Result<SignedRawTx, TxEngineError> {
        let expected_from: Address = staged
            .from
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        let tx_envelope: TxEnvelope = match unsigned {
            UnsignedEvmTx::Legacy(tx) => {
                let signed = tx.into_signed(signature);
                let recovered = signed
                    .recover_signer()
                    .map_err(|e| TxEngineError::Signer(format!("recover signer: {e}")))?;
                if recovered != expected_from {
                    return Err(TxEngineError::Signer(format!(
                        "host signature recovered {recovered:#x}, expected {expected_from:#x}"
                    )));
                }
                signed.into()
            }
            UnsignedEvmTx::Eip1559(tx) => {
                let signed = tx.into_signed(signature);
                let recovered = signed
                    .recover_signer()
                    .map_err(|e| TxEngineError::Signer(format!("recover signer: {e}")))?;
                if recovered != expected_from {
                    return Err(TxEngineError::Signer(format!(
                        "host signature recovered {recovered:#x}, expected {expected_from:#x}"
                    )));
                }
                signed.into()
            }
        };
        let mut buf = Vec::new();
        tx_envelope.encode_2718(&mut buf);
        let raw = Bytes::from(buf);
        let hash = alloy::primitives::keccak256(&raw);
        Ok(SignedRawTx { raw, hash })
    }

    #[cfg(test)]
    async fn build_signed_raw_tx(
        &self,
        staged: &StagedTx,
        chain: &ChainClient,
        signer: &PrivateKeySigner,
    ) -> Result<SignedRawTx, TxEngineError> {
        use alloy::signers::SignerSync;

        let unsigned = self.build_unsigned_evm_tx(staged, chain)?;
        let signature = signer
            .sign_hash_sync(&Self::unsigned_signing_hash(&unsigned))
            .map_err(|e| TxEngineError::Signer(e.to_string()))?;
        self.assemble_signed_raw_tx(staged, unsigned, signature)
    }

    async fn submit_signed_raw(
        &self,
        staged: &StagedTx,
        chain: &ChainClient,
        policy: &Policy,
        signed: &SignedRawTx,
    ) -> Result<SubmitResult, TxEngineError> {
        if policy.private.enabled {
            if !matches!(
                staged.chain_id,
                bloom_mempool::MAINNET_CHAIN_ID | bloom_mempool::SEPOLIA_CHAIN_ID
            ) {
                return Err(TxEngineError::PrivateNotSupportedOnChain(
                    chain.spec().name.clone(),
                ));
            }
            let returned = self
                .submit_via_private(staged.chain_id, &policy.private.provider, &signed.raw)
                .await?;
            Ok(SubmitResult {
                transport: BroadcastTransport::PrivateRpc,
                returned_hash: Some(returned),
            })
        } else {
            let returned = chain.send_raw(signed.raw.clone()).await?;
            if returned != signed.hash {
                return Err(TxEngineError::BroadcastHashMismatch {
                    expected: format!("{:#x}", signed.hash),
                    returned: format!("{:#x}", returned),
                });
            }
            Ok(SubmitResult {
                transport: BroadcastTransport::PublicRpc,
                returned_hash: Some(returned),
            })
        }
    }

    async fn submit_with_marker(
        &self,
        entry: &crate::outbox::OutboxEntry,
        action_kind: EvmOutboxActionKind,
        staged: &StagedTx,
        chain: &ChainClient,
        policy: &Policy,
        prepared: PreparedEvmTx,
    ) -> Result<B256, TxEngineError> {
        let kind = action_kind.broadcast_kind();
        self.ensure_broadcast_allowed(chain.spec())?;
        if policy.private.enabled
            && !matches!(
                staged.chain_id,
                bloom_mempool::MAINNET_CHAIN_ID | bloom_mempool::SEPOLIA_CHAIN_ID
            )
        {
            return Err(TxEngineError::PrivateNotSupportedOnChain(
                chain.spec().name.clone(),
            ));
        }
        // Refuse to broadcast into a nonce gap (would be queued and never mine).
        // Do this before signing/marker writes so a refused attempt leaves no
        // half-broadcast state — just an advisory beside the pending entry.
        let from: Address = staged
            .from
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        if let Err(e) = self
            .assert_nonce_not_ahead_of_chain(chain, from, staged.nonce)
            .await
        {
            if let TxEngineError::NonceGap {
                staged: s,
                chain_next,
                ..
            } = &e
            {
                let _ = self.write_nonce_gap_advisory(entry, *s, *chain_next);
            }
            return Err(e);
        }
        let signature = self
            .host_sign_evm_hash(staged, action_kind, prepared.signing_hash)
            .await?;
        let signed = self.assemble_signed_raw_tx(staged, prepared.unsigned, signature)?;
        self.outbox
            .write_broadcast_raw_tx(entry, kind, &signed.raw)?;
        let attempt = BroadcastAttempt {
            schema: "bloom.broadcast_attempted.v1".into(),
            tx_hash: format!("{:#x}", signed.hash),
            raw_tx_blake3: blake3::hash(&signed.raw).to_hex().to_string(),
            raw_tx_path: kind.raw_name().into(),
            from: staged.from.clone(),
            to: staged.to.clone(),
            nonce: staged.nonce,
            chain_id: staged.chain_id,
            created_ms: now_ms(),
            transport: if policy.private.enabled {
                BroadcastTransport::PrivateRpc
            } else {
                BroadcastTransport::PublicRpc
            },
            private_provider: policy
                .private
                .enabled
                .then(|| policy.private.provider.clone()),
        };
        self.outbox.write_broadcast_attempt(entry, kind, &attempt)?;
        let submitted = self
            .submit_signed_raw(staged, chain, policy, &signed)
            .await?;
        if matches!(submitted.transport, BroadcastTransport::PublicRpc)
            && submitted.returned_hash != Some(signed.hash)
        {
            return Err(TxEngineError::BroadcastHashMismatch {
                expected: format!("{:#x}", signed.hash),
                returned: submitted
                    .returned_hash
                    .map(|h| format!("{:#x}", h))
                    .unwrap_or_else(|| "<none>".into()),
            });
        }
        Ok(signed.hash)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute_evm_owner_session_use(
        &self,
        wallet: &str,
        session_id: &str,
        reservation_id: &str,
        request: &EvmOwnerSigningSessionUse,
        session: &StandingSessionRecord,
        chain_name: &str,
        chain: &ChainClient,
        from: Address,
        policy: &Policy,
    ) -> Result<EvmOwnerSessionExecution, TxEngineError> {
        self.ensure_broadcast_allowed(chain.spec())?;
        if chain.spec().chain_id != request.chain_id {
            return Err(TxEngineError::ApprovalDenied(format!(
                "owner-session chain mismatch: request {}, chain {}",
                request.chain_id,
                chain.spec().chain_id
            )));
        }
        if request.method != EVM_ERC20_TRANSFER_METHOD {
            return Err(TxEngineError::ApprovalDenied(
                "owner-session use supports only ERC-20 transfer".into(),
            ));
        }

        let token_address: Address = request
            .token_contract
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        let recipient: Address = request
            .recipient
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        let amount = U256::from_str_radix(&request.amount_base_units, 10)
            .map_err(|e| TxEngineError::Amount(format!("owner-session amount: {e}")))?;
        let call = IERC20::transferCall {
            to: recipient,
            amount,
        };
        let expected_calldata = format!("0x{}", hex::encode(call.abi_encode()));
        if !request
            .calldata_hex
            .eq_ignore_ascii_case(&expected_calldata)
        {
            return Err(TxEngineError::ApprovalDenied(
                "owner-session calldata does not match scoped ERC-20 transfer".into(),
            ));
        }

        let nonce = match request.nonce {
            Some(n) => n,
            None => chain.nonce(from).await?,
        };
        let gas_limit = request.gas_limit.unwrap_or(65_000);
        let max_fee = request
            .max_fee_per_gas_wei
            .clone()
            .unwrap_or_else(|| "2000000000".into());
        let max_priority = request
            .max_priority_fee_per_gas_wei
            .clone()
            .unwrap_or_else(|| "1000000".into());
        let id = format!("{session_id}:{reservation_id}");
        let staged = StagedTx {
            id,
            wallet: wallet.to_string(),
            chain: chain_name.to_string(),
            chain_id: request.chain_id,
            from: bloom_proto::checksum_address(&from),
            to: bloom_proto::checksum_address(&token_address),
            value_wei: "0".into(),
            data_hex: expected_calldata,
            gas_limit,
            max_fee_per_gas: Some(max_fee),
            max_priority_fee_per_gas: Some(max_priority),
            gas_price: None,
            nonce,
            policy_checks: Vec::new(),
            created_ms: now_ms(),
            expires_ms: u128::from(session.expires_ms),
            status: TxStatus::Pending,
            action_kind: TxActionKind::Erc20Transfer,
            tx_hash: None,
            token: Some(TokenRef {
                address: bloom_proto::checksum_address(&token_address),
                symbol: "ERC20".into(),
                decimals: 0,
                recipient: bloom_proto::checksum_address(&recipient),
                amount: request.amount_base_units.clone(),
                amount_base_units: Some(request.amount_base_units.clone()),
            }),
            nft: None,
            usd_value: None,
            valuation: None,
            depends_on: None,
            action_id: Some(session_id.to_string()),
            execution_origin: None,
        };
        let unsigned = self.build_unsigned_evm_tx(&staged, chain)?;
        let signing_hash = Self::unsigned_signing_hash(&unsigned);
        let signature = self
            .host_sign_evm_owner_session_hash(
                &staged,
                session_id,
                reservation_id,
                request,
                session,
                &signing_hash,
            )
            .await?;
        let signed = self.assemble_signed_raw_tx(&staged, unsigned, signature)?;
        let submitted = self
            .submit_signed_raw(&staged, chain, policy, &signed)
            .await?;
        if matches!(submitted.transport, BroadcastTransport::PublicRpc)
            && submitted.returned_hash != Some(signed.hash)
        {
            return Err(TxEngineError::BroadcastHashMismatch {
                expected: format!("{:#x}", signed.hash),
                returned: submitted
                    .returned_hash
                    .map(|h| format!("{:#x}", h))
                    .unwrap_or_else(|| "<none>".into()),
            });
        }
        Ok(EvmOwnerSessionExecution {
            tx_hash: signed.hash,
            nonce,
            signing_hash,
        })
    }

    /// Execute a sealed action through the first-party dispatcher.
    ///
    /// Dispatch is Petal-neutral: the selected executor is keyed only by the
    /// sealed action header's `(petal_id, petal_digest, subject_kind,
    /// action_kind)`. The current built-in executor is the EVM wallet Petal;
    /// it reconstructs the transaction solely from sealed subject bytes, signs
    /// via the wired `PetalHost`, and broadcasts through the existing TxEngine
    /// transport path.
    pub async fn execute_sealed_action(
        &self,
        sealed: &SealedAction,
        chain_name: &str,
        chain: &ChainClient,
        policy: &Policy,
    ) -> Result<SealedActionExecution, TxEngineError> {
        sealed
            .validate()
            .map_err(|e| TxEngineError::ApprovalState(format!("invalid sealed action: {e}")))?;
        let header = &sealed.envelope.header;
        match (
            sealed.envelope.subject_kind.as_str(),
            header.action_kind.as_str(),
        ) {
            (
                EVM_SEALED_INTENT_SUBJECT_KIND,
                "confirm" | "replace" | "cancel" | "owner_session_use",
            ) => {
                self.execute_evm_wallet_sealed_subject(sealed, chain_name, chain, policy)
                    .await
            }
            (subject_kind, action_kind) => Err(TxEngineError::ApprovalState(format!(
                "no sealed-action executor registered for petal_id={} petal_digest={} subject_kind={subject_kind} action_kind={action_kind}",
                header.petal_id, header.petal_digest,
            ))),
        }
    }

    /// Locate the per-wallet pending outbox entry whose sealed action id
    /// matches `action_id`, if any. Used by the daemon Mode 3 ceremony server
    /// to persist `approval.json` beside the projected challenge.
    pub fn find_pending_entry_dir_for_action(
        &self,
        wallet: &str,
        chain: &str,
        action_id: &str,
    ) -> Option<std::path::PathBuf> {
        self.find_pending_entry_for_action(wallet, chain, action_id)
            .map(|entry| entry.dir)
    }

    fn find_pending_entry_for_action(
        &self,
        wallet: &str,
        chain: &str,
        action_id: &str,
    ) -> Option<crate::outbox::OutboxEntry> {
        let ids = self.outbox.list(wallet, chain, OutboxState::Pending).ok()?;
        for id in ids {
            let Ok(entry) = self.outbox.read(wallet, chain, &id) else {
                continue;
            };
            let staged = &entry.staged;
            let matches = staged.action_id.as_deref() == Some(action_id)
                || [
                    EvmOutboxActionKind::Confirm,
                    EvmOutboxActionKind::Replace,
                    EvmOutboxActionKind::Cancel,
                ]
                .into_iter()
                .any(|kind| outbox_action_id(staged, kind) == action_id);
            if matches {
                return Some(entry);
            }
        }
        None
    }

    fn transition_sealed_wallet_entry_sent(
        &self,
        wallet: &str,
        chain: &str,
        action_id: &str,
        tx_hash: B256,
    ) -> Result<bool, TxEngineError> {
        let Some(entry) = self.find_pending_entry_for_action(wallet, chain, action_id) else {
            return Ok(false);
        };
        let mut staged = entry.staged.clone();
        staged.status = TxStatus::Sent;
        staged.tx_hash = Some(format!("{:#x}", tx_hash));
        let new_dir = self.outbox.transition(&entry, OutboxState::Sent)?;
        self.outbox.write_artefact(
            &new_dir,
            "intent.json",
            &serde_json::to_vec_pretty(&staged).unwrap(),
        )?;
        self.outbox.write_artefact(
            &new_dir,
            "tx_hash",
            staged.tx_hash.as_ref().unwrap().as_bytes(),
        )?;
        Ok(true)
    }

    pub fn project_sealed_action_execute_failure(
        &self,
        sealed: &SealedAction,
        chain_name: &str,
        reason: impl AsRef<str>,
    ) -> Result<(), TxEngineError> {
        let action_id = sealed.action_id();
        let wallet = sealed.wallet();
        let reason = reason.as_ref();
        let transitioned_wallet = if let Some(entry) =
            self.find_pending_entry_for_action(wallet, chain_name, action_id)
        {
            let mut staged = entry.staged.clone();
            staged.status = TxStatus::Failed;
            let new_dir = self.outbox.transition(&entry, OutboxState::Failed)?;
            self.outbox.write_artefact(
                &new_dir,
                "intent.json",
                &serde_json::to_vec_pretty(&staged).unwrap(),
            )?;
            self.outbox.write_artefact(
                &new_dir,
                "result.json",
                &serde_json::to_vec_pretty(&serde_json::json!({
                    "schema": "bloom.evm_execution_result.v1",
                    "action_id": action_id,
                    "state": OutboxState::Failed.dirname(),
                    "outcome": "failed",
                    "error": reason,
                    "created_ms": now_ms(),
                }))
                .unwrap(),
            )?;
            true
        } else {
            false
        };
        if !transitioned_wallet {
            self.outbox.transition_central_action(
                action_id,
                OutboxState::Pending,
                OutboxState::Failed,
            )?;
        }
        self.write_central_evm_failure_result(EvmCentralFailure {
            action_id,
            state: OutboxState::Failed,
            outcome: "failed",
            reason,
        })
    }

    /// Persist `approval.json` for a completed daemon-owned Interaction Mode 3
    /// ceremony beside the projected challenge — the per-wallet pending dir and
    /// the central outbox projection, the same places the challenge is written.
    ///
    /// This is an audit/projection artifact only; it carries the WebAuthn
    /// assertion and echoed challenge fields, never PRF output or key material
    /// (that invariant lives in the [`SignedApproval`] type). The grant is
    /// minted in daemon memory by the caller, not from this file.
    pub fn persist_outbox_ceremony_approval(
        &self,
        sealed: &SealedAction,
        approval: &SignedApproval,
    ) -> Result<(), TxEngineError> {
        let action_id = sealed.action_id();
        let wallet = sealed.wallet();
        // The outbox is keyed by the human chain name ("base"), not the CAIP-2
        // `network` header ("eip155:8453"). Using the header here silently missed
        // the per-wallet entry and dropped approval.json.
        //
        // This method persists into the EVM outbox and is only meaningful for a
        // broadcast action. Callers must not invoke it for non-broadcast
        // first-party actions (wallet-policy updates, policy-session mints),
        // which have no chain and no outbox entry — a missing chain_name here is
        // a caller error, not a routine case.
        let chain_name = sealed.chain_name().ok_or_else(|| {
            TxEngineError::ApprovalState(
                "sealed action is missing chain_name in its policy snapshot".into(),
            )
        })?;
        let body = serde_json::to_vec_pretty(approval)
            .map_err(|e| TxEngineError::ApprovalState(format!("encode approval.json: {e}")))?;
        // Per-wallet pending projection. The entry may legitimately be absent
        // (already transitioned, or the challenge came from another interaction
        // mode) — but a silent miss is what hid the earlier chain-key bug, so we
        // warn loudly when nothing was written here.
        let mut persisted = false;
        if let Some(dir) = self.find_pending_entry_dir_for_action(wallet, chain_name, action_id) {
            std::fs::write(dir.join(OUTBOX_APPROVAL_FILE), &body)
                .map_err(|e| TxEngineError::ApprovalBackend(format!("write approval.json: {e}")))?;
            persisted = true;
        }
        // Central outbox projection, keyed by the sealed action id (same place
        // the challenge is mirrored). No-op when no projection is attached, but
        // a real write error must not be swallowed — a silent allowlist reject
        // is exactly what previously kept approval.json out of the central dir.
        self.outbox.write_central_action_artifact(
            action_id,
            OutboxState::Pending,
            OUTBOX_APPROVAL_FILE,
            &body,
        )?;
        if !persisted {
            tracing::warn!(
                wallet,
                chain = %chain_name,
                action_id,
                "ceremony.approval.no_pending_entry: approval.json not written to a per-wallet pending dir"
            );
        }
        Ok(())
    }

    async fn execute_evm_wallet_sealed_subject(
        &self,
        sealed: &SealedAction,
        chain_name: &str,
        chain: &ChainClient,
        policy: &Policy,
    ) -> Result<SealedActionExecution, TxEngineError> {
        self.ensure_broadcast_allowed(chain.spec())?;
        let subject_bytes = base64::engine::general_purpose::STANDARD
            .decode(sealed.envelope.subject_bytes_b64.as_bytes())
            .map_err(|e| {
                TxEngineError::ApprovalState(format!("decode sealed subject bytes: {e}"))
            })?;
        let subject: EvmSealedIntentSubject = serde_json::from_slice(&subject_bytes)
            .map_err(|e| TxEngineError::ApprovalState(format!("decode EVM sealed subject: {e}")))?;
        subject.validate_evm().map_err(|e| {
            TxEngineError::ApprovalState(format!("invalid EVM sealed subject: {e}"))
        })?;
        self.ensure_evm_subject_matches_seal(sealed, &subject)?;
        if subject.surface == "outbox" {
            self.ensure_evm_subject_matches_persisted_origin(chain_name, &subject)?;
        }
        if chain.spec().chain_id != subject.chain_id {
            return Err(TxEngineError::ApprovalState(format!(
                "sealed action chain mismatch: subject {}, chain {}",
                subject.chain_id,
                chain.spec().chain_id
            )));
        }

        let from: Address = subject
            .account
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        let nonce = match subject.nonce_intent.nonce {
            Some(nonce) => nonce,
            None => chain.nonce(from).await?,
        };
        let gas_limit = subject
            .fee_facts
            .gas_limit
            .parse::<u64>()
            .map_err(|e| TxEngineError::Amount(format!("sealed gas_limit: {e}")))?;
        let staged = StagedTx {
            id: subject.action_id.clone(),
            wallet: subject.wallet.clone(),
            chain: chain_name.to_string(),
            chain_id: subject.chain_id,
            from: bloom_proto::checksum_address(&from),
            to: subject.call.to.clone(),
            value_wei: subject.value.native_value_wei.clone(),
            data_hex: subject.call.calldata_hex.clone(),
            gas_limit,
            max_fee_per_gas: subject.fee_facts.max_fee_per_gas_wei.clone(),
            max_priority_fee_per_gas: subject.fee_facts.max_priority_fee_per_gas_wei.clone(),
            gas_price: subject.fee_facts.gas_price_wei.clone(),
            nonce,
            policy_checks: Vec::new(),
            created_ms: now_ms(),
            expires_ms: u128::from(sealed.expires_ms),
            status: TxStatus::Pending,
            action_kind: if subject.token.is_some() {
                TxActionKind::Erc20Transfer
            } else if subject.authority_change {
                TxActionKind::Approval
            } else if subject.call.method == "native_transfer" {
                TxActionKind::NativeTransfer
            } else {
                TxActionKind::ContractCall
            },
            tx_hash: None,
            token: subject.token.as_ref().map(|token| TokenRef {
                address: token.token_address.clone(),
                symbol: token.symbol.clone(),
                decimals: token.decimals,
                recipient: subject.call.recipient.clone().unwrap_or_default(),
                amount: subject
                    .value
                    .token_amount_base_units
                    .clone()
                    .and_then(|amount| {
                        parse_units(&amount, token.decimals)
                            .ok()
                            .map(|value| format_units(value, token.decimals))
                    })
                    .unwrap_or_else(|| "0".into()),
                amount_base_units: subject.value.token_amount_base_units.clone(),
            }),
            nft: None,
            usd_value: subject
                .value
                .valuation_usd_micro
                .map(|micro| micro as f64 / 1_000_000.0),
            valuation: subject.value.valuation.clone(),
            depends_on: None,
            action_id: Some(subject.action_id.clone()),
            execution_origin: Some(ExecutionOrigin {
                petal_id: subject.petal_id.clone(),
                petal_digest: subject.petal_digest.clone(),
                petal_version: subject.petal_version.clone(),
            }),
        };
        let unsigned = self.build_unsigned_evm_tx(&staged, chain)?;
        let signing_hash = Self::unsigned_signing_hash(&unsigned);
        let sealed_hash: B256 = subject
            .unsigned_envelope
            .signing_hash
            .parse()
            .map_err(|e| TxEngineError::Signer(format!("sealed signing_hash: {e}")))?;
        if signing_hash != sealed_hash {
            return Err(TxEngineError::ApprovalState(
                "sealed subject signing hash does not match reconstructed transaction".into(),
            ));
        }
        let signature = self
            .host_sign_evm_sealed_subject_hash(&subject, &signing_hash)
            .await?;
        let signed = self.assemble_signed_raw_tx(&staged, unsigned, signature)?;
        // Same broadcast-time nonce-gap guard as the confirm path: never emit a
        // sealed tx that the node would queue behind a missing nonce.
        self.assert_nonce_not_ahead_of_chain(chain, from, nonce)
            .await?;
        let submitted = self
            .submit_signed_raw(&staged, chain, policy, &signed)
            .await?;
        if matches!(submitted.transport, BroadcastTransport::PublicRpc)
            && submitted.returned_hash != Some(signed.hash)
        {
            return Err(TxEngineError::BroadcastHashMismatch {
                expected: format!("{:#x}", signed.hash),
                returned: submitted
                    .returned_hash
                    .map(|h| format!("{:#x}", h))
                    .unwrap_or_else(|| "<none>".into()),
            });
        }
        if !self.transition_sealed_wallet_entry_sent(
            &subject.wallet,
            chain_name,
            &subject.action_id,
            signed.hash,
        )? {
            self.outbox.transition_central_action(
                &subject.action_id,
                OutboxState::Pending,
                OutboxState::Sent,
            )?;
        }
        self.write_central_evm_result(EvmCentralResult {
            action_id: &subject.action_id,
            state: OutboxState::Sent,
            outcome: "sent",
            tx_hash: signed.hash,
            nonce,
            signing_hash: &signing_hash,
            action_kind: subject.action_kind.as_str(),
        })?;
        Ok(SealedActionExecution {
            action_id: subject.action_id,
            petal_id: subject.petal_id,
            petal_digest: subject.petal_digest,
            action_kind: subject.action_kind.as_str().into(),
            tx_hash: signed.hash,
            nonce,
            signing_hash,
        })
    }

    fn ensure_evm_subject_matches_seal(
        &self,
        sealed: &SealedAction,
        subject: &EvmSealedIntentSubject,
    ) -> Result<(), TxEngineError> {
        let header = &sealed.envelope.header;
        let subject_envelope = subject.canonical_envelope(sealed.expires_ms).map_err(|e| {
            TxEngineError::ApprovalConstruction(format!("rebuild sealed EVM envelope: {e}"))
        })?;
        let subject_hash = subject_envelope.intent_hash().map_err(|e| {
            TxEngineError::ApprovalConstruction(format!("hash sealed EVM envelope: {e}"))
        })?;
        let sealed_hash = sealed
            .intent_hash()
            .map_err(|e| TxEngineError::ApprovalConstruction(format!("hash sealed action: {e}")))?;
        if subject_hash != sealed_hash || subject_envelope != sealed.envelope {
            return Err(TxEngineError::ApprovalState(
                "sealed subject bytes do not reproduce the sealed action envelope".into(),
            ));
        }
        let expected = [
            ("wallet", subject.wallet.as_str(), header.wallet.as_str()),
            ("surface", subject.surface.as_str(), header.surface.as_str()),
            (
                "action_id",
                subject.action_id.as_str(),
                header.action_id.as_str(),
            ),
            (
                "petal_id",
                subject.petal_id.as_str(),
                header.petal_id.as_str(),
            ),
            (
                "petal_digest",
                subject.petal_digest.as_str(),
                header.petal_digest.as_str(),
            ),
            (
                "petal_version",
                subject.petal_version.as_str(),
                header.petal_version.as_str(),
            ),
            ("account", subject.account.as_str(), header.account.as_str()),
            (
                "action_kind",
                subject.action_kind.as_str(),
                header.action_kind.as_str(),
            ),
        ];
        for (field, actual, expected) in expected {
            if actual != expected {
                return Err(TxEngineError::ApprovalState(format!(
                    "sealed {field} mismatch: subject={actual} header={expected}"
                )));
            }
        }
        if sealed.daemon_terms != subject.daemon_terms {
            return Err(TxEngineError::ApprovalState(
                "sealed daemon terms do not match EVM subject".into(),
            ));
        }
        if sealed.petal_policy != subject.policy_snapshot {
            return Err(TxEngineError::ApprovalState(
                "sealed Petal policy does not match EVM subject".into(),
            ));
        }
        Ok(())
    }

    fn ensure_evm_subject_matches_persisted_origin(
        &self,
        chain_name: &str,
        subject: &EvmSealedIntentSubject,
    ) -> Result<(), TxEngineError> {
        let entry = self
            .find_pending_entry_for_action(&subject.wallet, chain_name, &subject.action_id)
            .ok_or_else(|| {
                TxEngineError::ApprovalState(
                    "sealed EVM action has no pending staged transaction with persisted execution origin"
                        .into(),
                )
            })?;
        let origin = entry.staged.resolved_execution_origin();
        origin.validate().map_err(TxEngineError::ApprovalState)?;
        for (field, expected, actual) in [
            (
                "petal_id",
                origin.petal_id.as_str(),
                subject.petal_id.as_str(),
            ),
            (
                "petal_digest",
                origin.petal_digest.as_str(),
                subject.petal_digest.as_str(),
            ),
            (
                "petal_version",
                origin.petal_version.as_str(),
                subject.petal_version.as_str(),
            ),
        ] {
            if expected != actual {
                return Err(TxEngineError::ApprovalState(format!(
                    "sealed EVM {field} does not match persisted execution origin: sealed={actual} persisted={expected}"
                )));
            }
        }
        Ok(())
    }

    async fn host_sign_evm_sealed_subject_hash(
        &self,
        subject: &EvmSealedIntentSubject,
        signing_hash: &B256,
    ) -> Result<Signature, TxEngineError> {
        #[cfg(feature = "unsafe-debug-signer")]
        if let Some(signer) = self.unsafe_debug_signer(&subject.wallet) {
            return signer
                .sign_hash_sync(signing_hash)
                .map_err(|e| TxEngineError::Signer(format!("debug sign hash: {e}")));
        }
        let host = self.petal_host.as_ref().ok_or_else(|| {
            TxEngineError::ApprovalServiceUnavailable(
                "Sealed Approval Petal host is not wired".into(),
            )
        })?;
        let attestation = subject
            .signing_attestation_facts()
            .signing_attestation()
            .map_err(|e| {
                TxEngineError::ApprovalConstruction(format!(
                    "build EVM sealed signing attestation: {e}"
                ))
            })?;
        let sealed = host
            .sign_hash(
                SignHashRequest {
                    wallet: subject.wallet.clone(),
                    action_id: subject.action_id.clone(),
                    intent: EVM_TX_SIGN_INTENT.into(),
                    hash_hex: format!("{signing_hash:#x}"),
                },
                &attestation,
                now_ms() as u64,
            )
            .await
            .map_err(|e| TxEngineError::ApprovalBackend(format!("host sign_hash denied: {e}")))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sealed.signature_b64.as_bytes())
            .map_err(|e| TxEngineError::Signer(format!("decode host signature: {e}")))?;
        Signature::from_raw(&raw).map_err(|e| TxEngineError::Signer(format!("host signature: {e}")))
    }

    async fn host_sign_evm_hash(
        &self,
        staged: &StagedTx,
        action_kind: EvmOutboxActionKind,
        signing_hash: B256,
    ) -> Result<Signature, TxEngineError> {
        #[cfg(feature = "unsafe-debug-signer")]
        if let Some(signer) = self.unsafe_debug_signer(&staged.wallet) {
            return signer
                .sign_hash_sync(&signing_hash)
                .map_err(|e| TxEngineError::Signer(format!("debug sign hash: {e}")));
        }
        let host = self.petal_host.as_ref().ok_or_else(|| {
            TxEngineError::ApprovalServiceUnavailable(
                "Sealed Approval Petal host is not wired".into(),
            )
        })?;
        let action_id = outbox_action_id(staged, action_kind);
        let hash_hex = format!("{signing_hash:#x}");
        let attestation = evm_signing_attestation(staged, action_kind, &signing_hash)?;
        let sealed = host
            .sign_hash(
                SignHashRequest {
                    wallet: staged.wallet.clone(),
                    action_id,
                    intent: "evm.tx.sign".into(),
                    hash_hex,
                },
                &attestation,
                now_ms() as u64,
            )
            .await
            .map_err(|e| TxEngineError::ApprovalBackend(format!("host sign_hash denied: {e}")))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sealed.signature_b64.as_bytes())
            .map_err(|e| TxEngineError::Signer(format!("decode host signature: {e}")))?;
        Signature::from_raw(&raw).map_err(|e| TxEngineError::Signer(format!("host signature: {e}")))
    }

    async fn host_sign_evm_owner_session_hash(
        &self,
        staged: &StagedTx,
        session_id: &str,
        reservation_id: &str,
        request: &EvmOwnerSigningSessionUse,
        session: &StandingSessionRecord,
        signing_hash: &B256,
    ) -> Result<Signature, TxEngineError> {
        #[cfg(feature = "unsafe-debug-signer")]
        if let Some(signer) = self.unsafe_debug_signer(&staged.wallet) {
            return signer
                .sign_hash_sync(signing_hash)
                .map_err(|e| TxEngineError::Signer(format!("debug sign hash: {e}")));
        }
        let host = self.petal_host.as_ref().ok_or_else(|| {
            TxEngineError::ApprovalServiceUnavailable(
                "Sealed Approval Petal host is not wired".into(),
            )
        })?;
        let hash_hex = format!("{signing_hash:#x}");
        let attestation = evm_owner_session_signing_attestation(
            staged,
            session_id,
            reservation_id,
            request,
            session,
            signing_hash,
        )?;
        let sealed = host
            .sign_hash(
                SignHashRequest {
                    wallet: staged.wallet.clone(),
                    action_id: session_id.to_string(),
                    intent: EVM_TX_SIGN_INTENT.into(),
                    hash_hex,
                },
                &attestation,
                now_ms() as u64,
            )
            .await
            .map_err(|e| TxEngineError::ApprovalBackend(format!("host sign_hash denied: {e}")))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sealed.signature_b64.as_bytes())
            .map_err(|e| TxEngineError::Signer(format!("decode host signature: {e}")))?;
        Signature::from_raw(&raw).map_err(|e| TxEngineError::Signer(format!("host signature: {e}")))
    }

    fn ensure_broadcast_allowed(&self, spec: &ChainSpec) -> Result<(), TxEngineError> {
        if !spec.allow_broadcast {
            return Err(TxEngineError::BroadcastDisabled(spec.name.clone()));
        }
        Ok(())
    }

    /// Refuse to broadcast when a same-chain dependency has not mined
    /// successfully. Both "not yet confirmed" and "reverted/failed" are hard
    /// refusals: broadcasting a dependent tx before its predecessor confirms
    /// is precisely the footgun this guards against.
    fn ensure_dependency_satisfied(
        &self,
        wallet: &str,
        chain: &str,
        dep_id: &str,
    ) -> Result<(), TxEngineError> {
        let reject = |reason: &str| {
            Err(TxEngineError::DependencyNotSatisfied {
                dep_id: dep_id.to_string(),
                reason: reason.to_string(),
            })
        };
        let entry = match self.outbox.read(wallet, chain, dep_id) {
            Ok(e) => e,
            Err(OutboxError::NotFound(_)) => return reject("predecessor not found in the outbox"),
            Err(e) => return Err(e.into()),
        };
        match entry.state {
            crate::outbox::OutboxState::Failed => reject("predecessor failed or was cancelled"),
            crate::outbox::OutboxState::Pending => {
                reject("predecessor is still pending (not broadcast)")
            }
            crate::outbox::OutboxState::Sent => {
                match self.outbox.read_receipt(wallet, chain, dep_id)? {
                    Some(r) if r.is_success() => Ok(()),
                    Some(r) => {
                        let detail = r
                            .revert_reason
                            .map(|s| format!(": {s}"))
                            .unwrap_or_default();
                        Err(TxEngineError::DependencyNotSatisfied {
                            dep_id: dep_id.to_string(),
                            reason: format!("predecessor reverted{detail}"),
                        })
                    }
                    None => reject("predecessor broadcast but not yet confirmed"),
                }
            }
        }
    }

    /// `eth_call` the staged tx against current state; reject on revert. RPC
    /// failures simulating are non-fatal (don't block broadcast on infra).
    async fn simulate_or_reject(
        &self,
        staged: &StagedTx,
        chain: &ChainClient,
    ) -> Result<(), TxEngineError> {
        let from: Address = staged
            .from
            .parse()
            .map_err(|_| TxEngineError::Address(staged.from.clone()))?;
        let to: Address = staged
            .to
            .parse()
            .map_err(|_| TxEngineError::Address(staged.to.clone()))?;
        let value = U256::from_str_radix(&staged.value_wei, 10).unwrap_or(U256::ZERO);
        let data = staged.data_hex.parse::<Bytes>().unwrap_or_default();
        let req = TransactionRequest::default()
            .from(from)
            .to(to)
            .value(value)
            .input(data.into());
        match chain.eth_call_capture_revert(req, None).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(returndata)) => Err(TxEngineError::SimulationReverted {
                reason: crate::reconcile::decode_revert(&returndata),
            }),
            Err(e) => {
                debug!(id = %staged.id, error = %e, "tx.simulate_unavailable");
                Ok(())
            }
        }
    }

    async fn ensure_action_authorized(
        &self,
        entry: &crate::outbox::OutboxEntry,
        staged: &StagedTx,
        action_kind: EvmOutboxActionKind,
        signing_hash: &B256,
        policy: &Policy,
        surface: bloom_proto::AuthorizationSurface,
    ) -> Result<(), TxEngineError> {
        let subject = self.authorization_subject(staged);
        let budget = match self.budget_snapshot(staged) {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                tracing::warn!(
                    wallet = %staged.wallet,
                    id = %staged.id,
                    %error,
                    "tx.budget_ledger_unavailable_requires_review"
                );
                None
            }
        };
        let initial = bloom_proto::evaluate_action_authorization(
            policy,
            &staged.policy_checks,
            &subject,
            budget.as_ref(),
            None,
            surface.clone(),
        );
        match initial {
            bloom_proto::AutonomyDecision::ApprovedAutonomous { .. }
            | bloom_proto::AutonomyDecision::ApprovedFreshReview { .. }
            | bloom_proto::AutonomyDecision::NeedsFreshReview { .. } => {}
            bloom_proto::AutonomyDecision::ApprovedCapability { .. } => {
                return Err(TxEngineError::ApprovalDenied(
                    "scoped run capabilities are not implemented; fresh review required".into(),
                ));
            }
            bloom_proto::AutonomyDecision::Denied { reason } => {
                return Err(TxEngineError::ApprovalDenied(reason));
            }
        }

        #[cfg(feature = "unsafe-debug-signer")]
        if self.unsafe_debug_signer(&staged.wallet).is_some() {
            tracing::warn!(
                wallet = %staged.wallet,
                action = action_kind.action_kind(),
                "tx.unsafe_debug_approval_bypass"
            );
            return Ok(());
        }

        if self.approval_verifier.is_none()
            || self.auth_writer.is_none()
            || self.grant_store.is_none()
            || self.petal_host.is_none()
        {
            return Err(TxEngineError::ApprovalServiceUnavailable(
                "outbox confirm requires Sealed Approval; \
                 auth/grant/host services are not wired (marker fallback removed)"
                    .into(),
            ));
        }
        let sealed_approval_intent_hash = Some(
            self.ensure_sealed_outbox_approval(entry, staged, action_kind, signing_hash)
                .await?,
        );
        match bloom_proto::evaluate_action_authorization(
            policy,
            &staged.policy_checks,
            &subject,
            budget.as_ref(),
            sealed_approval_intent_hash.as_deref(),
            surface,
        ) {
            bloom_proto::AutonomyDecision::ApprovedFreshReview { .. }
            | bloom_proto::AutonomyDecision::ApprovedAutonomous { .. } => Ok(()),
            // Scoped run capabilities are NOT implemented: no evaluator produces
            // this decision today, so accepting it would be a latent
            // broadcast-authorization gap if a producer is ever added without
            // re-reviewing this path. Fail closed until the system actually lands.
            bloom_proto::AutonomyDecision::ApprovedCapability { .. } => {
                Err(TxEngineError::ApprovalDenied(
                    "scoped run capabilities are not implemented; fresh review required".into(),
                ))
            }
            bloom_proto::AutonomyDecision::NeedsFreshReview { reason }
            | bloom_proto::AutonomyDecision::Denied { reason } => {
                Err(TxEngineError::ApprovalDenied(reason))
            }
        }
    }

    async fn ensure_sealed_outbox_approval(
        &self,
        entry: &crate::outbox::OutboxEntry,
        staged: &StagedTx,
        action_kind: EvmOutboxActionKind,
        signing_hash: &B256,
    ) -> Result<String, TxEngineError> {
        let verifier = self.approval_verifier.as_ref().ok_or_else(|| {
            TxEngineError::ApprovalServiceUnavailable(
                "Sealed Approval verifier is not wired".into(),
            )
        })?;
        let writer = self.auth_writer.as_ref().ok_or_else(|| {
            TxEngineError::ApprovalServiceUnavailable(
                "Sealed Approval auth store writer is not wired".into(),
            )
        })?;
        let grant_store = self.grant_store.as_ref().ok_or_else(|| {
            TxEngineError::ApprovalServiceUnavailable(
                "Sealed Approval grant store is not wired".into(),
            )
        })?;
        let action_id = outbox_action_id(staged, action_kind);
        let execution_origin = staged.resolved_execution_origin();
        execution_origin
            .validate()
            .map_err(TxEngineError::ApprovalState)?;
        if grant_store
            .get_active(
                &staged.wallet,
                &action_id,
                &execution_origin.petal_id,
                &execution_origin.petal_digest,
                now_ms() as u64,
            )
            .await
            .map_err(|e| TxEngineError::ApprovalBackend(format!("read active grant: {e}")))?
            .is_some()
        {
            return outbox_canonical_envelope(staged, action_kind, signing_hash)?
                .intent_hash()
                .map_err(|e| {
                    TxEngineError::ApprovalConstruction(format!("hash sealed outbox action: {e}"))
                });
        }

        let subject = evm_sealed_subject(staged, action_kind, signing_hash)?;
        let envelope = subject
            .canonical_envelope(u64::try_from(staged.expires_ms).unwrap_or(u64::MAX))
            .map_err(|e| {
                TxEngineError::ApprovalConstruction(format!("build EVM sealed envelope: {e}"))
            })?;
        let action = SealedAction::new(
            envelope,
            format!(
                "{} {}:{} nonce {}",
                action_kind.action_kind(),
                staged.chain,
                staged.id,
                staged.nonce
            ),
            Vec::new(),
            subject.daemon_terms.clone(),
            subject.policy_snapshot.clone(),
            now_ms() as u64,
        )
        .map_err(|e| {
            TxEngineError::ApprovalConstruction(format!("seal outbox action failed: {e}"))
        })?;
        let intent_hash = action.envelope.intent_hash().map_err(|e| {
            TxEngineError::ApprovalConstruction(format!("hash sealed outbox action: {e}"))
        })?;
        let auth_entry = writer
            .stage_action(action, now_ms() as u64)
            .await
            .map_err(|e| {
                TxEngineError::ApprovalBackend(format!("stage outbox auth entry failed: {e}"))
            })?;
        if matches!(
            auth_entry.state,
            AuthEntryState::Approved | AuthEntryState::Submitting
        ) && auth_entry.nonce_state == NonceState::Consumed
        {
            return Ok(auth_entry.intent_hash);
        }
        let approval_path = entry.dir.join(OUTBOX_APPROVAL_FILE);
        if approval_path.exists() {
            let approval_body = std::fs::read(&approval_path)
                .map_err(|e| TxEngineError::ApprovalState(format!("read approval.json: {e}")))?;
            let approval: SignedApproval = serde_json::from_slice(&approval_body).map_err(|e| {
                TxEngineError::ApprovalState(format!("stored approval.json is invalid: {e}"))
            })?;
            let verification = verifier
                .verify_and_mint_grant(approval, grant_store.as_ref(), now_ms() as u64)
                .await;
            match verification {
                Ok(_) => return Ok(intent_hash),
                Err(bloom_auth_api::AuthApiError::Denied(reason))
                    if reason == "approval expired" =>
                {
                    // A completed browser ceremony can expire before the caller
                    // retries confirm. Do not pin the outbox entry to that stale
                    // approval forever: discard only the expired response and
                    // fall through to issue a fresh challenge for the exact same
                    // sealed action. Other verification failures remain fatal.
                    std::fs::remove_file(&approval_path).map_err(|e| {
                        TxEngineError::ApprovalBackend(format!("remove expired approval.json: {e}"))
                    })?;
                }
                Err(e) => {
                    return Err(TxEngineError::ApprovalDenied(format!(
                        "Sealed Approval rejected: {e}"
                    )));
                }
            }
        }

        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        let challenge = writer
            .issue_challenge(
                "outbox",
                &auth_entry.action_id,
                &nonce,
                (now_ms() as u64).saturating_add(OUTBOX_APPROVAL_TTL_MS),
                now_ms() as u64,
            )
            .await
            .map_err(|e| {
                TxEngineError::ApprovalBackend(format!(
                    "issue outbox approval challenge failed: {e}"
                ))
            })?
            .with_local_ceremony_url();
        let challenge_body = serde_json::to_vec_pretty(&challenge).map_err(|e| {
            TxEngineError::ApprovalConstruction(format!("encode approval challenge: {e}"))
        })?;
        std::fs::write(
            entry.dir.join(OUTBOX_APPROVAL_CHALLENGE_FILE),
            &challenge_body,
        )
        .map_err(|e| TxEngineError::ApprovalBackend(format!("write approval challenge: {e}")))?;
        if let Some(central_action_id) = staged.action_id.as_deref() {
            self.outbox
                .write_central_pending_artifact(
                    central_action_id,
                    OUTBOX_APPROVAL_CHALLENGE_FILE,
                    &challenge_body,
                )
                .map_err(|e| {
                    TxEngineError::ApprovalBackend(format!("write central approval challenge: {e}"))
                })?;
        }
        Err(TxEngineError::ApprovalRequired(ApprovalRequirement {
            action_id: challenge.action_id,
            ceremony_url: challenge
                .ceremony_url
                .unwrap_or_else(|| "unavailable".into()),
            expires_ms: challenge.expiry_ms,
            reason: format!(
                "outbox confirm requires signed Sealed Approval; wrote {} in {}; rerun the foreground confirm/write command with the passkey wallet to sign approval.json. local password wallets can only auto-confirm actions that remain in policy",
                OUTBOX_APPROVAL_CHALLENGE_FILE,
                entry.dir.display()
            ),
        }))
    }

    fn authorization_subject(&self, staged: &StagedTx) -> bloom_proto::AuthorizationSubject {
        let value_wei = U256::from_str_radix(&staged.value_wei, 10).unwrap_or(U256::ZERO);
        let data_nonempty = staged
            .data_hex
            .trim_start_matches("0x")
            .bytes()
            .any(|b| b != b'0');
        let value_moving = match staged.action_kind {
            bloom_proto::TxActionKind::NativeTransfer => value_wei > U256::ZERO,
            bloom_proto::TxActionKind::Erc20Transfer => true,
            bloom_proto::TxActionKind::Unknown
            | bloom_proto::TxActionKind::ContractCall
            | bloom_proto::TxActionKind::Approval
            | bloom_proto::TxActionKind::NftTransfer => {
                value_wei > U256::ZERO
                    || staged.token.is_some()
                    || staged.nft.is_some()
                    || data_nonempty
            }
        };
        let calldata_verified = matches!(
            staged.action_kind,
            bloom_proto::TxActionKind::NativeTransfer | bloom_proto::TxActionKind::Erc20Transfer
        );
        let authority_change = matches!(staged.action_kind, bloom_proto::TxActionKind::Approval);
        let total_value_usd_micro = staged
            .valuation
            .as_ref()
            .filter(|quote| {
                quote
                    .validate_for_authorization(&ValuationPolicy::default(), now_ms() as u64)
                    .is_ok()
            })
            .map(|quote| quote.usd_micro);
        bloom_proto::AuthorizationSubject {
            kind: "evm_tx".into(),
            wallet: staged.wallet.clone(),
            chain: Some(staged.chain.clone()),
            subject_hash: format!(
                "{}:{}:{}:{}:{}:{}:{}",
                staged.chain_id,
                staged.from,
                staged.to,
                staged.value_wei,
                staged.data_hex,
                staged.nonce,
                staged.id
            ),
            total_value_usd_micro,
            value_moving,
            // Only the typed native/ERC-20 transfer paths have verified asset
            // and amount facts. Generic calldata remains review-only.
            calldata_verified,
            authority_change,
        }
    }

    fn budget_snapshot(
        &self,
        staged: &StagedTx,
    ) -> Result<bloom_proto::BudgetSnapshot, TxEngineError> {
        const DAY_MS: u128 = 24 * 60 * 60 * 1000;
        const WEEK_MS: u128 = 7 * DAY_MS;
        const MONTH_MS: u128 = 30 * DAY_MS;
        let now = now_ms();
        let day = self.outbox.sum_usd_since(
            &staged.wallet,
            now.saturating_sub(DAY_MS),
            Some((&staged.chain, &staged.id)),
        )?;
        let week = self.outbox.sum_usd_since(
            &staged.wallet,
            now.saturating_sub(WEEK_MS),
            Some((&staged.chain, &staged.id)),
        )?;
        let month = self.outbox.sum_usd_since(
            &staged.wallet,
            now.saturating_sub(MONTH_MS),
            Some((&staged.chain, &staged.id)),
        )?;
        Ok(bloom_proto::BudgetSnapshot {
            spent_day_micro_usd: f64_to_micro_usd(day).unwrap_or(i128::MAX),
            spent_week_micro_usd: f64_to_micro_usd(week).unwrap_or(i128::MAX),
            spent_month_micro_usd: f64_to_micro_usd(month).unwrap_or(i128::MAX),
        })
    }

    #[cfg(test)]
    async fn broadcast(
        &self,
        staged: &StagedTx,
        chain: &ChainClient,
        signer: &PrivateKeySigner,
        policy: &Policy,
    ) -> Result<B256, TxEngineError> {
        let signed = self.build_signed_raw_tx(staged, chain, signer).await?;
        self.submit_signed_raw(staged, chain, policy, &signed)
            .await?;
        Ok(signed.hash)
    }

    fn read_replaceable_entry(
        &self,
        wallet: &str,
        chain_name: &str,
        original_id: &str,
    ) -> Result<crate::outbox::OutboxEntry, TxEngineError> {
        match self
            .outbox
            .read_in_state(wallet, chain_name, original_id, OutboxState::Pending)
        {
            Ok(entry) => Ok(entry),
            Err(OutboxError::StateMismatch { actual: "sent", .. }) => {
                let entry = self.outbox.read_in_state(
                    wallet,
                    chain_name,
                    original_id,
                    OutboxState::Sent,
                )?;
                if matches!(entry.staged.status, TxStatus::Sent) {
                    Ok(entry)
                } else {
                    Err(TxEngineError::InvalidTxStatus {
                        id: original_id.to_string(),
                        status: format!("{:?}", entry.staged.status),
                    })
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Issue a same-nonce replacement tx with bumped fees. The original
    /// must already be persisted in the outbox and be either still staged
    /// in `pending/` or broadcast-but-unmined in `sent/`. Floors `bump_pct`
    /// at 10 to satisfy the mempool's >= 10% rule.
    #[allow(clippy::too_many_arguments)]
    pub async fn replace(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        chain_name: &str,
        original_id: &str,
        chain: &ChainClient,
        bump_pct: u32,
        policy: &Policy,
    ) -> Result<StagedTx, TxEngineError> {
        self.replace_with_intent(
            permit,
            wallet,
            chain_name,
            original_id,
            chain,
            bump_pct,
            None,
            None,
            policy,
        )
        .await
    }

    /// Same-nonce replacement that optionally substitutes the calldata
    /// (fix #10 carry-over). When `substitute` is `Some(intent)`, the
    /// new (`to`, `value`, `data`) are derived from it via the same
    /// encoding pipeline `stage` uses, but the original nonce is
    /// preserved. Fees are bumped at least `bump_pct%` (floored at 10).
    /// Enso-flavoured intents are rejected here for the same reason
    /// they're rejected in stage — they go through the enso petal's HTTP path.
    #[allow(clippy::too_many_arguments)]
    pub async fn replace_with_intent(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        chain_name: &str,
        original_id: &str,
        chain: &ChainClient,
        bump_pct: u32,
        substitute: Option<RawIntent>,
        address_book: Option<&AddressBook>,
        policy: &Policy,
    ) -> Result<StagedTx, TxEngineError> {
        self.assert_write_permit(permit)?;
        let bump = bump_pct.max(10);
        let entry = self.read_replaceable_entry(wallet, chain_name, original_id)?;
        let original = &entry.staged;

        let mut bumped = original.clone();
        bumped.status = TxStatus::Pending;
        bumped.tx_hash = None;

        if let Some(intent) = substitute.as_ref() {
            let chain_id = chain.chain_id().await?;
            // The `from` passed here must match the original wallet
            // address; recover it from the original staged tx so NFT
            // transfer calldata stays correct under same-nonce
            // substitution.
            let from: Address = original
                .from
                .parse()
                .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
            let (to, value_wei, data_hex, token, nft) = self
                .resolve_intent_body(&intent.body, chain, chain_id, address_book, from)
                .await?;
            bumped.to = bloom_proto::checksum_address(&to);
            bumped.value_wei = value_wei.to_string();
            bumped.data_hex = data_hex;
            bumped.token = token;
            bumped.nft = nft;
            // Substituted replacements are hard-denied below; classify a
            // non-token send conservatively because this path does not stage
            // a fresh destination-code fact.
            bumped.action_kind = classify_action_kind(&intent.body, bumped.token.is_some(), true);
            // A substituted body is currently hard-denied below. Do not
            // leave the original quote attached to the replacement facts.
            bumped.usd_value = None;
            bumped.valuation = None;
            bumped.policy_checks.push(bloom_proto::PolicyCheck::hard(
                "replacement.substitute",
                bloom_proto::PolicyOutcome::Deny,
                "same-nonce replacement with substituted to/value/data is disabled; stage a fresh transaction instead",
            ));
        }
        bump_fees_in_place(&mut bumped, bump);
        let unsigned = self.build_unsigned_evm_tx(&bumped, chain)?;
        let prepared = PreparedEvmTx {
            signing_hash: Self::unsigned_signing_hash(&unsigned),
            unsigned,
        };
        self.ensure_action_authorized(
            &entry,
            &bumped,
            EvmOutboxActionKind::Replace,
            &prepared.signing_hash,
            policy,
            bloom_proto::AuthorizationSurface::Cli,
        )
        .await?;

        let tx_hash = self
            .submit_with_marker(
                &entry,
                EvmOutboxActionKind::Replace,
                &bumped,
                chain,
                policy,
                prepared,
            )
            .await?;
        bumped.tx_hash = Some(format!("{:#x}", tx_hash));
        bumped.status = TxStatus::Sent;

        self.outbox.write_artefact(
            &entry.dir,
            "replacement_tx_hash",
            bumped.tx_hash.as_ref().unwrap().as_bytes(),
        )?;
        self.outbox.write_artefact(
            &entry.dir,
            "replacement_intent.json",
            &serde_json::to_vec_pretty(&bumped).unwrap(),
        )?;
        let _ = self
            .outbox
            .remove_broadcast_raw_tx(&entry, BroadcastAttemptKind::Replacement);
        info!(
            id = %original.id,
            replacement = %bumped.tx_hash.as_deref().unwrap_or(""),
            substituted = substitute.is_some(),
            "tx.replace"
        );
        Ok(bumped)
    }

    /// Issue a same-nonce self-send to cancel the original. The original
    /// must be either still staged in `pending/` or broadcast-but-unmined in
    /// `sent/`.
    #[allow(clippy::too_many_arguments)]
    pub async fn cancel(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        chain_name: &str,
        original_id: &str,
        chain: &ChainClient,
        bump_pct: u32,
        policy: &Policy,
    ) -> Result<StagedTx, TxEngineError> {
        self.assert_write_permit(permit)?;
        let bump = bump_pct.max(10);
        let entry = self.read_replaceable_entry(wallet, chain_name, original_id)?;
        let original = &entry.staged;

        let mut cancel_tx = cancellation_candidate(original)?;
        bump_fees_in_place(&mut cancel_tx, bump);
        let unsigned = self.build_unsigned_evm_tx(&cancel_tx, chain)?;
        let prepared = PreparedEvmTx {
            signing_hash: Self::unsigned_signing_hash(&unsigned),
            unsigned,
        };
        self.ensure_action_authorized(
            &entry,
            &cancel_tx,
            EvmOutboxActionKind::Cancel,
            &prepared.signing_hash,
            policy,
            bloom_proto::AuthorizationSurface::Cli,
        )
        .await?;

        let tx_hash = self
            .submit_with_marker(
                &entry,
                EvmOutboxActionKind::Cancel,
                &cancel_tx,
                chain,
                policy,
                prepared,
            )
            .await?;
        cancel_tx.tx_hash = Some(format!("{:#x}", tx_hash));
        cancel_tx.status = TxStatus::Cancelled;

        self.outbox.write_artefact(
            &entry.dir,
            "cancel_tx_hash",
            cancel_tx.tx_hash.as_ref().unwrap().as_bytes(),
        )?;
        self.outbox.write_artefact(
            &entry.dir,
            "cancel_intent.json",
            &serde_json::to_vec_pretty(&cancel_tx).unwrap(),
        )?;
        let _ = self
            .outbox
            .remove_broadcast_raw_tx(&entry, BroadcastAttemptKind::CancelReplacement);
        if entry.state != OutboxState::Failed
            && let Err(e) = self.outbox.transition(&entry, OutboxState::Failed)
        {
            debug!(
                id = %original.id,
                error = %e,
                "tx.cancel_transition_failed"
            );
        }
        info!(
            id = %original.id,
            cancel = %cancel_tx.tx_hash.as_deref().unwrap_or(""),
            "tx.cancel"
        );
        Ok(cancel_tx)
    }
}

fn cancellation_candidate(original: &StagedTx) -> Result<StagedTx, TxEngineError> {
    let from_addr: Address = original
        .from
        .parse()
        .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
    let mut cancel = original.clone();
    cancel.status = TxStatus::Pending;
    cancel.tx_hash = None;
    cancel.to = bloom_proto::checksum_address(&from_addr);
    cancel.value_wei = "0".into();
    cancel.data_hex = "0x".into();
    cancel.gas_limit = 21_000;
    cancel.action_kind = TxActionKind::NativeTransfer;
    cancel.token = None;
    cancel.nft = None;
    cancel.usd_value = None;
    cancel.valuation = None;
    cancel.policy_checks.clear();
    Ok(cancel)
}

/// Bump fee fields by `pct%` (rounded up by ≥ 1 wei). Whichever set is
/// populated — 1559 or legacy — gets bumped.
fn bump_fees_in_place(staged: &mut StagedTx, pct: u32) {
    fn bump_one(s: &Option<String>, pct: u32) -> Option<String> {
        s.as_deref().and_then(|x| {
            let v = x.parse::<u128>().ok()?;
            let bump = v.saturating_mul(pct as u128) / 100;
            let bumped = v.saturating_add(bump.max(1));
            Some(bumped.to_string())
        })
    }
    if let Some(b) = bump_one(&staged.max_fee_per_gas, pct) {
        staged.max_fee_per_gas = Some(b);
    }
    if let Some(b) = bump_one(&staged.max_priority_fee_per_gas, pct) {
        staged.max_priority_fee_per_gas = Some(b);
    }
    if let Some(b) = bump_one(&staged.gas_price, pct) {
        staged.gas_price = Some(b);
    }
}

fn decode_data(s: &str) -> Result<Bytes, TxEngineError> {
    let s = s.trim();
    if s.is_empty() || s == "0x" {
        return Ok(Bytes::new());
    }
    let s = s.strip_prefix("0x").unwrap_or(s);
    let v = hex::decode(s).map_err(|e| TxEngineError::Amount(format!("data: {e}")))?;
    Ok(Bytes::from(v))
}

/// Parse the Enso quote age in seconds from calldata, if present.
/// Enso appends a raw JSON blob starting with `{"Source":"Enso` to every
/// route calldata. Returns `None` for non-Enso calldata or parse failures.
fn enso_quote_age_secs(data_hex: &str, now_secs: u64) -> Option<u64> {
    let bytes = hex::decode(data_hex.trim_start_matches("0x")).ok()?;
    const MARKER: &[u8] = b"{\"Source\":\"Enso";
    let pos = bytes.windows(MARKER.len()).position(|w| w == MARKER)?;
    // Marker found — try to extract timestamp.
    let v: serde_json::Value = match serde_json::Deserializer::from_slice(&bytes[pos..])
        .into_iter()
        .next()
    {
        Some(Ok(val)) => val,
        other => {
            tracing::warn!(?other, "enso.calldata.marker_found_parse_failed");
            return None;
        }
    };
    let ts = match v["Timestamp"].as_u64() {
        Some(t) => t,
        None => {
            tracing::warn!(enso_json = %v, "enso.calldata.timestamp_missing");
            return None;
        }
    };
    now_secs.checked_sub(ts).or_else(|| {
        tracing::warn!(enso_ts = ts, now = now_secs, "enso.quote.future_timestamp");
        None
    })
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn outbox_action_id(staged: &StagedTx, action_kind: EvmOutboxActionKind) -> String {
    match action_kind {
        EvmOutboxActionKind::Confirm => staged
            .action_id
            .clone()
            .unwrap_or_else(|| format!("{}:{}", staged.chain_id, staged.id)),
        EvmOutboxActionKind::Replace => format!("{}:{}:replace", staged.chain_id, staged.id),
        EvmOutboxActionKind::Cancel => format!("{}:{}:cancel", staged.chain_id, staged.id),
    }
}

fn outbox_canonical_envelope(
    staged: &StagedTx,
    action_kind: EvmOutboxActionKind,
    signing_hash: &B256,
) -> Result<CanonicalEnvelope, TxEngineError> {
    evm_sealed_subject(staged, action_kind, signing_hash)?
        .canonical_envelope(u64::try_from(staged.expires_ms).unwrap_or(u64::MAX))
        .map_err(|e| TxEngineError::ApprovalConstruction(format!("build EVM sealed envelope: {e}")))
}

fn evm_signing_attestation(
    staged: &StagedTx,
    action_kind: EvmOutboxActionKind,
    signing_hash: &B256,
) -> Result<SigningAttestation, TxEngineError> {
    evm_sealed_subject(staged, action_kind, signing_hash)?
        .signing_attestation_facts()
        .signing_attestation()
        .map_err(|e| {
            TxEngineError::ApprovalConstruction(format!("build EVM signing attestation: {e}"))
        })
}

fn evm_owner_session_signing_attestation(
    staged: &StagedTx,
    session_id: &str,
    reservation_id: &str,
    request: &EvmOwnerSigningSessionUse,
    session: &StandingSessionRecord,
    signing_hash: &B256,
) -> Result<SigningAttestation, TxEngineError> {
    evm_owner_session_sealed_subject(
        staged,
        session_id,
        reservation_id,
        request,
        session,
        signing_hash,
    )?
    .signing_attestation_facts()
    .signing_attestation()
    .map_err(|e| {
        TxEngineError::ApprovalConstruction(format!(
            "build EVM owner-session signing attestation: {e}"
        ))
    })
}

fn evm_fee_facts(staged: &StagedTx) -> EvmFeeFacts {
    let (tx_type, gas_price_wei, max_fee_per_gas_wei, max_priority_fee_per_gas_wei) =
        if let Some(gas_price) = staged.gas_price.clone() {
            ("legacy", Some(gas_price), None, None)
        } else {
            (
                "eip1559",
                None,
                Some(staged.max_fee_per_gas.clone().unwrap_or_else(|| "0".into())),
                Some(
                    staged
                        .max_priority_fee_per_gas
                        .clone()
                        .unwrap_or_else(|| "0".into()),
                ),
            )
        };
    EvmFeeFacts {
        tx_type: tx_type.into(),
        gas_limit: staged.gas_limit.to_string(),
        max_fee_per_gas_wei,
        max_priority_fee_per_gas_wei,
        gas_price_wei,
        max_total_fee_wei: None,
    }
}

fn evm_owner_session_sealed_subject(
    staged: &StagedTx,
    session_id: &str,
    reservation_id: &str,
    request: &EvmOwnerSigningSessionUse,
    session: &StandingSessionRecord,
    signing_hash: &B256,
) -> Result<EvmSealedIntentSubject, TxEngineError> {
    let scope: EvmOwnerSigningSessionScope = serde_json::from_value(session.scope.clone())
        .map_err(|e| TxEngineError::ApprovalState(format!("parse owner-session scope: {e}")))?;
    let signing_hash_hex = format!("{signing_hash:#x}");
    let calldata = decode_data(&staged.data_hex)?;
    let calldata_hash = format!("0x{}", blake3::hash(&calldata).to_hex());
    let unsigned_tx_bytes_hash = format!("0x{}", blake3::hash(signing_hash.as_ref()).to_hex());
    let fee_facts = evm_fee_facts(staged);
    let token = staged.token.as_ref().map(|t| EvmTokenFact {
        chain_id: staged.chain_id,
        token_address: t.address.clone(),
        symbol: t.symbol.clone(),
        decimals: t.decimals,
    });
    let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Hardened);
    terms.allowed_sign_intents = vec![EVM_TX_SIGN_INTENT.into()];
    terms.max_signatures = scope.max_signature_count;
    terms.max_ttl_secs = scope.ttl_ms / 1000;
    terms.extra.insert(
        "evm.action_kind".into(),
        serde_json::json!(EVM_OWNER_SESSION_USE_ACTION_KIND),
    );
    terms.extra.insert(
        "evm.signing_hash_source".into(),
        serde_json::json!("sealed_evm_owner_session_unsigned_tx"),
    );
    terms
        .extra
        .insert("signer_cache_required".into(), serde_json::json!(true));

    let scope_value = serde_json::to_value(&scope).map_err(|e| {
        TxEngineError::ApprovalConstruction(format!("serialize owner-session scope: {e}"))
    })?;
    let scope_map = scope_value
        .as_object()
        .ok_or_else(|| {
            TxEngineError::ApprovalConstruction(
                "owner-session scope did not serialize as object".into(),
            )
        })?
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut caps = BTreeMap::new();
    caps.insert(
        "daily_cap_base_units".into(),
        serde_json::json!(scope.daily_cap_base_units),
    );
    caps.insert(
        "max_signature_count".into(),
        serde_json::json!(scope.max_signature_count),
    );
    let mut config = BTreeMap::new();
    config.insert("chain_id".into(), serde_json::json!(scope.chain_id));
    config.insert(
        "token_contract".into(),
        serde_json::json!(scope.token_contract),
    );
    config.insert("recipient".into(), serde_json::json!(scope.recipient));
    config.insert("method".into(), serde_json::json!(scope.method));
    let mut budget_state = BTreeMap::new();
    budget_state.insert("reservation_id".into(), serde_json::json!(reservation_id));
    budget_state.insert(
        "amount_base_units".into(),
        serde_json::json!(request.amount_base_units),
    );
    let policy_snapshot = PetalPolicySnapshot {
        policy_version: session.frozen_policy_version,
        wallet: staged.wallet.clone(),
        petal_id: PETAL_ID_EVM_WALLET.into(),
        petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
        caps,
        hard_rules: Vec::new(),
        step_up_rules: Vec::new(),
        config,
        budget_state,
        session_scope: Some(scope_map),
    };
    let policy_snapshot_digest = policy_snapshot.petal_policy_digest().map_err(|e| {
        TxEngineError::ApprovalConstruction(format!(
            "digest EVM owner-session policy snapshot: {e}"
        ))
    })?;
    let daemon_terms_digest = terms.daemon_terms_digest().map_err(|e| {
        TxEngineError::ApprovalConstruction(format!("digest EVM owner-session daemon terms: {e}"))
    })?;

    Ok(EvmSealedIntentSubject {
        schema: EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1.into(),
        action_id: session_id.to_string(),
        wallet: staged.wallet.clone(),
        surface: "policy-session".into(),
        petal_id: PETAL_ID_EVM_WALLET.into(),
        petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
        petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
        action_kind: EvmSealedActionKind::OwnerSessionUse,
        chain_id: staged.chain_id,
        account: staged.from.clone(),
        call: EvmCallFact {
            to: staged.to.clone(),
            recipient: Some(scope.recipient.clone()),
            calldata_hex: staged.data_hex.clone(),
            calldata_hash,
            method: EVM_ERC20_TRANSFER_METHOD.into(),
        },
        value: EvmValueFact {
            native_value_wei: "0".into(),
            token_amount_base_units: Some(request.amount_base_units.clone()),
            valuation_usd_micro: None,
            valuation: None,
        },
        token,
        nonce_intent: EvmNonceIntent {
            mode: "exact".into(),
            nonce: Some(staged.nonce),
            original_action_id: None,
        },
        fee_facts,
        replacement_fee_facts: None,
        unsigned_envelope: EvmUnsignedEnvelopeFacts {
            envelope_kind: if staged.gas_price.is_some() {
                "legacy".into()
            } else {
                "eip1559".into()
            },
            unsigned_tx_bytes_hash,
            signing_hash: signing_hash_hex,
        },
        original_tx: None,
        owner_session_use: Some(EvmOwnerSessionUseFact {
            session_id: session_id.to_string(),
            reservation_id: reservation_id.to_string(),
            token_address: scope.token_contract,
            recipient: scope.recipient,
            daily_cap_base_units: scope.daily_cap_base_units,
            expires_ms: session.expires_ms,
            max_signature_count: scope.max_signature_count,
        }),
        policy_snapshot_digest,
        policy_snapshot,
        daemon_terms: terms,
        daemon_terms_digest,
        authority_change: false,
    })
}

fn evm_sealed_subject(
    staged: &StagedTx,
    action_kind: EvmOutboxActionKind,
    signing_hash: &B256,
) -> Result<EvmSealedIntentSubject, TxEngineError> {
    let signing_hash_hex = format!("{signing_hash:#x}");
    let calldata = decode_data(&staged.data_hex)?;
    let calldata_hash = format!("0x{}", blake3::hash(&calldata).to_hex());
    let unsigned_tx_bytes_hash = format!("0x{}", blake3::hash(signing_hash.as_ref()).to_hex());
    let fee_facts = evm_fee_facts(staged);
    let token = staged.token.as_ref().map(|t| EvmTokenFact {
        chain_id: staged.chain_id,
        token_address: t.address.clone(),
        symbol: t.symbol.clone(),
        decimals: t.decimals,
    });
    let approval = matches!(staged.action_kind, TxActionKind::Approval);
    // Approval facts are deliberately kept separate from transfer metadata:
    // `to` is the token contract, `recipient` is the spender, and the token
    // amount field binds the exact allowance (including uint256 max).
    let recipient = if approval {
        decode_approve_spender(&calldata).map(|spender| bloom_proto::checksum_address(&spender))
    } else {
        staged
            .token
            .as_ref()
            .map(|t| t.recipient.clone())
            .or_else(|| (staged.to != "0x").then(|| staged.to.clone()))
    };
    let token_amount_base_units = if approval {
        decode_approve_amount(&calldata).map(|amount| amount.to_string())
    } else {
        staged
            .token
            .as_ref()
            .map(|t| {
                t.amount_base_units
                    .as_deref()
                    .map_or_else(
                        || parse_units(&t.amount, t.decimals),
                        |amount| parse_units(amount, 0),
                    )
                    .map(|amount| amount.to_string())
                    .map_err(|e| TxEngineError::Amount(format!("token amount: {e}")))
            })
            .transpose()?
    };
    let method = if matches!(action_kind, EvmOutboxActionKind::Cancel) {
        "cancel"
    } else {
        match staged.action_kind {
            TxActionKind::NativeTransfer => "native_transfer",
            TxActionKind::Erc20Transfer => bloom_auth_api::EVM_ERC20_TRANSFER_METHOD,
            TxActionKind::Approval => "approval",
            TxActionKind::NftTransfer => "nft_transfer",
            TxActionKind::ContractCall => "contract_call",
            TxActionKind::Unknown => "unknown",
        }
    };
    let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Standard);
    terms.allowed_sign_intents = vec![bloom_auth_api::EVM_TX_SIGN_INTENT.into()];
    terms.max_signatures = 1;
    terms.extra.insert(
        "evm.action_kind".into(),
        serde_json::json!(action_kind.action_kind()),
    );
    terms.extra.insert(
        "evm.signing_hash_source".into(),
        serde_json::json!("sealed_evm_unsigned_tx"),
    );
    let execution_origin = staged.resolved_execution_origin();
    execution_origin
        .validate()
        .map_err(TxEngineError::ApprovalState)?;

    let mut policy_snapshot = PetalPolicySnapshot {
        policy_version: 0,
        wallet: staged.wallet.clone(),
        petal_id: execution_origin.petal_id.clone(),
        petal_digest: execution_origin.petal_digest.clone(),
        caps: BTreeMap::new(),
        hard_rules: Vec::new(),
        step_up_rules: Vec::new(),
        config: BTreeMap::new(),
        budget_state: BTreeMap::new(),
        session_scope: None,
    };
    policy_snapshot.budget_state.insert(
        "staged_usd_value".into(),
        serde_json::json!(staged.usd_value),
    );
    policy_snapshot
        .config
        .insert("chain_name".into(), serde_json::json!(staged.chain.clone()));
    policy_snapshot.budget_state.insert(
        "policy_checks".into(),
        serde_json::json!(staged.policy_checks),
    );
    let policy_snapshot_digest = policy_snapshot.petal_policy_digest().map_err(|e| {
        TxEngineError::ApprovalConstruction(format!("digest EVM policy snapshot: {e}"))
    })?;
    let daemon_terms_digest = terms.daemon_terms_digest().map_err(|e| {
        TxEngineError::ApprovalConstruction(format!("digest EVM daemon terms: {e}"))
    })?;
    let original_tx = if matches!(
        action_kind,
        EvmOutboxActionKind::Replace | EvmOutboxActionKind::Cancel
    ) {
        staged.tx_hash.as_ref().map(|hash| EvmOriginalTxFact {
            original_action_id: format!("{}:{}", staged.chain_id, staged.id),
            original_tx_hash: hash.clone(),
            original_nonce: Some(staged.nonce),
        })
    } else {
        None
    };

    Ok(EvmSealedIntentSubject {
        schema: EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1.into(),
        action_id: outbox_action_id(staged, action_kind),
        wallet: staged.wallet.clone(),
        surface: "outbox".into(),
        petal_id: execution_origin.petal_id,
        petal_digest: execution_origin.petal_digest,
        petal_version: execution_origin.petal_version,
        action_kind: action_kind.sealed_action_kind(),
        chain_id: staged.chain_id,
        account: staged.from.clone(),
        call: EvmCallFact {
            to: staged.to.clone(),
            recipient,
            calldata_hex: staged.data_hex.clone(),
            calldata_hash,
            method: method.into(),
        },
        value: EvmValueFact {
            native_value_wei: staged.value_wei.clone(),
            token_amount_base_units,
            valuation_usd_micro: staged.valuation.as_ref().map(|quote| quote.usd_micro),
            valuation: staged.valuation.clone(),
        },
        token,
        nonce_intent: EvmNonceIntent {
            mode: "exact".into(),
            nonce: Some(staged.nonce),
            original_action_id: matches!(
                action_kind,
                EvmOutboxActionKind::Replace | EvmOutboxActionKind::Cancel
            )
            .then(|| format!("{}:{}", staged.chain_id, staged.id)),
        },
        fee_facts: fee_facts.clone(),
        replacement_fee_facts: matches!(
            action_kind,
            EvmOutboxActionKind::Replace | EvmOutboxActionKind::Cancel
        )
        .then_some(fee_facts),
        unsigned_envelope: EvmUnsignedEnvelopeFacts {
            envelope_kind: if staged.gas_price.is_some() {
                "legacy".into()
            } else {
                "eip1559".into()
            },
            unsigned_tx_bytes_hash,
            signing_hash: signing_hash_hex,
        },
        original_tx,
        owner_session_use: None,
        policy_snapshot_digest,
        policy_snapshot,
        daemon_terms: terms,
        daemon_terms_digest,
        authority_change: matches!(staged.action_kind, TxActionKind::Approval),
    })
}

fn f64_to_micro_usd(v: f64) -> Option<i128> {
    if !v.is_finite() || v < 0.0 {
        return None;
    }
    let micro = (v * 1_000_000.0).round();
    if micro > i128::MAX as f64 {
        None
    } else {
        Some(micro as i128)
    }
}

#[allow(clippy::too_many_arguments)]
fn insufficient_native_funds_check(
    account: &str,
    chain: &str,
    native_symbol: &str,
    native_decimals: u8,
    available: U256,
    value: U256,
    gas_limit: u64,
    fee_cap_per_gas: u128,
) -> Option<bloom_proto::PolicyCheck> {
    let gas_budget = U256::from(gas_limit).saturating_mul(U256::from(fee_cap_per_gas));
    let required = value.saturating_add(gas_budget);
    if available >= required {
        return None;
    }

    let available_display = bloom_proto::format_units(available, native_decimals);
    let required_display = bloom_proto::format_units(required, native_decimals);
    let value_display = bloom_proto::format_units(value, native_decimals);
    let gas_display = bloom_proto::format_units(gas_budget, native_decimals);
    Some(bloom_proto::PolicyCheck::hard(
        "balance.native_funds",
        bloom_proto::PolicyOutcome::Deny,
        format!(
            "account {account} has {available_display} {native_symbol} on {chain}; \
             requires up to {required_display} {native_symbol} \
             ({value_display} value + {gas_display} gas at the staged fee cap). \
             Fund the account and restage this transaction before approving."
        ),
    ))
}

/// Approve amount: accepts `"max"` (alias for 2^256 - 1) or a decimal
/// integer string. Empty falls through to max so the common case
/// (`{"kind":"approve","token":"…","spender":"…"}`) doesn't require a
/// magic constant.
fn parse_approve_amount(s: &str) -> Result<U256, String> {
    let t = s.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("max") {
        return Ok(U256::MAX);
    }
    U256::from_str_radix(t, 10).map_err(|e| format!("invalid uint256 '{s}': {e}"))
}

/// Pull the `spender` argument out of an `approve(address,uint256)`
/// calldata blob. Returns `None` if the buffer doesn't decode as an
/// approve call — the caller treats that as "no spender hint" and
/// policy contexts fall back to the default recipient.
fn decode_approve_spender(data: &[u8]) -> Option<Address> {
    match IERC20::approveCall::abi_decode(data) {
        Ok(c) => Some(c.spender),
        Err(e) => {
            debug!(
                error = %e,
                data_len = data.len(),
                "tx.decode_approve_spender_failed"
            );
            None
        }
    }
}

/// Pull the exact allowance out of an `approve(address,uint256)` calldata
/// blob. Failure is intentionally represented as `None`; the sealed subject
/// then remains review-only without inventing an approval amount.
fn decode_approve_amount(data: &[u8]) -> Option<U256> {
    IERC20::approveCall::abi_decode(data)
        .ok()
        .map(|call| call.amount)
}

/// Pull the recipient out of an NFT transfer calldata blob. Tries the
/// ERC-721 3-arg form first, then the 1155 5-arg form; falls back to
/// the legacy `transferFrom` shape last.
fn decode_nft_recipient(data: &[u8]) -> Option<Address> {
    let e_721 = match INftWrite721::safeTransferFromCall::abi_decode(data) {
        Ok(c) => return Some(c.to),
        Err(e) => e,
    };
    let e_1155 = match INftWrite1155::safeTransferFromCall::abi_decode(data) {
        Ok(c) => return Some(c.to),
        Err(e) => e,
    };
    let e_legacy = match INftWrite721::transferFromCall::abi_decode(data) {
        Ok(c) => return Some(c.to),
        Err(e) => e,
    };
    debug!(
        data_len = data.len(),
        err_721 = %e_721,
        err_1155 = %e_1155,
        err_legacy = %e_legacy,
        "tx.decode_nft_recipient_no_match"
    );
    None
}

/// Pull the operator out of an ERC-721 `approve(address,uint256)`
/// calldata blob (ABI-distinct from ERC-20's `approve(address,uint256)`
/// — both selectors are `0x095ea7b3`, so we use the field name `to`
/// rather than `spender` to match the NFT shape).
fn decode_nft_approve_operator(data: &[u8]) -> Option<Address> {
    match INftWrite721::approveCall::abi_decode(data) {
        Ok(c) => Some(c.to),
        Err(e) => {
            debug!(
                error = %e,
                data_len = data.len(),
                "tx.decode_nft_approve_operator_failed"
            );
            None
        }
    }
}

/// Stringify an `NftKind` for plan/audit display.
fn nft_kind_label(kind: NftKind) -> String {
    match kind {
        NftKind::Erc721 => "erc721".into(),
        NftKind::Erc1155 => "erc1155".into(),
        NftKind::Unknown => "unknown".into(),
    }
}

/// Best-effort `ERC-721 symbol()` lookup, falling back to the empty
/// string. Failure to resolve must never block staging — the plan
/// renders the bare contract address in that case.
async fn best_effort_nft_symbol(chain: &ChainClient, contract: Address) -> String {
    match chain.erc721_symbol(contract).await {
        Ok(Some(s)) if !s.is_empty() => s,
        Ok(Some(_)) => {
            debug!(%contract, "tx.nft_symbol_empty");
            String::new()
        }
        Ok(None) => {
            debug!(%contract, "tx.nft_symbol_absent");
            String::new()
        }
        Err(e) => {
            debug!(%contract, error = %e, "tx.nft_symbol_failed");
            String::new()
        }
    }
}

/// Decimal or `0x`-hex `uint256` parser shared by NFT calldata helpers.
fn parse_u256(s: &str) -> Result<U256, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty".into());
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return U256::from_str_radix(hex, 16).map_err(|e| format!("invalid hex uint256: {e}"));
    }
    U256::from_str_radix(t, 10).map_err(|e| format!("invalid uint256 '{s}': {e}"))
}

fn short_addr_label(a: &Address) -> String {
    let s = format!("{a:#x}");
    if s.len() > 10 {
        format!("{}…{}", &s[..6], &s[s.len() - 4..])
    } else {
        s
    }
}

/// Resolve a common ERC-20 symbol to its address via the shared
/// `bloom_proto::tokens` table (the single source of truth across the send
/// path, route path, and VFS token surface). Anvil mainnet forks share chain
/// id 31337 with vanilla Anvil, so they reuse the Ethereum (id 1) majors; a
/// caller can always pass a 0x address explicitly.
fn lookup_known_token(chain_id: u64, symbol_upper: &str) -> Option<&'static str> {
    let lookup_chain = if chain_id == 31337 { 1 } else { chain_id };
    let hit = bloom_proto::tokens::resolve_symbol(lookup_chain, symbol_upper).map(|t| t.address);
    if hit.is_none() {
        debug!(chain_id, symbol = symbol_upper, "tx.known_token_miss");
    }
    hit
}

const _PARSE_UNITS: fn(&str, u8) -> Result<U256, bloom_proto::units::UnitError> = parse_units;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use bloom_auth_api::{
        APPROVAL_CHALLENGE_SCHEMA_V1, APPROVAL_SCHEMA_V1, ApprovalChallenge, AuditEvent,
        AuthApiError, AuthEntryRecord, AuthEntryState, ExecutorKind, NonceState,
        SealedApprovalGrant, SealedPetalContext, SignerTransport, SigningAttestationSchemaRegistry,
        WebAuthnAssertionRecord,
    };
    use bloom_proto::TxStatus;

    const TEST_SIGNER_PK: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const TEST_SIGNER_ADDRESS: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    fn test_signer() -> alloy::signers::local::PrivateKeySigner {
        TEST_SIGNER_PK
            .parse()
            .expect("valid deterministic test key")
    }

    #[derive(Clone)]
    struct RecordingOracle {
        calls: Arc<parking_lot::Mutex<Vec<(String, String)>>>,
        usd_micro: i128,
        age_ms: u64,
        max_age_ms: u64,
    }

    #[async_trait::async_trait]
    impl bloom_auth_api::PriceOracle for RecordingOracle {
        async fn quote_usd(
            &self,
            asset_id: &str,
            amount_base_units: &str,
            _asset_decimals: u8,
            now_ms: u64,
        ) -> Result<bloom_auth_api::ValuationQuote, bloom_auth_api::AuthApiError> {
            self.calls
                .lock()
                .push((asset_id.to_string(), amount_base_units.to_string()));
            let fetched_at_ms = now_ms.saturating_sub(self.age_ms).max(1);
            Ok(bloom_auth_api::ValuationQuote {
                asset_id: asset_id.to_string(),
                amount_base_units: amount_base_units.to_string(),
                usd_micro: self.usd_micro,
                source: "test-oracle".into(),
                quote_timestamp_ms: fetched_at_ms,
                fetched_at_ms,
                max_age_ms: self.max_age_ms,
                confidence_ppm: None,
                stablecoin_assumption: false,
            })
        }
    }

    /// A small JSON-RPC fixture for stage() tests. Keeping this local to the
    /// tx crate makes the valuation tests independent of a running node and
    /// exercises the complete chain/session/nonce/gas/balance path.
    async fn spawn_stage_rpc(include_code: bool) -> String {
        use std::net::SocketAddr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let responses = Arc::new(parking_lot::Mutex::new(stage_rpc_responses(include_code)));
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let responses = responses.clone();
                tokio::spawn(async move {
                    let mut bytes = Vec::with_capacity(16 * 1024);
                    let mut chunk = [0u8; 4096];
                    let body = loop {
                        let read = match socket.read(&mut chunk).await {
                            Ok(0) => return,
                            Ok(read) => read,
                            Err(_) => return,
                        };
                        bytes.extend_from_slice(&chunk[..read]);
                        let Some(header_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let headers = String::from_utf8_lossy(&bytes[..header_end]);
                        let content_length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.trim()
                                    .eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        let body_start = header_end + 4;
                        while bytes.len() < body_start + content_length {
                            let read = match socket.read(&mut chunk).await {
                                Ok(0) => return,
                                Ok(read) => read,
                                Err(_) => return,
                            };
                            bytes.extend_from_slice(&chunk[..read]);
                        }
                        break String::from_utf8_lossy(
                            &bytes[body_start..body_start + content_length],
                        )
                        .to_string();
                    };

                    let request: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    let id = request.get("id").cloned().unwrap_or(serde_json::json!(1));
                    let method = request
                        .get("method")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let result = responses.lock().get_mut(&method).and_then(|queue| {
                        if queue.is_empty() {
                            None
                        } else {
                            Some(queue.remove(0))
                        }
                    });
                    let response_body = match result {
                        Some(result) => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
                            serde_json::to_string(&id).unwrap(),
                            result
                        ),
                        None => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32601,\"message\":\"unmocked method: {}\"}}}}",
                            serde_json::to_string(&id).unwrap(),
                            method
                        ),
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response_body.len(),
                        response_body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        format!("http://{addr}")
    }

    fn stage_rpc_responses(include_code: bool) -> HashMap<String, Vec<String>> {
        let zero32 = format!("0x{}", "00".repeat(32));
        let zero8 = "0x0000000000000000";
        let zero_addr = format!("0x{}", "00".repeat(20));
        let zero_bloom = format!("0x{}", "00".repeat(256));
        let block = serde_json::json!({
            "number": "0x64",
            "hash": format!("0x{}", "11".repeat(32)),
            "parentHash": zero32,
            "sha3Uncles": zero32,
            "logsBloom": zero_bloom,
            "transactionsRoot": zero32,
            "stateRoot": zero32,
            "receiptsRoot": zero32,
            "miner": zero_addr,
            "difficulty": "0x0",
            "totalDifficulty": "0x0",
            "extraData": "0x",
            "size": "0x0",
            "gasLimit": "0x0",
            "gasUsed": "0x0",
            "timestamp": "0x0",
            "uncles": [],
            "transactions": [],
            "mixHash": zero32,
            "nonce": zero8,
            "baseFeePerGas": "0x0"
        })
        .to_string();
        let mut responses = HashMap::from([
            ("eth_chainId".into(), vec!["\"0x7a69\"".into()]),
            ("eth_getBlockByNumber".into(), vec![block]),
            ("eth_getTransactionCount".into(), vec!["\"0x0\"".into()]),
            ("eth_gasPrice".into(), vec!["\"0x3b9aca00\"".into()]),
            ("eth_estimateGas".into(), vec!["\"0x5208\"".into()]),
            (
                "eth_getBalance".into(),
                vec!["\"0x3635c9adc5dea00000\"".into()],
            ),
        ]);
        if include_code {
            responses.insert("eth_getCode".into(), vec!["\"0x\"".into()]);
        }
        responses
    }

    fn stage_chain(url: &str) -> ChainClient {
        let spec = ChainSpec {
            name: "anvil".into(),
            chain_id: 31337,
            rpc_urls: vec![url.into()],
            rpc_endpoints: Vec::new(),
            allow_broadcast: true,
            etherscan_api_url: None,
            display_name: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            legacy_tx: false,
            op_stack: false,
        };
        ChainClient::new(spec).unwrap()
    }

    fn stage_fixture(
        url: &str,
        oracle: RecordingOracle,
    ) -> (TxEngine, tempfile::TempDir, HomeWritePermit, ChainClient) {
        let dir = tempfile::tempdir().unwrap();
        let outbox = crate::outbox::Outbox::new(dir.path().join("outbox")).unwrap();
        let engine = TxEngine::new(outbox, 60_000).with_price_oracle(Arc::new(oracle));
        let permit = permit_for(&dir);
        let chain = stage_chain(url);
        (engine, dir, permit, chain)
    }

    fn policy_with_usd_cap() -> Policy {
        let mut policy = Policy::default();
        policy.caps.per_tx_usd = Some(10_000.0);
        policy
    }

    fn under_policy_with_usd_limits() -> Policy {
        let mut policy = policy_with_usd_cap();
        policy.approval.agent_autonomy = Some(bloom_proto::AgentAutonomyMode::UnderPolicy);
        policy.limits.max_tx_usd = Some("100".into());
        policy.limits.max_day_usd = Some("100".into());
        policy
    }

    fn native_intent(value: &str, usd_hint: Option<&str>) -> RawIntent {
        RawIntent {
            body: RawIntentBody::Send {
                to: "0x2222222222222222222222222222222222222222".into(),
                value: value.into(),
                token: None,
                amount: String::new(),
                data: None,
            },
            chain: Some("anvil".into()),
            gas: bloom_proto::intent::GasStrategy::Auto,
            nonce: None,
            gas_limit_hint: None,
            usd_value_hint: usd_hint.map(str::to_string),
        }
    }

    #[test]
    fn native_send_to_contract_is_not_typed_as_transfer() {
        let body = RawIntentBody::Send {
            to: "0x2222222222222222222222222222222222222222".into(),
            value: "1 eth".into(),
            token: None,
            amount: String::new(),
            data: None,
        };
        assert_eq!(
            classify_action_kind(&body, false, true),
            TxActionKind::ContractCall
        );
        assert_eq!(
            classify_action_kind(&body, false, false),
            TxActionKind::NativeTransfer
        );
    }

    #[tokio::test]
    async fn stage_native_transfer_uses_bound_oracle_value_not_hint() {
        let url = spawn_stage_rpc(true).await;
        let oracle = RecordingOracle {
            calls: Arc::new(parking_lot::Mutex::new(Vec::new())),
            usd_micro: 42_000_000,
            age_ms: 0,
            max_age_ms: 60_000,
        };
        let calls = oracle.calls.clone();
        let (engine, _dir, permit, chain) = stage_fixture(&url, oracle);
        let staged = engine
            .stage(
                &permit,
                "alice",
                "0x1111111111111111111111111111111111111111"
                    .parse()
                    .unwrap(),
                native_intent("1 eth", Some("999999")),
                &chain,
                &policy_with_usd_cap(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(staged.action_kind, TxActionKind::NativeTransfer);
        assert_eq!(staged.value_wei, "1000000000000000000");
        assert_eq!(staged.usd_value, Some(42.0));
        let quote = staged.valuation.as_ref().unwrap();
        assert_eq!(quote.asset_id, "native:anvil");
        assert_eq!(quote.amount_base_units, "1000000000000000000");
        assert_eq!(quote.usd_micro, 42_000_000);
        assert_eq!(
            calls.lock().as_slice(),
            &[("native:anvil".into(), "1000000000000000000".into())]
        );
    }

    #[tokio::test]
    async fn stage_erc20_transfer_uses_exact_base_units_for_oracle() {
        let url = spawn_stage_rpc(false).await;
        let oracle = RecordingOracle {
            calls: Arc::new(parking_lot::Mutex::new(Vec::new())),
            usd_micro: 1_250_000,
            age_ms: 0,
            max_age_ms: 60_000,
        };
        let calls = oracle.calls.clone();
        let (engine, _dir, permit, chain) = stage_fixture(&url, oracle);
        let token_addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        engine.token_cache.write().insert(
            (31337, token_addr),
            TokenMeta {
                address: token_addr,
                symbol: "USDC".into(),
                decimals: 6,
            },
        );
        let intent = RawIntent {
            body: RawIntentBody::Send {
                to: "0x2222222222222222222222222222222222222222".into(),
                value: String::new(),
                token: Some(token_addr.to_string()),
                amount: "1.25 usdc".into(),
                data: None,
            },
            chain: Some("anvil".into()),
            gas: bloom_proto::intent::GasStrategy::Auto,
            nonce: None,
            gas_limit_hint: None,
            usd_value_hint: None,
        };
        let staged = engine
            .stage(
                &permit,
                "alice",
                "0x3333333333333333333333333333333333333333"
                    .parse()
                    .unwrap(),
                intent,
                &chain,
                &policy_with_usd_cap(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(staged.action_kind, TxActionKind::Erc20Transfer);
        let token = staged.token.as_ref().unwrap();
        assert_eq!(token.amount, "1.25");
        assert_eq!(token.amount_base_units.as_deref(), Some("1250000"));
        let quote = staged.valuation.as_ref().unwrap();
        assert_eq!(quote.asset_id, format!("anvil:{}", token.address));
        assert_eq!(quote.amount_base_units, "1250000");
        let subject = engine.authorization_subject(&staged);
        assert!(subject.calldata_verified);
        assert_eq!(subject.total_value_usd_micro, Some(1_250_000));
        assert_eq!(calls.lock().len(), 1);
        assert_eq!(calls.lock()[0].1, "1250000");
    }

    #[tokio::test]
    async fn fresh_native_valuation_can_satisfy_under_policy_authorization() {
        let url = spawn_stage_rpc(true).await;
        let oracle = RecordingOracle {
            calls: Arc::new(parking_lot::Mutex::new(Vec::new())),
            usd_micro: 42_000_000,
            age_ms: 0,
            max_age_ms: 60_000,
        };
        let (engine, _dir, permit, chain) = stage_fixture(&url, oracle);
        let policy = under_policy_with_usd_limits();
        let staged = engine
            .stage(
                &permit,
                "alice",
                "0x1111111111111111111111111111111111111111"
                    .parse()
                    .unwrap(),
                native_intent("1 eth", None),
                &chain,
                &policy,
                None,
            )
            .await
            .unwrap();
        let subject = engine.authorization_subject(&staged);
        let decision = bloom_proto::evaluate_action_authorization(
            &policy,
            &staged.policy_checks,
            &subject,
            Some(&bloom_proto::BudgetSnapshot {
                spent_day_micro_usd: 0,
                spent_week_micro_usd: 0,
                spent_month_micro_usd: 0,
            }),
            None,
            bloom_proto::AuthorizationSurface::Cli,
        );
        assert!(matches!(
            decision,
            bloom_proto::AutonomyDecision::ApprovedAutonomous {
                debit_micro_usd: 42_000_000,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn stage_discards_stale_oracle_quote() {
        let url = spawn_stage_rpc(true).await;
        let oracle = RecordingOracle {
            calls: Arc::new(parking_lot::Mutex::new(Vec::new())),
            usd_micro: 42_000_000,
            age_ms: 10_000,
            max_age_ms: 100,
        };
        let (engine, _dir, permit, chain) = stage_fixture(&url, oracle);
        let staged = engine
            .stage(
                &permit,
                "alice",
                "0x1111111111111111111111111111111111111111"
                    .parse()
                    .unwrap(),
                native_intent("1 eth", None),
                &chain,
                &policy_with_usd_cap(),
                None,
            )
            .await
            .unwrap();

        assert!(staged.valuation.is_none());
        assert!(staged.usd_value.is_none());
        let policy = under_policy_with_usd_limits();
        let subject = engine.authorization_subject(&staged);
        let decision = bloom_proto::evaluate_action_authorization(
            &policy,
            &staged.policy_checks,
            &subject,
            Some(&bloom_proto::BudgetSnapshot {
                spent_day_micro_usd: 0,
                spent_week_micro_usd: 0,
                spent_month_micro_usd: 0,
            }),
            None,
            bloom_proto::AuthorizationSurface::Cli,
        );
        assert!(!matches!(
            decision,
            bloom_proto::AutonomyDecision::ApprovedAutonomous { .. }
        ));
    }

    #[tokio::test]
    async fn stage_does_not_value_generic_calldata() {
        let url = spawn_stage_rpc(false).await;
        let oracle = RecordingOracle {
            calls: Arc::new(parking_lot::Mutex::new(Vec::new())),
            usd_micro: 42_000_000,
            age_ms: 0,
            max_age_ms: 60_000,
        };
        let calls = oracle.calls.clone();
        let (engine, _dir, permit, chain) = stage_fixture(&url, oracle);
        let intent = RawIntent {
            body: RawIntentBody::Raw {
                to: "0x2222222222222222222222222222222222222222".into(),
                value: String::new(),
                data: "0x12345678".into(),
            },
            chain: Some("anvil".into()),
            gas: bloom_proto::intent::GasStrategy::Auto,
            nonce: None,
            gas_limit_hint: None,
            usd_value_hint: Some("999999".into()),
        };
        let staged = engine
            .stage(
                &permit,
                "alice",
                "0x1111111111111111111111111111111111111111"
                    .parse()
                    .unwrap(),
                intent,
                &chain,
                &policy_with_usd_cap(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(staged.action_kind, TxActionKind::ContractCall);
        assert!(staged.valuation.is_none());
        assert!(calls.lock().is_empty());
        assert!(!engine.authorization_subject(&staged).calldata_verified);
    }

    #[tokio::test]
    async fn stage_enso_route_values_exact_input_without_trusting_hint() {
        let url = spawn_stage_rpc(false).await;
        let oracle = RecordingOracle {
            calls: Arc::new(parking_lot::Mutex::new(Vec::new())),
            usd_micro: 7_500_000,
            age_ms: 0,
            max_age_ms: 60_000,
        };
        let calls = oracle.calls.clone();
        let (engine, _dir, permit, chain) = stage_fixture(&url, oracle);
        let intent = RawIntent {
            body: RawIntentBody::Raw {
                to: "0x2222222222222222222222222222222222222222".into(),
                value: "0".into(),
                data: "0x12345678".into(),
            },
            chain: Some("anvil".into()),
            gas: bloom_proto::intent::GasStrategy::Auto,
            nonce: None,
            gas_limit_hint: None,
            usd_value_hint: Some("999999".into()),
        };
        let staged = engine
            .stage_with_oracle_valuation_target(
                &permit,
                "alice",
                "0x1111111111111111111111111111111111111111"
                    .parse()
                    .unwrap(),
                intent.clone(),
                &chain,
                &policy_with_usd_cap(),
                None,
                BoundValuationTarget {
                    asset_id: "anvil:0x1111111111111111111111111111111111111111".into(),
                    amount_base_units: "1250000".into(),
                    asset_decimals: 6,
                    expected_to: "0x2222222222222222222222222222222222222222"
                        .parse()
                        .unwrap(),
                    expected_value_wei: U256::ZERO,
                    expected_calldata: Bytes::from(hex::decode("12345678").unwrap()),
                },
            )
            .await
            .unwrap();

        let quote = staged.valuation.as_ref().unwrap();
        assert_eq!(
            quote.asset_id,
            "anvil:0x1111111111111111111111111111111111111111"
        );
        assert_eq!(quote.amount_base_units, "1250000");
        assert_eq!(quote.usd_micro, 7_500_000);
        assert!(!engine.authorization_subject(&staged).calldata_verified);
        assert_eq!(
            calls.lock().as_slice(),
            &[(
                "anvil:0x1111111111111111111111111111111111111111".into(),
                "1250000".into(),
            )]
        );

        let error = engine
            .stage_with_oracle_valuation_target(
                &permit,
                "alice",
                "0x1111111111111111111111111111111111111111"
                    .parse()
                    .unwrap(),
                intent,
                &chain,
                &policy_with_usd_cap(),
                None,
                BoundValuationTarget {
                    asset_id: "anvil:0x1111111111111111111111111111111111111111".into(),
                    amount_base_units: "1250000".into(),
                    asset_decimals: 6,
                    expected_to: "0x2222222222222222222222222222222222222222"
                        .parse()
                        .unwrap(),
                    expected_value_wei: U256::ZERO,
                    expected_calldata: Bytes::from(hex::decode("deadbeef").unwrap()),
                },
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn approval_sealed_subject_binds_token_spender_and_allowance() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let token: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let spender: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let amount = U256::from(123_456u64);
        let mut staged = fake_staged_1559("approval-facts");
        staged.to = bloom_proto::checksum_address(&token);
        staged.data_hex = format!(
            "0x{}",
            hex::encode(IERC20::approveCall { spender, amount }.abi_encode())
        );
        staged.action_kind = TxActionKind::Approval;

        let subject =
            evm_sealed_subject(&staged, EvmOutboxActionKind::Confirm, &test_signing_hash())
                .unwrap();
        assert_eq!(subject.call.method, "approval");
        assert_eq!(subject.call.to, bloom_proto::checksum_address(&token));
        assert_eq!(
            subject.call.recipient.as_deref(),
            Some(bloom_proto::checksum_address(&spender).as_str())
        );
        assert_eq!(
            subject.value.token_amount_base_units.as_deref(),
            Some("123456")
        );
        assert!(subject.authority_change);

        let auth = engine.authorization_subject(&staged);
        assert!(auth.authority_change);
        assert!(!auth.calldata_verified);
        assert!(auth.total_value_usd_micro.is_none());
    }

    fn fake_grant(
        wallet: impl Into<String>,
        action_id: impl Into<String>,
        petal_id: impl Into<String>,
        petal_digest: impl Into<String>,
    ) -> SealedApprovalGrant {
        let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Standard);
        terms.allowed_sign_intents = vec!["evm.tx.sign".into()];
        terms.max_signatures = 100;
        SealedApprovalGrant {
            grant_id: "test-grant".into(),
            wallet: wallet.into(),
            action_id: action_id.into(),
            intent_hash: "test-intent".into(),
            petal_id: petal_id.into(),
            petal_digest: petal_digest.into(),
            petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
            daemon_terms: terms,
            petal_policy_digest: "0".repeat(64),
            policy_version: 0,
            issued_ms: 0,
            expiry_ms: u64::MAX,
            max_signatures: 100,
            consumed_signature_count: 0,
            revoked: false,
        }
    }

    struct TestGrantStore {
        active: bool,
    }

    #[async_trait::async_trait]
    impl GrantStore for TestGrantStore {
        async fn mint(
            &self,
            sealed: &SealedAction,
            approval_expiry_ms: u64,
            now_ms: u64,
        ) -> Result<SealedApprovalGrant, AuthApiError> {
            SealedApprovalGrant::mint("test-grant", sealed, approval_expiry_ms, now_ms)
        }

        async fn consume_signature(
            &self,
            grant_id: &str,
            _intent: &str,
            _now_ms: u64,
        ) -> Result<SealedApprovalGrant, AuthApiError> {
            let mut grant = fake_grant(
                "alice",
                "test-action",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
            );
            grant.grant_id = grant_id.to_string();
            grant.consumed_signature_count = 1;
            Ok(grant)
        }

        async fn revoke(&self, _grant_id: &str, _now_ms: u64) -> Result<(), AuthApiError> {
            Ok(())
        }

        async fn revoke_all_for_wallet(
            &self,
            _wallet: &str,
            _now_ms: u64,
        ) -> Result<usize, AuthApiError> {
            Ok(0)
        }

        async fn get_active(
            &self,
            wallet: &str,
            action_id: &str,
            petal_id: &str,
            petal_digest: &str,
            _now_ms: u64,
        ) -> Result<Option<SealedApprovalGrant>, AuthApiError> {
            Ok(self
                .active
                .then(|| fake_grant(wallet, action_id, petal_id, petal_digest)))
        }
    }

    struct TestPetalHost;

    #[async_trait::async_trait]
    impl PetalHost for TestPetalHost {
        async fn seal_context(&self, petal_id: &str) -> Result<SealedPetalContext, AuthApiError> {
            Ok(SealedPetalContext {
                canonical_intent_bytes_hash: "0".repeat(64),
                intent_hash: "test-intent".into(),
                daemon_terms_digest: DaemonGrantTerms::minimal(AssuranceLevel::Standard)
                    .daemon_terms_digest()?,
                petal_policy_digest: "0".repeat(64),
                policy_version: 0,
                petal_id: petal_id.into(),
            })
        }

        async fn sealed_policy_snapshot(
            &self,
            wallet: &str,
            petal_id: &str,
        ) -> Result<PetalPolicySnapshot, AuthApiError> {
            Ok(PetalPolicySnapshot {
                policy_version: 0,
                wallet: wallet.into(),
                petal_id: petal_id.into(),
                petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
                caps: BTreeMap::new(),
                hard_rules: Vec::new(),
                step_up_rules: Vec::new(),
                config: BTreeMap::new(),
                budget_state: BTreeMap::new(),
                session_scope: None,
            })
        }

        async fn sign_hash(
            &self,
            request: SignHashRequest,
            attestation: &SigningAttestation,
            now_ms: u64,
        ) -> Result<bloom_auth_api::SealedSignature, AuthApiError> {
            bloom_auth_api::DefaultAttestationRegistry::new().validate_attestation(attestation)?;
            if request.intent != "evm.tx.sign" {
                return Err(AuthApiError::Denied("unexpected test intent".into()));
            }
            let hash: B256 = request
                .hash_hex
                .parse()
                .map_err(|e| AuthApiError::Denied(format!("invalid test hash: {e}")))?;
            use alloy::signers::SignerSync;
            let sig = test_signer()
                .sign_hash_sync(&hash)
                .map_err(|e| AuthApiError::Denied(format!("test sign hash: {e}")))?;
            Ok(bloom_auth_api::SealedSignature {
                intent_hash: "test-intent".into(),
                signature_b64: base64::engine::general_purpose::STANDARD.encode(sig.as_bytes()),
                signed_at_ms: now_ms,
            })
        }

        async fn audit(&self, _event: AuditEvent) -> Result<(), AuthApiError> {
            Ok(())
        }
    }

    fn with_test_host(engine: TxEngine, active: bool) -> TxEngine {
        engine.with_host_signing_services(
            Arc::new(TestGrantStore { active }),
            Arc::new(TestPetalHost),
        )
    }

    fn with_test_auth_and_host(engine: TxEngine, active: bool) -> TxEngine {
        with_test_host(
            engine.with_auth_services(
                Arc::new(RejectingTestVerifier),
                Arc::new(ChallengeOnlyWriter),
            ),
            active,
        )
    }

    struct RejectingTestVerifier;

    #[async_trait::async_trait]
    impl ApprovalVerifier for RejectingTestVerifier {
        async fn verify_and_consume(
            &self,
            _approval: SignedApproval,
            _now_ms: u64,
        ) -> Result<(), AuthApiError> {
            Err(AuthApiError::Denied("test verifier rejects".into()))
        }
    }

    struct AcceptingTestVerifier;

    #[async_trait::async_trait]
    impl ApprovalVerifier for AcceptingTestVerifier {
        async fn verify_and_consume(
            &self,
            approval: SignedApproval,
            _now_ms: u64,
        ) -> Result<(), AuthApiError> {
            if approval.surface != "outbox" {
                return Err(AuthApiError::Denied("wrong surface".into()));
            }
            Ok(())
        }

        async fn verify_and_mint_grant(
            &self,
            approval: SignedApproval,
            _grant_store: &dyn GrantStore,
            _now_ms: u64,
        ) -> Result<SealedApprovalGrant, AuthApiError> {
            if approval.surface != "outbox" {
                return Err(AuthApiError::Denied("wrong surface".into()));
            }
            Ok(fake_grant(
                approval.wallet,
                approval.action_id,
                approval.petal_id,
                approval.petal_digest,
            ))
        }
    }

    struct ChallengeOnlyWriter;

    #[async_trait::async_trait]
    impl AuthStoreWriter for ChallengeOnlyWriter {
        async fn stage_entry(
            &self,
            envelope: CanonicalEnvelope,
            assurance: AssuranceLevel,
            now_ms: u64,
        ) -> Result<AuthEntryRecord, AuthApiError> {
            Ok(AuthEntryRecord {
                surface: envelope.header.surface.clone(),
                action_id: envelope.header.action_id.clone(),
                state: AuthEntryState::Staged,
                intent_hash: envelope.intent_hash()?,
                assurance,
                nonce: None,
                nonce_state: NonceState::Unused,
                reservation_id: None,
                updated_ms: now_ms,
            })
        }

        async fn stage_action(
            &self,
            action: SealedAction,
            now_ms: u64,
        ) -> Result<AuthEntryRecord, AuthApiError> {
            let assurance = action.daemon_terms.assurance;
            let envelope = action.envelope;
            Ok(AuthEntryRecord {
                surface: envelope.header.surface.clone(),
                action_id: envelope.header.action_id.clone(),
                state: AuthEntryState::Staged,
                intent_hash: envelope.intent_hash()?,
                assurance,
                nonce: None,
                nonce_state: NonceState::Unused,
                reservation_id: None,
                updated_ms: now_ms,
            })
        }

        async fn issue_challenge(
            &self,
            surface: &str,
            action_id: &str,
            server_nonce: &str,
            expiry_ms: u64,
            _now_ms: u64,
        ) -> Result<ApprovalChallenge, AuthApiError> {
            Ok(ApprovalChallenge {
                schema: APPROVAL_CHALLENGE_SCHEMA_V1.to_string(),
                action_id: action_id.to_string(),
                wallet: "alice".to_string(),
                surface: surface.to_string(),
                petal_id: PETAL_ID_EVM_WALLET.to_string(),
                petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.to_string(),
                intent_hash: "outbox-intent".to_string(),
                server_nonce: server_nonce.to_string(),
                assurance: AssuranceLevel::Standard,
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms,
                ceremony_url: None,
            })
        }

        async fn issue_review_session(
            &self,
            review_session_id: &str,
            surface: &str,
            action_id: &str,
            expires_ms: u64,
            now_ms: u64,
        ) -> Result<bloom_auth_api::ReviewSessionRecord, AuthApiError> {
            Ok(bloom_auth_api::ReviewSessionRecord {
                review_session_id: review_session_id.to_string(),
                surface: surface.to_string(),
                action_id: action_id.to_string(),
                intent_hash: "outbox-intent".to_string(),
                assurance: AssuranceLevel::Standard,
                expires_ms,
                consumed_ms: None,
                created_ms: now_ms,
            })
        }
    }

    struct PreApprovedWriter;

    #[async_trait::async_trait]
    impl AuthStoreWriter for PreApprovedWriter {
        async fn stage_entry(
            &self,
            envelope: CanonicalEnvelope,
            assurance: AssuranceLevel,
            now_ms: u64,
        ) -> Result<AuthEntryRecord, AuthApiError> {
            Ok(AuthEntryRecord {
                surface: envelope.header.surface.clone(),
                action_id: envelope.header.action_id.clone(),
                state: AuthEntryState::Approved,
                intent_hash: envelope.intent_hash()?,
                assurance,
                nonce: Some("already-consumed".into()),
                nonce_state: NonceState::Consumed,
                reservation_id: None,
                updated_ms: now_ms,
            })
        }

        async fn stage_action(
            &self,
            action: SealedAction,
            now_ms: u64,
        ) -> Result<AuthEntryRecord, AuthApiError> {
            let assurance = action.daemon_terms.assurance;
            let envelope = action.envelope;
            Ok(AuthEntryRecord {
                surface: envelope.header.surface.clone(),
                action_id: envelope.header.action_id.clone(),
                state: AuthEntryState::Approved,
                intent_hash: envelope.intent_hash()?,
                assurance,
                nonce: Some("already-consumed".into()),
                nonce_state: NonceState::Consumed,
                reservation_id: None,
                updated_ms: now_ms,
            })
        }

        async fn issue_challenge(
            &self,
            _surface: &str,
            _action_id: &str,
            _server_nonce: &str,
            _expiry_ms: u64,
            _now_ms: u64,
        ) -> Result<ApprovalChallenge, AuthApiError> {
            Err(AuthApiError::Denied(
                "pre-approved retry must not issue a new challenge".into(),
            ))
        }

        async fn issue_review_session(
            &self,
            _review_session_id: &str,
            _surface: &str,
            _action_id: &str,
            _expires_ms: u64,
            _now_ms: u64,
        ) -> Result<bloom_auth_api::ReviewSessionRecord, AuthApiError> {
            Err(AuthApiError::Denied(
                "pre-approved retry must not issue a review session".into(),
            ))
        }
    }

    fn fake_staged_1559(id: &str) -> StagedTx {
        StagedTx {
            id: id.into(),
            wallet: "alice".into(),
            chain: "anvil".into(),
            chain_id: 31337,
            from: TEST_SIGNER_ADDRESS.into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            value_wei: "0".into(),
            data_hex: "0x".into(),
            gas_limit: 21000,
            max_fee_per_gas: Some("100".into()),
            max_priority_fee_per_gas: Some("10".into()),
            gas_price: None,
            nonce: 0,
            policy_checks: vec![],
            created_ms: 0,
            expires_ms: 0,
            status: TxStatus::Pending,
            action_kind: TxActionKind::Unknown,
            tx_hash: None,
            token: None,
            nft: None,
            usd_value: None,
            valuation: None,
            depends_on: None,
            action_id: None,
            execution_origin: None,
        }
    }

    fn outbox_intent_hash_for(staged: &StagedTx) -> String {
        outbox_canonical_envelope(staged, EvmOutboxActionKind::Confirm, &test_signing_hash())
            .unwrap()
            .intent_hash()
            .unwrap()
    }

    fn sealed_action_from_staged(staged: &StagedTx) -> SealedAction {
        let subject =
            evm_sealed_subject(staged, EvmOutboxActionKind::Confirm, &test_signing_hash()).unwrap();
        SealedAction::new(
            subject
                .canonical_envelope(u64::try_from(staged.expires_ms).unwrap_or(u64::MAX))
                .unwrap(),
            "test plan".into(),
            Vec::new(),
            subject.daemon_terms.clone(),
            subject.policy_snapshot.clone(),
            1,
        )
        .unwrap()
    }

    fn fake_chain_client(allow_broadcast: bool) -> bloom_evm::ChainClient {
        let spec = bloom_proto::ChainSpec {
            name: "anvil".into(),
            chain_id: 31337,
            rpc_urls: vec!["http://127.0.0.1:1".into()],
            rpc_endpoints: Vec::new(),
            allow_broadcast,
            etherscan_api_url: None,
            display_name: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            legacy_tx: false,
            op_stack: false,
        };
        bloom_evm::ChainClient::new(spec).unwrap()
    }

    fn test_signing_hash() -> B256 {
        B256::repeat_byte(0x11)
    }

    fn assert_outbox_intent_hash_changes<F: FnOnce(&mut StagedTx)>(field: &str, mutate: F) {
        let base = fake_staged_1559("0001-bind");
        let base_hash = outbox_intent_hash_for(&base);
        let mut changed = base;
        mutate(&mut changed);
        let changed_hash = outbox_intent_hash_for(&changed);
        assert_ne!(
            base_hash, changed_hash,
            "mutating EVM sealed intent field {field} must change intent hash"
        );
    }

    #[test]
    fn evm_outbox_canonical_envelope_binds_reference_identity() {
        let mut staged = fake_staged_1559("0001-reference");
        staged.value_wei = "42".into();
        staged.data_hex = "0xa9059cbb".into();
        staged.usd_value = Some(1.25);
        staged.action_kind = TxActionKind::Erc20Transfer;
        staged.token = Some(bloom_proto::TokenRef {
            address: "0x0000000000000000000000000000000000000003".into(),
            symbol: "USDC".into(),
            decimals: 6,
            recipient: "0x0000000000000000000000000000000000000002".into(),
            amount: "1.25".into(),
            amount_base_units: Some("1250000".into()),
        });

        let envelope =
            outbox_canonical_envelope(&staged, EvmOutboxActionKind::Confirm, &test_signing_hash())
                .unwrap();
        assert_eq!(envelope.header.wallet, "alice");
        assert_eq!(envelope.header.surface, "outbox");
        assert_eq!(envelope.header.action_id, "31337:0001-reference");
        assert_eq!(envelope.header.petal_id, PETAL_ID_EVM_WALLET);
        assert_eq!(envelope.header.petal_digest, PLACEHOLDER_DIGEST_EVM_WALLET);
        assert_eq!(envelope.header.petal_version, FIRST_PARTY_PETAL_VERSION_V0);
        assert_eq!(envelope.header.executor_kind, ExecutorKind::FirstParty);
        assert_eq!(envelope.header.network, "eip155:31337");
        assert_eq!(envelope.header.account, TEST_SIGNER_ADDRESS);
        assert_eq!(envelope.header.action_kind, "confirm");
        assert!(envelope.header.value_movement);
        assert!(!envelope.header.authority_change);
        assert_eq!(
            envelope.subject_kind,
            bloom_auth_api::EVM_SEALED_INTENT_SUBJECT_KIND
        );
        assert_eq!(
            envelope.subject_schema,
            bloom_auth_api::EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1
        );

        let subject_bytes = base64::engine::general_purpose::STANDARD
            .decode(&envelope.subject_bytes_b64)
            .unwrap();
        let subject: serde_json::Value = serde_json::from_slice(&subject_bytes).unwrap();
        assert_eq!(
            subject["schema"],
            bloom_auth_api::EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1
        );
        assert_eq!(subject["action_id"], "31337:0001-reference");
        assert_eq!(subject["chain_id"], 31337);
        assert_eq!(subject["call"]["to"], staged.to);
        assert_eq!(subject["value"]["native_value_wei"], "42");
        assert_eq!(subject["value"]["token_amount_base_units"], "1250000");
        assert_eq!(subject["call"]["calldata_hex"], "0xa9059cbb");
        assert_eq!(subject["call"]["method"], "erc20_transfer");
        assert_eq!(subject["token"]["symbol"], "USDC");
    }

    #[test]
    fn evm_outbox_canonical_envelope_binds_critical_fields() {
        assert_outbox_intent_hash_changes("wallet", |s| s.wallet = "other-wallet".into());
        assert_outbox_intent_hash_changes("chain", |s| s.chain = "base".into());
        assert_outbox_intent_hash_changes("chain_id", |s| s.chain_id = 8453);
        assert_outbox_intent_hash_changes("id", |s| s.id = "0002-bind".into());
        assert_outbox_intent_hash_changes("from", |s| {
            s.from = "0x0000000000000000000000000000000000000004".into()
        });
        assert_outbox_intent_hash_changes("to", |s| {
            s.to = "0x0000000000000000000000000000000000000005".into()
        });
        assert_outbox_intent_hash_changes("value_wei", |s| s.value_wei = "1".into());
        assert_outbox_intent_hash_changes("data_hex", |s| s.data_hex = "0x01".into());
        assert_outbox_intent_hash_changes("gas_limit", |s| s.gas_limit = 50_000);
        assert_outbox_intent_hash_changes("max_fee_per_gas", |s| {
            s.max_fee_per_gas = Some("200".into())
        });
        assert_outbox_intent_hash_changes("max_priority_fee_per_gas", |s| {
            s.max_priority_fee_per_gas = Some("20".into())
        });
        assert_outbox_intent_hash_changes("nonce", |s| s.nonce = 1);
        assert_outbox_intent_hash_changes("token", |s| {
            s.token = Some(bloom_proto::TokenRef {
                address: "0x0000000000000000000000000000000000000003".into(),
                symbol: "USDC".into(),
                decimals: 6,
                recipient: "0x0000000000000000000000000000000000000002".into(),
                amount: "0.000001".into(),
                amount_base_units: Some("1".into()),
            })
        });
        assert_outbox_intent_hash_changes("policy_checks", |s| {
            s.policy_checks.push(bloom_proto::PolicyCheck::hard(
                "evm.test",
                bloom_proto::PolicyOutcome::Deny,
                "test denial",
            ))
        });
        assert_outbox_intent_hash_changes("expires_ms", |s| s.expires_ms = 123_456);
    }

    #[test]
    fn sealed_dispatcher_accepts_exact_evm_subject_bytes() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let mut staged = fake_staged_1559("0001-sealed");
        staged.action_id = Some("action-0001".into());
        staged.expires_ms = 10_000;
        let sealed = sealed_action_from_staged(&staged);
        let subject_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sealed.envelope.subject_bytes_b64)
            .unwrap();
        let subject: EvmSealedIntentSubject = serde_json::from_slice(&subject_bytes).unwrap();

        engine
            .ensure_evm_subject_matches_seal(&sealed, &subject)
            .unwrap();
    }

    #[test]
    fn sealed_dispatcher_rejects_tampered_evm_subject_bytes() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let mut staged = fake_staged_1559("0001-sealed");
        staged.action_id = Some("action-0001".into());
        staged.expires_ms = 10_000;
        let sealed = sealed_action_from_staged(&staged);
        let subject_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sealed.envelope.subject_bytes_b64)
            .unwrap();
        let mut subject: EvmSealedIntentSubject = serde_json::from_slice(&subject_bytes).unwrap();
        subject.call.to = "0x0000000000000000000000000000000000000005".into();

        let err = engine
            .ensure_evm_subject_matches_seal(&sealed, &subject)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("sealed subject bytes do not reproduce"),
            "{err}"
        );
    }

    #[test]
    fn petal_execution_origin_binds_evm_sealed_subject_and_executor_match() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let mut staged = fake_staged_1559("0001-local-origin");
        staged.action_id = Some("local-origin-action".into());
        staged.execution_origin = Some(ExecutionOrigin {
            petal_id: "petal:polymarket".into(),
            petal_digest: "a".repeat(64),
            petal_version: "v1-package".into(),
        });
        engine.outbox.write_pending(&staged, "# plan").unwrap();

        let subject =
            evm_sealed_subject(&staged, EvmOutboxActionKind::Confirm, &test_signing_hash())
                .unwrap();
        assert_eq!(subject.petal_id, "petal:polymarket");
        assert_eq!(subject.petal_digest, "a".repeat(64));
        assert_eq!(subject.petal_version, "v1-package");
        assert_eq!(subject.policy_snapshot.petal_id, subject.petal_id);
        assert_eq!(subject.policy_snapshot.petal_digest, subject.petal_digest);

        engine
            .ensure_evm_subject_matches_persisted_origin("anvil", &subject)
            .unwrap();

        let mut mismatched = subject;
        mismatched.petal_digest = "b".repeat(64);
        let err = engine
            .ensure_evm_subject_matches_persisted_origin("anvil", &mismatched)
            .unwrap_err()
            .to_string();
        assert!(err.contains("petal_digest does not match persisted execution origin"));
    }

    #[tokio::test]
    async fn sealed_dispatcher_errors_for_unregistered_fake_petal() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let header = bloom_auth_api::CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: "alice".into(),
            surface: "fake".into(),
            action_id: "fake-action".into(),
            petal_id: "fake-petal".into(),
            petal_digest: "fake-digest".into(),
            petal_version: "v0".into(),
            executor_kind: ExecutorKind::FirstParty,
            network: "testnet".into(),
            account: TEST_SIGNER_ADDRESS.into(),
            action_kind: "fake_execute".into(),
            value_movement: false,
            authority_change: false,
            expires_ms: 10_000,
        };
        let envelope = CanonicalEnvelope::new(
            header.clone(),
            "fake_subject",
            "fake.subject.v1",
            br#"{\"ok\":true}"#.to_vec(),
        );
        let policy = PetalPolicySnapshot::minimal(&header);
        let sealed = SealedAction::new(
            envelope,
            "fake plan".into(),
            Vec::new(),
            DaemonGrantTerms::minimal(AssuranceLevel::Standard),
            policy,
            1,
        )
        .unwrap();
        let chain = fake_chain_client(true);

        let err = engine
            .execute_sealed_action(&sealed, "anvil", &chain, &Policy::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no sealed-action executor registered for petal_id=fake-petal"),
            "{err}"
        );
    }

    #[test]
    fn bump_fees_1559_at_least_10pct() {
        let mut s = fake_staged_1559("a");
        bump_fees_in_place(&mut s, 15);
        // 100 * 1.15 = 115; integer math: 100 + (100*15/100) = 115.
        assert_eq!(s.max_fee_per_gas.as_deref(), Some("115"));
        // 10 * 1.15 = 11.5 — integer math: 10 + (10*15/100=1) = 11.
        // But our bump-one floors the bump at 1 wei.
        assert_eq!(s.max_priority_fee_per_gas.as_deref(), Some("11"));
    }

    #[test]
    fn bump_fees_legacy_path() {
        let mut s = fake_staged_1559("a");
        s.max_fee_per_gas = None;
        s.max_priority_fee_per_gas = None;
        s.gas_price = Some("1000".into());
        bump_fees_in_place(&mut s, 12);
        // 1000 + 1000*12/100 = 1120.
        assert_eq!(s.gas_price.as_deref(), Some("1120"));
    }

    #[test]
    fn cancellation_candidate_clears_original_value_and_authority_facts() {
        let mut original = fake_staged_1559("cancel-facts");
        original.action_kind = TxActionKind::Approval;
        original.value_wei = "123".into();
        original.data_hex = "0xdeadbeef".into();
        original.token = Some(TokenRef {
            address: "0x2222222222222222222222222222222222222222".into(),
            symbol: "TOK".into(),
            decimals: 6,
            recipient: "0x3333333333333333333333333333333333333333".into(),
            amount: "1".into(),
            amount_base_units: Some("1000000".into()),
        });
        original.usd_value = Some(10.0);
        original.valuation = Some(bloom_auth_api::ValuationQuote {
            asset_id: "anvil:0x2222222222222222222222222222222222222222".into(),
            amount_base_units: "1000000".into(),
            usd_micro: 10_000_000,
            source: "test".into(),
            quote_timestamp_ms: 1,
            fetched_at_ms: 1,
            max_age_ms: 30_000,
            confidence_ppm: None,
            stablecoin_assumption: false,
        });

        let cancel = cancellation_candidate(&original).unwrap();
        assert!(cancel.to.eq_ignore_ascii_case(&original.from));
        assert_eq!(cancel.value_wei, "0");
        assert_eq!(cancel.data_hex, "0x");
        assert_eq!(cancel.gas_limit, 21_000);
        assert_eq!(cancel.action_kind, TxActionKind::NativeTransfer);
        assert!(cancel.token.is_none());
        assert!(cancel.nft.is_none());
        assert!(cancel.usd_value.is_none());
        assert!(cancel.valuation.is_none());
        assert!(cancel.policy_checks.is_empty());
    }

    #[test]
    fn lookup_usdc_mainnet() {
        let addr = lookup_known_token(1, "USDC").unwrap();
        assert!(addr.to_ascii_lowercase().starts_with("0xa0b86991"));
    }

    #[test]
    fn resolve_token_address_via_hex() {
        let (a, sym) =
            TxEngine::resolve_token_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 1)
                .unwrap();
        assert_eq!(
            format!("{a:#x}"),
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        );
        assert!(sym.starts_with("0x"));
    }

    #[test]
    fn resolve_token_unknown_symbol_errors() {
        let err = TxEngine::resolve_token_address("MOCK", 1).unwrap_err();
        assert!(matches!(err, TxEngineError::Token(_)));
    }

    #[test]
    fn resolve_token_symbol_resolves_on_arbitrum() {
        // Regression: USDC by symbol must resolve on non-mainnet chains via the
        // shared bloom_proto::tokens table (previously only chains 1/31337).
        let (a, sym) = TxEngine::resolve_token_address("USDC", 42161).unwrap();
        assert_eq!(
            format!("{a:#x}"),
            "0xaf88d065e77c8cc2239327c5edb3a432268e5831"
        );
        assert_eq!(sym, "USDC");
    }

    #[test]
    fn resolve_token_symbol_resolves_on_polygon_and_base() {
        assert!(TxEngine::resolve_token_address("USDC", 137).is_ok());
        assert!(TxEngine::resolve_token_address("USDC", 8453).is_ok());
    }

    // -------------------------------------------------------------------
    // Nonce-conflict body tests. These exercise the index lookup +
    // body shape directly; the full stage() path is covered elsewhere
    // and requires a live RPC.
    // -------------------------------------------------------------------

    fn make_pending_tx(
        addr: Address,
        nonce: u64,
        hash_byte: u8,
        observed_secs: u64,
    ) -> bloom_mempool::PendingTx {
        use alloy::primitives::{B256, Bytes, U256};
        let mut hash = [0u8; 32];
        hash.fill(hash_byte);
        bloom_mempool::PendingTx {
            hash: B256::from(hash),
            from: addr,
            to: None,
            nonce,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: bloom_mempool::TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: UNIX_EPOCH + Duration::from_secs(observed_secs),
        }
    }

    fn nonce_conflict_engine() -> (TxEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let outbox = crate::outbox::Outbox::new(dir.path()).unwrap();
        let engine = TxEngine::new(outbox, 60_000);
        (engine, dir)
    }

    #[cfg(feature = "unsafe-debug-signer")]
    #[test]
    fn unsafe_debug_signer_is_available_only_for_configured_wallet() {
        let (engine, _dir) = nonce_conflict_engine();
        let signer = Arc::new(test_signer());
        let expected_address = signer.address();
        let engine = engine.with_unsafe_debug_signer("dev-wallet", signer);

        assert_eq!(
            engine
                .unsafe_debug_signer("dev-wallet")
                .map(|signer| signer.address()),
            Some(expected_address)
        );
        assert!(engine.unsafe_debug_signer("other-wallet").is_none());
    }

    /// `persist_outbox_ceremony_approval` is an outbox-only method: it requires
    /// a broadcast action's `chain_name`. Non-broadcast first-party actions
    /// (wallet-policy updates, policy-session mints) must not be routed here by
    /// the ceremony server — this test pins the contract so the caller-side gate
    /// (which skips this call for non-broadcast actions) stays load-bearing.
    #[test]
    fn persist_ceremony_approval_requires_broadcast_chain_name() {
        let (engine, _dir) = nonce_conflict_engine();
        let staged = fake_staged_1559("0001-policy-like");
        let mut action = sealed_action_from_staged(&staged);
        action.petal_policy.config.remove("chain_name");
        assert_eq!(action.chain_name(), None, "precondition: no chain_name");

        let approval = SignedApproval {
            schema: APPROVAL_SCHEMA_V1.into(),
            action_id: action.action_id().to_string(),
            wallet: action.wallet().to_string(),
            surface: "wallet-policy".into(),
            petal_id: action.petal_id().to_string(),
            petal_digest: action.petal_digest().to_string(),
            intent_hash: "policy-intent".into(),
            server_nonce: "nonce-1".into(),
            assurance: AssuranceLevel::Standard,
            daemon_terms_digest: "1".repeat(64),
            petal_policy_digest: "2".repeat(64),
            policy_version: 0,
            expiry_ms: now_ms() as u64 + 60_000,
            signer_transport: SignerTransport::BrowserWebauthn,
            credential_id: "cred-1".into(),
            review_session_id: None,
            webauthn_assertion: WebAuthnAssertionRecord {
                credential_id: "cred-1".into(),
                authenticator_data_b64: "AA".into(),
                client_data_json_b64: "e30".into(),
                signature_b64: "AA".into(),
                user_handle_b64: None,
            },
        };

        let err = engine
            .persist_outbox_ceremony_approval(&action, &approval)
            .expect_err("outbox persistence must reject a non-broadcast action");
        assert!(
            matches!(err, TxEngineError::ApprovalState(_)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn dependency_gate_blocks_until_predecessor_succeeds() {
        use crate::outbox::{MinedReceipt, OutboxState, RECEIPT_FILE};
        let (engine, _dir) = nonce_conflict_engine();

        // No predecessor in the outbox → refused.
        assert!(matches!(
            engine.ensure_dependency_satisfied("alice", "anvil", "approve"),
            Err(TxEngineError::DependencyNotSatisfied { .. })
        ));

        // Predecessor staged but still pending → refused.
        let mut dep = fake_staged_1559("approve");
        dep.tx_hash = Some(format!("{:#x}", B256::repeat_byte(9)));
        engine.outbox.write_pending(&dep, "# plan").unwrap();
        assert!(matches!(
            engine.ensure_dependency_satisfied("alice", "anvil", "approve"),
            Err(TxEngineError::DependencyNotSatisfied { .. })
        ));

        // Broadcast (sent) but no receipt yet → refused (waiting to confirm).
        let entry = engine.outbox.read("alice", "anvil", "approve").unwrap();
        engine.outbox.transition(&entry, OutboxState::Sent).unwrap();
        assert!(matches!(
            engine.ensure_dependency_satisfied("alice", "anvil", "approve"),
            Err(TxEngineError::DependencyNotSatisfied { .. })
        ));

        // Reverted receipt → refused, with the reason surfaced.
        let se = &engine.outbox.walk_all_sent().unwrap()[0];
        let reverted = MinedReceipt {
            outcome: "reverted".into(),
            tx_hash: dep.tx_hash.clone().unwrap(),
            block_number: Some(1),
            revert_reason: Some("ERC20: insufficient allowance".into()),
        };
        engine
            .outbox
            .write_sent_sibling(se, RECEIPT_FILE, &serde_json::to_vec(&reverted).unwrap())
            .unwrap();
        match engine.ensure_dependency_satisfied("alice", "anvil", "approve") {
            Err(TxEngineError::DependencyNotSatisfied { reason, .. }) => {
                assert!(reason.contains("reverted"))
            }
            other => panic!("expected reverted refusal, got {other:?}"),
        }

        // Success receipt → allowed.
        let success = MinedReceipt {
            outcome: "success".into(),
            tx_hash: dep.tx_hash.clone().unwrap(),
            block_number: Some(1),
            revert_reason: None,
        };
        engine
            .outbox
            .write_sent_sibling(se, RECEIPT_FILE, &serde_json::to_vec(&success).unwrap())
            .unwrap();
        assert!(
            engine
                .ensure_dependency_satisfied("alice", "anvil", "approve")
                .is_ok()
        );
    }

    #[test]
    fn build_nonce_conflict_body_returns_none_when_no_index() {
        let (engine, _dir) = nonce_conflict_engine();
        let addr = "0x0000000000000000000000000000000000000001"
            .parse::<Address>()
            .unwrap();
        assert!(engine.build_nonce_conflict_body("anvil", addr, 0).is_none());
    }

    #[test]
    fn build_nonce_conflict_body_returns_none_when_no_match() {
        let (engine, _dir) = nonce_conflict_engine();
        let idx = bloom_mempool::PendingTxIndex::new(8);
        engine.set_mempool_index("anvil", idx);
        let addr = "0x0000000000000000000000000000000000000001"
            .parse::<Address>()
            .unwrap();
        assert!(engine.build_nonce_conflict_body("anvil", addr, 7).is_none());
    }

    #[test]
    fn build_nonce_conflict_body_returns_some_when_match() {
        let (engine, _dir) = nonce_conflict_engine();
        let idx = bloom_mempool::PendingTxIndex::new(8);
        let addr = "0x0000000000000000000000000000000000000001"
            .parse::<Address>()
            .unwrap();
        idx.insert(make_pending_tx(addr, 7, 0xAB, 1_700_000_000));
        engine.set_mempool_index("anvil", idx);

        let body = engine
            .build_nonce_conflict_body("anvil", addr, 7)
            .expect("expected nonce conflict body");
        assert_eq!(body["conflict_nonce"], 7);
        let hash_str = body["external_hash"].as_str().unwrap();
        assert!(
            hash_str.starts_with("0xabab"),
            "external_hash should start with 0xabab, got {hash_str}"
        );
        // Length: "0x" + 64 hex chars.
        assert_eq!(hash_str.len(), 66);
        assert_eq!(body["external_observed_at"], 1_700_000_000);
        let advice = body["advice"].as_str().unwrap();
        assert!(advice.contains(hash_str));
    }

    // -------------------------------------------------------------------
    // MEV-heuristic helpers. These exercise the policy→config mapping and
    // the synchronous `evaluate_mev_risk` shim that wraps
    // `bloom_mempool::heuristic::evaluate` with the stub quoter; the full
    // `stage()` path is covered elsewhere and needs a live RPC.
    // -------------------------------------------------------------------

    #[test]
    fn mev_cfg_from_policy_uses_policy_slippage_and_default_threshold() {
        let mut policy = bloom_proto::Policy::default();
        policy.mev.max_slippage_bps = 250;
        let cfg = mev_cfg_from_policy(&policy);
        assert_eq!(cfg.max_slippage_bps, 250);
        assert_eq!(
            cfg.zero_min_amount_in_threshold,
            U256::from(10u64).pow(U256::from(18u64))
        );
    }

    #[test]
    fn evaluate_mev_risk_high_on_zero_amount_out_min() {
        // The fixture decodes a swap with amountOutMin = 0 and an
        // amountIn well above 1e18. Even with the stub quoter (always
        // returns None) this must classify as High via the
        // amount_out_min_zero check, independent of the slippage path.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let hex_str = std::fs::read_to_string(format!(
            "{manifest_dir}/../bloom-mempool/tests/fixtures/uniswap_v2_zero_min.hex"
        ))
        .unwrap();
        let cd = alloy::hex::decode(hex_str.trim()).unwrap();

        let spec = bloom_proto::ChainSpec {
            name: "anvil".into(),
            chain_id: 31337,
            // Unreachable URL — the stub quoter doesn't hit the chain.
            rpc_urls: vec!["http://127.0.0.1:1".into()],
            rpc_endpoints: Vec::new(),
            allow_broadcast: true,
            etherscan_api_url: None,
            display_name: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            legacy_tx: false,
            op_stack: false,
        };
        let chain = bloom_evm::ChainClient::new(spec).unwrap();
        let policy = bloom_proto::Policy::default();
        let report = evaluate_mev_risk(&chain, &cd, U256::ZERO, &policy);
        assert_eq!(report.risk, bloom_mempool::MevRisk::High);
        assert!(
            report.checks.iter().any(|s| s == "amount_out_min_zero"),
            "expected amount_out_min_zero in checks, got {:?}",
            report.checks
        );
    }

    /// Helpers shared by the confirm-flow regression tests below. They
    /// build a self-contained TxEngine + Outbox + ChainClient pointing at
    /// an unreachable URL — every test below must fail (expectedly!)
    /// before any chain call is attempted, otherwise the assertion
    /// becomes "could not connect" and you can't tell which gate the
    /// confirm flow is meant to be honouring.
    fn fake_engine(stage_ttl_ms: u128) -> (TxEngine, bloom_proto::ChainSpec, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let outbox = crate::outbox::Outbox::new(dir.path().join("outbox")).unwrap();
        let engine = TxEngine::new(outbox, stage_ttl_ms);
        let spec = bloom_proto::ChainSpec {
            name: "anvil".into(),
            chain_id: 31337,
            // Unreachable URL — confirms that fail before broadcast must
            // not depend on this being reachable.
            rpc_urls: vec!["http://127.0.0.1:1".into()],
            rpc_endpoints: Vec::new(),
            allow_broadcast: true,
            etherscan_api_url: None,
            display_name: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            legacy_tx: false,
            op_stack: false,
        };
        (engine, spec, dir)
    }

    fn permit_for(dir: &tempfile::TempDir) -> HomeWritePermit {
        bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(dir.path())).unwrap()
    }

    /// Fix #2: writing `pending/<sent-id>/confirm` must not rebroadcast
    /// — the engine must refuse to confirm an id that no longer lives in
    /// `pending`.
    #[tokio::test]
    async fn confirm_rejects_id_already_in_sent() {
        let (engine, spec, dir) = fake_engine(60_000);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let policy = bloom_proto::Policy::default();

        // Stage manually (write_pending) so we don't need a live RPC.
        let mut staged = fake_staged_1559("0001-test");
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();
        // Move it to sent to simulate a stale path that targets the wrong
        // state.
        let entry = engine.outbox.read("alice", "anvil", "0001-test").unwrap();
        engine
            .outbox
            .transition(&entry, crate::outbox::OutboxState::Sent)
            .unwrap();

        let r = engine
            .confirm(&permit, "alice", "anvil", "0001-test", &chain, &policy, "y")
            .await;
        match r {
            Err(TxEngineError::Outbox(OutboxError::StateMismatch { actual, .. })) => {
                assert_eq!(actual, "sent");
            }
            other => panic!("expected StateMismatch, got {other:?}"),
        }
    }

    /// Fix #3: confirm must reject a pending entry whose stage TTL has
    /// expired. The check fires before broadcast, so the (unreachable)
    /// chain URL is never touched.
    #[tokio::test]
    async fn confirm_rejects_expired_stage() {
        let (engine, spec, dir) = fake_engine(60_000);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let policy = bloom_proto::Policy::default();

        let mut staged = fake_staged_1559("0001-test");
        // Already expired the moment this test runs.
        staged.expires_ms = 1;
        engine.outbox.write_pending(&staged, "p").unwrap();

        let r = engine
            .confirm(&permit, "alice", "anvil", "0001-test", &chain, &policy, "y")
            .await;
        match r {
            Err(TxEngineError::Outbox(OutboxError::StagedExpired { id, .. })) => {
                assert_eq!(id, "0001-test");
            }
            other => panic!("expected StagedExpired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn confirm_writes_broadcast_attempt_before_public_submit_error() {
        let (engine, spec, dir) = fake_engine(60_000);
        let engine = with_test_auth_and_host(engine, true);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let policy = bloom_proto::Policy::default();

        let mut staged = fake_staged_1559("0001-attempt");
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-attempt",
                &chain,
                &policy,
                "y",
            )
            .await;
        assert!(r.is_err(), "unreachable public RPC should fail");
        let entry = engine
            .outbox
            .read_in_state(
                "alice",
                "anvil",
                "0001-attempt",
                crate::outbox::OutboxState::Pending,
            )
            .unwrap();
        let attempt = engine
            .outbox
            .read_broadcast_attempt(&entry, BroadcastAttemptKind::Confirm)
            .unwrap()
            .expect("confirm attempt marker");
        assert_eq!(attempt.transport, BroadcastTransport::PublicRpc);
        assert!(entry.dir.join("raw_tx").exists());
    }

    #[tokio::test]
    async fn confirm_keeps_session_debit_after_broadcast_attempt_error() {
        let (engine, spec, dir) = fake_engine(60_000);
        let engine = with_test_auth_and_host(engine, true);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let policy = bloom_proto::Policy::default();

        let mut staged = fake_staged_1559("0001-session-attempt");
        staged.value_wei = "1".into();
        staged.expires_ms = now_ms() + 60_000;
        staged.usd_value = Some(2.0);
        staged.action_kind = TxActionKind::NativeTransfer;
        staged.valuation = Some(bloom_auth_api::ValuationQuote {
            asset_id: "native:anvil".into(),
            amount_base_units: "1".into(),
            usd_micro: 2_000_000,
            source: "test".into(),
            quote_timestamp_ms: now_ms() as u64,
            fetched_at_ms: now_ms() as u64,
            max_age_ms: 60_000,
            confidence_ppm: None,
            stablecoin_assumption: false,
        });
        engine.outbox.write_pending(&staged, "p").unwrap();
        engine.session_store.mint(crate::session::ActiveSession {
            id: "session-attempt".into(),
            wallet: "alice".into(),
            chains: std::collections::BTreeSet::from([31337]),
            expires_ms: now_ms() + 60_000,
            max_micro_usd: 5_000_000,
            spent_micro_usd: 0,
            allowed_pending_ids: std::collections::BTreeSet::from([crate::session::pending_key(
                31337,
                "0001-session-attempt",
            )]),
        });

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-session-attempt",
                &chain,
                &policy,
                "y",
            )
            .await;
        assert!(r.is_err(), "unreachable public RPC should fail");
        let session = engine
            .session_store
            .active(now_ms())
            .into_iter()
            .find(|s| s.id == "session-attempt")
            .expect("session remains active");
        assert_eq!(session.spent_micro_usd, 2_000_000);
    }

    #[tokio::test]
    async fn replace_and_cancel_by_replacement_write_broadcast_attempts_before_submit_error() {
        let (engine, spec, dir) = fake_engine(60_000);
        let engine = with_test_auth_and_host(engine, true);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let policy = bloom_proto::Policy::default();

        let mut staged = fake_staged_1559("0001-replace");
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();
        let r = engine
            .replace(
                &permit,
                "alice",
                "anvil",
                "0001-replace",
                &chain,
                10,
                &policy,
            )
            .await;
        assert!(r.is_err(), "unreachable public RPC should fail");
        let entry = engine
            .outbox
            .read_in_state(
                "alice",
                "anvil",
                "0001-replace",
                crate::outbox::OutboxState::Pending,
            )
            .unwrap();
        assert!(
            engine
                .outbox
                .read_broadcast_attempt(&entry, BroadcastAttemptKind::Replacement)
                .unwrap()
                .is_some(),
            "replacement marker"
        );
        assert!(entry.dir.join("replacement_raw_tx").exists());

        let mut staged = fake_staged_1559("0002-cancel");
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();
        let r = engine
            .cancel(
                &permit,
                "alice",
                "anvil",
                "0002-cancel",
                &chain,
                10,
                &policy,
            )
            .await;
        assert!(r.is_err(), "unreachable public RPC should fail");
        let entry = engine
            .outbox
            .read_in_state(
                "alice",
                "anvil",
                "0002-cancel",
                crate::outbox::OutboxState::Pending,
            )
            .unwrap();
        assert!(
            engine
                .outbox
                .read_broadcast_attempt(&entry, BroadcastAttemptKind::CancelReplacement)
                .unwrap()
                .is_some(),
            "cancel replacement marker"
        );
        assert!(entry.dir.join("cancel_raw_tx").exists());
    }

    #[tokio::test]
    async fn replace_and_cancel_by_replacement_respect_broadcast_gate() {
        let (engine, mut spec, dir) = fake_engine(60_000);
        let engine = with_test_auth_and_host(engine, true);
        spec.allow_broadcast = false;
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let policy = bloom_proto::Policy::default();

        let mut staged = fake_staged_1559("0001-replace-gated");
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();
        let r = engine
            .replace(
                &permit,
                "alice",
                "anvil",
                "0001-replace-gated",
                &chain,
                10,
                &policy,
            )
            .await;
        assert!(matches!(r, Err(TxEngineError::BroadcastDisabled(_))));
        let entry = engine
            .outbox
            .read_in_state(
                "alice",
                "anvil",
                "0001-replace-gated",
                crate::outbox::OutboxState::Pending,
            )
            .unwrap();
        assert!(
            engine
                .outbox
                .read_broadcast_attempt(&entry, BroadcastAttemptKind::Replacement)
                .unwrap()
                .is_none(),
            "broadcast-disabled replacement must not write marker"
        );
        assert!(!entry.dir.join("replacement_raw_tx").exists());

        let mut staged = fake_staged_1559("0002-cancel-gated");
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();
        let r = engine
            .cancel(
                &permit,
                "alice",
                "anvil",
                "0002-cancel-gated",
                &chain,
                10,
                &policy,
            )
            .await;
        assert!(matches!(r, Err(TxEngineError::BroadcastDisabled(_))));
        let entry = engine
            .outbox
            .read_in_state(
                "alice",
                "anvil",
                "0002-cancel-gated",
                crate::outbox::OutboxState::Pending,
            )
            .unwrap();
        assert!(
            engine
                .outbox
                .read_broadcast_attempt(&entry, BroadcastAttemptKind::CancelReplacement)
                .unwrap()
                .is_none(),
            "broadcast-disabled cancel must not write marker"
        );
        assert!(!entry.dir.join("cancel_raw_tx").exists());
    }

    // -------------------------------------------------------------------
    // NFT calldata encoding tests. The selectors below are the canonical
    // 4-byte function selectors per the spec; encoding the corresponding
    // alloy `sol!` Call types must produce calldata starting with each.
    // Argument layout is verified against the standard ABI rules
    // (right-padded 32-byte words for `address` / `uint256`).
    // -------------------------------------------------------------------

    #[test]
    fn nft_erc721_safe_transfer_from_calldata_matches_selector_and_args() {
        use alloy::sol_types::SolCall;
        // Selector for safeTransferFrom(address,address,uint256) per ERC-721.
        let selector = [0x42u8, 0x84, 0x2e, 0x0e];
        let from = "0x0000000000000000000000000000000000000111"
            .parse::<Address>()
            .unwrap();
        let to = "0x0000000000000000000000000000000000000222"
            .parse::<Address>()
            .unwrap();
        let token_id = U256::from(0xabcdu64);
        let call = INftWrite721::safeTransferFromCall {
            from,
            to,
            tokenId: token_id,
        };
        let bytes = call.abi_encode();
        assert_eq!(&bytes[..4], &selector);
        // 3 args x 32 bytes = 96 bytes payload.
        assert_eq!(bytes.len(), 4 + 32 * 3);
        // Last byte of the third word matches the low byte of token id.
        assert_eq!(bytes[4 + 32 * 3 - 1], 0xcd);
        assert_eq!(bytes[4 + 32 * 3 - 2], 0xab);
    }

    #[test]
    fn nft_erc721_transfer_from_calldata_matches_selector() {
        use alloy::sol_types::SolCall;
        let selector = [0x23u8, 0xb8, 0x72, 0xdd];
        let call = INftWrite721::transferFromCall {
            from: Address::ZERO,
            to: Address::ZERO,
            tokenId: U256::ZERO,
        };
        let bytes = call.abi_encode();
        assert_eq!(&bytes[..4], &selector);
    }

    #[test]
    fn nft_erc721_approve_calldata_matches_selector_and_args() {
        use alloy::sol_types::SolCall;
        // Same 4-byte selector as ERC-20 `approve(address,uint256)`.
        let selector = [0x09u8, 0x5e, 0xa7, 0xb3];
        let operator = "0x000000000000000000000000000000000000dEaD"
            .parse::<Address>()
            .unwrap();
        let token_id = U256::from(7u64);
        let call = INftWrite721::approveCall {
            to: operator,
            tokenId: token_id,
        };
        let bytes = call.abi_encode();
        assert_eq!(&bytes[..4], &selector);
        // operator's last byte is 0xad; tokenId's last byte is 0x07.
        assert_eq!(bytes[4 + 32 - 1], 0xad);
        assert_eq!(bytes[4 + 64 - 1], 0x07);
    }

    #[test]
    fn nft_set_approval_for_all_calldata_matches_selector_and_bool() {
        use alloy::sol_types::SolCall;
        let selector = [0xa2u8, 0x2c, 0xb4, 0x65];
        let operator = "0x0000000000000000000000000000000000000abc"
            .parse::<Address>()
            .unwrap();

        let call_true = INftWrite721::setApprovalForAllCall {
            operator,
            approved: true,
        };
        let bytes_true = call_true.abi_encode();
        assert_eq!(&bytes_true[..4], &selector);
        // bool true → final word ends in 0x01.
        assert_eq!(bytes_true[4 + 64 - 1], 0x01);

        let call_false = INftWrite721::setApprovalForAllCall {
            operator,
            approved: false,
        };
        let bytes_false = call_false.abi_encode();
        assert_eq!(bytes_false[4 + 64 - 1], 0x00);
    }

    #[test]
    fn nft_erc1155_safe_transfer_from_calldata_matches_selector() {
        use alloy::sol_types::SolCall;
        let selector = [0xf2u8, 0x42, 0x43, 0x2a];
        let call = INftWrite1155::safeTransferFromCall {
            from: Address::ZERO,
            to: Address::ZERO,
            id: U256::from(1u64),
            amount: U256::from(2u64),
            data: Bytes::new(),
        };
        let bytes = call.abi_encode();
        assert_eq!(&bytes[..4], &selector);
    }

    #[test]
    fn parse_u256_accepts_decimal_and_hex() {
        assert_eq!(parse_u256("42").unwrap(), U256::from(42u64));
        assert_eq!(parse_u256("0xff").unwrap(), U256::from(255u64));
        assert!(parse_u256("").is_err());
        assert!(parse_u256("notanumber").is_err());
    }

    #[test]
    fn decode_nft_recipient_round_trips() {
        use alloy::sol_types::SolCall;
        let to = "0x000000000000000000000000000000000000babe"
            .parse::<Address>()
            .unwrap();
        let call = INftWrite721::safeTransferFromCall {
            from: Address::ZERO,
            to,
            tokenId: U256::from(1u64),
        };
        let bytes = call.abi_encode();
        assert_eq!(decode_nft_recipient(&bytes), Some(to));
    }

    #[test]
    fn decode_nft_approve_operator_round_trips() {
        use alloy::sol_types::SolCall;
        let to = "0x000000000000000000000000000000000000beef"
            .parse::<Address>()
            .unwrap();
        let call = INftWrite721::approveCall {
            to,
            tokenId: U256::from(99u64),
        };
        let bytes = call.abi_encode();
        assert_eq!(decode_nft_approve_operator(&bytes), Some(to));
    }

    #[tokio::test]
    async fn resolve_nft_kind_honours_explicit_standard_hint() {
        // The hint short-circuits the on-chain ERC-165 probe; we never
        // actually dial the RPC URL in `spec`, which is why this test
        // can run with a stub spec and no live node.
        let (engine, spec, _dir) = fake_engine(60_000);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let addr = Address::ZERO;
        assert_eq!(
            engine
                .resolve_nft_kind(&chain, addr, Some("erc721"))
                .await
                .unwrap(),
            NftKind::Erc721
        );
        assert_eq!(
            engine
                .resolve_nft_kind(&chain, addr, Some("erc1155"))
                .await
                .unwrap(),
            NftKind::Erc1155
        );
        let err = engine
            .resolve_nft_kind(&chain, addr, Some("erc999"))
            .await
            .unwrap_err();
        assert!(matches!(err, TxEngineError::Token(_)));
    }

    /// `resolve_intent_body` must accept an `NftTransfer` with an
    /// explicit `erc721` hint, encode the safeTransferFrom selector
    /// (0x42842e0e), and hand back an `NftRef` describing the action.
    /// The unreachable RPC means `best_effort_nft_symbol` falls through
    /// to its empty-string branch — that's fine, the test isn't asserting
    /// on the symbol.
    #[tokio::test]
    async fn resolve_intent_body_nft_transfer_hinted_erc721() {
        use bloom_proto::intent::RawIntentBody;
        let (engine, spec, _dir) = fake_engine(60_000);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let from = "0x000000000000000000000000000000000000aaaa"
            .parse::<Address>()
            .unwrap();
        let body = RawIntentBody::NftTransfer {
            contract: "0x000000000000000000000000000000000000ccc7".into(),
            to: "0x000000000000000000000000000000000000beef".into(),
            token_id: "42".into(),
            standard: Some("erc721".into()),
            amount: None,
            safe: true,
            data: None,
        };
        let (to, value, data, token, nft) = engine
            .resolve_intent_body(&body, &chain, 31337, None, from)
            .await
            .unwrap();
        assert_eq!(
            to,
            "0x000000000000000000000000000000000000ccc7"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(value, U256::ZERO);
        // 0x42842e0e = safeTransferFrom(address,address,uint256)
        assert!(data.starts_with("0x42842e0e"), "calldata: {data}");
        assert!(token.is_none());
        let nft = nft.expect("nft ref populated");
        assert!(matches!(nft.action, NftAction::Transfer));
        assert_eq!(nft.kind, "erc721");
        assert_eq!(nft.token_id, "42");
    }

    /// ERC-1155 transfers must encode `safeTransferFrom(address,address,
    /// uint256,uint256,bytes)` — selector 0xf242432a — and default the
    /// amount to `1` when the intent omits it.
    #[tokio::test]
    async fn resolve_intent_body_nft_transfer_hinted_erc1155_defaults_amount_to_one() {
        use bloom_proto::intent::RawIntentBody;
        let (engine, spec, _dir) = fake_engine(60_000);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let from = "0x000000000000000000000000000000000000aaaa"
            .parse::<Address>()
            .unwrap();
        let body = RawIntentBody::NftTransfer {
            contract: "0x0000000000000000000000000000000000001155".into(),
            to: "0x000000000000000000000000000000000000beef".into(),
            token_id: "7".into(),
            standard: Some("erc1155".into()),
            amount: None,
            safe: true,
            data: None,
        };
        let (_to, _v, data, _t, nft) = engine
            .resolve_intent_body(&body, &chain, 31337, None, from)
            .await
            .unwrap();
        assert!(data.starts_with("0xf242432a"), "calldata: {data}");
        let nft = nft.expect("nft ref populated");
        assert_eq!(nft.kind, "erc1155");
        assert_eq!(nft.amount, "1");
    }

    /// Per-token `nft_approve` resolves through the standard probe; with
    /// an explicit erc721 hint we never dial the RPC. Selector must be
    /// the canonical ERC-721 approve (0x095ea7b3).
    #[tokio::test]
    async fn resolve_intent_body_nft_approve_errors_on_unreachable_rpc() {
        use bloom_proto::intent::RawIntentBody;
        // We have no hint on `NftApprove`, so the chain probe runs; with
        // an unreachable URL it errors. Use the resolver directly to
        // exercise just the calldata path: build the intent, then call
        // `resolve_intent_body` against a chain whose nft_detect we can
        // short-circuit. The simplest reproduction: ensure that a clear
        // error surfaces (nft_detect failure) — we already cover the
        // happy path via the calldata-encoding tests above. Here we
        // assert that an Unknown contract is rejected as expected.
        let (engine, spec, _dir) = fake_engine(60_000);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let from = "0x000000000000000000000000000000000000aaaa"
            .parse::<Address>()
            .unwrap();
        let body = RawIntentBody::NftApprove {
            contract: "0x0000000000000000000000000000000000001155".into(),
            operator: "0x000000000000000000000000000000000000beef".into(),
            token_id: "9".into(),
        };
        // Unreachable RPC -> Chain error from nft_detect.
        let r = engine
            .resolve_intent_body(&body, &chain, 31337, None, from)
            .await;
        assert!(r.is_err(), "expected chain error, got {r:?}");
    }

    /// `nft_transfer` against a contract that exposes neither ERC-721
    /// nor ERC-1155 must surface the "not an NFT contract" rejection
    /// path. We can't exercise the live ERC-165 probe here, so we
    /// drive the path by passing a hint that resolves cleanly and
    /// rely on the unhinted `NftApprove` flow above as the chain-error
    /// regression. This test instead checks that an `unknown` standard
    /// hint is rejected as a TokenError.
    #[tokio::test]
    async fn resolve_intent_body_rejects_unknown_standard_hint() {
        use bloom_proto::intent::RawIntentBody;
        let (engine, spec, _dir) = fake_engine(60_000);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let from = Address::ZERO;
        let body = RawIntentBody::NftTransfer {
            contract: "0x0000000000000000000000000000000000001155".into(),
            to: "0x000000000000000000000000000000000000beef".into(),
            token_id: "1".into(),
            standard: Some("erc999".into()),
            amount: None,
            safe: true,
            data: None,
        };
        let err = engine
            .resolve_intent_body(&body, &chain, 31337, None, from)
            .await
            .unwrap_err();
        assert!(matches!(err, TxEngineError::Token(_)), "got {err:?}");
    }

    /// Fix #11: the override sentinel comes from policy.toml, not a hard
    /// "override" string. A custom token must be honoured.
    #[tokio::test]
    async fn confirm_uses_policy_override_token() {
        use bloom_proto::policy::{PolicyAutomation, PolicyCaps, PolicyCheck, PolicyOutcome};

        let (engine, spec, dir) = fake_engine(60_000);
        let engine = with_test_auth_and_host(engine, true);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();

        // Soft-warn on tx, with a non-default override token.
        let policy = bloom_proto::Policy {
            automation: PolicyAutomation {
                override_token: Some("yolo".into()),
                ..Default::default()
            },
            caps: PolicyCaps::default(),
            ..Default::default()
        };

        let mut staged = fake_staged_1559("0001-test");
        staged.expires_ms = now_ms() + 60_000;
        // Inject a Warn check directly so the override gate fires.
        staged.policy_checks = vec![PolicyCheck::soft(
            "test.warn",
            PolicyOutcome::Warn,
            "soft cap",
        )];
        engine.outbox.write_pending(&staged, "p").unwrap();

        // "y" must be rejected — needs the policy's override token.
        let r = engine
            .confirm(&permit, "alice", "anvil", "0001-test", &chain, &policy, "y")
            .await;
        assert!(matches!(r, Err(TxEngineError::PolicyDenied)));

        // Default sentinel ("override") must NOT bypass when policy
        // overrides it.
        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-test",
                &chain,
                &policy,
                "override",
            )
            .await;
        assert!(matches!(r, Err(TxEngineError::PolicyDenied)));

        // The configured token gets past the policy gate; the next gate
        // is broadcast, which fails on the unreachable RPC. We treat any
        // *non*-PolicyDenied error as the policy gate having let us
        // through.
        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-test",
                &chain,
                &policy,
                "yolo",
            )
            .await;
        match r {
            Err(TxEngineError::PolicyDenied) => panic!("override token did not bypass warn"),
            Ok(_) => panic!("unexpected broadcast success on unreachable RPC"),
            Err(_) => {}
        }
    }

    /// A hard-Deny policy check must block confirm() before broadcast,
    /// return PolicyDenied, and move the outbox entry to Failed.
    #[tokio::test]
    async fn policy_hard_deny_blocks_confirm_and_marks_failed() {
        use bloom_proto::policy::{PolicyCheck, PolicyOutcome};

        let (engine, spec, dir) = fake_engine(60_000);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let policy = bloom_proto::Policy::default();

        let mut staged = fake_staged_1559("0001-test");
        staged.expires_ms = now_ms() + 60_000;
        staged.policy_checks = vec![PolicyCheck::hard(
            "caps.max_value_eth",
            PolicyOutcome::Deny,
            "value exceeds max",
        )];
        engine.outbox.write_pending(&staged, "p").unwrap();

        let r = engine
            .confirm(&permit, "alice", "anvil", "0001-test", &chain, &policy, "y")
            .await;
        assert!(
            matches!(r, Err(TxEngineError::PolicyDenied)),
            "expected PolicyDenied, got {r:?}"
        );

        // The outbox entry must have been moved to the `failed` state.
        let entry = engine.outbox.read("alice", "anvil", "0001-test").unwrap();
        assert_eq!(
            entry.state,
            crate::outbox::OutboxState::Failed,
            "tx must be Failed after hard deny"
        );
    }

    /// A soft-Warn check must block confirm() when no override sentinel is
    /// given, and must pass the policy gate when the correct sentinel is
    /// given. The outbox entry must stay Pending after a Warn rejection so
    /// the user can retry with the override — it must NOT be moved to Failed.
    #[tokio::test]
    async fn policy_soft_warn_requires_override_sentinel() {
        use bloom_proto::policy::{PolicyCheck, PolicyOutcome};

        let (engine, spec, dir) = fake_engine(60_000);
        let engine = with_test_auth_and_host(engine, true);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let mut policy = bloom_proto::Policy::default();
        policy.automation.override_token = Some("y".into());

        let mut staged = fake_staged_1559("0001-test");
        staged.expires_ms = now_ms() + 60_000;
        staged.policy_checks = vec![PolicyCheck::soft(
            "caps.warn_value_eth",
            PolicyOutcome::Warn,
            "soft cap exceeded",
        )];
        engine.outbox.write_pending(&staged, "p").unwrap();

        // An explicit false decision must be rejected even when the policy's
        // configured text sentinel is the historically common value "y".
        let r = engine
            .confirm_with_warning_override(
                &permit,
                "alice",
                "anvil",
                "0001-test",
                &chain,
                &policy,
                false,
            )
            .await;
        assert!(
            matches!(r, Err(TxEngineError::PolicyDenied)),
            "expected PolicyDenied without override, got {r:?}"
        );

        // After a Warn rejection the entry must still be Pending (not Failed).
        let entry = engine.outbox.read("alice", "anvil", "0001-test").unwrap();
        assert_eq!(
            entry.state,
            crate::outbox::OutboxState::Pending,
            "tx must stay Pending after warn-without-override"
        );

        // Correct sentinel — gets past the policy gate; broadcast will fail
        // on the unreachable RPC. Any error other than PolicyDenied means
        // the policy gate was successfully passed.
        let r = engine
            .confirm(&permit, "alice", "anvil", "0001-test", &chain, &policy, "y")
            .await;
        match r {
            Err(TxEngineError::PolicyDenied) => panic!("override sentinel did not bypass warn"),
            Ok(_) => panic!("unexpected broadcast success on unreachable RPC"),
            Err(_) => {} // any other error means the policy gate was passed
        }
    }

    #[tokio::test]
    async fn broadcast_approval_required_blocks_confirm_before_rpc() {
        let (engine, spec, dir) = fake_engine(60_000);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let mut policy = bloom_proto::Policy::default();
        policy.approval.require_broadcast_approval = true;

        let mut staged = fake_staged_1559("0001-approval");
        staged.value_wei = "1".into();
        staged.usd_value = Some(0.01);
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();

        // Without auth services wired, confirm must fail closed instead of
        // accepting forgeable marker files (M1: marker fallback removed).
        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-approval",
                &chain,
                &policy,
                "y",
            )
            .await;
        assert!(
            matches!(r, Err(TxEngineError::ApprovalServiceUnavailable(ref e)) if e.contains("not wired")),
            "expected fail-closed when unwired, got {r:?}"
        );

        // Supplying a review hash no longer helps without wired auth services.
        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-approval",
                &chain,
                &policy,
                "y",
            )
            .await;
        assert!(
            matches!(r, Err(TxEngineError::ApprovalServiceUnavailable(ref e)) if e.contains("not wired")),
            "expected fail-closed when unwired even with review hash, got {r:?}"
        );
    }

    #[tokio::test]
    async fn wired_auth_outbox_confirm_ignores_legacy_marker_and_issues_challenge() {
        let (engine, spec, dir) = fake_engine(60_000);
        let engine = engine.with_auth_services(
            Arc::new(RejectingTestVerifier),
            Arc::new(ChallengeOnlyWriter),
        );
        let engine = with_test_host(engine, false);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let mut policy = bloom_proto::Policy::default();
        policy.approval.require_broadcast_approval = true;

        let mut staged = fake_staged_1559("0001-sealed-approval");
        staged.value_wei = "1".into();
        staged.usd_value = Some(0.01);
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();

        let entry = engine
            .outbox
            .read("alice", "anvil", "0001-sealed-approval")
            .unwrap();
        let legacy_hash = "legacy-reviewed-hash";
        engine
            .outbox
            .write_artefact(&entry.dir, "review_intent.json", br#"{"schema":"legacy"}"#)
            .unwrap();
        engine
            .outbox
            .write_artefact(
                &entry.dir,
                "review_approved.json",
                &serde_json::to_vec_pretty(&serde_json::json!({
                    "schema": "bloom.review_approved.v1",
                    "intent_hash": legacy_hash,
                }))
                .unwrap(),
            )
            .unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-sealed-approval",
                &chain,
                &policy,
                "y",
            )
            .await;
        let requirement = match &r {
            Err(TxEngineError::ApprovalRequired(requirement)) => requirement,
            other => panic!("expected typed Sealed Approval requirement, got {other:?}"),
        };
        let challenge: ApprovalChallenge = serde_json::from_slice(
            &std::fs::read(entry.dir.join(OUTBOX_APPROVAL_CHALLENGE_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(challenge.surface, "outbox");
        assert_eq!(
            challenge.action_id,
            outbox_action_id(&staged, EvmOutboxActionKind::Confirm)
        );
        assert_eq!(challenge.intent_hash, "outbox-intent");
        assert_eq!(requirement.action_id, challenge.action_id);
        assert_eq!(requirement.expires_ms, challenge.expiry_ms);
        assert_eq!(
            requirement.ceremony_url,
            challenge.ceremony_url.as_deref().unwrap()
        );
    }

    #[tokio::test]
    async fn wired_auth_outbox_confirm_accepts_approval_without_legacy_marker() {
        let (engine, spec, dir) = fake_engine(60_000);
        let engine = engine.with_auth_services(
            Arc::new(AcceptingTestVerifier),
            Arc::new(ChallengeOnlyWriter),
        );
        let engine = with_test_host(engine, false);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let mut policy = bloom_proto::Policy::default();
        policy.approval.require_broadcast_approval = true;

        let mut staged = fake_staged_1559("0001-sealed-approval-ok");
        staged.value_wei = "1".into();
        staged.usd_value = Some(0.01);
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();
        let entry = engine
            .outbox
            .read("alice", "anvil", "0001-sealed-approval-ok")
            .unwrap();
        engine
            .outbox
            .write_artefact(
                &entry.dir,
                OUTBOX_APPROVAL_FILE,
                &serde_json::to_vec_pretty(&SignedApproval {
                    schema: APPROVAL_SCHEMA_V1.into(),
                    action_id: outbox_action_id(&staged, EvmOutboxActionKind::Confirm),
                    wallet: "alice".into(),
                    surface: "outbox".into(),
                    petal_id: PETAL_ID_EVM_WALLET.into(),
                    petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
                    intent_hash: "outbox-intent".into(),
                    server_nonce: "nonce-1".into(),
                    assurance: AssuranceLevel::Standard,
                    daemon_terms_digest: "1".repeat(64),
                    petal_policy_digest: "2".repeat(64),
                    policy_version: 0,
                    expiry_ms: now_ms() as u64 + 60_000,
                    signer_transport: SignerTransport::BrowserWebauthn,
                    credential_id: "cred-1".into(),
                    review_session_id: None,
                    webauthn_assertion: WebAuthnAssertionRecord {
                        credential_id: "cred-1".into(),
                        authenticator_data_b64: "AA".into(),
                        client_data_json_b64: "e30".into(),
                        signature_b64: "AA".into(),
                        user_handle_b64: None,
                    },
                })
                .unwrap(),
            )
            .unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-sealed-approval-ok",
                &chain,
                &policy,
                "y",
            )
            .await;
        match r {
            Err(TxEngineError::ApprovalRequired(e)) => {
                panic!("signed approval should satisfy approval gate: {e}")
            }
            Ok(_) => panic!("unexpected broadcast success on unreachable RPC"),
            Err(_) => {}
        }
        let entry = engine
            .outbox
            .read("alice", "anvil", "0001-sealed-approval-ok")
            .unwrap();
        assert!(
            engine
                .outbox
                .read_broadcast_attempt(&entry, BroadcastAttemptKind::Confirm)
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn malformed_stored_approval_is_state_error_not_ceremony() {
        let (engine, spec, dir) = fake_engine(60_000);
        let engine = engine.with_auth_services(
            Arc::new(RejectingTestVerifier),
            Arc::new(ChallengeOnlyWriter),
        );
        let engine = with_test_host(engine, false);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec).unwrap();
        let mut policy = bloom_proto::Policy::default();
        policy.approval.require_broadcast_approval = true;
        let mut staged = fake_staged_1559("0001-malformed-approval");
        staged.value_wei = "1".into();
        staged.usd_value = Some(0.01);
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();
        let entry = engine
            .outbox
            .read("alice", "anvil", "0001-malformed-approval")
            .unwrap();
        std::fs::write(entry.dir.join(OUTBOX_APPROVAL_FILE), b"not-json").unwrap();

        let result = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-malformed-approval",
                &chain,
                &policy,
                "y",
            )
            .await;
        assert!(
            matches!(result, Err(TxEngineError::ApprovalState(ref message)) if message.contains("stored approval.json is invalid")),
            "malformed approval must not initiate a ceremony: {result:?}"
        );
    }

    #[tokio::test]
    async fn wired_auth_outbox_confirm_retries_consumed_approval_for_same_intent() {
        let (engine, spec, dir) = fake_engine(60_000);
        let engine =
            engine.with_auth_services(Arc::new(RejectingTestVerifier), Arc::new(PreApprovedWriter));
        let engine = with_test_host(engine, false);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let mut policy = bloom_proto::Policy::default();
        policy.approval.require_broadcast_approval = true;

        let mut staged = fake_staged_1559("0001-sealed-approval-retry");
        staged.value_wei = "1".into();
        staged.usd_value = Some(0.01);
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-sealed-approval-retry",
                &chain,
                &policy,
                "y",
            )
            .await;
        match r {
            Err(TxEngineError::ApprovalRequired(e)) => {
                panic!("consumed approval for same intent should satisfy retry gate: {e}")
            }
            Ok(_) => panic!("unexpected broadcast success on unreachable RPC"),
            Err(_) => {}
        }
    }

    #[tokio::test]
    async fn under_policy_autonomy_requires_usd_and_limits() {
        let (engine, spec, dir) = fake_engine(60_000);
        let engine = with_test_auth_and_host(engine, true);
        let permit = permit_for(&dir);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let mut policy = bloom_proto::Policy::default();
        policy.approval.agent_autonomy = Some(bloom_proto::AgentAutonomyMode::UnderPolicy);
        policy.limits.max_tx_usd = Some("3".into());
        policy.limits.max_day_usd = Some("10".into());

        let mut no_usd = fake_staged_1559("0001-no-usd");
        no_usd.value_wei = "1".into();
        no_usd.action_kind = TxActionKind::NativeTransfer;
        no_usd.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&no_usd, "p").unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-no-usd",
                &chain,
                &policy,
                "y",
            )
            .await;
        assert!(
            !matches!(r, Err(TxEngineError::ApprovalDenied(ref e)) if e.contains("USD valuation")),
            "missing valuation must fall back to fresh review, got {r:?}"
        );

        let mut priced = fake_staged_1559("0002-priced");
        priced.value_wei = "1".into();
        priced.usd_value = Some(2.0);
        priced.action_kind = TxActionKind::NativeTransfer;
        priced.valuation = Some(bloom_auth_api::ValuationQuote {
            asset_id: "native:anvil".into(),
            amount_base_units: "1".into(),
            usd_micro: 2_000_000,
            source: "test".into(),
            quote_timestamp_ms: now_ms() as u64,
            fetched_at_ms: now_ms() as u64,
            max_age_ms: 60_000,
            confidence_ppm: None,
            stablecoin_assumption: false,
        });
        priced.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&priced, "p").unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0002-priced",
                &chain,
                &policy,
                "y",
            )
            .await;
        match r {
            Err(TxEngineError::ApprovalRequired(e)) => {
                panic!("under-policy tx should pass approval gate, got {e}")
            }
            Ok(_) => panic!("unexpected broadcast success on unreachable RPC"),
            Err(_) => {}
        }
    }

    #[test]
    fn budget_snapshot_does_not_double_count_current_pending_action() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let mut staged = fake_staged_1559("current-budget");
        staged.created_ms = now_ms();
        staged.action_kind = TxActionKind::NativeTransfer;
        staged.value_wei = "1".into();
        staged.valuation = Some(bloom_auth_api::ValuationQuote {
            asset_id: "native:anvil".into(),
            amount_base_units: "1".into(),
            usd_micro: 6_000_000,
            source: "test".into(),
            quote_timestamp_ms: now_ms() as u64,
            fetched_at_ms: now_ms() as u64,
            max_age_ms: 30_000,
            confidence_ppm: None,
            stablecoin_assumption: false,
        });
        engine.outbox.write_pending(&staged, "p").unwrap();

        let budget = engine.budget_snapshot(&staged).unwrap();
        assert_eq!(budget.spent_day_micro_usd, 0);

        let mut policy = Policy::default();
        policy.approval.agent_autonomy = Some(bloom_proto::AgentAutonomyMode::UnderPolicy);
        policy.limits.max_tx_usd = Some("10".into());
        policy.limits.max_day_usd = Some("10".into());
        assert!(matches!(
            bloom_proto::evaluate_action_authorization(
                &policy,
                &[],
                &engine.authorization_subject(&staged),
                Some(&budget),
                None,
                bloom_proto::AuthorizationSurface::Cli,
            ),
            bloom_proto::AutonomyDecision::ApprovedAutonomous { .. }
        ));
    }

    /// `submit_via_private` looks up the registered provider by
    /// `(chain_id, provider_id)` and forwards the raw bytes. The mock
    /// records every submission so we can verify routing without a
    /// live chain.
    #[tokio::test]
    async fn submit_via_private_routes_to_registered_provider() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let mock = Arc::new(bloom_mempool::MockPrivateRpcProvider::new("mev_blocker"));
        engine
            .register_private_rpc(bloom_mempool::MAINNET_CHAIN_ID, mock.clone())
            .expect("register_private_rpc");

        let raw = alloy::primitives::Bytes::from_static(b"\x01\x02\x03");
        let hash = engine
            .submit_via_private(bloom_mempool::MAINNET_CHAIN_ID, "mev_blocker", &raw)
            .await
            .expect("submit_via_private");
        assert_eq!(hash, alloy::primitives::keccak256(&raw));
        assert_eq!(mock.submissions().len(), 1);
        assert_eq!(mock.submissions()[0], raw);
    }

    /// When the requested provider id is not registered for the given
    /// chain id, the helper returns `PrivateProviderNotConfigured` and
    /// does NOT silently fall through to public broadcast.
    #[tokio::test]
    async fn submit_via_private_errors_when_not_configured() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let mock = Arc::new(bloom_mempool::MockPrivateRpcProvider::new("mev_blocker"));
        engine
            .register_private_rpc(bloom_mempool::MAINNET_CHAIN_ID, mock)
            .expect("register_private_rpc");

        let raw = alloy::primitives::Bytes::from_static(b"\x01\x02\x03");
        let r = engine
            .submit_via_private(bloom_mempool::MAINNET_CHAIN_ID, "flashbots", &raw)
            .await;
        match r {
            Err(TxEngineError::PrivateProviderNotConfigured(id)) => {
                assert_eq!(id, "flashbots");
            }
            other => panic!("expected PrivateProviderNotConfigured, got {other:?}"),
        }
    }

    /// The registry is keyed by `(chain_id, provider_id)`, so two
    /// providers registered on the same chain must be reachable
    /// independently and only the one keyed by the requested id should
    /// see the submission.
    #[tokio::test]
    async fn register_private_rpc_uses_provider_id_as_key() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let mev_blocker = Arc::new(bloom_mempool::MockPrivateRpcProvider::new("mev_blocker"));
        let flashbots = Arc::new(bloom_mempool::MockPrivateRpcProvider::new("flashbots"));
        engine
            .register_private_rpc(bloom_mempool::MAINNET_CHAIN_ID, mev_blocker.clone())
            .expect("register_private_rpc mev_blocker");
        engine
            .register_private_rpc(bloom_mempool::MAINNET_CHAIN_ID, flashbots.clone())
            .expect("register_private_rpc flashbots");

        let raw_a = alloy::primitives::Bytes::from_static(b"\xaa");
        let raw_b = alloy::primitives::Bytes::from_static(b"\xbb");
        engine
            .submit_via_private(bloom_mempool::MAINNET_CHAIN_ID, "mev_blocker", &raw_a)
            .await
            .expect("submit mev_blocker");
        engine
            .submit_via_private(bloom_mempool::MAINNET_CHAIN_ID, "flashbots", &raw_b)
            .await
            .expect("submit flashbots");

        assert_eq!(mev_blocker.submissions(), vec![raw_a]);
        assert_eq!(flashbots.submissions(), vec![raw_b]);
    }

    /// Registering a provider under a chain id it does not declare in
    /// `supported_chains()` is rejected at the registration call. This
    /// catches misconfiguration in the daemon wiring before any tx is
    /// ever submitted.
    #[tokio::test]
    async fn register_private_rpc_rejects_unsupported_chain() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let mock = Arc::new(bloom_mempool::MockPrivateRpcProvider::new("mev_blocker"));
        // MockPrivateRpcProvider reports &[MAINNET_CHAIN_ID] (= 1).
        // Registering against an unsupported chain must fail.
        let r = engine.register_private_rpc(5, mock);
        match r {
            Err(TxEngineError::PrivateProviderChainMismatch { provider, chain_id }) => {
                assert_eq!(provider, "mev_blocker");
                assert_eq!(chain_id, 5);
            }
            other => panic!("expected PrivateProviderChainMismatch, got {other:?}"),
        }
    }

    /// Sepolia is the live low-risk exercise path for Flashbots Protect.
    /// When a provider explicitly declares Sepolia support, broadcast
    /// should route privately instead of falling through to public RPC.
    #[tokio::test]
    async fn broadcast_routes_private_on_sepolia_when_provider_supports_it() {
        static SEPOLIA_ONLY: &[u64] = &[bloom_mempool::SEPOLIA_CHAIN_ID];

        let (engine, mut spec, _dir) = fake_engine(60_000);
        spec.name = "sepolia".into();
        spec.chain_id = bloom_mempool::SEPOLIA_CHAIN_ID;
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let signer = test_signer();
        let mut policy = bloom_proto::Policy::default();
        policy.private.enabled = true;
        policy.private.provider = "flashbots".into();

        let mock = Arc::new(
            bloom_mempool::MockPrivateRpcProvider::new("flashbots")
                .with_supported_chains(SEPOLIA_ONLY),
        );
        engine
            .register_private_rpc(bloom_mempool::SEPOLIA_CHAIN_ID, mock.clone())
            .expect("register sepolia private provider");

        let mut staged = fake_staged_1559("0001-private-sepolia");
        staged.chain = "sepolia".into();
        staged.chain_id = bloom_mempool::SEPOLIA_CHAIN_ID;

        let hash = engine
            .broadcast(&staged, &chain, &signer, &policy)
            .await
            .expect("private sepolia broadcast");

        assert_eq!(mock.submissions().len(), 1);
        assert_eq!(hash, alloy::primitives::keccak256(&mock.submissions()[0]));
    }

    /// Private routing is allowlisted by chain. When `policy.private.enabled`
    /// is set on an unsupported local/test chain, `broadcast` must reject
    /// before touching the RPC.
    #[tokio::test]
    async fn broadcast_rejects_private_on_non_mainnet() {
        let (engine, spec, _dir) = fake_engine(60_000);
        let chain = bloom_evm::ChainClient::new(spec.clone()).unwrap();
        let signer = test_signer();
        let mut policy = bloom_proto::Policy::default();
        policy.private.enabled = true;
        policy.private.provider = "mev_blocker".into();

        // fake_staged_1559 uses chain_id 31337 (anvil) — not mainnet.
        let staged = fake_staged_1559("0001-private-testnet");

        let r = engine.broadcast(&staged, &chain, &signer, &policy).await;
        match r {
            Err(TxEngineError::PrivateNotSupportedOnChain(name)) => {
                assert_eq!(name, "anvil");
            }
            other => panic!("expected PrivateNotSupportedOnChain, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // enso_quote_age_secs
    // -------------------------------------------------------------------

    fn enso_hex(json: &str) -> String {
        format!("0x{}", hex::encode(json.as_bytes()))
    }

    #[test]
    fn enso_quote_age_parses_timestamp() {
        let hex = enso_hex(r#"{"Source":"Enso","Timestamp":1700000000}"#);
        assert_eq!(enso_quote_age_secs(&hex, 1700000300), Some(300));
    }

    #[test]
    fn enso_quote_age_zero_for_current() {
        let hex = enso_hex(r#"{"Source":"Enso","Timestamp":1700000000}"#);
        assert_eq!(enso_quote_age_secs(&hex, 1700000000), Some(0));
    }

    #[test]
    fn enso_quote_age_none_for_future() {
        let hex = enso_hex(r#"{"Source":"Enso","Timestamp":1700000100}"#);
        assert_eq!(enso_quote_age_secs(&hex, 1700000000), None);
    }

    #[test]
    fn enso_quote_age_none_for_non_enso_calldata() {
        assert_eq!(enso_quote_age_secs("0xdeadbeef", 1700000000), None);
    }

    #[test]
    fn enso_quote_age_none_for_missing_timestamp() {
        let hex = enso_hex(r#"{"Source":"Enso","Route":"0x1234"}"#);
        assert_eq!(enso_quote_age_secs(&hex, 1700000000), None);
    }

    #[test]
    fn f64_to_micro_usd_normal() {
        assert_eq!(f64_to_micro_usd(0.0), Some(0));
        assert_eq!(f64_to_micro_usd(1.0), Some(1_000_000));
        assert_eq!(f64_to_micro_usd(1.5), Some(1_500_000));
    }

    #[test]
    fn authorization_subject_requires_verified_typed_transfer_kind() {
        let (engine, _spec, _dir) = fake_engine(60_000);
        let mut native = fake_staged_1559("typed-native");
        native.value_wei = "1".into();
        native.action_kind = TxActionKind::NativeTransfer;
        native.valuation = Some(bloom_auth_api::ValuationQuote {
            asset_id: "native:anvil".into(),
            amount_base_units: "1".into(),
            usd_micro: 1_000_000,
            source: "test".into(),
            quote_timestamp_ms: now_ms() as u64,
            fetched_at_ms: now_ms() as u64,
            max_age_ms: 60_000,
            confidence_ppm: None,
            stablecoin_assumption: false,
        });
        let subject = engine.authorization_subject(&native);
        assert!(subject.value_moving);
        assert!(subject.calldata_verified);
        assert_eq!(subject.total_value_usd_micro, Some(1_000_000));

        let mut raw = native;
        raw.action_kind = TxActionKind::ContractCall;
        raw.data_hex = "0xdeadbeef".into();
        let subject = engine.authorization_subject(&raw);
        assert!(subject.value_moving);
        assert!(!subject.calldata_verified);
        assert_eq!(subject.total_value_usd_micro, Some(1_000_000));
    }

    #[test]
    fn legacy_usd_value_is_not_resealed_as_authoritative_valuation() {
        let mut staged = fake_staged_1559("legacy-usd");
        staged.action_kind = TxActionKind::NativeTransfer;
        staged.value_wei = "1".into();
        staged.usd_value = Some(999_999.0);

        let subject =
            evm_sealed_subject(&staged, EvmOutboxActionKind::Confirm, &test_signing_hash())
                .unwrap();
        assert_eq!(subject.value.valuation_usd_micro, None);
        assert_eq!(subject.value.valuation, None);
    }

    #[test]
    fn f64_to_micro_usd_rejects_nan() {
        assert_eq!(f64_to_micro_usd(f64::NAN), None);
    }

    #[test]
    fn f64_to_micro_usd_rejects_infinity() {
        assert_eq!(f64_to_micro_usd(f64::INFINITY), None);
        assert_eq!(f64_to_micro_usd(f64::NEG_INFINITY), None);
    }

    #[test]
    fn f64_to_micro_usd_rejects_negative() {
        assert_eq!(f64_to_micro_usd(-1.0), None);
        assert_eq!(f64_to_micro_usd(-0.001), None);
    }

    #[test]
    fn f64_to_micro_usd_rejects_overflow() {
        assert_eq!(f64_to_micro_usd(f64::MAX), None);
    }

    #[test]
    fn insufficient_native_funds_check_is_hard_and_actionable_in_plan() {
        let account = "0x0000000000000000000000000000000000000001";
        let check = insufficient_native_funds_check(
            account,
            "Base",
            "ETH",
            18,
            U256::ZERO,
            U256::from(1_000_000_000_000_000_000u128),
            21_000,
            100_000_000_000,
        )
        .expect("zero balance cannot cover value and gas");

        assert_eq!(check.rule, "balance.native_funds");
        assert!(check.is_hard_violation());
        assert!(
            check
                .message
                .contains(&format!("account {account} has 0 ETH on Base"))
        );
        assert!(check.message.contains("requires up to 1.0021 ETH"));
        assert!(check.message.contains("1 value + 0.0021 gas"));
        assert!(check.message.contains("Fund the account and restage"));

        let mut staged = fake_staged_1559("0001-insufficient-funds");
        staged.policy_checks.push(check);
        let plan = bloom_proto::PlanRender::render(&staged, "ETH", 18);
        assert!(plan.contains("[Deny] balance.native_funds:"));
        assert!(plan.contains("Fund the account and restage"));
    }

    #[test]
    fn native_funding_check_accepts_exact_required_balance() {
        let gas_budget = U256::from(21_000u64) * U256::from(100_000_000_000u128);
        let value = U256::from(1_000_000_000_000_000_000u128);

        assert!(
            insufficient_native_funds_check(
                "0x0000000000000000000000000000000000000001",
                "Base",
                "ETH",
                18,
                value + gas_budget,
                value,
                21_000,
                100_000_000_000,
            )
            .is_none(),
            "an account with exactly value plus the staged gas cap is funded"
        );
    }

    #[test]
    fn eip1559_fee_overrides_require_a_complete_decimal_ordered_pair() {
        assert_eq!(
            Eip1559FeeOverrides::from_decimal_pair(Some("100"), Some("10"), false).unwrap(),
            Some(Eip1559FeeOverrides {
                max_fee_per_gas: 100,
                max_priority_fee_per_gas: 10,
            })
        );
        assert!(
            Eip1559FeeOverrides::from_decimal_pair(None, None, false)
                .unwrap()
                .is_none()
        );

        for result in [
            Eip1559FeeOverrides::from_decimal_pair(Some("100"), None, false),
            Eip1559FeeOverrides::from_decimal_pair(None, Some("10"), false),
            Eip1559FeeOverrides::from_decimal_pair(Some("1e2"), Some("10"), false),
            Eip1559FeeOverrides::from_decimal_pair(Some("100"), Some("101"), false),
            Eip1559FeeOverrides::from_decimal_pair(Some("100"), Some("10"), true),
        ] {
            assert!(matches!(result, Err(TxEngineError::InvalidFeeOverride(_))));
        }
    }
}
