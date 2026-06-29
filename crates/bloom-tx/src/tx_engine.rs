//! Tx engine: turn a parsed RawIntent into a StagedTx, simulate it,
//! then on confirm sign and broadcast. Also handles same-nonce
//! replacement / cancel txs and a legacy (non-1559) build path.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::network::EthereumWallet;
use alloy::network::{NetworkTransactionBuilder, TransactionBuilder};
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::rpc::types::eth::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use bloom_chain::{ChainClient, ChainError, IERC20, NftKind};

// Local NFT-write interfaces. `bloom-chain` declares the read shapes for
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
use bloom_proto::{
    AddressBook, ChainSpec, HomeWritePermit, NftAction, NftRef, Policy, RawIntent, RawIntentBody,
    StagedTx, TokenRef, TxStatus, parse_amount, parse_eth, parse_units,
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
    #[error("policy denied")]
    PolicyDenied,
    #[error("broadcast disabled for chain '{0}' (set allow_broadcast=true)")]
    BroadcastDisabled(String),
    #[error("broadcast approval required: {0}")]
    BroadcastApprovalRequired(String),
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

/// Per-(wallet, chain, from) stage-serialisation lock map.
/// Outer lock: `parking_lot` (held microseconds for HashMap lookup/insert).
/// Inner lock: `tokio` async mutex (held for the stage critical section).
type NonceLocks =
    Arc<parking_lot::Mutex<HashMap<(String, String, Address), Arc<tokio::sync::Mutex<()>>>>>;

/// Stage / confirm the lifecycle.
#[derive(Clone)]
pub struct TxEngine {
    pub outbox: Outbox,
    /// Default stage TTL in ms.
    pub stage_ttl_ms: u128,
    /// Mainnet broadcast kill-switch.
    pub block_mainnet_broadcast: bool,
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
}

impl TxEngine {
    pub fn new(outbox: Outbox, stage_ttl_ms: u128, block_mainnet_broadcast: bool) -> Self {
        Self {
            outbox,
            stage_ttl_ms,
            block_mainnet_broadcast,
            token_cache: Arc::new(RwLock::new(HashMap::new())),
            resolver: None,
            price_oracle: None,
            mempool_indexes: Arc::new(RwLock::new(BTreeMap::new())),
            private_rpcs: Arc::new(RwLock::new(BTreeMap::new())),
            nonce_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            session_store: crate::session::SessionStore::new(),
        }
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
                data,
            } => {
                let to_addr = self.resolve_recipient_async(to, address_book).await?;
                if let Some(v) = Self::resolve_native_value(value, token)? {
                    let data = data.clone().unwrap_or_else(|| "0x".into());
                    Ok((to_addr, v, data, None, None))
                } else {
                    let token_str = token.as_deref().unwrap_or("");
                    let (token_addr, sym_hint) = Self::resolve_token_address(token_str, chain_id)?;
                    let meta = self.token_meta(chain, token_addr, &sym_hint).await?;
                    let parsed =
                        parse_amount(value).map_err(|e| TxEngineError::Amount(e.to_string()))?;
                    // A native metric unit (wei/gwei/eth) on an ERC-20 amount is
                    // ambiguous — it would be silently rescaled by token
                    // decimals. Reject it and point at the unambiguous forms.
                    // A bare integer (explicit_unit == false) is still accepted
                    // as a human token amount.
                    if parsed.explicit_unit && parsed.is_native() {
                        return Err(TxEngineError::Amount(format!(
                            "'{value}' uses a native unit ('{}') for an ERC-20 token; write a human \
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
                "Enso intents flow through bloom-defi (not in v1 stage path)".into(),
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
        self.assert_write_permit(permit)?;
        let spec: &ChainSpec = chain.spec();
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
        let max_fee = gas_price.saturating_mul(2);
        let prio = (gas_price / 10).max(1);

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
                    let data_nonempty = !data_bytes.is_empty();
                    let to_has_code = session
                        .code(to)
                        .await
                        .map(|c| !c.is_empty())
                        .unwrap_or(false);
                    policy_ctx.destination_is_contract = data_nonempty || to_has_code;
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
                staged_policy_extras.push(bloom_proto::PolicyCheck {
                    rule: "nft.approve_all".into(),
                    outcome,
                    message: if *approved {
                        format!(
                            "operator-wide approval to {op_disp} — review carefully (write override token to confirm)"
                        )
                    } else {
                        format!("revoking operator-wide approval for {op_disp}")
                    },
                });
            }
            RawIntentBody::Enso { .. } => {}
        }
        // Only call the oracle when the active policy actually evaluates
        // a dollar-denominated rule — otherwise we'd add HTTP latency to
        // every stage for nothing.
        let needs_usd = policy.caps.per_tx_usd.is_some()
            || policy.caps.require_confirm_above_usd.is_some()
            || policy.caps.per_day_usd.is_some();
        policy_ctx.usd_value = intent
            .usd_value_hint
            .as_deref()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0);
        if policy_ctx.usd_value.is_none() && needs_usd && value_wei > U256::ZERO {
            policy_ctx.usd_value = if let Some(oracle) = &self.price_oracle {
                oracle
                    .native_usd(&spec.name, value_wei, spec.native_decimals)
                    .await
            } else {
                None
            };
        }
        // Trailing 24h USD spend across all chains for this wallet.
        // Only consulted when the policy actually has a per_day cap;
        // we still set it whenever a USD rule fires so plan.md / audit
        // can show the running total (cheap — just walks intent.json).
        if needs_usd {
            const DAY_MS: u128 = 24 * 60 * 60 * 1000;
            let since = now_ms.saturating_sub(DAY_MS);
            policy_ctx.usd_spent_last_24h = self.outbox.sum_usd_since(wallet, since).ok();
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
            tx_hash: None,
            token: token_for_plan,
            nft: nft_for_plan,
            usd_value: policy_ctx.usd_value,
            depends_on: None,
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
    pub async fn confirm(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        chain_name: &str,
        id: &str,
        chain: &ChainClient,
        signer: &PrivateKeySigner,
        policy: &Policy,
        confirm_text: &str,
        reviewed_intent_hash: Option<&str>,
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
                .reconcile_confirm_attempt(&entry, attempt, chain, policy, reviewed_intent_hash)
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
        let sentinel = policy.override_sentinel();
        let override_text = confirm_text.trim().eq_ignore_ascii_case(sentinel);
        if warn && !override_text {
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
            && !override_text
        {
            return Err(TxEngineError::EnsoQuoteStale { age });
        }

        // Broadcast gate: never broadcast to mainnet by default.
        let spec = chain.spec();
        let is_mainnet = bloom_proto::Config::is_mainnet_id(spec.chain_id);
        if (self.block_mainnet_broadcast && is_mainnet) || !spec.allow_broadcast {
            debug!(
                id = %staged.id,
                wallet,
                chain = %spec.name,
                is_mainnet,
                allow_broadcast = spec.allow_broadcast,
                block_mainnet = self.block_mainnet_broadcast,
                "tx.broadcast_disabled"
            );
            return Err(TxEngineError::BroadcastDisabled(spec.name.clone()));
        }
        // Pre-broadcast simulation first (no side effects): eth_call against
        // current state so a tx that would revert is caught here instead of
        // burning gas. The override sentinel forces it through.
        if !override_text {
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
            subject.value_moving,
            now_ms(),
        );
        if let Some((ref sid, _)) = session_debit {
            debug!(id = %staged.id, session = %sid, "tx.authorized_by_session");
        } else {
            self.ensure_action_authorized(
                &staged,
                policy,
                reviewed_intent_hash,
                bloom_proto::AuthorizationSurface::Cli,
            )?;
        }

        let tx_hash = match self
            .submit_with_marker(
                &entry,
                BroadcastAttemptKind::Confirm,
                &staged,
                chain,
                signer,
                policy,
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

        Ok(staged)
    }

    async fn reconcile_confirm_attempt(
        &self,
        entry: &crate::outbox::OutboxEntry,
        attempt: BroadcastAttempt,
        chain: &ChainClient,
        policy: &Policy,
        reviewed_intent_hash: Option<&str>,
    ) -> Result<StagedTx, TxEngineError> {
        let tx_hash: B256 = attempt
            .tx_hash
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        if chain.tx_by_hash(tx_hash).await?.is_some() || chain.receipt(tx_hash).await?.is_some() {
            return self.finalize_sent(entry, tx_hash);
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
                let is_mainnet = bloom_proto::Config::is_mainnet_id(spec.chain_id);
                if (self.block_mainnet_broadcast && is_mainnet) || !spec.allow_broadcast {
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
                self.ensure_action_authorized(
                    &entry.staged,
                    policy,
                    reviewed_intent_hash,
                    bloom_proto::AuthorizationSurface::Cli,
                )?;
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
                self.finalize_sent(entry, tx_hash)
            }
        }
    }

    fn finalize_sent(
        &self,
        entry: &crate::outbox::OutboxEntry,
        tx_hash: B256,
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
        Ok(staged)
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

    async fn build_signed_raw_tx(
        &self,
        staged: &StagedTx,
        chain: &ChainClient,
        signer: &PrivateKeySigner,
    ) -> Result<SignedRawTx, TxEngineError> {
        let to_addr: Address = staged
            .to
            .parse()
            .map_err(|e: alloy::hex::FromHexError| TxEngineError::Address(e.to_string()))?;
        let value: U256 = staged
            .value_wei
            .parse()
            .map_err(|_| TxEngineError::Amount("value_wei".into()))?;
        let data = decode_data(&staged.data_hex)?;

        let mut req = TransactionRequest::default()
            .with_from(signer.address())
            .with_to(to_addr)
            .with_value(value)
            .with_input(data)
            .with_nonce(staged.nonce)
            .with_chain_id(staged.chain_id)
            .with_gas_limit(staged.gas_limit);

        if chain.spec().legacy_tx {
            let gp: u128 = staged
                .gas_price
                .as_deref()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(1_000_000_000);
            req = req.with_gas_price(gp);
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
            req = req
                .with_max_fee_per_gas(max_fee)
                .with_max_priority_fee_per_gas(prio);
        }

        let wallet_signer = EthereumWallet::from(signer.clone());
        let tx_envelope = req
            .build(&wallet_signer)
            .await
            .map_err(|e| TxEngineError::Signer(e.to_string()))?;
        let mut buf = Vec::new();
        alloy::eips::Encodable2718::encode_2718(&tx_envelope, &mut buf);
        let raw = Bytes::from(buf);
        let hash = alloy::primitives::keccak256(&raw);
        Ok(SignedRawTx { raw, hash })
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
        kind: BroadcastAttemptKind,
        staged: &StagedTx,
        chain: &ChainClient,
        signer: &PrivateKeySigner,
        policy: &Policy,
    ) -> Result<B256, TxEngineError> {
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
        let signed = self.build_signed_raw_tx(staged, chain, signer).await?;
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

    fn ensure_broadcast_allowed(&self, spec: &ChainSpec) -> Result<(), TxEngineError> {
        let is_mainnet = bloom_proto::Config::is_mainnet_id(spec.chain_id);
        if (self.block_mainnet_broadcast && is_mainnet) || !spec.allow_broadcast {
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

    fn ensure_action_authorized(
        &self,
        staged: &StagedTx,
        policy: &Policy,
        reviewed_intent_hash: Option<&str>,
        surface: bloom_proto::AuthorizationSurface,
    ) -> Result<(), TxEngineError> {
        let reviewed_intent_hash =
            self.verified_reviewed_intent_hash(staged, reviewed_intent_hash)?;
        let budget = self.budget_snapshot(&staged.wallet)?;
        let subject = self.authorization_subject(staged);
        match bloom_proto::evaluate_action_authorization(
            policy,
            &staged.policy_checks,
            &subject,
            Some(&budget),
            reviewed_intent_hash.as_deref(),
            surface,
        ) {
            bloom_proto::AutonomyDecision::ApprovedFreshReview { .. }
            | bloom_proto::AutonomyDecision::ApprovedAutonomous { .. } => Ok(()),
            // Scoped run capabilities are NOT implemented: no evaluator produces
            // this decision today, so accepting it would be a latent
            // broadcast-authorization gap if a producer is ever added without
            // re-reviewing this path. Fail closed until the system actually lands.
            bloom_proto::AutonomyDecision::ApprovedCapability { .. } => {
                Err(TxEngineError::BroadcastApprovalRequired(
                    "scoped run capabilities are not implemented; fresh review required".into(),
                ))
            }
            bloom_proto::AutonomyDecision::NeedsFreshReview { reason }
            | bloom_proto::AutonomyDecision::Denied { reason } => {
                Err(TxEngineError::BroadcastApprovalRequired(reason))
            }
        }
    }

    fn verified_reviewed_intent_hash(
        &self,
        staged: &StagedTx,
        reviewed_intent_hash: Option<&str>,
    ) -> Result<Option<String>, TxEngineError> {
        let Some(hash) = reviewed_intent_hash
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        let entry = self
            .outbox
            .read(&staged.wallet, &staged.chain, &staged.id)?;
        let path = entry.dir.join("review_intent.json");
        let body = std::fs::read(&path).map_err(|_| {
            TxEngineError::BroadcastApprovalRequired(
                "review hash supplied but no review_intent.json is stored for this outbox entry"
                    .into(),
            )
        })?;
        let intent: bloom_proto::CeremonyIntent = serde_json::from_slice(&body).map_err(|e| {
            TxEngineError::BroadcastApprovalRequired(format!(
                "stored review_intent.json is invalid: {e}"
            ))
        })?;
        let expected = intent.intent_hash();
        if hash != expected {
            return Err(TxEngineError::BroadcastApprovalRequired(
                "review hash does not match the stored review intent for this outbox entry".into(),
            ));
        }
        let approved_path = entry.dir.join("review_approved.json");
        let approved_body = std::fs::read(&approved_path).map_err(|_| {
            TxEngineError::BroadcastApprovalRequired(
                "review hash supplied but no passkey approval marker is stored for this outbox entry"
                    .into(),
            )
        })?;
        let approved: serde_json::Value = serde_json::from_slice(&approved_body).map_err(|e| {
            TxEngineError::BroadcastApprovalRequired(format!(
                "stored review_approved.json is invalid: {e}"
            ))
        })?;
        if approved
            .get("intent_hash")
            .and_then(|v| v.as_str())
            .map(str::trim)
            != Some(hash)
        {
            return Err(TxEngineError::BroadcastApprovalRequired(
                "passkey approval marker does not match the reviewed intent hash".into(),
            ));
        }
        Ok(Some(hash.to_string()))
    }

    fn authorization_subject(&self, staged: &StagedTx) -> bloom_proto::AuthorizationSubject {
        let value_wei = U256::from_str_radix(&staged.value_wei, 10).unwrap_or(U256::ZERO);
        let data_nonempty = staged
            .data_hex
            .trim_start_matches("0x")
            .bytes()
            .any(|b| b != b'0');
        let value_moving = value_wei > U256::ZERO
            || staged.token.is_some()
            || staged.nft.is_some()
            || data_nonempty;
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
            total_value_usd_micro: staged.usd_value.and_then(f64_to_micro_usd),
            value_moving,
            // A staged EVM transaction is byte-immutable: the evaluator is
            // authorizing the exact to/value/data/nonce persisted in outbox.
            // DeFi route receiver/min-output verification remains represented
            // by policy checks attached during staging.
            calldata_verified: true,
        }
    }

    fn budget_snapshot(&self, wallet: &str) -> Result<bloom_proto::BudgetSnapshot, TxEngineError> {
        const DAY_MS: u128 = 24 * 60 * 60 * 1000;
        const WEEK_MS: u128 = 7 * DAY_MS;
        const MONTH_MS: u128 = 30 * DAY_MS;
        let now = now_ms();
        let day = self
            .outbox
            .sum_usd_since(wallet, now.saturating_sub(DAY_MS))?;
        let week = self
            .outbox
            .sum_usd_since(wallet, now.saturating_sub(WEEK_MS))?;
        let month = self
            .outbox
            .sum_usd_since(wallet, now.saturating_sub(MONTH_MS))?;
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
        signer: &PrivateKeySigner,
        bump_pct: u32,
        policy: &Policy,
        reviewed_intent_hash: Option<&str>,
    ) -> Result<StagedTx, TxEngineError> {
        self.replace_with_intent(
            permit,
            wallet,
            chain_name,
            original_id,
            chain,
            signer,
            bump_pct,
            None,
            None,
            policy,
            reviewed_intent_hash,
        )
        .await
    }

    /// Same-nonce replacement that optionally substitutes the calldata
    /// (fix #10 carry-over). When `substitute` is `Some(intent)`, the
    /// new (`to`, `value`, `data`) are derived from it via the same
    /// encoding pipeline `stage` uses, but the original nonce is
    /// preserved. Fees are bumped at least `bump_pct%` (floored at 10).
    /// Enso-flavoured intents are rejected here for the same reason
    /// they're rejected in stage — they need bloom-defi's HTTP path.
    #[allow(clippy::too_many_arguments)]
    pub async fn replace_with_intent(
        &self,
        permit: &HomeWritePermit,
        wallet: &str,
        chain_name: &str,
        original_id: &str,
        chain: &ChainClient,
        signer: &PrivateKeySigner,
        bump_pct: u32,
        substitute: Option<RawIntent>,
        address_book: Option<&AddressBook>,
        policy: &Policy,
        reviewed_intent_hash: Option<&str>,
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
            bumped.policy_checks.push(bloom_proto::PolicyCheck {
                rule: "replacement.substitute".into(),
                outcome: bloom_proto::PolicyOutcome::Deny,
                message: "same-nonce replacement with substituted to/value/data is disabled; stage a fresh transaction instead".into(),
            });
        }
        bump_fees_in_place(&mut bumped, bump);
        self.ensure_action_authorized(
            &bumped,
            policy,
            reviewed_intent_hash,
            bloom_proto::AuthorizationSurface::Cli,
        )?;

        let tx_hash = self
            .submit_with_marker(
                &entry,
                BroadcastAttemptKind::Replacement,
                &bumped,
                chain,
                signer,
                policy,
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
        signer: &PrivateKeySigner,
        bump_pct: u32,
        policy: &Policy,
        reviewed_intent_hash: Option<&str>,
    ) -> Result<StagedTx, TxEngineError> {
        self.assert_write_permit(permit)?;
        let bump = bump_pct.max(10);
        let entry = self.read_replaceable_entry(wallet, chain_name, original_id)?;
        let original = &entry.staged;

        let mut cancel_tx = original.clone();
        cancel_tx.status = TxStatus::Pending;
        cancel_tx.tx_hash = None;
        cancel_tx.to = bloom_proto::checksum_address(&signer.address());
        cancel_tx.value_wei = "0".to_string();
        cancel_tx.data_hex = "0x".to_string();
        cancel_tx.token = None;
        bump_fees_in_place(&mut cancel_tx, bump);
        self.ensure_action_authorized(
            &cancel_tx,
            policy,
            reviewed_intent_hash,
            bloom_proto::AuthorizationSurface::Cli,
        )?;

        let tx_hash = self
            .submit_with_marker(
                &entry,
                BroadcastAttemptKind::CancelReplacement,
                &cancel_tx,
                chain,
                signer,
                policy,
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
    use bloom_proto::TxStatus;

    fn fake_staged_1559(id: &str) -> StagedTx {
        StagedTx {
            id: id.into(),
            wallet: "alice".into(),
            chain: "anvil".into(),
            chain_id: 31337,
            from: "0x0000000000000000000000000000000000000001".into(),
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
            tx_hash: None,
            token: None,
            nft: None,
            usd_value: None,
            depends_on: None,
        }
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
        let engine = TxEngine::new(outbox, 60_000, false);
        (engine, dir)
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
        };
        let chain = bloom_chain::ChainClient::new(spec).unwrap();
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
        let engine = TxEngine::new(outbox, stage_ttl_ms, false);
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
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
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-test",
                &chain,
                &signer,
                &policy,
                "y",
                None,
            )
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let policy = bloom_proto::Policy::default();

        let mut staged = fake_staged_1559("0001-test");
        // Already expired the moment this test runs.
        staged.expires_ms = 1;
        engine.outbox.write_pending(&staged, "p").unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-test",
                &chain,
                &signer,
                &policy,
                "y",
                None,
            )
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
        let permit = permit_for(&dir);
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
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
                &signer,
                &policy,
                "y",
                None,
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
        let permit = permit_for(&dir);
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let policy = bloom_proto::Policy::default();

        let mut staged = fake_staged_1559("0001-session-attempt");
        staged.expires_ms = now_ms() + 60_000;
        staged.usd_value = Some(2.0);
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
                &signer,
                &policy,
                "y",
                None,
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
        let permit = permit_for(&dir);
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
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
                &signer,
                10,
                &policy,
                None,
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
                &signer,
                10,
                &policy,
                None,
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
        spec.allow_broadcast = false;
        let permit = permit_for(&dir);
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
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
                &signer,
                10,
                &policy,
                None,
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
                &signer,
                10,
                &policy,
                None,
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
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
        let permit = permit_for(&dir);
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();

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
        staged.policy_checks = vec![PolicyCheck {
            rule: "test.warn".into(),
            outcome: PolicyOutcome::Warn,
            message: "soft cap".into(),
        }];
        engine.outbox.write_pending(&staged, "p").unwrap();

        // "y" must be rejected — needs the policy's override token.
        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-test",
                &chain,
                &signer,
                &policy,
                "y",
                None,
            )
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
                &signer,
                &policy,
                "override",
                None,
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
                &signer,
                &policy,
                "yolo",
                None,
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let policy = bloom_proto::Policy::default();

        let mut staged = fake_staged_1559("0001-test");
        staged.expires_ms = now_ms() + 60_000;
        staged.policy_checks = vec![PolicyCheck {
            rule: "caps.max_value_eth".into(),
            outcome: PolicyOutcome::Deny,
            message: "value exceeds max".into(),
        }];
        engine.outbox.write_pending(&staged, "p").unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-test",
                &chain,
                &signer,
                &policy,
                "y",
                None,
            )
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
        let permit = permit_for(&dir);
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let policy = bloom_proto::Policy::default(); // override_sentinel() == "override"

        let mut staged = fake_staged_1559("0001-test");
        staged.expires_ms = now_ms() + 60_000;
        staged.policy_checks = vec![PolicyCheck {
            rule: "caps.warn_value_eth".into(),
            outcome: PolicyOutcome::Warn,
            message: "soft cap exceeded".into(),
        }];
        engine.outbox.write_pending(&staged, "p").unwrap();

        // Wrong text — must be rejected.
        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-test",
                &chain,
                &signer,
                &policy,
                "y",
                None,
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
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-test",
                &chain,
                &signer,
                &policy,
                "override",
                None,
            )
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let mut policy = bloom_proto::Policy::default();
        policy.approval.require_broadcast_approval = true;

        let mut staged = fake_staged_1559("0001-approval");
        staged.value_wei = "1".into();
        staged.usd_value = Some(0.01);
        staged.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&staged, "p").unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-approval",
                &chain,
                &signer,
                &policy,
                "y",
                None,
            )
            .await;
        assert!(
            matches!(r, Err(TxEngineError::BroadcastApprovalRequired(_))),
            "expected approval refusal, got {r:?}"
        );

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-approval",
                &chain,
                &signer,
                &policy,
                "y",
                Some("reviewed"),
            )
            .await;
        assert!(
            matches!(r, Err(TxEngineError::BroadcastApprovalRequired(ref e)) if e.contains("review_intent")),
            "expected missing review artifact refusal, got {r:?}"
        );

        let entry = engine
            .outbox
            .read("alice", "anvil", "0001-approval")
            .unwrap();
        let intent = bloom_proto::CeremonyIntent::new(
            "alice",
            "Approve anvil Transaction",
            bloom_proto::CeremonyIntentKind::EvmTransaction,
        )
        .subject(serde_json::json!({
            "kind": "outbox_confirm",
            "wallet": "alice",
            "chain": "anvil",
            "outbox_id": "0001-approval",
        }));
        let review_hash = intent.intent_hash();
        engine
            .outbox
            .write_artefact(
                &entry.dir,
                "review_intent.json",
                &serde_json::to_vec_pretty(&intent).unwrap(),
            )
            .unwrap();
        engine
            .outbox
            .write_artefact(
                &entry.dir,
                "review_approved.json",
                &serde_json::to_vec_pretty(&serde_json::json!({
                    "schema": "bloom.review_approved.v1",
                    "intent_hash": review_hash,
                }))
                .unwrap(),
            )
            .unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-approval",
                &chain,
                &signer,
                &policy,
                "y",
                Some(&review_hash),
            )
            .await;
        match r {
            Err(TxEngineError::BroadcastApprovalRequired(_)) => {
                panic!("review hash should satisfy approval gate")
            }
            Ok(_) => panic!("unexpected broadcast success on unreachable RPC"),
            Err(_) => {}
        }
    }

    #[tokio::test]
    async fn under_policy_autonomy_requires_usd_and_limits() {
        let (engine, spec, dir) = fake_engine(60_000);
        let permit = permit_for(&dir);
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let mut policy = bloom_proto::Policy::default();
        policy.approval.agent_autonomy = Some(bloom_proto::AgentAutonomyMode::UnderPolicy);
        policy.limits.max_tx_usd = Some("3".into());
        policy.limits.max_day_usd = Some("10".into());

        let mut no_usd = fake_staged_1559("0001-no-usd");
        no_usd.value_wei = "1".into();
        no_usd.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&no_usd, "p").unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0001-no-usd",
                &chain,
                &signer,
                &policy,
                "y",
                None,
            )
            .await;
        assert!(
            matches!(r, Err(TxEngineError::BroadcastApprovalRequired(ref e)) if e.contains("USD valuation")),
            "expected unknown USD refusal, got {r:?}"
        );

        let mut priced = fake_staged_1559("0002-priced");
        priced.value_wei = "1".into();
        priced.usd_value = Some(2.0);
        priced.expires_ms = now_ms() + 60_000;
        engine.outbox.write_pending(&priced, "p").unwrap();

        let r = engine
            .confirm(
                &permit,
                "alice",
                "anvil",
                "0002-priced",
                &chain,
                &signer,
                &policy,
                "y",
                None,
            )
            .await;
        match r {
            Err(TxEngineError::BroadcastApprovalRequired(e)) => {
                panic!("under-policy tx should pass approval gate, got {e}")
            }
            Ok(_) => panic!("unexpected broadcast success on unreachable RPC"),
            Err(_) => {}
        }
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
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
        let chain = bloom_chain::ChainClient::new(spec.clone()).unwrap();
        let signer = alloy::signers::local::PrivateKeySigner::random();
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
}
