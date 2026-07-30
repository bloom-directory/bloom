//! EVM RPC pool and wallet client.
//!
//! v1 uses a single alloy `RootProvider<Http>` per chain (the pool layer
//! is a thin wrapper that walks `rpc_urls` in priority order on call
//! failure). Subscriptions and websocket transports are deferred.

#![forbid(unsafe_code)]

use std::sync::Arc;

use alloy::consensus::Transaction as TxTrait;
use alloy::eips::BlockNumberOrTag;
use alloy::network::{Ethereum, ReceiptResponse, TransactionBuilder};
use alloy::primitives::{Address, B256, BlockHash, Bytes, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::eth::state::StateOverride;
use alloy::rpc::types::eth::{
    Block, Filter, Log, Transaction, TransactionReceipt, TransactionRequest,
};
use alloy::sol;
use alloy::transports::TransportError;
use op_alloy::network::Optimism;
use parking_lot::RwLock;
use thiserror::Error;
use tracing::{debug, warn};

use bloom_proto::{ChainId, ChainSpec};

pub use bloom_rpc::Session;

sol! {
    #[sol(rpc)]
    #[allow(missing_docs)]
    interface IERC20 {
        function decimals() external view returns (uint8);
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function symbol() external view returns (string);
        function approve(address spender, uint256 amount) external returns (bool);
        function transfer(address to, uint256 amount) external returns (bool);
    }

    #[sol(rpc)]
    #[allow(missing_docs)]
    interface IERC165 {
        function supportsInterface(bytes4 interfaceId) external view returns (bool);
    }

    #[sol(rpc)]
    #[allow(missing_docs)]
    interface IERC721 {
        function ownerOf(uint256 tokenId) external view returns (address);
        function balanceOf(address owner) external view returns (uint256);
        function getApproved(uint256 tokenId) external view returns (address);
        function isApprovedForAll(address owner, address operator) external view returns (bool);
    }

    #[sol(rpc)]
    #[allow(missing_docs)]
    interface IERC721Metadata {
        function name() external view returns (string);
        function symbol() external view returns (string);
        function tokenURI(uint256 tokenId) external view returns (string);
    }

    #[sol(rpc)]
    #[allow(missing_docs)]
    interface IERC721Enumerable {
        function totalSupply() external view returns (uint256);
    }

    #[sol(rpc)]
    #[allow(missing_docs)]
    interface IERC1155 {
        function balanceOf(address account, uint256 id) external view returns (uint256);
        function isApprovedForAll(address account, address operator) external view returns (bool);
    }

    #[sol(rpc)]
    #[allow(missing_docs)]
    interface IERC1155MetadataURI {
        function uri(uint256 id) external view returns (string);
    }
}

/// ERC-165 interface IDs for the standards we care about.
pub const ERC165_INTERFACE_ID_ERC721: [u8; 4] = [0x80, 0xac, 0x58, 0xcd];
pub const ERC165_INTERFACE_ID_ERC1155: [u8; 4] = [0xd9, 0xb6, 0x7a, 0x26];

/// What kind of NFT contract `addr` is. Detected via `supportsInterface`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftKind {
    Erc721,
    Erc1155,
    Unknown,
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("no rpc endpoints configured for chain '{0}'")]
    NoEndpoints(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("url parse: {0}")]
    Url(String),
    #[error("rpc: {0}")]
    Rpc(String),
}

impl From<TransportError> for ChainError {
    fn from(e: TransportError) -> Self {
        ChainError::Transport(e.to_string())
    }
}

impl From<bloom_rpc::BloomRpcError> for ChainError {
    fn from(e: bloom_rpc::BloomRpcError) -> Self {
        map_rpc_error(e)
    }
}

/// Translate a `bloom_rpc::BloomRpcError` into the historical `ChainError`
/// surface so existing matchers in the workspace keep working.
fn map_rpc_error(e: bloom_rpc::BloomRpcError) -> ChainError {
    use bloom_rpc::BloomRpcError;
    match e {
        BloomRpcError::NoEndpoints(name) => ChainError::NoEndpoints(name),
        BloomRpcError::InvalidUrl { url, source } => ChainError::Url(format!("{url}: {source}")),
        BloomRpcError::Transport(t) => ChainError::Transport(t.to_string()),
        BloomRpcError::AllEndpointsFailed { chain, last_error } => {
            ChainError::Transport(format!("all endpoints failed for {chain}: {last_error}"))
        }
    }
}

/// Build the `eth_call` request that replays a mined transaction,
/// preserving all execution-relevant fields (fees, access list, etc.)
/// so the replay matches the original execution.
///
/// Fee fields are mutually exclusive: legacy transactions report their
/// gas price through both `gas_price()` and `max_fee_per_gas()`, and
/// geth-family nodes reject calls carrying both `gasPrice` and
/// EIP-1559 fee fields.
fn revert_replay_request<T: TxTrait>(from: Address, tx: &T) -> TransactionRequest {
    let mut builder = TransactionRequest::default()
        .with_from(from)
        .with_input(tx.input().clone())
        .with_gas_limit(tx.gas_limit())
        .with_value(tx.value());
    if let Some(gas_price) = tx.gas_price() {
        builder = builder.with_gas_price(gas_price);
    } else {
        builder = builder.with_max_fee_per_gas(tx.max_fee_per_gas());
        if let Some(prio_fee) = tx.max_priority_fee_per_gas() {
            builder = builder.with_max_priority_fee_per_gas(prio_fee);
        }
    }
    if let Some(chain_id) = tx.chain_id() {
        builder = builder.with_chain_id(chain_id);
    }
    if let Some(to) = tx.to() {
        builder = builder.with_to(to);
    }
    if let Some(access_list) = tx.access_list() {
        builder = builder.with_access_list(access_list.clone());
    }
    builder
}

/// One alloy provider backed by the layered `bloom-rpc` engine.
///
/// The provider is a `RootProvider<Ethereum>` whose transport is the
/// fallback fan-out built by `bloom_rpc::RpcEngine::build`. Existing
/// call sites that grab `provider()` keep working unchanged — only the
/// underlying transport changed.
#[derive(Clone)]
pub struct ChainClient {
    spec: Arc<ChainSpec>,
    primary: Arc<RootProvider<Ethereum>>,
    /// When `op_stack` is set, a `RootProvider<Optimism>` sharing the
    /// same transport as `primary`. Its `get_transaction_by_hash` /
    /// `get_transaction_receipt` natively decode deposit/system txs
    /// (type `0x7e`) and L1-fee receipt fields.
    op_primary: Option<Arc<RootProvider<Optimism>>>,
    engine: Arc<bloom_rpc::RpcEngine>,
    /// Cached chain id once the provider has reported it.
    cached_chain_id: Arc<RwLock<Option<u64>>>,
}

impl ChainClient {
    /// Construct a client from a `ChainSpec`.
    ///
    /// Builds the layered `bloom_rpc::RpcEngine` (retry → optional
    /// throttle → HTTP, all behind a `FallbackLayer`) for every entry
    /// returned by `spec.endpoints()`. Returns
    /// `ChainError::NoEndpoints` when the spec resolves to zero
    /// endpoints (both `rpc_urls` and `rpc_endpoints` empty), and
    /// `ChainError::Url` for unparseable endpoint URLs.
    pub fn new(spec: ChainSpec) -> Result<Self, ChainError> {
        let engine = bloom_rpc::RpcEngine::build(&spec).map_err(map_rpc_error)?;
        let provider = engine.provider();
        let op_primary = if spec.op_stack {
            Some(Arc::new(RootProvider::<Optimism>::new(engine.raw_client())))
        } else {
            None
        };
        Ok(Self {
            spec: Arc::new(spec),
            primary: provider,
            op_primary,
            engine: Arc::new(engine),
            cached_chain_id: Arc::new(RwLock::new(None)),
        })
    }

    pub fn spec(&self) -> &ChainSpec {
        &self.spec
    }
    pub fn id(&self) -> ChainId {
        ChainId(self.spec.chain_id)
    }
    /// True when this chain uses the OP Stack (Base, Optimism, …).
    pub fn is_op_stack(&self) -> bool {
        self.spec.op_stack
    }
    pub fn provider(&self) -> Arc<RootProvider<Ethereum>> {
        self.primary.clone()
    }

    /// True when at least one configured endpoint is `ws://` or
    /// `wss://` and not flagged `http_only`. The watch executor uses
    /// this to gate the WS subscription fast path; the actual
    /// `RootProvider` for subscriptions is opened lazily by
    /// [`Self::ws_provider`].
    pub fn supports_subscriptions(&self) -> bool {
        self.engine.supports_subscriptions()
    }

    /// Snapshot of per-endpoint health for this chain. The returned
    /// vec mirrors the engine's configured endpoint order — index `i`
    /// in the snapshot corresponds to `spec().endpoints()[i]`.
    ///
    /// This is a snapshot taken at call time. Values may have changed
    /// by the time the caller reads them; callers that want
    /// transactional consistency across multiple leaves should
    /// snapshot once and read all leaves from the snapshot.
    pub fn endpoints(&self) -> Vec<bloom_rpc::EndpointHealthSnapshot> {
        self.engine.endpoints_snapshot()
    }

    /// Number of endpoints currently parked in cooldown. Useful for
    /// status displays that don't need the full snapshot.
    pub fn cooled_down_count(&self) -> usize {
        self.engine.cooled_down_count()
    }

    /// Lazily-opened WS provider for `subscribe_*` calls. Returns
    /// `None` when no WS endpoints are configured (callers should fall
    /// back to polling via [`Self::provider`]). The first call opens
    /// the connection and caches the resulting provider; subsequent
    /// callers share the same `Arc`. Failure to open is logged via
    /// `rpc.transport.ws_provider_open_failed` and surfaces as `None`
    /// so the caller can retry on the next watchdog tick.
    ///
    /// This is intentionally distinct from [`Self::provider`] — the
    /// HTTP-fallback provider is the engine's request/response
    /// pool, while this one exists exclusively for pubsub.
    pub async fn ws_provider(&self) -> Option<Arc<RootProvider<Ethereum>>> {
        self.engine.ws_provider().await
    }

    /// Open a new pinned read session at the current `latest` block.
    ///
    /// The returned [`Session`] borrows the engine's provider and
    /// freezes a `(block_number, block_hash)` pair so multi-call
    /// logical operations (tx staging, aggregate VFS reads) observe a
    /// consistent state even when the layered fallback transport
    /// rotates upstreams between calls. Sessions are unconditional
    /// (Decisions Ratified #2 in the spec): there is no toggle.
    ///
    /// On failure to read the head block this returns
    /// `ChainError::Transport`; on a successful open with a `null`
    /// block result (extremely rare; only on a brand-new chain before
    /// genesis is queryable) it returns `ChainError::NotFound`.
    pub async fn open_session(&self) -> Result<Session<'_>, ChainError> {
        let block = self
            .primary
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .ok_or_else(|| ChainError::NotFound("latest block".into()))?;
        let pinned_number = block.header.number;
        let pinned_hash = block.header.hash;
        debug!(
            chain = %self.spec.name,
            pinned_number,
            pinned_hash = %pinned_hash,
            "rpc.session.opened"
        );
        Ok(Session::from_pinned(
            self.primary.as_ref(),
            self.spec.name.clone(),
            pinned_number,
            pinned_hash,
        ))
    }

    /// Open a pinned read session at an explicit historical block number.
    ///
    /// Every session read asks for the resolved block hash first, and falls
    /// back to the same block number only if an upstream cannot serve the hash.
    pub async fn open_session_at(&self, block_number: u64) -> Result<Session<'_>, ChainError> {
        let block = self
            .primary
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .await?
            .ok_or_else(|| ChainError::NotFound(format!("block {block_number}")))?;
        let pinned_number = block.header.number;
        let pinned_hash = block.header.hash;
        debug!(
            chain = %self.spec.name,
            pinned_number,
            pinned_hash = %pinned_hash,
            "rpc.session.opened_at"
        );
        Ok(Session::from_pinned(
            self.primary.as_ref(),
            self.spec.name.clone(),
            pinned_number,
            pinned_hash,
        ))
    }

    pub async fn chain_id(&self) -> Result<u64, ChainError> {
        if let Some(id) = *self.cached_chain_id.read() {
            return Ok(id);
        }
        let id = self.primary.get_chain_id().await?;
        *self.cached_chain_id.write() = Some(id);
        Ok(id)
    }

    pub async fn block_number(&self) -> Result<u64, ChainError> {
        Ok(self.primary.get_block_number().await?)
    }

    pub async fn balance(&self, addr: Address) -> Result<U256, ChainError> {
        Ok(self.primary.get_balance(addr).await?)
    }

    pub async fn nonce(&self, addr: Address) -> Result<u64, ChainError> {
        // Use the pending block so back-to-back stages don't collide on the
        // same nonce when an earlier tx is still propagating between RPC
        // nodes. Falls back to latest if the provider doesn't support it.
        Ok(self.primary.get_transaction_count(addr).pending().await?)
    }

    pub async fn code(&self, addr: Address) -> Result<Vec<u8>, ChainError> {
        Ok(self.primary.get_code_at(addr).await?.to_vec())
    }

    pub async fn block_by_number(&self, n: u64) -> Result<Option<Block>, ChainError> {
        let res = self
            .primary
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Number(n))
            .await?;
        Ok(res)
    }

    pub async fn block_latest(&self) -> Result<Option<Block>, ChainError> {
        let res = self
            .primary
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await?;
        Ok(res)
    }

    pub async fn tx_by_hash(&self, hash: B256) -> Result<Option<Transaction>, ChainError> {
        Ok(self.primary.get_transaction_by_hash(hash).await?)
    }

    /// Fetch a transaction as typed JSON. On OP-stack chains the
    /// `RootProvider<Optimism>` natively decodes deposit/system
    /// transactions (type `0x7e`); on L1 chains the standard alloy
    /// `Transaction` decoder is used.
    pub async fn tx_json(&self, hash: B256) -> Result<Option<serde_json::Value>, ChainError> {
        if let Some(op) = &self.op_primary {
            match op.get_transaction_by_hash(hash).await? {
                Some(tx) => serde_json::to_value(&tx)
                    .map_err(|e| ChainError::Decode(format!("tx {hash:#x}: {e}")))
                    .map(Some),
                None => Ok(None),
            }
        } else {
            match self.tx_by_hash(hash).await? {
                Some(tx) => serde_json::to_value(&tx)
                    .map_err(|e| ChainError::Decode(format!("tx {hash:#x}: {e}")))
                    .map(Some),
                None => Ok(None),
            }
        }
    }

    pub async fn receipt(&self, hash: B256) -> Result<Option<TransactionReceipt>, ChainError> {
        Ok(self.primary.get_transaction_receipt(hash).await?)
    }

    /// Fetch a receipt as typed JSON. On OP-stack chains the
    /// `RootProvider<Optimism>` natively decodes L1-fee fields and
    /// deposit-tx metadata.
    pub async fn receipt_json(&self, hash: B256) -> Result<Option<serde_json::Value>, ChainError> {
        if let Some(op) = &self.op_primary {
            match op.get_transaction_receipt(hash).await? {
                Some(r) => serde_json::to_value(&r)
                    .map_err(|e| ChainError::Decode(format!("receipt {hash:#x}: {e}")))
                    .map(Some),
                None => Ok(None),
            }
        } else {
            match self.receipt(hash).await? {
                Some(r) => serde_json::to_value(&r)
                    .map_err(|e| ChainError::Decode(format!("receipt {hash:#x}: {e}")))
                    .map(Some),
                None => Ok(None),
            }
        }
    }

    /// Extract the block number from a transaction receipt using the
    /// typed decoder appropriate for the chain family.
    pub async fn receipt_block_number(&self, hash: B256) -> Result<Option<u64>, ChainError> {
        if let Some(op) = &self.op_primary {
            Ok(op
                .get_transaction_receipt(hash)
                .await?
                .and_then(|r| r.block_number()))
        } else {
            Ok(self.receipt(hash).await?.and_then(|r| r.block_number))
        }
    }

    /// Re-execute a *reverted* transaction via `eth_call` at the block it
    /// was mined in, to capture revert returndata. Returns:
    ///
    /// * `Ok(None)` — tx succeeded, isn't on-chain, or the RPC didn't
    ///   surface revert data on the replay (some providers strip it).
    /// * `Ok(Some(bytes))` — the replayed call reverted and we extracted
    ///   the encoded returndata from the JSON-RPC error.
    pub async fn trace_revert(&self, hash: B256) -> Result<Option<Bytes>, ChainError> {
        let block_number;
        let req;

        if let Some(op) = &self.op_primary {
            // OP-stack path: the Optimism provider decodes deposit/system
            // txs and L1-fee receipts natively.
            let receipt = match op.get_transaction_receipt(hash).await? {
                Some(r) => r,
                None => {
                    debug!(%hash, "trace_revert.no_receipt");
                    return Ok(None);
                }
            };
            if receipt.status() {
                debug!(%hash, "trace_revert.tx_succeeded");
                return Ok(None);
            }
            block_number = match receipt.block_number() {
                Some(n) => n,
                None => {
                    debug!(%hash, "trace_revert.no_block_number");
                    return Ok(None);
                }
            };
            let from = receipt.from();
            let tx = match op.get_transaction_by_hash(hash).await? {
                Some(t) => t,
                None => {
                    debug!(%hash, "trace_revert.no_tx");
                    return Ok(None);
                }
            };
            req = revert_replay_request(from, &tx);
        } else {
            // L1 path: standard typed decode handles all known tx types.
            let receipt = match self.primary.get_transaction_receipt(hash).await? {
                Some(r) => r,
                None => {
                    debug!(%hash, "trace_revert.no_receipt");
                    return Ok(None);
                }
            };
            if receipt.status() {
                debug!(%hash, "trace_revert.tx_succeeded");
                return Ok(None);
            }
            block_number = match receipt.block_number {
                Some(n) => n,
                None => {
                    debug!(%hash, "trace_revert.no_block_number");
                    return Ok(None);
                }
            };
            let tx = match self.primary.get_transaction_by_hash(hash).await? {
                Some(t) => t,
                None => {
                    debug!(%hash, "trace_revert.no_tx");
                    return Ok(None);
                }
            };
            req = tx.into_request().with_from(receipt.from);
        }

        let call = self
            .primary
            .call(req)
            .block(BlockNumberOrTag::Number(block_number).into());
        match call.await {
            // The replay succeeded? That means the original failure was
            // not a deterministic revert (e.g. out-of-gas / nonce race).
            // Surface as `None` so callers can fall back to the receipt.
            Ok(_) => {
                debug!(%hash, block_number, "trace_revert.replay_succeeded");
                Ok(None)
            }
            Err(e) => match &e {
                TransportError::ErrorResp(payload) => {
                    let data = payload.as_revert_data();
                    if data.is_none() {
                        // Some providers strip revert payloads from replay
                        // responses; surface so callers know we asked.
                        debug!(%hash, block_number, "trace_revert.no_revert_data");
                    }
                    Ok(data)
                }
                _ => Err(ChainError::Transport(e.to_string())),
            },
        }
    }

    /// Run an `eth_call` and, on revert, return the encoded returndata so
    /// callers can pass it to a [`bloom_revert::DecoderChain`]. The
    /// `Result` semantics mirror [`Self::trace_revert`]:
    ///
    /// * `Ok(Ok(bytes))` — the call succeeded; `bytes` is the return data.
    /// * `Ok(Err(returndata))` — the call reverted; `returndata` is the
    ///   raw revert payload (possibly empty when the contract reverted
    ///   with no reason).
    /// * `Err(e)` — transport/RPC failure unrelated to a revert.
    pub async fn eth_call_capture_revert(
        &self,
        req: TransactionRequest,
        overrides: Option<StateOverride>,
    ) -> Result<Result<Bytes, Bytes>, ChainError> {
        let call = self.primary.call(req);
        let result = match overrides {
            Some(o) => call.overrides(o).await,
            None => call.await,
        };
        match result {
            Ok(bytes) => Ok(Ok(bytes)),
            Err(e) => match &e {
                TransportError::ErrorResp(payload) => {
                    let data = payload.as_revert_data().unwrap_or_else(|| {
                        // The RPC error came back tagged as a revert but
                        // carried no payload — log so callers chasing an
                        // empty `Bytes` know it wasn't a decoder bug.
                        debug!("eth_call_capture_revert.empty_payload");
                        Default::default()
                    });
                    Ok(Err(data))
                }
                _ => Err(ChainError::Transport(e.to_string())),
            },
        }
    }

    pub async fn gas_price(&self) -> Result<u128, ChainError> {
        Ok(self.primary.get_gas_price().await?)
    }

    pub async fn estimate_gas(
        &self,
        tx: &alloy::rpc::types::eth::TransactionRequest,
    ) -> Result<u64, ChainError> {
        Ok(self.primary.estimate_gas(tx.clone()).await?)
    }

    pub async fn fee_history(
        &self,
        block_count: u64,
    ) -> Result<alloy::rpc::types::eth::FeeHistory, ChainError> {
        let fh = self
            .primary
            .get_fee_history(
                block_count,
                alloy::eips::BlockNumberOrTag::Latest,
                &[10.0, 50.0, 90.0],
            )
            .await?;
        Ok(fh)
    }

    pub async fn send_raw(&self, raw: alloy::primitives::Bytes) -> Result<B256, ChainError> {
        let pending = self.primary.send_raw_transaction(raw.as_ref()).await?;
        Ok(*pending.tx_hash())
    }

    /// Read an ERC-20 token's `decimals()`. Returns `None` if the call
    /// reverts — callers should fall back to a sensible default (or
    /// refuse to stage).
    pub async fn erc20_decimals(&self, token: Address) -> Result<Option<u8>, ChainError> {
        let contract = IERC20::new(token, self.primary.clone());
        match contract.decimals().call().await {
            Ok(d) => Ok(Some(d)),
            Err(e) => {
                debug!(error = %e, "erc20_decimals.call_failed");
                Ok(None)
            }
        }
    }

    /// Read an ERC-20 token's `balanceOf(holder)`. Returns `None` if the
    /// call reverts.
    pub async fn erc20_balance(
        &self,
        token: Address,
        holder: Address,
    ) -> Result<Option<U256>, ChainError> {
        let contract = IERC20::new(token, self.primary.clone());
        match contract.balanceOf(holder).call().await {
            Ok(b) => Ok(Some(b)),
            Err(e) => {
                debug!(error = %e, "erc20_balance.call_failed");
                Ok(None)
            }
        }
    }

    /// Read an ERC-20 token's `allowance(owner, spender)`. Returns
    /// `None` if the call reverts.
    pub async fn erc20_allowance(
        &self,
        token: Address,
        owner: Address,
        spender: Address,
    ) -> Result<Option<U256>, ChainError> {
        let contract = IERC20::new(token, self.primary.clone());
        match contract.allowance(owner, spender).call().await {
            Ok(a) => Ok(Some(a)),
            Err(e) => {
                debug!(error = %e, "erc20_allowance.call_failed");
                Ok(None)
            }
        }
    }

    /// Read an ERC-20 token's `symbol()`. Returns `None` if the call
    /// reverts. (Some early tokens encode `symbol` as `bytes32` instead
    /// of `string`; those will surface here as a decode error.)
    pub async fn erc20_symbol(&self, token: Address) -> Result<Option<String>, ChainError> {
        let contract = IERC20::new(token, self.primary.clone());
        match contract.symbol().call().await {
            Ok(s) => Ok(Some(s.trim_matches('\0').to_string())),
            Err(e) => {
                debug!(error = %e, "erc20_symbol.call_failed");
                Ok(None)
            }
        }
    }

    // ---- NFT (ERC-721 / ERC-1155) reads --------------------------------

    /// `IERC165.supportsInterface(selector)`. Returns `Ok(false)` on revert.
    pub async fn supports_interface(
        &self,
        addr: Address,
        selector: [u8; 4],
    ) -> Result<bool, ChainError> {
        let contract = IERC165::new(addr, self.primary.clone());
        match contract.supportsInterface(selector.into()).call().await {
            Ok(b) => Ok(b),
            Err(e) => {
                debug!(error = %e, "supports_interface.call_failed");
                Ok(false)
            }
        }
    }

    /// Detect whether `addr` is ERC-721, ERC-1155, or neither.
    pub async fn nft_detect(&self, addr: Address) -> Result<NftKind, ChainError> {
        if self
            .supports_interface(addr, ERC165_INTERFACE_ID_ERC721)
            .await?
        {
            return Ok(NftKind::Erc721);
        }
        if self
            .supports_interface(addr, ERC165_INTERFACE_ID_ERC1155)
            .await?
        {
            return Ok(NftKind::Erc1155);
        }
        Ok(NftKind::Unknown)
    }

    /// `IERC721.ownerOf(tokenId)`. `None` on revert (typical for
    /// nonexistent / burnt tokens).
    pub async fn erc721_owner_of(
        &self,
        addr: Address,
        token_id: U256,
    ) -> Result<Option<Address>, ChainError> {
        let contract = IERC721::new(addr, self.primary.clone());
        match contract.ownerOf(token_id).call().await {
            Ok(a) => Ok(Some(a)),
            Err(e) => {
                debug!(error = %e, "erc721_owner_of.call_failed");
                Ok(None)
            }
        }
    }

    /// `IERC721.balanceOf(owner)` — number of tokens held by `owner`.
    pub async fn erc721_balance_of(
        &self,
        addr: Address,
        owner: Address,
    ) -> Result<Option<U256>, ChainError> {
        let contract = IERC721::new(addr, self.primary.clone());
        match contract.balanceOf(owner).call().await {
            Ok(b) => Ok(Some(b)),
            Err(e) => {
                debug!(error = %e, "erc721_balance_of.call_failed");
                Ok(None)
            }
        }
    }

    /// `IERC721.getApproved(tokenId)`.
    pub async fn erc721_get_approved(
        &self,
        addr: Address,
        token_id: U256,
    ) -> Result<Option<Address>, ChainError> {
        let contract = IERC721::new(addr, self.primary.clone());
        match contract.getApproved(token_id).call().await {
            Ok(a) => Ok(Some(a)),
            Err(e) => {
                debug!(error = %e, "erc721_get_approved.call_failed");
                Ok(None)
            }
        }
    }

    /// `IERC721Metadata.tokenURI(tokenId)`.
    pub async fn erc721_token_uri(
        &self,
        addr: Address,
        token_id: U256,
    ) -> Result<Option<String>, ChainError> {
        let contract = IERC721Metadata::new(addr, self.primary.clone());
        match contract.tokenURI(token_id).call().await {
            Ok(s) => Ok(Some(s)),
            Err(e) => {
                debug!(error = %e, "erc721_token_uri.call_failed");
                Ok(None)
            }
        }
    }

    /// `IERC721Metadata.name()`.
    pub async fn erc721_name(&self, addr: Address) -> Result<Option<String>, ChainError> {
        let contract = IERC721Metadata::new(addr, self.primary.clone());
        match contract.name().call().await {
            Ok(s) => Ok(Some(s.trim_matches('\0').to_string())),
            Err(e) => {
                debug!(error = %e, "erc721_name.call_failed");
                Ok(None)
            }
        }
    }

    /// `IERC721Metadata.symbol()`.
    pub async fn erc721_symbol(&self, addr: Address) -> Result<Option<String>, ChainError> {
        let contract = IERC721Metadata::new(addr, self.primary.clone());
        match contract.symbol().call().await {
            Ok(s) => Ok(Some(s.trim_matches('\0').to_string())),
            Err(e) => {
                debug!(error = %e, "erc721_symbol.call_failed");
                Ok(None)
            }
        }
    }

    /// `IERC721Enumerable.totalSupply()`. `None` if not enumerable.
    pub async fn erc721_total_supply(&self, addr: Address) -> Result<Option<U256>, ChainError> {
        let contract = IERC721Enumerable::new(addr, self.primary.clone());
        match contract.totalSupply().call().await {
            Ok(n) => Ok(Some(n)),
            Err(e) => {
                debug!(error = %e, "erc721_total_supply.call_failed");
                Ok(None)
            }
        }
    }

    /// `IERC1155.balanceOf(holder, tokenId)`.
    pub async fn erc1155_balance_of(
        &self,
        addr: Address,
        holder: Address,
        token_id: U256,
    ) -> Result<Option<U256>, ChainError> {
        let contract = IERC1155::new(addr, self.primary.clone());
        match contract.balanceOf(holder, token_id).call().await {
            Ok(b) => Ok(Some(b)),
            Err(e) => {
                debug!(error = %e, "erc1155_balance_of.call_failed");
                Ok(None)
            }
        }
    }

    /// `IERC1155MetadataURI.uri(tokenId)`. Caller must perform `{id}`
    /// substitution per the ERC-1155 metadata spec.
    pub async fn erc1155_uri(
        &self,
        addr: Address,
        token_id: U256,
    ) -> Result<Option<String>, ChainError> {
        let contract = IERC1155MetadataURI::new(addr, self.primary.clone());
        match contract.uri(token_id).call().await {
            Ok(s) => Ok(Some(s)),
            Err(e) => {
                debug!(error = %e, "erc1155_uri.call_failed");
                Ok(None)
            }
        }
    }

    /// `isApprovedForAll(owner, operator)`. Selector is shared by
    /// ERC-721 and ERC-1155.
    pub async fn is_approved_for_all(
        &self,
        addr: Address,
        owner: Address,
        operator: Address,
    ) -> Result<Option<bool>, ChainError> {
        let contract = IERC721::new(addr, self.primary.clone());
        match contract.isApprovedForAll(owner, operator).call().await {
            Ok(b) => Ok(Some(b)),
            Err(e) => {
                debug!(error = %e, "is_approved_for_all.call_failed");
                Ok(None)
            }
        }
    }

    /// Read a single 32-byte storage slot at `addr`, optionally pinning
    /// the read to a specific block (defaults to `latest`). The `block`
    /// arg accepts `"latest"`, a decimal block number, or `0x`-prefixed
    /// hex. Surfaces `eth_getStorageAt` directly so callers can read raw
    /// state (EIP-1967 proxy slots, ERC-20 internals, packed structs).
    pub async fn eth_get_storage_at(
        &self,
        addr: Address,
        slot: U256,
        block: Option<&str>,
    ) -> Result<B256, ChainError> {
        let req = self.primary.get_storage_at(addr, slot);
        let val: U256 = match block {
            None | Some("latest") | Some("") => req.await?,
            Some("earliest") => req.block_id(BlockNumberOrTag::Earliest.into()).await?,
            Some("pending") => req.block_id(BlockNumberOrTag::Pending.into()).await?,
            Some(s) => {
                let n = parse_block_arg(s)?;
                req.block_id(BlockNumberOrTag::Number(n).into()).await?
            }
        };
        Ok(B256::from(val.to_be_bytes::<32>()))
    }

    /// Fetch logs for a fully-formed `Filter`. Thin wrapper over
    /// `eth_getLogs`; the contract handler builds the `Filter` from
    /// user-supplied `from_block`/`to_block`/topics so the wrapper stays
    /// transport-agnostic.
    pub async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>, ChainError> {
        Ok(self.primary.get_logs(filter).await?)
    }

    /// Run `eth_call` against the latest block, optionally applying a set of
    /// state overrides (account balance / nonce / code / storage). This is the
    /// simulator's main hammer — never broadcasts.
    pub async fn eth_call_with_overrides(
        &self,
        req: TransactionRequest,
        overrides: Option<StateOverride>,
    ) -> Result<Bytes, ChainError> {
        let call = self.primary.call(req);
        let bytes = match overrides {
            Some(o) => call.overrides(o).await?,
            None => call.await?,
        };
        Ok(bytes)
    }

    /// Run `eth_call` against an explicit block tag/number. Used by the
    /// `methods/<m>.read` surface so users can read state at a historical
    /// block. `block` accepts the same vocabulary as
    /// [`Self::eth_get_storage_at`].
    pub async fn eth_call_at_block(
        &self,
        req: TransactionRequest,
        block: Option<&str>,
    ) -> Result<Bytes, ChainError> {
        let call = self.primary.call(req);
        let bytes = match block {
            None | Some("latest") | Some("") => call.await?,
            Some("earliest") => call.block(BlockNumberOrTag::Earliest.into()).await?,
            Some("pending") => call.block(BlockNumberOrTag::Pending.into()).await?,
            Some(s) => {
                let n = parse_block_arg(s)?;
                call.block(BlockNumberOrTag::Number(n).into()).await?
            }
        };
        Ok(bytes)
    }

    /// Attempt `debug_traceCall`. Many providers (Alchemy free, Infura) don't
    /// support this; the caller should treat any RPC error here as
    /// "tracing unsupported" and surface that as informational rather than fatal.
    pub async fn debug_trace_call(
        &self,
        req: TransactionRequest,
        overrides: Option<StateOverride>,
    ) -> Result<serde_json::Value, ChainError> {
        // params order: [tx, blockTag, traceConfig]
        // We pass a `callTracer` config when overrides are absent; when overrides
        // are present, we splice them into the trace config (Geth-style).
        let block: alloy::eips::BlockNumberOrTag = alloy::eips::BlockNumberOrTag::Latest;
        let mut cfg = serde_json::json!({ "tracer": "callTracer" });
        if let Some(o) = overrides {
            cfg["stateOverrides"] =
                serde_json::to_value(o).map_err(|e| ChainError::Decode(e.to_string()))?;
        }
        let params = (req, block, cfg);
        let res: serde_json::Value = self
            .primary
            .client()
            .request("debug_traceCall", params)
            .await
            .map_err(|e| ChainError::Rpc(e.to_string()))?;
        Ok(res)
    }
}

/// A registry of chain clients keyed by name.
#[derive(Clone, Default)]
pub struct ChainRegistry {
    inner: Arc<RwLock<std::collections::BTreeMap<String, ChainClient>>>,
}

impl ChainRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, client: ChainClient) {
        let name = client.spec().name.clone();
        debug!(chain = %name, "registry.add");
        self.inner.write().insert(name, client);
    }

    pub fn get(&self, name: &str) -> Option<ChainClient> {
        self.inner.read().get(name).cloned()
    }

    pub fn list_names(&self) -> Vec<String> {
        self.inner.read().keys().cloned().collect()
    }

    /// Resolve a registered chain's path segment name from its numeric id, e.g.
    /// `42161` → `"arbitrum"`. Used to render chain-qualified paths.
    pub fn name_for_chain_id(&self, chain_id: u64) -> Option<String> {
        self.inner
            .read()
            .values()
            .find(|c| c.spec().chain_id == chain_id)
            .map(|c| c.spec().name.clone())
    }

    pub fn from_chains<I: IntoIterator<Item = ChainSpec>>(specs: I) -> Result<Self, ChainError> {
        let r = Self::new();
        for s in specs {
            match ChainClient::new(s) {
                Ok(c) => r.add(c),
                Err(e) => warn!(error = %e, "registry.skip"),
            }
        }
        Ok(r)
    }
}

/// Convenience: derive a hash for a B256 hex string.
pub fn parse_block_hash(s: &str) -> Result<BlockHash, ChainError> {
    s.parse::<BlockHash>()
        .map_err(|e| ChainError::Decode(e.to_string()))
}

/// Parse a block-number argument as decimal or `0x`-prefixed hex.
/// Used by the storage / methods surfaces so users can write either
/// `latest`, `123`, or `0x7b` interchangeably.
pub fn parse_block_arg(s: &str) -> Result<u64, ChainError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| ChainError::Decode(format!("block hex: {e}")))
    } else {
        s.parse::<u64>()
            .map_err(|e| ChainError::Decode(format!("block dec: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Legacy txs report their gas price through both `gas_price()` and
    /// `max_fee_per_gas()`; the replay request must carry exactly one
    /// fee style or geth-family nodes reject the `eth_call`.
    #[test]
    fn revert_replay_request_sets_one_fee_style() {
        let legacy = alloy::consensus::TxLegacy {
            gas_price: 7,
            gas_limit: 21_000,
            ..Default::default()
        };
        let req = revert_replay_request(Address::ZERO, &legacy);
        assert_eq!(req.gas_price, Some(7));
        assert_eq!(req.max_fee_per_gas, None);
        assert_eq!(req.max_priority_fee_per_gas, None);

        let eip1559 = alloy::consensus::TxEip1559 {
            max_fee_per_gas: 9,
            max_priority_fee_per_gas: 2,
            gas_limit: 21_000,
            ..Default::default()
        };
        let req = revert_replay_request(Address::ZERO, &eip1559);
        assert_eq!(req.gas_price, None);
        assert_eq!(req.max_fee_per_gas, Some(9));
        assert_eq!(req.max_priority_fee_per_gas, Some(2));
    }

    #[test]
    fn registry_add_get() {
        let spec = ChainSpec::anvil_default();
        let c = ChainClient::new(spec.clone()).unwrap();
        let r = ChainRegistry::new();
        r.add(c);
        assert!(r.get("anvil").is_some());
        assert_eq!(r.list_names(), vec!["anvil".to_string()]);
    }

    #[test]
    fn missing_endpoints_error() {
        // §F.3 of the spec: the error must fire when both `rpc_urls`
        // and `rpc_endpoints` are empty. Clearing only one leg now
        // succeeds because of the back-compat shim in WP-1.
        let mut s = ChainSpec::anvil_default();
        s.rpc_urls.clear();
        s.rpc_endpoints.clear();
        match ChainClient::new(s) {
            Err(ChainError::NoEndpoints(name)) => assert_eq!(name, "anvil"),
            Err(e) => panic!("expected NoEndpoints, got {e:?}"),
            Ok(_) => panic!("expected NoEndpoints error"),
        }
    }

    #[test]
    fn endpoints_only_path_builds_client() {
        // The richer `rpc_endpoints` form must let us build a client
        // even with `rpc_urls` empty — this is the new path WP-1
        // unblocks and WP-2 honours through `RpcEngine::build`.
        use bloom_proto::EndpointSpec;
        let mut s = ChainSpec::anvil_default();
        s.rpc_urls.clear();
        s.rpc_endpoints.push(EndpointSpec {
            url: "http://127.0.0.1:8545".into(),
            weight: 100,
            cu_per_sec: None,
            max_rps: None,
            http_only: false,
        });
        let client = ChainClient::new(s).expect("build client from rich form");
        assert!(!client.supports_subscriptions());
    }

    #[test]
    fn invalid_url_returns_url_error() {
        let mut s = ChainSpec::anvil_default();
        s.rpc_urls = vec!["::not a url::".to_string()];
        match ChainClient::new(s) {
            Err(ChainError::Url(_)) => {}
            Err(e) => panic!("expected Url error, got {e:?}"),
            Ok(_) => panic!("expected Url error"),
        }
    }

    #[test]
    fn from_chains_skips_bad_specs() {
        // Empty rpc_urls should be skipped (logged as warn) without erroring the registry.
        let good = ChainSpec::anvil_default();
        let mut bad = ChainSpec::anvil_default();
        bad.name = "broken".to_string();
        bad.rpc_urls.clear();
        let r = ChainRegistry::from_chains(vec![good, bad]).unwrap();
        assert!(r.get("anvil").is_some());
        assert!(r.get("broken").is_none());
    }

    #[test]
    fn registry_overwrites_on_duplicate_name() {
        // The BTreeMap insert semantics mean a second `add` for the same chain name
        // replaces the previous entry — that's fine but worth pinning so a future
        // refactor doesn't silently change to a "first-wins" or "error" model.
        let r = ChainRegistry::new();
        let mut s1 = ChainSpec::anvil_default();
        s1.chain_id = 1;
        let mut s2 = ChainSpec::anvil_default();
        s2.chain_id = 2;
        r.add(ChainClient::new(s1).unwrap());
        r.add(ChainClient::new(s2).unwrap());
        let got = r.get("anvil").unwrap();
        assert_eq!(got.spec().chain_id, 2);
    }

    #[test]
    fn parse_block_arg_dec_and_hex() {
        assert_eq!(parse_block_arg("0").unwrap(), 0);
        assert_eq!(parse_block_arg("123").unwrap(), 123);
        assert_eq!(parse_block_arg("0x7b").unwrap(), 123);
        assert_eq!(parse_block_arg("0X7B").unwrap(), 123);
        assert!(parse_block_arg("nope").is_err());
        assert!(parse_block_arg("0xZZ").is_err());
    }

    #[test]
    fn parse_block_arg_trims_whitespace() {
        assert_eq!(parse_block_arg("  42  ").unwrap(), 42);
        assert_eq!(parse_block_arg("\t0x10\n").unwrap(), 16);
    }

    #[test]
    fn parse_block_arg_error_is_decode_variant() {
        let err = parse_block_arg("nope").unwrap_err();
        assert!(matches!(err, ChainError::Decode(_)), "got {err:?}");
        let err = parse_block_arg("0xZZ").unwrap_err();
        assert!(matches!(err, ChainError::Decode(_)), "got {err:?}");
    }

    #[test]
    fn parse_block_hash_roundtrip() {
        let h = "0x".to_string() + &"ab".repeat(32);
        let parsed = parse_block_hash(&h).unwrap();
        assert_eq!(format!("{parsed:?}"), format!("0x{}", "ab".repeat(32)));
    }

    #[test]
    fn parse_block_hash_rejects_garbage() {
        let err = parse_block_hash("not a hash").unwrap_err();
        assert!(matches!(err, ChainError::Decode(_)), "got {err:?}");
    }

    #[test]
    fn chain_error_display_messages() {
        // Pin the user-facing display strings — these surface in the CLI
        // and a refactor could silently break log greppability.
        assert_eq!(
            ChainError::NoEndpoints("foo".into()).to_string(),
            "no rpc endpoints configured for chain 'foo'"
        );
        assert_eq!(
            ChainError::Transport("connection refused".into()).to_string(),
            "transport: connection refused"
        );
        assert_eq!(
            ChainError::Decode("bad utf8".into()).to_string(),
            "decode: bad utf8"
        );
        assert_eq!(
            ChainError::NotFound("tx".into()).to_string(),
            "not found: tx"
        );
        assert_eq!(
            ChainError::Url("invalid".into()).to_string(),
            "url parse: invalid"
        );
        assert_eq!(ChainError::Rpc("revert".into()).to_string(), "rpc: revert");
    }

    #[test]
    fn chain_client_id_and_spec_accessors() {
        let mut spec = ChainSpec::anvil_default();
        spec.chain_id = 12345;
        let c = ChainClient::new(spec.clone()).unwrap();
        assert_eq!(c.id().0, 12345);
        assert_eq!(c.spec().name, spec.name);
        // provider() returns an Arc clone — sanity that the pointer is usable.
        let p = c.provider();
        assert!(Arc::strong_count(&p) >= 1);
    }
}

// ---------------------------------------------------------------------------
// Mock-RPC tests
// ---------------------------------------------------------------------------
//
// These tests spin up a tiny dispatching JSON-RPC server on `127.0.0.1:0` and
// point a `ChainClient` at it. We avoid pulling in `mockito`/`wiremock`/etc.
// — a hand-rolled tokio listener mirrors the pattern used in `bloom-prices`
// and `bloom-defi`.
//
// Rules for the mock:
//   * Each test owns its own listener; no global state, no port reuse.
//   * The handler dispatches by JSON-RPC `method` so a single server can
//     answer the multi-call sequences alloy issues internally.
//   * Responses are pre-baked JSON — we don't try to model alloy's full
//     wire format, just produce the shape its decoder expects.
//
#[cfg(test)]
mod mock_rpc_tests {
    use super::*;
    use alloy::network::TransactionBuilder;
    use alloy::primitives::address;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Either a canned success result (raw JSON value as a string) or a
    /// JSON-RPC error response body. The dispatcher embeds this into a
    /// `{ "jsonrpc": "2.0", "id": <echo>, "result": <X> }` envelope.
    #[derive(Clone)]
    #[allow(dead_code)] // RawBody kept for future malformed-frame tests.
    enum MockResponse {
        /// Raw JSON for the `result` field (already JSON-encoded).
        Ok(String),
        /// `(code, message, data)` for the `error` field.
        Err(i64, String, Option<String>),
        /// Raw HTTP body — useful for malformed-response tests.
        RawBody(String),
    }

    /// Spawn a tiny dispatching mock server. Returns the URL.
    ///
    /// `responses` maps JSON-RPC method names to a queue of responses.
    /// Methods are popped from the front on each call so tests can model
    /// request-order-dependent behaviour. If a method is missing or its
    /// queue is exhausted the server replies with a generic JSON-RPC error
    /// to make the failure mode obvious in test output.
    async fn spawn_mock(responses: HashMap<String, Vec<MockResponse>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let state = Arc::new(parking_lot::Mutex::new(responses));
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::with_capacity(16 * 1024);
                    let mut tmp = [0u8; 4096];
                    // Read until we have headers + Content-Length bytes.
                    let body = loop {
                        let n = match sock.read(&mut tmp).await {
                            Ok(0) => break String::new(),
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers = match std::str::from_utf8(&buf[..end]) {
                                Ok(s) => s,
                                Err(_) => return,
                            };
                            let cl = headers
                                .lines()
                                .find_map(|l| {
                                    let l = l.trim();
                                    let mut p = l.splitn(2, ':');
                                    let k = p.next()?.trim();
                                    if k.eq_ignore_ascii_case("content-length") {
                                        p.next()?.trim().parse::<usize>().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            let body_start = end + 4;
                            // Read remaining body if needed.
                            while buf.len() < body_start + cl {
                                let n = match sock.read(&mut tmp).await {
                                    Ok(0) => break,
                                    Ok(n) => n,
                                    Err(_) => return,
                                };
                                buf.extend_from_slice(&tmp[..n]);
                            }
                            let body_end = body_start + cl;
                            break String::from_utf8_lossy(&buf[body_start..body_end]).to_string();
                        }
                    };
                    let req: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    let id = req.get("id").cloned().unwrap_or(serde_json::json!(1));
                    let method = req
                        .get("method")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string();

                    let resp = {
                        let mut g = state.lock();
                        g.get_mut(&method).and_then(|q| {
                            if q.is_empty() {
                                None
                            } else {
                                Some(q.remove(0))
                            }
                        })
                    };
                    let (status_line, body) = match resp {
                        Some(MockResponse::Ok(result)) => (
                            "HTTP/1.1 200 OK",
                            format!(
                                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
                                serde_json::to_string(&id).unwrap(),
                                result
                            ),
                        ),
                        Some(MockResponse::Err(code, message, data)) => {
                            let data_str =
                                data.map(|d| format!(",\"data\":{}", d)).unwrap_or_default();
                            (
                                "HTTP/1.1 200 OK",
                                format!(
                                    "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":{},\"message\":{}{}}}}}",
                                    serde_json::to_string(&id).unwrap(),
                                    code,
                                    serde_json::to_string(&message).unwrap(),
                                    data_str
                                ),
                            )
                        }
                        Some(MockResponse::RawBody(b)) => ("HTTP/1.1 200 OK", b),
                        None => (
                            "HTTP/1.1 200 OK",
                            format!(
                                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32601,\"message\":\"method not mocked: {}\"}}}}",
                                serde_json::to_string(&id).unwrap(),
                                method
                            ),
                        ),
                    };
                    let resp = format!(
                        "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status_line,
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        format!("http://{addr}")
    }

    /// Build a ChainClient that talks to `url`.
    fn client_at(url: &str) -> ChainClient {
        let mut spec = ChainSpec::anvil_default();
        spec.rpc_urls = vec![url.to_string()];
        ChainClient::new(spec).unwrap()
    }

    /// Convenience: hex-encode a u64 as a JSON-RPC quantity string.
    fn qty(n: u64) -> String {
        format!("\"0x{:x}\"", n)
    }

    /// Convenience: hex-encode a U256.
    fn qty_u256(n: U256) -> String {
        format!("\"0x{:x}\"", n)
    }

    fn responses() -> HashMap<String, Vec<MockResponse>> {
        HashMap::new()
    }

    // -- chain_id ----------------------------------------------------------

    #[tokio::test]
    async fn chain_id_happy_path_and_caches() {
        let mut r = responses();
        r.insert("eth_chainId".into(), vec![MockResponse::Ok(qty(31337))]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        assert_eq!(c.chain_id().await.unwrap(), 31337);
        // Cache: a second call must NOT hit the (now-empty) mock.
        assert_eq!(c.chain_id().await.unwrap(), 31337);
    }

    #[tokio::test]
    async fn chain_id_malformed_response_is_transport_error() {
        let mut r = responses();
        // `result` claims to be a string but isn't a valid quantity hex.
        r.insert(
            "eth_chainId".into(),
            vec![MockResponse::Ok("\"not-a-number\"".to_string())],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let err = c.chain_id().await.unwrap_err();
        // Decoding errors come through alloy's transport layer in this stack.
        match err {
            ChainError::Transport(_) => {}
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    // -- block_number -----------------------------------------------------

    #[tokio::test]
    async fn block_number_happy_path() {
        let mut r = responses();
        r.insert(
            "eth_blockNumber".into(),
            vec![MockResponse::Ok(qty(0xabcd))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        assert_eq!(c.block_number().await.unwrap(), 0xabcd);
    }

    // -- balance ----------------------------------------------------------

    #[tokio::test]
    async fn balance_happy_path() {
        let want = U256::from(1_234_567u128);
        let mut r = responses();
        r.insert(
            "eth_getBalance".into(),
            vec![MockResponse::Ok(qty_u256(want))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let addr = address!("0x1111111111111111111111111111111111111111");
        assert_eq!(c.balance(addr).await.unwrap(), want);
    }

    #[tokio::test]
    async fn balance_zero_for_unknown_account() {
        let mut r = responses();
        r.insert(
            "eth_getBalance".into(),
            vec![MockResponse::Ok("\"0x0\"".to_string())],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let addr = address!("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead");
        assert_eq!(c.balance(addr).await.unwrap(), U256::ZERO);
    }

    // -- nonce ------------------------------------------------------------

    #[tokio::test]
    async fn nonce_happy_path() {
        let mut r = responses();
        r.insert(
            "eth_getTransactionCount".into(),
            vec![MockResponse::Ok(qty(7))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let addr = address!("0x2222222222222222222222222222222222222222");
        assert_eq!(c.nonce(addr).await.unwrap(), 7);
    }

    // -- code -------------------------------------------------------------

    #[tokio::test]
    async fn code_returns_bytes() {
        let mut r = responses();
        r.insert(
            "eth_getCode".into(),
            vec![MockResponse::Ok("\"0x6080604052\"".into())],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let addr = address!("0x3333333333333333333333333333333333333333");
        let bytes = c.code(addr).await.unwrap();
        assert_eq!(bytes, vec![0x60, 0x80, 0x60, 0x40, 0x52]);
    }

    #[tokio::test]
    async fn code_empty_for_eoa() {
        let mut r = responses();
        r.insert(
            "eth_getCode".into(),
            vec![MockResponse::Ok("\"0x\"".into())],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let addr = address!("0x4444444444444444444444444444444444444444");
        assert!(c.code(addr).await.unwrap().is_empty());
    }

    // -- receipt ----------------------------------------------------------

    #[tokio::test]
    async fn receipt_missing_returns_none() {
        // alloy treats `result: null` from `eth_getTransactionReceipt` as Ok(None).
        let mut r = responses();
        r.insert(
            "eth_getTransactionReceipt".into(),
            vec![MockResponse::Ok("null".into())],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let h = B256::repeat_byte(0xaa);
        assert!(c.receipt(h).await.unwrap().is_none());
    }

    // -- gas_price --------------------------------------------------------

    #[tokio::test]
    async fn gas_price_happy_path() {
        let mut r = responses();
        r.insert(
            "eth_gasPrice".into(),
            vec![MockResponse::Ok(qty(1_000_000_000))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        assert_eq!(c.gas_price().await.unwrap(), 1_000_000_000);
    }

    // -- estimate_gas -----------------------------------------------------

    #[tokio::test]
    async fn estimate_gas_happy_path() {
        let mut r = responses();
        r.insert("eth_estimateGas".into(), vec![MockResponse::Ok(qty(21000))]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let req = TransactionRequest::default();
        assert_eq!(c.estimate_gas(&req).await.unwrap(), 21000);
    }

    #[tokio::test]
    async fn estimate_gas_revert_is_transport_error() {
        let mut r = responses();
        r.insert(
            "eth_estimateGas".into(),
            vec![MockResponse::Err(
                3,
                "execution reverted: insufficient allowance".into(),
                None,
            )],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let req = TransactionRequest::default();
        let err = c.estimate_gas(&req).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("execution reverted") || msg.contains("insufficient allowance"),
            "expected revert text in error, got: {msg}"
        );
    }

    // -- send_raw ---------------------------------------------------------

    #[tokio::test]
    async fn send_raw_happy_path() {
        let h = B256::repeat_byte(0x42);
        let mut r = responses();
        r.insert(
            "eth_sendRawTransaction".into(),
            vec![MockResponse::Ok(format!(
                "\"0x{}\"",
                hex::encode(h.as_slice())
            ))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        // Minimal payload — the mock doesn't validate.
        let raw = Bytes::from(vec![0x02, 0xc0]);
        let got = c.send_raw(raw).await.unwrap();
        assert_eq!(got, h);
    }

    #[tokio::test]
    async fn send_raw_already_known_is_error() {
        // Geth/Erigon return a -32000 with "already known" when re-broadcasting.
        let mut r = responses();
        r.insert(
            "eth_sendRawTransaction".into(),
            vec![MockResponse::Err(-32000, "already known".into(), None)],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let err = c.send_raw(Bytes::from(vec![0x02, 0xc0])).await.unwrap_err();
        assert!(err.to_string().contains("already known"), "got {err}");
    }

    #[tokio::test]
    async fn send_raw_insufficient_funds_is_error() {
        let mut r = responses();
        r.insert(
            "eth_sendRawTransaction".into(),
            vec![MockResponse::Err(
                -32000,
                "insufficient funds for gas * price + value".into(),
                None,
            )],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let err = c.send_raw(Bytes::from(vec![0x02, 0xc0])).await.unwrap_err();
        assert!(err.to_string().contains("insufficient funds"), "got {err}");
    }

    // -- ERC-20 helpers ---------------------------------------------------

    /// ABI-encode a uint8 (right-aligned in a 32-byte word) as a hex JSON string.
    fn enc_uint8(v: u8) -> String {
        let mut w = [0u8; 32];
        w[31] = v;
        format!("\"0x{}\"", hex::encode(w))
    }

    /// ABI-encode a uint256 right-aligned.
    fn enc_uint256(v: U256) -> String {
        format!("\"0x{}\"", hex::encode(v.to_be_bytes::<32>()))
    }

    /// ABI-encode a dynamic string with offset+len header.
    fn enc_string(s: &str) -> String {
        let len = s.len();
        // offset: 0x20
        let mut buf = Vec::new();
        let mut w = [0u8; 32];
        w[31] = 0x20;
        buf.extend_from_slice(&w);
        // length
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(len as u64).to_be_bytes());
        buf.extend_from_slice(&lw);
        // payload, padded to 32-byte boundary.
        let mut payload = s.as_bytes().to_vec();
        let pad = (32 - (len % 32)) % 32;
        payload.extend(std::iter::repeat_n(0u8, pad));
        buf.extend_from_slice(&payload);
        format!("\"0x{}\"", hex::encode(buf))
    }

    #[tokio::test]
    async fn erc20_decimals_happy_path() {
        let mut r = responses();
        r.insert("eth_call".into(), vec![MockResponse::Ok(enc_uint8(6))]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let token = address!("0x5555555555555555555555555555555555555555");
        assert_eq!(c.erc20_decimals(token).await.unwrap(), Some(6));
    }

    #[tokio::test]
    async fn erc20_decimals_revert_returns_none() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Err(3, "execution reverted".into(), None)],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let token = address!("0x5555555555555555555555555555555555555555");
        assert_eq!(c.erc20_decimals(token).await.unwrap(), None);
    }

    #[tokio::test]
    async fn erc20_decimals_short_response_returns_none() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Ok("\"0x1234\"".into())],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let token = address!("0x5555555555555555555555555555555555555555");
        assert_eq!(c.erc20_decimals(token).await.unwrap(), None);
    }

    #[tokio::test]
    async fn erc20_balance_happy_path() {
        let want = U256::from(987_654_321u128);
        let mut r = responses();
        r.insert("eth_call".into(), vec![MockResponse::Ok(enc_uint256(want))]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let token = address!("0x6666666666666666666666666666666666666666");
        let holder = address!("0x7777777777777777777777777777777777777777");
        assert_eq!(c.erc20_balance(token, holder).await.unwrap(), Some(want));
    }

    #[tokio::test]
    async fn erc20_balance_revert_returns_none() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Err(3, "revert".into(), None)],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let token = address!("0x6666666666666666666666666666666666666666");
        let holder = address!("0x7777777777777777777777777777777777777777");
        assert_eq!(c.erc20_balance(token, holder).await.unwrap(), None);
    }

    #[tokio::test]
    async fn erc20_symbol_happy_path() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Ok(enc_string("USDC"))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let token = address!("0x8888888888888888888888888888888888888888");
        assert_eq!(
            c.erc20_symbol(token).await.unwrap().as_deref(),
            Some("USDC")
        );
    }

    #[tokio::test]
    async fn erc20_symbol_revert_returns_none() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Err(3, "revert".into(), None)],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let token = address!("0x8888888888888888888888888888888888888888");
        assert_eq!(c.erc20_symbol(token).await.unwrap(), None);
    }

    #[tokio::test]
    async fn erc20_symbol_zero_word_decodes_as_empty_string() {
        // A single 32-byte zero word is what alloy's sol!-derived decoder
        // sees as a string with offset 0 / length 0 → empty string.
        let mut r = responses();
        r.insert("eth_call".into(), vec![MockResponse::Ok(enc_uint8(0))]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let token = address!("0x8888888888888888888888888888888888888888");
        assert_eq!(c.erc20_symbol(token).await.unwrap().as_deref(), Some(""));
    }

    // -- eth_call helpers -------------------------------------------------

    #[tokio::test]
    async fn eth_call_with_overrides_no_overrides() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Ok("\"0xdead\"".into())],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let req = TransactionRequest::default()
            .with_to(address!("0x9999999999999999999999999999999999999999"))
            .with_input(Bytes::from(vec![0x01]));
        let out = c.eth_call_with_overrides(req, None).await.unwrap();
        assert_eq!(out.as_ref(), &[0xde, 0xad]);
    }

    #[tokio::test]
    async fn eth_call_at_block_uses_named_tag() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Ok("\"0xbeef\"".into())],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let req = TransactionRequest::default()
            .with_to(address!("0x9999999999999999999999999999999999999999"));
        let out = c.eth_call_at_block(req, Some("earliest")).await.unwrap();
        assert_eq!(out.as_ref(), &[0xbe, 0xef]);
    }

    #[tokio::test]
    async fn eth_call_at_block_decoded_block_number() {
        // Asks for `0x10` — confirm parse_block_arg path is taken without
        // an explicit assertion on params (mock is method-only).
        let mut r = responses();
        r.insert("eth_call".into(), vec![MockResponse::Ok("\"0x01\"".into())]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let req = TransactionRequest::default();
        let out = c.eth_call_at_block(req, Some("0x10")).await.unwrap();
        assert_eq!(out.as_ref(), &[0x01]);
    }

    #[tokio::test]
    async fn eth_call_at_block_bad_arg_returns_decode_error() {
        let mut r = responses();
        // The decode happens before we hit RPC, but having the mock around
        // ensures we don't accidentally fall through to a real network.
        r.insert("eth_call".into(), vec![MockResponse::Ok("\"0x\"".into())]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let req = TransactionRequest::default();
        let err = c
            .eth_call_at_block(req, Some("not-a-block"))
            .await
            .unwrap_err();
        assert!(matches!(err, ChainError::Decode(_)), "got {err:?}");
    }

    // -- eth_getStorageAt -------------------------------------------------

    #[tokio::test]
    async fn eth_get_storage_at_happy_path() {
        let mut w = [0u8; 32];
        w[31] = 0x2a;
        let mut r = responses();
        r.insert(
            "eth_getStorageAt".into(),
            vec![MockResponse::Ok(format!("\"0x{}\"", hex::encode(w)))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let addr = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let got = c
            .eth_get_storage_at(addr, U256::ZERO, Some("latest"))
            .await
            .unwrap();
        assert_eq!(got.as_slice()[31], 0x2a);
    }

    #[tokio::test]
    async fn eth_get_storage_at_bad_block_arg_decode_error() {
        let r = responses();
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let addr = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let err = c
            .eth_get_storage_at(addr, U256::ZERO, Some("zzz"))
            .await
            .unwrap_err();
        assert!(matches!(err, ChainError::Decode(_)), "got {err:?}");
    }

    // -- debug_traceCall --------------------------------------------------

    #[tokio::test]
    async fn debug_trace_call_unsupported_maps_to_rpc_error() {
        let mut r = responses();
        r.insert(
            "debug_traceCall".into(),
            vec![MockResponse::Err(
                -32601,
                "the method debug_traceCall does not exist".into(),
                None,
            )],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let req = TransactionRequest::default();
        let err = c.debug_trace_call(req, None).await.unwrap_err();
        match err {
            ChainError::Rpc(msg) => {
                assert!(msg.contains("debug_traceCall"), "got {msg}");
            }
            other => panic!("expected ChainError::Rpc, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn debug_trace_call_happy_path() {
        let mut r = responses();
        r.insert(
            "debug_traceCall".into(),
            vec![MockResponse::Ok(
                "{\"type\":\"CALL\",\"gasUsed\":\"0x1\"}".into(),
            )],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let req = TransactionRequest::default();
        let v = c.debug_trace_call(req, None).await.unwrap();
        assert_eq!(v["type"], "CALL");
        assert_eq!(v["gasUsed"], "0x1");
    }

    // -- eth_call_capture_revert ------------------------------------------

    #[tokio::test]
    async fn eth_call_capture_revert_success_returns_bytes() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Ok(format!("\"0x{}\"", "12abcd"))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let req = TransactionRequest::default();
        let out = c.eth_call_capture_revert(req, None).await.unwrap();
        match out {
            Ok(bytes) => assert_eq!(bytes.as_ref(), &[0x12, 0xab, 0xcd]),
            Err(_) => panic!("expected Ok(success bytes)"),
        }
    }

    /// Builtin `Error("boom")` returndata: 0x08c379a0 + abi-encode("boom").
    fn error_string_returndata(msg: &str) -> Vec<u8> {
        use alloy::sol;
        use alloy::sol_types::{SolError, SolValue as _};
        sol! { error Error(string); }
        let _ = <(String,)>::abi_encode(&(msg.to_string(),)); // ensure trait in scope
        Error(msg.to_string()).abi_encode()
    }

    #[tokio::test]
    async fn eth_call_capture_revert_error_returns_revert_data() {
        let payload = error_string_returndata("boom");
        // alloy provider expects `data` either as a 0x-prefixed hex string
        // *or* as an object with a `data` field. JSON-RPC servers (like
        // anvil) respond with `data` as a 0x-prefixed hex string.
        let data_field = format!("\"0x{}\"", hex::encode(&payload));
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Err(
                3,
                "execution reverted: boom".into(),
                Some(data_field),
            )],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let req = TransactionRequest::default();
        let out = c.eth_call_capture_revert(req, None).await.unwrap();
        match out {
            Ok(_) => panic!("expected revert"),
            Err(returndata) => assert_eq!(returndata.as_ref(), payload.as_slice()),
        }
    }

    // -- transport-layer error mapping ------------------------------------

    #[tokio::test]
    async fn transport_failure_maps_to_transport_error() {
        // No server at all — connect to a port we know isn't bound.
        // Pick port 1 (privileged) on 127.0.0.1; should reliably refuse on
        // every supported CI host.
        let mut spec = ChainSpec::anvil_default();
        spec.rpc_urls = vec!["http://127.0.0.1:1".into()];
        let c = ChainClient::new(spec).unwrap();
        let err = c.block_number().await.unwrap_err();
        assert!(matches!(err, ChainError::Transport(_)), "got {err:?}");
    }

    // -- NFT (ERC-721 / ERC-1155) helpers --------------------------------

    /// ABI-encode a bool as a 32-byte word.
    fn enc_bool(v: bool) -> String {
        let mut w = [0u8; 32];
        w[31] = u8::from(v);
        format!("\"0x{}\"", hex::encode(w))
    }

    /// ABI-encode a 20-byte address right-padded into a 32-byte word.
    fn enc_address(addr: Address) -> String {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(addr.as_slice());
        format!("\"0x{}\"", hex::encode(w))
    }

    #[tokio::test]
    async fn supports_interface_true() {
        let mut r = responses();
        r.insert("eth_call".into(), vec![MockResponse::Ok(enc_bool(true))]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0x1111111111111111111111111111111111111111");
        assert!(
            c.supports_interface(nft, ERC165_INTERFACE_ID_ERC721)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn supports_interface_revert_returns_false() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Err(3, "execution reverted".into(), None)],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0x2222222222222222222222222222222222222222");
        assert!(
            !c.supports_interface(nft, ERC165_INTERFACE_ID_ERC1155)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn nft_detect_erc721() {
        // First call (ERC-721 selector) returns true; ERC-1155 not asked.
        let mut r = responses();
        r.insert("eth_call".into(), vec![MockResponse::Ok(enc_bool(true))]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0x3333333333333333333333333333333333333333");
        assert_eq!(c.nft_detect(nft).await.unwrap(), NftKind::Erc721);
    }

    #[tokio::test]
    async fn nft_detect_erc1155() {
        // ERC-721 → false, ERC-1155 → true.
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![
                MockResponse::Ok(enc_bool(false)),
                MockResponse::Ok(enc_bool(true)),
            ],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0x4444444444444444444444444444444444444444");
        assert_eq!(c.nft_detect(nft).await.unwrap(), NftKind::Erc1155);
    }

    #[tokio::test]
    async fn nft_detect_unknown() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![
                MockResponse::Ok(enc_bool(false)),
                MockResponse::Ok(enc_bool(false)),
            ],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0x5555555555555555555555555555555555555555");
        assert_eq!(c.nft_detect(nft).await.unwrap(), NftKind::Unknown);
    }

    #[tokio::test]
    async fn erc721_owner_of_happy_path() {
        let owner = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Ok(enc_address(owner))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0x6666666666666666666666666666666666666666");
        assert_eq!(
            c.erc721_owner_of(nft, U256::from(42)).await.unwrap(),
            Some(owner)
        );
    }

    #[tokio::test]
    async fn erc721_owner_of_revert_returns_none() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Err(
                3,
                "ERC721: invalid token ID".into(),
                None,
            )],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0x6666666666666666666666666666666666666666");
        assert_eq!(c.erc721_owner_of(nft, U256::from(99)).await.unwrap(), None);
    }

    #[tokio::test]
    async fn erc721_token_uri_happy_path() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Ok(enc_string("ipfs://Qm.../1.json"))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0x7777777777777777777777777777777777777777");
        assert_eq!(
            c.erc721_token_uri(nft, U256::from(1)).await.unwrap(),
            Some("ipfs://Qm.../1.json".into())
        );
    }

    #[tokio::test]
    async fn erc721_get_approved_zero_means_no_approval() {
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Ok(enc_address(Address::ZERO))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0x8888888888888888888888888888888888888888");
        assert_eq!(
            c.erc721_get_approved(nft, U256::from(7)).await.unwrap(),
            Some(Address::ZERO)
        );
    }

    #[tokio::test]
    async fn erc721_total_supply_revert_returns_none() {
        // Plenty of NFTs aren't enumerable; assert the call surfaces
        // None rather than an error.
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Err(3, "execution reverted".into(), None)],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0x9999999999999999999999999999999999999999");
        assert_eq!(c.erc721_total_supply(nft).await.unwrap(), None);
    }

    #[tokio::test]
    async fn erc1155_balance_of_happy_path() {
        let want = U256::from(42u64);
        let mut r = responses();
        r.insert("eth_call".into(), vec![MockResponse::Ok(enc_uint256(want))]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let holder = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(
            c.erc1155_balance_of(nft, holder, U256::from(123))
                .await
                .unwrap(),
            Some(want)
        );
    }

    #[tokio::test]
    async fn erc1155_uri_happy_path_with_id_placeholder() {
        // The ChainClient returns the raw URI; substitution is a handler
        // concern. Assert we get the placeholder back verbatim.
        let mut r = responses();
        r.insert(
            "eth_call".into(),
            vec![MockResponse::Ok(enc_string("https://example/{id}.json"))],
        );
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0xcccccccccccccccccccccccccccccccccccccccc");
        assert_eq!(
            c.erc1155_uri(nft, U256::from(7)).await.unwrap(),
            Some("https://example/{id}.json".into())
        );
    }

    #[tokio::test]
    async fn is_approved_for_all_true() {
        let mut r = responses();
        r.insert("eth_call".into(), vec![MockResponse::Ok(enc_bool(true))]);
        let url = spawn_mock(r).await;
        let c = client_at(&url);
        let nft = address!("0xdddddddddddddddddddddddddddddddddddddddd");
        let owner = address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        let operator = address!("0xffffffffffffffffffffffffffffffffffffffff");
        assert_eq!(
            c.is_approved_for_all(nft, owner, operator).await.unwrap(),
            Some(true)
        );
    }
}

// ---------------------------------------------------------------------------
// Session tests
// ---------------------------------------------------------------------------
//
// Lifted from `bloom-rpc` per the WP-5 spec note: mocking through
// `ChainClient` is the natural seam since `Session` is opened via
// `ChainClient::open_session`, and the existing mock_rpc_tests pattern
// already handles the JSON-RPC dispatch shape we need. The dispatcher
// here is a slimmed copy that records request params so each test can
// assert the session passed `BlockId::Hash(pinned_hash)` (or fell
// through to `BlockId::Number(pinned_number)` on the degraded path).
//
#[cfg(test)]
mod session_tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Either a canned JSON `result` payload or a JSON-RPC error tuple.
    #[derive(Clone, Debug)]
    enum Resp {
        Ok(String),
        Err(i64, String),
    }

    /// Recorded request: `(method, params_json)`. Tests pop these to
    /// assert what the session actually sent.
    type Recorded = Arc<parking_lot::Mutex<Vec<(String, serde_json::Value)>>>;

    /// Spawn a tiny dispatcher that records `(method, params)` and
    /// pops a per-method response queue. Same TCP/HTTP shape as the
    /// `mock_rpc_tests` dispatcher above; intentionally not shared
    /// because we need params capture and the original was
    /// method-only. Returns `(url, recorded)`.
    async fn spawn(responses: HashMap<String, Vec<Resp>>) -> (String, Recorded) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let state = Arc::new(parking_lot::Mutex::new(responses));
        let recorded: Recorded = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let recorded_writer = recorded.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let state = state.clone();
                let rec = recorded_writer.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::with_capacity(16 * 1024);
                    let mut tmp = [0u8; 4096];
                    let body = loop {
                        let n = match sock.read(&mut tmp).await {
                            Ok(0) => break String::new(),
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers = match std::str::from_utf8(&buf[..end]) {
                                Ok(s) => s,
                                Err(_) => return,
                            };
                            let cl = headers
                                .lines()
                                .find_map(|l| {
                                    let mut p = l.trim().splitn(2, ':');
                                    let k = p.next()?.trim();
                                    if k.eq_ignore_ascii_case("content-length") {
                                        p.next()?.trim().parse::<usize>().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            let body_start = end + 4;
                            while buf.len() < body_start + cl {
                                let n = match sock.read(&mut tmp).await {
                                    Ok(0) => break,
                                    Ok(n) => n,
                                    Err(_) => return,
                                };
                                buf.extend_from_slice(&tmp[..n]);
                            }
                            break String::from_utf8_lossy(&buf[body_start..body_start + cl])
                                .to_string();
                        }
                    };
                    let req: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    let id = req.get("id").cloned().unwrap_or(serde_json::json!(1));
                    let method = req
                        .get("method")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string();
                    let params = req
                        .get("params")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    rec.lock().push((method.clone(), params));

                    let resp = {
                        let mut g = state.lock();
                        g.get_mut(&method).and_then(|q| {
                            if q.is_empty() {
                                None
                            } else {
                                Some(q.remove(0))
                            }
                        })
                    };
                    let body = match resp {
                        Some(Resp::Ok(result)) => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
                            serde_json::to_string(&id).unwrap(),
                            result
                        ),
                        Some(Resp::Err(code, msg)) => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":{},\"message\":{}}}}}",
                            serde_json::to_string(&id).unwrap(),
                            code,
                            serde_json::to_string(&msg).unwrap()
                        ),
                        None => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32601,\"message\":\"unmocked: {}\"}}}}",
                            serde_json::to_string(&id).unwrap(),
                            method
                        ),
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (format!("http://{addr}"), recorded)
    }

    fn client_at(url: &str) -> ChainClient {
        let mut spec = ChainSpec::anvil_default();
        spec.rpc_urls = vec![url.to_string()];
        ChainClient::new(spec).unwrap()
    }

    /// Build a JSON `Block` payload at `(number, hash)`. The session
    /// only consumes `header.number` and `header.hash` so we keep this
    /// minimal. Other required fields are filled with zero/empty
    /// values so the alloy decoder accepts it.
    fn block_payload(number: u64, hash: B256) -> String {
        let zero32 = format!("0x{}", "00".repeat(32));
        let zero8 = "0x0000000000000000".to_string();
        let zero_addr = format!("0x{}", "00".repeat(20));
        let zero_bloom = format!("0x{}", "00".repeat(256));
        let hash_hex = format!("0x{}", hex::encode(hash.as_slice()));
        let num_hex = format!("0x{:x}", number);
        serde_json::json!({
            "number": num_hex,
            "hash": hash_hex,
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
            "baseFeePerGas": "0x0",
        })
        .to_string()
    }

    #[tokio::test]
    async fn session_pins_block_hash() {
        // Open a session at block 100/hash A. The next call must carry
        // `BlockId::Hash(A)` in its params, even if the chain head has
        // moved on by the time we read.
        let pinned_hash = B256::repeat_byte(0xaa);
        let pinned_number = 100u64;

        let mut r: HashMap<String, Vec<Resp>> = HashMap::new();
        r.insert(
            "eth_getBlockByNumber".into(),
            vec![Resp::Ok(block_payload(pinned_number, pinned_hash))],
        );
        // Two `eth_getBalance` responses queued — alloy's fallback layer
        // races top-N transports in parallel, but with one URL only one
        // gets popped per call. Two queued lets the session's single
        // `balance` call drain reliably regardless of internal retries.
        r.insert(
            "eth_getBalance".into(),
            vec![Resp::Ok("\"0x539\"".into()), Resp::Ok("\"0x539\"".into())],
        );

        let (url, recorded) = spawn(r).await;
        let client = client_at(&url);

        let session = client.open_session().await.expect("open session");
        assert_eq!(session.block_number(), pinned_number);
        assert_eq!(session.block_hash(), pinned_hash);
        assert!(!session.is_degraded());

        let addr = Address::repeat_byte(0x11);
        let _ = session.balance(addr).await.expect("session balance");

        // Inspect the recorded eth_getBalance call. Params shape is
        // `[address, blockId]` where `blockId` for a hash pin is an
        // object `{ "blockHash": "0x..." }`. Permissive match: walk
        // the JSON and find the pinned hash anywhere.
        let calls = recorded.lock();
        let bal = calls
            .iter()
            .find(|(m, _)| m == "eth_getBalance")
            .expect("eth_getBalance recorded");
        let params_str = bal.1.to_string();
        let want_hex = format!("0x{}", hex::encode(pinned_hash.as_slice()));
        assert!(
            params_str.contains(&want_hex),
            "expected pinned hash in eth_getBalance params, got {params_str}"
        );
    }

    #[tokio::test]
    async fn session_degrades_when_pinned_hash_unavailable() {
        // First eth_getBalance returns "block not found" (vendor-style).
        // The session must retry with a number-based block id and flip
        // `is_degraded` to true. The second call delivers a real
        // balance so the test asserts the round-trip.
        let pinned_hash = B256::repeat_byte(0xbb);
        let pinned_number = 99u64;

        let mut r: HashMap<String, Vec<Resp>> = HashMap::new();
        r.insert(
            "eth_getBlockByNumber".into(),
            vec![Resp::Ok(block_payload(pinned_number, pinned_hash))],
        );
        r.insert(
            "eth_getBalance".into(),
            vec![
                Resp::Err(-32000, "block not found".into()),
                Resp::Ok("\"0x2a\"".into()),
            ],
        );

        let (url, recorded) = spawn(r).await;
        let client = client_at(&url);

        let session = client.open_session().await.expect("open session");
        let addr = Address::repeat_byte(0x22);
        let value = session.balance(addr).await.expect("session balance");
        assert_eq!(value, U256::from(0x2au64));
        assert!(session.is_degraded(), "session must mark itself degraded");

        // Recorded params: first call sent the hash, second sent the
        // number — pin the retry shape so a future refactor doesn't
        // accidentally retry with `latest`.
        let calls = recorded.lock();
        let balance_calls: Vec<_> = calls
            .iter()
            .filter(|(m, _)| m == "eth_getBalance")
            .collect();
        assert_eq!(
            balance_calls.len(),
            2,
            "expected exactly two eth_getBalance calls"
        );
        let first = balance_calls[0].1.to_string();
        let second = balance_calls[1].1.to_string();
        let hash_hex = format!("0x{}", hex::encode(pinned_hash.as_slice()));
        let num_hex = format!("0x{:x}", pinned_number);
        assert!(
            first.contains(&hash_hex),
            "first call should target hash, got {first}"
        );
        assert!(
            second.contains(&num_hex) && !second.contains(&hash_hex),
            "second call should target number and not the hash, got {second}"
        );
    }
}
