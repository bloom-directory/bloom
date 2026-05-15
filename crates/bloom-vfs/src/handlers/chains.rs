//! `chains/<chain>/` — read-only chain views.
//!
//! Subset implemented for v1:
//! - `chains/<chain>/chain_id`
//! - `chains/<chain>/head/number`
//! - `chains/<chain>/head/hash`
//! - `chains/<chain>/head/timestamp`
//! - `chains/<chain>/head/full.json`
//! - `chains/<chain>/blocks/<n>/full.json`
//! - `chains/<chain>/addresses/<addr>/balance` (wei, decimal)
//! - `chains/<chain>/addresses/<addr>/balance.eth`
//! - `chains/<chain>/addresses/<addr>/nonce`
//! - `chains/<chain>/addresses/<addr>/code` (hex bytecode)
//! - `chains/<chain>/addresses/<addr>/tokens/<token>/{balance,balance.raw,balance.formatted,symbol,decimals}`
//! - `chains/<chain>/tx/<hash>/{receipt.json,status,block_number,gas_used,logs.json,full.json}`
//! - `chains/<chain>/gas/current.json`
//!
//! Etherscan-backed (only mounted when an etherscan client is provided):
//! - `chains/<chain>/addresses/<addr>/txs` — recent native txs
//! - `chains/<chain>/addresses/<addr>/internal_txs` — internal txs
//! - `chains/<chain>/addresses/<addr>/erc20_txs` — ERC-20 transfers
//! - `chains/<chain>/addresses/<addr>/erc721_txs` — ERC-721 transfers
//! - `chains/<chain>/contracts/<addr>/source` — verified source
//! - `chains/<chain>/contracts/<addr>/abi` — verified ABI
//! - `chains/<chain>/contracts/<addr>/methods/<name>.{read,tx,sig}` —
//!   ABI-driven calldata + `eth_call` interaction.
//! - `chains/<chain>/contracts/<addr>/events/<name>/{recent,query,live}` —
//!   ABI-driven log decoding (RPC).
//!
//! RPC-only (always available):
//! - `chains/<chain>/contracts/<addr>/storage/<slot>` — `eth_getStorageAt`
//!   (slot is decimal or `0x`-hex). Backend default `rpc`.
//! - `chains/<chain>/contracts/<addr>/proxy/{implementation,admin,beacon}` —
//!   well-known EIP-1967 / EIP-1822 slot reads. Returns a checksummed
//!   address or `not a proxy\n` when the slot is empty.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use bloom_chain::{ChainClient, ChainRegistry};
use bloom_ens::{EnsClient, EnsError};
use bloom_etherscan::{AddressHistorySource, ContractMetadataSource, EtherscanClient};
use bloom_proto::{Backend, BackendsConfig, checksum_address, format_units};
use bloom_revert::{DecodeContext, DecodedRevert, DecoderChain};
use parking_lot::Mutex as PlMutex;

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

use super::chains_contracts::{
    self, AbiCache, EVENT_LEAVES, LiveTailState, METHOD_LEAVES, PROXY_LEAVES, PendingBodies,
};
use super::chains_history;
use super::chains_nfts::{
    self, NFT_COLLECTION_DIRS, NFT_COLLECTION_LEAVES, NFT_HOLDER_LEAVES, NftKindCache,
    PER_TOKEN_LEAVES,
};

#[derive(Clone)]
pub struct ChainsHandler {
    pub registry: ChainRegistry,
    /// Source for verified contract source + ABI lookups. Today this is
    /// always an `EtherscanClient` injected via [`with_etherscan`], but
    /// any [`ContractMetadataSource`] (e.g. a future local indexer) can
    /// be wired in via [`with_contract_metadata`].
    pub contract_metadata: Option<Arc<dyn ContractMetadataSource>>,
    /// Source for paginated address history feeds (txs / token transfers).
    pub address_history: Option<Arc<dyn AddressHistorySource>>,
    pub ens: Option<EnsClient>,
    pub backends: BackendsConfig,
    /// Short-TTL ABI cache shared across method/event reads. Lives on
    /// the handler so the dispatcher's caches stick around between
    /// requests; `Clone` of the handler is cheap because both fields
    /// are `Arc`.
    abi_cache: Arc<AbiCache>,
    /// Per-(chain, addr, event) cursor for the `events/<name>/live`
    /// long-poll surface. See `chains_contracts::LiveTailState` doc.
    live_state: Arc<LiveTailState>,
    /// Last-written body for each writable methods/events file. Reads
    /// fall back to an empty `{"args":[]}` body when nothing has been
    /// posted yet; this makes the surface ergonomic from the shell.
    pending: Arc<PendingBodies>,
    /// Process-wide cache of ERC-165 NFT kind detection.
    nft_cache: Arc<NftKindCache>,
    /// Tiered revert decoder chain, shared across requests. `None` is a
    /// degenerate config: `error.json` will return an empty marker.
    revert_decoder: Arc<DecoderChain>,
    /// Cache of decoded reverts keyed by `(chain, tx_hash)`. Reverts are
    /// immutable so a small unbounded map is fine in practice; the
    /// daemon process is the natural lifetime bound.
    revert_cache:
        Arc<PlMutex<std::collections::HashMap<(String, alloy::primitives::B256), DecodedRevert>>>,
    /// Per-chain mempool handlers. Empty by default; populated by the
    /// daemon via [`with_mempool_handlers`] when mempool providers are
    /// configured. Keys are chain names (e.g., "ethereum").
    mempool_handlers:
        Arc<std::collections::BTreeMap<String, Arc<super::chains_mempool::MempoolHandler>>>,
}

impl ChainsHandler {
    pub fn new(registry: ChainRegistry) -> Self {
        Self {
            registry,
            contract_metadata: None,
            address_history: None,
            ens: None,
            backends: BackendsConfig::default(),
            abi_cache: Arc::new(AbiCache::new()),
            live_state: Arc::new(LiveTailState::new()),
            pending: Arc::new(PendingBodies::new()),
            nft_cache: Arc::new(NftKindCache::new()),
            revert_decoder: Arc::new(DecoderChain::new()),
            revert_cache: Arc::new(PlMutex::new(std::collections::HashMap::new())),
            mempool_handlers: Arc::new(std::collections::BTreeMap::new()),
        }
    }

    /// Builder: install a tiered revert decoder chain. Used by `error.json`
    /// reads on reverted transactions.
    pub fn with_revert_decoder(mut self, chain: Arc<DecoderChain>) -> Self {
        self.revert_decoder = chain;
        self
    }

    /// Builder: attach an Etherscan client. Convenience for the common
    /// case — wires the same client as both the contract-metadata source
    /// and the address-history source. Without one, the etherscan-backed
    /// paths return `NotFound` and existing chain reads are unaffected.
    pub fn with_etherscan(mut self, client: Option<Arc<EtherscanClient>>) -> Self {
        self.contract_metadata = client.clone().map(|c| c as Arc<dyn ContractMetadataSource>);
        self.address_history = client.map(|c| c as Arc<dyn AddressHistorySource>);
        self
    }

    /// Builder: install a custom contract-metadata source (e.g. an
    /// embedded indexer). Overrides what `with_etherscan` set.
    pub fn with_contract_metadata(mut self, src: Option<Arc<dyn ContractMetadataSource>>) -> Self {
        self.contract_metadata = src;
        self
    }

    /// Builder: install a custom address-history source.
    pub fn with_address_history(mut self, src: Option<Arc<dyn AddressHistorySource>>) -> Self {
        self.address_history = src;
        self
    }

    /// Builder: attach an ENS client so `addresses/<addr>/ens` returns
    /// the reverse-resolved name (cross-checked against forward
    /// resolution by `EnsClient::reverse`).
    pub fn with_ens(mut self, client: Option<EnsClient>) -> Self {
        self.ens = client;
        self
    }

    /// Builder: install the per-feature backend selection. Defaults to
    /// the historical wiring (Etherscan for metadata + history).
    pub fn with_backends(mut self, backends: BackendsConfig) -> Self {
        self.backends = backends;
        self
    }

    /// Builder: install per-chain mempool handlers. Empty by default.
    /// When populated, `chains/<chain>/mempool/...` is delegated to the
    /// per-chain `MempoolHandler`.
    pub fn with_mempool_handlers(
        mut self,
        handlers: std::collections::BTreeMap<String, Arc<super::chains_mempool::MempoolHandler>>,
    ) -> Self {
        self.mempool_handlers = Arc::new(handlers);
        self
    }

    fn client(&self, name: &str) -> Result<ChainClient, HandlerError> {
        self.registry
            .get(name)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", name)))
    }

    /// Resolve the contract-metadata source. Returns `NotFound` with an
    /// explicit message when the feature is configured for etherscan
    /// but no credentials are wired.
    fn require_contract_metadata_source(
        &self,
    ) -> Result<&Arc<dyn ContractMetadataSource>, HandlerError> {
        self.contract_metadata.as_ref().ok_or_else(|| {
            HandlerError::not_found(
                "contract_metadata backend = \"etherscan\" but [etherscan] is not configured"
                    .to_string(),
            )
        })
    }

    /// Resolve the address-history source.
    fn require_address_history_source(
        &self,
    ) -> Result<&Arc<dyn AddressHistorySource>, HandlerError> {
        self.address_history.as_ref().ok_or_else(|| {
            HandlerError::not_found(
                "address_history backend = \"etherscan\" but [etherscan] is not configured"
                    .to_string(),
            )
        })
    }

    /// Gate the contract-metadata surfaces based on the declared
    /// backend. Returns the source on success; a clear error on a
    /// backend mismatch or missing credentials.
    fn require_contract_metadata_backend(
        &self,
    ) -> Result<&Arc<dyn ContractMetadataSource>, HandlerError> {
        match self.backends.contract_metadata {
            Backend::Etherscan => self.require_contract_metadata_source(),
            Backend::Rpc => Err(HandlerError::not_found(
                "contract_metadata configured as backend = \"rpc\"; this surface requires \"etherscan\" \
                 (or a future \"indexer\")"
                    .to_string(),
            )),
            Backend::Indexer => Err(HandlerError::not_found(
                "contract_metadata configured as backend = \"indexer\" but the embedded indexer is not yet implemented"
                    .to_string(),
            )),
        }
    }

    /// Gate the address-history surfaces based on the declared backend.
    fn require_address_history_backend(
        &self,
    ) -> Result<&Arc<dyn AddressHistorySource>, HandlerError> {
        match self.backends.address_history {
            Backend::Etherscan => self.require_address_history_source(),
            Backend::Rpc => Err(HandlerError::not_found(
                "address_history configured as backend = \"rpc\"; this surface requires \"etherscan\" \
                 (or a future \"indexer\")"
                    .to_string(),
            )),
            Backend::Indexer => Err(HandlerError::not_found(
                "address_history configured as backend = \"indexer\" but the embedded indexer is not yet implemented"
                    .to_string(),
            )),
        }
    }

    fn ens_or_404(&self) -> Result<&EnsClient, HandlerError> {
        self.ens
            .as_ref()
            .ok_or_else(|| HandlerError::not_found("ens not configured"))
    }

    /// Whether `address_history` is currently usable (configured as
    /// etherscan with credentials wired). Used by `list()` to decide
    /// whether to advertise the etherscan-backed entries.
    fn address_history_ready(&self) -> bool {
        matches!(self.backends.address_history, Backend::Etherscan)
            && self.address_history.is_some()
    }

    /// Whether `contract_metadata` is currently usable.
    fn contract_metadata_ready(&self) -> bool {
        matches!(self.backends.contract_metadata, Backend::Etherscan)
            && self.contract_metadata.is_some()
    }

    /// Decompose `methods/<name>.<leaf>` into (`name`, `leaf`). Returns
    /// `None` if the trailing segment doesn't look like one of our
    /// `.read`/`.tx`/`.sig` leaves.
    fn split_method_leaf(seg: &str) -> Option<(&str, &str)> {
        for leaf in METHOD_LEAVES {
            let pat = format!(".{leaf}");
            if let Some(name) = seg.strip_suffix(&pat)
                && !name.is_empty()
            {
                return Some((name, leaf));
            }
        }
        None
    }

    async fn lookup_contracts(
        &self,
        path: &VfsPath,
        segs: &[String],
    ) -> Result<Entry, HandlerError> {
        // segs = ["<chain>", "contracts", "<addr>", ...rest]
        match segs.len() {
            2 => Ok(Entry::dir("contracts")),
            3 => {
                // contracts/<addr> is itself a dir even without etherscan;
                // subtrees gate themselves (source/abi/methods/events
                // need contract_metadata; storage/proxy/nft do not).
                let _ = parse_addr(&segs[2])?;
                Ok(Entry::dir(&segs[2]))
            }
            n if n >= 4 => {
                let _addr = parse_addr(&segs[2])?;
                let kind = segs[3].as_str();
                match kind {
                    "source" | "abi" => {
                        if n != 4 {
                            return Err(HandlerError::not_found(path.to_string_path()));
                        }
                        self.require_contract_metadata_backend()?;
                        Ok(Entry::file(kind))
                    }
                    "methods" => {
                        self.require_contract_metadata_backend()?;
                        match n {
                            4 => Ok(Entry::dir("methods")),
                            5 => {
                                let leaf = segs[4].as_str();
                                let (_, suffix) =
                                    Self::split_method_leaf(leaf).ok_or_else(|| {
                                        HandlerError::not_found(path.to_string_path())
                                    })?;
                                Ok(if suffix == "sig" {
                                    Entry::file(leaf)
                                } else {
                                    Entry::writable_file(leaf)
                                })
                            }
                            _ => Err(HandlerError::not_found(path.to_string_path())),
                        }
                    }
                    "events" => {
                        self.require_contract_metadata_backend()?;
                        match n {
                            4 => Ok(Entry::dir("events")),
                            5 => Ok(Entry::dir(&segs[4])),
                            6 => {
                                let leaf = segs[5].as_str();
                                if !EVENT_LEAVES.contains(&leaf) {
                                    return Err(HandlerError::not_found(path.to_string_path()));
                                }
                                Ok(if leaf == "query" {
                                    Entry::writable_file(leaf)
                                } else {
                                    Entry::file(leaf)
                                })
                            }
                            _ => Err(HandlerError::not_found(path.to_string_path())),
                        }
                    }
                    "storage" => match n {
                        4 => Ok(Entry::dir("storage")),
                        5 => Ok(Entry::file(&segs[4])),
                        _ => Err(HandlerError::not_found(path.to_string_path())),
                    },
                    "proxy" => match n {
                        4 => Ok(Entry::dir("proxy")),
                        5 => {
                            let leaf = segs[4].as_str();
                            if PROXY_LEAVES.contains(&leaf) {
                                Ok(Entry::file(leaf))
                            } else {
                                Err(HandlerError::not_found(path.to_string_path()))
                            }
                        }
                        _ => Err(HandlerError::not_found(path.to_string_path())),
                    },
                    "nft" => match n {
                        4 => Ok(Entry::dir("nft")),
                        5 => {
                            let leaf = segs[4].as_str();
                            if NFT_COLLECTION_LEAVES.contains(&leaf) {
                                Ok(Entry::file(leaf))
                            } else if NFT_COLLECTION_DIRS.contains(&leaf) {
                                Ok(Entry::dir(leaf))
                            } else {
                                Err(HandlerError::not_found(path.to_string_path()))
                            }
                        }
                        6 => {
                            let leaf = segs[4].as_str();
                            match leaf {
                                "owner_of" | "token_uri" => {
                                    let _ = chains_nfts::parse_token_id(&segs[5])?;
                                    Ok(Entry::file(&segs[5]))
                                }
                                "is_approved_for_all" => {
                                    let _ = parse_addr(&segs[5])?;
                                    Ok(Entry::dir(&segs[5]))
                                }
                                _ => Err(HandlerError::not_found(path.to_string_path())),
                            }
                        }
                        7 if segs[4] == "is_approved_for_all" => {
                            let _ = parse_addr(&segs[5])?;
                            let _ = parse_addr(&segs[6])?;
                            Ok(Entry::file(&segs[6]))
                        }
                        _ => Err(HandlerError::not_found(path.to_string_path())),
                    },
                    _ => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }
}

fn parse_addr(s: &str) -> Result<alloy::primitives::Address, HandlerError> {
    s.parse::<alloy::primitives::Address>()
        .map_err(|e| HandlerError::invalid(format!("address: {}", e)))
}

fn err_be(e: impl std::fmt::Display) -> HandlerError {
    HandlerError::backend(e.to_string())
}

/// Files exposed under `addresses/<addr>/`. Etherscan-backed entries are
/// flagged so we only emit them when an etherscan client is configured.
const ADDRESS_FILES_CORE: &[&str] = &[
    "balance",
    "balance.eth",
    "balance.raw",
    "nonce",
    "code",
    "is_contract",
];
const ADDRESS_FILES_ETHERSCAN: &[&str] = &["txs", "internal_txs", "erc20_txs", "erc721_txs"];
/// Files that need an ENS-capable chain to be wired into the handler.
const ADDRESS_FILES_ENS: &[&str] = &["ens"];

const CONTRACT_FILES_ETHERSCAN: &[&str] = &["source", "abi"];

const TX_FILES: &[&str] = &[
    "receipt.json",
    "status",
    "block_number",
    "gas_used",
    "logs.json",
    "full.json",
    "error.json",
];

const TOKEN_FILES: &[&str] = &[
    "balance",
    "balance.raw",
    "balance.formatted",
    "symbol",
    "decimals",
];

#[async_trait]
impl Handler for ChainsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                error = %e,
                "chains.lookup_err"
            );
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                error = %e,
                "chains.read_err"
            );
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                error = %e,
                "chains.list_err"
            );
        }
        r
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let r = self.write_inner(path, data).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                bytes = data.len(),
                error = %e,
                "chains.write_err"
            );
        }
        r
    }

    fn cache_ttl(&self, path: &VfsPath) -> Option<Duration> {
        self.cache_ttl_inner(path)
    }
}

impl ChainsHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Ok(Entry::dir(""));
        }
        let chain = &segs[0];
        let _client = self.client(chain)?;
        if segs.len() == 1 {
            return Ok(Entry::dir(chain));
        }
        match segs[1].as_str() {
            "chain_id" if segs.len() == 2 => Ok(Entry::file("chain_id")),
            "head" => match segs.get(2).map(|s| s.as_str()) {
                None => Ok(Entry::dir("head")),
                Some("number") | Some("hash") | Some("timestamp") | Some("full.json") => {
                    Ok(Entry::file(segs.last().unwrap()))
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "blocks" => match segs.len() {
                2 => Ok(Entry::dir("blocks")),
                3 => Ok(Entry::dir(&segs[2])),
                4 if segs[3] == "full.json" => Ok(Entry::file("full.json")),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "addresses" => match segs.len() {
                2 => Ok(Entry::dir("addresses")),
                3 => Ok(Entry::dir(&segs[2])),
                4 => {
                    let f = segs[3].as_str();
                    if ADDRESS_FILES_CORE.contains(&f) {
                        Ok(Entry::file(f))
                    } else if ADDRESS_FILES_ETHERSCAN.contains(&f) {
                        // Surface only mounts when address_history is
                        // backed by etherscan and credentials are wired.
                        self.require_address_history_backend()?;
                        Ok(Entry::file(f))
                    } else if ADDRESS_FILES_ENS.contains(&f) {
                        self.ens_or_404()?;
                        Ok(Entry::file(f))
                    } else if f == "tokens" || f == "nfts" {
                        Ok(Entry::dir(f))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                5 if segs[3] == "tokens" => Ok(Entry::dir(&segs[4])),
                6 if segs[3] == "tokens" => {
                    let f = segs[5].as_str();
                    if TOKEN_FILES.contains(&f) {
                        Ok(Entry::file(f))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                // ---- nfts subtree -----------------------------------
                // /addresses/<a>/nfts/<leaf-or-contract>
                5 if segs[3] == "nfts" => {
                    let f = segs[4].as_str();
                    if NFT_HOLDER_LEAVES.contains(&f) {
                        // Holder-level history files require etherscan.
                        self.require_address_history_backend()?;
                        Ok(Entry::file(f))
                    } else {
                        // Treat as a contract address; per-token files
                        // sit underneath. Validate the address format.
                        let _ = parse_addr(f)?;
                        Ok(Entry::dir(f))
                    }
                }
                6 if segs[3] == "nfts" => {
                    let _ = parse_addr(&segs[4])?;
                    // /addresses/<a>/nfts/<contract>/<token_id>
                    let _ = chains_nfts::parse_token_id(&segs[5])?;
                    Ok(Entry::dir(&segs[5]))
                }
                7 if segs[3] == "nfts" => {
                    let _ = parse_addr(&segs[4])?;
                    let _ = chains_nfts::parse_token_id(&segs[5])?;
                    let f = segs[6].as_str();
                    if PER_TOKEN_LEAVES.contains(&f) {
                        Ok(Entry::file(f))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "tx" => match segs.len() {
                2 => Ok(Entry::dir("tx")),
                3 => Ok(Entry::dir(&segs[2])),
                4 => {
                    let f = segs[3].as_str();
                    if TX_FILES.contains(&f) {
                        Ok(Entry::file(f))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "contracts" => self.lookup_contracts(path, segs).await,
            "gas" => match segs.get(2).map(|s| s.as_str()) {
                None => Ok(Entry::dir("gas")),
                Some("current.json") => Ok(Entry::file("current.json")),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "mempool" => match self.mempool_handlers.get(chain.as_str()) {
                Some(h) => h.lookup(path).await,
                None => Err(HandlerError::not_found(path.to_string_path())),
            },
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        }
        let chain = &segs[0];
        let client = self.client(chain)?;
        match segs.get(1).map(|s| s.as_str()).unwrap_or("") {
            "chain_id" => {
                let id = client.chain_id().await.map_err(err_be)?;
                Ok(format!("{}\n", id).into_bytes())
            }
            "head" => {
                let block = client
                    .block_latest()
                    .await
                    .map_err(err_be)?
                    .ok_or_else(|| HandlerError::backend("no head block"))?;
                match segs.get(2).map(|s| s.as_str()).unwrap_or("") {
                    "number" => Ok(format!("{}\n", block.header.number).into_bytes()),
                    "hash" => Ok(format!("{:#x}\n", block.header.hash).into_bytes()),
                    "timestamp" => Ok(format!("{}\n", block.header.timestamp).into_bytes()),
                    "full.json" => Ok(serde_json::to_vec_pretty(&block).map_err(err_be)?),
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            "blocks" if segs.len() == 4 && segs[3] == "full.json" => {
                let n: u64 = segs[2]
                    .parse()
                    .map_err(|_| HandlerError::invalid("block number"))?;
                let block = client
                    .block_by_number(n)
                    .await
                    .map_err(err_be)?
                    .ok_or_else(|| HandlerError::not_found(format!("block {}", n)))?;
                Ok(serde_json::to_vec_pretty(&block).map_err(err_be)?)
            }
            "addresses" if segs.len() == 4 => {
                let addr = parse_addr(&segs[2])?;
                let spec = client.spec();
                match segs[3].as_str() {
                    "balance" | "balance.raw" => {
                        let bal = client.balance(addr).await.map_err(err_be)?;
                        Ok(format!("{}\n", bal).into_bytes())
                    }
                    "balance.eth" => {
                        let bal = client.balance(addr).await.map_err(err_be)?;
                        Ok(format!(
                            "{} {}\n",
                            format_units(bal, spec.native_decimals),
                            spec.native_symbol
                        )
                        .into_bytes())
                    }
                    "nonce" => {
                        let n = client.nonce(addr).await.map_err(err_be)?;
                        Ok(format!("{}\n", n).into_bytes())
                    }
                    "code" => {
                        let code = client.code(addr).await.map_err(err_be)?;
                        Ok(format!("0x{}\n", hex::encode(&code)).into_bytes())
                    }
                    "is_contract" => {
                        let code = client.code(addr).await.map_err(err_be)?;
                        Ok(format!("{}\n", !code.is_empty()).into_bytes())
                    }
                    "txs" => {
                        let es = self.require_address_history_backend()?;
                        chains_history::read_txs(es, spec.chain_id, addr).await
                    }
                    "internal_txs" => {
                        let es = self.require_address_history_backend()?;
                        chains_history::read_internal_txs(es, spec.chain_id, addr).await
                    }
                    "erc20_txs" => {
                        let es = self.require_address_history_backend()?;
                        chains_history::read_erc20_txs(es, spec.chain_id, addr).await
                    }
                    "erc721_txs" => {
                        let es = self.require_address_history_backend()?;
                        chains_history::read_erc721_txs(es, spec.chain_id, addr).await
                    }
                    "ens" => {
                        let ens = self.ens_or_404()?;
                        match ens.reverse(addr).await {
                            Ok(name) => Ok(format!("{}\n", name).into_bytes()),
                            Err(EnsError::NotFound(_)) => Ok(b"unresolved\n".to_vec()),
                            Err(EnsError::InvalidName(s)) => Err(HandlerError::invalid(s)),
                            Err(e) => Err(HandlerError::backend(e.to_string())),
                        }
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            "addresses" if segs.len() == 6 && segs[3] == "tokens" => {
                let holder = parse_addr(&segs[2])?;
                let token = parse_addr(&segs[4])?;
                match segs[5].as_str() {
                    "balance" | "balance.raw" => {
                        let bal = client
                            .erc20_balance(token, holder)
                            .await
                            .map_err(err_be)?
                            .ok_or_else(|| HandlerError::backend("erc20 balanceOf reverted"))?;
                        Ok(format!("{}\n", bal).into_bytes())
                    }
                    "balance.formatted" => {
                        let bal = client
                            .erc20_balance(token, holder)
                            .await
                            .map_err(err_be)?
                            .ok_or_else(|| HandlerError::backend("erc20 balanceOf reverted"))?;
                        let dec = client
                            .erc20_decimals(token)
                            .await
                            .map_err(err_be)?
                            .unwrap_or(18);
                        let sym = client.erc20_symbol(token).await.map_err(err_be)?;
                        Ok(format!(
                            "{} {}\n",
                            format_units(bal, dec),
                            sym.unwrap_or_else(|| "?".into())
                        )
                        .into_bytes())
                    }
                    "symbol" => {
                        let sym = client.erc20_symbol(token).await.map_err(err_be)?;
                        Ok(format!("{}\n", sym.unwrap_or_default()).into_bytes())
                    }
                    "decimals" => {
                        let dec = client
                            .erc20_decimals(token)
                            .await
                            .map_err(err_be)?
                            .unwrap_or(18);
                        Ok(format!("{}\n", dec).into_bytes())
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            // /addresses/<a>/nfts/{erc721_txs,erc1155_txs,owned.json}
            "addresses" if segs.len() == 5 && segs[3] == "nfts" => {
                let holder = parse_addr(&segs[2])?;
                let chain_id = client.spec().chain_id;
                match segs[4].as_str() {
                    "erc721_txs" => {
                        let es = self.require_address_history_backend()?;
                        chains_nfts::read_erc721_txs(es, chain_id, holder).await
                    }
                    "erc1155_txs" => {
                        let es = self.require_address_history_backend()?;
                        chains_nfts::read_erc1155_txs(es, chain_id, holder).await
                    }
                    "owned.json" => {
                        let es = self.require_address_history_backend()?;
                        chains_nfts::read_owned(es, chain_id, holder).await
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            // /addresses/<a>/nfts/<contract>/<token_id>/<leaf>
            "addresses" if segs.len() == 7 && segs[3] == "nfts" => {
                let holder = parse_addr(&segs[2])?;
                let contract = parse_addr(&segs[4])?;
                let tid = chains_nfts::parse_token_id(&segs[5])?;
                match segs[6].as_str() {
                    "owner" => {
                        chains_nfts::read_per_token_owner(&self.nft_cache, &client, contract, tid)
                            .await
                    }
                    "uri" => {
                        chains_nfts::read_per_token_uri(&self.nft_cache, &client, contract, tid)
                            .await
                    }
                    "metadata.json" => {
                        chains_nfts::read_per_token_metadata(
                            &self.nft_cache,
                            &client,
                            contract,
                            tid,
                        )
                        .await
                    }
                    "balance" => {
                        chains_nfts::read_per_token_balance(
                            &self.nft_cache,
                            &client,
                            contract,
                            holder,
                            tid,
                        )
                        .await
                    }
                    "is_owner" => {
                        chains_nfts::read_per_token_is_owner(
                            &self.nft_cache,
                            &client,
                            contract,
                            holder,
                            tid,
                        )
                        .await
                    }
                    "approved" => {
                        chains_nfts::read_per_token_approved(
                            &self.nft_cache,
                            &client,
                            contract,
                            tid,
                        )
                        .await
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            "tx" if segs.len() == 4 => {
                use alloy::primitives::B256;
                let hash = segs[2]
                    .parse::<B256>()
                    .map_err(|e| HandlerError::invalid(format!("tx hash: {e}")))?;
                match segs[3].as_str() {
                    "full.json" => {
                        let tx = client
                            .tx_by_hash(hash)
                            .await
                            .map_err(err_be)?
                            .ok_or_else(|| HandlerError::not_found(format!("tx {hash:#x}")))?;
                        Ok(serde_json::to_vec_pretty(&tx).map_err(err_be)?)
                    }
                    "receipt.json" => {
                        let r =
                            client.receipt(hash).await.map_err(err_be)?.ok_or_else(|| {
                                HandlerError::not_found(format!("receipt {hash:#x}"))
                            })?;
                        Ok(serde_json::to_vec_pretty(&r).map_err(err_be)?)
                    }
                    "status" => {
                        let r =
                            client.receipt(hash).await.map_err(err_be)?.ok_or_else(|| {
                                HandlerError::not_found(format!("receipt {hash:#x}"))
                            })?;
                        let s = if r.status() { "success" } else { "reverted" };
                        Ok(format!("{}\n", s).into_bytes())
                    }
                    "block_number" => {
                        let r =
                            client.receipt(hash).await.map_err(err_be)?.ok_or_else(|| {
                                HandlerError::not_found(format!("receipt {hash:#x}"))
                            })?;
                        Ok(format!("{}\n", r.block_number.unwrap_or(0)).into_bytes())
                    }
                    "gas_used" => {
                        let r =
                            client.receipt(hash).await.map_err(err_be)?.ok_or_else(|| {
                                HandlerError::not_found(format!("receipt {hash:#x}"))
                            })?;
                        Ok(format!("{}\n", r.gas_used).into_bytes())
                    }
                    "logs.json" => {
                        let r =
                            client.receipt(hash).await.map_err(err_be)?.ok_or_else(|| {
                                HandlerError::not_found(format!("receipt {hash:#x}"))
                            })?;
                        Ok(serde_json::to_vec_pretty(&r.inner.logs()).map_err(err_be)?)
                    }
                    "error.json" => {
                        let r =
                            client.receipt(hash).await.map_err(err_be)?.ok_or_else(|| {
                                HandlerError::not_found(format!("receipt {hash:#x}"))
                            })?;
                        if r.status() {
                            // Successful tx → emit an explicit "no error"
                            // marker rather than a NotFound. Lets callers
                            // `cat` the file unconditionally without
                            // branching on tx success, and avoids the
                            // mount adapter logging a render-failure WARN
                            // for every getattr on a successful tx.
                            return Ok(b"null\n".to_vec());
                        }
                        if let Some(cached) = self
                            .revert_cache
                            .lock()
                            .get(&(chain.clone(), hash))
                            .cloned()
                        {
                            return serde_json::to_vec_pretty(&cached).map_err(err_be);
                        }
                        let returndata = client
                            .trace_revert(hash)
                            .await
                            .map_err(err_be)?
                            .unwrap_or_default();
                        let chain_id = client.chain_id().await.map_err(err_be)?;
                        let to = r.to;
                        let ctx = DecodeContext {
                            returndata,
                            to,
                            chain_id,
                        };
                        let decoded = self.revert_decoder.decode(&ctx).await;
                        self.revert_cache
                            .lock()
                            .insert((chain.clone(), hash), decoded.clone());
                        Ok(serde_json::to_vec_pretty(&decoded).map_err(err_be)?)
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            "contracts" if segs.len() >= 4 => self.read_contracts(path, segs, &client).await,
            "gas" if segs.get(2).map(|s| s.as_str()) == Some("current.json") => {
                let gp = client.gas_price().await.map_err(err_be)?;
                let body = serde_json::json!({ "gas_price_wei": gp });
                Ok(serde_json::to_vec_pretty(&body).unwrap())
            }
            "mempool" => match self.mempool_handlers.get(chain.as_str()) {
                Some(h) => h.read(path).await,
                None => Err(HandlerError::not_found(path.to_string_path())),
            },
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Ok(self
                .registry
                .list_names()
                .into_iter()
                .map(|n| Entry::dir(&n))
                .collect());
        }
        let chain = &segs[0];
        let _client = self.client(chain)?;
        match segs.len() {
            1 => {
                let mut entries = vec![
                    Entry::file("chain_id"),
                    Entry::dir("head"),
                    Entry::dir("blocks"),
                    Entry::dir("addresses"),
                    Entry::dir("tx"),
                    Entry::dir("gas"),
                    // `contracts/` always advertised — `nft/`, `storage/`
                    // and `proxy/` work over RPC without etherscan; the
                    // etherscan-only subtrees gate themselves.
                    Entry::dir("contracts"),
                ];
                if self.mempool_handlers.contains_key(chain.as_str()) {
                    entries.push(Entry::dir("mempool"));
                }
                Ok(entries)
            }
            2 if segs[1] == "head" => Ok(vec![
                Entry::file("number"),
                Entry::file("hash"),
                Entry::file("timestamp"),
                Entry::file("full.json"),
            ]),
            2 if segs[1] == "gas" => Ok(vec![Entry::file("current.json")]),
            3 if segs[1] == "addresses" => {
                // /chains/<chain>/addresses/<addr>
                let mut entries: Vec<Entry> =
                    ADDRESS_FILES_CORE.iter().map(|n| Entry::file(n)).collect();
                entries.push(Entry::dir("tokens"));
                entries.push(Entry::dir("nfts"));
                if self.address_history_ready() {
                    for n in ADDRESS_FILES_ETHERSCAN {
                        entries.push(Entry::file(n));
                    }
                }
                if self.ens.is_some() {
                    for n in ADDRESS_FILES_ENS {
                        entries.push(Entry::file(n));
                    }
                }
                Ok(entries)
            }
            5 if segs[1] == "addresses" && segs[3] == "tokens" => {
                // /chains/<chain>/addresses/<addr>/tokens/<token>
                Ok(TOKEN_FILES.iter().map(|n| Entry::file(n)).collect())
            }
            4 if segs[1] == "addresses" && segs[3] == "nfts" => {
                // /chains/<chain>/addresses/<addr>/nfts
                let mut entries: Vec<Entry> = Vec::new();
                if self.address_history_ready() {
                    for n in NFT_HOLDER_LEAVES {
                        entries.push(Entry::file(n));
                    }
                }
                Ok(entries)
            }
            6 if segs[1] == "addresses" && segs[3] == "nfts" => {
                // /chains/<chain>/addresses/<addr>/nfts/<contract>/<token_id>
                Ok(PER_TOKEN_LEAVES.iter().map(|n| Entry::file(n)).collect())
            }
            3 if segs[1] == "tx" => {
                // /chains/<chain>/tx/<hash>
                Ok(TX_FILES.iter().map(|n| Entry::file(n)).collect())
            }
            n if n >= 3 && segs[1] == "contracts" => {
                let client = self.client(chain)?;
                self.list_contracts(segs, &client).await
            }
            n if n >= 2 && segs[1] == "mempool" => {
                match self.mempool_handlers.get(chain.as_str()) {
                    Some(h) => h.list(path).await,
                    None => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
            _ => Ok(Vec::new()),
        }
    }

    async fn write_inner(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        if segs.len() >= 4 && segs[1] == "contracts" {
            // Validate the chain so the caller doesn't get a permission
            // error for a non-existent chain.
            let _ = self.client(&segs[0])?;
            return self.write_contracts(path, segs, data).await;
        }
        Err(HandlerError::PermissionDenied)
    }

    /// Per-path TTLs. The router consults this before dispatching the
    /// read; `None` means "always go to the handler". We keep TTLs
    /// short for live data (head, balance, nonce) and longer for
    /// immutable data (chain id, mined tx receipt, etherscan-backed
    /// txs) that doesn't change in practice.
    fn cache_ttl_inner(&self, path: &VfsPath) -> Option<Duration> {
        let segs = path.segments();
        if segs.is_empty() {
            return None;
        }
        match segs.get(1).map(|s| s.as_str()).unwrap_or("") {
            "chain_id" => Some(Duration::from_secs(86_400)),
            "head" => Some(Duration::from_secs(1)),
            "gas" => Some(Duration::from_secs(2)),
            // `tx/<hash>/...` — once mined these never change, so a
            // generous 60s TTL keeps us off the RPC during burst polling.
            "tx" => Some(Duration::from_secs(60)),
            // Address-scoped reads: balance/nonce/code change with the
            // chain head. Etherscan-backed history is rate-limited so
            // we cache it longer.
            "addresses" => match segs.get(3).map(|s| s.as_str()) {
                Some("balance" | "balance.eth" | "balance.raw" | "nonce") => {
                    Some(Duration::from_secs(5))
                }
                Some("code" | "is_contract") => Some(Duration::from_secs(86_400)),
                Some("txs" | "internal_txs" | "erc20_txs" | "erc721_txs") => {
                    Some(Duration::from_secs(30))
                }
                // Reverse ENS rarely changes; the EnsClient itself
                // also caches, but a layered TTL cuts repeat reads.
                Some("ens") => Some(Duration::from_secs(300)),
                Some("nfts") => match (
                    segs.get(4).map(|s| s.as_str()),
                    segs.get(6).map(|s| s.as_str()),
                ) {
                    // Holder-level history / holdings.
                    (Some("erc721_txs" | "erc1155_txs" | "owned.json"), _) => {
                        Some(Duration::from_secs(30))
                    }
                    // Per-token leaves.
                    (_, Some("uri" | "metadata.json")) => Some(Duration::from_secs(3600)),
                    (_, Some("owner" | "balance" | "is_owner" | "approved")) => {
                        Some(Duration::from_secs(5))
                    }
                    _ => None,
                },
                _ => None,
            },
            // Verified source / ABI: effectively immutable. Method
            // and event reads change with chain state so don't cache
            // them at the router level — the dynamic surfaces enforce
            // freshness themselves.
            "contracts" => match segs.get(3).map(|s| s.as_str()) {
                Some("source" | "abi") => Some(Duration::from_secs(7 * 86_400)),
                Some("nft") => match (
                    segs.get(4).map(|s| s.as_str()),
                    segs.get(5).map(|s| s.as_str()),
                ) {
                    // Static collection metadata.
                    (Some("kind" | "name" | "symbol"), _) => Some(Duration::from_secs(86_400)),
                    (Some("total_supply"), _) => Some(Duration::from_secs(30)),
                    (Some("owner_of"), Some(_)) => Some(Duration::from_secs(5)),
                    (Some("token_uri"), Some(_)) => Some(Duration::from_secs(3600)),
                    _ => None,
                },
                _ => None,
            },
            // Block by number is permanent past finality; we don't know
            // finality here so use a long but bounded TTL.
            "blocks" => Some(Duration::from_secs(300)),
            _ => None,
        }
    }
}

// silence unused `checksum_address` lint while still keeping it exported
const _: fn(&alloy::primitives::Address) -> String = checksum_address;

impl ChainsHandler {
    /// Routing helper for `contracts/<addr>/...` reads. Splits the
    /// existing source/abi paths from the new dynamic surfaces. The
    /// caller has already validated the chain.
    async fn read_contracts(
        &self,
        path: &VfsPath,
        segs: &[String],
        client: &ChainClient,
    ) -> Result<Vec<u8>, HandlerError> {
        let addr = parse_addr(&segs[2])?;
        let chain_id = client.spec().chain_id;
        let kind = segs[3].as_str();
        match kind {
            "source" if segs.len() == 4 => {
                let es = self.require_contract_metadata_backend()?;
                chains_history::read_contract_source(es, chain_id, addr).await
            }
            "abi" if segs.len() == 4 => {
                let es = self.require_contract_metadata_backend()?;
                // Proxy-aware: when the contract is an EIP-1967 proxy
                // we surface the implementation's ABI so the rendered
                // file matches what `methods/` enumerates. Falls back
                // to the proxy's own ABI whenever the slot is zero or
                // the implementation has no verified ABI upstream.
                let target = chains_contracts::resolve_eip1967_implementation(client, addr).await;
                chains_contracts::read_contract_abi_for(es, chain_id, addr, target).await
            }
            "methods" if segs.len() == 5 => {
                let es = self.require_contract_metadata_backend()?;
                let leaf = segs[4].as_str();
                let (name, suffix) = Self::split_method_leaf(leaf)
                    .ok_or_else(|| HandlerError::not_found(path.to_string_path()))?;
                let abi = chains_contracts::fetch_abi_proxy_aware(
                    &self.abi_cache,
                    es,
                    client,
                    chain_id,
                    addr,
                )
                .await?;
                // Sniff `selector` from the staged body so overloads
                // disambiguate before we encode args.
                let body_str = std::str::from_utf8(&self.pending.peek(&path.to_string_path()))
                    .ok()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let selector_hint = serde_json::from_str::<serde_json::Value>(&body_str)
                    .ok()
                    .and_then(|v| {
                        v.get("selector")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                    });
                let func = chains_contracts::pick_function(&abi, name, selector_hint.as_deref())?;
                match suffix {
                    "sig" => Ok(chains_contracts::render_method_sig(func)),
                    "read" => {
                        let body: chains_contracts::MethodCallBody =
                            self.read_pending_body(path)?;
                        chains_contracts::run_method_read(client, addr, func, &body).await
                    }
                    "tx" => {
                        let body: chains_contracts::MethodCallBody =
                            self.read_pending_body(path)?;
                        chains_contracts::run_method_tx(addr, func, &body)
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            "events" if segs.len() == 6 => {
                let es = self.require_contract_metadata_backend()?;
                let abi = chains_contracts::fetch_abi_proxy_aware(
                    &self.abi_cache,
                    es,
                    client,
                    chain_id,
                    addr,
                )
                .await?;
                let event_name = segs[4].as_str();
                let event = chains_contracts::pick_event(&abi, event_name)?;
                match segs[5].as_str() {
                    "recent" => chains_contracts::run_event_recent(client, addr, event).await,
                    "query" => {
                        let body: chains_contracts::EventQueryBody =
                            self.read_pending_body(path)?;
                        chains_contracts::run_event_query(client, addr, event, &body).await
                    }
                    "live" => {
                        chains_contracts::run_event_live(
                            &self.live_state,
                            client,
                            chain_id,
                            addr,
                            event_name,
                            event,
                        )
                        .await
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            "storage" if segs.len() == 5 => {
                chains_contracts::read_storage_slot(client, addr, &segs[4]).await
            }
            "proxy" if segs.len() == 5 => {
                let leaf = segs[4].as_str();
                let (slot, fb) = chains_contracts::proxy_slot(leaf)
                    .ok_or_else(|| HandlerError::not_found(path.to_string_path()))?;
                chains_contracts::read_proxy_slot(client, addr, slot, fb).await
            }
            "nft" => match segs.len() {
                5 => match segs[4].as_str() {
                    "kind" => {
                        chains_nfts::read_collection_kind(&self.nft_cache, client, addr).await
                    }
                    "name" => chains_nfts::read_collection_name(client, addr).await,
                    "symbol" => chains_nfts::read_collection_symbol(client, addr).await,
                    "total_supply" => {
                        chains_nfts::read_collection_total_supply(&self.nft_cache, client, addr)
                            .await
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                },
                6 => match segs[4].as_str() {
                    "owner_of" => {
                        let tid = chains_nfts::parse_token_id(&segs[5])?;
                        chains_nfts::read_collection_owner_of(&self.nft_cache, client, addr, tid)
                            .await
                    }
                    "token_uri" => {
                        let tid = chains_nfts::parse_token_id(&segs[5])?;
                        chains_nfts::read_collection_token_uri(&self.nft_cache, client, addr, tid)
                            .await
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                },
                7 if segs[4] == "is_approved_for_all" => {
                    let owner = parse_addr(&segs[5])?;
                    let operator = parse_addr(&segs[6])?;
                    chains_nfts::read_collection_is_approved_for_all(client, addr, owner, operator)
                        .await
                }
                _ => Err(HandlerError::NotAFile(path.to_string_path())),
            },
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    /// Pull the parsed body posted to `path` (or the empty default).
    /// Errors if the bytes don't deserialise as `B`.
    fn read_pending_body<B: serde::de::DeserializeOwned + Default>(
        &self,
        path: &VfsPath,
    ) -> Result<B, HandlerError> {
        let key = path.to_string_path();
        let bytes = self.pending.take_or_default(&key);
        let s = std::str::from_utf8(&bytes).map_err(|e| HandlerError::invalid(e.to_string()))?;
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(B::default());
        }
        serde_json::from_str(trimmed).map_err(|e| HandlerError::invalid(format!("body json: {e}")))
    }

    /// Routing helper for writes under `contracts/<addr>/...`.
    async fn write_contracts(
        &self,
        path: &VfsPath,
        segs: &[String],
        data: &[u8],
    ) -> Result<(), HandlerError> {
        // Validate addr early.
        let _ = parse_addr(&segs[2])?;
        let key = path.to_string_path();
        // Sniff that the body is well-formed JSON so writes fail loudly
        // rather than silently storing garbage.
        let trimmed = std::str::from_utf8(data)
            .map_err(|e| HandlerError::invalid(e.to_string()))?
            .trim();
        if !trimmed.is_empty() {
            let _: serde_json::Value = serde_json::from_str(trimmed)
                .map_err(|e| HandlerError::invalid(format!("body json: {e}")))?;
        }
        match segs.get(3).map(|s| s.as_str()) {
            Some("methods") if segs.len() == 5 => {
                let leaf = segs[4].as_str();
                let suffix = Self::split_method_leaf(leaf)
                    .map(|(_, s)| s)
                    .ok_or(HandlerError::PermissionDenied)?;
                if suffix == "sig" {
                    return Err(HandlerError::PermissionDenied);
                }
                self.pending.store(key, data.to_vec());
                Ok(())
            }
            Some("events") if segs.len() == 6 && segs[5] == "query" => {
                self.pending.store(key, data.to_vec());
                Ok(())
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    /// Listing helper for `contracts/<addr>/...` directories.
    ///
    /// `methods/` and `events/` enumerate against the resolved ABI —
    /// EIP-1967 proxies surface the implementation contract's surface
    /// here, not the proxy's own. A failed ABI fetch maps onto the
    /// usual `HandlerError`, so the user sees why their listing is
    /// empty rather than an unexplained zero-row directory.
    async fn list_contracts(
        &self,
        segs: &[String],
        client: &ChainClient,
    ) -> Result<Vec<Entry>, HandlerError> {
        match segs.len() {
            3 => {
                // contracts/<addr> always lists storage/proxy/nft (RPC-only);
                // source/abi/methods/events only show when contract_metadata
                // is etherscan-backed and credentials are wired.
                let mut out: Vec<Entry> = Vec::new();
                if self.contract_metadata_ready() {
                    for n in CONTRACT_FILES_ETHERSCAN {
                        out.push(Entry::file(n));
                    }
                    out.push(Entry::dir("methods"));
                    out.push(Entry::dir("events"));
                }
                out.push(Entry::dir("storage"));
                out.push(Entry::dir("proxy"));
                out.push(Entry::dir("nft"));
                Ok(out)
            }
            4 => match segs[3].as_str() {
                "methods" => {
                    let es = self.require_contract_metadata_backend()?;
                    let addr = parse_addr(&segs[2])?;
                    let chain_id = client.spec().chain_id;
                    // Resolve the (possibly proxy-resolved) ABI and
                    // enumerate one .sig/.read/.tx triple per function.
                    let abi = chains_contracts::fetch_abi_proxy_aware(
                        &self.abi_cache,
                        es,
                        client,
                        chain_id,
                        addr,
                    )
                    .await?;
                    Ok(chains_contracts::enumerate_method_leaves(&abi))
                }
                "events" => {
                    let es = self.require_contract_metadata_backend()?;
                    let addr = parse_addr(&segs[2])?;
                    let chain_id = client.spec().chain_id;
                    let abi = chains_contracts::fetch_abi_proxy_aware(
                        &self.abi_cache,
                        es,
                        client,
                        chain_id,
                        addr,
                    )
                    .await?;
                    Ok(chains_contracts::enumerate_event_dirs(&abi))
                }
                "storage" => Ok(Vec::new()),
                "proxy" => Ok(PROXY_LEAVES.iter().map(|n| Entry::file(n)).collect()),
                "nft" => {
                    let mut out: Vec<Entry> = NFT_COLLECTION_LEAVES
                        .iter()
                        .map(|n| Entry::file(n))
                        .collect();
                    for d in NFT_COLLECTION_DIRS {
                        out.push(Entry::dir(d));
                    }
                    Ok(out)
                }
                _ => Ok(Vec::new()),
            },
            5 if segs[3] == "events" => Ok(EVENT_LEAVES
                .iter()
                .map(|n| {
                    if *n == "query" {
                        Entry::writable_file(n)
                    } else {
                        Entry::file(n)
                    }
                })
                .collect()),
            _ => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_proto::ChainSpec;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use url::Url;

    /// Spawn a one-shot HTTP server that returns `body` for the next
    /// connection. Mirrors the prices handler test pattern.
    async fn spawn_canned(body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        addr
    }

    fn anvil_registry() -> ChainRegistry {
        let spec = ChainSpec::anvil_default();
        let client = ChainClient::new(spec).unwrap();
        let reg = ChainRegistry::default();
        reg.add(client);
        reg
    }

    fn etherscan_to(addr: SocketAddr) -> Arc<EtherscanClient> {
        let url = Url::parse(&format!("http://{addr}/api")).unwrap();
        Arc::new(EtherscanClient::with_base_url("test_key".into(), url))
    }

    #[tokio::test]
    async fn txs_path_returns_etherscan_payload() {
        // Realistic txlist response (single record).
        let body = r#"{"status":"1","message":"OK","result":[{
            "blockNumber":"19000000",
            "timeStamp":"1700000000",
            "hash":"0xabc",
            "nonce":"1",
            "blockHash":"0xbb",
            "transactionIndex":"0",
            "from":"0x0000000000000000000000000000000000000001",
            "to":"0x0000000000000000000000000000000000000002",
            "value":"1000",
            "gas":"21000",
            "gasPrice":"1",
            "isError":"0",
            "txreceipt_status":"1",
            "input":"0x",
            "contractAddress":"",
            "cumulativeGasUsed":"21000",
            "gasUsed":"21000",
            "confirmations":"5",
            "methodId":"",
            "functionName":""
        }]}"#;
        let addr = spawn_canned(body).await;
        let h = ChainsHandler::new(anvil_registry()).with_etherscan(Some(etherscan_to(addr)));

        let chain_name = h.registry.list_names()[0].clone();
        let p = VfsPath::parse(&format!(
            "/{chain}/addresses/0x0000000000000000000000000000000000000001/txs",
            chain = chain_name
        ))
        .unwrap();

        let bytes = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v.is_array());
        assert_eq!(v[0]["hash"], "0xabc");
        assert_eq!(v[0]["from"], "0x0000000000000000000000000000000000000001");
        // Trailing newline for shell ergonomics.
        assert_eq!(*bytes.last().unwrap(), b'\n');
    }

    #[tokio::test]
    async fn contract_abi_path_returns_decoded_array() {
        let body = r#"{"status":"1","message":"OK","result":"[{\"type\":\"function\",\"name\":\"foo\"}]"}"#;
        let addr = spawn_canned(body).await;
        let h = ChainsHandler::new(anvil_registry()).with_etherscan(Some(etherscan_to(addr)));

        let chain_name = h.registry.list_names()[0].clone();
        let p = VfsPath::parse(&format!(
            "/{chain}/contracts/0x0000000000000000000000000000000000000001/abi",
            chain = chain_name
        ))
        .unwrap();

        let bytes = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v.is_array());
        assert_eq!(v[0]["name"], "foo");
    }

    #[tokio::test]
    async fn history_paths_404_when_etherscan_absent() {
        let h = ChainsHandler::new(anvil_registry());
        let chain_name = h.registry.list_names()[0].clone();

        let p = VfsPath::parse(&format!(
            "/{chain}/addresses/0x0000000000000000000000000000000000000001/txs",
            chain = chain_name
        ))
        .unwrap();
        match h.lookup(&p).await {
            Err(HandlerError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }

        let p = VfsPath::parse(&format!(
            "/{chain}/contracts/0x0000000000000000000000000000000000000001/source",
            chain = chain_name
        ))
        .unwrap();
        match h.lookup(&p).await {
            Err(HandlerError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn core_paths_unaffected_without_etherscan() {
        // Sanity: existing behaviour must work when etherscan is None.
        let h = ChainsHandler::new(anvil_registry());
        let chain_name = h.registry.list_names()[0].clone();
        let p = VfsPath::parse(&format!("/{chain_name}/chain_id")).unwrap();
        let entry = h.lookup(&p).await.unwrap();
        assert_eq!(entry.name, "chain_id");
    }

    /// When `backends.address_history = "rpc"`, the etherscan-backed
    /// history paths must report a clear, distinct error rather than
    /// the generic "etherscan not configured" message — and they must
    /// not appear in directory listings.
    #[tokio::test]
    async fn rpc_backend_for_address_history_gates_paths_with_clear_error() {
        let backends = BackendsConfig {
            address_history: Backend::Rpc,
            ..Default::default()
        };
        let h = ChainsHandler::new(anvil_registry()).with_backends(backends);
        let chain_name = h.registry.list_names()[0].clone();

        let p = VfsPath::parse(&format!(
            "/{chain_name}/addresses/0x0000000000000000000000000000000000000001/txs"
        ))
        .unwrap();
        match h.lookup(&p).await {
            Err(HandlerError::NotFound(msg)) => {
                assert!(
                    msg.contains("address_history") && msg.contains("rpc"),
                    "expected backend-aware error, got: {msg}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }

        let dir = VfsPath::parse(&format!(
            "/{chain_name}/addresses/0x0000000000000000000000000000000000000001"
        ))
        .unwrap();
        let entries = h.list(&dir).await.unwrap();
        assert!(
            !entries.iter().any(|e| e.name == "txs"),
            "rpc-only address_history must not advertise etherscan-backed entries: {entries:?}"
        );
    }

    /// Indexer is reserved for a future implementation; selecting it
    /// must produce a "not yet implemented" error.
    #[tokio::test]
    async fn indexer_backend_returns_not_yet_implemented() {
        let backends = BackendsConfig {
            contract_metadata: Backend::Indexer,
            ..Default::default()
        };
        let h = ChainsHandler::new(anvil_registry()).with_backends(backends);
        let chain_name = h.registry.list_names()[0].clone();
        let p = VfsPath::parse(&format!(
            "/{chain_name}/contracts/0x0000000000000000000000000000000000000001/abi"
        ))
        .unwrap();
        match h.lookup(&p).await {
            Err(HandlerError::NotFound(msg)) => {
                assert!(
                    msg.contains("indexer") && msg.contains("not yet implemented"),
                    "expected indexer-not-implemented error, got: {msg}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// `addresses/<addr>/ens` is hidden from listings and 404s on
    /// lookup when no ENS-capable chain has been wired in.
    #[tokio::test]
    async fn ens_path_404s_when_unwired() {
        let h = ChainsHandler::new(anvil_registry());
        let chain_name = h.registry.list_names()[0].clone();

        let dir = VfsPath::parse(&format!(
            "/{chain_name}/addresses/0x0000000000000000000000000000000000000001"
        ))
        .unwrap();
        let entries = h.list(&dir).await.unwrap();
        assert!(
            !entries.iter().any(|e| e.name == "ens"),
            "should not advertise ens without a client: {entries:?}"
        );

        let p = VfsPath::parse(&format!(
            "/{chain_name}/addresses/0x0000000000000000000000000000000000000001/ens"
        ))
        .unwrap();
        match h.lookup(&p).await {
            Err(HandlerError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    // ---- contract surface tests ---------------------------------------
    //
    // The contract surface tests need a JSON-RPC mock that classifies
    // requests by `method` and replies appropriately, plus a single-shot
    // canned Etherscan server for the ABI fetch. We wire both, point a
    // synthetic `ChainSpec` at the RPC mock, and exercise each path
    // through the public `Handler` trait so we cover routing + dispatch.

    /// Spawn an HTTP server that handles many JSON-RPC requests on the
    /// same listener, dispatching by method name. Each entry in `routes`
    /// is `(method, response_result_value)`. `eth_chainId` is auto-handled
    /// when present in `chain_id` so callers don't have to repeat it.
    ///
    /// Returns when the listener accepts at least one connection; the
    /// task lives until all routes have been hit at least once or the
    /// caller's handle is dropped.
    fn spawn_rpc(
        chain_id: u64,
        responses: std::collections::HashMap<String, serde_json::Value>,
    ) -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut buf = vec![0u8; 65536];
                let mut total = 0usize;
                let mut header_end = None;
                let mut content_length = 0usize;
                // Read until we have headers + content_length bytes of body.
                loop {
                    let n = s.read(&mut buf[total..]).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    total += n;
                    if header_end.is_none()
                        && let Some(idx) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n")
                    {
                        header_end = Some(idx + 4);
                        // crude content-length parse
                        let head = std::str::from_utf8(&buf[..idx]).unwrap_or("");
                        for line in head.split("\r\n") {
                            if let Some(v) = line
                                .strip_prefix("Content-Length:")
                                .or_else(|| line.strip_prefix("content-length:"))
                            {
                                content_length = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    if let Some(he) = header_end
                        && total >= he + content_length
                    {
                        break;
                    }
                    if total == buf.len() {
                        break;
                    }
                }
                let body_start = header_end.unwrap_or(total);
                let body = &buf[body_start..total.min(body_start + content_length)];
                let req: serde_json::Value =
                    serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
                let id = req.get("id").cloned().unwrap_or(serde_json::json!(1));
                let method = req
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                let result = if method == "eth_chainId" {
                    serde_json::Value::String(format!("0x{:x}", chain_id))
                } else {
                    responses
                        .get(&method)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null)
                };
                let resp_body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        addr
    }

    /// Build a registry pointed at the supplied RPC mock, with a
    /// custom chain_id so the handler's `chain_id`-aware caches and
    /// path coding don't collide with the default 31337 anvil spec.
    fn registry_for_rpc(rpc: SocketAddr, chain_id: u64) -> ChainRegistry {
        let spec = ChainSpec {
            name: "test".into(),
            chain_id,
            rpc_urls: vec![format!("http://{rpc}")],
            rpc_endpoints: Vec::new(),
            allow_broadcast: false,
            etherscan_api_url: None,
            display_name: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            legacy_tx: false,
        };
        let client = ChainClient::new(spec).unwrap();
        let reg = ChainRegistry::default();
        reg.add(client);
        reg
    }

    /// Minimal ERC-20 ABI: `balanceOf`, `transfer`, `Transfer` event.
    /// Picked to exercise both function/event paths and overload branches.
    const ERC20_ABI: &str = r#"[
        {"type":"function","name":"balanceOf","stateMutability":"view",
         "inputs":[{"name":"owner","type":"address"}],
         "outputs":[{"name":"","type":"uint256"}]},
        {"type":"function","name":"transfer","stateMutability":"nonpayable",
         "inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],
         "outputs":[{"name":"","type":"bool"}]},
        {"type":"event","name":"Transfer","anonymous":false,
         "inputs":[{"name":"from","type":"address","indexed":true},
                   {"name":"to","type":"address","indexed":true},
                   {"name":"value","type":"uint256","indexed":false}]}
    ]"#;

    /// Spawn a canned Etherscan server returning `ERC20_ABI` for every
    /// request. The single-shot pattern is fine because the handler's
    /// AbiCache memoises the result for 60s and we never hit it twice
    /// in any one test.
    async fn spawn_erc20_etherscan() -> SocketAddr {
        let body = format!(
            r#"{{"status":"1","message":"OK","result":{}}}"#,
            serde_json::Value::String(ERC20_ABI.to_string())
        );
        // Leak the body so the canned server can hold a 'static slice.
        let body_static: &'static str = Box::leak(body.into_boxed_str());
        spawn_canned(body_static).await
    }

    /// Demo address — vitalik.eth, used purely as a stable EIP-55 sample.
    const SAMPLE_ADDR: &str = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

    #[tokio::test]
    async fn methods_sig_returns_signature_and_selector() {
        let es = spawn_erc20_etherscan().await;
        let rpc = spawn_rpc(31338, std::collections::HashMap::new());
        let h =
            ChainsHandler::new(registry_for_rpc(rpc, 31338)).with_etherscan(Some(etherscan_to(es)));
        let p = VfsPath::parse(&format!(
            "/test/contracts/{SAMPLE_ADDR}/methods/balanceOf.sig"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // alloy's signature_with_outputs is canonical Solidity-style.
        assert!(s.contains("balanceOf(address)"), "sig output: {s}");
        // ERC-20 balanceOf selector is 0x70a08231.
        assert!(s.contains("0x70a08231"), "missing selector: {s}");
    }

    #[tokio::test]
    async fn methods_read_decodes_uint256_result() {
        // Encode 1234 as a 32-byte big-endian uint256 — what `eth_call`
        // would return for `balanceOf(...) -> uint256`.
        let mut raw = [0u8; 32];
        raw[31] = 0xd2;
        raw[30] = 0x04;
        let hex_raw = format!("0x{}", hex::encode(raw));
        let mut routes = std::collections::HashMap::new();
        routes.insert("eth_call".to_string(), serde_json::Value::String(hex_raw));
        let es = spawn_erc20_etherscan().await;
        let rpc = spawn_rpc(31338, routes);
        let h =
            ChainsHandler::new(registry_for_rpc(rpc, 31338)).with_etherscan(Some(etherscan_to(es)));
        let p = VfsPath::parse(&format!(
            "/test/contracts/{SAMPLE_ADDR}/methods/balanceOf.read"
        ))
        .unwrap();
        // Stage the call args: balanceOf(SAMPLE_ADDR).
        let body = serde_json::json!({"args": [SAMPLE_ADDR]}).to_string();
        h.write(&p, body.as_bytes()).await.unwrap();
        let bytes = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["selector"], "0x70a08231");
        // Decoded value is the JSON array form; uint256 1234 serialises
        // as a string ("1234") via sol_to_json.
        assert_eq!(v["decoded"], serde_json::json!(["1234"]));
    }

    #[tokio::test]
    async fn methods_tx_returns_4byte_selector_and_calldata() {
        let es = spawn_erc20_etherscan().await;
        let rpc = spawn_rpc(31338, std::collections::HashMap::new());
        let h =
            ChainsHandler::new(registry_for_rpc(rpc, 31338)).with_etherscan(Some(etherscan_to(es)));
        let p = VfsPath::parse(&format!(
            "/test/contracts/{SAMPLE_ADDR}/methods/transfer.tx"
        ))
        .unwrap();
        let body = serde_json::json!({"args": [SAMPLE_ADDR, "1000"]}).to_string();
        h.write(&p, body.as_bytes()).await.unwrap();
        let bytes = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // ERC-20 transfer selector is 0xa9059cbb.
        assert_eq!(v["selector"], "0xa9059cbb");
        let calldata = v["calldata"].as_str().unwrap();
        assert!(calldata.starts_with("0xa9059cbb"));
        // 4-byte selector + 32-byte address + 32-byte amount = 68 bytes
        // = 136 hex chars + "0x".
        assert_eq!(calldata.len(), 2 + 4 * 2 + 32 * 2 + 32 * 2);
        // The "to" comes back checksummed.
        assert_eq!(v["to"], SAMPLE_ADDR);
    }

    #[tokio::test]
    async fn events_recent_decodes_transfer_log() {
        // Fake a single Transfer log on block 100 in the head=200 window.
        let from_addr = "0x000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045";
        let to_addr = "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let value_hex = format!("0x{}", "00".repeat(31) + "2a"); // 42
        // Transfer(address,address,uint256) topic0:
        let topic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
        let log = serde_json::json!({
            "address": SAMPLE_ADDR,
            "topics": [topic0, from_addr, to_addr],
            "data": value_hex,
            "blockNumber": "0x64",
            "transactionHash": format!("0x{}", "22".repeat(32)),
            "transactionIndex": "0x0",
            "blockHash": format!("0x{}", "11".repeat(32)),
            "logIndex": "0x0",
            "removed": false,
        });
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "eth_blockNumber".to_string(),
            serde_json::Value::String("0xc8".to_string()), // 200
        );
        routes.insert("eth_getLogs".to_string(), serde_json::json!([log]));
        let es = spawn_erc20_etherscan().await;
        let rpc = spawn_rpc(31338, routes);
        let h =
            ChainsHandler::new(registry_for_rpc(rpc, 31338)).with_etherscan(Some(etherscan_to(es)));
        let p = VfsPath::parse(&format!(
            "/test/contracts/{SAMPLE_ADDR}/events/Transfer/recent"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v.is_array(), "expected array, got {v}");
        assert_eq!(v[0]["block_number"], 100);
        // Indexed `from` decodes back to the original sample address.
        let decoded_from = v[0]["data"]["from"].as_str().unwrap().to_lowercase();
        assert_eq!(decoded_from, "0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
        // value (non-indexed) is in the body data — uint256 42 → "42".
        assert_eq!(v[0]["data"]["value"], "42");
    }

    #[tokio::test]
    async fn storage_slot_returns_eth_get_storage_at_value() {
        // 32 bytes ending in 0x07.
        let val_hex = format!("0x{}07", "00".repeat(31));
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "eth_getStorageAt".to_string(),
            serde_json::Value::String(val_hex.clone()),
        );
        // Etherscan isn't called here — storage is RPC-only — but we
        // still need the handler to build (no-op).
        let rpc = spawn_rpc(31338, routes);
        let h = ChainsHandler::new(registry_for_rpc(rpc, 31338));
        let p = VfsPath::parse(&format!("/test/contracts/{SAMPLE_ADDR}/storage/0x0")).unwrap();
        let bytes = h.read(&p).await.unwrap();
        let s = std::str::from_utf8(&bytes).unwrap().trim();
        assert_eq!(s, val_hex);
    }

    #[tokio::test]
    async fn proxy_implementation_returns_checksummed_address() {
        // Pretend the EIP-1967 implementation slot holds vitalik's
        // address right-aligned. The handler must trim the leading
        // 12 zero bytes and EIP-55-checksum the result.
        let mut padded = [0u8; 32];
        let want: alloy::primitives::Address = SAMPLE_ADDR.parse().unwrap();
        padded[12..].copy_from_slice(want.as_slice());
        let val_hex = format!("0x{}", hex::encode(padded));
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "eth_getStorageAt".to_string(),
            serde_json::Value::String(val_hex),
        );
        let rpc = spawn_rpc(31338, routes);
        let h = ChainsHandler::new(registry_for_rpc(rpc, 31338));
        let p = VfsPath::parse(&format!(
            "/test/contracts/{SAMPLE_ADDR}/proxy/implementation"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        let s = std::str::from_utf8(&bytes).unwrap().trim();
        assert_eq!(s, SAMPLE_ADDR);
    }

    #[tokio::test]
    async fn proxy_implementation_zero_slot_returns_not_a_proxy() {
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "eth_getStorageAt".to_string(),
            serde_json::Value::String(format!("0x{}", "00".repeat(32))),
        );
        let rpc = spawn_rpc(31338, routes);
        let h = ChainsHandler::new(registry_for_rpc(rpc, 31338));
        let p = VfsPath::parse(&format!(
            "/test/contracts/{SAMPLE_ADDR}/proxy/implementation"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(s, "not a proxy\n");
    }

    /// When two `foo` overloads exist on the ABI, calling `methods/foo.tx`
    /// without a `selector` hint must fail with a clear "ambiguous"
    /// error; passing the right selector resolves to the matching ABI.
    #[tokio::test]
    async fn method_overload_disambiguates_by_selector() {
        // ABI with `foo(uint256)` and `foo(address)` overloads.
        let body = format!(
            r#"{{"status":"1","message":"OK","result":{}}}"#,
            serde_json::Value::String(
                r#"[
                    {"type":"function","name":"foo","stateMutability":"view",
                     "inputs":[{"name":"a","type":"uint256"}],"outputs":[]},
                    {"type":"function","name":"foo","stateMutability":"view",
                     "inputs":[{"name":"a","type":"address"}],"outputs":[]}
                ]"#
                .to_string()
            )
        );
        let body_static: &'static str = Box::leak(body.into_boxed_str());
        let es = spawn_canned(body_static).await;
        let rpc = spawn_rpc(31338, std::collections::HashMap::new());
        let h =
            ChainsHandler::new(registry_for_rpc(rpc, 31338)).with_etherscan(Some(etherscan_to(es)));
        let p = VfsPath::parse(&format!("/test/contracts/{SAMPLE_ADDR}/methods/foo.tx")).unwrap();

        // Without a selector hint: the read must surface an ambiguity
        // error rather than encoding against an arbitrary overload.
        h.write(&p, b"{\"args\":[\"0\"]}").await.unwrap();
        match h.read(&p).await {
            Err(HandlerError::Invalid(msg)) => {
                assert!(msg.contains("overload"), "unexpected msg: {msg}");
            }
            other => panic!("expected Invalid(overload), got {other:?}"),
        }

        // With the selector for `foo(address)` (= 0x9d2cf9d3), the read
        // succeeds and the response carries the matching selector. We
        // need a second etherscan + rpc mock since both have been
        // consumed, but the handler's AbiCache should have memoised the
        // ABI from the previous attempt — so only the rpc mock matters
        // here, and we don't need rpc since `foo` has no outputs.
        // Selector for foo(address):
        let sel_addr = {
            use alloy::primitives::keccak256;
            let h = keccak256(b"foo(address)");
            format!("0x{}", hex::encode(&h.0[..4]))
        };
        let body = serde_json::json!({
            "args": [SAMPLE_ADDR],
            "selector": sel_addr,
        })
        .to_string();
        h.write(&p, body.as_bytes()).await.unwrap();
        let bytes = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["selector"], sel_addr);
    }

    /// `methods/...` and `events/...` require `contract_metadata`
    /// = `etherscan`; configuring it as `rpc` must hide and 404 those
    /// paths just like the address_history surface.
    #[tokio::test]
    async fn methods_and_events_404_when_contract_metadata_is_rpc() {
        let backends = BackendsConfig {
            contract_metadata: Backend::Rpc,
            ..Default::default()
        };
        let h = ChainsHandler::new(anvil_registry()).with_backends(backends);
        let chain_name = h.registry.list_names()[0].clone();

        let p = VfsPath::parse(&format!(
            "/{chain_name}/contracts/{SAMPLE_ADDR}/methods/balanceOf.sig"
        ))
        .unwrap();
        match h.lookup(&p).await {
            Err(HandlerError::NotFound(msg)) => {
                assert!(msg.contains("contract_metadata"), "got: {msg}");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }

        let p = VfsPath::parse(&format!(
            "/{chain_name}/contracts/{SAMPLE_ADDR}/events/Transfer/recent"
        ))
        .unwrap();
        match h.lookup(&p).await {
            Err(HandlerError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }

        // storage and proxy must remain reachable: they're RPC-only and
        // unaffected by the contract_metadata backend choice.
        let p = VfsPath::parse(&format!(
            "/{chain_name}/contracts/{SAMPLE_ADDR}/storage/0x0"
        ))
        .unwrap();
        h.lookup(&p).await.unwrap();
        let p = VfsPath::parse(&format!(
            "/{chain_name}/contracts/{SAMPLE_ADDR}/proxy/implementation"
        ))
        .unwrap();
        h.lookup(&p).await.unwrap();
    }

    // ---- NFT surface tests --------------------------------------------
    //
    // The ChainClient kind-detect path issues two `supportsInterface`
    // calls back-to-back, and the test mock answers each method with a
    // single canned response — so we seed `nft_cache` via the test seam
    // for tests that exercise reads beyond detection. Detection itself
    // is covered by ChainClient unit tests in bloom-chain.

    /// 32-byte big-endian encoding of a uint256 / bool / right-aligned
    /// address, wrapped as a JSON-RPC `result` string.
    fn enc_uint256_value(v: alloy::primitives::U256) -> serde_json::Value {
        serde_json::Value::String(format!("0x{}", hex::encode(v.to_be_bytes::<32>())))
    }

    fn enc_bool_value(b: bool) -> serde_json::Value {
        let mut w = [0u8; 32];
        w[31] = if b { 1 } else { 0 };
        serde_json::Value::String(format!("0x{}", hex::encode(w)))
    }

    /// Encode a Solidity `address` as a 32-byte right-aligned word.
    fn enc_address_value(addr: alloy::primitives::Address) -> serde_json::Value {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(addr.as_slice());
        serde_json::Value::String(format!("0x{}", hex::encode(w)))
    }

    /// Encode a dynamic-string return (offset 0x20, length, bytes pad).
    fn enc_string_value(s: &str) -> serde_json::Value {
        let mut buf = Vec::new();
        // offset = 0x20
        let mut head = [0u8; 32];
        head[31] = 0x20;
        buf.extend_from_slice(&head);
        // length
        let mut len = [0u8; 32];
        len[24..32].copy_from_slice(&(s.len() as u64).to_be_bytes());
        buf.extend_from_slice(&len);
        // bytes, padded
        let mut payload = s.as_bytes().to_vec();
        let pad = (32 - (s.len() % 32)) % 32;
        payload.extend(std::iter::repeat_n(0u8, pad));
        buf.extend_from_slice(&payload);
        serde_json::Value::String(format!("0x{}", hex::encode(buf)))
    }

    /// 0x address used for sample NFT contracts in tests.
    const NFT_CONTRACT: &str = "0xCCCCCCCCcCCCCCcCcccccccCcCCCCCCcCcccccCC";

    /// Sample holder address. Tests that compare against the handler's
    /// EIP-55-checksum echo derive the canonical form from `checksum_address`
    /// rather than relying on this literal.
    const HOLDER_ADDR: &str = "0xAAAaaAaaAAAAaAAAaaAAAaAAAaAaaAAaaaaAAaaA";

    /// Build a ChainsHandler with a wiremock RPC and (optionally) the
    /// kind cache pre-seeded.
    async fn nft_handler_with_seed(
        responses: std::collections::HashMap<String, serde_json::Value>,
        seed: Option<bloom_chain::NftKind>,
    ) -> ChainsHandler {
        let rpc = spawn_rpc(31338, responses);
        let h = ChainsHandler::new(registry_for_rpc(rpc, 31338));
        if let Some(kind) = seed {
            let addr: alloy::primitives::Address = NFT_CONTRACT.parse().unwrap();
            h.nft_cache.seed(31338, addr, kind);
        }
        h
    }

    #[tokio::test]
    async fn nft_lookup_per_token_leaf_is_a_file() {
        let h = nft_handler_with_seed(std::collections::HashMap::new(), None).await;
        let p = VfsPath::parse(&format!(
            "/test/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/42/owner"
        ))
        .unwrap();
        let entry = h.lookup(&p).await.unwrap();
        assert_eq!(entry.name, "owner");
        assert_eq!(entry.kind, crate::handler::EntryKind::File);
    }

    #[tokio::test]
    async fn nft_lookup_collection_dir_kind_file() {
        // /contracts/<a>/nft/kind is a file regardless of etherscan wiring.
        let h = nft_handler_with_seed(std::collections::HashMap::new(), None).await;
        let p = VfsPath::parse(&format!("/test/contracts/{NFT_CONTRACT}/nft/kind")).unwrap();
        let entry = h.lookup(&p).await.unwrap();
        assert_eq!(entry.name, "kind");
        assert_eq!(entry.kind, crate::handler::EntryKind::File);
    }

    #[tokio::test]
    async fn nft_lookup_owner_of_with_token_id_is_file() {
        let h = nft_handler_with_seed(std::collections::HashMap::new(), None).await;
        let p = VfsPath::parse(&format!("/test/contracts/{NFT_CONTRACT}/nft/owner_of/7")).unwrap();
        let entry = h.lookup(&p).await.unwrap();
        assert_eq!(entry.name, "7");
        assert_eq!(entry.kind, crate::handler::EntryKind::File);
    }

    #[tokio::test]
    async fn nft_lookup_invalid_token_id_is_invalid_error() {
        let h = nft_handler_with_seed(std::collections::HashMap::new(), None).await;
        let p = VfsPath::parse(&format!(
            "/test/contracts/{NFT_CONTRACT}/nft/owner_of/not-a-number"
        ))
        .unwrap();
        match h.lookup(&p).await {
            Err(HandlerError::Invalid(s)) => assert!(s.contains("token id"), "msg: {s}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn nft_lookup_unknown_collection_leaf_is_not_found() {
        let h = nft_handler_with_seed(std::collections::HashMap::new(), None).await;
        let p = VfsPath::parse(&format!("/test/contracts/{NFT_CONTRACT}/nft/bogus")).unwrap();
        match h.lookup(&p).await {
            Err(HandlerError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn nft_list_per_token_dir_advertises_six_leaves() {
        let h = nft_handler_with_seed(std::collections::HashMap::new(), None).await;
        let dir = VfsPath::parse(&format!(
            "/test/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/42"
        ))
        .unwrap();
        let entries = h.list(&dir).await.unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        for leaf in [
            "owner",
            "uri",
            "metadata.json",
            "balance",
            "is_owner",
            "approved",
        ] {
            assert!(names.contains(&leaf), "missing {leaf} in {names:?}");
        }
    }

    #[tokio::test]
    async fn nft_list_holder_dir_hidden_without_etherscan() {
        // /addresses/<a>/nfts only advertises history leaves when
        // address_history is etherscan-backed and configured.
        let h = nft_handler_with_seed(std::collections::HashMap::new(), None).await;
        let dir = VfsPath::parse(&format!("/test/addresses/{HOLDER_ADDR}/nfts")).unwrap();
        let entries = h.list(&dir).await.unwrap();
        assert!(
            entries.is_empty(),
            "expected empty listing without etherscan, got {entries:?}"
        );
    }

    #[tokio::test]
    async fn nft_list_collection_dir_lists_leaves_and_dirs() {
        let h = nft_handler_with_seed(std::collections::HashMap::new(), None).await;
        let dir = VfsPath::parse(&format!("/test/contracts/{NFT_CONTRACT}/nft")).unwrap();
        let entries = h.list(&dir).await.unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        for leaf in ["kind", "name", "symbol", "total_supply"] {
            assert!(names.contains(&leaf), "missing {leaf}");
        }
        for d in ["owner_of", "token_uri", "is_approved_for_all"] {
            assert!(names.contains(&d), "missing {d}");
        }
    }

    #[tokio::test]
    async fn nft_collection_kind_returns_erc721_when_seeded() {
        let h = nft_handler_with_seed(
            std::collections::HashMap::new(),
            Some(bloom_chain::NftKind::Erc721),
        )
        .await;
        let p = VfsPath::parse(&format!("/test/contracts/{NFT_CONTRACT}/nft/kind")).unwrap();
        let bytes = h.read(&p).await.unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "erc721\n");
    }

    #[tokio::test]
    async fn nft_collection_kind_returns_erc1155_when_seeded() {
        let h = nft_handler_with_seed(
            std::collections::HashMap::new(),
            Some(bloom_chain::NftKind::Erc1155),
        )
        .await;
        let p = VfsPath::parse(&format!("/test/contracts/{NFT_CONTRACT}/nft/kind")).unwrap();
        let bytes = h.read(&p).await.unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "erc1155\n");
    }

    #[tokio::test]
    async fn nft_collection_name_returns_string() {
        let mut routes = std::collections::HashMap::new();
        routes.insert("eth_call".into(), enc_string_value("Crypto Sample"));
        let h = nft_handler_with_seed(routes, None).await;
        let p = VfsPath::parse(&format!("/test/contracts/{NFT_CONTRACT}/nft/name")).unwrap();
        let bytes = h.read(&p).await.unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "Crypto Sample\n");
    }

    #[tokio::test]
    async fn nft_owner_of_erc721_returns_checksum_address() {
        // Returned owner: HOLDER_ADDR (right-aligned in 32 bytes).
        let owner_addr: alloy::primitives::Address = HOLDER_ADDR.parse().unwrap();
        let mut routes = std::collections::HashMap::new();
        routes.insert("eth_call".into(), enc_address_value(owner_addr));
        let h = nft_handler_with_seed(routes, Some(bloom_chain::NftKind::Erc721)).await;
        let p = VfsPath::parse(&format!("/test/contracts/{NFT_CONTRACT}/nft/owner_of/42")).unwrap();
        let bytes = h.read(&p).await.unwrap();
        let s = std::str::from_utf8(&bytes).unwrap().trim();
        // The handler emits an EIP-55 checksum for the owner — derive the
        // canonical form rather than trusting the literal-case input.
        let want = checksum_address(&owner_addr);
        assert_eq!(s, want);
    }

    #[tokio::test]
    async fn nft_owner_erc1155_returns_not_applicable() {
        // ERC-1155 has no per-token ownerOf; the handler returns a
        // sentinel rather than erroring so directory walks stay clean.
        let h = nft_handler_with_seed(
            std::collections::HashMap::new(),
            Some(bloom_chain::NftKind::Erc1155),
        )
        .await;
        let p = VfsPath::parse(&format!(
            "/test/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/42/owner"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "not applicable\n");
    }

    #[tokio::test]
    async fn nft_approved_erc1155_returns_not_applicable() {
        let h = nft_handler_with_seed(
            std::collections::HashMap::new(),
            Some(bloom_chain::NftKind::Erc1155),
        )
        .await;
        let p = VfsPath::parse(&format!(
            "/test/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/42/approved"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "not applicable\n");
    }

    #[tokio::test]
    async fn nft_uri_erc1155_substitutes_id_placeholder() {
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "eth_call".into(),
            enc_string_value("ipfs://QmFoo/{id}.json"),
        );
        let h = nft_handler_with_seed(routes, Some(bloom_chain::NftKind::Erc1155)).await;
        // Token id 1 → 64-char hex, all zeros except trailing 01.
        let p = VfsPath::parse(&format!(
            "/test/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/1/uri"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        let want_id = "0000000000000000000000000000000000000000000000000000000000000001";
        assert_eq!(s, format!("ipfs://QmFoo/{want_id}.json\n"));
    }

    #[tokio::test]
    async fn nft_metadata_json_resolves_data_uri_without_network() {
        // Returned tokenURI is a `data:` URI carrying inline JSON; the
        // handler must decode it without making any HTTP request.
        let data_uri = r#"data:application/json,{"name":"item-1"}"#;
        let mut routes = std::collections::HashMap::new();
        routes.insert("eth_call".into(), enc_string_value(data_uri));
        let h = nft_handler_with_seed(routes, Some(bloom_chain::NftKind::Erc721)).await;
        let p = VfsPath::parse(&format!(
            "/test/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/1/metadata.json"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["name"], "item-1");
        // Pretty-printed with trailing newline for shell ergonomics.
        assert_eq!(*bytes.last().unwrap(), b'\n');
    }

    #[tokio::test]
    async fn nft_balance_erc1155_decodes_uint256() {
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "eth_call".into(),
            enc_uint256_value(alloy::primitives::U256::from(5u64)),
        );
        let h = nft_handler_with_seed(routes, Some(bloom_chain::NftKind::Erc1155)).await;
        let p = VfsPath::parse(&format!(
            "/test/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/9/balance"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "5\n");
    }

    #[tokio::test]
    async fn nft_is_owner_erc721_true_when_owner_matches_holder() {
        let owner_addr: alloy::primitives::Address = HOLDER_ADDR.parse().unwrap();
        let mut routes = std::collections::HashMap::new();
        routes.insert("eth_call".into(), enc_address_value(owner_addr));
        let h = nft_handler_with_seed(routes, Some(bloom_chain::NftKind::Erc721)).await;
        let p = VfsPath::parse(&format!(
            "/test/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/42/is_owner"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "true\n");
    }

    #[tokio::test]
    async fn nft_is_approved_for_all_returns_bool() {
        let mut routes = std::collections::HashMap::new();
        routes.insert("eth_call".into(), enc_bool_value(true));
        // No kind seed needed: is_approved_for_all bypasses detection.
        let h = nft_handler_with_seed(routes, None).await;
        let owner = HOLDER_ADDR;
        let operator = "0xBbBbbBbBbbbBBbBbbbbbBbBbbbbBbBbBbbbbbBBb";
        let p = VfsPath::parse(&format!(
            "/test/contracts/{NFT_CONTRACT}/nft/is_approved_for_all/{owner}/{operator}"
        ))
        .unwrap();
        let bytes = h.read(&p).await.unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "true\n");
    }

    #[tokio::test]
    async fn nft_per_token_read_on_non_nft_contract_is_invalid() {
        // Kind cache reports Unknown (e.g. the address is an EOA or a
        // plain ERC-20). The handler must return a clean "not an NFT
        // contract" error rather than crashing or surfacing a low-level
        // decode error.
        let h = nft_handler_with_seed(
            std::collections::HashMap::new(),
            Some(bloom_chain::NftKind::Unknown),
        )
        .await;
        let p = VfsPath::parse(&format!(
            "/test/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/42/owner"
        ))
        .unwrap();
        match h.read(&p).await {
            Err(HandlerError::Invalid(s)) => {
                assert!(s.contains("not an NFT contract"), "got: {s}")
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn nft_total_supply_revert_returns_unknown_marker() {
        // Reverting `totalSupply()` (e.g. an ERC-721 without enumeration)
        // is a legitimate state, not an error: the handler emits
        // "unknown\n" so the file is still readable.
        let h = nft_handler_with_seed(
            std::collections::HashMap::new(),
            Some(bloom_chain::NftKind::Erc721),
        )
        .await;
        let p =
            VfsPath::parse(&format!("/test/contracts/{NFT_CONTRACT}/nft/total_supply")).unwrap();
        let bytes = h.read(&p).await.unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "unknown\n");
    }

    #[tokio::test]
    async fn nft_cache_ttls_match_spec() {
        let h = ChainsHandler::new(anvil_registry());
        let chain = h.registry.list_names()[0].clone();

        // Holder history files: 30s.
        let p =
            VfsPath::parse(&format!("/{chain}/addresses/{HOLDER_ADDR}/nfts/erc721_txs")).unwrap();
        assert_eq!(h.cache_ttl(&p), Some(Duration::from_secs(30)));

        // Per-token uri / metadata: 1h.
        let p = VfsPath::parse(&format!(
            "/{chain}/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/1/uri"
        ))
        .unwrap();
        assert_eq!(h.cache_ttl(&p), Some(Duration::from_secs(3600)));
        let p = VfsPath::parse(&format!(
            "/{chain}/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/1/metadata.json"
        ))
        .unwrap();
        assert_eq!(h.cache_ttl(&p), Some(Duration::from_secs(3600)));

        // Per-token volatile reads: 5s.
        let p = VfsPath::parse(&format!(
            "/{chain}/addresses/{HOLDER_ADDR}/nfts/{NFT_CONTRACT}/1/owner"
        ))
        .unwrap();
        assert_eq!(h.cache_ttl(&p), Some(Duration::from_secs(5)));

        // Collection static metadata: 1d.
        let p = VfsPath::parse(&format!("/{chain}/contracts/{NFT_CONTRACT}/nft/kind")).unwrap();
        assert_eq!(h.cache_ttl(&p), Some(Duration::from_secs(86_400)));

        // total_supply: 30s.
        let p = VfsPath::parse(&format!(
            "/{chain}/contracts/{NFT_CONTRACT}/nft/total_supply"
        ))
        .unwrap();
        assert_eq!(h.cache_ttl(&p), Some(Duration::from_secs(30)));

        // owner_of/<id>: 5s; token_uri/<id>: 1h.
        let p =
            VfsPath::parse(&format!("/{chain}/contracts/{NFT_CONTRACT}/nft/owner_of/1")).unwrap();
        assert_eq!(h.cache_ttl(&p), Some(Duration::from_secs(5)));
        let p = VfsPath::parse(&format!(
            "/{chain}/contracts/{NFT_CONTRACT}/nft/token_uri/1"
        ))
        .unwrap();
        assert_eq!(h.cache_ttl(&p), Some(Duration::from_secs(3600)));
    }

    // ---- methods/ enumeration + EIP-1967 proxy resolution ----------------
    //
    // These tests exercise the bug repro from operator testing:
    //   * `methods/` was empty even when `abi` resolved successfully (5a),
    //   * proxies returned the proxy admin ABI rather than the
    //     implementation ABI (5b — USDC mainnet).
    //
    // We mock `ContractMetadataSource` directly so the test can return
    // *different* ABIs for the proxy vs the implementation address —
    // something the single-shot HTTP server doesn't support.

    /// Mock metadata source that maps `addr -> abi JSON value`. Anything
    /// outside the map yields a `NotFound` data-source error so we can
    /// assert that the right address is being asked for.
    #[derive(Default)]
    struct StaticAbiSource {
        map: std::collections::HashMap<alloy::primitives::Address, serde_json::Value>,
    }

    #[async_trait]
    impl bloom_etherscan::ContractMetadataSource for StaticAbiSource {
        async fn get_source_code(
            &self,
            _chain_id: u64,
            _addr: alloy::primitives::Address,
        ) -> Result<bloom_etherscan::ContractSource, bloom_etherscan::DataSourceError> {
            Err(bloom_etherscan::DataSourceError::Unsupported(
                "test mock has no source".into(),
            ))
        }

        async fn get_abi(
            &self,
            _chain_id: u64,
            addr: alloy::primitives::Address,
        ) -> Result<serde_json::Value, bloom_etherscan::DataSourceError> {
            self.map.get(&addr).cloned().ok_or_else(|| {
                bloom_etherscan::DataSourceError::NotFound(format!("no abi for {addr}"))
            })
        }
    }

    /// Minimal "proxy admin" ABI: a single `admin()` function plus an
    /// `Upgraded(address)` event. Distinct from the ERC-20 surface so
    /// the test can tell which side is being enumerated.
    const PROXY_ADMIN_ABI: &str = r#"[
        {"type":"function","name":"admin","stateMutability":"view",
         "inputs":[],
         "outputs":[{"name":"","type":"address"}]},
        {"type":"event","name":"Upgraded","anonymous":false,
         "inputs":[{"name":"implementation","type":"address","indexed":true}]}
    ]"#;

    /// Right-pad an address into a 32-byte storage slot value (EIP-1967
    /// stores the impl right-aligned).
    fn slot_value_for_addr(addr: alloy::primitives::Address) -> serde_json::Value {
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(addr.as_slice());
        serde_json::Value::String(format!("0x{}", hex::encode(padded)))
    }

    /// 5a regression: `list` of `methods/` enumerates one .sig/.read/.tx
    /// triple per ABI function, sorted deterministically. Previously
    /// returned an empty Vec, which is what caused USDC's `methods/` to
    /// look empty in the live mount.
    #[tokio::test]
    async fn methods_dir_lists_one_triple_per_function() {
        // RPC: zero slot -> not a proxy -> ABI fetched directly from proxy.
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "eth_getStorageAt".to_string(),
            serde_json::Value::String(format!("0x{}", "00".repeat(32))),
        );
        let rpc = spawn_rpc(31338, routes);
        let proxy: alloy::primitives::Address = SAMPLE_ADDR.parse().unwrap();
        let mut map = std::collections::HashMap::new();
        map.insert(proxy, serde_json::from_str(ERC20_ABI).unwrap());
        let src: Arc<dyn bloom_etherscan::ContractMetadataSource> =
            Arc::new(StaticAbiSource { map });
        let h = ChainsHandler::new(registry_for_rpc(rpc, 31338)).with_contract_metadata(Some(src));

        let p = VfsPath::parse(&format!("/test/contracts/{SAMPLE_ADDR}/methods")).unwrap();
        let entries = h.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        // ERC20_ABI has two functions (balanceOf, transfer). Names are
        // sorted alphabetically; for each name we emit .sig then
        // .read/.tx in the constant push order.
        assert_eq!(
            names,
            vec![
                "balanceOf.sig",
                "balanceOf.read",
                "balanceOf.tx",
                "transfer.sig",
                "transfer.read",
                "transfer.tx",
            ]
        );
        // sig is read-only; read/tx are writable.
        for e in &entries {
            if e.name.ends_with(".sig") {
                assert_eq!(e.mode, 0o444, "{} should be read-only", e.name);
            } else {
                assert_eq!(e.mode, 0o644, "{} should be writable", e.name);
            }
        }
    }

    /// 5b regression: when the contract is an EIP-1967 proxy, `methods/`
    /// must enumerate the **implementation's** functions, not the proxy
    /// admin's.
    #[tokio::test]
    async fn methods_dir_resolves_eip1967_implementation() {
        // The implementation lives at this distinct address.
        let impl_addr: alloy::primitives::Address = "0x000000000000000000000000000000000000beef"
            .parse()
            .unwrap();
        let proxy: alloy::primitives::Address = SAMPLE_ADDR.parse().unwrap();

        // RPC: storage slot returns the implementation address (right-
        // aligned, like the chain actually returns it for EIP-1967).
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "eth_getStorageAt".to_string(),
            slot_value_for_addr(impl_addr),
        );
        let rpc = spawn_rpc(31338, routes);

        // Metadata source returns proxy-admin ABI for the proxy, ERC-20
        // ABI for the implementation. If the handler enumerates against
        // the proxy address it'll see admin() not balanceOf().
        let mut map = std::collections::HashMap::new();
        map.insert(proxy, serde_json::from_str(PROXY_ADMIN_ABI).unwrap());
        map.insert(impl_addr, serde_json::from_str(ERC20_ABI).unwrap());
        let src: Arc<dyn bloom_etherscan::ContractMetadataSource> =
            Arc::new(StaticAbiSource { map });
        let h = ChainsHandler::new(registry_for_rpc(rpc, 31338)).with_contract_metadata(Some(src));

        let p = VfsPath::parse(&format!("/test/contracts/{SAMPLE_ADDR}/methods")).unwrap();
        let entries = h.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        // ERC-20 surface: balanceOf, transfer. NOT the proxy's admin().
        assert!(
            names.contains(&"balanceOf.sig"),
            "expected impl ABI, got proxy ABI: {names:?}"
        );
        assert!(
            names.contains(&"transfer.read"),
            "expected impl ABI, got proxy ABI: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.starts_with("admin.")),
            "proxy admin function leaked through: {names:?}"
        );
    }

    /// 5b regression continued: `events/` likewise resolves the proxy
    /// before enumeration. ERC-20's `Transfer` should show up; the
    /// proxy's `Upgraded` should not.
    #[tokio::test]
    async fn events_dir_resolves_eip1967_implementation() {
        let impl_addr: alloy::primitives::Address = "0x000000000000000000000000000000000000beef"
            .parse()
            .unwrap();
        let proxy: alloy::primitives::Address = SAMPLE_ADDR.parse().unwrap();
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "eth_getStorageAt".to_string(),
            slot_value_for_addr(impl_addr),
        );
        let rpc = spawn_rpc(31338, routes);

        let mut map = std::collections::HashMap::new();
        map.insert(proxy, serde_json::from_str(PROXY_ADMIN_ABI).unwrap());
        map.insert(impl_addr, serde_json::from_str(ERC20_ABI).unwrap());
        let src: Arc<dyn bloom_etherscan::ContractMetadataSource> =
            Arc::new(StaticAbiSource { map });
        let h = ChainsHandler::new(registry_for_rpc(rpc, 31338)).with_contract_metadata(Some(src));

        let p = VfsPath::parse(&format!("/test/contracts/{SAMPLE_ADDR}/events")).unwrap();
        let entries = h.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["Transfer"]);
    }

    /// 5b: the user-facing `<addr>/abi` payload should also follow the
    /// proxy. We assert on substring rather than exact JSON shape so
    /// the test stays robust against pretty-printer changes.
    #[tokio::test]
    async fn abi_path_follows_eip1967_proxy_to_impl() {
        let impl_addr: alloy::primitives::Address = "0x000000000000000000000000000000000000beef"
            .parse()
            .unwrap();
        let proxy: alloy::primitives::Address = SAMPLE_ADDR.parse().unwrap();
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "eth_getStorageAt".to_string(),
            slot_value_for_addr(impl_addr),
        );
        let rpc = spawn_rpc(31338, routes);

        let mut map = std::collections::HashMap::new();
        map.insert(proxy, serde_json::from_str(PROXY_ADMIN_ABI).unwrap());
        map.insert(impl_addr, serde_json::from_str(ERC20_ABI).unwrap());
        let src: Arc<dyn bloom_etherscan::ContractMetadataSource> =
            Arc::new(StaticAbiSource { map });
        let h = ChainsHandler::new(registry_for_rpc(rpc, 31338)).with_contract_metadata(Some(src));

        let p = VfsPath::parse(&format!("/test/contracts/{SAMPLE_ADDR}/abi")).unwrap();
        let bytes = h.read(&p).await.unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("balanceOf"), "abi missing balanceOf: {s}");
        assert!(s.contains("transfer"), "abi missing transfer: {s}");
        // The proxy admin's `admin()` function name must not bleed in.
        assert!(
            !s.contains("\"admin\""),
            "proxy admin abi leaked into output: {s}"
        );
    }

    /// 5a/5b: when the storage slot is zero we should NOT chase a phantom
    /// implementation; the proxy's own ABI is enumerated.
    #[tokio::test]
    async fn methods_dir_uses_proxy_abi_when_slot_is_zero() {
        let proxy: alloy::primitives::Address = SAMPLE_ADDR.parse().unwrap();
        let mut routes = std::collections::HashMap::new();
        // Zero slot → not a proxy.
        routes.insert(
            "eth_getStorageAt".to_string(),
            serde_json::Value::String(format!("0x{}", "00".repeat(32))),
        );
        let rpc = spawn_rpc(31338, routes);
        let mut map = std::collections::HashMap::new();
        map.insert(proxy, serde_json::from_str(PROXY_ADMIN_ABI).unwrap());
        let src: Arc<dyn bloom_etherscan::ContractMetadataSource> =
            Arc::new(StaticAbiSource { map });
        let h = ChainsHandler::new(registry_for_rpc(rpc, 31338)).with_contract_metadata(Some(src));

        let p = VfsPath::parse(&format!("/test/contracts/{SAMPLE_ADDR}/methods")).unwrap();
        let entries = h.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        // Only `admin` from PROXY_ADMIN_ABI.
        assert_eq!(names, vec!["admin.sig", "admin.read", "admin.tx"]);
    }

    // ---- mempool delegation tests ----------------------------------------

    fn make_mempool_handler() -> Arc<crate::handlers::chains_mempool::MempoolHandler> {
        Arc::new(crate::handlers::chains_mempool::MempoolHandler::new(
            "anvil",
            "mock",
            bloom_mempool::PendingTxIndex::new(8),
        ))
    }

    #[tokio::test]
    async fn mempool_lookup_delegates_when_handler_present() {
        let mut handlers = std::collections::BTreeMap::new();
        handlers.insert("anvil".to_string(), make_mempool_handler());
        let h = ChainsHandler::new(anvil_registry()).with_mempool_handlers(handlers);
        let p = VfsPath::parse("anvil/mempool/status.json").unwrap();
        let entry = h.lookup(&p).await.unwrap();
        assert_eq!(entry.name, "status.json");
    }

    #[tokio::test]
    async fn mempool_lookup_returns_not_found_without_handler() {
        let h = ChainsHandler::new(anvil_registry());
        let p = VfsPath::parse("anvil/mempool/status.json").unwrap();
        let err = h.lookup(&p).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)));
    }

    #[tokio::test]
    async fn chain_root_listing_includes_mempool_when_handler_present() {
        let mut handlers = std::collections::BTreeMap::new();
        handlers.insert("anvil".to_string(), make_mempool_handler());
        let h_with = ChainsHandler::new(anvil_registry()).with_mempool_handlers(handlers);
        let p = VfsPath::parse("anvil").unwrap();
        let entries = h_with.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"mempool"),
            "expected mempool in listing, got: {names:?}"
        );

        let h_without = ChainsHandler::new(anvil_registry());
        let entries_without = h_without.list(&p).await.unwrap();
        let names_without: Vec<&str> = entries_without.iter().map(|e| e.name.as_str()).collect();
        assert!(
            !names_without.contains(&"mempool"),
            "mempool should not appear without handler"
        );
    }
}
