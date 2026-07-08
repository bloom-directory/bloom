//! Etherscan v2 multichain client.
//!
//! Talks to the unified Etherscan v2 endpoint
//! (`https://api.etherscan.io/v2/api`). Every request carries a `chainid`
//! query parameter so a single API key works across all supported chains.
//!
//! Quick tour:
//!
//! - [`EtherscanClient::new`] builds a client from an API key.
//! - Free-tier callers should keep the default 5 req/s limiter; heavier
//!   plans can raise it via [`EtherscanClient::with_rate_limit`].
//! - All methods return typed structs and a uniform [`EtherscanError`].
//! - [`cache::EtherscanCache`] is an optional read-through file cache.
//!
//! Quirks the client smooths over:
//!
//! - Etherscan returns ABIs as JSON-encoded strings inside a JSON envelope;
//!   we decode the inner string into `serde_json::Value` for callers.
//! - "Multi-file" verified sources are returned with the `SourceCode`
//!   field wrapped in an extra `{...}` (i.e. `{{...}}`); we strip the
//!   outer wrap and parse the inner standard-json object.
//! - Errors come back wrapped in `{status: "0", message: "...", result: ...}`
//!   bodies *with HTTP 200*; we promote them to typed errors.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::{debug, trace};
use url::Url;

use alloy::json_abi::JsonAbi;
use bloom_proto::prelude::{Address, B256, U256};

pub mod cache;
pub mod traits;
pub use cache::EtherscanCache;
pub use traits::{AddressHistorySource, ContractMetadataSource, DataSourceError};

/// EIP-1967 implementation slot (`keccak256("eip1967.proxy.implementation") - 1`).
pub const EIP1967_IMPL_SLOT: B256 = B256::new([
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d,
    0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc,
]);

/// Storage-read abstraction. Lets [`EtherscanClient::json_abi_for`] follow
/// EIP-1967 proxies without depending on `bloom-evm` directly.
#[async_trait::async_trait]
pub trait StorageReader: Send + Sync {
    /// Read 32 bytes from `addr` at `slot` (latest block).
    async fn read_slot(&self, addr: Address, slot: B256) -> Result<B256, EtherscanError>;
}

/// Default base URL for Etherscan v2 multichain API.
pub const DEFAULT_BASE_URL: &str = "https://api.etherscan.io/v2/api";

/// Default rate limit (free tier: 5 req/sec).
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 5;

/// All errors surfaced by this crate.
#[derive(Debug, Error)]
pub enum EtherscanError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("etherscan api error (status={status}): {message}")]
    Api { status: String, message: String },
    #[error("rate limited by etherscan")]
    RateLimit,
    #[error("etherscan returned a 'disabled' / not-supported response")]
    Disabled,
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("url: {0}")]
    Url(#[from] url::ParseError),
}

/// Sort direction for paginated endpoints.
#[derive(Debug, Clone, Copy)]
pub enum Sort {
    Asc,
    Desc,
}

impl Sort {
    fn as_str(&self) -> &'static str {
        match self {
            Sort::Asc => "asc",
            Sort::Desc => "desc",
        }
    }
}

/// Closeness option for `getblocknobytime`.
#[derive(Debug, Clone, Copy)]
pub enum Closest {
    Before,
    After,
}

impl Closest {
    fn as_str(&self) -> &'static str {
        match self {
            Closest::Before => "before",
            Closest::After => "after",
        }
    }
}

/// One verified contract record returned by `getsourcecode`.
///
/// Fields are kept as raw strings to mirror the upstream payload, which
/// uses string-encoded booleans / integers throughout.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ContractSource {
    /// Verified Solidity source. Either a single source string or, for
    /// multi-file projects, the standard-json object as JSON. The raw
    /// payload may have an outer `{...}` wrapper that we strip.
    #[serde(default)]
    pub source_code: String,
    #[serde(default, rename = "ABI")]
    pub abi: String,
    #[serde(default)]
    pub contract_name: String,
    #[serde(default)]
    pub compiler_version: String,
    #[serde(default)]
    pub optimization_used: String,
    #[serde(default)]
    pub runs: String,
    #[serde(default)]
    pub constructor_arguments: String,
    #[serde(default, rename = "EVMVersion")]
    pub evm_version: String,
    #[serde(default)]
    pub library: String,
    #[serde(default)]
    pub license_type: String,
    /// `"1"` if this is a proxy contract.
    #[serde(default)]
    pub proxy: String,
    /// Implementation address when proxied.
    #[serde(default)]
    pub implementation: String,
    #[serde(default)]
    pub swarm_source: String,
}

impl ContractSource {
    /// True when the upstream marked this contract as a proxy.
    pub fn is_proxy(&self) -> bool {
        self.proxy == "1"
    }

    /// Parsed ABI (decoded from the inner JSON-string field).
    pub fn parsed_abi(&self) -> Result<serde_json::Value, EtherscanError> {
        if self.abi.is_empty() || self.abi == "Contract source code not verified" {
            return Err(EtherscanError::InvalidResponse(
                "abi missing / not verified".to_string(),
            ));
        }
        Ok(serde_json::from_str(&self.abi)?)
    }

    /// Parsed source code blob. For multi-file projects the upstream wraps
    /// a standard-json object in extra `{...}`; we strip them.
    ///
    /// Returns `Ok(None)` for a plain (single-file) source string.
    pub fn parsed_multi_file_sources(&self) -> Result<Option<serde_json::Value>, EtherscanError> {
        let s = self.source_code.trim();
        if s.starts_with("{{") && s.ends_with("}}") {
            // strip exactly one outer brace pair
            let inner = &s[1..s.len() - 1];
            return Ok(Some(serde_json::from_str(inner)?));
        }
        if s.starts_with('{') && s.ends_with('}') {
            // some chains return the standard-json without the double wrap
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(s)
                && v.get("sources").is_some()
            {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }
}

/// Account-level transaction record (`txlist`, `txlistinternal`).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TxRecord {
    #[serde(default, rename = "blockNumber")]
    pub block_number: String,
    #[serde(default, rename = "timeStamp")]
    pub time_stamp: String,
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default, rename = "blockHash")]
    pub block_hash: String,
    #[serde(default, rename = "transactionIndex")]
    pub transaction_index: String,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub gas: String,
    #[serde(default, rename = "gasPrice")]
    pub gas_price: String,
    #[serde(default, rename = "isError")]
    pub is_error: String,
    #[serde(default, rename = "txreceipt_status")]
    pub txreceipt_status: String,
    #[serde(default)]
    pub input: String,
    #[serde(default, rename = "contractAddress")]
    pub contract_address: String,
    #[serde(default, rename = "cumulativeGasUsed")]
    pub cumulative_gas_used: String,
    #[serde(default, rename = "gasUsed")]
    pub gas_used: String,
    #[serde(default)]
    pub confirmations: String,
    #[serde(default, rename = "methodId")]
    pub method_id: String,
    #[serde(default, rename = "functionName")]
    pub function_name: String,
    /// Internal-tx specific fields (kept as `String` to follow upstream).
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default, rename = "traceId")]
    pub trace_id: String,
    #[serde(default, rename = "errCode")]
    pub err_code: String,
}

/// ERC-20 / 721 / 1155 transfer record (`tokentx` / `tokennfttx` /
/// `token1155tx`). NFT-only fields (`tokenID`, `tokenValue`) are
/// captured opportunistically; they are empty strings on ERC-20 rows.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TokenTransfer {
    #[serde(default, rename = "blockNumber")]
    pub block_number: String,
    #[serde(default, rename = "timeStamp")]
    pub time_stamp: String,
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default, rename = "blockHash")]
    pub block_hash: String,
    #[serde(default)]
    pub from: String,
    #[serde(default, rename = "contractAddress")]
    pub contract_address: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub value: String,
    #[serde(default, rename = "tokenName")]
    pub token_name: String,
    #[serde(default, rename = "tokenSymbol")]
    pub token_symbol: String,
    #[serde(default, rename = "tokenDecimal")]
    pub token_decimal: String,
    /// ERC-721 / ERC-1155 token id (decimal string). Empty for ERC-20.
    #[serde(default, rename = "tokenID")]
    pub token_id: String,
    /// ERC-1155 amount (decimal string). Empty for ERC-20 / ERC-721.
    #[serde(default, rename = "tokenValue")]
    pub token_value: String,
    #[serde(default, rename = "transactionIndex")]
    pub transaction_index: String,
    #[serde(default)]
    pub gas: String,
    #[serde(default, rename = "gasPrice")]
    pub gas_price: String,
    #[serde(default, rename = "gasUsed")]
    pub gas_used: String,
    #[serde(default, rename = "cumulativeGasUsed")]
    pub cumulative_gas_used: String,
    #[serde(default)]
    pub input: String,
    #[serde(default)]
    pub confirmations: String,
}

/// Log record (`getLogs`).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LogRecord {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub data: String,
    #[serde(default, rename = "blockNumber")]
    pub block_number: String,
    #[serde(default, rename = "blockHash")]
    pub block_hash: String,
    #[serde(default, rename = "timeStamp")]
    pub time_stamp: String,
    #[serde(default, rename = "gasPrice")]
    pub gas_price: String,
    #[serde(default, rename = "gasUsed")]
    pub gas_used: String,
    #[serde(default, rename = "logIndex")]
    pub log_index: String,
    #[serde(default, rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(default, rename = "transactionIndex")]
    pub transaction_index: String,
}

/// Configuration for [`EtherscanClient`].
#[derive(Debug, Clone)]
pub struct EtherscanConfig {
    pub api_key: String,
    pub base_url: Url,
    /// Maximum requests per second. Defaults to 5 (free tier).
    pub rate_limit_per_sec: u32,
    pub request_timeout: Duration,
}

impl EtherscanConfig {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            base_url: Url::parse(DEFAULT_BASE_URL).expect("hardcoded default url is valid"),
            rate_limit_per_sec: DEFAULT_RATE_LIMIT_PER_SEC,
            request_timeout: Duration::from_secs(15),
        }
    }
}

/// Etherscan v2 multichain client.
///
/// Cheap to clone; the inner state is shared via `Arc`.
#[derive(Clone)]
pub struct EtherscanClient {
    cfg: Arc<EtherscanConfig>,
    http: reqwest::Client,
    /// 1-permit-per-request semaphore that's permit-replenished on a tick.
    limiter: Arc<RateLimiter>,
    /// Optional cache, used by `json_abi_for` (and any future cached
    /// helpers). Always-on read-through; misses fall back to the network.
    cache: Option<Arc<EtherscanCache>>,
    /// Storage reader for proxy resolution (EIP-1967). When absent we
    /// fall back to Etherscan's own `Implementation` field.
    storage: Option<Arc<dyn StorageReader>>,
}

impl std::fmt::Debug for EtherscanClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtherscanClient")
            .field("cfg", &self.cfg)
            .field("limiter", &self.limiter)
            .field("cache", &self.cache.is_some())
            .field("storage", &self.storage.is_some())
            .finish()
    }
}

#[derive(Debug)]
struct RateLimiter {
    sem: Arc<Semaphore>,
    /// Per-permit hold time. Long-run throughput ≈ capacity / hold_ms.
    hold: Duration,
}

impl RateLimiter {
    fn new(per_sec: u32) -> Self {
        let capacity = per_sec.max(1);
        Self {
            sem: Arc::new(Semaphore::new(capacity as usize)),
            hold: Duration::from_millis(1000 / u64::from(capacity)),
        }
    }

    /// Acquire one slot. The slot is released asynchronously after `hold`
    /// elapses, so a sustained call rate of `capacity` permits per `hold`
    /// window is enforced (≈ per_sec / sec).
    async fn acquire(&self) {
        let permit = self
            .sem
            .clone()
            .acquire_owned()
            .await
            .expect("limiter semaphore is never closed");
        let hold = self.hold;
        tokio::spawn(async move {
            tokio::time::sleep(hold).await;
            drop(permit);
        });
    }
}

impl EtherscanClient {
    /// Build a new client with default configuration.
    pub fn new(api_key: String) -> Self {
        Self::from_config(EtherscanConfig::new(api_key))
    }

    /// Build with a custom base URL (e.g. a Routescan-compatible mirror).
    pub fn with_base_url(api_key: String, base_url: Url) -> Self {
        let mut cfg = EtherscanConfig::new(api_key);
        cfg.base_url = base_url;
        Self::from_config(cfg)
    }

    /// Override the requests-per-second limit.
    pub fn with_rate_limit(mut self, per_sec: u32) -> Self {
        Arc::make_mut(&mut self.cfg).rate_limit_per_sec = per_sec;
        self.limiter = Arc::new(RateLimiter::new(per_sec));
        self
    }

    /// Build from a fully-formed config.
    pub fn from_config(cfg: EtherscanConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(cfg.request_timeout)
            .build()
            .expect("reqwest client builder");
        let limiter = Arc::new(RateLimiter::new(cfg.rate_limit_per_sec));
        Self {
            cfg: Arc::new(cfg),
            http,
            limiter,
            cache: None,
            storage: None,
        }
    }

    /// Builder: attach a [`EtherscanCache`]. Currently used by
    /// [`Self::json_abi_for`]; other endpoints stay uncached for now.
    pub fn with_cache(mut self, cache: Arc<EtherscanCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Builder: attach a [`StorageReader`] used for EIP-1967 proxy
    /// detection in [`Self::json_abi_for`]. Without one, proxy resolution
    /// relies solely on Etherscan's own `Implementation` field.
    pub fn with_storage_reader(mut self, reader: Arc<dyn StorageReader>) -> Self {
        self.storage = Some(reader);
        self
    }

    /// Active configuration.
    pub fn config(&self) -> &EtherscanConfig {
        &self.cfg
    }

    /// Lower-level: hit a specific (module, action) combo and return the
    /// `result` field as a `serde_json::Value`. Useful when callers want
    /// access to endpoints we don't have a typed wrapper for.
    pub async fn raw_call(
        &self,
        chain_id: u64,
        module: &str,
        action: &str,
        extra: &[(&str, String)],
    ) -> Result<serde_json::Value, EtherscanError> {
        let env = self.envelope_call(chain_id, module, action, extra).await?;
        Ok(env.result)
    }

    async fn envelope_call(
        &self,
        chain_id: u64,
        module: &str,
        action: &str,
        extra: &[(&str, String)],
    ) -> Result<Envelope, EtherscanError> {
        self.limiter.acquire().await;
        let mut url = self.cfg.base_url.clone();
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("chainid", &chain_id.to_string());
            q.append_pair("module", module);
            q.append_pair("action", action);
            for (k, v) in extra {
                q.append_pair(k, v);
            }
            q.append_pair("apikey", &self.cfg.api_key);
        }
        debug!(%module, %action, chain_id, "etherscan.request");
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        trace!(%status, body_len = text.len(), "etherscan.response");
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(EtherscanError::RateLimit);
        }
        if !status.is_success() {
            return Err(EtherscanError::Api {
                status: status.as_u16().to_string(),
                message: text,
            });
        }
        let env: Envelope = serde_json::from_str(&text).map_err(|e| {
            EtherscanError::InvalidResponse(format!("non-json envelope: {e}: {text}"))
        })?;
        // status: "1" success, "0" error
        if env.status == "1" {
            return Ok(env);
        }
        // The "result" field on errors is usually a human description.
        let detail = match &env.result {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let combined = format!("{} {}", env.message, detail).to_ascii_lowercase();
        // Etherscan emits "No transactions found" / "No records found" with
        // status=0 but a perfectly valid (empty array) result. Translate to
        // a successful empty payload.
        if combined.contains("no transactions found") || combined.contains("no records found") {
            return Ok(Envelope {
                status: "1".into(),
                message: env.message,
                result: serde_json::Value::Array(vec![]),
            });
        }
        if combined.contains("max rate limit") || combined.contains("rate limit") {
            return Err(EtherscanError::RateLimit);
        }
        if combined.contains("not enabled") || combined.contains("not supported") {
            return Err(EtherscanError::Disabled);
        }
        Err(EtherscanError::Api {
            status: env.status,
            message: format!("{}: {}", env.message, detail),
        })
    }

    /// Decode `result` as `T`.
    fn decode<T: DeserializeOwned>(v: serde_json::Value) -> Result<T, EtherscanError> {
        serde_json::from_value(v).map_err(EtherscanError::from)
    }

    // --- Contract ----------------------------------------------------------

    /// `module=contract&action=getabi`. Returns the ABI as a parsed JSON
    /// value (Etherscan transports it as a JSON-string; we decode).
    pub async fn get_abi(
        &self,
        chain_id: u64,
        addr: Address,
    ) -> Result<serde_json::Value, EtherscanError> {
        let extra = [("address", addr.to_string())];
        let env = self
            .envelope_call(chain_id, "contract", "getabi", &extra)
            .await?;
        let s = match env.result {
            serde_json::Value::String(s) => s,
            other => {
                return Err(EtherscanError::InvalidResponse(format!(
                    "expected ABI string, got {other:?}"
                )));
            }
        };
        if s == "Contract source code not verified" {
            return Err(EtherscanError::Api {
                status: "0".into(),
                message: s,
            });
        }
        Ok(serde_json::from_str(&s)?)
    }

    /// `module=contract&action=getsourcecode`.
    pub async fn get_source_code(
        &self,
        chain_id: u64,
        addr: Address,
    ) -> Result<ContractSource, EtherscanError> {
        let extra = [("address", addr.to_string())];
        let result = self
            .raw_call(chain_id, "contract", "getsourcecode", &extra)
            .await?;
        let mut arr: Vec<ContractSource> = Self::decode(result)?;
        arr.pop().ok_or_else(|| {
            EtherscanError::InvalidResponse("getsourcecode returned empty array".into())
        })
    }

    /// Resolve a [`JsonAbi`] for `addr` on `chain_id`, transparently
    /// following EIP-1967 proxy delegation up to two hops deep.
    ///
    /// Resolution order for the implementation address:
    /// 1. If a [`StorageReader`] is wired, read the EIP-1967 implementation
    ///    slot. A non-zero value (lower 20 bytes) overrides `addr`.
    /// 2. Otherwise, if Etherscan's `getsourcecode` reports `Proxy=1`
    ///    with a non-empty `Implementation`, use that.
    ///
    /// Returns `Ok(None)` when the resolved address has no verified ABI.
    /// Cached under kind `abi`, key `0x<addr>` per chain.
    pub async fn json_abi_for(
        &self,
        chain_id: u64,
        addr: Address,
    ) -> Result<Option<JsonAbi>, EtherscanError> {
        if let Some(cache) = &self.cache {
            let key = format!("{addr:#x}");
            if let Some(cached) = cache.get::<JsonAbi>(chain_id, "abi", &key, None) {
                debug!(%addr, chain_id, "json_abi_for.cache.hit");
                return Ok(Some(cached));
            }
            trace!(%addr, chain_id, "json_abi_for.cache.miss");
        }
        let mut current = addr;
        let mut hops = 0;
        let abi = loop {
            // Storage read is the EIP-1967 standard path; fall back to
            // Etherscan's own proxy field if no reader is wired.
            let mut next = None;
            if let Some(reader) = &self.storage {
                match reader.read_slot(current, EIP1967_IMPL_SLOT).await {
                    Ok(slot) if !slot.is_zero() => {
                        let impl_addr = addr_from_slot(slot);
                        debug!(%current, %impl_addr, "json_abi_for.proxy.eip1967");
                        next = Some(impl_addr);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        debug!(error = %e, %current, "json_abi_for.slot_read_failed");
                    }
                }
            }
            // Always fetch source for the current address — we need the
            // ABI either way.
            let src = match self.get_source_code(chain_id, current).await {
                Ok(s) => s,
                Err(e @ EtherscanError::Api { .. })
                | Err(e @ EtherscanError::InvalidResponse(_)) => {
                    debug!(error = %e, %current, chain_id, "json_abi_for.source_unavailable");
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            // If the chain reader didn't already give us a target, look
            // at Etherscan's reported proxy fields.
            if next.is_none() && src.is_proxy() && !src.implementation.is_empty() {
                match src.implementation.parse::<Address>() {
                    Ok(impl_addr) if impl_addr != Address::ZERO => {
                        debug!(%current, %impl_addr, "json_abi_for.proxy.etherscan_field");
                        next = Some(impl_addr);
                    }
                    Ok(_) => {
                        debug!(%current, "json_abi_for.proxy.zero_implementation");
                    }
                    Err(e) => {
                        debug!(error = %e, %current, raw = %src.implementation, "json_abi_for.proxy.bad_implementation");
                    }
                }
            }
            if let Some(n) = next {
                if hops >= 2 || n == current {
                    // Cap recursion; fall back to the current ABI rather
                    // than chasing further.
                    debug!(%current, hops, next = %n, "json_abi_for.proxy.recursion_capped");
                    break src.parsed_abi().ok().or_else(|| {
                        debug!(%current, "json_abi_for.parsed_abi.empty_at_cap");
                        None
                    });
                }
                hops += 1;
                current = n;
                continue;
            }
            break match src.parsed_abi() {
                Ok(v) => Some(v),
                Err(e) => {
                    debug!(error = %e, %current, "json_abi_for.parsed_abi.failed");
                    None
                }
            };
        };

        let abi = match abi {
            Some(v) => v,
            None => {
                debug!(%addr, chain_id, "json_abi_for.unavailable");
                return Ok(None);
            }
        };
        let abi: JsonAbi = match serde_json::from_value(abi) {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, %addr, chain_id, "json_abi_for.parse_failed");
                return Ok(None);
            }
        };

        if let Some(cache) = &self.cache {
            let key = format!("{addr:#x}");
            if let Err(e) = cache.put(chain_id, "abi", &key, &abi) {
                tracing::warn!(error = %e, "json_abi_for.cache_put_failed");
            }
        }
        Ok(Some(abi))
    }

    // --- Account -----------------------------------------------------------

    /// `module=account&action=balance` (tag=latest).
    pub async fn get_balance(&self, chain_id: u64, addr: Address) -> Result<U256, EtherscanError> {
        let extra = [("address", addr.to_string()), ("tag", "latest".to_string())];
        let result = self
            .raw_call(chain_id, "account", "balance", &extra)
            .await?;
        let s: String = Self::decode(result)?;
        s.parse::<U256>()
            .map_err(|e| EtherscanError::InvalidResponse(format!("balance parse: {e}")))
    }

    /// `module=account&action=tokenbalance`.
    pub async fn get_token_balance(
        &self,
        chain_id: u64,
        addr: Address,
        contract_addr: Address,
    ) -> Result<U256, EtherscanError> {
        let extra = [
            ("contractaddress", contract_addr.to_string()),
            ("address", addr.to_string()),
            ("tag", "latest".to_string()),
        ];
        let result = self
            .raw_call(chain_id, "account", "tokenbalance", &extra)
            .await?;
        let s: String = Self::decode(result)?;
        s.parse::<U256>()
            .map_err(|e| EtherscanError::InvalidResponse(format!("tokenbalance parse: {e}")))
    }

    /// `module=account&action=txlist`.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_tx_list(
        &self,
        chain_id: u64,
        addr: Address,
        start_block: u64,
        end_block: u64,
        page: u32,
        offset: u32,
        sort: Sort,
    ) -> Result<Vec<TxRecord>, EtherscanError> {
        let extra = [
            ("address", addr.to_string()),
            ("startblock", start_block.to_string()),
            ("endblock", end_block.to_string()),
            ("page", page.to_string()),
            ("offset", offset.to_string()),
            ("sort", sort.as_str().to_string()),
        ];
        let result = self.raw_call(chain_id, "account", "txlist", &extra).await?;
        Self::decode(result)
    }

    /// `module=account&action=txlistinternal`.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_internal_tx_list(
        &self,
        chain_id: u64,
        addr: Address,
        start_block: u64,
        end_block: u64,
        page: u32,
        offset: u32,
        sort: Sort,
    ) -> Result<Vec<TxRecord>, EtherscanError> {
        let extra = [
            ("address", addr.to_string()),
            ("startblock", start_block.to_string()),
            ("endblock", end_block.to_string()),
            ("page", page.to_string()),
            ("offset", offset.to_string()),
            ("sort", sort.as_str().to_string()),
        ];
        let result = self
            .raw_call(chain_id, "account", "txlistinternal", &extra)
            .await?;
        Self::decode(result)
    }

    /// `module=account&action=tokentx`.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_token_tx(
        &self,
        chain_id: u64,
        addr: Address,
        contract_addr_filter: Option<Address>,
        start_block: u64,
        end_block: u64,
        page: u32,
        offset: u32,
        sort: Sort,
    ) -> Result<Vec<TokenTransfer>, EtherscanError> {
        let mut extra: Vec<(&str, String)> = vec![
            ("address", addr.to_string()),
            ("startblock", start_block.to_string()),
            ("endblock", end_block.to_string()),
            ("page", page.to_string()),
            ("offset", offset.to_string()),
            ("sort", sort.as_str().to_string()),
        ];
        if let Some(ca) = contract_addr_filter {
            extra.push(("contractaddress", ca.to_string()));
        }
        let result = self
            .raw_call(chain_id, "account", "tokentx", &extra)
            .await?;
        Self::decode(result)
    }

    /// `module=account&action=tokennfttx` (ERC-721 transfers).
    #[allow(clippy::too_many_arguments)]
    pub async fn get_nft_tx(
        &self,
        chain_id: u64,
        addr: Address,
        contract_addr_filter: Option<Address>,
        start_block: u64,
        end_block: u64,
        page: u32,
        offset: u32,
        sort: Sort,
    ) -> Result<Vec<TokenTransfer>, EtherscanError> {
        let mut extra: Vec<(&str, String)> = vec![
            ("address", addr.to_string()),
            ("startblock", start_block.to_string()),
            ("endblock", end_block.to_string()),
            ("page", page.to_string()),
            ("offset", offset.to_string()),
            ("sort", sort.as_str().to_string()),
        ];
        if let Some(ca) = contract_addr_filter {
            extra.push(("contractaddress", ca.to_string()));
        }
        let result = self
            .raw_call(chain_id, "account", "tokennfttx", &extra)
            .await?;
        Self::decode(result)
    }

    /// `module=account&action=token1155tx` (ERC-1155 transfers).
    #[allow(clippy::too_many_arguments)]
    pub async fn get_nft1155_tx(
        &self,
        chain_id: u64,
        addr: Address,
        contract_addr_filter: Option<Address>,
        start_block: u64,
        end_block: u64,
        page: u32,
        offset: u32,
        sort: Sort,
    ) -> Result<Vec<TokenTransfer>, EtherscanError> {
        let mut extra: Vec<(&str, String)> = vec![
            ("address", addr.to_string()),
            ("startblock", start_block.to_string()),
            ("endblock", end_block.to_string()),
            ("page", page.to_string()),
            ("offset", offset.to_string()),
            ("sort", sort.as_str().to_string()),
        ];
        if let Some(ca) = contract_addr_filter {
            extra.push(("contractaddress", ca.to_string()));
        }
        let result = self
            .raw_call(chain_id, "account", "token1155tx", &extra)
            .await?;
        Self::decode(result)
    }

    // --- Block -------------------------------------------------------------

    /// `module=block&action=getblocknobytime`.
    pub async fn get_block_no_by_time(
        &self,
        chain_id: u64,
        ts: u64,
        closest: Closest,
    ) -> Result<u64, EtherscanError> {
        let extra = [
            ("timestamp", ts.to_string()),
            ("closest", closest.as_str().to_string()),
        ];
        let result = self
            .raw_call(chain_id, "block", "getblocknobytime", &extra)
            .await?;
        let s: String = Self::decode(result)?;
        s.parse::<u64>()
            .map_err(|e| EtherscanError::InvalidResponse(format!("block number parse: {e}")))
    }

    // --- Logs --------------------------------------------------------------

    /// `module=logs&action=getLogs`.
    ///
    /// `topics` is positional: `[topic0, topic1, topic2, topic3]`. `None`
    /// entries are omitted from the request. Multi-topic operators (`and`/`or`)
    /// are deferred — callers that need them can use [`raw_call`].
    pub async fn get_logs(
        &self,
        chain_id: u64,
        from_block: u64,
        to_block: u64,
        addr: Option<Address>,
        topics: [Option<B256>; 4],
    ) -> Result<Vec<LogRecord>, EtherscanError> {
        let mut extra: Vec<(&str, String)> = vec![
            ("fromBlock", from_block.to_string()),
            ("toBlock", to_block.to_string()),
        ];
        if let Some(a) = addr {
            extra.push(("address", a.to_string()));
        }
        for (i, t) in topics.iter().enumerate() {
            if let Some(h) = t {
                extra.push((
                    match i {
                        0 => "topic0",
                        1 => "topic1",
                        2 => "topic2",
                        3 => "topic3",
                        _ => unreachable!(),
                    },
                    format!("0x{}", hex::encode(h.as_slice())),
                ));
            }
        }
        let result = self.raw_call(chain_id, "logs", "getLogs", &extra).await?;
        Self::decode(result)
    }
}

/// EIP-1967 storage slot encodes the implementation address right-aligned
/// in a 32-byte word (lower 20 bytes).
fn addr_from_slot(slot: B256) -> Address {
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&slot.as_slice()[12..]);
    Address::from(bytes)
}

/// Standard Etherscan envelope: `{status, message, result}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Envelope {
    #[serde(default)]
    status: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    result: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// One-shot HTTP echo server. Accepts a single connection, drains the
    /// request, writes `body` with a 200 response, then closes.
    async fn spawn_canned_server(body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain request headers (simple: read until \r\n\r\n).
            let mut buf = vec![0u8; 4096];
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(response.as_bytes()).await.unwrap();
            sock.shutdown().await.ok();
        });
        addr
    }

    fn client_for(addr: SocketAddr) -> EtherscanClient {
        let url = Url::parse(&format!("http://{addr}/api")).unwrap();
        EtherscanClient::with_base_url("test_key".into(), url)
    }

    #[tokio::test]
    async fn get_abi_decodes_string_field() {
        // ABI is conveyed as a JSON-encoded string inside `result`.
        let body = r#"{"status":"1","message":"OK","result":"[{\"type\":\"function\",\"name\":\"foo\"}]"}"#;
        let addr = spawn_canned_server(body).await;
        let c = client_for(addr);
        let abi = c
            .get_abi(
                1,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(abi.is_array());
        assert_eq!(abi[0]["name"], "foo");
    }

    #[tokio::test]
    async fn get_balance_parses_decimal() {
        let body = r#"{"status":"1","message":"OK","result":"123456789012345678"}"#;
        let addr = spawn_canned_server(body).await;
        let c = client_for(addr);
        let bal = c
            .get_balance(
                1,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bal.to_string(), "123456789012345678");
    }

    #[tokio::test]
    async fn get_source_code_extracts_first_record() {
        let body = r#"{"status":"1","message":"OK","result":[{
            "SourceCode":"contract X {}",
            "ABI":"[]",
            "ContractName":"X",
            "CompilerVersion":"v0.8.20+commit.a1b79de6",
            "OptimizationUsed":"1",
            "Runs":"200",
            "ConstructorArguments":"",
            "EVMVersion":"london",
            "Library":"",
            "LicenseType":"MIT",
            "Proxy":"0",
            "Implementation":"",
            "SwarmSource":""
        }]}"#;
        let addr = spawn_canned_server(body).await;
        let c = client_for(addr);
        let s = c
            .get_source_code(
                1,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(s.contract_name, "X");
        assert!(!s.is_proxy());
        assert!(s.parsed_multi_file_sources().unwrap().is_none());
    }

    #[tokio::test]
    async fn multi_file_source_unwraps_double_braces() {
        let inner = r#"{"language":"Solidity","sources":{"X.sol":{"content":"contract X{}"}}}"#;
        let wrapped = format!("{{{}}}", inner); // outer {{...}}
        // SourceCode value embedded as a JSON string with quotes/braces escaped.
        let escaped = serde_json::to_string(&wrapped).unwrap();
        let body = format!(
            r#"{{"status":"1","message":"OK","result":[{{
                "SourceCode":{escaped},
                "ABI":"[]",
                "ContractName":"X",
                "CompilerVersion":"v0.8.20",
                "OptimizationUsed":"1",
                "Runs":"200",
                "ConstructorArguments":"",
                "EVMVersion":"london",
                "Library":"",
                "LicenseType":"MIT",
                "Proxy":"0",
                "Implementation":"",
                "SwarmSource":""
            }}]}}"#
        );
        // We need to leak this static-ish; spawn_canned_server takes &'static.
        let leaked: &'static str = Box::leak(body.into_boxed_str());
        let addr = spawn_canned_server(leaked).await;
        let c = client_for(addr);
        let s = c
            .get_source_code(
                1,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap();
        let multi = s
            .parsed_multi_file_sources()
            .unwrap()
            .expect("multi-file expected");
        assert_eq!(multi["language"], "Solidity");
        assert!(multi["sources"]["X.sol"]["content"].is_string());
    }

    #[tokio::test]
    async fn api_error_is_typed() {
        let body = r#"{"status":"0","message":"NOTOK","result":"Invalid API Key"}"#;
        let addr = spawn_canned_server(body).await;
        let c = client_for(addr);
        let err = c
            .get_balance(
                1,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap_err();
        match err {
            EtherscanError::Api { status, message } => {
                assert_eq!(status, "0");
                assert!(message.contains("Invalid API Key"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rate_limit_is_typed() {
        let body = r#"{"status":"0","message":"NOTOK","result":"Max rate limit reached"}"#;
        let addr = spawn_canned_server(body).await;
        let c = client_for(addr);
        let err = c
            .get_balance(
                1,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, EtherscanError::RateLimit));
    }

    #[tokio::test]
    async fn no_records_translates_to_empty_array() {
        let body = r#"{"status":"0","message":"No transactions found","result":[]}"#;
        let addr = spawn_canned_server(body).await;
        let c = client_for(addr);
        let txs = c
            .get_tx_list(
                1,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
                0,
                99_999_999,
                1,
                10,
                Sort::Asc,
            )
            .await
            .unwrap();
        assert!(txs.is_empty());
    }

    #[tokio::test]
    async fn block_no_by_time_parses() {
        let body = r#"{"status":"1","message":"OK","result":"19000000"}"#;
        let addr = spawn_canned_server(body).await;
        let c = client_for(addr);
        let n = c
            .get_block_no_by_time(1, 1_700_000_000, Closest::Before)
            .await
            .unwrap();
        assert_eq!(n, 19_000_000);
    }

    #[tokio::test]
    async fn logs_decoded() {
        let body = r#"{"status":"1","message":"OK","result":[{
            "address":"0xabc",
            "topics":["0x01","0x02"],
            "data":"0x",
            "blockNumber":"0x1",
            "blockHash":"0xbb",
            "timeStamp":"0x65",
            "gasPrice":"0x0",
            "gasUsed":"0x0",
            "logIndex":"0x0",
            "transactionHash":"0xtx",
            "transactionIndex":"0x0"
        }]}"#;
        let addr = spawn_canned_server(body).await;
        let c = client_for(addr);
        let logs = c
            .get_logs(1, 0, 100, None, [None, None, None, None])
            .await
            .unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].topics.len(), 2);
    }

    #[tokio::test]
    async fn get_nft1155_tx_decodes_records() {
        // token1155tx returns tokenID + tokenValue alongside the usual
        // transfer fields. Our typed struct opportunistically captures
        // both; verify they round-trip.
        let body = r#"{"status":"1","message":"OK","result":[{
            "blockNumber":"19000000",
            "timeStamp":"1700000000",
            "hash":"0xabc",
            "nonce":"0",
            "blockHash":"0xbb",
            "transactionIndex":"0",
            "from":"0x1111111111111111111111111111111111111111",
            "contractAddress":"0x2222222222222222222222222222222222222222",
            "to":"0x3333333333333333333333333333333333333333",
            "value":"",
            "tokenName":"My1155",
            "tokenSymbol":"M1155",
            "tokenDecimal":"0",
            "tokenID":"42",
            "tokenValue":"7",
            "gas":"100000",
            "gasPrice":"1",
            "gasUsed":"50000",
            "cumulativeGasUsed":"50000",
            "input":"0x",
            "confirmations":"5"
        }]}"#;
        let addr = spawn_canned_server(body).await;
        let c = client_for(addr);
        let txs = c
            .get_nft1155_tx(
                1,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
                None,
                0,
                99_999_999,
                1,
                10,
                Sort::Desc,
            )
            .await
            .unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "42");
        assert_eq!(txs[0].token_value, "7");
        assert_eq!(txs[0].token_symbol, "M1155");
    }

    #[tokio::test]
    async fn token_balance_parses() {
        let body = r#"{"status":"1","message":"OK","result":"1000000"}"#;
        let addr = spawn_canned_server(body).await;
        let c = client_for(addr);
        let b = c
            .get_token_balance(
                1,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
                "0x0000000000000000000000000000000000000002"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(b.to_string(), "1000000");
    }

    #[test]
    fn error_display() {
        let e = EtherscanError::RateLimit;
        assert_eq!(e.to_string(), "rate limited by etherscan");
        let e = EtherscanError::Api {
            status: "0".into(),
            message: "x".into(),
        };
        assert!(e.to_string().contains("status=0"));
    }

    #[test]
    fn config_defaults() {
        let cfg = EtherscanConfig::new("k".into());
        assert_eq!(cfg.base_url.as_str(), "https://api.etherscan.io/v2/api");
        assert_eq!(cfg.rate_limit_per_sec, 5);
    }

    // ---- Live integration (gated) -----------------------------------------

    /// Live test against the real Etherscan v2 API. Needs
    /// `BLOOM_ETHERSCAN_KEY` in env. Skipped by default; run with
    /// `cargo test -p bloom-etherscan -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_etherscan_smoke() {
        let key = match std::env::var("BLOOM_ETHERSCAN_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => {
                eprintln!("SKIP: BLOOM_ETHERSCAN_KEY not set");
                return;
            }
        };
        let c = EtherscanClient::new(key);

        // 1. USDC's proxy contract on mainnet → ContractName == FiatTokenProxy.
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let src = c.get_source_code(1, usdc).await.expect("usdc source");
        eprintln!("USDC ContractName = {}", src.contract_name);
        assert!(
            src.contract_name == "FiatTokenProxy"
                || src.contract_name.contains("FiatToken")
                || src.is_proxy(),
            "unexpected contract name: {}",
            src.contract_name
        );

        // 2. vitalik.eth balance is ~certainly non-zero.
        let vitalik: Address = "0xd8dA6BF26964aF9D7eED9e03E53415D37aA96045"
            .parse()
            .unwrap();
        let bal = c.get_balance(1, vitalik).await.expect("vitalik balance");
        eprintln!("vitalik balance (wei) = {}", bal);
        assert!(bal > U256::ZERO, "expected non-zero balance");

        // 3. Sanity check: ABI fetch for USDC should yield a JSON array.
        let abi = c.get_abi(1, usdc).await.expect("usdc abi");
        assert!(abi.is_array(), "ABI should be array, got {abi:?}");
    }
}
