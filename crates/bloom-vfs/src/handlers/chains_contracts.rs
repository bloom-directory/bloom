//! Contract interaction surface under `chains/<chain>/contracts/<addr>/`.
//!
//! Split out of `chains.rs` to keep the main router readable. This module
//! owns the heavy ABI / RPC plumbing for:
//!
//! - `methods/<name>.read`  — writable JSON; encodes calldata, runs
//!   `eth_call`, decodes the return value via the verified ABI.
//! - `methods/<name>.tx`    — writable JSON; encodes calldata only and
//!   does **not** broadcast. Pipe into the wallet outbox to send.
//! - `methods/<name>.sig`   — read-only canonical function signature
//!   (`balanceOf(address) returns (uint256)`) and 4-byte selector.
//! - `events/<name>/recent` — read-only; last ~200 logs over the last
//!   ~10_000 blocks (or the full window if the chain is shorter).
//! - `events/<name>/query`  — writable JSON; user-driven filter.
//! - `events/<name>/live`   — read-only long-poll tail with per-handler
//!   cursor (caveat: not per-client; documented below).
//! - `storage/<slot>`       — read-only `eth_getStorageAt` (slot accepts
//!   decimal or `0x`-hex).
//! - `proxy/{implementation,admin,beacon}` — well-known EIP-1967 /
//!   EIP-1822 slot reads, returning a checksummed address (or
//!   `not a proxy\n` if the slot is empty).
//!
//! The `methods/...` and `events/...` paths require an Etherscan-backed
//! `contract_metadata` (we need the ABI). `storage` and `proxy` use raw
//! RPC and are therefore always available.
//!
//! ## Live tail caveat
//!
//! The per-event live cursor is keyed by `(chain, address, event)` and
//! lives in handler-process memory. Two clients tailing the same event
//! will race for "what's new since last read" — the simpler path scheme
//! buys clarity at the cost of a real per-client subscription. A future
//! refinement could mint per-session subdirectories, mirroring the watch
//! executor; the spec explicitly allowed this trade-off for v1.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::dyn_abi::{DynSolType, EventExt, FunctionExt, JsonAbiExt};
use alloy::json_abi::{Event, Function, JsonAbi};
use alloy::primitives::{Address, B256, U256};
use alloy::rpc::types::eth::{Filter, TransactionRequest};
use parking_lot::{Mutex, RwLock};

use bloom_etherscan::{ContractMetadataSource, DataSourceError};
use bloom_evm::ChainClient;
use bloom_proto::checksum_address;
use bloom_tools::abi::{json_to_sol, sol_to_json};

use crate::handler::{Entry, HandlerError};

use super::chains_history::map_err as map_data_err;

/// Logical leaves under `methods/<name>` that we expose. Stored as a
/// constant so the `list` and `lookup` paths agree.
pub(crate) const METHOD_LEAVES: &[&str] = &["read", "tx", "sig"];

/// Logical leaves under `events/<name>`.
pub(crate) const EVENT_LEAVES: &[&str] = &["recent", "query", "live"];

/// Logical leaves under `proxy/`.
pub(crate) const PROXY_LEAVES: &[&str] = &["implementation", "admin", "beacon"];

/// Recent-window default: cap the result to 200 logs over the last
/// 10_000 blocks, matching what the spec asks for.
const RECENT_WINDOW_BLOCKS: u64 = 10_000;
const RECENT_MAX_LOGS: usize = 200;

/// EIP-1967 slot for the implementation address.
/// `keccak256("eip1967.proxy.implementation") - 1`.
pub const EIP1967_IMPLEMENTATION_SLOT: B256 = B256::new([
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d,
    0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc,
]);
/// EIP-1967 slot for the admin address.
pub const EIP1967_ADMIN_SLOT: B256 = B256::new([
    0xb5, 0x31, 0x27, 0x68, 0x4a, 0x56, 0x8b, 0x31, 0x73, 0xae, 0x13, 0xb9, 0xf8, 0xa6, 0x01, 0x6e,
    0x24, 0x3e, 0x63, 0xb6, 0xe8, 0xee, 0x11, 0x78, 0xd6, 0xa7, 0x17, 0x85, 0x0b, 0x5d, 0x61, 0x03,
]);
/// EIP-1967 slot for the beacon contract.
pub const EIP1967_BEACON_SLOT: B256 = B256::new([
    0xa3, 0xf0, 0xad, 0x74, 0xe5, 0x42, 0x3a, 0xeb, 0xfd, 0x80, 0xd3, 0xef, 0x43, 0x46, 0x57, 0x83,
    0x35, 0xa9, 0xa7, 0x2a, 0xea, 0xee, 0x59, 0xff, 0x6c, 0xb3, 0x58, 0x2b, 0x35, 0x13, 0x3d, 0x50,
]);
/// EIP-1822 (UUPS) slot: `keccak256("PROXIABLE")`.
pub const EIP1822_IMPLEMENTATION_SLOT: B256 = B256::new([
    0xc5, 0xf1, 0x6f, 0x0f, 0xcc, 0x63, 0x9f, 0xa4, 0x8a, 0x69, 0x47, 0x83, 0x6d, 0x98, 0x50, 0xf5,
    0x04, 0x79, 0x85, 0x23, 0xbf, 0x8c, 0x9a, 0x3a, 0x87, 0xd5, 0x87, 0x6c, 0xf6, 0x22, 0xbc, 0xf7,
]);

/// ABI cache TTL — long enough to amortise across a burst of method
/// reads, short enough that re-verification is picked up promptly.
const ABI_CACHE_TTL: Duration = Duration::from_secs(60);

/// Cached ABI entry: `(insertion_time, parsed_abi)`. Lifted out so the
/// `HashMap` value type stays under clippy's `type_complexity` cap.
type AbiCacheEntry = (Instant, Arc<JsonAbi>);

/// Process-wide ABI cache shared across the handler. The key is
/// `(chain_id, addr)` so the same binary running across multiple
/// chains doesn't cross the streams.
#[derive(Default)]
pub struct AbiCache {
    inner: RwLock<HashMap<(u64, Address), AbiCacheEntry>>,
}

impl AbiCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, key: &(u64, Address)) -> Option<Arc<JsonAbi>> {
        let g = self.inner.read();
        if let Some((at, abi)) = g.get(key)
            && at.elapsed() < ABI_CACHE_TTL
        {
            return Some(abi.clone());
        }
        None
    }

    fn put(&self, key: (u64, Address), abi: Arc<JsonAbi>) {
        self.inner.write().insert(key, (Instant::now(), abi));
    }
}

/// Per-(chain, addr, event) cursor for the `events/<name>/live` tail.
///
/// One handler owns the map; concurrent reads against the same key
/// serialise on the mutex, which is fine for v1 — events/live is not a
/// hot path. See the module-level "Live tail caveat" doc.
#[derive(Default)]
pub struct LiveTailState {
    inner: Mutex<HashMap<(u64, Address, String), u64>>,
}

impl LiveTailState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Fetch the parsed ABI for `(chain_id, addr)`, going through the
/// short-TTL cache. Errors map onto sensible `HandlerError` variants.
///
/// **Not proxy-aware.** Most callers should reach for
/// [`fetch_abi_proxy_aware`] so EIP-1967 proxies (USDC etc.) surface the
/// implementation ABI rather than the proxy/admin one.
pub async fn fetch_abi(
    cache: &AbiCache,
    src: &Arc<dyn ContractMetadataSource>,
    chain_id: u64,
    addr: Address,
) -> Result<Arc<JsonAbi>, HandlerError> {
    if let Some(a) = cache.get(&(chain_id, addr)) {
        return Ok(a);
    }
    let abi = fetch_abi_uncached(src, chain_id, addr).await?;
    let arc = Arc::new(abi);
    cache.put((chain_id, addr), arc.clone());
    Ok(arc)
}

/// One ABI fetch + parse, no caching. Shared between the direct fetch
/// and the proxy-aware variant so error handling stays in one place.
async fn fetch_abi_uncached(
    src: &Arc<dyn ContractMetadataSource>,
    chain_id: u64,
    addr: Address,
) -> Result<JsonAbi, HandlerError> {
    let raw = src.get_abi(chain_id, addr).await.map_err(map_es_err)?;
    let s = match raw {
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => raw.to_string(),
        serde_json::Value::String(s) => s,
        other => {
            return Err(HandlerError::backend(format!(
                "unexpected ABI shape: {other}"
            )));
        }
    };
    serde_json::from_str(&s).map_err(|e| HandlerError::backend(format!("abi parse: {e}")))
}

/// Render the user-facing `<addr>/abi` payload, transparently following
/// an EIP-1967 proxy when `impl_addr` is supplied. The output is the raw
/// ABI value as the metadata source returned it (string or array) so we
/// don't lose fidelity for ABIs that don't round-trip through alloy's
/// strict `JsonAbi` parser.
///
/// When the implementation has no verified ABI we fall back to the
/// proxy's own ABI — better to show *something* than `NotFound`.
pub async fn read_contract_abi_for(
    src: &Arc<dyn ContractMetadataSource>,
    chain_id: u64,
    proxy: Address,
    impl_addr: Option<Address>,
) -> Result<Vec<u8>, HandlerError> {
    let raw = match impl_addr {
        Some(target) => match src.get_abi(chain_id, target).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(
                    %proxy,
                    %target,
                    error = ?e,
                    "chains.proxy.impl_abi_unavailable_falling_back_to_proxy_raw"
                );
                src.get_abi(chain_id, proxy).await.map_err(map_es_err)?
            }
        },
        None => src.get_abi(chain_id, proxy).await.map_err(map_es_err)?,
    };
    let mut bytes = serde_json::to_vec_pretty(&raw)
        .map_err(|e| HandlerError::backend(format!("abi serialise: {e}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Resolve the implementation address behind an EIP-1967 proxy by
/// reading the implementation slot. Returns `Ok(None)` when the slot is
/// zero (i.e. the contract is not an EIP-1967 proxy) **or** when the
/// storage read fails for any reason. The proxy detection is best-effort:
/// a transient RPC failure shouldn't break the whole `methods/` surface,
/// so we log and fall back to the proxy's own ABI.
///
/// Today we only check the standard EIP-1967 implementation slot. UUPS
/// (EIP-1822) and beacon proxies are intentionally not resolved here
/// because the patterns differ subtly enough to deserve their own pass —
/// see the module-level follow-ups list.
pub async fn resolve_eip1967_implementation(
    client: &ChainClient,
    addr: Address,
) -> Option<Address> {
    match client
        .eth_get_storage_at(
            addr,
            U256::from_be_bytes(EIP1967_IMPLEMENTATION_SLOT.0),
            None,
        )
        .await
    {
        Ok(slot) if slot != B256::ZERO => {
            let impl_addr = Address::from_word(slot);
            if impl_addr == Address::ZERO || impl_addr == addr {
                None
            } else {
                Some(impl_addr)
            }
        }
        Ok(_) => None,
        Err(e) => {
            tracing::debug!(%addr, error = %e, "chains.eip1967_slot_read_failed");
            None
        }
    }
}

/// Proxy-aware ABI fetch. Reads the EIP-1967 implementation slot from
/// the chain; if non-zero, fetches *that* contract's ABI rather than
/// the proxy's own. Falls back to the proxy ABI when:
/// - the slot is zero (not a proxy),
/// - the storage read fails, or
/// - the implementation has no verified ABI on the metadata source.
///
/// Caches under the **proxy** address so all callers for a given user-
/// facing address share the result.
pub async fn fetch_abi_proxy_aware(
    cache: &AbiCache,
    src: &Arc<dyn ContractMetadataSource>,
    client: &ChainClient,
    chain_id: u64,
    addr: Address,
) -> Result<Arc<JsonAbi>, HandlerError> {
    if let Some(a) = cache.get(&(chain_id, addr)) {
        return Ok(a);
    }
    let impl_addr = resolve_eip1967_implementation(client, addr).await;
    let abi = if let Some(target) = impl_addr {
        match fetch_abi_uncached(src, chain_id, target).await {
            Ok(a) => {
                tracing::debug!(%addr, %target, "chains.proxy.abi_resolved_via_eip1967");
                a
            }
            Err(e) => {
                tracing::debug!(
                    %addr,
                    %target,
                    error = %e,
                    "chains.proxy.impl_abi_unavailable_falling_back_to_proxy"
                );
                fetch_abi_uncached(src, chain_id, addr).await?
            }
        }
    } else {
        fetch_abi_uncached(src, chain_id, addr).await?
    };
    let arc = Arc::new(abi);
    cache.put((chain_id, addr), arc.clone());
    Ok(arc)
}

fn map_es_err(e: DataSourceError) -> HandlerError {
    map_data_err(e)
}

fn parse_addr(s: &str) -> Result<Address, HandlerError> {
    s.parse::<Address>()
        .map_err(|e| HandlerError::invalid(format!("address: {e}")))
}

/// Body shape accepted by `methods/<name>.{read,tx}` — args is the
/// only required field, selector / block / from let users disambiguate
/// overloads, pin a block, or simulate from a different sender.
#[derive(serde::Deserialize, Default)]
pub struct MethodCallBody {
    #[serde(default)]
    pub args: Vec<serde_json::Value>,
    #[serde(default)]
    pub selector: Option<String>,
    #[serde(default)]
    pub block: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
}

/// Body shape accepted by `events/<name>/query`. Supports either
/// positional `topics` (`[topic0, topic1, ...]` — topic0 is filled in
/// from the event signature, callers usually pass `null` there) or
/// indexed-param-name keyed filters via the `where` map (each value
/// matches a single 32-byte topic).
#[derive(serde::Deserialize, Default)]
pub struct EventQueryBody {
    #[serde(default)]
    pub from_block: Option<String>,
    #[serde(default)]
    pub to_block: Option<String>,
    #[serde(default)]
    pub topics: Option<Vec<Option<serde_json::Value>>>,
    #[serde(default, rename = "where")]
    pub where_: Option<HashMap<String, serde_json::Value>>,
}

fn parse_block_param(s: Option<&str>) -> Result<Option<u64>, HandlerError> {
    let Some(s) = s else { return Ok(None) };
    let s = s.trim();
    if s.is_empty() || s == "latest" {
        return Ok(None);
    }
    bloom_evm::parse_block_arg(s)
        .map(Some)
        .map_err(|e| HandlerError::invalid(e.to_string()))
}

/// Enumerate every leaf the `methods/` directory should expose for the
/// given ABI. Returns one `<fname>.sig`, `<fname>.read`, and `<fname>.tx`
/// triple per function on the ABI.
///
/// Overloads collapse onto one set of leaves keyed by the bare function
/// name; reads of an overloaded leaf require a `selector` hint in the
/// staged body — see `pick_function`.
///
/// `.sig` is read-only; `.read` and `.tx` are writable so callers can
/// stage a body before reading.
pub fn enumerate_method_leaves(abi: &JsonAbi) -> Vec<Entry> {
    use std::collections::BTreeSet;
    // BTreeSet so the listing is deterministic — readdir is unordered
    // by spec but a stable order saves the user's eyes when grepping.
    let names: BTreeSet<&str> = abi.functions().map(|f| f.name.as_str()).collect();
    let mut out: Vec<Entry> = Vec::with_capacity(names.len() * 3);
    for name in names {
        out.push(Entry::file(&format!("{name}.sig")));
        out.push(Entry::writable_file(&format!("{name}.read")));
        out.push(Entry::writable_file(&format!("{name}.tx")));
    }
    out
}

/// Enumerate every event directory `events/<name>` should expose, one
/// per event on the ABI. Each entry is a directory whose children are
/// the well-known event leaves (`recent`, `query`, `live`).
pub fn enumerate_event_dirs(abi: &JsonAbi) -> Vec<Entry> {
    use std::collections::BTreeSet;
    let names: BTreeSet<&str> = abi.events().map(|e| e.name.as_str()).collect();
    names.into_iter().map(Entry::dir).collect()
}

/// Find a function on the ABI by name, optionally narrowed by selector.
pub fn pick_function<'a>(
    abi: &'a JsonAbi,
    name: &str,
    selector: Option<&str>,
) -> Result<&'a Function, HandlerError> {
    let candidates = abi
        .function(name)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| HandlerError::not_found(format!("function '{name}'")))?;
    if let Some(sel_hex) = selector {
        let want = parse_selector(sel_hex)?;
        for f in candidates {
            if f.selector().as_slice() == want.as_slice() {
                return Ok(f);
            }
        }
        return Err(HandlerError::invalid(format!(
            "no overload of {name} matches selector {sel_hex}"
        )));
    }
    if candidates.len() > 1 {
        let sigs: Vec<String> = candidates.iter().map(|f| f.signature()).collect();
        return Err(HandlerError::invalid(format!(
            "function '{name}' has {} overloads — pass selector to disambiguate; candidates: {}",
            candidates.len(),
            sigs.join(", ")
        )));
    }
    Ok(&candidates[0])
}

pub fn pick_event<'a>(abi: &'a JsonAbi, name: &str) -> Result<&'a Event, HandlerError> {
    let candidates = abi
        .event(name)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| HandlerError::not_found(format!("event '{name}'")))?;
    if candidates.len() > 1 {
        // Event overloads in Solidity must differ in indexed-ness or
        // arg list, but practically we pick the first one and document
        // it. Users wanting precision can fall back to /query with
        // explicit topics.
        tracing::debug!(
            name,
            n = candidates.len(),
            "multiple event overloads — using first"
        );
    }
    Ok(&candidates[0])
}

fn parse_selector(s: &str) -> Result<[u8; 4], HandlerError> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| HandlerError::invalid(format!("selector hex: {e}")))?;
    if bytes.len() != 4 {
        return Err(HandlerError::invalid(format!(
            "selector must be 4 bytes, got {}",
            bytes.len()
        )));
    }
    Ok([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Encode a function call for the given user body. Returns
/// `(selector_hex, calldata)` for the resolved overload.
fn encode_call(func: &Function, body: &MethodCallBody) -> Result<(String, Vec<u8>), HandlerError> {
    if body.args.len() != func.inputs.len() {
        return Err(HandlerError::invalid(format!(
            "function {} expects {} args, got {}",
            func.signature(),
            func.inputs.len(),
            body.args.len()
        )));
    }
    let mut sol_values = Vec::with_capacity(body.args.len());
    for (i, (param, arg)) in func.inputs.iter().zip(body.args.iter()).enumerate() {
        // alloy::dyn_abi::DynSolType::parse / json_to_sol coerce the
        // user JSON into the right `DynSolValue`. See alloy-dyn-abi
        // docs for the JSON shape (numbers as strings for >u64 etc.).
        let ty: DynSolType = param.ty.parse().map_err(|e: alloy::dyn_abi::Error| {
            HandlerError::backend(format!("input {i}: type parse: {e}"))
        })?;
        let v = json_to_sol(&ty, arg)
            .map_err(|e| HandlerError::invalid(format!("input {i} ({}): {e}", param.ty)))?;
        sol_values.push(v);
    }
    let calldata = func
        .abi_encode_input(&sol_values)
        .map_err(|e| HandlerError::backend(format!("abi encode: {e}")))?;
    let sel = func.selector();
    Ok((format!("0x{}", hex::encode(sel)), calldata))
}

/// Decode a function's return value into a JSON array of values.
fn decode_outputs(func: &Function, raw: &[u8]) -> Result<serde_json::Value, HandlerError> {
    if raw.is_empty() {
        return Ok(serde_json::Value::Array(Vec::new()));
    }
    let decoded = func
        .abi_decode_output(raw)
        .map_err(|e| HandlerError::backend(format!("abi decode: {e}")))?;
    Ok(serde_json::Value::Array(
        decoded.iter().map(sol_to_json).collect(),
    ))
}

/// Render a `Log` into our shell-friendly JSON shape, decoding the
/// indexed + body params via the supplied event when possible.
fn render_log(event: &Event, log: &alloy::rpc::types::eth::Log) -> serde_json::Value {
    let mut data_obj = serde_json::Map::new();
    match event.decode_log(&log.inner.data) {
        Ok(decoded) => {
            // Indexed params come back in the order they appear; same for
            // body. Solidity guarantees both lists preserve declaration
            // order, so we walk the param list once and pop the matching
            // bucket as we go.
            let mut idx_iter = decoded.indexed.into_iter();
            let mut body_iter = decoded.body.into_iter();
            for p in &event.inputs {
                let value = if p.indexed {
                    idx_iter.next().map(|v| sol_to_json(&v))
                } else {
                    body_iter.next().map(|v| sol_to_json(&v))
                };
                if let Some(v) = value {
                    data_obj.insert(p.name.clone(), v);
                }
            }
        }
        Err(e) => {
            tracing::debug!(
                event = %event.name,
                tx_hash = ?log.transaction_hash,
                log_index = ?log.log_index,
                error = %e,
                "chains.render_log_decode_failed"
            );
        }
    }
    let topics: Vec<String> = log
        .topics()
        .iter()
        .map(|t| format!("0x{}", hex::encode(t.as_slice())))
        .collect();
    serde_json::json!({
        "block_number": log.block_number,
        "tx_hash": log.transaction_hash.map(|h| format!("{h:#x}")),
        "log_index": log.log_index,
        "data": serde_json::Value::Object(data_obj),
        "topics": topics,
        "removed": log.removed,
    })
}

/// Translate a single named-or-positional topic filter value into a
/// `B256`. Accepts hex strings or — when the indexed param type is
/// `address` — an EIP-55 address (zero-padded to 32 bytes).
fn coerce_topic(ty: &DynSolType, v: &serde_json::Value) -> Result<B256, HandlerError> {
    let s = v
        .as_str()
        .ok_or_else(|| HandlerError::invalid("topic filter must be hex string"))?;
    let trimmed = s.trim();
    if let Some(rest) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if rest.len() == 64 {
            return rest
                .parse::<B256>()
                .map_err(|e| HandlerError::invalid(format!("topic: {e}")));
        }
        if rest.len() == 40 && matches!(ty, DynSolType::Address) {
            let addr: Address = trimmed
                .parse()
                .map_err(|e: alloy::hex::FromHexError| HandlerError::invalid(e.to_string()))?;
            return Ok(addr.into_word());
        }
    }
    if matches!(ty, DynSolType::Uint(_) | DynSolType::Int(_)) {
        let n = U256::from_str_radix(trimmed.trim_start_matches("0x"), 16)
            .or_else(|_| U256::from_str_radix(trimmed, 10))
            .map_err(|e| HandlerError::invalid(format!("topic uint: {e}")))?;
        return Ok(B256::from(n.to_be_bytes::<32>()));
    }
    Err(HandlerError::invalid(format!(
        "could not coerce topic value {s} for type {ty:?}"
    )))
}

/// Build a `Filter` from the user body for an event on a given
/// contract. Resolves `from_block`/`to_block` and at most three indexed
/// topics (Solidity caps at 3 indexed params + topic0 = 4 topics).
fn build_event_filter(
    addr: Address,
    event: &Event,
    body: &EventQueryBody,
    fallback_from: u64,
    fallback_to: u64,
) -> Result<Filter, HandlerError> {
    let mut f = Filter::new()
        .address(addr)
        .event_signature(event.selector());
    let from = parse_block_param(body.from_block.as_deref())?.unwrap_or(fallback_from);
    let to = parse_block_param(body.to_block.as_deref())?.unwrap_or(fallback_to);
    f = f.from_block(from).to_block(to);

    // Indexed param types in declaration order; capped at 3 since
    // topic0 is the event signature.
    let indexed_types: Vec<(String, DynSolType)> = event
        .inputs
        .iter()
        .filter(|p| p.indexed)
        .take(3)
        .map(|p| {
            let ty: DynSolType = p.ty.parse().unwrap_or(DynSolType::Bytes);
            (p.name.clone(), ty)
        })
        .collect();

    if let Some(map) = &body.where_ {
        for (i, (name, ty)) in indexed_types.iter().enumerate() {
            let Some(v) = map.get(name) else { continue };
            let topic = coerce_topic(ty, v)?;
            f = match i {
                0 => f.topic1(topic),
                1 => f.topic2(topic),
                2 => f.topic3(topic),
                _ => f,
            };
        }
    } else if let Some(arr) = &body.topics {
        // Skip topic0 (caller usually passes null there to keep
        // positional alignment); apply 1..=3 if present.
        for (i, opt) in arr.iter().enumerate().take(4).skip(1) {
            let Some(v) = opt else { continue };
            let (_, ty) = indexed_types.get(i - 1).ok_or_else(|| {
                HandlerError::invalid(format!("topic index {i} has no matching indexed param"))
            })?;
            let topic = coerce_topic(ty, v)?;
            f = match i {
                1 => f.topic1(topic),
                2 => f.topic2(topic),
                3 => f.topic3(topic),
                _ => f,
            };
        }
    }
    Ok(f)
}

/// Read `<storage>/<slot>` — `slot` is decimal or `0x`-hex, returning
/// 32 bytes of state as `0x`-prefixed hex.
pub async fn read_storage_slot(
    client: &ChainClient,
    addr: Address,
    slot: &str,
) -> Result<Vec<u8>, HandlerError> {
    let slot_u = parse_slot(slot)?;
    let val = client
        .eth_get_storage_at(addr, slot_u, None)
        .await
        .map_err(|e| HandlerError::backend(e.to_string()))?;
    Ok(format!("0x{}\n", hex::encode(val.as_slice())).into_bytes())
}

/// Parse a slot argument. Accepts `0x`-prefixed hex (any length up to
/// 32 bytes) or decimal. Anything else is `Invalid`.
fn parse_slot(s: &str) -> Result<U256, HandlerError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.len() > 64 {
            return Err(HandlerError::invalid(format!(
                "slot hex too long ({} > 64 nibbles)",
                hex.len()
            )));
        }
        // U256::from_str_radix accepts any length up to 32 bytes; zero-pad
        // implicitly via the natural numeric interpretation.
        U256::from_str_radix(hex, 16)
            .map_err(|e| HandlerError::invalid(format!("slot hex parse: {e}")))
    } else {
        U256::from_str_radix(s, 10)
            .map_err(|e| HandlerError::invalid(format!("slot dec parse: {e}")))
    }
}

/// Read an EIP-1967 / EIP-1822 proxy slot and return either a
/// checksummed address (last 20 bytes) or `not a proxy\n` when the
/// slot is empty (all zero).
pub async fn read_proxy_slot(
    client: &ChainClient,
    addr: Address,
    slot: B256,
    fallback: Option<B256>,
) -> Result<Vec<u8>, HandlerError> {
    let primary = client
        .eth_get_storage_at(addr, U256::from_be_bytes(slot.0), None)
        .await
        .map_err(|e| HandlerError::backend(e.to_string()))?;
    let mut value = primary;
    if value == B256::ZERO
        && let Some(f) = fallback
    {
        value = client
            .eth_get_storage_at(addr, U256::from_be_bytes(f.0), None)
            .await
            .map_err(|e| HandlerError::backend(e.to_string()))?;
    }
    if value == B256::ZERO {
        return Ok(b"not a proxy\n".to_vec());
    }
    // EIP-1967 stores the address right-aligned in the 32-byte slot.
    let addr = Address::from_word(value);
    Ok(format!("{}\n", checksum_address(&addr)).into_bytes())
}

/// Render the `methods/<name>.sig` body — the canonical Solidity-style
/// signature with selector. Includes the return tuple when present.
pub fn render_method_sig(func: &Function) -> Vec<u8> {
    let sig = func.signature_with_outputs();
    let sel = format!("0x{}", hex::encode(func.selector()));
    format!("{sig}\nselector: {sel}\n").into_bytes()
}

/// Run `methods/<name>.read` — encode + eth_call + decode.
pub async fn run_method_read(
    client: &ChainClient,
    addr: Address,
    func: &Function,
    body: &MethodCallBody,
) -> Result<Vec<u8>, HandlerError> {
    let (selector_hex, calldata) = encode_call(func, body)?;
    let mut req = TransactionRequest::default()
        .to(addr)
        .input(alloy::primitives::Bytes::from(calldata).into());
    if let Some(from_s) = &body.from {
        let from = parse_addr(from_s)?;
        req = req.from(from);
    }
    let raw = client
        .eth_call_at_block(req, body.block.as_deref())
        .await
        .map_err(|e| HandlerError::backend(e.to_string()))?;
    let decoded = decode_outputs(func, raw.as_ref())?;
    let resp = serde_json::json!({
        "decoded": decoded,
        "raw": format!("0x{}", hex::encode(raw.as_ref())),
        "selector": selector_hex,
    });
    let mut bytes = serde_json::to_vec_pretty(&resp).unwrap();
    bytes.push(b'\n');
    Ok(bytes)
}

/// Run `methods/<name>.tx` — calldata only, no broadcast.
pub fn run_method_tx(
    addr: Address,
    func: &Function,
    body: &MethodCallBody,
) -> Result<Vec<u8>, HandlerError> {
    let (selector_hex, calldata) = encode_call(func, body)?;
    let resp = serde_json::json!({
        "to": checksum_address(&addr),
        "selector": selector_hex,
        "calldata": format!("0x{}", hex::encode(&calldata)),
    });
    let mut bytes = serde_json::to_vec_pretty(&resp).unwrap();
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decode a slice of fetched logs into JSON.
fn render_logs(event: &Event, logs: &[alloy::rpc::types::eth::Log]) -> Vec<u8> {
    let arr: Vec<serde_json::Value> = logs.iter().map(|l| render_log(event, l)).collect();
    let mut bytes = serde_json::to_vec_pretty(&arr).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// Run `events/<name>/recent` — last RECENT_MAX_LOGS over the last
/// RECENT_WINDOW_BLOCKS, newest-first.
pub async fn run_event_recent(
    client: &ChainClient,
    addr: Address,
    event: &Event,
) -> Result<Vec<u8>, HandlerError> {
    let head = client
        .block_number()
        .await
        .map_err(|e| HandlerError::backend(e.to_string()))?;
    let from = head.saturating_sub(RECENT_WINDOW_BLOCKS);
    let filter = Filter::new()
        .address(addr)
        .event_signature(event.selector())
        .from_block(from)
        .to_block(head);
    let mut logs = client
        .get_logs(&filter)
        .await
        .map_err(|e| HandlerError::backend(e.to_string()))?;
    logs.sort_by_key(|l| std::cmp::Reverse((l.block_number, l.log_index)));
    if logs.len() > RECENT_MAX_LOGS {
        logs.truncate(RECENT_MAX_LOGS);
    }
    Ok(render_logs(event, &logs))
}

/// Run `events/<name>/query` — user-supplied filter.
pub async fn run_event_query(
    client: &ChainClient,
    addr: Address,
    event: &Event,
    body: &EventQueryBody,
) -> Result<Vec<u8>, HandlerError> {
    let head = client
        .block_number()
        .await
        .map_err(|e| HandlerError::backend(e.to_string()))?;
    let fallback_from = head.saturating_sub(RECENT_WINDOW_BLOCKS);
    let filter = build_event_filter(addr, event, body, fallback_from, head)?;
    let logs = client
        .get_logs(&filter)
        .await
        .map_err(|e| HandlerError::backend(e.to_string()))?;
    Ok(render_logs(event, &logs))
}

/// Run `events/<name>/live` — emit logs since the last cursor and
/// advance the cursor to head. The cursor is shared across all clients
/// reading this exact event on this contract.
pub async fn run_event_live(
    state: &LiveTailState,
    client: &ChainClient,
    chain_id: u64,
    addr: Address,
    event_name: &str,
    event: &Event,
) -> Result<Vec<u8>, HandlerError> {
    let head = client
        .block_number()
        .await
        .map_err(|e| HandlerError::backend(e.to_string()))?;
    let key = (chain_id, addr, event_name.to_string());
    let from = {
        let g = state.inner.lock();
        g.get(&key).map(|b| b.saturating_add(1))
    };
    let from = from.unwrap_or_else(|| head.saturating_sub(RECENT_WINDOW_BLOCKS));
    if from > head {
        // Already up-to-date; emit an empty array.
        return Ok(b"[]\n".to_vec());
    }
    let filter = Filter::new()
        .address(addr)
        .event_signature(event.selector())
        .from_block(from)
        .to_block(head);
    let logs = client
        .get_logs(&filter)
        .await
        .map_err(|e| HandlerError::backend(e.to_string()))?;
    state.inner.lock().insert(key, head);
    Ok(render_logs(event, &logs))
}

/// Resolve the EIP-1967 slot for the given proxy leaf.
pub fn proxy_slot(leaf: &str) -> Option<(B256, Option<B256>)> {
    match leaf {
        "implementation" => Some((
            EIP1967_IMPLEMENTATION_SLOT,
            Some(EIP1822_IMPLEMENTATION_SLOT),
        )),
        "admin" => Some((EIP1967_ADMIN_SLOT, None)),
        "beacon" => Some((EIP1967_BEACON_SLOT, None)),
        _ => None,
    }
}

// ---- Routing -----------------------------------------------------------

/// Trait so `chains.rs` can call into us without circular imports.
#[async_trait::async_trait]
pub trait ContractsRouter: Send + Sync {
    async fn lookup_contract(&self, addr: Address, rest: &[String]) -> Result<Entry, HandlerError>;
    async fn read_contract(
        &self,
        client: &ChainClient,
        chain_id: u64,
        addr: Address,
        rest: &[String],
    ) -> Result<Vec<u8>, HandlerError>;
    async fn write_contract(
        &self,
        client: &ChainClient,
        chain_id: u64,
        addr: Address,
        rest: &[String],
        data: &[u8],
    ) -> Result<(), HandlerError>;
    async fn list_contract(
        &self,
        addr: Address,
        rest: &[String],
    ) -> Result<Vec<Entry>, HandlerError>;
}

/// Concrete dispatcher used by `ChainsHandler`. Holds the contract
/// metadata source (already resolved by the gating layer) and shared
/// caches.
pub struct ContractDispatcher {
    pub metadata: Arc<dyn ContractMetadataSource>,
    pub abi_cache: Arc<AbiCache>,
    pub live_state: Arc<LiveTailState>,
}

impl ContractDispatcher {
    pub fn new(metadata: Arc<dyn ContractMetadataSource>) -> Self {
        Self {
            metadata,
            abi_cache: Arc::new(AbiCache::new()),
            live_state: Arc::new(LiveTailState::new()),
        }
    }
}

/// Per-(addr, body) state for writable methods + events. Stored
/// in-handler keyed by the path so the next read returns the response
/// matching the most recent write.
#[derive(Default)]
pub struct PendingBodies {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl PendingBodies {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn store(&self, key: String, body: Vec<u8>) {
        self.inner.lock().insert(key, body);
    }
    /// Return the staged body for `key`, or a sensible empty default
    /// (`{"args":[]}`) if nothing has been written yet.
    pub fn take_or_default(&self, key: &str) -> Vec<u8> {
        self.inner
            .lock()
            .get(key)
            .cloned()
            .unwrap_or_else(|| b"{\"args\":[]}".to_vec())
    }
    /// Non-destructive peek — returns whatever is staged or an empty
    /// vec. Used to sniff `selector` for overload disambiguation
    /// without consuming the body.
    pub fn peek(&self, key: &str) -> Vec<u8> {
        self.inner.lock().get(key).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_and_hex_slot() {
        assert_eq!(parse_slot("0").unwrap(), U256::ZERO);
        assert_eq!(parse_slot("123").unwrap(), U256::from(123u64));
        assert_eq!(parse_slot("0x7b").unwrap(), U256::from(123u64));
        assert!(parse_slot("nope").is_err());
        assert!(parse_slot(&format!("0x{}", "ff".repeat(33))).is_err());
    }

    #[test]
    fn parses_4byte_selector_with_or_without_prefix() {
        assert_eq!(
            parse_selector("0xa9059cbb").unwrap(),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
        assert_eq!(
            parse_selector("a9059cbb").unwrap(),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
        assert!(parse_selector("0xa905").is_err());
    }

    #[test]
    fn proxy_slot_known_constants() {
        let (s, fb) = proxy_slot("implementation").unwrap();
        assert_eq!(s, EIP1967_IMPLEMENTATION_SLOT);
        assert_eq!(fb, Some(EIP1822_IMPLEMENTATION_SLOT));
        assert!(proxy_slot("nope").is_none());
    }

    /// Sanity-check the EIP-1967 slot constant against the spec
    /// definition (`keccak256("eip1967.proxy.implementation") - 1`).
    #[test]
    fn eip1967_implementation_slot_matches_keccak() {
        use alloy::primitives::keccak256;
        let h = keccak256(b"eip1967.proxy.implementation");
        let n = U256::from_be_bytes(h.0).wrapping_sub(U256::from(1u64));
        let expected = B256::from(n.to_be_bytes::<32>());
        assert_eq!(expected, EIP1967_IMPLEMENTATION_SLOT);
    }

    /// `enumerate_method_leaves` emits one .sig/.read/.tx triple per
    /// distinct function name, sorted alphabetically by name. Overloads
    /// (same name, different signature) collapse onto one set of
    /// leaves — disambiguation lives in `pick_function`.
    #[test]
    fn enumerate_method_leaves_emits_triple_per_function() {
        let abi: JsonAbi = serde_json::from_str(
            r#"[
                {"type":"function","name":"transfer","stateMutability":"nonpayable",
                 "inputs":[{"name":"to","type":"address"},{"name":"amt","type":"uint256"}],
                 "outputs":[{"name":"","type":"bool"}]},
                {"type":"function","name":"balanceOf","stateMutability":"view",
                 "inputs":[{"name":"o","type":"address"}],
                 "outputs":[{"name":"","type":"uint256"}]},
                {"type":"function","name":"transfer","stateMutability":"nonpayable",
                 "inputs":[{"name":"to","type":"address"}],
                 "outputs":[{"name":"","type":"bool"}]}
            ]"#,
        )
        .unwrap();
        let leaves = enumerate_method_leaves(&abi);
        let names: Vec<&str> = leaves.iter().map(|e| e.name.as_str()).collect();
        // Two distinct names -> 6 entries. Overloaded `transfer` collapses.
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
    }

    /// `enumerate_event_dirs` emits one directory per distinct event
    /// name, sorted alphabetically.
    #[test]
    fn enumerate_event_dirs_emits_one_per_event() {
        let abi: JsonAbi = serde_json::from_str(
            r#"[
                {"type":"event","name":"Transfer","anonymous":false,
                 "inputs":[{"name":"from","type":"address","indexed":true},
                           {"name":"to","type":"address","indexed":true},
                           {"name":"value","type":"uint256","indexed":false}]},
                {"type":"event","name":"Approval","anonymous":false,
                 "inputs":[{"name":"owner","type":"address","indexed":true},
                           {"name":"spender","type":"address","indexed":true},
                           {"name":"value","type":"uint256","indexed":false}]}
            ]"#,
        )
        .unwrap();
        let dirs = enumerate_event_dirs(&abi);
        let names: Vec<&str> = dirs.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["Approval", "Transfer"]);
        for d in &dirs {
            assert_eq!(d.kind, crate::handler::EntryKind::Dir);
        }
    }
}
