//! NFT (ERC-721 / ERC-1155) surface under `chains/<chain>/`.
//!
//! Wired from `chains.rs`. Two subtrees are owned here:
//!
//! - `addresses/<a>/nfts/...` — per-holder views: history (`erc721_txs`,
//!   `erc1155_txs`), best-effort holdings (`owned.json`), and per-token
//!   reads (`<contract>/<id>/{owner,uri,metadata.json,balance,is_owner,
//!   approved}`).
//! - `contracts/<a>/nft/...` — collection views: `kind`, `name`,
//!   `symbol`, `total_supply`, `owner_of/<id>`, `token_uri/<id>`,
//!   `is_approved_for_all/<owner>/<operator>`.
//!
//! ERC-721 vs ERC-1155 is auto-detected via ERC-165 `supportsInterface`
//! and cached per `(chain_id, contract)` for the lifetime of the
//! handler. Per-token RPC reads are always available; history /
//! holdings discovery requires an Etherscan-backed `address_history`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, U256};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use parking_lot::RwLock;
use serde_json::json;
use tracing::debug;

use bloom_chain::{ChainClient, NftKind};
use bloom_etherscan::{AddressHistorySource, DataSourceError, Sort};
use bloom_proto::checksum_address;

use crate::handler::HandlerError;

use super::chains_history::map_err as map_data_err;

/// Files exposed under `nfts/<contract>/<token_id>/`.
pub(crate) const PER_TOKEN_LEAVES: &[&str] = &[
    "owner",
    "uri",
    "metadata.json",
    "balance",
    "is_owner",
    "approved",
];

/// Files exposed under `contracts/<a>/nft/`. `owner_of`, `token_uri`,
/// and `is_approved_for_all` are directories, not files.
pub(crate) const NFT_COLLECTION_LEAVES: &[&str] = &["kind", "name", "symbol", "total_supply"];

pub(crate) const NFT_COLLECTION_DIRS: &[&str] = &["owner_of", "token_uri", "is_approved_for_all"];

/// Files at `addresses/<a>/nfts/`.
pub(crate) const NFT_HOLDER_LEAVES: &[&str] = &["erc721_txs", "erc1155_txs", "owned.json"];

/// Default page size for nft transfer listings (matches chains_history).
const DEFAULT_PAGE_SIZE: u32 = 50;

/// HTTP fetch ceilings for `metadata.json` reads.
const METADATA_TIMEOUT: Duration = Duration::from_secs(5);
const METADATA_MAX_BYTES: usize = 1024 * 1024;

/// Public IPFS gateway used for `ipfs://` rewrites.
const IPFS_GATEWAY: &str = "https://ipfs.io/ipfs/";

/// Process-wide cache for ERC-165 detection results. Interface support
/// is immutable for the lifetime of a contract, so we don't TTL it.
#[derive(Debug, Default)]
pub struct NftKindCache {
    inner: RwLock<HashMap<(u64, Address), NftKind>>,
}

impl NftKindCache {
    pub fn new() -> Self {
        Self::default()
    }
    fn get(&self, chain_id: u64, addr: Address) -> Option<NftKind> {
        self.inner.read().get(&(chain_id, addr)).copied()
    }
    fn put(&self, chain_id: u64, addr: Address, kind: NftKind) {
        self.inner.write().insert((chain_id, addr), kind);
    }
    /// Test-only seam: lets handler tests pre-populate the kind so they
    /// don't need to mock multiple `supportsInterface` calls in sequence.
    /// The mock RPC used by these tests answers each method with a
    /// single canned response, but `nft_detect` issues two ERC-165 calls
    /// in sequence, so seeding the cache is the cleanest workaround.
    #[cfg(test)]
    pub(crate) fn seed(&self, chain_id: u64, addr: Address, kind: NftKind) {
        self.put(chain_id, addr, kind);
    }
}

/// Detect (with cache) the NFT kind of `addr` on `client`'s chain.
pub async fn detect_kind(
    cache: &NftKindCache,
    client: &ChainClient,
    addr: Address,
) -> Result<NftKind, HandlerError> {
    let chain_id = client.spec().chain_id;
    if let Some(k) = cache.get(chain_id, addr) {
        return Ok(k);
    }
    let k = client.nft_detect(addr).await.map_err(err_be)?;
    cache.put(chain_id, addr, k);
    Ok(k)
}

fn err_be(e: impl std::fmt::Display) -> HandlerError {
    HandlerError::backend(e.to_string())
}

fn map_es_err(e: DataSourceError) -> HandlerError {
    map_data_err(e)
}

fn json_bytes<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, HandlerError> {
    let mut bytes = serde_json::to_vec_pretty(v).map_err(err_be)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Parse a token id segment as a U256 (decimal).
pub fn parse_token_id(s: &str) -> Result<U256, HandlerError> {
    s.parse::<U256>()
        .map_err(|e| HandlerError::invalid(format!("token id: {e}")))
}

/// ERC-1155 metadata `{id}` substitution: lowercase 64-char hex, no `0x`.
pub fn substitute_id_placeholder(uri: &str, token_id: U256) -> String {
    if !uri.contains("{id}") {
        return uri.to_string();
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&token_id.to_be_bytes::<32>());
    let hex_id = hex::encode(bytes); // 64 chars, lowercase, no 0x
    uri.replace("{id}", &hex_id)
}

/// Fetch metadata bytes from a `data:`, `ipfs://`, or `http(s)://` URI.
/// Caps response size at 1 MiB and total time at 5s.
pub async fn fetch_metadata(uri: &str) -> Result<Vec<u8>, HandlerError> {
    if let Some(rest) = uri.strip_prefix("data:") {
        return decode_data_uri(rest);
    }
    let url = if let Some(p) = uri.strip_prefix("ipfs://") {
        let p = p.strip_prefix("ipfs/").unwrap_or(p);
        format!("{IPFS_GATEWAY}{p}")
    } else if uri.starts_with("http://") || uri.starts_with("https://") {
        uri.to_string()
    } else {
        return Err(HandlerError::backend(format!(
            "unsupported metadata URI scheme: {uri}"
        )));
    };
    fetch_http(&url).await
}

fn decode_data_uri(rest: &str) -> Result<Vec<u8>, HandlerError> {
    // `data:[<mediatype>][;base64],<data>`
    let comma = rest
        .find(',')
        .ok_or_else(|| HandlerError::backend("malformed data: URI"))?;
    let meta = &rest[..comma];
    let payload = &rest[comma + 1..];
    let is_b64 = meta.split(';').any(|s| s.eq_ignore_ascii_case("base64"));
    if is_b64 {
        B64.decode(payload)
            .map_err(|e| HandlerError::backend(format!("data: base64 decode: {e}")))
    } else {
        // URL-decode (best effort) — `serde_json::from_str` will catch
        // malformed JSON downstream if the caller pretty-prints.
        match urlencoding_decode(payload) {
            Some(s) => Ok(s.into_bytes()),
            None => Ok(payload.as_bytes().to_vec()),
        }
    }
}

fn urlencoding_decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && i + 2 < bytes.len() {
            let h = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
            let v = u8::from_str_radix(h, 16).ok()?;
            out.push(v);
            i += 3;
        } else if b == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

async fn fetch_http(url: &str) -> Result<Vec<u8>, HandlerError> {
    let client = reqwest::Client::builder()
        .timeout(METADATA_TIMEOUT)
        .build()
        .map_err(err_be)?;
    let resp = client.get(url).send().await.map_err(err_be)?;
    if !resp.status().is_success() {
        return Err(HandlerError::backend(format!(
            "metadata fetch {} returned {}",
            url,
            resp.status()
        )));
    }
    let bytes = resp.bytes().await.map_err(err_be)?;
    if bytes.len() > METADATA_MAX_BYTES {
        return Err(HandlerError::backend(format!(
            "metadata too large: {} bytes > {}",
            bytes.len(),
            METADATA_MAX_BYTES
        )));
    }
    Ok(bytes.to_vec())
}

/// Try to render `bytes` as pretty JSON; if it isn't JSON, return
/// the bytes as-is with a trailing newline.
pub fn pretty_or_raw(bytes: Vec<u8>) -> Vec<u8> {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Ok(mut pretty) = serde_json::to_vec_pretty(&v)
    {
        pretty.push(b'\n');
        return pretty;
    }
    let mut out = bytes;
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out
}

// --- per-holder history reads -----------------------------------------

pub async fn read_erc721_txs(
    es: &Arc<dyn AddressHistorySource>,
    chain_id: u64,
    addr: Address,
) -> Result<Vec<u8>, HandlerError> {
    let txs = es
        .get_nft_tx(
            chain_id,
            addr,
            None,
            0,
            99_999_999,
            1,
            DEFAULT_PAGE_SIZE,
            Sort::Desc,
        )
        .await
        .map_err(map_es_err)?;
    json_bytes(&txs)
}

pub async fn read_erc1155_txs(
    es: &Arc<dyn AddressHistorySource>,
    chain_id: u64,
    addr: Address,
) -> Result<Vec<u8>, HandlerError> {
    let txs = es
        .get_nft1155_tx(
            chain_id,
            addr,
            None,
            0,
            99_999_999,
            1,
            DEFAULT_PAGE_SIZE,
            Sort::Desc,
        )
        .await
        .map_err(map_es_err)?;
    json_bytes(&txs)
}

/// Best-effort holdings list derived from the ERC-721 transfer history
/// reported by Etherscan. We reduce in/out for `(contract, token_id)`
/// to "the holder == `addr` after the last transfer". This is not
/// authoritative — out-of-band transfers, missed history, or reorgs
/// will skew the result. Schema:
/// ```json
/// {
///   "caveat": "best-effort: reduced from etherscan tx history",
///   "tokens": [{"contract":"0x..","token_id":"123","standard":"erc721"}, ...]
/// }
/// ```
pub async fn read_owned(
    es: &Arc<dyn AddressHistorySource>,
    chain_id: u64,
    addr: Address,
) -> Result<Vec<u8>, HandlerError> {
    // Pull the tail of ERC-721 transfers. The page cap mirrors
    // `read_erc721_txs`; large collectors may not be fully resolved.
    let txs = es
        .get_nft_tx(
            chain_id,
            addr,
            None,
            0,
            99_999_999,
            1,
            DEFAULT_PAGE_SIZE,
            Sort::Asc, // chronological reduce
        )
        .await
        .map_err(map_es_err)?;
    let me = format!("{:#x}", addr).to_ascii_lowercase();
    // Map (contract, token_id) -> last counterpart direction for `addr`.
    let mut owned: HashMap<(String, String), bool> = HashMap::new();
    for t in &txs {
        if t.token_id.is_empty() {
            continue;
        }
        let key = (t.contract_address.to_ascii_lowercase(), t.token_id.clone());
        let to_me = t.to.to_ascii_lowercase() == me;
        let from_me = t.from.to_ascii_lowercase() == me;
        if to_me {
            owned.insert(key, true);
        } else if from_me {
            owned.insert(key, false);
        }
    }
    let mut tokens: Vec<serde_json::Value> = owned
        .into_iter()
        .filter(|(_, holds)| *holds)
        .map(|((c, id), _)| {
            json!({
                "contract": c,
                "token_id": id,
                "standard": "erc721",
            })
        })
        .collect();
    tokens.sort_by(|a, b| {
        a["contract"]
            .as_str()
            .cmp(&b["contract"].as_str())
            .then(a["token_id"].as_str().cmp(&b["token_id"].as_str()))
    });
    let body = json!({
        "caveat": "best-effort: reduced from etherscan tx history; not authoritative",
        "tokens": tokens,
    });
    json_bytes(&body)
}

// --- per-token reads --------------------------------------------------

pub async fn read_per_token_owner(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
    token_id: U256,
) -> Result<Vec<u8>, HandlerError> {
    match detect_kind(cache, client, contract).await? {
        NftKind::Unknown => Err(HandlerError::invalid("not an NFT contract")),
        NftKind::Erc1155 => Ok(b"not applicable\n".to_vec()),
        NftKind::Erc721 => {
            let owner = client
                .erc721_owner_of(contract, token_id)
                .await
                .map_err(err_be)?
                .ok_or_else(|| HandlerError::backend("ownerOf reverted"))?;
            Ok(format!("{}\n", checksum_address(&owner)).into_bytes())
        }
    }
}

pub async fn read_per_token_uri(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
    token_id: U256,
) -> Result<Vec<u8>, HandlerError> {
    let uri = resolve_uri(cache, client, contract, token_id).await?;
    Ok(format!("{}\n", uri).into_bytes())
}

/// Resolve `tokenURI` (ERC-721) or `uri` (ERC-1155) and substitute
/// `{id}` for ERC-1155.
pub async fn resolve_uri(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
    token_id: U256,
) -> Result<String, HandlerError> {
    match detect_kind(cache, client, contract).await? {
        NftKind::Unknown => Err(HandlerError::invalid("not an NFT contract")),
        NftKind::Erc721 => client
            .erc721_token_uri(contract, token_id)
            .await
            .map_err(err_be)?
            .ok_or_else(|| HandlerError::backend("tokenURI reverted")),
        NftKind::Erc1155 => {
            let raw = client
                .erc1155_uri(contract, token_id)
                .await
                .map_err(err_be)?
                .ok_or_else(|| HandlerError::backend("uri reverted"))?;
            Ok(substitute_id_placeholder(&raw, token_id))
        }
    }
}

pub async fn read_per_token_metadata(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
    token_id: U256,
) -> Result<Vec<u8>, HandlerError> {
    let uri = resolve_uri(cache, client, contract, token_id).await?;
    debug!(uri = %uri, "nft.metadata.fetch");
    let bytes = fetch_metadata(&uri).await?;
    Ok(pretty_or_raw(bytes))
}

pub async fn read_per_token_balance(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
    holder: Address,
    token_id: U256,
) -> Result<Vec<u8>, HandlerError> {
    let n = balance_for(cache, client, contract, holder, token_id).await?;
    Ok(format!("{}\n", n).into_bytes())
}

pub async fn read_per_token_is_owner(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
    holder: Address,
    token_id: U256,
) -> Result<Vec<u8>, HandlerError> {
    let n = balance_for(cache, client, contract, holder, token_id).await?;
    let yes = n > U256::ZERO;
    Ok(format!("{}\n", yes).into_bytes())
}

async fn balance_for(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
    holder: Address,
    token_id: U256,
) -> Result<U256, HandlerError> {
    match detect_kind(cache, client, contract).await? {
        NftKind::Unknown => Err(HandlerError::invalid("not an NFT contract")),
        NftKind::Erc721 => {
            let owner = client
                .erc721_owner_of(contract, token_id)
                .await
                .map_err(err_be)?
                .ok_or_else(|| HandlerError::backend("ownerOf reverted"))?;
            Ok(if owner == holder {
                U256::from(1u64)
            } else {
                U256::ZERO
            })
        }
        NftKind::Erc1155 => client
            .erc1155_balance_of(contract, holder, token_id)
            .await
            .map_err(err_be)?
            .ok_or_else(|| HandlerError::backend("balanceOf reverted")),
    }
}

pub async fn read_per_token_approved(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
    token_id: U256,
) -> Result<Vec<u8>, HandlerError> {
    match detect_kind(cache, client, contract).await? {
        NftKind::Unknown => Err(HandlerError::invalid("not an NFT contract")),
        NftKind::Erc1155 => Ok(b"not applicable\n".to_vec()),
        NftKind::Erc721 => {
            let op = client
                .erc721_get_approved(contract, token_id)
                .await
                .map_err(err_be)?
                .ok_or_else(|| HandlerError::backend("getApproved reverted"))?;
            Ok(format!("{}\n", checksum_address(&op)).into_bytes())
        }
    }
}

// --- collection reads -------------------------------------------------

pub async fn read_collection_kind(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
) -> Result<Vec<u8>, HandlerError> {
    let s = match detect_kind(cache, client, contract).await? {
        NftKind::Erc721 => "erc721",
        NftKind::Erc1155 => "erc1155",
        NftKind::Unknown => "unknown",
    };
    Ok(format!("{}\n", s).into_bytes())
}

pub async fn read_collection_name(
    client: &ChainClient,
    contract: Address,
) -> Result<Vec<u8>, HandlerError> {
    let n = client
        .erc721_name(contract)
        .await
        .map_err(err_be)?
        .unwrap_or_default();
    Ok(format!("{}\n", n).into_bytes())
}

pub async fn read_collection_symbol(
    client: &ChainClient,
    contract: Address,
) -> Result<Vec<u8>, HandlerError> {
    let s = client
        .erc721_symbol(contract)
        .await
        .map_err(err_be)?
        .unwrap_or_default();
    Ok(format!("{}\n", s).into_bytes())
}

pub async fn read_collection_total_supply(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
) -> Result<Vec<u8>, HandlerError> {
    // Validate the contract is at least an NFT — we don't want
    // totalSupply() lying about a random contract.
    if matches!(
        detect_kind(cache, client, contract).await?,
        NftKind::Unknown
    ) {
        return Err(HandlerError::invalid("not an NFT contract"));
    }
    match client.erc721_total_supply(contract).await.map_err(err_be)? {
        Some(n) => Ok(format!("{}\n", n).into_bytes()),
        None => Ok(b"unknown\n".to_vec()),
    }
}

pub async fn read_collection_owner_of(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
    token_id: U256,
) -> Result<Vec<u8>, HandlerError> {
    read_per_token_owner(cache, client, contract, token_id).await
}

pub async fn read_collection_token_uri(
    cache: &NftKindCache,
    client: &ChainClient,
    contract: Address,
    token_id: U256,
) -> Result<Vec<u8>, HandlerError> {
    read_per_token_uri(cache, client, contract, token_id).await
}

pub async fn read_collection_is_approved_for_all(
    client: &ChainClient,
    contract: Address,
    owner: Address,
    operator: Address,
) -> Result<Vec<u8>, HandlerError> {
    let yes = client
        .is_approved_for_all(contract, owner, operator)
        .await
        .map_err(err_be)?
        .ok_or_else(|| HandlerError::backend("isApprovedForAll reverted"))?;
    Ok(format!("{}\n", yes).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_id_lowercase_64chars_no_0x() {
        let uri = "https://example/{id}.json";
        let out = substitute_id_placeholder(uri, U256::from(1u64));
        // 64 hex chars, all zeros except the last "01".
        let expected = format!(
            "https://example/{}.json",
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn substitute_id_no_placeholder_is_passthrough() {
        let uri = "ipfs://Qm.../1.json";
        assert_eq!(substitute_id_placeholder(uri, U256::from(7u64)), uri);
    }

    #[test]
    fn parse_token_id_decimal() {
        assert_eq!(parse_token_id("123").unwrap(), U256::from(123u64));
        assert!(parse_token_id("not-a-number").is_err());
    }

    #[tokio::test]
    async fn fetch_metadata_data_uri_plain_json() {
        let uri = r#"data:application/json,{"name":"x"}"#;
        let bytes = fetch_metadata(uri).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["name"], "x");
    }

    #[tokio::test]
    async fn fetch_metadata_data_uri_base64() {
        let payload = B64.encode(br#"{"name":"y"}"#);
        let uri = format!("data:application/json;base64,{payload}");
        let bytes = fetch_metadata(&uri).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["name"], "y");
    }

    #[tokio::test]
    async fn fetch_metadata_unsupported_scheme() {
        let err = fetch_metadata("ftp://example.com/x.json")
            .await
            .unwrap_err();
        match err {
            HandlerError::Backend(s) => assert!(s.contains("unsupported")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_metadata_data_uri_url_encoded() {
        // Some marketplaces emit data:application/json,<URL-encoded JSON>.
        let uri = "data:application/json,%7B%22name%22%3A%22z%22%7D";
        let bytes = fetch_metadata(uri).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["name"], "z");
    }

    #[test]
    fn pretty_or_raw_round_trip_json() {
        let bytes = b"{\"a\":1}".to_vec();
        let out = pretty_or_raw(bytes);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(*out.last().unwrap(), b'\n');
    }

    #[test]
    fn pretty_or_raw_passthrough_non_json() {
        let bytes = b"not json".to_vec();
        let out = pretty_or_raw(bytes);
        assert!(out.ends_with(b"\n"));
        assert!(out.starts_with(b"not json"));
    }
}
