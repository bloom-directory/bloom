//! DefiLlama price client.
//!
//! Thin async client around the public DefiLlama coins API
//! (`https://coins.llama.fi`). The endpoint is keyless, free, and supports
//! current spot, historical, chart, and 24h-percentage queries.
//!
//! Coins are addressed by [`CoinId`]:
//!
//! - [`CoinId::Erc20`] — `ethereum:0x...`, `polygon:0x...` etc.
//! - [`CoinId::Native`] — chain native (`ethereum`, `polygon`, ...) which
//!   DefiLlama exposes as `coingecko:<slug>` for most chains.
//! - [`CoinId::Symbol`] — common ticker (`ETH`, `USDC`, ...) resolved via a
//!   small built-in table to either a coingecko slug or an erc20 id.
//!
//! See the spec at `docs/specs/2026-05-08-bloom-design.md` §3.7 / §5.4.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

const DEFAULT_BASE_URL: &str = "https://coins.llama.fi";
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by [`PricesClient`].
#[derive(thiserror::Error, Debug)]
pub enum PricesError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("api error: {0}")]
    Api(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("disabled")]
    Disabled,
    #[error("invalid coin id: {0}")]
    InvalidCoinId(String),
}

// ---------------------------------------------------------------------------
// Coin identifiers
// ---------------------------------------------------------------------------

/// Identifier of a coin / token understood by DefiLlama.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CoinId {
    /// ERC20-style token: `chain:0x..address..`. `chain` is a DefiLlama chain
    /// slug (`ethereum`, `polygon`, `optimism`, `base`, `arbitrum`, ...).
    Erc20 { chain: String, address: String },
    /// Native chain coin. Internally we prefer the `coingecko:<slug>` form
    /// since it is the most reliable on DefiLlama.
    Native(String),
    /// Common ticker symbol (`ETH`, `USDC`, ...). Resolved at query time
    /// against a small built-in table.
    Symbol(String),
}

impl CoinId {
    /// Render to the wire form DefiLlama expects (`<chain>:<address>` or
    /// `coingecko:<slug>`).
    pub fn to_query(&self) -> String {
        match self {
            CoinId::Erc20 { chain, address } => format!("{}:{}", chain, address.to_lowercase()),
            CoinId::Native(s) => resolve_native(s).unwrap_or_else(|| s.clone()),
            CoinId::Symbol(s) => resolve_symbol(s).unwrap_or_else(|| s.clone()),
        }
    }

    /// Try to construct from a `chain:address` or `coingecko:slug` string.
    pub fn parse(s: &str) -> Result<CoinId, PricesError> {
        let (left, right) = s
            .split_once(':')
            .ok_or_else(|| PricesError::InvalidCoinId(s.to_string()))?;
        if left.eq_ignore_ascii_case("native") {
            return Ok(CoinId::Native(right.to_ascii_lowercase()));
        }
        if left.eq_ignore_ascii_case("coingecko") {
            return Ok(CoinId::Native(format!("coingecko:{right}")));
        }
        if right.starts_with("0x") || right.starts_with("0X") {
            return Ok(CoinId::Erc20 {
                chain: left.to_ascii_lowercase(),
                address: right.to_ascii_lowercase(),
            });
        }
        Err(PricesError::InvalidCoinId(s.to_string()))
    }
}

/// Single source of truth for built-in symbols: (lowercase ticker, wire id).
pub const SYMBOL_MAP: &[(&str, &str)] = &[
    ("eth", "coingecko:ethereum"),
    ("btc", "coingecko:bitcoin"),
    (
        "usdc",
        "ethereum:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    ),
    (
        "usdt",
        "ethereum:0xdac17f958d2ee523a2206206994597c13d831ec7",
    ),
    ("dai", "ethereum:0x6b175474e89094c44da98b954eedeac495271d0f"),
    (
        "weth",
        "ethereum:0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    ),
];

fn resolve_symbol(sym: &str) -> Option<String> {
    let s = sym.trim().to_ascii_lowercase();
    SYMBOL_MAP
        .iter()
        .find(|(k, _)| *k == s.as_str())
        .map(|(_, v)| v.to_string())
}

/// Resolve a native-chain identifier to a wire id (coingecko slug).
fn resolve_native(chain: &str) -> Option<String> {
    let s = chain.trim().to_ascii_lowercase();
    // DefiLlama already accepts these forms; we mostly upgrade bare chain
    // names to coingecko slugs.
    Some(
        match s.as_str() {
            "ethereum" | "mainnet" | "anvil" | "local" => "coingecko:ethereum",
            "bitcoin" => "coingecko:bitcoin",
            "polygon" | "matic" => "coingecko:matic-network",
            "optimism" => "coingecko:ethereum", // OP chain native is ETH
            "arbitrum" => "coingecko:ethereum", // arb native is ETH
            "base" => "coingecko:ethereum",     // base native is ETH
            other if other.starts_with("coingecko:") => other,
            _ => return None,
        }
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Quote / point types
// ---------------------------------------------------------------------------

/// Price quote for a single coin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriceQuote {
    pub price: f64,
    pub decimals: Option<u8>,
    pub symbol: Option<String>,
    pub timestamp: u64,
    pub confidence: Option<f64>,
}

/// Single point on a price chart.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PricePoint {
    pub timestamp: u64,
    pub price: f64,
}

// ---------------------------------------------------------------------------
// Wire types (serde-only; never leak)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CoinsResp {
    #[serde(default)]
    coins: HashMap<String, CoinEntry>,
}

#[derive(Debug, Deserialize)]
struct CoinEntry {
    price: f64,
    #[serde(default)]
    decimals: Option<u8>,
    #[serde(default)]
    symbol: Option<String>,
    #[serde(default)]
    timestamp: Option<u64>,
    #[serde(default)]
    confidence: Option<f64>,
}

impl CoinEntry {
    fn into_quote(self) -> PriceQuote {
        PriceQuote {
            price: self.price,
            decimals: self.decimals,
            symbol: self.symbol,
            timestamp: self.timestamp.unwrap_or(0),
            confidence: self.confidence,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ChartResp {
    #[serde(default)]
    coins: HashMap<String, ChartEntry>,
}

#[derive(Debug, Deserialize)]
struct ChartEntry {
    #[serde(default)]
    prices: Vec<ChartPoint>,
}

#[derive(Debug, Deserialize)]
struct ChartPoint {
    timestamp: u64,
    price: f64,
}

#[derive(Debug, Deserialize)]
struct PercentageResp {
    #[serde(default)]
    coins: HashMap<String, f64>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Async client for the DefiLlama coins API.
#[derive(Debug, Clone)]
pub struct PricesClient {
    base_url: String,
    http: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, CachedQuote>>>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct CachedQuote {
    quote: PriceQuote,
    fetched_at: Instant,
}

impl Default for PricesClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PricesClient {
    /// Create a client pointed at the public DefiLlama endpoint.
    pub fn new() -> Self {
        Self::with_base_url(DEFAULT_BASE_URL)
    }

    /// Create a client pointed at a custom base URL (handy for tests).
    pub fn with_base_url(url: impl Into<String>) -> Self {
        Self {
            base_url: url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl: DEFAULT_CACHE_TTL,
        }
    }

    /// Override the positive-cache TTL (default 30s).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Base URL the client is configured against.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Cache TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    // ----- public API ------------------------------------------------------

    /// Fetch the current price for a single coin.
    pub async fn current(&self, coin: CoinId) -> Result<PriceQuote, PricesError> {
        let key = wire_key(&coin)?;
        if let Some(q) = self.cache_get(&key) {
            debug!(%key, "prices.cache.hit");
            return Ok(q);
        }
        let mut got = self.fetch_current(std::slice::from_ref(&key)).await?;
        let quote = got.remove(&key).ok_or_else(|| {
            debug!(%key, "prices.current.coin_missing");
            PricesError::NotFound(key.clone())
        })?;
        self.cache_put(&key, &quote);
        Ok(quote)
    }

    /// Fetch the current price for many coins in a single request.
    ///
    /// Returns a map keyed by the *input* `CoinId` (so callers don't have to
    /// re-derive the wire form). Coins missing from the response are simply
    /// absent from the result map — this is not an error.
    pub async fn current_many(
        &self,
        coins: &[CoinId],
    ) -> Result<HashMap<CoinId, PriceQuote>, PricesError> {
        if coins.is_empty() {
            return Ok(HashMap::new());
        }

        let mut out: HashMap<CoinId, PriceQuote> = HashMap::new();
        let mut to_fetch_keys: Vec<String> = Vec::new();
        let mut to_fetch_pairs: Vec<(String, CoinId)> = Vec::new();

        for c in coins {
            let key = wire_key(c)?;
            if let Some(q) = self.cache_get(&key) {
                out.insert(c.clone(), q);
            } else {
                to_fetch_keys.push(key.clone());
                to_fetch_pairs.push((key, c.clone()));
            }
        }

        if !to_fetch_keys.is_empty() {
            let fetched = self.fetch_current(&to_fetch_keys).await?;
            for (key, coin) in to_fetch_pairs {
                if let Some(q) = fetched.get(&key) {
                    self.cache_put(&key, q);
                    out.insert(coin, q.clone());
                } else {
                    // The upstream silently omits unknown coins from the
                    // response; surface so callers can tell a miss apart
                    // from a transport failure.
                    debug!(%key, "prices.current_many.coin_missing");
                }
            }
        }

        Ok(out)
    }

    /// Fetch the historical price at a unix timestamp.
    pub async fn historical(&self, coin: CoinId, ts: u64) -> Result<PriceQuote, PricesError> {
        let key = wire_key(&coin)?;
        let url = format!("{}/prices/historical/{}/{}", self.base_url, ts, key);
        let resp: CoinsResp = self.get_json(&url).await?;
        resp.coins
            .into_iter()
            .find(|(k, _)| k == &key)
            .map(|(_, e)| e.into_quote())
            .ok_or_else(|| {
                debug!(%key, ts, "prices.historical.coin_missing");
                PricesError::NotFound(key)
            })
    }

    /// Fetch a price chart between two timestamps.
    ///
    /// `period` follows DefiLlama's syntax: e.g. `"1h"`, `"4h"`, `"1d"`.
    pub async fn chart(
        &self,
        coin: CoinId,
        start_ts: u64,
        end_ts: u64,
        period: &str,
    ) -> Result<Vec<PricePoint>, PricesError> {
        let key = wire_key(&coin)?;
        if end_ts < start_ts {
            return Err(PricesError::Api(format!(
                "end_ts ({end_ts}) before start_ts ({start_ts})"
            )));
        }
        let span = end_ts.saturating_sub(start_ts);
        let url = format!(
            "{}/chart/{}?start={}&span={}&period={}",
            self.base_url, key, start_ts, span, period
        );
        let resp: ChartResp = self.get_json(&url).await?;
        let entry = resp
            .coins
            .into_iter()
            .find(|(k, _)| k == &key)
            .map(|(_, e)| e)
            .ok_or_else(|| {
                debug!(%key, start_ts, end_ts, period, "prices.chart.coin_missing");
                PricesError::NotFound(key)
            })?;
        Ok(entry
            .prices
            .into_iter()
            .map(|p| PricePoint {
                timestamp: p.timestamp,
                price: p.price,
            })
            .collect())
    }

    /// Fetch the trailing 24h percentage change for a coin.
    pub async fn change_24h(&self, coin: CoinId) -> Result<f64, PricesError> {
        let key = wire_key(&coin)?;
        let url = format!(
            "{}/percentage/{}?lookForward=false&period=24h",
            self.base_url, key
        );
        let resp: PercentageResp = self.get_json(&url).await?;
        resp.coins
            .into_iter()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v)
            .ok_or_else(|| {
                debug!(%key, "prices.change_24h.coin_missing");
                PricesError::NotFound(key)
            })
    }

    // ----- internals -------------------------------------------------------

    async fn fetch_current(
        &self,
        keys: &[String],
    ) -> Result<HashMap<String, PriceQuote>, PricesError> {
        let joined = keys.join(",");
        let url = format!("{}/prices/current/{}", self.base_url, joined);
        let resp: CoinsResp = self.get_json(&url).await?;
        Ok(resp
            .coins
            .into_iter()
            .map(|(k, v)| (k, v.into_quote()))
            .collect())
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, PricesError> {
        debug!(%url, "prices.http.get");
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(PricesError::Api(format!("{}: {}", status.as_u16(), body)));
        }
        serde_json::from_str(&body).map_err(|e| {
            warn!(%url, error = %e, body_preview = %body.chars().take(200).collect::<String>(), "prices.json.decode_failed");
            PricesError::Json(e)
        })
    }

    fn cache_get(&self, key: &str) -> Option<PriceQuote> {
        let g = self.cache.read();
        let entry = g.get(key)?;
        let age = entry.fetched_at.elapsed();
        if age > self.ttl {
            debug!(%key, ?age, ttl = ?self.ttl, "prices.cache.expired");
            return None;
        }
        Some(entry.quote.clone())
    }

    fn cache_put(&self, key: &str, quote: &PriceQuote) {
        let mut g = self.cache.write();
        g.insert(
            key.to_string(),
            CachedQuote {
                quote: quote.clone(),
                fetched_at: Instant::now(),
            },
        );
    }
}

/// Render a coin id to wire form, rejecting symbols / chains we can't
/// resolve.
fn wire_key(coin: &CoinId) -> Result<String, PricesError> {
    match coin {
        CoinId::Erc20 { chain, address } => {
            if !address.starts_with("0x") && !address.starts_with("0X") {
                return Err(PricesError::InvalidCoinId(format!(
                    "erc20 address must start with 0x: {address}"
                )));
            }
            Ok(format!("{}:{}", chain, address.to_lowercase()))
        }
        CoinId::Native(s) => resolve_native(s)
            .ok_or_else(|| PricesError::InvalidCoinId(format!("unknown native chain: {s}"))),
        CoinId::Symbol(s) => resolve_symbol(s)
            .ok_or_else(|| PricesError::InvalidCoinId(format!("unknown symbol: {s}"))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spin up a one-shot HTTP server on a random local port. It accepts a
    /// single connection, reads the request, and writes back the canned
    /// response. Returns the bound base URL (`http://127.0.0.1:PORT`).
    async fn one_shot_server(response_body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        let handle = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                // Best-effort read of the request line / headers.
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        (format!("http://{addr}"), handle)
    }

    /// Mini-server that handles N sequential requests with the same body.
    async fn n_shot_server(
        response_body: &'static str,
        n: usize,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        let handle = tokio::spawn(async move {
            for _ in 0..n {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let resp = resp.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let _ = sock.read(&mut buf).await;
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    });
                }
            }
        });
        (format!("http://{addr}"), handle)
    }

    // Silence unused warnings on `Read` / `Write` for some toolchains.
    #[allow(dead_code)]
    fn _force_use(_: &dyn Read, _: &dyn Write) {}

    #[test]
    fn coin_id_to_query_renders_erc20() {
        let c = CoinId::Erc20 {
            chain: "ethereum".into(),
            address: "0xA0b86991C6218B36c1d19D4a2e9Eb0cE3606eB48".into(),
        };
        assert_eq!(
            c.to_query(),
            "ethereum:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        );
    }

    #[test]
    fn coin_id_to_query_renders_symbol() {
        assert_eq!(
            CoinId::Symbol("ETH".into()).to_query(),
            "coingecko:ethereum"
        );
        assert_eq!(
            CoinId::Symbol("eth".into()).to_query(),
            "coingecko:ethereum"
        );
        assert_eq!(
            CoinId::Symbol("USDC".into()).to_query(),
            "ethereum:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        );
    }

    #[test]
    fn coin_id_to_query_renders_native() {
        assert_eq!(
            CoinId::Native("ethereum".into()).to_query(),
            "coingecko:ethereum"
        );
        assert_eq!(
            CoinId::Native("polygon".into()).to_query(),
            "coingecko:matic-network"
        );
    }

    #[test]
    fn coin_id_parse_round_trips_erc20() {
        let parsed = CoinId::parse("ethereum:0xA0b86991C6218B36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        match parsed {
            CoinId::Erc20 { chain, address } => {
                assert_eq!(chain, "ethereum");
                assert_eq!(address, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
            }
            _ => panic!("expected erc20"),
        }
    }

    #[test]
    fn coin_id_parse_accepts_canonical_native_asset_ids() {
        assert_eq!(
            CoinId::parse("native:base").unwrap().to_query(),
            "coingecko:ethereum"
        );
        assert_eq!(
            CoinId::parse("native:anvil").unwrap().to_query(),
            "coingecko:ethereum"
        );
        assert_eq!(
            CoinId::parse("native:polygon").unwrap().to_query(),
            "coingecko:matic-network"
        );
    }

    #[test]
    fn coin_id_parse_rejects_garbage() {
        assert!(matches!(
            CoinId::parse("nope"),
            Err(PricesError::InvalidCoinId(_))
        ));
    }

    #[test]
    fn wire_key_rejects_unknown_symbol() {
        let err = wire_key(&CoinId::Symbol("XYZBOGUS".into())).unwrap_err();
        assert!(matches!(err, PricesError::InvalidCoinId(_)));
    }

    #[test]
    fn wire_key_rejects_bad_address() {
        let err = wire_key(&CoinId::Erc20 {
            chain: "ethereum".into(),
            address: "deadbeef".into(),
        })
        .unwrap_err();
        assert!(matches!(err, PricesError::InvalidCoinId(_)));
    }

    #[test]
    fn error_display_strings() {
        assert_eq!(PricesError::Disabled.to_string(), "disabled");
        assert_eq!(
            PricesError::NotFound("k".into()).to_string(),
            "not found: k"
        );
        assert_eq!(
            PricesError::Api("boom".into()).to_string(),
            "api error: boom"
        );
    }

    #[tokio::test]
    async fn current_decodes_quote() {
        let body = r#"{"coins":{"coingecko:ethereum":{"price":3500.5,"symbol":"ETH","timestamp":1700000000,"confidence":0.99,"decimals":18}}}"#;
        let (url, _h) = one_shot_server(body).await;
        let client = PricesClient::with_base_url(url);
        let q = client.current(CoinId::Symbol("ETH".into())).await.unwrap();
        assert_eq!(q.price, 3500.5);
        assert_eq!(q.symbol.as_deref(), Some("ETH"));
        assert_eq!(q.decimals, Some(18));
        assert_eq!(q.timestamp, 1700000000);
        assert_eq!(q.confidence, Some(0.99));
    }

    #[tokio::test]
    async fn current_uses_cache_within_ttl() {
        let body = r#"{"coins":{"coingecko:ethereum":{"price":1.0,"symbol":"ETH","timestamp":1}}}"#;
        // Only one request will be served — second call must hit the cache.
        let (url, _h) = one_shot_server(body).await;
        let client = PricesClient::with_base_url(url).with_ttl(Duration::from_secs(60));
        let q1 = client.current(CoinId::Symbol("ETH".into())).await.unwrap();
        let q2 = client.current(CoinId::Symbol("ETH".into())).await.unwrap();
        assert_eq!(q1, q2);
    }

    #[tokio::test]
    async fn current_returns_not_found_when_missing() {
        let body = r#"{"coins":{}}"#;
        let (url, _h) = one_shot_server(body).await;
        let client = PricesClient::with_base_url(url);
        let err = client
            .current(CoinId::Symbol("ETH".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, PricesError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn current_many_collects_results() {
        let body = r#"{"coins":{
            "coingecko:ethereum":{"price":3000.0,"symbol":"ETH","timestamp":1},
            "ethereum:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48":{"price":1.0,"symbol":"USDC","timestamp":1}
        }}"#;
        let (url, _h) = one_shot_server(body).await;
        let client = PricesClient::with_base_url(url);
        let coins = vec![CoinId::Symbol("ETH".into()), CoinId::Symbol("USDC".into())];
        let got = client.current_many(&coins).await.unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.contains_key(&CoinId::Symbol("ETH".into())));
        assert!(got.contains_key(&CoinId::Symbol("USDC".into())));
        assert_eq!(got[&CoinId::Symbol("USDC".into())].price, 1.0);
    }

    #[tokio::test]
    async fn current_many_empty_input_short_circuits() {
        let client = PricesClient::with_base_url("http://127.0.0.1:1");
        let got = client.current_many(&[]).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn historical_returns_quote() {
        let body = r#"{"coins":{"coingecko:ethereum":{"price":1900.0,"symbol":"ETH","timestamp":1600000000}}}"#;
        let (url, _h) = one_shot_server(body).await;
        let client = PricesClient::with_base_url(url);
        let q = client
            .historical(CoinId::Symbol("ETH".into()), 1600000000)
            .await
            .unwrap();
        assert_eq!(q.price, 1900.0);
    }

    #[tokio::test]
    async fn chart_returns_points() {
        let body = r#"{"coins":{"coingecko:ethereum":{"prices":[
            {"timestamp":100,"price":1.0},
            {"timestamp":200,"price":2.0}
        ]}}}"#;
        let (url, _h) = one_shot_server(body).await;
        let client = PricesClient::with_base_url(url);
        let pts = client
            .chart(CoinId::Symbol("ETH".into()), 100, 300, "1h")
            .await
            .unwrap();
        assert_eq!(pts.len(), 2);
        assert_eq!(pts[0].timestamp, 100);
        assert_eq!(pts[1].price, 2.0);
    }

    #[tokio::test]
    async fn chart_rejects_inverted_range() {
        let client = PricesClient::with_base_url("http://127.0.0.1:1");
        let err = client
            .chart(CoinId::Symbol("ETH".into()), 200, 100, "1h")
            .await
            .unwrap_err();
        assert!(matches!(err, PricesError::Api(_)));
    }

    #[tokio::test]
    async fn change_24h_returns_value() {
        let body = r#"{"coins":{"coingecko:ethereum":2.5}}"#;
        let (url, _h) = one_shot_server(body).await;
        let client = PricesClient::with_base_url(url);
        let v = client
            .change_24h(CoinId::Symbol("ETH".into()))
            .await
            .unwrap();
        assert_eq!(v, 2.5);
    }

    #[tokio::test]
    async fn http_error_status_becomes_api_error() {
        // Hand-crafted 500 response.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let body = "boom";
                let resp = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        let client = PricesClient::with_base_url(url);
        let err = client
            .current(CoinId::Symbol("ETH".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, PricesError::Api(_)), "got {err:?}");
    }

    // Force compile-error if `n_shot_server` is unused in some configurations.
    #[allow(dead_code)]
    async fn _exercise_n_shot() {
        let _ = n_shot_server("{}", 1).await;
    }

    // -----------------------------------------------------------------
    // LIVE integration tests — gated by `--ignored`.
    // Run with: `cargo test -p bloom-prices -- --ignored`
    // -----------------------------------------------------------------

    #[tokio::test]
    #[ignore = "live: hits public DefiLlama"]
    async fn live_current_eth() {
        let client = PricesClient::new();
        let q = client
            .current(CoinId::Symbol("ETH".into()))
            .await
            .expect("live ETH price");
        assert!(
            q.price > 0.0,
            "expected positive ETH price, got {}",
            q.price
        );
    }

    #[tokio::test]
    #[ignore = "live: hits public DefiLlama"]
    async fn live_current_many_eth_usdc() {
        let client = PricesClient::new();
        let coins = vec![CoinId::Symbol("ETH".into()), CoinId::Symbol("USDC".into())];
        let got = client.current_many(&coins).await.expect("live multi");
        assert!(
            got.contains_key(&CoinId::Symbol("ETH".into())),
            "missing ETH: {got:?}"
        );
        assert!(
            got.contains_key(&CoinId::Symbol("USDC".into())),
            "missing USDC: {got:?}"
        );
    }

    #[tokio::test]
    #[ignore = "live: hits public DefiLlama"]
    async fn live_change_24h_eth_in_band() {
        let client = PricesClient::new();
        let v = client
            .change_24h(CoinId::Symbol("ETH".into()))
            .await
            .expect("live change");
        assert!((-100.0..1000.0).contains(&v), "out-of-band 24h change: {v}");
    }
}
