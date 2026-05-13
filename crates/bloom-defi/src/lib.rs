//! Enso DeFi intent client.
//!
//! Real client against the Enso Shortcuts API
//! (<https://api.enso.finance>). Handles single-step routes (swaps,
//! deposits, etc.) and multi-step bundles. Read/quote-oriented; no
//! broadcasting concerns live here — the resulting tx is staged through
//! the wallet outbox by the caller.
//!
//! ## Endpoints
//! - `POST /api/v1/shortcuts/route`  — single-step intent
//! - `POST /api/v1/shortcuts/bundle` — multi-step intent
//! - `GET  /api/v1/shortcuts/quote`  — non-committal price quote
//!
//! Auth is `Authorization: Bearer <key>` (preferred) or `?apiKey=` query.

#![forbid(unsafe_code)]

use alloy::primitives::{Address, Bytes, U256};
use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_BASE_URL: &str = "https://api.enso.finance";

/// Sentinel address Enso uses for the chain's native token (ETH, MATIC, …).
pub const NATIVE_TOKEN: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

#[derive(thiserror::Error, Debug)]
pub enum EnsoError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("url: {0}")]
    Url(#[from] url::ParseError),
    #[error("api {status}: {body}")]
    Api { status: u16, body: String },
    #[error("disabled: no api key configured")]
    Disabled,
    #[error("missing API key (set BLOOM_ENSO_KEY or ENSO_API_KEY)")]
    MissingKey,
    #[error("invalid intent: {0}")]
    InvalidIntent(String),
}

/// Routing strategy. Maps directly onto Enso's `routingStrategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RoutingStrategy {
    /// Through Enso's router contract (most common).
    #[default]
    Router,
    /// Inline via delegatecall (e.g. inside a Safe).
    Delegate,
    /// Through Enso's wallet contract.
    EnsoWallet,
}

impl RoutingStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            RoutingStrategy::Router => "router",
            RoutingStrategy::Delegate => "delegate",
            RoutingStrategy::EnsoWallet => "ensowallet",
        }
    }
}

/// Single-step route request. All addresses serialise as 0x-hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRequest {
    pub from_address: Address,
    pub chain_id: u64,
    pub token_in: Address,
    pub token_out: Address,
    /// Decimal stringified raw amount (token decimals applied by caller).
    pub amount_in: U256,
    /// Slippage in basis points (50 = 0.5%). Defaults to 50 server-side
    /// when omitted; we always pass it explicitly.
    pub slippage_bps: u16,
    pub routing_strategy: Option<RoutingStrategy>,
    pub receiver: Option<Address>,
}

impl RouteRequest {
    pub fn new(
        from_address: Address,
        chain_id: u64,
        token_in: Address,
        token_out: Address,
        amount_in: U256,
    ) -> Self {
        Self {
            from_address,
            chain_id,
            token_in,
            token_out,
            amount_in,
            slippage_bps: 50,
            routing_strategy: Some(RoutingStrategy::Router),
            receiver: None,
        }
    }

    /// Wire shape: Enso wants `tokenIn` / `amountIn` as **arrays** to
    /// support multi-input routes, plus `slippage` as bps integer string.
    fn to_query(&self) -> Vec<(&'static str, String)> {
        let mut q: Vec<(&'static str, String)> = vec![
            ("fromAddress", format!("0x{:x}", self.from_address)),
            ("chainId", self.chain_id.to_string()),
            ("tokenIn", format!("0x{:x}", self.token_in)),
            ("tokenOut", format!("0x{:x}", self.token_out)),
            ("amountIn", self.amount_in.to_string()),
            ("slippage", self.slippage_bps.to_string()),
        ];
        if let Some(s) = self.routing_strategy {
            q.push(("routingStrategy", s.as_str().to_string()));
        }
        if let Some(r) = self.receiver {
            q.push(("receiver", format!("0x{:x}", r)));
        }
        q
    }
}

/// One step in a multi-step bundle. Mirrors `RouteRequest` but token
/// arrays are explicit (Enso's bundle endpoint accepts heterogeneous
/// shapes per-action; we keep the common swap/deposit one).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleStep {
    pub protocol: String,
    pub action: String,
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleRequest {
    pub from_address: Address,
    pub chain_id: u64,
    pub steps: Vec<BundleStep>,
    pub slippage_bps: u16,
    pub routing_strategy: Option<RoutingStrategy>,
}

/// The transaction Enso wants the wallet to broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTx {
    pub to: Address,
    #[serde(deserialize_with = "de_bytes_hex")]
    pub data: Bytes,
    #[serde(deserialize_with = "de_u256_dec_or_hex", default)]
    pub value: U256,
    pub from: Address,
}

/// Wire representation we accept for `RouteResponse`. Enso returns
/// numeric fields as decimal **strings** for `amountOut`/`gas` and the
/// raw route object as nested JSON; we keep the route opaque.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteResponse {
    pub tx: RouteTx,
    /// Decimal stringified amount-out (in token_out decimals).
    pub amount_out: String,
    /// Gas estimate, decimal string.
    #[serde(default)]
    pub gas: Option<String>,
    /// Opaque route description.
    #[serde(default)]
    pub route: serde_json::Value,
    /// Price impact in % (0.0..100.0), if Enso reports it.
    #[serde(default)]
    pub price_impact: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleResponse {
    pub tx: RouteTx,
    #[serde(default)]
    pub bundle: serde_json::Value,
    #[serde(default)]
    pub gas: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteResponse {
    /// Decimal string.
    pub amount_out: String,
    #[serde(default)]
    pub gas: Option<String>,
    #[serde(default)]
    pub price_impact: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct EnsoClient {
    base_url: Url,
    http: reqwest::Client,
    api_key: String,
}

impl EnsoClient {
    /// Construct a client with an explicit API key. Use [`Self::with_base_url`]
    /// to override the endpoint (e.g. for tests).
    pub fn new(api_key: impl Into<String>) -> Self {
        let key = api_key.into();
        Self {
            base_url: Url::parse(DEFAULT_BASE_URL).expect("hardcoded default url is valid"),
            http: reqwest::Client::new(),
            api_key: key,
        }
    }

    /// Try to construct from `BLOOM_ENSO_KEY` (preferred) or `ENSO_API_KEY`.
    pub fn from_env() -> Result<Self, EnsoError> {
        let key = match std::env::var("BLOOM_ENSO_KEY")
            .ok()
            .or_else(|| std::env::var("ENSO_API_KEY").ok())
        {
            Some(k) => k,
            None => {
                tracing::debug!("enso.from_env.missing_key");
                return Err(EnsoError::MissingKey);
            }
        };
        if key.is_empty() {
            tracing::debug!("enso.from_env.empty_key");
            return Err(EnsoError::MissingKey);
        }
        Ok(Self::new(key))
    }

    pub fn with_base_url(mut self, base: Url) -> Self {
        self.base_url = base;
        self
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.api_key.is_empty() {
            tracing::trace!("enso.auth.unconfigured");
            rb
        } else {
            rb.bearer_auth(&self.api_key)
        }
    }

    /// `POST /api/v1/shortcuts/route` — single-step.
    ///
    /// Enso's REST surface uses **GET** with query params for `route`
    /// (despite being mutating in spirit); we follow that.
    pub async fn route(&self, req: RouteRequest) -> Result<RouteResponse, EnsoError> {
        let url = self.base_url.join("/api/v1/shortcuts/route")?;
        tracing::trace!(
            chain_id = req.chain_id,
            token_in = %req.token_in,
            token_out = %req.token_out,
            amount_in = %req.amount_in,
            slippage_bps = req.slippage_bps,
            "enso.route.request"
        );
        let rb = self.http.get(url).query(&req.to_query());
        let resp = self.auth(rb).send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            tracing::warn!(
                status = status.as_u16(),
                chain_id = req.chain_id,
                token_in = %req.token_in,
                token_out = %req.token_out,
                "enso.route.api_error"
            );
            return Err(EnsoError::Api {
                status: status.as_u16(),
                body,
            });
        }
        let v: RouteResponse = serde_json::from_str(&body)?;
        tracing::debug!(
            chain_id = req.chain_id,
            token_in = %req.token_in,
            token_out = %req.token_out,
            amount_out = %v.amount_out,
            gas = v.gas.as_deref().unwrap_or(""),
            price_impact = v.price_impact.unwrap_or(0.0),
            "enso.route.ok"
        );
        Ok(v)
    }

    /// `POST /api/v1/shortcuts/bundle` — multi-step.
    pub async fn bundle(&self, req: BundleRequest) -> Result<BundleResponse, EnsoError> {
        let url = self.base_url.join("/api/v1/shortcuts/bundle")?;
        tracing::trace!(
            chain_id = req.chain_id,
            steps = req.steps.len(),
            slippage_bps = req.slippage_bps,
            "enso.bundle.request"
        );
        let body = serde_json::json!({
            "fromAddress": format!("0x{:x}", req.from_address),
            "chainId": req.chain_id,
            "actions": req.steps,
            "slippage": req.slippage_bps,
            "routingStrategy": req
                .routing_strategy
                .unwrap_or_default()
                .as_str(),
        });
        let resp = self.auth(self.http.post(url).json(&body)).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            tracing::warn!(
                status = status.as_u16(),
                chain_id = req.chain_id,
                steps = req.steps.len(),
                "enso.bundle.api_error"
            );
            return Err(EnsoError::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        let v: BundleResponse = serde_json::from_str(&text)?;
        tracing::debug!(
            chain_id = req.chain_id,
            steps = req.steps.len(),
            gas = v.gas.as_deref().unwrap_or(""),
            "enso.bundle.ok"
        );
        Ok(v)
    }

    /// `GET /api/v1/shortcuts/quote` — non-committal price preview.
    /// Returns `amountOut` without producing tx calldata.
    pub async fn quote(&self, req: RouteRequest) -> Result<QuoteResponse, EnsoError> {
        let url = self.base_url.join("/api/v1/shortcuts/quote")?;
        tracing::trace!(
            chain_id = req.chain_id,
            token_in = %req.token_in,
            token_out = %req.token_out,
            amount_in = %req.amount_in,
            slippage_bps = req.slippage_bps,
            "enso.quote.request"
        );
        let rb = self.http.get(url).query(&req.to_query());
        let resp = self.auth(rb).send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            tracing::warn!(
                status = status.as_u16(),
                chain_id = req.chain_id,
                token_in = %req.token_in,
                token_out = %req.token_out,
                "enso.quote.api_error"
            );
            return Err(EnsoError::Api {
                status: status.as_u16(),
                body,
            });
        }
        let v: QuoteResponse = serde_json::from_str(&body)?;
        tracing::debug!(
            chain_id = req.chain_id,
            token_in = %req.token_in,
            token_out = %req.token_out,
            amount_out = %v.amount_out,
            price_impact = v.price_impact.unwrap_or(0.0),
            "enso.quote.ok"
        );
        Ok(v)
    }
}

// --- helpers --------------------------------------------------------------

fn de_bytes_hex<'de, D>(d: D) -> Result<Bytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    let s = s.trim();
    if s.is_empty() || s == "0x" {
        return Ok(Bytes::new());
    }
    let s = s.strip_prefix("0x").unwrap_or(s);
    let v = hex::decode(s).map_err(serde::de::Error::custom)?;
    Ok(Bytes::from(v))
}

fn de_u256_dec_or_hex<'de, D>(d: D) -> Result<U256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Accept either a decimal string ("100"), a hex string ("0x64"),
    // or a JSON number.
    use serde::de::Error;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Null => Ok(U256::ZERO),
        serde_json::Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                return Ok(U256::ZERO);
            }
            if let Some(hex) = t.strip_prefix("0x") {
                U256::from_str_radix(hex, 16).map_err(D::Error::custom)
            } else {
                U256::from_str_radix(t, 10).map_err(D::Error::custom)
            }
        }
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(U256::from(u))
            } else {
                Err(D::Error::custom("non-u64 number for U256"))
            }
        }
        other => Err(D::Error::custom(format!("unexpected value: {other}"))),
    }
}

// --- natural-language intent ---------------------------------------------

/// A parsed natural-language swap intent (`swap <amount> <tok_in> to <tok_out>`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NaturalIntent {
    pub verb: String,
    pub amount: String,
    pub token_in: String,
    pub token_out: String,
    /// Optional trailing `on <chain>` qualifier.
    pub chain: Option<String>,
}

/// Parse `<verb> <amount> <token_in> to <token_out> [on <chain>]`.
///
/// The grammar is intentionally tiny — multi-step intents go through
/// the bundle path with a richer body.
pub fn parse_natural_intent(input: &str) -> Option<NaturalIntent> {
    let toks: Vec<&str> = input.split_whitespace().collect();
    // Need at least: verb amount tok_in to tok_out
    if toks.len() < 5 {
        tracing::debug!(tokens = toks.len(), "enso.intent.parse.too_few_tokens");
        return None;
    }
    if !toks[3].eq_ignore_ascii_case("to") {
        tracing::debug!(connective = %toks[3], "enso.intent.parse.missing_to");
        return None;
    }
    if !toks[1]
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        tracing::debug!(amount = %toks[1], "enso.intent.parse.non_numeric_amount");
        return None;
    }
    let chain = if toks.len() >= 7 && toks[5].eq_ignore_ascii_case("on") {
        Some(toks[6].to_string())
    } else {
        None
    };
    Some(NaturalIntent {
        verb: toks[0].to_ascii_lowercase(),
        amount: toks[1].to_string(),
        token_in: toks[2].to_string(),
        token_out: toks[4].to_string(),
        chain,
    })
}

/// Resolve a token symbol or address into a concrete [`Address`] for a chain.
///
/// Symbol set is intentionally tiny; the registry is meant to be
/// expanded by the daemon at runtime. Native ETH/MATIC/etc. are folded
/// into the [`NATIVE_TOKEN`] sentinel.
pub fn resolve_token_symbol(chain_id: u64, sym: &str) -> Option<Address> {
    let s = sym.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        match s.parse::<Address>() {
            Ok(addr) => return Some(addr),
            Err(e) => {
                tracing::debug!(input = %s, error = %e, "enso.token.parse_failed");
            }
        }
    }
    let upper = s.to_ascii_uppercase();
    // Native sentinel covers ETH on EVM mainnets.
    if matches!(upper.as_str(), "ETH" | "ETHER" | "MATIC" | "BNB" | "AVAX") {
        return NATIVE_TOKEN.parse().ok();
    }
    let resolved = match (chain_id, upper.as_str()) {
        (1, "USDC") => "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".parse().ok(),
        (1, "USDT") => "0xdAC17F958D2ee523a2206206994597C13D831ec7".parse().ok(),
        (1, "DAI") => "0x6B175474E89094C44Da98b954EedeAC495271d0F".parse().ok(),
        (1, "WETH") => "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".parse().ok(),
        (1, "WBTC") => "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599".parse().ok(),
        (10, "USDC") => "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85".parse().ok(),
        (8453, "USDC") => "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".parse().ok(),
        _ => None,
    };
    if resolved.is_none() {
        tracing::debug!(chain_id, symbol = %upper, "enso.token.unknown_symbol");
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// One-shot HTTP server. Reads first request, writes the canned body, closes.
    async fn spawn_canned(body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
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

    fn client_for(addr: SocketAddr) -> EnsoClient {
        let url = Url::parse(&format!("http://{addr}")).unwrap();
        EnsoClient::new("test_key").with_base_url(url)
    }

    #[test]
    fn parses_swap_intent() {
        let got = parse_natural_intent("swap 1 ETH to USDC").unwrap();
        assert_eq!(got.verb, "swap");
        assert_eq!(got.amount, "1");
        assert_eq!(got.token_in, "ETH");
        assert_eq!(got.token_out, "USDC");
        assert!(got.chain.is_none());
    }

    #[test]
    fn parses_swap_with_chain() {
        let got = parse_natural_intent("swap 0.5 ETH to USDC on ethereum").unwrap();
        assert_eq!(got.amount, "0.5");
        assert_eq!(got.chain.as_deref(), Some("ethereum"));
    }

    #[test]
    fn rejects_nonsense() {
        assert!(parse_natural_intent("hello world").is_none());
        assert!(parse_natural_intent("swap ETH to USDC").is_none());
        assert!(parse_natural_intent("swap 1 ETH into USDC").is_none());
        assert!(parse_natural_intent("").is_none());
    }

    #[test]
    fn resolves_native_and_known_symbols() {
        assert_eq!(
            resolve_token_symbol(1, "ETH").unwrap(),
            NATIVE_TOKEN.parse::<Address>().unwrap()
        );
        assert!(resolve_token_symbol(1, "USDC").is_some());
        assert!(resolve_token_symbol(1, "FOOBAR").is_none());
    }

    #[test]
    fn errors_render() {
        assert_eq!(
            EnsoError::Disabled.to_string(),
            "disabled: no api key configured"
        );
        assert_eq!(
            EnsoError::Api {
                status: 401,
                body: "nope".into()
            }
            .to_string(),
            "api 401: nope"
        );
        assert_eq!(
            EnsoError::InvalidIntent("bad".into()).to_string(),
            "invalid intent: bad"
        );
    }

    #[test]
    fn client_uses_default_base_url() {
        let c = EnsoClient::new("k");
        assert_eq!(c.base_url().as_str(), "https://api.enso.finance/");
        assert_eq!(c.api_key(), "k");
    }

    #[tokio::test]
    async fn route_decodes_canned_response() {
        let body = r#"{
            "tx": {
                "from": "0x0000000000000000000000000000000000000001",
                "to":   "0x0000000000000000000000000000000000000002",
                "data": "0xdeadbeef",
                "value": "1000000000000000000"
            },
            "amountOut": "12345",
            "gas": "210000",
            "route": [{"protocol":"uniswap-v3"}],
            "priceImpact": 0.12
        }"#;
        let addr = spawn_canned(body).await;
        let c = client_for(addr);
        let req = RouteRequest::new(
            "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            1,
            NATIVE_TOKEN.parse().unwrap(),
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
                .parse()
                .unwrap(),
            U256::from(1_000_000_000_000_000_000u128),
        );
        let r = c.route(req).await.unwrap();
        assert_eq!(r.amount_out, "12345");
        assert_eq!(r.gas.as_deref(), Some("210000"));
        assert_eq!(r.tx.value, U256::from(1_000_000_000_000_000_000u128));
        assert!(!r.tx.data.is_empty());
        assert_eq!(r.price_impact, Some(0.12));
    }

    #[tokio::test]
    async fn route_propagates_api_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
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
            let body = r#"{"error":"unauthorized"}"#;
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(response.as_bytes()).await.unwrap();
            sock.shutdown().await.ok();
        });
        let c = client_for(addr);
        let req = RouteRequest::new(
            "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            1,
            NATIVE_TOKEN.parse().unwrap(),
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
                .parse()
                .unwrap(),
            U256::from(1u128),
        );
        let err = c.route(req).await.unwrap_err();
        match err {
            EnsoError::Api { status, .. } => assert_eq!(status, 401),
            e => panic!("expected Api error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn quote_decodes_canned_response() {
        let body = r#"{"amountOut":"999","gas":"100","priceImpact":0.01}"#;
        let addr = spawn_canned(body).await;
        let c = client_for(addr);
        let req = RouteRequest::new(
            "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            1,
            NATIVE_TOKEN.parse().unwrap(),
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
                .parse()
                .unwrap(),
            U256::from(1u128),
        );
        let q = c.quote(req).await.unwrap();
        assert_eq!(q.amount_out, "999");
    }

    /// Live test against the real Enso API. Gated behind `--ignored` and
    /// the `BLOOM_ENSO_KEY` env var; `cargo test -p bloom-defi -- --ignored`
    /// will exercise it.
    #[tokio::test]
    #[ignore]
    async fn live_route_eth_to_usdc() {
        let key = match std::env::var("BLOOM_ENSO_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => {
                eprintln!("skip: BLOOM_ENSO_KEY not set");
                return;
            }
        };
        let c = EnsoClient::new(key);
        // vitalik.eth — well-known address used as a `fromAddress` source.
        let from: Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            .parse()
            .unwrap();
        let usdc: Address = resolve_token_symbol(1, "USDC").unwrap();
        let eth: Address = NATIVE_TOKEN.parse().unwrap();
        let req = RouteRequest {
            from_address: from,
            chain_id: 1,
            token_in: eth,
            token_out: usdc,
            amount_in: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
            slippage_bps: 50,
            routing_strategy: Some(RoutingStrategy::Router),
            receiver: None,
        };
        match c.route(req).await {
            Ok(r) => {
                assert!(!r.tx.data.is_empty(), "tx.data should be non-empty");
                assert_ne!(r.tx.to, Address::ZERO, "tx.to should be a real address");
                eprintln!(
                    "live OK: amountOut={}, gas={:?}, to=0x{:x}",
                    r.amount_out, r.gas, r.tx.to
                );
            }
            Err(e) => panic!("live Enso route failed: {e}"),
        }
    }
}
