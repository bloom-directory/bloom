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
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};
use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_BASE_URL: &str = "https://api.enso.finance";

/// Sentinel address Enso uses for the chain's native token (ETH, MATIC, …).
pub const NATIVE_TOKEN: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

// Enso Router V2 wraps the actual shortcut calldata in one of these calls.
// The input token is deliberately decoded from this outer envelope rather
// than guessed from the opaque downstream shortcut payload.
sol! {
    #[allow(missing_docs)]
    interface IEnsoRouter {
        struct Token {
            uint8 tokenType;
            bytes data;
        }

        function routeSingle(Token tokenIn, bytes data) external payable;
        function routeMulti(Token[] tokensIn, bytes data) external payable;
    }
}

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
    /// Destination chain id for cross-chain routes. When set, Enso
    /// bridges the input token and executes the route on the
    /// destination chain. The returned tx is still broadcast on
    /// `chain_id` (source chain).
    pub destination_chain_id: Option<u64>,
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
            destination_chain_id: None,
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
        if let Some(d) = self.destination_chain_id {
            q.push(("destinationChainId", d.to_string()));
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
    /// **Enso-reported, unit UNVERIFIED.** Observed raw values like `291` and
    /// `15` on near-1:1 routes make the unit (percent? bps? score?) ambiguous,
    /// so this is **display-only** and must never drive a policy threshold
    /// (Enso route discovery finding D8). Surfaces in plans labelled
    /// "Enso-reported".
    #[serde(default)]
    pub price_impact: Option<f64>,
    /// Destination chain id extracted from the first bridging hop
    /// in `route`. Populated post-deserialisation by [`EnsoClient::route`].
    #[serde(skip)]
    pub destination_chain_id: Option<u64>,
}

impl RouteResponse {
    /// Verify that the executable Router V2 transaction carries the same
    /// source asset and amount as the request. Enso's route metadata is useful
    /// for display, but the router calldata is the transaction fact that will
    /// actually move the input.
    ///
    /// The generic DeFi shortcut payload is intentionally not decoded here:
    /// Router V2 transfers the input into its shortcut contract first, so the
    /// outer `Token` envelope is the authoritative source-side fact. Routes
    /// with an unsupported envelope fail closed.
    pub fn input_matches_request(&self, req: &RouteRequest) -> bool {
        if self.tx.from != req.from_address {
            return false;
        }

        let Some(token) = (if let Ok(call) = IEnsoRouter::routeSingleCall::abi_decode(&self.tx.data)
        {
            Some(call.tokenIn)
        } else if let Ok(call) = IEnsoRouter::routeMultiCall::abi_decode(&self.tx.data) {
            (call.tokensIn.len() == 1).then(|| call.tokensIn.into_iter().next().unwrap())
        } else {
            None
        }) else {
            return false;
        };

        match token.tokenType {
            // Enso Router V2 TokenType.Native.
            0 => {
                let Ok((amount,)) = <(U256,)>::abi_decode_params(&token.data) else {
                    return false;
                };
                req.token_in == NATIVE_TOKEN.parse::<Address>().unwrap()
                    && amount == req.amount_in
                    && self.tx.value == amount
            }
            // Enso Router V2 TokenType.ERC20.
            1 => {
                let Ok((token_in, amount)) = <(Address, U256)>::abi_decode_params(&token.data)
                else {
                    return false;
                };
                req.token_in != NATIVE_TOKEN.parse::<Address>().unwrap()
                    && token_in == req.token_in
                    && amount == req.amount_in
                    && self.tx.value == U256::ZERO
            }
            // ERC-721/1155 inputs are not part of RouteRequest's single-token
            // fungible input model.
            _ => false,
        }
    }

    /// Conservatively extract protocol names from the opaque `route` array.
    ///
    /// Returns `(protocols, unknown)`. `unknown = true` means bloom could not
    /// parse the metadata (route is not an array, or no hop carried a
    /// recognisable `protocol`/`name` field) — callers must fail closed on it.
    /// Names are lower-cased and de-duplicated in encounter order.
    pub fn protocols(&self) -> (Vec<String>, bool) {
        let Some(hops) = self.route.as_array() else {
            return (Vec::new(), true);
        };
        let mut names: Vec<String> = Vec::new();
        let mut saw_field = false;
        for hop in hops {
            let name = hop
                .get("protocol")
                .or_else(|| hop.get("name"))
                .or_else(|| hop.get("project"));
            if let Some(n) = name.and_then(|v| v.as_str()) {
                saw_field = true;
                let lc = n.trim().to_lowercase();
                if !lc.is_empty() && !names.contains(&lc) {
                    names.push(lc);
                }
            }
        }
        // An array with hops but no protocol field anywhere ⇒ unparsed.
        let unknown = !hops.is_empty() && !saw_field;
        (names, unknown)
    }

    /// Whether the route's tx calldata encodes `receiver` as a 20-byte word.
    ///
    /// A WP0 receiver calldata-diff probe (placeholder receivers, Base→Polygon
    /// and Polygon→Polygon pUSD routes) showed Enso encodes the requested
    /// `receiver` **verbatim** in `tx.data` — once for a same-chain route, twice
    /// for the cross-chain bridge route — and that each route's calldata
    /// contains only its own requested receiver. So, since Bloom builds the
    /// route with `receiver = <expected>`, this confirms Enso honored that
    /// receiver rather than substituting a different one.
    ///
    /// Scope: this is a *consistency* check against an accidental / swapped /
    /// stale route response — **not** a defense against a malicious Enso
    /// (explicitly out of the plan's threat model: a hostile service could embed
    /// the expected address as a decoy while crediting another). Receiver offsets
    /// are route-shape-dependent, so this checks presence, not a fixed offset;
    /// for cross-chain, full assurance still requires destination settlement
    /// proof (WP5).
    pub fn calldata_contains_receiver(&self, receiver: Address) -> bool {
        self.tx.data.windows(20).any(|w| w == receiver.as_slice())
    }
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
        let mut v: RouteResponse = serde_json::from_str(&body)?;
        // Extract destination_chain_id from the first bridging hop.
        if let Some(hops) = v.route.as_array() {
            v.destination_chain_id = hops
                .iter()
                .find_map(|hop| hop.get("destinationChainId")?.as_u64());
        }
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

// --- Enso Quoter: simulate + validate ------------------------------------
//
// A separate service (`quoter.api.enso.build`) from the route API. `simulate`
// returns an Enso-attested effect model plus a `simulationId`; `validate` binds
// an exact tx (chainId/from/to/data/value) to that id. The wire shapes were
// pinned by the WP0 live probe (docs/plans/2026-06-13-enso-simulation-
// verification.md): `tokenIn`/`tokenOut`/`amountIn` are arrays, `chainId` is
// required both top-level and inside `transaction`, and `validate` is keyed by
// `simulationId`. Mutating any of the five tx fields flips its `checks` entry.

const DEFAULT_QUOTER_URL: &str = "https://quoter.api.enso.build";

fn ser_u256_dec<S: serde::Serializer>(v: &U256, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

/// The exact transaction the quoter simulates/validates. `value` serialises as
/// a decimal string and `data` as 0x-hex, matching the route tx wire shape.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoterTx {
    pub chain_id: u64,
    pub from: Address,
    pub to: Address,
    pub data: Bytes,
    #[serde(serialize_with = "ser_u256_dec")]
    pub value: U256,
}

impl QuoterTx {
    /// Build from a route's tx on `chain_id` (the source chain for x-chain).
    pub fn from_route_tx(chain_id: u64, tx: &RouteTx) -> Self {
        Self {
            chain_id,
            from: tx.from,
            to: tx.to,
            data: tx.data.clone(),
            value: tx.value,
        }
    }
}

/// `POST /api/v1/simulate` request. Token arrays support multi-in/out routes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateRequest {
    pub chain_id: u64,
    pub transaction: QuoterTx,
    pub token_in: Vec<Address>,
    pub token_out: Vec<Address>,
    pub amount_in: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_chain_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_strategy: Option<RoutingStrategy>,
}

/// `POST /api/v1/validate` request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateRequest {
    pub simulation_id: String,
    pub transaction: QuoterTx,
}

/// `simulate` response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateResponse {
    pub simulation_id: String,
    #[serde(default)]
    pub chain_id: Option<u64>,
    pub result: SimulateResult,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateResult {
    /// `"Success"` or `"Error"` (Quoter OpenAPI enum).
    pub status: String,
    /// **Output amounts in wei**, parallel to the request's `tokenOut` array.
    /// Per the Quoter OpenAPI this is `string[]` — amounts only, with **no
    /// token, address, or receiver**. So a `/simulate` result can prove an
    /// output *amount* (a min-output floor) but **cannot attribute output to a
    /// receiver**; receiver verification must come from decoding the route's
    /// receiver argument or from destination settlement (WP5), not from here.
    /// Empty even on `status:"Success"` when the tx produced nothing — see
    /// [`SimulateResponse::produced_output`].
    #[serde(default)]
    pub amount_out: Vec<String>,
    #[serde(default)]
    pub gas: Option<String>,
    /// Error detail when `status == "Error"`.
    #[serde(default)]
    pub error: Option<serde_json::Value>,
    /// Any fields beyond the modelled OpenAPI shape, preserved raw for audit.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl SimulateResponse {
    /// Enso reported the simulation status as success.
    pub fn status_success(&self) -> bool {
        self.result.status.eq_ignore_ascii_case("success")
    }

    /// Whether any output effect was attributed at all.
    pub fn amount_out_nonempty(&self) -> bool {
        !self.result.amount_out.is_empty()
    }

    /// **The real success gate.** WP0 proved `status:"Success"` alone is not
    /// enough — an unfunded tx returns success with an empty `amountOut`. A
    /// route only "produced output" when status is success AND `amountOut` is
    /// non-empty. Token/receiver/floor checks layer on top of this (WP3).
    pub fn produced_output(&self) -> bool {
        self.status_success() && self.amount_out_nonempty()
    }
}

/// `validate` response. Every `checks` field must be true for `valid`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateResponse {
    pub valid: bool,
    #[serde(default)]
    pub simulation_id: Option<String>,
    pub checks: ValidateChecks,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateChecks {
    pub chain_id: bool,
    pub data: bool,
    pub to: bool,
    pub value: bool,
    pub from: bool,
}

/// Client for the Enso Quoter (`simulate`/`validate`). Mirrors [`EnsoClient`]'s
/// `Bearer <key>` auth and env-key handling, against a different base URL.
#[derive(Debug, Clone)]
pub struct QuoterClient {
    base_url: Url,
    http: reqwest::Client,
    api_key: String,
}

impl QuoterClient {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            base_url: Url::parse(DEFAULT_QUOTER_URL).expect("hardcoded default url is valid"),
            http: reqwest::Client::new(),
            api_key: api_key.into(),
        }
    }

    /// From `BLOOM_ENSO_KEY` (preferred) or `ENSO_API_KEY` — the same key the
    /// route API uses.
    pub fn from_env() -> Result<Self, EnsoError> {
        let key = std::env::var("BLOOM_ENSO_KEY")
            .ok()
            .or_else(|| std::env::var("ENSO_API_KEY").ok())
            .filter(|k| !k.is_empty())
            .ok_or(EnsoError::MissingKey)?;
        Ok(Self::new(key))
    }

    pub fn with_base_url(mut self, base: Url) -> Self {
        self.base_url = base;
        self
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.api_key.is_empty() {
            rb
        } else {
            rb.bearer_auth(&self.api_key)
        }
    }

    /// `POST /api/v1/simulate`.
    pub async fn simulate(&self, req: &SimulateRequest) -> Result<SimulateResponse, EnsoError> {
        let url = self.base_url.join("/api/v1/simulate")?;
        let resp = self.auth(self.http.post(url).json(req)).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(EnsoError::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        Ok(serde_json::from_str(&text)?)
    }

    /// `POST /api/v1/validate`.
    pub async fn validate(&self, req: &ValidateRequest) -> Result<ValidateResponse, EnsoError> {
        let url = self.base_url.join("/api/v1/validate")?;
        let resp = self.auth(self.http.post(url).json(req)).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(EnsoError::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        Ok(serde_json::from_str(&text)?)
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
    // Symbol majors come from the shared `bloom_proto::tokens` table.
    let resolved =
        bloom_proto::tokens::resolve_symbol(chain_id, &upper).and_then(|t| t.address.parse().ok());
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

    #[test]
    fn protocol_extraction_and_unknown_fail_closed() {
        let mk = |route: serde_json::Value| RouteResponse {
            tx: RouteTx {
                to: "0x0000000000000000000000000000000000000002"
                    .parse()
                    .unwrap(),
                data: Default::default(),
                value: U256::ZERO,
                from: "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
            },
            amount_out: "1".into(),
            gas: None,
            route,
            price_impact: None,
            destination_chain_id: None,
        };
        // multi-hop with protocol fields → parsed, ordered, de-duped
        let (p, unk) = mk(serde_json::json!([
            {"protocol":"Stargate"}, {"protocol":"odos"}, {"protocol":"odos"}
        ]))
        .protocols();
        assert_eq!(p, vec!["stargate", "odos"]);
        assert!(!unk);
        // array with no protocol field anywhere → unknown (fail closed)
        let (p, unk) = mk(serde_json::json!([{"tokenIn":"0x.."}])).protocols();
        assert!(p.is_empty() && unk);
        // non-array route → unknown
        let (p, unk) = mk(serde_json::json!({"opaque":true})).protocols();
        assert!(p.is_empty() && unk);
    }

    /// `priceImpact` is Enso-reported with an unverified unit; surprising raw
    /// values must round-trip untouched (no silent reinterpretation as %/bps).
    #[test]
    fn price_impact_raw_value_is_preserved_not_reinterpreted() {
        let body = r#"{
            "tx":{"from":"0x0000000000000000000000000000000000000001",
                  "to":"0x0000000000000000000000000000000000000002",
                  "data":"0x","value":"0"},
            "amountOut":"1000000","route":[{"protocol":"enso"}],
            "priceImpact": 291
        }"#;
        let r: RouteResponse = serde_json::from_str(body).unwrap();
        assert_eq!(
            r.price_impact,
            Some(291.0),
            "raw value must not be rescaled"
        );
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
            destination_chain_id: None,
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

    // --- Quoter (simulate/validate), parsing captured WP0 fixtures ---------

    #[test]
    fn quoter_simulate_success_with_empty_output_is_not_produced_output() {
        let body = include_str!("../tests/fixtures/quoter_simulate_success_empty_output.json");
        let r: SimulateResponse = serde_json::from_str(body).unwrap();
        assert_eq!(r.simulation_id, "30d53f44-78ba-413d-b401-2a3a5b230806");
        assert_eq!(r.chain_id, Some(8453));
        assert!(r.status_success(), "status is Success");
        assert!(!r.amount_out_nonempty(), "amountOut is empty");
        // WP0: a Success status with empty amountOut must NOT count as output.
        assert!(!r.produced_output());
    }

    #[test]
    fn quoter_simulate_populated_amounts_parse_as_wei_strings() {
        // Schema-representative (Quoter OpenAPI: amountOut is string[] wei, no
        // receiver). A non-empty amountOut on Success = output produced; the
        // amounts are usable as a min-output floor, but carry no receiver.
        let body = r#"{"simulationId":"x","chainId":8453,
            "result":{"status":"Success","amountOut":["5040656"],"gas":"564908"}}"#;
        let r: SimulateResponse = serde_json::from_str(body).unwrap();
        assert!(r.produced_output());
        assert_eq!(r.result.amount_out, vec!["5040656".to_string()]);
        // amounts are plain wei strings, parseable for a floor comparison.
        assert_eq!(r.result.amount_out[0].parse::<u128>().unwrap(), 5_040_656);
    }

    #[test]
    fn route_calldata_contains_requested_receiver() {
        // Real Enso same-chain route calldata captured with a placeholder
        // receiver (0x2222…); the WP0 calldata-diff probe found the receiver
        // encoded verbatim in tx.data.
        let body = include_str!("../tests/fixtures/route_same_chain_receiver_placeholder.json");
        let r: RouteResponse = serde_json::from_str(body).unwrap();
        let recv: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let other: Address = "0x4444444444444444444444444444444444444444"
            .parse()
            .unwrap();
        assert!(
            r.calldata_contains_receiver(recv),
            "the requested receiver must be encoded in the route calldata"
        );
        assert!(
            !r.calldata_contains_receiver(other),
            "an address we did not request must not be found"
        );
    }

    #[test]
    fn route_calldata_binds_input_token_and_amount() {
        let body = include_str!("../tests/fixtures/route_same_chain_receiver_placeholder.json");
        let r: RouteResponse = serde_json::from_str(body).unwrap();
        let req = RouteRequest {
            from_address: "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            chain_id: 137,
            destination_chain_id: None,
            token_in: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"
                .parse()
                .unwrap(),
            token_out: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb"
                .parse()
                .unwrap(),
            amount_in: U256::from(5_000_000u64),
            slippage_bps: 50,
            routing_strategy: Some(RoutingStrategy::Router),
            receiver: None,
        };
        assert!(r.input_matches_request(&req));

        let mut wrong_amount = req.clone();
        wrong_amount.amount_in += U256::from(1u64);
        assert!(!r.input_matches_request(&wrong_amount));
    }

    #[test]
    fn native_route_calldata_binds_msg_value() {
        let from: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let amount = U256::from(1_000_000_000_000_000_000u128);
        let data = IEnsoRouter::routeSingleCall {
            tokenIn: IEnsoRouter::Token {
                tokenType: 0,
                data: (amount,).abi_encode_params().into(),
            },
            data: Bytes::new(),
        }
        .abi_encode();
        let route = RouteResponse {
            tx: RouteTx {
                to: Address::ZERO,
                data: data.into(),
                value: amount,
                from,
            },
            amount_out: "1".into(),
            gas: None,
            route: serde_json::Value::Null,
            price_impact: None,
            destination_chain_id: None,
        };
        let req = RouteRequest::new(
            from,
            1,
            NATIVE_TOKEN.parse().unwrap(),
            Address::ZERO,
            amount,
        );
        assert!(route.input_matches_request(&req));

        let mut wrong_value = route.clone();
        wrong_value.tx.value += U256::from(1u64);
        assert!(!wrong_value.input_matches_request(&req));
    }

    #[test]
    fn quoter_validate_fixtures_parse_checks() {
        let body = include_str!("../tests/fixtures/quoter_validate_valid.json");
        let r: ValidateResponse = serde_json::from_str(body).unwrap();
        assert!(r.valid);
        let c = r.checks;
        assert!(c.chain_id && c.data && c.to && c.value && c.from);

        let body = include_str!("../tests/fixtures/quoter_validate_invalid.json");
        let r: ValidateResponse = serde_json::from_str(body).unwrap();
        assert!(!r.valid);
        assert!(!r.checks.data, "the mutated data byte must fail its check");
        assert!(r.checks.to && r.checks.value && r.checks.from && r.checks.chain_id);
    }

    #[test]
    fn simulate_request_serialises_to_the_wp0_shape() {
        // All-lowercase addresses: avoids EIP-55 checksum parsing in the test.
        let tx = QuoterTx {
            chain_id: 8453,
            from: "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            to: "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf"
                .parse()
                .unwrap(),
            data: Bytes::from(vec![0xde, 0xad]),
            value: U256::from(71995316158156u64),
        };
        let req = SimulateRequest {
            chain_id: 8453,
            transaction: tx,
            token_in: vec![
                "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
                    .parse()
                    .unwrap(),
            ],
            token_out: vec![
                "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb"
                    .parse()
                    .unwrap(),
            ],
            amount_in: vec!["5052843".into()],
            destination_chain_id: Some(137),
            routing_strategy: Some(RoutingStrategy::Router),
        };
        let v = serde_json::to_value(&req).unwrap();
        // arrays + chainId top-level AND nested + decimal-string value.
        assert!(v["tokenIn"].is_array() && v["tokenOut"].is_array() && v["amountIn"].is_array());
        assert_eq!(v["chainId"], 8453);
        assert_eq!(v["transaction"]["chainId"], 8453);
        assert_eq!(v["transaction"]["value"], "71995316158156");
        assert_eq!(v["amountIn"][0], "5052843");
        assert_eq!(v["routingStrategy"], "router");
        assert_eq!(v["destinationChainId"], 137);
    }
}
