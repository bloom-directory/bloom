//! Hyperliquid HyperCore client for Bloom.
//!
//! The public API split mirrors Hyperliquid's docs:
//! - `POST /info` for read-only exchange and account data.
//! - `POST /exchange` for signed state-changing actions.
//!
//! Signing follows the official SDK shape for L1 actions: msgpack the action
//! with stable struct field order, append nonce/vault/expiresAfter fields into
//! a connection hash, then EIP-712 sign an `Agent(source, connectionId)`.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, Signature, U256};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use alloy_dyn_abi::eip712::TypedData;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use url::Url;

pub const MAINNET_API_URL: &str = "https://api.hyperliquid.xyz";
pub const TESTNET_API_URL: &str = "https://api.hyperliquid-testnet.xyz";

#[derive(Debug, thiserror::Error)]
pub enum HyperliquidError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url: {0}")]
    Url(#[from] url::ParseError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("msgpack: {0}")]
    Msgpack(#[from] rmp_serde::encode::Error),
    #[error("api error (status {status}): {body}")]
    Api { status: u16, body: String },
    #[error("exchange action error: {0}")]
    Action(String),
    #[error("signing: {0}")]
    Signing(String),
    #[error("invalid: {0}")]
    Invalid(String),
}

impl HyperliquidError {
    pub fn invalid(s: impl Into<String>) -> Self {
        Self::Invalid(s.into())
    }
    pub fn signing(s: impl Into<String>) -> Self {
        Self::Signing(s.into())
    }
}

pub type Result<T> = std::result::Result<T, HyperliquidError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HyperliquidNetwork {
    Mainnet,
    Testnet,
}

impl HyperliquidNetwork {
    pub fn api_url(self) -> &'static str {
        match self {
            Self::Mainnet => MAINNET_API_URL,
            Self::Testnet => TESTNET_API_URL,
        }
    }

    pub fn chain_name(self) -> &'static str {
        match self {
            Self::Mainnet => "Mainnet",
            Self::Testnet => "Testnet",
        }
    }

    pub fn signing_source(self) -> &'static str {
        match self {
            Self::Mainnet => "a",
            Self::Testnet => "b",
        }
    }

    /// EVM `signatureChainId` for **user-signed** actions (approveAgent,
    /// withdraw, transfers). Distinct from the L1 action domain (chainId 1337).
    ///
    /// Per the Hyperliquid docs (exchange-endpoint `approveAgent` and the
    /// user-signed-action EIP-712 example; bridge2), this is "the id of the
    /// chain used when signing": Arbitrum One (`0xa4b1` = 42161) on mainnet,
    /// Arbitrum Sepolia (`0x66eee` = 421614) on testnet. The domain `chainId`
    /// and the payload `signatureChainId` must match for signer recovery; the
    /// `hyperliquidChain` field additionally distinguishes the environment.
    pub fn signature_chain_id(self) -> u64 {
        match self {
            Self::Mainnet => 0xa4b1,
            Self::Testnet => 0x66eee,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HyperliquidClient {
    base_url: Url,
    http: reqwest::Client,
    network: HyperliquidNetwork,
}

impl HyperliquidClient {
    pub fn new(network: HyperliquidNetwork) -> Self {
        Self {
            base_url: Url::parse(network.api_url()).expect("valid default hyperliquid url"),
            http: reqwest::Client::new(),
            network,
        }
    }

    pub fn with_base_url(mut self, base_url: Url) -> Self {
        self.base_url = base_url;
        self
    }

    pub fn network(&self) -> HyperliquidNetwork {
        self.network
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub async fn info(&self, body: Value) -> Result<Value> {
        // Reads are idempotent → safe to retry any transport failure.
        self.post_json("info", &body, true).await
    }

    pub async fn exchange(&self, body: Value) -> Result<Value> {
        // `idempotent: false` is the retry safety boundary — writes retry only
        // pre-send connection failures. See `transport_retryable` before changing.
        let value = self.post_json("exchange", &body, false).await?;
        validate_exchange_response(&value)?;
        Ok(value)
    }

    /// POST `body` to `path`, retrying *transport* failures with bounded jittered
    /// backoff. A successful HTTP response carrying an API error is never retried
    /// (it's a real answer, not a transport flake). `idempotent` governs whether
    /// post-send failures (timeouts) may be retried — true for reads, false for
    /// `exchange`, where the action may already have landed.
    async fn post_json(&self, path: &str, body: &Value, idempotent: bool) -> Result<Value> {
        let url = self.base_url.join(path)?;
        let mut attempt = 0u32;
        let resp = loop {
            match self.http.post(url.clone()).json(body).send().await {
                Ok(resp) => break resp,
                Err(e) => {
                    if attempt < MAX_POST_RETRIES && transport_retryable(&e, idempotent) {
                        attempt += 1;
                        tokio::time::sleep(retry_backoff(attempt)).await;
                        continue;
                    }
                    return Err(e.into());
                }
            }
        };
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes).into_owned();
            return Err(HyperliquidError::Api {
                status: status.as_u16(),
                body,
            });
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// Max retry attempts for transport failures in [`HyperliquidClient::post_json`].
const MAX_POST_RETRIES: u32 = 3;

/// Whether a transport error is safe to retry. A connection failure never
/// reached the server, so it's always safe. Timeouts / incomplete sends are
/// retried only for idempotent reads — never for `exchange`, where the action
/// may already have been applied.
///
/// DO NOT BROADEN the non-idempotent (`exchange`) path. Writes must retry
/// ONLY `is_connect()` — a failure where the request provably never left the
/// client. The moment you let the `idempotent` branch (timeout / incomplete
/// send) apply to writes, a retry can double-submit an order that the exchange
/// already accepted but whose response was lost. The `idempotent` flag is the
/// safety boundary; it is only ever `true` for reads (`info`).
fn transport_retryable(e: &reqwest::Error, idempotent: bool) -> bool {
    e.is_connect() || (idempotent && (e.is_timeout() || e.is_request()))
}

/// Bounded jittered backoff: ~100/200/300ms plus up to ~100ms of clock jitter.
fn retry_backoff(attempt: u32) -> Duration {
    let base = 100u64 * u64::from(attempt);
    let jitter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) % 100)
        .unwrap_or(0);
    Duration::from_millis(base + jitter)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureJson {
    pub r: String,
    pub s: String,
    pub v: u8,
}

impl SignatureJson {
    pub fn from_signature(sig: &Signature) -> Self {
        let bytes = sig.as_bytes();
        let mut v = bytes[64];
        if v < 27 {
            v += 27;
        }
        Self {
            r: format!("0x{}", hex::encode(&bytes[0..32])),
            s: format!("0x{}", hex::encode(&bytes[32..64])),
            v,
        }
    }
}

#[derive(Clone)]
pub struct HyperliquidSigner {
    signer: Arc<PrivateKeySigner>,
    address: Address,
}

impl HyperliquidSigner {
    pub fn new(signer: Arc<PrivateKeySigner>) -> Self {
        let address = signer.address();
        Self { signer, address }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub async fn sign_l1_action(
        &self,
        network: HyperliquidNetwork,
        action: &ExchangeAction,
        nonce: u64,
        vault_address: Option<Address>,
        expires_after: Option<u64>,
    ) -> Result<SignatureJson> {
        let connection_id = action_hash(action, nonce, vault_address, expires_after)?;
        let typed = agent_typed_data(network, connection_id)?;
        let hash = typed
            .eip712_signing_hash()
            .map_err(|e| HyperliquidError::signing(format!("eip712: {e}")))?;
        let sig = self
            .signer
            .sign_hash(&hash)
            .await
            .map_err(|e| HyperliquidError::signing(e.to_string()))?;
        Ok(SignatureJson::from_signature(&sig))
    }

    /// Sign a Hyperliquid **`usdSend`** (internal USDC transfer) — user-signed
    /// EIP-712, same `HyperliquidSignTransaction` domain as `approveAgent`
    /// (chainId = Arbitrum). Owner-only: agent keys cannot authorize transfers.
    pub async fn sign_usd_send(
        &self,
        network: HyperliquidNetwork,
        destination: Address,
        amount: &str,
        nonce: u64,
    ) -> Result<(Value, SignatureJson)> {
        let typed = usd_send_typed_data(network, destination, amount, nonce)?;
        let hash = typed
            .eip712_signing_hash()
            .map_err(|e| HyperliquidError::signing(format!("eip712: {e}")))?;
        let sig = self
            .signer
            .sign_hash(&hash)
            .await
            .map_err(|e| HyperliquidError::signing(e.to_string()))?;
        let action = json!({
            "type": "usdSend",
            "hyperliquidChain": network.chain_name(),
            "signatureChainId": format!("0x{:x}", network.signature_chain_id()),
            "destination": format!("{destination:#x}"),
            "amount": amount,
            "time": nonce,
        });
        Ok((action, SignatureJson::from_signature(&sig)))
    }

    /// Sign a Hyperliquid **`approveAgent`** action — a *user-signed* EIP-712
    /// action (domain `HyperliquidSignTransaction`), distinct from the L1
    /// order/cancel scheme in [`Self::sign_l1_action`]. One owner signature
    /// approves an agent ("API") wallet that can trade but **cannot withdraw**.
    /// Returns the `action` object to POST and its signature.
    pub async fn sign_approve_agent(
        &self,
        network: HyperliquidNetwork,
        agent_address: Address,
        agent_name: Option<&str>,
        nonce: u64,
    ) -> Result<(Value, SignatureJson)> {
        let agent_name = agent_name.unwrap_or("");
        let typed = approve_agent_typed_data(network, agent_address, agent_name, nonce)?;
        let hash = typed
            .eip712_signing_hash()
            .map_err(|e| HyperliquidError::signing(format!("eip712: {e}")))?;
        let sig = self
            .signer
            .sign_hash(&hash)
            .await
            .map_err(|e| HyperliquidError::signing(e.to_string()))?;
        let action = json!({
            "type": "approveAgent",
            "hyperliquidChain": network.chain_name(),
            "signatureChainId": format!("0x{:x}", network.signature_chain_id()),
            "agentAddress": format!("{agent_address:#x}"),
            "agentName": agent_name,
            "nonce": nonce,
        });
        Ok((action, SignatureJson::from_signature(&sig)))
    }
}

/// EIP-712 typed data for a user-signed `approveAgent` action.
fn approve_agent_typed_data(
    network: HyperliquidNetwork,
    agent_address: Address,
    agent_name: &str,
    nonce: u64,
) -> Result<TypedData> {
    let value = json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "HyperliquidTransaction:ApproveAgent": [
                {"name": "hyperliquidChain", "type": "string"},
                {"name": "agentAddress", "type": "address"},
                {"name": "agentName", "type": "string"},
                {"name": "nonce", "type": "uint64"}
            ]
        },
        "primaryType": "HyperliquidTransaction:ApproveAgent",
        "domain": {
            "name": "HyperliquidSignTransaction",
            "version": "1",
            "chainId": network.signature_chain_id(),
            "verifyingContract": "0x0000000000000000000000000000000000000000"
        },
        "message": {
            "hyperliquidChain": network.chain_name(),
            "agentAddress": format!("{agent_address:#x}"),
            "agentName": agent_name,
            "nonce": nonce
        }
    });
    serde_json::from_value(value).map_err(HyperliquidError::Json)
}

/// Build the `/exchange` body for a user-signed action: `{action, nonce,
/// signature}` (no `vaultAddress`, unlike L1 submits).
pub fn user_signed_payload(action: Value, nonce: u64, signature: SignatureJson) -> Value {
    json!({ "action": action, "nonce": nonce, "signature": signature })
}

/// Request body for writing to `send_asset.json` / `usdSend`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsdSendRequest {
    /// Destination address (0x-prefixed 42-char hex).
    pub destination: String,
    /// Transfer amount as a plain USD decimal string, e.g. `"100"` or `"50.5"`.
    pub amount: String,
    /// Optional ms-timestamp nonce. Generated from `now_ms()` if absent.
    #[serde(default)]
    pub nonce: Option<u64>,
}

fn usd_send_typed_data(
    network: HyperliquidNetwork,
    destination: Address,
    amount: &str,
    nonce: u64,
) -> Result<TypedData> {
    let value = json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "HyperliquidTransaction:UsdSend": [
                {"name": "hyperliquidChain", "type": "string"},
                {"name": "destination", "type": "string"},
                {"name": "amount", "type": "string"},
                {"name": "time", "type": "uint64"}
            ]
        },
        "primaryType": "HyperliquidTransaction:UsdSend",
        "domain": {
            "name": "HyperliquidSignTransaction",
            "version": "1",
            "chainId": network.signature_chain_id(),
            "verifyingContract": "0x0000000000000000000000000000000000000000"
        },
        "message": {
            "hyperliquidChain": network.chain_name(),
            "destination": format!("{destination:#x}"),
            "amount": amount,
            "time": nonce
        }
    });
    serde_json::from_value(value).map_err(HyperliquidError::Json)
}

fn agent_typed_data(network: HyperliquidNetwork, connection_id: B256) -> Result<TypedData> {
    let value = json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Agent": [
                {"name": "source", "type": "string"},
                {"name": "connectionId", "type": "bytes32"}
            ]
        },
        "primaryType": "Agent",
        "domain": {
            "name": "Exchange",
            "version": "1",
            "chainId": 1337,
            "verifyingContract": "0x0000000000000000000000000000000000000000"
        },
        "message": {
            "source": network.signing_source(),
            "connectionId": format!("{connection_id:#x}")
        }
    });
    serde_json::from_value(value).map_err(HyperliquidError::Json)
}

pub fn action_hash(
    action: &ExchangeAction,
    nonce: u64,
    vault_address: Option<Address>,
    expires_after: Option<u64>,
) -> Result<B256> {
    let mut bytes = rmp_serde::to_vec_named(action)?;
    bytes.extend_from_slice(&nonce.to_be_bytes());
    match vault_address {
        Some(addr) => {
            bytes.push(1);
            bytes.extend_from_slice(addr.as_slice());
        }
        None => bytes.push(0),
    }
    if let Some(expires_after) = expires_after {
        bytes.push(0);
        bytes.extend_from_slice(&expires_after.to_be_bytes());
    }
    let digest = Keccak256::digest(&bytes);
    Ok(B256::from_slice(&digest))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ExchangeAction {
    #[serde(rename = "order")]
    Order {
        orders: Vec<OrderWire>,
        grouping: Grouping,
        #[serde(skip_serializing_if = "Option::is_none")]
        builder: Option<BuilderFee>,
    },
    #[serde(rename = "cancel")]
    Cancel {
        cancels: Vec<CancelWire>,
        #[serde(rename = "f", skip_serializing_if = "Option::is_none")]
        fast: Option<bool>,
    },
    #[serde(rename = "cancelByCloid")]
    CancelByCloid {
        cancels: Vec<CancelByCloidWire>,
        #[serde(rename = "f", skip_serializing_if = "Option::is_none")]
        fast: Option<bool>,
    },
    #[serde(rename = "scheduleCancel")]
    ScheduleCancel {
        #[serde(skip_serializing_if = "Option::is_none")]
        time: Option<u64>,
    },
    #[serde(rename = "updateLeverage")]
    UpdateLeverage {
        asset: u32,
        #[serde(rename = "isCross")]
        is_cross: bool,
        leverage: u32,
    },
}

impl ExchangeAction {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Order { .. } => "order",
            Self::Cancel { .. } => "cancel",
            Self::CancelByCloid { .. } => "cancelByCloid",
            Self::ScheduleCancel { .. } => "scheduleCancel",
            Self::UpdateLeverage { .. } => "updateLeverage",
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Order { orders, .. } => {
                if orders.is_empty() {
                    return Err(HyperliquidError::invalid("orders must not be empty"));
                }
                for order in orders {
                    order.validate()?;
                }
            }
            Self::Cancel { cancels, fast } => {
                if cancels.is_empty() {
                    return Err(HyperliquidError::invalid("cancels must not be empty"));
                }
                if *fast == Some(false) {
                    return Err(HyperliquidError::invalid(
                        "omit fast/f when false; Hyperliquid rejects f:false hashes",
                    ));
                }
            }
            Self::CancelByCloid { cancels, fast } => {
                if cancels.is_empty() {
                    return Err(HyperliquidError::invalid("cancels must not be empty"));
                }
                if *fast == Some(false) {
                    return Err(HyperliquidError::invalid(
                        "omit fast/f when false; Hyperliquid rejects f:false hashes",
                    ));
                }
                for c in cancels {
                    validate_cloid(&c.cloid)?;
                }
            }
            Self::ScheduleCancel { .. } => {}
            Self::UpdateLeverage { leverage, .. } => {
                if *leverage == 0 || *leverage > 50 {
                    return Err(HyperliquidError::invalid("leverage must be 1..=50"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderWire {
    #[serde(rename = "a")]
    pub asset: u32,
    #[serde(rename = "b")]
    pub is_buy: bool,
    #[serde(rename = "p")]
    pub price: String,
    #[serde(rename = "s")]
    pub size: String,
    #[serde(rename = "r")]
    pub reduce_only: bool,
    #[serde(rename = "t")]
    pub order_type: OrderTypeWire,
    #[serde(rename = "c", skip_serializing_if = "Option::is_none")]
    pub cloid: Option<String>,
}

impl OrderWire {
    fn validate(&self) -> Result<()> {
        validate_decimal_string("price", &self.price)?;
        validate_decimal_string("size", &self.size)?;
        if let Some(cloid) = &self.cloid {
            validate_cloid(cloid)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Grouping {
    #[serde(rename = "na")]
    Na,
    #[serde(rename = "normalTpsl")]
    NormalTpsl,
    #[serde(rename = "positionTpsl")]
    PositionTpsl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuilderFee {
    #[serde(rename = "b")]
    pub address: String,
    #[serde(rename = "f")]
    pub fee_tenths_bps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderTypeWire {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<LimitOrderType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<TriggerOrderType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitOrderType {
    pub tif: TimeInForce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerOrderType {
    #[serde(rename = "isMarket")]
    pub is_market: bool,
    #[serde(rename = "triggerPx")]
    pub trigger_px: String,
    pub tpsl: TpSl,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TimeInForce {
    Alo,
    Ioc,
    Gtc,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpSl {
    Tp,
    Sl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelWire {
    #[serde(rename = "a")]
    pub asset: u32,
    #[serde(rename = "o")]
    pub oid: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelByCloidWire {
    pub asset: u32,
    pub cloid: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignedSubmit {
    pub action: ExchangeAction,
    pub nonce: u64,
    pub signature: SignatureJson,
    #[serde(default, rename = "vaultAddress")]
    pub vault_address: Option<String>,
    #[serde(default, rename = "expiresAfter")]
    pub expires_after: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignSubmit {
    pub action: ExchangeAction,
    #[serde(default)]
    pub nonce: Option<u64>,
    #[serde(default, rename = "vaultAddress")]
    pub vault_address: Option<String>,
    #[serde(default, rename = "expiresAfter")]
    pub expires_after: Option<u64>,
}

pub fn signed_payload(
    action: ExchangeAction,
    nonce: u64,
    signature: SignatureJson,
    vault_address: Option<String>,
    expires_after: Option<u64>,
) -> Result<Value> {
    action.validate()?;
    let mut value = json!({
        "action": action,
        "nonce": nonce,
        "signature": signature,
    });
    let obj = value.as_object_mut().expect("json object");
    if let Some(vault) = vault_address {
        validate_address_str(&vault)?;
        obj.insert(
            "vaultAddress".to_string(),
            Value::String(vault.to_ascii_lowercase()),
        );
    }
    if let Some(expires) = expires_after {
        obj.insert(
            "expiresAfter".to_string(),
            Value::Number(serde_json::Number::from(expires)),
        );
    }
    Ok(value)
}

pub async fn sign_submit_payload(
    signer: &HyperliquidSigner,
    network: HyperliquidNetwork,
    req: SignSubmit,
) -> Result<Value> {
    req.action.validate()?;
    let nonce = req.nonce.unwrap_or_else(now_ms);
    let vault = match req.vault_address.as_deref() {
        Some(raw) => Some(parse_address(raw)?),
        None => None,
    };
    let signature = signer
        .sign_l1_action(network, &req.action, nonce, vault, req.expires_after)
        .await?;
    signed_payload(
        req.action,
        nonce,
        signature,
        req.vault_address,
        req.expires_after,
    )
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn parse_address(raw: &str) -> Result<Address> {
    validate_address_str(raw)?;
    raw.parse::<Address>()
        .map_err(|e| HyperliquidError::invalid(format!("address: {e}")))
}

fn validate_address_str(raw: &str) -> Result<()> {
    if raw.len() != 42 || !raw.starts_with("0x") || !raw[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(HyperliquidError::invalid(
            "address must be a 42-character 0x hex string",
        ));
    }
    Ok(())
}

fn validate_cloid(raw: &str) -> Result<()> {
    if raw.len() != 34 || !raw.starts_with("0x") || !raw[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(HyperliquidError::invalid(
            "cloid must be a 128-bit 0x hex string",
        ));
    }
    Ok(())
}

fn validate_decimal_string(name: &str, raw: &str) -> Result<()> {
    if raw.is_empty() || raw.len() > 40 {
        return Err(HyperliquidError::invalid(format!(
            "{name} must be 1..=40 chars"
        )));
    }
    if raw.starts_with('+') || raw.starts_with('-') || raw.contains('e') || raw.contains('E') {
        return Err(HyperliquidError::invalid(format!(
            "{name} must be a plain positive decimal string"
        )));
    }
    if raw.ends_with(".") || raw.starts_with(".") || raw.contains("..") {
        return Err(HyperliquidError::invalid(format!("{name} malformed")));
    }
    if raw.contains('.') && raw.ends_with('0') {
        return Err(HyperliquidError::invalid(format!(
            "{name} must not contain trailing zeroes when signed"
        )));
    }
    let parsed = raw
        .parse::<f64>()
        .map_err(|_| HyperliquidError::invalid(format!("{name} is not a decimal")))?;
    if !parsed.is_finite() || parsed <= 0.0 {
        return Err(HyperliquidError::invalid(format!("{name} must be > 0")));
    }
    Ok(())
}

pub fn validate_exchange_response(value: &Value) -> Result<()> {
    if value.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(HyperliquidError::Action(value.to_string()));
    }
    let statuses = value
        .pointer("/response/data/statuses")
        .and_then(Value::as_array);
    if let Some(statuses) = statuses {
        for status in statuses {
            if let Some(err) = status.get("error").and_then(Value::as_str) {
                return Err(HyperliquidError::Action(err.to_string()));
            }
        }
    }
    Ok(())
}

pub fn pretty_json(value: &Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    s.push('\n');
    s.into_bytes()
}

pub fn decimal_to_wire(raw: &str) -> Result<String> {
    validate_decimal_string("decimal", raw)?;
    Ok(raw.to_string())
}

pub fn asset_id_from_spot_index(index: u32) -> u32 {
    10_000 + index
}

pub fn builder_perp_asset_id(perp_dex_index: u32, index_in_meta: u32) -> u32 {
    100_000 + perp_dex_index * 10_000 + index_in_meta
}

pub fn outcome_asset_id(outcome: u32, side: u32) -> Result<u32> {
    if side > 1 {
        return Err(HyperliquidError::invalid("outcome side must be 0 or 1"));
    }
    Ok(100_000_000 + 10 * outcome + side)
}

pub fn u256_from_u64(n: u64) -> U256 {
    U256::from(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_order() -> ExchangeAction {
        ExchangeAction::Order {
            orders: vec![OrderWire {
                asset: 0,
                is_buy: true,
                price: "1000".into(),
                size: "0.01".into(),
                reduce_only: false,
                order_type: OrderTypeWire {
                    limit: Some(LimitOrderType {
                        tif: TimeInForce::Gtc,
                    }),
                    trigger: None,
                },
                cloid: Some("0x1234567890abcdef1234567890abcdef".into()),
            }],
            grouping: Grouping::Na,
            builder: None,
        }
    }

    #[tokio::test]
    async fn usd_send_signs_user_action_and_recovers_owner() {
        let pk = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let owner: PrivateKeySigner = pk.parse().unwrap();
        let owner_addr = owner.address();
        let signer = HyperliquidSigner::new(Arc::new(owner));
        let dest: Address = "0x000000000000000000000000000000000000dead"
            .parse()
            .unwrap();
        let nonce = 1_700_000_001_000u64;

        let (action, sig) = signer
            .sign_usd_send(HyperliquidNetwork::Mainnet, dest, "100", nonce)
            .await
            .unwrap();

        assert_eq!(action["type"], "usdSend");
        assert_eq!(action["hyperliquidChain"], "Mainnet");
        assert_eq!(action["signatureChainId"], "0xa4b1");
        assert_eq!(
            action["destination"],
            "0x000000000000000000000000000000000000dead"
        );
        assert_eq!(action["amount"], "100");
        assert_eq!(action["time"], nonce);

        let typed = usd_send_typed_data(HyperliquidNetwork::Mainnet, dest, "100", nonce).unwrap();
        let hash = typed.eip712_signing_hash().unwrap();
        let recovered = format!("0x{}{}{:02x}", &sig.r[2..], &sig.s[2..], sig.v)
            .parse::<Signature>()
            .unwrap()
            .recover_address_from_prehash(&hash)
            .unwrap();
        assert_eq!(recovered, owner_addr);
    }

    #[tokio::test]
    async fn approve_agent_signs_user_action_and_recovers_owner() {
        // Fixed key so the typed-data hash / recovery is deterministic.
        let pk = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let owner: PrivateKeySigner = pk.parse().unwrap();
        let owner_addr = owner.address();
        let signer = HyperliquidSigner::new(Arc::new(owner));
        let agent: Address = "0x000000000000000000000000000000000000a9e7"
            .parse()
            .unwrap();
        let nonce = 1_700_000_000_000u64;

        let (action, sig) = signer
            .sign_approve_agent(HyperliquidNetwork::Mainnet, agent, Some("bot"), nonce)
            .await
            .unwrap();

        // Mainnet user-signed actions sign on Arbitrum One (0xa4b1) per docs.
        assert_eq!(action["type"], "approveAgent");
        assert_eq!(action["hyperliquidChain"], "Mainnet");
        assert_eq!(action["signatureChainId"], "0xa4b1");
        assert_eq!(
            action["agentAddress"],
            "0x000000000000000000000000000000000000a9e7"
        );
        assert_eq!(action["agentName"], "bot");
        assert_eq!(action["nonce"], nonce);

        // Self-consistency: the signature recovers to the owner over the same
        // HyperliquidSignTransaction digest (domain chainId == payload
        // signatureChainId == 0xa4b1). This proves our signing matches the
        // documented scheme; it deliberately does NOT pin a byte-exact vector
        // (a self-computed pin would just assert our code against itself).
        let typed =
            approve_agent_typed_data(HyperliquidNetwork::Mainnet, agent, "bot", nonce).unwrap();
        let hash = typed.eip712_signing_hash().unwrap();
        let recovered = format!("0x{}{}{:02x}", &sig.r[2..], &sig.s[2..], sig.v)
            .parse::<Signature>()
            .unwrap()
            .recover_address_from_prehash(&hash)
            .unwrap();
        assert_eq!(recovered, owner_addr);

        // Per docs: mainnet signs on Arbitrum One, testnet on Arbitrum Sepolia.
        assert_eq!(HyperliquidNetwork::Mainnet.signature_chain_id(), 0xa4b1);
        assert_eq!(HyperliquidNetwork::Testnet.signature_chain_id(), 0x66eee);
    }

    #[test]
    fn retry_backoff_is_bounded_and_grows() {
        // Each attempt stays within [100*n, 100*n + 100) ms (base + <100ms jitter).
        for attempt in 1..=MAX_POST_RETRIES {
            let ms = retry_backoff(attempt).as_millis() as u64;
            let base = 100 * u64::from(attempt);
            assert!(
                (base..base + 100).contains(&ms),
                "attempt {attempt}: {ms}ms out of [{base}, {})",
                base + 100
            );
        }
    }

    #[test]
    fn user_signed_payload_has_no_vault_field() {
        let p = user_signed_payload(
            json!({"type": "approveAgent"}),
            7,
            SignatureJson {
                r: "0x01".into(),
                s: "0x02".into(),
                v: 27,
            },
        );
        assert_eq!(p["nonce"], 7);
        assert_eq!(p["action"]["type"], "approveAgent");
        assert!(p.get("vaultAddress").is_none());
        assert_eq!(p["signature"]["v"], 27);
    }

    #[test]
    fn rejects_trailing_zero_decimal() {
        let mut action = sample_order();
        if let ExchangeAction::Order { orders, .. } = &mut action {
            orders[0].price = "1000.0".into();
        }
        assert!(
            action
                .validate()
                .unwrap_err()
                .to_string()
                .contains("trailing")
        );
    }

    #[test]
    fn cancel_false_fast_is_rejected_before_signing() {
        let action = ExchangeAction::Cancel {
            cancels: vec![CancelWire { asset: 0, oid: 1 }],
            fast: Some(false),
        };
        assert!(action.validate().is_err());
    }

    #[test]
    fn nested_exchange_errors_fail_closed() {
        let v = json!({"status":"ok","response":{"type":"order","data":{"statuses":[{"error":"bad"}]}}});
        assert!(matches!(
            validate_exchange_response(&v),
            Err(HyperliquidError::Action(_))
        ));
    }

    #[test]
    fn action_hash_is_stable_for_same_payload() {
        let action = sample_order();
        let a = action_hash(&action, 1, None, None).unwrap();
        let b = action_hash(&action, 1, None, None).unwrap();
        assert_eq!(a, b);
        let c = action_hash(&action, 2, None, None).unwrap();
        assert_ne!(a, c);
    }
}
