//! Tempo MPP protocol adapter for Bloom paid HTTP requests.

use async_trait::async_trait;
use bloom_keystore::{Keystore, KeystoreError, WalletKind};
use bloom_paid_http::{NormalizedChallenge, ParsedRequest};
use bloom_proto::Policy;
use mpp::client::{PaymentProvider, TempoProvider, TempoSessionProvider};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::json;

#[async_trait]
pub trait PaymentBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn confirm(
        &self,
        challenge: &NormalizedChallenge,
        request: &ParsedRequest,
        wallet: &str,
        policy: &Policy,
        request_id: &str,
    ) -> Result<PaymentExecution, String>;
}

pub struct RealMppBackend {
    pub keystore: Keystore,
    pub client: reqwest::Client,
    pub rpc_url: String,
}

impl RealMppBackend {
    pub fn new(keystore: Keystore, client: reqwest::Client, rpc_url: String) -> Self {
        Self {
            keystore,
            client,
            rpc_url,
        }
    }

    fn signer_error(&self, wallet: &str, err: KeystoreError) -> String {
        match err {
            KeystoreError::Locked(_) => {
                let kind = self
                    .keystore
                    .raw_policy(wallet)
                    .ok()
                    .map(|(_, kind)| kind)
                    .or_else(|| self.keystore.info(wallet).ok().map(|info| info.kind));
                if kind == Some(WalletKind::PasskeyGated) {
                    format!(
                        "passkey wallet '{wallet}' is locked; run the foreground passkey unlock flow (`unlock-passkey` / Keystore::unlock_passkey) before confirming Tempo MPP payments"
                    )
                } else {
                    format!(
                        "wallet '{wallet}' is locked; unlock it before confirming Tempo MPP payments"
                    )
                }
            }
            other => format!("wallet '{wallet}' cannot be used for Tempo MPP signing: {other}"),
        }
    }
}

pub struct PaymentExecution {
    pub credential_metadata: serde_json::Value,
    pub receipt_raw: serde_json::Value,
    pub response_status: u16,
    pub response_headers: HeaderMap,
    pub response_body: Vec<u8>,
}

#[async_trait]
impl PaymentBackend for RealMppBackend {
    fn name(&self) -> &'static str {
        "mpp_tempo"
    }

    async fn confirm(
        &self,
        challenge: &NormalizedChallenge,
        request: &ParsedRequest,
        wallet: &str,
        policy: &Policy,
        _request_id: &str,
    ) -> Result<PaymentExecution, String> {
        if challenge.protocol != "mpp" || challenge.network.as_deref() != Some("tempo") {
            return Err(
                "only Tempo MPP challenges can be confirmed by the real MPP backend".to_string(),
            );
        }
        let signer = self
            .keystore
            .signer(wallet)
            .map_err(|e| self.signer_error(wallet, e))?;
        let payment_challenge = parse_stored_mpp_challenge(challenge)?;
        let credential = match challenge.intent.as_str() {
            "charge" => {
                let provider = TempoProvider::new((*signer).clone(), &self.rpc_url)
                    .map_err(|e| format!("TempoProvider: {e}"))?;
                provider.pay(&payment_challenge).await
            }
            "session" => {
                let mut provider = TempoSessionProvider::new((*signer).clone(), &self.rpc_url)
                    .map_err(|e| format!("TempoSessionProvider: {e}"))?;
                if let Some(max) = policy
                    .payments
                    .sessions
                    .max_deposit_usd
                    .and_then(f64_to_u128_amount)
                {
                    provider = provider.with_max_deposit(max);
                }
                provider.pay(&payment_challenge).await
            }
            other => {
                return Err(format!("unsupported MPP intent '{other}'"));
            }
        }
        .map_err(|e| format!("Tempo MPP credential: {e}"))?;
        let authorization = mpp::format_authorization(&credential)
            .map_err(|e| format!("format MPP Authorization: {e}"))?;
        let authorization_sha256 = bloom_tools::sha256_hex(authorization.as_bytes());
        let credential_value = serde_json::to_value(&credential)
            .map_err(|e| format!("serialize MPP credential metadata: {e}"))?;
        let retry = retry_paid_request(&self.client, request, &authorization).await?;
        let receipt_raw = retry
            .headers
            .get("payment-receipt")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| mpp::parse_receipt(h).ok())
            .and_then(|r| serde_json::to_value(r).ok())
            .unwrap_or_else(|| json!({}));
        Ok(PaymentExecution {
            credential_metadata: json!({
                "redacted": true,
                "protocol": challenge.protocol,
                "intent": challenge.intent,
                "backend": self.name(),
                "authorization_sha256": authorization_sha256,
                "source": credential_value.get("source").cloned(),
                "payload_type": credential_value.get("payload").and_then(|p| p.get("type")).cloned(),
                "charge_id": challenge.charge_id,
                "session_id": challenge.session_id,
                "channel_id": challenge.channel_id,
                "secret_material_in_vfs": false,
                "raw_authorization_stored": false,
                "raw_signed_payload_stored": false
            }),
            receipt_raw,
            response_status: retry.status,
            response_headers: retry.headers,
            response_body: retry.body,
        })
    }
}

fn parse_stored_mpp_challenge(
    challenge: &NormalizedChallenge,
) -> Result<mpp::PaymentChallenge, String> {
    challenge
        .headers
        .get("www-authenticate")
        .and_then(|h| {
            mpp::parse_www_authenticate_all([h.as_str()])
                .into_iter()
                .filter_map(Result::ok)
                .find(|c| c.method.as_str() == "tempo" && c.intent.as_str() == challenge.intent)
        })
        .ok_or_else(|| {
            "stored challenge is missing a parseable Tempo MPP WWW-Authenticate header".to_string()
        })
}

fn f64_to_u128_amount(v: f64) -> Option<u128> {
    if v.is_finite() && v >= 0.0 {
        Some(v.floor() as u128)
    } else {
        None
    }
}

pub struct RetryResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

async fn retry_paid_request(
    client: &reqwest::Client,
    request: &ParsedRequest,
    authorization: &str,
) -> Result<RetryResponse, String> {
    let mut req = client.request(
        request.method.parse().unwrap_or(reqwest::Method::GET),
        request.url.clone(),
    );
    for (k, v) in &request.headers {
        let name =
            HeaderName::from_bytes(k.as_bytes()).map_err(|e| format!("invalid header {k}: {e}"))?;
        let val = HeaderValue::from_str(v).map_err(|e| format!("invalid header {k}: {e}"))?;
        req = req.header(name, val);
    }
    req = req.header(reqwest::header::AUTHORIZATION, authorization);
    if let Some(body) = &request.body {
        req = req.body(body.clone());
    }
    let response = req
        .send()
        .await
        .map_err(|e| format!("paid HTTP retry failed: {e}"))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(|e| format!("read paid HTTP retry response: {e}"))?
        .to_vec();
    Ok(RetryResponse {
        status,
        headers,
        body,
    })
}
