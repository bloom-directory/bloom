//! Tempo MPP protocol adapter for Bloom paid HTTP requests.

use async_trait::async_trait;
use bloom_keystore::{Keystore, KeystoreError, WalletKind};
use bloom_paid_http::{
    EmptyPaidHttpChainRpcResolver, NormalizedChallenge, PaidHttpChainRpcResolver, ParsedRequest,
};
use bloom_proto::Policy;
use mpp::client::{PaymentProvider, TempoProvider, TempoSessionProvider};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::json;
use std::sync::Arc;

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
    pub rpc_resolver: Arc<dyn PaidHttpChainRpcResolver>,
}

impl RealMppBackend {
    pub fn new(
        keystore: Keystore,
        client: reqwest::Client,
        rpc_resolver: Arc<dyn PaidHttpChainRpcResolver>,
    ) -> Self {
        Self {
            keystore,
            client,
            rpc_resolver,
        }
    }

    pub fn without_rpc_resolver(keystore: Keystore, client: reqwest::Client) -> Self {
        Self::new(keystore, client, Arc::new(EmptyPaidHttpChainRpcResolver))
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
        let chain_id = challenge
            .chain_id
            .ok_or_else(|| "Tempo MPP challenge missing chainId".to_string())?;
        let rpc_url = self
            .rpc_resolver
            .http_rpc_url_for_chain_id(chain_id)
            .ok_or_else(|| {
                format!("no configured HTTP RPC URL for Tempo MPP chain_id {chain_id}")
            })?;
        let payment_challenge = parse_stored_mpp_challenge(challenge)?;
        let credential = match challenge.intent.as_str() {
            "charge" => {
                let provider = TempoProvider::new((*signer).clone(), &rpc_url)
                    .map_err(|e| format!("TempoProvider: {e}"))?;
                provider.pay(&payment_challenge).await
            }
            "session" => {
                let mut provider = TempoSessionProvider::new((*signer).clone(), &rpc_url)
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
                "raw_signed_payload_stored": false,
                "chain_id": chain_id,
                "rpc_url_configured": true
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
        if is_sensitive_retry_header(k) {
            continue;
        }
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

fn is_sensitive_retry_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "x-payment"
            | "payment-signature"
            | "x-api-key"
            | "api-key"
            | "apikey"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    #[tokio::test]
    async fn paid_retry_replaces_probe_authorization_header() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            tx.send(raw).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                .unwrap();
        });

        let mut headers = BTreeMap::new();
        headers.insert("authorization".to_string(), "Payment".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        let request = ParsedRequest {
            method: "POST".to_string(),
            url: format!("http://{addr}/paid").parse().unwrap(),
            wallet: Some("gavin".to_string()),
            max_amount_usd: None,
            headers,
            body: Some(r#"{"ok":true}"#.to_string()),
        };

        let response =
            retry_paid_request(&reqwest::Client::new(), &request, "Payment signed").await;
        assert_eq!(response.unwrap().status, 200);

        let raw = rx.recv().unwrap();
        let auth_lines: Vec<_> = raw
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            .collect();
        assert_eq!(auth_lines, vec!["authorization: Payment signed"]);
    }
}
