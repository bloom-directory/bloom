//! Unauthenticated JSON-RPC transport shared by the private orderflow
//! adapters (Flashbots Protect, MEV-Blocker).

use alloy::primitives::{B256, Bytes};

use crate::private::{HealthStatus, PrivateRpcError};

fn transport(e: reqwest::Error) -> PrivateRpcError {
    PrivateRpcError::Transport(e.to_string())
}

pub(super) fn http_client() -> Result<reqwest::Client, PrivateRpcError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(transport)
}

async fn call(
    http: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, PrivateRpcError> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    http.post(url)
        .json(&body)
        .send()
        .await
        .map_err(transport)?
        .error_for_status()
        .map_err(transport)?
        .json()
        .await
        .map_err(transport)
}

/// `eth_sendRawTransaction`, returning the provider-reported tx hash.
pub(super) async fn send_raw_transaction(
    http: &reqwest::Client,
    url: &str,
    signed_raw_tx: &Bytes,
) -> Result<B256, PrivateRpcError> {
    let raw_hex = format!("0x{}", hex::encode(signed_raw_tx.as_ref()));
    let resp = call(
        http,
        url,
        "eth_sendRawTransaction",
        serde_json::json!([raw_hex]),
    )
    .await?;
    if let Some(err) = resp.get("error") {
        return Err(PrivateRpcError::ProviderError(err.to_string()));
    }
    let hash_str = resp
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PrivateRpcError::ProviderError("missing result".into()))?;
    hash_str
        .parse()
        .map_err(|e| PrivateRpcError::ProviderError(format!("{e}")))
}

/// `eth_blockNumber` liveness probe.
pub(super) async fn health(
    http: &reqwest::Client,
    url: &str,
) -> Result<HealthStatus, PrivateRpcError> {
    let resp = call(http, url, "eth_blockNumber", serde_json::json!([])).await?;
    if resp.get("error").is_some() {
        Ok(HealthStatus::Unhealthy)
    } else if resp.get("result").is_some() {
        Ok(HealthStatus::Healthy)
    } else {
        Ok(HealthStatus::Degraded)
    }
}
