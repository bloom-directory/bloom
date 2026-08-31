//! Layered JSON-RPC transport for Solana.
//!
//! Mirrors `bloom-rpc`'s `transport.rs` shape for the parts that translate:
//! a `reqwest`-based JSON-RPC client over a weighted endpoint list, with
//! retry-on-transient, failover across endpoints, and an active `getHealth`
//! probe loop feeding the shared [`HealthRegistry`]. The `alloy` transport
//! stack (`RootProvider<Ethereum>`, `FallbackLayer`) is deliberately not
//! reused — Solana's JSON-RPC methods and response shapes do not fit it.

use std::time::{Duration, Instant};

use bloom_rpc_common::HealthRegistry;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::watch;

use crate::error::SolanaRpcError;
use crate::retry::{RetrySignal, should_retry};

/// Maximum retry passes across the endpoint list. Matches `bloom-rpc`'s
/// `MAX_RETRIES` so both transports budget transient recovery identically.
const MAX_ATTEMPTS: usize = 3;

/// Initial backoff; doubles per attempt (200 → 400 → 800 ms).
const INITIAL_BACKOFF_MS: u64 = 200;

/// Hard bound for one HTTP request, including body receipt. Without this a
/// connected endpoint that stops responding can stall failover indefinitely.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Active probe interval, matching `bloom-rpc`'s cadence.
const PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// One configured endpoint and its pre-built client.
struct Endpoint {
    url: String,
    weight: u32,
    client: reqwest::Client,
}

/// A collapsed transport failure with its retry classification.
struct CallFailure {
    error: SolanaRpcError,
    retryable: bool,
}

/// The shared Solana RPC transport. Built once per [`crate::SolanaSpec`] and
/// shared via `Arc`.
pub struct SolanaRpcClient {
    chain_name: String,
    endpoints: Vec<Endpoint>,
    health: HealthRegistry,
    shutdown_tx: Option<watch::Sender<bool>>,
}

impl SolanaRpcClient {
    /// Build the transport from a spec. Fails with
    /// [`SolanaRpcError::NoEndpoints`] when no usable endpoint is configured.
    pub fn build(spec: &crate::SolanaSpec) -> Result<Self, SolanaRpcError> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| SolanaRpcError::Transport(e.to_string()))?;
        let mut endpoints = Vec::new();
        for ep in &spec.endpoints {
            if ep.url.starts_with("ws://") || ep.url.starts_with("wss://") {
                continue; // read client is HTTP-only for now
            }
            endpoints.push(Endpoint {
                url: ep.url.clone(),
                weight: ep.weight,
                client: client.clone(),
            });
        }
        if endpoints.is_empty() {
            return Err(SolanaRpcError::NoEndpoints(spec.name.clone()));
        }
        endpoints.sort_by_key(|e| std::cmp::Reverse(e.weight));

        let health = HealthRegistry::new(endpoints.iter().map(|e| e.url.clone()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let client = Self {
            chain_name: spec.name.clone(),
            endpoints,
            health,
            shutdown_tx: Some(shutdown_tx),
        };

        client.spawn_probe_loop(shutdown_rx);
        Ok(client)
    }

    /// Per-endpoint health snapshot, mirroring `bloom-rpc`'s accessor.
    pub fn endpoints_snapshot(&self) -> Vec<bloom_rpc_common::EndpointHealthSnapshot> {
        self.health.snapshot()
    }

    /// Number of endpoints currently in cooldown.
    pub fn cooled_down_count(&self) -> usize {
        self.health.cooled_down_count()
    }

    /// The chain name this transport was built for.
    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    /// One JSON-RPC call with retry + failover. Returns the decoded `result`.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: &Value,
    ) -> Result<T, SolanaRpcError> {
        let value = self.call_raw(method, params).await?;
        serde_json::from_value::<T>(value)
            .map_err(|e| SolanaRpcError::Decode(format!("{method}: {e}")))
    }

    /// One JSON-RPC call with retry + failover, returning the raw `result`.
    ///
    /// A non-retryable error from one endpoint (e.g. "method not
    /// supported") says nothing about any *other* configured endpoint, so
    /// it must not short-circuit the whole call — every endpoint gets
    /// tried in this pass before giving up, matching EVM's
    /// `alloy`-`FallbackLayer` behaviour (dispatches to all endpoints, only
    /// fails once every one does), which this module's doc comment already
    /// claims but previously didn't implement.
    ///
    /// A *retryable* error from every endpoint is worth one more pass:
    /// the whole endpoint list is tried again up to `MAX_ATTEMPTS` times.
    /// A non-retryable error from any endpoint is deterministic — rotating
    /// endpoints or retrying the same one won't change the answer, so the
    /// call fails immediately rather than wasting the budget on retries
    /// that can't succeed.
    pub async fn call_raw(&self, method: &str, params: &Value) -> Result<Value, SolanaRpcError> {
        let mut last: Option<SolanaRpcError> = None;
        for attempt in 0..MAX_ATTEMPTS {
            let mut had_non_retryable = false;
            for (idx, endpoint) in self.endpoints.iter().enumerate() {
                let started = Instant::now();
                match self.post(endpoint, method, params).await {
                    Ok(value) => {
                        self.health.record_success(idx, started.elapsed(), None);
                        return Ok(value);
                    }
                    Err(failure) => {
                        let backoff = failure.retryable.then(|| backoff_for(attempt));
                        self.health.record_failure(idx, failure.retryable, backoff);
                        // Record and move on to the next endpoint regardless
                        // of retryability — only exhausting every endpoint
                        // (across all attempt passes) gives up.
                        last = Some(failure.error);
                        if !failure.retryable {
                            had_non_retryable = true;
                        }
                    }
                }
            }
            // A deterministic failure is a capability or argument error, not
            // a transient blip. Retrying won't change the answer; bail now
            // rather than burning the rest of the budget on identical calls.
            if had_non_retryable {
                break;
            }
            // Every endpoint failed with retryable errors; pause before the
            // next pass.
            if attempt + 1 < MAX_ATTEMPTS {
                tokio::time::sleep(backoff_for(attempt)).await;
            }
        }
        Err(last.unwrap_or_else(|| SolanaRpcError::NoEndpoints(self.chain_name.clone())))
    }

    /// Verify that every configured HTTP endpoint belongs to `expected`.
    ///
    /// Ordinary reads may fail over as soon as one endpoint answers. A write
    /// cannot use that rule: checking endpoint A and later submitting through
    /// endpoint B would leave B's cluster identity unproved. Any unreachable,
    /// malformed, or mismatched endpoint therefore fails the whole check.
    pub async fn verify_all_genesis(&self, expected: &str) -> Result<String, SolanaRpcError> {
        for endpoint in &self.endpoints {
            let observed = self
                .post(endpoint, "getGenesisHash", &serde_json::json!([]))
                .await
                .map_err(|failure| failure.error)?;
            let observed = observed.as_str().ok_or_else(|| {
                SolanaRpcError::Decode(format!(
                    "getGenesisHash from {} returned {observed}",
                    endpoint.url
                ))
            })?;
            if observed != expected {
                return Err(SolanaRpcError::GenesisMismatch {
                    chain: self.chain_name.clone(),
                    expected: expected.to_string(),
                    observed: observed.to_string(),
                });
            }
        }
        Ok(expected.to_string())
    }

    /// Submit one write through the highest-priority endpoint, after every
    /// configured endpoint has proved the pinned genesis.
    ///
    /// The write is deliberately attempted exactly once. A transport error can
    /// be an ambiguous outcome, so retry/failover belongs in signature-based
    /// reconciliation rather than in the RPC transport.
    pub async fn call_raw_after_genesis_check<F>(
        &self,
        expected: &str,
        method: &str,
        params: &Value,
        before_send: F,
    ) -> Result<Value, SolanaRpcError>
    where
        F: FnOnce() -> Result<(), SolanaRpcError>,
    {
        self.verify_all_genesis(expected).await?;
        before_send()?;
        self.post(&self.endpoints[0], method, params)
            .await
            .map_err(|failure| failure.error)
    }

    /// One raw HTTP POST, collapsing transport + node errors into a
    /// classified [`CallFailure`].
    async fn post(
        &self,
        endpoint: &Endpoint,
        method: &str,
        params: &Value,
    ) -> Result<Value, CallFailure> {
        let body =
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response = endpoint
            .client
            .post(&endpoint.url)
            .json(&body)
            .send()
            .await
            .map_err(classify_reqwest_error)?;

        let status = response.status();
        if !status.is_success() {
            let retryable = should_retry(RetrySignal::HttpStatus(status.as_u16()));
            return Err(CallFailure {
                error: SolanaRpcError::Transport(format!(
                    "{} returned HTTP {}",
                    endpoint.url,
                    status.as_u16()
                )),
                retryable,
            });
        }

        let payload: Value = response.json().await.map_err(|e| CallFailure {
            error: SolanaRpcError::Decode(e.to_string()),
            retryable: false,
        })?;

        if let Some(error) = payload.get("error") {
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or_default()
                .to_string();
            let retryable = should_retry(RetrySignal::RpcError {
                code,
                message: &message,
            });
            return Err(CallFailure {
                error: SolanaRpcError::Rpc { code, message },
                retryable,
            });
        }

        Ok(payload.get("result").cloned().unwrap_or(Value::Null))
    }

    fn spawn_probe_loop(&self, mut shutdown_rx: watch::Receiver<bool>) {
        let chain = self.chain_name.clone();
        let endpoints: Vec<(usize, String, reqwest::Client)> = self
            .endpoints
            .iter()
            .enumerate()
            .map(|(i, e)| (i, e.url.clone(), e.client.clone()))
            .collect();
        let health = self.health.clone();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::debug!(chain = %chain, "solana.health.probe_loop_skipped_no_runtime");
            return;
        };
        handle.spawn(async move {
            tracing::info!(
                chain = %chain,
                endpoints = endpoints.len(),
                "solana.health.probe_loop_started"
            );
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(PROBE_INTERVAL) => {}
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            return;
                        }
                    }
                }
                for (idx, url, client) in &endpoints {
                    let started = Instant::now();
                    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "getHealth", "params": [] });
                    let result = client.post(url).json(&body).send().await;
                    match result {
                        Ok(resp) if resp.status().is_success() => {
                            health.record_success(*idx, started.elapsed(), None);
                        }
                        Ok(resp) => {
                            let retryable = should_retry(RetrySignal::HttpStatus(resp.status().as_u16()));
                            health.record_failure(*idx, retryable, None);
                        }
                        Err(_) => {
                            health.record_failure(*idx, true, None);
                        }
                    }
                }
            }
        });
    }
}

impl Drop for SolanaRpcClient {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}

fn backoff_for(attempt: usize) -> Duration {
    Duration::from_millis(INITIAL_BACKOFF_MS << attempt.min(8))
}

fn classify_reqwest_error(e: reqwest::Error) -> CallFailure {
    if e.is_timeout() || e.is_connect() {
        return CallFailure {
            error: SolanaRpcError::Transport(e.to_string()),
            retryable: true,
        };
    }
    CallFailure {
        error: SolanaRpcError::Transport(e.to_string()),
        retryable: false,
    }
}
