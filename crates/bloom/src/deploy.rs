//! Local developer-tool bridge. Wallet keys and upstream credentials stay in
//! their existing services. The path token permits submission, never approval.
use super::{ResolvedEndpoint, machine_command};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use bloom_daemon::ipc::MachineCommand;
use clap::{Args, Subcommand};
use rand::RngCore;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

#[derive(Debug, Args)]
pub struct DeployArgs {
    #[arg(long)]
    wallet: String,
    #[arg(long)]
    chain: String,
    #[command(subcommand)]
    command: DeployCommand,
}
#[derive(Debug, Subcommand)]
enum DeployCommand {
    /// Serve a local authenticated EVM RPC endpoint. Prints its URL as JSON.
    Rpc,
    /// List durable submission IDs for this wallet and chain.
    List,
    /// Inspect the plan, approval, transaction, and receipt without executing.
    Status { id: String },
    /// Continue one exact submission after owner approval. Does not restage it.
    Resume { id: String },
}

#[derive(Clone)]
struct Bridge {
    endpoint: ResolvedEndpoint,
    wallet: String,
    chain: String,
    host: String,
    slots: Arc<tokio::sync::Semaphore>,
}
impl Bridge {
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let output = machine_command(
            &self.endpoint,
            MachineCommand::DeploymentRpc {
                wallet: self.wallet.clone(),
                chain: self.chain.clone(),
                method: method.into(),
                params,
            },
        )
        .await?;
        serde_json::from_str(&output.stdout).context("invalid deployment RPC response")
    }
    async fn request(&self, req: Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let error = |code, message: &str, data: Value| json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message,"data":data}});
        if !req.is_object()
            || req.get("jsonrpc") != Some(&json!("2.0"))
            || !(id.is_string() || id.is_number())
        {
            return error(
                -32600,
                "a JSON-RPC 2.0 request with an ID is required",
                Value::Null,
            );
        }
        let Some(method) = req.get("method").and_then(Value::as_str) else {
            return error(-32600, "method is required", Value::Null);
        };
        let params = req.get("params").cloned().unwrap_or_else(|| json!([]));
        // HTTP clients may observe and submit. Execution after an approval wait
        // is an explicit local `bloom deploy resume` operation, not background work.
        if method == "bloom_deploymentContinue" {
            return error(
                -32601,
                "use bloom deploy resume to continue a submission",
                Value::Null,
            );
        }
        let reply = match self.call(method, params).await {
            Ok(r) => r,
            Err(_) => {
                return error(
                    -32000,
                    "Bloom Machine unavailable; retry the same request",
                    Value::Null,
                );
            }
        };
        if method != "eth_sendTransaction" || reply.get("error").is_some() {
            return envelope(id, reply);
        }
        let Some(job) = reply.pointer("/result/id").and_then(Value::as_str) else {
            return error(-32603, "missing durable submission ID", Value::Null);
        };
        let first = match self.call("bloom_deploymentContinue", json!([job])).await {
            Ok(r) => r,
            Err(_) => {
                return error(
                    -32000,
                    "submission staged; inspect its status before retrying",
                    json!({"id":job}),
                );
            }
        };
        if let Some(plan) = first.pointer("/result/plan").and_then(Value::as_str) {
            eprintln!("{plan}");
        }
        eprintln!(
            "Deployment {job}\nInspect/continue: bloom deploy --wallet {} --chain {} resume {job}",
            self.wallet, self.chain
        );
        if let Some(url) = first
            .pointer("/result/approval/ceremony_url")
            .and_then(Value::as_str)
        {
            eprintln!("Owner approval: {url}");
        }
        let mut status = first;
        // Waiting for a human approval and waiting for chain execution are
        // different obligations. The approval phase is bounded by the
        // ceremony's own expiry (the owner is still deliberating while it is
        // alive); execution after signing gets a tight clock. Both timeouts
        // leave the durable submission discoverable and resumable.
        let mut execution_deadline: Option<tokio::time::Instant> = None;
        let fallback_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(hash) = status
                .pointer("/result/transaction/tx_hash")
                .and_then(Value::as_str)
            {
                return json!({"jsonrpc":"2.0","id":id,"result":hash});
            }
            if status
                .pointer("/result/status")
                .and_then(Value::as_str)
                .is_some_and(|s| matches!(s, "failed" | "blocked" | "reverted"))
                || status.get("error").is_some()
                || status
                    .pointer("/result/error")
                    .is_some_and(|e| !e.is_null())
            {
                return error(
                    -32000,
                    "deployment blocked; inspect the durable submission",
                    json!({"id":job,"status":status}),
                );
            }
            let phase = status
                .pointer("/result/status")
                .and_then(Value::as_str)
                .unwrap_or("staged");
            if phase == "approval_required" {
                execution_deadline = None;
                let expires_ms = status
                    .pointer("/result/approval/expires_ms")
                    .and_then(|field| {
                        field
                            .as_u64()
                            .or_else(|| field.as_str().and_then(|s| s.parse::<u64>().ok()))
                    });
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let expired = expires_ms
                    .map(|expires| now_ms >= expires)
                    .unwrap_or(tokio::time::Instant::now() >= fallback_deadline);
                if expired {
                    return error(
                        -32001,
                        "owner ceremony expired; continue this ID to prepare a fresh ceremony, then retry the original request",
                        json!({"id":job}),
                    );
                }
            } else {
                let deadline = execution_deadline
                    .get_or_insert_with(|| tokio::time::Instant::now() + Duration::from_secs(120));
                if tokio::time::Instant::now() >= *deadline {
                    return error(
                        -32001,
                        "execution pending after signing; continue this ID, then retry the original request",
                        json!({"id":job}),
                    );
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            status = match self.call("bloom_deploymentStatus", json!([job])).await {
                Ok(r) => r,
                Err(_) => {
                    return error(
                        -32000,
                        "Machine disconnected; recover this submission",
                        json!({"id":job}),
                    );
                }
            };
        }
    }
}
fn envelope(id: Value, mut reply: Value) -> Value {
    reply["jsonrpc"] = json!("2.0");
    reply["id"] = id;
    reply
}
async fn handle(
    State(bridge): State<Bridge>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    if headers.contains_key("origin")
        || headers.get("host").and_then(|h| h.to_str().ok()) != Some(&bridge.host)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let _permit = bridge
        .slots
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let result = if let Some(batch) = request.as_array() {
        if batch.is_empty() || batch.len() > 16 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let mut replies = Vec::new();
        for item in batch {
            replies.push(bridge.request(item.clone()).await);
        }
        json!(replies)
    } else {
        bridge.request(request).await
    };
    Ok(Json(result))
}

pub async fn run(endpoint: ResolvedEndpoint, args: DeployArgs) -> Result<()> {
    super::validate_wallet_name(&args.wallet)?;
    super::validate_wallet_name(&args.chain)?;
    let mut bridge = Bridge {
        endpoint,
        wallet: args.wallet,
        chain: args.chain,
        host: String::new(),
        slots: Arc::new(tokio::sync::Semaphore::new(32)),
    };
    if let DeployCommand::Rpc = args.command {
        let info = bridge.call("bloom_deploymentInfo", json!([])).await?;
        anyhow::ensure!(info.get("error").is_none(), "{info}");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        bridge.host = listener.local_addr()?.to_string();
        let mut token = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token);
        let path = format!("/{}", hex::encode(token));
        let url = format!("http://{}{path}", bridge.host);
        let app = Router::new()
            .route(&path, post(handle))
            .layer(DefaultBodyLimit::max(256 * 1024))
            .with_state(bridge);
        println!(
            "{}",
            json!({"rpc_url":url,"wallet":info["result"]["wallet"],"chain":info["result"]["chain"],"from":info["result"]["from"]})
        );
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                #[cfg(unix)]
                {
                    let mut term =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .expect("signal handler");
                    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
                }
                #[cfg(not(unix))]
                {
                    let _ = tokio::signal::ctrl_c().await;
                }
            })
            .await?;
    } else {
        let (method, params) = match args.command {
            DeployCommand::List => ("bloom_deploymentList", json!([])),
            DeployCommand::Status { id } => ("bloom_deploymentStatus", json!([id])),
            DeployCommand::Resume { id } => ("bloom_deploymentContinue", json!([id])),
            DeployCommand::Rpc => unreachable!(),
        };
        let result = bridge.call(method, params).await?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        anyhow::ensure!(
            result.get("error").is_none()
                && result.pointer("/result/error").is_none_or(Value::is_null),
            "deployment requires attention"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResolvedEndpoint;
    use axum::extract::State;

    fn bridge() -> Bridge {
        Bridge {
            endpoint: ResolvedEndpoint {
                socket: std::path::PathBuf::from("/tmp/bloom-test.sock"),
                display: "unix:/tmp/bloom-test.sock".into(),
            },
            wallet: "alice".into(),
            chain: "anvil".into(),
            host: "127.0.0.1:1234".into(),
            slots: Arc::new(tokio::sync::Semaphore::new(32)),
        }
    }

    #[tokio::test]
    async fn request_rejects_malformed_calls_before_contacting_machine() {
        let bridge = bridge();
        // No ID: rejected without touching the Machine socket.
        let reply = bridge
            .request(json!({"jsonrpc": "2.0", "method": "eth_chainId"}))
            .await;
        assert_eq!(reply["error"]["code"], -32600);
        // Wrong protocol version.
        let reply = bridge
            .request(json!({"jsonrpc": "1.0", "id": 1, "method": "eth_chainId"}))
            .await;
        assert_eq!(reply["error"]["code"], -32600);
        // Missing method.
        let reply = bridge.request(json!({"jsonrpc": "2.0", "id": 1})).await;
        assert_eq!(reply["error"]["message"], "method is required");
        // Continue over HTTP would bypass the explicit resume step.
        let reply = bridge
            .request(
                json!({"jsonrpc": "2.0", "id": 1, "method": "bloom_deploymentContinue", "params": ["deploy-abc"]}),
            )
            .await;
        assert_eq!(reply["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn handle_enforces_origin_host_and_batch_limits() {
        let bridge = bridge();
        let single = Json(json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId"}));
        // Browser origins are never served.
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://localhost:3000".parse().unwrap());
        headers.insert("host", "127.0.0.1:1234".parse().unwrap());
        assert_eq!(
            handle(State(bridge.clone()), headers, single.clone())
                .await
                .unwrap_err(),
            StatusCode::FORBIDDEN
        );
        // Host must be the bound loopback address (token alone is not enough).
        let mut headers = HeaderMap::new();
        headers.insert("host", "evil.example".parse().unwrap());
        assert_eq!(
            handle(State(bridge.clone()), headers, single.clone())
                .await
                .unwrap_err(),
            StatusCode::FORBIDDEN
        );
        // Batches are bounded on both ends.
        let mut headers = HeaderMap::new();
        headers.insert("host", "127.0.0.1:1234".parse().unwrap());
        for batch in [
            json!([]),
            json!(vec![json!({"jsonrpc": "2.0", "id": 1, "method": "x"}); 17]),
        ] {
            assert_eq!(
                handle(State(bridge.clone()), headers.clone(), Json(batch))
                    .await
                    .unwrap_err(),
                StatusCode::BAD_REQUEST
            );
        }
    }
}
