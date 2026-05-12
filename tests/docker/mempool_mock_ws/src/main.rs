//! Mempool mock WebSocket server.
//!
//! Emulates Alchemy's `alchemy_pendingTransactions` subscription by cycling
//! through a fixture file and emitting notifications every 200 ms per
//! connected client.
//!
//! Configuration via environment variables:
//!   MOCK_LISTEN_ADDR   — bind address (default: 0.0.0.0:9551)
//!   MOCK_FIXTURE_PATH  — path to JSON fixture array
//!                        (default: /workspace/tests/docker/mempool_mock_ws/fixture.json)

use std::sync::Arc;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, interval};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:9551";
const DEFAULT_FIXTURE_PATH: &str = "/workspace/tests/docker/mempool_mock_ws/fixture.json";
const TICK_MS: u64 = 200;

#[tokio::main]
async fn main() -> Result<()> {
    let addr =
        std::env::var("MOCK_LISTEN_ADDR").unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
    let fixture_path =
        std::env::var("MOCK_FIXTURE_PATH").unwrap_or_else(|_| DEFAULT_FIXTURE_PATH.to_string());

    let raw = std::fs::read_to_string(&fixture_path)
        .with_context(|| format!("reading fixture: {fixture_path}"))?;
    let fixture: Vec<Value> = serde_json::from_str(&raw).context("parsing fixture JSON array")?;
    anyhow::ensure!(!fixture.is_empty(), "fixture array must not be empty");

    let fixture = Arc::new(fixture);

    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding to {addr}"))?;
    eprintln!(
        "[mock] listening on {addr} ({} fixture entries)",
        fixture.len()
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        eprintln!("[mock] connection from {peer}");
        let fixture = Arc::clone(&fixture);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, fixture).await {
                eprintln!("[mock] connection error ({peer}): {e}");
            }
            eprintln!("[mock] disconnected: {peer}");
        });
    }
}

async fn handle_connection(stream: TcpStream, fixture: Arc<Vec<Value>>) -> Result<()> {
    let ws = accept_async(stream).await.context("WS upgrade")?;
    let (mut sink, mut source) = ws.split();

    // Wait for the eth_subscribe request before starting the ticker.
    let sub_id = loop {
        let msg = match source.next().await {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                eprintln!("[mock] recv error: {e}");
                return Ok(());
            }
            None => return Ok(()),
        };

        let txt = match msg.into_text() {
            Ok(t) => t,
            Err(_) => continue,
        };

        let req: Value = match serde_json::from_str(&txt) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[mock] parse error: {e} — raw: {txt}");
                continue;
            }
        };

        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let id = req.get("id").cloned().unwrap_or(Value::Null);

        if method == "eth_subscribe" {
            // Accept alchemy_pendingTransactions or newPendingTransactions
            // (and tolerate a missing / mismatched second param).
            let first_param = req
                .get("params")
                .and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if matches!(
                first_param,
                "alchemy_pendingTransactions" | "newPendingTransactions"
            ) {
                let reply = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": "0x1"
                });
                sink.send(Message::Text(reply.to_string()))
                    .await
                    .context("send subscribe ack")?;
                break "0x1";
            }
        }

        // Any other method: respond with method-not-found.
        let err_reply = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": "method not implemented"}
        });
        sink.send(Message::Text(err_reply.to_string()))
            .await
            .context("send error reply")?;
    };

    // Start the ticker loop — emit one fixture entry every TICK_MS.
    let mut ticker = interval(Duration::from_millis(TICK_MS));
    let mut idx: usize = 0;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let entry = &fixture[idx % fixture.len()];
                idx += 1;
                let notif = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "eth_subscription",
                    "params": {
                        "subscription": sub_id,
                        "result": entry
                    }
                });
                if sink.send(Message::Text(notif.to_string())).await.is_err() {
                    break;
                }
            }
            msg = source.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // ignore pings / other frames
                    Some(Err(e)) => {
                        eprintln!("[mock] stream error: {e}");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
