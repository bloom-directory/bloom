//! UDS JSON-RPC server at `<bloom_home>/chain/rpc.sock`.
//!
//! JSON-RPC 2.0 over a Unix domain socket, line-delimited (one request per
//! line, one response per line).  Reuses the line-delimited convention from
//! `bloom-rpc` / the existing daemon IPC without pulling in that crate.
//!
//! An optional TCP listener (same line-delimited JSON-RPC 2.0 framing) can be
//! enabled alongside the UDS listener via [`RpcServer::serve_tcp`]; this is
//! used by the docker-compose testnet harness where UDS sockets do not
//! traverse container/host boundaries cleanly (especially on macOS).
//!
//! # Methods
//!
//! - `chain_submit_tx` — admit a base64/hex-encoded SSZ `Tx` to the mempool.
//! - `chain_query_account` — look up account state by address.
//! - `chain_query_block` — look up a block by height or hash.
//! - `chain_query_tx` — look up a tx receipt by hash. Returns `null` if the
//!   tx hasn't been executed yet (or was never seen), or an object with
//!   `success`/`fuel_used`/`return_data`/`return_text`/`logs`.
//! - `chain_query_state` — look up a storage slot for a contract.
//! - `chain_ls_validators` — list the current validator set.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use bloom_chain_consensus::ValidatorSet;
use bloom_chain_state::State;
use bloom_chain_types::ssz::Decode;
use bloom_chain_types::{
    tx::Tx,
    types::{Address, Hash32},
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tracing::{debug, error, warn};

use crate::block_store::BlockStore;
use crate::mempool_persist::MempoolPersist;

// ---------------------------------------------------------------------------
// JSON-RPC framing
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: Value, code: i64, message: &str) -> Self {
        JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(json!({ "code": code, "message": message })),
        }
    }
}

// ---------------------------------------------------------------------------
// RpcServer
// ---------------------------------------------------------------------------

/// Shared handles exposed to the RPC handler.
#[derive(Clone)]
pub struct RpcServer {
    pub state: Arc<Mutex<State>>,
    pub block_store: Arc<BlockStore>,
    pub mempool_persist: Arc<MempoolPersist>,
    pub receipt_store: Arc<crate::receipt_store::ReceiptStore>,
    pub validator_set: Arc<ValidatorSet>,
    /// Sender for admitting txs to the in-memory mempool. The worker that
    /// receives on the other end performs mempool admission synchronously and
    /// replies via the oneshot — see `node.rs` § "Tx admission from RPC →
    /// mempool". The reply lets `chain_submit_tx` surface real rejection
    /// reasons (nonce mismatch, bad sig, insufficient balance) to the caller
    /// instead of silently warn-logging them.
    pub tx_submit: tokio::sync::mpsc::Sender<(
        Tx,
        tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
    )>,
}

impl RpcServer {
    /// Bind the UDS listener and accept connections.
    pub async fn serve(self, socket_path: &Path) -> Result<()> {
        // Remove stale socket.
        if socket_path.exists() {
            std::fs::remove_file(socket_path)
                .with_context(|| format!("remove stale socket: {}", socket_path.display()))?;
        }
        // Ensure parent dir exists.
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(socket_path)
            .with_context(|| format!("bind UDS: {}", socket_path.display()))?;
        debug!(socket = %socket_path.display(), "rpc.listening");

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let srv = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = srv.handle_connection(stream).await {
                            warn!(err = %e, "rpc.connection_error");
                        }
                    });
                }
                Err(e) => {
                    error!(err = %e, "rpc.accept_error");
                }
            }
        }
    }

    /// Bind a TCP listener on `addr` and accept JSON-RPC connections in parallel
    /// with [`RpcServer::serve`]. The TCP listener uses the exact same
    /// line-delimited JSON-RPC 2.0 framing as the UDS path; no TLS / auth.
    pub async fn serve_tcp(self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind RPC TCP: {addr}"))?;
        debug!(addr = %addr, "rpc.tcp.listening");

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let srv = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = srv.handle_connection(stream).await {
                            warn!(err = %e, "rpc.tcp.connection_error");
                        }
                    });
                }
                Err(e) => {
                    error!(err = %e, "rpc.tcp.accept_error");
                }
            }
        }
    }

    async fn handle_connection<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut lines = BufReader::new(read_half).lines();

        while let Some(line) = lines.next_line().await? {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            let response = self.dispatch_line(&line).await;
            let serialized = serde_json::to_string(&response)? + "\n";
            write_half.write_all(serialized.as_bytes()).await?;
        }
        Ok(())
    }

    async fn dispatch_line(&self, line: &str) -> JsonRpcResponse {
        let req = match serde_json::from_str::<JsonRpcRequest>(line) {
            Ok(r) => r,
            Err(e) => {
                return JsonRpcResponse::err(Value::Null, -32700, &format!("parse error: {e}"));
            }
        };
        let id = req.id.clone().unwrap_or(Value::Null);

        let result = self.dispatch(&req.method, &req.params).await;
        match result {
            Ok(v) => JsonRpcResponse::ok(id, v),
            Err(e) => JsonRpcResponse::err(id, -32000, &e.to_string()),
        }
    }

    async fn dispatch(&self, method: &str, params: &Value) -> Result<Value> {
        match method {
            "chain_submit_tx" => self.handle_submit_tx(params).await,
            "chain_query_account" => self.handle_query_account(params),
            "chain_query_block" => self.handle_query_block(params),
            "chain_query_tx" => self.handle_query_tx(params),
            "chain_query_state" => self.handle_query_state(params),
            "chain_ls_validators" => self.handle_ls_validators(),
            "chain_tip" => self.handle_tip(),
            _ => Err(anyhow!("method not found: {method}")),
        }
    }

    // -----------------------------------------------------------------------
    // Handlers
    // -----------------------------------------------------------------------

    async fn handle_submit_tx(&self, params: &Value) -> Result<Value> {
        // Params: { "tx_hex": "<hex-encoded SSZ tx>" }
        // or: { "tx_b64": "<base64-encoded SSZ tx>" }
        let tx_bytes = if let Some(h) = params.get("tx_hex").and_then(Value::as_str) {
            hex::decode(h).context("decode tx_hex")?
        } else if let Some(b) = params.get("tx_bytes").and_then(Value::as_array) {
            b.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect()
        } else {
            return Err(anyhow!("chain_submit_tx: missing 'tx_hex' param"));
        };

        let tx = Tx::from_ssz_bytes(&tx_bytes).map_err(|e| anyhow!("SSZ decode tx: {:?}", e))?;

        let tx_hash = tx.tx_hash();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.tx_submit
            .send((tx, reply_tx))
            .await
            .map_err(|_| anyhow!("mempool channel closed"))?;
        match reply_rx
            .await
            .map_err(|_| anyhow!("mempool admission worker dropped reply"))?
        {
            Ok(()) => Ok(json!({ "tx_hash": hex::encode(tx_hash.0) })),
            Err(msg) => Err(anyhow!("mempool admit rejected: {msg}")),
        }
    }

    fn handle_query_account(&self, params: &Value) -> Result<Value> {
        // Params: { "address": "<hex or b1 address>" }
        let addr_str = params
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing 'address' param"))?;
        let addr = parse_address(addr_str)?;
        let state = self.state.lock();
        match state.get_account(&addr) {
            None => Ok(json!(null)),
            Some(acct) => Ok(json!({
                "nonce": acct.nonce,
                "loom": acct.loom.to_string(),
                "code_hash": acct.code_hash.map(|h| hex::encode(h.0)),
                "storage_root": hex::encode(acct.storage_root.0),
            })),
        }
    }

    fn handle_query_block(&self, params: &Value) -> Result<Value> {
        // Params: { "height": <u64> } or { "hash": "<hex>" }
        //
        // The CLI accepts either form (`bloom chain query block <h_or_hash>`,
        // spec §12). Hash lookup walks the on-disk block-store window via
        // `BlockStore::get_by_hash` — v0 retention is ≤ 512 blocks so a
        // linear scan is fine.
        let block = if let Some(h) = params.get("height").and_then(Value::as_u64) {
            self.block_store.get(h)?
        } else if let Some(hash_str) = params.get("hash").and_then(Value::as_str) {
            let hash_bytes = hex::decode(hash_str).context("decode block hash hex")?;
            if hash_bytes.len() != 32 {
                return Err(anyhow!(
                    "block hash must be 32 bytes (got {})",
                    hash_bytes.len()
                ));
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&hash_bytes);
            let block_hash = Hash32(h);
            self.block_store.get_by_hash(&block_hash)?
        } else {
            return Err(anyhow!(
                "chain_query_block: provide either 'height' or 'hash'"
            ));
        };

        match block {
            None => Ok(json!(null)),
            Some(block) => Ok(json!({
                "height": block.header.height,
                "hash": hex::encode(block.header.block_hash().0),
                "parent_hash": hex::encode(block.header.parent_hash.0),
                "timestamp_ms": block.header.timestamp_ms,
                "proposer": hex::encode(block.header.proposer.0),
                "txs_root": hex::encode(block.header.txs_root.0),
                "state_root": hex::encode(block.header.state_root.0),
                "fuel_used": block.header.fuel_used,
                "fuel_limit": block.header.fuel_limit,
                "tx_count": block.txs.len(),
                "tx_hashes": block.txs.iter().map(|t| hex::encode(t.tx_hash().0)).collect::<Vec<_>>(),
            })),
        }
    }

    fn handle_query_tx(&self, params: &Value) -> Result<Value> {
        // Params: { "tx_hash": "<32-byte hex>" }
        // Returns null if not yet executed (still pending or unknown).
        let h_str = params
            .get("tx_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing 'tx_hash' param"))?;
        let h_bytes = hex::decode(h_str).context("decode tx_hash hex")?;
        if h_bytes.len() != 32 {
            return Err(anyhow!("tx_hash must be 32 bytes (got {})", h_bytes.len()));
        }
        let mut th = [0u8; 32];
        th.copy_from_slice(&h_bytes);
        let tx_hash = bloom_chain_types::types::Hash32(th);

        match self.receipt_store.get(&tx_hash)? {
            None => Ok(Value::Null),
            Some(r) => {
                // Decode return_data as UTF-8 if possible — petal-side revert
                // reasons are emitted as plain strings, so this lets the CLI
                // surface them without forcing every caller to hex-decode.
                let return_text = std::str::from_utf8(&r.return_data)
                    .ok()
                    .map(|s| s.to_string());
                Ok(json!({
                    "tx_hash": hex::encode(r.tx_hash.0),
                    "success": r.success,
                    "fuel_used": r.fuel_used,
                    "return_data": hex::encode(&r.return_data),
                    "return_text": return_text,
                    "logs": r.logs.iter().map(|l| json!({
                        "address": hex::encode(l.address.0),
                        "topics": l.topics.iter().map(|t| hex::encode(t.0)).collect::<Vec<_>>(),
                        "data": hex::encode(&l.data),
                    })).collect::<Vec<_>>(),
                }))
            }
        }
    }

    fn handle_query_state(&self, params: &Value) -> Result<Value> {
        // Params: { "address": "<hex>", "key": "<32-byte hex>" }
        let addr_str = params
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing 'address' param"))?;
        let key_str = params
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing 'key' param"))?;

        let addr = parse_address(addr_str)?;
        let key_bytes = hex::decode(key_str).context("decode key hex")?;
        if key_bytes.len() != 32 {
            return Err(anyhow!("key must be 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        let state = self.state.lock();
        let value = state.storage_read(&addr, &key);
        Ok(json!({ "value": hex::encode(value) }))
    }

    fn handle_ls_validators(&self) -> Result<Value> {
        let vs = &self.validator_set;
        let list: Vec<Value> = vs
            .validators()
            .iter()
            .map(|v| {
                json!({
                    "address": hex::encode(v.address.0),
                    "pubkey_len": v.pubkey.0.len(),
                    "voting_power": v.voting_power,
                })
            })
            .collect();
        Ok(json!({
            "total_power": vs.total_power(),
            "quorum": vs.quorum(),
            "validators": list,
        }))
    }

    fn handle_tip(&self) -> Result<Value> {
        let h = self.block_store.latest_height()?.unwrap_or(0);
        Ok(json!({ "height": h }))
    }
}

// ---------------------------------------------------------------------------
// RpcClient — thin client for CLI subcommands
// ---------------------------------------------------------------------------

/// Selects whether [`RpcClient`] dials a Unix domain socket or a TCP
/// `host:port`. The line-delimited JSON-RPC 2.0 wire format is identical.
#[derive(Debug, Clone)]
enum Transport {
    Uds(std::path::PathBuf),
    Tcp(String),
}

/// Thin client that sends one JSON-RPC request and returns the result.
/// Used by CLI subcommands like `bloom chain query account`.
pub struct RpcClient {
    transport: Transport,
}

impl RpcClient {
    /// Connect over a Unix domain socket. Back-compat constructor — existing
    /// callers (UDS-only) continue to work unchanged.
    pub fn new(socket_path: &Path) -> Self {
        RpcClient {
            transport: Transport::Uds(socket_path.to_path_buf()),
        }
    }

    /// Connect over TCP to `host:port` (line-delimited JSON-RPC 2.0, plain
    /// TCP, no TLS / auth — test infrastructure only).
    pub fn tcp(addr: impl Into<String>) -> Self {
        RpcClient {
            transport: Transport::Tcp(addr.into()),
        }
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let line = serde_json::to_string(&request)? + "\n";

        match &self.transport {
            Transport::Uds(path) => {
                let stream = UnixStream::connect(path)
                    .await
                    .with_context(|| format!("connect to chain RPC socket: {}", path.display()))?;
                let (read_half, mut write_half) = stream.into_split();
                write_half.write_all(line.as_bytes()).await?;
                drop(write_half);
                read_one_response(read_half).await
            }
            Transport::Tcp(addr) => {
                let stream = TcpStream::connect(addr)
                    .await
                    .with_context(|| format!("connect to chain RPC TCP: {addr}"))?;
                let (read_half, mut write_half) = stream.into_split();
                write_half.write_all(line.as_bytes()).await?;
                drop(write_half);
                read_one_response(read_half).await
            }
        }
    }
}

/// Read exactly one line-delimited JSON-RPC response and extract `result`.
async fn read_one_response<R>(read_half: R) -> Result<Value>
where
    R: AsyncRead + Unpin,
{
    let mut lines = BufReader::new(read_half).lines();
    let response_line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("RPC: no response"))?;

    let resp: serde_json::Map<String, Value> = serde_json::from_str(&response_line)?;

    if let Some(err) = resp.get("error") {
        return Err(anyhow!("RPC error: {}", err));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("RPC: missing 'result' field"))
}

// ---------------------------------------------------------------------------
// Address parser
// ---------------------------------------------------------------------------

fn parse_address(s: &str) -> Result<Address> {
    // Accept 64-char hex or b1-prefixed.
    if s.len() == 64 {
        let bytes = hex::decode(s).context("decode address hex")?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(Address(arr));
        }
    }
    // Delegate to genesis parser for b1 format.
    crate::genesis::parse_b1_address(s)
}
