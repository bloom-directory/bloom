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
//! - `chain_query_object` — look up an on-chain object by 32-byte id.
//! - `chain_query_code` — look up code bytes by 32-byte content hash.
//! - `chain_resolve_path` — resolve a signed manifest module path to a petal hash.
//! - `chain_ls_objects` — scan objects filtered by owner address or type name.
//! - `chain_ls_validators` — list the current validator set.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use bloom_chain_consensus::ValidatorSet;
use bloom_chain_state::State;
use bloom_chain_types::ssz::Decode;
use bloom_chain_types::{
    tx::Tx,
    types::{Address, Hash32},
};
use bloom_objects::Object;
use bloom_petal_manifest::{extract_petal_manifest_v0, to_petal_manifest_stub};
use bloom_script::{ChainStateIface, PetalManifestStub};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, warn};

use crate::block_store::BlockStore;
use crate::mempool_persist::MempoolPersist;

pub const RPC_MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const RPC_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const RPC_MAX_TX_BYTES: usize = 1024 * 1024;
const RPC_MAX_TCP_CONNECTIONS: usize = 128;
const RPC_READ_TIMEOUT: Duration = Duration::from_secs(10);
const RPC_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const RPC_READINESS_MAX_TIP_AGE: Duration = Duration::from_secs(30);

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
    pub chain_id: String,
    pub genesis_hash: Hash32,
    pub local_address: Address,
    /// Latest block height observed during node startup. Readiness requires
    /// the persisted tip to advance beyond this height.
    pub startup_height: u64,
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
        // Ensure parent dir exists.
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        remove_stale_socket(socket_path)?;
        let listener = match UnixListener::bind(socket_path) {
            Ok(listener) => listener,
            Err(first) => {
                remove_stale_socket(socket_path)?;
                UnixListener::bind(socket_path).with_context(|| {
                    format!(
                        "bind UDS after stale socket cleanup: {} (first error kind={:?}, err={})",
                        socket_path.display(),
                        first.kind(),
                        first
                    )
                })?
            }
        };
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
        let permits = Arc::new(Semaphore::new(RPC_MAX_TCP_CONNECTIONS));

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        warn!(addr = %addr, "rpc.tcp.connection_rejected: limit reached");
                        continue;
                    };
                    let srv = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
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
        let mut reader = BufReader::new(read_half);
        let mut buf = Vec::new();

        loop {
            buf.clear();
            let n =
                tokio::time::timeout(RPC_READ_TIMEOUT, read_bounded_line(&mut reader, &mut buf))
                    .await
                    .map_err(|_| anyhow!("RPC read timeout"))??;
            if n == 0 {
                break;
            }
            if buf.len() > RPC_MAX_REQUEST_BYTES {
                return Err(anyhow!(
                    "RPC request frame too large: {} > {}",
                    buf.len(),
                    RPC_MAX_REQUEST_BYTES
                ));
            }
            let line = std::str::from_utf8(&buf)
                .context("RPC request is not UTF-8")?
                .trim();
            if line.is_empty() {
                continue;
            }
            let response = self.dispatch_line(line).await;
            let serialized = serde_json::to_string(&response)? + "\n";
            if serialized.len() > RPC_MAX_RESPONSE_BYTES {
                return Err(anyhow!(
                    "RPC response frame too large: {} > {}",
                    serialized.len(),
                    RPC_MAX_RESPONSE_BYTES
                ));
            }
            tokio::time::timeout(
                RPC_WRITE_TIMEOUT,
                write_half.write_all(serialized.as_bytes()),
            )
            .await
            .map_err(|_| anyhow!("RPC write timeout"))??;
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
            "chain_query_object" => self.handle_query_object(params),
            "chain_query_code" => self.handle_query_code(params),
            "chain_resolve_path" => self.handle_resolve_path(params),
            "chain_ls_objects" => self.handle_ls_objects(params),
            "chain_ls_validators" => self.handle_ls_validators(),
            "chain_tip" => self.handle_tip(),
            "chain_health" => self.handle_health(),
            _ => Err(anyhow!("method not found: {method}")),
        }
    }

    // -----------------------------------------------------------------------
    // Handlers
    // -----------------------------------------------------------------------

    async fn handle_submit_tx(&self, params: &Value) -> Result<Value> {
        let tx_bytes = parse_submit_tx_bytes(params)?;
        if tx_bytes.len() > RPC_MAX_TX_BYTES {
            return Err(anyhow!(
                "chain_submit_tx: tx bytes too large: {} > {}",
                tx_bytes.len(),
                RPC_MAX_TX_BYTES
            ));
        }

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
                "receipts_root": hex::encode(block.header.receipts_root.0),
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

    fn handle_query_object(&self, params: &Value) -> Result<Value> {
        // Params: { "id": "<64-hex object id>" }
        // Returns null if no object with that id exists.
        let id_str = params
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing 'id' param"))?;
        let id_bytes = hex::decode(id_str).context("decode object id hex")?;
        if id_bytes.len() != 32 {
            return Err(anyhow!(
                "object id must be 32 bytes (got {})",
                id_bytes.len()
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_bytes);
        let object_id = bloom_objects::ObjectId(id);

        let state = self.state.lock();
        match state.get_object(&object_id) {
            None => Ok(Value::Null),
            Some(obj) => Ok(object_to_json(&obj)),
        }
    }

    fn handle_query_code(&self, params: &Value) -> Result<Value> {
        // Params: { "hash": "<64-hex content hash>" }
        // Returns null if no code with that hash exists.
        let hash = parse_hash_param(params, "hash")?;
        let state = self.state.lock();
        match state.get_code(&hash) {
            None => Ok(Value::Null),
            Some(bytes) => Ok(json!({ "hash": hex::encode(hash.0), "bytes": hex::encode(bytes) })),
        }
    }

    fn handle_resolve_path(&self, params: &Value) -> Result<Value> {
        // Params: { "path": "/bloom/module/path" }
        // Returns null if no deployed petal manifest owns the path.
        let path = params
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing 'path' param"))?;
        let state = self.state.lock();
        match state.vfs_lookup(path) {
            None => Ok(Value::Null),
            Some(hash) => Ok(json!({ "hash": hex::encode(hash.0) })),
        }
    }

    fn handle_ls_objects(&self, params: &Value) -> Result<Value> {
        // Params: { "owner_addr": "<hex>" } OR { "type_name": "<str>" }.
        // Scans every object and returns a JSON array of the same per-object
        // shape as `chain_query_object`, filtered by the supplied predicate.
        // Exactly one of the two filters must be present.
        let owner_filter = params
            .get("owner_addr")
            .and_then(Value::as_str)
            .map(|s| {
                let b = hex::decode(s).context("decode owner_addr hex")?;
                if b.len() != 32 {
                    return Err(anyhow!("owner_addr must be 32 bytes (got {})", b.len()));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                Ok::<_, anyhow::Error>(a)
            })
            .transpose()?;
        let type_filter = params.get("type_name").and_then(Value::as_str);
        if owner_filter.is_none() == type_filter.is_none() {
            return Err(anyhow!(
                "chain_ls_objects: provide exactly one of 'owner_addr' or 'type_name'"
            ));
        }

        let state = self.state.lock();
        let mut out = Vec::new();
        for (_id, obj) in state.iter_objects() {
            let keep = match (&owner_filter, type_filter) {
                (Some(addr), _) => matches!(
                    &obj.owner,
                    bloom_objects::Owner::Address(a) | bloom_objects::Owner::Object(bloom_objects::ObjectId(a))
                        if a == addr
                ),
                (None, Some(name)) => matches!(
                    &obj.type_tag,
                    bloom_objects::TypeTag::Concrete { type_name, .. } if type_name == name
                ),
                (None, None) => unreachable!("filter presence checked above"),
            };
            if keep {
                out.push(object_to_json(obj));
            }
        }
        Ok(Value::Array(out))
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

    fn handle_health(&self) -> Result<Value> {
        let height = self.block_store.latest_height()?.unwrap_or(0);
        let latest_block = if height == 0 {
            None
        } else {
            self.block_store.get(height)?
        };
        let state_root = latest_block.as_ref().map(|block| block.header.state_root);
        let now_ms = unix_time_ms();
        let max_tip_age_ms = RPC_READINESS_MAX_TIP_AGE.as_millis() as u64;
        let tip_age_ms = latest_block
            .as_ref()
            .map(|block| now_ms.saturating_sub(block.header.timestamp_ms));
        let tip_recent = tip_age_ms.is_some_and(|age| age <= max_tip_age_ms);
        let height_advanced = height > self.startup_height;
        let ready = height_advanced && tip_recent;
        let not_ready_reason = if ready {
            Value::Null
        } else if !height_advanced {
            json!("waiting_for_height_progress")
        } else if latest_block.is_none() {
            json!("latest_tip_unavailable")
        } else if !tip_recent {
            json!("latest_tip_stale")
        } else {
            json!("not_ready")
        };
        Ok(json!({
            "ok": ready,
            "live": true,
            "ready": ready,
            "not_ready_reason": not_ready_reason,
            "chain_id": self.chain_id,
            "genesis_hash": hex::encode(self.genesis_hash.0),
            "validator_address": hex::encode(self.local_address.0),
            "height": height,
            "startup_height": self.startup_height,
            "tip_age_ms": tip_age_ms,
            "max_tip_age_ms": max_tip_age_ms,
            "state_root": state_root.map(|root| hex::encode(root.0)),
            "latest_block_hash": latest_block.as_ref().map(|block| hex::encode(block.header.block_hash().0)),
            "validator_set_hash": hex::encode(self.validator_set.validator_set_hash().0),
        }))
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn remove_stale_socket(socket_path: &Path) -> Result<()> {
    match std::fs::remove_file(socket_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove stale socket: {}", socket_path.display())),
    }
}

async fn read_bounded_line<R>(reader: &mut BufReader<R>, out: &mut Vec<u8>) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(out.len());
        }
        let take = available
            .iter()
            .position(|b| *b == b'\n')
            .map(|pos| pos + 1)
            .unwrap_or(available.len());
        if out.len().saturating_add(take) > RPC_MAX_REQUEST_BYTES {
            return Err(anyhow!(
                "RPC request frame too large: > {}",
                RPC_MAX_REQUEST_BYTES
            ));
        }
        out.extend_from_slice(&available[..take]);
        reader.consume(take);
        if out.ends_with(b"\n") {
            return Ok(out.len());
        }
    }
}

fn parse_submit_tx_bytes(params: &Value) -> Result<Vec<u8>> {
    let obj = params
        .as_object()
        .ok_or_else(|| anyhow!("chain_submit_tx: params must be an object"))?;
    let present = ["tx_hex", "tx_b64", "tx_bytes"]
        .iter()
        .filter(|key| obj.contains_key(**key))
        .count();
    if present != 1 {
        return Err(anyhow!(
            "chain_submit_tx: provide exactly one of 'tx_hex', 'tx_b64', or 'tx_bytes'"
        ));
    }

    if let Some(h) = obj.get("tx_hex") {
        let h = h
            .as_str()
            .ok_or_else(|| anyhow!("chain_submit_tx: tx_hex must be a string"))?;
        return hex::decode(h).context("decode tx_hex");
    }
    if let Some(b64) = obj.get("tx_b64") {
        let b64 = b64
            .as_str()
            .ok_or_else(|| anyhow!("chain_submit_tx: tx_b64 must be a string"))?;
        return base64::engine::general_purpose::STANDARD
            .decode(b64)
            .context("decode tx_b64");
    }
    let arr = obj
        .get("tx_bytes")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("chain_submit_tx: tx_bytes must be an array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for (idx, v) in arr.iter().enumerate() {
        let n = v
            .as_u64()
            .ok_or_else(|| anyhow!("chain_submit_tx: tx_bytes[{idx}] must be an integer"))?;
        if n > u8::MAX as u64 {
            return Err(anyhow!(
                "chain_submit_tx: tx_bytes[{idx}] out of range: {n}"
            ));
        }
        out.push(n as u8);
    }
    Ok(out)
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
#[derive(Debug, Clone)]
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

/// Synchronous [`ChainStateIface`] adapter over the node JSON-RPC API.
///
/// The PTB builder/validator is deliberately sync. This adapter bridges to the
/// async RPC client by running each call on a short-lived helper thread, so it
/// is safe to use from both CLI and daemon async runtimes.
#[derive(Debug, Clone)]
pub struct RpcChainAdapter {
    client: RpcClient,
}

impl RpcChainAdapter {
    /// Build an adapter over an existing RPC client.
    pub fn new(client: RpcClient) -> Self {
        Self { client }
    }

    /// Build an adapter from the standard chain socket path.
    pub fn uds(socket_path: &Path) -> Self {
        Self::new(RpcClient::new(socket_path))
    }

    /// Build an adapter from `BLOOM_RPC_TCP` when set, otherwise UDS.
    pub fn from_env_or_socket(socket_path: &Path) -> Self {
        match std::env::var("BLOOM_RPC_TCP") {
            Ok(addr) if !addr.is_empty() => Self::new(RpcClient::tcp(addr)),
            _ => Self::uds(socket_path),
        }
    }

    fn call_blocking(&self, method: &'static str, params: Value) -> Result<Value> {
        let client = self.client.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().context("create RPC helper runtime")?;
            rt.block_on(client.call(method, params))
        })
        .join()
        .map_err(|_| anyhow!("RPC helper thread panicked"))?
    }
}

impl ChainStateIface for RpcChainAdapter {
    fn load_object(&self, id: &bloom_objects::ObjectId) -> Option<Object> {
        let value = self
            .call_blocking("chain_query_object", json!({ "id": hex::encode(id.0) }))
            .ok()?;
        if value.is_null() {
            return None;
        }
        let bytes = hex::decode(value.get("bytes")?.as_str()?).ok()?;
        Object::decode_canonical(&bytes).ok()
    }

    fn load_petal(&self, hash: &Hash32) -> Option<Vec<u8>> {
        let value = self
            .call_blocking("chain_query_code", json!({ "hash": hex::encode(hash.0) }))
            .ok()?;
        if value.is_null() {
            return None;
        }
        hex::decode(value.get("bytes")?.as_str()?).ok()
    }

    fn load_manifest(&self, hash: &Hash32) -> Option<PetalManifestStub> {
        let wasm = self.load_petal(hash)?;
        let manifest = extract_petal_manifest_v0(&wasm)?;
        Some(to_petal_manifest_stub(&manifest))
    }

    fn resolve_path(&self, path: &str) -> Option<Hash32> {
        let value = self
            .call_blocking("chain_resolve_path", json!({ "path": path }))
            .ok()?;
        if value.is_null() {
            return None;
        }
        let bytes = hex::decode(value.get("hash")?.as_str()?).ok()?;
        bytes.try_into().ok().map(Hash32)
    }

    fn current_block(&self) -> u64 {
        self.call_blocking("chain_tip", json!({}))
            .ok()
            .and_then(|v| v.get("height").and_then(Value::as_u64))
            .unwrap_or(0)
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
// Object → JSON
// ---------------------------------------------------------------------------

/// Shape an [`Object`] into the canonical JSON returned by
/// `chain_query_object` / `chain_ls_objects`. `type_name`/`petal_hash` are
/// only populated for `TypeTag::Concrete`; `owner_addr` carries the 32 bytes
/// for `Address`/`Object` owners and is null for `Shared`/`Immutable`.
fn object_to_json(obj: &bloom_objects::Object) -> Value {
    use bloom_objects::{Owner, TypeTag};

    let (type_name, petal_hash) = match &obj.type_tag {
        TypeTag::Concrete {
            petal_hash,
            type_name,
            ..
        } => (Some(type_name.clone()), Some(hex::encode(petal_hash))),
        _ => (None, None),
    };
    let (owner_kind, owner_addr) = match &obj.owner {
        Owner::Address(a) => ("address", Some(hex::encode(a))),
        Owner::Object(id) => ("object", Some(hex::encode(id.0))),
        Owner::Shared => ("shared", None),
        Owner::Immutable => ("immutable", None),
    };
    json!({
        "id": hex::encode(obj.id.0),
        "type_name": type_name,
        "petal_hash": petal_hash,
        "owner_kind": owner_kind,
        "owner_addr": owner_addr,
        "version": obj.version,
        "payload": hex::encode(&obj.payload),
        "bytes": hex::encode(obj.encode_canonical().expect("object canonical encode")),
    })
}

fn parse_hash_param(params: &Value, key: &str) -> Result<Hash32> {
    let s = params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing '{key}' param"))?;
    let bytes = hex::decode(s).with_context(|| format!("decode {key} hex"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{key} must be 32 bytes (got {})", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Hash32(out))
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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_chain_types::block::{Block, BlockHeader};
    use bloom_chain_types::vote::Commit;
    use bloom_objects::{Object, ObjectId, Owner, TypeTag};
    use bloom_test_util::{make_validator_set_signed, make_validator_with_keypair};

    /// Build an `RpcServer` over an in-memory `State` (with tempdir-backed
    /// stores) so the object handlers can be exercised in isolation. Returns
    /// the server plus the tempdir guard, which the caller must keep alive.
    fn make_server() -> (RpcServer, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let block_store = Arc::new(BlockStore::open(&tmp.path().join("blocks")).unwrap());
        let receipt_store = Arc::new(
            crate::receipt_store::ReceiptStore::open(&tmp.path().join("receipts")).unwrap(),
        );
        let mempool_persist =
            Arc::new(MempoolPersist::open(&tmp.path().join("mempool.sled")).unwrap());
        let state = Arc::new(Mutex::new(State::new()));
        let v = make_validator_with_keypair();
        let validator_set = Arc::new(make_validator_set_signed(&[&v], 100));
        let (tx_submit, _rx) = tokio::sync::mpsc::channel(8);
        let server = RpcServer {
            state,
            block_store,
            mempool_persist,
            receipt_store,
            validator_set,
            chain_id: "bloomchain.test".into(),
            genesis_hash: Hash32([0x42; 32]),
            local_address: v.addr,
            startup_height: 0,
            tx_submit,
        };
        (server, tmp)
    }

    fn test_block(height: u64) -> Block {
        test_block_with_timestamp(height, unix_time_ms())
    }

    fn test_block_with_timestamp(height: u64, timestamp_ms: u64) -> Block {
        let block_hash = Hash32([height as u8; 32]);
        Block {
            header: BlockHeader {
                chain_id: "bloomchain.test".into(),
                height,
                parent_hash: Hash32([0xAA; 32]),
                timestamp_ms,
                proposer: Address([0x11; 32]),
                txs_root: Hash32([0x22; 32]),
                state_root: Hash32([0x33; 32]),
                receipts_root: Hash32([0x44; 32]),
                validator_set_hash: Hash32([0x55; 32]),
                fuel_used: 0,
                fuel_limit: 30_000_000,
            },
            txs: vec![],
            commit: Commit {
                height,
                round: 0,
                block_hash,
                votes: vec![],
            },
        }
    }

    /// A `Concrete`-typed object owned by `owner`.
    fn concrete_object(id: u8, type_name: &str, owner: Owner) -> Object {
        Object {
            id: ObjectId([id; 32]),
            type_tag: TypeTag::Concrete {
                petal_hash: [0xAB; 32],
                type_name: type_name.to_string(),
                type_args: vec![],
            },
            owner,
            version: 7,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    #[test]
    fn query_account_does_not_project_coin_balance() {
        let (server, _tmp) = make_server();
        let addr = Address([0xA1; 32]);
        server
            .state
            .lock()
            .set_object(concrete_object(9, "Coin", Owner::Address(addr.0)));

        let account = server
            .handle_query_account(&json!({ "address": hex::encode(addr.0) }))
            .unwrap();

        assert!(account.is_null());
    }

    #[test]
    fn query_object_returns_full_shape() {
        let (server, _tmp) = make_server();
        let owner = [0x11u8; 32];
        let obj = concrete_object(0x42, "Coin", Owner::Address(owner));
        let expected_bytes = hex::encode(obj.encode_canonical().unwrap());
        server.state.lock().set_object(obj);

        let res = server
            .handle_query_object(&json!({ "id": hex::encode([0x42u8; 32]) }))
            .unwrap();
        assert_eq!(res["id"], hex::encode([0x42u8; 32]));
        assert_eq!(res["type_name"], "Coin");
        assert_eq!(res["petal_hash"], hex::encode([0xABu8; 32]));
        assert_eq!(res["owner_kind"], "address");
        assert_eq!(res["owner_addr"], hex::encode(owner));
        assert_eq!(res["version"], 7);
        assert_eq!(res["payload"], "deadbeef");
        assert_eq!(res["bytes"], expected_bytes);
    }

    #[test]
    fn query_object_missing_is_null() {
        let (server, _tmp) = make_server();
        let res = server
            .handle_query_object(&json!({ "id": hex::encode([0x99u8; 32]) }))
            .unwrap();
        assert!(res.is_null());
    }

    #[test]
    fn query_object_rejects_bad_length() {
        let (server, _tmp) = make_server();
        let err = server
            .handle_query_object(&json!({ "id": "deadbeef" }))
            .unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "got: {err}");
    }

    #[test]
    fn submit_tx_params_reject_silent_array_truncation() {
        let err = parse_submit_tx_bytes(&json!({ "tx_bytes": [1, 256, "3"] })).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("out of range") || msg.contains("must be an integer"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn submit_tx_params_require_exactly_one_encoding() {
        let err = parse_submit_tx_bytes(&json!({
            "tx_hex": "00",
            "tx_b64": "AA=="
        }))
        .unwrap_err();
        assert!(
            err.to_string().contains("exactly one"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn health_reports_identity_and_tip() {
        let (server, _tmp) = make_server();
        let res = server.handle_health().unwrap();
        assert_eq!(res["ok"], false);
        assert_eq!(res["live"], true);
        assert_eq!(res["ready"], false);
        assert_eq!(res["not_ready_reason"], "waiting_for_height_progress");
        assert_eq!(res["chain_id"], "bloomchain.test");
        assert_eq!(res["genesis_hash"], hex::encode([0x42u8; 32]));
        assert_eq!(
            res["validator_address"],
            hex::encode(server.local_address.0)
        );
        assert_eq!(res["height"], 0);
        assert_eq!(res["startup_height"], 0);
    }

    #[test]
    fn health_reports_ready_after_height_progress() {
        let (server, _tmp) = make_server();
        server.block_store.put(1, &test_block(1)).unwrap();
        let res = server.handle_health().unwrap();
        assert_eq!(res["ok"], true);
        assert_eq!(res["ready"], true);
        assert_eq!(res["not_ready_reason"], Value::Null);
        assert_eq!(res["height"], 1);
        assert_eq!(res["state_root"], hex::encode([0x33u8; 32]));
        assert!(res["latest_block_hash"].as_str().is_some());
    }

    #[test]
    fn health_rejects_stale_tip_after_height_progress() {
        let (server, _tmp) = make_server();
        server
            .block_store
            .put(1, &test_block_with_timestamp(1, 1))
            .unwrap();
        let res = server.handle_health().unwrap();
        assert_eq!(res["ok"], false);
        assert_eq!(res["ready"], false);
        assert_eq!(res["not_ready_reason"], "latest_tip_stale");
        assert_eq!(res["height"], 1);
    }

    #[test]
    fn query_object_shared_owner_has_null_addr() {
        let (server, _tmp) = make_server();
        let obj = concrete_object(0x01, "Pool", Owner::Shared);
        server.state.lock().set_object(obj);
        let res = server
            .handle_query_object(&json!({ "id": hex::encode([0x01u8; 32]) }))
            .unwrap();
        assert_eq!(res["owner_kind"], "shared");
        assert!(res["owner_addr"].is_null());
    }

    #[test]
    fn ls_objects_filters_by_owner_then_type() {
        let (server, _tmp) = make_server();
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        {
            let mut st = server.state.lock();
            st.set_object(concrete_object(0x01, "Coin", Owner::Address(alice)));
            st.set_object(concrete_object(0x02, "Pool", Owner::Address(alice)));
            st.set_object(concrete_object(0x03, "Coin", Owner::Address(bob)));
        }

        // Filter by owner: two of Alice's objects.
        let by_owner = server
            .handle_ls_objects(&json!({ "owner_addr": hex::encode(alice) }))
            .unwrap();
        let arr = by_owner.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().all(|o| o["owner_addr"] == hex::encode(alice)));

        // Filter by type: two "Coin" objects across owners.
        let by_type = server
            .handle_ls_objects(&json!({ "type_name": "Coin" }))
            .unwrap();
        let arr = by_type.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().all(|o| o["type_name"] == "Coin"));
    }

    #[test]
    fn ls_objects_requires_exactly_one_filter() {
        let (server, _tmp) = make_server();
        // Neither filter.
        assert!(server.handle_ls_objects(&json!({})).is_err());
        // Both filters.
        assert!(
            server
                .handle_ls_objects(
                    &json!({ "owner_addr": hex::encode([0u8; 32]), "type_name": "Coin" })
                )
                .is_err()
        );
    }

    #[test]
    fn query_code_returns_code_bytes() {
        let (server, _tmp) = make_server();
        let wasm = b"\0asm-test".to_vec();
        let hash = server.state.lock().insert_code(&wasm);

        let res = server
            .handle_query_code(&json!({ "hash": hex::encode(hash.0) }))
            .unwrap();
        assert_eq!(res["hash"], hex::encode(hash.0));
        assert_eq!(res["bytes"], hex::encode(wasm));
    }

    #[test]
    fn query_code_missing_is_null() {
        let (server, _tmp) = make_server();
        let res = server
            .handle_query_code(&json!({ "hash": hex::encode([0x55u8; 32]) }))
            .unwrap();
        assert!(res.is_null());
    }

    #[test]
    fn resolve_path_returns_bound_petal_hash() {
        let (server, _tmp) = make_server();
        let hash = Hash32([0xAA; 32]);
        server
            .state
            .lock()
            .set_vfs_binding("/bloom/dex/pool".to_string(), hash);

        let res = server
            .handle_resolve_path(&json!({ "path": "/bloom/dex/pool" }))
            .unwrap();
        assert_eq!(res["hash"], hex::encode(hash.0));
    }

    #[test]
    fn resolve_path_missing_is_null() {
        let (server, _tmp) = make_server();
        let res = server
            .handle_resolve_path(&json!({ "path": "/bloom/missing" }))
            .unwrap();
        assert!(res.is_null());
    }
}
