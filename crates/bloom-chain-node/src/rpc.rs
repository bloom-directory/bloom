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
//! - `chain_list_vfs` — list VFS petal path bindings.
//! - `chain_ls_objects` — scan objects filtered by owner address, type name, or all.
//! - `chain_view_call` — execute one read-only petal call against a snapshot.
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
use bloom_objects::{AccessMode, Object, ObjectId, TypeTag};
use bloom_petal_manifest::{extract_petal_manifest_v0, to_petal_manifest_stub};
use bloom_script::{
    ArgDeclStub, CORE_FUNGIBLE_PATH, ChainStateIface, PetalManifestStub,
    decode_json_const_with_manifest_loader, decode_json_type_tag,
    decode_return_json_with_manifest_loader, loom_coin_type_tag,
    types::{Arg, Command, ExpectedVersion, MoveCmd, PetalRef, PtbTx},
    validator::{SignatureVerifier, ValidationMode},
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, warn};

use crate::block_store::BlockStore;
use crate::mempool_persist::MempoolPersist;
use crate::petal_executor::run_ptb;
use crate::ptb_chain_iface::PtbChainAdapter;
use crate::state_blob::StateBlobStore;
use crate::state_index::StateIndex;

pub const RPC_MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const RPC_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const RPC_MAX_TX_BYTES: usize = 1024 * 1024;
const RPC_MAX_LS_OBJECTS: usize = 1_024;
const RPC_CHAIN_ADAPTER_OBJECT_PAGE_LIMIT: usize = RPC_MAX_LS_OBJECTS;
const DEFAULT_VIEW_FUEL_LIMIT: u64 = 1_000_000;
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

#[derive(Deserialize, Debug)]
struct ViewCallParams {
    #[serde(default)]
    commands: Vec<ViewCommandParams>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    function: Option<String>,
    #[serde(default)]
    hash: Option<String>,
    #[serde(default)]
    type_args: Vec<Value>,
    #[serde(default)]
    args: Vec<Value>,
    #[serde(default)]
    signers: Vec<String>,
    #[serde(default)]
    at_block: Option<u64>,
    #[serde(default)]
    fuel_limit: Option<u64>,
}

#[derive(Deserialize, Debug, Clone)]
struct ViewCommandParams {
    path: String,
    function: String,
    #[serde(default)]
    hash: Option<String>,
    #[serde(default)]
    type_args: Vec<Value>,
    #[serde(default)]
    args: Vec<Value>,
}

#[derive(Debug)]
struct ViewSnapshot {
    state: State,
    height: u64,
    block_ctx: bloom_petals::BlockCtx,
    chain_head: u64,
}

struct ViewNoSignatureVerifier;

impl SignatureVerifier for ViewNoSignatureVerifier {
    fn verify(&self, _digest: &[u8; 32], _pubkey: &[u8; 32], _signature: &[u8]) -> bool {
        unreachable!("ReadOnly validation must not verify signatures")
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
    pub blob_store: Arc<StateBlobStore>,
    pub state_index: Arc<StateIndex>,
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
    /// Node-side maximum for standalone view fuel.
    pub max_view_fuel_limit: u64,
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
            "chain_list_vfs" => self.handle_list_vfs(),
            "chain_ls_objects" => self.handle_ls_objects(params),
            "chain_view_call" => self.handle_view_call(params),
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

    fn handle_list_vfs(&self) -> Result<Value> {
        let state = self.state.lock();
        Ok(json!({
            "bindings": state
                .iter_vfs()
                .map(|(path, hash)| json!({
                    "path": path,
                    "hash": hex::encode(hash.0),
                }))
                .collect::<Vec<_>>()
        }))
    }

    fn handle_ls_objects(&self, params: &Value) -> Result<Value> {
        // Params: { "owner_addr": "<hex>" } OR { "type_name": "<str>" } OR { "all": true }.
        // Optional: { "limit": n, "offset": n }. Returns the same per-object
        // shape as `chain_query_object`, filtered by the supplied predicate.
        // Exactly one filter must be present.
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
        let all_filter = params.get("all").and_then(Value::as_bool) == Some(true);
        let filter_count =
            owner_filter.is_some() as u8 + type_filter.is_some() as u8 + all_filter as u8;
        if filter_count != 1 {
            return Err(anyhow!(
                "chain_ls_objects: provide exactly one of 'owner_addr', 'type_name', or 'all'"
            ));
        }
        let limit = params
            .get("limit")
            .and_then(Value::as_u64)
            .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
            .unwrap_or(RPC_MAX_LS_OBJECTS)
            .min(RPC_MAX_LS_OBJECTS);
        if limit == 0 {
            return Err(anyhow!("chain_ls_objects: limit must be > 0"));
        }
        let offset = params
            .get("offset")
            .and_then(Value::as_u64)
            .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
            .unwrap_or(0);

        let state = self.state.lock();
        let mut out = Vec::new();
        let mut skipped = 0usize;
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
                (None, None) if all_filter => true,
                (None, None) => unreachable!("filter presence checked above"),
            };
            if keep {
                if skipped < offset {
                    skipped += 1;
                    continue;
                }
                out.push(object_to_json(obj));
                if out.len() >= limit {
                    break;
                }
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

    fn handle_view_call(&self, params: &Value) -> Result<Value> {
        let params: ViewCallParams = serde_json::from_value(params.clone())
            .context("chain_view_call: invalid params shape")?;
        let requested_commands = view_commands_from_params(&params)?;
        let snapshot = self.resolve_view_snapshot(params.at_block)?;
        let state = snapshot.state;
        let adapter = PtbChainAdapter::new(&state, snapshot.height);

        let signers = view_signers(&params)?;
        let mut commands = Vec::with_capacity(requested_commands.len());
        let mut response_meta = Vec::with_capacity(requested_commands.len());
        let mut declared_returns = Vec::with_capacity(requested_commands.len());

        for (cmd_idx, cmd) in requested_commands.iter().enumerate() {
            if cmd.path.is_empty() {
                return Err(anyhow!(
                    "chain_view_call: command {cmd_idx}: path must not be empty"
                ));
            }
            if cmd.function.is_empty() {
                return Err(anyhow!(
                    "chain_view_call: command {cmd_idx}: function must not be empty"
                ));
            }
            let bound_hash = adapter
                .resolve_path(&cmd.path)
                .ok_or_else(|| anyhow!("chain_view_call: path not deployed: {}", cmd.path))?;
            let petal_hash = match cmd.hash.as_deref() {
                Some(hash) => {
                    let pinned = parse_hash_hex(hash).with_context(|| {
                        format!("chain_view_call: command {cmd_idx}: decode hash")
                    })?;
                    if pinned != bound_hash {
                        return Err(anyhow!(
                            "chain_view_call: petal hash mismatch for path {}",
                            cmd.path
                        ));
                    }
                    pinned
                }
                None => bound_hash,
            };
            if bound_hash != petal_hash {
                return Err(anyhow!(
                    "chain_view_call: petal hash mismatch for path {}",
                    cmd.path
                ));
            }
            let manifest = adapter
                .load_manifest(&petal_hash)
                .ok_or_else(|| anyhow!("chain_view_call: manifest not found for {}", cmd.path))?;
            let function = manifest.function(&cmd.function).ok_or_else(|| {
                anyhow!(
                    "chain_view_call: function {} not found in {}",
                    cmd.function,
                    cmd.path
                )
            })?;
            if !function.view {
                return Err(anyhow!("FunctionNotAView: {}::{}", cmd.path, cmd.function));
            }
            let type_args = cmd
                .type_args
                .iter()
                .enumerate()
                .map(|(idx, value)| {
                    decode_json_type_tag(value).with_context(|| {
                        format!("chain_view_call: command {cmd_idx}: type_arg {idx}")
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let load_manifest = |hash: &Hash32| adapter.load_manifest(hash);
            let arg_ctx = ViewArgDecodeCtx {
                type_args: &type_args,
                manifest: &manifest,
                self_hash: petal_hash.0,
                load_manifest: &load_manifest,
                state: &state,
            };
            let args = decode_view_args(cmd_idx, &cmd.args, &function.args, &arg_ctx)?;
            declared_returns.push(
                function
                    .returns
                    .iter()
                    .map(|t| {
                        resolve_self_type_refs(&substitute_type_args(t, &type_args), petal_hash.0)
                    })
                    .collect::<Vec<_>>(),
            );
            response_meta.push((cmd.path.clone(), cmd.function.clone(), petal_hash, manifest));
            commands.push(Command::Move(MoveCmd {
                petal: PetalRef {
                    path: cmd.path.clone(),
                    hash: Some(petal_hash),
                },
                function: cmd.function.clone(),
                type_args,
                args,
            }));
        }

        let fuel_limit = params
            .fuel_limit
            .unwrap_or(DEFAULT_VIEW_FUEL_LIMIT)
            .min(self.max_view_fuel_limit.max(1));
        let fungible_petal_hash = state.vfs_lookup(CORE_FUNGIBLE_PATH).ok_or_else(|| {
            anyhow!("chain_view_call: missing required VFS binding for {CORE_FUNGIBLE_PATH}")
        })?;
        let loom_coin_type = loom_coin_type_tag(fungible_petal_hash);
        let tx = PtbTx {
            signers,
            commands,
            gas_payer: ObjectId([0u8; 32]),
            gas_budget: fuel_limit,
            gas_price: 0,
            expiry_block: snapshot.height,
            signatures: vec![],
        };

        let verifier = ViewNoSignatureVerifier;
        let sender = Address(tx.signers.first().copied().unwrap_or([0u8; 32]));
        let run = run_ptb(
            &state,
            snapshot.height,
            snapshot.block_ctx,
            sender,
            &tx,
            loom_coin_type,
            fungible_petal_hash,
            &verifier,
            None,
            ValidationMode::ReadOnly,
            |_validated, snapshot| Ok(snapshot),
        )
        .context("chain_view_call: validation/execution failed")?;
        let report = run.report;

        if !report.success {
            let reason = report
                .reverted_with
                .as_ref()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "view call reverted".to_string());
            return Err(anyhow!("chain_view_call: {reason}"));
        }
        if !report.object_writes.is_empty()
            || !report.object_deletes.is_empty()
            || !report.ownership_changes.is_empty()
            || !report.publish_events.is_empty()
        {
            return Err(anyhow!(
                "chain_view_call: view attempted state changes (writes={}, deletes={}, ownership_changes={}, publish_events={})",
                report.object_writes.len(),
                report.object_deletes.len(),
                report.ownership_changes.len(),
                report.publish_events.len(),
            ));
        }

        let mut out_commands = Vec::with_capacity(response_meta.len());
        for (idx, (path, function, petal_hash, manifest)) in response_meta.into_iter().enumerate() {
            let outputs = report.command_outputs.get(idx).cloned().unwrap_or_default();
            let raw = outputs.iter().map(hex::encode).collect::<Vec<_>>();
            let mut typed = Vec::with_capacity(outputs.len());
            for (ret_idx, bytes) in outputs.iter().enumerate() {
                let Some(tag) = declared_returns.get(idx).and_then(|v| v.get(ret_idx)) else {
                    typed.push(Value::Null);
                    continue;
                };
                let load_manifest = |hash: &Hash32| adapter.load_manifest(hash);
                typed.push(decode_return_json_with_manifest_loader(
                    &manifest,
                    petal_hash.0,
                    tag,
                    bytes,
                    Some(&load_manifest),
                )?);
            }
            out_commands.push(json!({
                "path": path,
                "function": function,
                "petal_hash": hex::encode(petal_hash.0),
                "returns": typed,
                "returns_raw": raw,
                "logs": [],
            }));
        }

        Ok(json!({
            "at_block": snapshot.height,
            "chain_head": snapshot.chain_head,
            "fuel_used": report.fuel_used,
            "commands": out_commands,
            "logs": report.logs.iter().map(|l| json!({
                "petal": hex::encode(l.petal.0),
                "topic": hex::encode(&l.topic),
                "data": hex::encode(&l.data),
            })).collect::<Vec<_>>(),
        }))
    }

    fn resolve_view_snapshot(&self, at_block: Option<u64>) -> Result<ViewSnapshot> {
        let block_head = self.block_store.latest_height()?.unwrap_or(0);
        let indexed_head = self.state_index.latest_height()?.unwrap_or(0);
        let chain_head = block_head.max(indexed_head);
        let height = at_block.unwrap_or(if indexed_head > 0 {
            indexed_head
        } else {
            block_head
        });
        if height > chain_head {
            return Err(anyhow!(
                "HeightUnavailable {{ requested: {height}, oldest_retained: {}, head: {chain_head} }}",
                self.state_index.oldest_height()?.unwrap_or(chain_head)
            ));
        }

        let block_ctx = if height == 0 {
            bloom_petals::BlockCtx {
                number: 0,
                timestamp_ms: 0,
                prevhash: Hash32([0u8; 32]),
            }
        } else {
            let oldest_retained = self.state_index.oldest_height()?.unwrap_or(chain_head);
            let block = self.block_store.get(height)?.ok_or_else(|| {
                anyhow!(
                    "HeightUnavailable {{ requested: {height}, oldest_retained: {}, head: {chain_head} }}",
                    oldest_retained
                )
            })?;
            bloom_petals::BlockCtx {
                number: height,
                timestamp_ms: block.header.timestamp_ms,
                prevhash: block.header.parent_hash,
            }
        };

        let use_live_state = height == 0 && chain_head == 0 && self.state_index.get(0)?.is_none();
        let state = if use_live_state {
            self.state.lock().clone()
        } else {
            self.load_indexed_state(height, chain_head)?
        };

        Ok(ViewSnapshot {
            state,
            height,
            block_ctx,
            chain_head,
        })
    }

    fn load_indexed_state(&self, height: u64, chain_head: u64) -> Result<State> {
        let oldest_retained = self.state_index.oldest_height()?.unwrap_or(chain_head);
        let Some((state_root, blob_hash)) = self.state_index.get(height)? else {
            return Err(anyhow!(
                "HeightUnavailable {{ requested: {height}, oldest_retained: {oldest_retained}, head: {chain_head} }}"
            ));
        };
        let Some(blob) = self.blob_store.get(&blob_hash)? else {
            return Err(anyhow!(
                "HeightUnavailable {{ requested: {height}, oldest_retained: {oldest_retained}, head: {chain_head} }}"
            ));
        };
        let actual_blob_hash = State::blob_hash(&blob);
        if actual_blob_hash != blob_hash {
            return Err(anyhow!(
                "chain_view_call: state blob hash mismatch at height {height}"
            ));
        }
        let (blob_height, blob_state_root, _) = State::blob_header(&blob).with_context(|| {
            format!("chain_view_call: read state blob header at height {height}")
        })?;
        if blob_height != height {
            return Err(anyhow!(
                "chain_view_call: state blob height mismatch: requested={height} blob={blob_height}"
            ));
        }
        if blob_state_root != state_root {
            return Err(anyhow!(
                "chain_view_call: state blob root mismatch at height {height}: indexed={} blob={}",
                hex::encode(state_root.0),
                hex::encode(blob_state_root.0)
            ));
        }
        if height > 0 {
            let block = self.block_store.get(height)?.ok_or_else(|| {
                anyhow!(
                    "HeightUnavailable {{ requested: {height}, oldest_retained: {oldest_retained}, head: {chain_head} }}"
                )
            })?;
            if block.header.state_root != state_root {
                return Err(anyhow!(
                    "chain_view_call: block state root mismatch at height {height}: indexed={} block={}",
                    hex::encode(state_root.0),
                    hex::encode(block.header.state_root.0)
                ));
            }
        }
        State::from_blob(&blob, state_root)
            .with_context(|| format!("chain_view_call: restore state at height {height}"))
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

fn view_commands_from_params(params: &ViewCallParams) -> Result<Vec<ViewCommandParams>> {
    if !params.commands.is_empty() {
        return Ok(params.commands.clone());
    }
    let path = params
        .path
        .clone()
        .ok_or_else(|| anyhow!("chain_view_call: provide commands or path/function"))?;
    let function = params
        .function
        .clone()
        .ok_or_else(|| anyhow!("chain_view_call: provide commands or path/function"))?;
    Ok(vec![ViewCommandParams {
        path,
        function,
        hash: params.hash.clone(),
        type_args: params.type_args.clone(),
        args: params.args.clone(),
    }])
}

fn view_signers(params: &ViewCallParams) -> Result<Vec<[u8; 32]>> {
    params
        .signers
        .iter()
        .map(|s| parse_address(s).map(|a| a.0))
        .collect()
}

struct ViewArgDecodeCtx<'a> {
    type_args: &'a [TypeTag],
    manifest: &'a PetalManifestStub,
    self_hash: [u8; 32],
    load_manifest: &'a dyn Fn(&Hash32) -> Option<PetalManifestStub>,
    state: &'a State,
}

fn decode_view_args(
    cmd_idx: usize,
    values: &[Value],
    decls: &[ArgDeclStub],
    ctx: &ViewArgDecodeCtx<'_>,
) -> Result<Vec<Arg>> {
    if values.len() != decls.len() {
        return Err(anyhow!(
            "chain_view_call: command {cmd_idx}: arg count mismatch: got {}, expected {}",
            values.len(),
            decls.len()
        ));
    }
    values
        .iter()
        .zip(decls.iter())
        .enumerate()
        .map(|(arg_idx, (value, decl))| match decl {
            ArgDeclStub::Signer => parse_signer_arg(cmd_idx, arg_idx, value),
            ArgDeclStub::Const(tag) => parse_const_arg(cmd_idx, arg_idx, tag, value, ctx),
            ArgDeclStub::Object { .. } => parse_object_arg(cmd_idx, arg_idx, value, ctx.state),
            ArgDeclStub::TypeArg(idx) => {
                let tag = if let Some(tag) = ctx.type_args.get(*idx as usize) {
                    tag.clone()
                } else {
                    decode_json_type_tag(value).with_context(|| {
                        format!("chain_view_call: command {cmd_idx}: arg {arg_idx}: TypeTag")
                    })?
                };
                Ok(Arg::TypeArg(tag))
            }
        })
        .collect()
}

fn parse_signer_arg(cmd_idx: usize, arg_idx: usize, value: &Value) -> Result<Arg> {
    let index = if let Some(index) = value.as_u64() {
        index
    } else if let Some(index) = value.get("signer").and_then(Value::as_u64) {
        index
    } else if value.get("kind").and_then(Value::as_str) == Some("signer") {
        value.get("index").and_then(Value::as_u64).ok_or_else(|| {
            anyhow!("chain_view_call: command {cmd_idx}: arg {arg_idx}: signer index missing")
        })?
    } else {
        return Err(anyhow!(
            "chain_view_call: command {cmd_idx}: arg {arg_idx}: expected signer index"
        ));
    };
    Ok(Arg::Signer(index.try_into().map_err(|_| {
        anyhow!("chain_view_call: command {cmd_idx}: arg {arg_idx}: signer index out of range")
    })?))
}

fn parse_const_arg(
    cmd_idx: usize,
    arg_idx: usize,
    tag: &TypeTag,
    value: &Value,
    ctx: &ViewArgDecodeCtx<'_>,
) -> Result<Arg> {
    if value.get("kind").and_then(Value::as_str) == Some("const")
        && let Some(hex) = value.get("hex").and_then(Value::as_str)
    {
        return Err(anyhow!(
            "chain_view_call: command {cmd_idx}: arg {arg_idx}: raw const hex is not accepted for typed JSON args: {hex}"
        ));
    }
    if let Some(use_ref) = parse_use_arg(value)? {
        return Ok(Arg::Use {
            cmd_idx: use_ref.0,
            ret_idx: use_ref.1,
        });
    }
    let value = if value.get("kind").and_then(Value::as_str) == Some("const") {
        value.get("value").unwrap_or(value)
    } else {
        value
    };
    let resolved = substitute_type_args(tag, ctx.type_args);
    Ok(Arg::Const(
        decode_json_const_with_manifest_loader(
            ctx.manifest,
            ctx.self_hash,
            &resolved,
            value,
            Some(ctx.load_manifest),
        )
        .with_context(|| {
            format!("chain_view_call: command {cmd_idx}: arg {arg_idx}: decode typed const")
        })?,
    ))
}

fn parse_object_arg(cmd_idx: usize, arg_idx: usize, value: &Value, state: &State) -> Result<Arg> {
    if let Some(use_ref) = parse_use_arg(value)? {
        return Ok(Arg::Use {
            cmd_idx: use_ref.0,
            ret_idx: use_ref.1,
        });
    }
    let obj = if value.get("kind").and_then(Value::as_str) == Some("object") {
        value
    } else {
        value.get("object").unwrap_or(value)
    };
    let id_str = obj
        .get("id")
        .and_then(Value::as_str)
        .or_else(|| obj.as_str())
        .ok_or_else(|| {
            anyhow!("chain_view_call: command {cmd_idx}: arg {arg_idx}: object id missing")
        })?;
    let id = parse_object_id_hex(id_str)?;
    let expected_version = match obj.get("version").and_then(Value::as_u64) {
        Some(version) => ExpectedVersion(version),
        None => {
            let obj = state
                .get_object(&id)
                .ok_or_else(|| anyhow!("object {} not found for view arg", hex::encode(id.0)))?;
            ExpectedVersion(obj.version)
        }
    };
    Ok(Arg::Object {
        id,
        expected_version,
        access_mode: AccessMode::ReadOnly,
    })
}

fn parse_use_arg(value: &Value) -> Result<Option<(u16, u16)>> {
    let Some(use_value) = value.get("use") else {
        return Ok(None);
    };
    let cmd = use_value
        .get("cmd")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("view use-ref missing cmd"))?;
    let ret = use_value
        .get("ret")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("view use-ref missing ret"))?;
    Ok(Some((
        cmd.try_into()
            .map_err(|_| anyhow!("view use-ref cmd out of range"))?,
        ret.try_into()
            .map_err(|_| anyhow!("view use-ref ret out of range"))?,
    )))
}

fn parse_hash_hex(s: &str) -> Result<Hash32> {
    let bytes = hex::decode(s).context("decode hash hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("hash must be 32 bytes (got {})", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Hash32(out))
}

fn parse_object_id_hex(s: &str) -> Result<ObjectId> {
    let bytes = hex::decode(s).context("decode object id hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("object id must be 32 bytes (got {})", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(ObjectId(out))
}

fn substitute_type_args(t: &TypeTag, type_args: &[TypeTag]) -> TypeTag {
    match t {
        TypeTag::Generic { idx } => type_args
            .get(*idx as usize)
            .cloned()
            .unwrap_or_else(|| t.clone()),
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args: inner,
        } => TypeTag::Concrete {
            petal_hash: *petal_hash,
            type_name: type_name.clone(),
            type_args: inner
                .iter()
                .map(|x| substitute_type_args(x, type_args))
                .collect(),
        },
        TypeTag::External { .. } => t.clone(),
    }
}

fn resolve_self_type_refs(t: &TypeTag, self_hash: [u8; 32]) -> TypeTag {
    match t {
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args,
        } => TypeTag::Concrete {
            petal_hash: if petal_hash == &[0u8; 32] && type_name != "Coin" {
                self_hash
            } else {
                *petal_hash
            },
            type_name: type_name.clone(),
            type_args: if type_name == "Coin" {
                type_args.clone()
            } else {
                type_args
                    .iter()
                    .map(|x| resolve_self_type_refs(x, self_hash))
                    .collect()
            },
        },
        TypeTag::Generic { .. } | TypeTag::External { .. } => t.clone(),
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

    fn iter_vfs(&self) -> Vec<(String, Hash32)> {
        let Ok(value) = self.call_blocking("chain_list_vfs", json!({})) else {
            return Vec::new();
        };
        let Some(bindings) = value.get("bindings").and_then(Value::as_array) else {
            return Vec::new();
        };
        bindings
            .iter()
            .filter_map(|binding| {
                let path = binding.get("path")?.as_str()?.to_string();
                let hash_hex = binding.get("hash")?.as_str()?;
                let bytes: [u8; 32] = hex::decode(hash_hex).ok()?.try_into().ok()?;
                Some((path, Hash32(bytes)))
            })
            .collect()
    }

    fn iter_objects(&self) -> Vec<(bloom_objects::ObjectId, Object)> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        loop {
            let Ok(value) = self.call_blocking(
                "chain_ls_objects",
                json!({
                    "all": true,
                    "limit": RPC_CHAIN_ADAPTER_OBJECT_PAGE_LIMIT,
                    "offset": offset,
                }),
            ) else {
                return out;
            };
            let Some(objects) = value.as_array() else {
                return out;
            };
            out.extend(objects.iter().filter_map(|value| {
                let bytes = hex::decode(value.get("bytes")?.as_str()?).ok()?;
                let object = Object::decode_canonical(&bytes).ok()?;
                Some((object.id, object))
            }));
            if objects.len() < RPC_CHAIN_ADAPTER_OBJECT_PAGE_LIMIT {
                return out;
            }
            offset = offset.saturating_add(RPC_CHAIN_ADAPTER_OBJECT_PAGE_LIMIT);
        }
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
    use bloom_petal_manifest::codec;
    use bloom_petal_manifest::types::{FunctionDecl, PetalManifestV0, SCHEMA_VERSION, SemVer};
    use bloom_script::DEFAULT_FUNGIBLE_PETAL_HASH;
    use bloom_test_util::{make_validator_set_signed, make_validator_with_keypair};

    /// Build an `RpcServer` over an in-memory `State` (with tempdir-backed
    /// stores) so the object handlers can be exercised in isolation. Returns
    /// the server plus the tempdir guard, which the caller must keep alive.
    fn make_server() -> (RpcServer, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let block_store = Arc::new(BlockStore::open(&tmp.path().join("blocks")).unwrap());
        let blob_store = Arc::new(
            crate::state_blob::StateBlobStore::open(&tmp.path().join("state_blobs")).unwrap(),
        );
        let state_index = Arc::new(
            crate::state_index::StateIndex::open(&tmp.path().join("state_index.sqlite")).unwrap(),
        );
        let receipt_store = Arc::new(
            crate::receipt_store::ReceiptStore::open(&tmp.path().join("receipts")).unwrap(),
        );
        let mempool_persist =
            Arc::new(MempoolPersist::open(&tmp.path().join("mempool.sled")).unwrap());
        let mut initial_state = State::new();
        initial_state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
        let state = Arc::new(Mutex::new(initial_state));
        let v = make_validator_with_keypair();
        let validator_set = Arc::new(make_validator_set_signed(&[&v], 100));
        let (tx_submit, _rx) = tokio::sync::mpsc::channel(8);
        let server = RpcServer {
            state,
            block_store,
            blob_store,
            state_index,
            mempool_persist,
            receipt_store,
            validator_set,
            chain_id: "bloomchain.test".into(),
            genesis_hash: Hash32([0x42; 32]),
            local_address: v.addr,
            startup_height: 0,
            tx_submit,
            max_view_fuel_limit: DEFAULT_VIEW_FUEL_LIMIT,
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

    fn leb128(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    fn custom_section(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        leb128(&mut body, name.len() as u64);
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(payload);
        body
    }

    fn section(out: &mut Vec<u8>, id: u8, body: &[u8]) {
        out.push(id);
        leb128(out, body.len() as u64);
        out.extend_from_slice(body);
    }

    fn append_manifest(mut wasm: Vec<u8>, manifest: PetalManifestV0) -> Vec<u8> {
        let bytes = codec::encode(&manifest).expect("manifest encodes");
        let custom = custom_section("bloom_petal_manifest_v0", &bytes);
        section(&mut wasm, 0, &custom);
        wasm
    }

    fn u128_tag() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: bloom_objects::BUILTIN_TYPE_HASH,
            type_name: "u128".to_string(),
            type_args: vec![],
        }
    }

    fn view_manifest(path: &str, functions: Vec<FunctionDecl>) -> PetalManifestV0 {
        PetalManifestV0 {
            schema_version: SCHEMA_VERSION,
            module_path: path.to_string(),
            framework_version: SemVer::new(0, 1, 0),
            functions,
            ..Default::default()
        }
    }

    fn install_view_wasm(server: &RpcServer, path: &str, wasm: &[u8]) -> Hash32 {
        let mut state = server.state.lock();
        let hash = state.insert_code(wasm);
        state.set_vfs_binding(path.to_string(), hash);
        hash
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
    fn view_call_executes_read_only_petal_without_committing_state() {
        let (server, _tmp) = make_server();
        let wasm = wat::parse_str(
            r#"
            (module
              (import "chain" "petal.return" (func $ret (param i32 i32)))
              (import "chain" "msg.calldata.read" (func $read (param i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              ;; count=1, len=16 (ULEB), u128=42
              (data (i32.const 0) "\00\00\00\01\10\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\2a")
              (func (export "__petal_answer") (param i32 i32) (result i32)
                (call $ret (i32.const 0) (i32.const 21))
                i32.const 0)
            )
            "#,
        )
        .unwrap();
        let path = "/bloom/test/view";
        let wasm = append_manifest(
            wasm,
            view_manifest(
                path,
                vec![FunctionDecl {
                    name: "answer".to_string(),
                    view: true,
                    returns: vec![u128_tag()],
                    ..Default::default()
                }],
            ),
        );
        let hash = install_view_wasm(&server, path, &wasm);

        let res = server
            .handle_view_call(&json!({
                "path": path,
                "function": "answer"
            }))
            .unwrap();

        assert_eq!(res["at_block"], 0);
        assert_eq!(res["chain_head"], 0);
        assert_eq!(res["commands"][0]["path"], path);
        assert_eq!(res["commands"][0]["function"], "answer");
        assert_eq!(res["commands"][0]["petal_hash"], hex::encode(hash.0));
        assert_eq!(res["commands"][0]["returns"][0], "42");
        assert_eq!(
            res["commands"][0]["returns_raw"][0],
            "0000000000000000000000000000002a"
        );
        assert!(server.state.lock().iter_objects().next().is_none());
    }

    #[test]
    fn view_call_composes_multiple_commands_with_use_refs() {
        let (server, _tmp) = make_server();
        let path = "/bloom/test/view-compose";
        let wasm = wat::parse_str(
            r#"
            (module
              (import "chain" "petal.return" (func $ret (param i32 i32)))
              (import "chain" "msg.calldata.read" (func $read (param i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              ;; count=1, len=16 (ULEB), u128=42
              (data (i32.const 0) "\00\00\00\01\10\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\2a")
              (data (i32.const 64) "\00\00\00\01\10")
              (func (export "__petal_answer") (param i32 i32) (result i32)
                (call $ret (i32.const 0) (i32.const 21))
                i32.const 0)
              (func (export "__petal_echo") (param $ptr i32) (param $len i32) (result i32)
                ;; Args buffer: count(4), tag(1), len(ULEB), payload(16). Return count/len + payload.
                (drop (call $read (i32.const 128) (i32.const 0) (i32.const 22)))
                (memory.copy (i32.const 69) (i32.const 134) (i32.const 16))
                (call $ret (i32.const 64) (i32.const 21))
                i32.const 0)
            )
            "#,
        )
        .unwrap();
        let wasm = append_manifest(
            wasm,
            view_manifest(
                path,
                vec![
                    FunctionDecl {
                        name: "answer".to_string(),
                        view: true,
                        returns: vec![u128_tag()],
                        ..Default::default()
                    },
                    FunctionDecl {
                        name: "echo".to_string(),
                        view: true,
                        args: vec![bloom_petal_manifest::types::ArgDecl {
                            name: "value".to_string(),
                            kind: bloom_petal_manifest::types::ArgKind::Const(u128_tag()),
                        }],
                        returns: vec![u128_tag()],
                        ..Default::default()
                    },
                ],
            ),
        );
        install_view_wasm(&server, path, &wasm);

        let res = server
            .handle_view_call(&json!({
                "commands": [
                    { "path": path, "function": "answer" },
                    { "path": path, "function": "echo", "args": [ { "use": { "cmd": 0, "ret": 0 } } ] }
                ]
            }))
            .unwrap();

        assert_eq!(res["commands"][0]["returns"][0], "42");
        assert_eq!(res["commands"][1]["returns"][0], "42");
        assert_eq!(
            res["commands"][1]["returns_raw"][0],
            "0000000000000000000000000000002a"
        );
    }

    #[test]
    fn view_call_at_block_uses_retained_snapshot() {
        let (server, _tmp) = make_server();
        let path = "/bloom/test/historical-view";
        let wasm_old = wat::parse_str(
            r#"
            (module
              (import "chain" "petal.return" (func $ret (param i32 i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "\00\00\00\01\10\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\2a")
              (func (export "__petal_answer") (param i32 i32) (result i32)
                (call $ret (i32.const 0) (i32.const 21))
                i32.const 0)
            )
            "#,
        )
        .unwrap();
        let wasm_new = wat::parse_str(
            r#"
            (module
              (import "chain" "petal.return" (func $ret (param i32 i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "\00\00\00\01\10\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\63")
              (func (export "__petal_answer") (param i32 i32) (result i32)
                (call $ret (i32.const 0) (i32.const 21))
                i32.const 0)
            )
            "#,
        )
        .unwrap();
        let wasm_old = append_manifest(
            wasm_old,
            view_manifest(
                path,
                vec![FunctionDecl {
                    name: "answer".to_string(),
                    view: true,
                    returns: vec![u128_tag()],
                    ..Default::default()
                }],
            ),
        );
        let wasm_new = append_manifest(
            wasm_new,
            view_manifest(
                path,
                vec![FunctionDecl {
                    name: "answer".to_string(),
                    view: true,
                    returns: vec![u128_tag()],
                    ..Default::default()
                }],
            ),
        );

        let mut old_state = State::new();
        old_state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
        let old_hash = old_state.insert_code(&wasm_old);
        old_state.set_vfs_binding(path.to_string(), old_hash);
        let old_root = old_state.state_root();
        let mut block1 = test_block_with_timestamp(1, 10);
        block1.header.state_root = old_root;
        server.block_store.put(1, &block1).unwrap();
        let (blob, blob_hash) = old_state.to_blob(1, block1.header.parent_hash);
        server.blob_store.put(&blob).unwrap();
        server.state_index.put(1, &old_root, &blob_hash).unwrap();

        {
            let mut current = server.state.lock();
            let new_hash = current.insert_code(&wasm_new);
            current.set_vfs_binding(path.to_string(), new_hash);
        }
        let block2 = test_block_with_timestamp(2, 20);
        server.block_store.put(2, &block2).unwrap();

        let historical = server
            .handle_view_call(&json!({
                "path": path,
                "function": "answer",
                "at_block": 1
            }))
            .unwrap();
        let tip = server
            .handle_view_call(&json!({
                "path": path,
                "function": "answer"
            }))
            .unwrap();

        assert_eq!(historical["at_block"], 1);
        assert_eq!(historical["chain_head"], 2);
        assert_eq!(historical["commands"][0]["returns"][0], "42");
        assert_eq!(tip["at_block"], 1);
        assert_eq!(tip["chain_head"], 2);
        assert_eq!(tip["commands"][0]["returns"][0], "42");

        let genesis = server
            .handle_view_call(&json!({
                "path": path,
                "function": "answer",
                "at_block": 0
            }))
            .unwrap_err();
        let msg = genesis.to_string();
        assert!(
            msg.contains("HeightUnavailable") && msg.contains("requested: 0"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn indexed_state_rejects_mismatched_blob_header() {
        let (server, _tmp) = make_server();
        let mut state = State::new();
        state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
        let root = state.state_root();
        let mut block = test_block(1);
        block.header.state_root = root;
        server.block_store.put(1, &block).unwrap();
        let (blob, blob_hash) = state.to_blob(2, block.header.parent_hash);
        server.blob_store.put(&blob).unwrap();
        server.state_index.put(1, &root, &blob_hash).unwrap();

        let err = server.load_indexed_state(1, 1).unwrap_err();
        assert!(
            err.to_string().contains("state blob height mismatch"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn indexed_state_rejects_block_root_mismatch() {
        let (server, _tmp) = make_server();
        let mut state = State::new();
        state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
        let root = state.state_root();
        let block = test_block(1);
        server.block_store.put(1, &block).unwrap();
        let (blob, blob_hash) = state.to_blob(1, block.header.parent_hash);
        server.blob_store.put(&blob).unwrap();
        server.state_index.put(1, &root, &blob_hash).unwrap();

        let err = server.load_indexed_state(1, 1).unwrap_err();
        assert!(
            err.to_string().contains("block state root mismatch"),
            "unexpected error: {err:#}"
        );
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

        let all = server.handle_ls_objects(&json!({ "all": true })).unwrap();
        assert_eq!(all.as_array().unwrap().len(), 3);
        let paged = server
            .handle_ls_objects(&json!({ "all": true, "limit": 2, "offset": 1 }))
            .unwrap();
        assert_eq!(paged.as_array().unwrap().len(), 2);
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
        assert!(
            server
                .handle_ls_objects(&json!({ "type_name": "Coin", "all": true }))
                .is_err()
        );
        assert!(
            server
                .handle_ls_objects(&json!({ "all": true, "limit": 0 }))
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
            .set_vfs_binding("/bloom/petals/dex/pool".to_string(), hash);

        let res = server
            .handle_resolve_path(&json!({ "path": "/bloom/petals/dex/pool" }))
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
