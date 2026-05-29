//! Unix-domain-socket JSON-RPC 2.0 server for the daemon.
//!
//! The on-disk socket lives at `<home>/run/bloom.sock` (mode 0600). Clients
//! send newline-delimited JSON-RPC requests and receive newline-delimited
//! responses; one connection can carry many requests in sequence.
//!
//! Methods exposed (mirroring the VFS handler trait):
//!
//! | method     | params                                | result                    |
//! | ---------- | ------------------------------------- | ------------------------- |
//! | `lookup`   | `{ "path": "/..." }`                  | `{ "name", "kind", ... }` |
//! | `read`     | `{ "path": "/..." }`                  | `{ "bytes_b64": "..." }`  |
//! | `write`    | `{ "path": "/...", "bytes_b64": "" }` | `null`                    |
//! | `list`     | `{ "path": "/..." }`                  | `[ entry, ... ]`          |
//! | `version`  | `null`                                | `"x.y.z"`                 |
//! | `chains`   | `null`                                | `[ "ethereum", ... ]`     |
//! | `shutdown` | `null`                                | `null`                    |
//!
//! Wire framing is one JSON document per line. Encoding/decoding errors
//! produce a JSON-RPC `-32700` parse-error response and the connection
//! continues. Unknown methods produce `-32601`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_petals::{Capability, PetalError, PetalRunner, RunOptions, VfsHost};
use bloom_vfs::{Entry, EntryKind, Handler, HandlerError, Vfs, VfsPath};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tracing::{debug, info, trace, warn};

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("home dir does not exist: {0}")]
    NoHome(PathBuf),
}

/// Default socket path under `<home>/run/bloom.sock`.
pub fn default_socket_path(home_root: &Path) -> PathBuf {
    home_root.join("run").join("bloom.sock")
}

/// RAII guard that removes the socket file on drop, covering normal exit
/// and panics during [`IpcServer::serve`].
struct SocketGuard(PathBuf);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[derive(Debug, Deserialize)]
struct Request {
    #[serde(default)]
    jsonrpc: String,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl Response {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }
    fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// Server context. Cloning is cheap (Arc-shared).
#[derive(Clone)]
pub struct IpcServer {
    pub vfs: Vfs,
    pub version: String,
    pub chains: Vec<String>,
    petals: Option<PetalRunner>,
    /// Pre-wrapped `Arc<Vfs>` for building [`VfsHost`] per `petals.run`.
    /// We keep it next to the bare `vfs` clone so the existing handler
    /// surface stays untouched.
    vfs_arc: Arc<Vfs>,
    shutdown: Arc<Notify>,
}

impl IpcServer {
    pub fn new(vfs: Vfs, version: impl Into<String>, chains: Vec<String>) -> Self {
        let vfs_arc = Arc::new(vfs.clone());
        Self {
            vfs,
            version: version.into(),
            chains,
            petals: None,
            vfs_arc,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Enable `petals.*` IPC methods. Without this the methods return
    /// `-32601 method not found`.
    pub fn with_petals(mut self, runner: PetalRunner) -> Self {
        self.petals = Some(runner);
        self
    }

    /// Trigger graceful shutdown of the running [`serve`] loop.
    pub fn trigger_shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    /// Bind a UDS at `socket_path` and accept connections until shutdown
    /// is triggered (either via the `shutdown` RPC method or
    /// [`IpcServer::trigger_shutdown`]).
    pub async fn serve(&self, socket_path: &Path) -> Result<(), IpcError> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Stale socket files survive non-graceful shutdowns; remove first.
        if socket_path.exists() {
            debug!(socket = %socket_path.display(), "ipc.stale_socket_removed");
            let _ = std::fs::remove_file(socket_path);
        }
        let listener = UnixListener::bind(socket_path)?;
        let _guard = SocketGuard(socket_path.to_owned());
        // Best-effort restrict permissions to user.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(socket_path)?.permissions();
            perms.set_mode(0o600);
            if let Err(e) = std::fs::set_permissions(socket_path, perms) {
                debug!(socket = %socket_path.display(), error = %e, "ipc.chmod_failed");
            }
        }
        info!(socket = %socket_path.display(), "ipc.listening");

        loop {
            tokio::select! {
                _ = self.shutdown.notified() => {
                    info!("ipc.shutdown_requested");
                    break;
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _addr)) => {
                            trace!("ipc.conn_accepted");
                            let me = self.clone();
                            tokio::spawn(async move {
                                match me.handle_conn(stream).await {
                                    Ok(()) => trace!("ipc.conn_closed"),
                                    Err(e) => warn!(error = %e, "ipc.conn_err"),
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "ipc.accept_err");
                        }
                    }
                }
            }
        }

        info!(socket = %socket_path.display(), "ipc.shutdown");
        Ok(())
    }

    async fn handle_conn(&self, stream: UnixStream) -> std::io::Result<()> {
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);
        let mut line = String::new();
        loop {
            line.clear();
            let n = rd.read_line(&mut line).await?;
            if n == 0 {
                return Ok(());
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let resp = match serde_json::from_str::<Request>(trimmed) {
                Ok(req) => {
                    trace!(method = %req.method, "ipc.request");
                    self.dispatch(req).await
                }
                Err(e) => {
                    debug!(error = %e, "ipc.parse_error");
                    Response::err(Value::Null, -32700, format!("parse error: {e}"))
                }
            };
            let mut out = serde_json::to_vec(&resp).unwrap_or_else(|e| {
                debug!(error = %e, "ipc.response_serialise_failed");
                // We cannot echo the request id here (serialisation of the
                // proper Response already failed, so we may not have a
                // well-formed id either). `null` is the safe default per
                // JSON-RPC 2.0 §5 when the id cannot be determined.
                br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}"#
                    .to_vec()
            });
            out.push(b'\n');
            wr.write_all(&out).await?;
            wr.flush().await?;
        }
    }

    async fn dispatch(&self, req: Request) -> Response {
        if !req.jsonrpc.is_empty() && req.jsonrpc != "2.0" {
            debug!(version = %req.jsonrpc, "ipc.dispatch.bad_version");
            return Response::err(req.id, -32600, "jsonrpc must be 2.0");
        }
        let id = req.id.clone();
        match req.method.as_str() {
            "version" => Response::ok(id, Value::String(self.version.clone())),
            "chains" => Response::ok(id, json!(self.chains)),
            "shutdown" => {
                info!("ipc.shutdown_requested_via_rpc");
                self.shutdown.notify_waiters();
                Response::ok(id, Value::Null)
            }
            "lookup" => match self.do_lookup(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_handler_err(id, e),
            },
            "read" => match self.do_read(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_handler_err(id, e),
            },
            "write" => match self.do_write(&req.params).await {
                Ok(()) => Response::ok(id, Value::Null),
                Err(e) => map_handler_err(id, e),
            },
            "list" => match self.do_list(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_handler_err(id, e),
            },
            "petals.install" => match self.do_petals_install(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_petal_err(id, e),
            },
            "petals.run" => match self.do_petals_run(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_petal_err(id, e),
            },
            "petals.list" => match self.do_petals_list().await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_petal_err(id, e),
            },
            "petals.resolve" => match self.do_petals_resolve(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_petal_err(id, e),
            },
            "petals.name" => match self.do_petals_name(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_petal_err(id, e),
            },
            "petals.uninstall" => match self.do_petals_uninstall(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_petal_err(id, e),
            },
            other => {
                debug!(method = %other, "ipc.dispatch.method_not_found");
                Response::err(id, -32601, format!("method not found: {other}"))
            }
        }
    }

    async fn do_lookup(&self, params: &Value) -> Result<Value, HandlerError> {
        let path = parse_path(params)?;
        let e = self.vfs.lookup(&path).await?;
        Ok(entry_to_json(&e))
    }

    async fn do_read(&self, params: &Value) -> Result<Value, HandlerError> {
        let path = parse_path(params)?;
        let bytes = self.vfs.read(&path).await?;
        Ok(json!({ "bytes_b64": B64.encode(&bytes), "len": bytes.len() }))
    }

    async fn do_write(&self, params: &Value) -> Result<(), HandlerError> {
        let path = parse_path(params)?;
        let bytes = if let Some(s) = params.get("bytes_b64").and_then(|v| v.as_str()) {
            B64.decode(s)
                .map_err(|e| HandlerError::invalid(format!("bytes_b64: {e}")))?
        } else if let Some(s) = params.get("text").and_then(|v| v.as_str()) {
            s.as_bytes().to_vec()
        } else {
            return Err(HandlerError::invalid("write needs bytes_b64 or text"));
        };
        self.vfs.write(&path, &bytes).await
    }

    async fn do_list(&self, params: &Value) -> Result<Value, HandlerError> {
        let path = parse_path(params)?;
        let entries = self.vfs.list(&path).await?;
        Ok(json!(entries.iter().map(entry_to_json).collect::<Vec<_>>()))
    }

    fn petals(&self) -> Result<&PetalRunner, PetalError> {
        self.petals
            .as_ref()
            .ok_or_else(|| PetalError::vm("petals not enabled on this daemon"))
    }

    /// `params`: `{ bytes_b64? | text?, name?, caps?: ["vfs.read","vfs.write"] }`.
    /// Either `bytes_b64` (raw wasm or WAT) or `text` (WAT only) must be set.
    async fn do_petals_install(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals()?;
        let bytes = if let Some(s) = params.get("bytes_b64").and_then(|v| v.as_str()) {
            B64.decode(s)
                .map_err(|e| PetalError::vm(format!("bytes_b64: {e}")))?
        } else if let Some(s) = params.get("text").and_then(|v| v.as_str()) {
            s.as_bytes().to_vec()
        } else {
            return Err(PetalError::vm("install needs bytes_b64 or text"));
        };
        let name = params.get("name").and_then(|v| v.as_str());
        let caps = parse_caps(params.get("caps"))?;
        let mode = match params.get("mode").and_then(|v| v.as_str()) {
            None => bloom_petals::PetalMode::Local,
            Some("local") => bloom_petals::PetalMode::Local,
            Some(other) => {
                return Err(PetalError::vm(format!("install: unknown mode {other:?}")));
            }
        };
        let (result, meta) = runner.install(&bytes, name, &caps, mode)?;
        Ok(json!({
            "hash": result.hash,
            "size": result.size,
            "already_present": result.already_present,
            "name": meta.name,
            "caps": meta.caps.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            "installed_at_ms": meta.installed_at_ms,
            "mode": meta.mode_str(),
        }))
    }

    /// `params`: `{ name_or_hash, stdin_b64?, input?, cap_mask?: ["vfs.read",...] }`.
    /// `cap_mask` narrows the petal's declared caps; absent ⇒ use them as-is.
    async fn do_petals_run(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals()?;
        let target = params
            .get("name_or_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("missing 'name_or_hash'"))?;
        let stdin = if let Some(s) = params.get("stdin_b64").and_then(|v| v.as_str()) {
            B64.decode(s)
                .map_err(|e| PetalError::vm(format!("stdin_b64: {e}")))?
        } else if let Some(s) = params.get("input").and_then(|v| v.as_str()) {
            s.as_bytes().to_vec()
        } else {
            Vec::new()
        };
        let cap_mask = match params.get("cap_mask") {
            Some(v) if !v.is_null() => Some(parse_caps(Some(v))?),
            _ => None,
        };
        let host = Arc::new(VfsHost::new(self.vfs_arc.clone()));
        let out = runner
            .run(target, stdin, host, cap_mask, RunOptions::default())
            .await?;
        let meta = runner.store().load_meta(&runner.resolve(target)?)?;
        Ok(json!({
            "exit_code": out.exit_code,
            "stdout_b64": B64.encode(&out.stdout),
            "stderr_b64": B64.encode(&out.stderr),
            "fuel_consumed": out.fuel_consumed,
            "mode": meta.mode_str(),
        }))
    }

    async fn do_petals_list(&self) -> Result<Value, PetalError> {
        let runner = self.petals()?;
        let names = runner.registry().snapshot();
        // Build a hash → first-matching-name reverse map so each entry
        // can carry its registered name (or null).
        let mut name_for_hash: std::collections::BTreeMap<String, String> = Default::default();
        for (name, hash) in &names {
            name_for_hash.entry(hash.clone()).or_insert(name.clone());
        }
        let hashes = runner.store().list_hashes()?;
        let mut out = Vec::with_capacity(hashes.len());
        for hash in hashes {
            let meta = runner.store().load_meta(&hash)?;
            out.push(json!({
                "hash": meta.hash,
                "size": meta.size,
                "name": name_for_hash.get(&meta.hash).cloned(),
                "caps": meta.caps.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                "installed_at_ms": meta.installed_at_ms,
                "mode": meta.mode_str(),
            }));
        }
        Ok(Value::Array(out))
    }

    async fn do_petals_resolve(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals()?;
        let target = params
            .get("name_or_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("missing 'name_or_hash'"))?;
        let hash = runner.resolve(target)?;
        Ok(json!({ "hash": hash }))
    }

    /// `params`: `{ name, hash? }`. Omitted/empty `hash` unsets the name.
    async fn do_petals_name(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals()?;
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("missing 'name'"))?;
        let hash = params
            .get("hash")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        match hash {
            Some(h) => {
                runner.registry().set(name, h)?;
                Ok(json!({ "name": name, "hash": h }))
            }
            None => {
                let removed = runner.registry().unset(name)?;
                Ok(json!({ "name": name, "removed": removed }))
            }
        }
    }

    async fn do_petals_uninstall(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals()?;
        let hash = params
            .get("hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("missing 'hash'"))?;
        let removed = runner.uninstall(hash)?;
        Ok(json!({ "removed": removed }))
    }
}

fn parse_caps(v: Option<&Value>) -> Result<BTreeSet<Capability>, PetalError> {
    let Some(v) = v else {
        return Ok(BTreeSet::new());
    };
    if v.is_null() {
        return Ok(BTreeSet::new());
    }
    let arr = v
        .as_array()
        .ok_or_else(|| PetalError::vm("'caps' must be an array of strings"))?;
    let mut out = BTreeSet::new();
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| PetalError::vm("'caps' entries must be strings"))?;
        out.insert(Capability::parse(s).ok_or_else(|| {
            PetalError::vm(format!(
                "unknown capability {s:?}; expected 'vfs.read' or 'vfs.write'"
            ))
        })?);
    }
    Ok(out)
}

fn parse_path(params: &Value) -> Result<VfsPath, HandlerError> {
    let s = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::invalid("missing 'path'"))?;
    VfsPath::parse(s).map_err(|e| HandlerError::invalid(format!("bad path: {e}")))
}

fn entry_to_json(e: &Entry) -> Value {
    let kind = match e.kind {
        EntryKind::Dir => "dir",
        EntryKind::File => "file",
        EntryKind::Symlink => "symlink",
    };
    json!({
        "name": e.name,
        "kind": kind,
        "size": e.size,
        "mode": e.mode,
        "link_target": e.link_target,
    })
}

fn map_petal_err(id: Value, e: PetalError) -> Response {
    let (code, msg) = match e {
        PetalError::NotFound(s) => (-32004, format!("not found: {s}")),
        PetalError::InvalidHash(s) => (-32602, format!("invalid hash: {s}")),
        PetalError::InvalidName(s) => (-32602, format!("invalid name: {s}")),
        PetalError::InvalidWasm(s) => (-32602, format!("invalid wasm: {s}")),
        PetalError::CapabilityDenied { petal, cap } => (
            -32007,
            format!("capability denied: petal={petal} cap={cap}"),
        ),
        PetalError::Vm(s) => (-32000, format!("vm: {s}")),
        PetalError::Io(e) => (-32001, format!("io: {e}")),
        PetalError::Serde(s) => (-32602, format!("serde: {s}")),
        PetalError::ModeCapMismatch { mode, cap } => (
            -32602,
            format!("mode/cap mismatch: mode={mode} disallows cap={cap}"),
        ),
        PetalError::CapMismatch => (
            -32602,
            "cap mismatch: petal already installed with different capabilities".to_string(),
        ),
        PetalError::ModeConflict { existing } => (
            -32008,
            format!("mode conflict: petal already installed as {existing}; uninstall first"),
        ),
        PetalError::ModeUnsupported(s) => (-32009, format!("mode unsupported: {s}")),
        PetalError::ChainCall(s) => (-32010, format!("chain call: {s}")),
        PetalError::ChainCallTrap { detail, fuel_used } => (
            -32010,
            format!("chain call trapped after {fuel_used} fuel: {detail}"),
        ),
    };
    debug!(code, message = %msg, "ipc.petal_err");
    Response::err(id, code, msg)
}

fn map_handler_err(id: Value, e: HandlerError) -> Response {
    let (code, msg) = match e {
        HandlerError::NotFound(s) => (-32004, format!("not found: {s}")),
        HandlerError::NotADir(s) => (-32005, format!("not a dir: {s}")),
        HandlerError::NotAFile(s) => (-32006, format!("not a file: {s}")),
        HandlerError::PermissionDenied => (-32007, "permission denied".into()),
        HandlerError::Invalid(s) => (-32602, format!("invalid: {s}")),
        HandlerError::Unsupported(s) => (-32008, format!("unsupported: {s}")),
        HandlerError::Backend(s) => (-32000, format!("backend: {s}")),
        HandlerError::Io(e) => (-32001, format!("io: {e}")),
    };
    debug!(code, message = %msg, "ipc.handler_err");
    Response::err(id, code, msg)
}

// ---- Tiny client for the CLI side -------------------------------------------

/// Minimal JSON-RPC client over UDS, used by the CLI when a daemon is up.
pub struct IpcClient {
    socket_path: PathBuf,
}

impl IpcClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket_path
    }

    pub async fn call(&self, method: &str, params: Value) -> std::io::Result<Value> {
        trace!(socket = %self.socket_path.display(), %method, "ipc.client.call");
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let mut out = serde_json::to_vec(&req).unwrap();
        out.push(b'\n');
        wr.write_all(&out).await?;
        wr.flush().await?;
        let mut line = String::new();
        rd.read_line(&mut line).await?;
        let v: Value = serde_json::from_str(line.trim())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(err) = v.get("error") {
            debug!(%method, error = %err, "ipc.client.rpc_error");
            return Err(std::io::Error::other(err.to_string()));
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_test_util::mocks::SingleFileHandler;
    use std::sync::Arc;

    fn vfs() -> Vfs {
        Vfs::builder()
            .mount(
                "stub",
                Arc::new(SingleFileHandler::new("greet", b"hi\n".to_vec())),
            )
            .build()
    }

    #[tokio::test]
    async fn end_to_end_over_uds() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("bloom.sock");
        let server = IpcServer::new(vfs(), "0.0.0-test", vec!["ethereum".into()]);
        let server2 = server.clone();
        let sock2 = sock.clone();
        let handle = tokio::spawn(async move {
            server2.serve(&sock2).await.unwrap();
        });

        // wait for socket to appear
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let client = IpcClient::new(&sock);

        let v = client.call("version", Value::Null).await.unwrap();
        assert_eq!(v.as_str().unwrap(), "0.0.0-test");

        let chains = client.call("chains", Value::Null).await.unwrap();
        assert_eq!(chains[0], "ethereum");

        let listed = client.call("list", json!({"path": "/stub"})).await.unwrap();
        assert_eq!(listed[0]["name"], "greet");

        let read = client
            .call("read", json!({"path": "/stub/greet"}))
            .await
            .unwrap();
        let bytes = B64.decode(read["bytes_b64"].as_str().unwrap()).unwrap();
        assert_eq!(bytes, b"hi\n");

        let _ = client.call("shutdown", Value::Null).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn unknown_method_returns_minus_32601() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("bloom.sock");
        let server = IpcServer::new(vfs(), "0", vec![]);
        let server2 = server.clone();
        let sock2 = sock.clone();
        let handle = tokio::spawn(async move {
            server2.serve(&sock2).await.unwrap();
        });
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let stream = UnixStream::connect(&sock).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);
        wr.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"nope\"}\n")
            .await
            .unwrap();
        wr.flush().await.unwrap();
        let mut line = String::new();
        rd.read_line(&mut line).await.unwrap();
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["error"]["code"], -32601);

        server.trigger_shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }
}
