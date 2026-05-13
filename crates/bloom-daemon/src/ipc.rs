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
use bloom_vfs::{Entry, EntryKind, Handler, HandlerError, Vfs, VfsPath};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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
    shutdown: Arc<Notify>,
}

impl IpcServer {
    pub fn new(vfs: Vfs, version: impl Into<String>, chains: Vec<String>) -> Self {
        Self {
            vfs,
            version: version.into(),
            chains,
            shutdown: Arc::new(Notify::new()),
        }
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
        let _ = std::fs::remove_file(socket_path);
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
                b"{}".to_vec()
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
    use async_trait::async_trait;
    use std::sync::Arc;

    struct StubHandler;

    #[async_trait]
    impl Handler for StubHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            if p.is_root() {
                Ok(Entry::dir(""))
            } else if p.segments().last().map(|s| s.as_str()) == Some("greet") {
                Ok(Entry::file("greet"))
            } else {
                Err(HandlerError::NotFound(p.to_string_path()))
            }
        }
        async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            Ok(b"hi\n".to_vec())
        }
        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![Entry::file("greet")])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
    }

    fn vfs() -> Vfs {
        Vfs::builder().mount("stub", Arc::new(StubHandler)).build()
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
