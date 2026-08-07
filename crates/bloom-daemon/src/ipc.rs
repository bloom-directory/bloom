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
//! | `confirm_batch` | `{ "wallet", "txs", "text" }` | batch result              |
//! | `petals.install` | `{ "path", "ref"? }`             | package metadata          |
//! | `petals.build` | `{ "package_dir", "out"? }`       | package metadata          |
//! | `petals.list` | `null`                              | `[ package, ... ]`        |
//! | `petals.uninstall` | `{ "hash" }`                   | `{ "removed" }`          |
//! | `shutdown` | `null`                                | `null`                    |
//!
//! Wire framing is one JSON document per line. Encoding/decoding errors
//! produce a JSON-RPC `-32700` parse-error response and the connection
//! continues. Unknown methods produce `-32601`.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_petals::{PetalError, PetalRunner};
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchConfirmIpcRequest {
    pub wallet: String,
    pub txs: Vec<String>,
    pub text: String,
}

pub type BatchConfirmFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>>;

/// Narrow Machine-local execution seam for the CLI batch command. This is
/// deliberately separate from the VFS and from the authenticated triad wire:
/// the implementation may only orchestrate already-staged outbox entries
/// through the canonical Broker batch-signing path.
pub trait BatchConfirmationService: Send + Sync {
    fn confirm_batch<'a>(&'a self, request: BatchConfirmIpcRequest) -> BatchConfirmFuture<'a>;
}

/// Narrow seam for trusted remote-source installs. Local package install,
/// build, list, and uninstall stay implemented by the IPC server against its
/// daemon-owned [`PetalRunner`].
pub trait PetalSourceInstallService: Send + Sync {
    fn install_source(&self, params: Value) -> Result<Value, String>;
}

/// Server context. Cloning is cheap (Arc-shared).
#[derive(Clone)]
pub struct IpcServer {
    pub vfs: Vfs,
    pub version: String,
    pub chains: Vec<String>,
    petals: Option<PetalRunner>,
    petal_runtime_endpoints: BTreeMap<String, BTreeMap<String, String>>,
    petal_source_installer: Option<Arc<dyn PetalSourceInstallService>>,
    petal_mutation: Arc<tokio::sync::Mutex<()>>,
    batch_confirmation: Option<Arc<dyn BatchConfirmationService>>,
    shutdown: Arc<Notify>,
}

impl IpcServer {
    pub fn new(vfs: Vfs, version: impl Into<String>, chains: Vec<String>) -> Self {
        Self {
            vfs,
            version: version.into(),
            chains,
            petals: None,
            petal_runtime_endpoints: BTreeMap::new(),
            petal_source_installer: None,
            petal_mutation: Arc::new(tokio::sync::Mutex::new(())),
            batch_confirmation: None,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Enable `petals.*` IPC methods. Without this the methods return
    /// `-32601 method not found`.
    pub fn with_petals(mut self, runner: PetalRunner) -> Self {
        self.petals = Some(runner);
        self
    }

    pub fn with_petal_runtime_endpoints(
        mut self,
        endpoints: BTreeMap<String, BTreeMap<String, String>>,
    ) -> Self {
        self.petal_runtime_endpoints = endpoints;
        self
    }

    pub fn with_petal_source_installer(
        mut self,
        installer: Arc<dyn PetalSourceInstallService>,
    ) -> Self {
        self.petal_source_installer = Some(installer);
        self
    }

    pub fn with_batch_confirmation(mut self, service: Arc<dyn BatchConfirmationService>) -> Self {
        self.batch_confirmation = Some(service);
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
            "confirm_batch" => {
                let Some(service) = self.batch_confirmation.as_ref() else {
                    return Response::err(id, -32601, "method not found: confirm_batch");
                };
                let request = match serde_json::from_value::<BatchConfirmIpcRequest>(req.params) {
                    Ok(request) => request,
                    Err(error) => {
                        return Response::err(
                            id,
                            -32602,
                            format!("invalid confirm_batch parameters: {error}"),
                        );
                    }
                };
                match service.confirm_batch(request).await {
                    Ok(result) => Response::ok(id, result),
                    Err(error) => Response::err(id, -32000, error),
                }
            }
            "sign_hash" => Response::err(
                id,
                -32601,
                "UNSUPPORTED_VERSION: hash-only signing is disabled; use bloom:sign/signing@0.2.0",
            ),
            "list" => match self.do_list(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_handler_err(id, e),
            },
            "petals.install" => match self.do_petals_install(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_petal_err(id, e),
            },
            "petals.build" => match self.do_petals_build(&req.params).await {
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
        if write_path_uses_wallet_signer(&path) {
            return Err(HandlerError::PermissionDenied);
        }
        let bytes = parse_write_bytes(params)?;
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

    /// `params`: `{ path, ref? }` where path is a package directory,
    /// `.petal.tar`, or trusted remote source URL.
    async fn do_petals_install(&self, params: &Value) -> Result<Value, PetalError> {
        let path = params
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| PetalError::vm("missing 'path'"))?;
        if path.contains("://") || path.starts_with("git@github.com:") {
            let installer = self.petal_source_installer.clone().ok_or_else(|| {
                PetalError::vm("trusted remote Petal installs are not enabled on this daemon")
            })?;
            let params = params.clone();
            let mutation = self.petal_mutation.clone().lock_owned().await;
            return tokio::task::spawn_blocking(move || {
                let _mutation = mutation;
                installer.install_source(params)
            })
            .await
            .map_err(|error| {
                PetalError::vm(format!("petal source install worker failed: {error}"))
            })?
            .map_err(PetalError::vm);
        }
        if params.get("ref").is_some_and(|value| !value.is_null()) {
            return Err(PetalError::vm(
                "--ref is only supported for trusted GitHub source installs",
            ));
        }

        let runner = self.petals()?.clone();
        let path = path.to_owned();
        let bindings_by_name = self.petal_runtime_endpoints.clone();
        let mutation = self.petal_mutation.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _mutation = mutation;
            let metadata = std::fs::metadata(&path)?;
            let is_dir = metadata.is_dir();
            if !is_dir && !path.ends_with(".petal.tar") {
                return Err(PetalError::vm(
                    "petals install only accepts Petal package directories, .petal.tar archives, or trusted GitHub source repositories",
                ));
            }
            let package = if is_dir {
                bloom_petals::package::PreparedPetalPackage::from_dir(&path)?
            } else {
                bloom_petals::package::PreparedPetalPackage::from_petal_tar(&path)?
            };
            let mut consent = bloom_petals::package::petal_consent_summary(&package)?;
            let bindings = bindings_by_name
                .get(&consent.name)
                .cloned()
                .unwrap_or_default();
            bloom_petals::package::apply_petal_consent_endpoint_bindings(
                &mut consent,
                &bindings,
            )?;
            let (result, meta, index) = if is_dir {
                runner.store().install_petal_package_dir(&path)?
            } else {
                runner.store().install_petal_package_tar(&path)?
            };
            Ok(json!({
                "hash": result.hash,
                "mode": "petal",
                "size": result.size,
                "already_present": result.already_present,
                "petal_mount": meta.petal.as_ref().map(|petal| format!("petals/{}/", petal.name)),
                "routes": index.routes.len(),
                "consent_lines": petal_consent_lines(&consent),
            }))
        })
        .await
        .map_err(|error| PetalError::vm(format!("petal install worker failed: {error}")))?
    }

    /// `params`: `{ package_dir, out? }`.
    async fn do_petals_build(&self, params: &Value) -> Result<Value, PetalError> {
        self.petals()?;
        let package_dir = params
            .get("package_dir")
            .and_then(Value::as_str)
            .ok_or_else(|| PetalError::vm("missing 'package_dir'"))?;
        let package_dir = package_dir.to_owned();
        let out = params.get("out").and_then(Value::as_str).map(str::to_owned);
        let mutation = self.petal_mutation.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _mutation = mutation;
            if let Some(out) = out.as_deref() {
                reject_archive_output_inside_package(&package_dir, out)?;
            }
            let package = bloom_petals::package::build_petal_package_dir(&package_dir)?;
            let consent = bloom_petals::package::petal_consent_summary(&package)?;
            if let Some(out) = out.as_deref() {
                package.write_petal_tar(std::fs::File::create(out)?)?;
            }
            Ok(json!({
                "hash": package.hash,
                "contract": bloom_petals::package::ROUTE_PACKAGE,
                "wit_digest": bloom_petals::package::contract_wit_digest(),
                "petal_mount": format!("petals/{}/", package.name),
                "routes": package.route_index.routes.len(),
                "artifacts": format!("{package_dir}/artifacts"),
                "archive": out,
                "consent_lines": petal_consent_lines(&consent),
            }))
        })
        .await
        .map_err(|error| PetalError::vm(format!("petal build worker failed: {error}")))?
    }

    /// `params`: `{ name_or_hash, stdin_b64?, input?, cap_mask?: ["vfs.read",...] }`.
    /// `cap_mask` narrows the petal's declared caps; absent ⇒ use them as-is.
    async fn do_petals_run(&self, _params: &Value) -> Result<Value, PetalError> {
        Err(PetalError::vm(
            "raw petal IPC run is unsupported; Petal routes are dispatched through /petals",
        ))
    }

    async fn do_petals_list(&self) -> Result<Value, PetalError> {
        let runner = self.petals()?.clone();
        let mutation = self.petal_mutation.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _mutation = mutation;
            let names = runner.registry().snapshot();
            // Build a hash → first-matching-name reverse map so each entry
            // can carry its registered name (or null).
            let mut name_for_hash: BTreeMap<String, String> = Default::default();
            for (name, hash) in &names {
                name_for_hash.entry(hash.clone()).or_insert(name.clone());
            }
            let hashes = runner.store().list_package_hashes()?;
            let mut out = Vec::with_capacity(hashes.len());
            for hash in hashes {
                let meta = runner.store().load_meta(&hash)?;
                let petal_mount = meta
                    .petal
                    .as_ref()
                    .map(|app| format!("petals/{}/", app.name));
                out.push(json!({
                    "hash": meta.hash,
                    "size": meta.size,
                    "name": name_for_hash.get(&meta.hash).cloned(),
                    "caps": meta.caps.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "installed_at_ms": meta.installed_at_ms,
                    "mode": meta.mode_str(),
                    "petal_mount": petal_mount,
                    "petal": meta.petal,
                    "source": meta.source,
                }));
            }
            Ok(Value::Array(out))
        })
        .await
        .map_err(|error| PetalError::vm(format!("petal list worker failed: {error}")))?
    }

    async fn do_petals_resolve(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals()?.clone();
        let target = params
            .get("name_or_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("missing 'name_or_hash'"))?;
        let target = target.to_owned();
        let mutation = self.petal_mutation.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _mutation = mutation;
            let hash = runner.resolve(&target)?;
            Ok(json!({ "hash": hash }))
        })
        .await
        .map_err(|error| PetalError::vm(format!("petal resolve worker failed: {error}")))?
    }

    /// `params`: `{ name, hash? }`. Omitted/empty `hash` unsets the name.
    async fn do_petals_name(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals()?.clone();
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("missing 'name'"))?;
        let hash = params
            .get("hash")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let name = name.to_owned();
        let mutation = self.petal_mutation.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _mutation = mutation;
            match hash {
                Some(hash) => {
                    runner.registry().set(&name, &hash)?;
                    Ok(json!({ "name": name, "hash": hash }))
                }
                None => {
                    let removed = runner.registry().unset(&name)?;
                    Ok(json!({ "name": name, "removed": removed }))
                }
            }
        })
        .await
        .map_err(|error| PetalError::vm(format!("petal name worker failed: {error}")))?
    }

    async fn do_petals_uninstall(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals()?.clone();
        let hash = params
            .get("hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("missing 'hash'"))?;
        let hash = hash.to_owned();
        let mutation = self.petal_mutation.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _mutation = mutation;
            let removed = runner.uninstall(&hash)?;
            Ok(json!({ "removed": removed }))
        })
        .await
        .map_err(|error| PetalError::vm(format!("petal uninstall worker failed: {error}")))?
    }
}

fn write_path_uses_wallet_signer(path: &VfsPath) -> bool {
    let segs = path.segments();
    match segs {
        // Wallet outbox confirm intentionally reaches the VFS
        // handler: the tx engine's central authorization evaluator decides
        // whether policy permits autonomous execution or needs fresh review.
        //
        // Cancel/replace consume a signer and are not fully covered by the
        // outbox-confirm review-hash marker flow, so they must use
        // write_unlocked rather than a plain IPC write.
        [root, _wallet, chains, _chain, outbox, pending, _id, action]
            if root == "wallets"
                && chains == "chains"
                && outbox == "outbox"
                && pending == "pending"
                && matches!(action.as_str(), "cancel" | "replace") =>
        {
            true
        }
        // wallets/<wallet>/sign/{message,hash,typed_data}
        [root, _wallet, sign, kind]
            if root == "wallets"
                && sign == "sign"
                && matches!(kind.as_str(), "message" | "hash" | "typed_data") =>
        {
            true
        }
        // Everything else reaches the VFS handler through the plain write lane.
        // In particular Broker-backed policy, Sealed Approval, transaction, and
        // paid-request operations are not raw signer lanes. They must reach the
        // owning VFS handler, which delegates authorization and signing to
        // Broker rather than consuming Machine-held authority.
        _ => false,
    }
}

fn parse_path(params: &Value) -> Result<VfsPath, HandlerError> {
    let s = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::invalid("missing 'path'"))?;
    VfsPath::parse(s).map_err(|e| HandlerError::invalid(format!("bad path: {e}")))
}

fn parse_write_bytes(params: &Value) -> Result<Vec<u8>, HandlerError> {
    if let Some(s) = params.get("bytes_b64").and_then(|v| v.as_str()) {
        B64.decode(s)
            .map_err(|e| HandlerError::invalid(format!("bytes_b64: {e}")))
    } else if let Some(s) = params.get("text").and_then(|v| v.as_str()) {
        Ok(s.as_bytes().to_vec())
    } else {
        Err(HandlerError::invalid("write needs bytes_b64 or text"))
    }
}

fn reject_archive_output_inside_package(package_dir: &str, out: &str) -> Result<(), PetalError> {
    let package_dir = std::fs::canonicalize(package_dir)?;
    let out_path = Path::new(out);
    let out_parent = out_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let out_abs = std::fs::canonicalize(out_parent)?.join(out_path.file_name().unwrap_or_default());
    if out_abs.starts_with(package_dir) {
        return Err(PetalError::vm(
            "--out must be outside the package directory so archives are not packaged into future builds",
        ));
    }
    Ok(())
}

fn petal_consent_lines(summary: &bloom_petals::package::PetalConsentSummary) -> Vec<String> {
    let mut lines = vec!["consent:".to_owned()];
    if let Some(package_summary) = &summary.package_summary {
        lines.push(format!("  summary: {package_summary}"));
    }
    lines.push(format!("  docs: {}", summary.docs.join(", ")));
    if !summary.capabilities.is_empty() {
        lines.push(format!(
            "  capabilities: {}",
            summary.capabilities.join(", ")
        ));
    }
    if !summary.network.is_empty() {
        lines.push("  network:".to_owned());
        for rule in &summary.network {
            let binding = rule
                .binding
                .as_deref()
                .map(|binding| format!(" binding={binding}"))
                .unwrap_or_default();
            let effective = rule
                .effective_origin
                .as_deref()
                .map(|origin| format!(" effective_origin={origin}"))
                .unwrap_or_default();
            lines.push(format!(
                "    - declared_host={}{}{} methods=[{}] paths=[{}]",
                rule.host,
                binding,
                effective,
                rule.methods.join(","),
                rule.paths.join(",")
            ));
        }
    }
    if !summary.sign_intents.is_empty() {
        lines.push(format!(
            "  signing_intents: {}",
            summary.sign_intents.join(", ")
        ));
    }
    if !summary.store_namespaces.is_empty() {
        lines.push("  private_store:".to_owned());
        for namespace in &summary.store_namespaces {
            let visibility = if namespace.secret {
                "secret"
            } else {
                "private"
            };
            lines.push(format!("    - {} {visibility}", namespace.namespace));
        }
    }
    if !summary.routes.is_empty() {
        lines.push("  routes:".to_owned());
        for route in &summary.routes {
            let ops = route
                .ops
                .iter()
                .map(|op| format!("{op:?}").to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(",");
            let mut flags = Vec::new();
            if route.side_effecting_read {
                flags.push("side_effecting_read".to_owned());
            }
            if route.write_async {
                flags.push("write_async".to_owned());
            }
            if let Some(ttl) = route.cache_ttl_ms {
                flags.push(format!("cache_ttl_ms={ttl}"));
            }
            let caps = if route.required_caps.is_empty() {
                "-".to_owned()
            } else {
                route.required_caps.join(",")
            };
            let flags = if flags.is_empty() {
                String::new()
            } else {
                format!(" flags=[{}]", flags.join(","))
            };
            lines.push(format!(
                "    - {} ops=[{}] caps=[{}]{}",
                route.path, ops, caps, flags
            ));
        }
    }
    lines
}

fn entry_to_json(e: &Entry) -> Value {
    let kind = match e.kind {
        EntryKind::Dir => "dir",
        EntryKind::File => "file",
        EntryKind::Symlink => "symlink",
    };
    let modified_ms = e.modified.map(|modified| {
        modified
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    });
    json!({
        "name": e.name,
        "kind": kind,
        "size": e.size,
        "mode": e.mode,
        "link_target": e.link_target,
        "modified_ms": modified_ms,
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
        HandlerError::OperationNotPermitted => (-32007, "operation not permitted".into()),
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct MockBatchConfirmation;

    struct TrackingSourceInstaller {
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    impl PetalSourceInstallService for TrackingSourceInstaller {
        fn install_source(&self, _params: Value) -> Result<Value, String> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(100));
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(json!({"installed": true}))
        }
    }

    impl BatchConfirmationService for MockBatchConfirmation {
        fn confirm_batch<'a>(&'a self, request: BatchConfirmIpcRequest) -> BatchConfirmFuture<'a> {
            Box::pin(async move {
                Ok(json!({
                    "wallet": request.wallet,
                    "txs": request.txs,
                    "operation_id": "batch-operation",
                    "signer_receipt_digest": "signer-receipt",
                    "broker_receipt_digest": "broker-receipt",
                }))
            })
        }
    }

    struct SingleFileHandler {
        name: String,
        body: Vec<u8>,
    }

    impl SingleFileHandler {
        fn new(name: impl Into<String>, body: Vec<u8>) -> Self {
            Self {
                name: name.into(),
                body,
            }
        }
    }

    #[async_trait::async_trait]
    impl Handler for SingleFileHandler {
        async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
            match path
                .segments()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice()
            {
                [] => Ok(Entry::dir("stub")),
                [leaf] if *leaf == self.name => Ok(Entry::read_only_file(&self.name)),
                _ => Err(HandlerError::NotFound(path.to_string_path())),
            }
        }

        async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            match path
                .segments()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice()
            {
                [leaf] if *leaf == self.name => Ok(self.body.clone()),
                [] => Err(HandlerError::NotAFile(path.to_string_path())),
                _ => Err(HandlerError::NotFound(path.to_string_path())),
            }
        }

        async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if path.is_root() {
                Ok(vec![Entry::read_only_file(&self.name)])
            } else {
                Err(HandlerError::NotADir(path.to_string_path()))
            }
        }
    }

    fn vfs() -> Vfs {
        Vfs::builder()
            .mount(
                "stub",
                Arc::new(SingleFileHandler::new("greet", b"hi\n".to_vec())),
            )
            .build()
    }

    fn write_demo_petal_package(root: &Path) {
        let write = |rel: &str, body: &[u8]| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        };
        write(
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "demo"

[consent]
summary = "Demo app used by IPC tests."
"#,
        );
        write("README.md", b"# demo\n");
        write("AGENTS.md", b"# demo agents\n");
        write(
            "petal/demo/hello.txt.wasm",
            include_bytes!("../../bloom-petals/tests/fixtures/route_component_no_imports.wasm"),
        );
    }

    #[test]
    fn plain_ipc_write_rejects_signer_consuming_paths() {
        for path in [
            "/wallets/minnow/sign/message",
            "/wallets/minnow/sign/hash",
            "/wallets/minnow/sign/typed_data",
        ] {
            let p = VfsPath::parse(path).unwrap();
            assert!(write_path_uses_wallet_signer(&p), "{path}");
        }

        for path in [
            // Policy updates and Sealed Approval lifecycle operations reach the
            // VFS handler and are delegated to Broker.
            "/wallets/minnow/policy.toml",
            "/wallets/minnow/sealed-approvals/new.json",
            "/wallets/minnow/sealed-approvals/approval-1/revoke",
            "/wallets/minnow/chains/polygon/outbox/new.tx",
            "/wallets/minnow/chains/polygon/outbox/pending/0001/confirm",
            // Paid-request confirm reaches its Broker exact-signing handler.
            "/requests/latest/confirm",
            "/requests/req_123/confirm",
            "/requests/pending/req_123/confirm",
            "/requests/new",
            "/requests/pending/req_123/cancel",
        ] {
            let p = VfsPath::parse(path).unwrap();
            assert!(!write_path_uses_wallet_signer(&p), "{path}");
        }

        for path in [
            "/wallets/minnow/chains/polygon/outbox/pending/0001/cancel",
            "/wallets/minnow/chains/polygon/outbox/pending/0001/replace",
        ] {
            let p = VfsPath::parse(path).unwrap();
            assert!(write_path_uses_wallet_signer(&p), "{path}");
        }
    }

    #[tokio::test]
    async fn batch_confirmation_is_explicitly_wired_and_returns_authority_receipts() {
        let server = IpcServer::new(vfs(), "0", vec![])
            .with_batch_confirmation(Arc::new(MockBatchConfirmation));
        let response = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "confirm_batch".into(),
                params: serde_json::to_value(BatchConfirmIpcRequest {
                    wallet: "minnow".into(),
                    txs: vec!["base:first".into(), "base:second".into()],
                    text: "override".into(),
                })
                .unwrap(),
            })
            .await;
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["operation_id"], "batch-operation");
        assert_eq!(result["signer_receipt_digest"], "signer-receipt");
        assert_eq!(result["broker_receipt_digest"], "broker-receipt");
        assert_eq!(result["txs"], json!(["base:first", "base:second"]));
    }

    #[tokio::test]
    async fn batch_confirmation_is_unavailable_without_canonical_service() {
        let response = IpcServer::new(vfs(), "0", vec![])
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "confirm_batch".into(),
                params: json!({
                    "wallet": "minnow",
                    "txs": ["base:first"],
                    "text": "override",
                }),
            })
            .await;
        assert_eq!(response.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn petals_list_reports_petal_packages() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("demo-package");
        write_demo_petal_package(&package);

        let store = bloom_petals::PetalStore::open(dir.path().join("store")).unwrap();
        let registry =
            Arc::new(bloom_petals::NameRegistry::open(dir.path().join("registry")).unwrap());
        let vm = bloom_petals::PetalVm::new().unwrap();
        let runner = PetalRunner::new(store.clone(), registry, vm);
        let (installed, _, _) = store.install_petal_package_dir(&package).unwrap();

        let server = IpcServer::new(vfs(), "0", vec![]).with_petals(runner);
        let listed = server.do_petals_list().await.unwrap();
        let entries = listed.as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["hash"], installed.hash);
        assert_eq!(entries[0]["mode"], "local");
        assert_eq!(entries[0]["petal_mount"], "petals/demo/");
        assert_eq!(entries[0]["petal"]["name"], "demo");
    }

    #[tokio::test]
    async fn petals_package_build_and_install_are_daemon_owned_rpc_operations() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("demo-package");
        let archive = dir.path().join("demo.petal.tar");
        write_demo_petal_package(&package);

        let store = bloom_petals::PetalStore::open(dir.path().join("store")).unwrap();
        let registry =
            Arc::new(bloom_petals::NameRegistry::open(dir.path().join("registry")).unwrap());
        let runner = PetalRunner::new(store, registry, bloom_petals::PetalVm::new().unwrap());
        let server = IpcServer::new(vfs(), "0", vec![]).with_petals(runner);

        let build = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "petals.build".into(),
                params: json!({
                    "package_dir": package,
                    "out": archive,
                }),
            })
            .await;
        assert!(build.error.is_none());
        assert_eq!(build.result.unwrap()["routes"], 1);
        assert!(archive.is_file());

        let install = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(2),
                method: "petals.install".into(),
                params: json!({ "path": archive }),
            })
            .await;
        assert!(install.error.is_none());
        let result = install.result.unwrap();
        assert_eq!(result["mode"], "petal");
        assert_eq!(result["petal_mount"], "petals/demo/");
        assert_eq!(result["routes"], 1);
    }

    #[tokio::test]
    async fn petal_mutations_are_serialized_across_concurrent_connections() {
        let installer = Arc::new(TrackingSourceInstaller {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let server =
            IpcServer::new(vfs(), "0", vec![]).with_petal_source_installer(installer.clone());
        let first = server.dispatch(Request {
            jsonrpc: "2.0".into(),
            id: json!(1),
            method: "petals.install".into(),
            params: json!({"path": "https://github.com/bloom-directory/first"}),
        });
        let second = server.dispatch(Request {
            jsonrpc: "2.0".into(),
            id: json!(2),
            method: "petals.install".into(),
            params: json!({"path": "https://github.com/bloom-directory/second"}),
        });

        let (first, second) = tokio::join!(first, second);
        assert!(first.error.is_none());
        assert!(second.error.is_none());
        assert_eq!(
            installer.max_active.load(Ordering::SeqCst),
            1,
            "daemon must allow only one Petal mutation at a time"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_petal_source_work_does_not_stall_the_async_runtime() {
        let installer = Arc::new(TrackingSourceInstaller {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let server =
            IpcServer::new(vfs(), "0", vec![]).with_petal_source_installer(installer.clone());
        let started = std::time::Instant::now();
        let install = tokio::spawn(async move {
            server
                .dispatch(Request {
                    jsonrpc: "2.0".into(),
                    id: json!(1),
                    method: "petals.install".into(),
                    params: json!({"path": "https://github.com/bloom-directory/slow"}),
                })
                .await
        });

        while installer.active.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_millis(75),
            "synchronous source work stalled the current-thread runtime"
        );
        assert!(install.await.unwrap().error.is_none());
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
    async fn unknown_and_retired_secret_methods_return_minus_32601() {
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
        for (id, method) in ["nope", "write_unlocked", "wallet.sign_policy"]
            .into_iter()
            .enumerate()
        {
            let request = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": {}
            });
            wr.write_all(serde_json::to_string(&request).unwrap().as_bytes())
                .await
                .unwrap();
            wr.write_all(b"\n").await.unwrap();
            wr.flush().await.unwrap();
            let mut line = String::new();
            rd.read_line(&mut line).await.unwrap();
            let response: Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(response["error"]["code"], -32601, "{method}");
        }

        server.trigger_shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }
}
