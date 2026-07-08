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
//! | `write_unlocked` | `{ "path": "/...", "bytes_b64": "", "wallet": "...", "passphrase"? }` | `null` |
//! | `list`     | `{ "path": "/..." }`                  | `[ entry, ... ]`          |
//! | `version`  | `null`                                | `"x.y.z"`                 |
//! | `chains`   | `null`                                | `[ "ethereum", ... ]`     |
//! | `wallet.sign_policy` | `{ "wallet": "..." }`          | `null`                    |
//! | `shutdown` | `null`                                | `null`                    |
//!
//! Wire framing is one JSON document per line. Encoding/decoding errors
//! produce a JSON-RPC `-32700` parse-error response and the connection
//! continues. Unknown methods produce `-32601`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_keystore::petal_host::SignerCache;
use bloom_keystore::{Keystore, WalletKind};
use bloom_petals::{Capability, PetalError, PetalRunner, RunOptions, VfsHost};
use bloom_proto::{CeremonyIntent, CeremonyIntentKind};
use bloom_vfs::{AuthServices, Entry, EntryKind, Handler, HandlerError, Vfs, VfsPath};
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
    keystore: Option<Keystore>,
    petals: Option<PetalRunner>,
    auth_services: AuthServices,
    signer_cache: Option<Arc<SignerCache>>,
    /// Pre-wrapped `Arc<Vfs>` for building [`VfsHost`] per `petals.run`.
    /// We keep it next to the bare `vfs` clone so the existing handler
    /// surface stays untouched.
    vfs_arc: Arc<Vfs>,
    shutdown: Arc<Notify>,
}

const PASSKEY_WRITE_UNLOCKED_DISABLED: &str = "write_unlocked is disabled for passkey wallets; \
stage a Sealed Approval action and sign through PetalHost::sign_hash";

fn reject_passkey_write_unlocked(kind: WalletKind) -> Result<(), HandlerError> {
    if kind == WalletKind::PasskeyGated {
        return Err(HandlerError::Unsupported(
            PASSKEY_WRITE_UNLOCKED_DISABLED.into(),
        ));
    }
    Ok(())
}

impl IpcServer {
    pub fn new(vfs: Vfs, version: impl Into<String>, chains: Vec<String>) -> Self {
        let vfs_arc = Arc::new(vfs.clone());
        Self {
            vfs,
            version: version.into(),
            chains,
            keystore: None,
            petals: None,
            auth_services: AuthServices::default(),
            signer_cache: None,
            vfs_arc,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Enable IPC methods that need wallet unlock state, such as
    /// `write_unlocked`. The daemon remains the single writer; the client only
    /// requests the ceremony.
    pub fn with_keystore(mut self, keystore: Keystore) -> Self {
        self.keystore = Some(keystore);
        self
    }

    /// Enable `petals.*` IPC methods. Without this the methods return
    /// `-32601 method not found`.
    pub fn with_petals(mut self, runner: PetalRunner) -> Self {
        self.petals = Some(runner);
        self
    }

    pub fn with_auth_services(mut self, auth_services: AuthServices) -> Self {
        self.auth_services = auth_services;
        self
    }

    pub fn with_signer_cache(mut self, signer_cache: Arc<SignerCache>) -> Self {
        self.signer_cache = Some(signer_cache);
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
            "write_unlocked" => match self.do_write_unlocked(&req.params).await {
                Ok(()) => Response::ok(id, Value::Null),
                Err(e) => map_handler_err(id, e),
            },
            "sign_hash" => match self.do_sign_hash(&req.params).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_handler_err(id, e),
            },
            "wallet.sign_policy" => match self.do_wallet_sign_policy(&req.params).await {
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
        if write_path_uses_wallet_signer(&path) {
            return Err(HandlerError::PermissionDenied);
        }
        let bytes = parse_write_bytes(params)?;
        self.vfs.write(&path, &bytes).await
    }

    async fn do_write_unlocked(&self, params: &Value) -> Result<(), HandlerError> {
        let path = parse_path(params)?;
        let bytes = parse_write_bytes(params)?;
        let wallet = params
            .get("wallet")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HandlerError::invalid("write_unlocked needs wallet"))?;
        let passphrase = params.get("passphrase").and_then(|v| v.as_str());
        let keystore = self
            .keystore
            .as_ref()
            .ok_or_else(|| HandlerError::Unsupported("write_unlocked not enabled".into()))?;
        let info = keystore
            .info(wallet)
            .map_err(|e: bloom_keystore::KeystoreError| HandlerError::backend(e.to_string()))?;
        match info.kind {
            WalletKind::PasskeyGated => {
                reject_passkey_write_unlocked(info.kind)?;
            }
            _ => {
                keystore.unlock(wallet, passphrase.unwrap_or("")).map_err(
                    |e: bloom_keystore::KeystoreError| HandlerError::backend(e.to_string()),
                )?;
                if self.auth_services.is_wired()
                    && let Some((challenge_path, _approval_path)) =
                        sealed_approval_paths(keystore, wallet, &path, &bytes)
                    && challenge_path.exists()
                {
                    return Err(HandlerError::Unsupported(
                        "fresh Sealed Approval requires a passkey wallet; local password wallets can only auto-confirm actions that remain in policy".into(),
                    ));
                }
            }
        }
        // For a policy-session mint, require wired Sealed Approval. The old
        // forgeable marker fallback is removed; fail closed when unwired.
        if is_policy_session_new(wallet, &path) && !self.auth_services.is_wired() {
            return Err(HandlerError::Unsupported(
                "policy-session mint requires Sealed Approval; \
                 auth services are not wired (marker fallback removed)"
                    .into(),
            ));
        }
        // Paid request confirms can sign x402 or Tempo MPP credentials. The old
        // forgeable marker fallback is removed; fail closed when unwired.
        if let Some(home) = keystore.root().parent()
            && let Some(_id) = request_confirm_id(home, &path)
            && !self.auth_services.is_wired()
        {
            return Err(HandlerError::Unsupported(
                "request confirm requires Sealed Approval; \
                 auth services are not wired (marker fallback removed)"
                    .into(),
            ));
        }
        match self.vfs.write(&path, &bytes).await {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// WS-1 IPC delegate for `sign_hash`. Thin wrapper that hands off
    /// to [`crate::sign_hash::handle_sign_hash`] after looking up the
    /// wired [`AuthServices`]. All validation, grant gating, audit
    /// emission, and error mapping happens in that module.
    async fn do_sign_hash(&self, params: &Value) -> Result<Value, HandlerError> {
        crate::sign_hash::handle_sign_hash(&self.auth_services, params).await
    }

    async fn do_wallet_sign_policy(&self, params: &Value) -> Result<(), HandlerError> {
        let wallet = params
            .get("wallet")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HandlerError::invalid("wallet.sign_policy needs wallet"))?;
        let keystore = self
            .keystore
            .as_ref()
            .ok_or_else(|| HandlerError::Unsupported("wallet.sign_policy not enabled".into()))?;
        let (policy_toml, kind) = keystore
            .raw_policy(wallet)
            .map_err(|e: bloom_keystore::KeystoreError| HandlerError::backend(e.to_string()))?;
        if kind == WalletKind::PasskeyGated {
            let wallet_dir = keystore.root().join(wallet);
            let policy_path = wallet_dir.join("policy.toml");
            let address = std::fs::read_to_string(wallet_dir.join("address"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let policy_digest = blake3::hash(policy_toml.as_bytes()).to_hex().to_string();
            let mut intent =
                CeremonyIntent::new(wallet, "Sign Wallet Policy", CeremonyIntentKind::SignPolicy);
            intent.wallet_address = address.clone();
            intent.summary_lines = vec![
                format!("Review rules for wallet '{wallet}'."),
                "This does not move money or place a trade.".into(),
                "After approval, Bloom uses these rules to decide what is allowed.".into(),
            ];
            intent.policy_lines = policy_toml.lines().map(str::to_string).collect();
            intent.risk_lines = vec![
                "Approving these rules can change what Bloom allows later.".into(),
                "The OS passkey prompt only proves your presence; review the details on this page."
                    .into(),
            ];
            intent.artifact_paths = vec![policy_path.display().to_string()];
            intent.canonical_subject = serde_json::json!({
                "kind": "sign_policy",
                "wallet": wallet,
                "policy_path": policy_path,
                "policy_blake3": policy_digest,
            });
            keystore.lock(wallet);
            let reviewed_policy = keystore
                .unlock_passkey_with_intent_and_policy_edit(
                    wallet,
                    Some(intent),
                    Some(policy_toml.clone()),
                )
                .await
                .map_err(|e: bloom_keystore::KeystoreError| HandlerError::backend(e.to_string()))?;
            let final_policy = reviewed_policy.unwrap_or(policy_toml);
            toml::from_str::<bloom_proto::Policy>(&final_policy)
                .map_err(|e| HandlerError::backend(format!("reviewed policy.toml: {e}")))?;
            if final_policy != std::fs::read_to_string(&policy_path).unwrap_or_default() {
                std::fs::write(&policy_path, final_policy.as_bytes())
                    .map_err(|e| HandlerError::backend(format!("write policy.toml: {e}")))?;
            }
            let final_digest = blake3::hash(final_policy.as_bytes()).to_hex().to_string();
            let mut reviewed_intent =
                CeremonyIntent::new(wallet, "Sign Wallet Policy", CeremonyIntentKind::SignPolicy);
            reviewed_intent.wallet_address = address;
            reviewed_intent.summary_lines = vec![
                format!("Review rules for wallet '{wallet}'."),
                "This does not move money or place a trade.".into(),
                "After approval, Bloom uses these rules to decide what is allowed.".into(),
                format!("Policy digest: {final_digest}"),
            ];
            reviewed_intent.policy_lines = final_policy.lines().map(str::to_string).collect();
            reviewed_intent.risk_lines = vec![
                "Approving these rules can change what Bloom allows later.".into(),
                "The OS passkey prompt only proves your presence; review the details on this page."
                    .into(),
            ];
            reviewed_intent.artifact_paths = vec![policy_path.display().to_string()];
            reviewed_intent.canonical_subject = serde_json::json!({
                "kind": "sign_policy",
                "wallet": wallet,
                "policy_path": policy_path,
                "policy_blake3": final_digest,
            });
            if let Ok(bytes) = serde_json::to_vec_pretty(&reviewed_intent) {
                let review_path = wallet_dir.join("policy.review.json");
                let _ = std::fs::write(&review_path, bytes);
            }
        }
        keystore
            .sign_policy(wallet)
            .map_err(|e: bloom_keystore::KeystoreError| HandlerError::backend(e.to_string()))?;
        Ok(())
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
        // polymarket/onboard/<wallet>/begin signs CLOB auth and relayer/deposit-wallet operations.
        [root, action, _wallet, begin]
            if root == "polymarket" && action == "onboard" && begin == "begin" =>
        {
            true
        }
        // Everything else reaches the VFS handler through the plain write lane.
        // In particular these first-party Sealed Approval actions are NOT raw
        // signer lanes and must forward through to `vfs.write` rather than be
        // denied here:
        //   * Wallet policy writes (`policy.toml`): passkey wallets stage a
        //     challenge and install only under a grant-gated PetalHost signature;
        //     local wallets write immediately (their policy is unsigned).
        //   * Policy-session minting (`policy-session/new`): the wallets handler
        //     stages an approval challenge and mints the bounded session only
        //     under a grant-gated signature — exactly like `policy.toml`.
        //   * Paid HTTP confirm (`/requests/<id>/confirm`): the requests handler
        //     stages an approval challenge on the first write and signs the
        //     x402/Tempo MPP credential only under a grant-gated PetalHost
        //     signature.
        //   * Hyperliquid owner approvals (`agent_sessions/<wallet>/new.json`
        //     and `exchange/<wallet>/send_asset.json`): the Hyperliquid
        //     handler stages approval and signs only under a grant-gated
        //     PetalHost signature.
        // None of these silently consumes a cached signer, and the old
        // write_unlocked lane is disabled for passkey wallets — denying them here
        // would leave mounted confirm/mint with no working path.
        _ => false,
    }
}

fn request_confirm_id(home: &Path, path: &VfsPath) -> Option<String> {
    match path.segments() {
        [root, reference, action] if root == "requests" && action == "confirm" => {
            if reference == "latest" {
                latest_pending_request_id(home)
            } else {
                Some(reference.to_string())
            }
        }
        [root, state, id, action]
            if root == "requests" && state == "pending" && action == "confirm" =>
        {
            Some(id.to_string())
        }
        _ => None,
    }
}

fn latest_pending_request_id(home: &Path) -> Option<String> {
    let latest = std::fs::read_to_string(home.join("requests").join("latest")).ok()?;
    let (state, id) = latest.trim().split_once('/')?;
    (state == "pending").then(|| id.to_string())
}

fn is_wallet_policy_write(wallet: &str, path: &VfsPath) -> bool {
    matches!(
        path.segments(),
        [root, w, file] if root == "wallets" && w == wallet && file == "policy.toml"
    )
}

fn is_policy_session_new(wallet: &str, path: &VfsPath) -> bool {
    matches!(
        path.segments(),
        [root, w, ps, leaf]
            if root == "wallets" && w == wallet && ps == "policy-session" && leaf == "new"
    )
}

fn sealed_approval_paths(
    keystore: &Keystore,
    wallet: &str,
    path: &VfsPath,
    bytes: &[u8],
) -> Option<(PathBuf, PathBuf)> {
    let home = keystore.root().parent()?;
    if let Some(id) = request_confirm_id(home, path) {
        let dir = home.join("requests").join("pending").join(id);
        return Some((
            dir.join("approval_challenge.json"),
            dir.join("approval.json"),
        ));
    }
    if let Some(dir) = outbox_confirm_dir(wallet, path, &home.join("outbox")) {
        return Some((
            dir.join("approval_challenge.json"),
            dir.join("approval.json"),
        ));
    }
    if is_policy_session_new(wallet, path) {
        let action_id = policy_session_action_id(wallet, bytes);
        let dir = keystore
            .root()
            .join(wallet)
            .join("policy-session")
            .join(action_id);
        return Some((
            dir.join("approval_challenge.json"),
            dir.join("approval.json"),
        ));
    }
    if is_wallet_policy_write(wallet, path) {
        let old_policy = keystore.raw_policy(wallet).ok()?.0;
        let action_id = wallet_policy_action_id(wallet, old_policy.as_bytes(), bytes);
        let dir = keystore
            .root()
            .join(wallet)
            .join("policy-updates")
            .join(action_id);
        return Some((
            dir.join("approval_challenge.json"),
            dir.join("approval.json"),
        ));
    }
    if let Some(dir) = polymarket_onboard_dir(home, wallet, path) {
        return Some((
            dir.join("approval_challenge.json"),
            dir.join("approval.json"),
        ));
    }
    if let Some(dir) = hyperliquid_usd_send_dir(home, wallet, path) {
        return Some((
            dir.join("approval_challenge.json"),
            dir.join("approval.json"),
        ));
    }
    if let Some(dir) = hyperliquid_agent_session_dir(home, wallet, path, bytes) {
        return Some((
            dir.join("approval_challenge.json"),
            dir.join("approval.json"),
        ));
    }
    None
}

fn policy_session_action_id(wallet: &str, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.policy_session.entry.v1");
    hasher.update(wallet.as_bytes());
    hasher.update(&[0]);
    hasher.update(data);
    format!("ps-{}", hasher.finalize().to_hex())
}

fn wallet_policy_hash_hex(policy: &[u8]) -> String {
    blake3::hash(policy).to_hex().to_string()
}

fn wallet_policy_action_id(wallet: &str, old_policy: &[u8], proposed_policy: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.wallet_policy.update.v1");
    hasher.update(wallet.as_bytes());
    hasher.update(&[0]);
    hasher.update(wallet_policy_hash_hex(old_policy).as_bytes());
    hasher.update(&[0]);
    hasher.update(wallet_policy_hash_hex(proposed_policy).as_bytes());
    format!("policy-update-{}", hasher.finalize().to_hex())
}

fn outbox_confirm_dir(wallet: &str, path: &VfsPath, outbox_root: &Path) -> Option<PathBuf> {
    let [root, w, chains, chain, outbox, pending, id, confirm] = path.segments() else {
        return None;
    };
    if root == "wallets"
        && w == wallet
        && chains == "chains"
        && outbox == "outbox"
        && pending == "pending"
        && confirm == "confirm"
    {
        Some(
            outbox_root
                .join(wallet)
                .join(chain)
                .join("pending")
                .join(id),
        )
    } else {
        None
    }
}

fn polymarket_onboard_dir(home: &Path, wallet: &str, path: &VfsPath) -> Option<PathBuf> {
    let [root, action, w, leaf] = path.segments() else {
        return None;
    };
    if root == "polymarket" && action == "onboard" && w == wallet && leaf == "begin" {
        Some(
            home.join("polymarket")
                .join(safe_sealed_approval_segment(wallet)?),
        )
    } else {
        None
    }
}

fn hyperliquid_usd_send_dir(home: &Path, wallet: &str, path: &VfsPath) -> Option<PathBuf> {
    let [root, network, branch, w, leaf] = path.segments() else {
        return None;
    };
    if root == "hyperliquid" && branch == "exchange" && w == wallet && leaf == "send_asset.json" {
        Some(
            home.join("hyperliquid")
                .join("exchange")
                .join(safe_sealed_approval_segment(network)?)
                .join(safe_sealed_approval_segment(wallet)?),
        )
    } else {
        None
    }
}

fn hyperliquid_agent_session_dir(
    home: &Path,
    wallet: &str,
    path: &VfsPath,
    bytes: &[u8],
) -> Option<PathBuf> {
    let [root, network, branch, w, leaf] = path.segments() else {
        return None;
    };
    if !(root == "hyperliquid" && branch == "agent_sessions" && w == wallet && leaf == "new.json") {
        return None;
    }
    let body: Value = serde_json::from_slice(bytes).ok()?;
    let session_id = body.get("id")?.as_str()?;
    Some(
        home.join("hyperliquid")
            .join("agent_sessions")
            .join(safe_sealed_approval_segment(network)?)
            .join(safe_sealed_approval_segment(wallet)?)
            .join(safe_sealed_approval_segment(session_id)?),
    )
}

fn safe_sealed_approval_segment(raw: &str) -> Option<String> {
    if raw.is_empty()
        || raw == "."
        || raw == ".."
        || raw.len() > 128
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(raw.to_string())
}

#[cfg(test)]
fn write_unlocked_intent(
    wallet: &str,
    path: &VfsPath,
    body: &[u8],
    wallet_address: Option<String>,
    outbox_root: Option<PathBuf>,
    wallet_policy_toml: Option<&str>,
) -> CeremonyIntent {
    let path_s = path.to_string_path();
    let segs = path.segments();
    let is_wallet_policy_write = matches!(
        segs,
        [root, w, file] if root == "wallets" && w == wallet && file == "policy.toml"
    );
    if is_wallet_policy_write {
        let policy_text = String::from_utf8_lossy(body);
        let policy_digest = blake3::hash(body).to_hex().to_string();
        let mut intent = CeremonyIntent::new(
            wallet,
            "Approve Wallet Policy Write",
            CeremonyIntentKind::SignPolicy,
        );
        intent.wallet_address = wallet_address;
        intent.summary_lines = vec![
            format!("Review rules for wallet '{wallet}'."),
            "This does not move money or place a trade.".into(),
            "After approval, Bloom uses these rules to decide what is allowed.".into(),
        ];
        intent.policy_lines = policy_text.lines().map(str::to_string).collect();
        intent.risk_lines = vec![
            "Approving these rules can change what Bloom allows later.".into(),
            "The OS passkey prompt only proves your presence; review the details on this page."
                .into(),
        ];
        intent.artifact_paths = vec![path_s.clone()];
        intent.canonical_subject = json!({
            "kind": "vfs_policy_write",
            "wallet": wallet,
            "path": path_s,
            "policy_blake3": policy_digest,
        });
        return intent;
    }

    // Minting a bounded policy session: render the full envelope (chains, USD
    // cap, TTL, and the exact pending-tx ids) so the human approves a concrete,
    // finite authorization rather than an open-ended one.
    let is_policy_session_new = matches!(
        segs,
        [root, w, ps, leaf]
            if root == "wallets" && w == wallet && ps == "policy-session" && leaf == "new"
    );
    if is_policy_session_new {
        let mut intent = bloom_proto::policy_session_mint_intent(wallet, &path_s, body);
        intent.wallet_address = wallet_address;
        return intent;
    }

    if let Some(intent) = outbox_confirm_unlock_intent(
        wallet,
        &path_s,
        segs,
        wallet_address.clone(),
        outbox_root.as_deref(),
    ) {
        return intent;
    }

    if let Some(intent) = bloom_proto::hyperliquid_write_unlock_intent(
        wallet,
        &path_s,
        segs,
        body,
        wallet_address.clone(),
        wallet_policy_toml,
    ) {
        return intent;
    }

    // Polymarket onboarding `begin` is far more than a generic write: it can
    // deploy the deposit wallet, sign an eight-grant approval batch, mint CLOB
    // credentials, and auto-create a (revocable, submission-only) builder API
    // key. Show the reviewer exactly that, with one source of truth for the
    // grant list, instead of a bare path.
    let is_pm_onboard_begin = matches!(
        segs,
        [root, action, _w, begin]
            if root == "polymarket" && action == "onboard" && begin == "begin"
    );
    if is_pm_onboard_begin {
        return bloom_polymarket::polymarket_onboard_ceremony_intent(
            wallet,
            Some(&path_s),
            wallet_address.clone(),
        );
    }

    let mut intent = CeremonyIntent::new(
        wallet,
        "Approve VFS Wallet Write",
        CeremonyIntentKind::WalletUnlock,
    );
    intent.summary_lines = vec![
        format!("Approve one VFS write for wallet '{wallet}'."),
        format!("Path: {path_s}"),
    ];
    intent.risk_lines = vec![
        "This unlock is scoped to the foreground write request.".into(),
        "The OS passkey prompt will show bloom/localhost, not the VFS path.".into(),
    ];
    intent.artifact_paths = vec![path_s.clone()];
    intent.canonical_subject = json!({
        "kind": "vfs_write_unlocked",
        "wallet": wallet,
        "path": path_s,
    });
    intent
}

#[cfg(test)]
fn outbox_confirm_unlock_intent(
    wallet: &str,
    path_s: &str,
    segs: &[String],
    wallet_address: Option<String>,
    outbox_root: Option<&Path>,
) -> Option<CeremonyIntent> {
    let [root, w, chains, chain, outbox, pending, id, confirm] = segs else {
        return None;
    };
    if root != "wallets"
        || w != wallet
        || chains != "chains"
        || outbox != "outbox"
        || pending != "pending"
        || confirm != "confirm"
    {
        return None;
    }
    let plan_path = outbox_root?
        .join(wallet)
        .join(chain)
        .join("pending")
        .join(id)
        .join("plan.md");
    let plan = std::fs::read_to_string(&plan_path).ok()?;
    let plan_hash = blake3::hash(plan.as_bytes()).to_hex().to_string();
    let defi_review = find_defi_review_for_outbox(outbox_root?, wallet, chain, id);
    let mut intent = CeremonyIntent::new(
        wallet,
        format!("Approve {} Transaction", chain),
        CeremonyIntentKind::EvmTransaction,
    );
    intent.wallet_address = wallet_address;
    intent.summary_lines = defi_review
        .as_ref()
        .map(|review| review.summary_lines.clone())
        .unwrap_or_default();
    if !intent.summary_lines.is_empty() {
        intent.summary_lines.push("Transaction to sign:".into());
    }
    intent.summary_lines.extend(
        plan.lines()
            .filter(|line| {
                line.starts_with("Wallet:")
                    || line.starts_with("From:")
                    || line.starts_with("To:")
                    || line.starts_with("Chain:")
                    || line.starts_with("Value:")
                    || line.starts_with("Nonce:")
                    || line.starts_with("Gas:")
                    || line.starts_with("Data:")
            })
            .map(|line| line.trim().to_string()),
    );
    if intent.summary_lines.is_empty() {
        intent
            .summary_lines
            .push(format!("Broadcast staged transaction {id} on {chain}."));
    }
    intent.risk_lines = defi_review
        .as_ref()
        .map(|review| review.risk_lines.clone())
        .unwrap_or_default();
    intent.risk_lines.extend(vec![
        "Approving will sign and broadcast this transaction.".into(),
        "For cross-chain routes, source-chain confirmation is not destination settlement.".into(),
        "The OS passkey prompt only proves your presence; review the transaction on this page."
            .into(),
    ]);
    intent.policy_lines = defi_review
        .as_ref()
        .map(|review| {
            let mut lines: Vec<String> = review.plan_md.lines().map(str::to_string).collect();
            lines.extend(["".into(), "---".into(), "".into()]);
            lines.extend(plan.lines().map(str::to_string));
            lines
        })
        .unwrap_or_else(|| plan.lines().map(str::to_string).collect());
    intent.artifact_paths = vec![path_s.to_string(), plan_path.display().to_string()];
    if let Some(review) = &defi_review {
        intent
            .artifact_paths
            .push(format!("defi session {}", review.id));
    }
    intent.canonical_subject = json!({
        "kind": "outbox_confirm",
        "wallet": wallet,
        "chain": chain,
        "outbox_id": id,
        "path": path_s,
        "plan_blake3": plan_hash,
        "defi_session_id": defi_review.as_ref().map(|review| review.id.as_str()),
        "defi_plan_blake3": defi_review.as_ref().map(|review| review.plan_hash.as_str()),
    });
    Some(intent)
}

#[derive(Debug, Clone)]
#[cfg(test)]
struct DefiReview {
    id: String,
    plan_md: String,
    plan_hash: String,
    summary_lines: Vec<String>,
    risk_lines: Vec<String>,
}

#[cfg(test)]
fn find_defi_review_for_outbox(
    outbox_root: &Path,
    wallet: &str,
    chain: &str,
    outbox_id: &str,
) -> Option<DefiReview> {
    let home = if outbox_root.file_name().is_some_and(|name| name == "outbox") {
        outbox_root.parent().unwrap_or(outbox_root)
    } else {
        outbox_root
    };
    let sessions = home.join("defi").join(wallet).join("sessions");
    for entry in std::fs::read_dir(sessions).ok()? {
        // Skip an unreadable/corrupt sibling rather than aborting the whole scan
        // (which would silently drop a valid same-chain review later in the dir).
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        // Outbox ids are scoped per chain (`.../wallet/<chain>/pending/<id>`),
        // so the same id can exist on two chains. Bind the review to the chain
        // being confirmed, or a session for a *different* chain (e.g. a Polygon
        // route) could shadow this confirm's copy with the wrong chain.
        let chain_matches = value.get("chain").and_then(|v| v.as_str()) == Some(chain);
        let staged = value
            .get("staged_ids")
            .and_then(|v| v.as_array())
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(outbox_id)));
        if !chain_matches || !staged {
            continue;
        }
        let id = value
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let plan_md = value
            .get("plan_md")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let plan_hash = blake3::hash(plan_md.as_bytes()).to_hex().to_string();
        let mut summary_lines = vec![format!("DeFi route intent {id}:")];
        summary_lines.extend(plan_md.lines().filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("Intent:")
                || trimmed.starts_with("Chain:")
                || trimmed.starts_with("Dest chain:")
                || trimmed.starts_with("Receiver:")
                || trimmed.starts_with("Token in:")
                || trimmed.starts_with("Token out:")
                || trimmed.starts_with("Slippage:")
                || trimmed.starts_with("Router:")
                || trimmed.starts_with("Protocols:")
                || trimmed.starts_with("Tx value:")
            {
                Some(trimmed.to_string())
            } else {
                None
            }
        }));
        let risk_lines = value
            .get("policy_checks")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter(|check| check.get("outcome").and_then(|v| v.as_str()) == Some("warn"))
            .filter_map(|check| {
                let rule = check.get("rule").and_then(|v| v.as_str()).unwrap_or("defi");
                let message = check.get("message").and_then(|v| v.as_str())?;
                Some(format!("{rule}: {message}"))
            })
            .collect();
        return Some(DefiReview {
            id,
            plan_md,
            plan_hash,
            summary_lines,
            risk_lines,
        });
    }
    None
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

    #[test]
    fn plain_ipc_write_rejects_signer_consuming_paths() {
        for path in [
            "/wallets/minnow/sign/message",
            "/wallets/minnow/sign/hash",
            "/wallets/minnow/sign/typed_data",
            "/polymarket/onboard/minnow/begin",
        ] {
            let p = VfsPath::parse(path).unwrap();
            assert!(write_path_uses_wallet_signer(&p), "{path}");
        }

        for path in [
            "/defi/intents/minnow/0001/confirm",
            "/polymarket/trade/minnow/new",
            // policy.toml now reaches the VFS handler, which stages a Sealed
            // Approval for passkey wallets rather than being denied at the lane.
            "/wallets/minnow/policy.toml",
            // policy-session/new likewise reaches the wallets handler, which
            // stages a Sealed Approval challenge and mints the bounded session
            // only under a grant-gated signature (handler-owned, not a raw lane).
            "/wallets/minnow/policy-session/new",
            "/wallets/minnow/chains/polygon/outbox/new.tx",
            "/wallets/minnow/chains/polygon/outbox/pending/0001/confirm",
            // Paid-request confirm likewise reaches the VFS handler: the first
            // write stages a Sealed Approval challenge and signing only happens
            // under a grant-gated PetalHost signature.
            "/requests/latest/confirm",
            "/requests/req_123/confirm",
            "/requests/pending/req_123/confirm",
            "/requests/new",
            "/requests/pending/req_123/cancel",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/schedule_cancel.json",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/order.json",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/cancel_all",
            "/hyperliquid/mainnet/agent_sessions/minnow/new.json",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/orphan_cancel_all",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/orphan_close_all",
            "/hyperliquid/mainnet/exchange/minnow/order.json",
            "/hyperliquid/mainnet/exchange/minnow/cancel.json",
            "/hyperliquid/mainnet/exchange/minnow/schedule_cancel.json",
            "/hyperliquid/mainnet/exchange/minnow/update_leverage.json",
            "/hyperliquid/mainnet/exchange/minnow/send_asset.json",
            "/hyperliquid/mainnet/exchange/minnow/raw_signed.json",
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

    #[test]
    fn passkey_write_unlocked_is_hard_disabled() {
        let err = reject_passkey_write_unlocked(WalletKind::PasskeyGated).unwrap_err();
        let HandlerError::Unsupported(msg) = err else {
            panic!("expected unsupported error");
        };
        assert!(msg.contains("write_unlocked is disabled"), "{msg}");
        assert!(msg.contains("Sealed Approval"), "{msg}");
        assert!(msg.contains("PetalHost::sign_hash"), "{msg}");
    }

    #[test]
    fn local_write_unlocked_lane_is_retained() {
        reject_passkey_write_unlocked(WalletKind::Local).unwrap();
    }

    #[test]
    fn onboard_begin_unlock_intent_lists_grants_not_just_the_path() {
        let p = VfsPath::parse("/polymarket/onboard/minnow/begin").unwrap();
        let intent = write_unlocked_intent("minnow", &p, b"y", None, None, None);
        // The reviewer must see the concrete onboarding effects, not a bare path.
        let text = intent.summary_lines.join("\n");
        assert!(text.contains("approve(MAX) -> CTF Exchange V2"), "{text}");
        assert!(text.contains("setApprovalForAll(true)"), "{text}");
        assert!(text.contains("builder API key"), "{text}");
        assert_eq!(
            intent.canonical_subject["kind"], "polymarket_onboard_begin",
            "onboarding has a distinct hashed subject from a generic write"
        );
        // A generic write keeps the old, minimal intent.
        let g = write_unlocked_intent(
            "minnow",
            &VfsPath::parse("/wallets/minnow/sign/message").unwrap(),
            b"hello",
            None,
            None,
            None,
        );
        assert_eq!(g.canonical_subject["kind"], "vfs_write_unlocked");
        assert!(g.intent_hash() != intent.intent_hash());
    }

    #[test]
    fn policy_write_unlock_intent_shows_policy_body() {
        let p = VfsPath::parse("/wallets/minnow/policy.toml").unwrap();
        let body = b"[defi]\nrequire_calldata_verification = false\n";
        let intent = write_unlocked_intent("minnow", &p, body, Some("0xabc".into()), None, None);
        assert_eq!(intent.kind, CeremonyIntentKind::SignPolicy);
        assert_eq!(intent.canonical_subject["kind"], "vfs_policy_write");
        assert_eq!(intent.wallet_address.as_deref(), Some("0xabc"));
        let policy = intent.policy_lines.join("\n");
        assert!(policy.contains("require_calldata_verification = false"));
        assert!(intent.summary_lines.join("\n").contains("Review rules"));
    }

    #[test]
    fn hyperliquid_agent_session_intent_shows_authority_and_bounds() {
        let p = VfsPath::parse("/hyperliquid/mainnet/agent_sessions/minnow/new.json").unwrap();
        let body = br#"{"id":"btc-hour-1","agent_name":"bloom-btc-hour"}"#;
        let policy = r#"
[hyperliquid]
allowed_assets = ["BTC"]
allowed_order_types = ["limit"]
max_notional_usd = "12"
max_position_usd = "12"
max_loss_usd = "5"
max_leverage = 3
max_session_secs = 1800
allow_reduce_only = true
allow_trigger_orders = false
allow_twap = false
allow_builder_fees = false
allow_vault_or_subaccount = false
"#;
        let intent =
            write_unlocked_intent("minnow", &p, body, Some("0xabc".into()), None, Some(policy));
        let summary = intent.summary_lines.join("\n");
        let review = intent.policy_lines.join("\n");
        assert_eq!(intent.title, "Authorize Hyperliquid Trading Session");
        assert_eq!(
            intent.canonical_subject["kind"],
            "hyperliquid_agent_session_grant"
        );
        assert!(summary.contains("trade-only API wallet"));
        assert!(summary.contains("Session id: btc-hour-1"));
        assert!(summary.contains("Agent name: bloom-btc-hour"));
        assert!(summary.contains("without more passkey prompts"));
        assert!(review.contains("session_key = \"trade-only API wallet\""));
        assert!(review.contains("allowed_assets = \"BTC\""));
        assert!(review.contains("max_notional_usd = \"$12"));
        assert!(review.contains("max_session_secs = \"1800\""));
        assert!(review.contains("withdrawals = \"not allowed\""));
    }

    #[test]
    fn outbox_confirm_unlock_intent_shows_staged_plan() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp
            .path()
            .join("minnow")
            .join("base")
            .join("pending")
            .join("0001-test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("plan.md"),
            "# Staged tx 0001-test\n\nWallet: minnow\nFrom:   0xabc\nTo:     0xdef\nChain:  base (id 8453)\nValue:  0.1 ETH\nNonce:  7\nGas:    limit=1\nData:   4 bytes\n",
        )
        .unwrap();
        let p =
            VfsPath::parse("/wallets/minnow/chains/base/outbox/pending/0001-test/confirm").unwrap();
        let intent = write_unlocked_intent(
            "minnow",
            &p,
            b"y",
            Some("0xabc".into()),
            Some(tmp.path().to_path_buf()),
            None,
        );
        assert_eq!(intent.title, "Approve base Transaction");
        assert_eq!(intent.kind, CeremonyIntentKind::EvmTransaction);
        assert_eq!(intent.canonical_subject["kind"], "outbox_confirm");
        assert!(intent.summary_lines.join("\n").contains("Value:  0.1 ETH"));
        assert!(
            intent
                .policy_lines
                .join("\n")
                .contains("# Staged tx 0001-test")
        );
    }

    #[test]
    fn outbox_confirm_unlock_intent_includes_defi_route_plan() {
        let tmp = tempfile::tempdir().unwrap();
        let outbox_root = tmp.path().join("outbox");
        let dir = outbox_root
            .join("minnow")
            .join("base")
            .join("pending")
            .join("0001-test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("plan.md"),
            "# Staged tx 0001-test\n\nWallet: minnow\nFrom:   0xabc\nTo:     0xdef\nChain:  base (id 8453)\nValue:  0.1 ETH\nNonce:  7\nGas:    limit=1\nData:   4 bytes\n",
        )
        .unwrap();
        let sessions = tmp.path().join("defi").join("minnow").join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(
            sessions.join("0001-route.json"),
            serde_json::to_vec_pretty(&json!({
                "id": "0001-route",
                "chain": "base",
                "staged_ids": ["0001-test"],
                "plan_md": "# DeFi intent\n\nIntent:    swap 5 USDC to MATIC\nChain:     base (id 8453)\nDest chain:polygon (id 137)\nReceiver:  0xabc\nToken in:  USDC amount=5000000 (raw)\nToken out: MATIC amountOut≈1\nSlippage:  50 bps\nRouter:    0xrouter\nProtocols: stargate -> 1inch\nTx value:  1 wei\n",
                "policy_checks": [
                    {
                        "outcome": "warn",
                        "rule": "defi.min_output",
                        "message": "minimum-output is quote-derived"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let p =
            VfsPath::parse("/wallets/minnow/chains/base/outbox/pending/0001-test/confirm").unwrap();
        let intent = write_unlocked_intent(
            "minnow",
            &p,
            b"y",
            Some("0xabc".into()),
            Some(outbox_root),
            None,
        );
        let summary = intent.summary_lines.join("\n");
        assert!(summary.contains("DeFi route intent 0001-route"));
        assert!(summary.contains("Intent:    swap 5 USDC to MATIC"));
        assert!(summary.contains("Transaction to sign:"));
        assert!(intent.risk_lines.join("\n").contains("defi.min_output"));
        assert!(intent.policy_lines.join("\n").contains("# DeFi intent"));
        assert!(
            intent
                .policy_lines
                .join("\n")
                .contains("# Staged tx 0001-test")
        );
        assert_eq!(intent.canonical_subject["defi_session_id"], "0001-route");
    }

    #[test]
    fn outbox_confirm_ignores_defi_review_for_a_different_chain() {
        // Regression: outbox ids are per-chain, so a same-id session on another
        // chain must NOT shadow this confirm's copy (the stale "Polygon" bleed).
        let tmp = tempfile::tempdir().unwrap();
        let outbox_root = tmp.path().join("outbox");
        let dir = outbox_root
            .join("minnow")
            .join("base")
            .join("pending")
            .join("0001-test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("plan.md"),
            "# Staged tx 0001-test\n\nWallet: minnow\nFrom:   0xabc\nTo:     0xdef\nChain:  base (id 8453)\nValue:  0.1 ETH\nNonce:  7\nGas:    limit=1\nData:   4 bytes\n",
        )
        .unwrap();
        // A *Polygon* session that happens to reference the same outbox id.
        let sessions = tmp.path().join("defi").join("minnow").join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        std::fs::write(
            sessions.join("0001-route.json"),
            serde_json::to_vec_pretty(&json!({
                "id": "0001-route",
                "chain": "polygon",
                "staged_ids": ["0001-test"],
                "plan_md": "# DeFi intent\n\nIntent:    swap 1 USDC to MATIC\nChain:     polygon (id 137)\n",
                "policy_checks": []
            }))
            .unwrap(),
        )
        .unwrap();
        let p =
            VfsPath::parse("/wallets/minnow/chains/base/outbox/pending/0001-test/confirm").unwrap();
        let intent = write_unlocked_intent(
            "minnow",
            &p,
            b"y",
            Some("0xabc".into()),
            Some(outbox_root),
            None,
        );
        let summary = intent.summary_lines.join("\n");
        // The Base confirm shows Base, never the Polygon session's copy.
        assert!(summary.contains("Chain:  base (id 8453)"));
        assert!(!summary.contains("DeFi route intent"));
        assert!(!summary.to_lowercase().contains("polygon"));
        assert!(intent.canonical_subject["defi_session_id"].is_null());
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
