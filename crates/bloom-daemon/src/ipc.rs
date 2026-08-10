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
//! | `write_with_lookup` | write params plus `projection_path` | identity entry           |
//! | `list`     | `{ "path": "/..." }`                  | `[ entry, ... ]`          |
//! | `version`  | `null`                                | `"x.y.z"`                 |
//! | `chains`   | `null`                                | `[ "ethereum", ... ]`     |
//! | `confirm_batch` | `{ "wallet", "txs", "text" }` | batch result              |
//! | `petals.install` | remote source or package transport | package metadata          |
//! | `petals.build` | `{ "package_dir", "out"? }`           | package metadata       |
//! | `petals.list` | `null`                              | `[ package, ... ]`        |
//! | `petals.uninstall` | `{ "hash" }`                   | `{ "removed" }`          |
//! | `machine.execute` | tagged [`MachineCommand`]        | [`MachineCommandOutput`] |
//! | `shutdown` | `null`                                | `null`                    |
//!
//! Wire framing is one JSON document per line. Logical documents above the
//! physical frame limit use ordered base64 chunk envelopes and are capped at
//! [`MAX_IPC_MESSAGE_BYTES`]. Long-running operations may emit `bloom.output`
//! notifications containing base64-encoded stdout/stderr bytes before their
//! final response. Dropping the connection cancels the active operation.
//! Encoding/decoding errors produce a JSON-RPC `-32700` parse-error response.
//! Unknown methods produce `-32601`. Every request, response, and notification
//! carries a `bloom_protocol` range; peers fail closed when the ranges do not
//! overlap.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::UNIX_EPOCH;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_petals::{PetalError, PetalRunner};
use bloom_vfs::{Entry, EntryKind, Handler, HandlerError, Vfs, VfsPath};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tracing::{debug, info, trace, warn};

/// Maximum physical newline-delimited frame and reassembled logical message.
/// Logical messages above one frame are transported as ordered base64 chunks.
const MAX_IPC_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_IPC_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const IPC_CHUNK_BYTES: usize = 2 * 1024 * 1024;
const IPC_DATA_CHUNK_BYTES: usize = 1024 * 1024;
const IPC_OUTPUT_CHANNEL_CAPACITY: usize = 8;

/// Current Bloom CLI-to-daemon IPC protocol and the range this build can
/// decode. Package versions are diagnostic; this range is the compatibility
/// contract enforced on every request and response.
pub const IPC_PROTOCOL_CURRENT: u32 = 1;
pub const IPC_PROTOCOL_MIN_SUPPORTED: u32 = 1;
pub const IPC_PROTOCOL_MAX_SUPPORTED: u32 = IPC_PROTOCOL_CURRENT;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IpcProtocolRange {
    pub current: u32,
    pub min: u32,
    pub max: u32,
}

impl IpcProtocolRange {
    pub const fn supported() -> Self {
        Self {
            current: IPC_PROTOCOL_CURRENT,
            min: IPC_PROTOCOL_MIN_SUPPORTED,
            max: IPC_PROTOCOL_MAX_SUPPORTED,
        }
    }

    fn is_valid(self) -> bool {
        self.min <= self.current && self.current <= self.max
    }

    pub fn negotiate(self, peer: Self) -> Option<u32> {
        if !self.is_valid() || !peer.is_valid() {
            return None;
        }
        let minimum = self.min.max(peer.min);
        let maximum = self.max.min(peer.max);
        (minimum <= maximum).then_some(maximum)
    }
}

impl std::fmt::Display for IpcProtocolRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.min == self.max {
            write!(f, "{}", self.current)
        } else {
            write!(
                f,
                "{} (supported {}..={})",
                self.current, self.min, self.max
            )
        }
    }
}

async fn read_bounded_frame<R>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Ok(Some(frame))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let payload_len = newline.unwrap_or(available.len());
        if frame.len().saturating_add(payload_len) > MAX_IPC_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("IPC frame exceeds {MAX_IPC_FRAME_BYTES} bytes"),
            ));
        }
        frame.extend_from_slice(&available[..payload_len]);
        let consumed = payload_len + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(frame));
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct IpcChunkEnvelope {
    bloom_chunk: IpcChunk,
}

#[derive(Debug, Deserialize, Serialize)]
struct IpcChunk {
    sequence: u32,
    final_chunk: bool,
    bytes_b64: String,
}

async fn read_ipc_message<R>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let Some(first) = read_bounded_frame(reader).await? else {
        return Ok(None);
    };
    let Ok(mut envelope) = serde_json::from_slice::<IpcChunkEnvelope>(&first) else {
        return Ok(Some(first));
    };
    let mut message = Vec::new();
    let mut expected_sequence = 0_u32;
    loop {
        if envelope.bloom_chunk.sequence != expected_sequence {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "IPC chunk sequence is not contiguous",
            ));
        }
        let chunk = B64
            .decode(&envelope.bloom_chunk.bytes_b64)
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("IPC chunk is not valid base64: {error}"),
                )
            })?;
        if message.len().saturating_add(chunk.len()) > MAX_IPC_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("IPC message exceeds {MAX_IPC_MESSAGE_BYTES} bytes"),
            ));
        }
        message.extend_from_slice(&chunk);
        if envelope.bloom_chunk.final_chunk {
            return Ok(Some(message));
        }
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "IPC chunk sequence overflow",
            )
        })?;
        let next = read_bounded_frame(reader).await?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "IPC chunked message ended before its final chunk",
            )
        })?;
        envelope = serde_json::from_slice(&next).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid IPC chunk envelope: {error}"),
            )
        })?;
    }
}

async fn write_ipc_message<W>(writer: &mut W, message: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if message.len() > MAX_IPC_MESSAGE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("IPC message exceeds {MAX_IPC_MESSAGE_BYTES} bytes"),
        ));
    }
    if message.len() <= MAX_IPC_FRAME_BYTES {
        writer.write_all(message).await?;
        writer.write_all(b"\n").await?;
        return writer.flush().await;
    }
    let chunks = message.chunks(IPC_CHUNK_BYTES);
    let chunk_count = chunks.len();
    for (sequence, chunk) in chunks.enumerate() {
        let frame = serde_json::to_vec(&IpcChunkEnvelope {
            bloom_chunk: IpcChunk {
                sequence: sequence as u32,
                final_chunk: sequence + 1 == chunk_count,
                bytes_b64: B64.encode(chunk),
            },
        })
        .expect("IPC chunk envelope serializes");
        debug_assert!(frame.len() <= MAX_IPC_FRAME_BYTES);
        writer.write_all(&frame).await?;
        writer.write_all(b"\n").await?;
    }
    writer.flush().await
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("home dir does not exist: {0}")]
    NoHome(PathBuf),
    #[error("refusing insecure IPC socket {path}: {reason}")]
    InsecureSocket { path: PathBuf, reason: String },
    #[error("IPC endpoint is already served: {0}")]
    EndpointBusy(PathBuf),
}

/// Default socket path under `<home>/run/bloom.sock`.
pub fn default_socket_path(home_root: &Path) -> PathBuf {
    home_root.join("run").join("bloom.sock")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

/// Keeps the persistent endpoint ownership record locked for the listener's
/// full lifetime. The record is deliberately not removed on drop: unlinking a
/// lock path would let a raced publisher lock a different inode.
struct EndpointLock {
    _file: std::fs::File,
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

#[derive(Debug, Deserialize)]
struct WireRequest {
    #[serde(flatten)]
    request: Request,
    #[serde(default)]
    bloom_protocol: Option<IpcProtocolRange>,
}

#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    id: Value,
    bloom_protocol: IpcProtocolRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OutputNotification {
    jsonrpc: &'static str,
    method: &'static str,
    bloom_protocol: IpcProtocolRange,
    params: OutputNotificationParams,
}

#[derive(Debug, Deserialize, Serialize)]
struct OutputNotificationParams {
    stream: IpcOutputStream,
    bytes_b64: String,
}

impl OutputNotification {
    fn new(event: IpcOutputEvent) -> Self {
        Self {
            jsonrpc: "2.0",
            method: "bloom.output",
            bloom_protocol: IpcProtocolRange::supported(),
            params: OutputNotificationParams {
                stream: event.stream,
                bytes_b64: B64.encode(event.bytes),
            },
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct RpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineErrorKind {
    InvalidParams,
    PermissionDenied,
    Unavailable,
    Conflict,
    NotFound,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("{message}")]
pub struct MachineError {
    pub kind: MachineErrorKind,
    pub code: String,
    pub message: String,
}

impl MachineError {
    pub fn new(
        kind: MachineErrorKind,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            code: code.into(),
            message: message.into(),
        }
    }

    fn rpc_code(&self) -> i32 {
        match self.kind {
            MachineErrorKind::InvalidParams => -32602,
            MachineErrorKind::PermissionDenied => -32007,
            MachineErrorKind::Unavailable => -32003,
            MachineErrorKind::Conflict => -32009,
            MachineErrorKind::NotFound => -32004,
            MachineErrorKind::Internal => -32603,
        }
    }
}

impl Response {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            bloom_protocol: IpcProtocolRange::supported(),
            result: Some(result),
            error: None,
        }
    }
    fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            bloom_protocol: IpcProtocolRange::supported(),
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    fn machine_err(id: Value, error: MachineError) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            bloom_protocol: IpcProtocolRange::supported(),
            result: None,
            error: Some(RpcError {
                code: error.rpc_code(),
                message: error.message.clone(),
                data: Some(serde_json::to_value(error).expect("Machine error serializes")),
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
    fn install_source(&self, params: Value, context: IpcOperationContext) -> Result<Value, String>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcOutputStream {
    Stdout,
    Stderr,
    Data,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpcOutputEvent {
    pub stream: IpcOutputStream,
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct IpcOperationContext {
    output: Option<tokio::sync::mpsc::Sender<IpcOutputEvent>>,
    cancelled: Arc<AtomicBool>,
}

impl IpcOperationContext {
    fn connected(output: tokio::sync::mpsc::Sender<IpcOutputEvent>) -> Self {
        Self {
            output: Some(output),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    fn detached() -> Self {
        Self {
            output: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn emit(&self, stream: IpcOutputStream, bytes: impl Into<Vec<u8>>) -> bool {
        if self.is_cancelled() {
            return false;
        }
        let Some(output) = &self.output else {
            return true;
        };
        if output
            .blocking_send(IpcOutputEvent {
                stream,
                bytes: bytes.into(),
            })
            .is_err()
        {
            self.cancel();
            return false;
        }
        true
    }

    async fn emit_async(&self, stream: IpcOutputStream, bytes: Vec<u8>) -> bool {
        if self.is_cancelled() {
            return false;
        }
        let Some(output) = &self.output else {
            return true;
        };
        if output.send(IpcOutputEvent { stream, bytes }).await.is_err() {
            self.cancel();
            return false;
        }
        true
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineCustodyKind {
    New,
    Import,
    Rebind,
    Delete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineCeremonyAction {
    Status,
    Cancel,
    Result,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineOperationAction {
    Status,
    Cancel,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineLegacyMigrationReceipt {
    pub schema: String,
    pub operation_id: bloom_broker_api::OperationId,
    pub wallet_name: bloom_broker_api::Token,
    pub address: String,
    pub public_key_fingerprint: bloom_broker_api::Digest32,
    pub credential_id_fingerprint: bloom_broker_api::Digest32,
    pub legacy_format_version: u8,
    pub bundle_digest: bloom_broker_api::Digest32,
    pub policy_mode: String,
    pub exact_terms_digest: bloom_broker_api::Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum MachineCommand {
    Status,
    AuditStatus,
    AuditReconcile {
        correlation_id: String,
        outcome: String,
        confirm: String,
    },
    WalletList,
    WalletProjection {
        name: String,
    },
    WalletAddress {
        name: String,
    },
    WalletUnlock {
        name: String,
    },
    WalletCustody {
        name: String,
        kind: MachineCustodyKind,
    },
    WalletMigrate {
        receipt: MachineLegacyMigrationReceipt,
    },
    WalletPolicyPrepare {
        name: String,
        policy: Vec<u8>,
        assurance_level: String,
    },
    WalletPolicyCommit {
        operation_id: String,
    },
    WalletOutboxCancel {
        wallet: String,
        chain: String,
        id: String,
        text: String,
    },
    WalletOutboxReplace {
        wallet: String,
        chain: String,
        id: String,
        intent: String,
    },
    Ceremony {
        action: MachineCeremonyAction,
        operation_id: String,
    },
    Operation {
        action: MachineOperationAction,
        operation_id: String,
    },
    UpdateStatus,
    UpdateCheck,
    Completions {
        shell: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineCommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

pub type MachineCommandFuture<'a> =
    Pin<Box<dyn Future<Output = Result<MachineCommandOutput, MachineError>> + Send + 'a>>;

/// Daemon-owned service seam for Machine command families that are not VFS
/// operations. The CLI transports the closed [`MachineCommand`] contract;
/// authority access and durable state remain in `bloom serve`.
pub trait MachineCommandService: Send + Sync {
    fn execute(&self, command: MachineCommand) -> MachineCommandFuture<'_>;
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
    machine_commands: Option<Arc<dyn MachineCommandService>>,
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
            machine_commands: None,
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

    pub fn with_machine_commands(mut self, service: Arc<dyn MachineCommandService>) -> Self {
        self.machine_commands = Some(service);
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
        let target = canonical_socket_target(socket_path)?;
        let _endpoint_lock = acquire_endpoint_lock(&target)?;
        let staging = private_socket_staging_dir(&target)?;
        // Keep the unpublished path no longer than a typical endpoint name;
        // sockaddr_un has a small fixed path limit on macOS.
        let staged_socket = staging.path().join("s");
        let listener = std::os::unix::net::UnixListener::bind(&staged_socket)?;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staged_socket, std::fs::Permissions::from_mode(0o600))?;
        let identity = verify_socket_security(&staged_socket, rustix::process::geteuid().as_raw())?;
        let stale_identity = validate_stale_socket(&target)?;
        let revalidated_stale_identity = validate_stale_socket(&target)?;
        if stale_identity != revalidated_stale_identity {
            return Err(IpcError::EndpointBusy(target));
        }
        std::fs::rename(&staged_socket, &target)?;
        if stale_identity.is_some() {
            debug!(socket = %target.display(), "ipc.stale_socket_replaced");
        }
        drop(staging);
        let published_identity =
            verify_socket_security(&target, rustix::process::geteuid().as_raw())?;
        if published_identity != identity {
            return Err(IpcError::InsecureSocket {
                path: target,
                reason: "published socket inode does not match the staged listener".to_owned(),
            });
        }
        listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(listener)?;
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
                            let observed_uid = match stream.peer_cred() {
                                Ok(credential) => credential.uid(),
                                Err(error) => {
                                    warn!(%error, "ipc.peer_credentials_failed");
                                    continue;
                                }
                            };
                            if !peer_uid_allowed(
                                rustix::process::geteuid().as_raw(),
                                observed_uid,
                            ) {
                                warn!(observed_uid, "ipc.peer_rejected");
                                continue;
                            }
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
        loop {
            let Some(line) = read_ipc_message(&mut rd).await? else {
                return Ok(());
            };
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let resp = match serde_json::from_slice::<WireRequest>(&line) {
                Ok(wire) => {
                    trace!(method = %wire.request.method, "ipc.request");
                    match wire.bloom_protocol {
                        Some(peer) if IpcProtocolRange::supported().negotiate(peer).is_some() => {
                            let (output_tx, mut output_rx) =
                                tokio::sync::mpsc::channel(IPC_OUTPUT_CHANNEL_CAPACITY);
                            let context = IpcOperationContext::connected(output_tx);
                            let mut dispatched =
                                Box::pin(self.dispatch_with_context(wire.request, context.clone()));
                            let mut disconnect = [0_u8; 1];
                            let response = loop {
                                tokio::select! {
                                    biased;
                                    event = output_rx.recv() => {
                                        if let Some(event) = event {
                                            let notification = serde_json::to_vec(
                                                &OutputNotification::new(event)
                                            ).expect("IPC output notification serializes");
                                            if let Err(error) = write_ipc_message(&mut wr, &notification).await {
                                                context.cancel();
                                                let _ = dispatched.await;
                                                return Err(error);
                                            }
                                        }
                                    }
                                    response = &mut dispatched => break response,
                                    read = rd.read(&mut disconnect) => {
                                        match read {
                                            Ok(0) => {
                                                context.cancel();
                                                let _ = dispatched.await;
                                                return Ok(());
                                            }
                                            Ok(_) => {
                                                context.cancel();
                                                return Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidData,
                                                    "pipelined IPC requests are unsupported",
                                                ));
                                            }
                                            Err(error) => {
                                                context.cancel();
                                                return Err(error);
                                            }
                                        }
                                    }
                                }
                            };
                            while let Ok(event) = output_rx.try_recv() {
                                let notification =
                                    serde_json::to_vec(&OutputNotification::new(event))
                                        .expect("IPC output notification serializes");
                                write_ipc_message(&mut wr, &notification).await?;
                            }
                            response
                        }
                        Some(peer) => Response::err(
                            wire.request.id,
                            -32010,
                            format!(
                                "incompatible Bloom IPC protocol: daemon supports {}, client supports {peer}",
                                IpcProtocolRange::supported()
                            ),
                        ),
                        None => Response::err(
                            wire.request.id,
                            -32010,
                            "missing Bloom IPC protocol metadata; upgrade the CLI and daemon together",
                        ),
                    }
                }
                Err(e) => {
                    debug!(error = %e, "ipc.parse_error");
                    Response::err(Value::Null, -32700, format!("parse error: {e}"))
                }
            };
            let out = serde_json::to_vec(&resp).unwrap_or_else(|e| {
                debug!(error = %e, "ipc.response_serialise_failed");
                // We cannot echo the request id here (serialisation of the
                // proper Response already failed, so we may not have a
                // well-formed id either). `null` is the safe default per
                // JSON-RPC 2.0 §5 when the id cannot be determined.
                br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}"#
                    .to_vec()
            });
            write_ipc_message(&mut wr, &out).await?;
        }
    }

    #[cfg(test)]
    async fn dispatch(&self, req: Request) -> Response {
        self.dispatch_with_context(req, IpcOperationContext::detached())
            .await
    }

    async fn dispatch_with_context(&self, req: Request, context: IpcOperationContext) -> Response {
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
            "read" => match self.do_read(&req.params, &context).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_handler_err(id, e),
            },
            "write" => match self.do_write(&req.params).await {
                Ok(()) => Response::ok(id, Value::Null),
                Err(e) => map_handler_err(id, e),
            },
            "write_with_lookup" => match self.do_write_with_lookup(&req.params).await {
                Ok(value) => Response::ok(id, value),
                Err(error) => map_handler_err(id, error),
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
            "petals.install" => match self.do_petals_install(&req.params, context.clone()).await {
                Ok(v) => Response::ok(id, v),
                Err(e) => map_petal_err(id, e),
            },
            "petals.build" => match self.do_petals_build(&req.params, context).await {
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
            "machine.execute" => {
                let Some(service) = self.machine_commands.as_ref() else {
                    return Response::err(id, -32601, "method not found: machine.execute");
                };
                let command = match serde_json::from_value::<MachineCommand>(req.params.clone()) {
                    Ok(command) => command,
                    Err(error) => {
                        return Response::err(id, -32602, format!("invalid params: {error}"));
                    }
                };
                if serde_json::to_value(&command).expect("Machine command serializes") != req.params
                {
                    return Response::err(id, -32602, "invalid params: unknown fields");
                }
                match service.execute(command).await {
                    Ok(value) => Response::ok(
                        id,
                        serde_json::to_value(value).expect("Machine command output serializes"),
                    ),
                    Err(error) => Response::machine_err(id, error),
                }
            }
            operation if operation.starts_with("machine.") => {
                Response::err(id, -32601, format!("method not found: {operation}"))
            }
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

    async fn do_read(
        &self,
        params: &Value,
        context: &IpcOperationContext,
    ) -> Result<Value, HandlerError> {
        let path = parse_path(params)?;
        let bytes = self.vfs.read(&path).await?;
        if bytes.len() > IPC_DATA_CHUNK_BYTES {
            let len = bytes.len();
            for chunk in bytes.chunks(IPC_DATA_CHUNK_BYTES) {
                if !context
                    .emit_async(IpcOutputStream::Data, chunk.to_vec())
                    .await
                {
                    return Err(HandlerError::backend(
                        "IPC read cancelled by disconnected client",
                    ));
                }
            }
            return Ok(json!({ "streamed": true, "len": len }));
        }
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

    /// Serialize a VFS mutation with lookup of the identity projection it
    /// creates. This avoids the historical client-side write-then-`latest`
    /// race while preserving the existing VFS protocol.
    async fn do_write_with_lookup(&self, params: &Value) -> Result<Value, HandlerError> {
        let path = parse_path(params)?;
        if write_path_uses_wallet_signer(&path) {
            return Err(HandlerError::PermissionDenied);
        }
        let bytes = parse_write_bytes(params)?;
        let projection_path = params
            .get("projection_path")
            .and_then(Value::as_str)
            .ok_or_else(|| HandlerError::invalid("missing projection_path"))?;
        let projection = VfsPath::parse(projection_path)
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        let entry = self
            .vfs
            .write_then_lookup(&path, &bytes, &projection)
            .await?;
        Ok(entry_to_json(&entry))
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
    async fn do_petals_install(
        &self,
        params: &Value,
        context: IpcOperationContext,
    ) -> Result<Value, PetalError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct InstallRequest {
            path: String,
            #[serde(rename = "ref")]
            requested_ref: Option<String>,
        }
        let request: InstallRequest = serde_json::from_value(params.clone())
            .map_err(|error| PetalError::vm(format!("invalid petals.install request: {error}")))?;
        let remote_path = Some(request.path.as_str());
        if remote_path
            .is_some_and(|path| path.contains("://") || path.starts_with("git@github.com:"))
        {
            let installer = self.petal_source_installer.clone().ok_or_else(|| {
                PetalError::vm("trusted remote Petal installs are not enabled on this daemon")
            })?;
            let params = json!({"path": request.path, "ref": request.requested_ref});
            let mutation = self.petal_mutation.clone().lock_owned().await;
            return tokio::task::spawn_blocking(move || {
                let _mutation = mutation;
                if context.is_cancelled() {
                    return Err("Petal source install cancelled by disconnected client".to_owned());
                }
                installer.install_source(params, context)
            })
            .await
            .map_err(|error| {
                PetalError::vm(format!("petal source install worker failed: {error}"))
            })?
            .map_err(PetalError::vm);
        }
        if request.requested_ref.is_some() {
            return Err(PetalError::vm(
                "--ref is only supported for trusted GitHub source installs",
            ));
        }

        let runner = self.petals()?.clone();
        let path = PathBuf::from(request.path);
        if !path.is_absolute() {
            return Err(PetalError::vm("local Petal install path must be absolute"));
        }
        let bindings_by_name = self.petal_runtime_endpoints.clone();
        let mutation = self.petal_mutation.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _mutation = mutation;
            if context.is_cancelled() {
                return Err(PetalError::vm(
                    "Petal install cancelled by disconnected client",
                ));
            }
            let is_dir = std::fs::metadata(&path)?.is_dir();
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
            bloom_petals::package::apply_petal_consent_endpoint_bindings(&mut consent, &bindings)?;
            if context.is_cancelled() {
                return Err(PetalError::vm(
                    "Petal install cancelled by disconnected client",
                ));
            }
            let (result, meta, index) = runner
                .store()
                .install_prepared_petal_package_with_source_guarded(package, None, || {
                    if context.is_cancelled() {
                        Err(PetalError::vm(
                            "Petal install cancelled by disconnected client",
                        ))
                    } else {
                        Ok(())
                    }
                })?;
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
    async fn do_petals_build(
        &self,
        params: &Value,
        context: IpcOperationContext,
    ) -> Result<Value, PetalError> {
        self.petals()?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BuildRequest {
            package_dir: PathBuf,
            out: Option<PathBuf>,
        }
        let request: BuildRequest = serde_json::from_value(params.clone())
            .map_err(|error| PetalError::vm(format!("invalid petals.build request: {error}")))?;
        if !request.package_dir.is_absolute()
            || request.out.as_ref().is_some_and(|path| !path.is_absolute())
        {
            return Err(PetalError::vm(
                "Petal build package and output paths must be absolute",
            ));
        }
        let package_dir = std::fs::canonicalize(&request.package_dir).map_err(|error| {
            PetalError::vm(format!(
                "resolve Petal package directory {}: {error}",
                request.package_dir.display()
            ))
        })?;
        let output = request
            .out
            .as_deref()
            .map(|path| validated_petal_archive_output(&package_dir, path))
            .transpose()?;
        let mutation = self.petal_mutation.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _mutation = mutation;
            if context.is_cancelled() {
                return Err(PetalError::vm(
                    "Petal build cancelled by disconnected client",
                ));
            }
            let package =
                bloom_petals::package::build_petal_package_dir_guarded(&package_dir, || {
                    if context.is_cancelled() {
                        Err(PetalError::vm(
                            "Petal build cancelled by disconnected client",
                        ))
                    } else {
                        Ok(())
                    }
                })?;
            let consent = bloom_petals::package::petal_consent_summary(&package)?;
            if context.is_cancelled() {
                return Err(PetalError::vm(
                    "Petal build cancelled by disconnected client",
                ));
            }
            if let Some(out) = output.as_ref() {
                let parent = out.parent().expect("validated archive has a parent");
                let mut archive = tempfile::NamedTempFile::new_in(parent)?;
                package.write_petal_tar(&mut archive)?;
                archive.flush()?;
                archive.as_file().sync_all()?;
                if context.is_cancelled() {
                    return Err(PetalError::vm(
                        "Petal build cancelled by disconnected client",
                    ));
                }
                archive.persist(out).map_err(|error| error.error)?;
            }
            Ok(json!({
                "hash": package.hash,
                "contract": bloom_petals::package::ROUTE_PACKAGE,
                "wit_digest": bloom_petals::package::contract_wit_digest(),
                "petal_mount": format!("petals/{}/", package.name),
                "routes": package.route_index.routes.len(),
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

fn peer_uid_allowed(effective_uid: u32, observed_uid: u32) -> bool {
    effective_uid == observed_uid
}

fn canonical_socket_target(socket_path: &Path) -> Result<PathBuf, IpcError> {
    let parent = socket_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| IpcError::InsecureSocket {
            path: socket_path.to_owned(),
            reason: "socket path has no parent directory".to_owned(),
        })?;
    let file_name = socket_path
        .file_name()
        .ok_or_else(|| IpcError::InsecureSocket {
            path: socket_path.to_owned(),
            reason: "socket path has no file name".to_owned(),
        })?;
    std::fs::create_dir_all(parent)?;
    let canonical_parent = std::fs::canonicalize(parent)?;
    if !std::fs::metadata(&canonical_parent)?.is_dir() {
        return Err(IpcError::InsecureSocket {
            path: socket_path.to_owned(),
            reason: format!("socket parent {} is not a directory", parent.display()),
        });
    }
    Ok(canonical_parent.join(file_name))
}

fn private_socket_staging_dir(socket_path: &Path) -> Result<tempfile::TempDir, IpcError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let parent = socket_path
        .parent()
        .ok_or_else(|| IpcError::InsecureSocket {
            path: socket_path.to_owned(),
            reason: "socket path has no parent directory".to_owned(),
        })?;
    let staging = tempfile::Builder::new()
        .prefix(".b-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    let metadata = std::fs::symlink_metadata(staging.path())?;
    let mode = metadata.permissions().mode() & 0o777;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_dir() || metadata.uid() != effective_uid || mode != 0o700 {
        return Err(IpcError::InsecureSocket {
            path: socket_path.to_owned(),
            reason: format!(
                "private socket staging directory must have uid={effective_uid} mode=0700; observed uid={} mode={mode:04o}",
                metadata.uid()
            ),
        });
    }
    Ok(staging)
}

fn acquire_endpoint_lock(socket_path: &Path) -> Result<EndpointLock, IpcError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let lock_path = endpoint_lock_path(socket_path)?;
    let fd = rustix::fs::open(
        &lock_path,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
    let file = std::fs::File::from(fd);
    let metadata = file.metadata()?;
    let mode = metadata.permissions().mode() & 0o777;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file() || metadata.uid() != effective_uid || mode & 0o077 != 0 {
        return Err(IpcError::InsecureSocket {
            path: lock_path,
            reason: format!(
                "endpoint lock must be a regular owner-only file with uid={effective_uid}; observed uid={} mode={mode:04o}",
                metadata.uid()
            ),
        });
    }
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(EndpointLock { _file: file }),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Err(IpcError::EndpointBusy(socket_path.to_owned()))
        }
        Err(error) => Err(error.into()),
    }
}

fn endpoint_lock_path(socket_path: &Path) -> Result<PathBuf, IpcError> {
    use std::os::unix::ffi::OsStringExt as _;

    let file_name = socket_path
        .file_name()
        .ok_or_else(|| IpcError::InsecureSocket {
            path: socket_path.to_owned(),
            reason: "socket path has no file name".to_owned(),
        })?;
    let mut lock_name = file_name.as_encoded_bytes().to_vec();
    lock_name.extend_from_slice(b".lock");
    Ok(socket_path.with_file_name(std::ffi::OsString::from_vec(lock_name)))
}

fn validate_stale_socket(socket_path: &Path) -> Result<Option<SocketIdentity>, IpcError> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_socket() || metadata.uid() != effective_uid {
        return Err(IpcError::InsecureSocket {
            path: socket_path.to_owned(),
            reason: "pre-existing path is not a socket owned by the daemon user".to_owned(),
        });
    }
    let identity = SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(_) => return Err(IpcError::EndpointBusy(socket_path.to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(error) => {
            return Err(IpcError::InsecureSocket {
                path: socket_path.to_owned(),
                reason: format!("cannot prove pre-existing socket is stale: {error}"),
            });
        }
    }
    let revalidated = std::fs::symlink_metadata(socket_path)?;
    let revalidated_identity = SocketIdentity {
        device: revalidated.dev(),
        inode: revalidated.ino(),
    };
    if !revalidated.file_type().is_socket()
        || revalidated.uid() != effective_uid
        || revalidated_identity != identity
    {
        return Err(IpcError::EndpointBusy(socket_path.to_owned()));
    }
    Ok(Some(identity))
}

fn verify_socket_security(
    socket_path: &Path,
    effective_uid: u32,
) -> Result<SocketIdentity, IpcError> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    let metadata = std::fs::symlink_metadata(socket_path)?;
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_socket() || metadata.uid() != effective_uid || mode != 0o600 {
        return Err(IpcError::InsecureSocket {
            path: socket_path.to_owned(),
            reason: format!(
                "expected socket uid={effective_uid} mode=0600, observed uid={} mode={mode:04o}",
                metadata.uid()
            ),
        });
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn validated_petal_archive_output(
    package_dir: &Path,
    output: &Path,
) -> Result<PathBuf, PetalError> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| PetalError::vm("Petal archive path has no parent"))?;
    let parent = std::fs::canonicalize(parent).map_err(|error| {
        PetalError::vm(format!(
            "resolve Petal archive parent {}: {error}",
            parent.display()
        ))
    })?;
    let file_name = output
        .file_name()
        .ok_or_else(|| PetalError::vm("Petal archive path has no file name"))?;
    let output = parent.join(file_name);
    if output.starts_with(package_dir) {
        return Err(PetalError::vm(
            "--out must be outside the package directory so archives are not packaged into future builds",
        ));
    }
    match std::fs::symlink_metadata(&output) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(PetalError::vm(format!(
                "Petal archive output {} must be a regular file and not a symlink",
                output.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(output)
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

#[derive(Debug, Error)]
pub enum IpcClientError {
    #[error(transparent)]
    Transport(#[from] std::io::Error),
    #[error("{0}")]
    Rpc(RpcCallError),
    #[error("invalid IPC response: {0}")]
    Protocol(String),
    #[error("refusing insecure Bloom daemon endpoint: {0}")]
    EndpointSecurity(String),
    #[error("incompatible Bloom IPC protocol: client supports {client}, daemon supports {daemon}")]
    Incompatible {
        client: IpcProtocolRange,
        daemon: IpcProtocolRange,
    },
}

#[derive(Debug)]
pub struct IpcCallResult {
    pub result: Value,
    pub daemon_protocol: IpcProtocolRange,
    pub negotiated_protocol: u32,
    pub output_events: usize,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct RpcCallError {
    pub rpc_code: i32,
    pub message: String,
    pub machine: Option<MachineError>,
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

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, IpcClientError> {
        Ok(self.call_with_protocol(method, params).await?.result)
    }

    pub async fn call_with_protocol(
        &self,
        method: &str,
        params: Value,
    ) -> Result<IpcCallResult, IpcClientError> {
        let mut streamed_data = Vec::new();
        let mut reply = self
            .call_streaming(method, params, |event| {
                if event.stream == IpcOutputStream::Data {
                    streamed_data.extend_from_slice(&event.bytes);
                }
                Ok(())
            })
            .await?;
        if reply.result.get("streamed").and_then(Value::as_bool) == Some(true) {
            let expected = reply
                .result
                .get("len")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    IpcClientError::Protocol("streamed response is missing len".into())
                })?;
            if streamed_data.len() as u64 != expected {
                return Err(IpcClientError::Protocol(format!(
                    "streamed byte count mismatch: expected {expected}, received {}",
                    streamed_data.len()
                )));
            }
            let result = reply.result.as_object_mut().ok_or_else(|| {
                IpcClientError::Protocol("streamed response is not an object".into())
            })?;
            result.insert("bytes_b64".into(), Value::String(B64.encode(streamed_data)));
            result.remove("streamed");
        }
        Ok(reply)
    }

    pub async fn call_streaming<F>(
        &self,
        method: &str,
        params: Value,
        mut on_output: F,
    ) -> Result<IpcCallResult, IpcClientError>
    where
        F: FnMut(IpcOutputEvent) -> std::io::Result<()>,
    {
        trace!(socket = %self.socket_path.display(), %method, "ipc.client.call");
        let client_protocol = IpcProtocolRange::supported();
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
            "bloom_protocol": client_protocol,
        });
        let out = serde_json::to_vec(&req).unwrap();
        if out.len() > MAX_IPC_MESSAGE_BYTES {
            return Err(IpcClientError::Protocol(format!(
                "IPC request exceeds {MAX_IPC_MESSAGE_BYTES} bytes"
            )));
        }
        match verify_socket_security(&self.socket_path, rustix::process::geteuid().as_raw()) {
            Ok(_) => {}
            Err(IpcError::Io(error)) => return Err(IpcClientError::Transport(error)),
            Err(error) => return Err(IpcClientError::EndpointSecurity(error.to_string())),
        }
        let stream = UnixStream::connect(&self.socket_path).await?;
        let observed_uid = stream.peer_cred()?.uid();
        let expected_uid = rustix::process::geteuid().as_raw();
        if !peer_uid_allowed(expected_uid, observed_uid) {
            return Err(IpcClientError::EndpointSecurity(format!(
                "daemon peer uid mismatch: expected {expected_uid}, observed {observed_uid}"
            )));
        }
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);
        write_ipc_message(&mut wr, &out).await?;
        let mut output_events = 0_usize;
        let v = loop {
            let line = read_ipc_message(&mut rd).await?.ok_or_else(|| {
                IpcClientError::Protocol("daemon closed the connection without a response".into())
            })?;
            let value: Value = serde_json::from_slice(&line)
                .map_err(|error| IpcClientError::Protocol(error.to_string()))?;
            if value.get("method").and_then(Value::as_str) == Some("bloom.output") {
                let notification_protocol = value
                    .get("bloom_protocol")
                    .cloned()
                    .ok_or_else(|| {
                        IpcClientError::Protocol(
                            "output notification does not advertise a Bloom IPC protocol version"
                                .into(),
                        )
                    })
                    .and_then(|value| {
                        serde_json::from_value::<IpcProtocolRange>(value)
                            .map_err(|error| IpcClientError::Protocol(error.to_string()))
                    })?;
                if client_protocol.negotiate(notification_protocol).is_none() {
                    return Err(IpcClientError::Incompatible {
                        client: client_protocol,
                        daemon: notification_protocol,
                    });
                }
                let params = value.get("params").ok_or_else(|| {
                    IpcClientError::Protocol("output notification is missing params".into())
                })?;
                let stream = serde_json::from_value::<IpcOutputStream>(
                    params.get("stream").cloned().ok_or_else(|| {
                        IpcClientError::Protocol("output notification is missing its stream".into())
                    })?,
                )
                .map_err(|error| IpcClientError::Protocol(error.to_string()))?;
                let bytes =
                    B64.decode(params.get("bytes_b64").and_then(Value::as_str).ok_or_else(
                        || {
                            IpcClientError::Protocol(
                                "output notification is missing bytes_b64".into(),
                            )
                        },
                    )?)
                    .map_err(|error| IpcClientError::Protocol(error.to_string()))?;
                on_output(IpcOutputEvent { stream, bytes })?;
                output_events = output_events.saturating_add(1);
                continue;
            }
            break value;
        };
        let daemon_protocol = v
            .get("bloom_protocol")
            .cloned()
            .ok_or_else(|| {
                IpcClientError::Protocol(
                    "daemon does not advertise a Bloom IPC protocol version; upgrade or restart the daemon"
                        .to_owned(),
                )
            })
            .and_then(|value| {
                serde_json::from_value::<IpcProtocolRange>(value)
                    .map_err(|error| IpcClientError::Protocol(error.to_string()))
            })?;
        let negotiated_protocol =
            client_protocol
                .negotiate(daemon_protocol)
                .ok_or(IpcClientError::Incompatible {
                    client: client_protocol,
                    daemon: daemon_protocol,
                })?;
        if let Some(error) = v.get("error") {
            debug!(%method, error = %error, "ipc.client.rpc_error");
            let error: RpcError = serde_json::from_value(error.clone())
                .map_err(|error| IpcClientError::Protocol(error.to_string()))?;
            let machine = error
                .data
                .and_then(|data| serde_json::from_value::<MachineError>(data).ok());
            return Err(IpcClientError::Rpc(RpcCallError {
                rpc_code: error.code,
                message: error.message,
                machine,
            }));
        }
        Ok(IpcCallResult {
            result: v.get("result").cloned().unwrap_or(Value::Null),
            daemon_protocol,
            negotiated_protocol,
            output_events,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn bounded_frame_reader_rejects_oversized_input_before_newline() {
        let input = vec![b'x'; MAX_IPC_FRAME_BYTES + 1];
        let mut reader = BufReader::new(input.as_slice());
        let error = read_bounded_frame(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("IPC frame exceeds"));
    }

    #[test]
    fn protocol_ranges_negotiate_the_highest_shared_version() {
        let local = IpcProtocolRange {
            current: 3,
            min: 1,
            max: 3,
        };
        let overlapping = IpcProtocolRange {
            current: 4,
            min: 2,
            max: 4,
        };
        let disjoint = IpcProtocolRange {
            current: 5,
            min: 4,
            max: 5,
        };
        assert_eq!(local.negotiate(overlapping), Some(3));
        assert_eq!(local.negotiate(disjoint), None);
    }

    #[tokio::test]
    async fn client_rejects_oversized_request_before_connecting() {
        let client = IpcClient::new("/definitely/missing/bloom.sock");
        let error = client
            .call(
                "oversized",
                json!({ "payload": "x".repeat(MAX_IPC_MESSAGE_BYTES) }),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, IpcClientError::Protocol(_)));
        assert!(error.to_string().contains("IPC request exceeds"));
    }

    #[tokio::test]
    async fn client_rejects_a_daemon_that_does_not_advertise_its_protocol() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("legacy.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let legacy_daemon = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let mut rd = BufReader::new(rd);
            let mut request = String::new();
            rd.read_line(&mut request).await.unwrap();
            wr.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0.0.0-old\"}\n")
                .await
                .unwrap();
        });

        let error = IpcClient::new(&socket)
            .call("version", Value::Null)
            .await
            .unwrap_err();
        assert!(matches!(error, IpcClientError::Protocol(_)));
        assert!(error.to_string().contains("does not advertise"));
        legacy_daemon.await.unwrap();
    }

    #[tokio::test]
    async fn chunked_transport_round_trips_messages_above_the_physical_frame_limit() {
        let message = vec![0xa5; MAX_IPC_FRAME_BYTES + 17];
        let expected = message.clone();
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);
        let writing = tokio::spawn(async move { write_ipc_message(&mut writer, &message).await });
        let mut reader = BufReader::new(reader);
        let received = read_ipc_message(&mut reader).await.unwrap().unwrap();
        writing.await.unwrap().unwrap();
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn client_rejects_insecure_socket_metadata_before_sending_a_request() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("insecure.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
        let error = IpcClient::new(&socket)
            .call("version", Value::Null)
            .await
            .unwrap_err();
        assert!(matches!(error, IpcClientError::EndpointSecurity(_)));
    }

    struct MockBatchConfirmation;

    struct MockMachineCommands;

    struct FailingMachineCommands(MachineError);

    impl MachineCommandService for MockMachineCommands {
        fn execute(&self, command: MachineCommand) -> MachineCommandFuture<'_> {
            Box::pin(async move {
                Ok(MachineCommandOutput {
                    stdout: serde_json::to_string(&command).unwrap(),
                    stderr: String::new(),
                    exit_code: 0,
                })
            })
        }
    }

    impl MachineCommandService for FailingMachineCommands {
        fn execute(&self, _command: MachineCommand) -> MachineCommandFuture<'_> {
            let error = self.0.clone();
            Box::pin(async move { Err(error) })
        }
    }

    struct TrackingSourceInstaller {
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    struct BlockingSourceInstaller {
        started: AtomicBool,
        cancelled: AtomicBool,
        committed: AtomicBool,
    }

    impl PetalSourceInstallService for BlockingSourceInstaller {
        fn install_source(
            &self,
            _params: Value,
            context: IpcOperationContext,
        ) -> Result<Value, String> {
            self.started.store(true, Ordering::SeqCst);
            while !context.is_cancelled() {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            self.cancelled.store(true, Ordering::SeqCst);
            Err("cancelled before commit".to_owned())
        }
    }

    impl PetalSourceInstallService for TrackingSourceInstaller {
        fn install_source(
            &self,
            _params: Value,
            _context: IpcOperationContext,
        ) -> Result<Value, String> {
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

    struct CapturedWriteHandler(tokio::sync::Mutex<Vec<u8>>);

    #[async_trait::async_trait]
    impl Handler for CapturedWriteHandler {
        async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
            Ok(Entry::file(
                path.segments()
                    .last()
                    .map(String::as_str)
                    .unwrap_or("large"),
            ))
        }

        async fn write(&self, _path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
            *self.0.lock().await = data.to_vec();
            Ok(())
        }
    }

    struct AtomicProjectionHandler {
        latest: tokio::sync::Mutex<String>,
        lookup_started: Notify,
        release_lookup: Notify,
    }

    #[async_trait::async_trait]
    impl Handler for AtomicProjectionHandler {
        async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
            if path.to_string_path() != "/latest" {
                return Err(HandlerError::NotFound(path.to_string_path()));
            }
            self.lookup_started.notify_one();
            self.release_lookup.notified().await;
            Ok(Entry::symlink("latest", &self.latest.lock().await))
        }

        async fn write(&self, _path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
            *self.latest.lock().await = String::from_utf8(data.to_vec()).unwrap();
            Ok(())
        }
    }

    #[tokio::test]
    async fn write_with_lookup_excludes_concurrent_ordinary_ipc_write() {
        let handler = Arc::new(AtomicProjectionHandler {
            latest: tokio::sync::Mutex::new(String::new()),
            lookup_started: Notify::new(),
            release_lookup: Notify::new(),
        });
        let server = IpcServer::new(
            Vfs::builder().mount("ids", handler.clone()).build(),
            "0",
            vec![],
        );
        let atomic_server = server.clone();
        let atomic = tokio::spawn(async move {
            atomic_server
                .dispatch(Request {
                    jsonrpc: "2.0".into(),
                    id: json!(1),
                    method: "write_with_lookup".into(),
                    params: json!({
                        "path": "/ids/new",
                        "bytes_b64": B64.encode(b"atomic"),
                        "projection_path": "/ids/latest",
                    }),
                })
                .await
        });
        handler.lookup_started.notified().await;
        let ordinary_server = server.clone();
        let ordinary = tokio::spawn(async move {
            ordinary_server
                .dispatch(Request {
                    jsonrpc: "2.0".into(),
                    id: json!(2),
                    method: "write".into(),
                    params: json!({
                        "path": "/ids/new",
                        "bytes_b64": B64.encode(b"ordinary"),
                    }),
                })
                .await
        });
        tokio::task::yield_now().await;
        handler.release_lookup.notify_one();

        let atomic_response = atomic.await.unwrap();
        assert!(atomic_response.error.is_none());
        assert_eq!(
            atomic_response.result.unwrap()["link_target"],
            json!("atomic")
        );
        assert!(ordinary.await.unwrap().error.is_none());
        assert_eq!(&*handler.latest.lock().await, "ordinary");
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

    #[tokio::test]
    async fn machine_commands_are_dispatched_only_through_the_configured_daemon_service() {
        let server =
            IpcServer::new(vfs(), "0", vec![]).with_machine_commands(Arc::new(MockMachineCommands));
        let response = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "machine.execute".into(),
                params: json!({ "command": "status" }),
            })
            .await;
        assert!(response.error.is_none());
        assert_eq!(
            response.result.unwrap()["stdout"],
            r#"{"command":"status"}"#
        );
    }

    #[tokio::test]
    async fn machine_command_contract_rejects_unknown_fields_and_method_skew() {
        let server =
            IpcServer::new(vfs(), "0", vec![]).with_machine_commands(Arc::new(MockMachineCommands));
        let unknown_field = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "machine.execute".into(),
                params: json!({ "command": "status", "extra": true }),
            })
            .await;
        assert_eq!(unknown_field.error.unwrap().code, -32602);

        let retired_method = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(2),
                method: "machine.status".into(),
                params: Value::Null,
            })
            .await;
        assert_eq!(retired_method.error.unwrap().code, -32601);

        let unknown_command = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(3),
                method: "machine.execute".into(),
                params: json!({ "command": "future_command" }),
            })
            .await;
        assert_eq!(unknown_command.error.unwrap().code, -32602);

        let valid_outbox_action = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(4),
                method: "machine.execute".into(),
                params: json!({
                    "command": "wallet_outbox_cancel",
                    "wallet": "minnow",
                    "chain": "base",
                    "id": "tx-1",
                    "text": "approve",
                }),
            })
            .await;
        assert!(valid_outbox_action.error.is_none());

        let outbox_action_with_unknown_field = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(5),
                method: "machine.execute".into(),
                params: json!({
                    "command": "wallet_outbox_replace",
                    "wallet": "minnow",
                    "chain": "base",
                    "id": "tx-1",
                    "intent": "replacement intent",
                    "bytes_b64": "must-not-be-accepted",
                }),
            })
            .await;
        assert_eq!(outbox_action_with_unknown_field.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn machine_errors_preserve_typed_contract_and_rpc_code() {
        let expected = MachineError::new(
            MachineErrorKind::Unavailable,
            "UNAVAILABLE",
            "Broker is unavailable",
        );
        let server = IpcServer::new(vfs(), "0", vec![])
            .with_machine_commands(Arc::new(FailingMachineCommands(expected.clone())));
        let response = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "machine.execute".into(),
                params: json!({ "command": "status" }),
            })
            .await;
        let error = response.error.unwrap();
        assert_eq!(error.code, -32003);
        assert_eq!(error.message, "Broker is unavailable");
        assert_eq!(
            serde_json::from_value::<MachineError>(error.data.unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn peer_uid_policy_protects_both_server_and_client_directions() {
        assert!(peer_uid_allowed(501, 501));
        assert!(!peer_uid_allowed(501, 0));
        assert!(!peer_uid_allowed(501, 502));
    }

    #[tokio::test]
    async fn server_refuses_to_replace_a_non_socket_path() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("private-run");
        std::fs::create_dir(&parent).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = parent.join("bloom.sock");
        std::fs::write(&socket, b"do not remove").unwrap();
        let error = IpcServer::new(vfs(), "0", vec![])
            .serve(&socket)
            .await
            .unwrap_err();
        assert!(matches!(error, IpcError::InsecureSocket { .. }));
        assert_eq!(std::fs::read(&socket).unwrap(), b"do not remove");
    }

    #[tokio::test]
    async fn server_refuses_to_replace_an_independently_bound_live_listener() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("independent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let inode = std::fs::symlink_metadata(&socket).unwrap().ino();

        let error = IpcServer::new(vfs(), "replacement", vec![])
            .serve(&socket)
            .await
            .unwrap_err();
        assert!(matches!(error, IpcError::EndpointBusy(_)));
        assert_eq!(std::fs::symlink_metadata(&socket).unwrap().ino(), inode);
        assert!(std::os::unix::net::UnixStream::connect(&socket).is_ok());
        drop(listener);
    }

    #[tokio::test]
    async fn server_creates_a_missing_socket_parent_and_accepts_connections() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("private-run");
        let socket = parent.join("bloom.sock");
        let server = IpcServer::new(vfs(), "0", vec![]);
        let serving = server.clone();
        let serving_socket = socket.clone();
        let handle = tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            IpcClient::new(&socket)
                .call("version", Value::Null)
                .await
                .unwrap(),
            "0"
        );
        IpcClient::new(&socket)
            .call("shutdown", Value::Null)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(
            socket.exists(),
            "shutdown leaves an inert socket for restart"
        );
    }

    #[tokio::test]
    async fn server_accepts_an_existing_0755_socket_parent_without_chmod() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("shared-run");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let socket = parent.join("bloom.sock");
        let server = IpcServer::new(vfs(), "0", vec![]);
        let serving = server.clone();
        let serving_socket = socket.clone();
        let handle = tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            IpcClient::new(&socket)
                .call("version", Value::Null)
                .await
                .unwrap(),
            "0"
        );
        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let lock_metadata =
            std::fs::symlink_metadata(endpoint_lock_path(&socket).unwrap()).unwrap();
        assert!(lock_metadata.file_type().is_file());
        assert_eq!(lock_metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(lock_metadata.permissions().mode() & 0o077, 0);
        assert!(
            std::fs::read_dir(&parent).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".b-")),
            "private staging directory must be removed after publication"
        );
        IpcClient::new(&socket)
            .call("shutdown", Value::Null)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(
            socket.exists(),
            "shutdown leaves an inert socket for restart"
        );
        std::fs::remove_file(endpoint_lock_path(&socket).unwrap()).unwrap();
        std::fs::remove_file(&socket).unwrap();
    }

    #[tokio::test]
    async fn atomically_published_listener_accepts_connections_in_tmp() {
        let reserved = tempfile::Builder::new()
            .prefix("bloom-ipc-")
            .tempfile_in("/tmp")
            .unwrap();
        let socket = reserved.path().to_owned();
        reserved.close().unwrap();

        let server = IpcServer::new(vfs(), "0", vec![]);
        let serving = server.clone();
        let serving_socket = socket.clone();
        let handle = tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            IpcClient::new(&socket)
                .call("version", Value::Null)
                .await
                .unwrap(),
            "0"
        );
        IpcClient::new(&socket)
            .call("shutdown", Value::Null)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(
            socket.exists(),
            "shutdown leaves an inert socket for restart"
        );
        std::fs::remove_file(endpoint_lock_path(&socket).unwrap()).unwrap();
        std::fs::remove_file(&socket).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn atomically_published_listener_accepts_connections_in_nested_private_tmp() {
        let home = tempfile::Builder::new()
            .prefix("bloom-ipc-home-")
            .tempdir_in("/private/tmp")
            .unwrap();
        let socket = home.path().join("run/bloom.sock");
        let server = IpcServer::new(vfs(), "0", vec![]);
        let serving = server.clone();
        let serving_socket = socket.clone();
        let handle = tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            IpcClient::new(&socket)
                .call("version", Value::Null)
                .await
                .unwrap(),
            "0"
        );
        IpcClient::new(&socket)
            .call("shutdown", Value::Null)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(
            socket.exists(),
            "shutdown leaves an inert socket for restart"
        );
    }

    #[tokio::test]
    async fn restart_atomically_replaces_the_stale_socket_and_accepts_connections() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("bloom.sock");
        let first = IpcServer::new(vfs(), "first", vec![]);
        let serving = first.clone();
        let serving_socket = socket.clone();
        let first_handle =
            tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let first_inode = std::fs::symlink_metadata(&socket).unwrap().ino();
        IpcClient::new(&socket)
            .call("shutdown", Value::Null)
            .await
            .unwrap();
        first_handle.await.unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&socket).unwrap().ino(),
            first_inode
        );

        let second = IpcServer::new(vfs(), "second", vec![]);
        let serving = second.clone();
        let serving_socket = socket.clone();
        let second_handle =
            tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..50 {
            if std::fs::symlink_metadata(&socket)
                .map(|metadata| metadata.ino() != first_inode)
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_ne!(
            std::fs::symlink_metadata(&socket).unwrap().ino(),
            first_inode
        );
        assert_eq!(
            IpcClient::new(&socket)
                .call("version", Value::Null)
                .await
                .unwrap(),
            "second"
        );
        IpcClient::new(&socket)
            .call("shutdown", Value::Null)
            .await
            .unwrap();
        second_handle.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_server_cannot_replace_the_live_endpoint() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("bloom.sock");
        let first = IpcServer::new(vfs(), "first", vec![]);
        let serving = first.clone();
        let serving_socket = socket.clone();
        let first_handle =
            tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let first_inode = std::fs::symlink_metadata(&socket).unwrap().ino();

        let second = IpcServer::new(vfs(), "second", vec![]);
        let serving = second.clone();
        let serving_socket = socket.clone();
        let second_handle = tokio::spawn(async move { serving.serve(&serving_socket).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            second_handle.is_finished(),
            "lock conflict must fail promptly"
        );
        let second_result = second_handle.await.unwrap();
        assert!(
            matches!(&second_result, Err(IpcError::EndpointBusy(_))),
            "unexpected second server result: {second_result:?}"
        );
        assert_eq!(
            std::fs::symlink_metadata(&socket).unwrap().ino(),
            first_inode
        );
        assert_eq!(
            IpcClient::new(&socket)
                .call("version", Value::Null)
                .await
                .unwrap(),
            "first"
        );
        IpcClient::new(&socket)
            .call("shutdown", Value::Null)
            .await
            .unwrap();
        first_handle.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_never_unlinks_a_replacement_endpoint_inode() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("bloom.sock");
        let server = IpcServer::new(vfs(), "old", vec![]);
        let serving = server.clone();
        let serving_socket = socket.clone();
        let handle = tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let replacement_path = dir.path().join("replacement.sock");
        let replacement = std::os::unix::net::UnixListener::bind(&replacement_path).unwrap();
        let replacement_inode = std::fs::symlink_metadata(&replacement_path).unwrap().ino();
        std::fs::rename(&replacement_path, &socket).unwrap();
        server.trigger_shutdown();
        handle.await.unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&socket).unwrap().ino(),
            replacement_inode
        );
        drop(replacement);
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
    async fn raw_ipc_write_cannot_invoke_wallet_cancel_or_replace() {
        let server = IpcServer::new(vfs(), "0", vec![]);
        for (id, action) in ["cancel", "replace"].into_iter().enumerate() {
            let response = server
                .dispatch(Request {
                    jsonrpc: "2.0".into(),
                    id: json!(id),
                    method: "write".into(),
                    params: json!({
                        "path": format!(
                            "/wallets/minnow/chains/base/outbox/pending/tx-1/{action}"
                        ),
                        "bytes_b64": B64.encode(b"body"),
                    }),
                })
                .await;
            assert_eq!(response.error.unwrap().code, -32007, "{action}");
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
        std::fs::create_dir(package.join("artifacts")).unwrap();
        std::fs::write(package.join("artifacts/keep.txt"), b"preserve").unwrap();
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
                    "package_dir": package.display().to_string(),
                    "out": archive.display().to_string(),
                }),
            })
            .await;
        assert!(build.error.is_none());
        let build = build.result.unwrap();
        assert_eq!(build["routes"], 1);
        assert!(archive.is_file());
        assert_eq!(
            std::fs::read(package.join("artifacts/keep.txt")).unwrap(),
            b"preserve"
        );

        let install = server
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(2),
                method: "petals.install".into(),
                params: json!({ "path": archive.display().to_string() }),
            })
            .await;
        assert!(install.error.is_none());
        let result = install.result.unwrap();
        assert_eq!(result["mode"], "petal");
        assert_eq!(result["petal_mount"], "petals/demo/");
        assert_eq!(result["routes"], 1);
    }

    #[tokio::test]
    async fn petals_build_rpc_rejects_archive_inside_package() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("demo-package");
        write_demo_petal_package(&package);
        let store = bloom_petals::PetalStore::open(dir.path().join("store")).unwrap();
        let registry =
            Arc::new(bloom_petals::NameRegistry::open(dir.path().join("registry")).unwrap());
        let runner = PetalRunner::new(store, registry, bloom_petals::PetalVm::new().unwrap());
        let response = IpcServer::new(vfs(), "0", vec![])
            .with_petals(runner)
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "petals.build".into(),
                params: json!({
                    "package_dir": package.display().to_string(),
                    "out": package.join("archive.petal.tar").display().to_string(),
                }),
            })
            .await;
        let error = response.error.unwrap();
        assert!(error.message.contains("outside the package directory"));
        assert!(!package.join("archive.petal.tar").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn petals_build_rpc_rejects_symlink_archive_output() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("demo-package");
        let target = dir.path().join("target.petal.tar");
        let output = dir.path().join("output.petal.tar");
        write_demo_petal_package(&package);
        std::fs::write(&target, b"sentinel").unwrap();
        std::os::unix::fs::symlink(&target, &output).unwrap();
        let store = bloom_petals::PetalStore::open(dir.path().join("store")).unwrap();
        let registry =
            Arc::new(bloom_petals::NameRegistry::open(dir.path().join("registry")).unwrap());
        let runner = PetalRunner::new(store, registry, bloom_petals::PetalVm::new().unwrap());
        let response = IpcServer::new(vfs(), "0", vec![])
            .with_petals(runner)
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "petals.build".into(),
                params: json!({
                    "package_dir": package.display().to_string(),
                    "out": output.display().to_string(),
                }),
            })
            .await;
        assert!(response.error.unwrap().message.contains("not a symlink"));
        assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
    }

    #[tokio::test]
    async fn petals_build_rpc_rejects_non_regular_archive_output() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("demo-package");
        let output = dir.path().join("archive-directory");
        write_demo_petal_package(&package);
        std::fs::create_dir(&output).unwrap();
        let store = bloom_petals::PetalStore::open(dir.path().join("store")).unwrap();
        let registry =
            Arc::new(bloom_petals::NameRegistry::open(dir.path().join("registry")).unwrap());
        let runner = PetalRunner::new(store, registry, bloom_petals::PetalVm::new().unwrap());
        let response = IpcServer::new(vfs(), "0", vec![])
            .with_petals(runner)
            .dispatch(Request {
                jsonrpc: "2.0".into(),
                id: json!(1),
                method: "petals.build".into(),
                params: json!({
                    "package_dir": package.display().to_string(),
                    "out": output.display().to_string(),
                }),
            })
            .await;
        assert!(
            response
                .error
                .unwrap()
                .message
                .contains("must be a regular file")
        );
        assert!(output.is_dir());
    }

    #[tokio::test]
    async fn concurrent_builds_of_the_same_package_are_serialized() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("demo-package");
        write_demo_petal_package(&package);
        let store = bloom_petals::PetalStore::open(dir.path().join("store")).unwrap();
        let registry =
            Arc::new(bloom_petals::NameRegistry::open(dir.path().join("registry")).unwrap());
        let runner = PetalRunner::new(store, registry, bloom_petals::PetalVm::new().unwrap());
        let server = IpcServer::new(vfs(), "0", vec![]).with_petals(runner);
        let params = json!({"package_dir": package.display().to_string(), "out": null});
        let first = server.dispatch(Request {
            jsonrpc: "2.0".into(),
            id: json!(1),
            method: "petals.build".into(),
            params: params.clone(),
        });
        let second = server.dispatch(Request {
            jsonrpc: "2.0".into(),
            id: json!(2),
            method: "petals.build".into(),
            params,
        });

        let (first, second) = tokio::join!(first, second);
        assert!(first.error.is_none(), "{:?}", first.error);
        assert!(second.error.is_none(), "{:?}", second.error);
        assert!(package.join("artifacts/routes/r000001.wasm").is_file());
        assert!(package.join("artifacts/build-manifest.json").is_file());
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
    async fn disconnect_cancels_blocked_source_install_before_commit() {
        let installer = Arc::new(BlockingSourceInstaller {
            started: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            committed: AtomicBool::new(false),
        });
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("private-run/bloom.sock");
        let server =
            IpcServer::new(vfs(), "0", vec![]).with_petal_source_installer(installer.clone());
        let serving = server.clone();
        let serving_socket = socket.clone();
        let server_task =
            tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let client = IpcClient::new(&socket);
        let install_task = tokio::spawn(async move {
            client
                .call(
                    "petals.install",
                    json!({"path": "https://github.com/bloom-directory/blocked"}),
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !installer.started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        install_task.abort();
        let _ = install_task.await;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !installer.cancelled.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!installer.committed.load(Ordering::SeqCst));

        server.trigger_shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn end_to_end_over_uds() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("private-run/bloom.sock");
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            let metadata = std::fs::symlink_metadata(&sock).unwrap();
            assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        let client = IpcClient::new(&sock);

        let version = client
            .call_with_protocol("version", Value::Null)
            .await
            .unwrap();
        assert_eq!(version.result.as_str().unwrap(), "0.0.0-test");
        assert_eq!(version.daemon_protocol, IpcProtocolRange::supported());
        assert_eq!(version.negotiated_protocol, IPC_PROTOCOL_CURRENT);

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
    async fn vfs_read_succeeds_below_and_above_the_single_frame_base64_threshold() {
        let effective_threshold = MAX_IPC_FRAME_BYTES / 4 * 3;
        for size in [
            effective_threshold - 64 * 1024,
            effective_threshold + 64 * 1024,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("private-run/bloom.sock");
            let body = vec![0x5a; size];
            let vfs = Vfs::builder()
                .mount(
                    "stub",
                    Arc::new(SingleFileHandler::new("large", body.clone())),
                )
                .build();
            let server = IpcServer::new(vfs, "0", vec![]);
            let serving = server.clone();
            let serving_socket = socket.clone();
            let handle = tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
            for _ in 0..100 {
                if socket.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            let result = IpcClient::new(&socket)
                .call("read", json!({"path": "/stub/large"}))
                .await
                .unwrap();
            assert_eq!(
                B64.decode(result["bytes_b64"].as_str().unwrap()).unwrap(),
                body
            );
            IpcClient::new(&socket)
                .call("shutdown", Value::Null)
                .await
                .unwrap();
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn vfs_read_streams_above_the_logical_message_limit() {
        let size = MAX_IPC_MESSAGE_BYTES / 4 * 3 + 64 * 1024;
        let body = vec![0x5a; size];
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("private-run/bloom.sock");
        let vfs = Vfs::builder()
            .mount(
                "stub",
                Arc::new(SingleFileHandler::new("large", body.clone())),
            )
            .build();
        let server = IpcServer::new(vfs, "0", vec![]);
        let serving = server.clone();
        let serving_socket = socket.clone();
        let handle = tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut received = Vec::new();
        let result = IpcClient::new(&socket)
            .call_streaming("read", json!({"path": "/stub/large"}), |event| {
                assert_eq!(event.stream, IpcOutputStream::Data);
                received.extend_from_slice(&event.bytes);
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(result.result["streamed"], true);
        assert_eq!(received, body);

        IpcClient::new(&socket)
            .call("shutdown", Value::Null)
            .await
            .unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn vfs_write_succeeds_above_the_single_frame_base64_threshold() {
        let size = MAX_IPC_FRAME_BYTES / 4 * 3 + 64 * 1024;
        let body = vec![0x5a; size];
        let handler = Arc::new(CapturedWriteHandler(tokio::sync::Mutex::new(Vec::new())));
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("private-run/bloom.sock");
        let server = IpcServer::new(
            Vfs::builder().mount("capture", handler.clone()).build(),
            "0",
            vec![],
        );
        let serving = server.clone();
        let serving_socket = socket.clone();
        let server_task =
            tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        IpcClient::new(&socket)
            .call(
                "write",
                json!({"path": "/capture/large", "bytes_b64": B64.encode(&body)}),
            )
            .await
            .unwrap();
        assert_eq!(&*handler.0.lock().await, &body);
        IpcClient::new(&socket)
            .call("shutdown", Value::Null)
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn client_decodes_machine_rpc_errors_without_json_wrappers() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("private-run/bloom.sock");
        let expected = MachineError::new(
            MachineErrorKind::InvalidParams,
            "INVALID_ARGUMENT",
            "wallet name is invalid",
        );
        let server = IpcServer::new(vfs(), "0", vec![])
            .with_machine_commands(Arc::new(FailingMachineCommands(expected.clone())));
        let serving = server.clone();
        let serving_socket = sock.clone();
        let handle = tokio::spawn(async move { serving.serve(&serving_socket).await.unwrap() });
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let error = IpcClient::new(&sock)
            .call("machine.execute", json!({ "command": "status" }))
            .await
            .unwrap_err();
        let IpcClientError::Rpc(error) = error else {
            panic!("expected decoded RPC error");
        };
        assert_eq!(error.to_string(), "wallet name is invalid");
        assert_eq!(error.rpc_code, -32602);
        assert_eq!(error.machine, Some(expected));

        server.trigger_shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn unknown_and_retired_secret_methods_return_minus_32601() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("private-run/bloom.sock");
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

        for bloom_protocol in [None, Some(json!({"current": 2, "min": 2, "max": 2}))] {
            let mut request = json!({
                "jsonrpc": "2.0",
                "id": "incompatible",
                "method": "version",
                "params": null,
            });
            if let Some(protocol) = bloom_protocol {
                request["bloom_protocol"] = protocol;
            }
            wr.write_all(serde_json::to_string(&request).unwrap().as_bytes())
                .await
                .unwrap();
            wr.write_all(b"\n").await.unwrap();
            wr.flush().await.unwrap();
            let mut line = String::new();
            rd.read_line(&mut line).await.unwrap();
            let response: Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(response["error"]["code"], -32010);
            assert_eq!(response["bloom_protocol"]["current"], IPC_PROTOCOL_CURRENT);
        }

        for (id, method) in ["nope", "write_unlocked", "wallet.sign_policy"]
            .into_iter()
            .enumerate()
        {
            let request = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": {},
                "bloom_protocol": IpcProtocolRange::supported(),
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
