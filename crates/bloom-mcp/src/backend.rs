//! The canonical VFS command surface the MCP server is allowed to proxy.
//!
//! Every MCP tool and resource lands on [`VfsCommands::call`], which speaks the
//! daemon's existing JSON-RPC IPC methods. There is no second semantic layer:
//! path parsing, authorization, audit, caching, and error shaping all happen
//! where they already happen — inside `bloom_vfs::Vfs` and its handlers.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bloom_daemon::ipc::{IpcClient, IpcClientError};
use serde_json::Value;
use thiserror::Error;

/// JSON-RPC code used when the proxy could not reach the daemon at all, or the
/// daemon answered with a reply this proxy cannot decode. Both are failures of
/// this server rather than of the request, which is exactly JSON-RPC's
/// `-32603 Internal error`.
///
/// It deliberately is **not** `-32002`: MCP reserves that code for "Resource
/// not found" on `resources/read`, so using it for a transport failure would
/// tell clients a path is absent when the daemon is merely down.
///
/// Daemon-originated failures keep the daemon's own code
/// ([`DAEMON_NOT_FOUND_CODE`], `-32007` permission denied, …) so clients see
/// one error vocabulary.
pub const DAEMON_UNREACHABLE_CODE: i32 = -32603;

/// The daemon's "not found" code, as emitted by `HandlerError::NotFound`. The
/// resource surface translates it into MCP's own not-found code; the tool
/// surface passes it through untouched.
pub const DAEMON_NOT_FOUND_CODE: i32 = -32004;

/// The five VFS commands `bloom vfs …` uses, and the only methods this proxy
/// can name. Modelling them as an enum keeps non-VFS IPC methods
/// (`machine.execute`, `petals.*`, `confirm_batch`, `shutdown`) unreachable
/// from MCP by construction rather than by review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VfsMethod {
    /// `bloom vfs stat` — metadata for one path.
    Lookup,
    /// `bloom vfs cat` — file bytes.
    Read,
    /// `bloom vfs write` — bytes into a writable path.
    Write,
    /// Write, then look up the identity projection it produced, under the
    /// daemon's mutation gate.
    WriteWithLookup,
    /// `bloom vfs ls` — directory children.
    List,
}

impl VfsMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            VfsMethod::Lookup => "lookup",
            VfsMethod::Read => "read",
            VfsMethod::Write => "write",
            VfsMethod::WriteWithLookup => "write_with_lookup",
            VfsMethod::List => "list",
        }
    }
}

/// A failed VFS command, carrying the daemon's JSON-RPC code verbatim.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct VfsCommandError {
    pub code: i32,
    pub message: String,
}

impl VfsCommandError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn unreachable(message: impl Into<String>) -> Self {
        Self::new(DAEMON_UNREACHABLE_CODE, message)
    }
}

/// Transport for the canonical VFS command surface.
#[async_trait]
pub trait VfsCommands: Send + Sync {
    async fn call(&self, method: VfsMethod, params: Value) -> Result<Value, VfsCommandError>;

    /// Human-readable upstream description, surfaced in MCP server
    /// instructions and transport errors.
    fn endpoint(&self) -> String;
}

/// Production transport: the same Unix-socket JSON-RPC endpoint the CLI uses.
#[derive(Clone, Debug)]
pub struct IpcVfsCommands {
    socket: PathBuf,
}

impl IpcVfsCommands {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

#[async_trait]
impl VfsCommands for IpcVfsCommands {
    async fn call(&self, method: VfsMethod, params: Value) -> Result<Value, VfsCommandError> {
        let client = IpcClient::new(&self.socket);
        client
            .call(method.as_str(), params)
            .await
            .map_err(|error| self.map_error(error))
    }

    fn endpoint(&self) -> String {
        format!("unix:{}", self.socket.display())
    }
}

impl IpcVfsCommands {
    fn map_error(&self, error: IpcClientError) -> VfsCommandError {
        match error {
            // A daemon-side failure. Keep its code and message exactly as the
            // CLI would print them.
            IpcClientError::Rpc(error) => VfsCommandError::new(error.rpc_code, error.message),
            IpcClientError::Transport(error) if error.kind() == std::io::ErrorKind::NotFound => {
                VfsCommandError::unreachable(format!(
                    "Bloom daemon endpoint {} is not available: {error}; start it with 'bloom serve'",
                    self.endpoint()
                ))
            }
            IpcClientError::Transport(error) => VfsCommandError::unreachable(format!(
                "Bloom daemon endpoint {} failed: {error}; start it with 'bloom serve'",
                self.endpoint()
            )),
            IpcClientError::Protocol(message) => VfsCommandError::unreachable(format!(
                "Bloom daemon endpoint {} returned {message}",
                self.endpoint()
            )),
            IpcClientError::EndpointSecurity(message) => VfsCommandError::unreachable(format!(
                "Bloom daemon endpoint {} is insecure: {message}",
                self.endpoint()
            )),
            error @ IpcClientError::Incompatible { .. } => VfsCommandError::unreachable(format!(
                "Bloom daemon endpoint {} rejected: {error}",
                self.endpoint()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_names_match_the_daemon_ipc_surface() {
        assert_eq!(VfsMethod::Lookup.as_str(), "lookup");
        assert_eq!(VfsMethod::Read.as_str(), "read");
        assert_eq!(VfsMethod::Write.as_str(), "write");
        assert_eq!(VfsMethod::WriteWithLookup.as_str(), "write_with_lookup");
        assert_eq!(VfsMethod::List.as_str(), "list");
    }

    #[tokio::test]
    async fn a_missing_socket_is_reported_as_an_unreachable_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let commands = IpcVfsCommands::new(dir.path().join("absent.sock"));
        let error = commands
            .call(VfsMethod::List, serde_json::json!({"path": "/"}))
            .await
            .unwrap_err();
        assert_eq!(error.code, DAEMON_UNREACHABLE_CODE);
        assert!(error.message.contains("bloom serve"), "{error}");
    }

    /// A dead daemon must never be reported with MCP's resource-not-found
    /// code, which would read as "this VFS path does not exist".
    #[test]
    fn the_unreachable_code_does_not_collide_with_mcp_or_daemon_codes() {
        assert_eq!(DAEMON_UNREACHABLE_CODE, -32603);
        assert_ne!(DAEMON_UNREACHABLE_CODE, -32002);
        assert_ne!(DAEMON_UNREACHABLE_CODE, DAEMON_NOT_FOUND_CODE);
    }
}
