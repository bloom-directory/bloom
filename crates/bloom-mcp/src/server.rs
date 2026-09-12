//! Newline-delimited JSON-RPC 2.0 server speaking the Model Context Protocol.
//!
//! Transport is stdio only: an MCP client spawns `bloom mcp serve` as a child
//! process and owns its lifetime. That keeps the proxy off the network, gives
//! it the invoking user's identity for the daemon's peer-uid check, and means
//! nothing is listening when no client is attached. Diagnostics go to stderr;
//! stdout carries protocol frames exclusively.

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::{debug, warn};

use crate::backend::{VfsCommandError, VfsCommands, VfsMethod};
use crate::tools::{self, ToolError};

/// Server name reported in `initialize`.
pub const SERVER_NAME: &str = "bloom-vfs";

/// MCP revision this server implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Revisions this server can speak. `initialize` echoes the client's revision
/// when it is one of these, and otherwise answers with [`PROTOCOL_VERSION`].
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// Largest accepted inbound frame. MCP requests are small; the cap stops a
/// misbehaving client from growing the read buffer without bound.
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

const INSTRUCTIONS: &str = "Bloom exposes an agentic Ethereum wallet as a virtual filesystem. \
Discover paths with `vfs_list` starting at `/`, read files with `vfs_read`, inspect metadata with \
`vfs_stat`, and stage actions by writing intents with `vfs_write`. Value-moving actions are staged \
and must be confirmed by a second write after reviewing the generated plan. This server is a proxy \
for the same VFS commands as `bloom vfs …`; it holds no keys and adds no permissions of its own.";

/// An MCP server bound to one canonical VFS command transport.
#[derive(Clone)]
pub struct McpServer {
    commands: Arc<dyn VfsCommands>,
    version: String,
}

impl McpServer {
    pub fn new(commands: Arc<dyn VfsCommands>, version: impl Into<String>) -> Self {
        Self {
            commands,
            version: version.into(),
        }
    }

    /// Serve MCP on this process's stdin/stdout until the client closes stdin.
    pub async fn serve_stdio(&self) -> std::io::Result<()> {
        self.serve(BufReader::new(tokio::io::stdin()), tokio::io::stdout())
            .await
    }

    /// Serve MCP over any framed byte pair. Exits cleanly at end of input.
    pub async fn serve<R, W>(&self, mut reader: R, mut writer: W) -> std::io::Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        while let Some(frame) = read_bounded_line(&mut reader).await? {
            let frame = String::from_utf8_lossy(&frame);
            let frame = frame.trim();
            if frame.is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(frame) {
                Ok(request) => self.handle(request).await,
                Err(error) => {
                    warn!(%error, "mcp.parse_error");
                    Some(error_response(
                        Value::Null,
                        -32700,
                        format!("parse error: {error}"),
                    ))
                }
            };
            let Some(response) = response else { continue };
            let mut line = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
            line.push(b'\n');
            writer.write_all(&line).await?;
            writer.flush().await?;
        }
        Ok(())
    }

    /// Handle one decoded JSON-RPC message. `None` means "notification — say
    /// nothing", which MCP requires for `notifications/*`.
    pub async fn handle(&self, request: Value) -> Option<Value> {
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let id = request.get("id").cloned();
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        debug!(%method, "mcp.request");

        // No id: a notification. Never answer, not even on error.
        let Some(id) = id.filter(|id| !id.is_null()) else {
            return None;
        };
        if let Some(version) = request.get("jsonrpc").and_then(Value::as_str)
            && version != "2.0"
        {
            return Some(error_response(id, -32600, "jsonrpc must be 2.0"));
        }

        Some(match method {
            "initialize" => ok_response(id, self.initialize(&params)),
            "ping" => ok_response(id, json!({})),
            "tools/list" => ok_response(id, json!({ "tools": tool_descriptors() })),
            "tools/call" => self.tools_call(id, &params).await,
            "resources/list" => self.resources_list(id).await,
            "resources/templates/list" => ok_response(id, resource_templates()),
            "resources/read" => self.resources_read(id, &params).await,
            other => error_response(id, -32601, format!("method not found: {other}")),
        })
    }

    fn initialize(&self, params: &Value) -> Value {
        let requested = params.get("protocolVersion").and_then(Value::as_str);
        let negotiated = requested
            .filter(|version| SUPPORTED_PROTOCOL_VERSIONS.contains(version))
            .unwrap_or(PROTOCOL_VERSION);
        json!({
            "protocolVersion": negotiated,
            "capabilities": {
                "tools": { "listChanged": false },
                "resources": { "listChanged": false, "subscribe": false },
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "title": "Bloom VFS",
                "version": self.version,
            },
            "instructions": INSTRUCTIONS,
        })
    }

    async fn tools_call(&self, id: Value, params: &Value) -> Value {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return error_response(id, -32602, "tools/call requires a tool `name`");
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
        match tools::call(self.commands.as_ref(), name, &arguments).await {
            Ok(result) => ok_response(id, result),
            Err(error @ (ToolError::UnknownTool(_) | ToolError::InvalidArguments(_))) => {
                error_response(id, -32602, error.message())
            }
        }
    }

    /// Resources are the VFS root's files. Everything deeper is reachable
    /// through the `bloom:///{path}` template and the `vfs_*` tools, which is
    /// also what keeps this from eagerly walking (and side-effecting on) the
    /// whole tree.
    async fn resources_list(&self, id: Value) -> Value {
        let listed = self
            .commands
            .call(VfsMethod::List, json!({ "path": "/" }))
            .await;
        let entries = match listed {
            Ok(Value::Array(entries)) => entries,
            Ok(_) => return error_response(id, -32603, "daemon list reply is not an array"),
            Err(error) => return vfs_error_response(id, &error),
        };
        let resources: Vec<Value> = entries
            .iter()
            .filter(|entry| entry.get("kind").and_then(Value::as_str) == Some("file"))
            .filter_map(|entry| {
                let name = entry.get("name").and_then(Value::as_str)?;
                let path = format!("/{name}");
                Some(json!({
                    "uri": tools::resource_uri(&path),
                    "name": name,
                    "title": path,
                    "mimeType": tools::mime_type_for(&path, true),
                    "size": entry.get("size").cloned().unwrap_or(Value::Null),
                }))
            })
            .collect();
        ok_response(id, json!({ "resources": resources }))
    }

    async fn resources_read(&self, id: Value, params: &Value) -> Value {
        let Some(uri) = params.get("uri").and_then(Value::as_str) else {
            return error_response(id, -32602, "resources/read requires a `uri`");
        };
        let path = match tools::path_from_uri(uri) {
            Ok(path) => path,
            Err(message) => return error_response(id, -32602, message),
        };
        let read = self
            .commands
            .call(VfsMethod::Read, json!({ "path": path }))
            .await;
        let bytes = match read.and_then(|result| tools::read_bytes(&result)) {
            Ok(bytes) => bytes,
            Err(error) => return vfs_error_response(id, &error),
        };
        let content = match std::str::from_utf8(&bytes) {
            Ok(text) => json!({
                "uri": uri,
                "mimeType": tools::mime_type_for(&path, true),
                "text": text,
            }),
            Err(_) => {
                let (content, _) = tools::bytes_payload(&path, &bytes);
                let mut blob = content[0]["resource"].clone();
                blob["uri"] = Value::String(uri.to_owned());
                blob
            }
        };
        ok_response(id, json!({ "contents": [content] }))
    }
}

fn tool_descriptors() -> Vec<Value> {
    tools::TOOLS.iter().map(|tool| tool.descriptor()).collect()
}

fn resource_templates() -> Value {
    json!({
        "resourceTemplates": [{
            "uriTemplate": "bloom:///{+path}",
            "name": "bloom-vfs-path",
            "title": "Bloom VFS path",
            "description": "Any readable Bloom VFS path, for example `bloom:///status/health`. Use `vfs_list` to discover paths.",
        }],
    })
}

fn ok_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i32, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() },
    })
}

/// Protocol-level surfaces (`resources/*`) propagate the daemon's own JSON-RPC
/// code and message rather than inventing a proxy-specific vocabulary.
fn vfs_error_response(id: Value, error: &VfsCommandError) -> Value {
    error_response(id, error.code, error.message.clone())
}

/// Read one newline-terminated frame, refusing to buffer past
/// [`MAX_MESSAGE_BYTES`]. Mirrors the daemon's bounded IPC framing.
async fn read_bounded_line<R>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((!frame.is_empty()).then_some(frame));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map(|index| index + 1).unwrap_or(available.len());
        if frame.len().saturating_add(take) > MAX_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("MCP message exceeds {MAX_MESSAGE_BYTES} bytes"),
            ));
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(Some(frame));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    /// Records what the proxy asked the canonical command surface for.
    struct RecordingCommands {
        calls: std::sync::Mutex<Vec<(VfsMethod, Value)>>,
        reply: Result<Value, VfsCommandError>,
    }

    impl RecordingCommands {
        fn new(reply: Result<Value, VfsCommandError>) -> Arc<Self> {
            Arc::new(Self {
                calls: std::sync::Mutex::new(Vec::new()),
                reply,
            })
        }
    }

    #[async_trait]
    impl VfsCommands for RecordingCommands {
        async fn call(&self, method: VfsMethod, params: Value) -> Result<Value, VfsCommandError> {
            self.calls.lock().unwrap().push((method, params));
            self.reply.clone()
        }

        fn endpoint(&self) -> String {
            "test".into()
        }
    }

    fn server(reply: Result<Value, VfsCommandError>) -> (McpServer, Arc<RecordingCommands>) {
        let commands = RecordingCommands::new(reply);
        (McpServer::new(commands.clone(), "0.0.0-test"), commands)
    }

    #[tokio::test]
    async fn initialize_echoes_a_supported_client_revision() {
        let (server, _) = server(Ok(Value::Null));
        let response = server
            .handle(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(response["result"]["serverInfo"]["name"], SERVER_NAME);
    }

    #[tokio::test]
    async fn initialize_falls_back_to_this_servers_revision() {
        let (server, _) = server(Ok(Value::Null));
        let response = server
            .handle(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "1999-01-01"},
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn notifications_get_no_response() {
        let (server, _) = server(Ok(Value::Null));
        assert!(
            server
                .handle(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn unknown_methods_and_tools_are_rejected_without_touching_the_daemon() {
        let (server, commands) = server(Ok(Value::Null));
        let response = server
            .handle(json!({"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe"}))
            .await
            .unwrap();
        assert_eq!(response["error"]["code"], -32601);

        let response = server
            .handle(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "machine_execute", "arguments": {}},
            }))
            .await
            .unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("unknown tool")
        );
        assert!(commands.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn tools_call_maps_onto_the_canonical_command() {
        let (server, commands) = server(Ok(json!({"bytes_b64": "aGk=", "len": 2})));
        let response = server
            .handle(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "vfs_read", "arguments": {"path": "/docs/README.md"}},
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["content"][0]["text"], "hi");
        let calls = commands.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, VfsMethod::Read);
        assert_eq!(calls[0].1, json!({"path": "/docs/README.md"}));
    }

    #[tokio::test]
    async fn daemon_errors_become_tool_errors_with_the_daemon_code() {
        let (server, _) = server(Err(VfsCommandError::new(-32007, "permission denied")));
        let response = server
            .handle(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "vfs_write", "arguments": {"path": "/x", "text": "y"}},
            }))
            .await
            .unwrap();
        let result = &response["result"];
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["error"]["code"], -32007);
        assert_eq!(result["content"][0]["text"], "permission denied");
        assert!(response.get("error").is_none(), "{response}");
    }

    #[tokio::test]
    async fn resources_read_propagates_the_daemon_error_as_a_protocol_error() {
        let (server, _) = server(Err(VfsCommandError::new(-32004, "not found: /nope")));
        let response = server
            .handle(json!({
                "jsonrpc": "2.0", "id": 1, "method": "resources/read",
                "params": {"uri": "bloom:///nope"},
            }))
            .await
            .unwrap();
        assert_eq!(response["error"]["code"], -32004);
        assert_eq!(response["error"]["message"], "not found: /nope");
    }

    #[tokio::test]
    async fn resources_read_rejects_foreign_uri_schemes() {
        let (server, commands) = server(Ok(Value::Null));
        let response = server
            .handle(json!({
                "jsonrpc": "2.0", "id": 1, "method": "resources/read",
                "params": {"uri": "file:///etc/passwd"},
            }))
            .await
            .unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert!(commands.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn tools_list_advertises_every_vfs_capability() {
        let (server, _) = server(Ok(Value::Null));
        let response = server
            .handle(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
            .await
            .unwrap();
        let names: Vec<&str> = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "vfs_list",
                "vfs_read",
                "vfs_stat",
                "vfs_write",
                "vfs_write_then_stat"
            ]
        );
    }

    #[tokio::test]
    async fn serve_answers_framed_requests_and_stops_at_end_of_input() {
        let (server, _) = server(Ok(Value::Null));
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\
                     {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
        let mut output = Vec::new();
        server
            .serve(BufReader::new(input.as_bytes()), &mut output)
            .await
            .unwrap();
        let lines: Vec<&str> = std::str::from_utf8(&output)
            .unwrap()
            .lines()
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), 1, "notifications must not be answered");
        let response: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"], json!({}));
    }

    #[tokio::test]
    async fn malformed_frames_get_a_parse_error_without_killing_the_session() {
        let (server, _) = server(Ok(Value::Null));
        let input = "not json\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
        let mut output = Vec::new();
        server
            .serve(BufReader::new(input.as_bytes()), &mut output)
            .await
            .unwrap();
        let lines: Vec<Value> = std::str::from_utf8(&output)
            .unwrap()
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines[0]["error"]["code"], -32700);
        assert_eq!(lines[1]["id"], 2);
    }

    #[tokio::test]
    async fn oversized_frames_are_refused() {
        let mut input = vec![b'x'; MAX_MESSAGE_BYTES + 1];
        input.push(b'\n');
        let error = read_bounded_line(&mut BufReader::new(input.as_slice()))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
