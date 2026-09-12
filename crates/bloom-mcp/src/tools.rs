//! The MCP tool catalog: one tool per canonical VFS command.
//!
//! Each tool is a thin adapter — it copies the caller's arguments into the
//! daemon's JSON-RPC params and shapes the reply into MCP content. Argument
//! validation beyond "is this JSON the right shape" is deliberately left to the
//! daemon so MCP callers see exactly the errors `bloom vfs …` sees.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value, json};

use crate::backend::{DAEMON_UNREACHABLE_CODE, VfsCommandError, VfsCommands, VfsMethod};

/// URI scheme for VFS paths exposed as MCP resources: `bloom:///status/health`.
pub const RESOURCE_SCHEME: &str = "bloom://";

/// A tool the MCP server advertises, bound to the VFS command it proxies.
#[derive(Clone, Copy, Debug)]
pub struct ToolSpec {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub method: VfsMethod,
    /// Mirrors the VFS mutation boundary: `read`/`list`/`lookup` are reads,
    /// the two write commands are not. Note that a handful of VFS reads are
    /// deliberately side-effecting (signing, broadcast); the daemon audits
    /// those regardless of which client asks.
    pub read_only: bool,
}

/// Every VFS capability reachable from the public CLI/IPC surface.
pub const TOOLS: [ToolSpec; 5] = [
    ToolSpec {
        name: "vfs_list",
        title: "List a Bloom VFS directory",
        description: "List the children of a Bloom VFS directory. Equivalent to `bloom vfs ls <path>`; returns one entry per child with its name, kind (dir/file/symlink), size, POSIX mode, symlink target, and modification time. Start at `/` to discover the available subtrees.",
        method: VfsMethod::List,
        read_only: true,
    },
    ToolSpec {
        name: "vfs_read",
        title: "Read a Bloom VFS file",
        description: "Read the bytes of a Bloom VFS file. Equivalent to `bloom vfs cat <path>`. UTF-8 content is returned as text; anything else is returned as a base64 blob. Some paths are side-effecting by design (signing, broadcast); check the path's documentation before reading.",
        method: VfsMethod::Read,
        read_only: true,
    },
    ToolSpec {
        name: "vfs_stat",
        title: "Stat a Bloom VFS path",
        description: "Return Bloom VFS metadata for a path without reading it. Equivalent to `bloom vfs stat <path>`: name, kind, size, POSIX mode, symlink target, and modification time.",
        method: VfsMethod::Lookup,
        read_only: false,
    },
    ToolSpec {
        name: "vfs_write",
        title: "Write a Bloom VFS file",
        description: "Write bytes to a writable Bloom VFS path. Equivalent to `bloom vfs write <path>`. Supply either `text` (UTF-8) or `bytes_b64` (arbitrary bytes). Writes are audited and only a small set of injection points accept them; everything else fails with `permission denied`.",
        method: VfsMethod::Write,
        read_only: false,
    },
    ToolSpec {
        name: "vfs_write_then_stat",
        title: "Write a Bloom VFS file and stat its projection",
        description: "Write bytes to a writable Bloom VFS path and, under the daemon's mutation gate, stat the identity projection the write produced (for example writing `/requests/new` and reading back `/requests/latest`). Use this instead of a write followed by a separate stat when the projection identity matters.",
        method: VfsMethod::WriteWithLookup,
        read_only: false,
    },
];

pub fn find(name: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|tool| tool.name == name)
}

/// A tool call that never reached the daemon: the client asked for something
/// this server does not expose, or sent arguments of the wrong JSON shape.
#[derive(Debug, PartialEq, Eq)]
pub enum ToolError {
    UnknownTool(String),
    InvalidArguments(String),
}

impl ToolError {
    pub fn message(&self) -> String {
        match self {
            ToolError::UnknownTool(name) => format!("unknown tool: {name}"),
            ToolError::InvalidArguments(detail) => format!("invalid tool arguments: {detail}"),
        }
    }
}

impl ToolSpec {
    /// The JSON Schema advertised in `tools/list`.
    pub fn input_schema(&self) -> Value {
        let path = json!({
            "type": "string",
            "description": "Absolute Bloom VFS path, for example `/status/health`.",
        });
        let text = json!({
            "type": "string",
            "description": "UTF-8 payload to write. Mutually exclusive with `bytes_b64`.",
        });
        let bytes_b64 = json!({
            "type": "string",
            "description": "Standard base64 payload, for writing arbitrary (non-UTF-8) bytes. Takes precedence over `text`.",
        });
        match self.method {
            VfsMethod::List => json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute Bloom VFS directory path. Defaults to the VFS root.",
                        "default": "/",
                    },
                },
                "additionalProperties": false,
            }),
            VfsMethod::Read | VfsMethod::Lookup => json!({
                "type": "object",
                "properties": { "path": path },
                "required": ["path"],
                "additionalProperties": false,
            }),
            VfsMethod::Write => json!({
                "type": "object",
                "properties": { "path": path, "text": text, "bytes_b64": bytes_b64 },
                "required": ["path"],
                "additionalProperties": false,
            }),
            VfsMethod::WriteWithLookup => json!({
                "type": "object",
                "properties": {
                    "path": path,
                    "text": text,
                    "bytes_b64": bytes_b64,
                    "projection_path": {
                        "type": "string",
                        "description": "Absolute Bloom VFS path of the projection to stat after the write, for example `/requests/latest`.",
                    },
                },
                "required": ["path", "projection_path"],
                "additionalProperties": false,
            }),
        }
    }

    /// The `tools/list` entry for this tool.
    pub fn descriptor(&self) -> Value {
        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema(),
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.read_only,
                "destructiveHint": !self.read_only,
                "idempotentHint": false,
                "openWorldHint": true,
            },
        })
    }
}

/// Translate a `tools/call` into its canonical VFS command, run it, and shape
/// the reply. `Ok` carries a `tools/call` result — including the `isError: true`
/// form when the daemon rejected the command, which is how MCP reports tool
/// failures without collapsing them into transport errors.
pub async fn call(
    commands: &dyn VfsCommands,
    name: &str,
    arguments: &Value,
) -> Result<Value, ToolError> {
    let tool = find(name).ok_or_else(|| ToolError::UnknownTool(name.to_owned()))?;
    let arguments = match arguments {
        Value::Null => Map::new(),
        Value::Object(map) => map.clone(),
        _ => {
            return Err(ToolError::InvalidArguments(
                "`arguments` must be an object".into(),
            ));
        }
    };
    let params = tool.params(&arguments)?;
    match commands.call(tool.method, params.clone()).await {
        Ok(result) => Ok(tool.success(&arguments, &params, result)),
        Err(error) => Ok(error_result(&error)),
    }
}

impl ToolSpec {
    /// The arguments this tool accepts, matching its advertised schema.
    fn accepted_arguments(&self) -> &'static [&'static str] {
        match self.method {
            VfsMethod::List | VfsMethod::Read | VfsMethod::Lookup => &["path"],
            VfsMethod::Write => &["path", "text", "bytes_b64"],
            VfsMethod::WriteWithLookup => &["path", "text", "bytes_b64", "projection_path"],
        }
    }

    /// Build the daemon params. Accepted keys are forwarded verbatim so the
    /// daemon — not this proxy — decides what is missing or malformed.
    fn params(&self, arguments: &Map<String, Value>) -> Result<Value, ToolError> {
        let accepted = self.accepted_arguments();
        let mut params = Map::new();
        for (key, value) in arguments {
            if !accepted.contains(&key.as_str()) {
                return Err(ToolError::InvalidArguments(format!(
                    "unexpected argument `{key}`"
                )));
            }
            let Value::String(value) = value else {
                return Err(ToolError::InvalidArguments(format!(
                    "`{key}` must be a string"
                )));
            };
            params.insert(key.clone(), Value::String(value.clone()));
        }
        // `vfs_list` mirrors the CLI's `ls` default of the VFS root; the other
        // tools let the daemon report a missing path in its own words.
        if self.method == VfsMethod::List && !params.contains_key("path") {
            params.insert("path".into(), Value::String("/".into()));
        }
        Ok(Value::Object(params))
    }

    fn success(&self, arguments: &Map<String, Value>, params: &Value, result: Value) -> Value {
        let path = params
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        match self.method {
            VfsMethod::List => {
                let entries = result;
                ok_result(
                    vec![json!({
                        "type": "text",
                        "text": pretty(&entries),
                    })],
                    json!({ "path": path, "entries": entries }),
                )
            }
            VfsMethod::Lookup => ok_result(
                vec![json!({"type": "text", "text": pretty(&result)})],
                json!({ "path": path, "entry": result }),
            ),
            VfsMethod::Read => match read_bytes(&result) {
                Ok(bytes) => {
                    let (content, structured) = bytes_payload(&path, &bytes);
                    ok_result(content, structured)
                }
                Err(error) => error_result(&error),
            },
            VfsMethod::Write => {
                let written = payload_len(arguments);
                ok_result(
                    vec![json!({
                        "type": "text",
                        "text": format!("wrote {written} byte(s) to {path}"),
                    })],
                    json!({ "path": path, "bytes_written": written }),
                )
            }
            VfsMethod::WriteWithLookup => {
                let written = payload_len(arguments);
                let projection_path = params
                    .get("projection_path")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                ok_result(
                    vec![json!({"type": "text", "text": pretty(&result)})],
                    json!({
                        "path": path,
                        "bytes_written": written,
                        "projection_path": projection_path,
                        "entry": result,
                    }),
                )
            }
        }
    }
}

/// Decode the daemon's `read` reply. `IpcClient` already reassembles chunked
/// reads into `bytes_b64`, so both the inline and streamed shapes land here.
pub fn read_bytes(result: &Value) -> Result<Vec<u8>, VfsCommandError> {
    let encoded = result
        .get("bytes_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            VfsCommandError::new(
                DAEMON_UNREACHABLE_CODE,
                "Bloom daemon read reply is missing bytes_b64",
            )
        })?;
    B64.decode(encoded).map_err(|error| {
        VfsCommandError::new(
            DAEMON_UNREACHABLE_CODE,
            format!("Bloom daemon read reply is not valid base64: {error}"),
        )
    })
}

/// Render VFS bytes as MCP content. UTF-8 becomes text; everything else stays
/// a base64 blob so binary artifacts survive the round trip intact.
pub fn bytes_payload(path: &str, bytes: &[u8]) -> (Vec<Value>, Value) {
    let uri = resource_uri(path);
    match std::str::from_utf8(bytes) {
        Ok(text) => (
            vec![json!({"type": "text", "text": text})],
            json!({
                "path": path,
                "uri": uri,
                "len": bytes.len(),
                "encoding": "utf-8",
                "mime_type": mime_type_for(path, true),
                "text": text,
            }),
        ),
        Err(_) => (
            vec![json!({
                "type": "resource",
                "resource": {
                    "uri": uri,
                    "mimeType": mime_type_for(path, false),
                    "blob": B64.encode(bytes),
                },
            })],
            json!({
                "path": path,
                "uri": uri,
                "len": bytes.len(),
                "encoding": "base64",
                "mime_type": mime_type_for(path, false),
                "bytes_b64": B64.encode(bytes),
            }),
        ),
    }
}

pub fn mime_type_for(path: &str, utf8: bool) -> &'static str {
    if !utf8 {
        return "application/octet-stream";
    }
    match path.rsplit('.').next() {
        Some("json") => "application/json",
        Some("md") => "text/markdown",
        _ => "text/plain",
    }
}

/// `/status/health` → `bloom:///status/health`.
pub fn resource_uri(path: &str) -> String {
    if path.starts_with('/') {
        format!("{RESOURCE_SCHEME}{path}")
    } else {
        format!("{RESOURCE_SCHEME}/{path}")
    }
}

/// Inverse of [`resource_uri`]. Rejects anything that is not a `bloom://` URI.
pub fn path_from_uri(uri: &str) -> Result<String, String> {
    let path = uri
        .strip_prefix(RESOURCE_SCHEME)
        .ok_or_else(|| format!("unsupported resource URI {uri:?}; expected a bloom:// URI"))?;
    if path.starts_with('/') {
        Ok(path.to_owned())
    } else {
        Ok(format!("/{path}"))
    }
}

fn payload_len(arguments: &Map<String, Value>) -> usize {
    if let Some(encoded) = arguments.get("bytes_b64").and_then(Value::as_str) {
        return B64.decode(encoded).map(|bytes| bytes.len()).unwrap_or(0);
    }
    arguments
        .get("text")
        .and_then(Value::as_str)
        .map(|text| text.len())
        .unwrap_or(0)
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn ok_result(content: Vec<Value>, structured: Value) -> Value {
    json!({
        "content": content,
        "structuredContent": structured,
        "isError": false,
    })
}

/// A daemon-rejected command. MCP wants tool failures inside the result, and
/// the daemon's code/message are preserved so clients can branch on them.
pub fn error_result(error: &VfsCommandError) -> Value {
    json!({
        "content": [{"type": "text", "text": error.message.clone()}],
        "structuredContent": {
            "error": { "code": error.code, "message": error.message.clone() },
        },
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_canonical_vfs_command_has_exactly_one_tool() {
        let mut methods: Vec<&str> = TOOLS.iter().map(|tool| tool.method.as_str()).collect();
        methods.sort_unstable();
        assert_eq!(
            methods,
            ["list", "lookup", "read", "write", "write_with_lookup"]
        );
    }

    #[test]
    fn list_defaults_to_the_vfs_root_like_the_cli() {
        let spec = find("vfs_list").unwrap();
        let params = spec.params(&Map::new()).unwrap();
        assert_eq!(params, json!({"path": "/"}));
    }

    #[test]
    fn write_arguments_are_forwarded_verbatim() {
        let spec = find("vfs_write").unwrap();
        let arguments = json!({"path": "/x", "bytes_b64": "AAE="});
        let params = spec
            .params(arguments.as_object().unwrap())
            .expect("params build");
        assert_eq!(params, json!({"path": "/x", "bytes_b64": "AAE="}));
    }

    #[test]
    fn unexpected_arguments_are_rejected_before_the_daemon_is_called() {
        let spec = find("vfs_read").unwrap();
        let arguments = json!({"path": "/x", "block": 42});
        let error = spec.params(arguments.as_object().unwrap()).unwrap_err();
        assert_eq!(
            error,
            ToolError::InvalidArguments("unexpected argument `block`".into())
        );

        // A write-only argument is not silently forwarded on a read tool.
        let arguments = json!({"path": "/x", "text": "hi"});
        assert_eq!(
            spec.params(arguments.as_object().unwrap()).unwrap_err(),
            ToolError::InvalidArguments("unexpected argument `text`".into())
        );
    }

    #[test]
    fn non_string_path_is_rejected() {
        let spec = find("vfs_read").unwrap();
        let arguments = json!({"path": 7});
        let error = spec.params(arguments.as_object().unwrap()).unwrap_err();
        assert_eq!(
            error,
            ToolError::InvalidArguments("`path` must be a string".into())
        );
    }

    #[test]
    fn resource_uris_round_trip() {
        assert_eq!(resource_uri("/status/health"), "bloom:///status/health");
        assert_eq!(resource_uri("status/health"), "bloom:///status/health");
        assert_eq!(
            path_from_uri("bloom:///status/health").unwrap(),
            "/status/health"
        );
        assert!(path_from_uri("file:///etc/passwd").is_err());
    }

    #[test]
    fn non_utf8_bytes_are_returned_as_a_base64_blob() {
        let (content, structured) = bytes_payload("/blob.bin", &[0xff, 0x00, 0xfe]);
        assert_eq!(content[0]["type"], "resource");
        assert_eq!(
            content[0]["resource"]["blob"],
            B64.encode([0xff, 0x00, 0xfe])
        );
        assert_eq!(structured["encoding"], "base64");
        assert_eq!(structured["len"], 3);
    }

    #[test]
    fn utf8_bytes_are_returned_as_text() {
        let (content, structured) = bytes_payload("/notes.md", "hello".as_bytes());
        assert_eq!(content[0], json!({"type": "text", "text": "hello"}));
        assert_eq!(structured["encoding"], "utf-8");
        assert_eq!(structured["mime_type"], "text/markdown");
    }
}
