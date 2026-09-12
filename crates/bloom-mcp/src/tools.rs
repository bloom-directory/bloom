//! The MCP tool catalog: one tool per canonical VFS command.
//!
//! Each tool is a thin adapter — it copies the caller's arguments into the
//! daemon's JSON-RPC params and shapes the reply into MCP content. Argument
//! validation beyond "is this JSON the right shape" is deliberately left to the
//! daemon so MCP callers see exactly the errors `bloom vfs …` sees.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use serde_json::{Map, Value, json};

use crate::backend::{DAEMON_UNREACHABLE_CODE, VfsCommandError, VfsCommands, VfsMethod};

/// URI scheme for VFS paths exposed as MCP resources: `bloom:///status/health`.
pub const RESOURCE_SCHEME: &str = "bloom://";

/// Characters a VFS path segment may legitimately contain that would change
/// how an RFC 3986 parser reads the URI: the generic delimiters that end a
/// path (`?`, `#`), the segment separator itself, the escape character, and
/// everything a URL parser is entitled to normalise or reject. Encoding this
/// set — and nothing else — keeps `bloom:///docs/README.md` readable while
/// making `a/b`, `a#b`, `a?b`, `100%`, and `two words` round-trip exactly.
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b'[')
    .add(b']')
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// A tool the MCP server advertises, bound to the VFS command it proxies.
#[derive(Clone, Copy, Debug)]
pub struct ToolSpec {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub method: VfsMethod,
    /// `readOnlyHint`: true only when *every* path the tool can reach is inert.
    /// `list` and `lookup` qualify; `read` does not, because a handful of VFS
    /// paths (outbox `confirm`/`replace`/`cancel`) sign or broadcast when read.
    /// The daemon audits those regardless of which client asks, but a client
    /// that trusts `readOnlyHint` would skip its confirmation prompt.
    pub read_only: bool,
    /// `destructiveHint`, only meaningful when [`Self::read_only`] is false.
    /// Writes are staged and confirmable, but they are the surface that moves
    /// value, so they claim the conservative hint; a side-effecting read
    /// produces artifacts rather than overwriting them.
    pub destructive: bool,
}

/// Every VFS capability reachable from the public CLI/IPC surface.
pub const TOOLS: [ToolSpec; 5] = [
    ToolSpec {
        name: "vfs_list",
        title: "List a Bloom VFS directory",
        description: "List the children of a Bloom VFS directory. Equivalent to `bloom vfs ls <path>`; returns one entry per child with its name, kind (dir/file/symlink), size, POSIX mode, symlink target, and modification time. Start at `/` to discover the available subtrees.",
        method: VfsMethod::List,
        read_only: true,
        destructive: false,
    },
    ToolSpec {
        name: "vfs_read",
        title: "Read a Bloom VFS file",
        description: "Read the bytes of a Bloom VFS file. Equivalent to `bloom vfs cat <path>`. UTF-8 content is returned as text; anything else is returned as a base64 blob. Most paths are inert data, but a few are side-effecting by design: reading a wallet outbox `confirm`, `confirm.override`, `replace`, or `cancel` file performs that action. Call `vfs_stat` first — it reports `read_side_effecting` — and treat a true there as an action needing confirmation, not a fetch.",
        method: VfsMethod::Read,
        read_only: false,
        destructive: false,
    },
    ToolSpec {
        name: "vfs_stat",
        title: "Stat a Bloom VFS path",
        description: "Return Bloom VFS metadata for a path without reading it. Equivalent to `bloom vfs stat <path>`: name, kind, size, POSIX mode, symlink target, modification time, and `read_side_effecting` — whether reading the path would sign or broadcast. Always inert; safe to call before any read.",
        method: VfsMethod::Lookup,
        read_only: true,
        destructive: false,
    },
    ToolSpec {
        name: "vfs_write",
        title: "Write a Bloom VFS file",
        description: "Write bytes to a writable Bloom VFS path. Equivalent to `bloom vfs write <path>`. Supply either `text` (UTF-8) or `bytes_b64` (arbitrary bytes). Writes are audited and only a small set of injection points accept them; everything else fails with `permission denied`.",
        method: VfsMethod::Write,
        read_only: false,
        destructive: true,
    },
    ToolSpec {
        name: "vfs_write_then_stat",
        title: "Write a Bloom VFS file and stat its projection",
        description: "Write bytes to a writable Bloom VFS path and, under the daemon's mutation gate, stat the identity projection the write produced (for example writing `/requests/new` and reading back `/requests/latest`). Use this instead of a write followed by a separate stat when the projection identity matters.",
        method: VfsMethod::WriteWithLookup,
        read_only: false,
        destructive: true,
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
                "destructiveHint": self.destructive,
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

/// `/status/health` → `bloom:///status/health`, percent-encoding each segment
/// so a path containing `%`, a space, `#`, or `?` survives an RFC 3986 parser.
/// The authority is always empty, which is what the leading `///` means.
pub fn resource_uri(path: &str) -> String {
    let mut uri = format!("{RESOURCE_SCHEME}/");
    for (index, segment) in path.trim_start_matches('/').split('/').enumerate() {
        if index > 0 {
            uri.push('/');
        }
        uri.extend(utf8_percent_encode(segment, PATH_SEGMENT));
    }
    uri
}

/// Inverse of [`resource_uri`]. Rejects anything that is not a `bloom://` URI
/// with an empty authority, and refuses percent-escapes that would decode into
/// a different path than the one the URI names.
pub fn path_from_uri(uri: &str) -> Result<String, String> {
    let rest = uri
        .strip_prefix(RESOURCE_SCHEME)
        .ok_or_else(|| format!("unsupported resource URI {uri:?}; expected a bloom:// URI"))?;
    // `bloom://host/path` names a different authority, not a VFS path.
    let encoded = rest
        .strip_prefix('/')
        .ok_or_else(|| format!("unsupported resource URI {uri:?}; expected bloom:///<path>"))?;
    if let Some(index) = encoded.find(['?', '#']) {
        return Err(format!(
            "unsupported resource URI {uri:?}: a Bloom VFS path has no {:?} component (percent-encode the character to use it in a path)",
            &encoded[index..index + 1]
        ));
    }
    let mut path = String::new();
    for segment in encoded.split('/') {
        let decoded = percent_decode_str(segment)
            .decode_utf8()
            .map_err(|error| format!("resource URI {uri:?} is not valid UTF-8: {error}"))?;
        // A `%2F` must not smuggle an extra separator past the split above,
        // and a NUL cannot appear in a VFS path at all.
        if decoded.contains('/') || decoded.contains('\0') {
            return Err(format!(
                "unsupported resource URI {uri:?}: a percent-escape decodes to a path separator"
            ));
        }
        path.push('/');
        path.push_str(&decoded);
    }
    Ok(path)
}

/// Whether the daemon's `lookup` reply says reading this path signs,
/// broadcasts, or otherwise mutates state. A reply from a daemon predating
/// the field reads as `false`, matching the VFS default for unknown paths.
pub fn read_is_side_effecting(entry: &Value) -> bool {
    entry
        .get("read_side_effecting")
        .and_then(Value::as_bool)
        .unwrap_or(false)
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

    /// The allowlist is what makes a new daemon parameter invisible to MCP
    /// clients, so it must at least never disagree with the schema clients are
    /// told to fill in.
    #[test]
    fn advertised_schema_matches_the_forwarded_argument_allowlist() {
        for tool in &TOOLS {
            let schema = tool.input_schema();
            let mut advertised: Vec<&str> = schema["properties"]
                .as_object()
                .expect("object schema")
                .keys()
                .map(String::as_str)
                .collect();
            advertised.sort_unstable();
            let mut accepted = tool.accepted_arguments().to_vec();
            accepted.sort_unstable();
            assert_eq!(advertised, accepted, "{}", tool.name);
            assert_eq!(
                schema["additionalProperties"], false,
                "{} must not invite arguments it will reject",
                tool.name
            );
        }
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
        // An authority is not a path prefix.
        assert!(path_from_uri("bloom://host/status/health").is_err());
    }

    /// A VFS segment may hold any byte but `/` and NUL. Every such segment has
    /// to survive the trip to an RFC 3986 URI and back, or a compliant client
    /// silently reads a different path.
    #[test]
    fn reserved_characters_survive_the_uri_round_trip() {
        for path in [
            "/requests/two words/plan.md",
            "/requests/100%/plan.md",
            "/requests/a#b",
            "/requests/a?b=c",
            "/requests/a%2Fb",
            "/docs/caf\u{e9}.md",
            "/requests/a+b",
            "/",
        ] {
            let uri = resource_uri(path);
            assert!(!uri[RESOURCE_SCHEME.len()..].contains(['?', '#']), "{uri}");
            assert_eq!(path_from_uri(&uri).unwrap(), path, "via {uri}");
        }

        // Readable paths stay readable: nothing is over-encoded.
        assert_eq!(resource_uri("/docs/README.md"), "bloom:///docs/README.md");
        assert_eq!(resource_uri("/requests/100%"), "bloom:///requests/100%25");
        assert_eq!(resource_uri("/a b"), "bloom:///a%20b");
    }

    #[test]
    fn uris_that_would_name_a_different_path_are_refused() {
        // A raw `#`/`?` is a fragment/query to an RFC 3986 parser, so it can
        // never have come from a VFS segment.
        assert!(path_from_uri("bloom:///requests/a#b").is_err());
        assert!(path_from_uri("bloom:///requests/a?b").is_err());
        // `%252F` decodes to `%2F`, a literal segment, not a separator.
        assert_eq!(
            path_from_uri("bloom:///requests/a%252Fb").unwrap(),
            "/requests/a%2Fb"
        );
    }

    /// `readOnlyHint` is what a client gates its confirmation prompt on, so it
    /// has to match the VFS mutation boundary exactly.
    #[test]
    fn advertised_annotations_match_the_vfs_mutation_boundary() {
        let hints = |name: &str| {
            let annotations = find(name).unwrap().descriptor()["annotations"].clone();
            (
                annotations["readOnlyHint"].as_bool().unwrap(),
                annotations["destructiveHint"].as_bool().unwrap(),
            )
        };
        // `lookup` and `list` touch nothing.
        assert_eq!(hints("vfs_stat"), (true, false));
        assert_eq!(hints("vfs_list"), (true, false));
        // A read can sign or broadcast on outbox control paths, so it cannot
        // claim to leave the environment alone.
        assert_eq!(hints("vfs_read"), (false, false));
        assert_eq!(hints("vfs_write"), (false, true));
        assert_eq!(hints("vfs_write_then_stat"), (false, true));
    }

    #[test]
    fn a_lookup_reply_without_the_flag_reads_as_inert() {
        assert!(read_is_side_effecting(
            &json!({"name": "confirm", "read_side_effecting": true})
        ));
        assert!(!read_is_side_effecting(
            &json!({"name": "confirm", "read_side_effecting": false})
        ));
        assert!(!read_is_side_effecting(&json!({"name": "greet"})));
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
