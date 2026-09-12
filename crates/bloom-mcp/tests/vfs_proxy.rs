//! Category: integration
//!
//! End-to-end proof that the MCP server is a proxy: every tool and resource in
//! these tests travels MCP → daemon JSON-RPC → `bloom_vfs::Vfs` → handler, over
//! a real Unix socket. Nothing here stubs the command surface, so a behaviour
//! or error-code change in the VFS shows up as a failure right here.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_daemon::ipc::IpcServer;
use bloom_mcp::{IpcVfsCommands, McpServer};
use bloom_vfs::{Entry, Handler, HandlerError, Vfs, VfsPath};
use serde_json::{Value, json};

const GREET: &[u8] = b"hi\n";
const BLOB: &[u8] = &[0xff, 0x00, 0xfe, 0x80];
/// Every character a VFS segment may hold that an RFC 3986 parser treats
/// specially. `\` and NUL are the only bytes `VfsPath::parse` rejects.
const RESERVED_NAME: &str = "odd name#1?q=100%.md";
/// Larger than the daemon's 1 MiB read chunk, so the reply arrives as streamed
/// `bloom.output` data rather than a single inline frame.
const BIG_LEN: usize = 2 * 1024 * 1024 + 7;

/// A handler with one of each thing the VFS can hold: a UTF-8 file, a binary
/// file, an oversized file, a file whose name is full of URI metacharacters, a
/// writable sink, the projection that sink produces, and — modelling the
/// wallet outbox control files — a file whose *read* performs an action.
#[derive(Default)]
struct ProbeHandler {
    latest: Mutex<Option<Vec<u8>>>,
    /// Incremented by reading `confirm`, so a test can prove nothing read it.
    confirmed: std::sync::atomic::AtomicUsize,
}

impl ProbeHandler {
    fn big() -> Vec<u8> {
        (0..BIG_LEN).map(|index| (index % 251) as u8).collect()
    }
}

#[async_trait]
impl Handler for ProbeHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let latest = self.latest.lock().unwrap().clone();
        match path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()[..]
        {
            [] => Ok(Entry::dir("probe")),
            ["greet"] => Ok(Entry::read_only_file("greet").with_size(GREET.len() as u64)),
            ["blob.bin"] => Ok(Entry::read_only_file("blob.bin").with_size(BLOB.len() as u64)),
            ["big.bin"] => Ok(Entry::read_only_file("big.bin").with_size(BIG_LEN as u64)),
            ["new"] => Ok(Entry::writable_file("new")),
            ["confirm"] => Ok(Entry::read_only_file("confirm")),
            [name] if name == RESERVED_NAME => {
                Ok(Entry::read_only_file(RESERVED_NAME).with_size(GREET.len() as u64))
            }
            ["latest"] => match latest {
                Some(bytes) => Ok(Entry::read_only_file("latest").with_size(bytes.len() as u64)),
                None => Err(HandlerError::not_found(path.to_string_path())),
            },
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let latest = self.latest.lock().unwrap().clone();
        match path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()[..]
        {
            [] => Err(HandlerError::NotAFile(path.to_string_path())),
            ["greet"] => Ok(GREET.to_vec()),
            ["blob.bin"] => Ok(BLOB.to_vec()),
            ["big.bin"] => Ok(Self::big()),
            ["confirm"] => {
                self.confirmed
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(b"broadcast\n".to_vec())
            }
            [name] if name == RESERVED_NAME => Ok(GREET.to_vec()),
            ["latest"] => latest.ok_or_else(|| HandlerError::not_found(path.to_string_path())),
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    /// The whole point of the flag: reading `confirm` *is* the broadcast.
    fn is_read_side_effecting(&self, path: &VfsPath) -> bool {
        path.segments().last().map(String::as_str) == Some("confirm")
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        match path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()[..]
        {
            ["new"] => {
                *self.latest.lock().unwrap() = Some(data.to_vec());
                Ok(())
            }
            // Read-only entries fail exactly the way the real tree does.
            ["greet"] | ["blob.bin"] | ["big.bin"] | ["latest"] => {
                Err(HandlerError::PermissionDenied)
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        match path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()[..]
        {
            [] => Ok(vec![
                Entry::read_only_file("blob.bin"),
                Entry::read_only_file("greet"),
                Entry::writable_file("new"),
            ]),
            ["greet"] => Err(HandlerError::NotADir(path.to_string_path())),
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }
}

/// A live daemon endpoint plus an MCP server pointed at it.
struct Harness {
    server: McpServer,
    ipc: IpcServer,
    probe: Arc<ProbeHandler>,
    handle: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("private-run/bloom.sock");
        let probe = Arc::new(ProbeHandler::default());
        let vfs = Vfs::builder().mount("probe", probe.clone()).build();
        let ipc = IpcServer::new(vfs, "0.0.0-test", vec!["ethereum".into()]);
        let serving = ipc.clone();
        let serving_socket = socket.clone();
        let handle =
            tokio::spawn(async move { serving.serve(&serving_socket).await.expect("ipc serve") });
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(socket.exists(), "daemon socket never appeared");
        Self {
            server: McpServer::new(Arc::new(IpcVfsCommands::new(socket)), "0.0.0-test"),
            ipc,
            probe,
            handle,
            _dir: dir,
        }
    }

    fn confirms(&self) -> usize {
        self.probe
            .confirmed
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn request(&self, method: &str, params: Value) -> Value {
        self.server
            .handle(json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .await
            .expect("request gets a response")
    }

    /// Call a tool and return the `tools/call` result, asserting the call was
    /// not rejected at the protocol level.
    async fn tool(&self, name: &str, arguments: Value) -> Value {
        let response = self
            .request("tools/call", json!({"name": name, "arguments": arguments}))
            .await;
        assert!(
            response.get("error").is_none(),
            "unexpected protocol error: {response}"
        );
        response["result"].clone()
    }

    async fn ok_tool(&self, name: &str, arguments: Value) -> Value {
        let result = self.tool(name, arguments).await;
        assert_eq!(result["isError"], false, "tool failed: {result}");
        result
    }

    async fn tool_error(&self, name: &str, arguments: Value) -> (i64, String) {
        let result = self.tool(name, arguments).await;
        assert_eq!(result["isError"], true, "expected failure: {result}");
        (
            result["structuredContent"]["error"]["code"]
                .as_i64()
                .expect("error code"),
            result["structuredContent"]["error"]["message"]
                .as_str()
                .expect("error message")
                .to_owned(),
        )
    }

    async fn stop(self) {
        self.ipc.trigger_shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.handle).await;
    }
}

#[tokio::test]
async fn initialize_then_discover_and_read_through_the_canonical_surface() {
    let harness = Harness::start().await;

    let initialize = harness
        .request(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "clientInfo": {"name": "test", "version": "1"}}),
        )
        .await;
    assert_eq!(initialize["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        initialize["result"]["capabilities"]["tools"].is_object(),
        true
    );

    // Root discovery goes through the router, so the router's own entries
    // (agent guidance files) and the mounted subtree both show up.
    let root = harness.ok_tool("vfs_list", json!({})).await;
    let names: Vec<&str> = root["structuredContent"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"probe"), "{names:?}");
    assert!(names.contains(&"AGENTS.md"), "{names:?}");

    let listed = harness.ok_tool("vfs_list", json!({"path": "/probe"})).await;
    let entries = listed["structuredContent"]["entries"].as_array().unwrap();
    let names: Vec<&str> = entries
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["blob.bin", "greet", "new"]);
    // Entry metadata is the daemon's projection, not a proxy invention.
    let new_entry = entries.iter().find(|e| e["name"] == "new").unwrap();
    assert_eq!(new_entry["kind"], "file");
    assert_eq!(new_entry["mode"], 0o644);

    let read = harness
        .ok_tool("vfs_read", json!({"path": "/probe/greet"}))
        .await;
    assert_eq!(read["content"][0]["type"], "text");
    assert_eq!(read["content"][0]["text"], "hi\n");
    assert_eq!(read["structuredContent"]["encoding"], "utf-8");
    assert_eq!(read["structuredContent"]["len"], GREET.len());

    let stat = harness
        .ok_tool("vfs_stat", json!({"path": "/probe/greet"}))
        .await;
    let entry = &stat["structuredContent"]["entry"];
    assert_eq!(entry["name"], "greet");
    assert_eq!(entry["kind"], "file");
    assert_eq!(entry["mode"], 0o444);
    assert_eq!(entry["size"], GREET.len());

    harness.stop().await;
}

#[tokio::test]
async fn non_utf8_reads_stay_bytes_through_the_proxy() {
    let harness = Harness::start().await;

    let read = harness
        .ok_tool("vfs_read", json!({"path": "/probe/blob.bin"}))
        .await;
    assert_eq!(read["content"][0]["type"], "resource");
    assert_eq!(
        read["content"][0]["resource"]["mimeType"],
        "application/octet-stream"
    );
    assert_eq!(read["structuredContent"]["encoding"], "base64");
    let decoded = B64
        .decode(read["structuredContent"]["bytes_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, BLOB, "binary content must survive byte-for-byte");

    // Reads above the daemon's chunk threshold arrive streamed; the proxy must
    // reassemble them without truncation.
    let big = harness
        .ok_tool("vfs_read", json!({"path": "/probe/big.bin"}))
        .await;
    let decoded = B64
        .decode(big["structuredContent"]["bytes_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded.len(), BIG_LEN);
    assert_eq!(decoded, ProbeHandler::big());

    harness.stop().await;
}

#[tokio::test]
async fn writes_accept_text_and_arbitrary_bytes() {
    let harness = Harness::start().await;

    let written = harness
        .ok_tool(
            "vfs_write",
            json!({"path": "/probe/new", "text": "confirm"}),
        )
        .await;
    assert_eq!(written["structuredContent"]["bytes_written"], 7);
    let echoed = harness
        .ok_tool("vfs_read", json!({"path": "/probe/latest"}))
        .await;
    assert_eq!(echoed["structuredContent"]["text"], "confirm");

    // A non-UTF-8 payload must reach the handler unchanged.
    let payload: Vec<u8> = vec![0x00, 0xff, 0x10, 0x80, 0xfe];
    let written = harness
        .ok_tool(
            "vfs_write",
            json!({"path": "/probe/new", "bytes_b64": B64.encode(&payload)}),
        )
        .await;
    assert_eq!(written["structuredContent"]["bytes_written"], payload.len());
    let echoed = harness
        .ok_tool("vfs_read", json!({"path": "/probe/latest"}))
        .await;
    let decoded = B64
        .decode(echoed["structuredContent"]["bytes_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, payload);

    harness.stop().await;
}

#[tokio::test]
async fn write_then_stat_returns_the_projection_the_write_produced() {
    let harness = Harness::start().await;

    let result = harness
        .ok_tool(
            "vfs_write_then_stat",
            json!({
                "path": "/probe/new",
                "text": "staged intent",
                "projection_path": "/probe/latest",
            }),
        )
        .await;
    let entry = &result["structuredContent"]["entry"];
    assert_eq!(entry["name"], "latest");
    assert_eq!(entry["size"], "staged intent".len());
    assert_eq!(
        result["structuredContent"]["projection_path"],
        "/probe/latest"
    );

    // A missing projection_path is the daemon's error to report, not ours.
    let (code, message) = harness
        .tool_error("vfs_write", json!({"path": "/probe/new"}))
        .await;
    assert_eq!(code, -32602);
    assert!(message.contains("bytes_b64 or text"), "{message}");

    harness.stop().await;
}

#[tokio::test]
async fn vfs_errors_reach_the_client_with_the_daemons_own_codes() {
    let harness = Harness::start().await;

    let (code, message) = harness
        .tool_error("vfs_read", json!({"path": "/probe/missing"}))
        .await;
    assert_eq!(code, -32004, "{message}");
    assert!(message.starts_with("not found"), "{message}");

    let (code, _) = harness
        .tool_error("vfs_read", json!({"path": "/probe"}))
        .await;
    assert_eq!(code, -32006, "reading a directory is `not a file`");

    let (code, _) = harness
        .tool_error("vfs_list", json!({"path": "/probe/greet"}))
        .await;
    assert_eq!(code, -32005, "listing a file is `not a dir`");

    let (code, message) = harness
        .tool_error("vfs_write", json!({"path": "/probe/greet", "text": "nope"}))
        .await;
    assert_eq!(code, -32007, "{message}");
    assert_eq!(message, "permission denied");

    let (code, message) = harness
        .tool_error("vfs_stat", json!({"path": "/absent-subtree/x"}))
        .await;
    assert_eq!(code, -32004, "{message}");

    harness.stop().await;
}

#[tokio::test]
async fn resources_expose_the_same_paths_as_the_read_command() {
    let harness = Harness::start().await;

    let listed = harness.request("resources/list", json!({})).await;
    let resources = listed["result"]["resources"].as_array().unwrap();
    let uris: Vec<&str> = resources
        .iter()
        .map(|resource| resource["uri"].as_str().unwrap())
        .collect();
    assert!(uris.contains(&"bloom:///AGENTS.md"), "{uris:?}");
    // Directories are not resources; `vfs_list` walks the tree instead.
    assert!(!uris.iter().any(|uri| *uri == "bloom:///probe"), "{uris:?}");

    let templates = harness.request("resources/templates/list", json!({})).await;
    assert_eq!(
        templates["result"]["resourceTemplates"][0]["uriTemplate"],
        "bloom:///{+path}"
    );

    let read = harness
        .request("resources/read", json!({"uri": "bloom:///probe/greet"}))
        .await;
    assert_eq!(read["result"]["contents"][0]["uri"], "bloom:///probe/greet");
    assert_eq!(read["result"]["contents"][0]["text"], "hi\n");

    let read = harness
        .request("resources/read", json!({"uri": "bloom:///probe/blob.bin"}))
        .await;
    let content = &read["result"]["contents"][0];
    assert_eq!(content["mimeType"], "application/octet-stream");
    assert_eq!(
        B64.decode(content["blob"].as_str().unwrap()).unwrap(),
        BLOB,
        "binary resources stay bytes"
    );

    // A missing path is MCP's own resource-not-found; the daemon's code is
    // kept as diagnostic data rather than shipped as the protocol code.
    let missing = harness
        .request("resources/read", json!({"uri": "bloom:///probe/missing"}))
        .await;
    assert_eq!(missing["error"]["code"], -32002);
    assert_eq!(missing["error"]["data"]["daemonCode"], -32004);
    assert_eq!(missing["error"]["data"]["uri"], "bloom:///probe/missing");

    harness.stop().await;
}

/// A resource URI is an RFC 3986 URI: a client that percent-encodes reserved
/// characters (as it must) has to land on the same VFS path the server
/// advertised.
#[tokio::test]
async fn resource_uris_round_trip_paths_containing_reserved_characters() {
    let harness = Harness::start().await;
    let path = format!("/probe/{RESERVED_NAME}");

    // The URI the server itself hands out for this path, via a tool read.
    let read = harness.ok_tool("vfs_read", json!({"path": path})).await;
    let uri = read["structuredContent"]["uri"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        uri, "bloom:///probe/odd%20name%231%3Fq=100%25.md",
        "reserved characters must be percent-encoded"
    );

    // Feeding it straight back reaches the same file rather than a truncated
    // or nonexistent one.
    let resource = harness.request("resources/read", json!({"uri": uri})).await;
    assert!(resource.get("error").is_none(), "{resource}");
    assert_eq!(resource["result"]["contents"][0]["text"], "hi\n");
    assert_eq!(resource["result"]["contents"][0]["uri"], uri);

    // The unencoded form is a different URI — everything from `#` on is a
    // fragment — and must be refused rather than silently read as `/probe/odd
    // name`.
    let raw = harness
        .request(
            "resources/read",
            json!({"uri": format!("bloom:///probe/{RESERVED_NAME}")}),
        )
        .await;
    assert_eq!(raw["error"]["code"], -32602, "{raw}");

    harness.stop().await;
}

/// Clients fetch resources without asking a human. The few VFS paths whose
/// read signs or broadcasts must therefore be unreachable that way — and must
/// still be reachable through the tool, which a client can gate.
#[tokio::test]
async fn a_side_effecting_read_is_not_an_inert_resource_but_is_still_a_tool() {
    let harness = Harness::start().await;
    let uri = "bloom:///probe/confirm";

    // `vfs_stat` is how a client finds out, and stat'ing must not trigger it.
    let stat = harness
        .ok_tool("vfs_stat", json!({"path": "/probe/confirm"}))
        .await;
    assert_eq!(
        stat["structuredContent"]["entry"]["read_side_effecting"],
        true
    );
    assert_eq!(harness.confirms(), 0, "stat must not broadcast");

    let refused = harness.request("resources/read", json!({"uri": uri})).await;
    assert_eq!(refused["error"]["code"], -32010, "{refused}");
    assert_eq!(refused["error"]["data"]["tool"], "vfs_read");
    assert_eq!(
        harness.confirms(),
        0,
        "resources/read must not have performed the action"
    );

    // The inert sibling is unaffected: this is a per-path gate, not a subtree
    // ban, and it is the daemon's judgement rather than a list kept here.
    let inert = harness
        .request("resources/read", json!({"uri": "bloom:///probe/greet"}))
        .await;
    assert_eq!(inert["result"]["contents"][0]["text"], "hi\n");

    // No VFS functionality is lost: the tool still performs the read.
    let performed = harness
        .ok_tool("vfs_read", json!({"path": "/probe/confirm"}))
        .await;
    assert_eq!(performed["content"][0]["text"], "broadcast\n");
    assert_eq!(harness.confirms(), 1, "the tool must still do the work");

    harness.stop().await;
}

/// The argument allowlist is the reason a new daemon parameter cannot leak
/// through this proxy; it is only safe while every argument it *does* allow
/// still means something to the daemon.
#[tokio::test]
async fn every_advertised_argument_reaches_the_daemon() {
    let harness = Harness::start().await;

    let listed = harness.request("tools/list", json!({})).await;
    for tool in listed["result"]["tools"].as_array().unwrap() {
        let name = tool["name"].as_str().unwrap();
        // A path each tool can legitimately act on, so a failure means the
        // argument did not reach the daemon rather than that the path was
        // wrong for the command.
        let path = match name {
            "vfs_list" => "/probe",
            "vfs_read" | "vfs_stat" => "/probe/greet",
            _ => "/probe/new",
        };
        let arguments: Value = tool["inputSchema"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(|key| {
                let value = match key.as_str() {
                    "path" => path,
                    "projection_path" => "/probe/latest",
                    "bytes_b64" => "aGk=",
                    "text" => "hi",
                    other => panic!("{name} advertises an unhandled argument `{other}`"),
                };
                (key.clone(), Value::String(value.into()))
            })
            .collect::<serde_json::Map<_, _>>()
            .into();

        // Every advertised argument is forwarded (no `unexpected argument`
        // rejection) and the daemon accepts the whole set.
        let result = harness.tool(name, arguments.clone()).await;
        assert_eq!(result["isError"], false, "{name}: {result} for {arguments}");
    }

    harness.stop().await;
}

#[tokio::test]
async fn the_proxy_cannot_reach_non_vfs_daemon_methods() {
    let harness = Harness::start().await;

    // The daemon does expose `version`, `chains`, `shutdown`, `petals.*`, and
    // `machine.execute` — none of them are tools here, and there is no generic
    // pass-through, so an MCP client cannot name them.
    let tools = harness.request("tools/list", json!({})).await;
    let names: Vec<&str> = tools["result"]["tools"]
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

    for forbidden in ["shutdown", "machine.execute", "petals.install", "version"] {
        let response = harness
            .request("tools/call", json!({"name": forbidden, "arguments": {}}))
            .await;
        assert_eq!(response["error"]["code"], -32602, "{response}");
    }

    // The daemon is still alive: the shutdown attempt above went nowhere.
    harness
        .ok_tool("vfs_read", json!({"path": "/probe/greet"}))
        .await;

    harness.stop().await;
}

#[tokio::test]
async fn a_stdio_session_answers_framed_requests_in_order() {
    let harness = Harness::start().await;

    let input = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "vfs_read", "arguments": {"path": "/probe/greet"}}}),
    ]
    .iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";

    let mut output = Vec::new();
    harness
        .server
        .serve(tokio::io::BufReader::new(input.as_bytes()), &mut output)
        .await
        .expect("stdio session");

    let responses: Vec<Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(responses.len(), 2, "the notification is not answered");
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[1]["id"], 2);
    assert_eq!(responses[1]["result"]["content"][0]["text"], "hi\n");

    harness.stop().await;
}
