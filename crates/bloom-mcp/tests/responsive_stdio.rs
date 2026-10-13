//! Category: integration
//! Exercise the real stdio scheduler with a deliberately blocked backend.
use async_trait::async_trait;
use bloom_mcp::{McpServer, VfsCommandError, VfsCommands, VfsMethod};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{Notify, Semaphore};
use tokio::time::{Duration, timeout};

struct Backend {
    calls: Mutex<Vec<String>>,
    started: Notify,
    release: Semaphore,
}
#[async_trait]
impl VfsCommands for Backend {
    async fn call(&self, _: VfsMethod, params: Value) -> Result<Value, VfsCommandError> {
        let path = params["path"].as_str().unwrap().to_owned();
        self.calls.lock().unwrap().push(path.clone());
        if path == "/slow" {
            self.started.notify_one();
            self.release.acquire().await.unwrap().forget();
        }
        Ok(json!({"bytes_b64":"aGk="}))
    }
    fn endpoint(&self) -> String {
        "test".into()
    }
}
struct Session {
    backend: Arc<Backend>,
    input: WriteHalf<DuplexStream>,
    output: BufReader<ReadHalf<DuplexStream>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Session {
    fn new() -> Self {
        let backend = Arc::new(Backend {
            calls: Mutex::new(vec![]),
            started: Notify::new(),
            release: Semaphore::new(0),
        });
        let server = McpServer::new(backend.clone(), "test");
        let (client, transport) = tokio::io::duplex(65536);
        let (read, write) = tokio::io::split(transport);
        let task = tokio::spawn(async move { server.serve(BufReader::new(read), write).await });
        let (read, input) = tokio::io::split(client);
        Self {
            backend,
            input,
            output: BufReader::new(read),
            task,
        }
    }
    async fn send(&mut self, value: Value) {
        self.input
            .write_all(format!("{value}\n").as_bytes())
            .await
            .unwrap();
    }
    async fn recv(&mut self) -> Value {
        let mut line = String::new();
        timeout(Duration::from_secs(3), self.output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }
    async fn block(&mut self) {
        self.send(call(1, "/slow")).await;
        timeout(Duration::from_secs(3), self.backend.started.notified())
            .await
            .unwrap();
    }
    async fn ping(&mut self) {
        self.send(json!({"jsonrpc":"2.0","id":"ping","method":"ping"}))
            .await;
        assert_eq!(
            self.recv().await,
            json!({"jsonrpc":"2.0","id":"ping","result":{}})
        );
    }
    async fn close(mut self) {
        self.input.shutdown().await.unwrap();
        timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
fn call(id: u64, path: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"vfs_write","arguments":{"path":path,"text":"test"}}})
}
fn cancel(id: u64) -> Value {
    json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id}})
}

#[tokio::test]
async fn ping_and_cancellation_bypass_slow_work_without_reordering_writes() {
    let mut s = Session::new();
    s.block().await;
    s.send(call(2, "/cancelled")).await;
    s.send(call(3, "/third")).await;
    s.send(call(4, "/fourth")).await;
    s.send(cancel(2)).await;
    s.send(cancel(999)).await; // Unknown cancellations are silent.
    s.send(json!({"jsonrpc":"2.0","id":5,"method":"tools/list"}))
        .await;
    assert_eq!(
        s.recv().await["result"]["tools"].as_array().unwrap().len(),
        5
    );
    s.ping().await;
    assert_eq!(*s.backend.calls.lock().unwrap(), ["/slow"]);
    s.backend.release.add_permits(1);
    for id in [1, 3, 4] {
        assert_eq!(s.recv().await["id"], id);
    }
    assert_eq!(
        *s.backend.calls.lock().unwrap(),
        ["/slow", "/third", "/fourth"]
    );
    s.close().await;
}

#[tokio::test]
async fn cancelling_active_work_retains_its_slot_and_suppresses_its_reply() {
    let mut s = Session::new();
    s.block().await;
    s.send(cancel(1)).await;
    s.send(call(2, "/next")).await;
    s.ping().await;
    assert_eq!(*s.backend.calls.lock().unwrap(), ["/slow"]);
    s.backend.release.add_permits(1);
    assert_eq!(s.recv().await["id"], 2);
    s.ping().await; // No late reply for cancelled request 1.
    s.close().await;
}

#[tokio::test]
async fn batch_cancellation_keeps_one_aggregate_response() {
    let mut s = Session::new();
    s.block().await;
    s.send(json!([
        call(2, "/cancelled"),
        call(3, "/kept"),
        cancel(2),
        7
    ]))
    .await;
    s.ping().await;
    s.backend.release.add_permits(1);
    assert_eq!(s.recv().await["id"], 1);
    let batch = s.recv().await;
    let batch = batch.as_array().unwrap();
    assert_eq!(batch.len(), 2);
    assert!(batch.iter().any(|r| r["id"] == 3));
    assert!(batch.iter().any(|r| r["error"]["code"] == -32600));
    assert_eq!(*s.backend.calls.lock().unwrap(), ["/slow", "/kept"]);
    s.close().await;
}

#[tokio::test]
async fn full_queue_rejects_work_but_still_accepts_control_messages() {
    let mut s = Session::new();
    s.block().await;
    for id in 2..=34 {
        s.send(call(id, "/queued")).await;
    }
    let error = s.recv().await;
    assert_eq!(error["id"], 34);
    assert_eq!(error["error"]["code"], -32000);
    s.send(cancel(2)).await;
    s.send(call(35, "/replacement")).await;
    s.ping().await;
    s.backend.release.add_permits(1);
    assert_eq!(s.recv().await["id"], 1);
    for id in (3..=33).chain([35]) {
        assert_eq!(s.recv().await["id"], id);
    }
    s.close().await;
}

#[tokio::test]
async fn operation_completion_does_not_discard_a_partial_input_frame() {
    let mut s = Session::new();
    s.block().await;
    s.input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":")
        .await
        .unwrap();
    s.backend.release.add_permits(1);
    assert_eq!(s.recv().await["id"], 1);
    s.input
        .write_all(b"2,\"method\":\"ping\"}\n")
        .await
        .unwrap();
    assert_eq!(s.recv().await["id"], 2);
    s.close().await;
}

#[tokio::test]
async fn disconnect_does_not_dispatch_queued_effects() {
    let mut s = Session::new();
    s.block().await;
    s.send(call(2, "/must-not-run")).await;
    s.ping().await;
    let backend = s.backend.clone();
    s.close().await;
    assert_eq!(*backend.calls.lock().unwrap(), ["/slow"]);
}

#[tokio::test]
async fn byte_limit_rejects_large_queued_work_and_cancellation_frees_capacity() {
    let mut s = Session::new();
    s.block().await;
    let mut large = call(2, "/large");
    large["params"]["arguments"]["text"] = Value::String("\0".repeat(768 * 1024));
    s.send(large.clone()).await;
    large["id"] = json!(3);
    s.send(large.clone()).await;
    let error = s.recv().await;
    assert_eq!(error["id"], 3);
    assert_eq!(error["error"]["code"], -32000);
    s.send(cancel(2)).await;
    large["id"] = json!(4);
    s.send(large).await;
    s.ping().await;
    s.backend.release.add_permits(1);
    assert_eq!(s.recv().await["id"], 1);
    assert_eq!(s.recv().await["id"], 4);
    assert_eq!(*s.backend.calls.lock().unwrap(), ["/slow", "/large"]);
    s.close().await;
}

#[tokio::test]
async fn malformed_frames_never_dispatch_and_session_survives() {
    let mut session = Session::new();
    let mut invalid = serde_json::to_vec(&call(1, "/bad")).unwrap();
    let at = invalid
        .windows(4)
        .position(|bytes| bytes == b"/bad")
        .unwrap();
    invalid[at + 1] = 0xff;
    invalid.push(b'\n');
    session.input.write_all(&invalid).await.unwrap();
    assert_eq!(session.recv().await["error"]["code"], -32700);
    let mut missing_version = call(2, "/bad");
    missing_version.as_object_mut().unwrap().remove("jsonrpc");
    session.send(missing_version).await;
    assert_eq!(session.recv().await["error"]["code"], -32600);
    session.ping().await;
    assert!(session.backend.calls.lock().unwrap().is_empty());
    session.close().await;
}

#[tokio::test]
async fn oversized_frame_is_drained_even_when_an_operation_completes_mid_frame() {
    let mut session = Session::new();
    session.block().await;
    session
        .input
        .write_all(&vec![b'x'; 8 * 1024 * 1024 + 1])
        .await
        .unwrap();
    session.backend.release.add_permits(1);
    assert_eq!(session.recv().await["id"], 1);
    // This suffix would be a valid write if draining state were lost.
    session.send(call(2, "/must-not-run")).await;
    assert_eq!(session.recv().await["error"]["code"], -32600);
    session.ping().await;
    assert_eq!(*session.backend.calls.lock().unwrap(), ["/slow"]);
    session.close().await;
}

#[tokio::test]
async fn write_payload_validation_precedes_backend_dispatch() {
    let mut session = Session::new();
    for (name, payload) in [
        ("vfs_write", json!({})),
        ("vfs_write", json!({"text":"", "bytes_b64":""})),
        ("vfs_write_then_stat", json!({})),
        ("vfs_write_then_stat", json!({"text":"", "bytes_b64":""})),
        ("vfs_write", json!({"text":"x".repeat(1024 * 1024 + 1)})),
    ] {
        let mut arguments = payload;
        arguments["path"] = json!("/never");
        if name == "vfs_write_then_stat" {
            arguments["projection_path"] = json!("/latest");
        }
        session.send(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await;
        assert_eq!(session.recv().await["error"]["code"], -32602);
    }
    assert!(session.backend.calls.lock().unwrap().is_empty());
    session.ping().await;
    session.close().await;
}
