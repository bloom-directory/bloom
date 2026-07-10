#![cfg(feature = "mount")]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bloom_mount::{MountConfig, MountHandle, NfsMountHandle, serve_nfs, serve_nfs_with};
use bloom_vfs::handler::{Entry, Handler, HandlerError};
use bloom_vfs::{Vfs, VfsPath};

#[derive(Default)]
struct ChallengeStagingHandler {
    lookups: parking_lot::Mutex<usize>,
    lists: parking_lot::Mutex<usize>,
    staged: parking_lot::Mutex<Vec<Vec<u8>>>,
}

impl ChallengeStagingHandler {
    fn lookup_count(&self) -> usize {
        *self.lookups.lock()
    }

    fn list_count(&self) -> usize {
        *self.lists.lock()
    }

    fn staged_count(&self) -> usize {
        self.staged.lock().len()
    }

    fn staged_payloads(&self) -> Vec<Vec<u8>> {
        self.staged.lock().clone()
    }
}

#[async_trait]
impl Handler for ChallengeStagingHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        *self.lookups.lock() += 1;
        if path.is_root() {
            return Ok(Entry::dir(""));
        }
        match path.first() {
            Some("challenge") => Ok(Entry::writable_file("challenge")),
            Some("approval_challenge.json") if self.staged_count() > 0 => {
                Ok(Entry::file("approval_challenge.json"))
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        match path.first() {
            Some("challenge") => {
                self.staged.lock().push(data.to_vec());
                Err(HandlerError::PermissionDenied)
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn prepare_write_open(&self, path: &VfsPath) -> Result<(), HandlerError> {
        match path.first() {
            Some("challenge") => {
                let mut staged = self.staged.lock();
                if staged.is_empty() {
                    staged.push(Vec::new());
                }
                Err(HandlerError::PermissionDenied)
            }
            _ => Ok(()),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        *self.lists.lock() += 1;
        if path.is_root() {
            let mut entries = vec![Entry::writable_file("challenge")];
            if self.staged_count() > 0 {
                entries.push(Entry::file("approval_challenge.json"));
            }
            Ok(entries)
        } else {
            Err(HandlerError::NotADir(path.to_string_path()))
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        match path.first() {
            Some("approval_challenge.json") if self.staged_count() > 0 => {
                Ok(br#"{"schema":"test.approval_challenge","status":"pending"}"#.to_vec())
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }
}

const HL_TEST_SESSION: &str = "mount-session-1";

#[derive(Default)]
struct HyperliquidMountWorkflowHandler {
    approved: AtomicBool,
    challenge_staged: AtomicBool,
    writes: parking_lot::Mutex<Vec<(String, Vec<u8>)>>,
}

impl HyperliquidMountWorkflowHandler {
    fn approve(&self) {
        self.approved.store(true, Ordering::SeqCst);
    }

    fn writes_for(&self, leaf: &str) -> Vec<Vec<u8>> {
        self.writes
            .lock()
            .iter()
            .filter(|(path, _)| path.ends_with(leaf))
            .map(|(_, body)| body.clone())
            .collect()
    }
}

#[async_trait]
impl Handler for HyperliquidMountWorkflowHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let rendered = path.to_string_path();
        match rendered.as_str() {
            "/" => Ok(Entry::dir("")),
            "/mainnet" => Ok(Entry::dir("mainnet")),
            "/mainnet/agent_sessions" => Ok(Entry::dir("agent_sessions")),
            "/mainnet/agent_sessions/minnow" => Ok(Entry::dir("minnow")),
            "/mainnet/agent_sessions/minnow/new.json" => Ok(Entry::writable_file("new.json")),
            "/mainnet/agent_sessions/minnow/mount-session-1" => Ok(Entry::dir(HL_TEST_SESSION)),
            "/mainnet/agent_sessions/minnow/mount-session-1/approval_challenge.json"
                if self.challenge_staged.load(Ordering::SeqCst) =>
            {
                Ok(Entry::file("approval_challenge.json"))
            }
            "/mainnet/agent_sessions/minnow/mount-session-1/status.json" => {
                Ok(Entry::file("status.json"))
            }
            "/mainnet/agent_sessions/minnow/mount-session-1/order.json" => {
                Ok(Entry::writable_file("order.json"))
            }
            "/mainnet/agent_sessions/minnow/mount-session-1/cancel.json" => {
                Ok(Entry::writable_file("cancel.json"))
            }
            "/mainnet/agent_sessions/minnow/mount-session-1/stop" => {
                Ok(Entry::writable_file("stop"))
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let rendered = path.to_string_path();
        match rendered.as_str() {
            "/mainnet/agent_sessions/minnow/mount-session-1/approval_challenge.json"
                if self.challenge_staged.load(Ordering::SeqCst) =>
            {
                Ok(br#"{"schema":"test.hyperliquid.approval","status":"pending"}"#.to_vec())
            }
            "/mainnet/agent_sessions/minnow/mount-session-1/status.json" => {
                let status = if self.approved.load(Ordering::SeqCst) {
                    "active"
                } else {
                    "pending"
                };
                Ok(format!(r#"{{"status":"{status}"}}"#).into_bytes())
            }
            "/mainnet/agent_sessions/minnow/new.json" => {
                Ok(br#"{"hint":"write a session request"}"#.to_vec())
            }
            "/mainnet/agent_sessions/minnow/mount-session-1/order.json" => {
                Ok(br#"{"hint":"write order.json"}"#.to_vec())
            }
            "/mainnet/agent_sessions/minnow/mount-session-1/cancel.json" => {
                Ok(br#"{"hint":"write cancel.json"}"#.to_vec())
            }
            "/mainnet/agent_sessions/minnow/mount-session-1/stop" => {
                Ok(br#"{"hint":"write stop"}"#.to_vec())
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        self.writes
            .lock()
            .push((path.to_string_path(), data.to_vec()));
        let rendered = path.to_string_path();
        match rendered.as_str() {
            "/mainnet/agent_sessions/minnow/new.json" => {
                if !String::from_utf8_lossy(data).contains(HL_TEST_SESSION) {
                    return Err(HandlerError::invalid("missing session id"));
                }
                if !self.approved.load(Ordering::SeqCst) {
                    self.challenge_staged.store(true, Ordering::SeqCst);
                    return Err(HandlerError::PermissionDenied);
                }
                Ok(())
            }
            "/mainnet/agent_sessions/minnow/mount-session-1/order.json"
            | "/mainnet/agent_sessions/minnow/mount-session-1/cancel.json"
            | "/mainnet/agent_sessions/minnow/mount-session-1/stop" => {
                if self.approved.load(Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(HandlerError::PermissionDenied)
                }
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let rendered = path.to_string_path();
        match rendered.as_str() {
            "/" => Ok(vec![Entry::dir("mainnet")]),
            "/mainnet" => Ok(vec![Entry::dir("agent_sessions")]),
            "/mainnet/agent_sessions" => Ok(vec![Entry::dir("minnow")]),
            "/mainnet/agent_sessions/minnow" => Ok(vec![
                Entry::writable_file("new.json"),
                Entry::dir(HL_TEST_SESSION),
            ]),
            "/mainnet/agent_sessions/minnow/mount-session-1" => {
                let mut entries = vec![
                    Entry::file("status.json"),
                    Entry::writable_file("order.json"),
                    Entry::writable_file("cancel.json"),
                    Entry::writable_file("stop"),
                ];
                if self.challenge_staged.load(Ordering::SeqCst) {
                    entries.push(Entry::file("approval_challenge.json"));
                }
                Ok(entries)
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

fn unique_mount_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("bloom-mount-denied-{}-{nanos}", std::process::id()))
}

fn run_command_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> std::io::Result<Option<Output>> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map(Some);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn command_output_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> std::io::Result<Option<Output>> {
    tokio::task::spawn_blocking(move || run_command_output_with_timeout(&mut command, timeout))
        .await
        .expect("command timeout worker panicked")
}

async fn command_text(cmd: &str, args: &[&str], timeout: Duration) -> String {
    let mut command = Command::new(cmd);
    command.args(args);
    match command_output_with_timeout(command, timeout).await {
        Ok(Some(output)) => format!(
            "status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Ok(None) => "timed out".to_string(),
        Err(err) => format!("failed to run: {err}"),
    }
}

fn require_real_mount_test() -> bool {
    matches!(
        std::env::var("BLOOM_MOUNT_TEST_REQUIRE_REAL").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

async fn serve_test_mount(
    vfs: Vfs,
    mount_dir: &std::path::Path,
) -> Result<NfsMountHandle, bloom_mount::MountError> {
    match std::env::var("BLOOM_MOUNT_TEST_NFS_PORT") {
        Ok(raw) if !raw.trim().is_empty() => {
            let port = raw.trim().parse::<u16>().map_err(|err| {
                bloom_mount::MountError::Config(format!(
                    "invalid BLOOM_MOUNT_TEST_NFS_PORT={raw:?}: {err}"
                ))
            })?;
            serve_nfs_with(
                vfs,
                MountConfig {
                    mount_path: mount_dir.to_path_buf(),
                    nfs_listen: ([127, 0, 0, 1], port).into(),
                    readonly: false,
                },
            )
            .await
        }
        _ => serve_nfs(vfs, mount_dir).await,
    }
}

/// Manual issue #77 coverage: a real shell redirect through a kernel NFS
/// mount must fail when the handler stages a challenge and returns
/// PermissionDenied. This needs platform mount privileges, so it is ignored
/// and self-skips when `serve_nfs` cannot establish the mount.
#[tokio::test]
#[ignore = "requires local NFS mount privileges"]
async fn mounted_printf_surfaces_permission_denied() {
    let mount_dir = unique_mount_dir();
    std::fs::create_dir(&mount_dir).expect("create temporary mount dir");

    let handler = Arc::new(ChallengeStagingHandler::default());
    let vfs = Vfs::builder().mount("stage", handler.clone()).build();
    let mount = match serve_test_mount(vfs, &mount_dir).await {
        Ok(mount) => mount,
        Err(err) => {
            let _ = std::fs::remove_dir(&mount_dir);
            if require_real_mount_test() {
                panic!("real mount permission-denied test failed to mount: {err}");
            }
            eprintln!("skipping real mount permission-denied test: {err}");
            return;
        }
    };

    let mut root_ls = Command::new("ls");
    root_ls.arg("-la").arg(&mount_dir);
    match command_output_with_timeout(root_ls, Duration::from_secs(30))
        .await
        .expect("run ls through mounted root")
    {
        Some(output) if output.status.success() => {}
        Some(output) => {
            let msg = format!(
                "root ls failed: stdout={} stderr={} lookups={} lists={} staged_count={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            if require_real_mount_test() {
                panic!("real mount permission-denied test failed: {msg}");
            }
            eprintln!("skipping real mount permission-denied test: {msg}");
            return;
        }
        None => {
            let mount_text = command_text("mount", &[], Duration::from_secs(2)).await;
            let nfsstat_text = command_text("nfsstat", &["-m"], Duration::from_secs(2)).await;
            let msg = format!(
                "root ls timed out; nfs_addr={} mount={} nfsstat={} lookups={} lists={} staged_count={}",
                mount.nfs_addr(),
                mount_text,
                nfsstat_text,
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            if require_real_mount_test() {
                panic!("real mount permission-denied test failed: {msg}");
            }
            eprintln!("skipping real mount permission-denied test: {msg}");
            return;
        }
    }

    let stage_dir = mount_dir.join("stage");
    let mut stage_ls = Command::new("ls");
    stage_ls.arg("-la").arg(&stage_dir);
    match command_output_with_timeout(stage_ls, Duration::from_secs(30))
        .await
        .expect("run ls through mounted stage dir")
    {
        Some(output) if output.status.success() => {}
        Some(output) => {
            let msg = format!(
                "stage ls failed: stdout={} stderr={} lookups={} lists={} staged_count={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            if require_real_mount_test() {
                panic!("real mount permission-denied test failed: {msg}");
            }
            eprintln!("skipping real mount permission-denied test: {msg}");
            return;
        }
        None => {
            let msg = format!(
                "stage ls timed out; lookups={} lists={} staged_count={}",
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            if require_real_mount_test() {
                panic!("real mount permission-denied test failed: {msg}");
            }
            eprintln!("skipping real mount permission-denied test: {msg}");
            return;
        }
    }

    let target = mount_dir.join("stage").join("challenge");
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("printf '%s' '{\"action\":\"usdSend\"}' > \"$1\"")
        .arg("bloom-mount-test")
        .arg(&target);
    let output = match command_output_with_timeout(command, Duration::from_secs(10))
        .await
        .expect("run shell redirect through mounted path")
    {
        Some(output) => output,
        None => {
            let msg = format!(
                "shell redirect timed out; lookups={} lists={} staged_count={}",
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            if require_real_mount_test() {
                panic!("real mount permission-denied test failed: {msg}");
            }
            eprintln!("skipping real mount permission-denied test: {msg}");
            return;
        }
    };

    assert!(
        !output.status.success(),
        "mounted shell redirect unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert!(
        stderr.contains("permission denied") || stderr.contains("access"),
        "mounted shell redirect failed without a permission/access denial: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let challenge = mount_dir.join("stage").join("approval_challenge.json");
    let mut cat_challenge = Command::new("cat");
    cat_challenge.arg(&challenge);
    let challenge_output = match command_output_with_timeout(cat_challenge, Duration::from_secs(10))
        .await
        .expect("cat staged approval challenge through mounted path")
    {
        Some(output) => output,
        None => {
            let msg = format!(
                "cat approval_challenge.json timed out; lookups={} lists={} staged_count={}",
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            if require_real_mount_test() {
                panic!("real mount permission-denied test failed: {msg}");
            }
            eprintln!("skipping real mount permission-denied test: {msg}");
            return;
        }
    };
    if let Err(err) = mount.unmount().await {
        eprintln!("real mount permission-denied test cleanup: unmount failed: {err}");
    }
    let _ = std::fs::remove_dir(&mount_dir);

    assert!(
        challenge_output.status.success(),
        "cat approval_challenge.json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&challenge_output.stdout),
        String::from_utf8_lossy(&challenge_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&challenge_output.stdout).contains("test.approval_challenge"),
        "mounted approval challenge did not contain expected body: stdout={}",
        String::from_utf8_lossy(&challenge_output.stdout)
    );
    assert_eq!(
        handler.staged_count(),
        1,
        "write-open should stage exactly one challenge before denying"
    );
    assert_eq!(
        handler.staged_payloads(),
        vec![Vec::<u8>::new()],
        "open-time denial must happen before the shell writes the payload"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the host to allow a real localhost NFS mount"]
async fn mounted_hyperliquid_session_flow_reaches_handler() {
    let mount_dir = unique_mount_dir();
    std::fs::create_dir_all(&mount_dir).expect("create Hyperliquid mount test directory");
    let handler = Arc::new(HyperliquidMountWorkflowHandler::default());
    let vfs = Vfs::builder().mount("hyperliquid", handler.clone()).build();
    let mount = match serve_test_mount(vfs, &mount_dir).await {
        Ok(mount) => mount,
        Err(err) => {
            let _ = std::fs::remove_dir(&mount_dir);
            if require_real_mount_test() {
                panic!("real mounted Hyperliquid workflow failed to mount: {err}");
            }
            eprintln!("skipping real mounted Hyperliquid workflow: {err}");
            return;
        }
    };

    let wallet_root = mount_dir.join("hyperliquid/mainnet/agent_sessions/minnow");
    let new_path = wallet_root.join("new.json");
    let session_root = wallet_root.join(HL_TEST_SESSION);
    let payload = format!(r#"{{"id":"{HL_TEST_SESSION}","agent_name":"mounted-test"}}"#);
    let write_redirect = |path: &std::path::Path, body: &str| {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("printf '%s\\n' \"$2\" > \"$1\"")
            .arg("sh")
            .arg(path)
            .arg(body);
        command
    };

    let first =
        command_output_with_timeout(write_redirect(&new_path, &payload), Duration::from_secs(10))
            .await
            .expect("attempt mounted Hyperliquid session creation")
            .expect("mounted Hyperliquid session creation timed out");

    let mut cat_challenge = Command::new("cat");
    cat_challenge.arg(session_root.join("approval_challenge.json"));
    let challenge = command_output_with_timeout(cat_challenge, Duration::from_secs(10))
        .await
        .expect("read mounted Hyperliquid approval challenge")
        .expect("mounted Hyperliquid approval challenge read timed out");

    handler.approve();
    let approved =
        command_output_with_timeout(write_redirect(&new_path, &payload), Duration::from_secs(10))
            .await
            .expect("retry mounted Hyperliquid session creation")
            .expect("approved mounted Hyperliquid session creation timed out");

    let order_body = r#"{"action":{"type":"order"}}"#;
    let order = command_output_with_timeout(
        write_redirect(&session_root.join("order.json"), order_body),
        Duration::from_secs(10),
    )
    .await
    .expect("submit mounted Hyperliquid order")
    .expect("mounted Hyperliquid order timed out");

    let cancel_body = r#"{"action":{"type":"cancel"}}"#;
    let cancel = command_output_with_timeout(
        write_redirect(&session_root.join("cancel.json"), cancel_body),
        Duration::from_secs(10),
    )
    .await
    .expect("submit mounted Hyperliquid cancel")
    .expect("mounted Hyperliquid cancel timed out");

    let mut cat_status = Command::new("cat");
    cat_status.arg(session_root.join("status.json"));
    let status = command_output_with_timeout(cat_status, Duration::from_secs(10))
        .await
        .expect("read mounted Hyperliquid session status")
        .expect("mounted Hyperliquid session status read timed out");

    if let Err(err) = mount.unmount().await {
        eprintln!("real mounted Hyperliquid cleanup: unmount failed: {err}");
    }
    let _ = std::fs::remove_dir(&mount_dir);

    // macOS may still report success for a deferred NFS WRITE error. The
    // important mount-only contract is that the payload reached the handler
    // and the resulting challenge is immediately discoverable/readable.
    assert!(
        first.status.success(),
        "atomic command transport must defer handler denial instead of returning a macOS NFS write error: stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(challenge.status.success());
    assert!(String::from_utf8_lossy(&challenge.stdout).contains("test.hyperliquid.approval"));
    assert!(
        approved.status.success(),
        "approved session creation failed: stderr={}",
        String::from_utf8_lossy(&approved.stderr)
    );
    assert!(
        order.status.success(),
        "mounted order failed: stderr={}",
        String::from_utf8_lossy(&order.stderr)
    );
    assert!(
        cancel.status.success(),
        "mounted cancel failed: stderr={}",
        String::from_utf8_lossy(&cancel.stderr)
    );
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains(r#""status":"active""#));
    let new_writes = handler.writes_for("new.json");
    assert!(
        new_writes.len() >= 2,
        "initial and approved retries must both reach the handler"
    );
    assert!(
        new_writes
            .iter()
            .all(|body| body == &format!("{payload}\n").into_bytes()),
        "NFS retransmissions must preserve the exact session request: {new_writes:?}"
    );
    assert_eq!(
        handler.writes_for("order.json"),
        vec![format!("{order_body}\n").into_bytes()]
    );
    assert_eq!(
        handler.writes_for("cancel.json"),
        vec![format!("{cancel_body}\n").into_bytes()]
    );
}
