//! Category: CLI-subprocess
//!
//! CLI smoke tests for the `bloom` binary.
//!
//! Each test allocates a fresh `tempfile::tempdir()` home and invokes the
//! built `bloom` binary via `assert_cmd::Command::cargo_bin`. We exercise
//! the local one-shot path for status / vfs / wallet, and stand up an
//! in-process `IpcServer` to verify the "socket exists → route via IPC"
//! branch in the CLI's vfs subcommand.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use assert_cmd::Command;
use async_trait::async_trait;
use bloom_vfs::{Entry, Handler, HandlerError, VfsPath};
use predicates::prelude::*;
use tempfile::TempDir;

/// Build a Command for the `bloom` binary that always runs against a
/// hermetic temp home. Returns the tempdir handle so callers can keep it
/// alive (and pass it back into the same process for follow-up calls).
fn bloom_cmd(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("bloom").expect("locate bloom binary");
    cmd.env("BLOOM_HOME", home);
    // Quiet logging keeps stdout/stderr predictable for assertions.
    cmd.env("RUST_LOG", "error");
    cmd
}

fn fresh_home() -> TempDir {
    tempfile::tempdir().expect("create temp home")
}

/// Write `passphrase` to a file under `home` and return its path string. Used
/// to feed `--passphrase-file` for non-interactive passphrase-wallet creation
/// (the only way to create a local wallet without a tty — passkey is default).
fn write_passphrase_file(home: &Path, passphrase: &str) -> String {
    let path = home.join(".passphrase");
    std::fs::write(&path, passphrase).expect("write passphrase file");
    path.to_string_lossy().into_owned()
}

#[derive(Default)]
struct RecordingWriteHandler {
    writes: Mutex<Vec<(String, Vec<u8>)>>,
}

impl RecordingWriteHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn writes(&self) -> Vec<(String, Vec<u8>)> {
        self.writes.lock().unwrap().clone()
    }
}

#[async_trait]
impl Handler for RecordingWriteHandler {
    async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
        if p.is_root() {
            return Ok(Entry::dir(""));
        }
        Ok(Entry::writable_file(
            p.segments().last().map(String::as_str).unwrap_or("write"),
        ))
    }

    async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if p.is_root() {
            Ok(vec![])
        } else {
            Err(HandlerError::NotADir(p.to_string_path()))
        }
    }

    async fn write(&self, p: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        self.writes
            .lock()
            .unwrap()
            .push((p.to_string_path(), data.to_vec()));
        Ok(())
    }
}

fn spawn_ipc_server(
    home: &Path,
    vfs: bloom_vfs::Vfs,
) -> (bloom_daemon::ipc::IpcServer, std::thread::JoinHandle<()>) {
    use bloom_daemon::ipc::{IpcServer, default_socket_path};

    let socket = default_socket_path(home);
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let server = IpcServer::new(vfs, "ipc-test-version", vec!["ipc-chain".into()]);
    let server_for_thread = server.clone();
    let socket_for_thread = socket.clone();
    let server_thread = std::thread::spawn(move || {
        rt.block_on(async move {
            server_for_thread
                .serve(&socket_for_thread)
                .await
                .expect("ipc serve");
        });
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        if std::time::Instant::now() >= deadline {
            panic!("ipc server never created socket at {}", socket.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    (server, server_thread)
}

fn stop_ipc_server(
    server: bloom_daemon::ipc::IpcServer,
    server_thread: std::thread::JoinHandle<()>,
) {
    server.trigger_shutdown();
    let join_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !server_thread.is_finished() {
        if std::time::Instant::now() >= join_deadline {
            panic!("ipc server thread did not exit after shutdown");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    server_thread.join().expect("ipc server thread panicked");
}

fn http_fixture(
    status: u16,
    headers: &[(&str, &str)],
    body: &'static [u8],
) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock HTTP server");
    let addr = listener.local_addr().expect("mock server addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_thread = hits.clone();
    let header_lines = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect::<String>();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            hits_for_thread.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0_u8; 4096];
            let _ = stream.read(&mut buf);
            let reason = if status == 402 {
                "Payment Required"
            } else {
                "OK"
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\n{header_lines}\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        }
    });
    (format!("http://{addr}/resource"), hits)
}

#[test]
fn help_lists_all_subcommands() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("vfs"))
        .stdout(predicate::str::contains("wallet"))
        .stdout(predicate::str::contains("request"))
        .stdout(predicate::str::contains("serve"))
        .stdout(predicate::str::contains("ipc"))
        .stdout(predicate::str::contains("petals"))
        .stdout(predicate::str::contains("init"));
}

#[test]
fn vfs_write_help_lists_unlock_flags() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["vfs", "write", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--unlock-wallet"))
        .stdout(predicate::str::contains("--passphrase"))
        // The dual-runtime guidance an agent needs: in-process daemon (bypasses
        // IPC) and the foreground requirement for the passkey ceremony.
        .stdout(predicate::str::contains("in-process"))
        .stdout(predicate::str::contains("FOREGROUND"));
}

#[test]
fn polymarket_help_lists_obligations() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["polymarket", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("obligations"))
        .stdout(predicate::str::contains("redeem"));
}

#[test]
fn status_prints_version_and_chain_summary() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .arg("status")
        .assert()
        .success()
        // Version line uses the package version; just assert the prefix.
        .stdout(predicate::str::contains("version: "))
        .stdout(predicate::str::contains("home: "))
        .stdout(predicate::str::contains("chains: "))
        .stdout(predicate::str::contains("block_mainnet_broadcast: "));
}

#[test]
fn vfs_ls_root_lists_top_level_handlers() {
    let home = fresh_home();
    let assert = bloom_cmd(home.path())
        .args(["vfs", "ls", "/"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // The default daemon mounts these handlers; each appears as a Dir
    // entry. We don't assert on extras (defi is config-gated).
    for required in [
        "AGENTS.md",
        "CLAUDE.md",
        "chains",
        "status",
        "wallets",
        "tools",
        "requests",
        "docs",
    ] {
        assert!(
            out.lines().any(|l| l.starts_with(required)),
            "expected `{required}` in vfs ls /, got:\n{out}"
        );
    }
}

#[test]
fn vfs_cat_root_agent_guidance_returns_identical_content() {
    let home = fresh_home();
    let agents = bloom_cmd(home.path())
        .args(["vfs", "cat", "/AGENTS.md"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let claude = bloom_cmd(home.path())
        .args(["vfs", "cat", "/CLAUDE.md"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(agents, claude);
    let text = String::from_utf8(agents).expect("guidance is utf-8");
    assert!(text.contains("/docs"), "guidance should call out /docs");
    assert!(
        text.contains("bloom vfs"),
        "guidance should mention the bloom vfs CLI"
    );
}

#[test]
fn vfs_ls_status_lists_known_files() {
    let home = fresh_home();
    let assert = bloom_cmd(home.path())
        .args(["vfs", "ls", "/status"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for required in ["version", "uptime", "started_at", "home", "chains", "audit"] {
        assert!(
            out.lines().any(|l| l.starts_with(required)),
            "expected `{required}` in vfs ls /status, got:\n{out}"
        );
    }
}

#[test]
fn vfs_cat_status_version_returns_pkg_version() {
    let home = fresh_home();
    let expected = format!("{}\n", env!("CARGO_PKG_VERSION"));
    bloom_cmd(home.path())
        .args(["vfs", "cat", "/status/version"])
        .assert()
        .success()
        .stdout(predicate::eq(expected));
}

#[test]
fn vfs_default_missing_socket_falls_back_in_process() {
    let home = fresh_home();
    let socket = home.path().join("run").join("bloom.sock");
    assert!(
        !socket.exists(),
        "fresh home should not have a daemon socket"
    );

    bloom_cmd(home.path())
        .args(["vfs", "cat", "/status/version"])
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn vfs_explicit_missing_endpoint_fails_closed() {
    let home = fresh_home();
    let socket = home.path().join("run").join("missing.sock");
    let endpoint = format!("unix:{}", socket.display());

    bloom_cmd(home.path())
        .args(["--connect", &endpoint, "vfs", "cat", "/status/version"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("explicit Bloom endpoint")
                .and(predicate::str::contains(socket.display().to_string())),
        );
}

#[test]
fn vfs_legacy_ipc_socket_env_fails_closed() {
    let home = fresh_home();
    let socket = home.path().join("run").join("missing-legacy.sock");

    bloom_cmd(home.path())
        .env("BLOOM_IPC_SOCKET", &socket)
        .args(["vfs", "ls", "/"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("explicit Bloom endpoint")
                .and(predicate::str::contains(socket.display().to_string())),
        );
}

#[test]
fn rpc_endpoint_env_beats_legacy_ipc_socket_env() {
    let home = fresh_home();
    let rpc_socket = home.path().join("run").join("rpc-missing.sock");
    let legacy_socket = home.path().join("run").join("legacy-missing.sock");
    let rpc_endpoint = format!("unix:{}", rpc_socket.display());

    bloom_cmd(home.path())
        .env("BLOOM_RPC_ENDPOINT", rpc_endpoint)
        .env("BLOOM_IPC_SOCKET", &legacy_socket)
        .args(["vfs", "ls", "/"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains(rpc_socket.display().to_string())
                .and(predicate::str::contains(legacy_socket.display().to_string()).not()),
        );
}

#[test]
fn connect_flag_beats_rpc_endpoint_env() {
    let home = fresh_home();
    let flag_socket = home.path().join("run").join("flag-missing.sock");
    let env_socket = home.path().join("run").join("env-missing.sock");
    let flag_endpoint = format!("unix:{}", flag_socket.display());
    let env_endpoint = format!("unix:{}", env_socket.display());

    bloom_cmd(home.path())
        .env("BLOOM_RPC_ENDPOINT", env_endpoint)
        .args(["--connect", &flag_endpoint, "vfs", "ls", "/"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains(flag_socket.display().to_string())
                .and(predicate::str::contains(env_socket.display().to_string()).not()),
        );
}

#[test]
fn ipc_socket_flag_beats_rpc_endpoint_env() {
    let home = fresh_home();
    let flag_socket = home.path().join("run").join("ipc-flag-missing.sock");
    let env_socket = home.path().join("run").join("env-missing.sock");
    let env_endpoint = format!("unix:{}", env_socket.display());

    bloom_cmd(home.path())
        .env("BLOOM_RPC_ENDPOINT", env_endpoint)
        .args([
            "--ipc-socket",
            flag_socket.to_str().unwrap(),
            "vfs",
            "ls",
            "/",
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains(flag_socket.display().to_string())
                .and(predicate::str::contains(env_socket.display().to_string()).not()),
        );
}

#[test]
fn serve_refuses_when_home_write_lock_is_live() {
    let home = fresh_home();
    let _permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(home.path()))
        .expect("hold home write permit");
    let lock = home.path().join("run").join(".daemon.lock");

    bloom_cmd(home.path())
        .arg("serve")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("already open for writing")
                .and(predicate::str::contains(lock.display().to_string())),
        );
}

#[test]
fn chain_health_does_not_take_home_write_lock() {
    let home = fresh_home();
    let _permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(home.path()))
        .expect("hold home write permit");

    bloom_cmd(home.path())
        .args(["chain", "health"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already open for writing").not());
}

#[test]
fn chain_ls_validators_does_not_take_home_write_lock() {
    let home = fresh_home();
    let _permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(home.path()))
        .expect("hold home write permit");

    bloom_cmd(home.path())
        .args(["chain", "ls-validators"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already open for writing").not());
}

#[test]
fn request_new_routes_via_ipc_when_home_write_lock_is_live() {
    use bloom_vfs::Vfs;

    let home = fresh_home();
    let _permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(home.path()))
        .expect("hold home write permit");
    let requests = RecordingWriteHandler::new();
    let vfs = Vfs::builder().mount("requests", requests.clone()).build();
    let (server, server_thread) = spawn_ipc_server(home.path(), vfs);

    bloom_cmd(home.path())
        .args([
            "request",
            "new",
            "--dry-run",
            "--wallet",
            "alice",
            "GET https://example.com",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("already open for writing").not())
        .stdout(predicate::str::contains("dry_run: true"));

    stop_ipc_server(server, server_thread);
    let writes = requests.writes();
    assert_eq!(writes.len(), 1, "writes={writes:?}");
    assert_eq!(writes[0].0, "/new.dry-run");
    assert_eq!(
        String::from_utf8_lossy(&writes[0].1),
        "GET https://example.com wallet=alice"
    );
}

#[test]
fn wallet_stage_routes_via_ipc_when_home_write_lock_is_live() {
    use bloom_vfs::Vfs;

    let home = fresh_home();
    let _permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(home.path()))
        .expect("hold home write permit");
    let wallets = RecordingWriteHandler::new();
    let vfs = Vfs::builder().mount("wallets", wallets.clone()).build();
    let (server, server_thread) = spawn_ipc_server(home.path(), vfs);
    let intent = "send 0.001 eth to 0x0000000000000000000000000000000000000000 on anvil";

    bloom_cmd(home.path())
        .args(["wallet", "stage", "alice", "anvil", "--intent", intent])
        .assert()
        .success()
        .stderr(predicate::str::contains("already open for writing").not());

    stop_ipc_server(server, server_thread);
    let writes = wallets.writes();
    assert_eq!(writes.len(), 1, "writes={writes:?}");
    assert_eq!(writes[0].0, "/alice/chains/anvil/outbox/new.tx");
    assert_eq!(String::from_utf8_lossy(&writes[0].1), intent);
}

#[test]
fn wallet_stage_without_daemon_uses_in_process_parser() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args([
            "wallet",
            "stage",
            "alice",
            "anvil",
            "--intent",
            "not an intent",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("parse intent"))
        .stderr(predicate::str::contains("already open for writing").not());
}

#[test]
fn wallet_new_then_list_round_trip() {
    let home = fresh_home();
    let pass_file = write_passphrase_file(home.path(), "smoke-test-pass");
    let create = bloom_cmd(home.path())
        .args([
            "wallet",
            "new",
            "alice",
            "--local",
            "--allow-passphrase-wallet",
            "--passphrase-file",
            &pass_file,
        ])
        .assert()
        .success();
    let create_out = String::from_utf8(create.get_output().stdout.clone()).unwrap();
    assert!(
        create_out.contains("created wallet 'alice'"),
        "unexpected create output: {create_out}"
    );
    assert!(
        create_out.contains("default_wallet: alice"),
        "first wallet creation should announce default wallet selection: {create_out}"
    );
    let config = std::fs::read_to_string(home.path().join("config.toml")).unwrap();
    assert!(
        config.contains("default_wallet = \"alice\""),
        "config should persist default wallet, got:\n{config}"
    );
    // Address line is `created wallet 'alice': 0x...` — capture and reuse
    // the address to assert the listing matches what was just minted.
    let addr = create_out
        .split_whitespace()
        .find(|tok| tok.starts_with("0x") && tok.len() == 42)
        .expect("create output should contain a 0x-prefixed address");

    let list = bloom_cmd(home.path())
        .args(["wallet", "list"])
        .assert()
        .success();
    let list_out = String::from_utf8(list.get_output().stdout.clone()).unwrap();
    assert!(
        list_out.lines().any(|l| {
            let mut parts = l.split('\t');
            parts.next() == Some("alice")
                && parts.next() == Some(addr)
                && parts.next() == Some("local")
        }),
        "wallet list missing freshly-created entry; got:\n{list_out}"
    );
}

#[test]
fn wallet_new_local_via_passphrase_file() {
    // BLOOM_PASSPHRASE no longer creates wallets — passkey is the default, and
    // passphrase-wallet creation must be explicit: --local +
    // --allow-passphrase-wallet + --passphrase-file (non-interactive).
    let home = fresh_home();
    let pass_file = write_passphrase_file(home.path(), "env-pass-1");
    bloom_cmd(home.path())
        .args([
            "wallet",
            "new",
            "bob",
            "--local",
            "--allow-passphrase-wallet",
            "--passphrase-file",
            &pass_file,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("created wallet 'bob'"));
    let bob_dir = home.path().join("keystore").join("bob");
    assert!(
        bob_dir.join("address").exists(),
        "expected keystore/bob/address to be written"
    );
    assert!(
        bob_dir.join("encrypted.key").exists(),
        "expected keystore/bob/encrypted.key to be written"
    );
    assert!(
        bob_dir.join("RECOVERY.txt").exists(),
        "passphrase wallets must write a RECOVERY.txt"
    );
}

/// Creating a passphrase wallet non-interactively WITHOUT --allow-passphrase-wallet
/// must fail closed — this is the gate that stops an agent from silently minting
/// a passphrase wallet. (assert_cmd stdin is not a tty.)
#[test]
fn wallet_new_local_refused_without_ack_when_noninteractive() {
    let home = fresh_home();
    let pass_file = write_passphrase_file(home.path(), "pw");
    let assert = bloom_cmd(home.path())
        .args([
            "wallet",
            "new",
            "sneaky",
            "--local",
            "--passphrase-file",
            &pass_file,
        ])
        .assert()
        .failure();
    let err = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        err.contains("--allow-passphrase-wallet"),
        "error should demand the ack flag, got: {err}"
    );
    // Nothing was created.
    assert!(
        !home.path().join("keystore").join("sneaky").exists(),
        "no wallet directory should exist after a refused creation"
    );
}

/// A successful wallet creation appends a first-class `wallet.created` audit
/// record — the CLI path does not flow through the VFS router, so without this
/// event a CLI-created wallet leaves no trail (the original eth-long-1 bug).
#[test]
fn wallet_created_audit_event() {
    let home = fresh_home();
    let pass_file = write_passphrase_file(home.path(), "audit-pass");
    bloom_cmd(home.path())
        .args([
            "wallet",
            "new",
            "audited",
            "--local",
            "--allow-passphrase-wallet",
            "--passphrase-file",
            &pass_file,
        ])
        .assert()
        .success();
    let audit = std::fs::read_to_string(home.path().join("audit.jsonl")).unwrap();
    assert!(
        audit.contains("\"kind\":\"wallet.created\"") && audit.contains("audited"),
        "audit log should contain a wallet.created event for 'audited', got:\n{audit}"
    );
}

#[test]
fn request_cli_dry_run_uses_vfs_lifecycle_and_body_receipt_helpers() {
    let home = fresh_home();
    let pass_file = write_passphrase_file(home.path(), "pw");
    bloom_cmd(home.path())
        .args([
            "wallet",
            "new",
            "alice",
            "--local",
            "--allow-passphrase-wallet",
            "--passphrase-file",
            &pass_file,
        ])
        .assert()
        .success();

    let (url, hits) = http_fixture(200, &[("content-type", "text/plain")], b"cli-body\n");
    let new = bloom_cmd(home.path())
        .args(["request", "new", "--dry-run", &format!("GET {url}")])
        .assert()
        .success()
        .stdout(predicate::str::contains("request: sent/"))
        .stdout(predicate::str::contains("dry_run: true"))
        .get_output()
        .stdout
        .clone();
    let new = String::from_utf8(new).unwrap();
    let id = new
        .lines()
        .find_map(|line| line.strip_prefix("request: sent/"))
        .expect("request id in request new output")
        .trim()
        .to_string();

    bloom_cmd(home.path())
        .args(["request", "plan", "latest"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run: true"));
    bloom_cmd(home.path())
        .args(["request", "body", &id])
        .assert()
        .success()
        .stdout(predicate::eq("cli-body\n"));
    bloom_cmd(home.path())
        .args(["request", "receipt", &id])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"protocol\": \"free\""));
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "read helpers must not re-issue HTTP"
    );
}

#[test]
fn status_on_empty_keystore_points_to_wallet_creation() {
    let home = fresh_home();
    let assert = bloom_cmd(home.path()).args(["status"]).assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        out.contains("no wallets yet"),
        "empty status should say no wallet exists:\n{out}"
    );
    assert!(
        out.contains("bloom wallet new main"),
        "status should point at the explicit wallet command:\n{out}"
    );
}

/// `wallet address <name>` prints the bare checksummed address; adding `--qr`
/// prepends a scannable QR block while keeping the address line.
#[test]
fn wallet_address_with_and_without_qr() {
    let home = fresh_home();
    let pass_file = write_passphrase_file(home.path(), "addr-smoke-pass");
    bloom_cmd(home.path())
        .args([
            "wallet",
            "new",
            "alice",
            "--local",
            "--allow-passphrase-wallet",
            "--passphrase-file",
            &pass_file,
        ])
        .assert()
        .success();

    let plain = bloom_cmd(home.path())
        .args(["wallet", "address", "alice"])
        .assert()
        .success();
    let plain_out = String::from_utf8(plain.get_output().stdout.clone()).unwrap();
    let addr = plain_out.trim();
    assert!(
        addr.starts_with("0x") && addr.len() == 42,
        "plain output should be a bare address, got: {plain_out:?}"
    );

    let qr = bloom_cmd(home.path())
        .args(["wallet", "address", "alice", "--qr"])
        .assert()
        .success();
    let qr_out = String::from_utf8(qr.get_output().stdout.clone()).unwrap();
    assert!(
        qr_out.contains(addr),
        "--qr output must still include the address:\n{qr_out}"
    );
    assert!(
        qr_out.lines().count() > plain_out.lines().count(),
        "--qr should add a QR block above the address:\n{qr_out}"
    );
}

/// `wallet address <name> --qr-out <path>` writes a scannable SVG QR file and
/// still prints the address; the SVG is a real `<svg>` document.
#[test]
fn wallet_address_qr_out_writes_svg() {
    let home = fresh_home();
    let pass_file = write_passphrase_file(home.path(), "qr-out-pass");
    bloom_cmd(home.path())
        .args([
            "wallet",
            "new",
            "alice",
            "--local",
            "--allow-passphrase-wallet",
            "--passphrase-file",
            &pass_file,
        ])
        .assert()
        .success();
    let svg_path = home.path().join("deposit.svg");
    let out = bloom_cmd(home.path())
        .args([
            "wallet",
            "address",
            "alice",
            "--qr-out",
            svg_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    // The bare address still goes to stdout (scriptable).
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.trim().starts_with("0x"), "stdout: {stdout:?}");
    // The SVG file exists and is a real SVG document.
    let svg = std::fs::read_to_string(&svg_path).expect("qr svg written");
    assert!(
        svg.contains("<svg") && svg.contains("</svg>"),
        "expected an SVG document, got: {}",
        &svg[..svg.len().min(80)]
    );
}

/// Spin up an in-process `IpcServer` bound to the home's default socket
/// path, then invoke the CLI so its `vfs` subcommand routes through IPC.
/// The CLI's local-vs-IPC selection keys solely off `socket.exists()`, so
/// proving the IPC branch reduces to seeing data we know only the server
/// would produce.
#[test]
fn vfs_routes_via_ipc_when_socket_exists() {
    use bloom_daemon::ipc::{IpcServer, default_socket_path};
    use bloom_test_util::mocks::SingleFileHandler;
    use bloom_vfs::Vfs;

    // A trivial in-memory handler that the production daemon never mounts;
    // if the CLI's `vfs ls /probe` returns this entry, the request must
    // have gone through our test server.
    let probe = SingleFileHandler::new("marker", b"ipc-only-marker\n".to_vec());

    let home = fresh_home();
    let socket = default_socket_path(home.path());
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();

    let vfs = Vfs::builder()
        .mount("probe", std::sync::Arc::new(probe))
        .build();

    // Build a Tokio runtime for the server in a dedicated thread; the
    // CLI subprocess provides its own runtime separately.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let server = IpcServer::new(vfs, "ipc-test-version", vec!["ipc-chain".into()]);
    let server_for_thread = server.clone();
    let socket_for_thread = socket.clone();
    let server_thread = std::thread::spawn(move || {
        rt.block_on(async move {
            server_for_thread
                .serve(&socket_for_thread)
                .await
                .expect("ipc serve");
        });
    });

    // Wait for the socket file to materialise (server binds before
    // accepting connections; this is the same pattern used by the daemon's
    // own ipc tests).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        if std::time::Instant::now() >= deadline {
            panic!("ipc server never created socket at {}", socket.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // `vfs ls /probe` should hit the test server (which advertises the
    // bespoke marker entry); the production daemon doesn't mount `probe`,
    // so a positive match proves the IPC code path executed.
    let out = bloom_cmd(home.path())
        .args(["vfs", "ls", "/probe"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.lines().any(|l| l.starts_with("marker")),
        "expected `marker` entry from in-process IPC server; got:\n{stdout}"
    );

    // `vfs cat` exercises the IPC `read` method + base64 decode in the
    // CLI. Asserting on the unique payload also rules out an accidental
    // local-path fallback.
    bloom_cmd(home.path())
        .args(["vfs", "cat", "/probe/marker"])
        .assert()
        .success()
        .stdout(predicate::eq("ipc-only-marker\n"));

    // Tear the server down cleanly. The serve loop awaits the shutdown
    // notify alongside `accept()`; triggering it breaks the loop on the
    // next select poll. Joining the thread guarantees the socket file is
    // removed (the server unlinks on shutdown), which keeps test
    // isolation tight even though the tempdir would also clean up.
    server.trigger_shutdown();
    let join_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !server_thread.is_finished() {
        if std::time::Instant::now() >= join_deadline {
            panic!("ipc server thread did not exit after shutdown");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    server_thread.join().expect("ipc server thread panicked");
}

/// End-to-end petals smoke test: install a WAT module from a file,
/// confirm `petals ls` shows it under both its hash and its petname, then
/// `petals run` it and check that WASI stdout reaches the parent process.
/// The WAT writes a fixed string via `fd_write` and exits 0, so a success
/// here proves the wasmtime engine, WASI shims, and the runner are wired
/// through the daemon end to end.
#[test]
fn petals_install_then_ls_then_run() {
    let home = fresh_home();
    let wat_path = home.path().join("hello.wat");
    // Self-contained WASI petal: writes 21 bytes to fd 1 (stdout), exits 0.
    // The iovec table at offset 32 points at the string at offset 0.
    let wat = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "hello from cli petal\n")
          (data (i32.const 32) "\00\00\00\00\15\00\00\00")
          (func (export "_start")
            (call $fd_write (i32.const 1) (i32.const 32) (i32.const 1) (i32.const 48))
            drop
            (call $exit (i32.const 0)))
        )
    "#;
    std::fs::write(&wat_path, wat).unwrap();

    let install = bloom_cmd(home.path())
        .args([
            "petals",
            "install",
            wat_path.to_str().unwrap(),
            "--name",
            "hello",
        ])
        .assert()
        .success();
    let install_out = String::from_utf8(install.get_output().stdout.clone()).unwrap();
    let hash_line = install_out
        .lines()
        .find(|l| l.starts_with("hash: "))
        .expect("install stdout must include a hash line");
    let hash = hash_line.trim_start_matches("hash: ").trim();
    assert_eq!(hash.len(), 64, "expected 64-char hex hash, got {hash:?}");

    let ls = bloom_cmd(home.path())
        .args(["petals", "ls"])
        .assert()
        .success();
    let ls_out = String::from_utf8(ls.get_output().stdout.clone()).unwrap();
    // ls prints the first 12 chars of the hash plus the petname.
    let short = &hash[..12];
    assert!(
        ls_out.contains(short),
        "petals ls should mention installed hash {short}; got:\n{ls_out}"
    );
    assert!(
        ls_out.contains("name=hello"),
        "petals ls should show name=hello; got:\n{ls_out}"
    );

    // Run via the petname.
    let run_by_name = bloom_cmd(home.path())
        .args(["petals", "run", "hello"])
        .assert()
        .success();
    let stdout_name = String::from_utf8(run_by_name.get_output().stdout.clone()).unwrap();
    assert_eq!(
        stdout_name, "hello from cli petal\n",
        "stdout from petal didn't match"
    );

    // Run via the bare hash.
    let run_by_hash = bloom_cmd(home.path())
        .args(["petals", "run", hash])
        .assert()
        .success();
    let stdout_hash = String::from_utf8(run_by_hash.get_output().stdout.clone()).unwrap();
    assert_eq!(stdout_hash, "hello from cli petal\n");
}

/// `bloom petals name <name> <hash>` binds a petname, and `name <name>`
/// with no hash unbinds it. Verified by reading `public/<name>` via the
/// VFS subcommand, which goes through the PetalsHandler we mounted in
/// `bloom-daemon`.
#[test]
fn petals_name_bind_unbind_reflects_in_vfs() {
    let home = fresh_home();
    let wat_path = home.path().join("noop.wat");
    // Minimal valid wasm module: `(module)` compiles to 8 bytes. We use
    // a slightly fuller WAT just so it survives a wasmtime parse.
    let wat = r#"(module (memory (export "memory") 1) (func (export "_start")))"#;
    std::fs::write(&wat_path, wat).unwrap();

    let install = bloom_cmd(home.path())
        .args(["petals", "install", wat_path.to_str().unwrap()])
        .assert()
        .success();
    let install_out = String::from_utf8(install.get_output().stdout.clone()).unwrap();
    let hash = install_out
        .lines()
        .find(|l| l.starts_with("hash: "))
        .unwrap()
        .trim_start_matches("hash: ")
        .trim()
        .to_string();

    // Bind a new petname.
    bloom_cmd(home.path())
        .args(["petals", "name", "greet", &hash])
        .assert()
        .success();

    // `vfs ls /public` should expose the petname as a symlink. We just
    // check the entry is listed; symlink targets aren't shown by the ls
    // formatter, but the daemon-side handler emits the entry.
    let ls = bloom_cmd(home.path())
        .args(["vfs", "ls", "/public/local"])
        .assert()
        .success();
    let ls_out = String::from_utf8(ls.get_output().stdout.clone()).unwrap();
    assert!(
        ls_out.lines().any(|l| l.starts_with("greet")),
        "expected 'greet' entry under /public/local; got:\n{ls_out}"
    );

    // Unbind by omitting the hash.
    bloom_cmd(home.path())
        .args(["petals", "name", "greet"])
        .assert()
        .success();

    let ls_after = bloom_cmd(home.path())
        .args(["vfs", "ls", "/public/local"])
        .assert()
        .success();
    let ls_after_out = String::from_utf8(ls_after.get_output().stdout.clone()).unwrap();
    assert!(
        !ls_after_out.lines().any(|l| l.starts_with("greet")),
        "expected 'greet' entry removed; got:\n{ls_after_out}"
    );
}

#[test]
fn install_same_hash_same_mode_different_caps_returns_cap_mismatch() {
    let home = fresh_home();
    let wat_path = home.path().join("hello.wat");
    std::fs::write(&wat_path, "(module (func (export \"_start\")))").unwrap();
    bloom_cmd(home.path())
        .args([
            "petals",
            "install",
            wat_path.to_str().unwrap(),
            "--cap",
            "vfs.read",
        ])
        .assert()
        .success();
    bloom_cmd(home.path())
        .args([
            "petals",
            "install",
            wat_path.to_str().unwrap(),
            "--cap",
            "vfs.write",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cap mismatch"));
}

// ---------------------------------------------------------------------------
// `bloom chain init` — review 2026-05-19 #9
// ---------------------------------------------------------------------------

/// `chain init` must refuse to overwrite an existing `validator.xdsa` unless
/// `--force` is passed. Pre-fix the second invocation would silently
/// generate a fresh keypair and clobber the operator's existing secret.
#[test]
fn chain_init_refuses_to_overwrite_validator_key_without_force() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["chain", "init"])
        .assert()
        .success();
    let key_path = home
        .path()
        .join("chain")
        .join("keystore")
        .join("validator.xdsa");
    let first = std::fs::read(&key_path).expect("first init wrote a key");

    bloom_cmd(home.path())
        .args(["chain", "init"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"))
        .stderr(predicate::str::contains("--force"));

    let after_fail = std::fs::read(&key_path).expect("key still present after refused re-init");
    assert_eq!(
        first, after_fail,
        "refused chain init must not have touched the existing key"
    );

    bloom_cmd(home.path())
        .args(["chain", "init", "--force"])
        .assert()
        .success();
    let forced = std::fs::read(&key_path).expect("forced init wrote a key");
    assert_ne!(
        first, forced,
        "--force must mint a fresh keypair (replacing the previous bytes)"
    );
}

/// On Unix, the freshly written validator secret must be mode 0o600 — no
/// group / world read or write. Pre-fix the file landed with umask-default
/// 0644 and a malicious group member could lift the secret.
#[cfg(unix)]
#[test]
fn chain_init_writes_validator_key_with_mode_0600() {
    use std::os::unix::fs::PermissionsExt;

    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["chain", "init"])
        .assert()
        .success();
    let key_path = home
        .path()
        .join("chain")
        .join("keystore")
        .join("validator.xdsa");
    let mode = std::fs::metadata(&key_path)
        .expect("stat validator.xdsa")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "validator.xdsa must be mode 0o600, got 0o{mode:o}"
    );

    // `--force` re-init must also leave the file at 0o600, not whatever the
    // pre-existing mode was.
    bloom_cmd(home.path())
        .args(["chain", "init", "--force"])
        .assert()
        .success();
    let mode_after_force = std::fs::metadata(&key_path)
        .expect("stat validator.xdsa after --force")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode_after_force, 0o600);
}

/// `chain testnet` writes per-validator key files in fresh `home<i>/chain/`
/// directories. Those files must also be mode 0o600 on Unix.
#[cfg(unix)]
#[test]
fn chain_testnet_writes_validator_keys_with_mode_0600() {
    use std::os::unix::fs::PermissionsExt;

    let home = fresh_home();
    let outdir = home.path().join("testnet");
    bloom_cmd(home.path())
        .args([
            "chain",
            "testnet",
            "--validators",
            "2",
            "--output-dir",
            outdir.to_str().unwrap(),
        ])
        .assert()
        .success();
    let genesis = std::fs::read_to_string(outdir.join("home0").join("chain").join("genesis.toml"))
        .expect("read generated genesis.toml");
    assert!(
        genesis.contains("[[petals]]")
            && genesis.contains(r#"path = "/bloom/petals/core/fungible""#)
            && genesis.contains("wasm_hex = \"00"),
        "generated funded genesis must bind the core fungible petal"
    );
    for i in 0..2u8 {
        let key = outdir
            .join(format!("home{i}"))
            .join("chain")
            .join("keystore")
            .join("validator.xdsa");
        let mode = std::fs::metadata(&key)
            .unwrap_or_else(|e| panic!("stat {}: {e}", key.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode,
            0o600,
            "{} must be mode 0o600, got 0o{mode:o}",
            key.display()
        );
    }
}
