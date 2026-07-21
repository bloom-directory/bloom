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
use std::time::{Duration, UNIX_EPOCH};

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

fn write_file(root: &Path, rel: &str, body: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).expect("create fixture parent");
    std::fs::write(path, body).expect("write fixture file");
}

fn write_demo_petal_package(root: &Path) {
    write_file(
        root,
        "petal.toml",
        br#"schema = "bloom.petal.package.v1"
name = "demo"

[consent]
summary = "Demo app used by CLI tests."
"#,
    );
    write_file(root, "README.md", b"# demo\n");
    write_file(root, "AGENTS.md", b"# demo agents\n");
    write_file(
        root,
        "petal/demo/hello.txt.wasm",
        include_bytes!("../../bloom-petals/tests/fixtures/route_component_no_imports.wasm"),
    );
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

struct FixedStatHandler;

#[async_trait]
impl Handler for FixedStatHandler {
    async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
        if p.is_root() {
            return Ok(Entry::dir(""));
        }
        let mut entry = Entry::read_only_file("meta");
        entry.size = 42;
        Ok(entry.with_modified(UNIX_EPOCH + Duration::from_millis(1_700_000_000_123)))
    }

    async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if p.is_root() {
            Ok(vec![Entry::read_only_file("meta").with_modified(
                UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
            )])
        } else {
            Err(HandlerError::NotADir(p.to_string_path()))
        }
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
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("polymarket").not());
}

#[test]
fn init_respects_persistent_preinstalled_petal_opt_out_without_network() {
    let home = fresh_home();
    let home_dir = bloom_proto::HomeDir::at(home.path());
    let mut config = bloom_proto::Config::local_default();
    config.petals.preinstalled.clear();
    config.save(&home_dir.config_path()).unwrap();

    bloom_cmd(home.path())
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("preinstalled_petals: []"));

    bloom_cmd(home.path())
        .args(["petals", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(no petals installed)"));
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
fn wallet_help_lists_outbox_cancel_and_replace() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["wallet", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("cancel"))
        .stdout(predicate::str::contains("replace"))
        .stdout(predicate::str::contains("confirm"));
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
        .stdout(predicate::str::contains("chains: "));
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
    assert!(
        !out.lines().any(|line| line.starts_with("polymarket\t")),
        "native polymarket handler must not be mounted:\n{out}"
    );
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
    assert!(
        text.contains("cat docs/README.md"),
        "guidance should use mounted filesystem examples"
    );
    assert!(
        !text.contains("bloom vfs"),
        "guidance should not mention the bloom vfs CLI"
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
    for required in ["version", "uptime", "started_at", "chains", "audit"] {
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
fn vfs_stat_reports_metadata_without_mount() {
    let home = fresh_home();
    let out = bloom_cmd(home.path())
        .args(["vfs", "stat", "/status/version"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("path: /status/version"), "{stdout}");
    assert!(stdout.contains("name: version"), "{stdout}");
    assert!(stdout.contains("kind: file"), "{stdout}");
    assert!(stdout.contains("mode: 0444"), "{stdout}");
    assert!(stdout.contains("size: 0"), "{stdout}");
    assert!(stdout.contains("modified_ms: "), "{stdout}");
    assert!(stdout.contains("modified: "), "{stdout}");
    assert!(
        stdout.contains("modified_source: synthetic_now"),
        "{stdout}"
    );
}

#[test]
fn vfs_stat_via_ipc_preserves_entry_modified_ms() {
    let home = fresh_home();
    let vfs = bloom_vfs::Vfs::builder()
        .mount("fixed", Arc::new(FixedStatHandler))
        .build();
    let (server, server_thread) = spawn_ipc_server(home.path(), vfs);

    let out = bloom_cmd(home.path())
        .args(["vfs", "stat", "/fixed/meta"])
        .assert()
        .success();

    stop_ipc_server(server, server_thread);

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("path: /fixed/meta"), "{stdout}");
    assert!(stdout.contains("name: meta"), "{stdout}");
    assert!(stdout.contains("kind: file"), "{stdout}");
    assert!(stdout.contains("mode: 0444"), "{stdout}");
    assert!(stdout.contains("size: 42"), "{stdout}");
    assert!(stdout.contains("modified_ms: 1700000000123"), "{stdout}");
    assert!(stdout.contains("modified_source: artifact"), "{stdout}");
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
fn vfs_ls_status_includes_update_subtree() {
    let home = fresh_home();
    let out = bloom_cmd(home.path())
        .args(["vfs", "ls", "/status"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("update"),
        "expected `update` in ls /status, got:\n{stdout}"
    );
}

#[test]
fn vfs_cat_status_update_installed_matches_pkg_version() {
    let home = fresh_home();
    let expected = format!("{}\n", env!("CARGO_PKG_VERSION"));
    bloom_cmd(home.path())
        .args(["vfs", "cat", "/status/update/installed"])
        .assert()
        .success()
        .stdout(predicate::eq(expected));
}

#[test]
fn vfs_cat_status_update_when_no_cache_reports_unknown() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["vfs", "cat", "/status/update/available"])
        .assert()
        .success()
        .stdout(predicate::eq("unknown\n"));
    bloom_cmd(home.path())
        .args(["vfs", "cat", "/status/update/latest"])
        .assert()
        .success()
        .stdout(predicate::eq("\n"));
    bloom_cmd(home.path())
        .args(["vfs", "cat", "/status/update/behind_by"])
        .assert()
        .success()
        .stdout(predicate::eq("0\n"));
}

#[test]
fn vfs_cat_status_update_with_seed_cache_reports_behind() {
    let home = fresh_home();
    let cache_dir = home.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let cache = serde_json::json!({
        "version": 1,
        "installed": "0.1.0",
        "latest": "0.2.0",
        "release_url": "https://github.com/bloom-directory/bloom/releases/tag/v0.2.0",
        "checked_at": null,
        "status": "ok"
    });
    std::fs::write(
        cache_dir.join("update_cache.json"),
        serde_json::to_vec_pretty(&cache).unwrap(),
    )
    .unwrap();
    bloom_cmd(home.path())
        .args(["vfs", "cat", "/status/update/latest"])
        .assert()
        .success()
        .stdout(predicate::eq("0.2.0\n"));
    bloom_cmd(home.path())
        .args(["vfs", "cat", "/status/update/available"])
        .assert()
        .success()
        .stdout(predicate::eq(
            if bloom_update::compare_semver(env!("CARGO_PKG_VERSION"), "0.2.0")
                == std::cmp::Ordering::Less
            {
                "out_of_date\n"
            } else {
                "up_to_date\n"
            },
        ));
}

#[test]
fn bloom_update_status_prints_cached_snapshot() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["update", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"installed\""))
        .stdout(predicate::str::contains("\"status\""));
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
fn init_refuses_when_home_write_lock_is_live() {
    let home = fresh_home();
    let _permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(home.path()))
        .expect("hold home write permit");
    let lock = home.path().join("run").join(".daemon.lock");

    bloom_cmd(home.path())
        .arg("init")
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
    use bloom_vfs::{Entry, Handler, HandlerError, Vfs, VfsPath};

    struct SingleFileHandler {
        name: String,
        body: Vec<u8>,
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
                [] => Ok(Entry::dir("probe")),
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

#[test]
fn wallet_confirm_uses_plain_ipc_write_when_socket_exists() {
    let home = fresh_home();
    let handler = RecordingWriteHandler::new();
    let vfs = bloom_vfs::Vfs::builder()
        .mount("wallets", handler.clone())
        .build();
    let (server, server_thread) = spawn_ipc_server(home.path(), vfs);

    bloom_cmd(home.path())
        .args([
            "wallet",
            "confirm",
            "alice",
            "base",
            "0001-deadbeef",
            "--text",
            "y",
        ])
        .assert()
        .success();

    stop_ipc_server(server, server_thread);

    let writes = handler.writes();
    assert_eq!(writes.len(), 1, "expected one VFS write, got {writes:?}");
    assert_eq!(
        writes[0].0,
        "/alice/chains/base/outbox/pending/0001-deadbeef/confirm"
    );
    assert_eq!(writes[0].1, b"y");
}

#[test]
fn petal_cli_build_install_list_and_vfs_read_happy_path() {
    let home = fresh_home();
    let work = tempfile::tempdir().expect("create package workdir");
    let package = work.path().join("demo-package");
    let archive = work.path().join("demo.petal.tar");
    write_demo_petal_package(&package);

    let package_arg = package.to_str().unwrap();
    let archive_arg = archive.to_str().unwrap();
    bloom_cmd(home.path())
        .args(["petals", "build", package_arg, "--out", archive_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("petal_mount: petals/demo/"))
        .stdout(predicate::str::contains("routes: 1"))
        .stdout(predicate::str::contains("archive: "));
    assert!(
        archive.is_file(),
        "build should write {}",
        archive.display()
    );

    bloom_cmd(home.path())
        .args(["petals", "install", archive_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("mode: petal"))
        .stdout(predicate::str::contains("petal_mount: petals/demo/"))
        .stdout(predicate::str::contains("routes: 1"));

    bloom_cmd(home.path())
        .args(["petals", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("app=petals/demo/"));

    bloom_cmd(home.path())
        .args(["vfs", "cat", "/petals/demo/hello.txt"])
        .assert()
        .success()
        .stdout(predicate::eq("component"));

    bloom_cmd(home.path())
        .args(["vfs", "cat", "/petals/demo/README.md"])
        .assert()
        .success()
        .stdout(predicate::str::contains("# demo"));
}

#[test]
#[ignore = "clones and builds the public Polymarket Petal source repo"]
fn github_source_install_polymarket_dispatches_route_contract() {
    let petal_ref = "e2e898b69046c9f5d905dd2cd66b3a57ef195542";
    let home = fresh_home();
    let home_dir = bloom_proto::HomeDir::at(home.path());
    let mut config = bloom_proto::Config::local_default();
    config.petals.preinstalled.clear();
    config.save(&home_dir.config_path()).unwrap();

    bloom_cmd(home.path())
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("preinstalled_petals: []"));

    bloom_cmd(home.path())
        .args([
            "petals",
            "install",
            "https://github.com/bloom-directory/bloom-petal-polymarket",
            "--ref",
            petal_ref,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "Resolved commit: {petal_ref}"
        )))
        .stdout(predicate::str::contains("\"routes\": 95"));

    bloom_cmd(home.path())
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("preinstalled_petals: []"));

    bloom_cmd(home.path())
        .args(["petals", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "source=bloom-directory/bloom-petal-polymarket@{petal_ref}"
        )));

    bloom_cmd(home.path())
        .args(["vfs", "cat", "/petals/polymarket/meta/route-contract.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "bloom.polymarket.petal-route-contract.v1",
        ));

    bloom_cmd(home.path())
        .args(["vfs", "cat", "/petals/polymarket/README.md"])
        .assert()
        .success()
        .stdout(predicate::str::contains("# Polymarket Petal"));
}

#[test]
fn petals_install_rejects_untrusted_owner_and_raw_remote_wasm() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["petals", "install", "https://github.com/not-bloom/petal"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported GitHub owner"));

    bloom_cmd(home.path())
        .args([
            "petals",
            "install",
            "https://github.com/bloom-directory/petal/raw/main/route.wasm",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "raw remote .wasm installs are not supported",
        ));
}
