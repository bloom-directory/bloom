//! CLI smoke tests for the `bloom` binary.
//!
//! Each test allocates a fresh `tempfile::tempdir()` home and invokes the
//! built `bloom` binary via `assert_cmd::Command::cargo_bin`. We exercise
//! the local one-shot path for status / vfs / wallet, and stand up an
//! in-process `IpcServer` to verify the "socket exists → route via IPC"
//! branch in the CLI's vfs subcommand.

use std::path::Path;
use std::time::Duration;

use assert_cmd::Command;
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
        .stdout(predicate::str::contains("serve"))
        .stdout(predicate::str::contains("ipc"))
        .stdout(predicate::str::contains("init"));
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
fn wallet_new_then_list_round_trip() {
    let home = fresh_home();
    let create = bloom_cmd(home.path())
        .args(["wallet", "new", "alice", "--passphrase", "smoke-test-pass"])
        .assert()
        .success();
    let create_out = String::from_utf8(create.get_output().stdout.clone()).unwrap();
    assert!(
        create_out.contains("created wallet 'alice'"),
        "unexpected create output: {create_out}"
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
fn wallet_new_via_env_passphrase() {
    // BLOOM_PASSPHRASE feeds the same arg via env. Confirms the env path
    // works and that the wallet ends up in the keystore directory on disk.
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["wallet", "new", "bob"])
        .env("BLOOM_PASSPHRASE", "env-pass-1")
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
}

/// Spin up an in-process `IpcServer` bound to the home's default socket
/// path, then invoke the CLI so its `vfs` subcommand routes through IPC.
/// The CLI's local-vs-IPC selection keys solely off `socket.exists()`, so
/// proving the IPC branch reduces to seeing data we know only the server
/// would produce.
#[test]
fn vfs_routes_via_ipc_when_socket_exists() {
    use bloom_daemon::ipc::{IpcServer, default_socket_path};
    use bloom_vfs::handler::{Entry, Handler, HandlerError};
    use bloom_vfs::{Vfs, VfsPath};

    // A trivial in-memory handler that the production daemon never mounts;
    // if the CLI's `vfs ls /probe` returns this entry, the request must
    // have gone through our test server.
    struct ProbeHandler;
    #[async_trait::async_trait]
    impl Handler for ProbeHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            if p.is_root() {
                Ok(Entry::dir(""))
            } else if p.segments().len() == 1 && p.segments()[0] == "marker" {
                Ok(Entry::file("marker"))
            } else {
                Err(HandlerError::not_found(p.to_string_path()))
            }
        }
        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![Entry::file("marker")])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
        async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            Ok(b"ipc-only-marker\n".to_vec())
        }
    }

    let home = fresh_home();
    let socket = default_socket_path(home.path());
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();

    let vfs = Vfs::builder()
        .mount("probe", std::sync::Arc::new(ProbeHandler))
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
