//! Category: CLI-subprocess
//!
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

fn write_file(root: &Path, rel: &str, body: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).expect("create fixture parent");
    std::fs::write(path, body).expect("write fixture file");
}

fn write_demo_v2_package(root: &Path) {
    write_file(
        root,
        "petal.toml",
        br#"schema = "bloom.petal.local-app.v2"
name = "demo"

[consent]
summary = "Demo app used by CLI tests."
"#,
    );
    write_file(root, "README.md", b"# demo\n");
    write_file(root, "AGENTS.md", b"# demo agents\n");
    write_file(
        root,
        "app/demo/hello.txt.wasm",
        include_bytes!("../../bloom-petals/tests/fixtures/route_component_no_imports.wasm"),
    );
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
fn v2_app_cli_build_install_list_and_vfs_read_happy_path() {
    let home = fresh_home();
    let work = tempfile::tempdir().expect("create package workdir");
    let package = work.path().join("demo-package");
    let archive = work.path().join("demo.petal.tar");
    write_demo_v2_package(&package);

    let package_arg = package.to_str().unwrap();
    let archive_arg = archive.to_str().unwrap();
    bloom_cmd(home.path())
        .args(["petal", "app", "build", package_arg, "--out", archive_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("app_mount: apps/demo/"))
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
        .stdout(predicate::str::contains("mode: local-app"))
        .stdout(predicate::str::contains("app_mount: apps/demo/"))
        .stdout(predicate::str::contains("routes: 1"));

    bloom_cmd(home.path())
        .args(["petals", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("app=apps/demo/"));

    bloom_cmd(home.path())
        .args(["vfs", "cat", "/apps/demo/hello.txt"])
        .assert()
        .success()
        .stdout(predicate::eq("component"));
}

#[test]
#[ignore = "clones and builds the public Polymarket Petal source repo"]
fn github_source_install_polymarket_dispatches_parity() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args([
            "petals",
            "install",
            "https://github.com/bloom-directory/bloom-petal-polymarket",
            "--ref",
            "v0.1.1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Selected tag: v0.1.1"))
        .stdout(predicate::str::contains(
            "source: bloom-directory/bloom-petal-polymarket@v0.1.1",
        ))
        .stdout(predicate::str::contains("routes: 67"));

    bloom_cmd(home.path())
        .args(["petals", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "source=bloom-directory/bloom-petal-polymarket@v0.1.1",
        ));

    bloom_cmd(home.path())
        .args(["vfs", "cat", "/apps/polymarket/meta/parity.json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("polymarket_v2_petal_parity"));
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
