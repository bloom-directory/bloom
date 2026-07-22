//! Category: CLI-subprocess
//!
//! Regression test for the exact two-terminal flow the asynchronous passkey
//! registration protocol fixes (see
//! `docs/plans/2026-07-21-async-vfs-passkey-registration.md`):
//!
//! ```sh
//! # terminal 1
//! bloom serve
//!
//! # terminal 2
//! bloom vfs write --data "test" /wallets/new
//! ```
//!
//! Before this change, the daemon's IPC write handler called
//! `Keystore::create_passkey`, which tried to bind a second listener on the
//! same fixed loopback port `bloom serve` already owns for its Sealed
//! Approval ceremony server — `Address already in use`. This test spawns a
//! real `bloom serve` subprocess, waits for its IPC socket *and* its
//! ceremony listener to be live, then runs `bloom vfs write` against that
//! same home and asserts the whole flow succeeds without a second bind.
//!
//! This test binds the real, fixed `LOCAL_CEREMONY_PORT` (18734) — it must
//! not run concurrently with another instance of itself or with a real
//! `bloom serve` on the same machine. Every test in this file that spawns a
//! `bloom serve` subprocess acquires [`PORT_18734_LOCK`] first so they never
//! race each other for the port under `cargo test`'s default parallelism.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use tempfile::TempDir;

const LOCAL_CEREMONY_PORT: u16 = 18734;

/// Held for the duration of any test that binds the real, fixed
/// `LOCAL_CEREMONY_PORT` via a spawned `bloom serve` subprocess.
static PORT_18734_LOCK: Mutex<()> = Mutex::new(());

fn fresh_home() -> TempDir {
    tempfile::tempdir().expect("create temp home")
}

/// Kills the child `bloom serve` process on drop, so a panicking assertion
/// never leaks a background daemon holding port 18734.
struct ServeGuard {
    child: Child,
}

impl Drop for ServeGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_serve(home: &Path) -> ServeGuard {
    let child = Command::new(assert_cmd::cargo::cargo_bin("bloom"))
        .env("BLOOM_HOME", home)
        .env("RUST_LOG", "error")
        .arg("serve")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bloom serve");
    ServeGuard { child }
}

fn wait_for_socket(home: &Path) {
    let socket = home.join("run").join("bloom.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        if Instant::now() >= deadline {
            panic!(
                "bloom serve never created its IPC socket at {}",
                socket.display()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Waits until the daemon-owned loopback ceremony listener accepts
/// connections — i.e. `ceremony_server::spawn` has already bound the port
/// and (per the fix under test) armed the registration coordinator.
fn wait_for_ceremony_listener() {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", LOCAL_CEREMONY_PORT)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("bloom serve never bound the ceremony listener on {LOCAL_CEREMONY_PORT}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn bloom_cmd(home: &Path) -> AssertCommand {
    let mut cmd = AssertCommand::cargo_bin("bloom").expect("locate bloom binary");
    cmd.env("BLOOM_HOME", home);
    cmd.env("RUST_LOG", "error");
    cmd
}

#[test]
fn two_terminal_vfs_write_stages_without_port_conflict() {
    let _port_guard = PORT_18734_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let home = fresh_home();
    let mut guard = spawn_serve(home.path());
    wait_for_socket(home.path());
    wait_for_ceremony_listener();

    // The exact regression command: an IPC write to /wallets/new while
    // `bloom serve` already owns the ceremony listener.
    bloom_cmd(home.path())
        .args(["vfs", "write", "--data", "test", "/wallets/new"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Address already in use").not());

    // The daemon subprocess must still be alive — a bind panic/crash inside
    // its IPC handler would have killed it.
    assert!(
        guard.child_still_running(),
        "bloom serve process exited after the write"
    );

    // status.json reflects a staged, live registration.
    bloom_cmd(home.path())
        .args(["vfs", "cat", "/wallets/registrations/test/status.json"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"state\": \"awaiting_user\"")
                .or(predicate::str::contains("\"state\":\"awaiting_user\"")),
        );

    // ceremony_url resolves on the already-bound listener (not a fallback
    // port, and not a fresh bind from this second command).
    let url_output = bloom_cmd(home.path())
        .args(["vfs", "cat", "/wallets/registrations/test/ceremony_url"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let url = String::from_utf8(url_output).expect("ceremony_url utf8");
    assert!(
        url.contains(&format!(":{LOCAL_CEREMONY_PORT}/wallet-registration/")),
        "unexpected ceremony_url: {url}"
    );
    let resp = std::net::TcpStream::connect(("127.0.0.1", LOCAL_CEREMONY_PORT));
    assert!(
        resp.is_ok(),
        "ceremony_url's listener is not reachable on the pre-bound port"
    );

    // Every response on this token-keyed route group — the page and all of
    // its JSON endpoints, including `/complete`'s one-time response
    // carrying the plaintext recovery key — must be marked uncacheable.
    // `page()` used to set this manually and the JSON endpoints never did
    // at all; it's now applied by a single layer over the whole group.
    let token_path = url
        .trim()
        .split_once(&format!(":{LOCAL_CEREMONY_PORT}"))
        .map(|(_, path)| path)
        .expect("ceremony_url must contain the ceremony port");
    let page_headers = http_get_response_head(token_path);
    assert!(
        page_headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "GET {token_path} missing no-store Cache-Control:\n{page_headers}"
    );
    let session_json_headers = http_get_response_head(&format!("{token_path}/session.json"));
    assert!(
        session_json_headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"),
        "GET {token_path}/session.json missing no-store Cache-Control:\n{session_json_headers}"
    );
}

/// Issues a raw `GET` on the pre-bound ceremony listener and returns the
/// response's status line + headers (everything up to the blank line
/// separating headers from body).
fn http_get_response_head(path: &str) -> String {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", LOCAL_CEREMONY_PORT))
        .expect("connect to ceremony listener");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .expect("write request");
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read response");
    buf.split("\r\n\r\n").next().unwrap_or(&buf).to_string()
}

/// In-process `bloom vfs write` (no daemon reachable) must fail closed
/// before staging anything — never fall back to an in-process ceremony
/// whose lifetime ends with the command, and never leave a dangling
/// registration record behind.
#[test]
fn in_process_write_without_daemon_fails_before_staging() {
    let home = fresh_home();

    bloom_cmd(home.path())
        .args(["vfs", "write", "--data", "solo", "/wallets/new"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("bloom serve"));

    bloom_cmd(home.path())
        .args(["vfs", "cat", "/wallets/registrations/solo/status.json"])
        .assert()
        .failure();
}

/// `wallet list` builds its own in-process `Daemon` unconditionally (it
/// never tries IPC — see `Cmd::Wallet(WalletCmd::List)`), which used to run
/// restart reconciliation as a side effect of construction and would mark a
/// live `bloom serve` registration `failed` purely because this second,
/// unrelated process had no in-memory session to compare against. Restart
/// reconciliation must instead run only in the process that actually binds
/// the shared ceremony listener — i.e. `bloom serve` itself, once, at
/// startup — so a concurrent read-only command must leave a live session
/// completely untouched.
#[test]
fn read_only_command_does_not_fail_a_live_serve_registration() {
    let _port_guard = PORT_18734_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let home = fresh_home();
    let mut guard = spawn_serve(home.path());
    wait_for_socket(home.path());
    wait_for_ceremony_listener();

    bloom_cmd(home.path())
        .args(["vfs", "write", "--data", "test", "/wallets/new"])
        .assert()
        .success();

    // A read-only command against the same home, while `bloom serve` is
    // still alive and still owns the ceremony listener. This constructs a
    // second, independent `Daemon` in-process.
    bloom_cmd(home.path())
        .args(["wallet", "list"])
        .assert()
        .success();

    assert!(
        guard.child_still_running(),
        "bloom serve process exited during the read-only command"
    );

    // The live session must still be `awaiting_user`, not `failed`.
    bloom_cmd(home.path())
        .args(["vfs", "cat", "/wallets/registrations/test/status.json"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"state\": \"awaiting_user\"")
                .or(predicate::str::contains("\"state\":\"awaiting_user\"")),
        );
}

trait ChildStillRunning {
    fn child_still_running(&mut self) -> bool;
}

impl ChildStillRunning for ServeGuard {
    fn child_still_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}
