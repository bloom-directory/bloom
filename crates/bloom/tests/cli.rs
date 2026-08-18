//! Category: CLI-subprocess
//!
//! CLI smoke tests for the `bloom` binary.
//!
//! Each test allocates a fresh `tempfile::tempdir()` home and invokes the
//! built `bloom` binary via `assert_cmd::Command::cargo_bin`. Runtime command
//! tests either start a real `bloom serve` process or a focused in-process IPC
//! fixture; missing-endpoint tests prove there is no one-shot fallback.

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
use base64::Engine as _;
use bloom_broker_api::{
    Base64UrlBytes, CanonicalWalletPolicy, CryptoSuite, DecimalU64, Digest32, KeyPublic, KeyRef,
    KeyRole, KeySpec, SignedPolicySnapshot, Token, WalletPublic,
};
use bloom_machine_client::{ProjectionFreshness, ProjectionVerification, WalletProjection};
use bloom_vfs::{Entry, Handler, HandlerError, VfsPath};
use predicates::prelude::*;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
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
    #[cfg(target_os = "macos")]
    return tempfile::Builder::new()
        .prefix("bloom-cli-test-")
        .tempdir_in("/private/tmp")
        .expect("create temp home");
    #[cfg(not(target_os = "macos"))]
    tempfile::tempdir().expect("create temp home")
}

fn ipc_endpoint_accepting(socket: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

struct RunningBloom(std::process::Child);

impl RunningBloom {
    fn start(home: &Path) -> Self {
        Self::start_with_automatic_update_checks(home, true)
    }

    fn start_without_automatic_update_checks(home: &Path) -> Self {
        Self::start_with_automatic_update_checks(home, false)
    }

    fn start_with_automatic_update_checks(home: &Path, automatic_update_checks: bool) -> Self {
        let home_dir = bloom_proto::HomeDir::at(home);
        let mut config = if home_dir.config_path().is_file() {
            bloom_proto::Config::load(&home_dir.config_path()).unwrap()
        } else {
            bloom_proto::Config::local_default()
        };
        config.petals.preinstalled.clear();
        config.save(&home_dir.config_path()).unwrap();
        let binary = Command::cargo_bin("bloom").expect("locate bloom binary");
        let mut command = std::process::Command::new(binary.get_program());
        command
            .env("BLOOM_HOME", home)
            .env("RUST_LOG", "error")
            .arg("serve")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        if !automatic_update_checks {
            command.env(bloom_update::DISABLE_AUTO_CHECK_ENV, "1");
        }
        let mut child = command.spawn().expect("start Bloom daemon for CLI test");
        let socket = bloom_daemon::ipc::default_socket_path(home);
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if ipc_endpoint_accepting(&socket) {
                return Self(child);
            }
            if child.try_wait().expect("poll Bloom daemon").is_some() {
                let mut stderr = String::new();
                child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .unwrap();
                panic!(
                    "Bloom daemon exited before creating {}: {stderr}",
                    socket.display()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        panic!(
            "Bloom daemon did not accept connections at {} within 30 seconds: {stderr}",
            socket.display()
        );
    }
}

impl Drop for RunningBloom {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn every_non_lifecycle_command_family_requires_the_daemon_endpoint() {
    let home = fresh_home();
    let operation_id = "11".repeat(32);
    let commands: Vec<Vec<&str>> = vec![
        vec!["status"],
        vec!["audit", "status"],
        vec!["vfs", "ls", "/"],
        vec!["wallet", "unlock", "alice"],
        vec!["ceremony", "status", &operation_id],
        vec!["operation", "status", &operation_id],
        vec!["request", "plan", "latest"],
        vec!["ipc", "call", "version"],
        vec!["petals", "ls"],
        vec!["update", "status"],
        vec!["completions", "bash"],
    ];
    for args in commands {
        bloom_cmd(home.path())
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Bloom daemon endpoint"))
            .stderr(predicate::str::contains("bloom serve"))
            .stderr(predicate::str::contains("already open for writing").not());
    }
}

#[test]
fn version_reports_the_cli_when_the_daemon_is_unavailable() {
    let home = fresh_home();
    let expected = format!(
        "bloom {}\nbloom-daemon unavailable\nbloom-ipc {} (not negotiated)\n",
        env!("CARGO_PKG_VERSION"),
        bloom_daemon::ipc::IPC_PROTOCOL_CURRENT,
    );

    bloom_cmd(home.path())
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::eq(expected));
}

#[test]
fn version_reports_cli_daemon_and_negotiated_ipc_versions() {
    let home = fresh_home();
    let (server, server_thread) = spawn_ipc_server(home.path(), bloom_vfs::Vfs::new());
    let protocol = bloom_daemon::ipc::IPC_PROTOCOL_CURRENT;
    let expected = format!(
        "bloom {}\nbloom-daemon ipc-test-version\nbloom-ipc {protocol} (compatible; cli {protocol}, daemon {protocol})\n",
        env!("CARGO_PKG_VERSION"),
    );

    bloom_cmd(home.path())
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::eq(expected));

    stop_ipc_server(server, server_thread);
}

#[cfg(target_os = "macos")]
#[test]
fn global_session_agent_exits_successfully_for_an_unenrolled_login() {
    let root = tempfile::tempdir().expect("create isolated sentinel roots");
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["serve", "session-sentinel"])
        .env("BLOOM_ENROLLMENT_ROOT", root.path().join("enrollments"))
        .env("BLOOM_CONFIG_ROOT", root.path().join("config"))
        .env("BLOOM_RUNTIME_ROOT", root.path().join("runtime"))
        .assert()
        .success();
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

/// Seed a pre-migration wallet solely as a read/staging fixture. Production
/// CLI custody commands must never call these keystore creation methods.
fn seed_legacy_wallet_fixture(home: &Path, name: &str) {
    // Deliberately malformed-but-present pre-triad state. The production CLI
    // must ignore the directory without linking the retired keystore parser.
    write_file(
        home,
        &format!("keystore/{name}/wallet.json"),
        b"legacy authority state must remain opaque",
    );
}

/// Seed the authenticated, key-free public projection cache that production
/// Machine uses while Broker is unavailable. This deliberately contains only
/// public key metadata and a Broker-authenticated policy snapshot.
fn seed_wallet_projection_fixture(home: &Path, name: &str) {
    #[derive(Serialize)]
    struct ProjectionDigestInput<'a> {
        schema: &'static str,
        wallet: &'a WalletPublic,
        keys: &'a [KeyPublic],
        credentials: &'a [bloom_broker_api::CredentialPublic],
        policy: &'a SignedPolicySnapshot,
    }

    let wallet_id = Token::new(name.to_owned()).expect("valid fixture wallet ID");
    let key_ref = KeyRef {
        backend: Token::new("local").unwrap(),
        backend_instance: Token::new("primary").unwrap(),
        locator: format!("{name}/root"),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: Digest32::from_bytes([3; 32]),
        derivation: None,
    };
    let canonical_policy = serde_jcs::to_vec(&CanonicalWalletPolicy {
        wallet_id: wallet_id.clone(),
        maximum_approval_lifetime_ms: 300_000,
        allowed_petal_packages: Vec::new(),
        allowed_destinations: Vec::new(),
        required_verifiers: Vec::new(),
    })
    .expect("canonicalize fixture policy");
    let policy_digest = Digest32::from_bytes(Sha256::digest(&canonical_policy).into());
    let wallet = WalletPublic {
        wallet_id: wallet_id.clone(),
        wallet_kind: Token::new("passkey").unwrap(),
        root_key_ref: Some(key_ref.clone()),
        key_refs: vec![key_ref.clone()],
        policy_version: DecimalU64::new(1),
        policy_digest: policy_digest.clone(),
        wallet_revocation_epoch: DecimalU64::new(0),
    };
    let keys = vec![KeyPublic {
        key_ref,
        role: KeyRole::WalletRoot,
        canonical_public_key: Base64UrlBytes::from_bytes(&[4; 33]),
        addresses: vec!["0x0000000000000000000000000000000000000001".into()],
        supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
    }];
    let credentials = Vec::new();
    let policy = SignedPolicySnapshot {
        wallet_id,
        version: DecimalU64::new(1),
        canonical_policy: Base64UrlBytes::from_bytes(&canonical_policy),
        policy_digest,
        policy_signing_key_id: Token::new("policy-key").unwrap(),
        policy_verifying_key: Base64UrlBytes::from_bytes(&[5; 32]),
        signer_signature: Base64UrlBytes::from_bytes(&[6; 64]),
    };
    let response_digest = Digest32::from_bytes(
        Sha256::digest(
            serde_jcs::to_vec(&ProjectionDigestInput {
                schema: "bloom.machine-wallet-projections.v1",
                wallet: &wallet,
                keys: &keys,
                credentials: &credentials,
                policy: &policy,
            })
            .expect("canonicalize fixture projection"),
        )
        .into(),
    );
    let projection = WalletProjection {
        wallet,
        keys,
        credentials,
        policy,
        source_protocol: "bloom.machine-broker.v1".into(),
        response_digest,
        observed_at_ms: 1,
        freshness: ProjectionFreshness::Fresh,
        verification: ProjectionVerification::AuthenticatedBroker,
    };
    write_file(
        home,
        "cache/wallet-projections.json",
        &serde_json::to_vec(&serde_json::json!({
            "schema": "bloom.machine-wallet-projections.v1",
            "wallets": {
                name: {
                    "state": "live",
                    "projection": projection,
                }
            }
        }))
        .expect("encode fixture projection cache"),
    );
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
        if p.segments()
            .last()
            .is_some_and(|segment| segment == "latest")
        {
            let sequence = self.writes.lock().unwrap().len();
            let target = if p.segments().iter().any(|segment| segment == "outbox") {
                format!("pending/tx-{sequence}")
            } else {
                format!("pending/request-{sequence}")
            };
            return Ok(Entry::symlink("latest", &target));
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
    while !ipc_endpoint_accepting(&socket) {
        if std::time::Instant::now() >= deadline {
            panic!("ipc server never created socket at {}", socket.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    (server, server_thread)
}

struct FixedBatchConfirmation;

#[derive(Default)]
struct RecordingMachineCommands {
    commands: Mutex<Vec<bloom_daemon::ipc::MachineCommand>>,
}

impl RecordingMachineCommands {
    fn commands(&self) -> Vec<bloom_daemon::ipc::MachineCommand> {
        self.commands.lock().unwrap().clone()
    }
}

impl bloom_daemon::ipc::MachineCommandService for RecordingMachineCommands {
    fn execute(
        &self,
        command: bloom_daemon::ipc::MachineCommand,
    ) -> bloom_daemon::ipc::MachineCommandFuture<'_> {
        let stdout = match &command {
            bloom_daemon::ipc::MachineCommand::WalletOutboxCancel { id, .. } => {
                format!("cancel submitted for {id}\n")
            }
            bloom_daemon::ipc::MachineCommand::WalletOutboxReplace { id, .. } => {
                format!("replacement submitted for {id}\n")
            }
            _ => String::new(),
        };
        self.commands.lock().unwrap().push(command);
        Box::pin(async move {
            Ok(bloom_daemon::ipc::MachineCommandOutput {
                stdout,
                stderr: String::new(),
                exit_code: 0,
            })
        })
    }
}

impl bloom_daemon::ipc::BatchConfirmationService for FixedBatchConfirmation {
    fn confirm_batch<'a>(
        &'a self,
        request: bloom_daemon::ipc::BatchConfirmIpcRequest,
    ) -> bloom_daemon::ipc::BatchConfirmFuture<'a> {
        Box::pin(async move {
            Ok(serde_json::json!({
                "operation_id": "batch-operation-id",
                "signer_receipt_digest": "signer-receipt-digest",
                "broker_receipt_digest": "broker-receipt-digest",
                "wallet": request.wallet,
                "txs": request.txs,
                "confirmation_text": request.text,
            }))
        })
    }
}

fn spawn_batch_ipc_server(
    home: &Path,
) -> (bloom_daemon::ipc::IpcServer, std::thread::JoinHandle<()>) {
    use bloom_daemon::ipc::{IpcServer, default_socket_path};

    let socket = default_socket_path(home);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let server = IpcServer::new(
        bloom_vfs::Vfs::builder().build(),
        "ipc-test-version",
        vec![],
    )
    .with_batch_confirmation(Arc::new(FixedBatchConfirmation));
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
    while !ipc_endpoint_accepting(&socket) {
        assert!(
            std::time::Instant::now() < deadline,
            "batch IPC server never created socket at {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    (server, server_thread)
}

fn spawn_machine_ipc_server(
    home: &Path,
    service: Arc<RecordingMachineCommands>,
) -> (bloom_daemon::ipc::IpcServer, std::thread::JoinHandle<()>) {
    use bloom_daemon::ipc::{IpcServer, default_socket_path};

    let socket = default_socket_path(home);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let server = IpcServer::new(bloom_vfs::Vfs::new(), "ipc-test-version", vec![])
        .with_machine_commands(service);
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
    while !ipc_endpoint_accepting(&socket) {
        assert!(
            std::time::Instant::now() < deadline,
            "Machine IPC server never created socket at {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    (server, server_thread)
}

fn spawn_petals_ipc_server(
    home: &Path,
) -> (bloom_daemon::ipc::IpcServer, std::thread::JoinHandle<()>) {
    use bloom_daemon::ipc::{IpcServer, default_socket_path};

    let socket = default_socket_path(home);
    let store = bloom_petals::PetalStore::open(home.join("petals/store")).unwrap();
    let registry =
        Arc::new(bloom_petals::NameRegistry::open(home.join("petals/registry")).unwrap());
    let runner =
        bloom_petals::PetalRunner::new(store, registry, bloom_petals::PetalVm::new().unwrap());
    let server = IpcServer::new(
        bloom_vfs::Vfs::builder().build(),
        "ipc-test-version",
        vec![],
    )
    .with_petals(runner)
    .with_petal_source_installer(Arc::new(TestPetalSourceInstaller));
    let server_for_thread = server.clone();
    let socket_for_thread = socket.clone();
    let server_thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                server_for_thread.serve(&socket_for_thread).await.unwrap();
            });
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ipc_endpoint_accepting(&socket) {
        assert!(
            std::time::Instant::now() < deadline,
            "Petal IPC server never created socket at {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    (server, server_thread)
}

struct TestPetalSourceInstaller;

impl bloom_daemon::ipc::PetalSourceInstallService for TestPetalSourceInstaller {
    fn install_source(
        &self,
        params: serde_json::Value,
        _context: bloom_daemon::ipc::IpcOperationContext,
    ) -> Result<serde_json::Value, String> {
        let path = params["path"].as_str().unwrap_or_default();
        if path.contains("github.com/not-bloom/") {
            return Err("unsupported GitHub owner".to_owned());
        }
        if path.contains("/raw/") || path.ends_with(".wasm") {
            return Err("raw remote .wasm installs are not supported".to_owned());
        }
        if path == "https://github.com/bloom-directory/demo" {
            return Ok(serde_json::json!({
            "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "mode": "petal",
            "size": 42,
            "already_present": false,
            "petal_mount": "petals/demo/",
            "routes": 1,
            "source": "bloom-directory/demo@v1.0.0",
            "resolved_commit": "0123456789abcdef",
                "progress_lines": [
                    "Resolving https://github.com/bloom-directory/demo",
                    "Selected tag: v1.0.0",
                    "Resolved commit: 0123456789abcdef",
                    "Building source package..."
                ],
                "build_stdout_b64": base64::engine::general_purpose::STANDARD.encode(b"{\"routes\": 95}\n"),
                "build_stderr_b64": base64::engine::general_purpose::STANDARD.encode(b"build warning\n"),
                "completion_progress_lines": ["Validating Petal package..."],
                "consent_lines": ["consent:", "  docs: README.md"]
            }));
        }
        if path == "https://github.com/bloom-directory/failing-demo" {
            let output = std::process::Command::new("sh")
                .args([
                    "-c",
                    "echo 'partial build output'; echo 'build exploded' >&2; exit 42",
                ])
                .output()
                .map_err(|error| error.to_string())?;
            return Ok(serde_json::json!({
                "progress_lines": [
                    "Resolving https://github.com/bloom-directory/failing-demo",
                    "Resolved commit: deadbeef",
                    "Building source package..."
                ],
                "build_stdout_b64": base64::engine::general_purpose::STANDARD.encode(&output.stdout),
                "build_stderr_b64": base64::engine::general_purpose::STANDARD.encode(&output.stderr),
                "operation_error": format!("build command failed: scripts/build.sh (status {})", output.status),
            }));
        }
        Err("network source installs are disabled in CLI tests".to_owned())
    }
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

fn spawn_bloom_serve(home: &Path) -> std::process::Child {
    let binary = Command::cargo_bin("bloom")
        .expect("locate bloom binary")
        .get_program()
        .to_owned();
    let mut child = std::process::Command::new(binary)
        .env("BLOOM_HOME", home)
        .env("RUST_LOG", "error")
        .arg("serve")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn bloom serve");
    let socket = bloom_daemon::ipc::default_socket_path(home);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !ipc_endpoint_accepting(&socket) {
        assert!(
            child.try_wait().unwrap().is_none(),
            "bloom serve exited before binding {}",
            socket.display()
        );
        assert!(
            std::time::Instant::now() < deadline,
            "bloom serve did not bind {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    child
}

fn stop_bloom_serve(home: &Path, mut child: std::process::Child) {
    bloom_cmd(home)
        .args(["ipc", "call", "shutdown"])
        .assert()
        .success();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            return;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().expect("kill stuck bloom serve");
            panic!("bloom serve did not stop after shutdown RPC");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
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

    let (server, server_thread) = spawn_petals_ipc_server(home.path());
    bloom_cmd(home.path())
        .args(["petals", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(no petals installed)"));
    stop_ipc_server(server, server_thread);
}

#[test]
fn vfs_write_help_exposes_no_unlock_or_secret_flags() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["vfs", "write", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--unlock-wallet").not())
        .stdout(predicate::str::contains("--passphrase").not());
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
    let _daemon = RunningBloom::start(home.path());
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
    let _daemon = RunningBloom::start(home.path());
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
    let _daemon = RunningBloom::start(home.path());
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
fn docs_petals_discovers_installed_package_from_manifest() {
    let home = fresh_home();
    let package = home.path().join("demo-petal");
    write_demo_petal_package(&package);
    let (server, server_thread) = spawn_petals_ipc_server(home.path());
    bloom_cmd(home.path())
        .args(["petals", "install", package.to_str().unwrap()])
        .assert()
        .success();
    stop_ipc_server(server, server_thread);
    let _daemon = RunningBloom::start(home.path());

    bloom_cmd(home.path())
        .args(["vfs", "cat", "/docs/petals.md"])
        .assert()
        .success()
        .stdout(predicate::str::contains("## `demo`"))
        .stdout(predicate::str::contains("`petals/demo/`"))
        .stdout(predicate::str::contains("Demo app used by CLI tests."))
        .stdout(predicate::str::contains("Declared capabilities: none"))
        .stdout(predicate::str::contains("`petals/demo/README.md`"));
}

#[test]
fn petals_commands_route_through_ipc_while_home_write_lock_is_live() {
    let home = fresh_home();
    let package = home.path().join("demo-petal");
    let archive = home.path().join("demo.petal.tar");
    write_demo_petal_package(&package);
    write_file(&package, "artifacts/routes/stale.wasm", b"stale route");
    write_file(&package, "artifacts/build-manifest.json", b"stale manifest");
    write_file(&package, "artifacts/keep.txt", b"preserve me");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            package.join("artifacts/keep.txt"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let keep_before = std::fs::metadata(package.join("artifacts/keep.txt")).unwrap();
    let _permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(home.path()))
        .expect("hold home write permit as the running daemon would");
    let (server, server_thread) = spawn_petals_ipc_server(home.path());

    bloom_cmd(home.path())
        .args(["petals", "install", package.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("already open for writing").not())
        .stdout(predicate::str::contains("petal_mount: petals/demo/"));

    bloom_cmd(home.path())
        .args(["petals", "ls"])
        .assert()
        .success()
        .stderr(predicate::str::contains("already open for writing").not())
        .stdout(predicate::str::contains("app=petals/demo/"));

    bloom_cmd(home.path())
        .args([
            "petals",
            "build",
            package.to_str().unwrap(),
            "--out",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("already open for writing").not())
        .stdout(predicate::str::contains("archive:"));
    assert!(
        archive.is_file(),
        "daemon should write the requested archive"
    );
    assert_eq!(
        std::fs::read(package.join("artifacts/routes/r000001.wasm")).unwrap(),
        std::fs::read(package.join("petal/demo/hello.txt.wasm")).unwrap(),
        "daemon-generated route artifact must be materialized into the caller package"
    );
    assert!(
        !package.join("artifacts/routes/stale.wasm").exists(),
        "stale generated routes must be replaced"
    );
    assert_eq!(
        std::fs::read(package.join("artifacts/keep.txt")).unwrap(),
        b"preserve me",
        "unrelated artifact files must retain the builder's replacement semantics"
    );
    let keep_after = std::fs::metadata(package.join("artifacts/keep.txt")).unwrap();
    assert_eq!(
        keep_after.modified().unwrap(),
        keep_before.modified().unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        assert_eq!(keep_after.ino(), keep_before.ino());
        assert_eq!(keep_after.permissions().mode() & 0o777, 0o600);
    }

    bloom_cmd(home.path())
        .args(["petals", "uninstall", "demo"])
        .assert()
        .success()
        .stderr(predicate::str::contains("already open for writing").not())
        .stdout(predicate::str::contains("removed demo"));

    stop_ipc_server(server, server_thread);
}

#[test]
fn petals_commands_fail_against_an_explicit_missing_endpoint() {
    let home = fresh_home();
    let package = home.path().join("demo-petal");
    write_demo_petal_package(&package);
    let socket = home.path().join("run/missing-petals.sock");
    let endpoint = format!("unix:{}", socket.display());

    for args in [
        vec!["petals", "ls"],
        vec!["petals", "install", package.to_str().unwrap()],
        vec!["petals", "build", package.to_str().unwrap()],
        vec!["petals", "uninstall", "demo"],
    ] {
        bloom_cmd(home.path())
            .args(["--connect", &endpoint])
            .args(args)
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("ipc")
                    .and(predicate::str::contains(socket.display().to_string())),
            );
    }
}

#[cfg(unix)]
#[test]
fn petals_build_preserves_builder_symlink_rejection_semantics() {
    let home = fresh_home();
    let package = home.path().join("demo-petal");
    let outside = home.path().join("outside-artifacts");
    write_demo_petal_package(&package);
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"keep").unwrap();
    std::os::unix::fs::symlink(&outside, package.join("artifacts")).unwrap();
    let (server, server_thread) = spawn_petals_ipc_server(home.path());

    bloom_cmd(home.path())
        .args(["petals", "build", package.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("artifacts"));
    assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"keep");

    stop_ipc_server(server, server_thread);
}

#[test]
fn petals_relative_package_paths_are_resolved_from_the_cli_working_directory() {
    let home = fresh_home();
    let work = tempfile::tempdir().expect("create caller workdir");
    let package = work.path().join("demo-package");
    let archive = work.path().join("demo.petal.tar");
    write_demo_petal_package(&package);
    let (server, server_thread) = spawn_petals_ipc_server(home.path());

    bloom_cmd(home.path())
        .current_dir(work.path())
        .args(["petals", "build", "demo-package", "--out", "demo.petal.tar"])
        .assert()
        .success()
        .stdout(predicate::str::contains("archive: demo.petal.tar"));
    assert!(
        archive.is_file(),
        "relative --out must be written under the CLI working directory"
    );

    bloom_cmd(home.path())
        .current_dir(work.path())
        .args(["petals", "install", "demo.petal.tar"])
        .assert()
        .success()
        .stdout(predicate::str::contains("petal_mount: petals/demo/"));

    stop_ipc_server(server, server_thread);
}

#[test]
fn petals_source_install_prints_daemon_progress() {
    let home = fresh_home();
    let (server, server_thread) = spawn_petals_ipc_server(home.path());

    bloom_cmd(home.path())
        .args([
            "petals",
            "install",
            "https://github.com/bloom-directory/demo",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Resolving https://github.com/bloom-directory/demo",
        ))
        .stdout(predicate::str::contains("Selected tag: v1.0.0"))
        .stdout(predicate::str::contains(
            "Resolved commit: 0123456789abcdef",
        ))
        .stdout(predicate::str::contains("Building source package..."))
        .stdout(predicate::str::contains("{\"routes\": 95}"))
        .stderr(predicate::str::contains("build warning"))
        .stdout(predicate::str::contains("Validating Petal package..."));

    stop_ipc_server(server, server_thread);
}

#[test]
fn petals_source_build_failure_replays_output_before_returning_an_error() {
    let home = fresh_home();
    let (server, server_thread) = spawn_petals_ipc_server(home.path());

    let assert = bloom_cmd(home.path())
        .args([
            "petals",
            "install",
            "https://github.com/bloom-directory/failing-demo",
        ])
        .assert()
        .failure();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    let resolving = stdout
        .find("Resolving https://github.com/bloom-directory/failing-demo")
        .unwrap();
    let building = stdout.find("Building source package...").unwrap();
    let build_output = stdout.find("partial build output").unwrap();
    assert!(resolving < building && building < build_output, "{stdout}");
    let build_stderr = stderr.find("build exploded").unwrap();
    let final_error = stderr
        .find("build command failed: scripts/build.sh")
        .unwrap();
    assert!(build_stderr < final_error, "{stderr}");

    stop_ipc_server(server, server_thread);
}

#[test]
fn vfs_ls_status_lists_known_files() {
    let home = fresh_home();
    let _daemon = RunningBloom::start(home.path());
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
    let _daemon = RunningBloom::start(home.path());
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
    let _daemon = RunningBloom::start(home.path());
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
fn vfs_default_missing_socket_fails_closed() {
    let home = fresh_home();
    let socket = home.path().join("run").join("bloom.sock");
    assert!(
        !socket.exists(),
        "fresh home should not have a daemon socket"
    );

    bloom_cmd(home.path())
        .args(["vfs", "cat", "/status/version"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Bloom daemon endpoint"));
}

#[test]
fn vfs_ls_status_includes_update_subtree() {
    let home = fresh_home();
    let _daemon = RunningBloom::start(home.path());
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
    let _daemon = RunningBloom::start(home.path());
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
    // This fixture asserts the empty-cache projection before any refresh.
    // Keep only this child daemon offline from automatic update checks.
    let _daemon = RunningBloom::start_without_automatic_update_checks(home.path());
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
    bloom_update::cache::write(
        &cache_dir,
        &bloom_update::UpdateSnapshot::ok(
            "0.1.0".into(),
            Some("0.2.0".into()),
            Some("https://github.com/bloom-directory/bloom/releases/tag/v0.2.0".into()),
        ),
    )
    .unwrap();
    // This fixture asserts the daemon's seeded-cache rendering, not GitHub
    // refresh behavior. Disable only this child process's automatic check so
    // a parallel startup refresh cannot replace the deterministic snapshot.
    let _daemon = RunningBloom::start_without_automatic_update_checks(home.path());
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
    bloom_cmd(home.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("latest_release: 0.2.0"))
        .stdout(predicate::str::contains("update_available: out_of_date"))
        .stderr(predicate::str::contains("hint: bloom v0.2.0 is available"));
}

#[test]
fn bloom_update_status_prints_cached_snapshot() {
    let home = fresh_home();
    let _daemon = RunningBloom::start(home.path());
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
            predicate::str::contains("Bloom daemon endpoint")
                .and(predicate::str::contains(socket.display().to_string())),
        );
}

#[cfg(unix)]
#[test]
fn refused_endpoint_is_never_unlinked_by_a_client() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    let home = fresh_home();
    let socket = home.path().join("run/refused.sock");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(listener);
    let endpoint = format!("unix:{}", socket.display());

    bloom_cmd(home.path())
        .args(["--connect", &endpoint, "vfs", "cat", "/status/version"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("not responding")
                .and(predicate::str::contains("start it with 'bloom serve'")),
        );

    assert!(
        std::fs::symlink_metadata(&socket).is_ok(),
        "a client must never unlink an endpoint during a daemon restart race"
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
            predicate::str::contains("Bloom daemon endpoint")
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
fn lifecycle_commands_ignore_invalid_client_endpoint_configuration() {
    let home = fresh_home();
    let home_dir = bloom_proto::HomeDir::at(home.path());
    let mut config = bloom_proto::Config::local_default();
    config.petals.preinstalled.clear();
    config.save(&home_dir.config_path()).unwrap();
    bloom_cmd(home.path())
        .env("BLOOM_RPC_ENDPOINT", "tcp:invalid")
        .arg("init")
        .assert()
        .success();

    let binary = Command::cargo_bin("bloom").expect("locate bloom binary");
    let mut child = std::process::Command::new(binary.get_program())
        .env("BLOOM_HOME", home.path())
        .env("BLOOM_RPC_ENDPOINT", "tcp:invalid")
        .env("RUST_LOG", "error")
        .env(bloom_update::DISABLE_AUTO_CHECK_ENV, "1")
        .arg("serve")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start Bloom daemon with invalid client endpoint configuration");
    let socket = bloom_daemon::ipc::default_socket_path(home.path());
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline && !ipc_endpoint_accepting(&socket) {
        if child.try_wait().unwrap().is_some() {
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("lifecycle daemon exited before binding its socket: {stderr}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ipc_endpoint_accepting(&socket));
    child.kill().unwrap();
    child.wait().unwrap();
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

    let mut command = bloom_cmd(home.path());
    command.arg("serve");
    command.assert().failure().stderr(
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
        .stdout(predicate::str::contains("request: pending/request-1"))
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
fn concurrent_request_clients_receive_the_identity_from_their_own_atomic_write() {
    use bloom_vfs::Vfs;

    let home = fresh_home();
    let requests = RecordingWriteHandler::new();
    let vfs = Vfs::builder().mount("requests", requests).build();
    let (server, server_thread) = spawn_ipc_server(home.path(), vfs);
    let home_path = home.path().to_path_buf();
    let clients = (0..2)
        .map(|index| {
            let home_path = home_path.clone();
            std::thread::spawn(move || {
                let output = bloom_cmd(&home_path)
                    .args([
                        "request",
                        "new",
                        &format!("GET https://example.com/{index}"),
                    ])
                    .output()
                    .expect("run concurrent request client");
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                String::from_utf8(output.stdout).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let mut outputs = clients
        .into_iter()
        .map(|client| client.join().expect("request client panicked"))
        .collect::<Vec<_>>();
    outputs.sort();
    assert_eq!(
        outputs,
        vec![
            "request: pending/request-1\n".to_owned(),
            "request: pending/request-2\n".to_owned(),
        ]
    );
    stop_ipc_server(server, server_thread);
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
        .stdout(predicate::eq("tx-1\n"))
        .stderr(predicate::str::contains("already open for writing").not());

    stop_ipc_server(server, server_thread);
    let writes = wallets.writes();
    assert_eq!(writes.len(), 1, "writes={writes:?}");
    assert_eq!(writes[0].0, "/alice/chains/anvil/outbox/new.tx");
    assert_eq!(String::from_utf8_lossy(&writes[0].1), intent);
}

#[test]
fn wallet_stage_without_daemon_fails_before_local_parsing() {
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
        .stderr(predicate::str::contains("Bloom daemon endpoint"))
        .stderr(predicate::str::contains("parse intent").not())
        .stderr(predicate::str::contains("already open for writing").not());
}

#[test]
fn wallet_list_ignores_legacy_keystore_without_a_broker_projection() {
    let home = fresh_home();
    seed_legacy_wallet_fixture(home.path(), "alice");
    let _daemon = RunningBloom::start(home.path());
    bloom_cmd(home.path())
        .args(["wallet", "list"])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "Broker is unavailable and no cached wallet projection exists",
        ));
}

#[test]
fn wallet_projection_prints_only_the_authenticated_key_free_cache() {
    let home = fresh_home();
    seed_wallet_projection_fixture(home.path(), "alice");
    let _daemon = RunningBloom::start(home.path());
    let output = bloom_cmd(home.path())
        .args(["wallet", "projection", "alice"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let projection: WalletProjection = serde_json::from_slice(&output).unwrap();
    assert_eq!(projection.wallet.wallet_id.as_str(), "alice");
    assert_eq!(projection.keys.len(), 1);
    assert!(projection.credentials.is_empty());
    assert_eq!(
        projection.verification,
        ProjectionVerification::AuthenticatedBroker
    );
    assert_eq!(projection.freshness, ProjectionFreshness::Stale);
    assert!(!home.path().join("keystore").exists());
    assert!(!home.path().join("auth").exists());
}

#[test]
fn wallet_projection_ignores_a_legacy_keystore_record() {
    let home = fresh_home();
    seed_legacy_wallet_fixture(home.path(), "alice");
    let _daemon = RunningBloom::start(home.path());
    bloom_cmd(home.path())
        .args(["wallet", "projection", "alice"])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("has no cached projection"));
}

#[test]
fn wallet_new_requires_broker_and_never_creates_machine_key_material() {
    let home = fresh_home();
    let _daemon = RunningBloom::start(home.path());
    bloom_cmd(home.path())
        .args(["wallet", "new", "alice"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("custody requires the authenticated Machine-to-Broker edge")
                .and(predicate::str::contains("jsonrpc").not())
                .and(predicate::str::contains("\"code\"").not())
                .and(predicate::str::contains("ipc machine.execute").not()),
        );
    assert!(!home.path().join("keystore").join("alice").exists());
}

#[test]
fn machine_operation_errors_are_clean_and_preserve_cli_text() {
    let home = fresh_home();
    let _daemon = RunningBloom::start(home.path());
    bloom_cmd(home.path())
        .args(["wallet", "unlock", "alice"])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("wallet unlock for 'alice' is fail-closed")
                .and(predicate::str::contains("jsonrpc").not())
                .and(predicate::str::contains("\"code\"").not())
                .and(predicate::str::contains("ipc machine.execute").not()),
        );
}

#[test]
fn raw_ipc_call_reports_invalid_machine_params_without_json_error_wrappers() {
    let home = fresh_home();
    let _daemon = RunningBloom::start(home.path());
    bloom_cmd(home.path())
        .args([
            "ipc",
            "call",
            "machine.execute",
            "--params",
            r#"{"command":"status","extra":true}"#,
        ])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("invalid params: unknown fields")
                .and(predicate::str::contains("jsonrpc").not())
                .and(predicate::str::contains("\"code\"").not())
                .and(predicate::str::contains("ipc call to").not()),
        );
}

#[test]
fn wallet_import_accepts_no_machine_private_key_argument() {
    let home = fresh_home();
    bloom_cmd(home.path())
        .args(["wallet", "import", "alice", "deadbeef"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument 'deadbeef'"));
    assert!(!home.path().join("keystore").join("alice").exists());
}

#[test]
fn wallet_import_rejects_path_names_before_broker_contact() {
    let home = fresh_home();
    let _daemon = RunningBloom::start(home.path());
    for name in ["../escape", "../../escape", "a/b", "..", "/etc/passwd"] {
        bloom_cmd(home.path())
            .args(["wallet", "import", name])
            .assert()
            .failure()
            .stderr(
                predicate::str::contains(
                    "requested wallet name must be a safe single path segment",
                )
                .and(predicate::str::contains("jsonrpc").not())
                .and(predicate::str::contains("\"code\"").not())
                .and(predicate::str::contains("ipc machine.execute").not()),
            );
    }
    assert!(!home.path().join("keystore").join("escape").exists());
}

#[test]
fn request_cli_dry_run_uses_vfs_lifecycle_and_body_receipt_helpers() {
    let home = fresh_home();
    seed_wallet_projection_fixture(home.path(), "alice");
    let _daemon = RunningBloom::start(home.path());

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
fn status_without_broker_or_projection_reports_wallets_unavailable() {
    let home = fresh_home();
    let _daemon = RunningBloom::start(home.path());
    let assert = bloom_cmd(home.path()).args(["status"]).assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        out.contains("wallets: unavailable"),
        "status must not treat an unavailable projection as an empty wallet set:\n{out}"
    );
    assert!(
        !out.contains("no wallets yet"),
        "status must not falsely claim that no wallets exist:\n{out}"
    );
    assert!(
        !home.path().join("keystore").join("default").exists(),
        "public status must not create wallet key material"
    );
}

#[test]
fn wallet_address_ignores_legacy_keystore_without_a_broker_projection() {
    let home = fresh_home();
    seed_legacy_wallet_fixture(home.path(), "alice");
    let _daemon = RunningBloom::start(home.path());

    bloom_cmd(home.path())
        .args(["wallet", "address", "alice"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("has no cached projection"));

    bloom_cmd(home.path())
        .args(["wallet", "address", "alice", "--qr"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("has no cached projection"));
}

#[test]
fn wallet_address_qr_out_does_not_use_legacy_keystore() {
    let home = fresh_home();
    seed_legacy_wallet_fixture(home.path(), "alice");
    let _daemon = RunningBloom::start(home.path());
    let svg_path = home.path().join("deposit.svg");
    bloom_cmd(home.path())
        .args([
            "wallet",
            "address",
            "alice",
            "--qr-out",
            svg_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("has no cached projection"));
    assert!(!svg_path.exists());
}

/// Spin up an in-process `IpcServer` bound to the home's default socket
/// path, then invoke the CLI so its `vfs` subcommand routes through IPC.
/// Seeing data only this server can produce proves the command used the
/// configured IPC authority plane.
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
    while !ipc_endpoint_accepting(&socket) {
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
    // CLI. Asserting on the unique payload also proves the daemon response is
    // the source of client output.
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
fn wallet_cancel_uses_daemon_owned_machine_command_while_home_lock_is_live() {
    let home = fresh_home();
    let _permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(home.path()))
        .expect("hold home write permit");
    let commands = Arc::new(RecordingMachineCommands::default());
    let (server, server_thread) = spawn_machine_ipc_server(home.path(), commands.clone());

    bloom_cmd(home.path())
        .args([
            "wallet",
            "cancel",
            "alice",
            "base",
            "0001-deadbeef",
            "--text",
            "approve",
        ])
        .assert()
        .success()
        .stdout(predicate::eq("cancel submitted for 0001-deadbeef\n"))
        .stderr(predicate::str::contains("already open for writing").not());

    stop_ipc_server(server, server_thread);
    assert_eq!(
        serde_json::to_value(commands.commands()).unwrap(),
        serde_json::json!([{
            "command": "wallet_outbox_cancel",
            "wallet": "alice",
            "chain": "base",
            "id": "0001-deadbeef",
            "text": "approve"
        }])
    );
}

#[test]
fn wallet_replace_uses_daemon_owned_machine_command_while_home_lock_is_live() {
    let home = fresh_home();
    let _permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(home.path()))
        .expect("hold home write permit");
    let commands = Arc::new(RecordingMachineCommands::default());
    let (server, server_thread) = spawn_machine_ipc_server(home.path(), commands.clone());
    let intent = "send 0.002 eth to 0x0000000000000000000000000000000000000000 on base";

    bloom_cmd(home.path())
        .args([
            "wallet",
            "replace",
            "alice",
            "base",
            "0001-deadbeef",
            "--intent",
            intent,
        ])
        .assert()
        .success()
        .stdout(predicate::eq("replacement submitted for 0001-deadbeef\n"))
        .stderr(predicate::str::contains("already open for writing").not());

    stop_ipc_server(server, server_thread);
    assert_eq!(
        serde_json::to_value(commands.commands()).unwrap(),
        serde_json::json!([{
            "command": "wallet_outbox_replace",
            "wallet": "alice",
            "chain": "base",
            "id": "0001-deadbeef",
            "intent": intent
        }])
    );
}

#[test]
fn wallet_outbox_machine_command_reports_invalid_path_params_cleanly() {
    let home = fresh_home();
    let _daemon = RunningBloom::start(home.path());

    for invalid_wallet in ["alice/other", "alice\\other"] {
        bloom_cmd(home.path())
            .args(["wallet", "cancel", invalid_wallet, "base", "0001-deadbeef"])
            .assert()
            .failure()
            .stdout(predicate::str::is_empty())
            .stderr(
                predicate::str::contains("invalid wallet outbox wallet")
                    .and(predicate::str::contains("jsonrpc").not())
                    .and(predicate::str::contains("ipc machine.execute").not()),
            );
    }

    bloom_cmd(home.path())
        .args([
            "ipc",
            "call",
            "machine.execute",
            "--params",
            r#"{"command":"wallet_outbox_cancel","wallet":"alice\u0000other","chain":"base","id":"0001-deadbeef","text":"approve"}"#,
        ])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("invalid wallet outbox wallet")
                .and(predicate::str::contains("jsonrpc").not())
                .and(predicate::str::contains("\"code\"").not()),
        );
}

#[test]
fn wallet_confirm_batch_uses_canonical_ipc_and_prints_authority_receipts() {
    let home = fresh_home();
    let (server, server_thread) = spawn_batch_ipc_server(home.path());

    bloom_cmd(home.path())
        .args([
            "wallet",
            "confirm-batch",
            "alice",
            "base:0001-deadbeef",
            "ethereum:0002-cafebabe",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("batch-operation-id"))
        .stdout(predicate::str::contains("signer-receipt-digest"))
        .stdout(predicate::str::contains("broker-receipt-digest"))
        .stdout(predicate::str::contains("\"confirmation_text\": \"y\""));

    stop_ipc_server(server, server_thread);
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
    let (server, server_thread) = spawn_petals_ipc_server(home.path());
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

    stop_ipc_server(server, server_thread);
    let _daemon = RunningBloom::start(home.path());

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
fn github_source_install_polymarket_dispatches_route_contract() {
    if std::env::var_os("BLOOM_RUN_NETWORK_TESTS").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    // This commit uses the same canonical Petal contract revision as Bloom.
    let petal_ref = "a47e7e462c2be117d497a3edd2399fb1f4acfe8d";
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

    let daemon = spawn_bloom_serve(home.path());

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
        .stdout(predicate::str::contains("Building source package..."))
        .stdout(predicate::str::contains("Validating Petal package..."))
        .stdout(predicate::str::contains("\"routes\": 97"))
        .stdout(predicate::str::contains("routes: 97"));

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

    stop_bloom_serve(home.path(), daemon);
}

#[test]
fn petals_install_rejects_untrusted_owner_and_raw_remote_wasm() {
    let home = fresh_home();
    let (server, server_thread) = spawn_petals_ipc_server(home.path());
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
    stop_ipc_server(server, server_thread);
}
