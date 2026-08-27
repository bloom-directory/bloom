//! The mainnet-beta gate, end to end through the real environment.
//!
//! The unit tests in `bloom-proto` cover the authorization's own decisions.
//! This one covers the wiring the guards actually depend on: an authorization
//! file on disk, named by the real environment variable, reaching
//! [`SolanaClient::verify_genesis`] against a cluster whose *live* genesis is
//! mainnet-beta.
//!
//! The environment has to be set genuinely, and `std::env::set_var` is unsafe
//! (and both crates forbid unsafe), so the parent re-execs this binary with
//! the variable already in place — the same shape systemd or an operator would
//! produce. The child reports the guard's verdict through its exit code.
//!
//! The expectation deliberately flips with the feature: a production build
//! must refuse *even with a perfect authorization present*, which is the
//! property that matters most here.

use std::path::Path;
use std::process::{Command, Stdio};

use bloom_proto::EndpointSpec;
use bloom_proto::canary::{AUTHORIZATION_ENV, AUTHORIZATION_SCHEMA, CanaryAuthorization};
use bloom_solana::{MAINNET_BETA_GENESIS_HASH, SolanaClient, SolanaSpec};

const CHILD_ENDPOINT: &str = "BLOOM_CANARY_TEST_ENDPOINT";
const CHILD_TEST: &str = "the_mainnet_gate_consults_the_canary_authorization";
const CHAIN: &str = "solana-mainnet-canary";
const EXIT_PERMITTED: i32 = 30;
const EXIT_REFUSED: i32 = 31;

/// A loopback node that claims to be mainnet-beta.
async fn spawn_mainnet_stub() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await.unwrap_or(0);
                let body =
                    format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{MAINNET_BETA_GENESIS_HASH}"}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

fn mainnet_spec(endpoint: &str) -> SolanaSpec {
    SolanaSpec {
        name: CHAIN.to_string(),
        endpoints: vec![EndpointSpec {
            url: endpoint.to_string(),
            weight: 100,
            cu_per_sec: None,
            max_rps: None,
            http_only: false,
        }],
        expected_genesis_hex: Some(MAINNET_BETA_GENESIS_HASH.to_string()),
        allow_broadcast: true,
    }
}

/// Write an authorization bound to this binary, valid far into the future.
fn write_authorization(path: &Path) {
    let artifact =
        bloom_proto::canary::running_artifact_sha256().expect("hash the running test binary");
    let mut auth = CanaryAuthorization {
        schema: AUTHORIZATION_SCHEMA.into(),
        artifact_sha256: artifact,
        chain: CHAIN.into(),
        wallet: "canary".into(),
        key_fingerprint: "cd".repeat(32),
        derivation_path: "m/44'/501'/0'/0'".into(),
        source_address: "SoURCE1111111111111111111111111111111111111".into(),
        destination: "DeST22222222222222222222222222222222222222".into(),
        max_balance_lamports: 2_000_000,
        transfer_lamports: 1_000_000,
        max_fee_lamports: 10_000,
        max_transactions: bloom_proto::canary::MAX_TRANSACTIONS,
        expires_ms: u128::from(u64::MAX),
        acknowledgement: String::new(),
    };
    auth.acknowledgement = auth.canonical_acknowledgement();
    auth.validate_shape()
        .expect("the fixture must be well formed");
    std::fs::write(path, serde_json::to_vec(&auth).unwrap()).unwrap();
}

/// The child half: ask the real guard and report its verdict.
///
/// This already runs inside the harness's tokio runtime, so it awaits rather
/// than building a nested one.
async fn run_child() -> ! {
    let endpoint = std::env::var(CHILD_ENDPOINT).expect("endpoint");
    let client = SolanaClient::build(&mainnet_spec(&endpoint)).expect("build client");
    match client.verify_genesis().await {
        Ok(_) => {
            eprintln!("PERMITTED");
            std::process::exit(EXIT_PERMITTED);
        }
        Err(error) => {
            eprintln!("REFUSED {error}");
            std::process::exit(EXIT_REFUSED);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_mainnet_gate_consults_the_canary_authorization() {
    if std::env::var_os(CHILD_ENDPOINT).is_some() {
        run_child().await;
    }
    let endpoint = spawn_mainnet_stub().await;

    // Sanity: with no authorization at all, mainnet-beta is refused in every
    // build. This is the behaviour that must never regress.
    let client = SolanaClient::build(&mainnet_spec(&endpoint)).unwrap();
    let error = client
        .verify_genesis()
        .await
        .expect_err("mainnet-beta with no authorization must always be refused");
    assert!(
        error.to_string().contains("mainnet-beta is disabled"),
        "{error}"
    );

    // Now with a perfect authorization in the real environment.
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("canary.json");
    write_authorization(&auth_path);

    let output = Command::new(std::env::current_exe().unwrap())
        .arg(CHILD_TEST)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_ENDPOINT, &endpoint)
        .env(AUTHORIZATION_ENV, &auth_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child")
        .wait_with_output()
        .expect("child output");
    let stderr = String::from_utf8_lossy(&output.stderr);

    #[cfg(not(feature = "mainnet-canary"))]
    {
        // The load-bearing assertion: a production build is handed a valid,
        // unexpired, correctly-bound authorization and refuses anyway,
        // because the code that would read it was never compiled in.
        assert_eq!(
            output.status.code(),
            Some(EXIT_REFUSED),
            "a production build must refuse mainnet-beta even with a valid \
             authorization present.\nstderr: {stderr}"
        );
        assert!(stderr.contains("mainnet-beta is disabled"), "{stderr}");
    }
    #[cfg(feature = "mainnet-canary")]
    {
        assert_eq!(
            output.status.code(),
            Some(EXIT_PERMITTED),
            "a labelled canary build holding a valid authorization must be \
             permitted past the genesis gate.\nstderr: {stderr}"
        );
    }
}

/// A canary build must still refuse when the authorization does not apply.
#[tokio::test(flavor = "multi_thread")]
async fn an_authorization_for_another_chain_or_artifact_does_not_open_the_gate() {
    if std::env::var_os(CHILD_ENDPOINT).is_some() {
        return;
    }
    let endpoint = spawn_mainnet_stub().await;
    let dir = tempfile::tempdir().unwrap();

    for (label, mutate) in [
        (
            "another chain",
            Box::new(|auth: &mut CanaryAuthorization| auth.chain = "solana-devnet".into())
                as Box<dyn Fn(&mut CanaryAuthorization)>,
        ),
        (
            "another artifact",
            Box::new(|auth: &mut CanaryAuthorization| auth.artifact_sha256 = "ff".repeat(32)),
        ),
        (
            "an expired window",
            Box::new(|auth: &mut CanaryAuthorization| auth.expires_ms = 1),
        ),
    ] {
        let path = dir.path().join(format!("{}.json", label.replace(' ', "-")));
        write_authorization(&path);
        let mut auth: CanaryAuthorization =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        mutate(&mut auth);
        // The acknowledgement is re-derived so the refusal is attributable to
        // the mutated field rather than to a stale sentence.
        auth.acknowledgement = auth.canonical_acknowledgement();
        std::fs::write(&path, serde_json::to_vec(&auth).unwrap()).unwrap();

        let output = Command::new(std::env::current_exe().unwrap())
            .arg(CHILD_TEST)
            .arg("--exact")
            .arg("--nocapture")
            .env(CHILD_ENDPOINT, &endpoint)
            .env(AUTHORIZATION_ENV, &path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child")
            .wait_with_output()
            .expect("child output");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(EXIT_REFUSED),
            "{label} must not open the mainnet gate.\nstderr: {stderr}"
        );
    }
}
