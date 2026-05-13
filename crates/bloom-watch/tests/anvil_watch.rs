//! End-to-end test: drive [`WatchExecutor`] against a real anvil node.
//!
//! Marked `#[ignore]` so the default `cargo test` does not attempt to
//! launch a child process. Run via:
//!
//! ```text
//! cargo test -p bloom-watch -- --ignored
//! ```
//!
//! Requires Foundry's `anvil` and `cast` to be available at
//! `~/.foundry/bin/{anvil,cast}` (matching the path used by `bloom-it`).

use std::net::TcpListener;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bloom_chain::{ChainClient, ChainRegistry};
use bloom_proto::{ChainSpec, HomeDir};
use bloom_watch::{WatchExecutor, WatchKind, WatchRegistry, WatchSpec};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const ANVIL_BIN: &str = "/Users/joshua/.foundry/bin/anvil";
const CAST_BIN: &str = "/Users/joshua/.foundry/bin/cast";
const FUNDER_PRIV_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
// Anvil prefunded account #1 — receives the funded watch.
const ALICE_ADDR: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

struct AnvilGuard {
    child: Option<Child>,
    port: u16,
}

impl AnvilGuard {
    fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for AnvilGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.start_kill();
        }
    }
}

fn pick_free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

async fn spawn_anvil() -> Result<AnvilGuard> {
    let port = pick_free_port()?;
    let mut cmd = Command::new(ANVIL_BIN);
    cmd.arg("--port")
        .arg(port.to_string())
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--chain-id")
        .arg("31337")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().context("spawn anvil")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("anvil stdout missing"))?;
    let mut reader = BufReader::new(stdout).lines();
    let wait = async {
        loop {
            match reader.next_line().await? {
                Some(line) if line.contains("Listening on") => return Ok::<(), anyhow::Error>(()),
                Some(_) => continue,
                None => return Err(anyhow!("anvil exited before becoming ready")),
            }
        }
    };
    timeout(Duration::from_secs(15), wait)
        .await
        .map_err(|_| anyhow!("timed out waiting for anvil to start"))??;
    Ok(AnvilGuard {
        child: Some(child),
        port,
    })
}

async fn fund(rpc_url: &str, to: &str, value_eth: u64) -> Result<()> {
    let out = Command::new(CAST_BIN)
        .arg("send")
        .arg("--private-key")
        .arg(FUNDER_PRIV_KEY)
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg(to)
        .arg("--value")
        .arg(format!("{}ether", value_eth))
        .output()
        .await
        .context("invoke cast send")?;
    if !out.status.success() {
        return Err(anyhow!(
            "cast send failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn balance_watch_records_transition() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,bloom_watch=info")),
        )
        .with_test_writer()
        .try_init();

    let anvil = spawn_anvil().await?;
    let rpc_url = anvil.rpc_url();

    // Build a temp home + minimal ChainRegistry pointing at our anvil.
    let tmp = tempfile::tempdir()?;
    let home = HomeDir::at(tmp.path());
    home.ensure().map_err(|e| anyhow!("home: {e}"))?;

    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![rpc_url.clone()];
    let chains = ChainRegistry::default();
    chains.add(ChainClient::new(spec).map_err(|e| anyhow!("chain client: {e}"))?);

    let registry = Arc::new(WatchRegistry::new(home.watch_dir()).map_err(|e| anyhow!("{e}"))?);

    // Register a balance watch on alice (anvil prefunded #1, already
    // funded with 10000 ETH at genesis; we fund again to force a delta).
    let watch_spec = WatchSpec {
        id: "w-0001".into(),
        wallet: "alice".into(),
        created_ms: 0,
        kind: WatchKind::Balance {
            address: ALICE_ADDR.to_string(),
            threshold_wei: "0".into(),
            comparator: ">".into(),
        },
        note: None,
    };
    registry
        .add(watch_spec.clone())
        .map_err(|e| anyhow!("registry.add: {e}"))?;

    let exec = Arc::new(
        WatchExecutor::new(chains, registry, home.clone()).with_tick(Duration::from_millis(200)),
    );
    exec.start().map_err(|e| anyhow!("start: {e}"))?;

    // Let the executor capture the initial balance, then fund alice
    // again so the next tick records a transition.
    sleep(Duration::from_millis(800)).await;
    fund(&rpc_url, ALICE_ADDR, 1).await?;

    // Wait for the executor to observe the new balance.
    let live_path = WatchExecutor::live_path_for_spec(&home, &watch_spec);
    let mut transitions: Vec<serde_json::Value> = Vec::new();
    for _ in 0..50 {
        sleep(Duration::from_millis(200)).await;
        if let Ok(body) = std::fs::read_to_string(&live_path) {
            transitions = body
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            // We want at least two records — initial sample + post-fund
            // delta — so we can assert we saw a real transition.
            if transitions.len() >= 2 {
                break;
            }
        }
    }
    exec.stop().await;

    assert!(
        transitions.len() >= 2,
        "expected >=2 balance records in live, got {transitions:?}"
    );
    let last = transitions.last().unwrap();
    assert_eq!(last["kind"], "balance");
    assert_eq!(
        last["addr"].as_str().unwrap().to_lowercase(),
        ALICE_ADDR.to_lowercase()
    );
    assert!(last["balance_wei"].is_string());
    assert!(last["prev_wei"].is_string());

    drop(anvil);
    Ok(())
}
