//! Integration tests for the ERC-20 + replace/cancel paths in
//! `bloom_tx::TxEngine`.
//!
//! Like the rest of `bloom-it`, these tests are `#[ignore]` and run on
//! demand:
//!
//! ```text
//! cargo test -p bloom-it -- --ignored
//! ```
//!
//! They spawn a local `anvil` from `~/.foundry/bin/anvil`.

use std::net::TcpListener;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bloom_chain::ChainClient;
use bloom_proto::{ChainSpec, Policy, RawIntent, RawIntentBody};
use bloom_tx::Outbox;
use bloom_tx::tx_engine::{TxEngine, TxEngineError};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

const ANVIL_BIN: &str = "/Users/joshua/.foundry/bin/anvil";

/// Anvil prefunded account #0.
const ANVIL_PK0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_ADDR0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
/// Anvil prefunded account #1 (recipient).
const ANVIL_ADDR1: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

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

async fn spawn_anvil(no_mining: bool) -> Result<AnvilGuard> {
    let port = pick_free_port()?;
    let mut cmd = Command::new(ANVIL_BIN);
    cmd.arg("--port")
        .arg(port.to_string())
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--chain-id")
        .arg("31337");
    if no_mining {
        // Hold txs in the mempool so we can submit a replacement.
        cmd.arg("--no-mining");
    }
    cmd.stdout(Stdio::piped())
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
                Some(line) => {
                    if line.contains("Listening on") {
                        return Ok::<(), anyhow::Error>(());
                    }
                }
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

fn anvil_chain_spec(rpc_url: &str) -> ChainSpec {
    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![rpc_url.to_string()];
    spec.allow_broadcast = true;
    spec
}

/// Stage an ERC-20 transfer to a hardcoded token symbol that resolves
/// to the canonical mainnet address. On a fresh anvil there is no code
/// at that address, so `decimals()` returns empty and stage fails with
/// a `Token` error — which proves the path is wired end-to-end.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn erc20_stage_fails_when_decimals_unreadable() -> Result<()> {
    let anvil = spawn_anvil(false).await?;
    let rpc_url = anvil.rpc_url();
    let chain = ChainClient::new(anvil_chain_spec(&rpc_url)).map_err(|e| anyhow!("chain: {e}"))?;

    let tmp = tempfile::tempdir()?;
    let outbox = Outbox::new(tmp.path()).map_err(|e| anyhow!("outbox: {e}"))?;
    let engine = TxEngine::new(outbox, 60_000, false);

    let from = ANVIL_ADDR0.parse().unwrap();
    let intent = RawIntent {
        body: RawIntentBody::Send {
            to: ANVIL_ADDR1.to_string(),
            value: "100".into(),
            token: Some("USDC".into()),
            data: None,
        },
        chain: Some("anvil".to_string()),
        gas: Default::default(),
        nonce: None,
    };

    let res = engine
        .stage("alice", from, intent, &chain, &Policy::permissive(), None)
        .await;
    let err = match res {
        Ok(_) => return Err(anyhow!("expected staging to fail (no code at USDC addr)")),
        Err(e) => e,
    };
    match err {
        TxEngineError::Token(_) => {}
        other => return Err(anyhow!("expected Token error, got {other:?}")),
    }
    Ok(())
}

/// Stage a native send, broadcast via `confirm`, then call `replace`
/// with a 15% fee bump. Asserts that the replacement carries the same
/// nonce and strictly higher fees.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn replace_keeps_nonce_and_bumps_fees() -> Result<()> {
    let anvil = spawn_anvil(true).await?;
    let rpc_url = anvil.rpc_url();
    let chain = ChainClient::new(anvil_chain_spec(&rpc_url)).map_err(|e| anyhow!("chain: {e}"))?;

    let tmp = tempfile::tempdir()?;
    let outbox = Outbox::new(tmp.path()).map_err(|e| anyhow!("outbox: {e}"))?;
    let engine = TxEngine::new(outbox, 60_000, false);

    // Use anvil's prefunded account #0 as the signer.
    let signer: alloy::signers::local::PrivateKeySigner = ANVIL_PK0.parse()?;
    let from = signer.address();

    let intent = RawIntent {
        body: RawIntentBody::Send {
            to: ANVIL_ADDR1.to_string(),
            value: "0.01 eth".into(),
            token: None,
            data: None,
        },
        chain: Some("anvil".to_string()),
        gas: Default::default(),
        nonce: None,
    };

    let staged = engine
        .stage("alice", from, intent, &chain, &Policy::permissive(), None)
        .await
        .map_err(|e| anyhow!("stage: {e}"))?;
    let original_nonce = staged.nonce;
    let original_max_fee: u128 = staged
        .max_fee_per_gas
        .as_deref()
        .ok_or_else(|| anyhow!("missing max_fee_per_gas"))?
        .parse()?;

    let confirmed = engine
        .confirm(
            "alice",
            "anvil",
            &staged.id,
            &chain,
            &signer,
            &Policy::permissive(),
            "y",
        )
        .await
        .map_err(|e| anyhow!("confirm: {e}"))?;
    assert!(confirmed.tx_hash.is_some(), "confirm produced no tx hash");

    // Replace with +15% fees.
    let replaced = engine
        .replace(
            "alice",
            "anvil",
            &staged.id,
            &chain,
            &signer,
            15,
            &Policy::permissive(),
        )
        .await
        .map_err(|e| anyhow!("replace: {e}"))?;
    assert_eq!(replaced.nonce, original_nonce, "nonce must match");
    let new_max_fee: u128 = replaced
        .max_fee_per_gas
        .as_deref()
        .ok_or_else(|| anyhow!("missing replacement max_fee_per_gas"))?
        .parse()?;
    assert!(
        new_max_fee > original_max_fee,
        "fee not bumped: {} -> {}",
        original_max_fee,
        new_max_fee
    );
    assert!(
        replaced.tx_hash.is_some(),
        "replacement broadcast produced no tx hash"
    );

    drop(anvil);
    Ok(())
}
