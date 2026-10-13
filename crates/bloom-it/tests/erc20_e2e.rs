//! Category: integration
//!
//! Integration tests for the ERC-20 + replace/cancel paths in
//! `bloom_tx::TxEngine`.
//!
//! These tests run by default because WS-4 requires EVM auth-hardening
//! integration coverage:
//!
//! ```text
//! cargo test -p bloom-it --test erc20_e2e
//! ```
//!
//! They spawn a local `anvil` from `$PATH` (or `BLOOM_ANVIL_BIN`).

use std::net::TcpListener;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bloom_evm::ChainClient;
use bloom_it::{exact_signing_broker, exact_signing_catalog};
use bloom_proto::{
    AgentAutonomyMode, ChainSpec, Policy, RawIntent, RawIntentBody, ValuationError, ValuationQuote,
};
use bloom_tx::tx_engine::{TxEngine, TxEngineError};
use bloom_tx::{Outbox, PriceOracle};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

/// Anvil prefunded account #0.
const ANVIL_PK0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_ADDR0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
/// Anvil prefunded account #1 (recipient).
const ANVIL_ADDR1: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

struct TestPriceOracle;

#[async_trait::async_trait]
impl PriceOracle for TestPriceOracle {
    async fn quote_usd(
        &self,
        asset_id: &str,
        amount_base_units: &str,
        _asset_decimals: u8,
        now_ms: u64,
    ) -> std::result::Result<ValuationQuote, ValuationError> {
        Ok(ValuationQuote {
            asset_id: asset_id.into(),
            amount_base_units: amount_base_units.into(),
            usd_micro: 1_000_000,
            source: "integration-test-oracle".into(),
            quote_timestamp_ms: now_ms,
            fetched_at_ms: now_ms,
            max_age_ms: 30_000,
            confidence_ppm: None,
            stablecoin_assumption: false,
        })
    }
}

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

fn anvil_bin() -> String {
    std::env::var("BLOOM_ANVIL_BIN").unwrap_or_else(|_| "anvil".to_string())
}

async fn spawn_anvil(no_mining: bool) -> Result<AnvilGuard> {
    let port = pick_free_port()?;
    let mut cmd = Command::new(anvil_bin());
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

/// Mine whatever is queued on a `--no-mining` anvil.
async fn mine_pending(rpc_url: &str) -> Result<()> {
    let response = reqwest::Client::new()
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "evm_mine", "params": []
        }))
        .send()
        .await
        .context("evm_mine")?;
    if !response.status().is_success() {
        return Err(anyhow!("evm_mine failed: {}", response.status()));
    }
    Ok(())
}

fn anvil_chain_spec(rpc_url: &str) -> ChainSpec {
    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![rpc_url.to_string()];
    spec
}

/// Stage an ERC-20 transfer to a hardcoded token symbol that resolves
/// to the canonical mainnet address. On a fresh anvil there is no code
/// at that address, so `decimals()` returns empty and stage fails with
/// a `Token` error — which proves the path is wired end-to-end.
#[tokio::test(flavor = "multi_thread")]
async fn erc20_stage_fails_when_decimals_unreadable() -> Result<()> {
    let anvil = spawn_anvil(false).await?;
    let rpc_url = anvil.rpc_url();
    let chain = ChainClient::new(anvil_chain_spec(&rpc_url)).map_err(|e| anyhow!("chain: {e}"))?;

    let tmp = tempfile::tempdir()?;
    let permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(tmp.path()))?;
    let outbox = Outbox::new(tmp.path().join("outbox")).map_err(|e| anyhow!("outbox: {e}"))?;
    let engine = TxEngine::new(outbox, 60_000);

    let from = ANVIL_ADDR0.parse().unwrap();
    let intent = RawIntent {
        body: RawIntentBody::Send {
            to: ANVIL_ADDR1.to_string(),
            value: String::new(),
            token: Some("USDC".into()),
            amount: "100".into(),
            data: None,
        },
        chain: Some("anvil".to_string()),
        gas: Default::default(),
        nonce: None,
        gas_limit_hint: None,
        usd_value_hint: None,
        review_mode: None,
    };

    let res = engine
        .stage(
            &permit,
            "alice",
            from,
            intent,
            &chain,
            &Policy::permissive(),
            None,
        )
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

/// An unmined transaction holds its own nonce in the mempool, so the pending
/// count already includes it. Reading the pending count to decide whether a
/// nonce is still replaceable therefore reports every broadcast-but-unmined
/// transaction as consumed by itself, and refuses exactly the two operations
/// the guard exists to permit: repricing a stuck transaction and cancelling
/// one. Only a mined nonce is spent, so the guard reads the latest count.
///
/// Anvil runs with `--no-mining` here, so `confirm` leaves the transaction in
/// the mempool and pending and latest genuinely disagree — the precondition
/// is asserted rather than assumed.
#[tokio::test(flavor = "multi_thread")]
async fn an_unmined_nonce_stays_replaceable_and_a_mined_one_does_not() -> Result<()> {
    let anvil = spawn_anvil(true).await?;
    let rpc_url = anvil.rpc_url();
    let chain = ChainClient::new(anvil_chain_spec(&rpc_url)).map_err(|e| anyhow!("chain: {e}"))?;

    let tmp = tempfile::tempdir()?;
    let permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(tmp.path()))?;
    let outbox = Outbox::new(tmp.path().join("outbox")).map_err(|e| anyhow!("outbox: {e}"))?;
    let (broker, broker_fixture) = exact_signing_broker(ANVIL_PK0)?;
    let engine = TxEngine::new(outbox, 60_000)
        .with_price_oracle(Arc::new(TestPriceOracle))
        .with_triad_signing(
            broker,
            exact_signing_catalog(&[
                "transaction.confirm",
                "transaction.replace",
                "transaction.cancel",
            ]),
        )
        .map_err(|e| anyhow!("triad signing: {e}"))?;
    broker_fixture.activate();

    let signer: alloy_signer_local::PrivateKeySigner = ANVIL_PK0.parse()?;
    let from = signer.address();
    let policy = {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("1000".into());
        p.limits.max_day_usd = Some("10000".into());
        p
    };
    let send = || RawIntent {
        body: RawIntentBody::Send {
            to: ANVIL_ADDR1.to_string(),
            value: "0.01 eth".into(),
            token: None,
            amount: String::new(),
            data: None,
        },
        chain: Some("anvil".to_string()),
        gas: Default::default(),
        nonce: None,
        gas_limit_hint: None,
        usd_value_hint: Some("1".into()),
        review_mode: None,
    };
    // Broadcast one transaction and leave it in the mempool.
    let first = engine
        .stage(&permit, "alice", from, send(), &chain, &policy, None)
        .await
        .map_err(|e| anyhow!("stage first: {e}"))?;
    // Every value-moving operation needs its own exact approval. The first
    // attempt prepares one and reports ApprovalRequired; the fixture answers
    // "approved" for whatever is outstanding, so the retry proceeds. A
    // one-shot call would pass for the wrong reason, so each step asserts the
    // refusal before retrying.
    let first_confirm = engine
        .confirm(&permit, "alice", "anvil", &first.id, &chain, &policy, "y")
        .await;
    assert!(
        matches!(first_confirm, Err(TxEngineError::ApprovalRequired(_))),
        "confirm should ask for its own approval first: {first_confirm:?}"
    );
    let confirmed = engine
        .confirm(&permit, "alice", "anvil", &first.id, &chain, &policy, "y")
        .await
        .map_err(|e| anyhow!("confirm first: {e}"))?;
    assert!(confirmed.tx_hash.is_some(), "confirm produced no tx hash");

    // The precondition the guard used to trip over: the transaction is in the
    // mempool, so pending is ahead of latest and its own nonce is below
    // pending. A guard reading pending would call this nonce consumed.
    let pending = chain
        .nonce(from)
        .await
        .map_err(|e| anyhow!("pending nonce: {e}"))?;
    let latest = chain
        .nonce_latest(from)
        .await
        .map_err(|e| anyhow!("latest nonce: {e}"))?;
    assert_eq!(
        latest, first.nonce,
        "nothing is mined yet, so latest must still be the staged nonce"
    );
    assert!(
        pending > first.nonce,
        "the unmined transaction should raise the pending count: pending {pending}, nonce {}",
        first.nonce
    );

    // Replacement: permitted, same nonce.
    let first_replace = engine
        .replace(&permit, "alice", "anvil", &first.id, &chain, 15, &policy)
        .await;
    assert!(
        matches!(first_replace, Err(TxEngineError::ApprovalRequired(_))),
        "replace should ask for its own approval first: {first_replace:?}"
    );
    let replaced = engine
        .replace(&permit, "alice", "anvil", &first.id, &chain, 15, &policy)
        .await
        .map_err(|e| anyhow!("replace of an unmined nonce was refused: {e}"))?;
    assert_eq!(
        replaced.nonce, first.nonce,
        "a replacement must reuse the original nonce"
    );

    // Cancellation: the same guard, the same verdict. It gets its own
    // transaction because a cancel re-bumps from the entry's recorded fees,
    // and cancelling the row just replaced would be underpriced against the
    // replacement already in the mempool — a fee question, not a nonce one.
    let second = engine
        .stage(&permit, "alice", from, send(), &chain, &policy, None)
        .await
        .map_err(|e| anyhow!("stage second: {e}"))?;
    assert!(
        second.nonce > first.nonce,
        "the second stage should reserve the next nonce"
    );
    let second_confirm = engine
        .confirm(&permit, "alice", "anvil", &second.id, &chain, &policy, "y")
        .await;
    assert!(
        matches!(second_confirm, Err(TxEngineError::ApprovalRequired(_))),
        "confirm should ask for its own approval first: {second_confirm:?}"
    );
    engine
        .confirm(&permit, "alice", "anvil", &second.id, &chain, &policy, "y")
        .await
        .map_err(|e| anyhow!("confirm second: {e}"))?;

    let first_cancel = engine
        .cancel(&permit, "alice", "anvil", &second.id, &chain, 15, &policy)
        .await;
    assert!(
        matches!(first_cancel, Err(TxEngineError::ApprovalRequired(_))),
        "cancel should ask for its own approval first: {first_cancel:?}"
    );
    let cancelled = engine
        .cancel(&permit, "alice", "anvil", &second.id, &chain, 15, &policy)
        .await
        .map_err(|e| anyhow!("cancel of an unmined nonce was refused: {e}"))?;
    assert_eq!(
        cancelled.nonce, second.nonce,
        "a cancellation must reuse the original nonce"
    );

    // A third transaction, left untouched, is what the post-mining cancel
    // acts on: the row cancelled above is terminal, and a terminal row is
    // refused for a reason that has nothing to do with nonces.
    let third = engine
        .stage(&permit, "alice", from, send(), &chain, &policy, None)
        .await
        .map_err(|e| anyhow!("stage third: {e}"))?;
    let third_confirm = engine
        .confirm(&permit, "alice", "anvil", &third.id, &chain, &policy, "y")
        .await;
    assert!(
        matches!(third_confirm, Err(TxEngineError::ApprovalRequired(_))),
        "confirm should ask for its own approval first: {third_confirm:?}"
    );
    engine
        .confirm(&permit, "alice", "anvil", &third.id, &chain, &policy, "y")
        .await
        .map_err(|e| anyhow!("confirm third: {e}"))?;

    // Mine what is queued. The nonce is now genuinely spent, and the guard
    // must say so rather than let a doomed same-nonce broadcast through.
    mine_pending(&rpc_url).await?;
    let mined_latest = chain
        .nonce_latest(from)
        .await
        .map_err(|e| anyhow!("latest nonce after mining: {e}"))?;
    assert!(
        mined_latest > first.nonce,
        "mining should advance the latest count past {}: {mined_latest}",
        first.nonce
    );

    let after_mining = engine
        .replace(&permit, "alice", "anvil", &first.id, &chain, 15, &policy)
        .await;
    assert!(
        matches!(after_mining, Err(TxEngineError::NonceConsumed { .. })),
        "a mined nonce must report NonceConsumed: {after_mining:?}"
    );
    let cancel_after_mining = engine
        .cancel(&permit, "alice", "anvil", &third.id, &chain, 15, &policy)
        .await;
    assert!(
        matches!(
            cancel_after_mining,
            Err(TxEngineError::NonceConsumed { .. })
        ),
        "cancelling a mined nonce must report NonceConsumed: {cancel_after_mining:?}"
    );

    drop(anvil);
    Ok(())
}

/// Stage a native send, broadcast via `confirm`, then call `replace`
/// with a 15% fee bump. Asserts that the replacement carries the same
/// nonce and strictly higher fees.
#[tokio::test(flavor = "multi_thread")]
async fn replace_keeps_nonce_and_bumps_fees() -> Result<()> {
    let anvil = spawn_anvil(true).await?;
    let rpc_url = anvil.rpc_url();
    let chain = ChainClient::new(anvil_chain_spec(&rpc_url)).map_err(|e| anyhow!("chain: {e}"))?;

    let tmp = tempfile::tempdir()?;
    let permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(tmp.path()))?;
    let outbox = Outbox::new(tmp.path().join("outbox")).map_err(|e| anyhow!("outbox: {e}"))?;
    let (broker, broker_fixture) = exact_signing_broker(ANVIL_PK0)?;
    let engine = TxEngine::new(outbox, 60_000)
        .with_price_oracle(Arc::new(TestPriceOracle))
        .with_triad_signing(
            broker,
            exact_signing_catalog(&["transaction.confirm", "transaction.replace"]),
        )
        .map_err(|e| anyhow!("triad signing: {e}"))?;

    // Use anvil's prefunded account #0 as the signer.
    let signer: alloy_signer_local::PrivateKeySigner = ANVIL_PK0.parse()?;
    let from = signer.address();

    // Keep the staged transaction inside ordinary policy limits. Confirm and
    // replace still require separate pre-minted Sealed Approval grants below.
    let policy = {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("1000".into());
        p.limits.max_day_usd = Some("10000".into());
        p
    };

    let intent = RawIntent {
        body: RawIntentBody::Send {
            to: ANVIL_ADDR1.to_string(),
            value: "0.01 eth".into(),
            token: None,
            amount: String::new(),
            data: None,
        },
        chain: Some("anvil".to_string()),
        gas: Default::default(),
        nonce: None,
        gas_limit_hint: None,
        usd_value_hint: Some("1".into()),
        review_mode: None,
    };

    let staged = engine
        .stage(&permit, "alice", from, intent, &chain, &policy, None)
        .await
        .map_err(|e| anyhow!("stage: {e}"))?;
    let original_nonce = staged.nonce;
    let original_max_fee: u128 = staged
        .max_fee_per_gas
        .as_deref()
        .ok_or_else(|| anyhow!("missing max_fee_per_gas"))?
        .parse()?;

    assert!(matches!(
        engine
            .confirm(&permit, "alice", "anvil", &staged.id, &chain, &policy, "y")
            .await,
        Err(TxEngineError::ApprovalRequired(_))
    ));
    broker_fixture.activate();
    let confirmed = engine
        .confirm(&permit, "alice", "anvil", &staged.id, &chain, &policy, "y")
        .await
        .map_err(|e| anyhow!("confirm: {e}"))?;
    assert!(confirmed.tx_hash.is_some(), "confirm produced no tx hash");

    // Replace with +15% fees.
    let first_replace = engine
        .replace(&permit, "alice", "anvil", &staged.id, &chain, 15, &policy)
        .await;
    assert!(
        matches!(first_replace, Err(TxEngineError::ApprovalRequired(_))),
        "first replacement should require its own exact approval: {first_replace:?}"
    );
    let replaced = engine
        .replace(&permit, "alice", "anvil", &staged.id, &chain, 15, &policy)
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
