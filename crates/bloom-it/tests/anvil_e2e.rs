//! Category: integration
//!
//! End-to-end integration test for the bloom stage-confirm flow.
//!
//! Runs against a real `anvil` instance spawned as a child process:
//!
//! ```text
//! cargo test -p bloom-it --test anvil_e2e
//! ```
//!
//! Requires the `anvil` and `cast` binaries from Foundry to be available
//! at `~/.foundry/bin/{anvil,cast}` (or on `$PATH`).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bloom_daemon::Daemon;
use bloom_it::{cast_send, exact_signing_broker, exact_signing_catalog, spawn_anvil};
use bloom_proto::{ChainSpec, Config, HomeDir, HomeWritePermit};
use bloom_vfs::VfsPath;
use bloom_vfs::handler::Handler;
use tokio::time::sleep;

const TEST_WALLET_PRIVATE_KEY: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000001";

/// Fund `to_addr` with `value_eth` ETH from anvil's prefunded account #0.
async fn fund_via_cast(rpc_url: &str, to_addr: &str, value_eth: u64) -> Result<()> {
    let value = format!("{}ether", value_eth);
    let _ = cast_send(rpc_url, &[to_addr, "--value", &value]).await?;
    Ok(())
}

/// Build a config.toml under `home` that points the anvil chain at our spawned
/// node and enables broadcast.
fn write_config(home_root: &std::path::Path, rpc_url: &str) -> Result<()> {
    let mut cfg = Config::local_default();
    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![rpc_url.to_string()];
    spec.allow_broadcast = true;
    cfg.chains.insert("anvil".to_string(), spec);
    let path = home_root.join("config.toml");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    cfg.save(&path).map_err(|e| anyhow!("save config: {e}"))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn anvil_full_stage_confirm_flow() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,bloom_tx=info")),
        )
        .with_test_writer()
        .try_init();

    // 1. Anvil up.
    let anvil = spawn_anvil().await?;
    let rpc_url = anvil.rpc_url();

    // 2. Build a daemon under a temp home pointing at our anvil.
    let tmp = tempfile::tempdir()?;
    let home_root = tmp.path().to_path_buf();
    write_config(&home_root, &rpc_url)?;
    let home = HomeDir::at(&home_root);
    let permit = Arc::new(HomeWritePermit::acquire(&home)?);
    let test_signer: alloy_signer_local::PrivateKeySigner = TEST_WALLET_PRIVATE_KEY.parse()?;
    let (broker, fixture) = exact_signing_broker(TEST_WALLET_PRIVATE_KEY)?;
    let daemon = Daemon::from_home_with_permit_and_broker(
        home,
        permit,
        broker,
        exact_signing_catalog(&["transaction.confirm"]),
    )
    .map_err(|e| anyhow!("daemon: {e}"))?;

    // The Broker fixture publishes the wallet projection and produces the
    // exact signature. Machine owns no parallel keystore or policy fixture.
    let alice_addr = format!("{:#x}", test_signer.address());

    // 4. Fund alice from anvil's prefunded #0 via `cast send`.
    fund_via_cast(&rpc_url, &alice_addr, 10).await?;

    // Allow the funding tx to be picked up by anvil's auto-mine.
    sleep(Duration::from_millis(250)).await;

    // 5. Verify the balance is reflected through the VFS.
    let bal_path = VfsPath::parse("/wallets/alice/chains/anvil/balance").unwrap();
    let bal_bytes = daemon
        .vfs
        .read(&bal_path)
        .await
        .map_err(|e| anyhow!("read balance: {e}"))?;
    let bal_str = String::from_utf8(bal_bytes)?;
    assert!(
        bal_str.contains("ETH"),
        "balance missing native symbol suffix: {bal_str:?}"
    );
    assert!(
        bal_str.starts_with("10"),
        "expected 10 ETH balance, got {bal_str:?}"
    );

    // 6. Stage a send by writing into outbox/new.tx.
    //    Recipient: anvil prefunded account #1
    //    (0x70997970C51812dc3A010C7d01b50e0d17dc79C8).
    let recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    let intent = serde_json::json!({
        "kind": "send",
        "to": recipient,
        "value": "1 eth",
        "chain": "anvil",
        "usd_value_hint": "1",
    })
    .to_string();
    let new_tx_path = VfsPath::parse("/wallets/alice/chains/anvil/outbox/new.tx").unwrap();
    daemon
        .vfs
        .write(&new_tx_path, intent.as_bytes())
        .await
        .map_err(|e| anyhow!("stage write: {e}"))?;

    // Confirm a pending entry now exists.
    let pending_dir = VfsPath::parse("/wallets/alice/chains/anvil/outbox/pending").unwrap();
    let entries = daemon
        .vfs
        .list(&pending_dir)
        .await
        .map_err(|e| anyhow!("list pending: {e}"))?;
    assert_eq!(entries.len(), 1, "expected exactly one pending entry");
    let pending_id = entries[0].name.clone();

    // 7. Read plan.md and policy_check.json from the pending dir.
    let plan_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/plan.md"
    ))
    .unwrap();
    let plan_bytes = daemon
        .vfs
        .read(&plan_path)
        .await
        .map_err(|e| anyhow!("read plan.md: {e}"))?;
    let plan = String::from_utf8(plan_bytes)?;
    assert!(!plan.is_empty(), "plan.md is empty");

    let policy_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/policy_check.json"
    ))
    .unwrap();
    let policy_bytes = daemon
        .vfs
        .read(&policy_path)
        .await
        .map_err(|e| anyhow!("read policy_check.json: {e}"))?;
    let _: serde_json::Value =
        serde_json::from_slice(&policy_bytes).context("policy_check.json must be valid JSON")?;

    // 8. First confirm must fail closed and persist the exact Broker ceremony
    // projection. Once the fixture reports the same approval active, retry
    // signs the exact EIP-1559 preimage through MachineBrokerClient.
    let confirm_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/confirm"
    ))
    .unwrap();
    let confirm_body = "y\n";
    let first_confirm = daemon
        .vfs
        .write(&confirm_path, confirm_body.as_bytes())
        .await;
    assert!(
        first_confirm.is_err(),
        "initial confirm unexpectedly succeeded without Sealed Approval"
    );

    let ceremony_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/ceremony.json"
    ))
    .unwrap();
    let ceremony_bytes = daemon
        .vfs
        .read(&ceremony_path)
        .await
        .map_err(|e| anyhow!("read ceremony.json: {e}"))?;
    let ceremony: serde_json::Value =
        serde_json::from_slice(&ceremony_bytes).context("ceremony.json must be valid JSON")?;
    assert!(
        ceremony
            .get("ceremony_url")
            .and_then(|v| v.as_str())
            .is_some_and(|url| url == "http://localhost:18734/ceremony/exact-signing-test-secret"),
        "ceremony.json omitted the Broker launch URL: {ceremony}"
    );
    assert!(
        ceremony
            .get("approval_operation_id")
            .and_then(|v| v.as_str())
            .is_some_and(|id| id.len() == 64),
        "ceremony.json omitted durable operation identity: {ceremony}"
    );

    fixture.activate();
    daemon
        .vfs
        .write(&confirm_path, confirm_body.as_bytes())
        .await
        .map_err(|e| anyhow!("Broker-backed confirm retry write: {e}"))?;
    let terminal: serde_json::Value = serde_json::from_slice(
        &daemon
            .vfs
            .read(
                &VfsPath::parse(&format!(
                    "/wallets/alice/chains/anvil/outbox/sent/{pending_id}/ceremony.json"
                ))
                .unwrap(),
            )
            .await
            .map_err(|e| anyhow!("read terminal ceremony.json: {e}"))?,
    )?;
    assert!(
        terminal
            .get("ceremony_url")
            .is_some_and(serde_json::Value::is_null),
        "terminal signing projection retained launch URL: {terminal}"
    );
    assert!(
        terminal
            .get("sign_dispatched")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        "terminal signing projection omitted durable dispatch marker: {terminal}"
    );

    // 9. Verify the entry now lives in `sent/` with a tx_hash artefact.
    let sent_dir = VfsPath::parse("/wallets/alice/chains/anvil/outbox/sent").unwrap();
    let sent_entries = daemon
        .vfs
        .list(&sent_dir)
        .await
        .map_err(|e| anyhow!("list sent: {e}"))?;
    assert!(
        sent_entries.iter().any(|e| e.name == pending_id),
        "expected {pending_id} in sent/, got {:?}",
        sent_entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );

    let tx_hash_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/sent/{pending_id}/tx_hash"
    ))
    .unwrap();
    let tx_hash_bytes = daemon
        .vfs
        .read(&tx_hash_path)
        .await
        .map_err(|e| anyhow!("read tx_hash: {e}"))?;
    let tx_hash = String::from_utf8(tx_hash_bytes)?;
    assert!(
        tx_hash.starts_with("0x") && tx_hash.len() >= 66,
        "tx_hash looks malformed: {tx_hash:?}"
    );

    // intent.json should reflect Sent status with a tx_hash.
    let intent_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/sent/{pending_id}/intent.json"
    ))
    .unwrap();
    let intent_bytes = daemon
        .vfs
        .read(&intent_path)
        .await
        .map_err(|e| anyhow!("read intent.json: {e}"))?;
    let intent_val: serde_json::Value = serde_json::from_slice(&intent_bytes)?;
    assert_eq!(
        intent_val.get("status").and_then(|v| v.as_str()),
        Some("sent"),
        "intent.json status should be 'sent', got {intent_val}"
    );
    assert!(
        intent_val
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.starts_with("0x"))
            .unwrap_or(false),
        "intent.json missing tx_hash"
    );

    // Drop guard kills anvil.
    drop(anvil);
    Ok(())
}

/// A confirm whose staged nonce is ahead of the account's on-chain nonce must
/// be refused at broadcast (the node would queue it behind the missing nonce
/// and it could never mine), leaving a `nonce_gap.json` advisory and the entry
/// still pending. Exercises both the broadcast-time gap guard and the explicit
/// `nonce` override intake on `outbox/new.tx`.
#[tokio::test(flavor = "multi_thread")]
async fn anvil_confirm_refuses_nonce_gap() -> Result<()> {
    let anvil = spawn_anvil().await?;
    let rpc_url = anvil.rpc_url();

    let tmp = tempfile::tempdir()?;
    let home_root = tmp.path().to_path_buf();
    write_config(&home_root, &rpc_url)?;
    let home = HomeDir::at(&home_root);
    let permit = Arc::new(HomeWritePermit::acquire(&home)?);
    let test_signer: alloy_signer_local::PrivateKeySigner = TEST_WALLET_PRIVATE_KEY.parse()?;
    let (broker, _fixture) = exact_signing_broker(TEST_WALLET_PRIVATE_KEY)?;
    let daemon = Daemon::from_home_with_permit_and_broker(
        home,
        permit,
        broker,
        exact_signing_catalog(&["transaction.confirm"]),
    )
    .map_err(|e| anyhow!("daemon: {e}"))?;
    let alice_addr = format!("{:#x}", test_signer.address());

    // Fund alice so gas is affordable — the refusal must be the nonce gap, not
    // an insufficient-funds error.
    fund_via_cast(&rpc_url, &alice_addr, 10).await?;
    sleep(Duration::from_millis(250)).await;

    // Stage a send pinned to nonce 5, five slots ahead of alice's real nonce (0).
    let recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    let intent = serde_json::json!({
        "kind": "send",
        "to": recipient,
        "value": "1 eth",
        "chain": "anvil",
        "usd_value_hint": "1",
        "nonce": 5,
    })
    .to_string();
    let new_tx_path = VfsPath::parse("/wallets/alice/chains/anvil/outbox/new.tx").unwrap();
    daemon
        .vfs
        .write(&new_tx_path, intent.as_bytes())
        .await
        .map_err(|e| anyhow!("stage write: {e}"))?;

    let pending_dir = VfsPath::parse("/wallets/alice/chains/anvil/outbox/pending").unwrap();
    let entries = daemon
        .vfs
        .list(&pending_dir)
        .await
        .map_err(|e| anyhow!("list pending: {e}"))?;
    assert_eq!(entries.len(), 1, "expected exactly one pending entry");
    let pending_id = entries[0].name.clone();

    // The nonce gap is a deterministic pre-signing failure. It must be denied
    // before Machine creates a Broker ceremony or dispatches a signing request.
    let confirm_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/confirm"
    ))
    .unwrap();
    let gap_confirm = daemon.vfs.write(&confirm_path, b"y\n").await;
    let err = gap_confirm.expect_err("confirm at a nonce gap must be refused");
    let err = err.to_string().to_lowercase();
    assert!(
        err.contains("nonce gap"),
        "expected a nonce-gap refusal, got: {err}"
    );
    let ceremony_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/ceremony.json"
    ))
    .unwrap();
    assert!(
        daemon.vfs.read(&ceremony_path).await.is_err(),
        "nonce-gap denial must not create a signing ceremony"
    );

    // The entry stays pending (never sent), with a machine-readable advisory.
    let sent_dir = VfsPath::parse("/wallets/alice/chains/anvil/outbox/sent").unwrap();
    let sent = daemon
        .vfs
        .list(&sent_dir)
        .await
        .map(|e| e.iter().any(|e| e.name == pending_id))
        .unwrap_or(false);
    assert!(!sent, "gapped tx must not have been broadcast to sent/");

    let advisory_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/nonce_gap.json"
    ))
    .unwrap();
    let advisory: serde_json::Value = serde_json::from_slice(
        &daemon
            .vfs
            .read(&advisory_path)
            .await
            .map_err(|e| anyhow!("read nonce_gap.json: {e}"))?,
    )
    .context("nonce_gap.json must be valid JSON")?;
    assert_eq!(
        advisory.get("staged_nonce").and_then(|v| v.as_u64()),
        Some(5)
    );
    assert_eq!(
        advisory.get("chain_next_nonce").and_then(|v| v.as_u64()),
        Some(0)
    );

    drop(anvil);
    Ok(())
}

/// Disable anvil's auto-mining so a broadcast transaction sits in the mempool
/// instead of being included immediately. That gap — broadcast but not yet
/// mined — is the window this test is about.
async fn set_automine(rpc_url: &str, enabled: bool) -> Result<()> {
    let out = tokio::process::Command::new(bloom_it::cast_bin())
        .args(["rpc", "--rpc-url", rpc_url, "evm_setAutomine"])
        .arg(enabled.to_string())
        .output()
        .await
        .context("invoke cast rpc evm_setAutomine")?;
    if !out.status.success() {
        return Err(anyhow!(
            "evm_setAutomine failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Staging a second transaction while the first is broadcast but unmined must
/// not reuse the first one's nonce.
///
/// Regression: staging read the chain nonce from the pinned read session, which
/// reports the *historical* count at the pinned block and so cannot see a
/// transaction still in the mempool. `highest_pending_nonce` could not cover
/// the gap either, because broadcasting moves an entry out of `pending/` and
/// into `sent/`. Between broadcast and inclusion neither source knew about the
/// in-flight transaction, so the next stage handed out a nonce that was already
/// spent — whichever transaction mined second was rejected as a duplicate.
///
/// Seen live on a Morpho `approve` → `deposit` pair, where the deposit was
/// staged at the approve's nonce and had to be re-drafted by hand.
#[tokio::test(flavor = "multi_thread")]
async fn anvil_stage_does_not_reuse_the_nonce_of_a_broadcast_but_unmined_tx() -> Result<()> {
    let anvil = spawn_anvil().await?;
    let rpc_url = anvil.rpc_url();

    let tmp = tempfile::tempdir()?;
    let home_root = tmp.path().to_path_buf();
    write_config(&home_root, &rpc_url)?;
    let home = HomeDir::at(&home_root);
    let permit = Arc::new(HomeWritePermit::acquire(&home)?);
    let test_signer: alloy_signer_local::PrivateKeySigner = TEST_WALLET_PRIVATE_KEY.parse()?;
    let (broker, fixture) = exact_signing_broker(TEST_WALLET_PRIVATE_KEY)?;
    let daemon = Daemon::from_home_with_permit_and_broker(
        home,
        permit,
        broker,
        exact_signing_catalog(&["transaction.confirm"]),
    )
    .map_err(|e| anyhow!("daemon: {e}"))?;
    let alice_addr = format!("{:#x}", test_signer.address());
    // The owner ceremony is not what this test is about; stand it up once so
    // the confirm below actually broadcasts.
    fixture.activate();

    fund_via_cast(&rpc_url, &alice_addr, 10).await?;
    sleep(Duration::from_millis(250)).await;

    let recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    let stage = |label: &'static str| {
        let vfs = daemon.vfs.clone();
        async move {
            let intent = serde_json::json!({
                "kind": "send",
                "to": recipient,
                "value": "1 eth",
                "chain": "anvil",
                "usd_value_hint": "1",
            })
            .to_string();
            let new_tx_path = VfsPath::parse("/wallets/alice/chains/anvil/outbox/new.tx").unwrap();
            vfs.write(&new_tx_path, intent.as_bytes())
                .await
                .map_err(|e| anyhow!("stage {label}: {e}"))?;
            let pending_dir = VfsPath::parse("/wallets/alice/chains/anvil/outbox/pending").unwrap();
            let entries = vfs
                .list(&pending_dir)
                .await
                .map_err(|e| anyhow!("list pending after {label}: {e}"))?;
            let entry = entries
                .last()
                .ok_or_else(|| anyhow!("no pending entry after staging {label}"))?;
            Ok::<String, anyhow::Error>(entry.name.clone())
        }
    };

    // The first transaction takes nonce 0 and is broadcast.
    let first_id = stage("first").await?;
    // Stop mining before the confirm, so the broadcast transaction stays in the
    // mempool while the second stage reads its nonce.
    set_automine(&rpc_url, false).await?;
    let confirm_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{first_id}/confirm"
    ))
    .unwrap();
    // The first confirm always fails closed while it mints the approval; the
    // retry is the one that signs and broadcasts.
    assert!(
        daemon.vfs.write(&confirm_path, b"y\n").await.is_err(),
        "initial confirm unexpectedly succeeded without Sealed Approval"
    );
    daemon
        .vfs
        .write(&confirm_path, b"y\n")
        .await
        .map_err(|e| anyhow!("confirm first: {e}"))?;

    // It left `pending/` for `sent/`, so `highest_pending_nonce` no longer
    // sees it — the chain read is now the only thing standing between the next
    // stage and a duplicate nonce.
    let sent_intent = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/sent/{first_id}/intent.json"
    ))
    .unwrap();
    let first: serde_json::Value = serde_json::from_slice(
        &daemon
            .vfs
            .read(&sent_intent)
            .await
            .map_err(|e| anyhow!("read sent intent.json: {e}"))?,
    )
    .context("sent intent.json must be valid JSON")?;
    assert_eq!(
        first.get("nonce").and_then(|v| v.as_u64()),
        Some(0),
        "first transaction should have taken nonce 0"
    );

    let second_id = stage("second").await?;
    let second_intent = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{second_id}/intent.json"
    ))
    .unwrap();
    let second: serde_json::Value = serde_json::from_slice(
        &daemon
            .vfs
            .read(&second_intent)
            .await
            .map_err(|e| anyhow!("read pending intent.json: {e}"))?,
    )
    .context("pending intent.json must be valid JSON")?;
    assert_eq!(
        second.get("nonce").and_then(|v| v.as_u64()),
        Some(1),
        "staging must skip the nonce of the transaction still in the mempool"
    );

    set_automine(&rpc_url, true).await?;
    drop(anvil);
    Ok(())
}
