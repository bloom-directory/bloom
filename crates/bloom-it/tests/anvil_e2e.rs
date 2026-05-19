//! Category: integration
//!
//! End-to-end integration test for the bloom stage-confirm flow.
//!
//! Runs against a real `anvil` instance spawned as a child process. Marked
//! `#[ignore]` so it only runs when explicitly requested:
//!
//! ```text
//! cargo test -p bloom-it -- --ignored
//! ```
//!
//! Requires the `anvil` and `cast` binaries from Foundry to be available
//! at `~/.foundry/bin/{anvil,cast}` (or on `$PATH`).

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bloom_daemon::Daemon;
use bloom_it::{cast_send, spawn_anvil};
use bloom_proto::{ChainSpec, Config, HomeDir};
use bloom_vfs::VfsPath;
use bloom_vfs::handler::Handler;
use tokio::time::sleep;

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
#[ignore]
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
    let daemon = Daemon::from_home(home).map_err(|e| anyhow!("daemon: {e}"))?;

    // 3. Create a wallet via the keystore.
    let passphrase = "integration-test-pass";
    let info = daemon
        .keystore
        .create_local("alice", passphrase)
        .map_err(|e| anyhow!("create_local: {e}"))?;
    let alice_addr = format!("{:#x}", info.address);

    // 4. Fund alice from anvil's prefunded #0 via `cast send`.
    fund_via_cast(&rpc_url, &alice_addr, 10).await?;

    // Allow the funding tx to be picked up by anvil's auto-mine.
    sleep(Duration::from_millis(250)).await;

    // 5. Verify the balance is reflected through the VFS.
    let bal_path = VfsPath::parse("/wallets/alice/chains/anvil/balance.eth").unwrap();
    let bal_bytes = daemon
        .vfs
        .read(&bal_path)
        .await
        .map_err(|e| anyhow!("read balance: {e}"))?;
    let bal_str = String::from_utf8(bal_bytes)?;
    assert!(
        bal_str.contains("ETH"),
        "balance.eth missing 'ETH' suffix: {bal_str:?}"
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

    // 8. Unlock the wallet, then write `confirm` to broadcast.
    daemon
        .keystore
        .unlock("alice", passphrase)
        .map_err(|e| anyhow!("unlock: {e}"))?;
    let confirm_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/confirm"
    ))
    .unwrap();
    daemon
        .vfs
        .write(&confirm_path, b"y")
        .await
        .map_err(|e| anyhow!("confirm write: {e}"))?;

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
