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
use bloom_it::{cast_send, mint_evm_test_grant, spawn_anvil};
use bloom_proto::{ChainSpec, Config, HomeDir, HomeWritePermit};
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

fn now_ms_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
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
    let daemon = Daemon::from_home_with_permit(home, permit).map_err(|e| anyhow!("daemon: {e}"))?;

    // 3. Create a wallet via the keystore.
    let passphrase = "integration-test-pass";
    let info = daemon
        .keystore
        .create_local("alice", passphrase)
        .map_err(|e| anyhow!("create_local: {e}"))?;
    let alice_addr = format!("{:#x}", info.address);

    // Keep broadcast in fresh-review mode. The pre-minted Sealed Approval
    // grant below is the explicit authorization used by this test.
    let wallet_dir = tmp.path().join("keystore").join("alice");
    std::fs::write(
        wallet_dir.join("policy.toml"),
        "[approval]\nagent_autonomy = \"prompt_all\"\n",
    )?;

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

    // 8. First confirm must fail closed and emit a Sealed Approval challenge.
    // Then mint the same in-memory grant that a successful ceremony would mint
    // for the emitted central action id and retry confirm to broadcast. The
    // Anvil test does not have a browser/WebAuthn device, but this still
    // exercises the mounted denial boundary, challenge projection, production
    // grant-gated KeystorePetalHost sign_hash path, and raw tx broadcast.
    daemon
        .keystore
        .unlock("alice", passphrase)
        .map_err(|e| anyhow!("unlock: {e}"))?;
    let grant_store = daemon
        .auth_services
        .require_grant_store()
        .map_err(|e| anyhow!("grant store: {e}"))?;
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

    let challenge_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/approval_challenge.json"
    ))
    .unwrap();
    let challenge_bytes = daemon
        .vfs
        .read(&challenge_path)
        .await
        .map_err(|e| anyhow!("read approval_challenge.json: {e}"))?;
    let challenge: serde_json::Value = serde_json::from_slice(&challenge_bytes)
        .context("approval_challenge.json must be valid JSON")?;
    let action_id = challenge
        .get("action_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("approval_challenge.json missing action_id: {challenge}"))?;
    assert!(
        challenge
            .get("ceremony_url")
            .and_then(|v| v.as_str())
            .map(|url| url.starts_with("http://localhost") || url.starts_with("http://127.0.0.1"))
            .unwrap_or(false),
        "approval_challenge.json missing local ceremony_url: {challenge}"
    );

    mint_evm_test_grant(
        grant_store.as_ref(),
        "alice",
        action_id,
        "confirm",
        31337,
        &alice_addr,
        now_ms_u64(),
    )
    .await
    .map_err(|e| anyhow!("mint confirm grant: {e}"))?;
    daemon
        .vfs
        .write(&confirm_path, confirm_body.as_bytes())
        .await
        .map_err(|e| anyhow!("confirm retry write: {e}"))?;

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
    let daemon = Daemon::from_home_with_permit(home, permit).map_err(|e| anyhow!("daemon: {e}"))?;

    let passphrase = "integration-test-pass";
    let info = daemon
        .keystore
        .create_local("alice", passphrase)
        .map_err(|e| anyhow!("create_local: {e}"))?;
    let alice_addr = format!("{:#x}", info.address);

    let wallet_dir = tmp.path().join("keystore").join("alice");
    std::fs::write(
        wallet_dir.join("policy.toml"),
        "[approval]\nagent_autonomy = \"prompt_all\"\n",
    )?;

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

    // First confirm fails closed → emits a challenge; mint the grant a ceremony
    // would produce and retry.
    daemon
        .keystore
        .unlock("alice", passphrase)
        .map_err(|e| anyhow!("unlock: {e}"))?;
    let grant_store = daemon
        .auth_services
        .require_grant_store()
        .map_err(|e| anyhow!("grant store: {e}"))?;
    let confirm_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/confirm"
    ))
    .unwrap();
    let first_confirm = daemon.vfs.write(&confirm_path, b"y\n").await;
    assert!(
        first_confirm.is_err(),
        "initial confirm unexpectedly succeeded without Sealed Approval"
    );

    let challenge_path = VfsPath::parse(&format!(
        "/wallets/alice/chains/anvil/outbox/pending/{pending_id}/approval_challenge.json"
    ))
    .unwrap();
    let challenge: serde_json::Value = serde_json::from_slice(
        &daemon
            .vfs
            .read(&challenge_path)
            .await
            .map_err(|e| anyhow!("read approval_challenge.json: {e}"))?,
    )
    .context("approval_challenge.json must be valid JSON")?;
    let action_id = challenge
        .get("action_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("approval_challenge.json missing action_id: {challenge}"))?;

    mint_evm_test_grant(
        grant_store.as_ref(),
        "alice",
        action_id,
        "confirm",
        31337,
        &alice_addr,
        now_ms_u64(),
    )
    .await
    .map_err(|e| anyhow!("mint confirm grant: {e}"))?;

    // Retry with a live grant: the approval gate is now satisfied, but the
    // broadcast must be refused because nonce 5 is ahead of chain nonce 0.
    let gap_confirm = daemon.vfs.write(&confirm_path, b"y\n").await;
    let err = gap_confirm.expect_err("confirm at a nonce gap must be refused");
    let err = err.to_string().to_lowercase();
    assert!(
        err.contains("nonce gap"),
        "expected a nonce-gap refusal, got: {err}"
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
