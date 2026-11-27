//! The blockhash-expiry → restage recovery E2E, the companion to
//! `solana_workflow` for the failure path that workflow test never reaches.
//!
//! It proves two coupled properties of Bloom's Solana engine against a REAL
//! local Agave validator:
//!
//!   1. Fail-closed on expiry. Once the validator's block height passes a
//!      staged transfer's `last_valid_block_height`, `confirm` MUST refuse to
//!      sign or broadcast — even with owner approval already active, so the
//!      only possible reason to refuse is the expired blockhash.
//!   2. Recovery via restage. Writing `restage` rebuilds the SAME economic
//!      intent (same account pin, destination, lamports) with a FRESH blockhash
//!      as a new replacement entry, marks the old one `failed`/`Expired`, and
//!      links the two through `restage_advice.json`. Confirming the replacement
//!      then signs, broadcasts, and finalizes exactly once.
//!
//! Boundary, as in `solana_workflow` and the EVM `anvil_e2e`: the Broker is an
//! in-process fixture. The Daemon, VFS, wallet handler, Solana engine,
//! reconciler, and validator are real.

mod common;

use std::sync::atomic::Ordering;

use anyhow::{Result, anyhow};
use bloom_vfs::VfsPath;
use bloom_vfs::handler::Handler;
use common::*;
use sha2::{Digest as _, Sha256};

const LAMPORTS: u64 = 250_000_000;

fn block_height() -> Result<u64> {
    rpc("getBlockHeight", serde_json::json!([]))?["result"]
        .as_u64()
        .ok_or_else(|| anyhow!("validator did not answer getBlockHeight"))
}

/// A unique, non-fixed 32-byte destination so the test is idempotent even on a
/// reused ledger: a fresh address starts at zero balance and cannot collide
/// with a prior run. Derived from a monotonic nonce rather than a fixed byte
/// pattern.
fn unique_destination() -> [u8; 32] {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(b"bloom-restage-e2e-destination/v1");
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.finalize().into()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn solana_expired_blockhash_fails_closed_then_restages() -> Result<()> {
    init_tracing();

    step("1", "derive the Solana account from the BIP-39 mnemonic");
    let child = Child::derive(&seed()?, 0)?;
    let address = child.address.clone();
    println!("    path        {}", child.path);
    println!("    address     {address}");

    // 2. Real daemon over a temp home, wired to the local validator.
    step("2", "build a real Daemon with the Solana chain configured");
    let broker = SolanaBroker::new(vec![child]);
    let tmp = solana_home()?;
    let daemon = daemon_at(tmp.path(), broker.clone(), catalog(&[]))?;
    println!("    daemon constructed; solana-local admitted by the genesis guard");

    // 3. Fund the derived child and record its starting balance.
    step("3", "airdrop to the mnemonic-derived fee payer");
    airdrop(&address, 2_000_000_000).await?;
    let payer_before = balance(&address)?;
    println!("    fee payer balance before = {payer_before} lamports");

    // 4. A unique, non-fixed destination — idempotent on a reused ledger.
    let destination_bytes = unique_destination();
    let destination = bs58::encode(destination_bytes).into_string();
    let dest_before = balance(&destination)?;
    println!("    unique destination {destination} balance before = {dest_before} lamports");
    assert_eq!(
        dest_before, 0,
        "a freshly derived destination must start empty"
    );

    // 5. Stage transfer T1.
    step("5", "stage transfer T1");
    let new_tx = VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/new.tx").unwrap();
    let intent = serde_json::json!({"destination": destination, "lamports": LAMPORTS});
    daemon
        .vfs
        .write(&new_tx, serde_json::to_vec(&intent)?.as_slice())
        .await
        .map_err(|e| anyhow!("stage write: {e}"))?;
    let pending = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list pending: {e}"))?;
    let t1_id = pending
        .first()
        .ok_or_else(|| anyhow!("no pending entry staged"))?
        .name
        .clone();
    let t1 = read_json(
        &daemon,
        &format!("/wallets/alice/0/chains/solana-local/outbox/pending/{t1_id}/intent.json"),
    )
    .await?;
    let t1_lvbh = t1["last_valid_block_height"]
        .as_u64()
        .ok_or_else(|| anyhow!("T1 intent missing last_valid_block_height"))?;
    let t1_blockhash = t1["blockhash"].as_str().unwrap().to_string();
    assert_eq!(t1["fee_payer"].as_str().unwrap(), address);
    assert_eq!(t1["lamports"].as_u64(), Some(LAMPORTS));
    println!("    staged T1 id={t1_id} last_valid_block_height={t1_lvbh} blockhash={t1_blockhash}");

    // 6. Age the blockhash: wait until block height passes T1's window.
    step(
        "6",
        "wait until block height passes T1's last_valid_block_height",
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut current = block_height()?;
    while current <= t1_lvbh {
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "block height {current} never passed {t1_lvbh} within 120s"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        current = block_height()?;
    }
    println!("    block height {current} now exceeds T1's window {t1_lvbh}");

    // 7. Confirm T1 with owner approval ALREADY active, so the only possible
    //    reason to refuse is the expired blockhash. It must fail closed.
    step(
        "7",
        "confirm expired T1 must fail closed (no sign, no broadcast)",
    );
    broker.approval_active.store(true, Ordering::SeqCst);
    let confirm_t1 = VfsPath::parse(&format!(
        "/wallets/alice/0/chains/solana-local/outbox/pending/{t1_id}/confirm"
    ))
    .unwrap();
    let refusal = daemon.vfs.write(&confirm_t1, b"y\n").await;
    let refusal_msg = match &refusal {
        Err(e) => e.to_string(),
        Ok(()) => {
            return Err(anyhow!(
                "SECURITY: confirm of an expired blockhash succeeded"
            ));
        }
    };
    println!("    confirm correctly refused: {refusal_msg}");
    assert!(
        refusal_msg.contains("expired") || refusal_msg.contains("restage"),
        "the refusal must be about blockhash expiry, got: {refusal_msg}"
    );
    // The signer was never asked to sign the expired message.
    assert!(
        broker.sign_calls.lock().is_empty(),
        "fail-closed means the Broker was never asked to sign"
    );
    // Nothing moved to `sent`, and the destination is untouched.
    let sent = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/sent").unwrap())
        .await
        .map_err(|e| anyhow!("list sent: {e}"))?;
    assert!(
        !sent.iter().any(|e| e.name == t1_id),
        "an expired T1 must never appear in sent/"
    );
    let dest_mid = balance(&destination)?;
    assert_eq!(
        dest_mid, 0,
        "no broadcast means the destination stays empty"
    );
    println!("    no signing call, T1 not in sent/, destination still 0");

    // 8. Restage T1 → a fresh replacement, T1 marked failed/Expired.
    step("8", "restage T1 into a fresh replacement T2");
    let restage_t1 = VfsPath::parse(&format!(
        "/wallets/alice/0/chains/solana-local/outbox/pending/{t1_id}/restage"
    ))
    .unwrap();
    daemon
        .vfs
        .write(&restage_t1, b"y\n")
        .await
        .map_err(|e| anyhow!("restage write: {e}"))?;
    let advice = read_json(
        &daemon,
        &format!("/wallets/alice/0/chains/solana-local/outbox/failed/{t1_id}/restage_advice.json"),
    )
    .await?;
    println!(
        "    restage_advice.json = {}",
        serde_json::to_string(&advice)?
    );
    assert_eq!(
        advice["schema"].as_str(),
        Some("bloom.solana-restage-advice/1")
    );
    assert_eq!(advice["reason"].as_str(), Some("blockhash_expired"));
    let t2_id = advice["replacement_id"]
        .as_str()
        .ok_or_else(|| anyhow!("restage advice missing replacement_id"))?
        .to_string();
    assert_ne!(t2_id, t1_id, "the replacement must be a new entry");
    println!("    replacement id = {t2_id}");

    // T1 is now terminal: failed/, status Expired, and gone from pending/.
    let t1_failed = read_json(
        &daemon,
        &format!("/wallets/alice/0/chains/solana-local/outbox/failed/{t1_id}/intent.json"),
    )
    .await?;
    assert_eq!(
        t1_failed["status"].as_str(),
        Some("expired"),
        "the old entry's status must be Expired"
    );
    let pending_after = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list pending: {e}"))?;
    assert!(
        !pending_after.iter().any(|e| e.name == t1_id),
        "the expired entry must no longer be pending"
    );
    assert!(
        pending_after.iter().any(|e| e.name == t2_id),
        "the replacement must be pending"
    );

    // 9. The replacement carries the same economic intent with a fresh hash.
    step(
        "9",
        "the replacement T2 has a fresh blockhash and same intent",
    );
    let t2 = read_json(
        &daemon,
        &format!("/wallets/alice/0/chains/solana-local/outbox/pending/{t2_id}/intent.json"),
    )
    .await?;
    let t2_blockhash = t2["blockhash"].as_str().unwrap().to_string();
    let t2_fee = t2["fee_lamports"]
        .as_u64()
        .ok_or_else(|| anyhow!("T2 intent missing fee_lamports"))?;
    assert_ne!(
        t2_blockhash, t1_blockhash,
        "the replacement must not reuse the expired blockhash"
    );
    assert_eq!(t2["lamports"].as_u64(), Some(LAMPORTS), "same amount");
    assert_eq!(
        t2["destination"].as_str(),
        Some(destination.as_str()),
        "same destination"
    );
    assert_eq!(
        t2["fee_payer"].as_str(),
        Some(address.as_str()),
        "same payer"
    );
    println!("    T2 blockhash={t2_blockhash} fee={t2_fee} (T1 blockhash was {t1_blockhash})");

    // 10. Confirm T2. Approval is already active, so the first confirm still
    //     prepares the sealed approval (no approval_id sidecar yet) and refuses;
    //     the retry reuses the recorded approval and signs + broadcasts.
    step("10", "confirm T2: approve, sign, broadcast");
    let confirm_t2 = VfsPath::parse(&format!(
        "/wallets/alice/0/chains/solana-local/outbox/pending/{t2_id}/confirm"
    ))
    .unwrap();
    let first = daemon.vfs.write(&confirm_t2, b"y\n").await;
    assert!(
        first.is_err(),
        "the first confirm must prepare the approval and refuse"
    );
    println!(
        "    first confirm prepared the approval: {}",
        first.unwrap_err()
    );
    daemon
        .vfs
        .write(&confirm_t2, b"y\n")
        .await
        .map_err(|e| anyhow!("second confirm of T2: {e}"))?;
    println!("    second confirm accepted");

    // Exactly one signing call happened across the whole test — for T2 only.
    let calls = broker.sign_calls.lock().len();
    assert_eq!(
        calls, 1,
        "exactly one signing call (T2); expired T1 must never have signed"
    );
    let sent = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/sent").unwrap())
        .await
        .map_err(|e| anyhow!("list sent: {e}"))?;
    assert!(
        sent.iter().any(|e| e.name == t2_id),
        "T2 must be in sent/ after broadcast"
    );
    assert!(
        !sent.iter().any(|e| e.name == t1_id),
        "T1 must never reach sent/"
    );

    // 11. Reconcile T2 to a durable finalized receipt.
    step("11", "reconcile T2 to a finalized receipt");
    let mut receipt = None;
    for _ in 0..60 {
        if let Ok(value) = read_json(
            &daemon,
            &format!("/wallets/alice/0/chains/solana-local/outbox/sent/{t2_id}/receipt.json"),
        )
        .await
            && value["confirmation_status"].as_str() == Some("finalized")
        {
            receipt = Some(value);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let receipt = receipt.ok_or_else(|| anyhow!("T2 did not reach a finalized receipt"))?;
    println!("    receipt.json = {}", serde_json::to_string(&receipt)?);
    assert_eq!(receipt["outcome"].as_str(), Some("success"));
    assert_eq!(receipt["confirmation_status"].as_str(), Some("finalized"));

    // 12. Exactly one on-chain transfer landed: destination credited once,
    //     fee payer debited once (amount + T2 fee).
    step("12", "verify exactly one on-chain transfer");
    let dest_after = balance(&destination)?;
    assert_eq!(
        dest_after, LAMPORTS,
        "the destination must receive exactly the transfer amount, once"
    );
    let payer_after = balance(&address)?;
    let debit = payer_before - payer_after;
    println!(
        "    destination {dest_after} lamports; fee payer debited {debit} (= {LAMPORTS} + fee {t2_fee})"
    );
    assert_eq!(
        debit,
        LAMPORTS + t2_fee,
        "the payer must be debited exactly once: amount + the single T2 fee"
    );

    println!("\n=== RESTAGE RECOVERY COMPLETE ===");
    Ok(())
}
