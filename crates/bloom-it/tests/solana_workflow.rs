//! The missing full-workflow E2E: the Solana analogue of `bloom-it`'s
//! `anvil_full_stage_confirm_flow`.
//!
//! Drives a REAL `bloom_daemon::Daemon` (real VFS, real wallets handler, real
//! Solana engine wiring, real reconciler) against a REAL local Agave
//! validator, using a fee payer that is genuinely derived from a BIP-39
//! mnemonic through `bloom-signer-derive`.
//!
//! Boundary: the Broker is an in-process fixture, exactly as the EVM
//! `anvil_e2e` test does. This does not exercise the real bloom-broker /
//! bloom-signer processes or a kernel mount.

mod common;

use std::sync::atomic::Ordering;

use anyhow::{Result, anyhow};
use bloom_vfs::VfsPath;
use bloom_vfs::handler::Handler;
use common::*;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn solana_full_stage_confirm_flow() -> Result<()> {
    init_tracing();

    step("1", "derive the Solana account from the BIP-39 mnemonic");
    let child = Child::derive(&seed()?, 0)?;
    let address = child.address.clone();
    println!("    path        {}", child.path);
    println!("    public key  {}", hex::encode(child.pubkey));
    println!("    address     {address}");

    // 2. Real daemon over a temp home, wired to the local validator.
    step("2", "build a real Daemon with the Solana chain configured");
    let broker = SolanaBroker::new(vec![child]);
    let tmp = solana_home()?;
    // Mirror the shipped installer catalog
    // (packaging/triad/macos/config/provenance-catalog.unsigned.json).
    let catalog = catalog(&[
        ("transaction.replace", "transaction.replace", "ethereum"),
        ("transaction.cancel", "transaction.cancel", "ethereum"),
    ]);
    let daemon = daemon_at(tmp.path(), broker.clone(), catalog)?;
    println!("    daemon constructed; solana-local admitted by the genesis guard");

    // 3. The chain must be enumerable through the VFS.
    step(
        "3",
        "the Solana chain appears in the wallet's chain listing",
    );
    let chains = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains").unwrap())
        .await
        .map_err(|e| anyhow!("list chains: {e}"))?;
    let names: Vec<&str> = chains.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"solana-local"),
        "solana-local missing from {names:?}"
    );
    println!("    chains listing includes solana-local");

    // 4. Fund the derived child on the validator.
    step("4", "airdrop to the mnemonic-derived address");
    airdrop(&address, 2_000_000_000).await?;

    // 5. The write surface must be reachable the way a filesystem client
    //    reaches it: lookup first, then write.
    step(
        "5",
        "lookup the outbox write sinks (the mount-reachability path)",
    );
    let new_tx = VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/new.tx").unwrap();
    match daemon.vfs.lookup(&new_tx).await {
        Ok(entry) => {
            println!("    lookup new.tx -> mode {:o}", entry.mode);
            assert!(entry.mode & 0o200 != 0, "new.tx lookup must be writable");
        }
        Err(e) => return Err(anyhow!("lookup new.tx failed: {e}")),
    }
    let outbox_listing = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox").unwrap())
        .await
        .map_err(|e| anyhow!("list outbox: {e}"))?;
    println!(
        "    outbox listing: {:?}",
        outbox_listing
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>()
    );

    // 6. Stage.
    step("6", "stage a transfer by writing outbox/new.tx");
    let destination = bs58::encode([0xbbu8; 32]).into_string();
    let intent = serde_json::json!({"destination": destination, "lamports": 250_000_000u64});
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
    let id = pending
        .first()
        .ok_or_else(|| anyhow!("no pending entry staged"))?
        .name
        .clone();
    println!("    staged pending id = {id}");
    let intent_json = daemon
        .vfs
        .read(
            &VfsPath::parse(&format!(
                "/wallets/alice/0/chains/solana-local/outbox/pending/{id}/intent.json"
            ))
            .unwrap(),
        )
        .await
        .map_err(|e| anyhow!("read intent: {e}"))?;
    let staged: serde_json::Value = serde_json::from_slice(&intent_json)?;
    println!(
        "    fee_payer={} lamports={} fee={} blockhash={}",
        staged["fee_payer"], staged["lamports"], staged["fee_lamports"], staged["blockhash"]
    );
    assert_eq!(staged["fee_payer"].as_str().unwrap(), address);

    // 7. Confirm must fail closed before owner approval.
    step(
        "7",
        "first confirm must fail closed (no Sealed Approval yet)",
    );
    let confirm = VfsPath::parse(&format!(
        "/wallets/alice/0/chains/solana-local/outbox/pending/{id}/confirm"
    ))
    .unwrap();
    match daemon.vfs.lookup(&confirm).await {
        Ok(e) => println!("    lookup confirm -> mode {:o}", e.mode),
        Err(e) => return Err(anyhow!("lookup confirm failed: {e}")),
    }
    let first = daemon.vfs.write(&confirm, b"y\n").await;
    match &first {
        Err(e) => println!("    first confirm correctly refused: {e}"),
        Ok(()) => {
            return Err(anyhow!(
                "SECURITY: confirm succeeded without owner approval"
            ));
        }
    }

    // 8. Owner completes the ceremony; retry confirms, signs, broadcasts.
    step("8", "owner approves; confirm again -> sign + broadcast");
    broker.approval_active.store(true, Ordering::SeqCst);
    daemon
        .vfs
        .write(&confirm, b"y\n")
        .await
        .map_err(|e| anyhow!("second confirm: {e}"))?;
    println!("    confirm accepted");

    let sent = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/sent").unwrap())
        .await
        .map_err(|e| anyhow!("list sent: {e}"))?;
    println!(
        "    sent entries: {:?}",
        sent.iter().map(|e| e.name.as_str()).collect::<Vec<_>>()
    );

    // 9. What did the Broker actually get asked to sign?
    step("9", "the Broker signed exactly the staged message bytes");
    let calls = broker.sign_calls.lock().clone();
    println!("    SigningSign calls: {}", calls.len());
    let (_, signed_payload) = calls.last().ok_or_else(|| anyhow!("no signing call"))?;
    let expected = b64_decode(staged["message_b64"].as_str().unwrap());
    println!("    staged message  {} bytes", expected.len());
    println!("    signed payload  {} bytes", signed_payload.len());
    assert_eq!(
        signed_payload, &expected,
        "Broker was asked to sign bytes other than the staged message"
    );
    println!("    signed payload == staged message bytes");

    // 10. On-chain verification.
    step("10", "verify the transfer on the validator");
    let receipt_path =
        format!("/wallets/alice/0/chains/solana-local/outbox/sent/{id}/broadcast_attempted.json");
    if let Ok(b) = daemon
        .vfs
        .read(&VfsPath::parse(&receipt_path).unwrap())
        .await
    {
        println!(
            "    broadcast_attempted.json = {}",
            String::from_utf8_lossy(&b)
        );
    }
    for _ in 0..45 {
        let bal = balance(&destination)?;
        if bal > 0 {
            println!("    destination {destination} balance = {bal} lamports");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let payer_bal = balance(&address)?;
    println!("    fee payer balance = {payer_bal} lamports");

    // 11. Reconciliation writes the receipt.
    step("11", "reconcile to a durable receipt");
    for _ in 0..45 {
        let r = daemon
            .vfs
            .read(
                &VfsPath::parse(&format!(
                    "/wallets/alice/0/chains/solana-local/outbox/sent/{id}/receipt.json"
                ))
                .unwrap(),
            )
            .await;
        if let Ok(b) = r {
            println!("    receipt.json = {}", String::from_utf8_lossy(&b));
            let receipt: serde_json::Value = serde_json::from_slice(&b)?;
            assert_eq!(receipt["outcome"], "success");
            assert_eq!(receipt["confirmation_status"], "finalized");
            println!("\n=== WORKFLOW COMPLETE ===");
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    println!("    NO RECEIPT after 45s — reconciler did not finalize");
    Err(anyhow!("reconciliation did not produce a receipt"))
}
