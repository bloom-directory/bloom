//! Multi-account Solana selection against a real local Agave validator.
//!
//! The companion to `solana_workflow`, for the case that one could not cover:
//! a BIP-39 wallet with **two simultaneously active** Solana children. That is
//! the state Finding R1 is about — with one child every path is unambiguous,
//! and retiring a child to reach the second proves the account lifecycle
//! rather than multi-account usability.
//!
//! Both children are derived from the mnemonic through the production
//! derivation crate, and the Broker fixture signs with whichever key the
//! request's `key_ref` names. A selection bug therefore cannot pass this test
//! by accident: choosing the wrong child produces a signature that fails to
//! verify against the staged fee payer, and the validator rejects it.
//!
//! Boundary, stated plainly: the Broker here is an in-process fixture, exactly
//! as in `solana_workflow` and the EVM `anvil_e2e`. The Daemon, VFS, wallet
//! handler, Solana engine, reconciler, and validator are real. This is not the
//! separate-process bloom-broker/bloom-signer triad.

mod common;

use std::sync::atomic::Ordering;

use anyhow::{Result, anyhow};
use bloom_broker_api::Digest32;
use bloom_proto::HomeDir;
use bloom_vfs::VfsPath;
use bloom_vfs::handler::Handler;
use common::*;
use sha2::{Digest as _, Sha256};

// ------------------------------------------------------------------ main ---

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn two_active_solana_children_select_sign_and_reconcile_independently() -> Result<()> {
    init_tracing();

    // 1. Two children from one mnemonic, through the production derivation
    //    crate rather than fixture constants.
    step(
        "1",
        "derive Solana accounts 0 and 1 from the BIP-39 mnemonic",
    );
    let seed64 = seed()?;
    let account0 = Child::derive(&seed64, 0)?;
    let account1 = Child::derive(&seed64, 1)?;
    for child in [&account0, &account1] {
        println!(
            "    account {} path {} address {} fingerprint {}",
            child.account,
            child.path,
            child.address,
            child.fingerprint_hex()
        );
    }

    // 2. Independent checks on the two identities, so a later assertion about
    //    "account 1" cannot be satisfied by account 0 under another name.
    step("2", "verify the two accounts are distinct and canonical");
    assert_eq!(account0.path, "m/44'/501'/0'/0'");
    assert_eq!(account1.path, "m/44'/501'/1'/0'");
    assert_ne!(account0.pubkey, account1.pubkey, "children must differ");
    assert_ne!(account0.address, account1.address);
    assert_ne!(account0.fingerprint_hex(), account1.fingerprint_hex());
    // A Solana address is the base58 of the raw 32-byte key, and the
    // fingerprint commits to the canonical SPKI encoding of that same key.
    for child in [&account0, &account1] {
        let decoded = bs58::decode(&child.address)
            .into_vec()
            .map_err(|e| anyhow!("address base58: {e}"))?;
        assert_eq!(
            decoded,
            child.pubkey.to_vec(),
            "address must be the raw key"
        );
        let spki_bytes = spki(&child.pubkey);
        assert_eq!(spki_bytes.len(), 44);
        assert_eq!(&spki_bytes[12..], &child.pubkey[..]);
        assert_eq!(
            child.fingerprint_hex(),
            Digest32::from_bytes(Sha256::digest(&spki_bytes).into()).as_str()
        );
    }
    println!("    both accounts verified independently of the projection");

    // 3. Real daemon, both children active at once.
    step("3", "build a real Daemon with BOTH children active");
    let broker = SolanaBroker::new(vec![account0, account1]);
    let account0 = &broker.children[0];
    let account1 = &broker.children[1];
    let tmp = solana_home()?;
    let daemon = daemon_at(tmp.path(), broker.clone(), catalog(&[]))?;
    println!("    daemon constructed with 2 active Solana children");

    // 4. Fund ONLY account 1, so a transfer signed by account 0 could not
    //    succeed on-chain even if selection silently fell back to it.
    step("4", "airdrop to account 1 only");
    airdrop(&account1.address, 2_000_000_000).await?;
    // Account 0's balance is recorded, not assumed to be zero: the same
    // mnemonic's account 0 may already hold funds from another suite on this
    // validator. What matters is that this transfer leaves it untouched.
    let account0_balance = balance(&account0.address)?;
    println!("    account 0 balance before: {account0_balance} lamports");

    let new_tx = VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/new.tx").unwrap();
    let destination = bs58::encode([0xccu8; 32]).into_string();

    // 5. The account boundary itself: the wallet-level path stages from
    //    account 0, a numbered path pins its own account, the two pending
    //    sets never mix, and a numbered transfer settles on the validator
    //    signed by exactly that account's key (only account 1 is funded, so
    //    a wrong key cannot produce a finalized transfer).
    step(
        "5",
        "wallet-level staging defaults to account 0; numbered paths pin their own",
    );
    let ambiguous = serde_json::json!({
        "destination": destination,
        "lamports": 250_000_000u64,
    });

    // 5a. Wallet level, no selector: the canonical account 0 child is the
    //     default even while account 1 is also active.
    daemon
        .vfs
        .write(&new_tx, serde_json::to_vec(&ambiguous)?.as_slice())
        .await
        .map_err(|e| anyhow!("wallet-level stage: {e}"))?;
    let zero_staged = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list pending: {e}"))?;
    let wallet_level_id = zero_staged
        .first()
        .ok_or_else(|| anyhow!("nothing staged at wallet level"))?
        .name
        .clone();
    let staged_zero = read_json(
        &daemon,
        &format!(
            "/wallets/alice/0/chains/solana-local/outbox/pending/{wallet_level_id}/intent.json"
        ),
    )
    .await?;
    assert_eq!(
        staged_zero["account_fingerprint"].as_str().unwrap(),
        account0.fingerprint_hex(),
        "the wallet-level default must be the canonical account 0 child"
    );
    assert_eq!(
        staged_zero["fee_payer"].as_str().unwrap(),
        account0.address,
        "the wallet-level default must spend from account 0"
    );
    println!("    wallet-level stage pinned account 0: {wallet_level_id}");
    // Remove it: later steps need a clean pending set.
    daemon
        .vfs
        .write(
            &VfsPath::parse(&format!(
                "/wallets/alice/0/chains/solana-local/outbox/pending/{wallet_level_id}/cancel"
            ))
            .unwrap(),
            b"y\n",
        )
        .await
        .map_err(|e| anyhow!("cancel wallet-level stage: {e}"))?;

    // 5b. A body fingerprint that disagrees with the numbered path is an
    //     error, not a cross-account escalation.
    let numbered_tx = VfsPath::parse("/wallets/alice/1/chains/solana-local/outbox/new.tx").unwrap();
    let crossed = daemon
        .vfs
        .write(
            &numbered_tx,
            serde_json::to_vec(&serde_json::json!({
                "destination": destination,
                "lamports": 250_000_000u64,
                "account_fingerprint": account0.fingerprint_hex(),
            }))?
            .as_slice(),
        )
        .await
        .expect_err("an intent naming another account must not stage");
    println!("    path/body disagreement refused: {crossed}");

    // 5c. Stage through account 1's own path, with no selector in the body.
    let numbered_destination = bs58::encode([0xddu8; 32]).into_string();
    let numbered_destination_before = balance(&numbered_destination)?;
    daemon
        .vfs
        .write(
            &numbered_tx,
            serde_json::to_vec(&serde_json::json!({
                "destination": numbered_destination,
                "lamports": 250_000_000u64,
            }))?
            .as_slice(),
        )
        .await
        .map_err(|e| anyhow!("numbered stage: {e}"))?;
    let one_pending = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/1/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list account 1 pending: {e}"))?;
    let numbered_id = one_pending
        .first()
        .ok_or_else(|| anyhow!("nothing staged through account 1"))?
        .name
        .clone();
    let staged_one = read_json(
        &daemon,
        &format!("/wallets/alice/1/chains/solana-local/outbox/pending/{numbered_id}/intent.json"),
    )
    .await?;
    assert_eq!(
        staged_one["account_fingerprint"].as_str().unwrap(),
        account1.fingerprint_hex(),
        "the numbered path must pin its own account"
    );
    assert_eq!(
        staged_one["fee_payer"].as_str().unwrap(),
        account1.address,
        "the numbered path must spend from its own account"
    );
    println!("    numbered stage pinned account 1: {numbered_id}");

    // 5d. Account 0's pending does not list account 1's entry, and
    //     confirming account 1's entry through account 0's path is not
    //     found.
    let zero_pending = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list account 0 pending: {e}"))?;
    assert!(
        zero_pending.iter().all(|entry| entry.name != numbered_id),
        "account 1's entry must not appear under account 0: {zero_pending:?}"
    );
    let crossed_confirm = daemon
        .vfs
        .write(
            &VfsPath::parse(&format!(
                "/wallets/alice/0/chains/solana-local/outbox/pending/{numbered_id}/confirm"
            ))
            .unwrap(),
            b"y\n",
        )
        .await
        .expect_err("confirming account 1's entry through account 0 must not be found");
    println!("    cross-account confirm refused: {crossed_confirm}");

    // 5e. Confirm through account 1's path and settle on the validator.
    //     The refused confirm projects a challenge whose pointers must name
    //     account 1's outbox (the wallet-level one is account 0's and would
    //     not resolve), and the resume follows `retry_path` verbatim.
    let numbered_outbox = "wallets/alice/1/chains/solana-local/outbox";
    let numbered_confirm =
        VfsPath::parse(&format!("/{numbered_outbox}/pending/{numbered_id}/confirm")).unwrap();
    let refused = daemon
        .vfs
        .write(&numbered_confirm, b"y\n")
        .await
        .expect_err("confirm must fail closed before owner approval")
        .to_string();
    assert!(
        refused.contains(&format!(
            "owner approval pending; read {numbered_outbox}/pending/{numbered_id}/approval_challenge.json"
        )) && !refused.contains("http"),
        "{refused}"
    );
    let challenge = read_json(
        &daemon,
        &format!("/{numbered_outbox}/pending/{numbered_id}/approval_challenge.json"),
    )
    .await?;
    let plan_path = challenge["plan_path"].as_str().unwrap_or_default();
    let retry_path = challenge["retry_path"].as_str().unwrap_or_default();
    assert_eq!(
        plan_path,
        format!("{numbered_outbox}/pending/{numbered_id}/plan.md")
    );
    assert_eq!(
        retry_path,
        format!("{numbered_outbox}/pending/{numbered_id}/confirm")
    );
    let plan = daemon
        .vfs
        .read(&VfsPath::parse(&format!("/{plan_path}")).unwrap())
        .await
        .map_err(|e| anyhow!("read advertised plan_path {plan_path}: {e}"))?;
    assert!(!plan.is_empty(), "the advertised plan must be readable");
    broker.approval_active.store(true, Ordering::SeqCst);
    daemon
        .vfs
        .write(&VfsPath::parse(&format!("/{retry_path}")).unwrap(), b"y\n")
        .await
        .map_err(|e| anyhow!("confirm via advertised retry_path {retry_path}: {e}"))?;
    let mut numbered_receipt = None;
    for _ in 0..60 {
        if let Ok(value) = read_json(
            &daemon,
            &format!("/wallets/alice/1/chains/solana-local/outbox/sent/{numbered_id}/receipt.json"),
        )
        .await
            && value["confirmation_status"].as_str() == Some("finalized")
        {
            numbered_receipt = Some(value);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let numbered_receipt = numbered_receipt
        .ok_or_else(|| anyhow!("numbered transfer did not reach a finalized receipt"))?;
    assert_eq!(numbered_receipt["outcome"].as_str(), Some("success"));
    let numbered_destination_balance = balance(&numbered_destination)?;
    assert_eq!(
        numbered_destination_balance,
        numbered_destination_before + 250_000_000,
        "the numbered transfer settled on the validator"
    );
    println!("    numbered transfer settled; account boundary holds end to end");
    // Baselines for the later steps, which count calls and sent entries.
    // The numbered transfer lives in account 1's outbox view; the
    // wallet-level view is account 0's and must not show it.
    let sign_calls_before = broker.sign_calls.lock().len();
    let sent_before = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/1/chains/solana-local/outbox/sent").unwrap())
        .await
        .map_err(|e| anyhow!("list account 1 sent: {e}"))?
        .len();
    let wallet_sent_before = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/sent").unwrap())
        .await
        .map_err(|e| anyhow!("list wallet sent: {e}"))?
        .len();
    assert_eq!(sign_calls_before, 1, "the numbered confirm signed once");
    assert_eq!(
        sent_before, 1,
        "the numbered transfer is in account 1's sent"
    );
    assert_eq!(
        wallet_sent_before, 0,
        "the wallet-level view is account 0's: it must not show account 1's entry"
    );
    // Step 8 exercises its own approval gating; drop the fixture approval
    // again so its pre-approval refusal is real.
    broker.approval_active.store(false, Ordering::SeqCst);

    // 6. A fingerprint that belongs to no active child is refused too.
    step("6", "a foreign fingerprint is refused");
    let foreign = "f".repeat(64);
    let err = daemon
        .vfs
        .write(
            &new_tx,
            serde_json::to_vec(&serde_json::json!({
                "destination": destination,
                "lamports": 250_000_000u64,
                "account_fingerprint": foreign,
            }))?
            .as_slice(),
        )
        .await
        .expect_err("a fingerprint outside the wallet must never select");
    println!("    refused: {err}");

    // 7. The wallet-level path stages from account 0 only: account 1's
    //    fingerprint on the wallet-level `new.tx` is refused and nothing
    //    stages. Account 1 transfers go through `/wallets/alice/1/`.
    step(
        "7",
        "wallet-level staging refuses account 1's fingerprint; numbered path stages account 1",
    );
    let destination_before = balance(&destination)?;
    let override_intent = serde_json::json!({
        "destination": destination,
        "lamports": 250_000_000u64,
        "account_fingerprint": account1.fingerprint_hex(),
    });
    let override_refused = daemon
        .vfs
        .write(&new_tx, serde_json::to_vec(&override_intent)?.as_slice())
        .await;
    assert!(
        override_refused.is_err(),
        "the wallet-level path must not stage another account's transfer"
    );
    println!("    wallet-level account-1 stage refused: {override_refused:?}");
    let wallet_pending_after_refusal = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list wallet pending: {e}"))?;
    assert!(
        wallet_pending_after_refusal.is_empty(),
        "nothing may stage from the refused override: {wallet_pending_after_refusal:?}"
    );

    // The numbered path pins its own account and settles it.
    let intent = serde_json::json!({
        "destination": destination,
        "lamports": 250_000_000u64,
        "account_fingerprint": account1.fingerprint_hex(),
    });
    daemon
        .vfs
        .write(&numbered_tx, serde_json::to_vec(&intent)?.as_slice())
        .await
        .map_err(|e| anyhow!("numbered stage: {e}"))?;
    let pending = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/1/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list account 1 pending: {e}"))?;
    let id = pending
        .first()
        .ok_or_else(|| anyhow!("nothing staged"))?
        .name
        .clone();
    let staged = read_json(
        &daemon,
        &format!("/wallets/alice/1/chains/solana-local/outbox/pending/{id}/intent.json"),
    )
    .await?;
    println!("    staged id {id} fee_payer {}", staged["fee_payer"]);
    assert_eq!(
        staged["fee_payer"].as_str().unwrap(),
        account1.address,
        "the staged fee payer must be the selected account, not the first listed"
    );
    assert_eq!(
        staged["account_fingerprint"].as_str().unwrap(),
        account1.fingerprint_hex(),
        "the selected account must be pinned into the staged record"
    );

    // 8. Approve, confirm, broadcast.
    step("8", "owner approves; confirm signs and broadcasts");
    let confirm = VfsPath::parse(&format!(
        "/wallets/alice/1/chains/solana-local/outbox/pending/{id}/confirm"
    ))
    .unwrap();
    let refused = daemon.vfs.write(&confirm, b"y\n").await;
    assert!(
        refused.is_err(),
        "confirm must fail closed before owner approval"
    );
    println!("    pre-approval confirm correctly refused");

    broker.approval_active.store(true, Ordering::SeqCst);
    daemon
        .vfs
        .write(&confirm, b"y\n")
        .await
        .map_err(|e| anyhow!("confirm: {e}"))?;
    println!("    confirm accepted");

    // 9. The Broker was asked to sign with account 1's key, and with exactly
    //    the staged bytes.
    step("9", "the signing call named account 1 and the staged bytes");
    let calls = broker.sign_calls.lock().clone();
    assert_eq!(
        calls.len(),
        sign_calls_before + 1,
        "exactly one new signing call: {calls:?}"
    );
    let (locator, signed_bytes) = &calls[sign_calls_before];
    println!("    signed with key locator {locator}");
    assert_eq!(
        locator, &account1.key_ref.locator,
        "the wrong child was asked to sign"
    );
    let staged_message = b64_decode(staged["message_b64"].as_str().unwrap());
    assert_eq!(
        signed_bytes, &staged_message,
        "the Broker must sign the staged message bytes verbatim"
    );

    // 10. Independent signature verification over the RAW message, and the
    //     negative that Solana does not sign SHA-256(message).
    step(
        "10",
        "verify the signature independently over the raw message",
    );
    let broadcast = read_json(
        &daemon,
        &format!("/wallets/alice/1/chains/solana-local/outbox/sent/{id}/broadcast_attempted.json"),
    )
    .await?;
    let signature_b58 = broadcast["signature"]
        .as_str()
        .ok_or_else(|| anyhow!("no broadcast signature"))?
        .to_string();
    let signature_bytes: [u8; 64] = bs58::decode(&signature_b58)
        .into_vec()
        .map_err(|e| anyhow!("signature base58: {e}"))?
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

    use ed25519_dalek::Verifier as _;
    let account1_key = ed25519_dalek::VerifyingKey::from_bytes(&account1.pubkey)?;
    account1_key
        .verify(&staged_message, &signature)
        .map_err(|e| anyhow!("signature must verify over the raw message: {e}"))?;
    println!("    verifies against account 1 over the raw message");

    // The other active child must NOT verify it. This is the assertion a
    // selection bug fails.
    let account0_key = ed25519_dalek::VerifyingKey::from_bytes(&account0.pubkey)?;
    assert!(
        account0_key.verify(&staged_message, &signature).is_err(),
        "SECURITY: the signature verifies against the account that was not selected"
    );
    println!("    does not verify against account 0");

    // Solana signs the serialized message with Ed25519, not SHA-256 of it.
    let hashed = Sha256::digest(&staged_message);
    assert!(
        account1_key.verify(&hashed, &signature).is_err(),
        "signature must not verify over SHA-256(message)"
    );
    println!("    does not verify over SHA-256(message)");

    // 11. Reconcile to a durable finalized receipt, and check the money moved
    //     from the selected account.
    step("11", "reconcile to a finalized receipt and verify balances");
    let mut receipt = None;
    for _ in 0..60 {
        if let Ok(value) = read_json(
            &daemon,
            &format!("/wallets/alice/1/chains/solana-local/outbox/sent/{id}/receipt.json"),
        )
        .await
            && value["confirmation_status"].as_str() == Some("finalized")
        {
            receipt = Some(value);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let receipt = receipt.ok_or_else(|| anyhow!("transfer did not reach a finalized receipt"))?;
    println!("    receipt = {}", serde_json::to_string_pretty(&receipt)?);
    assert_eq!(receipt["outcome"].as_str(), Some("success"));
    assert_eq!(receipt["signature"].as_str(), Some(signature_b58.as_str()));

    let destination_balance = balance(&destination)?;
    assert_eq!(
        destination_balance,
        destination_before + 250_000_000,
        "destination debit"
    );
    let account0_after = balance(&account0.address)?;
    assert_eq!(
        account0_after, account0_balance,
        "the unselected account's balance must be untouched"
    );
    println!("    destination credited; account 0 untouched at {account0_after} lamports");

    // 12. Replay: confirming the same entry again must not produce a second
    //     transaction.
    step("12", "replaying confirm does not double-send");
    let replay = daemon.vfs.write(&confirm, b"y\n").await;
    println!("    replay result: {replay:?}");
    let calls_after = broker.sign_calls.lock().len();
    assert_eq!(
        calls_after,
        sign_calls_before + 1,
        "a replayed confirm must not sign again (calls={calls_after})"
    );
    let sent_after = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/1/chains/solana-local/outbox/sent").unwrap())
        .await
        .map_err(|e| anyhow!("list account 1 sent: {e}"))?;
    assert_eq!(
        sent_after.len(),
        sent_before + 1,
        "exactly one new sent entry must exist"
    );

    // 13. Restart: the durable receipt and the pinned account survive, and a
    //     post-restart confirm still does not resend.
    step(
        "13",
        "re-read the durable state the way a restarted process would",
    );
    // A Daemon holds the home write permit for the life of the process, by
    // design — one daemon per home. So an in-process "restart" cannot mean a
    // second Daemon over the same home; it means reading the state a fresh
    // process would read on start. That is what a restart actually recovers
    // from, so it is read straight off disk through a fresh outbox rather
    // than through the still-running daemon's caches.
    let reopened =
        bloom_solana_tx::outbox::SolanaOutbox::new(HomeDir::at(tmp.path()).solana_outbox_dir())
            .map_err(|e| anyhow!("reopen outbox: {e}"))?;

    // Still terminal, and still in `sent` — a restarted process therefore has
    // nothing pending to confirm, so it cannot resend.
    let reopened_entry = reopened
        .read_in_state(
            "alice",
            "solana-local",
            &id,
            bloom_solana_tx::outbox::SolanaOutboxState::Sent,
        )
        .map_err(|e| anyhow!("reopened entry must still be sent: {e}"))?;
    assert_eq!(
        reopened_entry.staged.account_fingerprint.as_deref(),
        Some(account1.fingerprint_hex()),
        "the pinned account must survive a restart"
    );
    assert_eq!(
        reopened_entry.staged.fee_payer, account1.address,
        "the staged fee payer must survive a restart"
    );
    assert!(
        reopened
            .read_in_state(
                "alice",
                "solana-local",
                &id,
                bloom_solana_tx::outbox::SolanaOutboxState::Pending,
            )
            .is_err(),
        "a completed transfer must not reappear as pending after a restart"
    );
    let receipt_after = read_json(
        &daemon,
        &format!("/wallets/alice/1/chains/solana-local/outbox/sent/{id}/receipt.json"),
    )
    .await?;
    assert_eq!(
        receipt_after["signature"].as_str(),
        Some(signature_b58.as_str()),
        "the receipt must be durable"
    );
    assert_eq!(
        receipt_after["confirmation_status"].as_str(),
        Some("finalized")
    );
    println!("    durable receipt and pinned account survive a fresh read");

    // Confirming again must still refuse, and must not sign again.
    let replay_again = daemon.vfs.write(&confirm, b"y\n").await;
    println!("    second replay result: {replay_again:?}");
    assert_eq!(
        broker.sign_calls.lock().len(),
        sign_calls_before + 1,
        "no replay may produce a second signing call"
    );

    // 14. The other child stays independently selectable while account 1
    //     is also active.
    step("14", "account 0 is still selectable in its own right");
    airdrop(&account0.address, 1_000_000_000).await?;
    daemon
        .vfs
        .write(
            &new_tx,
            serde_json::to_vec(&serde_json::json!({
                "destination": destination,
                "lamports": 100_000_000u64,
                "account_fingerprint": account0.fingerprint_hex(),
            }))?
            .as_slice(),
        )
        .await
        .map_err(|e| anyhow!("stage from account 0: {e}"))?;
    let pending = daemon
        .vfs
        .list(&VfsPath::parse("/wallets/alice/0/chains/solana-local/outbox/pending").unwrap())
        .await
        .map_err(|e| anyhow!("list pending: {e}"))?;
    let second_id = pending
        .first()
        .ok_or_else(|| anyhow!("nothing staged from account 0"))?
        .name
        .clone();
    let staged0 = read_json(
        &daemon,
        &format!("/wallets/alice/0/chains/solana-local/outbox/pending/{second_id}/intent.json"),
    )
    .await?;
    assert_eq!(
        staged0["fee_payer"].as_str(),
        Some(account0.address.as_str()),
        "account 0 must be selectable while account 1 is also active"
    );
    assert_eq!(
        staged0["account_fingerprint"].as_str(),
        Some(account0.fingerprint_hex())
    );
    println!("    account 0 staged independently: {second_id}");

    println!("\n=== MULTI-ACCOUNT SELECTION COMPLETE ===");
    Ok(())
}
