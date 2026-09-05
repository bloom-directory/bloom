//! Outbox lifecycle and reconciliation tests driven by fixtures (no network).

use bloom_solana_tx::outbox::{
    APPROVAL_CHALLENGE_FILE, OutboxError, SolanaOutbox, SolanaOutboxState,
};
use bloom_solana_tx::types::{SolanaTxStatus, StagedSolanaTransfer};
use tempfile::TempDir;

fn staged(id: &str) -> StagedSolanaTransfer {
    StagedSolanaTransfer {
        id: id.to_string(),
        wallet: "alice".into(),
        chain: "solana-devnet".into(),
        fee_payer: "FEEPAYER111111111111111111111111111111111".into(),
        account_fingerprint: None,
        account_derivation_path: None,
        destination: "DEST111111111111111111111111111111111111111".into(),
        lamports: 1_000_000,
        fee_lamports: 5_000,
        genesis_hash: "GENESIS111111111111111111111111111111111111".into(),
        blockhash: "BLOCKHASH111111111111111111111111111111111111".into(),
        last_valid_block_height: 123456,
        message_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"legacy-message-bytes",
        ),
        payload_digest_hex: "ab".repeat(32),
        signature: None,
        created_ms: 1000,
        expires_ms: 0,
        status: SolanaTxStatus::Pending,
        action_id: None,
    }
}

fn outbox() -> (TempDir, SolanaOutbox) {
    let dir = TempDir::new().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    (dir, outbox)
}

fn heights_past_window(chain: &str, height: u64) -> std::collections::HashMap<String, u64> {
    std::collections::HashMap::from([(chain.to_string(), height)])
}

#[test]
fn stage_and_read_roundtrip() {
    let (_dir, outbox) = outbox();
    let s = staged("0001-00001");
    outbox.write_pending(&s, "plan").unwrap();

    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    assert_eq!(entry.state, SolanaOutboxState::Pending);
    assert_eq!(entry.staged.destination, s.destination);
    assert_eq!(entry.staged.lamports, 1_000_000);

    // intent.json is write-once in spirit: re-writing identical bytes is
    // fine, but the stored record is what later reads return.
    let stored: StagedSolanaTransfer =
        serde_json::from_slice(&std::fs::read(entry.dir.join("intent.json")).unwrap()).unwrap();
    assert_eq!(stored, s);
}

#[test]
fn transition_moves_entry_atomically() {
    let (_dir, outbox) = outbox();
    let s = staged("0001-00001");
    outbox.write_pending(&s, "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();

    outbox.transition(&entry, SolanaOutboxState::Sent).unwrap();
    assert!(
        outbox
            .read_in_state(
                "alice",
                "solana-devnet",
                "0001-00001",
                SolanaOutboxState::Pending
            )
            .is_err()
    );
    assert!(
        outbox
            .read_in_state(
                "alice",
                "solana-devnet",
                "0001-00001",
                SolanaOutboxState::Sent
            )
            .is_ok()
    );
}

#[test]
fn approval_challenge_is_pending_only_and_cleared_on_terminal_transition() {
    let (_dir, outbox) = outbox();
    outbox
        .write_pending(&staged("approval-challenge"), "plan")
        .unwrap();
    let entry = outbox
        .read("alice", "solana-devnet", "approval-challenge")
        .unwrap();

    outbox
        .write_approval_challenge(&entry, br#"{"ceremony_url":"http://localhost/owner"}"#)
        .unwrap();
    assert!(entry.dir.join(APPROVAL_CHALLENGE_FILE).exists());

    let sent_dir = outbox.transition(&entry, SolanaOutboxState::Sent).unwrap();
    assert!(!sent_dir.join(APPROVAL_CHALLENGE_FILE).exists());

    let sent = outbox
        .read_in_state(
            "alice",
            "solana-devnet",
            "approval-challenge",
            SolanaOutboxState::Sent,
        )
        .unwrap();
    let error = outbox
        .write_approval_challenge(&sent, b"stale challenge")
        .unwrap_err();
    assert!(matches!(error, OutboxError::StateMismatch { .. }));
}

#[test]
fn read_in_state_distinguishes_wrong_state() {
    let (_dir, outbox) = outbox();
    outbox.write_pending(&staged("0001-00001"), "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    outbox
        .transition(&entry, SolanaOutboxState::Failed)
        .unwrap();

    let err = outbox
        .read_in_state(
            "alice",
            "solana-devnet",
            "0001-00001",
            SolanaOutboxState::Sent,
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            bloom_solana_tx::outbox::OutboxError::StateMismatch { .. }
        ),
        "{err}"
    );
}

#[test]
fn walk_all_sent_skips_unsigned_entries() {
    let (_dir, outbox) = outbox();
    // A pending entry with no signature is not "sent".
    outbox.write_pending(&staged("0001-00001"), "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    outbox.transition(&entry, SolanaOutboxState::Sent).unwrap();

    // No signature recorded -> walk skips it.
    assert!(outbox.walk_all_sent().unwrap().is_empty());

    // Stamp a signature by rewriting intent.json (simulating the signing
    // step, which is §4-blocked) and the entry becomes visible.
    let mut s = staged("0001-00001");
    s.signature = Some("SIG1111111111111111111111111111111111111111111111111111111111111".into());
    let dir = outbox.root().join("alice/solana-devnet/sent/0001-00001");
    std::fs::write(
        dir.join("intent.json"),
        serde_json::to_vec_pretty(&s).unwrap(),
    )
    .unwrap();

    let sent = outbox.walk_all_sent().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].signature, s.signature.clone().unwrap());
    assert!(!sent[0].mined);
}

#[test]
fn broadcast_attempt_binds_raw_tx_hash() {
    let (_dir, outbox) = outbox();
    outbox.write_pending(&staged("0001-00001"), "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();

    outbox
        .write_broadcast_attempt(&entry, "SIG", b"signed-tx-bytes", 2000)
        .unwrap();
    let raw = outbox.read_broadcast_raw_tx(&entry).unwrap();
    assert_eq!(raw, b"signed-tx-bytes");

    // Corrupt the raw tx on disk: the hash check must fail closed.
    std::fs::write(entry.dir.join("raw_tx"), b"tampered").unwrap();
    assert!(outbox.read_broadcast_raw_tx(&entry).is_err());
}

#[test]
fn broadcast_attempt_makes_a_pending_entry_non_cancellable() {
    let (_dir, outbox) = outbox();
    outbox.write_pending(&staged("0001-00001"), "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    outbox
        .write_broadcast_attempt(&entry, "SIG", b"signed-tx-bytes", 2000)
        .unwrap();

    let error = outbox
        .cancel("alice", "solana-devnet", "0001-00001")
        .unwrap_err();
    assert!(matches!(error, OutboxError::BroadcastAttempted(_)));
    assert!(
        outbox
            .read_in_state(
                "alice",
                "solana-devnet",
                "0001-00001",
                SolanaOutboxState::Pending,
            )
            .is_ok()
    );
}

#[test]
fn cancel_moves_pending_to_failed() {
    let (_dir, outbox) = outbox();
    outbox.write_pending(&staged("0001-00001"), "plan").unwrap();
    outbox
        .cancel("alice", "solana-devnet", "0001-00001")
        .unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    assert_eq!(entry.state, SolanaOutboxState::Failed);
    assert_eq!(entry.staged.status, SolanaTxStatus::Cancelled);
}

#[test]
fn sweep_expired_removes_only_expired() {
    let (_dir, outbox) = outbox();
    let mut expiring = staged("0001-00001");
    expiring.expires_ms = 500;
    outbox.write_pending(&expiring, "plan").unwrap();
    outbox.write_pending(&staged("0002-00002"), "plan").unwrap();

    let removed = outbox
        .sweep_expired(1000, &heights_past_window("solana-devnet", 123457))
        .unwrap();
    assert_eq!(removed, 1);
    let expired = outbox
        .read_in_state(
            "alice",
            "solana-devnet",
            "0001-00001",
            SolanaOutboxState::Failed,
        )
        .unwrap();
    assert_eq!(expired.staged.status, SolanaTxStatus::Expired);
    assert!(
        outbox
            .read_in_state(
                "alice",
                "solana-devnet",
                "0002-00002",
                SolanaOutboxState::Pending
            )
            .is_ok()
    );
}

#[test]
fn sweep_requires_live_cluster_height_not_just_the_wall_estimate() {
    let (_dir, outbox) = outbox();
    let mut expiring = staged("0001-00001");
    expiring.expires_ms = 500;
    outbox.write_pending(&expiring, "plan").unwrap();

    // The wall-clock estimate has fired, but the cluster is still inside the
    // blockhash window: `restage_expired` would refuse this entry, so the
    // sweeper must not strand it in `failed` either.
    assert_eq!(
        outbox
            .sweep_expired(1000, &heights_past_window("solana-devnet", 123456))
            .unwrap(),
        0
    );
    // No height observation at all (RPC down): retain and retry later.
    assert_eq!(outbox.sweep_expired(1000, &Default::default()).unwrap(), 0);
    assert!(
        outbox
            .read_in_state(
                "alice",
                "solana-devnet",
                "0001-00001",
                SolanaOutboxState::Pending
            )
            .is_ok()
    );
}

#[test]
fn sweep_reaps_a_signed_entry_without_a_broadcast_attempt() {
    let (_dir, outbox) = outbox();
    let mut signed = staged("0001-signed");
    signed.expires_ms = 500;
    signed.signature =
        Some("SIG1111111111111111111111111111111111111111111111111111111111111".into());
    outbox.write_pending(&signed, "plan").unwrap();

    assert_eq!(
        outbox
            .sweep_expired(1000, &heights_past_window("solana-devnet", 999_999))
            .unwrap(),
        1
    );
    let expired = outbox
        .read_in_state(
            "alice",
            "solana-devnet",
            "0001-signed",
            SolanaOutboxState::Failed,
        )
        .unwrap();
    assert_eq!(expired.staged.status, SolanaTxStatus::Expired);
}

#[test]
fn sweep_preserves_a_pending_entry_with_a_broadcast_attempt() {
    let (_dir, outbox) = outbox();
    let mut attempted = staged("0001-attempted");
    attempted.expires_ms = 500;
    outbox.write_pending(&attempted, "plan").unwrap();
    let entry = outbox
        .read("alice", "solana-devnet", "0001-attempted")
        .unwrap();
    outbox
        .write_broadcast_attempt(&entry, "SIG", b"signed-tx-bytes", 600)
        .unwrap();

    assert_eq!(
        outbox
            .sweep_expired(1000, &heights_past_window("solana-devnet", 999_999))
            .unwrap(),
        0
    );
    assert!(
        outbox
            .read_in_state(
                "alice",
                "solana-devnet",
                "0001-attempted",
                SolanaOutboxState::Pending,
            )
            .is_ok()
    );
}

// Fix C's related dead-code cleanup (PLAN-SOLANA-PR-FIXES.md): from_status
// was marked #[allow(dead_code)] with no real caller — pin the mapping it
// defines now that the engine's broadcast() actually derives its
// transition target from it.
#[test]
fn from_status_maps_every_status_to_its_outbox_state() {
    assert_eq!(
        SolanaOutboxState::from_status(&SolanaTxStatus::Pending),
        SolanaOutboxState::Pending
    );
    assert_eq!(
        SolanaOutboxState::from_status(&SolanaTxStatus::Sent),
        SolanaOutboxState::Sent
    );
    assert_eq!(
        SolanaOutboxState::from_status(&SolanaTxStatus::Success),
        SolanaOutboxState::Sent
    );
    assert_eq!(
        SolanaOutboxState::from_status(&SolanaTxStatus::Failed),
        SolanaOutboxState::Failed
    );
    assert_eq!(
        SolanaOutboxState::from_status(&SolanaTxStatus::Cancelled),
        SolanaOutboxState::Failed
    );
    assert_eq!(
        SolanaOutboxState::from_status(&SolanaTxStatus::Expired),
        SolanaOutboxState::Failed
    );
}

#[test]
fn allocated_ids_do_not_depend_on_process_local_restart_state() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("outbox");
    let first = SolanaOutbox::new(&root).unwrap().allocate_id();
    let second = SolanaOutbox::new(&root).unwrap().allocate_id();

    assert!(first.starts_with("sol-"), "unexpected id {first}");
    assert!(second.starts_with("sol-"), "unexpected id {second}");
    assert_ne!(first, second, "reopening the outbox reused an identity");
}

#[test]
fn duplicate_stage_is_rejected_without_overwriting_the_original() {
    let (_dir, outbox) = outbox();
    let original = staged("same-id");
    outbox.write_pending(&original, "original plan").unwrap();

    let mut replacement = original.clone();
    replacement.lamports = 999;
    let error = outbox
        .write_pending(&replacement, "replacement plan")
        .unwrap_err();
    assert!(matches!(error, OutboxError::TargetExists(_)));
    assert_eq!(
        outbox
            .read("alice", "solana-devnet", "same-id")
            .unwrap()
            .staged
            .lamports,
        original.lamports
    );
}

#[test]
fn transition_collision_preserves_both_entries() {
    let (_dir, outbox) = outbox();
    let original = staged("same-id");
    outbox.write_pending(&original, "pending plan").unwrap();
    let pending = outbox.read("alice", "solana-devnet", "same-id").unwrap();
    let target = outbox.root().join("alice/solana-devnet/sent/same-id");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("sentinel"), b"must survive").unwrap();

    let error = outbox
        .transition(&pending, SolanaOutboxState::Sent)
        .unwrap_err();
    assert!(matches!(error, OutboxError::TargetExists(_)));
    assert_eq!(
        std::fs::read(target.join("sentinel")).unwrap(),
        b"must survive"
    );
    assert!(pending.dir.join("intent.json").exists());
}

#[test]
fn recorded_signature_is_private_and_absent_from_public_intent() {
    let (_dir, outbox) = outbox();
    let mut unsigned = staged("private-signature");
    unsigned.signature = None;
    outbox.write_pending(&unsigned, "plan").unwrap();
    let entry = outbox
        .record_signature(
            "alice",
            "solana-devnet",
            "private-signature",
            "replayable-signature",
        )
        .unwrap();
    outbox
        .write_approval(&entry, b"private approval resume state")
        .unwrap();

    let public = std::fs::read_to_string(entry.dir.join("intent.json")).unwrap();
    assert!(!public.contains("replayable-signature"));
    assert_eq!(
        outbox.recorded_signature(&entry).unwrap().as_deref(),
        Some("replayable-signature")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(entry.dir.join(".signature"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(entry.dir.join("approval.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
