//! Category: feature
//!
//! Integration tests for `TxKind::SubmitPtb` activation (Task #31).
//!
//! Each test wires `ChainPetalExecutor::execute_tx` directly against a
//! freshly built `State`, mirroring what `apply_block_state_transitions`
//! does, and asserts on the resulting `ExecOutput`.
//!
//! Test plan (spec §16.2):
//!   1. Undecodable PTB bytes → revert with decode-error reason; no
//!      write set.
//!   2. Validator-rejected PTB (expired block) → revert atomic; no
//!      write set, no fuel charged beyond `gas_budget`.
//!   3. `signer.address(0)` host import returns the PTB's signer
//!      address. (Pending host-import implementation.)
//!   4. `log.emit` host import round-trips topic/data to receipt logs.
//!      (Pending host-import implementation.)
//!   5. Out-of-fuel during a petal call surfaces as PTB revert with no
//!      state diff. (Pending host-import implementation.)
//!
//! Per the original Task #31 brief (`/goal` 2026-05-20), each test
//! drives the production `ChainPetalExecutor` end-to-end; no
//! production code paths are mocked.

use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_node::petal_executor::ChainPetalExecutor;
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_script::{encode_ptb, PtbTx};

/// Build the smallest possible `TxKind::SubmitPtb` transaction with
/// the given PTB bytes. Fuel/fees are zero — the executor does not
/// debit them itself (that's `apply_block`'s job).
fn submit_ptb_tx(sender: Address, ptb_bytes: Vec<u8>) -> Tx {
    Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 0,
        max_fuel: 1_000_000,
        fee_per_unit: 0,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey: PubKeyBytes(vec![0u8; 32]),
        sig: SigBytes(vec![0u8; 64]),
    }
}

/// Sender used across these tests; not load-bearing — the executor
/// does not look the account up before dispatching to the PTB path.
fn test_sender() -> Address {
    Address([0x11u8; 32])
}

/// Test 1: PTB bytes that do not decode (empty payload) MUST revert
/// with `success = false`, `write_set = None`, and a revert reason
/// that mentions decode failure — not the legacy
/// `NotYetActivated: SubmitPtb (Phase 1)` placeholder.
#[test]
fn undecodable_ptb_bytes_revert_atomically() {
    let mut state = State::new();
    let sender = test_sender();

    // Empty bytes are not a valid canonical PTB encoding.
    let tx = submit_ptb_tx(sender, Vec::new());

    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAAu8; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(!out.success, "undecodable PTB must revert");
    assert!(out.write_set.is_none(), "revert must drop write set");
    assert!(out.logs.is_empty(), "revert must drop logs");

    let reason = String::from_utf8_lossy(&out.return_data);
    assert!(
        !reason.contains("NotYetActivated"),
        "SubmitPtb dispatcher is still the Phase-1 placeholder: {reason}"
    );
    assert!(
        reason.to_lowercase().contains("decode") || reason.to_lowercase().contains("invalid"),
        "expected decode/invalid revert reason, got: {reason}"
    );
}

/// Test 2: A structurally-decodable PTB that the validator rejects
/// (here: zero signers) MUST revert atomically. No write set, no logs,
/// and a reason that surfaces the validator error — not the decoder.
#[test]
fn validator_rejected_ptb_reverts_atomically() {
    let mut state = State::new();
    let sender = test_sender();

    // Empty PtbTx decodes fine but fails validation immediately at the
    // signer-count check (`PtbError::NoSigners`).
    let ptb = PtbTx::default();
    let bytes = encode_ptb(&ptb).expect("encode empty PTB");
    let tx = submit_ptb_tx(sender, bytes);

    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAAu8; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(!out.success, "validator-rejected PTB must revert");
    assert!(out.write_set.is_none(), "validator rejection must drop write set");
    assert!(out.logs.is_empty(), "validator rejection must drop logs");

    let reason = String::from_utf8_lossy(&out.return_data);
    assert!(
        reason.to_lowercase().contains("signer")
            || reason.to_lowercase().contains("validation")
            || reason.to_lowercase().contains("nosigners")
            || reason.to_lowercase().contains("validator"),
        "expected validator error reason, got: {reason}"
    );
}
