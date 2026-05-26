//! Category: feature (P0-3 conformance)
//!
//! Asserts that the **production** SubmitPtb path enforces real
//! cryptographic signature verification (spec §7.2 step 1).
//!
//! Before this fix the production validator instantiated
//! `AlwaysOkVerifier`, so any byte buffer with the correct length was
//! accepted as a signer signature — only the **outer chain `Tx`
//! envelope's** xDSA signature was actually verified. A malicious
//! relayer could substitute / mutate any PTB signer signature without
//! the chain noticing, as long as it owned the outer envelope key.
//!
//! These tests drive `bloom_chain_node::petal_executor::ChainPetalExecutor`
//! directly (the unit struct `node.rs` wires into the live consensus
//! engine), so they exercise the same code path live blocks run.
//!
//! Test plan:
//! 1. `accepts_valid_ed25519_signature` — build an empty-commands PTB
//!    with a valid Ed25519 signature over the canonical PTB digest,
//!    seed a `Coin<LOOM>` gas-payer, submit, assert `success: true`.
//! 2. `rejects_flipped_signature_byte` — same PTB, flip one byte in
//!    `signatures[0]`, submit, assert revert with a
//!    `BadSignature`-flavoured reason and no write set.
//! 3. `rejects_wrong_pubkey` — same PTB, replace `signers[0]` with a
//!    different (but valid) Ed25519 public key while keeping the
//!    original signature, submit, assert revert with a
//!    `BadSignature`-flavoured reason and no write set.

use bloom_chain_node::{consensus_driver::PetalExecutor, petal_executor::ChainPetalExecutor};
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{Object, ObjectId, Owner};
use bloom_script::{
    encode_ptb, loom_coin_type_tag,
    types::{PqSignature, PtbTx},
};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Canonical `Coin<LOOM>` payload for `value` bloomwei.
/// Matches the convention used by the chain-node fungible petal:
/// 32-byte ObjectId placeholder || value in BE u128 bytes.
fn coin_payload(value: u128) -> Vec<u8> {
    let mut p = vec![0u8; 32];
    p.extend_from_slice(&value.to_be_bytes());
    p
}

/// Mint a `Coin<LOOM>` object at `id`, owned by `Owner::Address(owner)`,
/// holding `value` bloomwei. Mirrors the fixture helper from
/// `ptb_submit_e2e.rs` but inlined here to keep this file self-contained.
fn make_loom_coin(id: ObjectId, owner: [u8; 32], value: u128) -> Object {
    Object {
        id,
        type_tag: loom_coin_type_tag(Hash32([0u8; 32])),
        owner: Owner::Address(owner),
        version: 1,
        payload: coin_payload(value),
    }
}

/// Build a freshly-generated Ed25519 signing key and its raw 32-byte
/// verifying-key bytes (the same shape the PTB `signers` field carries).
fn fresh_ed25519_keypair() -> (SigningKey, [u8; 32]) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

/// Wrap `ptb_bytes` in the chain's outer `Tx` envelope. The outer
/// envelope's signature fields are not exercised by this code path —
/// `ChainPetalExecutor::execute_tx` looks only at `tx.kind`.
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

/// Outer `Tx` sender address. Not load-bearing — the executor does not
/// re-derive sender → signer linkage at this layer.
fn outer_sender() -> Address {
    Address([0x11u8; 32])
}

/// Build a fully-valid PTB **before** signing.
///
/// Layout: zero commands (so no petal resolution is needed), one
/// signer (`pubkey`), the supplied gas payer, generous expiry, zero
/// fees so the gas-reservation check (`gas_budget * gas_price = 0`)
/// is satisfied by any nonzero coin value.
///
/// Returns the PTB *with* a placeholder signature slot — the caller
/// fills `signatures[0]` after computing `signing_digest()`.
fn unsigned_empty_ptb(pubkey: [u8; 32], gas_payer: ObjectId, expiry_block: u64) -> PtbTx {
    PtbTx {
        signers: vec![pubkey],
        commands: vec![],
        gas_payer,
        gas_budget: 0,
        gas_price: 0,
        expiry_block,
        // Single placeholder; will be overwritten with the real
        // signature (or a tampered one) before submission.
        signatures: vec![PqSignature(vec![0u8; 64])],
    }
}

/// Sign `ptb` with `sk` over its canonical signing digest, place the
/// signature in `signatures[0]`, and return the encoded bytes.
fn sign_and_encode(sk: &SigningKey, mut ptb: PtbTx) -> Vec<u8> {
    // Compute the digest with the signatures slot still as a
    // placeholder. `ptb_hash` deliberately excludes `signatures`
    // (see `bloom_script::types::PtbTx` wire-layout docs).
    let digest = ptb.signing_digest();
    let sig = sk.sign(&digest);
    ptb.signatures = vec![PqSignature(sig.to_bytes().to_vec())];
    encode_ptb(&ptb).expect("encode PTB")
}

// ---------------------------------------------------------------------------
// Test 1 — happy path: a valid Ed25519 signature is accepted.
// ---------------------------------------------------------------------------

#[test]
fn accepts_valid_ed25519_signature() {
    let (sk, pk) = fresh_ed25519_keypair();
    let gas_payer_id = ObjectId([0xCC; 32]);

    let mut state = State::new();
    // Seed a Coin<LOOM> owned by the PTB signer so step 6 (gas-payer
    // prep) succeeds. Without this the validator would reject the
    // PTB *after* the signature check, which is still OK for proving
    // the signature passed but masks the fact that a valid sig
    // reaches step 6 at all. Seeding makes the happy path complete.
    state.set_object(make_loom_coin(gas_payer_id, pk, 1_000_000_000));

    let ptb = unsigned_empty_ptb(pk, gas_payer_id, /*expiry*/ 100);
    let ptb_bytes = sign_and_encode(&sk, ptb);
    let tx = submit_ptb_tx(outer_sender(), ptb_bytes);

    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 50,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAA; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(
        out.success,
        "valid Ed25519 PTB signature must be accepted by production: \
         revert reason = {}",
        String::from_utf8_lossy(&out.return_data)
    );
    assert!(
        out.write_set.is_some(),
        "successful PTB must emit a write set",
    );
}

// ---------------------------------------------------------------------------
// Test 2 — flipping any byte in the signature must cause a revert.
// ---------------------------------------------------------------------------

#[test]
fn rejects_flipped_signature_byte() {
    let (sk, pk) = fresh_ed25519_keypair();
    let gas_payer_id = ObjectId([0xCC; 32]);

    let mut state = State::new();
    state.set_object(make_loom_coin(gas_payer_id, pk, 1_000_000_000));

    let mut ptb = unsigned_empty_ptb(pk, gas_payer_id, /*expiry*/ 100);
    let digest = ptb.signing_digest();
    let mut sig_bytes = sk.sign(&digest).to_bytes().to_vec();
    // Flip a single bit in the first signature byte.
    sig_bytes[0] ^= 0x01;
    ptb.signatures = vec![PqSignature(sig_bytes)];
    let ptb_bytes = encode_ptb(&ptb).expect("encode PTB");
    let tx = submit_ptb_tx(outer_sender(), ptb_bytes);

    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 50,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAA; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(
        !out.success,
        "tampered signature must revert; got success with return_data = {}",
        String::from_utf8_lossy(&out.return_data),
    );
    assert!(
        out.write_set.is_none(),
        "tampered-signature revert must drop the write set",
    );
    assert!(
        out.logs.is_empty(),
        "tampered-signature revert must drop logs"
    );

    let reason = String::from_utf8_lossy(&out.return_data).to_lowercase();
    assert!(
        reason.contains("signature")
            || reason.contains("badsignature")
            || reason.contains("signer"),
        "expected a signature-failure revert reason, got: {reason}",
    );
}

// ---------------------------------------------------------------------------
// Test 3 — replacing the signer pubkey with a different valid Ed25519
// key (while keeping the original signature) must also revert.
// ---------------------------------------------------------------------------

#[test]
fn rejects_wrong_pubkey() {
    let (sk, pk) = fresh_ed25519_keypair();
    let (_, attacker_pk) = fresh_ed25519_keypair();
    assert_ne!(pk, attacker_pk, "test keys must differ");
    let gas_payer_id = ObjectId([0xCC; 32]);

    let mut state = State::new();
    // The attacker's address is what would need to own the gas-payer
    // for step 6 to pass. Seeding under the attacker's pubkey makes
    // sure that — if the signature check were broken — the rest of
    // validation would still succeed and the test would notice.
    state.set_object(make_loom_coin(gas_payer_id, attacker_pk, 1_000_000_000));

    // Sign the ptb-as-if-the-real-key-signed-it, but then *swap in*
    // the attacker's pubkey as signers[0]. The signature is still
    // valid Ed25519 over `digest`, but is bound to `pk`, not
    // `attacker_pk`. Real verification must reject this.
    let mut ptb = unsigned_empty_ptb(pk, gas_payer_id, /*expiry*/ 100);
    let digest = ptb.signing_digest();
    let sig = sk.sign(&digest);
    ptb.signatures = vec![PqSignature(sig.to_bytes().to_vec())];
    // Recompute the digest after the swap would defeat the test: a
    // verifier-of-ptb-with-attacker-pk verifies a signature made by
    // `sk` against `attacker_pk`, which is exactly the attack we're
    // detecting. So we do **not** re-sign here.
    ptb.signers = vec![attacker_pk];
    // Note: PTB.signing_digest covers the signers field but NOT the
    // signatures field, so swapping signers changes the digest the
    // verifier will recompute, ensuring the original signature
    // doesn't accidentally validate.
    let ptb_bytes = encode_ptb(&ptb).expect("encode PTB");
    let tx = submit_ptb_tx(outer_sender(), ptb_bytes);

    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 50,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAA; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(
        !out.success,
        "signature bound to a different pubkey must revert; got success with return_data = {}",
        String::from_utf8_lossy(&out.return_data),
    );
    assert!(
        out.write_set.is_none(),
        "wrong-pubkey revert must drop the write set",
    );
    assert!(out.logs.is_empty(), "wrong-pubkey revert must drop logs");

    let reason = String::from_utf8_lossy(&out.return_data).to_lowercase();
    assert!(
        reason.contains("signature")
            || reason.contains("badsignature")
            || reason.contains("signer"),
        "expected a signature-failure revert reason, got: {reason}",
    );
}
