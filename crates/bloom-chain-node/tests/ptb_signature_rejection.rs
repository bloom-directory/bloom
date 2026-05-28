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
//! 1. `accepts_valid_xdsa_signature` — build an empty-commands PTB
//!    with a valid xDSA signature over the canonical PTB digest,
//!    seed a `Coin<LOOM>` gas-payer, submit, assert `success: true`.
//! 2. `rejects_flipped_signature_byte` — same PTB, flip one byte in
//!    `signatures[0]`, submit, assert revert with a
//!    `BadSignature`-flavoured reason and no write set.
//! 3. `rejects_wrong_pubkey` — same PTB, replace `signers[0]` with a
//!    different registered xDSA address while keeping the
//!    original signature, submit, assert revert with a
//!    `BadSignature`-flavoured reason and no write set.

use bloom_chain_consensus::{Mempool, NoopVerifier, error::ConsensusError};
use bloom_chain_node::{
    consensus_driver::{PetalExecutor, StateAdmissionView},
    petal_executor::ChainPetalExecutor,
};
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_keystore::xdsa::XdsaSecretKey;
use bloom_objects::{Object, ObjectId, Owner};
use bloom_script::{
    CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH, encode_ptb, loom_coin_type_tag,
    types::{PqSignature, PtbTx},
};

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
        type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
        owner: Owner::Address(owner),
        version: 1,
        payload: coin_payload(value),
    }
}

fn bind_bootstrap_fungible(state: &mut State) {
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
}

/// Build a freshly-generated xDSA signing key and its 32-byte address
/// (the same shape the PTB `signers` field carries).
fn fresh_xdsa_keypair() -> (XdsaSecretKey, PubKeyBytes, [u8; 32]) {
    let (sk, pk) = XdsaSecretKey::generate();
    let addr = Address::from_pubkey_bytes(&pk.0).0;
    (sk, PubKeyBytes(pk.to_bytes()), addr)
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
fn sign_and_encode(sk: &XdsaSecretKey, mut ptb: PtbTx) -> Vec<u8> {
    // Compute the digest with the signatures slot still as a
    // placeholder. `ptb_hash` deliberately excludes `signatures`
    // (see `bloom_script::types::PtbTx` wire-layout docs).
    let digest = ptb.signing_digest();
    let sig = sk.sign(&digest);
    ptb.signatures = vec![PqSignature(sig.to_bytes())];
    encode_ptb(&ptb).expect("encode PTB")
}

// ---------------------------------------------------------------------------
// Test 1 — happy path: a valid xDSA signature is accepted.
// ---------------------------------------------------------------------------

#[test]
fn accepts_valid_xdsa_signature() {
    let (sk, pk, signer_addr) = fresh_xdsa_keypair();
    let gas_payer_id = ObjectId([0xCC; 32]);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    state.register_pubkey(Address(signer_addr), pk);
    // Seed a Coin<LOOM> owned by the PTB signer so step 6 (gas-payer
    // prep) succeeds. Without this the validator would reject the
    // PTB *after* the signature check, which is still OK for proving
    // the signature passed but masks the fact that a valid sig
    // reaches step 6 at all. Seeding makes the happy path complete.
    state.set_object(make_loom_coin(gas_payer_id, signer_addr, 1_000_000_000));

    let ptb = unsigned_empty_ptb(signer_addr, gas_payer_id, /*expiry*/ 100);
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
        "valid xDSA PTB signature must be accepted by production: \
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
    let (sk, pk, signer_addr) = fresh_xdsa_keypair();
    let gas_payer_id = ObjectId([0xCC; 32]);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    state.register_pubkey(Address(signer_addr), pk);
    state.set_object(make_loom_coin(gas_payer_id, signer_addr, 1_000_000_000));

    let mut ptb = unsigned_empty_ptb(signer_addr, gas_payer_id, /*expiry*/ 100);
    let digest = ptb.signing_digest();
    let mut sig_bytes = sk.sign(&digest).to_bytes();
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
// Test 3 — replacing the signer address with a different registered xDSA key
// (while keeping the original signature) must also revert.
// ---------------------------------------------------------------------------

#[test]
fn rejects_wrong_pubkey() {
    let (sk, _pk, signer_addr) = fresh_xdsa_keypair();
    let (_attacker_sk, attacker_pk, attacker_addr) = fresh_xdsa_keypair();
    assert_ne!(signer_addr, attacker_addr, "test keys must differ");
    let gas_payer_id = ObjectId([0xCC; 32]);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    // The attacker's address is what would need to own the gas-payer
    // for step 6 to pass. Seeding under the attacker's pubkey makes
    // sure that — if the signature check were broken — the rest of
    // validation would still succeed and the test would notice.
    state.register_pubkey(Address(attacker_addr), attacker_pk);
    state.set_object(make_loom_coin(gas_payer_id, attacker_addr, 1_000_000_000));

    // Build the exact PTB the verifier will see: signer slot names the
    // attacker's registered address, and the gas payer is owned by that
    // address, so everything after signature verification would pass. Then
    // sign that same digest with the wrong xDSA key. This isolates registry
    // lookup/public-key mismatch from digest mutation.
    let mut ptb = unsigned_empty_ptb(attacker_addr, gas_payer_id, /*expiry*/ 100);
    let digest = ptb.signing_digest();
    let sig = sk.sign(&digest);
    ptb.signatures = vec![PqSignature(sig.to_bytes())];
    assert_eq!(
        digest,
        ptb.signing_digest(),
        "test must not rely on signer/digest mutation"
    );
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

// ---------------------------------------------------------------------------
// Test 4 — mempool admission must reject unauthenticated gas-sponsored PTBs.
// ---------------------------------------------------------------------------

#[test]
fn admission_rejects_bad_inner_signature_before_gas_payer_sponsorship() {
    let (victim_sk, victim_pk, victim_addr) = fresh_xdsa_keypair();
    let (attacker_sk, attacker_pk) = XdsaSecretKey::generate();
    let attacker = Address::from_pubkey_bytes(&attacker_pk.0);
    let gas_payer_id = ObjectId([0xDD; 32]);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    state.register_pubkey(Address(victim_addr), victim_pk);
    state.set_object(make_loom_coin(gas_payer_id, victim_addr, 1_000_000_000));

    let mut ptb = unsigned_empty_ptb(victim_addr, gas_payer_id, /*expiry*/ 100);
    ptb.gas_budget = 10;
    ptb.gas_price = 1;
    let digest = ptb.signing_digest();
    let mut bad_sig = victim_sk.sign(&digest).to_bytes();
    bad_sig[0] ^= 0x01;
    ptb.signatures = vec![PqSignature(bad_sig)];
    let ptb_bytes = encode_ptb(&ptb).expect("encode PTB");

    let mut tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender: attacker,
        nonce: 1,
        max_fuel: 10,
        fee_per_unit: 1,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey: PubKeyBytes(attacker_pk.0.clone()),
        sig: SigBytes(vec![]),
    };
    let outer_digest = tx.signing_digest();
    tx.sig = SigBytes(attacker_sk.sign(&outer_digest.0).to_bytes());

    let view = StateAdmissionView {
        state: &state,
        current_block: 50,
    };
    let mut mempool = Mempool::new(NoopVerifier);
    let err = mempool
        .admit_with_view(tx, &view)
        .expect_err("bad inner PTB signature must not be admitted");

    assert!(
        matches!(err, ConsensusError::InvalidSubmitPtb(ref reason) if reason.contains("signature") || reason.contains("BadSignature")),
        "expected invalid SubmitPtb signature rejection, got {err:?}"
    );
    assert_eq!(mempool.len(), 0, "rejected PTB must not persist in mempool");
}

#[test]
fn admission_accepts_outer_sender_as_first_ptb_signer_without_prior_key_registry_entry() {
    let (sk, pk) = XdsaSecretKey::generate();
    let signer = Address::from_pubkey_bytes(&pk.0);
    let gas_payer_id = ObjectId([0xDE; 32]);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    state.set_object(make_loom_coin(gas_payer_id, signer.0, 1_000_000_000));

    let mut ptb = unsigned_empty_ptb(signer.0, gas_payer_id, /*expiry*/ 100);
    ptb.gas_budget = 10;
    ptb.gas_price = 1;
    let digest = ptb.signing_digest();
    ptb.signatures = vec![PqSignature(sk.sign(&digest).to_bytes())];
    let ptb_bytes = encode_ptb(&ptb).expect("encode PTB");

    let mut tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender: signer,
        nonce: 1,
        max_fuel: 10,
        fee_per_unit: 1,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey: PubKeyBytes(pk.0.clone()),
        sig: SigBytes(vec![]),
    };
    let outer_digest = tx.signing_digest();
    tx.sig = SigBytes(sk.sign(&outer_digest.0).to_bytes());

    let view = StateAdmissionView {
        state: &state,
        current_block: 50,
    };
    let mut mempool = Mempool::new(NoopVerifier);
    mempool
        .admit_with_view(tx, &view)
        .expect("outer sender's pubkey should authenticate its matching PTB signer slot");

    assert_eq!(mempool.len(), 1);
}
