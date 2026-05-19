//! Regression coverage for the 2026-05-19 review #2 — catch-up block sync
//! must run the same validation boundary as live consensus.
//!
//! These tests pin the contract that any block reaching state apply has
//! passed [`bloom_chain_node::consensus_driver::validate_block_for_apply`]:
//! chain id, height, parent hash, tx root, validator set hash, commit
//! shape, and 2f+1 commit quorum with valid xDSA signatures.
//!
//! On master, BlockResponse handling fed raw wire blocks straight into
//! state apply — a peer could push a tampered tx root, a wrong validator
//! set hash, a forged commit, or a wrong parent and the validator would
//! happily apply it.

use std::sync::Arc;

use bloom_chain_consensus::{
    signer::Signer,
    validator_set::{Validator, ValidatorSet},
};
use bloom_chain_node::consensus_driver::{
    compute_txs_root, validate_block_for_apply, XdsaSigner, XdsaVerifier,
};
use bloom_chain_types::{
    block::{Block, BlockHeader},
    tx::{Tx, TxKind},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
    vote::{Commit, Vote, VoteKind},
};

struct Val {
    sk: Arc<bloom_keystore::xdsa::XdsaSecretKey>,
    pk: bloom_keystore::xdsa::XdsaPublicKey,
    addr: Address,
}

fn make_val() -> Val {
    let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let addr = bloom_chain_types::types::Address::from_pubkey_bytes(&pk.0);
    Val {
        sk: Arc::new(sk),
        pk,
        addr,
    }
}

fn validator_set(vals: &[&Val]) -> ValidatorSet {
    ValidatorSet::new(
        vals.iter()
            .map(|v| Validator {
                address: v.addr,
                pubkey: PubKeyBytes(v.pk.0.clone()),
                voting_power: 100,
            })
            .collect(),
    )
    .unwrap()
}

/// Build a block whose header is internally consistent (txs_root computed
/// from txs, validator_set_hash matches the set, etc.) and a commit
/// signed by `signers` (subset of `vset`). Caller-supplied tweaks let
/// individual tests mutate single fields to test rejection paths.
fn make_block(
    chain_id: &str,
    height: u64,
    parent_hash: Hash32,
    proposer: Address,
    vset: &ValidatorSet,
    signers: &[&Val],
) -> Block {
    let txs = vec![];
    let txs_root = compute_txs_root(&txs);
    let validator_set_hash = vset.validator_set_hash();

    let header = BlockHeader {
        chain_id: chain_id.to_string(),
        height,
        parent_hash,
        timestamp_ms: 1_747_526_400_000 + height * 1_000,
        proposer,
        txs_root,
        state_root: Hash32([0xBB; 32]),
        receipts_root: Hash32([0xCC; 32]),
        validator_set_hash,
        fuel_used: 0,
        fuel_limit: 30_000_000,
    };
    let block_hash = header.block_hash();

    let votes: Vec<Vote> = signers
        .iter()
        .map(|s| {
            let mut v = Vote {
                height,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: Some(block_hash),
                validator: s.addr,
                sig: SigBytes(vec![]),
            };
            let digest = v.signing_digest();
            v.sig = XdsaSigner::new(Arc::clone(&s.sk)).sign(&digest.0);
            v
        })
        .collect();

    Block {
        header,
        txs,
        commit: Commit {
            height,
            round: 0,
            block_hash,
            votes,
        },
    }
}

#[test]
fn well_formed_block_with_quorum_accepted() {
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    // 4 × 100 = 400 power; quorum = 2*400/3 + 1 = 267. 3 signers = 300.
    let block = make_block(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
    );
    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(result.is_ok(), "well-formed block rejected: {result:?}");
}

#[test]
fn block_with_tampered_txs_root_is_rejected() {
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    let mut block = make_block(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
    );
    // Attacker tampers the txs_root in the header.
    block.header.txs_root = Hash32([0xFF; 32]);
    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(
        result.is_err(),
        "tampered txs_root must be rejected; got {result:?}"
    );
    assert!(result.unwrap_err().contains("txs_root mismatch"));
}

#[test]
fn block_with_wrong_parent_hash_is_rejected() {
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    let block = make_block(
        "bloom-chain.v0",
        5,
        Hash32([0x11; 32]), // claims parent is 0x11..
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
    );
    // ..but our local block-store says the parent at h=4 hashes to 0x42..
    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(
        result.is_err(),
        "wrong parent_hash must be rejected; got {result:?}"
    );
    assert!(result.unwrap_err().contains("parent_hash mismatch"));
}

#[test]
fn block_with_wrong_validator_set_hash_is_rejected() {
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    let mut block = make_block(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
    );
    block.header.validator_set_hash = Hash32([0xAA; 32]);
    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("validator_set_hash mismatch"),
        "expected validator_set_hash mismatch error"
    );
}

#[test]
fn block_with_wrong_chain_id_is_rejected() {
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    // The block claims a different chain — could be a packet from a
    // testnet leaking into mainnet, or a deliberate cross-chain replay.
    let block = make_block(
        "evil-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
    );
    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("chain_id mismatch"));
}

#[test]
fn block_with_insufficient_commit_quorum_is_rejected() {
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    // Only TWO signers — 200 power, below quorum (267).
    let block = make_block(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2],
    );
    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("commit quorum not met"),
        "expected commit quorum error, got: {err}"
    );
}

#[test]
fn block_with_commit_vote_from_non_validator_is_rejected() {
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let mallory = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    // Three legit signers (quorum-meeting), plus a vote from an address
    // that is NOT in the validator set. The non-validator vote must be
    // rejected outright — counting it would let a peer fabricate quorum
    // by injecting votes from random addresses with valid self-signatures.
    let mut block = make_block(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3, &mallory],
    );
    // Sanity: prove the test is meaningful by also tampering the legit
    // signers down to two so the only path to quorum runs through
    // mallory's vote. (3×100 = 300 ≥ 267 by itself, so we drop one to
    // make mallory's count load-bearing.)
    block.commit.votes.remove(0); // drop v1's vote
    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(
        result.is_err(),
        "commit votes from non-validator must be rejected; got {result:?}"
    );
}

#[test]
fn block_with_forged_commit_signature_is_rejected() {
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    let mut block = make_block(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
    );
    // Flip a byte in one of the precommit signatures.
    block.commit.votes[1].sig.0[7] ^= 0xFF;
    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(
        result.is_err(),
        "forged commit signature must be rejected; got {result:?}"
    );
}

#[test]
fn block_with_wrong_height_in_header_is_rejected() {
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    let block = make_block(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
    );
    // Validator's engine is at height 7, but the wire block claims 5.
    let result = validate_block_for_apply(
        &block,
        7,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("height mismatch"));
}

#[test]
fn block_with_commit_for_different_block_hash_falls_below_quorum() {
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    let mut block = make_block(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
    );
    // Rewrite one vote to commit to a different block_hash. That vote
    // can't count toward quorum on the actual block we're applying —
    // dropping us to 200/400 power, below quorum.
    let wrong_hash = Hash32([0x99; 32]);
    block.commit.votes[2].block_hash = Some(wrong_hash);
    // Re-sign the perturbed vote so it's at least self-consistent (the
    // attacker would otherwise just put a fake sig and we'd reject on
    // sig mismatch — we want to prove quorum-by-hash is enforced even
    // when sigs are valid).
    let digest = block.commit.votes[2].signing_digest();
    block.commit.votes[2].sig = XdsaSigner::new(Arc::clone(&v3.sk)).sign(&digest.0);

    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(
        result.is_err(),
        "votes for a different block_hash must not count toward quorum; got {result:?}"
    );
    assert!(result.unwrap_err().contains("commit quorum not met"));
}

// ---------------------------------------------------------------------------
// Per-tx authentication — review 2026-05-19 (HIGH follow-ups):
//   apply-time sender-derivation does NOT bind the signature to the tx body
//   and does NOT enforce chain_id. A malicious proposer can therefore stuff
//   a forged or cross-chain tx into its own block (mempool admission never
//   sees proposer-built blocks), and pre-fix the validation boundary
//   accepted them. These tests pin the new behaviour: every tx in a
//   committed block must (a) verify its xDSA signature and (b) carry
//   `chain_id == expected_chain_id`.
// ---------------------------------------------------------------------------

/// Build a Tx whose pubkey + sig are valid for the chosen `chain_id` and
/// whose `sender` derives from that pubkey. `nonce=1` (smallest valid).
fn make_signed_tx(sk: &bloom_keystore::xdsa::XdsaSecretKey, chain_id: &str) -> Tx {
    let pk = sk.public_key();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let mut tx = Tx {
        chain_id: chain_id.to_string(),
        sender,
        nonce: 1,
        max_fuel: 100_000,
        fee_per_unit: 1,
        kind: TxKind::Transfer {
            to: Address([0x77; 32]),
            amount_loom: 1,
        },
        pubkey: PubKeyBytes(pk.0.clone()),
        sig: SigBytes(vec![]),
    };
    let digest = tx.signing_digest();
    let signature = sk.sign(&digest.0);
    tx.sig = SigBytes(signature.to_bytes());
    tx
}

/// Variant of `make_block` that carries a single tx and recomputes the
/// header's `txs_root` so block-level integrity is preserved (the test
/// then probes the per-tx checks specifically).
fn make_block_with_tx(
    chain_id: &str,
    height: u64,
    parent_hash: Hash32,
    proposer: Address,
    vset: &ValidatorSet,
    signers: &[&Val],
    tx: Tx,
) -> Block {
    let txs = vec![tx];
    let txs_root = compute_txs_root(&txs);
    let validator_set_hash = vset.validator_set_hash();
    let header = BlockHeader {
        chain_id: chain_id.to_string(),
        height,
        parent_hash,
        timestamp_ms: 1_747_526_400_000 + height * 1_000,
        proposer,
        txs_root,
        state_root: Hash32([0xBB; 32]),
        receipts_root: Hash32([0xCC; 32]),
        validator_set_hash,
        fuel_used: 0,
        fuel_limit: 30_000_000,
    };
    let block_hash = header.block_hash();
    let votes: Vec<Vote> = signers
        .iter()
        .map(|s| {
            let mut v = Vote {
                height,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: Some(block_hash),
                validator: s.addr,
                sig: SigBytes(vec![]),
            };
            let digest = v.signing_digest();
            v.sig = XdsaSigner::new(Arc::clone(&s.sk)).sign(&digest.0);
            v
        })
        .collect();
    Block {
        header,
        txs,
        commit: Commit {
            height,
            round: 0,
            block_hash,
            votes,
        },
    }
}

#[test]
fn block_with_forged_tx_signature_is_rejected() {
    // A malicious proposer builds a tx, signs it correctly, then flips
    // bytes in the signature to break it (or any other body change after
    // signing). On master, validate_block_for_apply never touched the tx
    // sig, so the block applied. Post-fix, this MUST reject the block.
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    let (sk_sender, _pk_sender) = bloom_keystore::xdsa::XdsaSecretKey::generate();

    let mut tx = make_signed_tx(&sk_sender, "bloom-chain.v0");
    // Tamper the signature — body still derives the same sender, but the
    // tx is no longer a genuine artefact of the private key holder.
    tx.sig.0[5] ^= 0xFF;

    let block = make_block_with_tx(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
        tx,
    );

    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(
        result.is_err(),
        "forged tx signature must be rejected; got {result:?}"
    );
    assert!(
        result.unwrap_err().contains("tx signature invalid"),
        "expected tx-signature error"
    );
}

#[test]
fn block_with_cross_chain_tx_is_rejected() {
    // A tx legitimately signed for `evil-chain.v0` is included in a
    // `bloom-chain.v0` block — classic cross-chain replay. The header
    // chain_id check alone is insufficient: the header could be honest
    // while the body is replayed. Mempool admission would have caught
    // it, but the proposer never goes through admit for its own block.
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);
    let (sk_sender, _pk_sender) = bloom_keystore::xdsa::XdsaSecretKey::generate();

    // Genuinely signed for the wrong chain — sig is valid against that
    // chain's signing digest, so the per-tx sig check alone would pass.
    // Only the per-tx chain_id equality check catches this.
    let tx = make_signed_tx(&sk_sender, "evil-chain.v0");

    let block = make_block_with_tx(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
        tx,
    );

    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(
        result.is_err(),
        "cross-chain tx must be rejected; got {result:?}"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("tx.chain_id"),
        "expected tx.chain_id error, got: {err}"
    );
}

#[test]
fn commit_with_votes_from_different_rounds_is_rejected() {
    // Tendermint safety: 2f+1 must come from a single (height, round)
    // tuple. On master, the validation boundary only checked
    // (height, kind, block_hash, sig), so an attacker who collected a
    // round-0 precommit, a round-1 precommit, and a round-2 precommit
    // — each for the same block_hash, each individually valid — could
    // assemble a forged commit. Real consensus never produces that
    // pattern (a single round either reaches commit or aborts), so the
    // boundary now refuses any commit whose vote.round disagrees with
    // commit.round.
    let v1 = make_val();
    let v2 = make_val();
    let v3 = make_val();
    let v4 = make_val();
    let vset = validator_set(&[&v1, &v2, &v3, &v4]);

    // Three signers — 300 power, well above quorum of 267.
    let mut block = make_block(
        "bloom-chain.v0",
        5,
        Hash32([0x42; 32]),
        v1.addr,
        &vset,
        &[&v1, &v2, &v3],
    );

    // Rewrite v3's vote so it commits to the same block_hash from
    // round=1 instead of round=0. Re-sign so the signature itself
    // remains valid — we are proving that even cryptographically
    // genuine cross-round votes get refused.
    block.commit.votes[2].round = 1;
    let digest = block.commit.votes[2].signing_digest();
    block.commit.votes[2].sig = XdsaSigner::new(Arc::clone(&v3.sk)).sign(&digest.0);
    // commit.round itself stays 0 (the "real" round we believe we're
    // finalising). The cross-round vote should be flagged here.

    let result = validate_block_for_apply(
        &block,
        5,
        "bloom-chain.v0",
        Hash32([0x42; 32]),
        &vset,
        &XdsaVerifier,
    );
    assert!(
        result.is_err(),
        "commit aggregating votes across rounds must be rejected; got {result:?}"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("commit.vote.round"),
        "expected cross-round error, got: {err}"
    );
}
