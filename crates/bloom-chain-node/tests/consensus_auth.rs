//! Regression coverage for the 2026-05-19 review #1 — consensus message
//! authentication at ingress.
//!
//! These tests pin the cross-crate contract that Vote / Proposal signatures
//! produced by the consensus engine (via the node's `XdsaSigner`) verify under
//! the `XdsaVerifier`, and that messages with forged signatures, wrong-key
//! signatures, or empty signatures are rejected by
//! [`bloom_chain_consensus::auth::verify_vote_sig`] /
//! [`bloom_chain_consensus::auth::verify_proposal_sig`].
//!
//! On master these tests fail because votes/proposals are emitted with empty
//! signatures and the node forwards them to the state machine without
//! verifying anything.

use std::sync::Arc;

use bloom_chain_consensus::{
    auth::{verify_proposal_sig, verify_vote_sig},
    signer::Signer,
    validator_set::{Validator, ValidatorSet},
};
use bloom_chain_node::consensus_driver::{XdsaSigner, XdsaVerifier};
use bloom_chain_types::{
    types::{Address, Hash32, PubKeyBytes, SigBytes},
    vote::{Proposal, Vote, VoteKind},
};

fn make_validator() -> (
    Arc<bloom_keystore::xdsa::XdsaSecretKey>,
    bloom_keystore::xdsa::XdsaPublicKey,
    Address,
) {
    let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let addr = bloom_chain_types::types::Address::from_pubkey_bytes(&pk.0);
    (Arc::new(sk), pk, addr)
}

fn make_validator_set(entries: &[(&bloom_keystore::xdsa::XdsaPublicKey, &Address)]) -> ValidatorSet {
    ValidatorSet::new(
        entries
            .iter()
            .map(|(pk, addr)| Validator {
                address: **addr,
                pubkey: PubKeyBytes(pk.0.clone()),
                voting_power: 100,
            })
            .collect(),
    )
    .unwrap()
}

#[test]
fn signed_vote_verifies_against_validator_set() {
    let (sk, pk, addr) = make_validator();
    let vset = make_validator_set(&[(&pk, &addr)]);

    let mut vote = Vote {
        height: 7,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(Hash32([0x11; 32])),
        validator: addr,
        sig: SigBytes(vec![]),
    };
    let signer = XdsaSigner::new(sk);
    let digest = vote.signing_digest();
    vote.sig = signer.sign(&digest.0);

    assert!(
        verify_vote_sig(&vote, &vset, &XdsaVerifier::default()),
        "a vote signed with the validator's xDSA key must verify"
    );
}

#[test]
fn signed_proposal_verifies_against_validator_set() {
    let (sk, pk, addr) = make_validator();
    let vset = make_validator_set(&[(&pk, &addr)]);

    let mut proposal = Proposal {
        height: 9,
        round: 1,
        block_hash: Hash32([0x55; 32]),
        pol_round: -1,
        proposer: addr,
        sig: SigBytes(vec![]),
    };
    let signer = XdsaSigner::new(sk);
    let digest = proposal.signing_digest();
    proposal.sig = signer.sign(&digest.0);

    assert!(
        verify_proposal_sig(&proposal, &vset, &XdsaVerifier::default()),
        "a proposal signed with the proposer's xDSA key must verify"
    );
}

#[test]
fn forged_vote_signature_rejected() {
    let (sk, pk, addr) = make_validator();
    let vset = make_validator_set(&[(&pk, &addr)]);

    let mut vote = Vote {
        height: 7,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(Hash32([0x11; 32])),
        validator: addr,
        sig: SigBytes(vec![]),
    };
    let signer = XdsaSigner::new(sk);
    let digest = vote.signing_digest();
    vote.sig = signer.sign(&digest.0);

    // Flip a byte in the signature — must invalidate it.
    vote.sig.0[5] ^= 0xFF;
    assert!(
        !verify_vote_sig(&vote, &vset, &XdsaVerifier::default()),
        "a vote with a tampered signature must NOT verify"
    );
}

#[test]
fn forged_proposal_signature_rejected() {
    let (sk, pk, addr) = make_validator();
    let vset = make_validator_set(&[(&pk, &addr)]);

    let mut proposal = Proposal {
        height: 9,
        round: 1,
        block_hash: Hash32([0x55; 32]),
        pol_round: -1,
        proposer: addr,
        sig: SigBytes(vec![]),
    };
    let signer = XdsaSigner::new(sk);
    let digest = proposal.signing_digest();
    proposal.sig = signer.sign(&digest.0);
    proposal.sig.0[100] ^= 0xFF;

    assert!(
        !verify_proposal_sig(&proposal, &vset, &XdsaVerifier::default()),
        "a proposal with a tampered signature must NOT verify"
    );
}

#[test]
fn empty_vote_signature_rejected() {
    let (_, pk, addr) = make_validator();
    let vset = make_validator_set(&[(&pk, &addr)]);

    // Empty sig: what the pre-fix engine emitted at engine.rs:118.
    let vote = Vote {
        height: 7,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(Hash32([0x11; 32])),
        validator: addr,
        sig: SigBytes(vec![]),
    };
    assert!(
        !verify_vote_sig(&vote, &vset, &XdsaVerifier::default()),
        "the pre-2026-05-19 empty-sig vote must be rejected by the ingress \
         check"
    );
}

#[test]
fn vote_signed_by_a_different_validators_key_is_rejected() {
    // Alice and Bob both validators; Bob tries to forge a vote claiming to be
    // from Alice but signs it with his own key.
    let (alice_sk, alice_pk, alice_addr) = make_validator();
    let (bob_sk, bob_pk, bob_addr) = make_validator();
    let vset = make_validator_set(&[(&alice_pk, &alice_addr), (&bob_pk, &bob_addr)]);
    let _ = alice_sk;

    let mut forged = Vote {
        height: 7,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(Hash32([0xAB; 32])),
        validator: alice_addr, // Claims to be Alice...
        sig: SigBytes(vec![]),
    };
    let bob_signer = XdsaSigner::new(bob_sk);
    let digest = forged.signing_digest();
    forged.sig = bob_signer.sign(&digest.0); // ...but signed by Bob.

    assert!(
        !verify_vote_sig(&forged, &vset, &XdsaVerifier::default()),
        "a vote claiming to be from validator A but signed with B's key must \
         be rejected"
    );
}

#[test]
fn vote_from_unknown_validator_is_rejected() {
    let (alice_sk, alice_pk, alice_addr) = make_validator();
    let vset = make_validator_set(&[(&alice_pk, &alice_addr)]);

    // Carol generates a key and tries to vote — she is not in the validator
    // set, so even a correctly-signed vote must be rejected.
    let (carol_sk, _carol_pk, carol_addr) = make_validator();
    let _ = alice_sk;
    let mut vote = Vote {
        height: 7,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(Hash32([0x11; 32])),
        validator: carol_addr,
        sig: SigBytes(vec![]),
    };
    let signer = XdsaSigner::new(carol_sk);
    let digest = vote.signing_digest();
    vote.sig = signer.sign(&digest.0);

    assert!(
        !verify_vote_sig(&vote, &vset, &XdsaVerifier::default()),
        "a vote from an address not in the validator set must be rejected, \
         even with a self-consistent signature"
    );
}

#[test]
fn engine_emits_signed_votes_when_signer_is_set() {
    // Drive the engine through a propose-timeout so it emits a nil-prevote,
    // and assert that prevote carries a real signature (not the empty bytes
    // emitted on master).
    use bloom_chain_consensus::{
        state_machine::{Action, Event, ProposalOrVote, TimeoutKind},
        ConsensusEngine,
    };

    let (sk, pk, addr) = make_validator();
    let vset = make_validator_set(&[(&pk, &addr)]);
    let signer: Arc<dyn Signer> = Arc::new(XdsaSigner::new(sk));

    let mut engine: ConsensusEngine<XdsaVerifier> = ConsensusEngine::new(
        1,
        addr,
        vset.clone(),
        XdsaVerifier::default(),
        None,
        30_000_000,
        Some(signer),
    );

    let actions = engine.step(Event::Tick(TimeoutKind::Propose));
    let prevote = actions
        .iter()
        .find_map(|a| match a {
            Action::Broadcast(ProposalOrVote::Vote(v)) => Some(v.clone()),
            _ => None,
        })
        .expect("propose-timeout must emit a nil-prevote");

    assert!(
        !prevote.sig.0.is_empty(),
        "engine with a Signer must NOT emit empty-sig votes (master regression)"
    );
    assert!(
        verify_vote_sig(&prevote, &vset, &XdsaVerifier::default()),
        "engine-emitted votes must verify under the same validator set"
    );
}
