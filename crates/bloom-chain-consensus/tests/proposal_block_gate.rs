//! Category: adversarial
//!
//! Regression coverage for the 2026-05-19 review #3 — `on_proposal` must
//! refuse to transition to Prevote until the proposed `block_hash` is present
//! in the blocks map.
//!
//! On master, the state machine accepted any well-formed proposal from the
//! expected proposer and immediately emitted a Prevote — even when the
//! proposed body was unknown to this validator. That made us attest to a
//! block we could not validate.
//!
//! Post-fix behaviour: an unknown-block proposal is silently dropped (no
//! state transition, no broadcast). The propose-timeout will eventually
//! fire and we will nil-prevote, which is the safe outcome for a missing
//! body. Once the block arrives via BlockResponse and the next proposal
//! arrives (or the same proposal is replayed), Prevote proceeds normally.

use std::collections::BTreeMap;

use bloom_chain_consensus::state_machine::{Action, ConsensusState, Event, ProposalOrVote, Step};
use bloom_chain_types::{
    block::Block,
    types::{Hash32, SigBytes},
    vote::{Proposal, Vote, VoteKind},
};
use bloom_test_util::{BlockBuilder, make_addr, make_validator_set_fake};

fn make_block(height: u64, proposer: u8) -> Block {
    BlockBuilder::at(height)
        .proposer(make_addr(proposer))
        .build()
}

#[test]
fn proposal_for_unknown_block_does_not_emit_prevote() {
    let height = 1u64;
    let proposer_idx = 1u8; // (h=1, r=0) → idx (1+0)%4 = 1.

    let block = make_block(height, proposer_idx);
    let block_hash = block.header.block_hash();
    // Crucially: blocks map is EMPTY. We have not seen this body.
    let blocks: BTreeMap<Hash32, Block> = BTreeMap::new();

    // Validator 0 (not the proposer) receives the proposal.
    let mut sm = ConsensusState::new(height, make_addr(0), make_validator_set_fake(4, 100));
    let proposal = Proposal {
        height,
        round: 0,
        block_hash,
        pol_round: -1,
        proposer: make_addr(proposer_idx),
        sig: SigBytes(vec![]),
    };

    let actions = sm.handle(Event::ReceiveProposal(proposal), &blocks);
    let prevotes: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Broadcast(ProposalOrVote::Vote(v)) if v.kind == VoteKind::Prevote => Some(v),
            _ => None,
        })
        .collect();
    assert!(
        prevotes.is_empty(),
        "must NOT prevote a proposal whose block we have not yet validated; got {} prevote(s)",
        prevotes.len()
    );
}

#[test]
fn proposal_with_known_block_still_emits_prevote() {
    // Sanity: the gate only kicks when the block is unknown — once the body
    // is registered, the happy path still works.
    let height = 1u64;
    let proposer_idx = 1u8;

    let block = make_block(height, proposer_idx);
    let block_hash = block.header.block_hash();
    let mut blocks: BTreeMap<Hash32, Block> = BTreeMap::new();
    blocks.insert(block_hash, block.clone());

    let mut sm = ConsensusState::new(height, make_addr(0), make_validator_set_fake(4, 100));
    let proposal = Proposal {
        height,
        round: 0,
        block_hash,
        pol_round: -1,
        proposer: make_addr(proposer_idx),
        sig: SigBytes(vec![]),
    };

    let actions = sm.handle(Event::ReceiveProposal(proposal), &blocks);
    let prevote = actions
        .iter()
        .find_map(|a| match a {
            Action::Broadcast(ProposalOrVote::Vote(v)) if v.kind == VoteKind::Prevote => Some(v),
            _ => None,
        })
        .expect("with the block registered, proposal must emit a prevote");
    assert_eq!(prevote.block_hash, Some(block_hash));
}

#[test]
fn pending_proposal_replays_when_block_arrives() {
    // Pin the liveness fix that pairs with the unknown-block gate:
    // a proposal received BEFORE the matching block frame must be stashed
    // and re-driven once `register_block` supplies the body, via
    // `try_resume_pending_proposal`. Without this, the 4-validator smoke
    // test had a single trailing validator that fell behind at height ~3
    // because:
    //   1. proposer broadcasts Frame::BlockResponse(block) (empty commit)
    //      followed by Frame::Proposal(p)
    //   2. on a slow peer, the proposal frame is processed BEFORE the
    //      block frame is registered
    //   3. the unknown-block gate stashed the proposal silently and the
    //      validator stalled — nil-prevote on each subsequent round
    //      until the test timed out.
    let height = 1u64;
    let proposer_idx = 1u8;

    let block = make_block(height, proposer_idx);
    let block_hash = block.header.block_hash();

    // Step 1: proposal arrives FIRST, blocks map empty → gate stashes.
    let mut blocks: BTreeMap<Hash32, Block> = BTreeMap::new();
    let mut sm = ConsensusState::new(height, make_addr(0), make_validator_set_fake(4, 100));
    let proposal = Proposal {
        height,
        round: 0,
        block_hash,
        pol_round: -1,
        proposer: make_addr(proposer_idx),
        sig: SigBytes(vec![]),
    };
    let initial = sm.handle(Event::ReceiveProposal(proposal.clone()), &blocks);
    let initial_prevotes: Vec<_> = initial
        .iter()
        .filter_map(|a| match a {
            Action::Broadcast(ProposalOrVote::Vote(v)) if v.kind == VoteKind::Prevote => Some(v),
            _ => None,
        })
        .collect();
    assert!(
        initial_prevotes.is_empty(),
        "gate must stash when block unknown"
    );
    assert!(
        sm.pending_proposal.is_some(),
        "pending_proposal must hold the stashed proposal"
    );

    // Step 2: block arrives, register it, then resume.
    blocks.insert(block_hash, block.clone());
    let resumed = sm.try_resume_pending_proposal(&blocks);
    let prevote = resumed
        .iter()
        .find_map(|a| match a {
            Action::Broadcast(ProposalOrVote::Vote(v)) if v.kind == VoteKind::Prevote => Some(v),
            _ => None,
        })
        .expect("resume must emit the previously-stashed prevote");
    assert_eq!(prevote.block_hash, Some(block_hash));
    assert!(
        sm.pending_proposal.is_none(),
        "pending_proposal must clear after successful resume"
    );
}

#[test]
fn pending_proposal_resume_rechecks_buffered_prevote_quorum() {
    // Reordered TCP can deliver Proposal first, then prevotes for that
    // proposal, and only later the BlockResponse. While the proposal is
    // stashed the machine is still in Propose, so receiving those prevotes
    // records the tally but does not run the current-round quorum branch.
    // Resuming the proposal must therefore re-check that buffered tally and
    // precommit immediately instead of waiting for the prevote timeout.
    let height = 1u64;
    let proposer_idx = 1u8;

    let block = make_block(height, proposer_idx);
    let block_hash = block.header.block_hash();
    let mut blocks: BTreeMap<Hash32, Block> = BTreeMap::new();
    let mut sm = ConsensusState::new(height, make_addr(0), make_validator_set_fake(4, 100));
    let proposal = Proposal {
        height,
        round: 0,
        block_hash,
        pol_round: -1,
        proposer: make_addr(proposer_idx),
        sig: SigBytes(vec![]),
    };

    let initial = sm.handle(Event::ReceiveProposal(proposal), &blocks);
    assert!(
        initial.is_empty(),
        "unknown block proposal should be stashed"
    );
    assert_eq!(sm.step, Step::Propose);

    for validator in [1u8, 2, 3] {
        let vote = Vote {
            height,
            round: 0,
            kind: VoteKind::Prevote,
            block_hash: Some(block_hash),
            validator: make_addr(validator),
            sig: SigBytes(vec![]),
        };
        let actions = sm.handle(Event::ReceiveVote(vote), &blocks);
        assert!(
            actions.is_empty(),
            "prevotes received before proposal resume should only be tallied"
        );
    }
    assert_eq!(sm.step, Step::Propose);

    blocks.insert(block_hash, block);
    let resumed = sm.try_resume_pending_proposal(&blocks);
    let prevote = resumed.iter().find_map(|a| match a {
        Action::Broadcast(ProposalOrVote::Vote(v)) if v.kind == VoteKind::Prevote => Some(v),
        _ => None,
    });
    let precommit = resumed.iter().find_map(|a| match a {
        Action::Broadcast(ProposalOrVote::Vote(v)) if v.kind == VoteKind::Precommit => Some(v),
        _ => None,
    });

    assert_eq!(
        prevote.and_then(|v| v.block_hash),
        Some(block_hash),
        "resume must still broadcast this validator's prevote"
    );
    assert_eq!(
        precommit.and_then(|v| v.block_hash),
        Some(block_hash),
        "resume must immediately precommit the buffered prevote quorum"
    );
    assert_eq!(sm.step, Step::Precommit);
    assert_eq!(sm.locked_block, Some((0, block_hash)));
    assert_eq!(sm.valid_block, Some((0, block_hash)));
}

#[test]
fn try_resume_is_noop_when_block_still_missing() {
    // Defensive: try_resume is called on every BlockResponse — many of
    // those will be for unrelated heights/blocks. It must be a true
    // no-op when the pending proposal's block is not yet registered.
    let height = 1u64;
    let proposer_idx = 1u8;

    let block = make_block(height, proposer_idx);
    let block_hash = block.header.block_hash();
    let other_block = make_block(2, 2);
    let other_hash = other_block.header.block_hash();

    let mut sm = ConsensusState::new(height, make_addr(0), make_validator_set_fake(4, 100));
    let proposal = Proposal {
        height,
        round: 0,
        block_hash,
        pol_round: -1,
        proposer: make_addr(proposer_idx),
        sig: SigBytes(vec![]),
    };
    let _ = sm.handle(Event::ReceiveProposal(proposal), &BTreeMap::new());
    assert!(sm.pending_proposal.is_some());

    // Register an unrelated block — try_resume must NOT emit a prevote.
    let mut blocks: BTreeMap<Hash32, Block> = BTreeMap::new();
    blocks.insert(other_hash, other_block);
    let actions = sm.try_resume_pending_proposal(&blocks);
    assert!(
        actions.is_empty(),
        "unrelated block must not satisfy the pending proposal"
    );
    assert!(
        sm.pending_proposal.is_some(),
        "pending_proposal must remain stashed"
    );
}
