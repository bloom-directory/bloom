//! Happy-path test: 4 validators drive one height to commit.
//!
//! Validator 0 proposes at (h=1, r=0) — index = (1+0)%4 = 1, so actually
//! validator 1 is the proposer.  We drive all 4 instances through propose →
//! prevote → precommit → commit and assert they all reach the same block hash.

use std::collections::BTreeMap;

use bloom_chain_consensus::{
    state_machine::{Action, ConsensusState, Event, ProposalOrVote},
    validator_set::{Validator, ValidatorSet},
};
use bloom_chain_types::{
    block::{Block, BlockHeader},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
    vote::{Commit, Proposal, Vote, VoteKind},
};

fn make_addr(seed: u8) -> Address {
    Address([seed; 32])
}

fn make_validator_set() -> ValidatorSet {
    ValidatorSet::new(
        (0u8..4)
            .map(|i| Validator {
                address: make_addr(i),
                pubkey: PubKeyBytes(vec![i; 4]),
                voting_power: 100,
            })
            .collect(),
    )
    .unwrap()
}

fn make_block(height: u64, proposer: u8) -> Block {
    let header = BlockHeader {
        chain_id: "bloomchain.v0".to_string(),
        height,
        parent_hash: Hash32([0; 32]),
        timestamp_ms: 1_747_526_400_000 + height * 1_000,
        proposer: make_addr(proposer),
        txs_root: Hash32([0xAA; 32]),
        state_root: Hash32([0xBB; 32]),
        receipts_root: Hash32([0xCC; 32]),
        validator_set_hash: Hash32([0xDD; 32]),
        fuel_used: 0,
        fuel_limit: 30_000_000,
    };
    Block {
        header,
        txs: vec![],
        commit: Commit {
            height: height.saturating_sub(1),
            round: 0,
            block_hash: Hash32([0; 32]),
            votes: vec![],
        },
    }
}

#[test]
fn four_validators_reach_same_commit() {
    let height = 1u64;

    // Proposer for (height=1, round=0) is index (1+0)%4 = 1 → addr(1).
    let proposer_idx = 1u8;

    // Build the canonical block.
    let block = make_block(height, proposer_idx);
    let block_hash = block.header.block_hash();

    // Build block store shared across all state machines (read-only in tests).
    let mut blocks: BTreeMap<Hash32, Block> = BTreeMap::new();
    blocks.insert(block_hash, block.clone());

    // Instantiate 4 state machines.
    let mut sms: Vec<ConsensusState> = (0u8..4)
        .map(|i| ConsensusState::new(height, make_addr(i), make_validator_set()))
        .collect();

    // --- Step 1: Proposer (validator 1) proposes ---
    let proposal = Proposal {
        height,
        round: 0,
        block_hash,
        pol_round: -1,
        proposer: make_addr(proposer_idx),
        sig: SigBytes(vec![]),
    };

    // Deliver proposal to all 4.
    let mut all_prevotes: Vec<Vote> = Vec::new();
    for sm in sms.iter_mut() {
        let actions = sm.handle(Event::ReceiveProposal(proposal.clone()), &blocks);
        for action in actions {
            if let Action::Broadcast(ProposalOrVote::Vote(v)) = action
                && v.kind == VoteKind::Prevote
            {
                all_prevotes.push(v);
            }
        }
    }

    // All 4 should have prevoted the block hash.
    assert_eq!(all_prevotes.len(), 4, "all 4 should have prevoted");
    assert!(
        all_prevotes.iter().all(|v| v.block_hash == Some(block_hash)),
        "all prevotes should be for the proposed block"
    );

    // --- Step 2: Deliver all prevotes to all 4 SMs ---
    let mut all_precommits: Vec<Vote> = Vec::new();
    for vote in all_prevotes.iter() {
        for sm in sms.iter_mut() {
            let actions = sm.handle(Event::ReceiveVote(vote.clone()), &blocks);
            for action in actions {
                if let Action::Broadcast(ProposalOrVote::Vote(v)) = action
                    && v.kind == VoteKind::Precommit
                    && v.block_hash == Some(block_hash)
                {
                    all_precommits.push(v);
                }
            }
        }
    }

    // After receiving 3 prevotes (2f+1 = 267 out of 400 total, need at least 3 × 100 = 300 ≥ 267),
    // each SM should emit a precommit.  Dedup by validator.
    let mut seen_precommitters = std::collections::HashSet::new();
    let unique_precommits: Vec<_> = all_precommits
        .into_iter()
        .filter(|v| seen_precommitters.insert(v.validator))
        .collect();
    assert_eq!(unique_precommits.len(), 4, "all 4 should have precommitted");

    // --- Step 3: Deliver all precommits to all 4 SMs ---
    let mut commit_count = 0usize;
    let mut committed_hashes = std::collections::HashSet::new();
    for vote in unique_precommits.iter() {
        for sm in sms.iter_mut() {
            let actions = sm.handle(Event::ReceiveVote(vote.clone()), &blocks);
            for action in actions {
                if let Action::Commit(committed_block, commit) = action {
                    commit_count += 1;
                    committed_hashes.insert(committed_block.header.block_hash());
                    assert_eq!(commit.block_hash, block_hash);
                    assert_eq!(commit.height, height);
                }

            }
        }
    }

    // All 4 SMs should have committed the same block.
    assert_eq!(commit_count, 4, "all 4 validators should commit");
    assert_eq!(
        committed_hashes.len(),
        1,
        "all 4 validators committed the same block hash"
    );
    assert!(
        committed_hashes.contains(&block_hash),
        "committed the expected block"
    );
}
