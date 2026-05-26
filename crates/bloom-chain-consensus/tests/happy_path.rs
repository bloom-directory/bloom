//! Category: integration
//!
//! Happy-path test: 4 validators drive one height to commit.
//!
//! Validator 0 proposes at (h=1, r=0) — index = (1+0)%4 = 1, so actually
//! validator 1 is the proposer.  We drive all 4 instances through propose →
//! prevote → precommit → commit and assert they all reach the same block hash.

use bloom_chain_consensus::state_machine::Action;
use bloom_chain_types::{types::SigBytes, vote::Proposal};
use bloom_test_util::{BlockBuilder, MultiValidatorMailbox, make_addr, make_validator_set_fake};

#[test]
fn four_validators_reach_same_commit() {
    let height = 1u64;

    // Proposer for (height=1, round=0) is index (1+0)%4 = 1 → addr(1).
    let proposer_idx = 1u8;

    // Build the canonical block.
    let block = BlockBuilder::at(height)
        .proposer(make_addr(proposer_idx))
        .build();
    let block_hash = block.header.block_hash();

    // Instantiate 4 state machines via the mailbox helper.
    let vset = make_validator_set_fake(4, 100);
    let addrs: Vec<_> = (0u8..4).map(make_addr).collect();
    let mut mb = MultiValidatorMailbox::new(height, &addrs, vset);
    mb.insert_block(block_hash, block);

    // --- Step 1: Proposer (validator 1) proposes ---
    let proposal = Proposal {
        height,
        round: 0,
        block_hash,
        pol_round: -1,
        proposer: make_addr(proposer_idx),
        sig: SigBytes(vec![]),
    };

    let actions = mb.broadcast_proposal(proposal);
    let all_prevotes = MultiValidatorMailbox::prevotes_in(actions);

    // All 4 should have prevoted the block hash.
    assert_eq!(all_prevotes.len(), 4, "all 4 should have prevoted");
    assert!(
        all_prevotes
            .iter()
            .all(|v| v.block_hash == Some(block_hash)),
        "all prevotes should be for the proposed block"
    );

    // --- Step 2: Deliver all prevotes to all 4 SMs ---
    let mut all_precommits = Vec::new();
    for vote in all_prevotes.iter() {
        let actions = mb.broadcast_vote(vote.clone());
        for v in MultiValidatorMailbox::precommits_in(actions) {
            if v.block_hash == Some(block_hash) {
                all_precommits.push(v);
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
        let actions = mb.broadcast_vote(vote.clone());
        for action in actions {
            if let Action::Commit(committed_block, commit) = action {
                commit_count += 1;
                committed_hashes.insert(committed_block.header.block_hash());
                assert_eq!(commit.block_hash, block_hash);
                assert_eq!(commit.height, height);
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
