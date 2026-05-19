//! Locking test: Buchman locking under proposer change (spec §9.3).
//!
//! Scenario:
//! - Height 1, round 0. Validator 1 proposes block A. Validators 0,1,2 prevote A
//!   and precommit A. Validator 3 is offline (misses everything).
//! - Round advances to r=1 (via precommit timeout, since v3 is offline and
//!   only 3 validators means 3×100=300 ≥ 267 quorum — actually this DOES commit!
//!
//! So we adjust: use 5 validators with votes split:
//!   - Total power = 500, quorum = 334.
//!   - Validators 0,1,2 prevote A and precommit A → 300 power, NOT enough (< 334).
//!   - Validator 3 and 4 are offline.
//!   - Round increments to r=1 (proposer 2 = (1+1)%5=2). Validator 2 proposes B.
//!   - Validators 0,1,2 are locked on A — they MUST prevote A, not B.
//!
//! We assert no validator prevotes B at round 1.

use std::collections::BTreeMap;

use bloom_chain_consensus::{
    state_machine::{Action, ConsensusState, Event, ProposalOrVote, TimeoutKind},
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

fn five_validator_set() -> ValidatorSet {
    ValidatorSet::new(
        (0u8..5)
            .map(|i| Validator {
                address: make_addr(i),
                pubkey: PubKeyBytes(vec![i; 4]),
                voting_power: 100,
            })
            .collect(),
    )
    .unwrap()
}

fn make_block_with_root(height: u64, proposer: u8, root_seed: u8) -> Block {
    let header = BlockHeader {
        chain_id: "bloomchain.v0".to_string(),
        height,
        parent_hash: Hash32([0; 32]),
        timestamp_ms: 1_747_526_400_000 + height * 1_000,
        proposer: make_addr(proposer),
        txs_root: Hash32([root_seed; 32]),
        state_root: Hash32([root_seed; 32]),
        receipts_root: Hash32([root_seed; 32]),
        validator_set_hash: Hash32([root_seed; 32]),
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
fn locked_validators_do_not_prevote_different_block() {
    let height = 1u64;
    // 5-validator set. total=500, quorum=334.
    // Proposer for (h=1, r=0): idx=(1+0)%5=1 → addr(1).
    // Proposer for (h=1, r=1): idx=(1+1)%5=2 → addr(2).

    let block_a = make_block_with_root(height, 1, 0xAA);
    let hash_a = block_a.header.block_hash();
    let block_b = make_block_with_root(height, 2, 0xBB);
    let hash_b = block_b.header.block_hash();

    let mut blocks: BTreeMap<Hash32, Block> = BTreeMap::new();
    blocks.insert(hash_a, block_a.clone());
    blocks.insert(hash_b, block_b.clone());

    // Instantiate 3 online validators (0, 1, 2); 3 and 4 are offline.
    let mut sms: Vec<ConsensusState> = (0u8..3)
        .map(|i| ConsensusState::new(height, make_addr(i), five_validator_set()))
        .collect();

    // --- Round 0: validator 1 proposes block A ---
    let proposal_a = Proposal {
        height,
        round: 0,
        block_hash: hash_a,
        pol_round: -1,
        proposer: make_addr(1),
        sig: SigBytes(vec![]),
    };

    let mut r0_prevotes: Vec<Vote> = Vec::new();
    for sm in sms.iter_mut() {
        let actions = sm.handle(Event::ReceiveProposal(proposal_a.clone()), &blocks);
        for action in actions {
            if let Action::Broadcast(ProposalOrVote::Vote(v)) = action
                && v.kind == VoteKind::Prevote
            {
                r0_prevotes.push(v);
            }
        }
    }

    // Deliver prevotes → validators should precommit A (if they hit 2f+1, but 3×100=300 < 334).
    // With 5 validators and 3 online, 2f+1 = 334, so 300 < 334.
    // They will NOT automatically precommit — prevote timeout fires instead.
    // But we need to manually lock them by having them "precommit" explicitly for the locking test.
    // To lock: simulate that each of 0,1,2 sees 2f+1 prevotes (we need to fake enough votes).
    // Actually, with only 300 power, none will precommit automatically.
    // The test instead uses the locked state set via seeing 300 prevotes then manually
    // triggering precommit via prevote timeout (nil-precommit) — but that doesn't lock.
    //
    // The correct test for locking: validators need to precommit A (they lock when they precommit).
    // To get them to precommit A with only 300 power (< 334 quorum), we can:
    //   - Use 4 validators with total=400, quorum=267, and have 3 of 4 online.
    //   - 3×100=300 ≥ 267 → they precommit A and lock.
    //   - But 300 still doesn't reach 334 (5-validator quorum) for final commit, only for 4-validator quorum.
    //
    // Let's restructure: use 4 validators (quorum=267). Validators 0,1,2 precommit A (300≥267).
    // Then round advances to r=1 because validator 3 (offline) means we never get 2f+1 precommits
    // for commit (we need 267, and we have 300 which IS enough to commit).
    //
    // The issue: 3/4 = 300 ≥ 267 → they DO commit. So locking scenario requires 4 validators
    // where 3 precommit A but the precommit never finalises (e.g. validator 3's nil-precommit
    // appears before 3 get their precommits heard).
    //
    // Simplest correct approach: use 4 validators. Simulate that 3 validators lock on A
    // by having them see 3 prevotes for A (≥ quorum) and then precommit A.
    // Validator 3 sends a nil-prevote. 3 precommits A but validator 3 nil-precommits.
    // Now we have 3 precommits for A (300) + 1 nil-precommit (100) = 400 total seen.
    // 300 ≥ 267 → commit fires! That's the happy path again.
    //
    // The only way to avoid immediate commit is to not reach 2f+1 precommits for any hash.
    // With 4 validators and 3 online: 300 ≥ 267. They always commit if they all precommit A.
    //
    // Real locking scenario: n=7, f=2. quorum=5. 4 of 7 prevote A, 4 precommit A (4≥5? no).
    // 4 < 5 so no commit. Round 1: proposer proposes B. The 4 locked on A must prevote A.
    // Actually: 5 of 7 need to prevote to hit quorum. Let's use n=7.
    //
    // For simplicity in this test, we manually set the locked state and verify the prevote
    // choice logic directly, without going through the full quorum mechanic.

    // Re-create with 4 validators but simulate locking by sending enough prevotes from
    // "fake" validators (the SM doesn't verify signatures — it just counts power).
    // Validator set: 4 validators each with power 100. quorum=267.
    // We inject 3 prevotes (power=300≥267) for A → SM precommits A and locks.
    // Validator 3 sends nil-prevote → total prevote power = 400 but A only gets 300.
    // Since A hit quorum, each SM commits... unless we don't deliver the 4th precommit.
    //
    // To prevent commit: we need < 267 precommit power for A.
    // If 2 of 4 precommit A (200 < 267) and 2 nil-precommit (200), no commit, round advances.

    // Let's do it properly: 4 validators, 2 precommit A (locked), 2 nil-precommit.
    // But: a SM won't precommit A unless it sees 2f+1 prevotes for A.
    // If only 2 prevote A, power=200 < 267 → SM prevote-timeouts → nil-precommit → not locked.
    //
    // So: 3 prevote A (power=300≥267) → each SM precommits A and locks.
    //     But only 2 of the 4 SMs receive all 3 prevotes (the other 2 miss them).
    //     → 2 validators lock, 2 don't.
    //     → We deliver 2 precommits for A (200<267) + 2 nil-precommits (200) → no commit.
    //     → Round advances to r=1.
    //     → At r=1 proposer proposes B. The 2 locked validators must prevote A, not B.
    //
    // This is the scenario we'll test.

    // Reset: use a fresh 4-validator setup.
    drop(sms);
    let vs4 = ValidatorSet::new(
        (0u8..4)
            .map(|i| Validator {
                address: make_addr(i),
                pubkey: PubKeyBytes(vec![i; 4]),
                voting_power: 100,
            })
            .collect(),
    )
    .unwrap();
    // quorum = 267

    let block_a = make_block_with_root(height, 1, 0xAA);
    let hash_a = block_a.header.block_hash();
    let block_b = make_block_with_root(height, 2, 0xBB); // proposer for (1,1) is idx (1+1)%4=2
    let hash_b = block_b.header.block_hash();

    let mut blocks: BTreeMap<Hash32, Block> = BTreeMap::new();
    blocks.insert(hash_a, block_a.clone());
    blocks.insert(hash_b, block_b.clone());

    // Validators 0 and 1 will lock on A; validators 2 and 3 will not.
    let mut sm0 = ConsensusState::new(height, make_addr(0), vs4.clone());
    let mut sm1 = ConsensusState::new(height, make_addr(1), vs4.clone());
    // sm2 and sm3 will get only nil-prevotes, so they won't lock.
    let mut sm2 = ConsensusState::new(height, make_addr(2), vs4.clone());
    let mut sm3 = ConsensusState::new(height, make_addr(3), vs4.clone());

    // Round 0: proposal A from validator 1 (proposer for h=1,r=0 is idx (1+0)%4=1).
    let proposal_a = Proposal {
        height,
        round: 0,
        block_hash: hash_a,
        pol_round: -1,
        proposer: make_addr(1),
        sig: SigBytes(vec![]),
    };

    // Deliver proposal to sm0 and sm1 only.
    let _ = sm0.handle(Event::ReceiveProposal(proposal_a.clone()), &blocks);
    let _ = sm1.handle(Event::ReceiveProposal(proposal_a.clone()), &blocks);

    // Fabricate 3 prevotes for A from validators 0, 1, 2.
    let prevote_a = |validator_seed: u8| Vote {
        height,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(hash_a),
        validator: make_addr(validator_seed),
        sig: SigBytes(vec![]),
    };

    // Deliver 3 prevotes for A to sm0 and sm1 — they'll see quorum and precommit A.
    for seed in [0u8, 1, 2] {
        let _ = sm0.handle(Event::ReceiveVote(prevote_a(seed)), &blocks);
        let _ = sm1.handle(Event::ReceiveVote(prevote_a(seed)), &blocks);
    }

    // Verify sm0 and sm1 are now locked on A.
    assert_eq!(
        sm0.locked_block.map(|(_, h)| h),
        Some(hash_a),
        "sm0 should be locked on A"
    );
    assert_eq!(
        sm1.locked_block.map(|(_, h)| h),
        Some(hash_a),
        "sm1 should be locked on A"
    );

    // sm2 and sm3 only see nil-prevotes → no lock.
    // Manually advance their round to r=1 via precommit timeout.
    let _ = sm2.handle(Event::Tick(TimeoutKind::Propose), &blocks);
    let _ = sm2.handle(Event::Tick(TimeoutKind::Prevote), &blocks);
    let _ = sm2.handle(Event::Tick(TimeoutKind::Precommit), &blocks);
    let _ = sm3.handle(Event::Tick(TimeoutKind::Propose), &blocks);
    let _ = sm3.handle(Event::Tick(TimeoutKind::Prevote), &blocks);
    let _ = sm3.handle(Event::Tick(TimeoutKind::Precommit), &blocks);

    // Advance sm0 and sm1 to r=1 as well (precommit timeout since only 2 precommit A).
    let _ = sm0.handle(Event::Tick(TimeoutKind::Precommit), &blocks);
    let _ = sm1.handle(Event::Tick(TimeoutKind::Precommit), &blocks);

    // Now all four SMs should be at round=1.
    assert_eq!(sm0.round, 1, "sm0 should be at round 1");
    assert_eq!(sm1.round, 1, "sm1 should be at round 1");

    // Round 1: validator 2 proposes block B. (proposer idx=(1+1)%4=2).
    let proposal_b = Proposal {
        height,
        round: 1,
        block_hash: hash_b,
        pol_round: -1,
        proposer: make_addr(2),
        sig: SigBytes(vec![]),
    };

    // Deliver proposal B to sm0 and sm1 (locked on A).
    let mut prevotes_from_locked: Vec<Vote> = Vec::new();
    for sm in [&mut sm0, &mut sm1] {
        let actions = sm.handle(Event::ReceiveProposal(proposal_b.clone()), &blocks);
        for action in actions {
            if let Action::Broadcast(ProposalOrVote::Vote(v)) = action
                && v.kind == VoteKind::Prevote
            {
                prevotes_from_locked.push(v);
            }
        }
    }

    // sm0 and sm1 are locked on A — they must NOT prevote B.
    for vote in &prevotes_from_locked {
        assert_ne!(
            vote.block_hash,
            Some(hash_b),
            "validator {:?} is locked on A and must not prevote B at round 1",
            vote.validator
        );
        assert_eq!(
            vote.block_hash,
            Some(hash_a),
            "validator {:?} should prevote the locked hash A",
            vote.validator
        );
    }
}
