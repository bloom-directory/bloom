//! Round-robin proposer rotation tests.

use bloom_chain_consensus::validator_set::{Validator, ValidatorSet};
use bloom_chain_types::types::{Address, PubKeyBytes};

fn make_vs(n: u8) -> ValidatorSet {
    ValidatorSet::new(
        (0..n)
            .map(|i| Validator {
                address: Address([i; 32]),
                pubkey: PubKeyBytes(vec![i; 4]),
                voting_power: 100,
            })
            .collect(),
    )
    .unwrap()
}

#[test]
fn proposer_formula_matches_spec() {
    // proposer_for(height, round) = validators[(height + round as u64) % n]
    let vs = make_vs(4);
    let n = 4u64;

    for height in 0u64..8 {
        for round in 0u32..4 {
            let expected_idx = (height + round as u64) % n;
            let expected_addr = Address([expected_idx as u8; 32]);
            let proposer = vs.proposer_for(height, round);
            assert_eq!(
                proposer.address,
                expected_addr,
                "proposer_for({height}, {round}) = idx {expected_idx}"
            );
        }
    }
}

#[test]
fn round_robin_cycles_through_all_validators() {
    let vs = make_vs(4);
    let height = 5u64;
    // As round advances 0,1,2,3 we cycle through all validators.
    let seen: Vec<Address> = (0u32..4).map(|r| vs.proposer_for(height, r).address).collect();
    // (5+0)%4=1, (5+1)%4=2, (5+2)%4=3, (5+3)%4=0
    assert_eq!(seen[0], Address([1; 32]));
    assert_eq!(seen[1], Address([2; 32]));
    assert_eq!(seen[2], Address([3; 32]));
    assert_eq!(seen[3], Address([0; 32]));
}

#[test]
fn single_validator_always_proposes() {
    let vs = make_vs(1);
    let expected = Address([0; 32]);
    for height in 0u64..5 {
        for round in 0u32..5 {
            assert_eq!(vs.proposer_for(height, round).address, expected);
        }
    }
}

#[test]
fn round_robin_is_deterministic_across_calls() {
    let vs = make_vs(4);
    // Calling proposer_for twice with the same args must return the same validator.
    for height in [0u64, 7, 100] {
        for round in [0u32, 1, 3] {
            let p1 = vs.proposer_for(height, round);
            let p2 = vs.proposer_for(height, round);
            assert_eq!(p1.address, p2.address);
        }
    }
}

#[test]
fn height_advances_rotation() {
    let vs = make_vs(4);
    // At round=0, proposer rotates with height: idx = height % 4.
    for height in 0u64..8 {
        let expected_idx = height % 4;
        let expected_addr = Address([expected_idx as u8; 32]);
        assert_eq!(vs.proposer_for(height, 0).address, expected_addr);
    }
}
