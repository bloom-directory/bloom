use bloom_chain_consensus::{
    Validator, ValidatorSet,
    round_validation::{RoundError, judge_proposer_round},
};
use bloom_chain_types::types::{Address, PubKeyBytes};

fn validator_set(n: u8) -> ValidatorSet {
    ValidatorSet::new(
        (0..n)
            .map(|idx| Validator {
                address: Address([idx; 32]),
                pubkey: PubKeyBytes(vec![idx]),
                voting_power: 1,
            })
            .collect(),
    )
    .expect("validator set")
}

#[test]
fn reproposed_block_uses_pol_round_for_header() {
    let validators = validator_set(4);
    let proposer = validators.proposer_for(10, 5).address;

    let judgment = judge_proposer_round(10, proposer, 5, 2, &validators, false).unwrap();

    assert!(judgment.proposer_ok);
    assert_eq!(judgment.header_round, 2);
}

#[test]
fn pol_round_ge_proposal_round_is_rejected() {
    let validators = validator_set(4);
    let proposer = validators.proposer_for(10, 5).address;

    let err = judge_proposer_round(10, proposer, 5, 5, &validators, false).unwrap_err();

    assert_eq!(
        err,
        RoundError::InvalidPolRound {
            proposal_round: 5,
            pol_round: 5
        }
    );
}

#[test]
fn apply_window_accepts_proposer_from_any_round_up_to_commit_round() {
    let validators = validator_set(4);
    let proposer = validators.proposer_for(10, 1).address;

    let judgment = judge_proposer_round(10, proposer, 3, -1, &validators, true).unwrap();

    assert!(judgment.proposer_ok);
    assert_eq!(judgment.header_round, 3);
}

#[test]
fn proposal_path_requires_exact_round_proposer() {
    let validators = validator_set(4);
    let wrong_round_proposer = validators.proposer_for(10, 1).address;

    let judgment =
        judge_proposer_round(10, wrong_round_proposer, 2, -1, &validators, false).unwrap();

    assert!(!judgment.proposer_ok);
    assert_eq!(judgment.header_round, 2);
}
