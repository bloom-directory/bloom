use bloom_chain_types::types::Address;
use thiserror::Error;

use crate::validator_set::ValidatorSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundJudgment {
    pub proposer_ok: bool,
    pub header_round: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RoundError {
    #[error("pol_round {pol_round} must be less than proposal_round {proposal_round}")]
    InvalidPolRound { proposal_round: u32, pol_round: i32 },
}

/// Judge the proposer schedule and resolve the block-header round.
///
/// `proposal_round` is the exact proposal/header round for normal proposal
/// paths. For committed-block apply validation, pass the commit round and set
/// `apply_window=true` to accept a header proposer from any bounded prior
/// round that could have produced the committed block body.
pub fn judge_proposer_round(
    height: u64,
    header_proposer: Address,
    proposal_round: u32,
    pol_round: i32,
    validator_set: &ValidatorSet,
    apply_window: bool,
) -> Result<RoundJudgment, RoundError> {
    let header_round = if pol_round >= 0 {
        let pol_round_u = pol_round as u32;
        if pol_round_u >= proposal_round {
            return Err(RoundError::InvalidPolRound {
                proposal_round,
                pol_round,
            });
        }
        pol_round_u
    } else {
        proposal_round
    };

    let proposer_ok = if apply_window {
        let proposer_round_window = bounded_round_window(validator_set.len(), proposal_round);
        (0..proposer_round_window).any(|round| {
            validator_set.proposer_for(height, round as u32).address == header_proposer
        })
    } else {
        validator_set.proposer_for(height, proposal_round).address == header_proposer
    };

    Ok(RoundJudgment {
        proposer_ok,
        header_round,
    })
}

pub fn bounded_round_window(validator_count: usize, proposal_round: u32) -> usize {
    usize::try_from(proposal_round)
        .ok()
        .and_then(|round| round.checked_add(1))
        .map_or(validator_count, |round_count| {
            validator_count.min(round_count)
        })
}
