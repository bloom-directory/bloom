//! Validator set for bloom-chain v0 (spec §9.1).
//!
//! The validator set is fixed at genesis; rotation is v1+.
//!
//! # Validator-set hash
//!
//! `validator_set_hash = blake3("bloom-chain.v0.validator_set:" || ssz_encode(validators))`
//!
//! The domain tag is defined locally because `bloom-chain-types::digest::tags` does not
//! include `validator_set:` (it is not needed by the types crate itself).

use bloom_chain_types::{
    digest::blake3_tagged,
    types::{Address, Hash32, PubKeyBytes},
};
use ssz::Encode;

use crate::error::ConsensusError;

/// Local domain tag for the validator-set hash (not in bloom-chain-types::digest::tags
/// because that crate does not need it; defined here per spec §9.1).
const TAG_VALIDATOR_SET: &str = "bloom-chain.v0.validator_set:";

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

/// A single validator entry (spec §9.1).
#[derive(Clone, Debug)]
pub struct Validator {
    pub address: Address,
    pub pubkey: PubKeyBytes,
    pub voting_power: u64,
}

// ---------------------------------------------------------------------------
// ValidatorSet
// ---------------------------------------------------------------------------

/// An ordered, deterministic set of validators (spec §9.1).
///
/// The ordering is insertion order and must be consistent across all nodes
/// (i.e. derived from genesis deterministically).
#[derive(Clone, Debug)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    total_power: u64,
}

impl ValidatorSet {
    /// Construct a `ValidatorSet` from an ordered list of validators.
    ///
    /// # Errors
    /// - Empty set.
    /// - Any validator has `voting_power == 0`.
    /// - Duplicate `address` values.
    pub fn new(validators: Vec<Validator>) -> Result<Self, ConsensusError> {
        if validators.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let mut seen = std::collections::HashSet::new();
        let mut total_power: u64 = 0;

        for v in &validators {
            if v.voting_power == 0 {
                return Err(ConsensusError::ZeroVotingPower);
            }
            if !seen.insert(v.address) {
                return Err(ConsensusError::DuplicateAddress(v.address.to_string()));
            }
            total_power = total_power
                .checked_add(v.voting_power)
                .expect("total voting power overflowed u64 — unrealistic in v0");
        }

        Ok(Self {
            validators,
            total_power,
        })
    }

    /// The BFT quorum threshold: `2 * total_power / 3 + 1` (spec §9.1).
    pub fn quorum(&self) -> u64 {
        2 * self.total_power / 3 + 1
    }

    /// Round-robin proposer for `(height, round)`: index = `(height + round as u64) % n`
    /// (spec §9.2).
    pub fn proposer_for(&self, height: u64, round: u32) -> &Validator {
        let n = self.validators.len() as u64;
        let idx = (height.wrapping_add(round as u64)) % n;
        &self.validators[idx as usize]
    }

    /// BLAKE3-based hash committing to the full ordered validator set.
    ///
    /// Uses a local domain tag (not in bloom-chain-types) as documented in the
    /// module-level doc comment.
    pub fn validator_set_hash(&self) -> Hash32 {
        // Encode each validator as: address(32) || pubkey_len(4 LE) || pubkey || power(8 LE).
        let mut buf = Vec::new();
        for v in &self.validators {
            buf.extend_from_slice(&v.address.as_ssz_bytes());
            let pk = v.pubkey.as_ssz_bytes();
            let pk_len = pk.len() as u32;
            buf.extend_from_slice(&pk_len.to_le_bytes());
            buf.extend_from_slice(&pk);
            buf.extend_from_slice(&v.voting_power.to_le_bytes());
        }
        blake3_tagged(TAG_VALIDATOR_SET, &buf)
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Returns `true` if the set is empty (cannot happen after `new`, but useful for completeness).
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Total voting power.
    pub fn total_power(&self) -> u64 {
        self.total_power
    }

    /// Borrow the ordered validator slice.
    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    /// Look up a validator by address; returns `None` if not found.
    pub fn get_by_address(&self, addr: &Address) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.address == addr)
    }

    /// Return the voting power for a given address, or 0 if unknown.
    pub fn voting_power_of(&self, addr: &Address) -> u64 {
        self.get_by_address(addr)
            .map(|v| v.voting_power)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(seed: u8, power: u64) -> Validator {
        Validator {
            address: Address([seed; 32]),
            pubkey: PubKeyBytes(vec![seed; 4]),
            voting_power: power,
        }
    }

    #[test]
    fn quorum_four_equal_validators() {
        // 4 validators × 100 = 400 total; 2*400/3+1 = 267
        let vs = ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
            make_validator(3, 100),
            make_validator(4, 100),
        ])
        .unwrap();
        assert_eq!(vs.quorum(), 267);
    }

    #[test]
    fn proposer_round_robin() {
        let vs = ValidatorSet::new(vec![
            make_validator(0, 1),
            make_validator(1, 1),
            make_validator(2, 1),
            make_validator(3, 1),
        ])
        .unwrap();
        // height=0, round=0 → idx=0
        assert_eq!(vs.proposer_for(0, 0).address, Address([0; 32]));
        // height=0, round=1 → idx=1
        assert_eq!(vs.proposer_for(0, 1).address, Address([1; 32]));
        // height=1, round=0 → idx=1
        assert_eq!(vs.proposer_for(1, 0).address, Address([1; 32]));
        // height=3, round=1 → (3+1)%4=0
        assert_eq!(vs.proposer_for(3, 1).address, Address([0; 32]));
    }

    #[test]
    fn rejects_empty() {
        assert!(ValidatorSet::new(vec![]).is_err());
    }

    #[test]
    fn rejects_zero_power() {
        assert!(ValidatorSet::new(vec![make_validator(1, 0)]).is_err());
    }

    #[test]
    fn rejects_duplicate_address() {
        let result = ValidatorSet::new(vec![make_validator(1, 10), make_validator(1, 10)]);
        assert!(result.is_err());
    }

    #[test]
    fn validator_set_hash_is_deterministic() {
        let vs = ValidatorSet::new(vec![make_validator(1, 100), make_validator(2, 100)]).unwrap();
        assert_eq!(vs.validator_set_hash(), vs.validator_set_hash());
    }

    #[test]
    fn validator_set_hash_differs_on_different_sets() {
        let vs1 = ValidatorSet::new(vec![make_validator(1, 100)]).unwrap();
        let vs2 = ValidatorSet::new(vec![make_validator(2, 100)]).unwrap();
        assert_ne!(vs1.validator_set_hash(), vs2.validator_set_hash());
    }
}
