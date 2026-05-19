//! Authentication boundary for inbound consensus messages.
//!
//! Every Vote or Proposal that enters [`crate::state_machine::ConsensusState`]
//! MUST first pass [`verify_vote_sig`] / [`verify_proposal_sig`]. Unverified
//! messages are an attack surface — a peer can otherwise forge votes from any
//! validator, manipulating quorum totals and finalising blocks they never
//! signed.
//!
//! These helpers are part of the single, narrow validation boundary
//! established by the 2026-05-19 consensus hardening review (docs/reviews/).
//!
//! The actual cryptographic check is delegated to a [`SigVerifier`]
//! implementation — `bloom-chain-node`'s `XdsaVerifier` is the production one.

use bloom_chain_types::vote::{Proposal, Vote};

use crate::{validator_set::ValidatorSet, verifier::SigVerifier};

/// Verify a [`Vote`]'s signature against the pubkey of `vote.validator` in
/// `validator_set`.
///
/// Returns `false` if:
/// - The voter is not in the validator set.
/// - The signature does not verify against the canonical signing digest
///   ([`Vote::signing_digest`]).
///
/// Successful return guarantees the message was produced by the holder of the
/// validator's xDSA secret key.
pub fn verify_vote_sig<V: SigVerifier>(
    vote: &Vote,
    validator_set: &ValidatorSet,
    verifier: &V,
) -> bool {
    let Some(v) = validator_set.get_by_address(&vote.validator) else {
        return false;
    };
    let digest = vote.signing_digest();
    verifier.verify(&v.pubkey, &digest.0, &vote.sig)
}

/// Verify a [`Proposal`]'s signature against the pubkey of `proposal.proposer`
/// in `validator_set`.
///
/// Returns `false` if the proposer is not in the validator set or the
/// signature does not verify.
pub fn verify_proposal_sig<V: SigVerifier>(
    proposal: &Proposal,
    validator_set: &ValidatorSet,
    verifier: &V,
) -> bool {
    let Some(v) = validator_set.get_by_address(&proposal.proposer) else {
        return false;
    };
    let digest = proposal.signing_digest();
    verifier.verify(&v.pubkey, &digest.0, &proposal.sig)
}
