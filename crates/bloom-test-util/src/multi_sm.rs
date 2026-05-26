//! In-memory multi-validator mailbox helper for state-machine tests.
//!
//! Replaces the hand-rolled `Vec<ConsensusState>` + action-routing loops
//! in `happy_path.rs` and `locking.rs`. Tests drive one `ConsensusState`
//! per validator address, then [`MultiValidatorMailbox::broadcast`] each
//! emitted Vote/Proposal back into every state machine and collect the
//! resulting actions.
//!
//! No async, no real time — pure synchronous routing intended for
//! deterministic spec-conformance tests.

use std::collections::BTreeMap;

use bloom_chain_consensus::{
    state_machine::{Action, ConsensusState, Event, ProposalOrVote, TimeoutKind},
    validator_set::ValidatorSet,
};
use bloom_chain_types::{
    block::Block,
    types::{Address, Hash32},
    vote::{Proposal, Vote},
};

/// Multi-validator harness: one `ConsensusState` per address, a shared
/// block store, and helpers for routing events to all instances.
pub struct MultiValidatorMailbox {
    /// State machines indexed by their owner address.
    pub sms: Vec<ConsensusState>,
    /// Block store shared by every validator (mutating tests can
    /// `blocks.insert(...)` to add a body).
    pub blocks: BTreeMap<Hash32, Block>,
}

impl MultiValidatorMailbox {
    /// Build a mailbox with `n` validators, each starting at `height` with
    /// the same `ValidatorSet`. `addrs` supplies the owner address for
    /// each instance (typically `make_addr(i)` for `i in 0..n`).
    pub fn new(height: u64, addrs: &[Address], vset: ValidatorSet) -> Self {
        let sms: Vec<ConsensusState> = addrs
            .iter()
            .map(|addr| ConsensusState::new(height, *addr, vset.clone()))
            .collect();
        Self {
            sms,
            blocks: BTreeMap::new(),
        }
    }

    /// Insert a known block body into the shared block store.
    pub fn insert_block(&mut self, hash: Hash32, block: Block) {
        self.blocks.insert(hash, block);
    }

    /// Deliver a `Proposal` to every state machine, collecting all
    /// emitted actions in order.
    pub fn broadcast_proposal(&mut self, proposal: Proposal) -> Vec<Action> {
        let mut out = Vec::new();
        for sm in self.sms.iter_mut() {
            out.extend(sm.handle(Event::ReceiveProposal(proposal.clone()), &self.blocks));
        }
        out
    }

    /// Deliver a `Vote` to every state machine, collecting all emitted
    /// actions in order.
    pub fn broadcast_vote(&mut self, vote: Vote) -> Vec<Action> {
        let mut out = Vec::new();
        for sm in self.sms.iter_mut() {
            out.extend(sm.handle(Event::ReceiveVote(vote.clone()), &self.blocks));
        }
        out
    }

    /// Deliver a `Tick` of the given kind to every state machine.
    pub fn broadcast_tick(&mut self, kind: TimeoutKind) -> Vec<Action> {
        let mut out = Vec::new();
        for sm in self.sms.iter_mut() {
            out.extend(sm.handle(Event::Tick(kind), &self.blocks));
        }
        out
    }

    /// Filter `actions` down to just the prevotes (handy for asserting
    /// every validator prevoted the same block).
    pub fn prevotes_in(actions: Vec<Action>) -> Vec<Vote> {
        use bloom_chain_types::vote::VoteKind;
        actions
            .into_iter()
            .filter_map(|a| match a {
                Action::Broadcast(ProposalOrVote::Vote(v)) if v.kind == VoteKind::Prevote => {
                    Some(v)
                }
                _ => None,
            })
            .collect()
    }

    /// Filter `actions` down to just the precommits.
    pub fn precommits_in(actions: Vec<Action>) -> Vec<Vote> {
        use bloom_chain_types::vote::VoteKind;
        actions
            .into_iter()
            .filter_map(|a| match a {
                Action::Broadcast(ProposalOrVote::Vote(v)) if v.kind == VoteKind::Precommit => {
                    Some(v)
                }
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::{make_addr, make_validator_set_fake};

    #[test]
    fn new_mailbox_creates_n_state_machines() {
        let vset = make_validator_set_fake(4, 100);
        let addrs: Vec<Address> = (0u8..4).map(make_addr).collect();
        let mb = MultiValidatorMailbox::new(1, &addrs, vset);
        assert_eq!(mb.sms.len(), 4);
        assert!(mb.blocks.is_empty());
    }

    #[test]
    fn insert_block_grows_block_store() {
        let vset = make_validator_set_fake(4, 100);
        let addrs: Vec<Address> = (0u8..4).map(make_addr).collect();
        let mut mb = MultiValidatorMailbox::new(1, &addrs, vset);
        let hash = Hash32([0xAB; 32]);
        let block = crate::blocks::BlockBuilder::at(1).build();
        mb.insert_block(hash, block);
        assert!(mb.blocks.contains_key(&hash));
    }
}
