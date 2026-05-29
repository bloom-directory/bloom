//! Tendermint-style BFT state machine (spec §9.2, §9.3).
//!
//! This module is a pure state-transition function — it receives `Event`s and
//! produces `Action`s. No I/O, no async, no side effects.
//!
//! # Locking rules (Buchman 2016 ch. 3)
//! If a validator precommits for `(h, r, hash)` it locks on that block.  It
//! must prevote the locked hash at subsequent rounds unless 2f+1 prevotes for
//! a different block at a higher round unlock it.
//!
//! # Round advancement
//! - **Propose timeout**: broadcast nil-prevote, advance step to Prevote.
//! - **Prevote timeout** (no 2f+1 for any single hash): broadcast nil-precommit,
//!   advance step to Precommit.
//! - **Precommit timeout** (no 2f+1 for any single hash): advance round,
//!   reset to Propose step with next proposer.

use std::collections::BTreeMap;
use std::time::Duration;

use bloom_chain_types::{
    block::Block,
    types::Hash32,
    vote::{Commit, Proposal, Vote, VoteKind},
};

use crate::{round_validation::judge_proposer_round, validator_set::ValidatorSet};

// ---------------------------------------------------------------------------
// Step
// ---------------------------------------------------------------------------

/// The current step within a height/round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

// ---------------------------------------------------------------------------
// TimeoutKind
// ---------------------------------------------------------------------------

/// Identifies which timeout a `Tick` event is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutKind {
    Propose,
    Prevote,
    Precommit,
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

/// An external event delivered to the state machine.
#[derive(Debug)]
pub enum Event {
    /// A timeout has fired.
    Tick(TimeoutKind),
    /// A proposal was received from the network (or self).
    ReceiveProposal(Proposal),
    /// A vote (prevote or precommit) was received.
    ReceiveVote(Vote),
}

// ---------------------------------------------------------------------------
// ProposalOrVote
// ---------------------------------------------------------------------------

/// What to broadcast: either a full proposal or a single vote.
#[derive(Debug, Clone)]
pub enum ProposalOrVote {
    Proposal(Proposal),
    Vote(Vote),
}

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/// An output action produced by the state machine.
#[derive(Debug)]
pub enum Action {
    /// Broadcast a message to all peers (and deliver to self).
    Broadcast(ProposalOrVote),
    /// The block at this height is final.  Persist it and advance height.
    Commit(Box<Block>, Commit),
    /// Schedule a timeout.
    StartTimeout(TimeoutKind, Duration),
}

// ---------------------------------------------------------------------------
// VoteTally
// ---------------------------------------------------------------------------

/// Aggregates votes for a single (height, round, kind) bucket.
///
/// Tracks per-block-hash accumulated voting power and detects 2f+1 events.
#[derive(Clone, Debug, Default)]
pub struct VoteTally {
    /// block_hash → accumulated voting_power of validators that voted for it.
    /// `None` key means nil-vote.
    per_hash: BTreeMap<Option<Hash32>, u64>,
    /// First vote recorded for each validator in this slot.
    votes: std::collections::HashMap<bloom_chain_types::types::Address, Option<Hash32>>,
    /// Validators that emitted conflicting votes in this slot.
    equivocators: std::collections::HashSet<bloom_chain_types::types::Address>,
}

impl VoteTally {
    /// Record a vote.  Returns the cumulative voting power for the voted hash
    /// after adding this vote. Duplicate identical votes are ignored. A
    /// conflicting duplicate is tracked as equivocation evidence while first
    /// vote wins for voting-power accounting.
    pub fn record(
        &mut self,
        validator: bloom_chain_types::types::Address,
        power: u64,
        hash: Option<Hash32>,
    ) -> u64 {
        if let Some(first_hash) = self.votes.get(&validator).copied() {
            if first_hash != hash {
                self.equivocators.insert(validator);
            }
            return self.per_hash.get(&hash).copied().unwrap_or(0);
        }
        self.votes.insert(validator, hash);
        let entry = self.per_hash.entry(hash).or_insert(0);
        *entry += power;
        *entry
    }

    /// Return the accumulated power for a specific block hash (or nil).
    pub fn power_for(&self, hash: Option<Hash32>) -> u64 {
        self.per_hash.get(&hash).copied().unwrap_or(0)
    }

    /// Return the block hash (if any) that has accumulated >= `quorum` power.
    /// Returns `None` if no single hash has reached quorum yet.
    pub fn quorum_hash(&self, quorum: u64) -> Option<Option<Hash32>> {
        for (hash, &power) in &self.per_hash {
            if power >= quorum {
                return Some(*hash);
            }
        }
        None
    }

    /// Returns `true` if any hash (including nil) has reached quorum.
    pub fn has_quorum(&self, quorum: u64) -> bool {
        self.quorum_hash(quorum).is_some()
    }

    /// Total power recorded so far across all hashes.
    pub fn total_power(&self) -> u64 {
        self.per_hash.values().sum()
    }

    /// Validators that emitted conflicting votes for this height/round/kind.
    pub fn equivocators(&self) -> impl Iterator<Item = bloom_chain_types::types::Address> + '_ {
        self.equivocators.iter().copied()
    }
}

// ---------------------------------------------------------------------------
// ConsensusState
// ---------------------------------------------------------------------------

/// Default per-round timeout for propose, prevote, and precommit steps.
///
/// Proposal construction validates and executes the candidate block before the
/// proposal is broadcast. Real PETAL PTBs can take materially longer than a
/// sub-second local-network timeout on shared CI runners, so keep enough budget
/// for block execution before peers nil-prevote the round.
pub const ROUND_TIMEOUT: Duration = Duration::from_secs(5);

/// The Tendermint-style BFT state machine for a single local validator.
///
/// One `ConsensusState` per validator per node.  Multiple instances can be
/// driven synchronously in tests.
pub struct ConsensusState {
    /// Current block height (1-based; genesis block is height 0, first consensus height is 1).
    pub height: u64,
    /// Current round within this height (0-based).
    pub round: u32,
    /// Current step within this round.
    pub step: Step,

    /// Buchman locking: `Some((round, hash))` if this validator has precommitted
    /// for a block in this height.
    pub locked_block: Option<(u32, Hash32)>,
    /// Best known polka: `Some((round, hash))` if 2f+1 prevotes seen for a block
    /// at that round.
    pub valid_block: Option<(u32, Hash32)>,

    /// The proposal received for the current round, if any.
    pub proposal: Option<Proposal>,

    /// A proposal that was received but whose block body is not yet present
    /// in the engine's `blocks` map. Stored so the node can re-attempt
    /// prevoting once `BlockResponse` (or any other source) supplies the
    /// missing body. Cleared on round/height transitions and on successful
    /// dispatch.
    ///
    /// Without this cache, the unknown-block proposal gate at [`on_proposal`]
    /// silently drops the proposal — if the proposer's initial block
    /// broadcast was received out-of-order with the proposal frame, the
    /// validator stalls until the next round, even though the block arrived
    /// moments later.
    pub pending_proposal: Option<Proposal>,

    /// Prevote tallies: round → VoteTally.
    pub prevotes: BTreeMap<u32, VoteTally>,
    /// Precommit tallies: round → VoteTally.
    pub precommits: BTreeMap<u32, VoteTally>,

    /// The full set of votes received (for building the Commit).
    all_precommit_votes: BTreeMap<u32, Vec<Vote>>,

    /// The local validator's address.
    local_address: bloom_chain_types::types::Address,

    /// Reference to the validator set (shared read-only).
    validator_set: ValidatorSet,

    /// The committed block for the current height (set when Commit action fires).
    pub committed_block: Option<Block>,
}

impl ConsensusState {
    /// Construct a new state machine at the given height, starting at round 0 / Propose.
    pub fn new(
        height: u64,
        local_address: bloom_chain_types::types::Address,
        validator_set: ValidatorSet,
    ) -> Self {
        Self {
            height,
            round: 0,
            step: Step::Propose,
            locked_block: None,
            valid_block: None,
            proposal: None,
            pending_proposal: None,
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            all_precommit_votes: BTreeMap::new(),
            local_address,
            validator_set,
            committed_block: None,
        }
    }

    /// Is this validator the proposer for the current `(height, round)`?
    pub fn is_proposer(&self) -> bool {
        self.validator_set
            .proposer_for(self.height, self.round)
            .address
            == self.local_address
    }

    /// Reset the state machine to begin consensus at `new_height`, round 0,
    /// step Propose.  Returns a single `StartTimeout(Propose, ROUND_TIMEOUT)` action
    /// so the caller can drive the new round.
    ///
    /// All per-height state (locked/valid block, proposal, votes, committed
    /// block) is cleared.  The validator set is preserved.
    pub fn enter_next_height(&mut self, new_height: u64) -> Vec<Action> {
        self.height = new_height;
        self.round = 0;
        self.step = Step::Propose;
        self.locked_block = None;
        self.valid_block = None;
        self.proposal = None;
        self.pending_proposal = None;
        self.prevotes.clear();
        self.precommits.clear();
        self.all_precommit_votes.clear();
        self.committed_block = None;
        vec![Action::StartTimeout(TimeoutKind::Propose, ROUND_TIMEOUT)]
    }

    /// If a proposal was previously stashed because its block was unknown,
    /// and the block is now in `blocks`, re-run `on_proposal` against it.
    /// Returns any actions emitted by the resumed handler — typically a
    /// prevote broadcast and a Prevote timeout. If current-round prevotes
    /// reached quorum while the proposal was stashed, this also emits the
    /// immediate precommit transition that `on_vote` could not run while
    /// the state machine was still in `Propose`.
    ///
    /// Called by the node after a `Frame::BlockResponse` registers a new
    /// block. Without this, a validator that received a proposal frame
    /// before the matching block frame would silently drop the proposal
    /// and stall its consensus round.
    pub fn try_resume_pending_proposal(&mut self, blocks: &BTreeMap<Hash32, Block>) -> Vec<Action> {
        let Some(p) = self.pending_proposal.as_ref() else {
            return vec![];
        };
        // Stale across height/round/step transitions — drop.
        if p.height != self.height || p.round != self.round || self.step != Step::Propose {
            self.pending_proposal = None;
            return vec![];
        }
        if !blocks.contains_key(&p.block_hash) {
            return vec![];
        }
        let p = self.pending_proposal.take().unwrap();
        let mut actions = self.on_proposal(p, blocks);
        actions.extend(self.try_precommit_current_round_from_prevotes(blocks));
        actions
    }

    /// Re-check precommit tallies for a freshly-registered block hash. If any
    /// round at the current height has already reached 2f+1 precommits for
    /// `hash` while we lacked the block body, emit the deferred `Commit`
    /// action now.
    ///
    /// Without this, a validator that received the precommit quorum before
    /// the matching block body (TCP reordering, restart, slow peer) records
    /// the quorum in its tally but never emits `Action::Commit` — the
    /// quorum-check in `on_vote` only fires on receipt of each individual
    /// precommit, and `try_resume_pending_proposal` only replays the prevote
    /// path. Called by the node after every `register_block`.
    pub fn try_commit_with_block(
        &mut self,
        hash: Hash32,
        blocks: &BTreeMap<Hash32, Block>,
    ) -> Vec<Action> {
        if self.step == Step::Commit {
            return vec![];
        }
        let Some(block) = blocks.get(&hash) else {
            return vec![];
        };
        let quorum = self.validator_set.quorum();
        let matching_round = self.precommits.iter().find_map(|(round, tally)| {
            matches!(tally.quorum_hash(quorum), Some(Some(qh)) if qh == hash).then_some(*round)
        });
        let Some(round) = matching_round else {
            return vec![];
        };
        self.step = Step::Commit;
        let commit_votes: Vec<Vote> = self
            .all_precommit_votes
            .get(&round)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|v| v.block_hash == Some(hash))
            .collect();
        let commit = Commit {
            height: self.height,
            round,
            block_hash: hash,
            votes: commit_votes,
        };
        self.committed_block = Some(block.clone());
        vec![Action::Commit(Box::new(block.clone()), commit)]
    }

    // ---------------------------------------------------------------------------
    // Main event handler
    // ---------------------------------------------------------------------------

    /// Process one event, returning a list of actions to perform.
    pub fn handle(&mut self, event: Event, blocks: &BTreeMap<Hash32, Block>) -> Vec<Action> {
        match event {
            Event::Tick(kind) => self.on_tick(kind, blocks),
            Event::ReceiveProposal(p) => self.on_proposal(p, blocks),
            Event::ReceiveVote(v) => self.on_vote(v, blocks),
        }
    }

    // ---------------------------------------------------------------------------
    // Tick handler
    // ---------------------------------------------------------------------------

    fn on_tick(&mut self, kind: TimeoutKind, blocks: &BTreeMap<Hash32, Block>) -> Vec<Action> {
        match kind {
            TimeoutKind::Propose => {
                // Propose timeout: if we're still in Propose step, broadcast nil-prevote.
                if self.step != Step::Propose {
                    return vec![];
                }
                self.step = Step::Prevote;
                let actions = vec![
                    Action::Broadcast(ProposalOrVote::Vote(self.make_prevote(None))),
                    Action::StartTimeout(TimeoutKind::Prevote, ROUND_TIMEOUT),
                ];
                actions
            }
            TimeoutKind::Prevote => {
                // Prevote timeout: no 2f+1 for any hash → nil-precommit.
                if self.step != Step::Prevote {
                    return vec![];
                }
                self.step = Step::Precommit;
                let actions = vec![
                    Action::Broadcast(ProposalOrVote::Vote(self.make_precommit(None))),
                    Action::StartTimeout(TimeoutKind::Precommit, ROUND_TIMEOUT),
                ];
                actions
            }
            TimeoutKind::Precommit => {
                // Precommit timeout: no 2f+1 → advance round.
                if self.step != Step::Precommit {
                    return vec![];
                }
                self.advance_round(blocks)
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Proposal handler
    // ---------------------------------------------------------------------------

    fn on_proposal(&mut self, p: Proposal, blocks: &BTreeMap<Hash32, Block>) -> Vec<Action> {
        if p.height != self.height || p.round != self.round {
            return vec![];
        }
        if self.step != Step::Propose {
            return vec![];
        }
        let Ok(judgment) = judge_proposer_round(
            self.height,
            p.proposer,
            self.round,
            p.pol_round,
            &self.validator_set,
            false,
        ) else {
            return vec![];
        };
        if !judgment.proposer_ok {
            return vec![];
        }
        // Refuse to prevote a block we have not yet seen. Stash the proposal
        // so the node can replay it once `BlockResponse` (or any other
        // source) registers the missing body — see
        // [`try_resume_pending_proposal`]. Prevoting on an unknown hash
        // makes us attest to a body we have not validated — exactly the
        // surface the 2026-05-19 review flagged at state_machine.rs:307.
        if !blocks.contains_key(&p.block_hash) {
            self.pending_proposal = Some(p);
            return vec![];
        }
        // Block is here — clear any stale pending entry for this round.
        self.pending_proposal = None;

        self.proposal = Some(p.clone());
        self.step = Step::Prevote;

        // Determine what to prevote:
        // - If locked on a different block and no polka-round override: prevote locked.
        // - If locked on the proposed block: prevote it.
        // - If not locked: prevote the proposal (we trust the proposer has a valid block).
        let prevote_hash = self.choose_prevote_hash(p.block_hash, p.pol_round);
        let prevote = self.make_prevote(prevote_hash);

        vec![
            Action::Broadcast(ProposalOrVote::Vote(prevote)),
            Action::StartTimeout(TimeoutKind::Prevote, ROUND_TIMEOUT),
        ]
    }

    /// Choose what hash to prevote given the proposed block hash and pol_round.
    fn choose_prevote_hash(&self, proposed: Hash32, pol_round: i32) -> Option<Hash32> {
        if let Some((locked_round, locked_hash)) = self.locked_block {
            // We're locked.
            if locked_hash == proposed {
                // Prevote the proposed block (same as what we're locked on).
                return Some(proposed);
            }
            // Locked on a different block.
            // Unlock condition: 2f+1 prevotes for the proposed block at a higher round
            // (pol_round > locked_round and pol_round is valid).
            if pol_round >= 0 {
                let pol_round_u = pol_round as u32;
                if pol_round_u > locked_round {
                    let quorum = self.validator_set.quorum();
                    let tally = self.prevotes.get(&pol_round_u);
                    let polka_power = tally.map(|t| t.power_for(Some(proposed))).unwrap_or(0);
                    if polka_power >= quorum {
                        // Unlocked — prevote the new proposal.
                        return Some(proposed);
                    }
                }
            }
            // Stay locked.
            Some(locked_hash)
        } else {
            // Not locked — prevote the proposal.
            Some(proposed)
        }
    }

    // ---------------------------------------------------------------------------
    // Vote handler
    // ---------------------------------------------------------------------------

    fn on_vote(&mut self, v: Vote, blocks: &BTreeMap<Hash32, Block>) -> Vec<Action> {
        if v.height != self.height {
            return vec![];
        }

        let power = self.validator_set.voting_power_of(&v.validator);
        if power == 0 {
            // Unknown validator — ignore.
            return vec![];
        }

        let quorum = self.validator_set.quorum();
        let mut actions = Vec::new();

        match v.kind {
            VoteKind::Prevote => {
                self.prevotes
                    .entry(v.round)
                    .or_default()
                    .record(v.validator, power, v.block_hash);

                // Check for 2f+1 prevotes for a non-nil hash in the current round.
                if v.round == self.round && self.step == Step::Prevote {
                    actions.extend(self.try_precommit_current_round_from_prevotes(blocks));
                }

                // For past rounds: if 2f+1 prevotes arrive late and we haven't advanced yet,
                // update valid_block for the proposer's benefit in the next round.
                if v.round < self.round
                    && let Some(Some(hash)) = self
                        .prevotes
                        .get(&v.round)
                        .and_then(|t| t.quorum_hash(quorum))
                    && blocks.contains_key(&hash)
                    && self.valid_block.map(|(r, _)| r < v.round).unwrap_or(true)
                {
                    self.valid_block = Some((v.round, hash));
                }
            }
            VoteKind::Precommit => {
                // Store the first precommit observed from each validator for
                // later Commit construction. VoteTally ignores duplicate
                // validators for power accounting; the Commit bytes must carry
                // the same de-duplicated validator set or strict apply-time
                // validation will reject blocks built from gossiped duplicates.
                let round_votes = self.all_precommit_votes.entry(v.round).or_default();
                if round_votes
                    .iter()
                    .all(|existing| existing.validator != v.validator)
                {
                    round_votes.push(v.clone());
                }

                let tally = self.precommits.entry(v.round).or_default();
                tally.record(v.validator, power, v.block_hash);

                // Check for 2f+1 precommits for a concrete hash.
                if let Some(Some(hash)) = tally.quorum_hash(quorum)
                    && self.step != Step::Commit
                    && let Some(block) = blocks.get(&hash)
                {
                    self.step = Step::Commit;
                    let commit_votes: Vec<Vote> = self
                        .all_precommit_votes
                        .get(&v.round)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|vote| vote.block_hash == Some(hash))
                        .collect();
                    let commit = Commit {
                        height: self.height,
                        round: v.round,
                        block_hash: hash,
                        votes: commit_votes,
                    };
                    self.committed_block = Some(block.clone());
                    actions.push(Action::Commit(Box::new(block.clone()), commit));
                }
            }
        }

        actions
    }

    fn try_precommit_current_round_from_prevotes(
        &mut self,
        blocks: &BTreeMap<Hash32, Block>,
    ) -> Vec<Action> {
        if self.step != Step::Prevote {
            return vec![];
        }
        let quorum = self.validator_set.quorum();
        let quorum_hash = self
            .prevotes
            .get(&self.round)
            .and_then(|tally| tally.quorum_hash(quorum));

        match quorum_hash {
            Some(Some(hash)) => {
                if !blocks.contains_key(&hash) {
                    return vec![];
                }
                // 2f+1 prevotes for a concrete block — update valid_block
                // and precommit for it.
                self.valid_block = Some((self.round, hash));
                self.step = Step::Precommit;
                let precommit = self.make_precommit(Some(hash));
                // Lock on this block.
                self.locked_block = Some((self.round, hash));
                vec![
                    Action::Broadcast(ProposalOrVote::Vote(precommit)),
                    Action::StartTimeout(TimeoutKind::Precommit, ROUND_TIMEOUT),
                ]
            }
            Some(None) => {
                // 2f+1 nil-prevotes — unlock and nil-precommit.
                self.locked_block = None;
                self.step = Step::Precommit;
                let precommit = self.make_precommit(None);
                vec![
                    Action::Broadcast(ProposalOrVote::Vote(precommit)),
                    Action::StartTimeout(TimeoutKind::Precommit, ROUND_TIMEOUT),
                ]
            }
            None => vec![],
        }
    }

    // ---------------------------------------------------------------------------
    // Round advancement
    // ---------------------------------------------------------------------------

    fn advance_round(&mut self, _blocks: &BTreeMap<Hash32, Block>) -> Vec<Action> {
        self.round += 1;
        self.step = Step::Propose;
        self.proposal = None;

        let actions = vec![Action::StartTimeout(TimeoutKind::Propose, ROUND_TIMEOUT)];

        // If this validator is the new proposer, they need to build and broadcast.
        // The engine layer handles building; here we just signal a propose timeout
        // starts.  If this validator is the proposer, engine will inject a proposal.
        actions
    }

    // ---------------------------------------------------------------------------
    // Vote constructors (unsigned stubs — the engine fills in the real sig)
    // ---------------------------------------------------------------------------

    fn make_prevote(&self, hash: Option<Hash32>) -> Vote {
        Vote {
            height: self.height,
            round: self.round,
            kind: VoteKind::Prevote,
            block_hash: hash,
            validator: self.local_address,
            sig: bloom_chain_types::types::SigBytes(vec![]),
        }
    }

    fn make_precommit(&self, hash: Option<Hash32>) -> Vote {
        Vote {
            height: self.height,
            round: self.round,
            kind: VoteKind::Precommit,
            block_hash: hash,
            validator: self.local_address,
            sig: bloom_chain_types::types::SigBytes(vec![]),
        }
    }

    // ---------------------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------------------

    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_chain_types::{
        block::{Block, BlockHeader},
        types::{Address, Hash32, PubKeyBytes, SigBytes},
        vote::{Commit, Proposal},
    };

    use crate::validator_set::ValidatorSet;

    fn make_addr(seed: u8) -> Address {
        Address([seed; 32])
    }

    fn make_validator_set() -> ValidatorSet {
        ValidatorSet::new(vec![
            crate::validator_set::Validator {
                address: make_addr(0),
                pubkey: PubKeyBytes(vec![0; 4]),
                voting_power: 100,
            },
            crate::validator_set::Validator {
                address: make_addr(1),
                pubkey: PubKeyBytes(vec![1; 4]),
                voting_power: 100,
            },
            crate::validator_set::Validator {
                address: make_addr(2),
                pubkey: PubKeyBytes(vec![2; 4]),
                voting_power: 100,
            },
            crate::validator_set::Validator {
                address: make_addr(3),
                pubkey: PubKeyBytes(vec![3; 4]),
                voting_power: 100,
            },
        ])
        .unwrap()
    }

    fn make_block(hash_seed: u8) -> (Hash32, Block) {
        let header = BlockHeader {
            chain_id: "bloomchain.v0".to_string(),
            height: 1,
            parent_hash: Hash32([0; 32]),
            timestamp_ms: 1_747_526_400_000,
            proposer: make_addr(0),
            txs_root: Hash32([hash_seed; 32]),
            state_root: Hash32([hash_seed; 32]),
            receipts_root: Hash32([hash_seed; 32]),
            validator_set_hash: Hash32([hash_seed; 32]),
            fuel_used: 0,
            fuel_limit: 30_000_000,
        };
        let hash = header.block_hash();
        let block = Block {
            header,
            txs: vec![],
            commit: Commit {
                height: 0,
                round: 0,
                block_hash: Hash32([0; 32]),
                votes: vec![],
            },
        };
        (hash, block)
    }

    #[test]
    fn propose_timeout_emits_nil_prevote() {
        let vs = make_validator_set();
        let mut sm = ConsensusState::new(1, make_addr(1), vs);
        let blocks = BTreeMap::new();
        let actions = sm.handle(Event::Tick(TimeoutKind::Propose), &blocks);
        assert!(actions.iter().any(
            |a| matches!(a, Action::Broadcast(ProposalOrVote::Vote(v)) if v.block_hash.is_none())
        ));
    }

    #[test]
    fn receive_proposal_emits_prevote() {
        // validator 1 is proposer for height=1, round=0 (idx=(1+0)%4=1).
        // We run from addr(2)'s perspective to test proposal receipt.
        let mut sm = ConsensusState::new(1, make_addr(2), make_validator_set());
        let (hash, block) = make_block(0xAA);
        let mut blocks = BTreeMap::new();
        blocks.insert(hash, block);

        let proposal = Proposal {
            height: 1,
            round: 0,
            block_hash: hash,
            pol_round: -1,
            proposer: make_addr(1), // proposer for (height=1, round=0)
            sig: SigBytes(vec![]),
        };

        let actions = sm.handle(Event::ReceiveProposal(proposal), &blocks);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Broadcast(ProposalOrVote::Vote(v)) if v.block_hash == Some(hash))));
    }

    #[test]
    fn receive_proposal_rejects_current_or_future_pol_round() {
        let mut sm = ConsensusState::new(1, make_addr(3), make_validator_set());
        sm.round = 1;
        let (hash, block) = make_block(0xAB);
        let mut blocks = BTreeMap::new();
        blocks.insert(hash, block);

        let proposal = Proposal {
            height: 1,
            round: 1,
            block_hash: hash,
            pol_round: 1,
            proposer: make_addr(2), // proposer for (height=1, round=1)
            sig: SigBytes(vec![]),
        };

        let actions = sm.handle(Event::ReceiveProposal(proposal), &blocks);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::Broadcast(ProposalOrVote::Vote(_)))),
            "invalid pol_round proposal must not be prevoted"
        );
    }

    #[test]
    fn vote_tally_quorum_detection() {
        let mut tally = VoteTally::default();
        let hash = Some(Hash32([0xBB; 32]));
        tally.record(make_addr(0), 100, hash);
        tally.record(make_addr(1), 100, hash);
        // 200 < 267 (quorum for 4 × 100)
        assert!(!tally.has_quorum(267));
        tally.record(make_addr(2), 100, hash);
        // 300 >= 267
        assert!(tally.has_quorum(267));
    }

    #[test]
    fn vote_tally_tracks_equivocation_without_double_counting() {
        let mut tally = VoteTally::default();
        let h1 = Some(Hash32([0xAA; 32]));
        let h2 = Some(Hash32([0xBB; 32]));
        tally.record(make_addr(0), 100, h1);
        tally.record(make_addr(0), 100, h2);

        assert_eq!(tally.power_for(h1), 100);
        assert_eq!(tally.power_for(h2), 0);
        assert_eq!(tally.total_power(), 100);
        assert_eq!(tally.equivocators().collect::<Vec<_>>(), vec![make_addr(0)]);
    }

    #[test]
    fn commit_votes_are_deduplicated_by_validator() {
        let mut sm = ConsensusState::new(1, make_addr(0), make_validator_set());
        let (hash, block) = make_block(0xCC);
        let mut blocks = BTreeMap::new();
        blocks.insert(hash, block);

        let vote = |seed| Vote {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(hash),
            validator: make_addr(seed),
            sig: SigBytes(vec![seed]),
        };

        assert!(sm.handle(Event::ReceiveVote(vote(0)), &blocks).is_empty());
        assert!(sm.handle(Event::ReceiveVote(vote(0)), &blocks).is_empty());
        assert!(sm.handle(Event::ReceiveVote(vote(1)), &blocks).is_empty());
        let actions = sm.handle(Event::ReceiveVote(vote(2)), &blocks);

        let commit = actions
            .iter()
            .find_map(|action| match action {
                Action::Commit(_, commit) => Some(commit),
                _ => None,
            })
            .expect("third unique precommit reaches quorum");
        assert_eq!(commit.votes.len(), 3);
        assert_eq!(commit.votes[0].validator, make_addr(0));
        assert_eq!(commit.votes[1].validator, make_addr(1));
        assert_eq!(commit.votes[2].validator, make_addr(2));
    }

    #[test]
    fn late_round_zero_polka_records_valid_block() {
        let mut sm = ConsensusState::new(1, make_addr(0), make_validator_set());
        sm.round = 1;
        sm.step = Step::Propose;
        let (hash, block) = make_block(0xDD);
        let mut blocks = BTreeMap::new();
        blocks.insert(hash, block);
        let vote = |seed| Vote {
            height: 1,
            round: 0,
            kind: VoteKind::Prevote,
            block_hash: Some(hash),
            validator: make_addr(seed),
            sig: SigBytes(vec![seed]),
        };

        assert!(sm.handle(Event::ReceiveVote(vote(0)), &blocks).is_empty());
        assert!(sm.handle(Event::ReceiveVote(vote(1)), &blocks).is_empty());
        assert!(sm.handle(Event::ReceiveVote(vote(2)), &blocks).is_empty());

        assert_eq!(sm.valid_block, Some((0, hash)));
    }

    #[test]
    fn prevote_quorum_for_unknown_hash_does_not_precommit() {
        let mut sm = ConsensusState::new(1, make_addr(0), make_validator_set());
        sm.step = Step::Prevote;
        let hash = Hash32([0xEE; 32]);
        let blocks = BTreeMap::new();
        let vote = |seed| Vote {
            height: 1,
            round: 0,
            kind: VoteKind::Prevote,
            block_hash: Some(hash),
            validator: make_addr(seed),
            sig: SigBytes(vec![seed]),
        };

        assert!(sm.handle(Event::ReceiveVote(vote(0)), &blocks).is_empty());
        assert!(sm.handle(Event::ReceiveVote(vote(1)), &blocks).is_empty());
        let actions = sm.handle(Event::ReceiveVote(vote(2)), &blocks);

        assert!(
            actions.iter().all(|action| {
                !matches!(
                    action,
                    Action::Broadcast(ProposalOrVote::Vote(v))
                        if v.kind == VoteKind::Precommit && v.block_hash == Some(hash)
                )
            }),
            "must not precommit a block hash whose body has not been registered"
        );
        assert_eq!(sm.step, Step::Prevote);
        assert_eq!(sm.locked_block, None);
        assert_eq!(sm.valid_block, None);
    }

    #[test]
    fn late_polka_for_unknown_hash_does_not_become_valid_block() {
        let mut sm = ConsensusState::new(1, make_addr(0), make_validator_set());
        sm.round = 1;
        sm.step = Step::Propose;
        let hash = Hash32([0xEF; 32]);
        let blocks = BTreeMap::new();
        let vote = |seed| Vote {
            height: 1,
            round: 0,
            kind: VoteKind::Prevote,
            block_hash: Some(hash),
            validator: make_addr(seed),
            sig: SigBytes(vec![seed]),
        };

        assert!(sm.handle(Event::ReceiveVote(vote(0)), &blocks).is_empty());
        assert!(sm.handle(Event::ReceiveVote(vote(1)), &blocks).is_empty());
        assert!(sm.handle(Event::ReceiveVote(vote(2)), &blocks).is_empty());

        assert_eq!(sm.valid_block, None);
    }
}
