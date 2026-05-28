//! Top-level async consensus engine.
//!
//! `ConsensusEngine` wires together `ValidatorSet`, `Mempool`, and
//! `ConsensusState`.  It does not do networking or persistence — those
//! live in `bloom-chain-node`.  It produces `Action`s; someone else delivers them.

use std::collections::BTreeMap;
use std::sync::Arc;

use bloom_chain_types::{
    block::Block,
    tx::Tx,
    types::{Address, Hash32},
    vote::Proposal,
};

use crate::{
    error::ConsensusError,
    mempool::Mempool,
    signer::Signer,
    state_machine::{Action, ConsensusState, Event, ProposalOrVote, Step},
    tx_admission::BalanceView,
    validator_set::ValidatorSet,
    verifier::SigVerifier,
};

/// Callback type for building a candidate block.
///
/// The node provides this closure; the engine calls it when this validator
/// is the round proposer.  The closure may call `mempool.select_for_block`
/// and populate the block fields from the current state.
pub type BlockBuilder<V> = Box<dyn Fn(u64, &mut Mempool<V>, u64) -> Block + Send + Sync + 'static>;

/// The top-level consensus engine for a single local validator.
///
/// Owns the validator set, mempool, and state machine.  Exposes:
/// - `step(event)` — process one event.
/// - `submit_tx(...)` — delegate to the mempool.
/// - `register_block(hash, block)` — teach the engine about a locally known block.
pub struct ConsensusEngine<V: SigVerifier> {
    pub validator_set: ValidatorSet,
    pub mempool: Mempool<V>,
    pub state: ConsensusState,
    local_address: Address,
    /// Known blocks by hash (proposal targets must be registered here before
    /// the state machine can commit them).
    blocks: BTreeMap<Hash32, Block>,
    /// Optional block builder (set for validators, omitted for followers).
    block_builder: Option<BlockBuilder<V>>,
    /// Block fuel limit (passed to the block builder).
    fuel_limit: u64,
    /// Optional signer for outbound Vote/Proposal messages. When `None`,
    /// emitted messages keep the empty `sig` produced by the state machine
    /// (test-only path; the production node always supplies one).
    signer: Option<Arc<dyn Signer>>,
    /// Proposal already emitted for a height/round. A proposer must not sign
    /// multiple block hashes for the same consensus slot.
    proposed: BTreeMap<(u64, u32), Proposal>,
}

impl<V: SigVerifier> ConsensusEngine<V> {
    /// Construct a new engine.
    ///
    /// - `height` — starting height (typically 1 after genesis).
    /// - `local_address` — this validator's address.
    /// - `validator_set` — the genesis validator set.
    /// - `verifier` — signature verifier implementation.
    /// - `block_builder` — optional callback for building candidate blocks.
    /// - `fuel_limit` — block-level fuel cap.
    pub fn new(
        height: u64,
        local_address: Address,
        validator_set: ValidatorSet,
        verifier: V,
        block_builder: Option<BlockBuilder<V>>,
        fuel_limit: u64,
        signer: Option<Arc<dyn Signer>>,
    ) -> Self {
        let state = ConsensusState::new(height, local_address, validator_set.clone());
        let mempool = Mempool::new(verifier);
        Self {
            validator_set,
            mempool,
            state,
            local_address,
            blocks: BTreeMap::new(),
            block_builder,
            fuel_limit,
            signer,
            proposed: BTreeMap::new(),
        }
    }

    /// Drive the state machine one step.
    ///
    /// Returns the list of actions the caller should perform (broadcast, etc.).
    /// If this validator is the proposer and a `Propose` timeout has not yet fired
    /// (i.e. the engine is at step=Propose and we just started a new round),
    /// the engine may prepend a `Broadcast(Proposal)` action.
    pub fn step(&mut self, event: Event) -> Vec<Action> {
        // After handling, check if we should auto-propose (we are the proposer and
        // the state is still in Propose — happens right after height/round starts).
        // The caller is responsible for calling `step(Event::Tick(Propose))` when
        // they want to advance past the propose timeout.  However, if the caller
        // wants the engine to immediately produce a proposal (e.g. happy path),
        // they should call `maybe_propose()` separately.
        let mut actions = self.state.handle(event, &self.blocks);
        self.sign_actions(&mut actions);
        actions
    }

    /// Walk `actions` and sign any outbound Vote / Proposal using the configured
    /// [`Signer`]. No-op if no signer is configured (test path).
    ///
    /// This is the only place outbound consensus messages acquire a signature.
    /// Keeping it inside the engine guarantees that every action that leaves
    /// the engine — whether via `step`, `maybe_propose`, or `enter_next_height`
    /// — is already signed, so the broadcast path in the node cannot
    /// accidentally emit an unsigned message.
    fn sign_actions(&self, actions: &mut [Action]) {
        let Some(signer) = self.signer.as_ref() else {
            return;
        };
        for action in actions.iter_mut() {
            if let Action::Broadcast(pov) = action {
                match pov {
                    ProposalOrVote::Vote(v) => {
                        let digest = v.signing_digest();
                        v.sig = signer.sign(&digest.0);
                    }
                    ProposalOrVote::Proposal(p) => {
                        let digest = p.signing_digest();
                        p.sig = signer.sign(&digest.0);
                    }
                }
            }
        }
    }

    /// If this validator is the proposer for the current (height, round),
    /// build and return a proposal action.  Returns `None` otherwise or if
    /// no block builder is configured.
    pub fn maybe_propose(&mut self) -> Option<Action> {
        if self.state.step != Step::Propose || !self.state.is_proposer() {
            return None;
        }
        let height = self.state.height;
        let round = self.state.round;
        if let Some(proposal) = self.proposed.get(&(height, round)).cloned() {
            return Some(Action::Broadcast(ProposalOrVote::Proposal(proposal)));
        }

        let (hash, pol_round) = if let Some((valid_round, valid_hash)) = self.state.valid_block
            && self.blocks.contains_key(&valid_hash)
        {
            (valid_hash, valid_round as i32)
        } else {
            let builder = self.block_builder.as_ref()?;
            let fuel_limit = self.fuel_limit;
            let block = builder(height, &mut self.mempool, fuel_limit);
            let hash = block.header.block_hash();
            self.blocks.insert(hash, block.clone());
            (hash, -1)
        };

        let mut proposal = Proposal {
            height,
            round,
            block_hash: hash,
            pol_round,
            proposer: self.local_address,
            sig: bloom_chain_types::types::SigBytes(vec![]),
        };
        if let Some(signer) = self.signer.as_ref() {
            let digest = proposal.signing_digest();
            proposal.sig = signer.sign(&digest.0);
        }
        self.proposed.insert((height, round), proposal.clone());
        Some(Action::Broadcast(ProposalOrVote::Proposal(proposal)))
    }

    /// Register a block so the state machine can commit it when 2f+1 precommits arrive.
    pub fn register_block(&mut self, block: Block) {
        let hash = block.header.block_hash();
        self.blocks.insert(hash, block);
    }

    /// Re-check precommit tallies for a block whose body just landed. If 2f+1
    /// precommits for `hash` were recorded earlier (before the body was
    /// registered), emit the deferred `Commit` action now.
    /// See [`crate::state_machine::ConsensusState::try_commit_with_block`].
    pub fn try_commit_with_block(&mut self, hash: Hash32) -> Vec<Action> {
        let mut actions = self.state.try_commit_with_block(hash, &self.blocks);
        self.sign_actions(&mut actions);
        actions
    }

    /// Re-attempt a previously-stashed proposal whose block has now arrived.
    /// See [`crate::state_machine::ConsensusState::try_resume_pending_proposal`].
    /// Returns the actions emitted by the state machine (signed in-place).
    pub fn try_resume_pending_proposal(&mut self) -> Vec<Action> {
        let mut actions = self.state.try_resume_pending_proposal(&self.blocks);
        self.sign_actions(&mut actions);
        actions
    }

    /// Look up a registered block by hash.
    pub fn get_registered_block(&self, hash: &Hash32) -> Option<Block> {
        self.blocks.get(hash).cloned()
    }

    /// Reset the engine to begin consensus at `new_height`.  Prunes only the
    /// blocks for heights strictly below `new_height` from the known-blocks
    /// map and delegates per-height state reset to `ConsensusState`.
    /// Returns the actions emitted by the state machine (a `StartTimeout` for
    /// the Propose step).
    ///
    /// Critical: blocks for `new_height` and beyond MUST be preserved. The
    /// proposer broadcasts the body for height N+1 right before its
    /// Proposal frame; with 1s blocks and async networking, that body can
    /// land at peers while they're still finalising height N. Clearing the
    /// whole map at the height boundary would lose those bodies — and the
    /// review #3 unknown-block gate (state_machine::on_proposal) would then
    /// silently stash the matching proposal forever, stalling consensus
    /// until a round timeout fires nil-prevote, repeatedly. This was the
    /// failure mode reproduced by the four-validator smoke test where a
    /// single trailing validator fell behind at height ~3 and never
    /// recovered.
    pub fn enter_next_height(&mut self, new_height: u64) -> Vec<Action> {
        self.blocks.retain(|_, b| b.header.height >= new_height);
        self.proposed.retain(|(height, _), _| *height >= new_height);
        let mut actions = self.state.enter_next_height(new_height);
        self.sign_actions(&mut actions);
        actions
    }

    /// Admit a non-PTB transaction into the mempool.
    ///
    /// Use [`Self::submit_tx_with_view`] for `SubmitPtb`; PTB admission needs a
    /// chain-state view to validate the gas-payer coin and balance.
    pub fn submit_tx(
        &mut self,
        tx: Tx,
        current_nonce: u64,
        current_balance: u128,
    ) -> Result<(), ConsensusError> {
        self.mempool.admit(tx, current_nonce, current_balance)
    }

    pub fn submit_tx_with_view(
        &mut self,
        tx: Tx,
        view: &dyn BalanceView,
    ) -> Result<(), ConsensusError> {
        self.mempool.admit_with_view(tx, view)
    }

    /// Current height.
    pub fn height(&self) -> u64 {
        self.state.height
    }

    /// Current round.
    pub fn round(&self) -> u32 {
        self.state.round
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use bloom_chain_types::{
        block::{Block, BlockHeader},
        types::Hash32,
        vote::Commit,
    };

    use super::*;
    use crate::{validator_set::Validator, verifier::NoopVerifier};

    fn addr(seed: u8) -> Address {
        Address([seed; 32])
    }

    fn validator_set() -> ValidatorSet {
        ValidatorSet::new(vec![
            Validator {
                address: addr(0),
                pubkey: bloom_chain_types::types::PubKeyBytes(vec![0; 4]),
                voting_power: 100,
            },
            Validator {
                address: addr(1),
                pubkey: bloom_chain_types::types::PubKeyBytes(vec![1; 4]),
                voting_power: 100,
            },
            Validator {
                address: addr(2),
                pubkey: bloom_chain_types::types::PubKeyBytes(vec![2; 4]),
                voting_power: 100,
            },
            Validator {
                address: addr(3),
                pubkey: bloom_chain_types::types::PubKeyBytes(vec![3; 4]),
                voting_power: 100,
            },
        ])
        .unwrap()
    }

    fn block(height: u64, proposer: Address, tag: u8) -> Block {
        Block {
            header: BlockHeader {
                chain_id: "test".to_string(),
                height,
                parent_hash: Hash32([0; 32]),
                timestamp_ms: tag as u64,
                proposer,
                txs_root: Hash32([tag; 32]),
                state_root: Hash32([tag.wrapping_add(1); 32]),
                receipts_root: Hash32([tag.wrapping_add(2); 32]),
                validator_set_hash: Hash32([0; 32]),
                fuel_used: 0,
                fuel_limit: 1_000,
            },
            txs: vec![],
            commit: Commit {
                height: 0,
                round: 0,
                block_hash: Hash32([0; 32]),
                votes: vec![],
            },
        }
    }

    fn proposal_hash(action: Option<Action>) -> Hash32 {
        match action.expect("proposal action") {
            Action::Broadcast(ProposalOrVote::Proposal(p)) => p.block_hash,
            other => panic!("unexpected action: {other:?}"),
        }
    }

    fn proposal(action: Option<Action>) -> Proposal {
        match action.expect("proposal action") {
            Action::Broadcast(ProposalOrVote::Proposal(p)) => p,
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn maybe_propose_is_idempotent_per_height_round() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_builder = Arc::clone(&calls);
        let local = addr(1); // proposer for height=1 round=0.
        let builder: BlockBuilder<NoopVerifier> = Box::new(move |height, _mempool, _fuel| {
            let tag = calls_for_builder.fetch_add(1, Ordering::SeqCst) as u8 + 1;
            block(height, local, tag)
        });
        let mut engine = ConsensusEngine::new(
            1,
            local,
            validator_set(),
            NoopVerifier,
            Some(builder),
            1_000,
            None,
        );

        let first = proposal_hash(engine.maybe_propose());
        let second = proposal_hash(engine.maybe_propose());

        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn maybe_propose_only_runs_in_propose_step() {
        let local = addr(1);
        let builder: BlockBuilder<NoopVerifier> =
            Box::new(move |height, _mempool, _fuel| block(height, local, 1));
        let mut engine = ConsensusEngine::new(
            1,
            local,
            validator_set(),
            NoopVerifier,
            Some(builder),
            1_000,
            None,
        );
        engine.state.step = Step::Prevote;

        assert!(engine.maybe_propose().is_none());
    }

    #[test]
    fn proposer_reuses_valid_block_with_polka_round() {
        let local = addr(2); // proposer for height=1 round=1.
        let valid = block(1, addr(1), 9);
        let valid_hash = valid.header.block_hash();
        let builder_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_builder = Arc::clone(&builder_calls);
        let builder: BlockBuilder<NoopVerifier> = Box::new(move |height, _mempool, _fuel| {
            calls_for_builder.fetch_add(1, Ordering::SeqCst);
            block(height, local, 1)
        });
        let mut engine = ConsensusEngine::new(
            1,
            local,
            validator_set(),
            NoopVerifier,
            Some(builder),
            1_000,
            None,
        );
        engine.state.round = 1;
        engine.state.valid_block = Some((0, valid_hash));
        engine.register_block(valid);

        let p = proposal(engine.maybe_propose());

        assert_eq!(p.block_hash, valid_hash);
        assert_eq!(p.pol_round, 0);
        assert_eq!(builder_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn repeated_valid_block_reproposal_is_idempotent() {
        let local = addr(2);
        let valid = block(1, addr(1), 9);
        let valid_hash = valid.header.block_hash();
        let mut engine =
            ConsensusEngine::new(1, local, validator_set(), NoopVerifier, None, 1_000, None);
        engine.state.round = 1;
        engine.state.valid_block = Some((0, valid_hash));
        engine.register_block(valid);

        let first = proposal(engine.maybe_propose());
        let second = proposal(engine.maybe_propose());

        assert_eq!(first.block_hash, second.block_hash);
        assert_eq!(first.pol_round, 0);
        assert_eq!(second.pol_round, 0);
    }
}
