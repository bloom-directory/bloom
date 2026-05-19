//! Top-level async consensus engine.
//!
//! `ConsensusEngine` wires together `ValidatorSet`, `Mempool`, and
//! `ConsensusState`.  It does not do networking or persistence — those
//! live in `bloom-chain-node`.  It produces `Action`s; someone else delivers them.

use std::collections::BTreeMap;

use bloom_chain_types::{
    block::Block,
    tx::Tx,
    types::{Address, Hash32},
};

use crate::{
    error::ConsensusError,
    mempool::Mempool,
    state_machine::{Action, ConsensusState, Event},
    validator_set::ValidatorSet,
    verifier::SigVerifier,
};

/// Callback type for building a candidate block.
///
/// The node provides this closure; the engine calls it when this validator
/// is the round proposer.  The closure may call `mempool.select_for_block`
/// and populate the block fields from the current state.
pub type BlockBuilder<V> =
    Box<dyn Fn(u64, &mut Mempool<V>, u64) -> Block + Send + Sync + 'static>;

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
        self.state.handle(event, &self.blocks)
    }

    /// If this validator is the proposer for the current (height, round),
    /// build and return a proposal action.  Returns `None` otherwise or if
    /// no block builder is configured.
    pub fn maybe_propose(&mut self) -> Option<Action> {
        if !self.state.is_proposer() {
            return None;
        }
        let builder = self.block_builder.as_ref()?;
        let height = self.state.height;
        let fuel_limit = self.fuel_limit;
        let block = builder(height, &mut self.mempool, fuel_limit);
        let hash = block.header.block_hash();
        self.blocks.insert(hash, block.clone());

        use bloom_chain_types::vote::Proposal;
        let proposal = Proposal {
            height,
            round: self.state.round,
            block_hash: hash,
            pol_round: -1,
            proposer: self.local_address,
            sig: bloom_chain_types::types::SigBytes(vec![]),
        };
        Some(Action::Broadcast(crate::state_machine::ProposalOrVote::Proposal(proposal)))
    }

    /// Register a block so the state machine can commit it when 2f+1 precommits arrive.
    pub fn register_block(&mut self, block: Block) {
        let hash = block.header.block_hash();
        self.blocks.insert(hash, block);
    }

    /// Look up a registered block by hash.
    pub fn get_registered_block(&self, hash: &Hash32) -> Option<Block> {
        self.blocks.get(hash).cloned()
    }

    /// Reset the engine to begin consensus at `new_height`.  Clears the known
    /// blocks map and delegates per-height state reset to `ConsensusState`.
    /// Returns the actions emitted by the state machine (a `StartTimeout` for
    /// the Propose step).
    pub fn enter_next_height(&mut self, new_height: u64) -> Vec<Action> {
        self.blocks.clear();
        self.state.enter_next_height(new_height)
    }

    /// Admit a transaction into the mempool.
    pub fn submit_tx(
        &mut self,
        tx: Tx,
        current_nonce: u64,
        current_balance: u128,
    ) -> Result<(), ConsensusError> {
        self.mempool.admit(tx, current_nonce, current_balance)
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
