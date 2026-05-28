//! Consensus driver task.
//!
//! Owns a `ConsensusEngine<XdsaVerifier>` and a 1s tick interval.
//! - On `Action::Broadcast{...}`: sends via `PeerPool`.
//! - On `Action::Commit(block, commit)`: applies through `state::apply_block`.
//! - Bridges inbound frames from peers to the driver.
//! - Implements `SigVerifier` using xDSA composite verification.
//!
//! # Execution boundary
//!
//! The consensus driver is intentionally generic over a local `PetalExecutor`
//! trait. Production wires this to `crate::petal_executor::ChainPetalExecutor`,
//! which performs Bloom-native chain-mode execution through `bloom_petals` and
//! the PTB/object pipeline. Tests can inject narrower executors while reusing
//! the same block validation, gas settlement, and commit logic.

use std::sync::Arc;

use anyhow::Result;
use bloom_chain_consensus::{
    ConsensusEngine,
    auth::verify_vote_sig,
    round_validation::{bounded_round_window, judge_proposer_round},
    signer::Signer,
    tx_admission::{AdmitOutcome, AdmitReject, BalanceView, check_admissible},
    validator_set::ValidatorSet,
    verifier::SigVerifier,
};
use bloom_chain_state::{Account, State, WriteSet};
use bloom_chain_types::{
    block::Block,
    digest::blake3_tagged,
    receipt::{Log, Receipt, receipts_root},
    tx::{Tx, TxKind},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
    vote::VoteKind,
};
use bloom_keystore::xdsa::{XdsaPublicKey, XdsaSignature};
use bloom_objects::{OWNER_KIND_ADDRESS, Owner, OwnershipIndexKey, TypeTag};
use bloom_petal_fungible::ops::decode_coin_value;
use bloom_script::{
    CORE_FUNGIBLE_PATH, PtbError, SignatureVerifier, ValidationContext, loom_coin_type_tag,
    validate_ptb,
};
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::{
    block_store::BlockStore,
    mempool_persist::MempoolPersist,
    petal_executor::{apply_coin_loom_transfer_with_domain, mint_coin_loom_to},
    ptb_chain_iface::PtbChainAdapter,
    receipt_store::ReceiptStore,
    state_blob::StateBlobStore,
    state_index::StateIndex,
    transport::PeerPool,
};

// ---------------------------------------------------------------------------
// PetalExecutor trait
// ---------------------------------------------------------------------------

/// Output from executing a single transaction via the chain-mode petal VM.
pub struct ExecOutput {
    pub success: bool,
    pub fuel_used: u64,
    pub return_data: Vec<u8>,
    pub logs: Vec<Log>,
    /// State mutations to apply on success (None = no mutations or already failed).
    pub write_set: Option<WriteSet>,
}

/// Abstraction over deterministic transaction execution.
///
/// The production implementation is [`crate::petal_executor::ChainPetalExecutor`].
/// Keeping the trait local to the driver isolates consensus/block-application
/// tests from the full VM while preserving the exact commit interface used by
/// the node.
pub trait PetalExecutor: Send + Sync + 'static {
    /// Execute a single transaction.
    ///
    /// `parent_hash` is the committing block's parent block hash. At height 1
    /// it is the all-zero hash (genesis parent).
    fn execute_tx(
        &self,
        tx: &Tx,
        state: &mut State,
        block_number: u64,
        timestamp_ms: u64,
        proposer: Address,
        parent_hash: Hash32,
    ) -> ExecOutput;
}

pub struct StateAdmissionView<'a> {
    pub state: &'a State,
    pub current_block: u64,
}

struct AdmissionPtbVerifier<'a> {
    state: &'a State,
    outer_sender: Address,
    outer_pubkey: &'a PubKeyBytes,
}

impl SignatureVerifier for AdmissionPtbVerifier<'_> {
    fn verify(&self, digest: &[u8; 32], signer: &[u8; 32], signature: &[u8]) -> bool {
        let signer_addr = Address(*signer);
        let pubkey = if signer_addr == self.outer_sender {
            self.outer_pubkey.clone()
        } else {
            let Some(pubkey) = self.state.get_pubkey(&signer_addr) else {
                return false;
            };
            pubkey
        };
        let Ok(pk) = XdsaPublicKey::from_bytes(&pubkey.0) else {
            return false;
        };
        let Ok(sig) = XdsaSignature::from_bytes(signature) else {
            return false;
        };
        pk.verify(digest, &sig).is_ok()
    }
}

impl BalanceView for StateAdmissionView<'_> {
    fn nonce(&self, addr: &Address) -> u64 {
        self.state.get_account(addr).map(|a| a.nonce).unwrap_or(0)
    }

    fn loom_balance(&self, addr: &Address) -> u128 {
        resolve_loom_coin_type(self.state)
            .map(|coin_type| coin_loom_balance(self.state, *addr, &coin_type))
            .unwrap_or(0)
    }

    fn validate_submit_ptb(
        &self,
        outer: &Tx,
        ptb: &bloom_script::PtbTx,
    ) -> Result<(), AdmitReject> {
        let Some(coin_type) = resolve_loom_coin_type(self.state) else {
            return Err(AdmitReject::EnvelopeInvalid(
                "missing required VFS binding for /bloom/core/fungible".to_string(),
            ));
        };
        let adapter = PtbChainAdapter::new(self.state, self.current_block);
        let verifier = AdmissionPtbVerifier {
            state: self.state,
            outer_sender: outer.sender,
            outer_pubkey: &outer.pubkey,
        };
        let ctx = ValidationContext {
            current_block: self.current_block,
            chain: &adapter,
            verifier: &verifier,
            loom_coin_type: coin_type,
        };
        validate_ptb(ptb, &ctx).map(|_| ()).map_err(|e| match e {
            PtbError::InsufficientGas { needed, available } => AdmitReject::InsufficientBalance {
                need: needed,
                have: available,
            },
            other => AdmitReject::EnvelopeInvalid(format!(
                "PTB validation failed before admission: {other}"
            )),
        })
    }

    fn ptb_gas_payer_balance(&self, ptb: &bloom_script::PtbTx) -> Result<u128, AdmitReject> {
        let Some(first_signer) = ptb.signers.first() else {
            return Err(AdmitReject::EnvelopeInvalid(
                "PTB has no signers".to_string(),
            ));
        };
        let Some(coin_type) = resolve_loom_coin_type(self.state) else {
            return Err(AdmitReject::EnvelopeInvalid(
                "missing required VFS binding for /bloom/core/fungible".to_string(),
            ));
        };
        let Some(obj) = self.state.get_object(&ptb.gas_payer) else {
            return Err(AdmitReject::EnvelopeInvalid(
                "gas-payer object not found".to_string(),
            ));
        };
        if obj.owner != Owner::Address(*first_signer) {
            return Err(AdmitReject::EnvelopeInvalid(
                "gas-payer object is not owned by first signer".to_string(),
            ));
        }
        if obj.type_tag != coin_type {
            return Err(AdmitReject::EnvelopeInvalid(
                "gas-payer object is not a Coin<LOOM>".to_string(),
            ));
        }
        decode_coin_value(&obj.payload).map_err(|e| {
            AdmitReject::EnvelopeInvalid(format!("gas-payer Coin<LOOM> decode failed: {e}"))
        })
    }
}

/// A no-op executor that marks every tx as succeeded with zero fuel (for scaffolding / testing).
pub struct NoopExecutor;

impl PetalExecutor for NoopExecutor {
    fn execute_tx(
        &self,
        tx: &Tx,
        state: &mut State,
        _block_number: u64,
        _timestamp_ms: u64,
        _proposer: Address,
        _parent_hash: Hash32,
    ) -> ExecOutput {
        let _ = tx;
        let _ = state;
        ExecOutput {
            success: true,
            fuel_used: 0,
            return_data: vec![],
            logs: vec![],
            write_set: None,
        }
    }
}

pub fn resolve_loom_coin_type(state: &State) -> Option<TypeTag> {
    state.vfs_lookup(CORE_FUNGIBLE_PATH).map(loom_coin_type_tag)
}

pub fn coin_loom_balance(state: &State, owner: Address, coin_type: &TypeTag) -> u128 {
    let okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: owner.0,
    };
    state
        .get_ownership(&okey)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|id| {
            let obj = state.get_object(&id)?;
            if obj.type_tag != *coin_type {
                return None;
            }
            match obj.owner {
                Owner::Address(addr) if addr == owner.0 => decode_coin_value(&obj.payload).ok(),
                _ => None,
            }
        })
        .try_fold(0u128, |acc, value| acc.checked_add(value))
        .unwrap_or(u128::MAX)
}

// ---------------------------------------------------------------------------
// XdsaVerifier — implements SigVerifier using bloom_keystore's xDSA
// ---------------------------------------------------------------------------

/// xDSA signature verifier wired to the actual `bloom_keystore::xdsa` module.
#[derive(Clone, Default)]
pub struct XdsaVerifier;

impl SigVerifier for XdsaVerifier {
    fn verify(&self, pubkey: &PubKeyBytes, msg: &[u8], sig: &SigBytes) -> bool {
        let Ok(pk) = bloom_keystore::xdsa::XdsaPublicKey::from_bytes(&pubkey.0) else {
            return false;
        };
        let Ok(signature) = bloom_keystore::xdsa::XdsaSignature::from_bytes(&sig.0) else {
            return false;
        };
        pk.verify(msg, &signature).is_ok()
    }
}

// ---------------------------------------------------------------------------
// XdsaSigner — implements Signer using the node's loaded xDSA secret key.
// ---------------------------------------------------------------------------

/// Production signer wrapping an `XdsaSecretKey` held in the node's memory.
///
/// Used by the consensus engine to sign outbound Vote and Proposal messages.
/// The corresponding pubkey is what every receiving validator looks up in the
/// validator set to verify these messages.
pub struct XdsaSigner {
    secret: Arc<bloom_keystore::xdsa::XdsaSecretKey>,
}

impl XdsaSigner {
    pub fn new(secret: Arc<bloom_keystore::xdsa::XdsaSecretKey>) -> Self {
        Self { secret }
    }
}

impl Signer for XdsaSigner {
    fn sign(&self, msg: &[u8]) -> SigBytes {
        let sig = self.secret.sign(msg);
        SigBytes(sig.to_bytes())
    }
}

// ---------------------------------------------------------------------------
// Block validation boundary (review 2026-05-19 #2)
// ---------------------------------------------------------------------------

/// Compute the deterministic txs_root committing to the ordered tx list.
///
/// Domain-tagged BLAKE3 of each tx's `tx_hash()` concatenated in order.
/// Kept here so the validation boundary and the block builder share one
/// implementation — disagreement here silently rejects every block.
pub fn compute_txs_root(txs: &[Tx]) -> Hash32 {
    let mut buf = Vec::with_capacity(txs.len() * 32);
    for tx in txs {
        buf.extend_from_slice(&tx.tx_hash().0);
    }
    blake3_tagged("bloom-chain.v0.txs_root:", &buf)
}

/// Single validation boundary entered BEFORE any committed block — whether
/// from live consensus or catch-up sync — is applied to state.
///
/// Checks (review 2026-05-19 #2 + HIGH follow-ups):
/// 1. `header.chain_id` matches our chain id.
/// 2. `header.height` matches `expected_height`.
/// 3. `header.parent_hash` matches `expected_parent_hash` (zero at height 1).
/// 4. `header.txs_root` matches `compute_txs_root(block.txs)`.
/// 5. `header.validator_set_hash` matches the current validator set.
/// 6. `block.commit` shape: `commit.height == header.height`,
///    `commit.block_hash == header.block_hash()`.
/// 7. Every tx carries `tx.chain_id == expected_chain_id` (rejects
///    cross-chain replay) AND `verify(tx.pubkey, tx.signing_digest, tx.sig)`
///    succeeds (rejects forged tx signatures). A malicious proposer can
///    include such a tx in its own block — mempool admission does not
///    gate proposer-built blocks. Apply-time sender-derivation alone is
///    insufficient because it does not bind the signature to the tx body.
/// 8. Every commit vote is a `Precommit` from a validator in the set,
///    with `vote.round == commit.round` (Tendermint safety: 2f+1 must
///    come from one (height, round) tuple), voting for
///    `header.block_hash()`, with a valid xDSA signature, and the summed
///    voting power meets quorum (`2f+1`).
///
/// On master, BlockResponse → catch-up apply trusted the wire bytes
/// outright. A peer (or a passive-MITM) could thereby push a tampered tx
/// root, a wrong validator set hash, a forged commit, or a wrong parent
/// hash and the validator would happily apply it.
///
/// Returns `Err(reason)` with a short message on the first failure.
pub fn validate_block_for_apply(
    block: &Block,
    expected_height: u64,
    expected_chain_id: &str,
    expected_parent_hash: Hash32,
    validator_set: &ValidatorSet,
    verifier: &XdsaVerifier,
) -> std::result::Result<(), String> {
    let h = &block.header;

    if h.chain_id != expected_chain_id {
        return Err(format!(
            "chain_id mismatch: header={:?} expected={:?}",
            h.chain_id, expected_chain_id
        ));
    }
    if h.height != expected_height {
        return Err(format!(
            "height mismatch: header={} expected={}",
            h.height, expected_height
        ));
    }
    if h.parent_hash != expected_parent_hash {
        return Err(format!(
            "parent_hash mismatch at height {}: header={} expected={}",
            h.height,
            hex::encode(h.parent_hash.0),
            hex::encode(expected_parent_hash.0)
        ));
    }
    let computed_txs_root = compute_txs_root(&block.txs);
    if h.txs_root != computed_txs_root {
        return Err(format!(
            "txs_root mismatch at height {}: header={} computed={}",
            h.height,
            hex::encode(h.txs_root.0),
            hex::encode(computed_txs_root.0)
        ));
    }
    let vs_hash = validator_set.validator_set_hash();
    if h.validator_set_hash != vs_hash {
        return Err(format!(
            "validator_set_hash mismatch at height {}: header={} expected={}",
            h.height,
            hex::encode(h.validator_set_hash.0),
            hex::encode(vs_hash.0)
        ));
    }

    let block_hash = h.block_hash();
    let commit = &block.commit;
    if commit.height != h.height {
        return Err(format!(
            "commit.height={} != header.height={}",
            commit.height, h.height
        ));
    }
    if commit.block_hash != block_hash {
        return Err(format!(
            "commit.block_hash={} != header.block_hash={}",
            hex::encode(commit.block_hash.0),
            hex::encode(block_hash.0)
        ));
    }
    let proposer_judgment =
        judge_proposer_round(h.height, h.proposer, commit.round, -1, validator_set, true)
            .map_err(|e| e.to_string())?;
    if !proposer_judgment.proposer_ok {
        let proposer_round_window = bounded_round_window(validator_set.len(), commit.round);
        return Err(format!(
            "header.proposer={} is not a proposer for height={} in bounded rounds 0..{}",
            hex::encode(h.proposer.0),
            h.height,
            proposer_round_window
        ));
    }

    // Per-tx authentication. A malicious proposer can include a tx with
    // a forged signature, a tx signed for another chain (replay), or a
    // tx whose declared sender does not match its pubkey — all of which
    // bypass mempool admission since the proposer never goes through
    // `Mempool::admit` for its own block. Apply-time was relying on
    // sender-derivation only, which leaves both forged-sig and
    // cross-chain replay open. Review 2026-05-19 (HIGH).
    //
    // These checks run inside the single validation boundary so they
    // also protect catch-up sync (BlockResponse → apply): a peer pushing
    // a tampered block is rejected before any state-transition runs.
    for tx in &block.txs {
        if tx.chain_id != expected_chain_id {
            return Err(format!(
                "tx.chain_id={:?} != expected_chain_id={:?} (tx_hash={})",
                tx.chain_id,
                expected_chain_id,
                hex::encode(tx.tx_hash().0)
            ));
        }
        let expected_sender = Address::from_pubkey_bytes(&tx.pubkey.0);
        if expected_sender != tx.sender {
            return Err(format!(
                "tx sender/pubkey mismatch (tx_hash={}, sender={}, derived={})",
                hex::encode(tx.tx_hash().0),
                hex::encode(tx.sender.0),
                hex::encode(expected_sender.0)
            ));
        }
        let digest = tx.signing_digest();
        if !verifier.verify(&tx.pubkey, &digest.0, &tx.sig) {
            return Err(format!(
                "tx signature invalid (tx_hash={}, sender={})",
                hex::encode(tx.tx_hash().0),
                hex::encode(tx.sender.0)
            ));
        }
    }

    // 2f+1 voting power of precommit votes for `block_hash` with valid
    // xDSA signatures. De-duplicate by validator address — a single
    // validator's vote must not be counted twice.
    let mut tallied: std::collections::BTreeSet<Address> = Default::default();
    let mut power: u64 = 0;
    for v in &commit.votes {
        if v.kind != VoteKind::Precommit {
            return Err(format!(
                "commit.vote not Precommit: validator={} kind={:?}",
                hex::encode(v.validator.0),
                v.kind
            ));
        }
        if v.height != h.height {
            return Err(format!(
                "commit.vote.height={} != block.height={}",
                v.height, h.height
            ));
        }
        // Tendermint safety: 2f+1 quorum must come from a single
        // (height, round) tuple. Aggregating precommits across rounds
        // breaks the locking guarantee and can finalize a block that
        // never had a single-round majority. Review 2026-05-19 (HIGH).
        if v.round != commit.round {
            return Err(format!(
                "commit.vote.round={} != commit.round={} (validator {})",
                v.round,
                commit.round,
                hex::encode(v.validator.0)
            ));
        }
        if v.block_hash != Some(block_hash) {
            return Err(format!(
                "commit.vote.block_hash from validator {} does not match block hash",
                hex::encode(v.validator.0)
            ));
        }
        if !tallied.insert(v.validator) {
            return Err(format!(
                "duplicate commit.vote from validator {}",
                hex::encode(v.validator.0)
            ));
        }
        let Some(val) = validator_set.get_by_address(&v.validator) else {
            return Err(format!(
                "commit.vote from non-validator {}",
                hex::encode(v.validator.0)
            ));
        };
        if !verify_vote_sig(v, validator_set, verifier) {
            return Err(format!(
                "commit.vote bad signature from validator {}",
                hex::encode(v.validator.0)
            ));
        }
        power = power
            .checked_add(val.voting_power)
            .ok_or_else(|| "commit voting power overflow".to_string())?;
    }
    let quorum = validator_set.quorum();
    if power < quorum {
        return Err(format!(
            "commit quorum not met at height {}: power={} quorum={}",
            h.height, power, quorum
        ));
    }
    Ok(())
}

/// Validate a proposal block before the consensus state machine is allowed to
/// prevote for it. Proposal dissemination carries an empty commit, so this is
/// the same structural boundary as committed-block validation minus commit
/// quorum checks and plus the expected proposer from the proposal frame.
pub fn validate_block_for_proposal(
    block: &Block,
    expected: ProposalValidation<'_>,
    validator_set: &ValidatorSet,
    verifier: &XdsaVerifier,
) -> std::result::Result<(), String> {
    let h = &block.header;

    if h.chain_id != expected.chain_id {
        return Err(format!(
            "chain_id mismatch: header={:?} expected={:?}",
            h.chain_id, expected.chain_id
        ));
    }
    if h.height != expected.height {
        return Err(format!(
            "height mismatch: header={} expected={}",
            h.height, expected.height
        ));
    }
    if h.parent_hash != expected.parent_hash {
        return Err(format!(
            "parent_hash mismatch at height {}: header={} expected={}",
            h.height,
            hex::encode(h.parent_hash.0),
            hex::encode(expected.parent_hash.0)
        ));
    }
    let proposer_judgment = judge_proposer_round(
        expected.height,
        h.proposer,
        expected.header_proposer_round,
        -1,
        validator_set,
        false,
    )
    .map_err(|e| e.to_string())?;
    if !proposer_judgment.proposer_ok {
        let expected_proposer = validator_set
            .proposer_for(expected.height, expected.header_proposer_round)
            .address;
        return Err(format!(
            "header.proposer={} != expected proposer={} for height={} proposal_round={} header_round={}",
            hex::encode(h.proposer.0),
            hex::encode(expected_proposer.0),
            expected.height,
            expected.round,
            expected.header_proposer_round
        ));
    }
    let computed_txs_root = compute_txs_root(&block.txs);
    if h.txs_root != computed_txs_root {
        return Err(format!(
            "txs_root mismatch at height {}: header={} computed={}",
            h.height,
            hex::encode(h.txs_root.0),
            hex::encode(computed_txs_root.0)
        ));
    }
    let vs_hash = validator_set.validator_set_hash();
    if h.validator_set_hash != vs_hash {
        return Err(format!(
            "validator_set_hash mismatch at height {}: header={} expected={}",
            h.height,
            hex::encode(h.validator_set_hash.0),
            hex::encode(vs_hash.0)
        ));
    }
    for tx in &block.txs {
        if tx.chain_id != expected.chain_id {
            return Err(format!(
                "tx.chain_id={:?} != expected_chain_id={:?} (tx_hash={})",
                tx.chain_id,
                expected.chain_id,
                hex::encode(tx.tx_hash().0)
            ));
        }
        let expected_sender = Address::from_pubkey_bytes(&tx.pubkey.0);
        if expected_sender != tx.sender {
            return Err(format!(
                "tx sender/pubkey mismatch (tx_hash={}, sender={}, derived={})",
                hex::encode(tx.tx_hash().0),
                hex::encode(tx.sender.0),
                hex::encode(expected_sender.0)
            ));
        }
        let digest = tx.signing_digest();
        if !verifier.verify(&tx.pubkey, &digest.0, &tx.sig) {
            return Err(format!(
                "tx signature invalid (tx_hash={}, sender={})",
                hex::encode(tx.tx_hash().0),
                hex::encode(tx.sender.0)
            ));
        }
    }
    Ok(())
}

pub struct ProposalValidation<'a> {
    pub height: u64,
    pub round: u32,
    pub header_proposer_round: u32,
    pub chain_id: &'a str,
    pub parent_hash: Hash32,
}

// ---------------------------------------------------------------------------
// Block state-transition application
// ---------------------------------------------------------------------------

/// Apply the state-transition portion of a committed block (steps 1-5 of
/// spec §6.4: sender derivation, nonce, balance, execution, fee
/// settlement, block emission). No validation, no persistence — callers
/// must drive those separately.
///
/// Used by:
/// - [`ConsensusDriver::apply_block`] (after validation, before persistence).
/// - Startup replay in `node.rs` (rebuilding state from `block_store`
///   without re-persisting). On master, restart replayed only proposer
///   emission and silently dropped every tx effect — review 2026-05-19 #4.
pub fn apply_block_state_transitions<E: PetalExecutor>(
    state: &mut State,
    executor: &E,
    block: &Block,
    block_emission: u128,
) -> (u64, Vec<Receipt>) {
    try_apply_block_state_transitions(state, executor, block, block_emission)
        .expect("block state transition failed")
}

/// Fallible form of [`apply_block_state_transitions`]. This is the consensus
/// validation path: apply failures reject the block/transition instead of
/// being logged and ignored.
pub fn try_apply_block_state_transitions<E: PetalExecutor>(
    state: &mut State,
    executor: &E,
    block: &Block,
    block_emission: u128,
) -> std::result::Result<(u64, Vec<Receipt>), String> {
    let proposer = block.header.proposer;
    let height = block.header.height;
    let timestamp_ms = block.header.timestamp_ms;
    // Parent block hash for execution metadata.
    let parent_hash = block.header.parent_hash;

    let mut total_fuel_used: u64 = 0;
    let mut receipts: Vec<Receipt> = Vec::new();

    for tx in &block.txs {
        let admission_view = StateAdmissionView {
            state,
            current_block: height,
        };
        if let AdmitOutcome::Reject(reject) = check_admissible(tx, &admission_view, true) {
            receipts.push(Receipt {
                tx_hash: tx.tx_hash(),
                success: false,
                fuel_used: 0,
                return_data: format!("tx admission rejected: {reject:?}").into_bytes(),
                logs: vec![],
            });
            continue;
        }

        // 3. SubmitPtb outer/inner gas reconciliation (P0-5, spec §7.2 +
        //    §9.4). PTBs run on the gas-payer `Coin<LOOM>` object. We still gate execution on
        //    the outer envelope's `tx.max_fuel` / `tx.fee_per_unit`
        //    caps so a malicious sender can't squeeze unlimited VM work
        //    out of a tiny outer fuel budget. Specifically:
        //
        //      tx.max_fuel      >= ptb.gas_budget   (cap covers inner budget)
        //      tx.fee_per_unit  >= ptb.gas_price    (price covers inner price)
        //
        //    Together these guarantee
        //      outer_max_fee = tx.max_fuel * tx.fee_per_unit
        //                    >= ptb.gas_budget * ptb.gas_price.
        //    If the PTB cannot decode or the inner budget exceeds either
        //    outer cap, the block is invalid. Mempool admission performs the
        //    same envelope precheck, but committed block validation and
        //    catch-up sync cannot trust mempool filtering: accepting those
        //    envelopes as zero-fuel nonce bumps lets a Byzantine proposer
        //    change state without consuming block fuel.
        if let TxKind::SubmitPtb { .. } = &tx.kind {
            let mut tx_state = state.clone();
            tx_state.register_pubkey(tx.sender, tx.pubkey.clone());

            // Bump nonce; sender's loom stays put.
            {
                let mut acct = state.get_account(&tx.sender).unwrap_or_else(empty_account);
                acct.nonce = acct
                    .nonce
                    .checked_add(1)
                    .expect("admission checked sender nonce can advance");
                tx_state.set_account(tx.sender, acct);
            }

            // 4. Execute via PetalExecutor. All gas settlement
            //    (gas-payer Coin<LOOM> debit + refund + proposer
            //    credit) lives in the executor's WriteSet.
            let output = executor.execute_tx(
                tx,
                &mut tx_state,
                height,
                timestamp_ms,
                proposer,
                parent_hash,
            );

            if output.fuel_used == 0 || output.write_set.is_none() {
                return Err(
                    "invalid SubmitPtb execution output: prechecked PTB must charge positive fuel \
                     and emit gas settlement"
                        .to_string(),
                );
            }
            if output.fuel_used > tx.max_fuel {
                return Err(format!(
                    "invalid SubmitPtb execution output: fuel_used {} exceeds max_fuel {}",
                    output.fuel_used, tx.max_fuel
                ));
            }

            // Apply whatever the executor produced. On revert the
            // executor still emits a write_set that carries the
            // burnt-gas accounting (gas-payer debit + proposer
            // credit), so we apply it unconditionally rather than
            // gating on `output.success`.
            if let Some(ws) = output.write_set {
                tx_state
                    .apply(ws)
                    .map_err(|e| format!("apply write_set failed (SubmitPtb): {e}"))?;
            }
            *state = tx_state;

            total_fuel_used = total_fuel_used
                .checked_add(output.fuel_used)
                .ok_or_else(|| "block execution fuel_used overflow".to_string())?;
            receipts.push(Receipt {
                tx_hash: tx.tx_hash(),
                success: output.success,
                fuel_used: output.fuel_used,
                logs: output.logs,
                return_data: output.return_data,
            });
            continue;
        }

        // 3. Max-fee reservation (non-PTB txs). The admission predicate above
        // already proved this arithmetic and the sender balance are valid.
        let max_fee = (tx.max_fuel as u128)
            .checked_mul(tx.fee_per_unit as u128)
            .expect("admission checked non-PTB max fee");
        let Some(coin_type) = resolve_loom_coin_type(state) else {
            receipts.push(Receipt {
                tx_hash: tx.tx_hash(),
                success: false,
                fuel_used: 0,
                return_data: b"missing required VFS binding for /bloom/core/fungible".to_vec(),
                logs: vec![],
            });
            continue;
        };

        let mut tx_state = state.clone();
        tx_state.register_pubkey(tx.sender, tx.pubkey.clone());

        // Bump nonce after Coin<LOOM> admission. Value and gas are settled by
        // object writes, not by account balance fields. Stage this on a
        // candidate state so fee settlement can fail without publishing
        // non-PTB effects.
        {
            let mut acct = state.get_account(&tx.sender).unwrap_or_else(empty_account);
            acct.nonce = acct
                .nonce
                .checked_add(1)
                .expect("admission checked sender nonce can advance");
            tx_state.set_account(tx.sender, acct);
        }

        // 4. Execute via PetalExecutor.
        let output = executor.execute_tx(
            tx,
            &mut tx_state,
            height,
            timestamp_ms,
            proposer,
            parent_hash,
        );

        if output.success && output.fuel_used == 0 {
            return Err(
                "invalid non-PTB execution output: successful tx must charge positive fuel"
                    .to_string(),
            );
        }
        if output.fuel_used > tx.max_fuel {
            return Err(format!(
                "invalid non-PTB execution output: fuel_used {} exceeds max_fuel {}",
                output.fuel_used, tx.max_fuel
            ));
        }

        if output.success {
            if let Some(ws) = output.write_set.clone() {
                tx_state
                    .apply(ws)
                    .map_err(|e| format!("apply write_set failed: {e}"))?;
            }
        } else {
            // Failed non-PTB txs forfeit the full max fee. Value was never
            // debited, so no value refund is needed.
        }

        // 5. Settle fuel and fees as Coin<LOOM> object transfers.
        let fee_charged = if output.success {
            (output.fuel_used as u128)
                .checked_mul(tx.fee_per_unit as u128)
                .ok_or_else(|| {
                    format!(
                        "invalid non-PTB execution output: fee settlement overflow for fuel_used {} and fee_per_unit {}",
                        output.fuel_used, tx.fee_per_unit
                    )
                })?
        } else {
            max_fee
        };
        if fee_charged > 0 {
            let mut fee_snap = tx_state.snapshot();
            if let Err(e) = apply_coin_loom_transfer_with_domain(
                &mut fee_snap,
                tx.sender,
                proposer,
                fee_charged,
                &tx.tx_hash(),
                coin_type,
                b"bloom.non_ptb.fee",
            ) {
                return Err(format!("non-PTB fee settlement failed: {e}"));
            }
            tx_state
                .apply(fee_snap.commit())
                .map_err(|e| format!("apply fee write_set failed: {e}"))?;
        }

        *state = tx_state;

        total_fuel_used = total_fuel_used
            .checked_add(output.fuel_used)
            .ok_or_else(|| "block execution fuel_used overflow".to_string())?;

        receipts.push(Receipt {
            tx_hash: tx.tx_hash(),
            success: output.success,
            fuel_used: output.fuel_used,
            logs: output.logs,
            return_data: output.return_data,
        });
    }

    // 6. LOOM block emission (spec §11.1), minted as Coin<LOOM>.
    if block_emission > 0
        && let Some(coin_type) = resolve_loom_coin_type(state)
    {
        let emission_seed = {
            let mut h = blake3::Hasher::new();
            h.update(b"bloom.block.emission.seed");
            h.update(&block.header.height.to_be_bytes());
            h.update(&block.header.parent_hash.0);
            h.update(&proposer.0);
            Hash32(*h.finalize().as_bytes())
        };
        let mut snap = state.snapshot();
        if let Err(e) = mint_coin_loom_to(
            &mut snap,
            proposer,
            block_emission,
            b"bloom.block.emission",
            &emission_seed,
            coin_type,
        ) {
            return Err(format!("block emission mint failed: {e}"));
        } else {
            state
                .apply(snap.commit())
                .map_err(|e| format!("apply block emission write_set failed: {e}"))?;
        }
    }

    Ok((total_fuel_used, receipts))
}

/// Result of deterministic block execution on a scratch state.
#[derive(Debug)]
pub struct ExecutionValidation {
    pub state: State,
    pub fuel_used: u64,
    pub receipts: Vec<Receipt>,
    pub state_root: Hash32,
    pub receipts_root: Hash32,
}

/// Execute a block on a cloned pre-state and verify the header commits to the
/// resulting consensus artifacts. Callers can then install `state` atomically.
pub fn validate_block_execution<E: PetalExecutor>(
    pre_state: &State,
    executor: &E,
    block: &Block,
    block_emission: u128,
) -> std::result::Result<ExecutionValidation, String> {
    let max_fuel: u64 = block
        .txs
        .iter()
        .try_fold(0u64, |acc, tx| acc.checked_add(tx.max_fuel))
        .ok_or_else(|| "block tx max_fuel sum overflow".to_string())?;
    if max_fuel > block.header.fuel_limit {
        return Err(format!(
            "block tx max_fuel sum {} exceeds header.fuel_limit {}",
            max_fuel, block.header.fuel_limit
        ));
    }

    let mut scratch = pre_state.clone();
    let (fuel_used, receipts) =
        try_apply_block_state_transitions(&mut scratch, executor, block, block_emission)?;
    if fuel_used > block.header.fuel_limit {
        return Err(format!(
            "executed fuel_used {} exceeds header.fuel_limit {}",
            fuel_used, block.header.fuel_limit
        ));
    }

    let state_root = scratch.state_root();
    if state_root != block.header.state_root {
        return Err(format!(
            "state_root mismatch at height {}: header={} computed={}",
            block.header.height,
            hex::encode(block.header.state_root.0),
            hex::encode(state_root.0)
        ));
    }
    let computed_receipts_root = receipts_root(&receipts);
    if computed_receipts_root != block.header.receipts_root {
        return Err(format!(
            "receipts_root mismatch at height {}: header={} computed={}",
            block.header.height,
            hex::encode(block.header.receipts_root.0),
            hex::encode(computed_receipts_root.0)
        ));
    }
    if fuel_used != block.header.fuel_used {
        return Err(format!(
            "fuel_used mismatch at height {}: header={} computed={}",
            block.header.height, block.header.fuel_used, fuel_used
        ));
    }

    Ok(ExecutionValidation {
        state: scratch,
        fuel_used,
        receipts,
        state_root,
        receipts_root: computed_receipts_root,
    })
}

// ---------------------------------------------------------------------------
// Default-like helper for Account
// ---------------------------------------------------------------------------

/// Return an empty account (nonce=0, no code, zero storage_root, no manifest
/// anchor).
pub(crate) fn empty_account() -> Account {
    Account::empty()
}

// ---------------------------------------------------------------------------
// ConsensusDriver
// ---------------------------------------------------------------------------

/// Shared state passed to the consensus driver task.
pub struct ConsensusDriver<E: PetalExecutor> {
    pub engine: Mutex<ConsensusEngine<XdsaVerifier>>,
    pub peer_pool: Arc<PeerPool>,
    /// Shared state — also captured by the block builder closure so the
    /// proposer can compute `state_root` for new headers.
    pub state: Arc<Mutex<State>>,
    pub block_store: Arc<BlockStore>,
    pub blob_store: Arc<StateBlobStore>,
    pub state_index: Arc<StateIndex>,
    pub mempool_persist: Arc<MempoolPersist>,
    pub receipt_store: Arc<ReceiptStore>,
    pub executor: Arc<E>,
    pub chain_id: String,
    pub local_address: Address,
    /// LOOM emission per block (spec §11.1): 10 × 10^18 bloomweis.
    pub block_emission: u128,
}

/// Per-block emission: 10 LOOM = 10 × 10^18 bloomweis (spec §11.1).
pub const BLOCK_EMISSION: u128 = 10_000_000_000_000_000_000u128;

impl<E: PetalExecutor> ConsensusDriver<E> {
    /// Resolve the expected parent hash for `height` from the local block
    /// store. Zero at height 1 (genesis-parent), prior block's
    /// `block_hash()` otherwise. Used by the validation boundary.
    fn expected_parent_hash(&self, height: u64) -> Result<Hash32> {
        if height <= 1 {
            return Ok(Hash32([0u8; 32]));
        }
        let parent = self
            .block_store
            .get(height - 1)?
            .ok_or_else(|| anyhow::anyhow!("parent block missing at height {}", height - 1))?;
        Ok(parent.header.block_hash())
    }

    /// Run the single block-validation boundary against the locally-known
    /// chain id, validator set, and parent hash. Used by both live commit
    /// and catch-up sync — see [`validate_block_for_apply`] for the checks.
    pub fn validate_block(
        &self,
        block: &Block,
        expected_height: u64,
    ) -> std::result::Result<(), String> {
        let parent = self
            .expected_parent_hash(expected_height)
            .map_err(|e| e.to_string())?;
        let validator_set = { self.engine.lock().validator_set.clone() };
        validate_block_for_apply(
            block,
            expected_height,
            &self.chain_id,
            parent,
            &validator_set,
            &XdsaVerifier,
        )
    }

    /// Validate an uncommitted proposal body before voting for it.
    pub fn validate_proposal_block(
        &self,
        block: &Block,
        expected_height: u64,
        expected_round: u32,
        expected_header_proposer_round: u32,
    ) -> std::result::Result<(), String> {
        let parent = self
            .expected_parent_hash(expected_height)
            .map_err(|e| e.to_string())?;
        let validator_set = { self.engine.lock().validator_set.clone() };
        validate_block_for_proposal(
            block,
            ProposalValidation {
                height: expected_height,
                round: expected_round,
                header_proposer_round: expected_header_proposer_round,
                chain_id: &self.chain_id,
                parent_hash: parent,
            },
            &validator_set,
            &XdsaVerifier,
        )?;
        let state = self.state.lock();
        validate_block_execution(&state, self.executor.as_ref(), block, self.block_emission)
            .map(|_| ())
    }

    /// Validate a committed block, including commit proof and deterministic
    /// execution outputs, without mutating state or durable stores.
    pub fn validate_committed_block(
        &self,
        block: &Block,
        expected_height: u64,
    ) -> std::result::Result<(), String> {
        self.validate_block(block, expected_height)?;
        let state = self.state.lock();
        validate_block_execution(&state, self.executor.as_ref(), block, self.block_emission)
            .map(|_| ())
    }

    /// Apply a committed block to state (spec §6.4, §11).
    ///
    /// The block is first run through the validation boundary
    /// ([`Self::validate_block`]) — chain id, height, parent hash, txs
    /// root, validator set hash, commit shape, and 2f+1 commit quorum
    /// with valid xDSA signatures. A block that fails validation is
    /// refused with an error, never partially applied.
    pub fn apply_block(&self, block: &Block) -> Result<()> {
        let height = block.header.height;
        if let Err(reason) = self.validate_block(block, height) {
            return Err(anyhow::anyhow!(
                "block validation failed at height {}: {}",
                height,
                reason
            ));
        }
        // Validate execution on a scratch clone. Durable writes below publish
        // the block/blob first and the state index last; only after that commit
        // marker succeeds do we install the already-validated state in memory.
        let execution = {
            let state = self.state.lock();
            validate_block_execution(&state, self.executor.as_ref(), block, self.block_emission)
                .map_err(|reason| {
                    anyhow::anyhow!(
                        "block execution validation failed at height {}: {}",
                        height,
                        reason
                    )
                })?
        };
        let total_fuel_used = execution.fuel_used;
        let receipts = execution.receipts;
        let state_root = execution.state_root;
        let (blob_data, expected_blob_hash) =
            execution.state.to_blob(height, block.header.parent_hash);

        // Persist block/blob durably, then publish the state index last as the
        // restart commit marker. A crash before this point leaves no newer
        // checkpoint for restart to select.
        let blob_hash = self.blob_store.put(&blob_data)?;
        if blob_hash != expected_blob_hash {
            return Err(anyhow::anyhow!(
                "state blob hash mismatch at height {}: state={} store={}",
                height,
                hex::encode(expected_blob_hash.0),
                hex::encode(blob_hash.0)
            ));
        }
        self.block_store.put(height, block)?;
        self.state_index.put(height, &state_root, &blob_hash)?;
        {
            *self.state.lock() = execution.state.clone();
        }
        self.block_store.prune(height)?;
        self.blob_store.gc(&[blob_hash])?;

        // Persist receipts so CLIs can distinguish a successful tx from a
        // silent revert. The consensus driver bumps the nonce *before*
        // calling the petal VM, so without receipts a CLI that only waits
        // on nonce advancement is blind to reverts.
        for r in &receipts {
            if let Err(e) = self.receipt_store.put(height, r) {
                warn!(err = %e, tx_hash = %hex::encode(r.tx_hash.0), "receipt_store.put failed");
            }
        }
        if let Err(e) = self.receipt_store.prune(height) {
            warn!(err = %e, "receipt_store.prune failed");
        }

        // Remove committed txs from persistent mempool.
        for tx in &block.txs {
            let _ = self.mempool_persist.remove(&tx.sender, tx.nonce);
        }
        let _ = self.mempool_persist.flush();

        info!(
            height,
            txs = block.txs.len(),
            fuel_used = total_fuel_used,
            state_root = %hex::encode(state_root.0),
            receipts_root = %hex::encode(execution.receipts_root.0),
            "block.committed"
        );
        Ok(())
    }
}
