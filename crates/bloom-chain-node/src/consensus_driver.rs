//! Consensus driver task.
//!
//! Owns a `ConsensusEngine<XdsaVerifier>` and a 1s tick interval.
//! - On `Action::Broadcast{...}`: sends via `PeerPool`.
//! - On `Action::Commit(block, commit)`: applies through `state::apply_block`.
//! - Bridges inbound frames from peers to the driver.
//! - Implements `SigVerifier` using xDSA composite verification.
//!
//! # PetalVm assumption
//!
//! The chain-mode petals API is assumed to follow `bloom_petals` spec §7.6:
//! ```ignore
//! PetalVm::new_chain(engine_cfg: ChainEngineCfg) -> PetalVm
//! vm.run_chain_call(ctx: ChainCallCtx, calldata: &[u8]) -> Result<ChainCallOutput>
//! ```
//! where `ChainCallOutput` contains `{ return_data, fuel_used, state_writes, logs, success }`.
//!
//! Because the `bloom-petals` chain-mode API is still in-flight, this module
//! references it through a `PetalExecutor` trait defined locally so that the
//! implementation can be swapped in once the final API shape is known.
//! TODO(adapter): reconcile PetalExecutor with actual bloom_petals chain-mode API.

use std::sync::Arc;

use anyhow::Result;
use bloom_chain_consensus::{
    Action, ConsensusEngine,
    auth::verify_vote_sig,
    signer::Signer,
    state_machine::TimeoutKind,
    validator_set::ValidatorSet,
    verifier::SigVerifier,
};
use bloom_chain_state::{Account, State, WriteSet};
use bloom_chain_types::{
    block::Block,
    digest::blake3_tagged,
    receipt::{Log, Receipt},
    tx::{Tx, TxKind},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
    vote::VoteKind,
};
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::{
    block_store::BlockStore,
    mempool_persist::MempoolPersist,
    receipt_store::ReceiptStore,
    state_blob::StateBlobStore,
    state_index::StateIndex,
    transport::PeerPool,
};

// ---------------------------------------------------------------------------
// PetalExecutor trait
// TODO(adapter): replace with actual bloom_petals chain-mode API.
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

/// Abstraction over the chain-mode petal VM.
///
/// TODO(adapter): the actual implementation will delegate to
/// `bloom_petals::PetalVm::run_chain_call(ctx, calldata)`.  The trait is
/// defined here so that the consensus driver compiles independently.
///
/// Assumed API shape:
/// ```ignore
/// // Create a chain-mode VM engine:
/// let vm = bloom_petals::PetalVm::new_chain(engine_cfg);
///
/// // Execute one tx:
/// let ctx = bloom_petals::ChainCallCtx {
///     block_number, timestamp_ms, proposer, sender, value_loom,
///     state_snapshot: &mut snap,
/// };
/// let out: ChainCallOutput = vm.run_chain_call(ctx, calldata)?;
/// // out.return_data, out.fuel_used, out.success, out.logs
/// ```
pub trait PetalExecutor: Send + Sync + 'static {
    /// Execute a single transaction.
    ///
    /// `parent_hash` is the committing block's parent block hash; it is
    /// surfaced inside the chain VM as `chain::block.prevhash`. At height 1
    /// it is the all-zero hash (genesis parent). See review 2026-05-19 #13.
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

/// A no-op executor that marks every tx as succeeded with zero fuel (for scaffolding / testing).
/// For Transfer txs it moves LOOM correctly without a petal VM.
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
        match &tx.kind {
            TxKind::Transfer { to, amount_loom } => {
                // Move LOOM from sender to recipient.
                let mut snap = state.snapshot();
                let mut to_acct = snap.get_account(to).unwrap_or_else(empty_account);
                to_acct.loom += amount_loom;
                snap.set_account(*to, to_acct);
                let ws = snap.commit();
                ExecOutput {
                    success: true,
                    fuel_used: 100,
                    return_data: vec![],
                    logs: vec![],
                    write_set: Some(ws),
                }
            }
            _ => ExecOutput {
                success: true,
                fuel_used: 0,
                return_data: vec![],
                logs: vec![],
                write_set: None,
            },
        }
    }
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
            // A vote that did not commit to this block can't count.
            continue;
        }
        if !tallied.insert(v.validator) {
            // Duplicate validator entry — ignore the duplicate but don't
            // double-count. Don't error; some chains repeat votes for liveness.
            continue;
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
        power = power.saturating_add(val.voting_power);
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
    let proposer = block.header.proposer;
    let height = block.header.height;
    let timestamp_ms = block.header.timestamp_ms;
    // Parent block hash — surfaced to chain-mode petals as
    // `chain::block.prevhash` (review 2026-05-19 #13).
    let parent_hash = block.header.parent_hash;

    let mut total_fuel_used: u64 = 0;
    let mut receipts: Vec<Receipt> = Vec::new();

    for tx in &block.txs {
        // 1. Verify sender derivation (cheap check before expensive xDSA).
        let expected_sender = Address::from_pubkey_bytes(&tx.pubkey.0);
        if expected_sender != tx.sender {
            receipts.push(Receipt {
                tx_hash: tx.tx_hash(),
                success: false,
                fuel_used: 0,
                return_data: b"sender mismatch".to_vec(),
                logs: vec![],
            });
            continue;
        }

        // 2. Nonce check — tx.nonce must equal sender.nonce + 1 (strict
        //    next-nonce ordering).  Without this, a tx accidentally
        //    re-included in a later block would silently re-apply.
        let sender_acct = state.get_account(&tx.sender);
        let current_nonce = sender_acct.as_ref().map(|a| a.nonce).unwrap_or(0);
        if tx.nonce != current_nonce + 1 {
            receipts.push(Receipt {
                tx_hash: tx.tx_hash(),
                success: false,
                fuel_used: 0,
                return_data: format!(
                    "nonce mismatch: tx.nonce={} expected={}",
                    tx.nonce,
                    current_nonce + 1
                )
                .into_bytes(),
                logs: vec![],
            });
            continue;
        }

        // 3. Max-fee reservation.
        let max_fee = tx.max_fuel as u128 * tx.fee_per_unit as u128;
        let value = match &tx.kind {
            TxKind::Call { value_loom, .. } => *value_loom,
            TxKind::Transfer { amount_loom, .. } => *amount_loom,
            TxKind::Deploy { .. } => 0,
            // PTBs (spec §16.1) do not carry a legacy-level LOOM value;
            // the petal executor handles gas/value flow at PTB dispatch.
            TxKind::SubmitPtb { .. } => 0,
        };
        let required = max_fee + value;
        let balance = sender_acct.as_ref().map(|a| a.loom).unwrap_or(0);
        if balance < required {
            receipts.push(Receipt {
                tx_hash: tx.tx_hash(),
                success: false,
                fuel_used: 0,
                return_data: b"insufficient balance".to_vec(),
                logs: vec![],
            });
            continue;
        }

        // Debit max-fee reservation.
        {
            let mut acct = sender_acct.unwrap_or_else(empty_account);
            acct.loom -= required;
            acct.nonce += 1;
            state.set_account(tx.sender, acct);
        }

        // 4. Execute via PetalExecutor.
        let output = executor.execute_tx(tx, state, height, timestamp_ms, proposer, parent_hash);

        // 5. Settle fuel and fees.
        let fuel_refund = tx.max_fuel.saturating_sub(output.fuel_used);
        let fee_refund = fuel_refund as u128 * tx.fee_per_unit as u128;
        let fee_earned = output.fuel_used as u128 * tx.fee_per_unit as u128;

        if output.success {
            // Apply write_set FIRST. `WriteSet` carries absolute
            // post-execution account values (see
            // `bloom_chain_state::state::AccountDelta::Set`), so applying
            // it AFTER fee/refund settlement would clobber the proposer
            // credit or sender refund whenever the executor's snapshot
            // touched those accounts (e.g. transfer-to-self,
            // recipient-is-proposer, sender-is-proposer). The snapshot
            // already reflects the pre-execution max-fee debit, so
            // settling on top of the post-write_set balance produces the
            // same numbers minus the clobber hazard. Review 2026-05-19 #5.
            if let Some(ws) = output.write_set {
                if let Err(e) = state.apply(ws) {
                    warn!(err = %e, "apply write_set failed");
                }
            }

            // Refund unused fuel.
            let mut sender = state.get_account(&tx.sender).unwrap_or_else(empty_account);
            sender.loom += fee_refund;
            state.set_account(tx.sender, sender);

            // Credit fee to proposer. Re-read after the refund so a
            // sender-is-proposer tx sees the refund in its base.
            let mut prop = state.get_account(&proposer).unwrap_or_else(empty_account);
            prop.loom += fee_earned;
            state.set_account(proposer, prop);
        } else {
            // Full max-fee forfeited to proposer (spec §6.4 step 5).
            let mut prop = state.get_account(&proposer).unwrap_or_else(empty_account);
            prop.loom += max_fee;
            state.set_account(proposer, prop);
            // Value refunded to sender.
            let mut sender = state.get_account(&tx.sender).unwrap_or_else(empty_account);
            sender.loom += value;
            state.set_account(tx.sender, sender);
        }

        total_fuel_used += output.fuel_used;

        receipts.push(Receipt {
            tx_hash: tx.tx_hash(),
            success: output.success,
            fuel_used: output.fuel_used,
            logs: output.logs,
            return_data: output.return_data,
        });
    }

    // 6. LOOM block emission (spec §11.1).
    {
        let mut prop = state.get_account(&proposer).unwrap_or_else(empty_account);
        prop.loom += block_emission;
        state.set_account(proposer, prop);
    }

    (total_fuel_used, receipts)
}

// ---------------------------------------------------------------------------
// Default-like helper for Account
// ---------------------------------------------------------------------------

/// Return an empty account (nonce=0, loom=0, no code, zero storage_root,
/// no manifest anchor).
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
        let parent =
            self.expected_parent_hash(expected_height).map_err(|e| e.to_string())?;
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
        // Hold the state lock continuously through state-transition + root
        // computation so concurrent readers (block builder, RPC) cannot
        // observe a partially-applied block. The persistence I/O after the
        // guard drops is keyed by `state_root`, which is now stable.
        let (total_fuel_used, receipts, state_root) = {
            let mut state = self.state.lock();
            let (fuel, recs) = apply_block_state_transitions(
                &mut state,
                self.executor.as_ref(),
                block,
                self.block_emission,
            );
            let root = state.state_root();
            (fuel, recs, root)
        };

        // Persist block and update indices.
        let blob_data = serde_json::to_vec(&hex::encode(&state_root.0)).unwrap_or_default();
        let blob_hash = self.blob_store.put(&blob_data)?;
        self.state_index.put(height, &state_root, &blob_hash)?;
        self.block_store.put(height, block)?;
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
            state_root = %hex::encode(&state_root.0),
            "block.committed"
        );
        Ok(())
    }
}
