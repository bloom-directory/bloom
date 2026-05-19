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
    state_machine::TimeoutKind,
    verifier::SigVerifier,
};
use bloom_chain_state::{Account, State, WriteSet};
use bloom_chain_types::{
    block::Block,
    receipt::{Log, Receipt},
    tx::{Tx, TxKind},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
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
    fn execute_tx(
        &self,
        tx: &Tx,
        state: &mut State,
        block_number: u64,
        timestamp_ms: u64,
        proposer: Address,
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
// Default-like helper for Account
// ---------------------------------------------------------------------------

/// Return an empty account (nonce=0, loom=0, no code, zero storage_root).
pub(crate) fn empty_account() -> Account {
    Account {
        nonce: 0,
        loom: 0,
        code_hash: None,
        storage_root: Hash32([0u8; 32]),
    }
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
    /// Apply a committed block to state (spec §6.4, §11).
    pub fn apply_block(&self, block: &Block) -> Result<()> {
        let mut state = self.state.lock();
        let proposer = block.header.proposer;
        let height = block.header.height;
        let timestamp_ms = block.header.timestamp_ms;

        let mut total_fuel_used: u64 = 0;
        let mut receipts: Vec<Receipt> = Vec::new();

        for tx in &block.txs {
            // 1. Verify sender derivation (cheap check before expensive xDSA).
            let expected_sender = {
                let mut h = blake3::Hasher::new();
                h.update(b"bloom-chain.v0.addr:");
                h.update(&tx.pubkey.0);
                let out = *h.finalize().as_bytes();
                Address(out)
            };
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

            // 3. Execute via PetalExecutor.
            let output = self.executor.execute_tx(tx, &mut *state, height, timestamp_ms, proposer);

            // 4. Settle fuel and fees.
            let fuel_refund = tx.max_fuel.saturating_sub(output.fuel_used);
            let fee_refund = fuel_refund as u128 * tx.fee_per_unit as u128;
            let fee_earned = output.fuel_used as u128 * tx.fee_per_unit as u128;

            if output.success {
                // Refund unused fuel.
                let mut sender = state.get_account(&tx.sender).unwrap_or_else(empty_account);
                sender.loom += fee_refund;
                state.set_account(tx.sender, sender);

                // Credit fee to proposer.
                let mut prop = state.get_account(&proposer).unwrap_or_else(empty_account);
                prop.loom += fee_earned;
                state.set_account(proposer, prop);

                // Apply write set.
                if let Some(ws) = output.write_set {
                    if let Err(e) = state.apply(ws) {
                        warn!(err = %e, "apply write_set failed");
                    }
                }
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

        // 5. LOOM block emission (spec §11.1).
        {
            let mut prop = state.get_account(&proposer).unwrap_or_else(empty_account);
            prop.loom += self.block_emission;
            state.set_account(proposer, prop);
        }

        // 6. Persist block and update indices.
        let state_root = state.state_root();
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
