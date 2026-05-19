//! Real chain-mode petal executor.
//!
//! Bridges `consensus_driver::PetalExecutor` to `bloom_petals::PetalVm::run_chain_call`.
//!
//! Handles the three tx kinds:
//! - `Transfer`: pure LOOM move (no VM invocation).
//! - `Deploy`: validate wasm → check address collision → stage code + account →
//!   invoke `init` via the chain VM → on success, commit snapshot writes and
//!   return the deploy address; on revert, drop writes.
//! - `Call`: load wasm by `code_hash` → forward value → invoke `call` via the
//!   chain VM → on success commit writes, on revert drop them.
//!
//! Snapshot semantics:
//! - `consensus_driver::apply_block` debits `max_fuel * fee_per_unit + value`
//!   from the sender at the `State` level *before* calling `execute_tx`. The
//!   snapshot we take here therefore already reflects that debit.
//! - The VM returns the (mutated) snapshot; we `.commit()` it into a `WriteSet`
//!   on success, or drop it on revert.

use bloom_chain_state::{Account, State};
use bloom_chain_types::{
    digest::{blake3_tagged, tags},
    receipt::Log,
    tx::{Tx, TxKind},
    types::{Address, Hash32},
};
use bloom_petals::{BlockCtx as PetalBlockCtx, ChainCallInput, ChainEntry, PetalVm};
use tracing::warn;

use crate::consensus_driver::{ExecOutput, PetalExecutor, empty_account};

/// Production chain-mode executor.
pub struct ChainPetalExecutor;

/// Domain-separated derivation of a contract instance address (spec §7.7).
///
///   instance_address = blake3(
///       "bloom-chain.v0.addr:" ||
///       "deploy:" || deployer || ":" || salt || ":" || petal_hash)
fn deploy_address(deployer: &Address, salt: &[u8; 32], petal_hash: &Hash32) -> Address {
    let mut h = blake3::Hasher::new();
    h.update(tags::ADDR.as_bytes());
    h.update(b"deploy:");
    h.update(&deployer.0);
    h.update(b":");
    h.update(salt);
    h.update(b":");
    h.update(&petal_hash.0);
    Address(*h.finalize().as_bytes())
}

fn petal_log_to_receipt_log(l: bloom_petals::LogEntry) -> Log {
    Log { address: l.address, topics: l.topics, data: l.data }
}

impl PetalExecutor for ChainPetalExecutor {
    fn execute_tx(
        &self,
        tx: &Tx,
        state: &mut State,
        block_number: u64,
        timestamp_ms: u64,
        _proposer: Address,
    ) -> ExecOutput {
        // TODO: thread real parent_hash through the executor signature.
        let parent_hash = Hash32([0u8; 32]);
        let block_ctx = PetalBlockCtx { number: block_number, timestamp_ms, prevhash: parent_hash };

        match &tx.kind {
            TxKind::Transfer { to, amount_loom } => {
                // Pure LOOM move — no VM invocation required.
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

            TxKind::Deploy { wasm, salt, init_args } => {
                if let Err(e) = PetalVm::validate_for_chain(wasm) {
                    return ExecOutput {
                        success: false,
                        fuel_used: 0,
                        return_data: format!("invalid wasm: {e}").into_bytes(),
                        logs: vec![],
                        write_set: None,
                    };
                }

                let petal_hash = blake3_tagged(tags::PETAL, wasm);
                let addr = deploy_address(&tx.sender, salt, &petal_hash);

                // Collision: address already deployed (§7.7).
                if let Some(a) = state.get_account(&addr)
                    && a.code_hash.is_some()
                {
                    return ExecOutput {
                        success: false,
                        fuel_used: 0,
                        return_data: b"deploy address already in use".to_vec(),
                        logs: vec![],
                        write_set: None,
                    };
                }

                // Stage account + code in the snapshot; invoke init.
                let mut snap = state.snapshot();
                snap.insert_code(wasm.clone());
                let mut acct = snap.get_account(&addr).unwrap_or_else(empty_account);
                acct.code_hash = Some(petal_hash);
                snap.set_account(addr, acct);

                let input = ChainCallInput {
                    wasm: wasm.clone(),
                    entry: ChainEntry::Init,
                    contract_address: addr,
                    msg_sender: tx.sender,
                    msg_value: 0,
                    calldata: init_args.clone(),
                    block: block_ctx,
                    fuel: tx.max_fuel,
                    snapshot: snap,
                };

                match PetalVm::run_chain_call(input) {
                    Ok(out) => {
                        if let Some(reason) = out.revert_reason {
                            // Snapshot writes discarded.
                            ExecOutput {
                                success: false,
                                fuel_used: out.fuel_used,
                                return_data: reason,
                                logs: out.logs.into_iter().map(petal_log_to_receipt_log).collect(),
                                write_set: None,
                            }
                        } else {
                            let ws = out.snapshot.commit();
                            tracing::info!(
                                addr = %hex::encode(&addr.0),
                                fuel_used = out.fuel_used,
                                "deploy committed"
                            );
                            ExecOutput {
                                success: true,
                                fuel_used: out.fuel_used,
                                return_data: addr.0.to_vec(),
                                logs: out.logs.into_iter().map(petal_log_to_receipt_log).collect(),
                                write_set: Some(ws),
                            }
                        }
                    }
                    Err(e) => {
                        warn!(err = %e, "deploy trapped");
                        ExecOutput {
                            success: false,
                            fuel_used: tx.max_fuel,
                            return_data: e.to_string().into_bytes(),
                            logs: vec![],
                            write_set: None,
                        }
                    }
                }
            }

            TxKind::Call { to, calldata, value_loom } => {
                // Resolve callee: contract → load wasm; non-contract → value-transfer only.
                let callee = state.get_account(to);
                let code_hash = callee.as_ref().and_then(|a| a.code_hash);

                let wasm: Vec<u8> = match code_hash {
                    Some(ref h) => match state.get_code(h) {
                        Some(b) => b.to_vec(),
                        None => {
                            return ExecOutput {
                                success: false,
                                fuel_used: 0,
                                return_data: b"code missing for code_hash".to_vec(),
                                logs: vec![],
                                write_set: None,
                            };
                        }
                    },
                    None => {
                        // Pure value transfer (callee is an EOA).
                        let mut snap = state.snapshot();
                        if *value_loom > 0 {
                            let mut to_acct = snap.get_account(to).unwrap_or_else(empty_account);
                            to_acct.loom += value_loom;
                            snap.set_account(*to, to_acct);
                        }
                        return ExecOutput {
                            success: true,
                            fuel_used: 100,
                            return_data: vec![],
                            logs: vec![],
                            write_set: Some(snap.commit()),
                        };
                    }
                };

                // Pre-credit value to callee inside the snapshot.
                let mut snap = state.snapshot();
                if *value_loom > 0 {
                    let mut to_acct = snap.get_account(to).unwrap_or_else(empty_account);
                    to_acct.loom += value_loom;
                    snap.set_account(*to, to_acct);
                }

                let input = ChainCallInput {
                    wasm,
                    entry: ChainEntry::Call,
                    contract_address: *to,
                    msg_sender: tx.sender,
                    msg_value: *value_loom,
                    calldata: calldata.clone(),
                    block: block_ctx,
                    fuel: tx.max_fuel,
                    snapshot: snap,
                };

                match PetalVm::run_chain_call(input) {
                    Ok(out) => {
                        if let Some(reason) = out.revert_reason {
                            warn!(
                                to = %hex::encode(&to.0),
                                fuel_used = out.fuel_used,
                                reason = %String::from_utf8_lossy(&reason),
                                "call reverted"
                            );
                            ExecOutput {
                                success: false,
                                fuel_used: out.fuel_used,
                                return_data: reason,
                                logs: out.logs.into_iter().map(petal_log_to_receipt_log).collect(),
                                write_set: None,
                            }
                        } else {
                            let ws = out.snapshot.commit();
                            ExecOutput {
                                success: true,
                                fuel_used: out.fuel_used,
                                return_data: out.return_data.unwrap_or_default(),
                                logs: out.logs.into_iter().map(petal_log_to_receipt_log).collect(),
                                write_set: Some(ws),
                            }
                        }
                    }
                    Err(e) => {
                        warn!(to = %hex::encode(&to.0), err = %e, "call trapped");
                        ExecOutput {
                            success: false,
                            fuel_used: tx.max_fuel,
                            return_data: e.to_string().into_bytes(),
                            logs: vec![],
                            write_set: None,
                        }
                    }
                }
            }
        }
    }
}

// suppress unused-import lints when Account isn't needed in some configs
#[allow(dead_code)]
fn _typecheck() -> Option<Account> { None }
