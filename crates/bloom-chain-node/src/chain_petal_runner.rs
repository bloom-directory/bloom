//! `ChainPetalRunner` — bridges `bloom_script::PetalRunner` (PTB
//! executor's wasm-call abstraction) to `bloom_petals::PetalVm` (the
//! real chain VM).
//!
//! # Lifetime
//!
//! One runner per PTB execution. The runner owns:
//! - An immutable map `Hash32 → wasm bytes` (cloned from the
//!   `ValidatedPtb.petals` the validator built upstream — using a
//!   `BTreeMap` for deterministic iteration in tests, but lookups are
//!   constant on hash bytes either way).
//! - An `Arc<Mutex<PtbHostCtx>>` shared with the chain-node executor
//!   wiring so the §16.2 host imports installed by `chain_vm.rs`
//!   mutate the same borrow table, logs, and host-created object state
//!   the `PtbExecutor` later drains.
//! - A `Mutex<StateSnapshot>` that threads the chain `WriteSet`
//!   through successive Move calls inside the same PTB. Between two
//!   adjacent `Command::Move` commands, any host-import mutations
//!   that landed on the snapshot inside call _i_ must be visible to
//!   call _i+1_.
//!
//! The chain-node executor takes ownership of the runner at the start
//! of the PTB, runs `PtbExecutor::execute`, then reclaims the final
//! snapshot via [`ChainPetalRunner::into_snapshot`] to fold into the
//! tx's write set.
//!
//! # Function name routing (spec §16.2)
//!
//! `bloom-resource-macros` emits one wasm export per `#[bloom::petal]`
//! function, named `__petal_<fn_name>`. The PTB executor passes the
//! bare `<fn_name>` through `PetalRunner::call`, and we prefix here.
//! Invariant exports (`__inv_<n>`) are already in their final wasm
//! form — `PetalRunner::call_invariant` receives the export name
//! directly so we don't add a second prefix.
//!
//! # Fuel / revert / trap semantics
//!
//! - `PetalVm::run_chain_call` returns `Ok(ChainCallOutput)` for both
//!   success and `petal.revert`; the only difference is whether
//!   `revert_reason.is_some()`. We surface a revert as
//!   `PtbError::PetalAbort { code: -1 }` so the executor rolls back
//!   the entire PTB. Trap / out-of-fuel surfaces as an `Err` from the
//!   chain VM and we translate to `PtbError::OutOfFuel` or
//!   `PtbError::PetalAbort` accordingly.
//! - Snapshot threading: on success we install the returned snapshot
//!   back into the runner's `Mutex<StateSnapshot>` so the *next*
//!   `call()` sees the same chain state. On revert / trap we leave
//!   the snapshot at the pre-call checkpoint (cloned before the call)
//!   so the executor's own revert behaviour (drop everything) is
//!   semantically aligned.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bloom_chain_state::StateSnapshot;
use bloom_chain_types::{Hash32, types::Address};
use bloom_objects::TypeTag;
use bloom_petals::{BlockCtx, ChainCallInput, ChainEntry, PetalError, PetalVm};
use bloom_script::{
    PtbError,
    executor::{InvariantResult, PetalCallResult, PetalRunner},
    host_ctx::PtbHostCtx,
};

/// Real-chain implementation of [`PetalRunner`].
pub struct ChainPetalRunner {
    /// Petal wasm bytes keyed by content hash. Owned (not borrowed)
    /// so the runner can be `'static`-compatible with the dyn
    /// `PetalRunner` reference the executor holds.
    petals: BTreeMap<Hash32, Vec<u8>>,
    /// Per-PTB host context shared with the §16.2 host imports.
    ctx: Arc<Mutex<PtbHostCtx>>,
    /// Threaded chain snapshot. Each successful `call()` swaps the
    /// returned snapshot back into here so the next call sees it.
    snapshot: Mutex<Option<StateSnapshot>>,
    /// Block-level context retained for receipt/execution metadata.
    block: BlockCtx,
    /// The PTB's first-signer address, retained as dispatch metadata.
    msg_sender: Address,
}

impl ChainPetalRunner {
    /// Construct a runner.
    ///
    /// - `petals` — the `ValidatedPtb.petals` map (keys are
    ///   `[u8;32]`; we re-key on `Hash32` here).
    /// - `ctx` — the host-context handle shared with the chain VM's
    ///   §16.2 imports.
    /// - `snapshot` — the initial chain snapshot. Threaded through
    ///   successive Move calls inside this PTB.
    /// - `block` — block-level context (number / timestamp / prevhash).
    /// - `msg_sender` — first signer address for dispatch metadata.
    pub fn new(
        petals: BTreeMap<Hash32, Vec<u8>>,
        ctx: Arc<Mutex<PtbHostCtx>>,
        snapshot: StateSnapshot,
        block: BlockCtx,
        msg_sender: Address,
    ) -> Self {
        Self {
            petals,
            ctx,
            snapshot: Mutex::new(Some(snapshot)),
            block,
            msg_sender,
        }
    }

    /// Convert from the validator's `[u8;32]`-keyed petals map.
    pub fn petals_from_validated(
        map: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    ) -> BTreeMap<Hash32, Vec<u8>> {
        map.iter().map(|(k, v)| (Hash32(*k), v.clone())).collect()
    }

    /// Consume the runner and return the final snapshot. Used by the
    /// chain-node executor to fold the per-PTB writes into the tx's
    /// `WriteSet`.
    pub fn into_snapshot(self) -> StateSnapshot {
        self.snapshot
            .into_inner()
            .expect("ChainPetalRunner snapshot mutex poisoned")
            .expect("ChainPetalRunner snapshot already consumed")
    }

    /// Common dispatch: prepare a `ChainCallInput`, run it, splice
    /// the returned snapshot back into `self.snapshot`, and translate
    /// outcomes to `PtbError`.
    fn dispatch(
        &self,
        petal_hash: &Hash32,
        export_name: String,
        calldata: Vec<u8>,
        fuel_budget: u64,
    ) -> Result<PetalCallResult, PtbError> {
        let wasm = self
            .petals
            .get(petal_hash)
            .ok_or(PtbError::PetalNotFound { hash: *petal_hash })?
            .clone();

        // Update the host context's `current_petal_hash` so §16.2
        // imports can attribute log emissions / enforce the
        // type-defining-petal rule for `object.create`.
        {
            let mut ctx = self.ctx.lock().expect("PtbHostCtx mutex poisoned");
            ctx.current_petal_hash = *petal_hash;
        }

        // Snapshot threading: pull the current chain snapshot out of
        // the runner. On success we install the post-call snapshot
        // back here; on revert / trap we restore the pre-call clone
        // so the executor's rollback semantics align.
        let mut snap_slot = self.snapshot.lock().expect("snapshot mutex poisoned");
        let pre_call = snap_slot.take().expect("ChainPetalRunner snapshot missing");
        let checkpoint = pre_call.clone();

        let input = ChainCallInput {
            wasm,
            entry: ChainEntry::Function(export_name),
            // contract_address is the petal's own address. PTB mode has no
            // first-class callee account, so we derive a stable metadata
            // address from the petal hash.
            contract_address: Address(petal_hash.0),
            msg_sender: self.msg_sender,
            msg_value: 0,
            calldata,
            block: self.block.clone(),
            fuel: fuel_budget,
            snapshot: pre_call,
            ptb_ctx: Some(Arc::clone(&self.ctx)),
        };

        match PetalVm::run_chain_call(input) {
            Ok(out) => {
                if let Some(reason) = out.revert_reason {
                    // Revert: drop the snapshot the VM mutated, restore
                    // the pre-call checkpoint, and surface as PetalAbort.
                    *snap_slot = Some(checkpoint);
                    let _ = reason; // reason is not carried in PtbError today
                    Err(PtbError::PetalAbort {
                        cmd_idx: 0,
                        code: -1,
                        fuel_used: out.fuel_used,
                    })
                } else {
                    // Success: install the post-call snapshot so the
                    // next Move call sees this call's chain-state
                    // mutations.
                    *snap_slot = Some(out.snapshot);
                    Ok(PetalCallResult {
                        ret_buf: out.return_data.unwrap_or_default(),
                        fuel_used: out.fuel_used,
                    })
                }
            }
            Err(e) => {
                // Trap / OOF: restore checkpoint; surface OutOfFuel if
                // the trap looks fuel-related, otherwise PetalAbort.
                //
                // wasmtime's fuel-exhaustion trap formats variously
                // depending on the version: "all fuel consumed by
                // WebAssembly", "out of fuel", or Debug-formatted as
                // `Trap(OutOfFuel)`. We accept any of those substrings
                // (case-insensitive) so the runner translates fuel
                // exhaustion into `PtbError::OutOfFuel` regardless of
                // which spelling the engine surfaces.
                *snap_slot = Some(checkpoint);
                let trap_fuel_used = match &e {
                    PetalError::ChainCallTrap { fuel_used, .. } => *fuel_used,
                    _ => fuel_budget,
                };
                let msg = e.to_string().to_lowercase();
                if msg.contains("out of fuel")
                    || msg.contains("outoffuel")
                    || msg.contains("all fuel consumed")
                    || msg.contains("fuel exhausted")
                {
                    Err(PtbError::OutOfFuel {
                        cmd_idx: 0,
                        limit: fuel_budget,
                        used: trap_fuel_used,
                    })
                } else {
                    Err(PtbError::PetalAbort {
                        cmd_idx: 0,
                        code: -2,
                        fuel_used: trap_fuel_used,
                    })
                }
            }
        }
    }
}

fn calldata_with_type_args(type_args: &[TypeTag], args_buf: &[u8]) -> Result<Vec<u8>, PtbError> {
    if type_args.is_empty() {
        return Ok(args_buf.to_vec());
    }
    if args_buf.len() < 4 {
        return Err(PtbError::BuiltinFailed {
            cmd_idx: 0,
            reason: "malformed PTB calldata: missing arg count".to_string(),
        });
    }

    let positional_count =
        u32::from_be_bytes(args_buf[..4].try_into().expect("slice length checked"));
    let type_count: u32 = type_args
        .len()
        .try_into()
        .map_err(|_| PtbError::BuiltinFailed {
            cmd_idx: 0,
            reason: "too many type args".to_string(),
        })?;
    let total =
        positional_count
            .checked_add(type_count)
            .ok_or_else(|| PtbError::BuiltinFailed {
                cmd_idx: 0,
                reason: "too many PTB args".to_string(),
            })?;

    let mut out = Vec::with_capacity(4 + type_args.len() * 8 + args_buf.len().saturating_sub(4));
    out.extend_from_slice(&total.to_be_bytes());
    for tag in type_args {
        out.push(4);
        let enc = tag.encode_canonical().map_err(PtbError::Codec)?;
        let len: u32 = enc.len().try_into().map_err(|_| PtbError::BuiltinFailed {
            cmd_idx: 0,
            reason: "TypeArg encoding too large".to_string(),
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&enc);
    }
    out.extend_from_slice(&args_buf[4..]);
    Ok(out)
}

impl PetalRunner for ChainPetalRunner {
    fn call(
        &self,
        petal_hash: &Hash32,
        function: &str,
        type_args: &[TypeTag],
        args_buf: &[u8],
        fuel_budget: u64,
    ) -> Result<PetalCallResult, PtbError> {
        // PTB-mode petals export `__petal_<fn_name>` per `bloom-resource-macros`.
        let export = format!("__petal_{function}");
        self.dispatch(
            petal_hash,
            export,
            calldata_with_type_args(type_args, args_buf)?,
            fuel_budget,
        )
    }

    fn call_invariant(
        &self,
        petal_hash: &Hash32,
        export_name: &str,
        scope_buf: &[u8],
        fuel_budget: u64,
    ) -> Result<InvariantResult, PtbError> {
        // Invariant exports are already in `__inv_<n>` form — pass
        // through unchanged.
        let result = self.dispatch(
            petal_hash,
            export_name.to_string(),
            scope_buf.to_vec(),
            fuel_budget,
        )?;
        // The invariant ABI is `() -> i32`; bloom-resource-macros
        // wraps it so the returned buffer's first byte is 1 (ok) or 0
        // (failed). An empty buffer is treated as failure (conservative).
        let ok = result.ret_buf.first().copied() == Some(1);
        Ok(InvariantResult {
            ok,
            fuel_used: result.fuel_used,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_chain_state::State;

    fn block_ctx() -> BlockCtx {
        BlockCtx {
            number: 1,
            timestamp_ms: 1_700_000_000_000,
            prevhash: Hash32([0u8; 32]),
        }
    }

    #[test]
    fn unknown_petal_hash_surfaces_petal_not_found() {
        let snap = State::new().snapshot();
        let ctx = Arc::new(Mutex::new(PtbHostCtx::new()));
        let runner =
            ChainPetalRunner::new(BTreeMap::new(), ctx, snap, block_ctx(), Address([0u8; 32]));
        let hash = Hash32([0xAB; 32]);
        let err = runner
            .call(&hash, "anything", &[], &[], 1_000_000)
            .unwrap_err();
        assert!(
            matches!(err, PtbError::PetalNotFound { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn into_snapshot_returns_initial_snapshot_when_no_calls_made() {
        let mut state = State::new();
        let mut acct = bloom_chain_state::Account::empty();
        acct.nonce = 7;
        state.set_account(Address([0x42; 32]), acct);
        let snap = state.snapshot();
        let ctx = Arc::new(Mutex::new(PtbHostCtx::new()));
        let runner =
            ChainPetalRunner::new(BTreeMap::new(), ctx, snap, block_ctx(), Address([0u8; 32]));
        let final_snap = runner.into_snapshot();
        // The snapshot must round-trip the account state we loaded.
        let acct = final_snap.get_account(&Address([0x42; 32])).unwrap();
        assert_eq!(acct.nonce, 7);
    }

    #[test]
    fn petals_from_validated_re_keys_hash32() {
        let mut input = std::collections::HashMap::new();
        input.insert([0x11u8; 32], vec![1, 2, 3]);
        input.insert([0x22u8; 32], vec![4, 5, 6]);
        let out = ChainPetalRunner::petals_from_validated(&input);
        assert_eq!(
            out.get(&Hash32([0x11; 32])).map(|v| v.as_slice()),
            Some([1, 2, 3].as_slice())
        );
        assert_eq!(
            out.get(&Hash32([0x22; 32])).map(|v| v.as_slice()),
            Some([4, 5, 6].as_slice())
        );
    }

    #[test]
    fn runner_calldata_prepends_type_args_before_positional_args() {
        let usdc = TypeTag::Concrete {
            petal_hash: [0x11; 32],
            type_name: "USDC".to_string(),
            type_args: vec![],
        };
        let mut positional = Vec::new();
        positional.extend_from_slice(&1u32.to_be_bytes());
        positional.push(1);
        positional.extend_from_slice(&16u32.to_be_bytes());
        positional.extend_from_slice(&42u128.to_be_bytes());

        let calldata = calldata_with_type_args(std::slice::from_ref(&usdc), &positional).unwrap();
        assert_eq!(u32::from_be_bytes(calldata[..4].try_into().unwrap()), 2);

        let mut cursor = &calldata[4..];
        assert_eq!(cursor[0], 4);
        cursor = &cursor[1..];
        let type_len = u32::from_be_bytes(cursor[..4].try_into().unwrap()) as usize;
        cursor = &cursor[4..];
        assert_eq!(
            TypeTag::decode_canonical(&cursor[..type_len]).unwrap(),
            usdc
        );
        cursor = &cursor[type_len..];
        assert_eq!(cursor[0], 1);
        cursor = &cursor[1..];
        let const_len = u32::from_be_bytes(cursor[..4].try_into().unwrap()) as usize;
        cursor = &cursor[4..];
        assert_eq!(const_len, 16);
        assert_eq!(&cursor[..const_len], &42u128.to_be_bytes());
        assert!(cursor[const_len..].is_empty());
    }
}
