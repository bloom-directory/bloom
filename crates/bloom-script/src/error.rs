//! Error variants for the PTB validation pipeline and executor.
//!
//! Every step of the validator (spec §7.2 steps 1–6) and the executor
//! (steps 7–10) maps to a distinct `PtbError` variant so receipts can
//! pinpoint the failure cause without inspecting logs.

use bloom_chain_types::Hash32;
use bloom_objects::{AccessMode, CodecError, ObjectId};
use thiserror::Error;

/// Errors returned by the PTB validator and executor.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PtbError {
    // -------------------------------------------------------------------
    // Codec / structural
    // -------------------------------------------------------------------
    /// Underlying canonical-codec failure (length overflow, unexpected
    /// EOF, invalid discriminant, ...).
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),

    // -------------------------------------------------------------------
    // Step 1: signature
    // -------------------------------------------------------------------
    /// The `signers` vector was empty.
    #[error("PTB has no signers")]
    NoSigners,
    /// The `signatures` length did not match `signers.len()`.
    #[error("signature count {got} does not match signer count {expected}")]
    SignatureCountMismatch {
        /// Expected signature count.
        expected: usize,
        /// Actual signature count.
        got: usize,
    },
    /// At least one signature failed cryptographic verification.
    #[error("signature verification failed for signer index {signer_idx}")]
    BadSignature {
        /// Zero-based index of the failing signer.
        signer_idx: u16,
    },

    // -------------------------------------------------------------------
    // Step 2: expiry
    // -------------------------------------------------------------------
    /// `current_block > expiry_block`.
    #[error("PTB expired (current_block {current_block} > expiry_block {expiry_block})")]
    Expired {
        /// Block height the validator saw.
        current_block: u64,
        /// `expiry_block` field declared in the PTB.
        expiry_block: u64,
    },

    // -------------------------------------------------------------------
    // Step 3: petal resolution
    // -------------------------------------------------------------------
    /// A `PetalRef` lacked the required `hash` pin (v0 requires it).
    #[error("petal at path {path} is not pinned (hash missing) — required in v0")]
    PetalNotPinned {
        /// The VFS path that was unpinned.
        path: String,
    },
    /// The requested petal hash was unknown to the chain.
    #[error("petal not found: hash {hash}")]
    PetalNotFound {
        /// Content hash that was looked up.
        hash: Hash32,
    },
    /// The `path` in a `PetalRef` did not resolve to the pinned `hash`
    /// (the VFS commits a different hash to the same path).
    #[error("petal path/hash mismatch at {path}: expected {expected}, found {found}")]
    PetalPathHashMismatch {
        /// VFS path queried.
        path: String,
        /// Hash declared in the PTB.
        expected: Hash32,
        /// Hash actually bound at the path.
        found: Hash32,
    },

    // -------------------------------------------------------------------
    // Step 4: function-signature typecheck
    // -------------------------------------------------------------------
    /// Function name was not in the petal's manifest.
    #[error("unknown function {function} in petal {petal_hash}")]
    UnknownFunction {
        /// Looked-up function name.
        function: String,
        /// Petal hash whose manifest was searched.
        petal_hash: Hash32,
    },
    /// `type_args.len()` did not match `type_params.len()`.
    #[error("type-arg count mismatch for {function}: expected {expected}, got {got}")]
    TypeArgCountMismatch {
        /// Function name.
        function: String,
        /// Declared count.
        expected: usize,
        /// Provided count.
        got: usize,
    },
    /// Provided arg list length did not match declared arg count.
    #[error("arg count mismatch for {function}: expected {expected}, got {got}")]
    ArgCountMismatch {
        /// Function name.
        function: String,
        /// Declared count.
        expected: usize,
        /// Provided count.
        got: usize,
    },
    /// A specific `Arg` did not match the declared `ArgKind` at the
    /// same index (e.g. `Signer` passed where `Const` expected).
    #[error("arg type mismatch at index {arg_idx} of {function}: {reason}")]
    TypeMismatch {
        /// Function name.
        function: String,
        /// Zero-based arg index.
        arg_idx: usize,
        /// Diagnostic message.
        reason: String,
    },

    // -------------------------------------------------------------------
    // Step 5: object version + access
    // -------------------------------------------------------------------
    /// `Arg::Object` referenced an `ObjectId` not present in the store.
    #[error("object {id} not found")]
    ObjectNotFound {
        /// Looked-up object id.
        id: ObjectId,
    },
    /// Object's stored `version` did not match the declared
    /// `expected_version`.
    #[error("object {id} version mismatch: expected {expected}, found {found}")]
    ObjectVersionMismatch {
        /// Object id.
        id: ObjectId,
        /// Caller-declared expected version.
        expected: u64,
        /// Version observed on chain.
        found: u64,
    },
    /// The requested `access_mode` is forbidden for the object's owner
    /// kind (e.g. `Mutable` on `Owner::Immutable`).
    #[error("access denied for object {id} (mode {mode:?}): {reason}")]
    AccessDenied {
        /// Object id.
        id: ObjectId,
        /// Requested access mode.
        mode: AccessMode,
        /// Diagnostic message.
        reason: String,
    },

    // -------------------------------------------------------------------
    // Step 6: gas
    // -------------------------------------------------------------------
    /// `gas_payer` was not a `Coin<LOOM>` owned by `Address(first_signer)`,
    /// or the coin's value did not cover `gas_budget * gas_price`.
    #[error("insufficient gas: need {needed}, payer has {available}")]
    InsufficientGas {
        /// Required amount in bloomweis.
        needed: u128,
        /// Available balance in the payer coin.
        available: u128,
    },
    /// `gas_budget * gas_price` cannot be represented exactly.
    #[error("gas reservation overflow: gas_budget {gas_budget} * gas_price {gas_price}")]
    GasReservationOverflow {
        /// Inner PTB gas budget.
        gas_budget: u64,
        /// Inner PTB gas price.
        gas_price: u128,
    },
    /// The `gas_payer` object exists but is not a `Coin<LOOM>` (wrong
    /// `type_tag`) or is owned by someone other than the first signer.
    #[error("invalid gas-payer object {id}: {reason}")]
    InvalidGasPayer {
        /// Gas-payer object id.
        id: ObjectId,
        /// Diagnostic message.
        reason: String,
    },

    // -------------------------------------------------------------------
    // Steps 7–10: execution
    // -------------------------------------------------------------------
    /// A `Use(cmd_idx, ret_idx)` referenced a command that has not
    /// executed yet, or a return slot that does not exist.
    #[error("dangling Use({cmd_idx}, {ret_idx})")]
    DanglingUse {
        /// Referenced command index.
        cmd_idx: u16,
        /// Referenced return slot.
        ret_idx: u16,
    },
    /// A `ReadOnly` borrow's payload was mutated during command execution.
    #[error("illegal mutation of read-only object {id} in command {cmd_idx}")]
    IllegalMutation {
        /// Object whose ReadOnly row went dirty.
        id: ObjectId,
        /// Command that mutated it.
        cmd_idx: u16,
    },
    /// One or more transient rows were left in the borrow table at
    /// tx-end without being consumed, transferred, shared, frozen, or
    /// deleted (spec §4.4).
    #[error("linearity violation: {orphans} orphan(s) at tx-end")]
    LinearityViolation {
        /// Number of orphans.
        orphans: usize,
        /// The orphaned object ids (truncated to first 8 in receipts).
        ids: Vec<ObjectId>,
    },
    /// A petal invariant returned `0` (not ok).
    #[error("invariant {name} failed in command {cmd_idx}")]
    InvariantFailed {
        /// Command that triggered the invariant.
        cmd_idx: u16,
        /// Invariant name from the manifest.
        name: String,
    },
    /// A petal call exhausted the per-command fuel budget.
    #[error("out of fuel in command {cmd_idx}: limit {limit}, used {used}")]
    OutOfFuel {
        /// Command index.
        cmd_idx: u16,
        /// Fuel limit allocated to the command.
        limit: u64,
        /// Fuel that was consumed.
        used: u64,
    },
    /// A petal call returned a non-zero abort code.
    #[error("petal abort in command {cmd_idx}: code {code}")]
    PetalAbort {
        /// Command index.
        cmd_idx: u16,
        /// Petal-defined abort code.
        code: i32,
        /// Fuel consumed before the abort.
        fuel_used: u64,
    },
    /// Built-in command failed (split/merge type mismatch, transfer to
    /// invalid owner, ...).
    #[error("built-in command {cmd_idx} failed: {reason}")]
    BuiltinFailed {
        /// Command index.
        cmd_idx: u16,
        /// Diagnostic message.
        reason: String,
    },
}
