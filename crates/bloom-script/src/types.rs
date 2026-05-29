//! Wire types for the Programmable Transaction Block (PTB) — spec §7.1
//! and §9.4 and §10.
//!
//! The canonical encoder/decoder for each type lives in
//! [`crate::encode`]; the signing-digest helper in [`crate::hash`].
//! These types deliberately carry no behaviour beyond field accessors
//! so the wire shape is the only source of truth.

use bloom_chain_types::Hash32;
use bloom_objects::{AccessMode, ObjectId, Owner, TypeTag};

use crate::chain_iface::ChainStateIface;

// ---------------------------------------------------------------------------
// Cryptographic placeholders
// ---------------------------------------------------------------------------

/// Post-quantum public-key bytes. The actual xDSA composite-key format
/// is handled by `bloom-keystore`; the PTB wire format treats each
/// signer as a fixed 32-byte identifier (the PQ address derivative the
/// chain already uses).
///
/// TODO(phase-2): if the chain decides to embed full composite-key bytes
/// in PTBs (rather than addresses), widen this to a length-prefixed
/// blob. For now, a 32-byte signer slot keeps the wire compact and
/// matches the `Address` type the validator compares against the
/// gas-payer's `Owner::Address`.
pub type PqPubkey = [u8; 32];

/// Length-prefixed post-quantum signature. Opaque to this crate; the
/// actual verify logic is supplied via [`crate::validator::SignatureVerifier`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct PqSignature(
    /// Raw signature bytes.
    pub Vec<u8>,
);

// ---------------------------------------------------------------------------
// Versioning
// ---------------------------------------------------------------------------

/// Expected on-chain object version a PTB-level `Arg::Object`
/// references. Optimistic-concurrency anchor: if the chain's stored
/// `version` differs, the validator rejects the PTB before execution.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct ExpectedVersion(
    /// Big-endian-encoded `u64` on the wire.
    pub u64,
);

// ---------------------------------------------------------------------------
// Petal reference
// ---------------------------------------------------------------------------

/// Pinned (or path-only) reference to a deployed petal.
///
/// v0 requires `hash` to be present at validation time
/// ([`crate::error::PtbError::PetalNotPinned`] otherwise). Path is
/// retained for human-readable receipts and for v1's optional
/// resolution-policy path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct PetalRef {
    /// Virtual-file-system path the petal is published at, e.g.
    /// `"/bloom/petals/dex/pool"`.
    pub path: String,
    /// Content hash (`blake3` of the wasm bytes). Required in v0.
    pub hash: Option<Hash32>,
}

// ---------------------------------------------------------------------------
// Argument and command shapes
// ---------------------------------------------------------------------------

/// Reference to a return value produced by an earlier command in the
/// same PTB. Wire layout: two `u16` BE indices.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct UseRef {
    /// Index of the producing command (zero-based).
    pub cmd_idx: u16,
    /// Return-slot index within that command (zero-based).
    pub ret_idx: u16,
}

/// A single command argument.
///
/// Wire layout: 1-byte discriminant + variant payload (see
/// [`crate::encode`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arg {
    /// Reference to the `i`-th entry in `PtbTx.signers`.
    Signer(u16),
    /// Inline canonical-codec literal.
    Const(Vec<u8>),
    /// Pinned reference to an existing on-chain object.
    Object {
        /// Object identifier.
        id: ObjectId,
        /// Expected on-chain version (optimistic concurrency).
        expected_version: ExpectedVersion,
        /// Requested access mode.
        access_mode: AccessMode,
    },
    /// Use the `ret_idx`-th return value of the `cmd_idx`-th command.
    Use {
        /// Producing command's index.
        cmd_idx: u16,
        /// Return slot.
        ret_idx: u16,
    },
    /// Pass a type as a value (drives generic instantiation).
    TypeArg(TypeTag),
}

/// A `Move`-style call into a petal-defined function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoveCmd {
    /// Pinned petal reference.
    pub petal: PetalRef,
    /// Function name (no 4-byte selector — name-based dispatch).
    pub function: String,
    /// Generic instantiation.
    pub type_args: Vec<TypeTag>,
    /// Concrete argument list.
    pub args: Vec<Arg>,
}

/// PTB-level command that publishes a new petal under a VFS path
/// (spec §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishCmd {
    /// Wasm bytes to upload.
    pub wasm_bytes: Vec<u8>,
    /// VFS path to publish at.
    pub module_path: String,
    /// `OwnerCap<Path>` use-ref if the path already exists (then this
    /// is effectively a re-publish gated by the cap; rare in v0 — most
    /// re-publishes go through `UpgradePetal`).
    pub publisher_cap: Option<UseRef>,
}

/// PTB-level command that upgrades an existing petal (spec §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeCmd {
    /// Wasm bytes for the new version.
    pub wasm_bytes: Vec<u8>,
    /// VFS path being upgraded.
    pub module_path: String,
    /// Required `OwnerCap<Path>` borrow that authorises the upgrade.
    pub publisher_cap: UseRef,
}

/// PTB command (variant tag = 1-byte; see [`crate::encode`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Petal function call.
    Move(MoveCmd),
    /// New-petal publish.
    Publish(PublishCmd),
    /// Transfer one or more (transient) objects to `owner`.
    TransferObjects {
        /// Use-refs of the objects being transferred.
        uses: Vec<UseRef>,
        /// New owner.
        owner: Owner,
    },
    /// Merge a set of `Coin<T>` together (consumes all, produces one).
    MergeCoins(Vec<UseRef>),
    /// Split a `Coin<T>` into N new coins of the listed amounts.
    SplitCoins {
        /// Source coin (transient).
        src: UseRef,
        /// Amounts for the new coins.
        amounts: Vec<u128>,
    },
    /// Bundle a homogeneous vector of object-typed values for a later
    /// `Move` call that takes `vector<T>`.
    MakeMoveVec {
        /// Element type.
        ty: TypeTag,
        /// Use-refs of the elements.
        uses: Vec<UseRef>,
    },
    /// Upgrade an existing petal.
    UpgradePetal(UpgradeCmd),
}

/// Command-variant tag byte for `Command::Move`.
pub const TAG_CMD_MOVE: u8 = 0;
/// Command-variant tag byte for `Command::Publish`.
pub const TAG_CMD_PUBLISH: u8 = 1;
/// Command-variant tag byte for `Command::TransferObjects`.
pub const TAG_CMD_TRANSFER: u8 = 2;
/// Command-variant tag byte for `Command::MergeCoins`.
pub const TAG_CMD_MERGE: u8 = 3;
/// Command-variant tag byte for `Command::SplitCoins`.
pub const TAG_CMD_SPLIT: u8 = 4;
/// Command-variant tag byte for `Command::MakeMoveVec`.
pub const TAG_CMD_MAKE_VEC: u8 = 5;
/// Command-variant tag byte for `Command::UpgradePetal`.
pub const TAG_CMD_UPGRADE: u8 = 6;

/// Arg-variant tag byte for `Arg::Signer`.
pub const TAG_ARG_SIGNER: u8 = 0;
/// Arg-variant tag byte for `Arg::Const`.
pub const TAG_ARG_CONST: u8 = 1;
/// Arg-variant tag byte for `Arg::Object`.
pub const TAG_ARG_OBJECT: u8 = 2;
/// Arg-variant tag byte for `Arg::Use`.
pub const TAG_ARG_USE: u8 = 3;
/// Arg-variant tag byte for `Arg::TypeArg`.
pub const TAG_ARG_TYPEARG: u8 = 4;

// ---------------------------------------------------------------------------
// Top-level transaction
// ---------------------------------------------------------------------------

/// A Programmable Transaction Block.
///
/// Wire layout (in order, all big-endian):
/// 1. `signers` — `Vec<PqPubkey>` with `u32 BE` count + 32×N bytes.
/// 2. `commands` — `Vec<Command>` with `u32 BE` count + variant-tag-prefixed payloads.
/// 3. `gas_payer` — 32 bytes (ObjectId).
/// 4. `gas_budget` — 8 bytes BE.
/// 5. `gas_price` — 16 bytes BE.
/// 6. `expiry_block` — 8 bytes BE.
/// 7. `signatures` — `Vec<PqSignature>` with `u32 BE` count + per-signature `u32 BE` length + bytes.
///
/// [`crate::hash::ptb_hash`] hashes layout (1)..(6) only (signatures
/// excluded) under the `PTB_HASH` domain tag.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PtbTx {
    /// One entry per distinct signer (chain verifies one xDSA verify each).
    pub signers: Vec<PqPubkey>,
    /// Ordered command list.
    pub commands: Vec<Command>,
    /// `Coin<LOOM>` object that funds gas (spec §9.4).
    pub gas_payer: ObjectId,
    /// Maximum fuel the PTB may burn.
    pub gas_budget: u64,
    /// Price per fuel unit, in bloomweis (1 LOOM = 10^18 bloomweis).
    pub gas_price: u128,
    /// Latest block height at which this PTB is valid.
    pub expiry_block: u64,
    /// One signature per signer, in the same order. Empty for unsigned
    /// digest computation (see [`PtbTx::signing_digest`]).
    pub signatures: Vec<PqSignature>,
}

impl PtbTx {
    /// 32-byte digest that signers cover. Equivalent to:
    /// `blake3_tagged(PTB_HASH, canonical_encode(self_without_signatures))`.
    pub fn signing_digest(&self) -> [u8; 32] {
        crate::hash::ptb_hash(self)
    }

    /// Required gas reservation: `gas_budget * gas_price`.
    ///
    /// Returns `None` when the reservation cannot be represented exactly.
    /// Callers must reject such PTBs instead of silently capping the debit.
    pub fn checked_gas_reservation(&self) -> Option<u128> {
        (self.gas_budget as u128).checked_mul(self.gas_price)
    }
}

// ---------------------------------------------------------------------------
// Coin<LOOM> well-known type tag
// ---------------------------------------------------------------------------

/// Type-name string the chain uses to identify a `Coin<LOOM>` (the
/// outer `Coin<...>` half) — the actual `petal_hash` is supplied by
/// the genesis pipeline once `bloom-petal-fungible` publishes.
pub const COIN_TYPE_NAME: &str = "Coin";

/// Type-name string for the inner `LOOM` marker witness type.
pub const LOOM_TYPE_NAME: &str = "LOOM";

/// Canonical VFS path for the core fungible petal.
pub const CORE_FUNGIBLE_PATH: &str = "/bloom/petals/core/fungible";

/// Sentinel fungible-petal hash used before a chain pins
/// [`CORE_FUNGIBLE_PATH`] in VFS.
pub const DEFAULT_FUNGIBLE_PETAL_HASH: Hash32 = Hash32([0u8; 32]);

/// Resolve the fungible petal hash from chain VFS.
///
/// Callers that intentionally run in a bootstrap/test state with the
/// sentinel hash must bind [`CORE_FUNGIBLE_PATH`] to
/// [`DEFAULT_FUNGIBLE_PETAL_HASH`] explicitly. A missing binding is
/// therefore distinguishable from a deliberate sentinel binding.
pub fn resolve_fungible_petal_hash(chain: &dyn ChainStateIface) -> Option<Hash32> {
    chain.resolve_path(CORE_FUNGIBLE_PATH)
}

/// Build the canonical `Coin<LOOM>` type tag from the fungible
/// petal's content hash.
///
/// The chain calls this once at startup (or per-call until phase 2
/// pins it) to materialise the well-known type tag against which the
/// gas-payer object is compared (spec §9.4). Until
/// `bloom-petal-fungible` lands, callers in tests can pass
/// `[0u8; 32]` and feed the same constant into the [`crate::chain_iface::ChainStateIface`]
/// mock so the validator's comparison succeeds.
pub fn loom_coin_type_tag(fungible_petal_hash: Hash32) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: fungible_petal_hash.0,
        type_name: COIN_TYPE_NAME.to_string(),
        type_args: vec![TypeTag::Concrete {
            petal_hash: fungible_petal_hash.0,
            type_name: LOOM_TYPE_NAME.to_string(),
            type_args: vec![],
        }],
    }
}

/// Returns the `LOOM` marker TypeTag for a given fungible petal hash
/// (used by the executor when fabricating gas-refund coins).
pub fn loom_marker_type_tag(fungible_petal_hash: Hash32) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: fungible_petal_hash.0,
        type_name: LOOM_TYPE_NAME.to_string(),
        type_args: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_gas_reservation_rejects_overflow() {
        let tx = PtbTx {
            gas_budget: u64::MAX,
            gas_price: u128::MAX,
            ..PtbTx::default()
        };
        assert_eq!(tx.checked_gas_reservation(), None);
    }

    #[test]
    fn checked_gas_reservation_normal() {
        let tx = PtbTx {
            gas_budget: 100_000,
            gas_price: 7,
            ..PtbTx::default()
        };
        assert_eq!(tx.checked_gas_reservation(), Some(700_000u128));
    }

    #[test]
    fn loom_coin_type_tag_shape() {
        let t = loom_coin_type_tag(Hash32([0u8; 32]));
        match t {
            TypeTag::Concrete {
                type_name,
                type_args,
                ..
            } => {
                assert_eq!(type_name, "Coin");
                assert_eq!(type_args.len(), 1);
                match &type_args[0] {
                    TypeTag::Concrete { type_name, .. } => assert_eq!(type_name, "LOOM"),
                    _ => panic!("inner type tag should be Concrete LOOM"),
                }
            }
            _ => panic!("outer type tag should be Concrete Coin<LOOM>"),
        }
    }
}
