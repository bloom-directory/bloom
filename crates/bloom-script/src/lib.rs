//! Programmable Transaction Block (PTB) wire types, canonical codec,
//! validator, and executor library for Bloom-native contracts.
//!
//! This crate is the third foundation crate of the Bloom-native
//! contract framework, after [`bloom_objects`] (object model) and
//! [`bloom_resource`] (guest-side runtime). It defines:
//!
//! - **Wire types** ([`types`]) — [`PtbTx`], [`Command`], [`Arg`],
//!   [`MoveCmd`], [`PetalRef`], [`UseRef`], [`PqPubkey`],
//!   [`PqSignature`], [`ExpectedVersion`].
//! - **Canonical codec** ([`encode`]) — deterministic encode/decode of
//!   the wire types (BE primitives, length-prefixed byte/string/vec,
//!   1-byte enum discriminants). Spec §10.
//! - **Signing digest** ([`hash::ptb_hash`]) — domain-tagged BLAKE3
//!   hash over a PTB's encoded body (signature-exclusive).
//! - **Chain interface** ([`chain_iface`]) — narrow [`ChainStateIface`]
//!   trait + manifest stubs that decouple the validator/executor from
//!   the real chain state crate.
//! - **Borrow table** ([`borrow_table`]) — per-tx tracking of every
//!   object touched by a PTB; powers the diff-check and linearity
//!   check (spec §4.4).
//! - **Validator** ([`validator`]) — pre-execution typecheck +
//!   access-mode + signature + gas check (spec §7.2 steps 1–6).
//! - **Executor** ([`executor`]) — sequential command dispatch with
//!   borrow-table bookkeeping, invariants, and atomic revert on any
//!   failure (spec §7.2 steps 7–10).
//!
//! Phase 1 (this crate): library only. Chain wiring lives in Phase 2
//! when `TxKind::SubmitPtb` is added to `bloom-chain-types`.
//!
//! [`PtbTx`]: types::PtbTx
//! [`Command`]: types::Command
//! [`Arg`]: types::Arg
//! [`MoveCmd`]: types::MoveCmd
//! [`PetalRef`]: types::PetalRef
//! [`UseRef`]: types::UseRef
//! [`PqPubkey`]: types::PqPubkey
//! [`PqSignature`]: types::PqSignature
//! [`ExpectedVersion`]: types::ExpectedVersion
//! [`ChainStateIface`]: chain_iface::ChainStateIface

#![deny(missing_docs)]

pub mod abi_json;
pub mod borrow_table;
pub mod chain_iface;
pub mod encode;
pub mod error;
pub mod executor;
pub mod hash;
pub mod host_ctx;
pub mod types;
pub mod validator;

pub use abi_json::{
    JsonAbiError, decode_json_const, decode_json_type_tag, decode_return_json, encode_type_tag_json,
};
pub use borrow_table::{BorrowRow, BorrowTable, RowState};
pub use chain_iface::{
    ArgDeclStub, ChainStateIface, ExternalTypeRefStub, FunctionDeclStub, InvariantDeclStub,
    ObjectTypeDeclStub, PetalManifestStub, TypeParamDeclStub,
};
pub use encode::{decode_ptb, encode_ptb};
pub use error::PtbError;
pub use executor::{
    ExecutionReport, InvariantResult, LogEntry, PetalCallResult, PetalPublishEvent, PetalRunner,
    PtbExecutor,
};
pub use hash::{PTB_HASH_TAG, ptb_hash};
pub use host_ctx::{HandleEntry, PtbHostCtx};
pub use types::{
    Arg, CORE_FUNGIBLE_PATH, Command, DEFAULT_FUNGIBLE_PETAL_HASH, ExpectedVersion, MoveCmd,
    PetalRef, PqPubkey, PqSignature, PtbTx, PublishCmd, UpgradeCmd, UseRef, loom_coin_type_tag,
    loom_marker_type_tag, resolve_fungible_petal_hash,
};
pub use validator::{
    AlwaysOkVerifier, SignatureVerifier, ValidatedPtb, ValidationContext, ValidationMode,
    validate_ptb,
};
