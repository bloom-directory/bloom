//! `bloom-ptb-builder` — the front-door builder for Bloom-native PTBs.
//!
//! [`PtbSession`] turns an ordered list of `(endpoint-path, args,
//! use-edges)` into a **validated** [`bloom_script::types::PtbTx`]. It
//! is the single source of truth shared by both front doors:
//!
//! - the `tx` VFS handler (`/bloom/tx/...`, NFS read/write staging), and
//! - the `bloom pipe '<expr>'` CLI.
//!
//! Spec: `docs/superpowers/specs/2026-05-22-vfs-petal-pipes-defi-design.md`
//! (§3.2, §3.4, §3.5, §6 "Protocol").
//!
//! # Layers
//!
//! - [`resolver`] — endpoint `path -> (petal_hash, fn, abi)` over the
//!   existing `ChainStateIface::resolve_path` + `load_manifest` hooks
//!   (fails closed on unknown path / function).
//! - [`grammar`] — the §3.4 command-line grammar + arg lowering.
//! - [`literal`] — canonical encoding of `Const` literals + type-tag /
//!   id parsing.
//! - [`pipe`] — the §3.5 pipe-expression lowering (linear `|` +
//!   named `--a <(…)>` DAG edges) into command lines.
//! - [`session`] — [`PtbSession`]: incremental validation + the
//!   commit/sign seam for Phase D.
//!
//! # Commit / sign seam (Phase D)
//!
//! This crate has no node or keystore. [`PtbSession::build_unsigned`]
//! assembles a `PtbTx` (empty `signatures`) and runs the full
//! `bloom_script::validate_ptb`. Phase D then selects the gas payer
//! (`coin_select`), supplies signer pubkeys, signs
//! [`bloom_script::types::PtbTx::signing_digest`] via the keystore, and
//! submits through the node. The session exposes
//! [`PtbSession::set_signers`], [`PtbSession::set_gas_payer`],
//! [`PtbSession::set_gas`], [`PtbSession::set_expiry_block`], and
//! [`PtbSession::set_fungible_petal_hash`] as the injection seams.

pub mod error;
pub mod grammar;
pub mod literal;
pub mod pipe;
pub mod resolver;
pub mod session;

pub use error::{BuildError, ResolveError};
pub use grammar::{LoweredArg, ParsedLine, UseToken, lower_args, parse_line, parse_use_token};
pub use literal::{encode_const_literal, parse_id32, parse_type_tag};
pub use pipe::lower_pipe_expr;
pub use resolver::{ResolvedEndpoint, resolve_endpoint, split_endpoint_path};
pub use session::{CommandStatus, PtbSession, SessionId, SessionStatus};

#[cfg(test)]
mod tests;
