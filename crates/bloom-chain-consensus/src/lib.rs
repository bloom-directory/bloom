//! `bloom-chain-consensus` — Tendermint-style BFT consensus engine for bloom-chain v0.
//!
//! # Overview
//!
//! This crate implements the consensus layer described in the bloom-chain design
//! spec (§9).  It is a pure state-transition library: it accepts events, produces
//! actions, and has no I/O of its own.  The node crate (`bloom-chain-node`)
//! drives it over the network.
//!
//! # Modules
//!
//! - [`validator_set`] — ordered validator set, quorum math, round-robin proposer selection.
//! - [`mempool`] — pending-tx pool with nonce ordering and replace-by-fee.
//! - [`verifier`] — `SigVerifier` trait; `NoopVerifier` / `RejectAllVerifier` for tests.
//! - [`state_machine`] — Tendermint propose/prevote/precommit/commit state machine.
//! - [`engine`] — top-level `ConsensusEngine` wiring all of the above.
//! - [`error`] — `ConsensusError` enum.

#![forbid(unsafe_code)]

pub mod auth;
pub mod engine;
pub mod error;
pub mod mempool;
pub mod round_validation;
pub mod signer;
pub mod state_machine;
pub mod tx_admission;
pub mod validator_set;
pub mod verifier;

// Convenience re-exports.
pub use auth::{verify_proposal_sig, verify_vote_sig};
pub use engine::ConsensusEngine;
pub use error::ConsensusError;
pub use mempool::Mempool;
pub use signer::{NoopSigner, Signer};
pub use state_machine::{Action, ConsensusState, Event, Step, TimeoutKind};
pub use validator_set::{Validator, ValidatorSet};
pub use verifier::{NoopVerifier, RejectAllVerifier, SigVerifier};
