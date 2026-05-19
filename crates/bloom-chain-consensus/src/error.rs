//! Consensus error types.

use thiserror::Error;

/// Errors produced by the consensus engine.
#[derive(Debug, Error)]
pub enum ConsensusError {
    // --- Validator set errors ---
    #[error("validator set is empty")]
    EmptyValidatorSet,

    #[error("validator has zero voting power")]
    ZeroVotingPower,

    #[error("duplicate validator address: {0}")]
    DuplicateAddress(String),

    // --- Mempool errors ---
    #[error("signature verification failed")]
    InvalidSignature,

    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: u64, got: u64 },

    #[error("insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: u128, have: u128 },

    #[error("duplicate (sender, nonce) — fee too low to replace")]
    ReplaceFeeNotHigher,

    #[error("address mismatch: pubkey does not hash to sender")]
    AddressMismatch,

    // --- State machine errors ---
    #[error("vote is for wrong height (expected {expected}, got {got})")]
    WrongHeight { expected: u64, got: u64 },

    #[error("proposal is for wrong height or round")]
    WrongHeightOrRound,

    #[error("unknown validator: {0}")]
    UnknownValidator(String),
}
