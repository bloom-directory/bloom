//! Solana-native transaction engine: durable outbox and reconciliation.
//!
//! The in-tree analogue of `bloom-tx` for Solana, on the new Signer+Broker
//! custody triad. It mirrors `bloom-tx`'s durable-state pattern exactly —
//! `<home>/outbox/<wallet>/<chain>/{pending,sent,failed}/<id>/` with a
//! write-once `intent.json`, a `receipt.json` mined-outcome sibling, and
//! broadcast-attempt markers — but every field is Solana-typed (base58 keys,
//! lamports, blockhash / `lastValidBlockHeight`), never `alloy`.
//!
//! This crate currently ships the *durable-state* half only: staging,
//! transitions, and the reconciliation polling loop. Signing and broadcast
//! land once the bip39 agent's §4 wires `wallet.accounts`/`AccountAllocate`
//! and the `TriadSigningService`-equivalent path into `bloom` (see the plan).

#![forbid(unsafe_code)]

pub mod account;
pub mod engine;
pub mod message;
pub mod outbox;
pub mod reconcile;
pub mod signing;
pub mod types;

pub use account::AccountSelectionError;
pub use engine::{EngineError, SolanaTransferEngine, SolanaTransferIntent};
pub use message::{MessageError, assemble_transaction, build_transfer_message, verify_signature};
pub use outbox::{OutboxError, SolanaOutbox, SolanaOutboxState};
pub use reconcile::SolanaReconciler;
pub use signing::{SolanaSignOutcome, SolanaTransferSigner};
pub use types::{SolanaReceipt, SolanaSentEntry, SolanaTxStatus, StagedSolanaTransfer};
