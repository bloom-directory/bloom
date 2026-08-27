//! Solana-typed durable-state records, mirroring `bloom-proto::StagedTx`'s
//! role in the EVM outbox but without any `alloy` fields.

use serde::{Deserialize, Serialize};

/// Lifecycle status of a staged Solana transfer, mirroring `TxStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolanaTxStatus {
    Pending,
    Sent,
    Success,
    Failed,
    Cancelled,
    Expired,
}

/// The write-once staged record, persisted as `intent.json`.
///
/// A Solana transfer's durable identity is its message bytes and the
/// blockhash/last-valid-height freshness window — there is no nonce. The
/// fields are exactly what construction pins before approval; signing and
/// broadcast only ever *consume* this record, never rewrite it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedSolanaTransfer {
    /// Outbox id (e.g. `"0001-12345"`), not the signature.
    pub id: String,
    pub wallet: String,
    /// Chain profile name (e.g. `"solana-devnet"`).
    pub chain: String,
    /// Fee payer and transfer source, base58.
    pub fee_payer: String,
    /// Full public-key fingerprint (hex) of the derived Solana child that
    /// `fee_payer` belongs to, pinned when the message was staged.
    ///
    /// The message bytes were built for exactly this account, so signing,
    /// broadcast, and reconciliation must re-select it rather than resolve the
    /// wallet's children again — a second active child would otherwise be able
    /// to sign a message it never authorised. Optional only so that entries
    /// staged before selection existed still parse; those resolve as before,
    /// which stays unambiguous because they cannot have had a second child.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_fingerprint: Option<String>,
    /// Canonical hardened derivation path of the selected child. New entries
    /// always carry it beside the fingerprint; optional only for legacy
    /// records created before explicit account selection existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_derivation_path: Option<String>,
    /// Transfer destination, base58.
    pub destination: String,
    /// Native SOL debit in lamports.
    pub lamports: u64,
    /// Network fee quoted by the genesis-bound RPC for these exact message bytes.
    pub fee_lamports: u64,
    /// Genesis hash observed and policy-checked when the message was staged.
    /// Broadcast re-checks the live RPC cluster against this immutable value.
    pub genesis_hash: String,
    /// Recent blockhash, base58 — the freshness anchor.
    pub blockhash: String,
    /// The block height at which `blockhash` stops being valid.
    pub last_valid_block_height: u64,
    /// Serialized legacy message (base64) — the exact bytes to be signed.
    pub message_b64: String,
    /// SHA-256 of the message bytes (hex) — Bloom's payload commitment.
    pub payload_digest_hex: String,
    /// Legacy compatibility field. New entries keep the pre-broadcast
    /// signature in a private sidecar and expose it only in the broadcast
    /// marker after submission succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub created_ms: u128,
    /// 0 means no expiry.
    pub expires_ms: u128,
    pub status: SolanaTxStatus,
    /// Central-outbox `action_id`, stamped when a projection is attached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
}

/// A parsed view of a `sent/<id>/intent.json` entry, for background scanners.
#[derive(Debug, Clone)]
pub struct SolanaSentEntry {
    pub wallet: String,
    pub chain: String,
    pub id: String,
    /// The transaction signature (base58), parsed from the broadcast marker;
    /// entries without a recorded signature are skipped by scanners.
    pub signature: String,
    pub fee_payer: String,
    pub destination: String,
    pub lamports: u64,
    pub blockhash: String,
    pub last_valid_block_height: u64,
    /// `intent.json` mtime — the stable "sent at" proxy (the directory mtime
    /// is unreliable because scanners write sibling artefacts into it).
    pub sent_at: std::time::SystemTime,
    /// `true` once a `receipt.json` has been written by the reconciler.
    pub mined: bool,
}

/// Filename of the mined-outcome sibling, written by the reconciliation loop.
pub const RECEIPT_FILE: &str = "receipt.json";

/// The persistent record of a sent transfer's on-chain outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaReceipt {
    /// `"success"` or `"failed"`.
    pub outcome: String,
    /// The transaction signature (base58).
    pub signature: String,
    /// Slot in which the transaction landed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    /// The node's `err` object, when the transaction failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<serde_json::Value>,
    /// The node's confirmation status (`processed`/`confirmed`/`finalized`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_status: Option<String>,
}

impl SolanaReceipt {
    pub fn is_success(&self) -> bool {
        self.outcome == "success"
    }
}
