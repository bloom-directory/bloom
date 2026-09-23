//! Background reconciliation of broadcast Solana transfers to their on-chain
//! outcome, mirroring `bloom-tx/src/reconcile.rs`.
//!
//! Nothing else writes a sent transfer's final status. This loop polls every
//! un-reconciled `sent/<id>/` entry, asks the node for its signature status,
//! and records a `receipt.json` sibling (`success`/`failed` + slot + error).
//! A post-dispatch timeout stays *un*reconciled until the node actually sees
//! the signature — the loop never invents an outcome.

use std::sync::Arc;
use std::time::Duration;

use bloom_proto::{AuditLog, AuditRecord};
use bloom_solana::{SolanaChainRegistry, SolanaClient};
use sha2::Digest as _;
use tokio::sync::oneshot;

use crate::outbox::{OutboxError, SolanaOutbox};
use crate::types::{RECEIPT_FILE, SolanaReceipt};

/// Polls sent transfers and records their on-chain outcome.
pub struct SolanaReconciler {
    outbox: SolanaOutbox,
    chains: SolanaChainRegistry,
    interval: Duration,
    audit: Arc<AuditLog>,
}

impl SolanaReconciler {
    pub fn new(outbox: SolanaOutbox, chains: SolanaChainRegistry, audit: Arc<AuditLog>) -> Self {
        Self {
            outbox,
            chains,
            interval: Duration::from_secs(15),
            audit,
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// One pass over all not-yet-reconciled sent entries. Returns the number
    /// of entries newly marked mined. Best-effort: per-entry errors are
    /// logged and skipped.
    pub async fn tick(&self) -> usize {
        let entries = match self.outbox.walk_all_sent() {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "solana_reconcile.walk_failed");
                return 0;
            }
        };
        let mut updated = 0;
        for entry in entries {
            if entry.mined {
                continue;
            }
            let Some(chain) = self.chains.get(&entry.chain) else {
                continue;
            };
            match self.reconcile_one(&chain, &entry).await {
                Ok(Some(receipt)) => {
                    tracing::info!(
                        id = %entry.id,
                        chain = %entry.chain,
                        outcome = %receipt.outcome,
                        "solana_reconcile.mined"
                    );
                    updated += 1;
                }
                Ok(None) => {} // not seen on-chain yet; leave unreconciled
                Err(e) => tracing::warn!(error = %e, id = %entry.id, "solana_reconcile.failed"),
            }
        }
        updated
    }

    /// Spawn the periodic loop. Returns a shutdown sender; send or drop to stop.
    pub fn spawn(self: Arc<Self>) -> oneshot::Sender<()> {
        let (tx, mut rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => { self.tick().await; }
                    _ = &mut rx => break,
                }
            }
        });
        tx
    }

    /// Reconcile a single sent entry. `Ok(None)` means "not seen yet" — the
    /// entry stays unreconciled for a later tick.
    async fn reconcile_one(
        &self,
        chain: &SolanaClient,
        entry: &crate::types::SolanaSentEntry,
    ) -> Result<Option<SolanaReceipt>, OutboxError> {
        let statuses = chain
            .get_signature_statuses(std::slice::from_ref(&entry.signature))
            .await
            .map_err(|e| OutboxError::Other(e.to_string()))?;
        let Some(Some(status)) = statuses.into_iter().next() else {
            // The failover path observed `null`. That is one endpoint's
            // absence, not the cluster's: a lagging or non-archival peer can
            // report `null` for a signature another endpoint finalized. Only
            // proceed once the validity window has closed, and then ask
            // every configured endpoint before writing anything terminal.
            let current_height = chain
                .get_block_height()
                .await
                .map_err(|error| OutboxError::Other(error.to_string()))?;
            if current_height <= entry.last_valid_block_height {
                return Ok(None);
            }
            let quorum = chain
                .probe_signature_status_all_endpoints(&entry.signature)
                .await;
            let mut finalized: Option<bloom_solana::SignatureStatus> = None;
            let mut seen_unfinalized = false;
            let mut absent = 0_usize;
            let mut unavailable = 0_usize;
            for probe in quorum {
                match probe.status {
                    Ok(None) => absent += 1,
                    Ok(Some(status)) => {
                        if status.confirmation_status.as_deref() == Some("finalized") {
                            finalized = Some(status);
                        } else {
                            seen_unfinalized = true;
                        }
                    }
                    Err(_) => unavailable += 1,
                }
            }
            if let Some(status) = finalized {
                // Some endpoint observed the transfer the failover path
                // missed. Reconcile from that observation.
                return self.write_outcome_receipt(entry, &status);
            }
            if seen_unfinalized {
                // Observed, but not yet finalized on any answering endpoint;
                // a durable receipt stays terminal-only.
                return Ok(None);
            }
            if unavailable > 0 {
                // Absence cannot be proven while endpoints are missing.
                // Keep the entry unreconciled rather than risk recording an
                // executed transfer as failed.
                return Err(OutboxError::Other(format!(
                    "signature absence not proven: {unavailable} of {} endpoints unavailable",
                    absent + unavailable,
                )));
            }
            // Once the validity window has closed, a signature no configured
            // endpoint reports — even from transaction history — cannot newly
            // land. Record that terminal fact instead of leaving the outbox
            // in `sent` forever.
            let receipt = SolanaReceipt {
                outcome: "failed".to_string(),
                signature: entry.signature.clone(),
                slot: None,
                err: Some(serde_json::json!({
                    "kind": "blockhash_expired_unseen",
                    "last_valid_block_height": entry.last_valid_block_height,
                    "observed_block_height": current_height,
                    "endpoints_reporting_unseen": absent,
                })),
                confirmation_status: None,
            };
            let bytes = serde_json::to_vec_pretty(&receipt)?;
            self.project_receipt(entry, &bytes)?;
            return Ok(Some(receipt));
        };

        // `processed` and `confirmed` are forkable observations. A durable
        // receipt is terminal state, so wait until the cluster reports finality.
        if status.confirmation_status.as_deref() != Some("finalized") {
            return Ok(None);
        }
        self.write_outcome_receipt(entry, &status)
    }

    /// Record a receipt from a finalized on-chain observation.
    fn write_outcome_receipt(
        &self,
        entry: &crate::types::SolanaSentEntry,
        status: &bloom_solana::SignatureStatus,
    ) -> Result<Option<SolanaReceipt>, OutboxError> {
        let outcome = if status.err.is_some() {
            "failed"
        } else {
            "success"
        };
        let receipt = SolanaReceipt {
            outcome: outcome.to_string(),
            signature: entry.signature.clone(),
            slot: Some(status.slot),
            err: status.err.clone(),
            confirmation_status: status.confirmation_status.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&receipt)?;
        self.project_receipt(entry, &bytes)?;
        Ok(Some(receipt))
    }

    fn project_receipt(
        &self,
        entry: &crate::types::SolanaSentEntry,
        bytes: &[u8],
    ) -> Result<(), OutboxError> {
        let details = serde_json::json!({
            "operation": "solana.tx.reconcile.receipt_projection",
            "wallet": entry.wallet,
            "chain": entry.chain,
            "tx_id": entry.id,
            "signature": entry.signature,
            "target": RECEIPT_FILE,
            "payload_sha256": hex::encode(sha2::Sha256::digest(bytes)),
            "payload_size": bytes.len(),
        });
        let correlation = self.audit_intent(entry, details).ok_or_else(|| {
            OutboxError::Other("Machine audit unavailable before receipt projection".to_owned())
        })?;
        let write_result = self.outbox.write_sent_sibling(entry, RECEIPT_FILE, bytes);
        let result = match &write_result {
            Ok(()) => serde_json::json!({"outcome": "written"}),
            Err(error) => serde_json::json!({
                "outcome": "error",
                "error": error.to_string(),
            }),
        };
        if !self.audit_result(entry, &correlation, result) {
            return Err(OutboxError::Other(
                "Machine audit unavailable after receipt projection".to_owned(),
            ));
        }
        write_result
    }

    fn audit_intent(
        &self,
        entry: &crate::types::SolanaSentEntry,
        details: serde_json::Value,
    ) -> Option<String> {
        let canonical = serde_jcs::to_vec(&details).ok()?;
        let operation_id = hex::encode(sha2::Sha256::digest(&canonical));
        let correlation_id = format!("{operation_id}:{}", self.audit.sequence() + 1);
        self.audit
            .append(AuditRecord {
                ts_ms: 0,
                kind: "machine.effect.intent".into(),
                wallet: Some(entry.wallet.clone()),
                chain: Some(entry.chain.clone()),
                data: serde_json::json!({
                    "operation_id": operation_id,
                    "correlation_id": correlation_id,
                    "details": details,
                }),
                prev: String::new(),
                digest: String::new(),
            })
            .map(|_| correlation_id)
            .map_err(|error| {
                tracing::error!(%error, "solana_reconcile.audit_intent_failed");
            })
            .ok()
    }

    fn audit_result(
        &self,
        entry: &crate::types::SolanaSentEntry,
        correlation_id: &str,
        result: serde_json::Value,
    ) -> bool {
        self.audit
            .append(AuditRecord {
                ts_ms: 0,
                kind: "machine.effect.result".into(),
                wallet: Some(entry.wallet.clone()),
                chain: Some(entry.chain.clone()),
                data: serde_json::json!({
                    "operation": "solana.tx.reconcile",
                    "correlation_id": correlation_id,
                    "result": result,
                }),
                prev: String::new(),
                digest: String::new(),
            })
            .map(|_| true)
            .map_err(|error| {
                tracing::error!(%error, "solana_reconcile.audit_result_failed");
            })
            .unwrap_or(false)
    }
}
