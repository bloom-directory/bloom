//! Background reconciliation of broadcast txs to their mined outcome.
//!
//! Nothing else writes a sent tx's `Success`/`Reverted` result. This loop
//! polls every un-reconciled `sent/<id>/` entry, fetches its receipt, and
//! records a `receipt.json` sibling (success/reverted + best-effort revert
//! reason). The dependency gate in [`crate::tx_engine`] reads that record to
//! decide whether a dependent same-chain tx may broadcast, and `BumpScanner`
//! treats a reconciled entry as mined (so it stops fee-bumping it).

use std::sync::Arc;
use std::time::Duration;

use bloom_evm::ChainRegistry;
use tokio::sync::oneshot;

use crate::outbox::{MinedReceipt, Outbox, RECEIPT_FILE};

/// Polls sent entries and records their mined outcome.
pub struct Reconciler {
    outbox: Outbox,
    chains: ChainRegistry,
    interval: Duration,
}

impl Reconciler {
    pub fn new(outbox: Outbox, chains: ChainRegistry) -> Self {
        Self {
            outbox,
            chains,
            interval: Duration::from_secs(15),
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// One pass over all not-yet-reconciled sent entries. Returns the number
    /// of entries newly marked mined. Best-effort: per-entry errors are logged
    /// and skipped.
    pub async fn tick(&self) -> usize {
        let entries = match self.outbox.walk_all_sent() {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "reconcile.walk_failed");
                return 0;
            }
        };
        let mut updated = 0;
        for se in entries {
            if se.mined {
                continue;
            }
            let Some(chain) = self.chains.get(&se.chain) else {
                continue;
            };
            let receipt = match chain.receipt(se.hash).await {
                Ok(Some(r)) => r,
                Ok(None) => continue, // not mined yet
                Err(e) => {
                    tracing::debug!(error = %e, id = %se.id, "reconcile.receipt_failed");
                    continue;
                }
            };
            let success = receipt.status();
            let revert_reason = if success {
                None
            } else {
                match chain.trace_revert(se.hash).await {
                    Ok(Some(bytes)) => Some(decode_revert(&bytes)),
                    _ => None,
                }
            };
            let record = MinedReceipt {
                outcome: if success { "success" } else { "reverted" }.to_string(),
                tx_hash: format!("{:#x}", se.hash),
                block_number: receipt.block_number,
                revert_reason,
            };
            match serde_json::to_vec_pretty(&record) {
                Ok(bytes) => match self.outbox.write_sent_sibling(&se, RECEIPT_FILE, &bytes) {
                    Ok(()) => {
                        tracing::info!(
                            id = %se.id,
                            chain = %se.chain,
                            outcome = %record.outcome,
                            "reconcile.mined"
                        );
                        updated += 1;
                    }
                    Err(e) => tracing::warn!(error = %e, id = %se.id, "reconcile.write_failed"),
                },
                Err(e) => tracing::warn!(error = %e, "reconcile.serialize_failed"),
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
}

/// Best-effort decode of standard `Error(string)` revert returndata
/// (selector `0x08c379a0`); falls back to hex.
pub(crate) fn decode_revert(bytes: &[u8]) -> String {
    if bytes.len() >= 68 && bytes[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        // Length is the low 8 bytes of the 32-byte word at [36..68].
        let len = usize::from_be_bytes(bytes[60..68].try_into().unwrap_or([0; 8]));
        if let Some(s) = bytes.get(68..68usize.saturating_add(len))
            && let Ok(text) = std::str::from_utf8(s)
        {
            return text.to_string();
        }
    }
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_standard_error_string() {
        // abi.encodeWithSignature("Error(string)", "boom")
        let mut data = vec![0x08, 0xc3, 0x79, 0xa0];
        data.extend_from_slice(&[0u8; 31]);
        data.push(0x20); // offset = 32
        data.extend_from_slice(&[0u8; 31]);
        data.push(0x04); // length = 4
        data.extend_from_slice(b"boom");
        data.extend_from_slice(&[0u8; 28]); // pad to 32
        assert_eq!(decode_revert(&data), "boom");
    }

    #[test]
    fn falls_back_to_hex_for_unknown_returndata() {
        assert_eq!(decode_revert(&[0xde, 0xad]), "0xdead");
    }
}
