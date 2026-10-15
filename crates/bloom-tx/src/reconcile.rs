//! Background reconciliation of broadcast txs to their mined outcome.
//!
//! Nothing else writes a sent tx's `Success`/`Reverted` result. This loop
//! polls every un-reconciled `sent/<id>/` entry, fetches its receipt, and
//! records a `receipt.json` sibling (success/reverted + best-effort revert
//! reason). The dependency gate in [`crate::tx_engine`] reads that record to
//! decide whether a dependent same-chain tx may broadcast, and `BumpScanner`
//! treats a reconciled entry as mined (so it stops fee-bumping it).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bloom_evm::ChainRegistry;
use bloom_proto::{AuditLog, AuditRecord};
use tokio::sync::oneshot;

use crate::outbox::{MinedReceipt, Outbox, RECEIPT_FILE};

/// How long an unanswered receipt lookup keeps the normal cadence. Every
/// lookup is journaled before it contacts the provider, so a transaction
/// that never gets a receipt (a dropped transaction, or a chain whose
/// endpoint is down) must not be looked up on every tick forever.
const RECEIPT_LOOKUP_GRACE: Duration = Duration::from_secs(5 * 60);
/// Longest wait between lookups for such a transaction.
const RECEIPT_LOOKUP_MAX_DELAY: Duration = Duration::from_secs(30 * 60);

/// Unanswered lookups for one sent entry.
struct LookupBackoff {
    first_miss: Instant,
    misses_after_grace: u32,
    next_at: Instant,
}

/// Polls sent entries and records their mined outcome.
pub struct Reconciler {
    outbox: Outbox,
    chains: ChainRegistry,
    interval: Duration,
    audit: Arc<AuditLog>,
    backoff: Mutex<HashMap<String, LookupBackoff>>,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl Reconciler {
    pub fn new(outbox: Outbox, chains: ChainRegistry, audit: Arc<AuditLog>) -> Self {
        Self {
            outbox,
            chains,
            interval: Duration::from_secs(15),
            audit,
            backoff: Mutex::new(HashMap::new()),
            clock: Arc::new(Instant::now),
        }
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    fn backoff_key(entry: &crate::outbox::SentEntry) -> String {
        format!("{}/{}/{}", entry.wallet, entry.chain, entry.id)
    }

    /// Whether `key` is still waiting out its backoff at `now`.
    fn lookup_deferred(&self, key: &str, now: Instant) -> bool {
        self.backoff
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .is_some_and(|backoff| now < backoff.next_at)
    }

    /// Record a lookup that found no receipt. The normal cadence holds for
    /// [`RECEIPT_LOOKUP_GRACE`]; after that the wait doubles, up to
    /// [`RECEIPT_LOOKUP_MAX_DELAY`].
    fn record_lookup_miss(&self, key: String, now: Instant) {
        let mut backoffs = self
            .backoff
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let backoff = backoffs.entry(key).or_insert(LookupBackoff {
            first_miss: now,
            misses_after_grace: 0,
            next_at: now,
        });
        if now.duration_since(backoff.first_miss) < RECEIPT_LOOKUP_GRACE {
            backoff.next_at = now;
            return;
        }
        backoff.misses_after_grace = backoff.misses_after_grace.saturating_add(1);
        let delay = self
            .interval
            .saturating_mul(1_u32 << backoff.misses_after_grace.min(16))
            .min(RECEIPT_LOOKUP_MAX_DELAY);
        backoff.next_at = now + delay;
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
        let now = (self.clock)();
        let mut updated = 0;
        let mut waiting = std::collections::HashSet::new();
        for se in entries {
            if se.mined {
                continue;
            }
            let Some(chain) = self.chains.get(&se.chain) else {
                continue;
            };
            let backoff_key = Self::backoff_key(&se);
            waiting.insert(backoff_key.clone());
            if self.lookup_deferred(&backoff_key, now) {
                continue;
            }
            let receipt_details = serde_json::json!({
                "operation": "tx.reconcile.receipt_lookup",
                "wallet": se.wallet,
                "chain": se.chain,
                "tx_id": se.id,
                "tx_hash": format!("{:#x}", se.hash),
            });
            let Some(receipt_correlation) = self.audit_intent(&se, receipt_details) else {
                break;
            };
            let receipt_call = chain.receipt(se.hash).await;
            let receipt_result = match &receipt_call {
                Ok(Some(receipt)) => serde_json::json!({
                    "outcome": "found",
                    "receipt": receipt,
                }),
                Ok(None) => serde_json::json!({"outcome": "not_found"}),
                Err(error) => serde_json::json!({
                    "outcome": "error",
                    "error": error.to_string(),
                }),
            };
            if !self.audit_result(&se, &receipt_correlation, receipt_result) {
                break;
            }
            let receipt = match receipt_call {
                Ok(Some(r)) => {
                    self.backoff
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&backoff_key);
                    r
                }
                Ok(None) => {
                    self.record_lookup_miss(backoff_key, now);
                    continue;
                }
                Err(e) => {
                    tracing::debug!(error = %e, id = %se.id, "reconcile.receipt_failed");
                    self.record_lookup_miss(backoff_key, now);
                    continue;
                }
            };
            let success = receipt.status();
            let revert_reason = if success {
                None
            } else {
                let Some(trace_call) = self
                    .audited_trace_revert(&se, || async {
                        chain.trace_revert(se.hash).await.map_err(|e| e.to_string())
                    })
                    .await
                else {
                    break;
                };
                match trace_call {
                    Ok(Some(bytes)) => Some(decode_revert(&bytes)),
                    _ => None,
                }
            };
            let record = MinedReceipt {
                outcome: if success { "success" } else { "reverted" }.to_string(),
                tx_hash: format!("{:#x}", se.hash),
                block_number: receipt.block_number,
                contract_address: receipt
                    .contract_address
                    .filter(|_| success)
                    .map(|address| format!("{address:#x}")),
                revert_reason,
            };
            match serde_json::to_vec_pretty(&record) {
                Ok(bytes) => match self.project_receipt(&se, &bytes) {
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
        // Forget entries that were mined, cancelled or removed.
        self.backoff
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|key, _| waiting.contains(key));
        updated
    }

    fn project_receipt(
        &self,
        entry: &crate::outbox::SentEntry,
        bytes: &[u8],
    ) -> Result<(), String> {
        let projection_details = serde_json::json!({
            "operation": "tx.reconcile.receipt_projection",
            "wallet": entry.wallet,
            "chain": entry.chain,
            "tx_id": entry.id,
            "target": RECEIPT_FILE,
            "payload_sha256": bloom_tools::sha256_hex(bytes),
            "payload_size": bytes.len(),
        });
        let correlation = self
            .audit_intent(entry, projection_details)
            .ok_or_else(|| "Machine audit unavailable before receipt projection".to_owned())?;
        let write_result = self.outbox.write_sent_sibling(entry, RECEIPT_FILE, bytes);
        let audit_result = match &write_result {
            Ok(()) => serde_json::json!({"outcome": "written"}),
            Err(error) => {
                serde_json::json!({"outcome": "error", "error": error.to_string()})
            }
        };
        if !self.audit_result(entry, &correlation, audit_result) {
            return Err("Machine audit unavailable after receipt projection".to_owned());
        }
        write_result.map_err(|error| error.to_string())
    }

    async fn audited_trace_revert<F, Fut>(
        &self,
        entry: &crate::outbox::SentEntry,
        trace: F,
    ) -> Option<Result<Option<alloy::primitives::Bytes>, String>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Option<alloy::primitives::Bytes>, String>>,
    {
        let trace_details = serde_json::json!({
            "operation": "tx.reconcile.trace_revert",
            "wallet": entry.wallet,
            "chain": entry.chain,
            "tx_id": entry.id,
            "tx_hash": format!("{:#x}", entry.hash),
        });
        let correlation = self.audit_intent(entry, trace_details)?;
        let trace_call = trace().await;
        let result = match &trace_call {
            Ok(Some(bytes)) => serde_json::json!({
                "outcome": "found",
                "returndata_hex": hex::encode(bytes),
            }),
            Ok(None) => serde_json::json!({"outcome": "not_found"}),
            Err(error) => serde_json::json!({
                "outcome": "error",
                "error": error,
            }),
        };
        self.audit_result(entry, &correlation, result)
            .then_some(trace_call)
    }

    fn audit_intent(
        &self,
        entry: &crate::outbox::SentEntry,
        details: serde_json::Value,
    ) -> Option<String> {
        let canonical = serde_jcs::to_vec(&details).ok()?;
        let operation_id = bloom_tools::sha256_hex(&canonical);
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
                tracing::error!(%error, "reconcile.audit_intent_failed");
            })
            .ok()
    }

    fn audit_result(
        &self,
        entry: &crate::outbox::SentEntry,
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
                    "operation": "tx.reconcile",
                    "correlation_id": correlation_id,
                    "result": result,
                }),
                prev: String::new(),
                digest: String::new(),
            })
            .map(|_| true)
            .map_err(|error| {
                tracing::error!(%error, "reconcile.audit_result_failed");
            })
            .unwrap_or(false)
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
    use bloom_evm::ChainClient;
    use bloom_proto::{ChainSpec, StagedTx, TxActionKind, TxStatus};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn sent_outbox() -> (tempfile::TempDir, Outbox) {
        let directory = tempfile::tempdir().unwrap();
        let outbox = Outbox::new(directory.path().join("outbox")).unwrap();
        let staged = StagedTx {
            id: "tx-1".into(),
            wallet: "alice".into(),
            chain: "anvil".into(),
            chain_id: 31337,
            from: "0x0000000000000000000000000000000000000001".into(),
            to: Some("0x0000000000000000000000000000000000000002".into()),
            value_wei: "0".into(),
            data_hex: "0x".into(),
            gas_limit: 21_000,
            max_fee_per_gas: Some("100".into()),
            max_priority_fee_per_gas: Some("10".into()),
            gas_price: None,
            nonce: 0,
            policy_checks: vec![],
            created_ms: 0,
            expires_ms: 0,
            status: TxStatus::Sent,
            action_kind: TxActionKind::Unknown,
            review_mode: None,
            tx_hash: Some(format!("{:#x}", alloy::primitives::B256::repeat_byte(7))),
            token: None,
            nft: None,
            usd_value: None,
            valuation: None,
            depends_on: None,
            action_id: None,
            execution_origin: None,
        };
        outbox.write_pending(&staged, "# plan").unwrap();
        let pending = outbox.read("alice", "anvil", "tx-1").unwrap();
        outbox
            .transition(&pending, crate::outbox::OutboxState::Sent)
            .unwrap();
        (directory, outbox)
    }

    async fn receipt_chain(
        result_json: &'static str,
        calls: Arc<AtomicUsize>,
        fail_result_audit: Option<Arc<AuditLog>>,
    ) -> ChainClient {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut request = vec![0_u8; 8192];
            let read = stream.read(&mut request).await.unwrap();
            calls.fetch_add(1, Ordering::SeqCst);
            if let Some(audit) = fail_result_audit {
                audit.fail_next_write_for_test();
            }
            let request_text = String::from_utf8_lossy(&request[..read]);
            let request_body = request_text.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let request_json: serde_json::Value =
                serde_json::from_str(request_body).unwrap_or_else(|_| serde_json::json!({}));
            let id = request_json
                .get("id")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::from_str::<serde_json::Value>(result_json).unwrap(),
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let mut spec = ChainSpec::anvil_default();
        spec.rpc_urls = vec![format!("http://{address}")];
        ChainClient::new(spec).unwrap()
    }

    #[tokio::test]
    async fn audit_prewrite_failure_prevents_receipt_network_call() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit_path = audit_directory.path().join("audit.jsonl");
        let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
        audit.fail_next_write_for_test();
        let calls = Arc::new(AtomicUsize::new(0));
        let chain = receipt_chain("null", calls.clone(), None).await;
        let chains = ChainRegistry::default();
        chains.add(chain);
        let reconciler = Reconciler::new(outbox, chains, audit.clone());
        assert_eq!(reconciler.tick().await, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(audit.mutation_degradation().is_some());
    }

    #[tokio::test]
    async fn lost_receipt_result_audit_latches_on_restart_without_projection() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit_path = audit_directory.path().join("audit.jsonl");
        let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let chain = receipt_chain("null", calls.clone(), Some(audit.clone())).await;
        let chains = ChainRegistry::default();
        chains.add(chain);
        let reconciler = Reconciler::new(outbox.clone(), chains, audit.clone());
        assert_eq!(reconciler.tick().await, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            outbox
                .read_receipt("alice", "anvil", "tx-1")
                .unwrap()
                .is_none()
        );
        drop(reconciler);
        drop(audit);
        let restarted = AuditLog::open(&audit_path).unwrap();
        assert!(restarted.mutation_degradation().is_some());
        assert_eq!(restarted.pending_effect_correlations().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn receipt_not_found_records_exact_closed_intent_result_pair() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let chain = receipt_chain("null", calls.clone(), None).await;
        let chains = ChainRegistry::default();
        chains.add(chain);
        let reconciler = Reconciler::new(outbox, chains, audit.clone());
        assert_eq!(reconciler.tick().await, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let records = audit.tail(2).unwrap();
        assert_eq!(records[0].kind, "machine.effect.intent");
        assert_eq!(
            records[0].data["details"]["operation"],
            "tx.reconcile.receipt_lookup"
        );
        assert_eq!(records[1].kind, "machine.effect.result");
        assert_eq!(records[1].data["result"]["outcome"], "not_found");
        assert!(audit.pending_effect_correlations().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unanswered_receipt_lookups_back_off_after_the_grace_period() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        // Answers once with no receipt, then refuses connections: both are
        // lookups that found nothing.
        let chain = receipt_chain("null", calls.clone(), None).await;
        let chains = ChainRegistry::default();
        chains.add(chain);
        let start = Instant::now();
        let elapsed = Arc::new(Mutex::new(Duration::ZERO));
        let clock_elapsed = elapsed.clone();
        let reconciler = Reconciler::new(outbox, chains, audit.clone())
            .with_clock(Arc::new(move || start + *clock_elapsed.lock().unwrap()));
        let lookups = |audit: &AuditLog| audit.count().unwrap() / 2;
        let at = |secs: u64| *elapsed.lock().unwrap() = Duration::from_secs(secs);

        // Inside the grace period every tick looks the receipt up.
        for secs in [0, 15, 60, 240] {
            at(secs);
            reconciler.tick().await;
        }
        assert_eq!(lookups(&audit), 4);
        // The first miss after the grace period waits two intervals.
        at(301);
        reconciler.tick().await;
        assert_eq!(lookups(&audit), 5);
        at(320);
        reconciler.tick().await;
        assert_eq!(lookups(&audit), 5, "deferred inside the backoff");
        at(332);
        reconciler.tick().await;
        assert_eq!(lookups(&audit), 6);
        // The wait keeps doubling but never exceeds the cap.
        let mut now = 332;
        for _ in 0..12 {
            now += RECEIPT_LOOKUP_MAX_DELAY.as_secs();
            at(now);
            reconciler.tick().await;
        }
        assert_eq!(lookups(&audit), 18, "capped at one lookup per interval");
        assert!(audit.pending_effect_correlations().unwrap().is_empty());
    }

    #[tokio::test]
    async fn backoff_is_forgotten_once_the_entry_leaves_the_sent_outbox() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = Outbox::new(directory.path().join("outbox")).unwrap();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let reconciler = Reconciler::new(outbox, ChainRegistry::default(), audit);
        let now = Instant::now();
        reconciler.record_lookup_miss("alice/anvil/gone".into(), now);
        assert_eq!(reconciler.backoff.lock().unwrap().len(), 1);
        reconciler.tick().await;
        assert!(reconciler.backoff.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn trace_revert_intent_prewrite_failure_prevents_network_call() {
        let (_directory, outbox) = sent_outbox();
        let entry = outbox.walk_all_sent().unwrap().remove(0);
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let reconciler = Reconciler::new(outbox, ChainRegistry::default(), audit.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        audit.fail_next_write_for_test();
        let result = reconciler
            .audited_trace_revert(&entry, {
                let calls = calls.clone();
                move || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(None)
                }
            })
            .await;
        assert!(result.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(audit.mutation_degradation().is_some());
    }

    #[tokio::test]
    async fn trace_revert_result_loss_latches_on_restart() {
        let (_directory, outbox) = sent_outbox();
        let entry = outbox.walk_all_sent().unwrap().remove(0);
        let audit_directory = tempfile::tempdir().unwrap();
        let audit_path = audit_directory.path().join("audit.jsonl");
        let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
        let reconciler = Reconciler::new(outbox, ChainRegistry::default(), audit.clone());
        let result = reconciler
            .audited_trace_revert(&entry, {
                let audit = audit.clone();
                move || async move {
                    audit.fail_next_write_for_test();
                    Ok(Some(alloy::primitives::Bytes::from(vec![0xde, 0xad])))
                }
            })
            .await;
        assert!(result.is_none());
        drop(reconciler);
        drop(audit);
        let restarted = AuditLog::open(&audit_path).unwrap();
        assert!(restarted.mutation_degradation().is_some());
        assert_eq!(restarted.pending_effect_correlations().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn trace_revert_provider_failure_closes_exact_audit_pair() {
        let (_directory, outbox) = sent_outbox();
        let entry = outbox.walk_all_sent().unwrap().remove(0);
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let reconciler = Reconciler::new(outbox, ChainRegistry::default(), audit.clone());
        let result = reconciler
            .audited_trace_revert(&entry, || async { Err("trace unavailable".to_owned()) })
            .await
            .expect("audit result must be durable");
        assert_eq!(result.unwrap_err(), "trace unavailable");
        let records = audit.tail(2).unwrap();
        assert_eq!(
            records[0].data["details"]["operation"],
            "tx.reconcile.trace_revert"
        );
        assert_eq!(records[1].data["result"]["outcome"], "error");
        assert_eq!(records[1].data["result"]["error"], "trace unavailable");
        assert!(audit.pending_effect_correlations().unwrap().is_empty());
    }

    #[test]
    fn receipt_projection_result_loss_is_durable_and_latches_on_restart() {
        let (_directory, outbox) = sent_outbox();
        let entry = outbox.walk_all_sent().unwrap().remove(0);
        let audit_directory = tempfile::tempdir().unwrap();
        let audit_path = audit_directory.path().join("audit.jsonl");
        let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
        audit.fail_after_writes_for_test(1);
        let reconciler = Reconciler::new(outbox.clone(), ChainRegistry::default(), audit.clone());
        let receipt = MinedReceipt {
            outcome: "success".into(),
            tx_hash: format!("{:#x}", entry.hash),
            block_number: Some(9),
            contract_address: None,
            revert_reason: None,
        };
        let bytes = serde_json::to_vec_pretty(&receipt).unwrap();
        assert!(reconciler.project_receipt(&entry, &bytes).is_err());
        assert!(
            outbox
                .sent_dir("alice", "anvil", "tx-1")
                .unwrap()
                .join(RECEIPT_FILE)
                .is_file()
        );
        drop(reconciler);
        drop(audit);
        let restarted = AuditLog::open(&audit_path).unwrap();
        assert!(restarted.mutation_degradation().is_some());
        assert_eq!(restarted.pending_effect_correlations().unwrap().len(), 1);
    }

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
