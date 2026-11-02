//! Background reconciliation of broadcast txs to their mined outcome.
//!
//! Nothing else writes a sent tx's `Success`/`Reverted` result. This loop
//! polls every un-reconciled `sent/<id>/` entry, fetches its receipt, and
//! records a `receipt.json` sibling (success/reverted + best-effort revert
//! reason). The dependency gate in [`crate::tx_engine`] reads that record to
//! decide whether a dependent same-chain tx may broadcast, and `BumpScanner`
//! treats a reconciled entry as mined (so it stops fee-bumping it).
//!
//! A receipt can only exist once the sender's confirmed (mined) nonce has
//! passed the transaction's nonce. Each tick reads that nonce once per sender
//! and chain and looks a receipt up, journaled before it contacts the
//! provider, only after the nonce is spent. A pending or dropped transaction
//! therefore costs no journaled lookup, and a mined transaction is recorded on
//! the tick after its nonce advances; ticks are two seconds apart, while any
//! further lookups for one transaction are journaled at most every fifteen. The nonce read itself is not journaled:
//! like a balance read, it reveals only the sender's address, not the
//! transaction. When no nonce is available the receipt is looked up anyway,
//! backing off only while the provider fails that lookup too.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bloom_evm::ChainRegistry;
use bloom_proto::{AuditLog, AuditRecord};
use tokio::sync::oneshot;

use crate::outbox::{BroadcastAttempt, BroadcastAttemptKind, MinedReceipt, Outbox, RECEIPT_FILE};

/// How long a transaction whose nonce is spent but whose receipt is missing
/// keeps [`RECEIPT_LOOKUP_SPACING`] before backing off further. That covers RPC endpoints that lag one another;
/// after it, another transaction with the same nonce (a cancel or speed-up)
/// most likely replaced this one, and its hash will never be mined.
const RECEIPT_LOOKUP_GRACE: Duration = Duration::from_secs(5 * 60);
/// Shortest gap between two journaled lookups for one transaction. The tick is
/// much faster, so a newly spent nonce is noticed within seconds, but every
/// lookup after the first is journaled at most this often, whatever the tick.
const RECEIPT_LOOKUP_SPACING: Duration = Duration::from_secs(15);
/// Longest wait between lookups for such a replaced transaction.
const RECEIPT_LOOKUP_MAX_DELAY: Duration = Duration::from_secs(30 * 60);

/// Missed lookups for one sent entry whose nonce is spent.
struct LookupBackoff {
    first_miss: Instant,
    misses_after_grace: u32,
    next_at: Instant,
    /// Whether the nonce has ever been seen spent. Sticky: history from
    /// before that (no nonce available) must not delay the first lookup once
    /// it is spent, but switching between spent and unavailable afterwards
    /// must not restart the backoff either.
    seen_spent: bool,
    /// When the nonce was last read while this entry waited out its backoff.
    nonce_checked_at: Option<Instant>,
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
            // Ticks cost no journal writes unless a nonce was spent, so tick
            // fast enough for chains with one- or two-second blocks.
            interval: Duration::from_secs(2),
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

    /// Whether `key`, already seen spent, can skip this tick's nonce read: it
    /// is waiting out a backoff and its nonce was read less than
    /// [`RECEIPT_LOOKUP_SPACING`] ago. The nonce is still read at that spacing,
    /// since a reorg can make a spent nonce unspent again.
    fn spent_nonce_read_deferred(&self, key: &str, now: Instant) -> bool {
        self.backoff
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .is_some_and(|backoff| {
                backoff.seen_spent
                    && now < backoff.next_at
                    && backoff
                        .nonce_checked_at
                        .is_some_and(|checked| now < checked + RECEIPT_LOOKUP_SPACING)
            })
    }

    /// Called when the nonce is seen spent. The first time, history from
    /// before it is forgotten so that lookup is never delayed; afterwards the
    /// backoff keeps going and only the time of this nonce read is noted.
    fn note_spent_nonce(&self, key: &str, now: Instant) {
        let mut backoffs = self
            .backoff
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match backoffs.get_mut(key) {
            Some(backoff) if backoff.seen_spent => backoff.nonce_checked_at = Some(now),
            Some(_) => {
                backoffs.remove(key);
            }
            None => {}
        }
    }

    /// Record a lookup that found no receipt for this hash, or failed. Once
    /// the nonce has been seen spent, lookups stay [`RECEIPT_LOOKUP_SPACING`]
    /// apart for [`RECEIPT_LOOKUP_GRACE`] and then the wait doubles, up to
    /// [`RECEIPT_LOOKUP_MAX_DELAY`]. `nonce_spent` says whether this lookup
    /// followed a spent nonce.
    fn record_lookup_miss(&self, key: String, now: Instant, nonce_spent: bool) {
        let mut backoffs = self
            .backoff
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let backoff = backoffs.entry(key).or_insert(LookupBackoff {
            first_miss: now,
            misses_after_grace: 0,
            next_at: now,
            seen_spent: nonce_spent,
            nonce_checked_at: None,
        });
        backoff.seen_spent |= nonce_spent;
        if nonce_spent {
            backoff.nonce_checked_at = Some(now);
        }
        if now.duration_since(backoff.first_miss) < RECEIPT_LOOKUP_GRACE {
            backoff.next_at = now + RECEIPT_LOOKUP_SPACING;
            return;
        }
        backoff.misses_after_grace = backoff.misses_after_grace.saturating_add(1);
        let delay = RECEIPT_LOOKUP_SPACING
            .saturating_mul(1_u32 << backoff.misses_after_grace.min(16))
            .min(RECEIPT_LOOKUP_MAX_DELAY);
        backoff.next_at = now + delay;
    }

    /// Record a lookup, made without a confirmed nonce, that found no receipt.
    /// A transaction never seen spent may simply be pending, so keep looking
    /// at the normal spacing; one already seen spent keeps its backoff.
    fn space_next_lookup(&self, key: String, now: Instant) {
        let seen_spent = self
            .backoff
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .is_some_and(|backoff| backoff.seen_spent);
        if seen_spent {
            return self.record_lookup_miss(key, now, false);
        }
        self.backoff
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                key,
                LookupBackoff {
                    first_miss: now,
                    misses_after_grace: 0,
                    next_at: now + RECEIPT_LOOKUP_SPACING,
                    seen_spent: false,
                    nonce_checked_at: None,
                },
            );
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
        let mut waiting = std::collections::HashSet::new();
        // Confirmed nonce per (chain, sender) for this tick; None when the
        // provider could not answer.
        let mut confirmed_nonces = HashMap::new();
        'entries: for se in entries {
            if se.mined {
                continue;
            }
            let Some(chain) = self.chains.get(&se.chain) else {
                continue;
            };
            let backoff_key = Self::backoff_key(&se);
            waiting.insert(backoff_key.clone());
            if self.spent_nonce_read_deferred(&backoff_key, (self.clock)()) {
                continue;
            }
            let nonce_key = (se.chain.clone(), se.from);
            let confirmed = match confirmed_nonces.get(&nonce_key) {
                Some(confirmed) => *confirmed,
                None => {
                    let confirmed = chain
                        .nonce_latest(se.from)
                        .await
                        .map_err(|error| {
                            tracing::debug!(%error, chain = %se.chain, "reconcile.nonce_unavailable")
                        })
                        .ok();
                    confirmed_nonces.insert(nonce_key, confirmed);
                    confirmed
                }
            };
            // Without a confirmed nonce (unsupported, or the provider is
            // failing) fall back to looking the receipt up, so a provider
            // that serves receipts but not nonces still reconciles.
            let nonce_spent = match confirmed {
                Some(confirmed) if confirmed <= se.nonce => {
                    // Not mined yet: nothing to look up. A nonce seen spent
                    // before was undone by a reorg, so its backoff no longer
                    // applies; spacing from no-nonce lookups is kept, so a
                    // flapping provider cannot reset it.
                    let mut backoffs = self
                        .backoff
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if backoffs
                        .get(&backoff_key)
                        .is_some_and(|backoff| backoff.seen_spent)
                    {
                        backoffs.remove(&backoff_key);
                    }
                    continue;
                }
                Some(_) => {
                    self.note_spent_nonce(&backoff_key, (self.clock)());
                    true
                }
                None => false,
            };
            // Spacing is measured from when each lookup actually happens, not
            // from the start of a tick that may have waited on nonce reads.
            let now = (self.clock)();
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
            let mut hash = se.hash;
            let mut receipt_call = chain.receipt(hash).await;
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
            // A replacement or cancel competes for the same nonce; broadcast
            // does not decide which one mines. When the followed hash has no
            // receipt, look up every other recorded attempt and settle the
            // one that mined. Only a mined cancel records a cancellation.
            if matches!(&receipt_call, Ok(None)) {
                for (other, cancel) in self.competing_attempts(&se) {
                    let operation = if cancel {
                        "tx.reconcile.cancel_receipt_lookup"
                    } else {
                        "tx.reconcile.competing_receipt_lookup"
                    };
                    let Some(correlation) = self.audit_intent(
                        &se,
                        serde_json::json!({
                            "operation": operation, "tx_hash": format!("{other:#x}")
                        }),
                    ) else {
                        break 'entries;
                    };
                    let found = chain.receipt(other).await;
                    if !self.audit_result(&se, &correlation, serde_json::json!({
                        "outcome": match &found { Ok(Some(_)) => "found", Ok(None) => "not_found", Err(_) => "error" }
                    })) { break 'entries; }
                    let Ok(Some(receipt)) = found else { continue };
                    if !cancel {
                        hash = other;
                        receipt_call = Ok(Some(receipt));
                        break;
                    }
                    let record = MinedReceipt {
                        outcome: "cancelled".into(),
                        tx_hash: format!("{other:#x}"),
                        block_number: receipt.block_number,
                        contract_address: None,
                        revert_reason: None,
                    };
                    if let Ok(bytes) = serde_json::to_vec_pretty(&record)
                        && self.project_receipt(&se, &bytes).is_ok()
                    {
                        updated += 1;
                    }
                    continue 'entries;
                }
            }
            let receipt = match receipt_call {
                Ok(Some(r)) => {
                    self.backoff
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&backoff_key);
                    r
                }
                // After the nonce was spent, no receipt for this hash means a
                // replacement was mined or the endpoint lags: back off. With
                // no nonce to go by, the transaction may simply be pending, so
                // keep looking at the normal spacing.
                Ok(None) => {
                    if nonce_spent {
                        self.record_lookup_miss(backoff_key, now, true);
                    } else {
                        self.space_next_lookup(backoff_key, now);
                    }
                    continue;
                }
                // A provider that answers neither is down: back off, which
                // bounds the journaled lookups it costs.
                Err(e) => {
                    tracing::debug!(error = %e, id = %se.id, "reconcile.receipt_failed");
                    self.record_lookup_miss(backoff_key, now, nonce_spent);
                    continue;
                }
            };
            let success = receipt.status();
            let revert_reason = if success {
                None
            } else {
                let Some(trace_call) = self
                    .audited_trace_revert(&se, hash, || async {
                        chain.trace_revert(hash).await.map_err(|e| e.to_string())
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
                tx_hash: format!("{hash:#x}"),
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

    /// Recorded same-nonce attempts other than the followed hash, each
    /// flagged when it is a cancel.
    fn competing_attempts(
        &self,
        entry: &crate::outbox::SentEntry,
    ) -> Vec<(alloy::primitives::B256, bool)> {
        let Ok(dir) = self.outbox.sent_dir(&entry.wallet, &entry.chain, &entry.id) else {
            return Vec::new();
        };
        let marker = |kind: BroadcastAttemptKind| {
            std::fs::read(dir.join(kind.marker_name()))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<BroadcastAttempt>(&bytes).ok())
                .map(|attempt| attempt.tx_hash)
        };
        let file = |name: &str| std::fs::read_to_string(dir.join(name)).ok();
        // A node-refused fee repair is retired but its bytes may still mine.
        let retired_prefix = format!(
            "{}.rejected-",
            BroadcastAttemptKind::Replacement.marker_name()
        );
        let retired = std::fs::read_dir(&dir).into_iter().flatten().flatten();
        let retired = retired.filter_map(|item| {
            let name = item.file_name().into_string().ok()?;
            Some((Some(name.strip_prefix(&retired_prefix)?.to_owned()), false))
        });
        let mut out: Vec<(alloy::primitives::B256, bool)> = Vec::new();
        for (hash, cancel) in [
            (file("cancel_tx_hash"), true),
            (marker(BroadcastAttemptKind::CancelReplacement), true),
            (marker(BroadcastAttemptKind::Confirm), false),
            (marker(BroadcastAttemptKind::Replacement), false),
            (file("replacement_tx_hash"), false),
        ]
        .into_iter()
        .chain(retired)
        {
            if let Some(hash) = hash.and_then(|hash| hash.trim().parse().ok())
                && hash != entry.hash
                && !out.iter().any(|(seen, _)| *seen == hash)
            {
                out.push((hash, cancel));
            }
        }
        out
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
        hash: alloy::primitives::B256,
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
            "tx_hash": format!("{hash:#x}"),
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
        add_sent(&outbox, "tx-1", 0, 7);
        (directory, outbox)
    }

    /// A sent transaction from the fixture sender with `nonce` and a hash of
    /// repeated `hash_byte`.
    fn add_sent(outbox: &Outbox, id: &str, nonce: u64, hash_byte: u8) {
        let staged = StagedTx {
            id: id.into(),
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
            nonce,
            policy_checks: vec![],
            created_ms: 0,
            expires_ms: 0,
            status: TxStatus::Sent,
            action_kind: TxActionKind::Unknown,
            review_mode: None,
            tx_hash: Some(format!(
                "{:#x}",
                alloy::primitives::B256::repeat_byte(hash_byte)
            )),
            token: None,
            nft: None,
            usd_value: None,
            valuation: None,
            depends_on: None,
            action_id: None,
            execution_origin: None,
        };
        outbox.write_pending(&staged, "# plan").unwrap();
        let pending = outbox.read("alice", "anvil", id).unwrap();
        outbox
            .transition(&pending, crate::outbox::OutboxState::Sent)
            .unwrap();
    }

    /// A test clock's elapsed time, and the seconds to set it to.
    type ClockOnNonce = Arc<Mutex<Option<(Arc<Mutex<Duration>>, u64)>>>;

    /// A JSON-RPC endpoint that keeps serving. `eth_getTransactionCount`
    /// answers with the confirmed `nonce`, or an error while it is `None`;
    /// `eth_getTransactionReceipt` answers with `receipt` and is counted in
    /// `calls`.
    #[derive(Clone)]
    struct MockRpc {
        nonce: Arc<Mutex<Option<u64>>>,
        receipt: Arc<Mutex<serde_json::Value>>,
        receipt_fails: Arc<Mutex<bool>>,
        /// The JSON-RPC error a failing receipt lookup answers with.
        receipt_error: serde_json::Value,
        /// Every method requested, in order.
        methods: Arc<Mutex<Vec<String>>>,
        calls: Arc<AtomicUsize>,
        nonce_calls: Arc<AtomicUsize>,
        /// Set the test clock to this many seconds when the next nonce read
        /// is answered, simulating a slow read inside one tick.
        clock_on_nonce: ClockOnNonce,
        fail_result_audit: Option<Arc<AuditLog>>,
        receipt_hash: Option<String>,
    }

    impl MockRpc {
        fn new(nonce: Option<u64>, receipt: serde_json::Value) -> Self {
            Self {
                nonce: Arc::new(Mutex::new(nonce)),
                receipt: Arc::new(Mutex::new(receipt)),
                receipt_fails: Arc::new(Mutex::new(false)),
                receipt_error: serde_json::json!({"code": -32000, "message": "unavailable"}),
                methods: Arc::new(Mutex::new(Vec::new())),
                calls: Arc::new(AtomicUsize::new(0)),
                nonce_calls: Arc::new(AtomicUsize::new(0)),
                clock_on_nonce: Arc::new(Mutex::new(None)),
                fail_result_audit: None,
                receipt_hash: None,
            }
        }

        fn lookups(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    async fn mock_chain(rpc: MockRpc) -> ChainClient {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let rpc = rpc.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let mut request = vec![0_u8; 8192];
                    let Ok(read) = stream.read(&mut request).await else {
                        return;
                    };
                    let request_text = String::from_utf8_lossy(&request[..read]);
                    let request_body = request_text.split("\r\n\r\n").nth(1).unwrap_or("{}");
                    let request_json: serde_json::Value = serde_json::from_str(request_body)
                        .unwrap_or_else(|_| serde_json::json!({}));
                    let id = request_json
                        .get("id")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    let reply = |field: &str, value: serde_json::Value| serde_json::json!({"jsonrpc": "2.0", "id": id, field: value});
                    if let Some(method) = request_json["method"].as_str() {
                        rpc.methods.lock().unwrap().push(method.to_owned());
                    }
                    let body = match request_json["method"].as_str() {
                        Some("eth_getTransactionCount") => {
                            rpc.nonce_calls.fetch_add(1, Ordering::SeqCst);
                            if let Some((elapsed, secs)) = rpc.clock_on_nonce.lock().unwrap().take()
                            {
                                *elapsed.lock().unwrap() = Duration::from_secs(secs);
                            }
                            match *rpc.nonce.lock().unwrap() {
                                Some(nonce) => {
                                    reply("result", serde_json::json!(format!("{nonce:#x}")))
                                }
                                None => reply(
                                    "error",
                                    serde_json::json!({"code": -32000, "message": "unavailable"}),
                                ),
                            }
                        }
                        Some("eth_getTransactionReceipt") => {
                            rpc.calls.fetch_add(1, Ordering::SeqCst);
                            if let Some(audit) = &rpc.fail_result_audit {
                                audit.fail_next_write_for_test();
                            }
                            if *rpc.receipt_fails.lock().unwrap() {
                                reply("error", rpc.receipt_error.clone())
                            } else if rpc.receipt_hash.as_ref().is_some_and(|hash| {
                                request_json["params"][0].as_str() != Some(hash.as_str())
                            }) {
                                reply("result", serde_json::Value::Null)
                            } else {
                                reply("result", rpc.receipt.lock().unwrap().clone())
                            }
                        }
                        _ => reply("result", serde_json::Value::Null),
                    }
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        let mut spec = ChainSpec::anvil_default();
        spec.rpc_urls = vec![format!("http://{address}")];
        ChainClient::new(spec).unwrap()
    }

    /// A chain where the sent fixture's nonce (0) is already spent, answering
    /// receipt lookups with `result_json`.
    async fn receipt_chain(
        result_json: &'static str,
        calls: Arc<AtomicUsize>,
        fail_result_audit: Option<Arc<AuditLog>>,
    ) -> ChainClient {
        let mut rpc = MockRpc::new(Some(1), serde_json::from_str(result_json).unwrap());
        rpc.calls = calls;
        rpc.fail_result_audit = fail_result_audit;
        mock_chain(rpc).await
    }

    /// A successful receipt for the sent fixture's transaction.
    fn mined_receipt() -> serde_json::Value {
        serde_json::json!({
            "transactionHash": format!("{:#x}", alloy::primitives::B256::repeat_byte(7)),
            "transactionIndex": "0x0",
            "blockHash": format!("{:#x}", alloy::primitives::B256::repeat_byte(9)),
            "blockNumber": "0x5",
            "from": "0x0000000000000000000000000000000000000001",
            "to": "0x0000000000000000000000000000000000000002",
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "contractAddress": null,
            "logs": [],
            "logsBloom": format!("0x{}", "00".repeat(256)),
            "status": "0x1",
            "effectiveGasPrice": "0x1",
            "type": "0x2"
        })
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
    async fn a_pending_transaction_is_looked_up_only_once_its_nonce_is_spent() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        // The receipt is already available, but the sender's confirmed nonce
        // has not passed the transaction's (0): nothing can be mined yet.
        let rpc = MockRpc::new(Some(0), mined_receipt());
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let reconciler = Reconciler::new(outbox.clone(), chains, audit.clone());
        for _ in 0..3 {
            assert_eq!(reconciler.tick().await, 0);
        }
        assert_eq!(rpc.lookups(), 0);
        assert_eq!(
            audit.count().unwrap(),
            0,
            "a pending transaction journals nothing"
        );

        // The tick after the nonce advances records the receipt.
        *rpc.nonce.lock().unwrap() = Some(1);
        assert_eq!(reconciler.tick().await, 1);
        assert_eq!(rpc.lookups(), 1);
        assert_eq!(
            outbox
                .read_receipt("alice", "anvil", "tx-1")
                .unwrap()
                .unwrap()
                .outcome,
            "success"
        );
        assert!(audit.pending_effect_correlations().unwrap().is_empty());
    }

    /// A reconciler over the fixture outbox whose clock a test sets in
    /// seconds.
    fn clocked(
        outbox: Outbox,
        chains: ChainRegistry,
        audit: Arc<AuditLog>,
    ) -> (Reconciler, impl Fn(u64)) {
        let (reconciler, elapsed) = clocked_with_elapsed(outbox, chains, audit);
        (reconciler, move |secs| {
            *elapsed.lock().unwrap() = Duration::from_secs(secs)
        })
    }

    fn clocked_with_elapsed(
        outbox: Outbox,
        chains: ChainRegistry,
        audit: Arc<AuditLog>,
    ) -> (Reconciler, Arc<Mutex<Duration>>) {
        let start = Instant::now();
        let elapsed = Arc::new(Mutex::new(Duration::ZERO));
        let clock_elapsed = elapsed.clone();
        let reconciler = Reconciler::new(outbox, chains, audit)
            .with_clock(Arc::new(move || start + *clock_elapsed.lock().unwrap()));
        (reconciler, elapsed)
    }

    #[tokio::test]
    async fn a_mined_cancel_terminates_the_original_without_reporting_its_success() {
        let (_directory, outbox) = sent_outbox();
        let entry = outbox.read("alice", "anvil", "tx-1").unwrap();
        let hash = format!("{:#x}", alloy::primitives::B256::repeat_byte(8));
        outbox
            .write_artefact(&entry.dir, "cancel_tx_hash", hash.as_bytes())
            .unwrap();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let mut rpc = MockRpc::new(Some(1), mined_receipt());
        rpc.receipt_hash = Some(hash.clone());
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc).await);
        let reconciler = Reconciler::new(outbox.clone(), chains, audit);
        assert_eq!(reconciler.tick().await, 1);
        let receipt = outbox
            .read_receipt("alice", "anvil", "tx-1")
            .unwrap()
            .unwrap();
        assert_eq!(receipt.outcome, "cancelled");
        assert_eq!(receipt.tx_hash, hash);
        assert!(!receipt.is_success());
        assert_eq!(
            outbox.read("alice", "anvil", "tx-1").unwrap().staged.status,
            TxStatus::Cancelled
        );
        assert_eq!(reconciler.tick().await, 0);
    }

    #[tokio::test]
    async fn original_receipt_is_recorded_when_it_beats_a_cancel_replacement() {
        let (_directory, outbox) = sent_outbox();
        let entry = outbox.read("alice", "anvil", "tx-1").unwrap();
        outbox
            .write_artefact(
                &entry.dir,
                "cancel_tx_hash",
                format!("{:#x}", alloy::primitives::B256::repeat_byte(8)).as_bytes(),
            )
            .unwrap();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let rpc = MockRpc::new(Some(1), mined_receipt());
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc).await);
        let reconciler = Reconciler::new(outbox.clone(), chains, audit);
        assert_eq!(reconciler.tick().await, 1);
        assert!(
            outbox
                .read_receipt("alice", "anvil", "tx-1")
                .unwrap()
                .is_some()
        );
    }

    /// A fee repair follows the replacement hash, but the rejected original
    /// can still win the nonce. Its receipt settles the row.
    #[tokio::test]
    async fn the_original_receipt_settles_a_row_that_follows_its_replacement() {
        let (_directory, outbox) = sent_outbox();
        let entry = outbox.read("alice", "anvil", "tx-1").unwrap();
        let original = format!("{:#x}", alloy::primitives::B256::repeat_byte(8));
        let attempt = BroadcastAttempt {
            schema: "bloom.broadcast_attempted.v1".into(),
            tx_hash: original.clone(),
            raw_tx_blake3: String::new(),
            raw_tx_path: BroadcastAttemptKind::Confirm.raw_name().into(),
            from: entry.staged.from.clone(),
            to: entry.staged.to.clone(),
            nonce: 0,
            chain_id: 31337,
            created_ms: 0,
            transport: crate::outbox::BroadcastTransport::PublicRpc,
            private_provider: None,
        };
        outbox
            .write_broadcast_attempt(&entry, BroadcastAttemptKind::Confirm, &attempt)
            .unwrap();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let mut rpc = MockRpc::new(Some(1), mined_receipt());
        rpc.receipt_hash = Some(original.clone());
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc).await);
        let reconciler = Reconciler::new(outbox.clone(), chains, audit);
        assert_eq!(reconciler.tick().await, 1);
        let receipt = outbox
            .read_receipt("alice", "anvil", "tx-1")
            .unwrap()
            .unwrap();
        assert_eq!(receipt.outcome, "success");
        assert_eq!(receipt.tx_hash, original);
        assert_eq!(reconciler.tick().await, 0);
    }

    /// A refused fee repair is retired, but its signed bytes may still be
    /// mined. Its retained hash settles the row.
    #[tokio::test]
    async fn a_retired_rejected_attempt_still_settles_the_row() {
        let (_directory, outbox) = sent_outbox();
        let entry = outbox.read("alice", "anvil", "tx-1").unwrap();
        let rejected = format!("{:#x}", alloy::primitives::B256::repeat_byte(9));
        let attempt = BroadcastAttempt {
            schema: "bloom.broadcast_attempted.v1".into(),
            tx_hash: rejected.clone(),
            raw_tx_blake3: String::new(),
            raw_tx_path: BroadcastAttemptKind::Replacement.raw_name().into(),
            from: entry.staged.from.clone(),
            to: entry.staged.to.clone(),
            nonce: 0,
            chain_id: 31337,
            created_ms: 0,
            transport: crate::outbox::BroadcastTransport::PublicRpc,
            private_provider: None,
        };
        outbox
            .write_broadcast_attempt(&entry, BroadcastAttemptKind::Replacement, &attempt)
            .unwrap();
        outbox
            .set_aside_rejected_attempt(&entry, BroadcastAttemptKind::Replacement, "ceremony.json")
            .unwrap();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let mut rpc = MockRpc::new(Some(1), mined_receipt());
        rpc.receipt_hash = Some(rejected.clone());
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc).await);
        let reconciler = Reconciler::new(outbox.clone(), chains, audit);
        assert_eq!(reconciler.tick().await, 1);
        let receipt = outbox
            .read_receipt("alice", "anvil", "tx-1")
            .unwrap()
            .unwrap();
        assert_eq!(receipt.tx_hash, rejected);
    }

    #[tokio::test]
    async fn a_provider_without_nonces_still_reconciles() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        // The nonce method fails but receipts are served.
        let rpc = MockRpc::new(None, mined_receipt());
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let reconciler = Reconciler::new(outbox.clone(), chains, audit);
        assert_eq!(reconciler.tick().await, 1);
        assert!(
            outbox
                .read_receipt("alice", "anvil", "tx-1")
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn without_nonces_a_pending_transaction_keeps_the_normal_cadence() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let rpc = MockRpc::new(None, serde_json::Value::Null);
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let (reconciler, at) = clocked(outbox, chains, audit);
        // Still looked up every tick well past the grace window: with no nonce
        // to go by, a receipt may appear at any moment.
        let ticks: Vec<u64> = (0..50).map(|tick| tick * 15).collect();
        for secs in &ticks {
            at(*secs);
            reconciler.tick().await;
        }
        assert_eq!(rpc.lookups(), ticks.len());
    }

    #[tokio::test]
    async fn a_provider_that_answers_nothing_backs_off() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let rpc = MockRpc::new(None, mined_receipt());
        *rpc.receipt_fails.lock().unwrap() = true;
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let (reconciler, at) = clocked(outbox.clone(), chains, audit.clone());
        for secs in [0, 15, 60, 240, 301, 320] {
            at(secs);
            reconciler.tick().await;
        }
        assert_eq!(rpc.lookups(), 5, "the grace window, then deferred");
        assert_eq!(audit.count().unwrap(), 10);
        // Recovery is picked up at the next scheduled lookup.
        *rpc.receipt_fails.lock().unwrap() = false;
        at(332);
        assert_eq!(reconciler.tick().await, 1);
    }

    /// Polygon's public endpoint answers a receipt lookup it cannot serve with
    /// an authorization error rather than `null`. That error must stay visible
    /// and leave the entry sent and unprojected until the receipt arrives; the
    /// reconciler never signs or broadcasts.
    #[tokio::test]
    async fn receipt_lookup_errors_keep_the_entry_sent_until_the_receipt_arrives() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let mut rpc = MockRpc::new(Some(1), mined_receipt());
        rpc.receipt_error = serde_json::json!({
            "code": -32602,
            "message": "Archive requests require a personal token",
        });
        *rpc.receipt_fails.lock().unwrap() = true;
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let (reconciler, at) = clocked(outbox.clone(), chains, audit.clone());
        for secs in [0, 15, 60, 240, 301, 320] {
            at(secs);
            assert_eq!(reconciler.tick().await, 0);
            let entry = outbox.read("alice", "anvil", "tx-1").unwrap();
            assert_eq!(entry.state, crate::outbox::OutboxState::Sent);
            assert!(
                outbox
                    .read_receipt("alice", "anvil", "tx-1")
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(rpc.lookups(), 5, "the grace window, then deferred");
        let last = audit.tail(1).unwrap();
        assert_eq!(last[0].data["result"]["outcome"], "error");
        assert!(
            last[0].data["result"]["error"]
                .as_str()
                .unwrap()
                .contains("Archive requests require a personal token")
        );

        *rpc.receipt_fails.lock().unwrap() = false;
        at(332);
        assert_eq!(reconciler.tick().await, 1);
        assert_eq!(
            outbox
                .read_receipt("alice", "anvil", "tx-1")
                .unwrap()
                .unwrap()
                .outcome,
            "success"
        );
        assert!(audit.pending_effect_correlations().unwrap().is_empty());
        let methods = rpc.methods.lock().unwrap();
        assert!(
            methods
                .iter()
                .all(|m| m == "eth_getTransactionCount" || m == "eth_getTransactionReceipt"),
            "reconciliation only reads: {methods:?}"
        );
    }

    #[tokio::test]
    async fn a_fast_tick_still_journals_lookups_at_most_every_fifteen_seconds() {
        for (nonce, receipt_fails, label) in [
            (Some(1), false, "spent nonce, no receipt for this hash"),
            (None, false, "no nonce, receipt not found"),
            (None, true, "provider answers nothing"),
        ] {
            let (_directory, outbox) = sent_outbox();
            let audit_directory = tempfile::tempdir().unwrap();
            let audit =
                Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
            let rpc = MockRpc::new(nonce, serde_json::Value::Null);
            *rpc.receipt_fails.lock().unwrap() = receipt_fails;
            let chains = ChainRegistry::default();
            chains.add(mock_chain(rpc.clone()).await);
            let (reconciler, at) = clocked(outbox, chains, audit.clone());
            // Two-second ticks for one minute, all inside the grace window.
            for secs in (0..=60).step_by(2) {
                at(secs);
                reconciler.tick().await;
            }
            assert_eq!(rpc.lookups(), 4, "{label}: lookups at 0, 16, 32 and 48 s");
            assert_eq!(audit.count().unwrap(), 8, "{label}");
        }
    }

    #[tokio::test]
    async fn a_nonce_seen_spent_after_being_unavailable_is_looked_up_at_once() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let rpc = MockRpc::new(None, serde_json::Value::Null);
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let (reconciler, at) = clocked(outbox, chains, audit);
        at(0);
        assert_eq!(reconciler.tick().await, 0);
        assert_eq!(rpc.lookups(), 1);
        // Two seconds later the nonce is available, spent, and the receipt
        // exists: the no-nonce spacing must not hold the lookup back.
        *rpc.nonce.lock().unwrap() = Some(1);
        *rpc.receipt.lock().unwrap() = mined_receipt();
        at(2);
        assert_eq!(reconciler.tick().await, 1);
    }

    #[tokio::test]
    async fn spacing_is_measured_from_the_lookup_not_the_start_of_the_tick() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let rpc = MockRpc::new(Some(1), serde_json::Value::Null);
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let (reconciler, elapsed) = clocked_with_elapsed(outbox, chains, audit);
        // The tick starts at 0, but its nonce read takes until 14 s, so the
        // journaled lookup happens at 14 s.
        *rpc.clock_on_nonce.lock().unwrap() = Some((elapsed.clone(), 14));
        reconciler.tick().await;
        assert_eq!(rpc.lookups(), 1);
        let at = |secs: u64| *elapsed.lock().unwrap() = Duration::from_secs(secs);
        at(16);
        reconciler.tick().await;
        assert_eq!(rpc.lookups(), 1, "only 2 s after the previous lookup");
        at(29);
        reconciler.tick().await;
        assert_eq!(rpc.lookups(), 2);
    }

    #[tokio::test]
    async fn a_reorg_that_unspends_the_nonce_is_noticed_during_backoff() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let rpc = MockRpc::new(Some(1), serde_json::Value::Null);
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let (reconciler, at) = clocked(outbox, chains, audit);
        // Spend the grace window so the backoff is long (next lookup at 331).
        for secs in [0, 15, 30, 60, 120, 180, 240, 301] {
            at(secs);
            reconciler.tick().await;
        }
        // A reorg makes the nonce unspent; the next spaced nonce read sees it.
        *rpc.nonce.lock().unwrap() = Some(0);
        at(316);
        reconciler.tick().await;
        // Our transaction is then mined: recorded on the next tick, not at 331.
        *rpc.nonce.lock().unwrap() = Some(1);
        *rpc.receipt.lock().unwrap() = mined_receipt();
        at(318);
        assert_eq!(reconciler.tick().await, 1);
    }

    #[tokio::test]
    async fn switching_between_spent_and_unavailable_keeps_the_backoff() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let rpc = MockRpc::new(Some(1), serde_json::Value::Null);
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let (reconciler, at) = clocked(outbox, chains, audit);
        at(0);
        reconciler.tick().await;
        assert_eq!(rpc.lookups(), 1);
        // The provider fails both calls at 16 s: a miss, still spaced.
        *rpc.nonce.lock().unwrap() = None;
        *rpc.receipt_fails.lock().unwrap() = true;
        at(16);
        reconciler.tick().await;
        assert_eq!(rpc.lookups(), 2);
        // Recovery at 18 s is not a first spent observation again.
        *rpc.nonce.lock().unwrap() = Some(1);
        *rpc.receipt_fails.lock().unwrap() = false;
        at(18);
        reconciler.tick().await;
        assert_eq!(rpc.lookups(), 2, "spacing still holds after the switch");
        at(31);
        reconciler.tick().await;
        assert_eq!(rpc.lookups(), 3);
    }

    #[tokio::test]
    async fn a_flapping_nonce_read_keeps_no_nonce_lookups_spaced() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let rpc = MockRpc::new(None, serde_json::Value::Null);
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let (reconciler, at) = clocked(outbox, chains, audit);
        // Unavailable, then available and unspent, alternately every 2 s.
        for (index, secs) in (0..30).step_by(2).enumerate() {
            *rpc.nonce.lock().unwrap() = if index % 2 == 0 { None } else { Some(0) };
            at(secs);
            reconciler.tick().await;
        }
        assert_eq!(rpc.lookups(), 2, "no-nonce lookups at 0 and 16 s only");
    }

    #[tokio::test]
    async fn transactions_sharing_a_sender_read_its_nonce_once_per_tick() {
        let (_directory, outbox) = sent_outbox();
        add_sent(&outbox, "tx-2", 1, 8);
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        let rpc = MockRpc::new(Some(0), mined_receipt());
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let reconciler = Reconciler::new(outbox, chains, audit.clone());
        reconciler.tick().await;
        assert_eq!(rpc.nonce_calls.load(Ordering::SeqCst), 1);
        assert_eq!(rpc.lookups(), 0);
        assert_eq!(audit.count().unwrap(), 0);
    }

    #[tokio::test]
    async fn a_spent_nonce_without_our_receipt_backs_off_after_the_grace_window() {
        let (_directory, outbox) = sent_outbox();
        let audit_directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(audit_directory.path().join("audit.jsonl")).unwrap());
        // The nonce is spent but this hash has no receipt: a replacement was
        // mined, or the receipt endpoint lags the nonce endpoint.
        let rpc = MockRpc::new(Some(1), serde_json::Value::Null);
        let chains = ChainRegistry::default();
        chains.add(mock_chain(rpc.clone()).await);
        let start = Instant::now();
        let elapsed = Arc::new(Mutex::new(Duration::ZERO));
        let clock_elapsed = elapsed.clone();
        let reconciler = Reconciler::new(outbox, chains, audit.clone())
            .with_clock(Arc::new(move || start + *clock_elapsed.lock().unwrap()));
        let at = |secs: u64| *elapsed.lock().unwrap() = Duration::from_secs(secs);

        // Inside the grace window every tick looks the receipt up.
        for secs in [0, 15, 60, 240] {
            at(secs);
            reconciler.tick().await;
        }
        assert_eq!(rpc.lookups(), 4);
        // The first miss after the window waits two intervals.
        at(301);
        reconciler.tick().await;
        assert_eq!(rpc.lookups(), 5);
        at(320);
        reconciler.tick().await;
        assert_eq!(rpc.lookups(), 5, "deferred inside the backoff");
        at(332);
        reconciler.tick().await;
        assert_eq!(rpc.lookups(), 6);
        // The wait keeps doubling but never exceeds the cap.
        let mut now = 332;
        for _ in 0..12 {
            now += RECEIPT_LOOKUP_MAX_DELAY.as_secs();
            at(now);
            reconciler.tick().await;
        }
        assert_eq!(rpc.lookups(), 18, "capped at one lookup per interval");
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
        reconciler.record_lookup_miss("alice/anvil/gone".into(), now, true);
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
            .audited_trace_revert(&entry, entry.hash, {
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
            .audited_trace_revert(&entry, entry.hash, {
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
            .audited_trace_revert(&entry, entry.hash, || async {
                Err("trace unavailable".to_owned())
            })
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
