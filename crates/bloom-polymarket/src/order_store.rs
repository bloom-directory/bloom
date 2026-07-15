//! Durable order drafts, receipts, audit trail, and the per-wallet order
//! lock.
//!
//! Layout under the polymarket state dir (same root as `OnboardStore` /
//! `CredentialStore`):
//!
//! ```text
//! <dir>/<wallet>/orders/drafts/<id>.json
//! <dir>/<wallet>/orders/receipts/<id>.json
//! <dir>/<wallet>/orders/audit.jsonl      (append-only)
//! <dir>/<wallet>/orders/.lock            (exclusive; stale after 5 min)
//! ```
//!
//! Drafts are reviewable snapshots — never permission to trade stale data;
//! confirm-time code revalidates everything. Receipts are the durable record
//! the daily policy cap is computed from: **posted** BUY amounts over the
//! trailing 24 h, excluding only receipts whose CLOB status definitively
//! proves no placement/fill (`unmatched`, `rejected`). Over-counting fails safe.
//!
//! The lock serializes confirm/post/receipt-write (and cancel/sell mutations)
//! per wallet so concurrent agent invocations cannot race the daily cap.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::order::OrderType;
use crate::types::Side;
use crate::{PolymarketError, Result, validate_wallet_name};

const LOCK_STALE_MS: u128 = 5 * 60 * 1000;

fn default_true() -> bool {
    true
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Lifecycle of a draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftStatus {
    Draft,
    Signed,
    Posted,
    Rejected,
    Cancelled,
    /// POST left the box but the outcome is unknown and reconciliation via
    /// open orders failed. Do not retry; investigate.
    Ambiguous,
}

impl DraftStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DraftStatus::Draft => "draft",
            DraftStatus::Signed => "signed",
            DraftStatus::Posted => "posted",
            DraftStatus::Rejected => "rejected",
            DraftStatus::Cancelled => "cancelled",
            DraftStatus::Ambiguous => "ambiguous",
        }
    }
}

/// A reviewable order draft. No secrets, no signatures — safe to expose
/// read-only through the VFS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderDraft {
    pub id: String,
    pub wallet: String,
    /// Owner EOA (the key that signs), checksummed.
    pub owner: String,
    /// Funder/maker address: the deposit wallet for signatureType 3, the
    /// owner EOA for legacy signatureType 0. `None` in pre-deposit drafts.
    #[serde(default)]
    pub funder: Option<String>,
    /// CLOB signature type (0 = EOA legacy, 3 = POLY_1271 deposit wallet).
    #[serde(default)]
    pub signature_type: u8,
    pub slug: String,
    pub question: String,
    pub condition_id: String,
    /// YES / NO.
    pub outcome: String,
    pub token_id: String,
    pub side: Side,
    pub order_type: OrderType,
    /// USD leg in micro-USD (spend for buys, proceeds for sells).
    pub amount_microusd: u64,
    /// User bound: max price for buys, min price for sells (micro).
    pub price_bound_micro: u64,
    /// Whether the limit re-derives from the book at confirm (marketable) or
    /// is pinned to `limit_price_micro` (explicit `--limit-price`).
    pub marketable: bool,
    pub limit_price_micro: u64,
    /// Shares in micro-units (multiple of 0.01 shares).
    pub size_micro: u64,
    pub tick_micro: u64,
    pub min_order_size_micro: u64,
    pub neg_risk: bool,
    pub active: bool,
    pub closed: bool,
    pub order_book_enabled: bool,
    /// Whether the market is a true binary YES/NO market (exactly two outcomes).
    /// Validated structurally at snapshot time; carried so confirm-time policy
    /// evaluates the real value instead of assuming binarity. `#[serde(default)]`
    /// ⇒ legacy drafts (pre-field) load as binary, matching prior behavior.
    #[serde(default = "default_true")]
    pub binary_outcomes: bool,
    pub best_ask_micro: Option<u64>,
    pub best_bid_micro: Option<u64>,
    pub book_snapshot_ms: u128,
    /// Snapshot of policy checks at draft time — **display only**; confirm
    /// re-evaluates policy from current config and receipts.
    pub policy_checks: serde_json::Value,
    pub status: DraftStatus,
    /// Salt of the built order, persisted just before signing so a lost POST
    /// can be reconciled (set at the `signing_prepared` step, before the
    /// signature exists).
    pub salt: Option<u64>,
    pub clob_order_id: Option<String>,
    pub clob_status: Option<String>,
    pub last_error: Option<String>,
    /// Short hash of the passkey review intent presented at confirm. The full
    /// intent is persisted via [`OrderStore::save_review_intent`].
    #[serde(default)]
    pub review_intent_hash: Option<String>,
    pub created_ms: u128,
    pub updated_ms: u128,
}

/// Durable record of one posted (or attempted) order. Inputs to the daily
/// policy cap; also what `sell` uses to reason about holdings history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderReceipt {
    pub draft_id: String,
    pub wallet: String,
    pub slug: String,
    pub token_id: String,
    pub side: Side,
    pub order_type: OrderType,
    /// Funder/maker the order was posted for (deposit wallet on sigtype 3).
    #[serde(default)]
    pub funder: Option<String>,
    /// CLOB signature type the order carried.
    #[serde(default)]
    pub signature_type: u8,
    /// USD leg, micro-USD: the **requested buy budget** (not the exact quoted
    /// maker spend — buys keep the user's bound so retries don't drift) or the
    /// **realized sell proceeds**. BUY receipts count toward the daily cap
    /// (budget ≥ realized, so the cap is conservative / over-counts, fail-safe).
    pub amount_microusd: u64,
    pub limit_price_micro: u64,
    pub size_micro: u64,
    pub salt: u64,
    pub clob_order_id: Option<String>,
    /// Exact CLOB status string (`matched`, `delayed`, `unmatched`, `live`,
    /// …) or `ambiguous` when the response was lost.
    pub clob_status: String,
    /// Filled share size in micro-units when the response reports it.
    pub filled_size_micro: Option<u64>,
    /// Raw CLOB response for audit/debugging.
    pub raw_response: serde_json::Value,
    /// Short hash of the passkey review intent that authorized this order.
    /// The full intent is in `orders/review_intents/<draft_id>.json`.
    #[serde(default)]
    pub review_intent_hash: Option<String>,
    pub posted_ms: u128,
}

/// JSON-file-backed store, one directory per wallet.
#[derive(Debug, Clone)]
pub struct OrderStore {
    dir: PathBuf,
}

impl OrderStore {
    /// `dir` is the polymarket state dir (e.g. `~/.bloom/polymarket`).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn orders_dir(&self, wallet: &str) -> PathBuf {
        self.dir.join(wallet).join("orders")
    }
    fn drafts_dir(&self, wallet: &str) -> PathBuf {
        self.orders_dir(wallet).join("drafts")
    }
    fn receipts_dir(&self, wallet: &str) -> PathBuf {
        self.orders_dir(wallet).join("receipts")
    }
    pub fn draft_path(&self, wallet: &str, id: &str) -> PathBuf {
        self.drafts_dir(wallet).join(format!("{id}.json"))
    }
    pub fn receipt_path(&self, wallet: &str, id: &str) -> PathBuf {
        self.receipts_dir(wallet).join(format!("{id}.json"))
    }
    fn review_intents_dir(&self, wallet: &str) -> PathBuf {
        self.orders_dir(wallet).join("review_intents")
    }
    pub fn review_intent_path(&self, wallet: &str, id: &str) -> PathBuf {
        self.review_intents_dir(wallet).join(format!("{id}.json"))
    }

    fn ensure_dirs(&self, wallet: &str) -> Result<()> {
        validate_wallet_name(wallet)?;
        for d in [
            self.drafts_dir(wallet),
            self.receipts_dir(wallet),
            self.review_intents_dir(wallet),
        ] {
            std::fs::create_dir_all(&d)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for d in [
                self.dir.join(wallet),
                self.orders_dir(wallet),
                self.drafts_dir(wallet),
                self.receipts_dir(wallet),
                self.review_intents_dir(wallet),
            ] {
                let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
            }
        }
        Ok(())
    }

    /// Persist the full reviewed passkey intent (opaque JSON — the store stays
    /// `bloom-proto`-free) for `id`. This is the durable, re-readable record of
    /// what the user approved; the short hash alone is not an audit record.
    pub fn save_review_intent(
        &self,
        wallet: &str,
        id: &str,
        intent: &serde_json::Value,
    ) -> Result<()> {
        self.ensure_dirs(wallet)?;
        self.write_json(&self.review_intent_path(wallet, id), intent)
    }

    pub fn load_review_intent(&self, wallet: &str, id: &str) -> Result<Option<serde_json::Value>> {
        validate_wallet_name(wallet)?;
        Self::read_json(&self.review_intent_path(wallet, id))
    }

    /// Create a new draft: allocates the next free id atomically
    /// (`create_new` refuses to overwrite a concurrent winner).
    pub fn create_draft(&self, mut draft: OrderDraft) -> Result<OrderDraft> {
        self.ensure_dirs(&draft.wallet)?;
        let existing = self.list_ids(&self.drafts_dir(&draft.wallet))?;
        let mut n = existing
            .iter()
            .filter_map(|id| id.parse::<u64>().ok())
            .max()
            .unwrap_or(0);
        for _ in 0..100 {
            n += 1;
            let id = format!("{n:04}");
            let path = self.draft_path(&draft.wallet, &id);
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => {
                    draft.id = id;
                    draft.created_ms = now_ms();
                    draft.updated_ms = draft.created_ms;
                    self.write_json(&path, &draft)?;
                    self.audit(
                        &draft.wallet,
                        "draft_created",
                        serde_json::json!({ "draft_id": draft.id, "slug": draft.slug }),
                    )?;
                    return Ok(draft);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(PolymarketError::invalid("could not allocate a draft id"))
    }

    pub fn save_draft(&self, draft: &mut OrderDraft) -> Result<()> {
        draft.updated_ms = now_ms();
        let path = self.draft_path(&draft.wallet, &draft.id);
        self.write_json(&path, draft)
    }

    pub fn load_draft(&self, wallet: &str, id: &str) -> Result<Option<OrderDraft>> {
        validate_wallet_name(wallet)?;
        Self::read_json(&self.draft_path(wallet, id))
    }

    pub fn list_drafts(&self, wallet: &str) -> Result<Vec<String>> {
        validate_wallet_name(wallet)?;
        self.list_ids(&self.drafts_dir(wallet))
    }

    pub fn save_receipt(&self, receipt: &OrderReceipt) -> Result<()> {
        self.ensure_dirs(&receipt.wallet)?;
        let path = self.receipt_path(&receipt.wallet, &receipt.draft_id);
        self.write_json(&path, receipt)?;
        self.audit(
            &receipt.wallet,
            "receipt_written",
            serde_json::json!({
                "draft_id": receipt.draft_id,
                "clob_status": receipt.clob_status,
                "amount_microusd": receipt.amount_microusd,
            }),
        )
    }

    pub fn load_receipt(&self, wallet: &str, id: &str) -> Result<Option<OrderReceipt>> {
        validate_wallet_name(wallet)?;
        Self::read_json(&self.receipt_path(wallet, id))
    }

    pub fn list_receipts(&self, wallet: &str) -> Result<Vec<String>> {
        validate_wallet_name(wallet)?;
        self.list_ids(&self.receipts_dir(wallet))
    }

    /// Posted BUY exposure over the trailing 24 h in micro-USD, fail-closed:
    /// any unreadable receipt is an error, not a skip. Receipts whose status
    /// definitively proves no placement/fill (`unmatched`, `rejected`) are
    /// excluded; everything else (matched, delayed, live, ambiguous, …) counts.
    ///
    /// Before summing, the receipt set is cross-checked against the append-only
    /// audit log: if `audit.jsonl` records a `receipt_written` for a draft whose
    /// receipt file is now missing, the store has been truncated — the daily cap
    /// would silently under-count — so this returns an error (the caller treats
    /// an unreadable exposure as a refusal when a daily cap is configured).
    pub fn daily_posted_microusd(&self, wallet: &str) -> Result<u64> {
        validate_wallet_name(wallet)?;
        let cutoff = now_ms().saturating_sub(24 * 60 * 60 * 1000);

        let present: std::collections::BTreeSet<String> =
            self.list_receipts(wallet)?.into_iter().collect();
        for draft_id in self.audited_receipt_ids_since(wallet, cutoff)? {
            if !present.contains(&draft_id) {
                return Err(PolymarketError::invalid(format!(
                    "audit log records a posted receipt for draft {draft_id} but its receipt \
                     file is missing — the receipt store may have been truncated; refusing to \
                     compute the daily cap from a tampered set"
                )));
            }
        }

        let mut total: u64 = 0;
        for id in &present {
            let r: OrderReceipt = Self::read_json(&self.receipt_path(wallet, id))?
                .ok_or_else(|| PolymarketError::invalid(format!("receipt {id} disappeared")))?;
            if r.posted_ms < cutoff || r.side != Side::Buy {
                continue;
            }
            if matches!(r.clob_status.as_str(), "unmatched" | "rejected") {
                continue;
            }
            total = total.saturating_add(r.amount_microusd);
        }
        Ok(total)
    }

    /// Distinct draft ids that the audit log shows a `receipt_written` for at or
    /// after `cutoff_ms`. Used to detect receipt-file truncation. A missing
    /// audit log yields an empty set (no tamper signal to assert against).
    fn audited_receipt_ids_since(&self, wallet: &str, cutoff_ms: u128) -> Result<Vec<String>> {
        let path = self.orders_dir(wallet).join("audit.jsonl");
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut ids = Vec::new();
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue; // tolerate a partially-written trailing line
            };
            if v.get("event").and_then(|e| e.as_str()) != Some("receipt_written") {
                continue;
            }
            let ts = v
                .get("ts_ms")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u128;
            if ts < cutoff_ms {
                continue;
            }
            if let Some(id) = v
                .get("details")
                .and_then(|d| d.get("draft_id"))
                .and_then(|d| d.as_str())
            {
                ids.push(id.to_string());
            }
        }
        Ok(ids)
    }

    /// Append one audit line (`audit.jsonl`).
    pub fn audit(&self, wallet: &str, event: &str, details: serde_json::Value) -> Result<()> {
        self.ensure_dirs(wallet)?;
        use std::io::Write;
        let line = serde_json::json!({
            "ts_ms": now_ms(),
            "event": event,
            "details": details,
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.orders_dir(wallet).join("audit.jsonl"))?;
        writeln!(f, "{line}")?;
        Ok(())
    }

    /// Take the per-wallet order lock. Held across confirm/post/receipt-write
    /// for orders, sells, and cancels. A lock older than 5 minutes is
    /// considered abandoned and is broken.
    pub fn lock(&self, wallet: &str) -> Result<OrderLock> {
        self.ensure_dirs(wallet)?;
        let path = self.orders_dir(wallet).join(".lock");
        for attempt in 0..2 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    use std::io::Write;
                    let _ = write!(
                        f,
                        "{}",
                        serde_json::json!({
                            "pid": std::process::id(),
                            "acquired_ms": now_ms(),
                        })
                    );
                    return Ok(OrderLock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                    let stale = std::fs::read_to_string(&path)
                        .ok()
                        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                        .and_then(|v| v["acquired_ms"].as_u64())
                        .map(|t| now_ms().saturating_sub(t as u128) > LOCK_STALE_MS)
                        .unwrap_or(true);
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    return Err(PolymarketError::invalid(format!(
                        "another order operation holds the lock for wallet '{wallet}' \
                         ({}); retry when it finishes",
                        path.display()
                    )));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(PolymarketError::invalid(format!(
                        "another order operation holds the lock for wallet '{wallet}'"
                    )));
                }
                Err(e) => return Err(e.into()),
            }
        }
        unreachable!("loop returns on every branch")
    }

    fn list_ids(&self, dir: &Path) -> Result<Vec<String>> {
        let mut out = Vec::new();
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for e in entries {
                    let name = e?.file_name();
                    if let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".json")) {
                        out.push(id.to_string());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        out.sort();
        Ok(out)
    }

    fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// Held lock; removing the file on drop releases it.
#[derive(Debug)]
pub struct OrderLock {
    path: PathBuf,
}

impl Drop for OrderLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Render a human-readable plan for a draft — the document an agent or human
/// reviews before any ceremony.
pub fn render_plan_md(d: &OrderDraft) -> String {
    use crate::order::format_micro;
    let mut s = String::new();
    s.push_str(&format!("# Polymarket order draft {}\n\n", d.id));
    // Make the safety state unmissable and machine-greppable: a draft has not
    // signed or posted anything. It is durable (persistent), so an agent can
    // review it across invocations before confirming.
    s.push_str(
        "Status:    DRAFT — value_moved=false order_posted=false persistent_staged_action=true\n",
    );
    s.push_str(
        "           nothing moved yet; review, then `bloom polymarket confirm <wallet> <draft-id>` to sign+post.\n",
    );
    s.push_str(&format!("Wallet:    {} ({})\n", d.wallet, d.owner));
    s.push_str(&format!(
        "Maker:     {} (signatureType {}{})\n",
        d.funder.as_deref().unwrap_or(&d.owner),
        d.signature_type,
        if d.signature_type == 3 {
            " — deposit wallet; owner EOA signs the wrapped POLY_1271 authorization"
        } else {
            " — legacy EOA (the CLOB rejects EOA makers at POST)"
        },
    ));
    s.push_str(&format!("Market:    {} ({})\n", d.question, d.slug));
    s.push_str(&format!("Condition: {}\n", d.condition_id));
    s.push_str(&format!(
        "Outcome:   {} (token {})\n",
        d.outcome, d.token_id
    ));
    s.push_str(&format!(
        "Flags:     active={} closed={} order_book={} neg_risk={}\n",
        d.active, d.closed, d.order_book_enabled, d.neg_risk
    ));
    let action = match d.side {
        Side::Buy => "BUY",
        Side::Sell => "SELL",
    };
    s.push_str(&format!(
        "\n{action} {} shares @ {} = {} pUSD ({}, {})\n",
        format_micro(d.size_micro),
        format_micro(d.limit_price_micro),
        format_micro(d.amount_microusd),
        d.order_type.as_str(),
        if d.order_type.can_rest() {
            "may rest on the book"
        } else {
            "fills now or cancels; never rests"
        },
    ));
    s.push_str(&format!(
        "Bound:     {} {} (limit {} from {})\n",
        match d.side {
            Side::Buy => "max price",
            Side::Sell => "min price",
        },
        format_micro(d.price_bound_micro),
        format_micro(d.limit_price_micro),
        if d.marketable {
            "live book"
        } else {
            "explicit --limit-price"
        },
    ));
    s.push_str(&format!(
        "Book:      best ask {} / best bid {} (tick {}, min size {}, snapshot {}ms)\n",
        d.best_ask_micro
            .map(format_micro)
            .unwrap_or_else(|| "-".into()),
        d.best_bid_micro
            .map(format_micro)
            .unwrap_or_else(|| "-".into()),
        format_micro(d.tick_micro),
        format_micro(d.min_order_size_micro),
        d.book_snapshot_ms,
    ));
    s.push_str("\n## Policy\n");
    if let Some(checks) = d.policy_checks.as_array() {
        for c in checks {
            s.push_str(&format!(
                "- [{}] {}: {}\n",
                c["outcome"].as_str().unwrap_or("?"),
                c["rule"].as_str().unwrap_or("?"),
                c["message"].as_str().unwrap_or(""),
            ));
        }
    }
    s.push_str(&format!("\nStatus: {}\n", d.status.as_str()));
    if let Some(e) = &d.last_error {
        s.push_str(&format!("Last error: {e}\n"));
    }
    s.push_str(
        "\n## Confirm\nRun `bloom polymarket confirm <wallet> <draft-id>` to revalidate, \
         sign (passkey ceremony), and post. Drafts are snapshots: market, book, and policy \
         are re-checked at confirm time.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn draft(wallet: &str) -> OrderDraft {
        OrderDraft {
            id: String::new(),
            wallet: wallet.into(),
            owner: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            funder: None,
            signature_type: 0,
            slug: "test-market".into(),
            question: "Will it?".into(),
            condition_id: "0xcond".into(),
            outcome: "YES".into(),
            token_id: "123".into(),
            side: Side::Buy,
            order_type: OrderType::FAK,
            amount_microusd: 10_000_000,
            price_bound_micro: 700_000,
            marketable: true,
            limit_price_micro: 695_000,
            size_micro: 14_380_000,
            tick_micro: 1_000,
            min_order_size_micro: 5_000_000,
            neg_risk: true,
            active: true,
            closed: false,
            order_book_enabled: true,
            binary_outcomes: true,
            best_ask_micro: Some(695_000),
            best_bid_micro: Some(690_000),
            book_snapshot_ms: 1,
            policy_checks: serde_json::json!([]),
            status: DraftStatus::Draft,
            salt: None,
            clob_order_id: None,
            clob_status: None,
            last_error: None,
            review_intent_hash: None,
            created_ms: 0,
            updated_ms: 0,
        }
    }

    #[test]
    fn draft_round_trip_and_id_allocation() {
        let tmp = TempDir::new().unwrap();
        let store = OrderStore::new(tmp.path());
        let a = store.create_draft(draft("w")).unwrap();
        let b = store.create_draft(draft("w")).unwrap();
        assert_eq!(a.id, "0001");
        assert_eq!(b.id, "0002");
        let loaded = store.load_draft("w", "0001").unwrap().unwrap();
        assert_eq!(loaded.slug, "test-market");
        assert_eq!(store.list_drafts("w").unwrap(), vec!["0001", "0002"]);
        assert!(store.load_draft("w", "0009").unwrap().is_none());
    }

    #[test]
    fn review_intent_artifact_round_trips() {
        let tmp = TempDir::new().unwrap();
        let store = OrderStore::new(tmp.path());
        assert!(store.load_review_intent("w", "0001").unwrap().is_none());
        let intent = serde_json::json!({
            "schema": "bloom.passkey_intent.v1",
            "kind": "polymarket_order",
            "canonical_subject": {"slug": "test-market", "size_micro": 5_000_000u64},
        });
        store.save_review_intent("w", "0001", &intent).unwrap();
        let loaded = store.load_review_intent("w", "0001").unwrap().unwrap();
        assert_eq!(loaded, intent);
        // hash carried on draft + receipt
        let mut d = draft("w");
        d.review_intent_hash = Some("deadbeefcafe0000".into());
        let d = store.create_draft(d).unwrap();
        let back = store.load_draft("w", &d.id).unwrap().unwrap();
        assert_eq!(back.review_intent_hash.as_deref(), Some("deadbeefcafe0000"));
    }

    #[test]
    fn daily_exposure_counts_posted_buys_only() {
        let tmp = TempDir::new().unwrap();
        let store = OrderStore::new(tmp.path());
        let now = now_ms();
        let mk = |id: &str, side: Side, status: &str, amount: u64, ts: u128| OrderReceipt {
            draft_id: id.into(),
            wallet: "w".into(),
            slug: "s".into(),
            token_id: "1".into(),
            side,
            order_type: OrderType::FAK,
            funder: None,
            signature_type: 0,
            amount_microusd: amount,
            limit_price_micro: 500_000,
            size_micro: amount * 2,
            salt: 1,
            clob_order_id: None,
            clob_status: status.into(),
            filled_size_micro: None,
            raw_response: serde_json::json!({}),
            review_intent_hash: None,
            posted_ms: ts,
        };
        store
            .save_receipt(&mk("0001", Side::Buy, "matched", 10_000_000, now))
            .unwrap();
        store
            .save_receipt(&mk("0002", Side::Buy, "unmatched", 7_000_000, now))
            .unwrap(); // zero fill
        store
            .save_receipt(&mk("0003", Side::Sell, "matched", 4_000_000, now))
            .unwrap(); // sell
        store
            .save_receipt(&mk(
                "0004",
                Side::Buy,
                "matched",
                3_000_000,
                now.saturating_sub(25 * 3600 * 1000),
            ))
            .unwrap(); // outside window
        store
            .save_receipt(&mk("0005", Side::Buy, "ambiguous", 2_000_000, now))
            .unwrap(); // counts
        store
            .save_receipt(&mk("0006", Side::Buy, "rejected", 8_000_000, now))
            .unwrap(); // no placement
        assert_eq!(store.daily_posted_microusd("w").unwrap(), 12_000_000);

        // R5: deleting a receipt file that the audit log still records as
        // written must fail closed rather than silently shrink the cap.
        std::fs::remove_file(store.receipt_path("w", "0001")).unwrap();
        let err = store.daily_posted_microusd("w").unwrap_err();
        assert!(
            err.to_string().contains("may have been truncated"),
            "expected a tamper refusal, got: {err}"
        );
    }

    #[test]
    fn lock_excludes_second_holder_and_releases_on_drop() {
        let tmp = TempDir::new().unwrap();
        let store = OrderStore::new(tmp.path());
        let l1 = store.lock("w").unwrap();
        assert!(store.lock("w").is_err());
        drop(l1);
        let _l2 = store.lock("w").unwrap();
    }

    #[test]
    fn stale_lock_is_broken() {
        let tmp = TempDir::new().unwrap();
        let store = OrderStore::new(tmp.path());
        let lock_path = tmp.path().join("w/orders/.lock");
        std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        std::fs::write(
            &lock_path,
            serde_json::json!({"pid": 1, "acquired_ms": 1}).to_string(),
        )
        .unwrap();
        let _l = store.lock("w").expect("stale lock must be breakable");
    }

    #[test]
    fn plan_renders_policy_and_confirm_sections() {
        let mut d = draft("w");
        d.id = "0001".into();
        d.policy_checks = serde_json::json!([
            {"rule": "polymarket.enabled", "outcome": "pass", "message": "trading enabled"}
        ]);
        let md = render_plan_md(&d);
        assert!(md.contains("# Polymarket order draft 0001"));
        assert!(md.contains("[pass] polymarket.enabled"));
        assert!(md.contains("## Confirm"));
        assert!(md.contains("never rests"));
    }
}
