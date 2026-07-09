//! Background scanner: walks outbox sent entries, identifies stuck txs,
//! and writes advisory `bump.tx`, `cancel.tx`, and `bump_advice.json`
//! artefacts next to each stuck entry.
//!
//! A tx is "stuck" if EITHER:
//! - **basefee trigger:** `current_basefee > original_max_fee * (100 + pct) / 100`
//! - **dwell trigger:** the tx is still in the mempool pending index after
//!   `stuck_after` seconds since it was sent.
//!
//! The scanner only writes artefact files — it does NOT broadcast.
//!
//! **Artefact format (advisory):** `bump.tx` / `cancel.tx` carry a
//! `kind: "bump"|"cancel"`, `replaces`, `nonce`, and a `fees` block with
//! the bumped (+12.5 %) `max_fee_per_gas` / `max_priority_fee_per_gas`.
//! This is **not** a valid `RawIntent` and cannot be staged directly by
//! copying the file into `outbox/new.tx`. The design spec calls for
//! making them stage-able by extending `RawIntent` with explicit fee
//! overrides; that work is tracked as follow-up. For now, agents must
//! read the advisory, synthesise a fresh send-style intent at the
//! advised fees, and stage that through the normal flow.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bloom_mempool::PendingTxIndex;
use parking_lot::RwLock;

use crate::outbox::{Outbox, SentEntry};

/// Per-chain map of pending-tx indexes (matches the type used in `TxEngine`).
pub type MempoolIndexes = Arc<RwLock<BTreeMap<String, Arc<PendingTxIndex>>>>;

/// Configuration for [`BumpScanner`].
#[derive(Clone)]
pub struct BumpScannerConfig {
    /// How often the background task wakes up to scan. Default: 30 s.
    pub interval: Duration,
    /// Minimum time a tx must be seen as pending before triggering the dwell
    /// check. Default: 90 s.
    pub stuck_after: Duration,
    /// Percentage above `original_max_fee` the current basefee must exceed
    /// before the basefee trigger fires. Default: 20 (%).
    pub basefee_overrun_pct: u32,
}

impl Default for BumpScannerConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            stuck_after: Duration::from_secs(90),
            basefee_overrun_pct: 20,
        }
    }
}

/// Trait for obtaining the current base fee for a chain.
/// Allows tests to inject a static value without a live RPC.
#[async_trait::async_trait]
pub trait BasefeeProvider: Send + Sync {
    async fn basefee_wei(&self, chain: &str) -> Option<u128>;
}

/// Per-wallet policy lookup. Returns `(stuck_after, basefee_overrun_pct)`
/// for a wallet — the two fields the scanner derives from
/// `policy.bump` in a wallet's `policy.toml`. The `interval` from the
/// global config is shared across wallets (the scanner is one task);
/// only the trigger thresholds vary per wallet.
pub type WalletPolicyLookup = Arc<dyn Fn(&str) -> (Duration, u32) + Send + Sync>;

/// Background scanner that identifies stuck transactions and writes
/// `bump.tx` / `cancel.tx` / `bump_advice.json` artefacts.
pub struct BumpScanner {
    outbox: Outbox,
    indexes: MempoolIndexes,
    basefee_provider: Arc<dyn BasefeeProvider>,
    cfg: BumpScannerConfig,
    /// Per-wallet override for the trigger thresholds. When `None`,
    /// `cfg.stuck_after` / `cfg.basefee_overrun_pct` are used for every
    /// wallet (back-compat: tests + existing call sites).
    wallet_policy: Option<WalletPolicyLookup>,
}

impl BumpScanner {
    pub fn new(
        outbox: Outbox,
        indexes: MempoolIndexes,
        basefee_provider: Arc<dyn BasefeeProvider>,
        cfg: BumpScannerConfig,
    ) -> Self {
        Self {
            outbox,
            indexes,
            basefee_provider,
            cfg,
            wallet_policy: None,
        }
    }

    /// Plumb a per-wallet policy lookup. The closure receives the wallet
    /// name (as stored on `SentEntry.wallet`) and returns
    /// `(stuck_after, basefee_overrun_pct)`. Errors / unknown wallets
    /// should fall back to the global default inside the closure.
    pub fn with_wallet_policy(mut self, lookup: WalletPolicyLookup) -> Self {
        self.wallet_policy = Some(lookup);
        self
    }

    fn trigger_thresholds(&self, wallet: &str) -> (Duration, u32) {
        match &self.wallet_policy {
            Some(f) => f(wallet),
            None => (self.cfg.stuck_after, self.cfg.basefee_overrun_pct),
        }
    }

    /// Run one scan pass. Public so tests can drive it deterministically.
    pub async fn tick(&self) -> anyhow::Result<()> {
        for entry in self.outbox.walk_all_sent()? {
            self.consider(entry).await?;
        }
        Ok(())
    }

    async fn consider(&self, entry: SentEntry) -> anyhow::Result<()> {
        // Skip if already mined.
        if entry.mined {
            return Ok(());
        }

        let (stuck_after, basefee_overrun_pct) = self.trigger_thresholds(&entry.wallet);

        let basefee = self.basefee_provider.basefee_wei(&entry.chain).await;
        let max_fee = entry.fees.max_fee_per_gas();
        let basefee_trigger = matches!(
            basefee,
            Some(bf) if bf > max_fee.saturating_mul(100 + basefee_overrun_pct as u128) / 100
        );

        let still_pending = self
            .indexes
            .read()
            .get(&entry.chain)
            .and_then(|idx| idx.lookup_by_hash(&entry.hash))
            .is_some();

        let dwell = entry.sent_at.elapsed().unwrap_or_default();
        let dwell_trigger = still_pending && dwell > stuck_after;

        if !(basefee_trigger || dwell_trigger) {
            return Ok(());
        }

        let bumped = bloom_mempool::compute_replacement_fees(entry.fees);
        let replaces = format!("{:#x}", entry.hash);
        let bump_tx = serde_json::json!({
            "to": format!("{:#x}", entry.to),
            "value": entry.value.to_string(),
            "data": entry.data,
            "nonce": entry.nonce,
            "fees": bumped,
            "kind": "bump",
            "replaces": replaces,
        });
        let cancel_tx = serde_json::json!({
            "to": format!("{:#x}", entry.from),
            "value": "0",
            "data": "0x",
            "nonce": entry.nonce,
            "fees": bumped,
            "kind": "cancel",
            "replaces": replaces,
        });
        let reason = if dwell_trigger {
            "stuck_dwell"
        } else {
            "basefee_overrun"
        };
        let advice = serde_json::json!({
            "reason": reason,
            "dwell_secs": dwell.as_secs(),
            "current_basefee_wei": basefee,
            "original_max_fee_per_gas": max_fee,
            "bumped_pct": 12.5,
        });

        self.outbox
            .write_sent_sibling(&entry, "bump.tx", &serde_json::to_vec_pretty(&bump_tx)?)?;
        self.outbox.write_sent_sibling(
            &entry,
            "cancel.tx",
            &serde_json::to_vec_pretty(&cancel_tx)?,
        )?;
        self.outbox.write_sent_sibling(
            &entry,
            "bump_advice.json",
            &serde_json::to_vec_pretty(&advice)?,
        )?;

        Ok(())
    }

    /// Spawn the scanner as a tokio task. Returns a shutdown sender — drop it
    /// (or call `send(())`) to stop the loop.
    pub fn spawn(self: Arc<Self>) -> tokio::sync::oneshot::Sender<()> {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let interval = self.cfg.interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = self.tick().await {
                            tracing::warn!(error = %e, "bump_scanner.tick.error");
                        }
                    }
                    _ = &mut rx => break,
                }
            }
        });
        tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    use bloom_proto::{StagedTx, TxStatus};

    struct StaticBasefee(Option<u128>);

    #[async_trait::async_trait]
    impl BasefeeProvider for StaticBasefee {
        async fn basefee_wei(&self, _chain: &str) -> Option<u128> {
            self.0
        }
    }

    /// Build a minimal `StagedTx` suitable for writing as an outbox sent entry.
    fn make_staged(
        id: &str,
        wallet: &str,
        chain: &str,
        max_fee_wei: u128,
        status: TxStatus,
        hash: &str,
    ) -> StagedTx {
        StagedTx {
            id: id.into(),
            wallet: wallet.into(),
            chain: chain.into(),
            chain_id: 1,
            from: "0x0000000000000000000000000000000000000001".into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            value_wei: "0".into(),
            data_hex: "0x".into(),
            gas_limit: 21_000,
            max_fee_per_gas: Some(max_fee_wei.to_string()),
            max_priority_fee_per_gas: Some("0".into()),
            gas_price: None,
            nonce: 0,
            policy_checks: vec![],
            created_ms: 0,
            expires_ms: 0,
            status,
            tx_hash: Some(hash.into()),
            token: None,
            nft: None,
            usd_value: None,
            depends_on: None,
            action_id: None,
            execution_origin: None,
        }
    }

    /// Write a sent entry directly to disk (bypassing TxEngine) and return
    /// the tx hash that was written.
    fn seed_sent_entry(
        outbox: &Outbox,
        wallet: &str,
        chain: &str,
        max_fee_wei: u128,
    ) -> alloy::primitives::B256 {
        seed_sent_entry_with_status(outbox, wallet, chain, max_fee_wei, TxStatus::Sent)
    }

    fn seed_sent_entry_with_status(
        outbox: &Outbox,
        wallet: &str,
        chain: &str,
        max_fee_wei: u128,
        status: TxStatus,
    ) -> alloy::primitives::B256 {
        let id = outbox.allocate_id();
        let hash_str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let staged = make_staged(&id, wallet, chain, max_fee_wei, status, hash_str);
        let dir = outbox.sent_dir(wallet, chain, &id).unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("intent.json"),
            serde_json::to_vec_pretty(&staged).unwrap(),
        )
        .unwrap();
        hash_str.parse().unwrap()
    }

    #[tokio::test]
    async fn tick_writes_bump_when_basefee_climbed_past_threshold() {
        let tmp = TempDir::new().unwrap();
        let outbox = Outbox::new(tmp.path()).unwrap();

        // Seed with max_fee = 100; basefee = 150 → 50% above, exceeds 20% threshold.
        seed_sent_entry(&outbox, "alice", "ethereum", 100);

        let indexes = Arc::new(RwLock::new(BTreeMap::new()));
        let basefee = Arc::new(StaticBasefee(Some(150)));
        let scanner = BumpScanner::new(
            outbox.clone(),
            indexes,
            basefee,
            BumpScannerConfig::default(),
        );
        scanner.tick().await.unwrap();

        // Find the id that was seeded so we can look up the artefact path.
        let entries = outbox.walk_all_sent().unwrap();
        assert_eq!(entries.len(), 1);
        let bump_path = outbox
            .sent_dir("alice", "ethereum", &entries[0].id)
            .unwrap()
            .join("bump.tx");
        assert!(bump_path.exists(), "bump.tx should have been written");

        let v: serde_json::Value = serde_json::from_slice(&fs::read(&bump_path).unwrap()).unwrap();
        assert_eq!(v["kind"], "bump");
        // TxFees is serde'd with u128_as_str, so values are strings.
        assert_eq!(
            v["fees"]["max_fee_per_gas"].as_str().unwrap(),
            "113", // ceil(100 * 9/8) = 113
            "bumped max_fee_per_gas should be 113"
        );
    }

    #[tokio::test]
    async fn tick_skips_already_mined() {
        let tmp = TempDir::new().unwrap();
        let outbox = Outbox::new(tmp.path()).unwrap();

        // Seed with Success status → mined = true.
        seed_sent_entry_with_status(&outbox, "alice", "ethereum", 100, TxStatus::Success);

        let indexes = Arc::new(RwLock::new(BTreeMap::new()));
        let basefee = Arc::new(StaticBasefee(Some(9999)));
        let scanner = BumpScanner::new(
            outbox.clone(),
            indexes,
            basefee,
            BumpScannerConfig::default(),
        );
        scanner.tick().await.unwrap();

        // No bump.tx should exist.
        let entries = outbox.walk_all_sent().unwrap();
        assert_eq!(entries.len(), 1, "expected exactly one seeded entry");
        for entry in &entries {
            let bump_path = outbox
                .sent_dir("alice", "ethereum", &entry.id)
                .unwrap()
                .join("bump.tx");
            assert!(
                !bump_path.exists(),
                "bump.tx should NOT be written for mined tx"
            );
        }
    }

    #[tokio::test]
    async fn tick_writes_cancel_alongside_bump() {
        let tmp = TempDir::new().unwrap();
        let outbox = Outbox::new(tmp.path()).unwrap();

        seed_sent_entry(&outbox, "alice", "ethereum", 100);

        let indexes = Arc::new(RwLock::new(BTreeMap::new()));
        let basefee = Arc::new(StaticBasefee(Some(150)));
        let scanner = BumpScanner::new(
            outbox.clone(),
            indexes,
            basefee,
            BumpScannerConfig::default(),
        );
        scanner.tick().await.unwrap();

        let entries = outbox.walk_all_sent().unwrap();
        assert_eq!(entries.len(), 1);
        let dir = outbox
            .sent_dir("alice", "ethereum", &entries[0].id)
            .unwrap();

        let cancel_path = dir.join("cancel.tx");
        assert!(cancel_path.exists(), "cancel.tx should have been written");
        let vc: serde_json::Value =
            serde_json::from_slice(&fs::read(&cancel_path).unwrap()).unwrap();
        assert_eq!(vc["kind"], "cancel");

        let advice_path = dir.join("bump_advice.json");
        assert!(
            advice_path.exists(),
            "bump_advice.json should have been written"
        );
        let va: serde_json::Value =
            serde_json::from_slice(&fs::read(&advice_path).unwrap()).unwrap();
        assert_eq!(va["reason"], "basefee_overrun");
    }
}
