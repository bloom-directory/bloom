//! Human-review payload for passkey ceremonies.

use serde::{Deserialize, Serialize};

const SCHEMA: &str = "bloom.passkey_intent.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyIntentKind {
    WalletUnlock,
    SignPolicy,
    EvmTransaction,
    PolymarketOrder,
    PolymarketCancel,
    PolymarketSell,
    PolymarketFund,
    PolymarketRedeem,
    PolymarketRevokeApprovals,
    RunCapability,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyIntent {
    pub schema: String,
    pub wallet: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
    pub title: String,
    pub kind: CeremonyIntentKind,
    #[serde(default)]
    pub summary_lines: Vec<String>,
    #[serde(default)]
    pub risk_lines: Vec<String>,
    #[serde(default)]
    pub policy_lines: Vec<String>,
    #[serde(default)]
    pub artifact_paths: Vec<String>,
    #[serde(default)]
    pub canonical_subject: serde_json::Value,
    pub created_at_ms: u64,
}

impl CeremonyIntent {
    pub fn new(
        wallet: impl Into<String>,
        title: impl Into<String>,
        kind: CeremonyIntentKind,
    ) -> Self {
        Self {
            schema: SCHEMA.into(),
            wallet: wallet.into(),
            wallet_address: None,
            title: title.into(),
            kind,
            summary_lines: Vec::new(),
            risk_lines: Vec::new(),
            policy_lines: Vec::new(),
            artifact_paths: Vec::new(),
            canonical_subject: serde_json::Value::Null,
            created_at_ms: now_ms_u64(),
        }
    }

    /// The 32-byte **stable subject hash**: blake3 over the canonical JSON of
    /// only `{schema, wallet, kind, canonical_subject}`. Display-only fields
    /// and `created_at_ms` are deliberately **excluded** so the hash is
    /// reproducible from the persisted `review_intent.json` for audit.
    /// serde_json (no `preserve_order`) emits object keys sorted, so this is
    /// canonical.
    pub fn stable_subject_hash(&self) -> [u8; 32] {
        let subject = serde_json::json!({
            "schema": self.schema,
            "wallet": self.wallet,
            "kind": self.kind,
            "canonical_subject": self.canonical_subject,
        });
        let bytes = serde_json::to_vec(&subject).expect("CeremonyIntent subject serializes");
        *blake3::hash(&bytes).as_bytes()
    }

    /// Short display hash: first 16 hex chars (64 bits) of the stable subject
    /// hash. Sufficient for local terminal↔browser consistency and stale-page
    /// detection; **not** adversarial tamper evidence (threat model is
    /// operator error, not a compromised binary). Audit recomputes the full
    /// subject hash from the persisted intent.
    pub fn intent_hash(&self) -> String {
        hex::encode(&self.stable_subject_hash()[..8])
    }

    // ── builder helpers (keep call sites terse) ───────────────────────────────

    pub fn with_address(mut self, addr: impl Into<String>) -> Self {
        self.wallet_address = Some(addr.into());
        self
    }
    pub fn summary(mut self, line: impl Into<String>) -> Self {
        self.summary_lines.push(line.into());
        self
    }
    pub fn risk(mut self, line: impl Into<String>) -> Self {
        self.risk_lines.push(line.into());
        self
    }
    pub fn policy(mut self, line: impl Into<String>) -> Self {
        self.policy_lines.push(line.into());
        self
    }
    pub fn artifact(mut self, path: impl Into<String>) -> Self {
        self.artifact_paths.push(path.into());
        self
    }
    /// Set the canonical (hashed) subject — the machine-readable object that
    /// determines authorization. Use integer money (wei / base units /
    /// micro-USD / micro-price), never floats or pretty strings.
    pub fn subject(mut self, subject: serde_json::Value) -> Self {
        self.canonical_subject = subject;
        self
    }
}

fn now_ms_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_hash_changes_with_subject() {
        let mut a = CeremonyIntent::new("alice", "Unlock", CeremonyIntentKind::WalletUnlock);
        a.created_at_ms = 1;
        let mut b = a.clone();
        b.canonical_subject = serde_json::json!({"digest":"0xabc"});
        assert_ne!(a.intent_hash(), b.intent_hash());
    }

    #[test]
    fn intent_hash_ignores_timestamp_and_display_wording() {
        let mut a = CeremonyIntent::new("alice", "Unlock", CeremonyIntentKind::WalletUnlock);
        a.created_at_ms = 1;
        a.summary_lines.push("first wording".into());
        a.canonical_subject = serde_json::json!({"address":"0xabc"});

        let mut b = a.clone();
        b.created_at_ms = 2;
        b.title = "Different display title".into();
        b.summary_lines = vec!["different wording".into()];

        assert_eq!(a.intent_hash(), b.intent_hash());
    }

    #[test]
    fn kind_is_part_of_the_subject_hash() {
        let subj = serde_json::json!({"x": 1});
        let a = CeremonyIntent::new("alice", "t", CeremonyIntentKind::WalletUnlock)
            .subject(subj.clone());
        let b = CeremonyIntent::new("alice", "t", CeremonyIntentKind::SignPolicy).subject(subj);
        assert_ne!(a.intent_hash(), b.intent_hash());
    }

    #[test]
    fn builder_display_helpers_do_not_change_hash() {
        let base = CeremonyIntent::new("alice", "t", CeremonyIntentKind::EvmTransaction)
            .subject(serde_json::json!({"to":"0x01","value":"7"}));
        let decorated = base
            .clone()
            .with_address("0xabc")
            .summary("human line")
            .risk("scary line")
            .policy("PASS x")
            .artifact("/tmp/review_intent.json");
        assert_eq!(base.intent_hash(), decorated.intent_hash());
        // and the 16-hex short form derives from the 32-byte stable hash
        assert_eq!(
            base.intent_hash(),
            hex::encode(&base.stable_subject_hash()[..8])
        );
    }
}
