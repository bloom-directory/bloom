//! Auth/Petal-event audit helpers.
//!
//! These helpers build [`AuditRecord`]s for auth/Petal lifecycle events
//! (sealed-action staged, grant minted, sign-hash success/denied) so that
//! every entry carries a labelled `petal_digest_kind` next to the
//! `petal_digest`. Spec §11.10 requires this labelling so audit consumers
//! and operators do not mistake a first-party placeholder digest for real
//! code attestation.
//!
//! Today every first-party digest is a placeholder, so the helper will
//! write `"placeholder"` in `data.petal_digest_kind`; once reproducible
//! build/source digests land, the same helper will write `"build"`
//! automatically.
//!
//! The helpers do **not** mutate the central [`AuditRecord`] schema. They
//! populate `AuditRecord::data` with a `serde_json::Value` that includes
//! the labelled kind. `AuditLog::append` fills in `ts_ms`, `prev`, and
//! `digest` as it does for any other record.

use bloom_auth_api::petal_identity::label_petal_digest;

use crate::audit::{AuditLog, AuditRecord};

/// Build an [`AuditRecord`] for an auth/Petal event with petal-digest
/// labelling applied.
///
/// The `kind` is a dotted event name like `"sealed.action.staged"`,
/// `"sealed.grant.minted"`, `"petal.sign.ok"`, `"petal.sign.denied"`.
///
/// `wallet` and `action_id` are optional — omit by passing `None`. The
/// `extra` value is merged into `data` under a top-level `extra` key so
/// existing keys (`action_id`, `petal_id`, `petal_digest`,
/// `petal_digest_kind`) cannot be silently overridden by callers.
///
/// `ts_ms`, `prev`, and `digest` are left as zero / empty so that
/// [`AuditLog::append`] can populate them when the record is written to
/// disk.
pub fn auth_event(
    kind: &str,
    wallet: Option<&str>,
    action_id: Option<&str>,
    petal_id: &str,
    petal_digest: &str,
    extra: serde_json::Value,
) -> AuditRecord {
    let mut data = serde_json::Map::new();
    data.insert(
        "action_id".to_string(),
        serde_json::Value::String(action_id.unwrap_or_default().to_string()),
    );
    data.insert(
        "petal_id".to_string(),
        serde_json::Value::String(petal_id.to_string()),
    );
    data.insert(
        "petal_digest".to_string(),
        serde_json::Value::String(petal_digest.to_string()),
    );
    data.insert(
        "petal_digest_kind".to_string(),
        serde_json::Value::String(label_petal_digest(petal_digest).to_string()),
    );
    data.insert("extra".to_string(), extra);

    AuditRecord {
        ts_ms: 0,
        kind: kind.to_string(),
        wallet: wallet.map(|s| s.to_string()),
        chain: None,
        data: serde_json::Value::Object(data),
        prev: String::new(),
        digest: String::new(),
    }
}

/// Append an [`auth_event`] to `audit` in one call.
///
/// Convenience wrapper that builds the record via [`auth_event`] and
/// hands it to [`AuditLog::append`]. Returns the appended record (with
/// `ts_ms`, `prev`, and `digest` filled in) or the [`crate::audit::AuditError`]
/// from the underlying append.
pub fn append_auth_event(
    audit: &AuditLog,
    kind: &str,
    wallet: Option<&str>,
    action_id: Option<&str>,
    petal_id: &str,
    petal_digest: &str,
    extra: serde_json::Value,
) -> Result<AuditRecord, crate::audit::AuditError> {
    let record = auth_event(kind, wallet, action_id, petal_id, petal_digest, extra);
    audit.append(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir_audit() -> (tempfile::TempDir, AuditLog) {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        (dir, log)
    }

    #[test]
    fn placeholder_digest_appears_in_audit_data() {
        let rec = auth_event(
            "sealed.action.staged",
            Some("my-wallet"),
            Some("act-001"),
            "evm-wallet",
            "first-party-placeholder:evm-wallet:v0",
            serde_json::json!({"plan": "send 1 ETH"}),
        );

        assert_eq!(rec.kind, "sealed.action.staged");
        assert_eq!(rec.wallet.as_deref(), Some("my-wallet"));
        assert_eq!(rec.ts_ms, 0, "ts_ms is filled in by AuditLog::append");
        assert!(rec.prev.is_empty());
        assert!(rec.digest.is_empty());

        let data = &rec.data;
        assert_eq!(data["action_id"], "act-001");
        assert_eq!(data["petal_id"], "evm-wallet");
        assert_eq!(
            data["petal_digest"],
            "first-party-placeholder:evm-wallet:v0"
        );
        assert_eq!(data["petal_digest_kind"], "placeholder");
        assert_eq!(data["extra"]["plan"], "send 1 ETH");
    }

    #[test]
    fn build_digest_appears_in_audit_data() {
        let rec = auth_event(
            "petal.sign.ok",
            Some("my-wallet"),
            Some("act-002"),
            "evm-wallet",
            "sha256:abcdef0123456789",
            serde_json::json!({"intent": "evm.tx.sign"}),
        );

        let data = &rec.data;
        assert_eq!(data["petal_digest_kind"], "build");
        assert_eq!(data["petal_digest"], "sha256:abcdef0123456789");
        assert_eq!(data["extra"]["intent"], "evm.tx.sign");
    }

    #[test]
    fn action_id_and_wallet_can_be_omitted() {
        let rec = auth_event(
            "host.note",
            None,
            None,
            "evm-wallet",
            "first-party-placeholder:evm-wallet:v0",
            serde_json::json!({}),
        );

        assert!(rec.wallet.is_none());
        let data = &rec.data;
        assert_eq!(data["action_id"], "");
        assert_eq!(data["petal_digest_kind"], "placeholder");
    }

    #[test]
    fn append_chains_records() {
        let (_dir, log) = tempdir_audit();

        let r1 = append_auth_event(
            &log,
            "sealed.action.staged",
            Some("my-wallet"),
            Some("act-001"),
            "evm-wallet",
            "first-party-placeholder:evm-wallet:v0",
            serde_json::json!({"i": 1}),
        )
        .unwrap();
        let r2 = append_auth_event(
            &log,
            "petal.sign.ok",
            Some("my-wallet"),
            Some("act-002"),
            "evm-wallet",
            "first-party-placeholder:evm-wallet:v0",
            serde_json::json!({"i": 2}),
        )
        .unwrap();
        let r3 = append_auth_event(
            &log,
            "petal.sign.denied",
            Some("my-wallet"),
            Some("act-003"),
            "evm-wallet",
            "first-party-placeholder:evm-wallet:v0",
            serde_json::json!({"i": 3}),
        )
        .unwrap();

        // ts_ms is filled in by append and is non-zero.
        assert!(r1.ts_ms > 0);
        assert!(r2.ts_ms > 0);
        assert!(r3.ts_ms > 0);

        // Chain links: each prev points at the previous record's digest.
        assert_eq!(r1.prev, "");
        assert_eq!(r2.prev, r1.digest);
        assert_eq!(r3.prev, r2.digest);

        // Each record carries a labelled kind.
        for r in [&r1, &r2, &r3] {
            assert_eq!(r.data["petal_digest_kind"], "placeholder");
        }

        // Hash chain verifies on disk.
        let path = log.path();
        AuditLog::verify(&path).unwrap();
    }

    #[test]
    fn extra_cannot_override_core_keys() {
        // Even if the caller tries to set `petal_digest_kind` via `extra`,
        // the helper's own field wins because it is inserted first/last
        // around `extra`. The implementation inserts the labelled kind
        // AFTER `extra`, so the helper always wins. This is a guardrail
        // test — the helper is the only thing that should set
        // `petal_digest_kind`.
        let rec = auth_event(
            "petal.sign.ok",
            Some("my-wallet"),
            Some("act-004"),
            "evm-wallet",
            "first-party-placeholder:evm-wallet:v0",
            serde_json::json!({
                "petal_digest_kind": "spoofed",
                "petal_id": "spoofed",
            }),
        );
        assert_eq!(rec.data["petal_digest_kind"], "placeholder");
        assert_eq!(rec.data["petal_id"], "evm-wallet");
    }
}
