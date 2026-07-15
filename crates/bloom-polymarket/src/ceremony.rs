use bloom_proto::{CeremonyIntent, CeremonyIntentKind};
use serde_json::json;

use crate::wallet::APPROVAL_LABELS;

/// Build the human-review payload for a Polymarket onboarding run.
///
/// Keep this shared between daemon IPC and foreground CLI paths so passkey
/// review text does not drift by transport.
pub fn polymarket_onboard_ceremony_intent(
    wallet: &str,
    path: Option<&str>,
    wallet_address: Option<String>,
) -> CeremonyIntent {
    let mut intent = CeremonyIntent::new(
        wallet,
        "Approve Polymarket Onboarding",
        CeremonyIntentKind::WalletUnlock,
    );
    intent.wallet_address = wallet_address;
    let mut summary = vec![
        format!("Run Polymarket onboarding for wallet '{wallet}'."),
        "May deploy your deposit wallet, mint CLOB credentials, and create a \
         revocable builder API key (relayer submission auth only; never fund authority)."
            .to_string(),
        "Signs one approval batch granting these eight spends from your deposit wallet:"
            .to_string(),
    ];
    summary.extend(APPROVAL_LABELS.iter().map(|l| format!("  - {l}")));
    intent.summary_lines = summary;
    intent.risk_lines = vec![
        "approve(MAX) grants unlimited pUSD spending to the contracts; \
         revoke later with `bloom polymarket revoke-approvals`."
            .into(),
        "The OS passkey prompt will show bloom/localhost, not these details.".into(),
    ];
    if let Some(path) = path {
        intent.artifact_paths = vec![path.to_string()];
    }
    intent.canonical_subject = json!({
        "kind": "polymarket_onboard_begin",
        "wallet": wallet,
        "path": path,
        "approvals": APPROVAL_LABELS,
    });
    intent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onboard_intent_names_approvals_and_max_risk() {
        let intent = polymarket_onboard_ceremony_intent(
            "test-wallet",
            Some("/polymarket/onboard/test-wallet/begin"),
            Some("0x0000000000000000000000000000000000000001".into()),
        );

        let summary = intent.summary_lines.join("\n");
        for label in APPROVAL_LABELS {
            assert!(summary.contains(label), "missing approval label {label}");
        }

        let risks = intent.risk_lines.join("\n");
        assert!(risks.contains("approve(MAX)"), "{risks}");
        assert_eq!(intent.canonical_subject["kind"], "polymarket_onboard_begin");
        assert_eq!(
            intent.canonical_subject["path"],
            "/polymarket/onboard/test-wallet/begin"
        );
        assert_eq!(
            intent.wallet_address.as_deref(),
            Some("0x0000000000000000000000000000000000000001")
        );
    }
}
