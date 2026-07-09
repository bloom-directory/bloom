use serde_json::{Value, json};

use crate::{CeremonyIntent, CeremonyIntentKind, Policy};

pub const DEFAULT_HYPERLIQUID_AGENT_SESSION_NAME: &str = "bloom-session";

pub fn resolve_hyperliquid_agent_session_name(agent_name: Option<&str>) -> String {
    agent_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(DEFAULT_HYPERLIQUID_AGENT_SESSION_NAME)
        .to_string()
}

pub fn hyperliquid_write_unlock_intent(
    wallet: &str,
    path_s: &str,
    segs: &[String],
    body: &[u8],
    wallet_address: Option<String>,
    wallet_policy_toml: Option<&str>,
) -> Option<CeremonyIntent> {
    let [root, network, branch, w, file] = segs else {
        return None;
    };
    if root != "hyperliquid" || w != wallet {
        return None;
    }
    let policy_lines = hyperliquid_policy_review_lines(wallet_policy_toml);
    let body_hash = blake3::hash(body).to_hex().to_string();
    if branch == "agent_sessions" && file == "new.json" {
        let mut intent = CeremonyIntent::new(
            wallet,
            "Authorize Hyperliquid Trading Session",
            CeremonyIntentKind::Other,
        );
        intent.wallet_address = wallet_address;
        intent.summary_lines = vec![
            format!("Authorize bounded Hyperliquid trading for wallet '{wallet}'."),
            format!("Venue: Hyperliquid {network}"),
            "Authority: approve a trade-only API wallet held by the Bloom daemon".into(),
        ];
        if let Ok(v) = serde_json::from_slice::<Value>(body) {
            if let Some(id) = v.get("id").and_then(Value::as_str) {
                intent.summary_lines.push(format!("Session id: {id}"));
            }
            let agent_name =
                resolve_hyperliquid_agent_session_name(v.get("agent_name").and_then(Value::as_str));
            intent
                .summary_lines
                .push(format!("Agent name: {agent_name}"));
        } else {
            intent.summary_lines.push(format!(
                "Agent name: {}",
                resolve_hyperliquid_agent_session_name(None)
            ));
        }
        intent.summary_lines.push(
            "Future matching trades may proceed without more passkey prompts until the session expires or is stopped.".into(),
        );
        intent.risk_lines = vec![
            "This grants standing Hyperliquid trading authority to a daemon-held API wallet until the session expires or is stopped.".into(),
            "The API wallet is trade-only. It does not allow withdrawals or third-party transfers.".into(),
            "Bloom must still refuse any session action that falls outside the configured Hyperliquid bounds shown below.".into(),
            "The OS passkey prompt only proves your presence for bloom/localhost; it does not display venue, size, or risk details.".into(),
        ];
        if !policy_lines.is_empty() {
            intent.policy_lines = policy_lines;
        }
        intent.artifact_paths = vec![path_s.to_string()];
        intent.canonical_subject = json!({
            "kind": "hyperliquid_agent_session_grant",
            "wallet": wallet,
            "network": network,
            "path": path_s,
            "body_blake3": body_hash,
        });
        return Some(intent);
    }
    if branch != "exchange" {
        return None;
    }
    let mut intent = CeremonyIntent::new(
        wallet,
        "Authorize Hyperliquid Trade",
        CeremonyIntentKind::Other,
    );
    intent.wallet_address = wallet_address;
    intent.summary_lines = vec![
        format!("Authorize one Hyperliquid action for wallet '{wallet}'."),
        format!("Venue: Hyperliquid {network}"),
        format!("Action file: {file}"),
    ];
    intent.risk_lines = vec![
        "This signs and submits a Hyperliquid Exchange action from the VFS write.".into(),
        "Review the JSON body and path before approving.".into(),
    ];
    intent.artifact_paths = vec![path_s.to_string()];
    if !policy_lines.is_empty() {
        intent.policy_lines = policy_lines;
    }
    intent.canonical_subject = json!({
        "kind": "hyperliquid_vfs_write",
        "wallet": wallet,
        "network": network,
        "file": file,
        "path": path_s,
        "body_blake3": body_hash,
    });
    Some(intent)
}

fn hyperliquid_policy_review_lines(wallet_policy_toml: Option<&str>) -> Vec<String> {
    let Some(policy_toml) = wallet_policy_toml else {
        return vec!["Wallet [hyperliquid] policy unavailable in review context.".into()];
    };
    let Ok(policy) = toml::from_str::<Policy>(policy_toml) else {
        return vec!["Wallet [hyperliquid] policy could not be parsed for review.".into()];
    };
    let hl = policy.hyperliquid;
    let mut lines = vec![
        "[hyperliquid_review]".into(),
        "surface = \"bounded trading session\"".into(),
        "session_key = \"trade-only API wallet\"".into(),
        "withdrawals = \"not allowed\"".into(),
        "transfers = \"not allowed\"".into(),
    ];
    if !hl.is_configured() {
        lines.push("status = \"trading is not enabled for this wallet\"".into());
        return lines;
    }
    if !hl.allowed_assets.is_empty() {
        lines.push(format!(
            "allowed_assets = \"{}\"",
            hl.allowed_assets
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    } else {
        lines.push("allowed_assets = \"UNLIMITED — any market\"".into());
    }
    if !hl.allowed_order_types.is_empty() {
        lines.push(format!(
            "allowed_order_types = \"{}\"",
            hl.allowed_order_types
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    lines.push(format!(
        "max_notional_usd = \"{}\"",
        hl.max_notional_usd
            .map(|v| format!("${}", format_usd_micro(v)))
            .unwrap_or_else(|| "UNLIMITED — no per-order cap".into())
    ));
    lines.push(format!(
        "max_position_usd = \"{}\"",
        hl.max_position_usd
            .map(|v| format!("${}", format_usd_micro(v)))
            .unwrap_or_else(|| "UNLIMITED — no position cap".into())
    ));
    lines.push(format!(
        "max_loss_usd = \"{}\"",
        hl.max_loss_usd
            .map(|v| format!("${}", format_usd_micro(v)))
            .unwrap_or_else(|| "UNLIMITED — no loss stop".into())
    ));
    lines.push(format!(
        "max_leverage = \"{}\"",
        hl.max_leverage
            .map(|v| format!("{v}x"))
            .unwrap_or_else(|| "UNLIMITED".into())
    ));
    if let Some(v) = hl.max_session_secs {
        lines.push(format!("max_session_secs = \"{v}\""));
    }
    lines.push(format!("allow_reduce_only = {}", hl.allow_reduce_only));
    lines.push(format!(
        "allow_trigger_orders = {}",
        hl.allow_trigger_orders
    ));
    lines.push(format!("allow_twap = {}", hl.allow_twap));
    lines.push(format!("allow_builder_fees = {}", hl.allow_builder_fees));
    lines.push(format!(
        "allow_vault_or_subaccount = {}",
        hl.allow_vault_or_subaccount
    ));
    lines
}

fn format_usd_micro(v: u64) -> String {
    crate::units::format_units(alloy::primitives::U256::from(v), 6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hyperliquid_agent_session_intent_shows_authority_and_bounds() {
        let body = br#"{"id":"btc-hour-1","agent_name":"bloom-btc-hour"}"#;
        let segs = vec![
            "hyperliquid".into(),
            "mainnet".into(),
            "agent_sessions".into(),
            "minnow".into(),
            "new.json".into(),
        ];
        let policy = r#"
[hyperliquid]
allowed_assets = ["BTC"]
allowed_order_types = ["limit"]
max_notional_usd = "12"
max_position_usd = "12"
max_loss_usd = "5"
max_leverage = 3
max_session_secs = 1800
allow_reduce_only = true
allow_trigger_orders = false
allow_twap = false
allow_builder_fees = false
allow_vault_or_subaccount = false
"#;
        let intent = hyperliquid_write_unlock_intent(
            "minnow",
            "/hyperliquid/mainnet/agent_sessions/minnow/new.json",
            &segs,
            body,
            Some("0xabc".into()),
            Some(policy),
        )
        .unwrap();
        let summary = intent.summary_lines.join("\n");
        let review = intent.policy_lines.join("\n");
        assert_eq!(intent.title, "Authorize Hyperliquid Trading Session");
        assert_eq!(
            intent.canonical_subject["kind"],
            "hyperliquid_agent_session_grant"
        );
        assert!(summary.contains("trade-only API wallet"));
        assert!(summary.contains("Session id: btc-hour-1"));
        assert!(summary.contains("Agent name: bloom-btc-hour"));
        assert!(summary.contains("without more passkey prompts"));
        assert!(review.contains("session_key = \"trade-only API wallet\""));
        assert!(review.contains("allowed_assets = \"BTC\""));
        assert!(review.contains("max_notional_usd = \"$12\""));
        assert!(review.contains("max_position_usd = \"$12\""));
        assert!(review.contains("max_loss_usd = \"$5\""));
        assert!(!review.contains("$12000000"));
        assert!(review.contains("max_session_secs = \"1800\""));
        assert!(review.contains("withdrawals = \"not allowed\""));
    }

    #[test]
    fn hyperliquid_agent_session_intent_shows_resolved_default_agent_name() {
        let body = br#"{"id":"btc-hour-1"}"#;
        let segs = vec![
            "hyperliquid".into(),
            "mainnet".into(),
            "agent_sessions".into(),
            "minnow".into(),
            "new.json".into(),
        ];
        let intent = hyperliquid_write_unlock_intent(
            "minnow",
            "/hyperliquid/mainnet/agent_sessions/minnow/new.json",
            &segs,
            body,
            Some("0xabc".into()),
            None,
        )
        .unwrap();
        let summary = intent.summary_lines.join("\n");
        assert!(summary.contains("Agent name: bloom-session"));
    }

    #[test]
    fn review_lines_show_unlimited_when_caps_missing() {
        let policy = r#"
[hyperliquid]
allowed_assets = ["BTC"]
max_session_secs = 1800
"#;
        let lines = hyperliquid_policy_review_lines(Some(policy)).join("\n");
        // Caps that ARE set should show their values.
        assert!(lines.contains("allowed_assets = \"BTC\""));
        assert!(lines.contains("max_session_secs = \"1800\""));
        // Caps that are NOT set must show UNLIMITED — never silently absent.
        assert!(lines.contains("max_notional_usd = \"UNLIMITED"));
        assert!(lines.contains("max_position_usd = \"UNLIMITED"));
        assert!(lines.contains("max_loss_usd = \"UNLIMITED"));
        assert!(lines.contains("max_leverage = \"UNLIMITED"));
    }

    #[test]
    fn review_lines_show_actual_values_when_all_caps_set() {
        let policy = r#"
[hyperliquid]
allowed_assets = ["BTC", "SOL"]
max_notional_usd = "100"
max_position_usd = "500"
max_loss_usd = "50"
max_leverage = 10
"#;
        let lines = hyperliquid_policy_review_lines(Some(policy)).join("\n");
        assert!(lines.contains("allowed_assets = \"BTC, SOL\""));
        assert!(lines.contains("max_notional_usd = \"$100\""));
        assert!(lines.contains("max_position_usd = \"$500\""));
        assert!(lines.contains("max_loss_usd = \"$50\""));
        assert!(lines.contains("max_leverage = \"10x\""));
        assert!(!lines.contains("UNLIMITED"));
    }
}
