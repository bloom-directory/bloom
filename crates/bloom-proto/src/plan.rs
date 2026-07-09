//! Staged-tx artefacts: the human-readable plan, policy_check, and the
//! tx state model.

use serde::{Deserialize, Serialize};

use bloom_auth_api::petal_identity::{
    FIRST_PARTY_PETAL_VERSION_V0, PETAL_ID_EVM_WALLET, PLACEHOLDER_DIGEST_EVM_WALLET,
};

use crate::policy::PolicyCheck;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TxStatus {
    Pending,
    Sent,
    Success,
    Reverted,
    Failed,
    Cancelled,
}

impl std::fmt::Display for TxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TxStatus::Pending => "pending",
            TxStatus::Sent => "sent",
            TxStatus::Success => "success",
            TxStatus::Reverted => "reverted",
            TxStatus::Failed => "failed",
            TxStatus::Cancelled => "cancelled",
        };
        f.write_str(s)
    }
}

/// Trusted application identity that originated an EVM execution request.
///
/// Older staged transactions omit this field and resolve to the native EVM
/// wallet identity through [`Default`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionOrigin {
    pub petal_id: String,
    pub petal_digest: String,
    pub petal_version: String,
}

impl Default for ExecutionOrigin {
    fn default() -> Self {
        Self {
            petal_id: PETAL_ID_EVM_WALLET.into(),
            petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
        }
    }
}

impl ExecutionOrigin {
    pub fn validate(&self) -> Result<(), String> {
        for (field, value) in [
            ("petal_id", self.petal_id.as_str()),
            ("petal_digest", self.petal_digest.as_str()),
            ("petal_version", self.petal_version.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("execution origin {field} is empty"));
            }
        }
        Ok(())
    }
}

/// A staged tx ready to be confirmed. `id` is unique per wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedTx {
    pub id: String,
    pub wallet: String,
    pub chain: String,
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    pub value_wei: String,
    pub data_hex: String,
    pub gas_limit: u64,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    /// For legacy (non-1559) chains. Mutually exclusive with the
    /// EIP-1559 fields above.
    #[serde(default)]
    pub gas_price: Option<String>,
    pub nonce: u64,
    pub policy_checks: Vec<PolicyCheck>,
    pub created_ms: u128,
    pub expires_ms: u128,
    pub status: TxStatus,
    /// Tx hash once broadcast.
    #[serde(default)]
    pub tx_hash: Option<String>,
    /// Optional ERC-20 token metadata for plan rendering. Set when the
    /// tx encodes a `transfer(address,uint256)` call against a token
    /// contract.
    #[serde(default)]
    pub token: Option<TokenRef>,
    /// Optional NFT metadata for plan rendering. Set for NFT transfer
    /// and approval intents. Mutually exclusive with `token`.
    #[serde(default)]
    pub nft: Option<NftRef>,
    /// USD-denominated value at stage time, when a price oracle was
    /// available. Persisted so the per-day rolling-window enforcement
    /// can sum historical sends without re-querying prices.
    #[serde(default)]
    pub usd_value: Option<f64>,
    /// Outbox id of a tx on the **same chain** that must mine successfully
    /// before this one may broadcast (e.g. an ERC-20 approve preceding the
    /// route that spends it). `confirm` refuses to broadcast until the
    /// dependency is reconciled to `Success`.
    #[serde(default)]
    pub depends_on: Option<String>,
    /// Central action_id allocated via the central outbox projection.
    /// Set when the tx is staged with a `CentralOutboxProjection` active,
    /// so that the daemon-wide `/outbox/` VFS surface can correlate this
    /// EVM entry to its unified action record.
    #[serde(default)]
    pub action_id: Option<String>,
    /// Optional trusted Petal provenance for EVM execution. Missing origins in
    /// historical `intent.json` entries resolve to the native EVM wallet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_origin: Option<ExecutionOrigin>,
}

impl StagedTx {
    /// Resolve the persisted execution origin, preserving native behavior for
    /// entries serialized before execution provenance existed.
    pub fn resolved_execution_origin(&self) -> ExecutionOrigin {
        self.execution_origin.clone().unwrap_or_default()
    }
}

/// Lightweight token reference embedded in a `StagedTx` for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRef {
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
    /// Recipient (decoded from the transfer call) — convenient for
    /// rendering plan.md.
    pub recipient: String,
    /// Human-readable amount in token units (e.g. "100" for 100 USDC).
    pub amount: String,
}

/// What kind of NFT-write action this staged tx encodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NftAction {
    Transfer,
    Approve,
    SetApprovalForAll,
}

/// Lightweight NFT reference embedded in a `StagedTx` for display.
/// `kind` is `"erc721"` or `"erc1155"`; `symbol` falls back to the
/// contract address when name/symbol aren't available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftRef {
    pub action: NftAction,
    pub contract: String,
    pub kind: String,
    /// Best-effort token symbol, e.g. `BAYC`. Empty string when not
    /// resolvable.
    pub symbol: String,
    /// Token id (decimal). Empty for `set_approval_for_all`.
    #[serde(default)]
    pub token_id: String,
    /// Recipient (transfer) or the approved operator (approve /
    /// set_approval_for_all). Checksummed.
    #[serde(default)]
    pub counterparty: String,
    /// Amount, ERC-1155 only.
    #[serde(default)]
    pub amount: String,
    /// `set_approval_for_all` boolean payload.
    #[serde(default)]
    pub approved: Option<bool>,
}

/// Helpers to render plan.md from a StagedTx.
pub struct PlanRender;

impl PlanRender {
    pub fn render(staged: &StagedTx, native_symbol: &str, native_decimals: u8) -> String {
        use crate::units::format_units;
        let value_u256 = alloy::primitives::U256::from_str_radix(&staged.value_wei, 10)
            .unwrap_or(alloy::primitives::U256::ZERO);
        let value_human = format_units(value_u256, native_decimals);
        let mut s = String::new();
        s.push_str(&format!("# Staged tx {}\n\n", staged.id));
        s.push_str(&format!("Wallet: {}\n", staged.wallet));
        // `From` is always the wallet's own owner/signer EOA — label it so it
        // is never read as a deposit/funder or other role address.
        s.push_str(&format!("From:   {} (owner/signer EOA)\n", staged.from));
        if let Some(tok) = &staged.token {
            // ERC-20 transfer view.
            s.push_str(&format!("To:     {} (token contract)\n", staged.to));
            s.push_str(&format!("Token:  {} ({})\n", tok.symbol, tok.address));
            s.push_str(&format!(
                "Action: Transfer {} {} to {}\n",
                tok.amount, tok.symbol, tok.recipient
            ));
        } else if let Some(nft) = &staged.nft {
            s.push_str(&format!("To:     {} (NFT contract)\n", staged.to));
            let label = if nft.symbol.is_empty() {
                nft.contract.clone()
            } else {
                format!("{} ({})", nft.symbol, nft.contract)
            };
            s.push_str(&format!("NFT:    {} [{}]\n", label, nft.kind));
            let line = match nft.action {
                NftAction::Transfer => {
                    if nft.kind.eq_ignore_ascii_case("erc1155") {
                        format!(
                            "Action: transfer ERC-1155 #{} x{} from {} to {}\n",
                            nft.token_id, nft.amount, staged.from, nft.counterparty
                        )
                    } else {
                        let label_inner = if nft.symbol.is_empty() {
                            String::new()
                        } else {
                            format!("{} ", nft.symbol)
                        };
                        format!(
                            "Action: transfer ERC-721 {}#{} from {} to {}\n",
                            label_inner, nft.token_id, staged.from, nft.counterparty
                        )
                    }
                }
                NftAction::Approve => {
                    let label_inner = if nft.symbol.is_empty() {
                        String::new()
                    } else {
                        format!("{} ", nft.symbol)
                    };
                    format!(
                        "Action: approve ERC-721 {}#{} to {}\n",
                        label_inner, nft.token_id, nft.counterparty
                    )
                }
                NftAction::SetApprovalForAll => {
                    let approved = nft.approved.unwrap_or(false);
                    let label_inner = if nft.symbol.is_empty() {
                        nft.contract.clone()
                    } else {
                        nft.symbol.clone()
                    };
                    format!(
                        "Action: set approval for all on {} -> {} ({})\n",
                        label_inner, nft.counterparty, approved
                    )
                }
            };
            s.push_str(&line);
        } else {
            s.push_str(&format!("To:     {}\n", staged.to));
        }
        s.push_str(&format!(
            "Chain:  {} (id {})\n",
            staged.chain, staged.chain_id
        ));
        s.push_str(&format!(
            "Value:  {} {} ({} wei)\n",
            value_human, native_symbol, staged.value_wei
        ));
        s.push_str(&format!("Nonce:  {}\n", staged.nonce));
        if let Some(gp) = staged.gas_price.as_deref() {
            s.push_str(&format!(
                "Gas:    limit={} gas_price={} (legacy)\n",
                staged.gas_limit, gp
            ));
        } else {
            let max_fee = staged.max_fee_per_gas.as_deref().unwrap_or("auto");
            let prio = staged.max_priority_fee_per_gas.as_deref().unwrap_or("auto");
            s.push_str(&format!(
                "Gas:    limit={} max_fee={} prio={}\n",
                staged.gas_limit, max_fee, prio
            ));
        }
        if !staged.data_hex.is_empty() && staged.data_hex != "0x" {
            s.push_str(&format!(
                "Data:   {} bytes\n",
                staged.data_hex.trim_start_matches("0x").len() / 2
            ));
        } else {
            s.push_str("Data:   (none)\n");
        }
        s.push_str("\n## Policy\n");
        if staged.policy_checks.is_empty() {
            s.push_str("- No policy rules configured.\n");
        } else {
            for c in &staged.policy_checks {
                s.push_str(&format!("- [{:?}] {}: {}\n", c.outcome, c.rule, c.message));
            }
        }
        s.push_str("\n## Confirm\n");
        s.push_str(
            "Write `y` to `confirm` to broadcast, `cancel` to discard, \
             `override` to bypass soft policy warnings.\n",
        );
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyCheck, PolicyOutcome};

    fn base_eth_send() -> StagedTx {
        StagedTx {
            id: "tx_001".to_string(),
            wallet: "alice".to_string(),
            chain: "ethereum".to_string(),
            chain_id: 1,
            from: "0xfromfromfromfromfromfromfromfromfromfrom".to_string(),
            to: "0xtotototototototototototototototototototo".to_string(),
            // 1.5 ETH
            value_wei: "1500000000000000000".to_string(),
            data_hex: "0x".to_string(),
            gas_limit: 21000,
            max_fee_per_gas: Some("30000000000".to_string()),
            max_priority_fee_per_gas: Some("2000000000".to_string()),
            gas_price: None,
            nonce: 7,
            policy_checks: vec![],
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_003_600,
            status: TxStatus::Pending,
            tx_hash: None,
            token: None,
            nft: None,
            usd_value: None,
            depends_on: None,
            action_id: None,
            execution_origin: None,
        }
    }

    #[test]
    fn tx_status_display() {
        assert_eq!(TxStatus::Pending.to_string(), "pending");
        assert_eq!(TxStatus::Sent.to_string(), "sent");
        assert_eq!(TxStatus::Success.to_string(), "success");
        assert_eq!(TxStatus::Reverted.to_string(), "reverted");
        assert_eq!(TxStatus::Failed.to_string(), "failed");
        assert_eq!(TxStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn tx_status_serde_snake_case() {
        let s = serde_json::to_string(&TxStatus::Cancelled).unwrap();
        assert_eq!(s, "\"cancelled\"");
        let back: TxStatus = serde_json::from_str("\"reverted\"").unwrap();
        assert_eq!(back, TxStatus::Reverted);
    }

    #[test]
    fn render_eth_send_eip1559_no_policy_no_data() {
        let staged = base_eth_send();
        let out = PlanRender::render(&staged, "ETH", 18);
        let expected = "\
# Staged tx tx_001

Wallet: alice
From:   0xfromfromfromfromfromfromfromfromfromfrom (owner/signer EOA)
To:     0xtotototototototototototototototototototo
Chain:  ethereum (id 1)
Value:  1.5 ETH (1500000000000000000 wei)
Nonce:  7
Gas:    limit=21000 max_fee=30000000000 prio=2000000000
Data:   (none)

## Policy
- No policy rules configured.

## Confirm
Write `y` to `confirm` to broadcast, `cancel` to discard, `override` to bypass soft policy warnings.
";
        assert_eq!(out, expected);
    }

    #[test]
    fn render_with_policy_checks() {
        let mut staged = base_eth_send();
        staged.policy_checks = vec![
            PolicyCheck {
                rule: "max_value".to_string(),
                outcome: PolicyOutcome::Pass,
                class: crate::PolicyRuleClass::Informational,
                message: "ok".to_string(),
            },
            PolicyCheck {
                rule: "allowlist".to_string(),
                outcome: PolicyOutcome::Warn,
                class: crate::PolicyRuleClass::Soft,
                message: "recipient not on allowlist".to_string(),
            },
            PolicyCheck {
                rule: "block_mainnet".to_string(),
                outcome: PolicyOutcome::Deny,
                class: crate::PolicyRuleClass::Hard,
                message: "broadcast denied".to_string(),
            },
        ];
        let out = PlanRender::render(&staged, "ETH", 18);
        assert!(out.contains("- [Pass] max_value: ok"));
        assert!(out.contains("- [Warn] allowlist: recipient not on allowlist"));
        assert!(out.contains("- [Deny] block_mainnet: broadcast denied"));
        // The "no rules" stub should NOT appear once we have rules.
        assert!(!out.contains("No policy rules configured"));
    }

    #[test]
    fn render_legacy_gas_price() {
        let mut staged = base_eth_send();
        staged.max_fee_per_gas = None;
        staged.max_priority_fee_per_gas = None;
        staged.gas_price = Some("12000000000".to_string());
        let out = PlanRender::render(&staged, "ETH", 18);
        assert!(out.contains("Gas:    limit=21000 gas_price=12000000000 (legacy)"));
        assert!(!out.contains("max_fee="));
        assert!(!out.contains("prio="));
    }

    #[test]
    fn render_eip1559_with_auto_when_fields_absent() {
        let mut staged = base_eth_send();
        staged.max_fee_per_gas = None;
        staged.max_priority_fee_per_gas = None;
        // gas_price also None → should fall through to EIP-1559 branch
        // and print "auto" placeholders.
        let out = PlanRender::render(&staged, "ETH", 18);
        assert!(out.contains("max_fee=auto"));
        assert!(out.contains("prio=auto"));
    }

    #[test]
    fn render_data_byte_count_strips_0x_prefix() {
        let mut staged = base_eth_send();
        // 4-byte selector; 8 hex chars after 0x.
        staged.data_hex = "0xa9059cbb".to_string();
        let out = PlanRender::render(&staged, "ETH", 18);
        assert!(out.contains("Data:   4 bytes"), "rendered: {out}");
    }

    #[test]
    fn render_token_transfer_view() {
        let mut staged = base_eth_send();
        staged.value_wei = "0".to_string();
        staged.token = Some(TokenRef {
            address: "0xtoken".to_string(),
            symbol: "USDC".to_string(),
            decimals: 6,
            recipient: "0xbob".to_string(),
            amount: "100".to_string(),
        });
        let out = PlanRender::render(&staged, "ETH", 18);
        assert!(
            out.contains("To:     0xtotototototototototototototototototototo (token contract)")
        );
        assert!(out.contains("Token:  USDC (0xtoken)"));
        assert!(out.contains("Action: Transfer 100 USDC to 0xbob"));
        // The plain "To:" line should not appear in the absence of a token block.
        // (We verified the qualifier above.)
    }

    #[test]
    fn render_invalid_value_wei_falls_back_to_zero() {
        let mut staged = base_eth_send();
        staged.value_wei = "not-a-number".to_string();
        let out = PlanRender::render(&staged, "ETH", 18);
        // Render should not panic and should display 0 for the human form,
        // while echoing the raw string in the (wei) suffix.
        assert!(
            out.contains("Value:  0 ETH (not-a-number wei)"),
            "out: {out}"
        );
    }

    #[test]
    fn render_uses_native_symbol_and_decimals() {
        let mut staged = base_eth_send();
        staged.chain = "polygon".to_string();
        staged.chain_id = 137;
        // 2 MATIC at 18 decimals.
        staged.value_wei = "2000000000000000000".to_string();
        let out = PlanRender::render(&staged, "MATIC", 18);
        assert!(out.contains("Chain:  polygon (id 137)"));
        assert!(out.contains("Value:  2 MATIC (2000000000000000000 wei)"));
    }

    #[test]
    fn staged_tx_json_round_trip_minimal() {
        // Build a minimal serialised form that exercises serde defaults
        // for token, tx_hash, gas_price, usd_value.
        let json = r#"{
            "id":"x","wallet":"w","chain":"anvil","chain_id":31337,
            "from":"0xa","to":"0xb","value_wei":"0","data_hex":"0x",
            "gas_limit":21000,"max_fee_per_gas":null,"max_priority_fee_per_gas":null,
            "nonce":0,"policy_checks":[],"created_ms":0,"expires_ms":0,
            "status":"pending"
        }"#;
        let staged: StagedTx = serde_json::from_str(json).unwrap();
        assert_eq!(staged.id, "x");
        assert_eq!(staged.status, TxStatus::Pending);
        assert!(staged.gas_price.is_none());
        assert!(staged.token.is_none());
        assert!(staged.tx_hash.is_none());
        assert!(staged.usd_value.is_none());
        assert!(staged.execution_origin.is_none());
        assert_eq!(
            staged.resolved_execution_origin(),
            ExecutionOrigin::default()
        );

        // Round-trip back.
        let s = serde_json::to_string(&staged).unwrap();
        let back: StagedTx = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, staged.id);
        assert_eq!(back.status, staged.status);
    }

    #[test]
    fn render_includes_id_wallet_from_to() {
        // Edge case: "empty plan" in this codebase = no policy_checks +
        // no token + empty data. The render still emits the standard
        // header, gas, and confirm sections.
        let staged = base_eth_send();
        let out = PlanRender::render(&staged, "ETH", 18);
        assert!(out.starts_with("# Staged tx tx_001\n"));
        assert!(out.contains("Wallet: alice"));
        assert!(out.contains("From:   0xfromfromfromfromfromfromfromfromfromfrom"));
        assert!(out.ends_with(
            "## Confirm\nWrite `y` to `confirm` to broadcast, `cancel` to discard, \
             `override` to bypass soft policy warnings.\n"
        ));
    }
}
