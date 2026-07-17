//! `polymarket/...` VFS surface: public market reads, onboarding, account
//! views, staged funding requests, and trade draft/receipt reviews.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use alloy::primitives::{Address, U256};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD};
use bloom_auth_api::{
    AssuranceLevel, CanonicalEnvelope, CanonicalIntentHeader, DaemonGrantTerms, ExecutorKind,
    POLYMARKET_ORDER_SIGN_INTENT, POLYMARKET_SIGNING_ATTESTATION_FACTS_SCHEMA_V1,
    PetalPolicySnapshot, PolymarketSealedActionKind, PolymarketSigningAttestationFacts,
    SealedAction, SignHashRequest, SignedApproval, petal_identity,
};
use bloom_evm::ChainClient;
use bloom_keystore::{Keystore, KeystoreError};
use bloom_polymarket::eip712::{PUSD, PUSD_DECIMALS};
use bloom_polymarket::onboard::OnEvent;
use bloom_polymarket::order::{self, OrderType};
use bloom_polymarket::order_store::{OrderDraft, OrderReceipt, render_plan_md};
use bloom_polymarket::signing::{action_id_for, poly1271_signature_from_raw};
use bloom_polymarket::trade;
use bloom_polymarket::{
    BuilderCredentialStore, ChainReader, ClobClient, CredentialStore, DataClient, GammaClient,
    KeystoreSigner, OnboardEvent, OnboardState, Onboarder, OrderStore, PolymarketError, Side,
    Stage, validate_wallet_name,
};
use bloom_proto::audit::{AuditLog, AuditRecord};
use bloom_proto::polymarket_policy::{self as pm_policy, PolicySide, PolymarketOrderCtx};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

/// How many markets `markets/` enumerates (most active by volume).
pub const MARKETS_LIST_LIMIT: u32 = 20;

const MARKET_FILES: [&str; 3] = ["market.json", "book.json", "prices.json"];
const POSITION_FILES: [&str; 3] = ["positions.json", "trades.json", "activity.json"];
const ONBOARD_RO_FILES: [&str; 4] = [
    "status.json",
    "plan.md",
    "approvals.json",
    APPROVAL_CHALLENGE_FILE,
];
const ACCOUNT_FILES: [&str; 5] = [
    "portfolio.json",
    "orders.json",
    "status.json",
    "buying_power.json",
    "funding_options.json",
];
const FUND_FILES: [&str; 3] = ["plan.md", "request.json", "status.json"];
const DRAFT_FILES: [&str; 5] = [
    "plan.md",
    "order.json",
    "policy_check.json",
    "quote.json",
    "review_intent.json",
];

const ROOT_FILES: [&str; 1] = ["README.md"];
const APPROVAL_FILE: &str = "approval.json";
const APPROVAL_CHALLENGE_FILE: &str = "approval_challenge.json";
/// Approval-challenge TTL shared by the daemon handler and the foreground
/// CLI (both stage the same sealed actions).
pub const APPROVAL_TTL_MS: u64 = 5 * 60 * 1000;

/// Canonical subject schema tag for Polymarket order sealed actions.
const PM_ORDER_SUBJECT_SCHEMA_V1: &str = "bloom.polymarket_order_subject.v1";
/// `surface` identifier in the canonical intent header for Polymarket
/// first-party Petal sealed actions.
pub const POLYMARKET_SURFACE: &str = "polymarket";
// Per-trade auth directory for `/polymarket/trade/<wallet>/sign-hash/...`.

/// Sidecar file the CLI writes to ask for host-backed signing.
const PM_ORDER_SIGN_REQUEST_FILE: &str = "sign_request.json";
/// Sidecar file the VFS writes the host-signed wrapped signature into.
const PM_ORDER_SIGN_RESULT_FILE: &str = "sign_result.json";

const README: &[u8] = br#"# Polymarket VFS

All paths below are relative to this `polymarket/` directory. Directory
listings are authoritative: paths whose backing services are unavailable are
omitted.

## Market and account reads

| Path | Contents |
| --- | --- |
| `markets/` | Up to 20 active markets, ordered by volume. |
| `markets/<slug>/market.json` | Market metadata and outcomes. |
| `markets/<slug>/book.json` | Current YES-token order book. |
| `markets/<slug>/prices.json` | Midpoint, spread, and best buy price. |
| `search/<query>` | Market search results; encode spaces as `+`. |
| `positions/<wallet>/positions.json` | Current positions for a wallet name or address. |
| `positions/<wallet>/trades.json` | Trade history. |
| `positions/<wallet>/activity.json` | Account activity. |
| `account/<wallet>/portfolio.json` | Portfolio summary. |
| `account/<wallet>/orders.json` | Live resting orders and their ids. |
| `account/<wallet>/status.json` | Onboarding, balances, approvals, and trading readiness. |
| `account/<wallet>/buying_power.json` | Spendable pUSD and funding readiness. |
| `account/<wallet>/funding_options.json` | Supported funding routes and limits. |

## Onboarding

`onboard/<wallet>/` contains:

- `status.json` - current stage, liveness, and next required action.
- `plan.md` - the exact deployment, approval, and credential plan.
- `approvals.json` - token and exchange approvals that onboarding may grant.
- `begin` - writable sink that starts or resumes onboarding; the body is ignored.
- `approval_challenge.json` - appears when owner approval is required. Give its
  `ceremony_url` to the owner, then retry the same write to `begin` after
  approval.

Onboarding is complete when `status.json` reports the synchronized stage and
`account/<wallet>/status.json` reports `tradeable: true`.

## Funding

Create a reviewable pUSD funding request by writing JSON to
`fund/<wallet>/new`:

```json
{"target_pusd":"10","max_spend":"100","from_token":"native","slippage_bps":50}
```

`target_pusd` and `max_spend` must be positive. `from_token` may be `native`,
`POL`, `MATIC`, or an ERC-20 address. `slippage_bps` defaults to 50 and cannot
exceed 1000.

Each created request appears as `fund/<wallet>/<id>/`:

- `request.json` - immutable requested amounts and route constraints.
- `plan.md` - human-readable funding plan.
- `status.json` - `draft` or the latest execution state.
- `confirm` - writable confirmation sink. The mounted handler currently stages
  funding requests but does not execute this sink; a rejected write leaves the
  request in `draft` state.

## Trading

Create a reviewable order draft by writing JSON to `trade/<wallet>/new`:

```json
{"slug":"will-example-happen","outcome":"yes","amount":"1","max_price":"0.60"}
```

Fields:

- `slug`, `outcome`, and `amount` are required.
- `side` is `buy` by default; `sell` uses `amount` as share count.
- `max_price` bounds a buy; `min_price` bounds a sell.
- `limit_price` creates an explicit resting limit order.
- `order_type` may be `FAK`, `FOK`, or `GTC`.

Drafts appear under `trade/<wallet>/drafts/<id>/`:

- `plan.md` - review summary and confirmation requirements.
- `order.json` - canonical draft.
- `policy_check.json` - wallet-policy decisions.
- `quote.json` - size, price bounds, book snapshot, and tick data.
- `review_intent.json` - intent committed for review.
- `confirm` - writable sealed-signing bridge. A mounted write requires a
  complete prepared order sign request, which is not generated by the mounted
  draft surface. When accepted, it signs and stores an internal signing result;
  it does not post the order or create a receipt. A plain confirmation body is
  not sufficient.

Completed orders create `trade/<wallet>/receipts/<id>/receipt.json`.

Resting order ids come from `account/<wallet>/orders.json`. Cancel an order by
writing `confirm`, `y`, or `yes` to
`trade/<wallet>/orders/<order-id>/cancel`. Cancellation uses stored CLOB
credentials and executes after compliance checks; it does not request an owner
wallet signature.

## Exit and authority sinks

- `redeem/<wallet>/<slug>/confirm` - redeem a resolved market position. With
  an already-active Sealed Approval grant, a write submits the relayer batch.
  If permission is denied, this subtree does not expose the generated challenge
  or a settlement-status file.
- `revoke-approvals/<wallet>/request/confirm` - revoke Polymarket token and
  exchange approvals. It has the same active-grant requirement and does not
  expose a denied challenge or settlement-status file here.
- `withdraw/<wallet>/pusd/confirm` - advertised pUSD withdrawal sink. The
  mounted handler currently refuses execution because an amount-specific
  signed action is not available through this sink; a write must not be treated
  as a completed withdrawal.

## Status and verification

- Onboarding progress and its actionable owner challenge are exposed under
  `onboard/<wallet>/`.
- Funding request state is exposed in `fund/<wallet>/<id>/status.json`.
- Trade draft state is exposed in `trade/<wallet>/drafts/<id>/order.json`; only
  posted orders have `trade/<wallet>/receipts/<id>/receipt.json`.
- Cancellation has no dedicated status file; verify it through
  `account/<wallet>/orders.json`.
- Builder-key revocation has no dedicated status file; verify it through
  `builder-keys/<wallet>/keys.json`.
- Redemption, approval revocation, and withdrawal expose no completion receipt
  or transaction-status file in this subtree. A successful sink write must not
  be described as confirmed settlement.

## Builder keys

- `builder-keys/<wallet>/keys.json` lists builder API keys and whether Bloom
  stores each key; secrets are never exposed.
- `builder-keys/<wallet>/revoke` revokes the stored key when written with
  `confirm`, `y`, or `yes`. To select a key, write
  `{"confirm":true,"key":"<builder-key-id>"}`.

## Safety

Trading is enabled by default, but every order still passes market invariants,
wallet policy checks, price and exposure checks, review, signing, venue
compliance, receipt recording, and audit gates. Always inspect the draft or
central outbox artifacts before retrying an approval-gated sink.
"#;

const BEGIN_HINT: &[u8] = b"write anything here to (re)run onboarding; run in the foreground for passkey wallets; rests at 'fund' for pUSD; progress + liveness: status.json\n";
const TRADE_NEW_HINT: &[u8] = br#"write JSON to create a reviewable draft, e.g.
{"slug":"will-canada-win-the-2026-fifa-world-cup-755","outcome":"yes","amount":"1","max_price":"0.01"}
Then read drafts/<id>/plan.md and confirm it with:
bloom vfs write /polymarket/trade/<wallet>/drafts/<id>/confirm --unlock-wallet <wallet> --data confirm
"#;
const TRADE_CONFIRM_HINT: &[u8] = br#"write "confirm" here through the foreground CLI VFS path:
bloom vfs write /polymarket/trade/<wallet>/drafts/<id>/confirm --unlock-wallet <wallet> --data confirm

The confirm path dispatches to the same Polymarket order execution core as:
bloom polymarket confirm <wallet> <id>
"#;
const FUND_NEW_HINT: &[u8] = br#"write JSON to create a reviewable pUSD funding request, e.g.
{"target_pusd":"10","max_spend":"100","from_token":"native","slippage_bps":50}
Then read <id>/plan.md and execute it with:
bloom vfs write /polymarket/fund/<wallet>/<id>/confirm --unlock-wallet <wallet> --data confirm
"#;
const FUND_CONFIRM_HINT: &[u8] = br#"write "confirm" here through the foreground CLI VFS path:
bloom vfs write /polymarket/fund/<wallet>/<id>/confirm --unlock-wallet <wallet> --data confirm

The confirm path dispatches to the same Polymarket funding execution core as:
bloom polymarket fund <wallet> --request <id>
"#;
const REDEEM_CONFIRM_HINT: &[u8] = br#"write "confirm" here through the foreground CLI VFS path:
bloom vfs write /polymarket/redeem/<wallet>/<slug>/confirm --unlock-wallet <wallet> --data confirm

The confirm path dispatches to the same Polymarket redemption core as:
bloom polymarket redeem <wallet> <slug>

Print the plan first with: bloom polymarket redeem <wallet> <slug> --dry-run
"#;
const REVOKE_APPROVALS_CONFIRM_HINT: &[u8] = br#"write "confirm" here through the foreground CLI VFS path:
bloom vfs write /polymarket/revoke-approvals/<wallet>/request/confirm --unlock-wallet <wallet> --data confirm

The confirm path dispatches to the same Polymarket revoke-approvals core as:
bloom polymarket revoke-approvals <wallet>

Print the plan first with: bloom polymarket revoke-approvals <wallet> --dry-run
"#;
const WITHDRAW_PUSD_CONFIRM_HINT: &[u8] = br#"write a JSON/TOML body here through the foreground CLI VFS path, e.g.
{"confirm":true,"amount":"all"}
bloom vfs write /polymarket/withdraw/<wallet>/pusd/confirm --unlock-wallet <wallet> --data '{"confirm":true,"amount":"10"}'

The amount is value-moving and must be stated in the body (the path carries no
amount slot); a bare "confirm" is rejected. The confirm path dispatches to the
same Polymarket pUSD withdrawal core as:
bloom polymarket withdraw-pusd <wallet> <amount|all>

Print the plan first with: bloom polymarket withdraw-pusd <wallet> <amount|all> --dry-run
"#;
const CANCEL_HINT: &[u8] = br#"write "confirm" here to cancel this resting CLOB order.

Cancellation executes directly in the VFS after compliance checks -- no wallet
unlock is needed because it uses the wallet's stored CLOB credentials (L2 auth
only). Jurisdiction checks are hard gates for cancel.

Equivalent CLI:
bloom polymarket cancel <wallet> <order-id>

Discover resting order ids with: bloom vfs cat /polymarket/account/<wallet>/orders.json
"#;

const BUILDER_KEYS_REVOKE_HINT: &[u8] = br#"write "confirm" here to revoke the account builder API key, or JSON/TOML with an explicit key id:
{"confirm":true,"key":"<builder-key-id>"}

This mutates relayer submission auth only. Builder keys cannot move funds, and
no builder secret/passphrase is exposed through the VFS.

Equivalent CLI:
bloom polymarket builder-keys revoke <wallet> [key]
"#;

fn now_ms_u128() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn pm_now_ms_u64() -> u64 {
    now_ms_u128().try_into().unwrap_or(u64::MAX)
}

fn polymarket_onboard_auth_dir(root: &Path, wallet: &str) -> Result<PathBuf, HandlerError> {
    validate_wallet_name(wallet).map_err(err_be)?;
    Ok(root.join(wallet))
}

pub fn polymarket_onboard_action_id(wallet: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.polymarket.onboard.entry.v1");
    hasher.update(wallet.as_bytes());
    format!("pm-onboard-{}", hasher.finalize().to_hex())
}

pub fn polymarket_revoke_action_id(wallet: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.polymarket.revoke.v1");
    hasher.update(wallet.as_bytes());
    format!("pm-revoke-{}", &hasher.finalize().to_hex()[..32])
}

pub fn polymarket_withdraw_action_id(wallet: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.polymarket.withdraw.v1");
    hasher.update(wallet.as_bytes());
    format!("pm-withdraw-{}", &hasher.finalize().to_hex()[..32])
}

pub fn polymarket_redeem_action_id(wallet: &str, condition_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.polymarket.redeem.v1");
    hasher.update(wallet.as_bytes());
    hasher.update(condition_id.as_bytes());
    format!("pm-redeem-{}", &hasher.finalize().to_hex()[..32])
}

fn polymarket_onboard_envelope(
    wallet: &str,
    owner_address: &str,
) -> Result<CanonicalEnvelope, HandlerError> {
    let subject = serde_json::to_vec(&serde_json::json!({
        "schema": "bloom.polymarket_onboard_subject.v1",
        "wallet": wallet,
        "owner_address": owner_address,
        "approvals": bloom_polymarket::wallet::APPROVAL_LABELS,
        "effects": [
            "deploy_deposit_wallet_if_needed",
            "approve_spenders",
            "mint_clob_credentials",
            "create_builder_key_if_configured",
            "sync_buying_power"
        ],
    }))
    .map_err(|e| HandlerError::backend(format!("encode Polymarket onboarding intent: {e}")))?;
    Ok(CanonicalEnvelope::new(
        CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: wallet.to_string(),
            surface: "polymarket".into(),
            action_id: polymarket_onboard_action_id(wallet),
            petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network: "polygon".into(),
            account: wallet.to_string(),
            action_kind: "onboard".into(),
            value_movement: false,
            authority_change: true,
            // Must stay deterministic across repeated staging of the same
            // onboarding (re-sealing must reproduce identical bytes).
            // TODO(ws-H): commit a real onboarding expiry when Polymarket
            // staging computes venue terms.
            expires_ms: 0,
        },
        "polymarket_onboard",
        "bloom.polymarket_onboard_subject.v1",
        subject,
    ))
}

/// Sealed action for a Polymarket onboarding run: one Hardened grant
/// (max_signatures=3) covers deploy + onboarding approvals + CLOB creds + builder
/// key. Deterministic `action_id` per wallet, so re-staging is idempotent.
/// Shared by the daemon handler and the foreground CLI.
pub fn polymarket_onboard_sealed_action(
    wallet: &str,
    owner: Address,
    now_ms: u64,
) -> Result<SealedAction, HandlerError> {
    let envelope = polymarket_onboard_envelope(wallet, &format!("{owner:#x}"))?;
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("action_kind".to_string(), serde_json::json!("onboard"));
    let terms = bloom_auth_api::DaemonGrantTerms {
        max_ttl_secs: APPROVAL_TTL_MS / 1_000,
        max_signatures: 3,
        allowed_sign_intents: vec![bloom_auth_api::POLYMARKET_ONBOARDING_SIGN_INTENT.into()],
        assurance: AssuranceLevel::Hardened,
        extra,
    };
    let caps = std::collections::BTreeMap::new();
    let mut config = std::collections::BTreeMap::new();
    config.insert("chain_id".to_string(), serde_json::json!(137));
    let snapshot = bloom_auth_api::PetalPolicySnapshot {
        policy_version: 0,
        wallet: wallet.to_string(),
        petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
        petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
        caps,
        hard_rules: Vec::new(),
        step_up_rules: Vec::new(),
        config,
        budget_state: std::collections::BTreeMap::new(),
        session_scope: Some(std::collections::BTreeMap::new()),
    };
    SealedAction::new(
        envelope,
        "Polymarket onboarding (deploy + approvals + CLOB creds + builder key)".into(),
        Vec::new(),
        terms,
        snapshot,
        now_ms,
    )
    .map_err(|e| HandlerError::backend(format!("seal Polymarket onboarding action: {e}")))
}

/// Sealed action for a one-signature Polymarket relayer operation (redeem,
/// withdraw, revoke). The per-operation wrappers below fix the subject bytes,
/// intent, and assurance so the daemon handler and the foreground CLI stage
/// byte-identical actions for the same operation.
#[allow(clippy::too_many_arguments)]
fn polymarket_relayer_sealed_action(
    wallet: &str,
    action_id: &str,
    intent: &str,
    assurance: AssuranceLevel,
    subject_label: &str,
    subject_schema: &str,
    subject_bytes: Vec<u8>,
    now_ms: u64,
) -> Result<SealedAction, HandlerError> {
    let envelope = CanonicalEnvelope::new(
        CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: wallet.to_string(),
            surface: POLYMARKET_SURFACE.into(),
            action_id: action_id.into(),
            petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network: "polygon".into(),
            account: wallet.to_string(),
            action_kind: subject_label.into(),
            value_movement: true,
            authority_change: false,
            expires_ms: 0,
        },
        subject_label,
        subject_schema,
        subject_bytes,
    );
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("action_kind".to_string(), serde_json::json!(subject_label));
    let terms = bloom_auth_api::DaemonGrantTerms {
        max_ttl_secs: APPROVAL_TTL_MS / 1_000,
        max_signatures: 1,
        allowed_sign_intents: vec![intent.into()],
        assurance,
        extra,
    };
    let config = std::collections::BTreeMap::new();
    let snapshot = bloom_auth_api::PetalPolicySnapshot {
        policy_version: 0,
        wallet: wallet.to_string(),
        petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
        petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
        caps: std::collections::BTreeMap::new(),
        hard_rules: Vec::new(),
        step_up_rules: Vec::new(),
        config,
        budget_state: std::collections::BTreeMap::new(),
        session_scope: Some(std::collections::BTreeMap::new()),
    };
    SealedAction::new(
        envelope,
        format!("Polymarket {subject_label}"),
        Vec::new(),
        terms,
        snapshot,
        now_ms,
    )
    .map_err(|e| HandlerError::backend(format!("seal Polymarket {subject_label}: {e}")))
}

/// Sealed action for `revoke-approvals` (zero all allowances + operator
/// approvals via one relayer batch).
pub fn polymarket_revocation_sealed_action(
    wallet: &str,
    deposit_wallet: Address,
    now_ms: u64,
) -> Result<SealedAction, HandlerError> {
    let subject = serde_json::to_vec(&serde_json::json!({
        "schema": "bloom.polymarket_revocation_subject.v1",
        "wallet": wallet,
        "deposit_wallet": format!("{deposit_wallet:#x}"),
        "effects": ["zero_all_allowances", "revoke_all_operator_approvals"],
    }))
    .map_err(|e| HandlerError::backend(e.to_string()))?;
    polymarket_relayer_sealed_action(
        wallet,
        &polymarket_revoke_action_id(wallet),
        bloom_auth_api::POLYMARKET_REVOCATION_SIGN_INTENT,
        AssuranceLevel::Hardened,
        "revocation",
        "bloom.polymarket_revocation_subject.v1",
        subject,
        now_ms,
    )
}

/// Sealed action for `withdraw-pusd` (transfer pUSD from the deposit wallet
/// back to the owner EOA via one relayer batch).
pub fn polymarket_withdrawal_sealed_action(
    wallet: &str,
    deposit_wallet: Address,
    now_ms: u64,
) -> Result<SealedAction, HandlerError> {
    let subject = serde_json::to_vec(&serde_json::json!({
        "schema": "bloom.polymarket_withdrawal_subject.v1",
        "wallet": wallet,
        "deposit_wallet": format!("{deposit_wallet:#x}"),
        "token": "pUSD",
        "effects": ["transfer_pusd_to_owner"],
    }))
    .map_err(|e| HandlerError::backend(e.to_string()))?;
    polymarket_relayer_sealed_action(
        wallet,
        &polymarket_withdraw_action_id(wallet),
        bloom_auth_api::POLYMARKET_WITHDRAWAL_SIGN_INTENT,
        AssuranceLevel::Hardened,
        "withdrawal",
        "bloom.polymarket_withdrawal_subject.v1",
        subject,
        now_ms,
    )
}

/// Sealed action for `redeem` (burn resolved outcome tokens for pUSD via one
/// relayer batch).
pub fn polymarket_redemption_sealed_action(
    wallet: &str,
    deposit_wallet: Address,
    condition_id: &str,
    neg_risk: bool,
    now_ms: u64,
) -> Result<SealedAction, HandlerError> {
    let subject = serde_json::to_vec(&serde_json::json!({
        "schema": "bloom.polymarket_redemption_subject.v1",
        "wallet": wallet,
        "deposit_wallet": format!("{deposit_wallet:#x}"),
        "condition_id": condition_id,
        "neg_risk": neg_risk,
        "effects": ["redeem_positions"],
    }))
    .map_err(|e| HandlerError::backend(e.to_string()))?;
    polymarket_relayer_sealed_action(
        wallet,
        &polymarket_redeem_action_id(wallet, condition_id),
        bloom_auth_api::POLYMARKET_REDEMPTION_SIGN_INTENT,
        AssuranceLevel::Standard,
        "redemption",
        "bloom.polymarket_redemption_subject.v1",
        subject,
        now_ms,
    )
}

fn write_json(path: impl AsRef<Path>, value: &impl Serialize) -> Result<(), HandlerError> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value)
            .map_err(|e| HandlerError::backend(format!("encode auth json: {e}")))?,
    )?;
    Ok(())
}

// ── Sealed onboarding signer ──────────────────────────────────────────────

/// Owner-signing adapter that routes EIP-712 hash signatures through the
/// Bloom Machine's `PetalHost::sign_hash` under a live Sealed Approval grant
/// for the given action. One onboarding grant (max_signatures=3) covers all
/// onboarding signature operations: onboarding approval batch + CLOB L1 auth +
/// builder key. Public so the foreground CLI can execute the same sealed
/// relayer flows in-process.
pub struct SealedOnboardSigner {
    host: Arc<dyn bloom_auth_api::PetalHost>,
    wallet: String,
    action_id: String,
    kind: PolymarketSealedActionKind,
    owner: alloy::primitives::Address,
}

impl SealedOnboardSigner {
    pub fn new(
        host: Arc<dyn bloom_auth_api::PetalHost>,
        wallet: impl Into<String>,
        action_id: impl Into<String>,
        kind: PolymarketSealedActionKind,
        owner: alloy::primitives::Address,
    ) -> Self {
        Self {
            host,
            wallet: wallet.into(),
            action_id: action_id.into(),
            kind,
            owner,
        }
    }
}

#[async_trait::async_trait]
impl bloom_polymarket::OnboardSigner for SealedOnboardSigner {
    fn address(&self) -> alloy::primitives::Address {
        self.owner
    }

    async fn sign_eip712_hash(
        &self,
        hash: &alloy::primitives::B256,
    ) -> bloom_polymarket::Result<alloy::primitives::Signature> {
        let facts = PolymarketSigningAttestationFacts {
            facts_schema: POLYMARKET_SIGNING_ATTESTATION_FACTS_SCHEMA_V1.into(),
            kind: self.kind,
            petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            wallet: self.wallet.clone(),
            chain_id: bloom_polymarket::POLYGON,
            action_id: self.action_id.clone(),
            signing_hash: format!("{hash:#x}"),
        };
        let attestation = facts
            .signing_attestation()
            .map_err(|e| bloom_polymarket::PolymarketError::signing(e.to_string()))?;
        let intent = self.kind.intent().to_string();
        let result = self
            .host
            .sign_hash(
                bloom_auth_api::SignHashRequest {
                    wallet: self.wallet.clone(),
                    action_id: self.action_id.clone(),
                    intent,
                    hash_hex: format!("{hash:#x}"),
                },
                &attestation,
                pm_now_ms_u64(),
            )
            .await
            .map_err(|e| bloom_polymarket::PolymarketError::signing(e.to_string()))?;
        let raw = B64_STANDARD
            .decode(result.signature_b64.as_bytes())
            .map_err(|e| {
                bloom_polymarket::PolymarketError::signing(format!("decode host signature: {e}"))
            })?;
        let arr: [u8; 65] = raw.as_slice().try_into().map_err(|_| {
            bloom_polymarket::PolymarketError::signing(format!(
                "host signature is {} bytes, expected 65",
                raw.len()
            ))
        })?;
        alloy::primitives::Signature::from_raw(&arr)
            .map_err(|e| bloom_polymarket::PolymarketError::signing(e.to_string()))
    }

    async fn clob_auth_headers(
        &self,
        chain_id: u64,
        timestamp: u64,
        nonce: u32,
    ) -> bloom_polymarket::Result<Vec<(String, String)>> {
        let hash = bloom_polymarket::eip712::clob_auth_signing_hash(
            self.owner, timestamp, nonce, chain_id,
        );
        let sig = self.sign_eip712_hash(&hash).await?;
        Ok(vec![
            (
                bloom_polymarket::signer::POLY_ADDRESS.to_string(),
                format!("{:#x}", self.owner),
            ),
            (
                bloom_polymarket::signer::POLY_NONCE.to_string(),
                nonce.to_string(),
            ),
            (
                bloom_polymarket::signer::POLY_SIGNATURE.to_string(),
                sig.to_string(),
            ),
            (
                bloom_polymarket::signer::POLY_TIMESTAMP.to_string(),
                timestamp.to_string(),
            ),
        ])
    }
}

// ── Polymarket order sealed approval (WS-H) ─────────────────────────────────

/// Sidecar JSON the CLI writes at `/polymarket/trade/<wallet>/sign_request.json`
/// to ask the daemon to seal + grant + sign an order via the host.
///
/// The VFS handler stages a SealedAction keyed by `signing_hash`, mints a
/// challenge if no grant exists, or signs (via `host_sign_polymarket_order_hash`)
/// and writes the wrapped POLY_1271 signature into `sign_result.json` on
/// success.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolymarketOrderSignRequest {
    schema: String,
    draft_id: String,
    /// The salt the CLI committed to the draft (so the host signs the same
    /// bytes the user just approved).
    salt: String,
    /// The order_view produced by `bloom_polymarket::signing::order_action_and_hash`.
    order_view: serde_json::Value,
    /// `0x` + 64 hex — the inner POLY_1271 hash the host must sign. Sourced
    /// from `OrderAction.signing_hash` (not embedded inside `order_view`).
    signing_hash: String,
    /// Neg-risk flag — required to reproduce the inner POLY_1271 digest.
    neg_risk: bool,
    chain_id: u64,
    side: Side,
    /// Maker (deposit wallet) — recorded in the attestation for audit.
    maker: Address,
    /// Buyer-side human-readable label, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    market_slug: Option<String>,
}

/// Sidecar JSON written to `/polymarket/trade/<wallet>/sign_result.json`
/// once the host has signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolymarketOrderSignResult {
    schema: String,
    draft_id: String,
    action_id: String,
    /// 0x + 64 lowercase hex — the inner POLY_1271 hash the host signed.
    signing_hash: String,
    /// Wrapped POLY_1271 hex the CLOB expects.
    wrapped_signature: String,
    signed_at_ms: u64,
    /// Grant id consumed by this signature.
    grant_id: String,
}

/// Pure canonical-subject bytes for a Polymarket order sealed action.
/// Carries the full `order_view` so any canonical-subject byte change
/// invalidates the cached `intent_hash` and the staged action must be re-staged
/// (per WS-H §5.9: no step substitution after approval).
fn polymarket_order_subject_bytes(
    wallet: &str,
    order_view: &serde_json::Value,
    chain_id: u64,
    neg_risk: bool,
    signing_hash: &alloy::primitives::B256,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": PM_ORDER_SUBJECT_SCHEMA_V1,
        "wallet": wallet,
        "chain_id": chain_id,
        "neg_risk": neg_risk,
        "signing_hash": format!("{signing_hash:#x}"),
        "order_view": order_view,
    }))
    .expect("static polymarket order subject json")
}

/// Build the canonical intent envelope for a Polymarket order sealed action.
/// Action id determinism is derived from the inner signing hash (the bytes the
/// user actually approved), so any change to the order — including the
/// timestamp-derived salt — invalidates the staged action.
fn polymarket_order_envelope(
    wallet: &str,
    order_view: &serde_json::Value,
    signing_hash: &alloy::primitives::B256,
    chain_id: u64,
    neg_risk: bool,
) -> Result<CanonicalEnvelope, HandlerError> {
    let subject =
        polymarket_order_subject_bytes(wallet, order_view, chain_id, neg_risk, signing_hash);
    let action_id = action_id_for("polymarket.order.v1", signing_hash);
    Ok(CanonicalEnvelope::new(
        CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: wallet.to_string(),
            surface: POLYMARKET_SURFACE.into(),
            action_id,
            petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network: if chain_id == bloom_polymarket::POLYGON {
                "polygon".into()
            } else if chain_id == bloom_polymarket::AMOY {
                "amoy".into()
            } else {
                "polygon".into()
            },
            account: wallet.to_string(),
            action_kind: "order".into(),
            value_movement: true,
            authority_change: false,
            expires_ms: 0,
        },
        "polymarket_order",
        PM_ORDER_SUBJECT_SCHEMA_V1,
        subject,
    ))
}

/// Human-readable plan text bound into the Polymarket order sealed action.
/// Shared by the daemon handler and the foreground CLI so both stage the
/// same action bytes for the same signing hash.
pub fn polymarket_order_plan(
    side: Side,
    market_slug: Option<&str>,
    maker: Address,
    neg_risk: bool,
    chain_id: u64,
    signing_hash: &alloy::primitives::B256,
) -> String {
    format!(
        "Polymarket order ({:?}, market={}, maker={:#x}, neg_risk={}, chain_id={}, signing_hash={:#x})",
        side,
        market_slug.unwrap_or("<unknown>"),
        maker,
        neg_risk,
        chain_id,
        signing_hash,
    )
}

pub fn polymarket_order_sealed_action(
    wallet: &str,
    order_view: &serde_json::Value,
    signing_hash: &alloy::primitives::B256,
    chain_id: u64,
    neg_risk: bool,
    plan: String,
    now_ms: u64,
) -> Result<SealedAction, HandlerError> {
    let envelope = polymarket_order_envelope(wallet, order_view, signing_hash, chain_id, neg_risk)?;
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("action_kind".to_string(), serde_json::json!("order"));
    extra.insert(
        "signing_hash".to_string(),
        serde_json::json!(format!("{signing_hash:#x}")),
    );
    let terms = DaemonGrantTerms {
        max_ttl_secs: APPROVAL_TTL_MS / 1_000,
        max_signatures: 1,
        allowed_sign_intents: vec![POLYMARKET_ORDER_SIGN_INTENT.into()],
        assurance: AssuranceLevel::Standard,
        extra,
    };
    let mut caps = std::collections::BTreeMap::new();
    caps.insert(
        "signing_hash".to_string(),
        serde_json::json!(format!("{signing_hash:#x}")),
    );
    let mut config = std::collections::BTreeMap::new();
    config.insert("chain_id".to_string(), serde_json::json!(chain_id));
    config.insert("neg_risk".to_string(), serde_json::json!(neg_risk));
    let snapshot = PetalPolicySnapshot {
        policy_version: 0,
        wallet: wallet.to_string(),
        petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
        petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
        caps,
        hard_rules: Vec::new(),
        step_up_rules: Vec::new(),
        config,
        budget_state: std::collections::BTreeMap::new(),
        session_scope: Some(std::collections::BTreeMap::new()),
    };
    SealedAction::new(envelope, plan, Vec::new(), terms, snapshot, now_ms)
        .map_err(|e| HandlerError::backend(format!("seal Polymarket order action: {e}")))
}

/// Sign a Polymarket order's inner POLY_1271 hash via `PetalHost::sign_hash`
/// under a live grant for `action_id`, and wrap the raw 65-byte ECDSA into the
/// ERC-7739 signature hex the CLOB expects. Shared by the daemon handler and
/// the foreground CLI so both consume grants identically.
#[allow(clippy::too_many_arguments)]
pub async fn host_sign_polymarket_order_hash(
    host: &dyn bloom_auth_api::PetalHost,
    wallet: &str,
    action_id: &str,
    order: &order::Order,
    signing_hash: &alloy::primitives::B256,
    chain_id: u64,
    neg_risk: bool,
    now_ms: u64,
) -> Result<String, HandlerError> {
    let hash_hex = format!("{signing_hash:#x}");
    let order_facts = PolymarketSigningAttestationFacts {
        facts_schema: POLYMARKET_SIGNING_ATTESTATION_FACTS_SCHEMA_V1.into(),
        kind: PolymarketSealedActionKind::Order,
        petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
        petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
        petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
        wallet: wallet.to_string(),
        chain_id,
        action_id: action_id.to_string(),
        signing_hash: hash_hex.clone(),
    };
    let attestation = order_facts.signing_attestation().map_err(|e| {
        HandlerError::invalid(format!(
            "Polymarket Sealed Approval attestation invalid: {e}"
        ))
    })?;
    let sealed_sig = host
        .sign_hash(
            SignHashRequest {
                wallet: wallet.to_string(),
                action_id: action_id.to_string(),
                intent: POLYMARKET_ORDER_SIGN_INTENT.into(),
                hash_hex,
            },
            &attestation,
            now_ms,
        )
        .await
        .map_err(|e| HandlerError::invalid(format!("Polymarket Sealed Approval denied: {e}")))?;
    let raw = B64_STANDARD
        .decode(sealed_sig.signature_b64.as_bytes())
        .map_err(|e| HandlerError::backend(format!("decode host signature: {e}")))?;
    poly1271_signature_from_raw(order, &raw, chain_id, neg_risk)
        .map_err(|e| HandlerError::backend(format!("wrap POLY_1271 signature: {e}")))
}

impl PolymarketHandler {
    /// Wired-mode order signing flow:
    ///
    /// 1. `get_active(wallet, action_id, polymarket, …)` — if a live grant
    ///    exists, fall through to step 4.
    /// 2. Look for legacy `approval.json` and try `verify_and_mint_grant`
    ///    (dev / unmounted flow).
    /// 3. Else issue an `approval_challenge.json` and return `PermissionDenied`
    ///    so the user completes the ceremony.
    /// 4. Use `sign_hash` via `PetalHost` to sign the inner hash.
    /// 5. Wrap the raw 65-byte ECDSA via `poly1271_signature_from_raw`.
    ///
    /// Mirrors `prepare_wallet_policy_sealed` / `execute_wallet_policy_update`
    /// in `bloom-vfs/src/handlers/wallets.rs:670-825`.
    #[allow(clippy::too_many_arguments)]
    async fn prepare_and_sign_order_sealed(
        &self,
        wallet: &str,
        order_view: &serde_json::Value,
        signing_hash: &alloy::primitives::B256,
        chain_id: u64,
        neg_risk: bool,
        market_slug: Option<String>,
        maker: Address,
        side: Side,
    ) -> Result<PolymarketOrderSignResult, HandlerError> {
        let now = pm_now_ms_u64();
        let plan = polymarket_order_plan(
            side,
            market_slug.as_deref(),
            maker,
            neg_risk,
            chain_id,
            signing_hash,
        );
        let sealed = polymarket_order_sealed_action(
            wallet,
            order_view,
            signing_hash,
            chain_id,
            neg_risk,
            plan,
            now,
        )?;
        let action_id = sealed.action_id().to_string();
        let petal_id = sealed.petal_id().to_string();
        let petal_digest = sealed.petal_digest().to_string();
        self.auth_services
            .require_writer()?
            .stage_action(sealed, now)
            .await
            .map_err(|e| HandlerError::backend(format!("stage Polymarket order action: {e}")))?;
        // Re-fetch the sealed action's grant lookup key after staging so the
        // petals match what was bound into the SealedAction. Hold the grant
        // itself: signing below consumes it (max_signatures = 1), so its
        // `grant_id` must be captured before `sign_hash`, not looked up as
        // active afterwards.
        let grant = self
            .auth_services
            .require_grant_store()?
            .get_active(wallet, &action_id, &petal_id, &petal_digest, now)
            .await
            .map_err(|e| HandlerError::backend(format!("lookup Polymarket grant: {e}")))?;
        let grant = match grant {
            Some(grant) => grant,
            None => {
                // Legacy `approval.json` recovery path (matches wallets.rs:712).
                let auth_root = self
                    .onboarding
                    .as_ref()
                    .map(|ob| ob.auth_dir.clone())
                    .unwrap_or_else(|| self.keystore.root().join("_polymarket"));
                let dir = auth_root.join("trade").join(wallet).join(action_id.clone());
                fs::create_dir_all(&dir)?;
                let approval_path = dir.join(APPROVAL_FILE);
                if approval_path.exists() {
                    let approval: SignedApproval = read_json(&approval_path)?;
                    self.auth_services
                        .require_approval_verifier()?
                        .verify_and_mint_grant(
                            approval,
                            self.auth_services.require_grant_store()?.as_ref(),
                            now,
                        )
                        .await
                        .map_err(|e| {
                            HandlerError::invalid(format!("Sealed Approval rejected: {e}"))
                        })?
                } else {
                    let challenge = self
                        .issue_polymarket_order_challenge(&action_id)
                        .await?
                        .with_local_ceremony_url();
                    let challenge_path = approval_path.with_file_name(APPROVAL_CHALLENGE_FILE);
                    if let Some(parent) = challenge_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    write_json(challenge_path, &challenge)?;
                    return Err(HandlerError::PermissionDenied);
                }
            }
        };
        // We have a grant now. Sign via the host. We need a minimal `Order`
        // shell because the POLY_1271 wrap step embeds `contents_hash` (the
        // inner EIP-712 struct hash) and the APP_DOMAIN_SEPARATOR; the
        // `order_view` already carries those, but the wrap helper takes
        // `&Order` — we re-derive the shell here.
        let order_shell = order_shell_from_view(order_view)?;
        let hash_hex = format!("{signing_hash:#x}");
        let wrapped = host_sign_polymarket_order_hash(
            self.auth_services.require_petal_host()?.as_ref(),
            wallet,
            &action_id,
            &order_shell,
            signing_hash,
            chain_id,
            neg_risk,
            now,
        )
        .await?;
        Ok(PolymarketOrderSignResult {
            schema: PM_ORDER_SIGN_RESULT_FILE.into(),
            draft_id: order_view
                .get("draft_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            action_id,
            signing_hash: hash_hex,
            wrapped_signature: wrapped,
            signed_at_ms: now,
            grant_id: grant.grant_id,
        })
    }

    async fn issue_polymarket_order_challenge(
        &self,
        action_id: &str,
    ) -> Result<bloom_auth_api::ApprovalChallenge, HandlerError> {
        use base64::Engine as _;
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
        self.auth_services
            .require_writer()?
            .issue_challenge(
                POLYMARKET_SURFACE,
                action_id,
                &nonce_b64,
                pm_now_ms_u64() + APPROVAL_TTL_MS,
                pm_now_ms_u64(),
            )
            .await
            .map_err(|e| HandlerError::backend(format!("issue Polymarket order challenge: {e}")))
    }
}

/// Build a minimal `Order` shell from a `OrderAction.order_view` JSON.
/// The POLY_1271 wrap helper needs the `contents_hash` (which it re-derives
/// from the order struct), the `APP_DOMAIN_SEPARATOR` (which it derives from
/// `chain_id` + `neg_risk`), and the `ORDER_TYPE_STRING`. So the values we
/// have to round-trip are the numeric fields the struct hash binds on.
fn order_shell_from_view(view: &serde_json::Value) -> Result<order::Order, HandlerError> {
    use std::str::FromStr;
    let get = |k: &str| -> Result<String, HandlerError> {
        view.get(k)
            .and_then(|v| v.as_str().map(str::to_string))
            .ok_or_else(|| HandlerError::invalid(format!("order_view missing {k}")))
    };
    Ok(order::Order {
        salt: alloy::primitives::U256::from_str(&get("salt")?)
            .map_err(|e| HandlerError::invalid(format!("parse salt: {e}")))?,
        maker: get("maker")?
            .parse::<alloy::primitives::Address>()
            .map_err(|e| HandlerError::invalid(format!("parse maker: {e}")))?,
        signer: get("signer")?
            .parse::<alloy::primitives::Address>()
            .map_err(|e| HandlerError::invalid(format!("parse signer: {e}")))?,
        tokenId: alloy::primitives::U256::from_str(&get("tokenId")?)
            .map_err(|e| HandlerError::invalid(format!("parse tokenId: {e}")))?,
        makerAmount: alloy::primitives::U256::from_str(&get("makerAmount")?)
            .map_err(|e| HandlerError::invalid(format!("parse makerAmount: {e}")))?,
        takerAmount: alloy::primitives::U256::from_str(&get("takerAmount")?)
            .map_err(|e| HandlerError::invalid(format!("parse takerAmount: {e}")))?,
        side: {
            let s = get("side")?;
            s.parse::<u8>()
                .map_err(|e| HandlerError::invalid(format!("parse side: {e}")))?
        },
        signatureType: get("signatureType")?
            .parse::<u8>()
            .map_err(|e| HandlerError::invalid(format!("parse signatureType: {e}")))?,
        timestamp: alloy::primitives::U256::from_str(&get("timestamp")?)
            .map_err(|e| HandlerError::invalid(format!("parse timestamp: {e}")))?,
        metadata: view
            .get("metadata")
            .and_then(|v| v.as_str())
            .and_then(|s| alloy::primitives::B256::from_str(s).ok())
            .unwrap_or(alloy::primitives::B256::ZERO),
        builder: view
            .get("builder")
            .and_then(|v| v.as_str())
            .and_then(|s| alloy::primitives::B256::from_str(s).ok())
            .unwrap_or(alloy::primitives::B256::ZERO),
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> Result<T, HandlerError> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| HandlerError::backend(format!("read auth json: {e}")))
}

/// The onboarding/account dependencies, bundled so the read-only handler keeps
/// its constructor and the daemon opts in via [`PolymarketHandler::with_onboarding`].
pub struct PolymarketOnboarding {
    pub onboarder: Arc<Onboarder>,
    pub auth_dir: PathBuf,
    /// Read access to stored CLOB credentials (for the `account/` views).
    pub creds: CredentialStore,
    /// Chain reads for the `account/` views (same adapter the onboarder uses).
    pub chain: Arc<dyn ChainReader>,
}

#[derive(Debug, Deserialize)]
struct TradeNewRequest {
    slug: String,
    outcome: String,
    /// Buy: pUSD spend. Sell: share count.
    amount: String,
    /// Defaults to BUY.
    #[serde(default)]
    side: Option<String>,
    /// Buy price bound.
    #[serde(default)]
    max_price: Option<String>,
    /// Sell price bound.
    #[serde(default)]
    min_price: Option<String>,
    /// Explicit resting limit price.
    #[serde(default)]
    limit_price: Option<String>,
    /// FAK | FOK | GTC. Defaults to FAK for marketable, GTC for explicit limit.
    #[serde(default)]
    order_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct FundNewRequest {
    target_pusd: String,
    max_spend: String,
    #[serde(default)]
    from_token: Option<String>,
    #[serde(default = "default_slippage_bps")]
    slippage_bps: u16,
}

fn default_slippage_bps() -> u16 {
    50
}

/// Maximum acknowledgeable route slippage for a staged fund request (10%);
/// a bare `u16` would otherwise admit 655%.
const MAX_FUND_SLIPPAGE_BPS: u16 = 1000;

/// Validate a staged fund request at creation so a malformed draft can never be
/// persisted (and only blow up later in the value-moving CLI executor). The VFS
/// `fund/<wallet>/new` surface is **staging-only**; this is the input gate for it.
fn validate_fund_request(req: &FundNewRequest) -> Result<(), HandlerError> {
    // target_pusd: a positive pUSD amount at ≤ 6 dp (parse_micro enforces both).
    let target_micro = order::parse_micro(req.target_pusd.trim())
        .map_err(|e| HandlerError::invalid(format!("target_pusd: {e}")))?;
    if target_micro == 0 {
        return Err(HandlerError::invalid("target_pusd must be > 0"));
    }
    // max_spend: input-token units whose decimals depend on from_token (resolved
    // in the CLI). Validate syntax + positivity + length here, not exact precision.
    let max_spend = req.max_spend.trim();
    if max_spend.is_empty() || max_spend.len() > 32 {
        return Err(HandlerError::invalid("max_spend must be 1..=32 chars"));
    }
    let parsed = bloom_proto::units::parse_units(max_spend, 18)
        .map_err(|e| HandlerError::invalid(format!("max_spend: {e}")))?;
    if parsed.is_zero() {
        return Err(HandlerError::invalid("max_spend must be > 0"));
    }
    // from_token: a known native alias or a 0x ERC-20 address.
    if let Some(tok) = req.from_token.as_deref() {
        let t = tok.trim();
        let native = matches!(t.to_ascii_lowercase().as_str(), "native" | "pol" | "matic");
        if !native && t.parse::<Address>().is_err() {
            return Err(HandlerError::invalid(
                "from_token must be 'native'/'pol'/'matic' or a 0x ERC-20 address",
            ));
        }
    }
    if req.slippage_bps > MAX_FUND_SLIPPAGE_BPS {
        return Err(HandlerError::invalid(format!(
            "slippage_bps too high (max {MAX_FUND_SLIPPAGE_BPS} = 10%)"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FundSession {
    id: String,
    wallet: String,
    owner: String,
    deposit_wallet: String,
    deposit_wallet_source: String,
    deposit_wallet_fundable: bool,
    current_pusd_raw: String,
    current_pusd: String,
    target_pusd: String,
    max_spend: String,
    from_token: String,
    slippage_bps: u16,
    status: String,
    created_ms: u128,
    updated_ms: u128,
}

/// Adapts the daemon's [`ChainClient`] to the narrow read-only
/// [`ChainReader`] the onboarding machine probes through. Reverted reads map
/// to errors — "could not verify" must never read as "verified".
pub struct ChainClientReader(pub ChainClient);

#[async_trait]
impl ChainReader for ChainClientReader {
    async fn code_len(&self, addr: Address) -> bloom_polymarket::Result<usize> {
        self.0
            .code(addr)
            .await
            .map(|c| c.len())
            .map_err(|e| PolymarketError::invalid(format!("eth_getCode failed: {e}")))
    }
    async fn erc20_balance(
        &self,
        token: Address,
        holder: Address,
    ) -> bloom_polymarket::Result<U256> {
        self.0
            .erc20_balance(token, holder)
            .await
            .map_err(|e| PolymarketError::invalid(format!("balanceOf failed: {e}")))?
            .ok_or_else(|| PolymarketError::invalid("balanceOf reverted"))
    }
    async fn erc20_allowance(
        &self,
        token: Address,
        owner: Address,
        spender: Address,
    ) -> bloom_polymarket::Result<U256> {
        self.0
            .erc20_allowance(token, owner, spender)
            .await
            .map_err(|e| PolymarketError::invalid(format!("allowance failed: {e}")))?
            .ok_or_else(|| PolymarketError::invalid("allowance reverted"))
    }
    async fn is_approved_for_all(
        &self,
        token: Address,
        owner: Address,
        operator: Address,
    ) -> bloom_polymarket::Result<bool> {
        self.0
            .is_approved_for_all(token, owner, operator)
            .await
            .map_err(|e| PolymarketError::invalid(format!("isApprovedForAll failed: {e}")))?
            .ok_or_else(|| PolymarketError::invalid("isApprovedForAll reverted"))
    }
    async fn predict_deposit_wallet(&self, owner: Address) -> bloom_polymarket::Result<Address> {
        use bloom_polymarket::eip712::FACTORY;

        let call = |data: Vec<u8>| {
            let req = alloy::rpc::types::eth::TransactionRequest::default()
                .to(FACTORY)
                .input(data.into());
            self.0.eth_call_capture_revert(req, None)
        };
        let word_to_addr = |out: &[u8], what: &str| -> bloom_polymarket::Result<Address> {
            if out.len() < 32 {
                return Err(PolymarketError::invalid(format!(
                    "factory {what} returned {} bytes",
                    out.len()
                )));
            }
            Ok(Address::from_slice(&out[12..32]))
        };

        // implementation() — selector 0x5c60da1b.
        let impl_out = call(vec![0x5c, 0x60, 0xda, 0x1b])
            .await
            .map_err(|e| PolymarketError::invalid(format!("factory implementation(): {e}")))?
            .map_err(|r| {
                PolymarketError::invalid(format!(
                    "factory implementation() reverted: 0x{}",
                    hex::encode(&r)
                ))
            })?;
        let implementation = word_to_addr(&impl_out, "implementation()")?;

        // predictWalletAddress(address,bytes32) — selector 0x1f264778, with
        // walletId = bytes32(owner) (left-padded), exactly what the relayer's
        // WALLET-CREATE uses.
        let mut data = Vec::with_capacity(4 + 64);
        data.extend_from_slice(&[0x1f, 0x26, 0x47, 0x78]);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(implementation.as_slice());
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(owner.as_slice());
        let out = call(data)
            .await
            .map_err(|e| PolymarketError::invalid(format!("factory predictWalletAddress: {e}")))?
            .map_err(|r| {
                PolymarketError::invalid(format!(
                    "factory predictWalletAddress reverted: 0x{}",
                    hex::encode(&r)
                ))
            })?;
        word_to_addr(&out, "predictWalletAddress")
    }
}

/// Build the onboarder for a `[polymarket]` config + resolved chain client.
/// Bloom uses the deposit-wallet path (signatureType 3) for trading.
pub fn build_onboarder(
    pm_cfg: &bloom_proto::config::PolymarketConfig,
    chain_client: ChainClient,
    state_dir: &std::path::Path,
) -> Onboarder {
    use bloom_polymarket::{BuilderCredentialStore, OnboardStore, RelayerClient};

    let mut clob = ClobClient::new(pm_cfg.chain_id);
    if let Ok(u) = url::Url::parse(&pm_cfg.clob_url) {
        clob = clob.with_base_url(u);
    }
    let chain: Arc<dyn ChainReader> = Arc::new(ChainClientReader(chain_client.clone()));

    // Relayer auth precedence: a manually configured relayer key wins;
    // otherwise `builder_key_mode` decides whether bloom self-provisions a
    // builder API key (the default).
    let relayer = RelayerClient::new(pm_cfg.chain_id).with_base_url(pm_cfg.relayer_url.clone());
    let base = |relayer: RelayerClient| {
        Onboarder::new(
            chain.clone(),
            relayer,
            clob.clone(),
            CredentialStore::new(state_dir),
            OnboardStore::new(state_dir),
            pm_cfg.chain_id,
        )
    };
    match (&pm_cfg.relayer_api_key, &pm_cfg.relayer_api_key_address) {
        (Some(key), Some(addr)) => base(relayer.with_api_key(key.clone(), addr.clone())),
        _ => match pm_cfg.builder_key_mode.as_str() {
            "auto" => base(relayer).with_builder_auth(BuilderCredentialStore::new(state_dir)),
            "manual" => base(relayer).with_relayer_disabled(
                "builder_key_mode = \"manual\" but [polymarket].relayer_api_key / \
                 relayer_api_key_address are not set — configure them \
                 (polymarket.com/settings?tab=api-keys) or switch to \
                 builder_key_mode = \"auto\"",
            ),
            "disabled" => base(relayer).with_relayer_disabled(
                "builder_key_mode = \"disabled\": relayer auth is off, so deposit-wallet \
                 onboarding/trading is unavailable on this install",
            ),
            other => base(relayer).with_relayer_disabled(format!(
                "unknown builder_key_mode '{other}' (expected auto, manual, or disabled)"
            )),
        },
    }
}

#[derive(Clone)]
pub struct PolymarketHandler {
    gamma: Arc<GammaClient>,
    data: Arc<DataClient>,
    clob: Arc<ClobClient>,
    keystore: Keystore,
    onboarding: Option<Arc<PolymarketOnboarding>>,
    /// Read-only views over durable order drafts/receipts (`trade/`).
    orders: Option<Arc<OrderStore>>,
    /// Durable pUSD funding request reviews (`fund/`).
    fund_root: Option<PathBuf>,
    /// Stored builder-key metadata/secret file manager. VFS only exposes key ids.
    builder_store: Option<BuilderCredentialStore>,
    audit: Option<Arc<AuditLog>>,
    /// Wallets with an onboarding run in flight (single-flight guard).
    running: Arc<StdMutex<HashSet<String>>>,
    auth_services: crate::AuthServices,
}

impl PolymarketHandler {
    pub fn new(gamma: GammaClient, data: DataClient, clob: ClobClient, keystore: Keystore) -> Self {
        Self {
            gamma: Arc::new(gamma),
            data: Arc::new(data),
            clob: Arc::new(clob),
            keystore,
            onboarding: None,
            orders: None,
            fund_root: None,
            builder_store: None,
            audit: None,
            running: Arc::default(),
            auth_services: crate::AuthServices::default(),
        }
    }

    pub fn with_auth_services(mut self, auth_services: crate::AuthServices) -> Self {
        self.auth_services = auth_services;
        self
    }

    /// Enable the `onboard/` + `account/` subtrees.
    pub fn with_onboarding(mut self, onboarding: PolymarketOnboarding) -> Self {
        self.onboarding = Some(Arc::new(onboarding));
        self
    }

    /// Enable the `trade/` subtree (order drafts + receipts). Draft confirms
    /// are discoverable, but direct handler writes refuse with foreground
    /// `bloom vfs write --unlock-wallet` guidance so the signer ceremony stays
    /// in the process that signs.
    pub fn with_order_store(mut self, store: OrderStore) -> Self {
        self.orders = Some(Arc::new(store));
        self
    }

    /// Enable the `fund/` subtree for reviewable pUSD funding requests.
    pub fn with_fund_store(mut self, root: impl Into<PathBuf>) -> Self {
        self.fund_root = Some(root.into());
        self
    }

    /// Enable `builder-keys/` redacted list/revoke parity with the CLI.
    pub fn with_builder_key_store(mut self, store: BuilderCredentialStore) -> Self {
        self.builder_store = Some(store);
        self
    }

    fn orders_or_not_found(&self, path: &VfsPath) -> Result<&OrderStore, HandlerError> {
        self.orders
            .as_deref()
            .ok_or_else(|| HandlerError::not_found(path.to_string_path()))
    }

    fn builder_keys_or_not_found(
        &self,
        path: &VfsPath,
    ) -> Result<&BuilderCredentialStore, HandlerError> {
        if self.onboarding.is_none() {
            return Err(HandlerError::not_found(path.to_string_path()));
        }
        self.builder_store
            .as_ref()
            .ok_or_else(|| HandlerError::not_found(path.to_string_path()))
    }

    /// Audit log for onboarding side effects (relayer submits, cred mints).
    pub fn with_audit(mut self, audit: Arc<AuditLog>) -> Self {
        self.audit = Some(audit);
        self
    }

    fn onboarding_wired(&self) -> bool {
        self.onboarding.is_some()
    }

    fn fund_wired(&self) -> bool {
        self.fund_root.is_some() && self.onboarding_wired()
    }

    async fn trade_funder(&self, wallet: &str) -> Result<(Address, u8), HandlerError> {
        let ob = self
            .onboarding
            .as_ref()
            .ok_or_else(|| HandlerError::invalid("polymarket onboarding is not wired"))?;
        let owner = self.wallet_address(wallet)?;
        let st = ob.onboarder.status(wallet, owner).map_err(err_be)?;
        if !st.tradeable() {
            return Err(HandlerError::invalid(format!(
                "wallet '{wallet}' is not tradeable (stage={:?}, mode={:?}); run onboarding first",
                st.stage, st.mode
            )));
        }
        let deposit = st
            .deposit_wallet
            .parse()
            .map_err(|e| HandlerError::backend(format!("bad deposit wallet in state: {e}")))?;
        Ok((deposit, order::SIG_TYPE_POLY_1271))
    }

    /// `onboard/`/`account/` dependency, or NotFound (the subtree doesn't
    /// exist when onboarding isn't configured).
    fn onboarding_or_not_found(
        &self,
        path: &VfsPath,
    ) -> Result<&PolymarketOnboarding, HandlerError> {
        self.onboarding
            .as_deref()
            .ok_or_else(|| HandlerError::not_found(path.to_string_path()))
    }

    /// Resolve a `positions/<seg>` segment to an address: a literal `0x…`
    /// address is used directly (watch-only / external); otherwise it is a
    /// keystore wallet name resolved via `info` (a pure read — no unlock).
    fn resolve_address(&self, seg: &str) -> Result<Address, HandlerError> {
        if let Ok(addr) = seg.parse::<Address>() {
            return Ok(addr);
        }
        self.wallet_address(seg)
    }

    /// Keystore wallet name → owner address (no unlock).
    fn wallet_address(&self, wallet: &str) -> Result<Address, HandlerError> {
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::not_found(format!("wallet '{wallet}': {e}")))?;
        Ok(info.address)
    }

    async fn yes_token_for_slug(&self, slug: &str) -> Result<String, HandlerError> {
        let market = self.gamma.market_by_slug(slug).await.map_err(err_be)?;
        market
            .yes_token_id()
            .map(str::to_string)
            .ok_or_else(|| HandlerError::not_found(format!("market '{slug}' has no CLOB token")))
    }

    /// Direct VFS execution of `bloom polymarket cancel`. Cancel is
    /// risk-reducing and uses stored CLOB credentials (L2 auth only, no owner
    /// signing), so unlike the value-moving confirm paths it can run inside the
    /// mounted handler rather than being forced through the foreground ceremony.
    ///
    /// # Handler-Executable Criteria
    /// An operation may execute directly in the mounted handler (bypassing the
    /// foreground ceremony) only if ALL of the following are true:
    /// - No EVM owner signing is required (L2 CLOB credentials only).
    /// - The operation is risk-reducing (cannot move funds or increase risk).
    /// - Jurisdiction checks pass.
    ///
    /// If any criterion is false, the operation MUST go through the foreground
    /// confirm path (`bloom vfs write --unlock-wallet`). Builder-key revoke is
    /// another direct CLOB-auth operation: it mutates relayer submission auth
    /// but cannot move funds and requires no owner signing.
    async fn execute_cancel(&self, wallet: &str, order_id: &str) -> Result<(), HandlerError> {
        validate_wallet_name(wallet).map_err(err_be)?;
        // order-id path-traversal guard (real format validation is the CLOB's job).
        if order_id.is_empty()
            || order_id.contains('/')
            || order_id.contains('\\')
            || order_id == "."
            || order_id == ".."
        {
            return Err(HandlerError::invalid(format!(
                "invalid Polymarket order id '{order_id}'"
            )));
        }
        // Resolve all local state first so durable refusals happen before any
        // network call. Compliance gates are hard, even for cancels.
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::not_found(format!("wallet '{wallet}': {e}")))?;
        let ob = self.onboarding.as_ref().ok_or_else(|| {
            HandlerError::invalid(
                "polymarket onboarding is not wired: the daemon needs a [chains] entry \
                 whose chain_id matches [polymarket].chain_id (Polygon = 137)",
            )
        })?;
        let creds =
            ob.creds.load(wallet).map_err(err_be)?.ok_or_else(|| {
                HandlerError::invalid("wallet not onboarded (no CLOB credentials)")
            })?;
        let store = self
            .orders
            .as_deref()
            .ok_or_else(|| HandlerError::invalid("polymarket order store is not configured"))?;
        let _lock = store.lock(wallet).map_err(err_be)?;
        let result = self
            .clob
            .cancel_order(&creds, info.address, order_id)
            .await
            .map_err(err_be)?;
        store
            .audit(
                wallet,
                "order_cancelled",
                serde_json::json!({ "order_id": order_id, "response": result }),
            )
            .map_err(err_be)?;
        Ok(())
    }

    /// Wired-mode `confirm` dispatch for a draft trade. Reads the
    /// `sign_request.json` sidecar the CLI committed alongside the
    /// `build_order` step, stages a SealedAction, mints a challenge if no grant
    /// exists, otherwise signs via `PetalHost::sign_hash` and writes the
    /// wrapped POLY_1271 signature to `sign_result.json`.
    async fn confirm_order_via_sealed(
        &self,
        wallet: &str,
        draft_id: &str,
        _data: &[u8],
    ) -> Result<(), HandlerError> {
        validate_wallet_name(wallet).map_err(err_be)?;
        let store = self
            .orders
            .as_ref()
            .ok_or_else(|| HandlerError::not_found("polymarket trade/"))?;
        let draft = store
            .load_draft(wallet, draft_id)
            .map_err(err_be)?
            .ok_or_else(|| {
                HandlerError::not_found(format!(
                    "polymarket trade/{wallet}/drafts/{draft_id}/order.json"
                ))
            })?;
        // Sidecar location: <store.dir>/<wallet>/orders/drafts/<draft_id>/sign_request.json.
        let draft_path = store.draft_path(wallet, draft_id);
        let trade_dir = match draft_path.parent() {
            Some(p) => p.to_path_buf(),
            None => {
                return Err(HandlerError::not_found(format!(
                    "polymarket trade/{wallet}/drafts/{draft_id}"
                )));
            }
        };
        fs::create_dir_all(&trade_dir)?;
        let req_path = trade_dir.join(PM_ORDER_SIGN_REQUEST_FILE);
        let req: PolymarketOrderSignRequest = if req_path.exists() {
            read_json(&req_path)?
        } else {
            // CLI didn't drop a sidecar — we accept the request body in this
            // case so a future sealed-aware CLI doesn't need a sidecar at all.
            serde_json::from_slice(_data).map_err(|e| {
                HandlerError::invalid(format!(
                    "no {PM_ORDER_SIGN_REQUEST_FILE} sidecar and body is not a valid \
                     PolymarketOrderSignRequest: {e}"
                ))
            })?
        };
        if req.schema != "bloom.polymarket.order_sign_request.v1" {
            return Err(HandlerError::invalid(format!(
                "unsupported sign-request schema {}",
                req.schema
            )));
        }
        let signing_hash = req
            .signing_hash
            .parse::<alloy::primitives::B256>()
            .map_err(|e| HandlerError::invalid(format!("parse signing_hash: {e}")))?;
        let result = self
            .prepare_and_sign_order_sealed(
                wallet,
                &req.order_view,
                &signing_hash,
                req.chain_id,
                req.neg_risk,
                req.market_slug.clone(),
                req.maker,
                req.side,
            )
            .await?;
        let result_path = trade_dir.join(PM_ORDER_SIGN_RESULT_FILE);
        write_json(&result_path, &result)?;
        // Best-effort: record that the draft was sealed-signed via the host.
        let _ = std::fs::remove_file(&req_path);
        if let Some(audit) = self.audit.as_ref() {
            let _ = audit.append(AuditRecord {
                ts_ms: 0, // set by append
                kind: "polymarket.order.sealed_signed".into(),
                wallet: Some(wallet.to_string()),
                chain: None,
                data: serde_json::json!({
                    "draft_id": draft.id,
                    "action_id": result.action_id,
                    "grant_id": result.grant_id,
                    "signing_hash": result.signing_hash,
                }),
                prev: String::new(),
                digest: String::new(),
            });
        }
        Ok(())
    }

    async fn read_builder_keys(
        &self,
        path: &VfsPath,
        wallet: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let store = self.builder_keys_or_not_found(path)?;
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::not_found(format!("wallet '{wallet}': {e}")))?;
        let ob = self.onboarding_or_not_found(path)?;
        let creds =
            ob.creds.load(wallet).map_err(err_be)?.ok_or_else(|| {
                HandlerError::invalid("wallet not onboarded (no CLOB credentials)")
            })?;
        let stored = store.load(wallet).map_err(err_be)?.map(|b| b.key);
        let keys = self
            .clob
            .list_builder_api_keys(&creds, info.address)
            .await
            .map_err(err_be)?;
        let rows: Vec<_> = keys
            .into_iter()
            .map(|k| {
                serde_json::json!({
                    "key": k.key,
                    "created_at": k.created_at,
                    "revoked_at": k.revoked_at,
                    "stored_by_bloom": stored.as_deref() == Some(k.key.as_str()),
                })
            })
            .collect();
        pretty(&serde_json::json!({
            "wallet": wallet,
            "keys": rows,
            "secrets_exposed": false,
        }))
    }

    async fn execute_builder_key_revoke(
        &self,
        wallet: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        validate_wallet_name(wallet).map_err(err_be)?;
        let key = parse_builder_key_revoke_body(data)?;
        if self.builder_store.is_none() {
            return Err(HandlerError::not_found("builder-keys"));
        }
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::not_found(format!("wallet '{wallet}': {e}")))?;
        let ob = self.onboarding.as_ref().ok_or_else(|| {
            HandlerError::invalid(
                "polymarket onboarding is not wired: the daemon needs a [chains] entry \
                 whose chain_id matches [polymarket].chain_id (Polygon = 137)",
            )
        })?;
        let creds =
            ob.creds.load(wallet).map_err(err_be)?.ok_or_else(|| {
                HandlerError::invalid("wallet not onboarded (no CLOB credentials)")
            })?;
        self.clob
            .revoke_builder_api_key(&creds, info.address, key.as_deref())
            .await
            .map_err(err_be)?;

        if let Some(store) = self.builder_store.as_ref()
            && let Some(stored) = store.load(wallet).map_err(err_be)?
            && (key.is_none() || key.as_deref() == Some(stored.key.as_str()))
        {
            store.delete(wallet).map_err(err_be)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct BuilderKeyRevokeBody {
    #[serde(default)]
    confirm: Option<bool>,
    #[serde(default)]
    key: Option<String>,
}

fn parse_builder_key_revoke_body(data: &[u8]) -> Result<Option<String>, HandlerError> {
    let body = std::str::from_utf8(data)
        .map_err(|_| HandlerError::invalid("builder-key revoke body must be utf-8"))?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err(HandlerError::invalid(
            "builder-key revoke requires body 'confirm', 'y', or JSON/TOML with confirm=true",
        ));
    }
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "confirm" | "y" | "yes"
    ) {
        return Ok(None);
    }
    let parsed: BuilderKeyRevokeBody = match serde_json::from_str(trimmed) {
        Ok(parsed) => parsed,
        Err(json_err) => toml::from_str(trimmed).map_err(|toml_err| {
            HandlerError::invalid(format!(
                "confirm body must be 'confirm', 'y', JSON, or TOML: JSON: {json_err}; TOML: {toml_err}"
            ))
        })?,
    };
    if parsed.confirm != Some(true) {
        return Err(HandlerError::invalid(
            "builder-key revoke body must set confirm=true",
        ));
    }
    if let Some(key) = parsed.key.as_deref()
        && (key.is_empty() || key.contains('/') || key.contains('\\') || key == "." || key == "..")
    {
        return Err(HandlerError::invalid(format!(
            "invalid Polymarket builder key id '{key}'"
        )));
    }
    Ok(parsed.key)
}

fn err_be(e: PolymarketError) -> HandlerError {
    match e {
        PolymarketError::Api { status: 404, .. } => HandlerError::not_found("polymarket: 404"),
        PolymarketError::Invalid(s) => HandlerError::Invalid(s),
        other => HandlerError::backend(other.to_string()),
    }
}

fn pretty(v: &impl serde::Serialize) -> Result<Vec<u8>, HandlerError> {
    serde_json::to_vec_pretty(v).map_err(|e| HandlerError::backend(e.to_string()))
}

fn load_required_draft(
    store: &OrderStore,
    wallet: &str,
    id: &str,
) -> Result<OrderDraft, HandlerError> {
    store
        .load_draft(wallet, id)
        .map_err(err_be)?
        .ok_or_else(|| HandlerError::not_found(format!("polymarket draft {wallet}/{id}")))
}

fn load_required_receipt(
    store: &OrderStore,
    wallet: &str,
    id: &str,
) -> Result<OrderReceipt, HandlerError> {
    store
        .load_receipt(wallet, id)
        .map_err(err_be)?
        .ok_or_else(|| HandlerError::not_found(format!("polymarket receipt {wallet}/{id}")))
}

/// Removes `wallet` from the running set when the spawned run ends, however
/// it ends (success, error, or panic unwind).
struct RunningGuard {
    set: Arc<StdMutex<HashSet<String>>>,
    wallet: String,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.set.lock().unwrap().remove(&self.wallet);
    }
}

/// Append an onboarding side effect to the audit log. Records identifiers
/// only — never the L2 secret/passphrase.
fn audit_onboard_event(audit: Option<&AuditLog>, wallet: &str, event: &OnboardEvent) {
    let Some(log) = audit else { return };
    let (kind, data) = match event {
        OnboardEvent::RelayerSubmitted { kind, tx_id } => (
            format!("polymarket.onboard.{kind}.submitted"),
            serde_json::json!({ "tx_id": tx_id }),
        ),
        OnboardEvent::RelayerConfirmed {
            kind,
            tx_id,
            tx_hash,
        } => (
            format!("polymarket.onboard.{kind}.confirmed"),
            serde_json::json!({ "tx_id": tx_id, "tx_hash": tx_hash }),
        ),
        OnboardEvent::CredsMinted { api_key } => (
            "polymarket.onboard.creds.minted".to_string(),
            serde_json::json!({ "api_key": api_key }),
        ),
        OnboardEvent::BuilderKeyCreating => (
            "polymarket.onboard.builder_key.creating".to_string(),
            serde_json::json!({
                "note": "builder API key: relayer submission auth only; cannot move funds; \
                         revocable via `bloom polymarket builder-keys revoke`",
            }),
        ),
        OnboardEvent::BuilderKeyCreated { key } => (
            "polymarket.onboard.builder_key.created".to_string(),
            serde_json::json!({ "key": key }),
        ),
        OnboardEvent::OnchainSubmitted { kind, tx_hash } => (
            format!("polymarket.onboard.{kind}.onchain_submitted"),
            serde_json::json!({ "tx_hash": tx_hash }),
        ),
        OnboardEvent::OnchainConfirmed { kind, tx_hash } => (
            format!("polymarket.onboard.{kind}.onchain_confirmed"),
            serde_json::json!({ "tx_hash": tx_hash }),
        ),
        // Stage transitions are progress, not side effects — status.json has them.
        OnboardEvent::StageDone(_) => return,
    };
    let result = log.append(AuditRecord {
        ts_ms: 0, // set by append
        kind,
        wallet: Some(wallet.to_string()),
        chain: None,
        data,
        prev: String::new(),
        digest: String::new(),
    });
    if let Err(e) = result {
        tracing::warn!(wallet, error = %e, "polymarket.onboard.audit_append_failed");
    }
}

fn render_onboard_plan_md(st: &OnboardState) -> String {
    let mark = |done: bool| if done { "x" } else { " " };
    let s = st.stage;
    let fund_note = if st.deposit_wallet_fundable {
        format!("Or send pUSD directly to `{}`.", st.deposit_wallet)
    } else {
        "Do **not** fund the deposit wallet shown above yet: it is a local estimate. Run `begin`/`bloom polymarket onboard` so Bloom resolves the live factory address first.".to_string()
    };
    format!(
        "# Polymarket onboarding — `{wallet}`\n\
         \n\
         | | |\n|---|---|\n\
         | owner (bloom wallet) | `{owner}` |\n\
         | deposit wallet (CREATE2, deterministic) | `{deposit}` |\n\
         | chain id | {chain_id} |\n\
         | current stage | **{stage}** |\n\
         \n\
         Writing `begin` runs every incomplete stage, idempotently — each stage\n\
         re-checks real state (chain code, balances, allowances, the creds file)\n\
         before acting, so re-running is always safe.\n\
         \n\
         - [{m_derive}] **derive** — compute the deterministic deposit-wallet address (pure; no network)\n\
         - [{m_deploy}] **deploy** — gasless `WALLET-CREATE` via the Polymarket relayer; polled to `STATE_CONFIRMED`\n\
         - [{m_fund}] **fund** — the funding address needs pUSD ({pusd:#x}) on Polygon.\n\
           Preferred: `bloom polymarket fund {wallet} --target-pusd <amount> --max-spend <native>`\n\
           (target-denominated swap via the standard tx engine), or pass\n\
           `--target-pusd/--max-spend` to `bloom polymarket onboard` to fund inline.\n\
           {fund_note} Then write `begin` again.\n\
           (Advanced: the `defi/intents/{wallet}/new` VFS flow also works, but its\n\
           sessions are in-memory — it requires a persistent `bloom serve` daemon.)\n\
         - [{m_approve}] **approve** — one EIP-712-signed relayer batch granting the exchanges/adapters\n\
           spending rights *from the deposit wallet* (see `approvals.json` for the exact calldata)\n\
         - [{m_creds}] **creds** — sign the L1 `ClobAuth` attestation to mint CLOB API credentials\n\
           (stored mode 0600 under the bloom home; never exposed through the VFS)\n\
         - [{m_sync}] **sync** — tell the CLOB to recompute buying power for the deposit wallet\n\
         \n\
         **Timing.** `begin` spawns and runs to the first blocking point. It\n\
         *rests at* **fund** until pUSD reaches the deposit wallet — re-write\n\
         `begin` to resume. The network-bound stages (**deploy**, **approve**,\n\
         **creds**, **sync**) submit to the relayer/CLOB and poll for\n\
         confirmation for up to `poll_timeout_secs` (default 180s); while one is\n\
         in flight, `status.json` carries `in_flight_deadline_ms`.\n\
         \n\
         **Reading `status.json` (is a run alive, stalled, or done?):**\n\
         - `running=true` — a run is executing *in this daemon*; wait.\n\
         - `in_flight_deadline_ms` set, `now < deadline` — a network call is\n\
           legitimately in flight; wait until the deadline.\n\
         - `in_flight_deadline_ms` set, `now > deadline` — the call's process\n\
           died or never confirmed in the window; re-write `begin` (idempotent).\n\
         - `in_flight_deadline_ms=null` *and* `last_error=null` at a stage other\n\
           than `fund`/`complete` — a run stopped between network regions (clean\n\
           exit, or killed before an error was persisted); re-`begin` is safe.\n\
         - `last_error` set — a stage failed with a recorded reason; inspect, then re-`begin`.\n\
         - `stage=fund` — resting, awaiting pUSD; `stage=complete` — done.\n\
         \n\
         Note: `running` is in-memory per daemon. When onboarding is driven via\n\
         `bloom vfs write --unlock-wallet` (an in-process daemon), a *separate*\n\
         reader sees `running=false`; rely on `in_flight_deadline_ms` for\n\
         cross-process liveness.\n\
         \n\
         Preconditions enforced on `begin`: wallet unlocked\n\
         The owner key never leaves the bloom daemon.\n",
        wallet = st.wallet,
        owner = st.owner,
        deposit = st.deposit_wallet,
        fund_note = fund_note,
        chain_id = st.chain_id,
        stage = s.as_str(),
        pusd = PUSD,
        m_derive = mark(s > Stage::Derive),
        m_deploy = mark(s > Stage::Deploy),
        m_fund = mark(s > Stage::Fund),
        m_approve = mark(s > Stage::Approve),
        m_creds = mark(s > Stage::Creds),
        m_sync = mark(s > Stage::Sync),
    )
}

fn render_fund_plan_md(sess: &FundSession) -> String {
    format!(
        "# Polymarket pUSD funding request {id}\n\n\
         Wallet:    {wallet} ({owner})\n\
         Receiver:  {deposit_wallet} (Polymarket deposit wallet, source={source})\n\
         Token out: pUSD {pusd:#x} on Polygon\n\
         Current:   {current_pusd} pUSD\n\
         Target:    {target_pusd} pUSD\n\
         Input:     {from_token}, max spend {max_spend}\n\
         Slippage:  {slippage_bps} bps\n\
         Status:    {status}\n\n\
         This VFS request is a durable review artifact for the Polymarket funding flow. \
         Transaction staging/signing for this subtree is not wired yet; until then, use the \
         matching CLI command if you want to execute this exact funding request:\n\n\
         ```sh\n\
         bloom polymarket fund {wallet} --target-pusd {target_pusd} --max-spend {max_spend} \
         --from-token {from_token} --slippage-bps {slippage_bps}\n\
         ```\n",
        id = sess.id,
        wallet = sess.wallet,
        owner = sess.owner,
        deposit_wallet = sess.deposit_wallet,
        source = sess.deposit_wallet_source,
        pusd = PUSD,
        current_pusd = sess.current_pusd,
        target_pusd = sess.target_pusd,
        from_token = sess.from_token,
        max_spend = sess.max_spend,
        slippage_bps = sess.slippage_bps,
        status = sess.status,
    )
}

#[async_trait]
impl Handler for PolymarketHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path);
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "polymarket.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "polymarket.read_err");
        }
        r
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let r = self.write_inner(path, data).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                bytes = data.len(),
                error = %e,
                "polymarket.write_err"
            );
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "polymarket.list_err");
        }
        r
    }

    fn cache_ttl(&self, path: &VfsPath) -> Option<Duration> {
        let segs = path.segments();
        let secs = match segs.first().map(String::as_str) {
            // Onboarding progress must be live — a cached status.json would
            // mask a running state machine.
            Some("onboard") => return None,
            Some("account") => 5,
            // Volatile order-book data.
            Some("markets")
                if matches!(
                    segs.get(2).map(String::as_str),
                    Some("book.json") | Some("prices.json")
                ) =>
            {
                2
            }
            Some("markets") | Some("search") => 30,
            Some("positions") => 10,
            _ => 30,
        };
        Some(Duration::from_secs(secs))
    }
}

impl PolymarketHandler {
    fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Ok(Entry::dir(""));
        }
        if segs.len() == 1 && ROOT_FILES.contains(&segs[0].as_str()) {
            return Ok(Entry::file(&segs[0]));
        }
        match segs[0].as_str() {
            "markets" => match segs.len() {
                1 => Ok(Entry::dir("markets")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if MARKET_FILES.contains(&segs[2].as_str()) => Ok(Entry::file(&segs[2])),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "search" => match segs.len() {
                1 => Ok(Entry::dir("search")),
                2 => Ok(Entry::file(&segs[1])),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "positions" => match segs.len() {
                1 => Ok(Entry::dir("positions")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if POSITION_FILES.contains(&segs[2].as_str()) => Ok(Entry::file(&segs[2])),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "onboard" if self.onboarding_wired() => match segs.len() {
                1 => Ok(Entry::dir("onboard")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if segs[2] == "begin" => Ok(Entry::writable_file("begin")),
                3 if ONBOARD_RO_FILES.contains(&segs[2].as_str()) => {
                    if segs[2] == APPROVAL_CHALLENGE_FILE {
                        let ob = self.onboarding_or_not_found(path)?;
                        let challenge_path = polymarket_onboard_auth_dir(&ob.auth_dir, &segs[1])?
                            .join(APPROVAL_CHALLENGE_FILE);
                        if !challenge_path.exists() {
                            return Err(HandlerError::not_found(path.to_string_path()));
                        }
                    }
                    Ok(Entry::file(&segs[2]))
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "account" if self.onboarding_wired() => match segs.len() {
                1 => Ok(Entry::dir("account")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if ACCOUNT_FILES.contains(&segs[2].as_str()) => Ok(Entry::file(&segs[2])),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "builder-keys" if self.builder_store.is_some() && self.onboarding_wired() => {
                match segs.len() {
                    1 => Ok(Entry::dir("builder-keys")),
                    2 => Ok(Entry::dir(&segs[1])),
                    3 if segs[2] == "keys.json" => Ok(Entry::file("keys.json")),
                    3 if segs[2] == "revoke" => Ok(Entry::writable_file("revoke")),
                    _ => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
            "fund" if self.fund_wired() => match segs.len() {
                1 => Ok(Entry::dir("fund")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if segs[2] == "new" => Ok(Entry::writable_file("new")),
                3 => self.fund_session_dir_entry(path, &segs[1], &segs[2]),
                4 if FUND_FILES.contains(&segs[3].as_str()) => {
                    self.fund_session_file_entry(path, &segs[1], &segs[2], &segs[3])
                }
                4 if segs[3] == "confirm" => {
                    self.fund_session_file_entry(path, &segs[1], &segs[2], "confirm")
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "trade" if self.orders.is_some() => match segs.len() {
                1 => Ok(Entry::dir("trade")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if segs[2] == "new" => Ok(Entry::writable_file("new")),
                3 if segs[2] == "drafts" || segs[2] == "receipts" => Ok(Entry::dir(&segs[2])),
                4 if segs[2] == "drafts" => {
                    let store = self.orders_or_not_found(path)?;
                    self.draft_dir_entry(store, &segs[1], &segs[3])
                }
                4 if segs[2] == "receipts" => {
                    let store = self.orders_or_not_found(path)?;
                    self.receipt_dir_entry(store, &segs[1], &segs[3])
                }
                5 if segs[2] == "drafts" && segs[4] == "confirm" => {
                    let store = self.orders_or_not_found(path)?;
                    self.draft_file_entry(store, &segs[1], &segs[3], "confirm")
                }
                5 if segs[2] == "drafts" && DRAFT_FILES.contains(&segs[4].as_str()) => {
                    let store = self.orders_or_not_found(path)?;
                    self.draft_file_entry(store, &segs[1], &segs[3], &segs[4])
                }
                5 if segs[2] == "receipts" && segs[4] == "receipt.json" => {
                    let store = self.orders_or_not_found(path)?;
                    self.receipt_file_entry(store, &segs[1], &segs[3], &segs[4])
                }
                3 if segs[2] == "orders" => Ok(Entry::dir("orders")),
                4 if segs[2] == "orders" => Ok(Entry::dir(&segs[3])),
                5 if segs[2] == "orders" && segs[4] == "cancel" => {
                    Ok(Entry::writable_file("cancel"))
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            // Redeem is foreground-confirm only: the handler advertises the
            // confirm leaf and renders guidance; execution is refused here and
            // routed through the foreground CLI so the signer is in-process.
            "redeem" if self.orders.is_some() => match segs.len() {
                1 => Ok(Entry::dir("redeem")),
                2 => Ok(Entry::dir(&segs[1])),
                3 => Ok(Entry::dir(&segs[2])),
                4 if segs[3] == "confirm" => Ok(Entry::writable_file("confirm")),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            // Revoke-approvals is a singleton action keyed by the literal
            // `request` segment; foreground-confirm only.
            "revoke-approvals" if self.orders.is_some() => match segs.len() {
                1 => Ok(Entry::dir("revoke-approvals")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if segs[2] == "request" => Ok(Entry::dir("request")),
                4 if segs[2] == "request" && segs[3] == "confirm" => {
                    Ok(Entry::writable_file("confirm"))
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            // pUSD withdraw is a singleton action keyed by the literal `pusd`
            // segment; foreground-confirm only. The amount travels in the body.
            "withdraw" if self.orders.is_some() => match segs.len() {
                1 => Ok(Entry::dir("withdraw")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if segs[2] == "pusd" => Ok(Entry::dir("pusd")),
                4 if segs[2] == "pusd" && segs[3] == "confirm" => {
                    Ok(Entry::writable_file("confirm"))
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        match (segs.first().map(String::as_str), segs.len()) {
            (Some("markets"), 3) => {
                let slug = &segs[1];
                match segs[2].as_str() {
                    "market.json" => {
                        let m = self.gamma.market_by_slug(slug).await.map_err(err_be)?;
                        pretty(&m)
                    }
                    "book.json" => {
                        let yes = self.yes_token_for_slug(slug).await?;
                        let book = self.clob.book(&yes).await.map_err(err_be)?;
                        pretty(&book)
                    }
                    "prices.json" => {
                        let yes = self.yes_token_for_slug(slug).await?;
                        let midpoint = self.clob.midpoint(&yes).await.map_err(err_be)?;
                        let spread = self.clob.spread(&yes).await.map_err(err_be)?;
                        let best_buy = self.clob.price(&yes, Side::Buy).await.map_err(err_be)?;
                        pretty(&serde_json::json!({
                            "token_id": yes,
                            "midpoint": midpoint,
                            "spread": spread,
                            "best_buy": best_buy,
                        }))
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            (Some("search"), 2) => {
                let query = segs[1].replace('+', " ");
                let v = self.gamma.search(&query).await.map_err(err_be)?;
                pretty(&v)
            }
            (Some("positions"), 3) => {
                let addr = self.resolve_address(&segs[1])?;
                let addr = addr.to_checksum(None);
                match segs[2].as_str() {
                    "positions.json" => pretty(&self.data.positions(&addr).await.map_err(err_be)?),
                    "trades.json" => pretty(&self.data.trades(&addr).await.map_err(err_be)?),
                    "activity.json" => pretty(&self.data.activity(&addr).await.map_err(err_be)?),
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            (Some("onboard"), 3) => self.read_onboard(path, &segs[1], &segs[2]).await,
            (Some("account"), 3) => self.read_account(path, &segs[1], &segs[2]).await,
            (Some("builder-keys"), 3) if segs[2] == "keys.json" => {
                self.read_builder_keys(path, &segs[1]).await
            }
            (Some("builder-keys"), 3) if segs[2] == "revoke" => {
                Ok(BUILDER_KEYS_REVOKE_HINT.to_vec())
            }
            (Some("fund"), 3) if segs[2] == "new" => Ok(FUND_NEW_HINT.to_vec()),
            (Some("fund"), 4) if segs[3] == "confirm" => Ok(FUND_CONFIRM_HINT.to_vec()),
            (Some("fund"), 4) => self.read_fund(path, &segs[1], &segs[2], &segs[3]),
            (Some("trade"), 3) if segs[2] == "new" => Ok(TRADE_NEW_HINT.to_vec()),
            (Some("trade"), 5) if segs[2] == "drafts" && segs[4] == "confirm" => {
                Ok(TRADE_CONFIRM_HINT.to_vec())
            }
            (Some("trade"), 5) if segs[2] == "orders" && segs[4] == "cancel" => {
                Ok(CANCEL_HINT.to_vec())
            }
            (Some("trade"), 5) => self.read_trade(path, &segs[1], &segs[2], &segs[3], &segs[4]),
            (Some("redeem"), 4) if segs[3] == "confirm" => Ok(REDEEM_CONFIRM_HINT.to_vec()),
            (Some("revoke-approvals"), 4) if segs[2] == "request" && segs[3] == "confirm" => {
                Ok(REVOKE_APPROVALS_CONFIRM_HINT.to_vec())
            }
            (Some("withdraw"), 4) if segs[2] == "pusd" && segs[3] == "confirm" => {
                Ok(WITHDRAW_PUSD_CONFIRM_HINT.to_vec())
            }
            (Some("README.md"), 1) => Ok(README.to_vec()),
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    /// Read-only views over the durable order store. Drafts contain no
    /// secrets or signatures by construction.
    fn read_trade(
        &self,
        path: &VfsPath,
        wallet: &str,
        kind: &str,
        id: &str,
        file: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let store = self.orders_or_not_found(path)?;
        match kind {
            "drafts" => {
                let draft = store
                    .load_draft(wallet, id)
                    .map_err(err_be)?
                    .ok_or_else(|| HandlerError::not_found(path.to_string_path()))?;
                match file {
                    "plan.md" => Ok(render_plan_md(&draft).into_bytes()),
                    "order.json" => pretty(&draft),
                    "policy_check.json" => pretty(&draft.policy_checks),
                    "quote.json" => pretty(&serde_json::json!({
                        "side": draft.side,
                        "order_type": draft.order_type,
                        "marketable": draft.marketable,
                        "limit_price_micro": draft.limit_price_micro,
                        "price_bound_micro": draft.price_bound_micro,
                        "size_micro": draft.size_micro,
                        "amount_microusd": draft.amount_microusd,
                        "tick_micro": draft.tick_micro,
                        "min_order_size_micro": draft.min_order_size_micro,
                        "best_ask_micro": draft.best_ask_micro,
                        "best_bid_micro": draft.best_bid_micro,
                        "book_snapshot_ms": draft.book_snapshot_ms,
                    })),
                    "review_intent.json" => {
                        let intent = store
                            .load_review_intent(wallet, id)
                            .map_err(err_be)?
                            .ok_or_else(|| HandlerError::not_found(path.to_string_path()))?;
                        pretty(&intent)
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            "receipts" if file == "receipt.json" => {
                let receipt = store
                    .load_receipt(wallet, id)
                    .map_err(err_be)?
                    .ok_or_else(|| HandlerError::not_found(path.to_string_path()))?;
                pretty(&receipt)
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    fn fund_root_or_not_found(&self, path: &VfsPath) -> Result<&Path, HandlerError> {
        self.fund_root
            .as_deref()
            .filter(|_| self.onboarding_wired())
            .ok_or_else(|| HandlerError::not_found(path.to_string_path()))
    }

    fn fund_dir(&self, path: &VfsPath, wallet: &str) -> Result<PathBuf, HandlerError> {
        validate_wallet_name(wallet).map_err(err_be)?;
        Ok(self
            .fund_root_or_not_found(path)?
            .join(wallet)
            .join("fund")
            .join("requests"))
    }

    fn fund_path(&self, path: &VfsPath, wallet: &str, id: &str) -> Result<PathBuf, HandlerError> {
        validate_wallet_name(wallet).map_err(err_be)?;
        Self::validate_fund_id(id)?;
        Ok(self.fund_dir(path, wallet)?.join(format!("{id}.json")))
    }

    fn validate_fund_id(id: &str) -> Result<(), HandlerError> {
        if id.is_empty() || id.contains('/') || id.contains('\\') || id == "." || id == ".." {
            return Err(HandlerError::invalid(format!(
                "invalid fund request id '{id}'"
            )));
        }
        Ok(())
    }

    fn allocate_fund_id(&self, path: &VfsPath, wallet: &str) -> Result<String, HandlerError> {
        let dir = self.fund_dir(path, wallet)?;
        for _ in 0..32 {
            let suffix = now_ms_u128() % 1_000_000_000;
            let id = format!("fund-{suffix:09}");
            if !dir.join(format!("{id}.json")).exists() {
                return Ok(id);
            }
        }
        Err(HandlerError::backend("could not allocate fund request id"))
    }

    fn save_fund_session(&self, path: &VfsPath, sess: &FundSession) -> Result<(), HandlerError> {
        let dir = self.fund_dir(path, &sess.wallet)?;
        fs::create_dir_all(&dir).map_err(|e| HandlerError::backend(e.to_string()))?;
        let path = dir.join(format!("{}.json", sess.id));
        let tmp = path.with_extension("json.tmp");
        fs::write(
            &tmp,
            serde_json::to_vec_pretty(sess).map_err(|e| HandlerError::backend(e.to_string()))?,
        )
        .map_err(|e| HandlerError::backend(e.to_string()))?;
        fs::rename(tmp, path).map_err(|e| HandlerError::backend(e.to_string()))?;
        Ok(())
    }

    fn load_fund_session(
        &self,
        path: &VfsPath,
        wallet: &str,
        id: &str,
    ) -> Result<FundSession, HandlerError> {
        let path = self.fund_path(path, wallet, id)?;
        let bytes =
            fs::read(&path).map_err(|_| HandlerError::not_found(path.display().to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| HandlerError::backend(format!("fund request {}: {e}", path.display())))
    }

    fn list_fund_sessions(
        &self,
        path: &VfsPath,
        wallet: &str,
    ) -> Result<Vec<String>, HandlerError> {
        let dir = self.fund_dir(path, wallet)?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut ids = Vec::new();
        for entry in fs::read_dir(dir).map_err(|e| HandlerError::backend(e.to_string()))? {
            let entry = entry.map_err(|e| HandlerError::backend(e.to_string()))?;
            if entry.file_type().map(|t| t.is_file()).unwrap_or(false)
                && entry.path().extension().and_then(|s| s.to_str()) == Some("json")
                && let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str())
            {
                ids.push(stem.to_string());
            }
        }
        ids.sort();
        Ok(ids)
    }

    fn fund_session_dir_entry(
        &self,
        path: &VfsPath,
        wallet: &str,
        id: &str,
    ) -> Result<Entry, HandlerError> {
        let sess = self.load_fund_session(path, wallet, id)?;
        Ok(Entry::dir(id).with_modified_ms(sess.created_ms))
    }

    fn fund_session_file_entry(
        &self,
        path: &VfsPath,
        wallet: &str,
        id: &str,
        file: &str,
    ) -> Result<Entry, HandlerError> {
        let sess = self.load_fund_session(path, wallet, id)?;
        let entry = if file == "confirm" {
            Entry::writable_file(file)
        } else {
            Entry::file(file)
        };
        Ok(entry.with_modified_ms(sess.updated_ms))
    }

    fn draft_dir_entry(
        &self,
        store: &OrderStore,
        wallet: &str,
        id: &str,
    ) -> Result<Entry, HandlerError> {
        let draft = load_required_draft(store, wallet, id)?;
        Ok(Entry::dir(id).with_modified_ms(draft.created_ms))
    }

    fn draft_file_entry(
        &self,
        store: &OrderStore,
        wallet: &str,
        id: &str,
        file: &str,
    ) -> Result<Entry, HandlerError> {
        let draft = load_required_draft(store, wallet, id)?;
        let entry = if file == "confirm" {
            Entry::writable_file(file)
        } else {
            Entry::file(file)
        };
        Ok(entry.with_modified_ms(draft.updated_ms))
    }

    fn receipt_dir_entry(
        &self,
        store: &OrderStore,
        wallet: &str,
        id: &str,
    ) -> Result<Entry, HandlerError> {
        let receipt = load_required_receipt(store, wallet, id)?;
        Ok(Entry::dir(id).with_modified_ms(receipt.posted_ms))
    }

    fn receipt_file_entry(
        &self,
        store: &OrderStore,
        wallet: &str,
        id: &str,
        file: &str,
    ) -> Result<Entry, HandlerError> {
        let receipt = load_required_receipt(store, wallet, id)?;
        Ok(Entry::file(file).with_modified_ms(receipt.posted_ms))
    }

    fn read_fund(
        &self,
        path: &VfsPath,
        wallet: &str,
        id: &str,
        file: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let sess = self.load_fund_session(path, wallet, id)?;
        match file {
            "request.json" | "status.json" => pretty(&sess),
            "plan.md" => Ok(render_fund_plan_md(&sess).into_bytes()),
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    fn evaluate_draft_policy(
        &self,
        store: &OrderStore,
        draft: &OrderDraft,
    ) -> Result<Vec<bloom_proto::PolicyCheck>, HandlerError> {
        let info = self
            .keystore
            .info(&draft.wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        let (readable, daily) = match store.daily_posted_microusd(&draft.wallet) {
            Ok(v) => (true, Some(v)),
            Err(_) => (false, None),
        };
        let ctx = PolymarketOrderCtx {
            wallet: draft.wallet.clone(),
            slug: draft.slug.clone(),
            condition_id: draft.condition_id.clone(),
            side: match draft.side {
                Side::Buy => PolicySide::Buy,
                Side::Sell => PolicySide::Sell,
            },
            amount_microusd: draft.amount_microusd,
            limit_price_micro: draft.limit_price_micro,
            active: draft.active,
            closed: draft.closed,
            order_book_enabled: draft.order_book_enabled,
            binary_outcomes: draft.binary_outcomes,
            neg_risk: draft.neg_risk,
            receipt_store_readable: readable,
            daily_posted_microusd: daily,
        };
        Ok(pm_policy::evaluate_polymarket_order(
            &info.policy.polymarket,
            &ctx,
        ))
    }

    async fn create_trade_draft(&self, wallet: &str, data: &[u8]) -> Result<(), HandlerError> {
        let req: TradeNewRequest = serde_json::from_slice(data)
            .map_err(|e| HandlerError::invalid(format!("trade new JSON: {e}")))?;
        let side = match req
            .side
            .as_deref()
            .unwrap_or("buy")
            .to_ascii_lowercase()
            .as_str()
        {
            "buy" => Side::Buy,
            "sell" => Side::Sell,
            other => {
                return Err(HandlerError::invalid(format!(
                    "side must be buy or sell, got {other}"
                )));
            }
        };
        let amount_micro = order::parse_micro(&req.amount).map_err(err_be)?;
        let marketable = req.limit_price.is_none();
        let price_bound = match side {
            Side::Buy => req.max_price.as_ref().or(req.limit_price.as_ref()),
            Side::Sell => req.min_price.as_ref().or(req.limit_price.as_ref()),
        }
        .ok_or_else(|| {
            HandlerError::invalid(match side {
                Side::Buy => "buy requires max_price or limit_price",
                Side::Sell => "sell requires min_price or limit_price",
            })
        })?;
        let bound_micro = order::parse_micro(price_bound).map_err(err_be)?;
        let pinned_limit_micro = req
            .limit_price
            .as_ref()
            .map(|p| order::parse_micro(p).map_err(err_be))
            .transpose()?
            .unwrap_or(bound_micro);
        let order_type = match req.order_type.as_deref() {
            Some(s) => s
                .parse::<OrderType>()
                .map_err(|e| HandlerError::invalid(e.to_string()))?,
            None if marketable => OrderType::FAK,
            None => OrderType::GTC,
        };
        if order_type == OrderType::GTD {
            return Err(HandlerError::invalid("GTD orders are not supported"));
        }

        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        let (funder, signature_type) = self.trade_funder(wallet).await?;
        let snap = trade::snapshot(&self.gamma, &self.clob, &req.slug, &req.outcome)
            .await
            .map_err(err_be)?;
        let limit_micro =
            trade::choose_limit(side, marketable, bound_micro, pinned_limit_micro, &snap)
                .map_err(err_be)?;
        let quote = trade::build_quote(side, amount_micro, limit_micro, &snap, order_type)
            .map_err(err_be)?;
        let store = self
            .orders
            .as_deref()
            .ok_or_else(|| HandlerError::not_found("trade"))?;
        let mut draft = trade::draft_from_quote(
            wallet,
            bloom_proto::checksum_address(&info.address),
            Some(bloom_proto::checksum_address(&funder)),
            signature_type,
            &req.slug,
            &req.outcome,
            side,
            order_type,
            bound_micro,
            marketable,
            now_ms_u128(),
            &snap,
            &quote,
        );
        let checks = self.evaluate_draft_policy(store, &draft)?;
        draft.policy_checks =
            serde_json::to_value(&checks).map_err(|e| HandlerError::backend(e.to_string()))?;
        let draft = store.create_draft(draft).map_err(err_be)?;
        if let Some(audit) = &self.audit {
            let _ = audit.append(AuditRecord {
                ts_ms: 0,
                kind: "polymarket.trade.draft_created".into(),
                wallet: Some(wallet.into()),
                chain: None,
                data: serde_json::json!({
                    "wallet": wallet,
                    "draft_id": draft.id,
                    "slug": draft.slug,
                    "side": draft.side,
                    "amount_microusd": draft.amount_microusd,
                }),
                prev: String::new(),
                digest: String::new(),
            });
        }
        Ok(())
    }

    async fn read_onboard(
        &self,
        path: &VfsPath,
        wallet: &str,
        file: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let ob = self.onboarding_or_not_found(path)?;
        if file == "begin" {
            return Ok(BEGIN_HINT.to_vec());
        }
        let owner = self.wallet_address(wallet)?;
        let st = ob.onboarder.status(wallet, owner).map_err(err_be)?;
        match file {
            "status.json" => {
                let mut v =
                    serde_json::to_value(&st).map_err(|e| HandlerError::backend(e.to_string()))?;
                v["running"] = serde_json::json!(self.running.lock().unwrap().contains(wallet));
                v["poll_timeout_secs"] = serde_json::json!(ob.onboarder.poll_timeout_secs());
                // The CLOB rejects EOA makers: a Complete EOA run is NOT
                // tradeable, and status must never imply otherwise.
                v["tradeable"] = serde_json::json!(st.tradeable());
                if st.stage == Stage::Fund {
                    if st.deposit_wallet_fundable {
                        v["funding_instructions"] = serde_json::json!(format!(
                            "funding address needs pUSD ({PUSD:#x}) on Polygon. \
                             Preferred: `bloom polymarket fund {wallet} --target-pusd <amount> \
                             --max-spend <native-amount>` (target-denominated swap through the \
                             standard tx engine), or run `bloom polymarket onboard {wallet} \
                             --target-pusd <amount> --max-spend <native-amount>` to fund and \
                             finish onboarding in one command. \
                             Or send pUSD directly to {}. \
                             Then write onboard/{wallet}/begin again to resume.",
                            st.deposit_wallet
                        ));
                    } else {
                        v["funding_instructions"] = serde_json::json!(
                            "do not fund this deposit_wallet value: it is a local estimate. \
                             Run `bloom polymarket onboard {wallet}` or write begin first so \
                             Bloom resolves the live factory address."
                        );
                    }
                }
                pretty(&v)
            }
            "plan.md" => Ok(render_onboard_plan_md(&st).into_bytes()),
            "approvals.json" => pretty(&ob.onboarder.approval_preview(owner)),
            APPROVAL_CHALLENGE_FILE => {
                let challenge_path = polymarket_onboard_auth_dir(&ob.auth_dir, wallet)?
                    .join(APPROVAL_CHALLENGE_FILE);
                std::fs::read(&challenge_path).map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => HandlerError::NotAFile(path.to_string_path()),
                    _ => HandlerError::Io(e),
                })
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn read_account(
        &self,
        path: &VfsPath,
        wallet: &str,
        file: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let ob = self.onboarding_or_not_found(path)?;
        let owner = self.wallet_address(wallet)?;
        match file {
            // Sectioned by source so provenance is unambiguous: what the CLOB
            // believes vs. what the chain holds vs. where onboarding stands.
            "portfolio.json" => {
                let creds = ob.creds.load(wallet).map_err(err_be)?.ok_or_else(|| {
                    HandlerError::invalid(format!(
                        "wallet '{wallet}' is not onboarded (no CLOB credentials); \
                         write polymarket/onboard/{wallet}/begin first"
                    ))
                })?;
                let st = ob.onboarder.status(wallet, owner).map_err(err_be)?;
                let deposit: Address = st.deposit_wallet.parse().map_err(|_| {
                    HandlerError::backend("corrupt deposit_wallet in onboarding state")
                })?;
                let clob_ba = self
                    .clob
                    .balance_allowance(&creds, owner, "COLLATERAL", 3)
                    .await
                    .map_err(err_be)?;
                let pusd = ob
                    .chain
                    .erc20_balance(PUSD, deposit)
                    .await
                    .map_err(err_be)?;
                pretty(&serde_json::json!({
                    "clob_balance_allowance": clob_ba,
                    "deposit_wallet": {
                        "address": st.deposit_wallet,
                        "source": st.deposit_wallet_source,
                        "fundable": st.deposit_wallet_fundable,
                        "warning": st.deposit_wallet_warning,
                        "pusd_balance": pusd.to_string(),
                    },
                    "onboarding_state": {
                        "stage": st.stage.as_str(),
                        "creds_present": st.creds_present,
                    },
                }))
            }
            "orders.json" => {
                let creds = ob.creds.load(wallet).map_err(err_be)?.ok_or_else(|| {
                    HandlerError::invalid(format!(
                        "wallet '{wallet}' is not onboarded (no CLOB credentials); \
                         write polymarket/onboard/{wallet}/begin first"
                    ))
                })?;
                let orders = self.clob.open_orders(&creds, owner).await.map_err(err_be)?;
                pretty(&orders)
            }
            // Polymarket *trading* state only. Owner native balance is NOT here;
            // it is a chain fact at wallets/<w>/chains/<chain>/balance.json.
            "status.json" => {
                use bloom_polymarket::onboard::Stage;
                let st = ob.onboarder.status(wallet, owner).map_err(err_be)?;
                let deposit: Address = st.deposit_wallet.parse().map_err(|_| {
                    HandlerError::backend("corrupt deposit_wallet in onboarding state")
                })?;
                let pusd = ob
                    .chain
                    .erc20_balance(PUSD, deposit)
                    .await
                    .map_err(err_be)?;
                let tradeable = matches!(st.stage, Stage::Sync) && st.creds_present;
                let approvals_granted = matches!(st.stage, Stage::Creds | Stage::Sync);
                let next_required_action = if tradeable {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(format!(
                        "continue onboarding (stage: {})",
                        st.stage.as_str()
                    ))
                };
                let fmt = bloom_proto::format_units(pusd, PUSD_DECIMALS);
                pretty(&serde_json::json!({
                    "wallet": wallet,
                    "owner_address": bloom_proto::checksum_address(&owner),
                    "deposit_wallet": st.deposit_wallet,
                    "deposit_wallet_source": st.deposit_wallet_source,
                    "mode": "deposit_wallet",
                    "tradeable": tradeable,
                    "onboarding_stage": st.stage.as_str(),
                    "chain_id": st.chain_id,
                    "approvals_granted": approvals_granted,
                    "approve_tx_id": st.approve_tx_id,
                    "balances": {
                        "deposit_pusd": {
                            "symbol": "pUSD",
                            "raw": pusd.to_string(),
                            "formatted": fmt,
                            "display": format!("{fmt} pUSD"),
                        }
                    },
                    "next_required_action": next_required_action,
                }))
            }
            "buying_power.json" => {
                let creds = ob.creds.load(wallet).map_err(err_be)?.ok_or_else(|| {
                    HandlerError::invalid(format!(
                        "wallet '{wallet}' is not onboarded (no CLOB credentials); \
                         write polymarket/onboard/{wallet}/begin first"
                    ))
                })?;
                use bloom_polymarket::onboard::Stage;
                let st = ob.onboarder.status(wallet, owner).map_err(err_be)?;
                let deposit: Address = st.deposit_wallet.parse().map_err(|_| {
                    HandlerError::backend("corrupt deposit_wallet in onboarding state")
                })?;
                let clob_ba = self
                    .clob
                    .balance_allowance(&creds, owner, "COLLATERAL", 3)
                    .await
                    .map_err(err_be)?;
                let pusd = ob
                    .chain
                    .erc20_balance(PUSD, deposit)
                    .await
                    .map_err(err_be)?;
                let tradeable = matches!(st.stage, Stage::Sync) && st.creds_present;
                let fmt = bloom_proto::format_units(pusd, PUSD_DECIMALS);
                pretty(&serde_json::json!({
                    "wallet": wallet,
                    "spendable": {
                        "asset": "pUSD",
                        "raw": pusd.to_string(),
                        "formatted": fmt,
                        "source": "deposit_wallet",
                        "clob_balance_allowance": clob_ba,
                    },
                    "native_funding_capacity_ref":
                        format!("wallets/{wallet}/chains/polygon/balance.json"),
                    "can_trade_now": tradeable && pusd > U256::ZERO,
                    "funding_needed": pusd == U256::ZERO,
                    "notes": [
                        "Order size must be based on spendable pUSD, not owner native balance.",
                        "Native funding capacity is not embedded here; read native_funding_capacity_ref."
                    ],
                }))
            }
            "funding_options.json" => pretty(&serde_json::json!({
                "wallet": wallet,
                "target_asset": "pUSD",
                "options": [{
                    "from": "native",
                    "supported": true,
                    "review_required": true,
                    "notes": "Use Bloom Polymarket funding (`bloom polymarket fund` / `onboard --target-pusd`); do not call external DEX APIs directly."
                }],
                "limits": {
                    "policy_caps_apply": true,
                    "requires_quote": true,
                    "native_value_caps_are_quantity_caps": true
                }
            })),
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn create_fund_request(
        &self,
        path: &VfsPath,
        wallet: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        self.fund_root_or_not_found(path)?;
        validate_wallet_name(wallet).map_err(err_be)?;
        let body = std::str::from_utf8(data)
            .map_err(|_| HandlerError::invalid("fund request must be utf-8 json"))?;
        let req: FundNewRequest =
            serde_json::from_str(body).map_err(|e| HandlerError::invalid(format!("json: {e}")))?;
        validate_fund_request(&req)?;
        let owner = self.wallet_address(wallet)?;
        let ob = self.onboarding_or_not_found(path)?;
        let st = ob.onboarder.status(wallet, owner).map_err(err_be)?;
        if !st.deposit_wallet_fundable {
            return Err(HandlerError::invalid(
                "deposit wallet is not fundable yet; run onboarding until the live factory address is resolved",
            ));
        }
        let deposit: Address = st
            .deposit_wallet
            .parse()
            .map_err(|e| HandlerError::backend(format!("bad deposit wallet in state: {e}")))?;
        let pusd = ob
            .chain
            .erc20_balance(PUSD, deposit)
            .await
            .map_err(err_be)?;
        let id = self.allocate_fund_id(path, wallet)?;
        let now = now_ms_u128();
        let sess = FundSession {
            id,
            wallet: wallet.to_string(),
            owner: bloom_proto::checksum_address(&owner),
            deposit_wallet: st.deposit_wallet,
            deposit_wallet_source: st.deposit_wallet_source,
            deposit_wallet_fundable: st.deposit_wallet_fundable,
            current_pusd_raw: pusd.to_string(),
            current_pusd: bloom_proto::units::format_units(pusd, PUSD_DECIMALS),
            target_pusd: req.target_pusd,
            max_spend: req.max_spend,
            from_token: req.from_token.unwrap_or_else(|| "native".to_string()),
            slippage_bps: req.slippage_bps,
            status: "draft".to_string(),
            created_ms: now,
            updated_ms: now,
        };
        self.save_fund_session(path, &sess)?;
        if let Some(audit) = &self.audit {
            let _ = audit.append(AuditRecord {
                ts_ms: 0,
                kind: "polymarket.fund.request_created".into(),
                wallet: Some(wallet.into()),
                chain: Some("polygon".into()),
                data: serde_json::json!({
                    "wallet": wallet,
                    "request_id": sess.id,
                    "target_pusd": sess.target_pusd,
                    "max_spend": sess.max_spend,
                    "from_token": sess.from_token,
                    "deposit_wallet": sess.deposit_wallet,
                }),
                prev: String::new(),
                digest: String::new(),
            });
        }
        Ok(())
    }

    async fn write_inner(&self, path: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        if segs.len() == 3 && segs[0] == "fund" && segs[2] == "new" {
            if _data.is_empty() {
                return Err(HandlerError::invalid("empty fund new request"));
            }
            return self.create_fund_request(path, &segs[1], _data).await;
        }
        if segs.len() == 4 && segs[0] == "fund" && segs[3] == "confirm" {
            return Err(HandlerError::Unsupported(
                "fund confirmation must run through the foreground CLI VFS path so the \
                 wallet unlock and signer live in the same process: \
                 bloom vfs write /polymarket/fund/<wallet>/<id>/confirm \
                 --unlock-wallet <wallet> --data confirm"
                    .into(),
            ));
        }
        if segs.len() == 3 && segs[0] == "trade" && segs[2] == "new" {
            if _data.is_empty() {
                return Err(HandlerError::invalid("empty trade new request"));
            }
            return self.create_trade_draft(&segs[1], _data).await;
        }
        if segs.len() == 5 && segs[0] == "trade" && segs[2] == "drafts" && segs[4] == "confirm" {
            if self.auth_services.is_wired() {
                return self
                    .confirm_order_via_sealed(&segs[1], &segs[3], _data)
                    .await;
            }
            return Err(HandlerError::Unsupported(
                "trade draft confirmation must run through the foreground CLI VFS path so the \
                 wallet unlock and signer live in the same process: \
                 bloom vfs write /polymarket/trade/<wallet>/drafts/<id>/confirm \
                 --unlock-wallet <wallet> --data confirm"
                    .into(),
            ));
        }
        // Cancel uses stored CLOB creds (no owner signing), so it executes
        // directly here after compliance checks rather than refusing like the
        // owner-signed confirm paths.
        if segs.len() == 5 && segs[0] == "trade" && segs[2] == "orders" && segs[4] == "cancel" {
            let trimmed = std::str::from_utf8(_data)
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if !matches!(trimmed.as_str(), "confirm" | "y" | "yes") {
                return Err(HandlerError::invalid(
                    "cancel request body must be 'confirm', 'y', or 'yes'",
                ));
            }
            return self.execute_cancel(&segs[1], &segs[3]).await;
        }
        if segs.len() == 3 && segs[0] == "builder-keys" && segs[2] == "revoke" {
            return self.execute_builder_key_revoke(&segs[1], _data).await;
        }
        if segs.len() == 4 && segs[0] == "redeem" && segs[3] == "confirm" {
            if self.auth_services.is_wired() {
                return self.execute_redeem_sealed(&segs[1], &segs[2]).await;
            }
            return Err(HandlerError::Unsupported(
                "redeem confirmation must run through the foreground CLI VFS path so the \
                 wallet unlock and signer live in the same process: \
                 bloom vfs write /polymarket/redeem/<wallet>/<slug>/confirm \
                 --unlock-wallet <wallet> --data confirm"
                    .into(),
            ));
        }
        if segs.len() == 4
            && segs[0] == "revoke-approvals"
            && segs[2] == "request"
            && segs[3] == "confirm"
        {
            if self.auth_services.is_wired() {
                return self.execute_revoke_sealed(&segs[1]).await;
            }
            return Err(HandlerError::Unsupported(
                "revoke-approvals confirmation must run through the foreground CLI VFS path so the \
                 wallet unlock and signer live in the same process: \
                 bloom vfs write /polymarket/revoke-approvals/<wallet>/request/confirm \
                 --unlock-wallet <wallet> --data confirm"
                    .into(),
            ));
        }
        if segs.len() == 4 && segs[0] == "withdraw" && segs[2] == "pusd" && segs[3] == "confirm" {
            // The wired (serve-socket) withdraw path is intentionally closed: it
            // does not yet parse the body `amount`, bind it into the sealed
            // subject/action_id, or read the live pUSD balance, so it cannot
            // authorize a specific transfer. Until that lands (serve-socket
            // passkey ceremony, tracked in docs/issues C2) every withdrawal —
            // password *and* passkey wallets — goes through the foreground CLI
            // path, which reads the balance, validates the amount, and submits
            // the correct `pUSD.transfer(owner, amount)`.
            return Err(HandlerError::Unsupported(
                "pUSD withdrawal confirmation must run through the foreground CLI VFS path so the \
                 wallet unlock and signer live in the same process, and the amount is bound to the \
                 signed batch: \
                 bloom vfs write /polymarket/withdraw/<wallet>/pusd/confirm \
                 --unlock-wallet <wallet> --data '{\"confirm\":true,\"amount\":\"<amount|all>\"}'"
                    .into(),
            ));
        }
        if !(segs.len() == 3 && segs[0] == "onboard" && segs[2] == "begin") {
            return Err(HandlerError::PermissionDenied);
        }
        let wallet = segs[1].as_str();
        let Some(ob) = self.onboarding.as_ref() else {
            return Err(HandlerError::Unsupported(
                "polymarket onboarding is not configured: the daemon needs a [chains] entry \
                 whose chain_id matches [polymarket].chain_id (Polygon = 137)"
                    .into(),
            ));
        };
        validate_wallet_name(wallet).map_err(err_be)?;
        // Wallet must exist…
        self.wallet_address(wallet)?;
        if self.auth_services.is_wired() {
            return self.begin_onboard_sealed(ob, wallet).await;
        }
        // …and be unlocked: signing (approval batch, ClobAuth) needs the key.
        let signer_arc = self.keystore.signer(wallet).map_err(|e| match e {
            KeystoreError::Locked(_) => HandlerError::invalid(format!(
                "wallet '{wallet}' is locked; unlock it before onboarding"
            )),
            other => HandlerError::backend(other.to_string()),
        })?;
        // Single-flight per wallet.
        if !self.running.lock().unwrap().insert(wallet.to_string()) {
            return Err(HandlerError::invalid(format!(
                "onboarding for '{wallet}' is already running; read onboard/{wallet}/status.json"
            )));
        }
        let guard = RunningGuard {
            set: self.running.clone(),
            wallet: wallet.to_string(),
        };

        // The run polls the relayer for minutes; a synchronous write would
        // stall the NFS COMMIT path. Spawn and report through status.json —
        // Onboarder persists last_error, so failures stay observable.
        let onboarder = ob.onboarder.clone();
        let audit = self.audit.clone();
        let wallet = wallet.to_string();
        let signer = KeystoreSigner::new(signer_arc);
        tokio::spawn(async move {
            let _guard = guard;
            let audit_wallet = wallet.clone();
            let on_event = move |event: OnboardEvent| {
                audit_onboard_event(audit.as_deref(), &audit_wallet, &event);
            };
            match onboarder.run(&wallet, &signer, &on_event as &OnEvent).await {
                Ok(st) => tracing::info!(
                    wallet = %wallet,
                    stage = st.stage.as_str(),
                    "polymarket.onboard.run_finished"
                ),
                Err(e) => tracing::warn!(
                    wallet = %wallet,
                    error = %e,
                    "polymarket.onboard.run_failed"
                ),
            }
        });
        Ok(())
    }

    /// Wired-mode onboarding: stage a sealed action (deterministic action_id,
    /// max_signatures=3), check for a live grant, and either spawn the
    /// onboarder with a [`SealedOnboardSigner`] or issue a challenge +
    /// return `PermissionDenied`.
    async fn begin_onboard_sealed(
        &self,
        ob: &PolymarketOnboarding,
        wallet: &str,
    ) -> Result<(), HandlerError> {
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        let owner = info.address;
        let action_id = polymarket_onboard_action_id(wallet);
        let now = pm_now_ms_u64();

        // Stage the sealed action (idempotent — deterministic action_id).
        let sealed = polymarket_onboard_sealed_action(wallet, owner, now)?;
        self.auth_services
            .require_writer()?
            .stage_action(sealed, now)
            .await
            .map_err(|e| {
                HandlerError::backend(format!("stage Polymarket onboarding action: {e}"))
            })?;

        // Check for active grant.
        let grant_store = self.auth_services.require_grant_store()?;
        let grant = grant_store
            .get_active(
                wallet,
                &action_id,
                petal_identity::PETAL_ID_POLYMARKET,
                petal_identity::PLACEHOLDER_DIGEST_POLYMARKET,
                now,
            )
            .await
            .map_err(|e| HandlerError::backend(format!("lookup onboarding grant: {e}")))?;

        if grant.is_none() {
            // Legacy approval.json recovery path.
            let dir = polymarket_onboard_auth_dir(&ob.auth_dir, wallet)?;
            fs::create_dir_all(&dir)?;
            let approval_path = dir.join(APPROVAL_FILE);
            if approval_path.exists() {
                let approval: SignedApproval = read_json(&approval_path)?;
                self.auth_services
                    .require_approval_verifier()?
                    .verify_and_mint_grant(approval, grant_store.as_ref(), now)
                    .await
                    .map_err(|e| HandlerError::invalid(format!("Sealed Approval rejected: {e}")))?;
            } else {
                let mut nonce_bytes = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
                let server_nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
                let challenge = self
                    .auth_services
                    .require_writer()?
                    .issue_challenge(
                        POLYMARKET_SURFACE,
                        &action_id,
                        &server_nonce,
                        pm_now_ms_u64().saturating_add(APPROVAL_TTL_MS),
                        pm_now_ms_u64(),
                    )
                    .await
                    .map_err(|e| {
                        HandlerError::backend(format!("issue Polymarket onboarding challenge: {e}"))
                    })?
                    .with_local_ceremony_url();
                write_json(dir.join(APPROVAL_CHALLENGE_FILE), &challenge)?;
                return Err(HandlerError::PermissionDenied);
            }
        }

        // Grant exists — spawn the onboarder with a sealed signer.
        let host = self.auth_services.require_petal_host()?.clone();
        let signer = SealedOnboardSigner {
            host,
            wallet: wallet.to_string(),
            action_id,
            kind: PolymarketSealedActionKind::Onboarding,
            owner,
        };

        // Single-flight per wallet.
        if !self.running.lock().unwrap().insert(wallet.to_string()) {
            return Err(HandlerError::invalid(format!(
                "onboarding for '{wallet}' is already running; read onboard/{wallet}/status.json"
            )));
        }
        let guard = RunningGuard {
            set: self.running.clone(),
            wallet: wallet.to_string(),
        };
        let onboarder = ob.onboarder.clone();
        let audit = self.audit.clone();
        let wallet_owned = wallet.to_string();
        tokio::spawn(async move {
            let _guard = guard;
            let audit_wallet = wallet_owned.clone();
            let on_event = move |event: OnboardEvent| {
                audit_onboard_event(audit.as_deref(), &audit_wallet, &event);
            };
            match onboarder
                .run(&wallet_owned, &signer, &on_event as &OnEvent)
                .await
            {
                Ok(st) => tracing::info!(
                    wallet = %wallet_owned,
                    stage = st.stage.as_str(),
                    "polymarket.onboard.sealed_run_finished"
                ),
                Err(e) => tracing::warn!(
                    wallet = %wallet_owned,
                    error = %e,
                    "polymarket.onboard.sealed_run_failed"
                ),
            }
        });
        Ok(())
    }

    /// Stage a prebuilt sealed action for a polymarket operation and check
    /// for a live grant. Returns `Ok(())` if the grant exists (proceed with
    /// execution). Returns `PermissionDenied` (after writing a challenge) if
    /// no grant. Used by redeem, withdraw, and revoke.
    async fn stage_and_check_sealed(
        &self,
        wallet: &str,
        sealed: SealedAction,
        auth_dir: &Path,
    ) -> Result<(), HandlerError> {
        let now = pm_now_ms_u64();
        let action_id = sealed.action_id().to_string();
        let subject_label = sealed.envelope.header.action_kind.clone();
        self.auth_services
            .require_writer()?
            .stage_action(sealed, now)
            .await
            .map_err(|e| HandlerError::backend(format!("stage Polymarket {subject_label}: {e}")))?;
        let grant_store = self.auth_services.require_grant_store()?;
        let grant = grant_store
            .get_active(
                wallet,
                &action_id,
                petal_identity::PETAL_ID_POLYMARKET,
                petal_identity::PLACEHOLDER_DIGEST_POLYMARKET,
                now,
            )
            .await
            .map_err(|e| HandlerError::backend(format!("lookup grant: {e}")))?;
        if grant.is_none() {
            let dir = polymarket_onboard_auth_dir(auth_dir, wallet)?;
            fs::create_dir_all(&dir)?;
            let approval_path = dir.join(&action_id).join(APPROVAL_FILE);
            fs::create_dir_all(approval_path.parent().unwrap())?;
            if approval_path.exists() {
                let approval: SignedApproval = read_json(&approval_path)?;
                self.auth_services
                    .require_approval_verifier()?
                    .verify_and_mint_grant(approval, grant_store.as_ref(), now)
                    .await
                    .map_err(|e| HandlerError::invalid(format!("Sealed Approval rejected: {e}")))?;
            } else {
                let mut nonce_bytes = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
                let server_nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
                let challenge = self
                    .auth_services
                    .require_writer()?
                    .issue_challenge(
                        POLYMARKET_SURFACE,
                        &action_id,
                        &server_nonce,
                        pm_now_ms_u64().saturating_add(APPROVAL_TTL_MS),
                        pm_now_ms_u64(),
                    )
                    .await
                    .map_err(|e| HandlerError::backend(format!("issue challenge: {e}")))?
                    .with_local_ceremony_url();
                let challenge_path = approval_path.with_file_name(APPROVAL_CHALLENGE_FILE);
                write_json(challenge_path, &challenge)?;
                return Err(HandlerError::PermissionDenied);
            }
        }
        Ok(())
    }

    /// Resolve the deposit wallet address for `wallet` from onboarding state.
    async fn deposit_wallet_of(
        &self,
        wallet: &str,
    ) -> Result<alloy::primitives::Address, HandlerError> {
        let ob = self
            .onboarding
            .as_ref()
            .ok_or_else(|| HandlerError::not_found("polymarket onboarding not configured"))?;
        let store = bloom_polymarket::OnboardStore::new(&ob.auth_dir);
        let st = store
            .load(wallet)
            .map_err(err_be)?
            .ok_or_else(|| HandlerError::invalid("wallet not onboarded"))?;
        st.deposit_wallet
            .parse()
            .map_err(|_| HandlerError::backend("corrupt deposit_wallet"))
    }

    /// Wired-mode revoke-approvals: stage sealed → grant check → submit
    /// revocation batch via relayer.
    async fn execute_revoke_sealed(&self, wallet: &str) -> Result<(), HandlerError> {
        let ob = self
            .onboarding
            .as_ref()
            .ok_or_else(|| HandlerError::not_found("polymarket onboarding not configured"))?;
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        let owner = info.address;
        let deposit = self.deposit_wallet_of(wallet).await?;
        let action_id = polymarket_revoke_action_id(wallet);
        let sealed = polymarket_revocation_sealed_action(wallet, deposit, pm_now_ms_u64())?;
        self.stage_and_check_sealed(wallet, sealed, &ob.auth_dir)
            .await?;
        // Grant exists — submit the revocation batch.
        let host = self.auth_services.require_petal_host()?.clone();
        let signer = SealedOnboardSigner {
            host,
            wallet: wallet.into(),
            action_id: action_id.clone(),
            kind: PolymarketSealedActionKind::Revocation,
            owner,
        };
        let noop: &OnEvent = &|_| {};
        let relayer = ob
            .onboarder
            .relayer_for(wallet, owner, &signer, noop)
            .await
            .map_err(err_be)?;
        let nonce = relayer.wallet_nonce(owner).await.map_err(err_be)?;
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            + 3600;
        let tx = relayer
            .submit_wallet_batch(
                owner,
                deposit,
                bloom_polymarket::wallet::revoke_calls(),
                nonce,
                deadline,
                &signer,
            )
            .await
            .map_err(err_be)?;
        if let Some(audit) = self.audit.as_ref() {
            let _ = audit.append(AuditRecord {
                ts_ms: 0,
                kind: "polymarket.revoke.sealed_submitted".into(),
                wallet: Some(wallet.into()),
                chain: None,
                data: serde_json::json!({"tx_id": tx.id, "action_id": action_id}),
                prev: String::new(),
                digest: String::new(),
            });
        }
        Ok(())
    }

    /// Wired-mode redeem: stage sealed → grant check → submit redemption
    /// batch via relayer.
    async fn execute_redeem_sealed(&self, wallet: &str, slug: &str) -> Result<(), HandlerError> {
        let ob = self
            .onboarding
            .as_ref()
            .ok_or_else(|| HandlerError::not_found("polymarket onboarding not configured"))?;
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        let owner = info.address;
        let deposit = self.deposit_wallet_of(wallet).await?;
        // Resolve the market to get conditionId + negRisk.
        let market = self.gamma.market_by_slug(slug).await.map_err(err_be)?;
        let condition_id = if market.condition_id.is_empty() {
            return Err(HandlerError::invalid("market has no conditionId"));
        } else {
            &market.condition_id
        };
        let condition_id_b256 = condition_id
            .parse::<alloy::primitives::B256>()
            .map_err(|e| HandlerError::invalid(format!("conditionId parse: {e}")))?;
        let neg_risk = market.neg_risk;
        let action_id = polymarket_redeem_action_id(wallet, condition_id);
        let sealed = polymarket_redemption_sealed_action(
            wallet,
            deposit,
            condition_id,
            neg_risk,
            pm_now_ms_u64(),
        )?;
        self.stage_and_check_sealed(wallet, sealed, &ob.auth_dir)
            .await?;
        // Grant exists — submit the redemption batch.
        let host = self.auth_services.require_petal_host()?.clone();
        let signer = SealedOnboardSigner {
            host,
            wallet: wallet.into(),
            action_id: action_id.clone(),
            kind: PolymarketSealedActionKind::Redemption,
            owner,
        };
        let noop: &OnEvent = &|_| {};
        let relayer = ob
            .onboarder
            .relayer_for(wallet, owner, &signer, noop)
            .await
            .map_err(err_be)?;
        let calls = vec![bloom_polymarket::wallet::redeem_positions_call(
            condition_id_b256,
            neg_risk,
        )];
        let nonce = relayer.wallet_nonce(owner).await.map_err(err_be)?;
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            + 3600;
        let tx = relayer
            .submit_wallet_batch(owner, deposit, calls, nonce, deadline, &signer)
            .await
            .map_err(err_be)?;
        if let Some(audit) = self.audit.as_ref() {
            let _ = audit.append(AuditRecord {
                ts_ms: 0,
                kind: "polymarket.redeem.sealed_submitted".into(),
                wallet: Some(wallet.into()),
                chain: None,
                data: serde_json::json!({
                    "tx_id": tx.id,
                    "action_id": action_id,
                    "condition_id": condition_id,
                }),
                prev: String::new(),
                digest: String::new(),
            });
        }
        Ok(())
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        match (segs.first().map(String::as_str), segs.len()) {
            (None, 0) => {
                let mut entries = Vec::new();
                entries.push(Entry::file("README.md"));
                if self.onboarding_wired() {
                    entries.push(Entry::dir("account"));
                }
                entries.push(Entry::dir("markets"));
                if self.onboarding_wired() {
                    entries.push(Entry::dir("onboard"));
                }
                if self.builder_store.is_some() && self.onboarding_wired() {
                    entries.push(Entry::dir("builder-keys"));
                }
                if self.fund_wired() {
                    entries.push(Entry::dir("fund"));
                }
                entries.push(Entry::dir("positions"));
                entries.push(Entry::dir("search"));
                if self.orders.is_some() {
                    entries.push(Entry::dir("redeem"));
                    entries.push(Entry::dir("trade"));
                    entries.push(Entry::dir("revoke-approvals"));
                    entries.push(Entry::dir("withdraw"));
                }
                Ok(entries)
            }
            (Some("markets"), 1) => {
                let markets = self
                    .gamma
                    .list_markets(false, MARKETS_LIST_LIMIT, Some("volumeNum"), false)
                    .await
                    .map_err(err_be)?;
                Ok(markets
                    .into_iter()
                    .filter(|m| !m.slug.is_empty())
                    .map(|m| Entry::dir(&m.slug))
                    .collect())
            }
            (Some("markets"), 2) => Ok(MARKET_FILES.iter().map(|f| Entry::file(f)).collect()),
            // `search/` has no enumerable children — queries are arbitrary.
            (Some("search"), 1) => Ok(Vec::new()),
            // `positions/` lists the local keystore wallets as a convenience;
            // raw 0x addresses are also valid but not enumerable.
            (Some("positions"), 1) => self.list_keystore_wallets(),
            (Some("positions"), 2) => Ok(POSITION_FILES.iter().map(|f| Entry::file(f)).collect()),
            (Some("onboard"), 1) => {
                self.onboarding_or_not_found(path)?;
                self.list_keystore_wallets()
            }
            (Some("onboard"), 2) => {
                let ob = self.onboarding_or_not_found(path)?;
                let mut entries: Vec<Entry> =
                    ONBOARD_RO_FILES.iter().map(|f| Entry::file(f)).collect();
                entries.retain(|entry| {
                    entry.name != APPROVAL_CHALLENGE_FILE
                        || polymarket_onboard_auth_dir(&ob.auth_dir, &segs[1])
                            .map(|dir| dir.join(APPROVAL_CHALLENGE_FILE).exists())
                            .unwrap_or(false)
                });
                entries.push(Entry::writable_file("begin"));
                Ok(entries)
            }
            (Some("account"), 1) => {
                self.onboarding_or_not_found(path)?;
                self.list_keystore_wallets()
            }
            (Some("account"), 2) => {
                self.onboarding_or_not_found(path)?;
                Ok(ACCOUNT_FILES.iter().map(|f| Entry::file(f)).collect())
            }
            (Some("builder-keys"), 1) => {
                self.builder_keys_or_not_found(path)?;
                self.list_keystore_wallets()
            }
            (Some("builder-keys"), 2) => Ok(vec![
                Entry::file("keys.json"),
                Entry::writable_file("revoke"),
            ]),
            (Some("fund"), 1) => {
                self.fund_root_or_not_found(path)?;
                self.list_keystore_wallets()
            }
            (Some("fund"), 2) => {
                self.fund_root_or_not_found(path)?;
                let mut entries = vec![Entry::writable_file("new")];
                entries.extend(
                    self.list_fund_sessions(path, &segs[1])?
                        .iter()
                        .map(|id| {
                            self.fund_session_dir_entry(path, &segs[1], id)
                                .unwrap_or_else(|e| {
                                    tracing::warn!(id = %id, error = %e, "polymarket.fund_session.metadata_fallback");
                                    Entry::dir(id)
                                })
                        }),
                );
                Ok(entries)
            }
            (Some("fund"), 3) if segs[2] != "new" => {
                self.fund_root_or_not_found(path)?;
                let mut entries: Vec<Entry> = FUND_FILES
                    .iter()
                    .map(|f| {
                        self.fund_session_file_entry(path, &segs[1], &segs[2], f)
                            .unwrap_or_else(|e| {
                                tracing::warn!(file = *f, error = %e, "polymarket.fund_file.metadata_fallback");
                                if *f == "confirm" { Entry::writable_file(f) } else { Entry::file(f) }
                            })
                    })
                    .collect();
                entries.push(
                    self.fund_session_file_entry(path, &segs[1], &segs[2], "confirm")
                        .unwrap_or_else(|e| {
                            tracing::warn!(error = %e, "polymarket.fund_confirm.metadata_fallback");
                            Entry::writable_file("confirm")
                        }),
                );
                Ok(entries)
            }
            (Some("trade"), 1) => {
                self.orders_or_not_found(path)?;
                self.list_keystore_wallets()
            }
            (Some("trade"), 2) => {
                self.orders_or_not_found(path)?;
                Ok(vec![
                    Entry::writable_file("new"),
                    Entry::dir("drafts"),
                    Entry::dir("orders"),
                    Entry::dir("receipts"),
                ])
            }
            (Some("trade"), 3) if segs[2] == "drafts" => {
                let store = self.orders_or_not_found(path)?;
                let ids = store.list_drafts(&segs[1]).map_err(err_be)?;
                Ok(ids
                    .iter()
                    .map(|id| {
                        self.draft_dir_entry(store, &segs[1], id)
                            .unwrap_or_else(|e| {
                                tracing::warn!(id = %id, error = %e, "polymarket.draft.metadata_fallback");
                                Entry::dir(id)
                            })
                    })
                    .collect())
            }
            (Some("trade"), 3) if segs[2] == "receipts" => {
                let store = self.orders_or_not_found(path)?;
                let ids = store.list_receipts(&segs[1]).map_err(err_be)?;
                Ok(ids
                    .iter()
                    .map(|id| {
                        self.receipt_dir_entry(store, &segs[1], id)
                            .unwrap_or_else(|e| {
                                tracing::warn!(id = %id, error = %e, "polymarket.receipt.metadata_fallback");
                                Entry::dir(id)
                            })
                    })
                    .collect())
            }
            // Resting CLOB order-ids come from the live book/account views, not
            // the local store, so the orders dir is not enumerable by id here.
            (Some("trade"), 3) if segs[2] == "orders" => Ok(Vec::new()),
            (Some("trade"), 4) if segs[2] == "drafts" => {
                let store = self.orders_or_not_found(path)?;
                let mut entries: Vec<Entry> = DRAFT_FILES
                    .iter()
                    .map(|f| {
                        self.draft_file_entry(store, &segs[1], &segs[3], f)
                            .unwrap_or_else(|e| {
                                tracing::warn!(file = *f, error = %e, "polymarket.draft_file.metadata_fallback");
                                Entry::file(f)
                            })
                    })
                    .collect();
                entries.push(
                    self.draft_file_entry(store, &segs[1], &segs[3], "confirm")
                        .unwrap_or_else(|e| {
                            tracing::warn!(error = %e, "polymarket.draft_confirm.metadata_fallback");
                            Entry::writable_file("confirm")
                        }),
                );
                Ok(entries)
            }
            (Some("trade"), 4) if segs[2] == "receipts" => {
                let store = self.orders_or_not_found(path)?;
                Ok(vec![
                    self.receipt_file_entry(store, &segs[1], &segs[3], "receipt.json")
                        .unwrap_or_else(|e| {
                            tracing::warn!(error = %e, "polymarket.receipt_file.metadata_fallback");
                            Entry::file("receipt.json")
                        }),
                ])
            }
            (Some("trade"), 4) if segs[2] == "orders" => Ok(vec![Entry::writable_file("cancel")]),
            // redeem/<wallet>/ — slugs are arbitrary (discovered via markets/),
            // so the wallet dir is not enumerable; the confirm leaf is reachable
            // by lookup once the slug is known.
            (Some("redeem"), 1) => {
                self.orders_or_not_found(path)?;
                self.list_keystore_wallets()
            }
            (Some("redeem"), 2) => Ok(Vec::new()),
            (Some("redeem"), 3) => Ok(vec![Entry::writable_file("confirm")]),
            (Some("revoke-approvals"), 1) => {
                self.orders_or_not_found(path)?;
                self.list_keystore_wallets()
            }
            (Some("revoke-approvals"), 2) => Ok(vec![Entry::dir("request")]),
            (Some("revoke-approvals"), 3) if segs[2] == "request" => {
                Ok(vec![Entry::writable_file("confirm")])
            }
            (Some("withdraw"), 1) => {
                self.orders_or_not_found(path)?;
                self.list_keystore_wallets()
            }
            (Some("withdraw"), 2) => Ok(vec![Entry::dir("pusd")]),
            (Some("withdraw"), 3) if segs[2] == "pusd" => Ok(vec![Entry::writable_file("confirm")]),
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }

    fn list_keystore_wallets(&self) -> Result<Vec<Entry>, HandlerError> {
        let wallets = self
            .keystore
            .list()
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        Ok(wallets.into_iter().map(|w| Entry::dir(&w.name)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::SignerSync;
    use bloom_auth_api::{GrantStore, SigningAttestationSchemaRegistry};
    use bloom_polymarket::{OnboardSigner, OnboardStore, RelayerClient};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use url::Url;

    /// Canned single-request HTTP server (one connection, fixed JSON body) —
    /// the `prices.rs` test pattern. Each test that hits the network drives a
    /// single client call.
    async fn spawn_canned(body: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        (addr, h)
    }

    /// Multi-request variant: serves until dropped, routing by path substring
    /// (first match wins); unmatched paths get a 404.
    async fn spawn_scripted(
        rules: Vec<(&'static str, String)>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let path = loop {
                    let Ok(n) = s.read(&mut tmp).await else {
                        break None;
                    };
                    if n == 0 {
                        break None;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf);
                        break head
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .map(str::to_string);
                    }
                };
                let Some(path) = path else { continue };
                let (status, body) = rules
                    .iter()
                    .find(|(frag, _)| path.contains(frag))
                    .map(|(_, b)| (200, b.clone()))
                    .unwrap_or((404, format!("no rule for {path}")));
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        (addr, h)
    }

    fn handler_with(gamma_url: Option<&str>, data_url: Option<&str>) -> PolymarketHandler {
        let mut gamma = GammaClient::new();
        if let Some(u) = gamma_url {
            gamma = gamma.with_base_url(Url::parse(u).unwrap());
        }
        let mut data = DataClient::new();
        if let Some(u) = data_url {
            data = data.with_base_url(Url::parse(u).unwrap());
        }
        let ks_dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(ks_dir.path()).unwrap();
        // Leak the tempdir guard for the test's lifetime (keystore root must
        // outlive the handler); fine in a unit test.
        std::mem::forget(ks_dir);
        PolymarketHandler::new(gamma, data, clob_unreachable(), keystore)
    }

    fn clob_unreachable() -> ClobClient {
        ClobClient::default().with_base_url(Url::parse("http://127.0.0.1:1").unwrap())
    }

    fn p(s: &str) -> VfsPath {
        VfsPath::parse(s).unwrap()
    }

    #[tokio::test]
    async fn trade_surface_exposes_new_and_renders_drafts() {
        use bloom_polymarket::order::{LimitQuote, OrderType};

        let store_dir = tempfile::tempdir().unwrap();
        let store = OrderStore::new(store_dir.path());
        let snap = trade::Snapshot {
            market: serde_json::from_value(serde_json::json!({
                "id":"1","slug":"test-market","question":"Will it?","conditionId":"0xcond",
                "clobTokenIds":"[\"123\",\"456\"]","outcomes":"[\"Yes\",\"No\"]",
                "enableOrderBook":true,"active":true,"closed":false,"negRisk":true
            }))
            .unwrap(),
            token_id: "123".into(),
            neg_risk: true,
            tick_micro: 1_000,
            min_size_micro: 5_000_000,
            best_ask_micro: Some(695_000),
            best_bid_micro: Some(690_000),
        };
        let quote = LimitQuote {
            side: Side::Buy,
            price_micro: 695_000,
            size_micro: 14_380_000,
            maker_micro: 10_000_000,
            taker_micro: 14_380_000,
        };
        let mut draft = trade::draft_from_quote(
            "w",
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            None,
            0,
            "test-market",
            "YES",
            Side::Buy,
            OrderType::FAK,
            700_000,
            true,
            1,
            &snap,
            &quote,
        );
        draft.policy_checks = serde_json::json!([
            {"rule": "polymarket.enabled", "outcome": "pass", "message": "ok"}
        ]);
        let draft = store.create_draft(draft).unwrap();

        let h = handler_with(None, None).with_order_store(OrderStore::new(store_dir.path()));

        let root = h.list(&p("/trade/w")).await.unwrap();
        let root_names: Vec<_> = root.iter().map(|e| e.name.as_str()).collect();
        assert!(root_names.contains(&"new"));
        assert_eq!(h.lookup(&p("/trade/w/new")).await.unwrap().mode, 0o644);
        let hint = String::from_utf8(h.read(&p("/trade/w/new")).await.unwrap()).unwrap();
        assert!(hint.contains("\"slug\""));

        let entries = h.list(&p("/trade/w/drafts")).await.unwrap();
        assert_eq!(entries.len(), 1);
        let files = h
            .list(&p(&format!("/trade/w/drafts/{}", draft.id)))
            .await
            .unwrap();
        let names: Vec<_> = files.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"plan.md") && names.contains(&"policy_check.json"));
        assert!(names.contains(&"confirm"));

        let plan = h
            .read(&p(&format!("/trade/w/drafts/{}/plan.md", draft.id)))
            .await
            .unwrap();
        let plan = String::from_utf8(plan).unwrap();
        assert!(plan.contains("Polymarket order draft"));
        assert!(plan.contains("polymarket.enabled"));
        let checks = h
            .read(&p(&format!(
                "/trade/w/drafts/{}/policy_check.json",
                draft.id
            )))
            .await
            .unwrap();
        let checks: serde_json::Value = serde_json::from_slice(&checks).unwrap();
        assert_eq!(checks[0]["rule"], "polymarket.enabled");

        assert!(
            h.read(&p(&format!(
                "/trade/w/drafts/{}/review_intent.json",
                draft.id
            )))
            .await
            .is_err()
        );
        OrderStore::new(store_dir.path())
            .save_review_intent(
                "w",
                &draft.id,
                &serde_json::json!({"schema": "ceremony.v1", "title": "Polymarket order"}),
            )
            .unwrap();
        let intent = h
            .read(&p(&format!(
                "/trade/w/drafts/{}/review_intent.json",
                draft.id
            )))
            .await
            .unwrap();
        let intent: serde_json::Value = serde_json::from_slice(&intent).unwrap();
        assert_eq!(intent["title"], "Polymarket order");

        let confirm_path = p(&format!("/trade/w/drafts/{}/confirm", draft.id));
        assert_eq!(h.lookup(&confirm_path).await.unwrap().mode, 0o644);
        let hint = String::from_utf8(h.read(&confirm_path).await.unwrap()).unwrap();
        assert!(hint.contains("bloom vfs write"));
        assert!(hint.contains("bloom polymarket confirm"));
        let err = h.write(&confirm_path, b"confirm").await.unwrap_err();
        assert!(err.to_string().contains("foreground CLI VFS path"));
        assert!(handler_with(None, None).lookup(&p("/trade")).await.is_err());
    }

    #[tokio::test]
    async fn action_surfaces_advertise_and_refuse_direct_execution() {
        // These action paths are foreground-confirm only: the mounted handler
        // must advertise the confirm leaf, render guidance on read, and refuse
        // direct writes so the signer ceremony stays in the foreground process.
        let store_dir = tempfile::tempdir().unwrap();
        let h = handler_with(None, None).with_order_store(OrderStore::new(store_dir.path()));

        // Root discovery: all three action namespaces appear alongside trade.
        let root = h.list(&p("/")).await.unwrap();
        let root_names: Vec<_> = root.iter().map(|e| e.name.as_str()).collect();
        assert!(root_names.contains(&"redeem"));
        assert!(root_names.contains(&"revoke-approvals"));
        assert!(root_names.contains(&"withdraw"));

        // redeem/<wallet>/<slug>/confirm
        let redeem = p("/redeem/my-wallet/some-slug/confirm");
        assert_eq!(h.lookup(&redeem).await.unwrap().mode, 0o644);
        let hint = String::from_utf8(h.read(&redeem).await.unwrap()).unwrap();
        assert!(hint.contains("bloom vfs write"));
        assert!(hint.contains("bloom polymarket redeem"));
        let wallets = h.list(&p("/redeem")).await.unwrap();
        assert!(wallets.is_empty()); // no keystore wallets in the test root
        let err = h.write(&redeem, b"confirm").await.unwrap_err();
        assert!(err.to_string().contains("foreground CLI VFS path"));

        // revoke-approvals/<wallet>/request/confirm
        let revoke = p("/revoke-approvals/my-wallet/request/confirm");
        assert_eq!(h.lookup(&revoke).await.unwrap().mode, 0o644);
        let hint = String::from_utf8(h.read(&revoke).await.unwrap()).unwrap();
        assert!(hint.contains("bloom vfs write"));
        assert!(hint.contains("bloom polymarket revoke-approvals"));
        let req_listing = h.list(&p("/revoke-approvals/my-wallet")).await.unwrap();
        let req_names: Vec<_> = req_listing.iter().map(|e| e.name.as_str()).collect();
        assert!(req_names.contains(&"request"));
        let confirm_listing = h
            .list(&p("/revoke-approvals/my-wallet/request"))
            .await
            .unwrap();
        let confirm_names: Vec<_> = confirm_listing.iter().map(|e| e.name.as_str()).collect();
        assert!(confirm_names.contains(&"confirm"));
        let err = h.write(&revoke, b"confirm").await.unwrap_err();
        assert!(err.to_string().contains("foreground CLI VFS path"));

        // withdraw/<wallet>/pusd/confirm
        let withdraw = p("/withdraw/my-wallet/pusd/confirm");
        assert_eq!(h.lookup(&withdraw).await.unwrap().mode, 0o644);
        let hint = String::from_utf8(h.read(&withdraw).await.unwrap()).unwrap();
        assert!(hint.contains("bloom vfs write"));
        assert!(hint.contains("bloom polymarket withdraw-pusd"));
        assert!(hint.contains("amount")); // guidance must mention the amount requirement
        let pusd_listing = h.list(&p("/withdraw/my-wallet")).await.unwrap();
        let pusd_names: Vec<_> = pusd_listing.iter().map(|e| e.name.as_str()).collect();
        assert!(pusd_names.contains(&"pusd"));
        let err = h.write(&withdraw, b"confirm").await.unwrap_err();
        assert!(err.to_string().contains("foreground CLI VFS path"));

        // Without order_store wired, the action namespaces are not discoverable
        // (consistent with trade).
        let bare = handler_with(None, None);
        assert!(bare.lookup(&p("/redeem")).await.is_err());
        assert!(bare.lookup(&p("/revoke-approvals")).await.is_err());
        assert!(bare.lookup(&p("/withdraw")).await.is_err());
    }

    #[tokio::test]
    async fn cancel_surface_advertises_and_executes_in_handler() {
        // Cancel uses stored CLOB creds (no owner signing), so it executes
        // directly in the handler after compliance checks. It must NOT refuse
        // with foreground guidance like the value-moving confirm paths.
        let store_dir = tempfile::tempdir().unwrap();
        let h = handler_with(None, None).with_order_store(OrderStore::new(store_dir.path()));

        // Discovery: the orders dir is listed under trade/<wallet>/ and the
        // cancel leaf is writable with a guidance hint.
        let trade_w = h.list(&p("/trade/my-wallet")).await.unwrap();
        let names: Vec<_> = trade_w.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"orders"));

        let cancel_path = p("/trade/my-wallet/orders/0xSOMEORDER/cancel");
        assert_eq!(h.lookup(&cancel_path).await.unwrap().mode, 0o644);
        let hint = String::from_utf8(h.read(&cancel_path).await.unwrap()).unwrap();
        assert!(hint.contains("bloom polymarket cancel"));
        let order_listing = h
            .list(&p("/trade/my-wallet/orders/0xSOMEORDER"))
            .await
            .unwrap();
        let order_names: Vec<_> = order_listing.iter().map(|e| e.name.as_str()).collect();
        assert!(order_names.contains(&"cancel"));

        // An empty body is rejected.
        let err = h.write(&cancel_path, b"").await.unwrap_err();
        assert!(err.to_string().contains("'confirm', 'y', or 'yes'"));

        // A non-confirm body is rejected.
        let err = h.write(&cancel_path, b"garbage").await.unwrap_err();
        assert!(err.to_string().contains("'confirm', 'y', or 'yes'"));

        // The execution path runs in-handler and fails at a durable pre-network
        // gate (unknown wallet / onboarding not wired / no creds) — proving cancel
        // executes here rather than refusing like the foreground-confirm paths.
        let err = h.write(&cancel_path, b"confirm").await.unwrap_err();
        let msg = err.to_string();
        // Crucially, cancel is NOT a foreground-refusal path.
        assert!(
            !msg.contains("foreground CLI VFS path"),
            "cancel must not refuse: {msg}"
        );
        assert!(
            msg.contains("not found")
                || msg.contains("onboarding is not wired")
                || msg.contains("not onboarded"),
            "expected a durable pre-network refusal, got: {msg}"
        );
    }

    #[tokio::test]
    async fn clob_auth_actions_execute_but_owner_signed_writes_refuse() {
        // Regression guard: direct handler execution is limited to operations
        // that use stored CLOB/L2 auth and do not require owner signing. Owner-
        // signed value-moving paths must still refuse with foreground guidance.
        let store_dir = tempfile::tempdir().unwrap();
        let h = handler_with(None, None).with_order_store(OrderStore::new(store_dir.path()));

        // Cancel: executes (fails at durable pre-network gate, NOT a refusal).
        let err = h
            .write(&p("/trade/my-wallet/orders/0xORDER/cancel"), b"confirm")
            .await
            .unwrap_err();
        assert!(
            !err.to_string().contains("foreground CLI VFS path"),
            "cancel must not refuse: {err}"
        );

        // Redeem: refuses (foreground).
        let err = h
            .write(&p("/redeem/my-wallet/some-slug/confirm"), b"confirm")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("foreground CLI VFS path"));

        // Revoke-approvals: refuses (foreground).
        let err = h
            .write(
                &p("/revoke-approvals/my-wallet/request/confirm"),
                b"confirm",
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("foreground CLI VFS path"));

        // Withdraw: refuses (foreground).
        let err = h
            .write(
                &p("/withdraw/my-wallet/pusd/confirm"),
                br#"{"confirm":true,"amount":"all"}"#,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("foreground CLI VFS path"));
    }

    #[test]
    fn builder_key_revoke_body_accepts_ack_or_explicit_key() {
        assert_eq!(parse_builder_key_revoke_body(b"confirm").unwrap(), None);
        assert_eq!(
            parse_builder_key_revoke_body(br#"{"confirm":true,"key":"builder-key-1"}"#).unwrap(),
            Some("builder-key-1".to_string())
        );
        assert_eq!(
            parse_builder_key_revoke_body(
                br#"
confirm = true
key = "builder-key-2"
"#
            )
            .unwrap(),
            Some("builder-key-2".to_string())
        );
    }

    #[test]
    fn builder_key_revoke_body_rejects_unconfirmed_or_unsafe_key() {
        let err = parse_builder_key_revoke_body(br#"{"confirm":false}"#).unwrap_err();
        assert!(err.to_string().contains("confirm=true"));

        let err = parse_builder_key_revoke_body(br#"{"confirm":true,"key":"../x"}"#).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid Polymarket builder key id")
        );
    }

    struct ArmedChain;

    #[async_trait]
    impl ChainReader for ArmedChain {
        async fn code_len(&self, _: Address) -> bloom_polymarket::Result<usize> {
            Ok(1)
        }
        async fn predict_deposit_wallet(
            &self,
            owner: Address,
        ) -> bloom_polymarket::Result<Address> {
            Ok(bloom_polymarket::derive_deposit_wallet_address(&owner, 137))
        }
        async fn erc20_balance(&self, _: Address, _: Address) -> bloom_polymarket::Result<U256> {
            Ok(U256::from(25_000_000u64))
        }
        async fn erc20_allowance(
            &self,
            _: Address,
            _: Address,
            _: Address,
        ) -> bloom_polymarket::Result<U256> {
            Ok(U256::MAX)
        }
        async fn is_approved_for_all(
            &self,
            _: Address,
            _: Address,
            _: Address,
        ) -> bloom_polymarket::Result<bool> {
            Ok(true)
        }
    }

    struct OnboardFixture {
        handler: PolymarketHandler,
        keystore: Keystore,
        audit_path: std::path::PathBuf,
        /// Shared polymarket state root (OnboardStore + fund store live here),
        /// exposed so fund-surface tests can pre-persist onboarding state.
        state_dir: std::path::PathBuf,
        _dirs: Vec<tempfile::TempDir>,
    }

    async fn onboard_fixture(server: SocketAddr, unlocked: bool) -> OnboardFixture {
        let ks_dir = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(ks_dir.path()).unwrap();
        keystore.create_local("alice", "pw").unwrap();
        if unlocked {
            keystore.unlock("alice", "pw").unwrap();
        }
        let base = format!("http://{server}");
        let chain: Arc<dyn ChainReader> = Arc::new(ArmedChain);
        let onboarder = Onboarder::new(
            chain.clone(),
            RelayerClient::new(137).with_base_url("http://127.0.0.1:1"), // chain is armed → never hit
            ClobClient::new(137).with_base_url(Url::parse(&base).unwrap()),
            CredentialStore::new(state_dir.path()),
            OnboardStore::new(state_dir.path()),
            137,
        )
        .with_poll_timeout(Duration::from_secs(2));
        let audit_path = audit_dir.path().join("audit.jsonl");
        let handler = PolymarketHandler::new(
            GammaClient::new(),
            DataClient::new(),
            ClobClient::new(137).with_base_url(Url::parse(&base).unwrap()),
            keystore.clone(),
        )
        .with_onboarding(PolymarketOnboarding {
            onboarder: Arc::new(onboarder),
            auth_dir: state_dir.path().to_path_buf(),
            creds: CredentialStore::new(state_dir.path()),
            chain,
        })
        .with_fund_store(state_dir.path())
        .with_audit(Arc::new(AuditLog::open(&audit_path).unwrap()));
        let state_path = state_dir.path().to_path_buf();
        OnboardFixture {
            handler,
            keystore,
            audit_path,
            state_dir: state_path,
            _dirs: vec![ks_dir, state_dir, audit_dir],
        }
    }

    fn creds_rule() -> (&'static str, String) {
        (
            "/auth/",
            r#"{"apiKey":"11111111-2222-3333-4444-555555555555","secret":"c2VjcmV0LXZhbHVl","passphrase":"pp-hidden"}"#
                .to_string(),
        )
    }

    #[tokio::test]
    async fn root_lists_three_dirs() {
        let h = handler_with(None, None);
        let names: Vec<String> = h
            .list(&VfsPath::root())
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["README.md", "markets", "positions", "search"]);
    }

    #[tokio::test]
    async fn readme_documents_the_live_vfs_without_cli_commands() {
        let h = handler_with(None, None);
        let text = String::from_utf8(h.read(&p("/README.md")).await.unwrap()).unwrap();
        let lower = text.to_ascii_lowercase();
        for forbidden in ["bloom polymarket", "bloom vfs", "--unlock-wallet", "cli"] {
            assert!(!lower.contains(forbidden), "README contains {forbidden:?}");
        }
        for required in [
            "markets/<slug>/market.json",
            "positions/<wallet>/positions.json",
            "onboard/<wallet>/",
            "account/<wallet>/status.json",
            "fund/<wallet>/new",
            "trade/<wallet>/new",
            "trade/<wallet>/drafts/<id>/",
            "trade/<wallet>/receipts/<id>/receipt.json",
            "trade/<wallet>/orders/<order-id>/cancel",
            "redeem/<wallet>/<slug>/confirm",
            "revoke-approvals/<wallet>/request/confirm",
            "withdraw/<wallet>/pusd/confirm",
            "builder-keys/<wallet>/keys.json",
            "fund/<wallet>/<id>/status.json",
        ] {
            assert!(text.contains(required), "README missing {required:?}");
        }
    }

    #[tokio::test]
    async fn lookup_market_file_and_unknown() {
        let h = handler_with(None, None);
        let e = h.lookup(&p("/markets/some-slug/book.json")).await.unwrap();
        assert_eq!(e.kind, crate::handler::EntryKind::File);
        assert!(h.lookup(&p("/markets/some-slug/nope.json")).await.is_err());
        assert!(h.lookup(&p("/unknown")).await.is_err());
    }

    #[tokio::test]
    async fn onboard_hidden_when_not_wired() {
        let h = handler_with(None, None);
        assert!(h.lookup(&p("/onboard")).await.is_err());
        assert!(h.lookup(&p("/account")).await.is_err());
        let err = h
            .write(&p("/onboard/alice/begin"), b"go")
            .await
            .unwrap_err();
        assert!(
            matches!(err, HandlerError::Unsupported(_)),
            "begin without wiring must say why: {err}"
        );
    }

    #[tokio::test]
    async fn cache_ttls_match_design() {
        let h = handler_with(None, None);
        assert_eq!(
            h.cache_ttl(&p("/markets/x/book.json")),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            h.cache_ttl(&p("/markets/x/prices.json")),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            h.cache_ttl(&p("/markets/x/market.json")),
            Some(Duration::from_secs(30))
        );
        assert_eq!(h.cache_ttl(&p("/markets")), Some(Duration::from_secs(30)));
        assert_eq!(
            h.cache_ttl(&p("/positions/alice/positions.json")),
            Some(Duration::from_secs(10))
        );
        assert_eq!(h.cache_ttl(&p("/onboard/alice/status.json")), None);
        assert_eq!(
            h.cache_ttl(&p("/account/alice/portfolio.json")),
            Some(Duration::from_secs(5))
        );
    }

    #[tokio::test]
    async fn market_json_parses_from_canned_gamma() {
        let body = r#"{"id":"1","slug":"will-x","question":"Will X?","conditionId":"0xabc",
            "clobTokenIds":"[\"69\",\"51\"]","outcomes":"[\"Yes\",\"No\"]","enableOrderBook":true}"#;
        let (addr, _h) = spawn_canned(body).await;
        let handler = handler_with(Some(&format!("http://{addr}")), None);
        let bytes = handler
            .read(&p("/markets/will-x/market.json"))
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["conditionId"], "0xabc");
        assert_eq!(v["clobTokenIds"][0], "69");
    }

    #[tokio::test]
    async fn markets_dir_lists_slugs_from_canned_gamma() {
        let body = r#"[{"slug":"market-a"},{"slug":"market-b"}]"#;
        let (addr, _h) = spawn_canned(body).await;
        let handler = handler_with(Some(&format!("http://{addr}")), None);
        let names: Vec<String> = handler
            .list(&p("/markets"))
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["market-a", "market-b"]);
    }

    #[tokio::test]
    async fn search_treats_plus_as_space() {
        let (addr, _h) = spawn_scripted(vec![
            (
                "q=canada+world+cup",
                r#"{"events":[{"slug":"world-cup-winner"}],"pagination":{"totalResults":1}}"#
                    .to_string(),
            ),
            (
                "q=canada%2Bworld%2Bcup",
                r#"{"events":[],"pagination":{"totalResults":0}}"#.to_string(),
            ),
        ])
        .await;
        let handler = handler_with(Some(&format!("http://{addr}")), None);
        let bytes = handler.read(&p("/search/canada+world+cup")).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["events"][0]["slug"], "world-cup-winner");
    }

    #[tokio::test]
    async fn positions_resolves_raw_address_from_canned_data() {
        let body = r#"[{"proxyWallet":"0x1","asset":"69","conditionId":"0xabc","size":10.0}]"#;
        let (addr, _h) = spawn_canned(body).await;
        let handler = handler_with(None, Some(&format!("http://{addr}")));
        let path = "/positions/0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045/positions.json";
        let bytes = handler.read(&p(path)).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v[0]["asset"], "69");
    }

    #[tokio::test]
    async fn onboard_shape_when_wired() {
        let (addr, _s) = spawn_scripted(vec![]).await;
        let f = onboard_fixture(addr, true).await;

        let root: Vec<String> = f
            .handler
            .list(&VfsPath::root())
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(
            root,
            vec![
                "README.md",
                "account",
                "markets",
                "onboard",
                "fund",
                "positions",
                "search"
            ]
        );

        let names: Vec<String> = f
            .handler
            .list(&p("/onboard/alice"))
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(
            names,
            vec!["status.json", "plan.md", "approvals.json", "begin"]
        );
        let begin = f.handler.lookup(&p("/onboard/alice/begin")).await.unwrap();
        assert_eq!(begin.mode, 0o644, "begin must be writable");
        let status = f
            .handler
            .lookup(&p("/onboard/alice/status.json"))
            .await
            .unwrap();
        assert_eq!(status.mode, 0o444);
    }

    #[tokio::test]
    async fn begin_preconditions_each_refuse_clearly() {
        let (addr, _s) = spawn_scripted(vec![]).await;
        let f = onboard_fixture(addr, true).await;
        let err = f
            .handler
            .write(&p("/onboard/nobody/begin"), b"x")
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)), "{err}");

        let (addr, _s) = spawn_scripted(vec![]).await;
        let f = onboard_fixture(addr, false).await;
        let err = f
            .handler
            .write(&p("/onboard/alice/begin"), b"x")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("locked"), "{err}");
    }

    #[tokio::test]
    async fn wired_onboard_denies_and_writes_challenge_without_grant() {
        let (addr, _s) = spawn_scripted(vec![]).await;
        let f = onboard_fixture(addr, true).await;
        let handler = f.handler.clone().with_auth_services(pm_wired_auth());

        let err = handler
            .write(&p("/onboard/alice/begin"), b"x")
            .await
            .unwrap_err();
        assert!(
            matches!(err, HandlerError::PermissionDenied),
            "expected PermissionDenied, got: {err}"
        );

        // The challenge file should be under <auth_dir>/<wallet>/.
        let challenge_path = f.state_dir.join("alice").join(APPROVAL_CHALLENGE_FILE);
        assert!(
            challenge_path.exists(),
            "approval_challenge.json not written"
        );
        let challenge: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&challenge_path).unwrap()).unwrap();
        assert_eq!(challenge["surface"], "polymarket");
        assert_eq!(challenge["petal_id"], petal_identity::PETAL_ID_POLYMARKET);

        let entries = handler.list(&p("/onboard/alice")).await.unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.name == APPROVAL_CHALLENGE_FILE),
            "approval_challenge.json must be listed after staging"
        );
        let projected: serde_json::Value = serde_json::from_slice(
            &handler
                .read(&p("/onboard/alice/approval_challenge.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(projected, challenge);
    }

    #[tokio::test]
    async fn begin_runs_to_complete_with_audit_and_no_secret_leak() {
        let (addr, _s) = spawn_scripted(vec![
            creds_rule(),
            ("/balance-allowance/update", r#"{"ok":true}"#.to_string()),
        ])
        .await;
        let f = onboard_fixture(addr, true).await;

        let st0 = f
            .handler
            .read(&p("/onboard/alice/status.json"))
            .await
            .unwrap();
        let v0: serde_json::Value = serde_json::from_slice(&st0).unwrap();
        assert_eq!(v0["stage"], "derive");
        assert_eq!(v0["running"], false);
        assert_eq!(
            v0["poll_timeout_secs"], 2,
            "the poll budget must be surfaced so an agent can compute a stall deadline"
        );
        assert!(
            v0["in_flight_deadline_ms"].is_null(),
            "no network op in flight on fresh state"
        );
        let plan =
            String::from_utf8(f.handler.read(&p("/onboard/alice/plan.md")).await.unwrap()).unwrap();
        assert!(plan.contains(&v0["deposit_wallet"].as_str().unwrap().to_string()));
        let approvals = f
            .handler
            .read(&p("/onboard/alice/approvals.json"))
            .await
            .unwrap();
        let av: serde_json::Value = serde_json::from_slice(&approvals).unwrap();
        assert_eq!(av["calls"].as_array().unwrap().len(), 8);

        f.handler
            .write(&p("/onboard/alice/begin"), b"go")
            .await
            .unwrap();
        let mut last = serde_json::Value::Null;
        for _ in 0..100 {
            let bytes = f
                .handler
                .read(&p("/onboard/alice/status.json"))
                .await
                .unwrap();
            last = serde_json::from_slice(&bytes).unwrap();
            if last["stage"] == "complete" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(last["stage"], "complete", "status: {last}");
        assert_eq!(last["creds_present"], true);
        assert_eq!(last["last_error"], serde_json::Value::Null);

        let status_text = last.to_string();
        assert!(
            !status_text.contains("c2VjcmV0"),
            "secret leaked: {status_text}"
        );
        assert!(!status_text.contains("pp-hidden"));

        let audit = std::fs::read_to_string(&f.audit_path).unwrap();
        assert!(
            audit.contains("polymarket.onboard.creds.minted"),
            "audit: {audit}"
        );
        assert!(audit.contains("11111111-2222-3333-4444-555555555555"));
        assert!(!audit.contains("c2VjcmV0"), "secret in audit log");
        assert!(!audit.contains("pp-hidden"), "passphrase in audit log");
        let _ = f.keystore;
    }

    #[tokio::test]
    async fn account_views_need_creds_then_serve_sectioned_portfolio() {
        let (addr, _s) = spawn_scripted(vec![
            (
                "/balance-allowance",
                r#"{"balance":"25000000","allowance":"max"}"#.to_string(),
            ),
            ("/data/orders", r#"[{"id":"order-1"}]"#.to_string()),
        ])
        .await;
        let f = onboard_fixture(addr, true).await;

        let err = f
            .handler
            .read(&p("/account/alice/portfolio.json"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not onboarded"), "{err}");

        f.handler
            .onboarding
            .as_ref()
            .unwrap()
            .creds
            .save(
                "alice",
                &bloom_polymarket::types::Credentials {
                    key: "k-1".into(),
                    secret: "c2VjcmV0LXZhbHVl".into(),
                    passphrase: "pp-hidden".into(),
                    nonce: 0,
                },
            )
            .unwrap();
        let bytes = f
            .handler
            .read(&p("/account/alice/portfolio.json"))
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["clob_balance_allowance"]["balance"], "25000000");
        assert_eq!(v["deposit_wallet"]["pusd_balance"], "25000000");
        assert_eq!(v["onboarding_state"]["creds_present"], true);
        let text = v.to_string();
        assert!(!text.contains("c2VjcmV0"), "secret leaked: {text}");
        assert!(!text.contains("pp-hidden"));

        let orders = f
            .handler
            .read(&p("/account/alice/orders.json"))
            .await
            .unwrap();
        let ov: serde_json::Value = serde_json::from_slice(&orders).unwrap();
        assert_eq!(ov[0]["id"], "order-1");
    }

    #[tokio::test]
    async fn account_status_and_funding_options_do_not_need_creds() {
        let (addr, _s) = spawn_scripted(vec![]).await;
        let f = onboard_fixture(addr, true).await;

        let status = f
            .handler
            .read(&p("/account/alice/status.json"))
            .await
            .unwrap();
        let status: serde_json::Value = serde_json::from_slice(&status).unwrap();
        assert_eq!(status["wallet"], "alice");
        assert_eq!(status["tradeable"], false);
        assert_eq!(status["onboarding_stage"], "derive");
        assert_eq!(status["balances"]["deposit_pusd"]["display"], "25 pUSD");

        let funding = f
            .handler
            .read(&p("/account/alice/funding_options.json"))
            .await
            .unwrap();
        let funding: serde_json::Value = serde_json::from_slice(&funding).unwrap();
        assert_eq!(funding["target_asset"], "pUSD");

        let err = f
            .handler
            .read(&p("/account/alice/buying_power.json"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not onboarded"), "{err}");
    }

    #[tokio::test]
    #[ignore = "hits live polymarket APIs"]
    async fn live_markets_and_book() {
        let ks_dir = tempfile::tempdir().unwrap();
        let h = PolymarketHandler::new(
            GammaClient::new(),
            DataClient::new(),
            ClobClient::default(),
            Keystore::new(ks_dir.path()).unwrap(),
        );
        let markets = h.list(&p("/markets")).await.unwrap();
        assert!(!markets.is_empty());
        let slug = &markets[0].name;
        let bytes = h
            .read(&p(&format!("/markets/{slug}/book.json")))
            .await
            .unwrap();
        let book: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(book.get("asset_id").is_some());
    }

    fn fund_req(
        target: &str,
        max_spend: &str,
        from: Option<&str>,
        slippage: u16,
    ) -> FundNewRequest {
        FundNewRequest {
            target_pusd: target.into(),
            max_spend: max_spend.into(),
            from_token: from.map(str::to_string),
            slippage_bps: slippage,
        }
    }

    #[test]
    fn validate_fund_request_enforces_precise_rules() {
        assert!(validate_fund_request(&fund_req("10", "100", Some("native"), 50)).is_ok());
        assert!(validate_fund_request(&fund_req("0.5", "1.25", Some("pol"), 0)).is_ok());
        let usdc = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174";
        assert!(validate_fund_request(&fund_req("3", "5", Some(usdc), 1000)).is_ok());

        assert!(validate_fund_request(&fund_req("0", "100", None, 50)).is_err());
        assert!(validate_fund_request(&fund_req("abc", "100", None, 50)).is_err());
        assert!(validate_fund_request(&fund_req("1.0000001", "100", None, 50)).is_err());
        assert!(validate_fund_request(&fund_req("", "100", None, 50)).is_err());

        assert!(validate_fund_request(&fund_req("10", "0", None, 50)).is_err());
        assert!(validate_fund_request(&fund_req("10", "nope", None, 50)).is_err());
        assert!(validate_fund_request(&fund_req("10", &"9".repeat(33), None, 50)).is_err());
        assert!(validate_fund_request(&fund_req("10", "", None, 50)).is_err());

        assert!(validate_fund_request(&fund_req("10", "100", Some("ether"), 50)).is_err());
        assert!(validate_fund_request(&fund_req("10", "100", Some("0xnothex"), 50)).is_err());

        assert!(validate_fund_request(&fund_req("10", "100", None, 1001)).is_err());
        assert!(validate_fund_request(&fund_req("10", "100", None, 65535)).is_err());
    }

    #[test]
    fn validate_fund_id_rejects_traversal() {
        for bad in ["", "..", ".", "a/b", "a\\b", "../x"] {
            assert!(
                PolymarketHandler::validate_fund_id(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert!(PolymarketHandler::validate_fund_id("fund-000000001").is_ok());
    }

    #[tokio::test]
    async fn fund_new_refuses_before_deposit_wallet_is_fundable() {
        let (addr, _s) = spawn_scripted(vec![]).await;
        let f = onboard_fixture(addr, false).await;
        let err = f
            .handler
            .write(
                &p("/fund/alice/new"),
                br#"{"target_pusd":"10","max_spend":"100"}"#,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not fundable"),
            "expected a not-fundable refusal, got: {err}"
        );
    }

    #[tokio::test]
    async fn fund_new_stages_a_request_and_reads_it_back() {
        let (addr, _s) = spawn_scripted(vec![]).await;
        let f = onboard_fixture(addr, false).await;
        let owner = f.keystore.info("alice").unwrap().address;
        let st: OnboardState = serde_json::from_value(serde_json::json!({
            "wallet": "alice",
            "owner": bloom_proto::checksum_address(&owner),
            "deposit_wallet": bloom_proto::checksum_address(&owner),
            "chain_id": 137,
            "stage": "complete",
            "deploy_tx_id": null,
            "approve_tx_id": null,
            "pusd_balance": null,
            "creds_present": true,
            "last_error": null,
            "updated_ms": 0,
        }))
        .unwrap();
        OnboardStore::new(&f.state_dir).save("alice", &st).unwrap();

        f.handler
            .write(
                &p("/fund/alice/new"),
                br#"{"target_pusd":"15","max_spend":"60","from_token":"native","slippage_bps":50}"#,
            )
            .await
            .unwrap();

        let dir = f.state_dir.join("alice").join("fund").join("requests");
        let id = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .find_map(|e| {
                e.file_name()
                    .to_str()
                    .and_then(|n| n.strip_suffix(".json"))
                    .map(str::to_string)
            })
            .expect("a staged request file");
        let bytes = f
            .handler
            .read(&p(&format!("/fund/alice/{id}/request.json")))
            .await
            .unwrap();
        let req: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(req["target_pusd"], "15");
        assert_eq!(req["max_spend"], "60");
        assert_eq!(req["status"], "draft");
        assert_eq!(req["deposit_wallet_fundable"], true);

        let confirm_path = p(&format!("/fund/alice/{id}/confirm"));
        assert_eq!(f.handler.lookup(&confirm_path).await.unwrap().mode, 0o644);
        let entries = f
            .handler
            .list(&p(&format!("/fund/alice/{id}")))
            .await
            .unwrap();
        assert!(entries.iter().any(|entry| entry.name == "confirm"));
        let hint = f.handler.read(&confirm_path).await.unwrap();
        assert!(String::from_utf8_lossy(&hint).contains("bloom vfs write"));
        let err = f
            .handler
            .write(&confirm_path, b"confirm")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("foreground CLI VFS path"),
            "expected foreground CLI guidance, got: {err}"
        );
    }

    // ── Phase 3b: sealed order confirm integration tests ───────────────

    /// Minimal `AuthStoreWriter` for polymarket sealed-action tests: succeeds
    /// at `stage_action` and `issue_challenge`, does not actually persist.
    struct PmTestWriter;

    #[async_trait]
    impl bloom_auth_api::AuthStoreWriter for PmTestWriter {
        async fn stage_entry(
            &self,
            envelope: CanonicalEnvelope,
            assurance: AssuranceLevel,
            now_ms: u64,
        ) -> Result<bloom_auth_api::AuthEntryRecord, bloom_auth_api::AuthApiError> {
            let intent_hash = envelope.intent_hash()?;
            Ok(bloom_auth_api::AuthEntryRecord {
                surface: envelope.header.surface.clone(),
                action_id: envelope.header.action_id.clone(),
                state: bloom_auth_api::AuthEntryState::Staged,
                intent_hash,
                assurance,
                nonce: None,
                nonce_state: bloom_auth_api::NonceState::Unused,
                reservation_id: None,
                updated_ms: now_ms,
            })
        }

        async fn stage_action(
            &self,
            action: SealedAction,
            now_ms: u64,
        ) -> Result<bloom_auth_api::AuthEntryRecord, bloom_auth_api::AuthApiError> {
            self.stage_entry(action.envelope, action.daemon_terms.assurance, now_ms)
                .await
        }

        async fn issue_challenge(
            &self,
            surface: &str,
            action_id: &str,
            server_nonce: &str,
            expiry_ms: u64,
            _now_ms: u64,
        ) -> Result<bloom_auth_api::ApprovalChallenge, bloom_auth_api::AuthApiError> {
            Ok(bloom_auth_api::ApprovalChallenge {
                schema: bloom_auth_api::APPROVAL_CHALLENGE_SCHEMA_V1.to_string(),
                action_id: action_id.to_string(),
                wallet: "w".to_string(),
                surface: surface.to_string(),
                petal_id: petal_identity::PETAL_ID_POLYMARKET.to_string(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.to_string(),
                intent_hash: "pm-test-intent".to_string(),
                server_nonce: server_nonce.to_string(),
                assurance: AssuranceLevel::Standard,
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms,
                ceremony_url: None,
            })
        }

        async fn issue_review_session(
            &self,
            _id: &str,
            _surface: &str,
            _action_id: &str,
            _expires_ms: u64,
            _now_ms: u64,
        ) -> Result<bloom_auth_api::ReviewSessionRecord, bloom_auth_api::AuthApiError> {
            Err(bloom_auth_api::AuthApiError::Store("unused".into()))
        }
    }

    fn pm_wired_auth() -> crate::AuthServices {
        crate::AuthServices::default()
            .with_grant_store(Arc::new(
                bloom_auth::grant_store::InMemoryGrantStore::default(),
            ))
            .with_writer(Arc::new(PmTestWriter))
    }

    /// Build an order draft + the `OrderAction` (containing `signing_hash`) so
    /// tests can construct a valid `PolymarketOrderSignRequest` sidecar.
    fn pm_order_draft_and_action(
        store: &OrderStore,
    ) -> (
        bloom_polymarket::order_store::OrderDraft,
        bloom_polymarket::signing::OrderAction,
    ) {
        use bloom_polymarket::order::{LimitQuote, OrderType};
        let snap = trade::Snapshot {
            market: serde_json::from_value(serde_json::json!({
                "id":"1","slug":"test-market","question":"Will it?","conditionId":"0xcond",
                "clobTokenIds":"[\"123\",\"456\"]","outcomes":"[\"Yes\",\"No\"]",
                "enableOrderBook":true,"active":true,"closed":false,"negRisk":true
            }))
            .unwrap(),
            token_id: "123".into(),
            neg_risk: true,
            tick_micro: 1_000,
            min_size_micro: 5_000_000,
            best_ask_micro: Some(695_000),
            best_bid_micro: Some(690_000),
        };
        let quote = LimitQuote {
            side: Side::Buy,
            price_micro: 695_000,
            size_micro: 14_380_000,
            maker_micro: 10_000_000,
            taker_micro: 14_380_000,
        };
        let draft = trade::draft_from_quote(
            "w",
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            None,
            0,
            "test-market",
            "YES",
            Side::Buy,
            OrderType::FAK,
            700_000,
            true,
            1,
            &snap,
            &quote,
        );
        let draft = store.create_draft(draft).unwrap();
        // Build a minimal Order directly for order_action_and_hash.
        let maker = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse::<alloy::primitives::Address>()
            .unwrap();
        let order_shell = bloom_polymarket::order::Order {
            salt: alloy::primitives::U256::from(1),
            maker,
            signer: maker,
            tokenId: alloy::primitives::U256::from(123),
            makerAmount: alloy::primitives::U256::from(10_000_000),
            takerAmount: alloy::primitives::U256::from(14_380_000),
            side: 0,
            signatureType: 0,
            timestamp: alloy::primitives::U256::from(1),
            metadata: alloy::primitives::B256::ZERO,
            builder: alloy::primitives::B256::ZERO,
        };
        let action = bloom_polymarket::signing::order_action_and_hash(
            &order_shell,
            137,
            true,
            bloom_polymarket::order::OrderType::GTC,
        );
        (draft, action)
    }

    #[tokio::test]
    async fn sealed_order_confirm_preserves_foreground_when_not_wired() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = OrderStore::new(store_dir.path());
        let (draft, _action) = pm_order_draft_and_action(&store);

        let h = handler_with(None, None).with_order_store(OrderStore::new(store_dir.path()));

        let confirm_path = p(&format!("/trade/w/drafts/{}/confirm", draft.id));
        let err = h.write(&confirm_path, b"confirm").await.unwrap_err();
        assert!(
            err.to_string().contains("foreground CLI VFS path"),
            "expected foreground CLI guidance when not wired, got: {err}"
        );
    }

    #[tokio::test]
    async fn sealed_order_confirm_denies_and_writes_challenge_without_grant() {
        let store_dir = tempfile::tempdir().unwrap();
        let auth_dir = tempfile::tempdir().unwrap();
        let store = OrderStore::new(store_dir.path());
        let (draft, action) = pm_order_draft_and_action(&store);

        // Wire a minimal onboarding config so `auth_dir` is known.
        let ks_dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(ks_dir.path()).unwrap();
        keystore.create_local("w", "pw").unwrap();
        let chain: Arc<dyn ChainReader> = Arc::new(ArmedChain);
        let h = PolymarketHandler::new(
            GammaClient::new(),
            DataClient::new(),
            clob_unreachable(),
            keystore,
        )
        .with_order_store(OrderStore::new(store_dir.path()))
        .with_onboarding(PolymarketOnboarding {
            onboarder: Arc::new(
                Onboarder::new(
                    chain.clone(),
                    RelayerClient::new(137).with_base_url("http://127.0.0.1:1"),
                    clob_unreachable(),
                    CredentialStore::new(auth_dir.path()),
                    OnboardStore::new(auth_dir.path()),
                    137,
                )
                .with_poll_timeout(Duration::from_secs(2)),
            ),
            auth_dir: auth_dir.path().to_path_buf(),
            creds: CredentialStore::new(auth_dir.path()),
            chain,
        })
        .with_auth_services(pm_wired_auth());

        // Drop the sign_request.json sidecar next to the draft.
        let draft_dir = store.draft_path("w", &draft.id);
        let sidecar = draft_dir.parent().unwrap().join(PM_ORDER_SIGN_REQUEST_FILE);
        let maker_hex = action.order_view["maker"].as_str().unwrap().to_string();
        let req = serde_json::json!({
            "schema": "bloom.polymarket.order_sign_request.v1",
            "draft_id": draft.id,
            "salt": "1",
            "order_view": action.order_view,
            "signing_hash": format!("{:#x}", action.signing_hash),
            "neg_risk": action.neg_risk,
            "chain_id": action.chain_id,
            "side": Side::Buy,
            "maker": maker_hex,
            "market_slug": "test-market",
        });
        std::fs::write(&sidecar, serde_json::to_vec(&req).unwrap()).unwrap();

        let confirm_path = p(&format!("/trade/w/drafts/{}/confirm", draft.id));
        let err = h.write(&confirm_path, b"confirm").await.unwrap_err();
        assert!(
            matches!(err, HandlerError::PermissionDenied),
            "expected PermissionDenied, got: {err}"
        );

        // The challenge file is written under <auth_dir>/trade/<wallet>/<action_id>/.
        let action_id =
            bloom_polymarket::action_id_for("polymarket.order.v1", &action.signing_hash);
        let challenge_path = auth_dir
            .path()
            .join("trade")
            .join("w")
            .join(&action_id)
            .join(APPROVAL_CHALLENGE_FILE);
        assert!(
            challenge_path.exists(),
            "approval_challenge.json not written at {}",
            challenge_path.display()
        );
        let challenge: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&challenge_path).unwrap()).unwrap();
        assert_eq!(challenge["surface"], "polymarket");
        assert_eq!(challenge["petal_id"], petal_identity::PETAL_ID_POLYMARKET);
        assert_eq!(challenge["action_id"], action_id);
    }

    fn fake_onboard_state() -> bloom_polymarket::OnboardState {
        bloom_polymarket::OnboardState {
            wallet: "alice".into(),
            owner: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            deposit_wallet: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            deposit_wallet_source: String::new(),
            deposit_wallet_fundable: true,
            deposit_wallet_warning: None,
            chain_id: 137,
            stage: bloom_polymarket::Stage::Complete,
            deploy_tx_id: None,
            approve_tx_id: None,
            pusd_balance: None,
            creds_present: true,
            last_error: None,
            updated_ms: 0,
            in_flight_deadline_ms: None,
            mode: bloom_polymarket::OnboardMode::DepositWallet,
            relayer_auth: None,
        }
    }

    #[tokio::test]
    async fn sealed_revoke_denies_and_writes_challenge_without_grant() {
        let (addr, _s) = spawn_scripted(vec![]).await;
        let f = onboard_fixture(addr, true).await;
        let store = bloom_polymarket::OnboardStore::new(&f.state_dir);
        store.save("alice", &fake_onboard_state()).unwrap();
        let handler = f.handler.clone().with_auth_services(pm_wired_auth());

        let err = handler
            .write(&p("/revoke-approvals/alice/request/confirm"), b"confirm")
            .await
            .unwrap_err();
        assert!(
            matches!(err, HandlerError::PermissionDenied),
            "expected PermissionDenied, got: {err}"
        );

        // The challenge is written under <auth_dir>/<wallet>/<action_id>/.
        let action_id = polymarket_revoke_action_id("alice");
        let challenge_path = f
            .state_dir
            .join("alice")
            .join(&action_id)
            .join(APPROVAL_CHALLENGE_FILE);
        assert!(challenge_path.exists(), "challenge not written");
    }

    #[tokio::test]
    async fn wired_withdraw_is_gated_to_foreground_cli() {
        // The wired (serve-socket) withdraw path is intentionally closed until
        // it binds the body `amount` into the sealed subject and submits a real
        // `transfer` (tracked in docs/issues C2). Until then, even under wired
        // auth the confirm returns Unsupported and stages nothing — every
        // withdrawal goes through the foreground CLI, which reads the balance,
        // validates the amount, and submits the correct transfer.
        let (addr, _s) = spawn_scripted(vec![]).await;
        let f = onboard_fixture(addr, true).await;
        let store = bloom_polymarket::OnboardStore::new(&f.state_dir);
        store.save("alice", &fake_onboard_state()).unwrap();
        let handler = f.handler.clone().with_auth_services(pm_wired_auth());

        let err = handler
            .write(&p("/withdraw/alice/pusd/confirm"), b"confirm")
            .await
            .unwrap_err();
        assert!(
            matches!(err, HandlerError::Unsupported(_)),
            "expected Unsupported, got: {err}"
        );
        assert!(
            err.to_string().contains("foreground CLI VFS path"),
            "gated error should point at the CLI, got: {err}"
        );

        // No sealed action is staged for the closed path — no challenge on disk.
        let action_id = polymarket_withdraw_action_id("alice");
        let challenge_path = f
            .state_dir
            .join("alice")
            .join(&action_id)
            .join(APPROVAL_CHALLENGE_FILE);
        assert!(
            !challenge_path.exists(),
            "gated withdraw must not stage a challenge"
        );
    }

    #[tokio::test]
    async fn sealed_redeem_revoke_withdraw_preserve_foreground_when_not_wired() {
        let (addr, _s) = spawn_scripted(vec![]).await;
        let f = onboard_fixture(addr, true).await;

        // Redeem
        let err = f
            .handler
            .write(&p("/redeem/alice/test-slug/confirm"), b"confirm")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("foreground CLI VFS path"));

        // Revoke
        let err = f
            .handler
            .write(&p("/revoke-approvals/alice/request/confirm"), b"confirm")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("foreground CLI VFS path"));

        // Withdraw
        let err = f
            .handler
            .write(&p("/withdraw/alice/pusd/confirm"), b"confirm")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("foreground CLI VFS path"));
    }

    // ── Phase 7c: end-to-end sealed order flow ──────────────────────────

    /// A `PetalHost` that actually signs hashes with a test key and accepts
    /// any polymarket intent. Consumes one signature off the live grant per
    /// `sign_hash`, like the production `KeystorePetalHost` — this is what
    /// invalidates a `max_signatures = 1` grant and would catch a post-sign
    /// `get_active` lookup regression. Used for end-to-end happy-path tests.
    struct PmSigningPetalHost {
        signer: Arc<alloy::signers::local::PrivateKeySigner>,
        grant_store: Arc<bloom_auth::grant_store::InMemoryGrantStore>,
    }

    #[async_trait]
    impl bloom_auth_api::PetalHost for PmSigningPetalHost {
        async fn seal_context(
            &self,
            _petal_id: &str,
        ) -> Result<bloom_auth_api::SealedPetalContext, bloom_auth_api::AuthApiError> {
            Err(bloom_auth_api::AuthApiError::Store("unused".into()))
        }

        async fn sealed_policy_snapshot(
            &self,
            _wallet: &str,
            _petal_id: &str,
        ) -> Result<bloom_auth_api::PetalPolicySnapshot, bloom_auth_api::AuthApiError> {
            Err(bloom_auth_api::AuthApiError::Store("unused".into()))
        }

        async fn sign_hash(
            &self,
            request: bloom_auth_api::SignHashRequest,
            _attestation: &bloom_auth_api::SigningAttestation,
            now_ms: u64,
        ) -> Result<bloom_auth_api::SealedSignature, bloom_auth_api::AuthApiError> {
            use bloom_auth_api::GrantStore as _;
            let grant = self
                .grant_store
                .get_active(
                    &request.wallet,
                    &request.action_id,
                    petal_identity::PETAL_ID_POLYMARKET,
                    petal_identity::PLACEHOLDER_DIGEST_POLYMARKET,
                    now_ms,
                )
                .await?
                .ok_or_else(|| {
                    bloom_auth_api::AuthApiError::Denied("no active grant for sign_hash".into())
                })?;
            let hash = hex::decode(request.hash_hex.trim_start_matches("0x"))
                .map_err(|e| bloom_auth_api::AuthApiError::Denied(format!("hash hex: {e}")))?;
            let hash = alloy::primitives::B256::from_slice(&hash);
            let sig = self
                .signer
                .sign_hash_sync(&hash)
                .map_err(|e| bloom_auth_api::AuthApiError::Denied(format!("test sign: {e}")))?;
            self.grant_store
                .consume_signature(&grant.grant_id, &request.intent, now_ms)
                .await?;
            Ok(bloom_auth_api::SealedSignature {
                intent_hash: "pm-test-intent".into(),
                signature_b64: B64_STANDARD.encode(sig.as_bytes()),
                signed_at_ms: now_ms,
            })
        }

        async fn audit(
            &self,
            _event: bloom_auth_api::AuditEvent,
        ) -> Result<(), bloom_auth_api::AuthApiError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn e2e_sealed_order_signs_and_writes_result_with_grant() {
        use bloom_polymarket::order::{LimitQuote, OrderType};
        use std::str::FromStr;

        let store_dir = tempfile::tempdir().unwrap();
        let _auth_dir = tempfile::tempdir().unwrap();
        let store = OrderStore::new(store_dir.path());

        // Build a draft.
        let snap = trade::Snapshot {
            market: serde_json::from_value(serde_json::json!({
                "id":"1","slug":"test-market","question":"Will it?","conditionId":"0xcond",
                "clobTokenIds":"[\"123\",\"456\"]","outcomes":"[\"Yes\",\"No\"]",
                "enableOrderBook":true,"active":true,"closed":false,"negRisk":true
            }))
            .unwrap(),
            token_id: "123".into(),
            neg_risk: true,
            tick_micro: 1_000,
            min_size_micro: 5_000_000,
            best_ask_micro: Some(695_000),
            best_bid_micro: Some(690_000),
        };
        let quote = LimitQuote {
            side: Side::Buy,
            price_micro: 695_000,
            size_micro: 14_380_000,
            maker_micro: 10_000_000,
            taker_micro: 14_380_000,
        };
        let draft = trade::draft_from_quote(
            "w",
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            None,
            0,
            "test-market",
            "YES",
            Side::Buy,
            OrderType::FAK,
            700_000,
            true,
            1,
            &snap,
            &quote,
        );
        let draft = store.create_draft(draft).unwrap();

        // Build the order action to get the signing hash.
        let maker =
            alloy::primitives::Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
                .unwrap();
        let order_shell = bloom_polymarket::order::Order {
            salt: alloy::primitives::U256::from(1),
            maker,
            signer: maker,
            tokenId: alloy::primitives::U256::from(123),
            makerAmount: alloy::primitives::U256::from(10_000_000),
            takerAmount: alloy::primitives::U256::from(14_380_000),
            side: 0,
            signatureType: 0,
            timestamp: alloy::primitives::U256::from(1),
            metadata: alloy::primitives::B256::ZERO,
            builder: alloy::primitives::B256::ZERO,
        };
        let action = bloom_polymarket::signing::order_action_and_hash(
            &order_shell,
            137,
            true,
            bloom_polymarket::order::OrderType::GTC,
        );

        // Pre-mint a grant so the handler finds one when it checks.
        let now = pm_now_ms_u64();
        let grant_store = Arc::new(bloom_auth::grant_store::InMemoryGrantStore::default());
        let envelope =
            polymarket_order_envelope("w", &action.order_view, &action.signing_hash, 137, true)
                .unwrap();
        let mut extra = std::collections::BTreeMap::new();
        extra.insert("action_kind".to_string(), serde_json::json!("order"));
        let terms = bloom_auth_api::DaemonGrantTerms {
            max_ttl_secs: APPROVAL_TTL_MS / 1_000,
            max_signatures: 1,
            allowed_sign_intents: vec![bloom_auth_api::POLYMARKET_ORDER_SIGN_INTENT.into()],
            assurance: AssuranceLevel::Standard,
            extra,
        };
        let config = std::collections::BTreeMap::new();
        let snapshot = bloom_auth_api::PetalPolicySnapshot {
            policy_version: 0,
            wallet: "w".into(),
            petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
            caps: std::collections::BTreeMap::new(),
            hard_rules: Vec::new(),
            step_up_rules: Vec::new(),
            config,
            budget_state: std::collections::BTreeMap::new(),
            session_scope: Some(std::collections::BTreeMap::new()),
        };
        let sealed = bloom_auth_api::SealedAction::new(
            envelope,
            "test order".into(),
            Vec::new(),
            terms,
            snapshot,
            now,
        )
        .unwrap();
        grant_store
            .mint(&sealed, now + APPROVAL_TTL_MS, now)
            .await
            .unwrap();

        // Build the handler with all auth services wired.
        let test_pk = alloy::signers::local::PrivateKeySigner::from_str(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();
        let petal_host: Arc<dyn bloom_auth_api::PetalHost> = Arc::new(PmSigningPetalHost {
            signer: Arc::new(test_pk),
            grant_store: grant_store.clone(),
        });
        let auth = crate::AuthServices::default()
            .with_grant_store(grant_store)
            .with_writer(Arc::new(PmTestWriter))
            .with_petal_host(petal_host);

        let ks_dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(ks_dir.path()).unwrap();
        keystore.create_local("w", "pw").unwrap();
        let h = PolymarketHandler::new(
            GammaClient::new(),
            DataClient::new(),
            clob_unreachable(),
            keystore,
        )
        .with_order_store(OrderStore::new(store_dir.path()))
        .with_auth_services(auth);

        // Write the sign_request.json sidecar.
        let draft_dir = store.draft_path("w", &draft.id);
        let sidecar = draft_dir.parent().unwrap().join(PM_ORDER_SIGN_REQUEST_FILE);
        let maker_hex = action.order_view["maker"].as_str().unwrap().to_string();
        let req = serde_json::json!({
            "schema": "bloom.polymarket.order_sign_request.v1",
            "draft_id": draft.id,
            "salt": "1",
            "order_view": action.order_view,
            "signing_hash": format!("{:#x}", action.signing_hash),
            "neg_risk": action.neg_risk,
            "chain_id": action.chain_id,
            "side": Side::Buy,
            "maker": maker_hex,
            "market_slug": "test-market",
        });
        std::fs::write(&sidecar, serde_json::to_vec(&req).unwrap()).unwrap();

        // Call confirm — should succeed now (grant exists).
        let confirm_path = p(&format!("/trade/w/drafts/{}/confirm", draft.id));
        h.write(&confirm_path, b"confirm").await.unwrap();

        // Verify the result sidecar was written.
        let result_path = sidecar.with_file_name(PM_ORDER_SIGN_RESULT_FILE);
        assert!(result_path.exists(), "sign_result.json not written");
        let result: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&result_path).unwrap()).unwrap();
        assert!(
            result["wrapped_signature"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
        assert!(result["action_id"].as_str().unwrap().starts_with("pm-"));
        assert!(result["grant_id"].as_str().unwrap().starts_with("grant-"));
    }

    /// A well-formed order-kind facts map must round-trip through the typed
    /// struct and pass the production `DefaultAttestationRegistry` validation.
    /// This guards against schema drift between the handler's facts map and the
    /// typed struct the host validates against.
    #[test]
    fn order_attestation_facts_pass_registry_validation() {
        let registry = bloom_auth_api::DefaultAttestationRegistry::new();
        let facts = PolymarketSigningAttestationFacts {
            facts_schema: POLYMARKET_SIGNING_ATTESTATION_FACTS_SCHEMA_V1.into(),
            kind: PolymarketSealedActionKind::Order,
            petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            wallet: "0x0000000000000000000000000000000000000001".into(),
            chain_id: bloom_polymarket::POLYGON,
            action_id: "pm-test-order-action".into(),
            signing_hash: format!("{:#x}", alloy::primitives::B256::with_last_byte(1)),
        };
        let attestation = facts.signing_attestation().expect("order facts valid");
        registry
            .validate_attestation(&attestation)
            .expect("order attestation passes registry validation");
    }

    /// Same round-trip for an onboarding-kind facts map.
    #[test]
    fn onboarding_attestation_facts_pass_registry_validation() {
        let registry = bloom_auth_api::DefaultAttestationRegistry::new();
        let facts = PolymarketSigningAttestationFacts {
            facts_schema: POLYMARKET_SIGNING_ATTESTATION_FACTS_SCHEMA_V1.into(),
            kind: PolymarketSealedActionKind::Onboarding,
            petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            wallet: "0x0000000000000000000000000000000000000002".into(),
            chain_id: bloom_polymarket::POLYGON,
            action_id: "pm-test-onboard-action".into(),
            signing_hash: format!("{:#x}", alloy::primitives::B256::with_last_byte(2)),
        };
        let attestation = facts.signing_attestation().expect("onboarding facts valid");
        registry
            .validate_attestation(&attestation)
            .expect("onboarding attestation passes registry validation");
    }

    /// Regression guard: the OLD hand-built facts map (wrong key `"schema"`
    /// instead of `"facts_schema"`, missing required fields) must be REJECTED
    /// by the production registry. This proves the test would have caught the
    /// original C1 bug.
    #[test]
    fn malformed_old_style_facts_fail_registry_validation() {
        let registry = bloom_auth_api::DefaultAttestationRegistry::new();
        // Exactly the shape the handler used to build: `"schema"` key, a raw
        // intent string for `kind`, and several required fields missing.
        let mut bad_facts = std::collections::BTreeMap::new();
        bad_facts.insert(
            "schema".into(),
            serde_json::json!("bloom.polymarket.signing_facts.v1"),
        );
        bad_facts.insert(
            "kind".into(),
            serde_json::json!(POLYMARKET_ORDER_SIGN_INTENT),
        );
        bad_facts.insert(
            "wallet".into(),
            serde_json::json!("0x0000000000000000000000000000000000000003"),
        );
        bad_facts.insert(
            "signing_hash".into(),
            serde_json::json!(format!("{:#x}", alloy::primitives::B256::with_last_byte(3))),
        );
        let attestation = bloom_auth_api::SigningAttestation {
            schema: bloom_auth_api::SIGNING_ATTESTATION_SCHEMA_V1.into(),
            petal_id: petal_identity::PETAL_ID_POLYMARKET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_POLYMARKET.into(),
            intent: POLYMARKET_ORDER_SIGN_INTENT.into(),
            facts: bad_facts,
        };
        let result = registry.validate_attestation(&attestation);
        assert!(
            result.is_err(),
            "old-style malformed facts map must be rejected, but was accepted: {result:?}"
        );
    }

    /// `order_shell_from_view` must propagate `metadata`/`builder` from the
    /// order view JSON instead of zeroing them — both bind into the EIP-712
    /// `Order` struct hash. A non-zero value must survive the round-trip.
    #[test]
    fn order_shell_from_view_preserves_metadata_and_builder() {
        let meta = alloy::primitives::B256::with_last_byte(0xab);
        let bldr = alloy::primitives::B256::with_last_byte(0xcd);
        let view = serde_json::json!({
            "salt": "1",
            "maker": "0x0000000000000000000000000000000000000001",
            "signer": "0x0000000000000000000000000000000000000001",
            "tokenId": "1",
            "makerAmount": "1",
            "takerAmount": "1",
            "side": "0",
            "signatureType": "0",
            "timestamp": "1",
            "metadata": format!("{meta:#x}"),
            "builder": format!("{bldr:#x}"),
        });
        let shell = order_shell_from_view(&view).expect("view parses");
        assert_eq!(shell.metadata, meta);
        assert_eq!(shell.builder, bldr);
    }

    /// Older order views may omit `metadata`/`builder`; those must fall back to
    /// zero rather than erroring.
    #[test]
    fn order_shell_from_view_defaults_missing_metadata_and_builder_to_zero() {
        let view = serde_json::json!({
            "salt": "1",
            "maker": "0x0000000000000000000000000000000000000001",
            "signer": "0x0000000000000000000000000000000000000001",
            "tokenId": "1",
            "makerAmount": "1",
            "takerAmount": "1",
            "side": "0",
            "signatureType": "0",
            "timestamp": "1",
        });
        let shell = order_shell_from_view(&view).expect("view parses");
        assert_eq!(shell.metadata, alloy::primitives::B256::ZERO);
        assert_eq!(shell.builder, alloy::primitives::B256::ZERO);
    }

    // ── Sealed-action builder parity ───────────────────────────────────
    //
    // The `pub` sealed-action builders used by the CLI must produce the same
    // `action_id` as the corresponding `pub fn polymarket_*_action_id` helper.
    // If these diverge, the CLI and the daemon handler stage different actions
    // for the same operation and a grant minted by one will not satisfy the
    // other.

    #[test]
    fn onboard_sealed_action_action_id_matches_helper() {
        let owner: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let sealed = polymarket_onboard_sealed_action("test-wallet", owner, 1_000).unwrap();
        assert_eq!(
            sealed.action_id(),
            &polymarket_onboard_action_id("test-wallet"),
        );
    }

    #[test]
    fn revoke_sealed_action_action_id_matches_helper() {
        let deposit: Address = "0x0000000000000000000000000000000000000002"
            .parse()
            .unwrap();
        let sealed = polymarket_revocation_sealed_action("test-wallet", deposit, 1_000).unwrap();
        assert_eq!(
            sealed.action_id(),
            &polymarket_revoke_action_id("test-wallet"),
        );
    }

    #[test]
    fn withdraw_sealed_action_action_id_matches_helper() {
        let deposit: Address = "0x0000000000000000000000000000000000000003"
            .parse()
            .unwrap();
        let sealed = polymarket_withdrawal_sealed_action("test-wallet", deposit, 1_000).unwrap();
        assert_eq!(
            sealed.action_id(),
            &polymarket_withdraw_action_id("test-wallet"),
        );
    }

    #[test]
    fn redeem_sealed_action_action_id_matches_helper() {
        let deposit: Address = "0x0000000000000000000000000000000000000004"
            .parse()
            .unwrap();
        let condition_id = "0xabc123";
        let sealed =
            polymarket_redemption_sealed_action("test-wallet", deposit, condition_id, true, 1_000)
                .unwrap();
        assert_eq!(
            sealed.action_id(),
            &polymarket_redeem_action_id("test-wallet", condition_id),
        );
    }

    #[test]
    fn order_sealed_action_action_id_matches_action_id_for() {
        let wallet = "test-wallet";
        let signing_hash = alloy::primitives::B256::with_last_byte(42);
        let order_view = serde_json::json!({
            "salt": "1",
            "maker": "0x0000000000000000000000000000000000000001",
            "signer": "0x0000000000000000000000000000000000000001",
            "tokenId": "1",
            "makerAmount": "1",
            "takerAmount": "1",
            "side": "0",
            "signatureType": "0",
            "timestamp": "1",
        });
        let sealed = polymarket_order_sealed_action(
            wallet,
            &order_view,
            &signing_hash,
            137,
            true,
            "test plan".into(),
            1_000,
        )
        .unwrap();
        let expected =
            bloom_polymarket::signing::action_id_for("polymarket.order.v1", &signing_hash);
        assert_eq!(sealed.action_id(), &expected);
    }

    // ── P1 #2: Grant ID captured before consumption ────────────────────
    //
    // Regression test: `prepare_and_sign_order_sealed` used to re-fetch the
    // grant with `get_active` AFTER `sign_hash` consumed it. With
    // `max_signatures: 1` the grant is no longer active, so the post-sign
    // lookup always returned `None` → "grant vanished after consumption".
    // The fix captures the grant before signing; this test verifies the
    // `grant_id` survives in the result even though the grant is consumed.

    #[tokio::test]
    async fn prepare_order_sealed_returns_grant_id_after_consume() {
        use bloom_polymarket::order::{LimitQuote, OrderType};
        use std::str::FromStr;

        let store_dir = tempfile::tempdir().unwrap();
        let store = OrderStore::new(store_dir.path());

        let snap = trade::Snapshot {
            market: serde_json::from_value(serde_json::json!({
                "id":"1","slug":"test-market","question":"Will it?","conditionId":"0xcond",
                "clobTokenIds":"[\"123\",\"456\"]","outcomes":"[\"Yes\",\"No\"]",
                "enableOrderBook":true,"active":true,"closed":false,"negRisk":true
            }))
            .unwrap(),
            token_id: "123".into(),
            neg_risk: true,
            tick_micro: 1_000,
            min_size_micro: 5_000_000,
            best_ask_micro: Some(695_000),
            best_bid_micro: Some(690_000),
        };
        let quote = LimitQuote {
            side: Side::Buy,
            price_micro: 695_000,
            size_micro: 14_380_000,
            maker_micro: 10_000_000,
            taker_micro: 14_380_000,
        };
        let _draft = store
            .create_draft(trade::draft_from_quote(
                "w",
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
                None,
                0,
                "test-market",
                "YES",
                Side::Buy,
                OrderType::FAK,
                700_000,
                true,
                1,
                &snap,
                &quote,
            ))
            .unwrap();

        let maker = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
        let order_shell = bloom_polymarket::order::Order {
            salt: alloy::primitives::U256::from(1),
            maker,
            signer: maker,
            tokenId: alloy::primitives::U256::from(123),
            makerAmount: alloy::primitives::U256::from(10_000_000),
            takerAmount: alloy::primitives::U256::from(14_380_000),
            side: 0,
            signatureType: 0,
            timestamp: alloy::primitives::U256::from(1),
            metadata: alloy::primitives::B256::ZERO,
            builder: alloy::primitives::B256::ZERO,
        };
        let action = bloom_polymarket::signing::order_action_and_hash(
            &order_shell,
            137,
            true,
            bloom_polymarket::order::OrderType::GTC,
        );

        // Pre-mint a one-signature grant.
        let now = pm_now_ms_u64();
        let grant_store = Arc::new(bloom_auth::grant_store::InMemoryGrantStore::default());
        let plan = polymarket_order_plan(
            Side::Buy,
            Some("test-market"),
            maker,
            true,
            137,
            &action.signing_hash,
        );
        let sealed = polymarket_order_sealed_action(
            "w",
            &action.order_view,
            &action.signing_hash,
            137,
            true,
            plan,
            now,
        )
        .unwrap();
        grant_store
            .mint(&sealed, now + APPROVAL_TTL_MS, now)
            .await
            .unwrap();

        // Wire the handler with the pre-minted grant + signing stub.
        let test_pk = alloy::signers::local::PrivateKeySigner::from_str(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();
        let petal_host: Arc<dyn bloom_auth_api::PetalHost> = Arc::new(PmSigningPetalHost {
            signer: Arc::new(test_pk),
            grant_store: grant_store.clone(),
        });
        let auth = crate::AuthServices::default()
            .with_grant_store(grant_store)
            .with_writer(Arc::new(PmTestWriter))
            .with_petal_host(petal_host);

        let ks_dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(ks_dir.path()).unwrap();
        keystore.create_local("w", "pw").unwrap();
        let h = PolymarketHandler::new(
            GammaClient::new(),
            DataClient::new(),
            clob_unreachable(),
            keystore.clone(),
        )
        .with_order_store(OrderStore::new(store_dir.path()))
        .with_auth_services(auth);

        // This must succeed and return a non-empty grant_id, even though
        // sign_hash consumes the one and only signature on the grant.
        let result = h
            .prepare_and_sign_order_sealed(
                "w",
                &action.order_view,
                &action.signing_hash,
                137,
                true,
                Some("test-market".into()),
                maker,
                Side::Buy,
            )
            .await;
        assert!(
            result.is_ok(),
            "prepare_and_sign_order_sealed failed: {:?}",
            result.err()
        );
        let result = result.unwrap();
        assert!(
            !result.grant_id.is_empty(),
            "grant_id must be captured before consumption, got empty string"
        );
        assert!(result.grant_id.starts_with("grant-"));
        assert!(result.wrapped_signature.starts_with("0x"));
    }

    // ── P1 #3: Challenge carries ceremony_url ──────────────────────────
    //
    // The EVM outbox and wallet-policy flows project `.with_local_ceremony_url()`
    // before writing `approval_challenge.json`. Polymarket challenges must do
    // the same so the agent/user can click through to the ceremony.

    #[tokio::test]
    async fn order_challenge_writes_ceremony_url() {
        use bloom_polymarket::order::{LimitQuote, OrderType};

        let store_dir = tempfile::tempdir().unwrap();
        let store = OrderStore::new(store_dir.path());

        let snap = trade::Snapshot {
            market: serde_json::from_value(serde_json::json!({
                "id":"1","slug":"test-market","question":"Will it?","conditionId":"0xcond",
                "clobTokenIds":"[\"123\",\"456\"]","outcomes":"[\"Yes\",\"No\"]",
                "enableOrderBook":true,"active":true,"closed":false,"negRisk":true
            }))
            .unwrap(),
            token_id: "123".into(),
            neg_risk: true,
            tick_micro: 1_000,
            min_size_micro: 5_000_000,
            best_ask_micro: Some(695_000),
            best_bid_micro: Some(690_000),
        };
        let quote = LimitQuote {
            side: Side::Buy,
            price_micro: 695_000,
            size_micro: 14_380_000,
            maker_micro: 10_000_000,
            taker_micro: 14_380_000,
        };
        let _draft = store
            .create_draft(trade::draft_from_quote(
                "w",
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
                None,
                0,
                "test-market",
                "YES",
                Side::Buy,
                OrderType::FAK,
                700_000,
                true,
                1,
                &snap,
                &quote,
            ))
            .unwrap();

        // No grant pre-minted → handler should issue a challenge.
        let grant_store = Arc::new(bloom_auth::grant_store::InMemoryGrantStore::default());
        let auth = crate::AuthServices::default()
            .with_grant_store(grant_store)
            .with_writer(Arc::new(PmTestWriter));

        let ks_dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(ks_dir.path()).unwrap();
        keystore.create_local("w", "pw").unwrap();
        let h = PolymarketHandler::new(
            GammaClient::new(),
            DataClient::new(),
            clob_unreachable(),
            keystore.clone(),
        )
        .with_order_store(OrderStore::new(store_dir.path()))
        .with_auth_services(auth);

        let maker: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse()
            .unwrap();
        let order_shell = bloom_polymarket::order::Order {
            salt: alloy::primitives::U256::from(1),
            maker,
            signer: maker,
            tokenId: alloy::primitives::U256::from(123),
            makerAmount: alloy::primitives::U256::from(10_000_000),
            takerAmount: alloy::primitives::U256::from(14_380_000),
            side: 0,
            signatureType: 0,
            timestamp: alloy::primitives::U256::from(1),
            metadata: alloy::primitives::B256::ZERO,
            builder: alloy::primitives::B256::ZERO,
        };
        let action = bloom_polymarket::signing::order_action_and_hash(
            &order_shell,
            137,
            true,
            bloom_polymarket::order::OrderType::GTC,
        );

        // Should return PermissionDenied (no grant → writes challenge).
        let result = h
            .prepare_and_sign_order_sealed(
                "w",
                &action.order_view,
                &action.signing_hash,
                137,
                true,
                Some("test-market".into()),
                maker,
                Side::Buy,
            )
            .await;
        assert!(result.is_err(), "expected PermissionDenied, got Ok");

        // The challenge file must have been written with ceremony_url set.
        let challenge_path = keystore
            .root()
            .join("_polymarket")
            .join("trade")
            .join("w")
            .join(bloom_polymarket::signing::action_id_for(
                "polymarket.order.v1",
                &action.signing_hash,
            ))
            .join(APPROVAL_CHALLENGE_FILE);
        assert!(
            challenge_path.exists(),
            "approval_challenge.json not written at {}",
            challenge_path.display()
        );
        let challenge: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&challenge_path).unwrap()).unwrap();
        let url = challenge["ceremony_url"].as_str();
        assert!(
            url.is_some() && !url.unwrap().is_empty(),
            "ceremony_url must be projected into approval_challenge.json, got: {challenge}"
        );
    }

    // ── P1 #1: SealedOnboardSigner routes through PetalHost ────────────
    //
    // The CLI uses `SealedOnboardSigner` for passkey wallets. Every signing
    // operation must go through `PetalHost::sign_hash` (never the raw
    // keystore). These tests verify the dispatch using a recording stub.

    /// `PetalHost` stub that records the last `sign_hash` request so tests
    /// can assert on `wallet`, `action_id`, `intent`, and `hash_hex`.
    struct RecordingPetalHost {
        signer: Arc<alloy::signers::local::PrivateKeySigner>,
        last_request: std::sync::Mutex<Option<bloom_auth_api::SignHashRequest>>,
    }

    #[async_trait]
    impl bloom_auth_api::PetalHost for RecordingPetalHost {
        async fn seal_context(
            &self,
            _petal_id: &str,
        ) -> Result<bloom_auth_api::SealedPetalContext, bloom_auth_api::AuthApiError> {
            Err(bloom_auth_api::AuthApiError::Store("unused".into()))
        }

        async fn sealed_policy_snapshot(
            &self,
            _wallet: &str,
            _petal_id: &str,
        ) -> Result<bloom_auth_api::PetalPolicySnapshot, bloom_auth_api::AuthApiError> {
            Err(bloom_auth_api::AuthApiError::Store("unused".into()))
        }

        async fn sign_hash(
            &self,
            request: bloom_auth_api::SignHashRequest,
            _attestation: &bloom_auth_api::SigningAttestation,
            now_ms: u64,
        ) -> Result<bloom_auth_api::SealedSignature, bloom_auth_api::AuthApiError> {
            *self.last_request.lock().unwrap() = Some(request.clone());
            let hash = hex::decode(request.hash_hex.trim_start_matches("0x"))
                .map_err(|e| bloom_auth_api::AuthApiError::Denied(format!("hash hex: {e}")))?;
            let hash = alloy::primitives::B256::from_slice(&hash);
            let sig = self
                .signer
                .sign_hash_sync(&hash)
                .map_err(|e| bloom_auth_api::AuthApiError::Denied(format!("test sign: {e}")))?;
            Ok(bloom_auth_api::SealedSignature {
                intent_hash: "pm-test-intent".into(),
                signature_b64: B64_STANDARD.encode(sig.as_bytes()),
                signed_at_ms: now_ms,
            })
        }

        async fn audit(
            &self,
            _event: bloom_auth_api::AuditEvent,
        ) -> Result<(), bloom_auth_api::AuthApiError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn sealed_onboard_signer_routes_sign_through_host() {
        use std::str::FromStr;

        let pk = alloy::signers::local::PrivateKeySigner::from_str(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();
        let host = Arc::new(RecordingPetalHost {
            signer: Arc::new(pk),
            last_request: std::sync::Mutex::new(None),
        });
        let signer = SealedOnboardSigner::new(
            host.clone(),
            "test-wallet",
            "pm-test-action",
            PolymarketSealedActionKind::Onboarding,
            "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
        );

        let hash = alloy::primitives::B256::with_last_byte(0x42);
        let sig = signer.sign_eip712_hash(&hash).await.unwrap();

        // Host was called exactly once with the right parameters.
        let req = host.last_request.lock().unwrap().clone().unwrap();
        assert_eq!(req.wallet, "test-wallet");
        assert_eq!(req.action_id, "pm-test-action");
        assert_eq!(
            req.intent,
            bloom_auth_api::POLYMARKET_ONBOARDING_SIGN_INTENT
        );
        assert_eq!(req.hash_hex, format!("{hash:#x}"));

        // The returned signature is 65 bytes (non-zero, from the host's key).
        assert_eq!(sig.as_bytes().len(), 65);
        assert!(sig.as_bytes().iter().any(|&b| b != 0));
    }

    #[tokio::test]
    async fn sealed_onboard_signer_kind_intent_mapping_is_correct() {
        use std::str::FromStr;

        let pk = alloy::signers::local::PrivateKeySigner::from_str(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap();

        let cases = [
            (
                PolymarketSealedActionKind::Onboarding,
                bloom_auth_api::POLYMARKET_ONBOARDING_SIGN_INTENT,
            ),
            (
                PolymarketSealedActionKind::Revocation,
                bloom_auth_api::POLYMARKET_REVOCATION_SIGN_INTENT,
            ),
            (
                PolymarketSealedActionKind::Withdrawal,
                bloom_auth_api::POLYMARKET_WITHDRAWAL_SIGN_INTENT,
            ),
            (
                PolymarketSealedActionKind::Redemption,
                bloom_auth_api::POLYMARKET_REDEMPTION_SIGN_INTENT,
            ),
        ];

        let hash = alloy::primitives::B256::with_last_byte(0x01);
        for (kind, expected_intent) in cases {
            let host = Arc::new(RecordingPetalHost {
                signer: Arc::new(pk.clone()),
                last_request: std::sync::Mutex::new(None),
            });
            let signer = SealedOnboardSigner::new(
                host.clone(),
                "w",
                "pm-action",
                kind,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
            );
            signer.sign_eip712_hash(&hash).await.unwrap();
            let req = host.last_request.lock().unwrap().clone().unwrap();
            assert_eq!(
                req.intent, expected_intent,
                "kind {:?} must map to intent {}",
                kind, expected_intent,
            );
        }
    }
}
