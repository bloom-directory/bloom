//! `polymarket/...` VFS surface: public market reads, onboarding, account
//! views, staged funding requests, and read-only trade drafts/receipts.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use alloy::primitives::{Address, U256};
use async_trait::async_trait;
use bloom_chain::ChainClient;
use bloom_keystore::{Keystore, KeystoreError};
use bloom_polymarket::eip712::PUSD;
use bloom_polymarket::onboard::OnEvent;
use bloom_polymarket::order::{self, OrderType};
use bloom_polymarket::order_store::{OrderDraft, render_plan_md};
use bloom_polymarket::trade;
use bloom_polymarket::{
    ChainReader, ClobClient, CredentialStore, DataClient, GammaClient, GeoblockClient,
    KeystoreSigner, OnboardEvent, OnboardState, Onboarder, OrderStore, PolymarketError, Side,
    Stage, validate_wallet_name,
};
use bloom_proto::audit::{AuditLog, AuditRecord};
use bloom_proto::polymarket_policy::{self as pm_policy, PolicySide, PolymarketOrderCtx};
use serde::{Deserialize, Serialize};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

/// How many markets `markets/` enumerates (most active by volume).
pub const MARKETS_LIST_LIMIT: u32 = 20;

const MARKET_FILES: [&str; 3] = ["market.json", "book.json", "prices.json"];
const POSITION_FILES: [&str; 3] = ["positions.json", "trades.json", "activity.json"];
const ONBOARD_RO_FILES: [&str; 3] = ["status.json", "plan.md", "approvals.json"];
const ACCOUNT_FILES: [&str; 2] = ["portfolio.json", "orders.json"];
const FUND_FILES: [&str; 3] = ["plan.md", "request.json", "status.json"];
const DRAFT_FILES: [&str; 5] = [
    "plan.md",
    "order.json",
    "policy_check.json",
    "quote.json",
    "review_intent.json",
];

const BEGIN_HINT: &[u8] = b"write anything here to (re)run onboarding; run in the foreground for passkey wallets; rests at 'fund' for pUSD; progress + liveness: status.json\n";
const TRADE_NEW_HINT: &[u8] = br#"write JSON to create a reviewable draft, e.g.
{"slug":"will-canada-win-the-2026-fifa-world-cup-755","outcome":"yes","amount":"1","max_price":"0.01"}
Then read drafts/<id>/plan.md. Confirmation still uses `bloom polymarket confirm <wallet> <id>` until the VFS signing path is wired.
"#;
const FUND_NEW_HINT: &[u8] = br#"write JSON to create a reviewable pUSD funding request, e.g.
{"target_pusd":"10","max_spend":"100","from_token":"native","slippage_bps":50}
Then read <id>/plan.md. Confirmation/staging is not wired on this VFS path yet.
"#;

fn now_ms_u128() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// The onboarding/account dependencies, bundled so the read-only handler keeps
/// its constructor and the daemon opts in via [`PolymarketHandler::with_onboarding`].
pub struct PolymarketOnboarding {
    pub onboarder: Arc<Onboarder>,
    pub geoblock: Arc<GeoblockClient>,
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
/// Bloom uses the deposit-wallet path (signatureType 3) for V2 trading.
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
    audit: Option<Arc<AuditLog>>,
    /// Wallets with an onboarding run in flight (single-flight guard).
    running: Arc<StdMutex<HashSet<String>>>,
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
            audit: None,
            running: Arc::default(),
        }
    }

    /// Enable the `onboard/` + `account/` subtrees.
    pub fn with_onboarding(mut self, onboarding: PolymarketOnboarding) -> Self {
        self.onboarding = Some(Arc::new(onboarding));
        self
    }

    /// Enable the read-only `trade/` subtree (order drafts + receipts).
    /// There is deliberately no writable confirm path here: confirmation
    /// needs a wallet unlock and fresh policy evaluation, which stay in the
    /// CLI (`bloom polymarket confirm`).
    pub fn with_order_store(mut self, store: OrderStore) -> Self {
        self.orders = Some(Arc::new(store));
        self
    }

    /// Enable the `fund/` subtree for reviewable pUSD funding requests.
    pub fn with_fund_store(mut self, root: impl Into<PathBuf>) -> Self {
        self.fund_root = Some(root.into());
        self
    }

    fn orders_or_not_found(&self, path: &VfsPath) -> Result<&OrderStore, HandlerError> {
        self.orders
            .as_deref()
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
         - [{m_approve}] **approve** — one EIP-712-signed relayer batch granting the V2 exchanges/adapters\n\
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
         Preconditions enforced on `begin`: wallet unlocked, region not geoblocked\n\
         (fail-closed — an unverifiable region refuses too; there is no bypass).\n\
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
                3 if ONBOARD_RO_FILES.contains(&segs[2].as_str()) => Ok(Entry::file(&segs[2])),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "account" if self.onboarding_wired() => match segs.len() {
                1 => Ok(Entry::dir("account")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if ACCOUNT_FILES.contains(&segs[2].as_str()) => Ok(Entry::file(&segs[2])),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "fund" if self.fund_wired() => match segs.len() {
                1 => Ok(Entry::dir("fund")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if segs[2] == "new" => Ok(Entry::writable_file("new")),
                3 => Ok(Entry::dir(&segs[2])),
                4 if FUND_FILES.contains(&segs[3].as_str()) => Ok(Entry::file(&segs[3])),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "trade" if self.orders.is_some() => match segs.len() {
                1 => Ok(Entry::dir("trade")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if segs[2] == "new" => Ok(Entry::writable_file("new")),
                3 if segs[2] == "drafts" || segs[2] == "receipts" => Ok(Entry::dir(&segs[2])),
                4 if segs[2] == "drafts" || segs[2] == "receipts" => Ok(Entry::dir(&segs[3])),
                5 if segs[2] == "drafts" && DRAFT_FILES.contains(&segs[4].as_str()) => {
                    Ok(Entry::file(&segs[4]))
                }
                5 if segs[2] == "receipts" && segs[4] == "receipt.json" => {
                    Ok(Entry::file(&segs[4]))
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
            (Some("fund"), 3) if segs[2] == "new" => Ok(FUND_NEW_HINT.to_vec()),
            (Some("fund"), 4) => self.read_fund(path, &segs[1], &segs[2], &segs[3]),
            (Some("trade"), 3) if segs[2] == "new" => Ok(TRADE_NEW_HINT.to_vec()),
            (Some("trade"), 5) => self.read_trade(path, &segs[1], &segs[2], &segs[3], &segs[4]),
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
                // The V2 CLOB rejects EOA makers: a Complete EOA run is NOT
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
        let creds = ob.creds.load(wallet).map_err(err_be)?.ok_or_else(|| {
            HandlerError::invalid(format!(
                "wallet '{wallet}' is not onboarded (no CLOB credentials); \
                     write polymarket/onboard/{wallet}/begin first"
            ))
        })?;
        match file {
            // Sectioned by source so provenance is unambiguous: what the CLOB
            // believes vs. what the chain holds vs. where onboarding stands.
            "portfolio.json" => {
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
                let orders = self.clob.open_orders(&creds, owner).await.map_err(err_be)?;
                pretty(&orders)
            }
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
            current_pusd: bloom_proto::units::format_units(pusd, 6),
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
        if segs.len() == 3 && segs[0] == "trade" && segs[2] == "new" {
            if _data.is_empty() {
                return Err(HandlerError::invalid("empty trade new request"));
            }
            return self.create_trade_draft(&segs[1], _data).await;
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
        // …and be unlocked: signing (approval batch, ClobAuth) needs the key.
        let signer_arc = self.keystore.signer(wallet).map_err(|e| match e {
            KeystoreError::Locked(_) => HandlerError::invalid(format!(
                "wallet '{wallet}' is locked; unlock it before onboarding"
            )),
            other => HandlerError::backend(other.to_string()),
        })?;
        // Geoblock refuse-line: blocked or unverifiable → refuse. No bypass.
        let geo = ob.geoblock.check().await.map_err(err_be)?;
        if geo.blocked {
            return Err(HandlerError::invalid(format!(
                "Polymarket is unavailable in your region (country={}, region={}); \
                 refusing to onboard",
                geo.country, geo.region
            )));
        }
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

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        match (segs.first().map(String::as_str), segs.len()) {
            (None, 0) => {
                let mut entries = Vec::new();
                if self.onboarding_wired() {
                    entries.push(Entry::dir("account"));
                }
                entries.push(Entry::dir("markets"));
                if self.onboarding_wired() {
                    entries.push(Entry::dir("onboard"));
                }
                if self.fund_wired() {
                    entries.push(Entry::dir("fund"));
                }
                entries.push(Entry::dir("positions"));
                entries.push(Entry::dir("search"));
                if self.orders.is_some() {
                    entries.push(Entry::dir("trade"));
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
                self.onboarding_or_not_found(path)?;
                let mut entries: Vec<Entry> =
                    ONBOARD_RO_FILES.iter().map(|f| Entry::file(f)).collect();
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
                        .map(|id| Entry::dir(id)),
                );
                Ok(entries)
            }
            (Some("fund"), 3) if segs[2] != "new" => {
                self.fund_root_or_not_found(path)?;
                Ok(FUND_FILES.iter().map(|f| Entry::file(f)).collect())
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
                    Entry::dir("receipts"),
                ])
            }
            (Some("trade"), 3) if segs[2] == "drafts" => {
                let store = self.orders_or_not_found(path)?;
                let ids = store.list_drafts(&segs[1]).map_err(err_be)?;
                Ok(ids.iter().map(|id| Entry::dir(id)).collect())
            }
            (Some("trade"), 3) if segs[2] == "receipts" => {
                let store = self.orders_or_not_found(path)?;
                let ids = store.list_receipts(&segs[1]).map_err(err_be)?;
                Ok(ids.iter().map(|id| Entry::dir(id)).collect())
            }
            (Some("trade"), 4) if segs[2] == "drafts" => {
                Ok(DRAFT_FILES.iter().map(|f| Entry::file(f)).collect())
            }
            (Some("trade"), 4) if segs[2] == "receipts" => Ok(vec![Entry::file("receipt.json")]),
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
    use bloom_polymarket::{OnboardStore, RelayerClient};
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

        assert!(
            h.lookup(&p(&format!("/trade/w/drafts/{}/confirm", draft.id)))
                .await
                .is_err()
        );
        assert!(handler_with(None, None).lookup(&p("/trade")).await.is_err());
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
            geoblock: Arc::new(
                GeoblockClient::new().with_base_url_for_tests(format!("{base}/api/geoblock")),
            ),
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

    fn geo_ok() -> (&'static str, String) {
        (
            "/api/geoblock",
            r#"{"blocked":false,"ip":"1.2.3.4","country":"AR","region":"X"}"#.to_string(),
        )
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
        assert_eq!(names, vec!["markets", "positions", "search"]);
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
        let (addr, _s) = spawn_scripted(vec![geo_ok()]).await;
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
        let (addr, _s) = spawn_scripted(vec![geo_ok()]).await;
        let f = onboard_fixture(addr, true).await;
        let err = f
            .handler
            .write(&p("/onboard/nobody/begin"), b"x")
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)), "{err}");

        let (addr, _s) = spawn_scripted(vec![geo_ok()]).await;
        let f = onboard_fixture(addr, false).await;
        let err = f
            .handler
            .write(&p("/onboard/alice/begin"), b"x")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("locked"), "{err}");

        let (addr, _s) = spawn_scripted(vec![(
            "/api/geoblock",
            r#"{"blocked":true,"ip":"1.1.1.1","country":"XX","region":"YY"}"#.to_string(),
        )])
        .await;
        let f = onboard_fixture(addr, true).await;
        let err = f
            .handler
            .write(&p("/onboard/alice/begin"), b"x")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("country=XX"), "{err}");

        let (addr, _s) = spawn_scripted(vec![]).await; // 404s everything
        let f = onboard_fixture(addr, true).await;
        let err = f
            .handler
            .write(&p("/onboard/alice/begin"), b"x")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("could not verify region availability"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn begin_runs_to_complete_with_audit_and_no_secret_leak() {
        let (addr, _s) = spawn_scripted(vec![
            geo_ok(),
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
            geo_ok(),
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
        let (addr, _s) = spawn_scripted(vec![geo_ok()]).await;
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
        let (addr, _s) = spawn_scripted(vec![geo_ok()]).await;
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
    }
}
