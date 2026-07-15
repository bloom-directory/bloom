//! Polymarket order lifecycle: draft → confirm → post, sell-to-close, cancel.
//!
//! Boundaries enforced here:
//! - every refusal (market state, cross-checks, policy) happens **before** the
//!   passkey ceremony;
//! - drafts are durable snapshots under `~/.bloom/polymarket/<wallet>/orders/`
//!   and are revalidated wholesale at confirm time — never permission to
//!   trade stale data;
//! - deny-level policy cannot be bypassed from argv; warns are acknowledged
//!   with `--confirm-risk`;
//! - the per-wallet order lock serializes confirm/post/receipt writes so
//!   parallel invocations cannot race the daily cap;
//! - ambiguous CLOB errors are never retried — we reconcile against open
//!   orders and otherwise stop with an `ambiguous` draft status.

use alloy::primitives::{Address, B256, U256};
use alloy::rpc::types::eth::TransactionRequest;
use anyhow::{Context, Result, bail, ensure};
use bloom_auth_api::PolymarketSealedActionKind;
use bloom_daemon::Daemon;
use bloom_polymarket::eip712::{CTF, CTF_EXCHANGE, NEG_RISK_EXCHANGE};
use bloom_polymarket::order::{self, OrderParams, OrderType};
use bloom_polymarket::order_store::{
    DraftStatus, OrderDraft, OrderReceipt, OrderStore, render_plan_md,
};
use bloom_polymarket::trade;
use bloom_polymarket::types::Side;
use bloom_polymarket::{
    BuilderCredentialStore, ClobClient, CredentialStore, DataClient, GammaClient, KeystoreSigner,
    OnboardSigner, RelayerClient,
};
use bloom_proto::HomeWritePermit;
use bloom_proto::polymarket_policy::{self as pm_policy, PolicySide, PolymarketOrderCtx};
use bloom_tx::TxEngineError;
use bloom_vfs::handlers::polymarket as pm_sealed;

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn now_ms_u64() -> u64 {
    u64::try_from(now_ms()).unwrap_or(u64::MAX)
}

/// Keep the value-moving CLI aligned with the VFS staged-request validator:
/// a `u16` alone would admit 655.35% slippage.
const MAX_FUND_SLIPPAGE_BPS: u16 = 1000;

fn polymarket_gamma_client(pm_cfg: &bloom_proto::config::PolymarketConfig) -> GammaClient {
    let mut gamma = GammaClient::new();
    if let Ok(url) = url::Url::parse(&pm_cfg.gamma_url) {
        gamma = gamma.with_base_url(url);
    }
    gamma
}

fn polymarket_clob_client(pm_cfg: &bloom_proto::config::PolymarketConfig) -> ClobClient {
    let mut clob = ClobClient::new(pm_cfg.chain_id);
    if let Ok(url) = url::Url::parse(&pm_cfg.clob_url) {
        clob = clob.with_base_url(url);
    }
    clob
}

fn polymarket_data_client(pm_cfg: &bloom_proto::config::PolymarketConfig) -> DataClient {
    let mut data = DataClient::new();
    if let Ok(url) = url::Url::parse(&pm_cfg.data_url) {
        data = data.with_base_url(url);
    }
    data
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn home_write_permit(d: &Daemon) -> Result<&HomeWritePermit> {
    d.home_write_permit.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "daemon was built without a home write permit; refusing EVM outbox mutation"
        )
    })
}

/// Arguments shared by `order` (buy) and `sell`.
pub struct PlaceArgs {
    pub wallet: String,
    pub slug: String,
    pub outcome: String,
    pub side: Side,
    /// Buy: pUSD spend. Sell: share count.
    pub amount: String,
    /// Buy: `--max-price`. Sell: `--min-price`. Required unless
    /// `--limit-price` is given.
    pub price_bound: Option<String>,
    /// Explicit resting limit price (may rest on the book; defaults the
    /// order type to GTC, which is allowed because cancel exists).
    pub limit_price: Option<String>,
    pub order_type: Option<String>,
    pub dry_run: bool,
    pub confirm_risk: bool,
    pub passphrase: Option<String>,
}

fn evaluate_policy(
    d: &Daemon,
    store: &OrderStore,
    draft: &OrderDraft,
) -> Result<(Vec<bloom_proto::PolicyCheck>, bool)> {
    let info = d.keystore.info(&draft.wallet)?;
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
        // snapshot() refuses non-binary markets before a draft exists; this
        // carries the validated value so the policy gate evaluates the real
        // market rather than assuming binarity.
        binary_outcomes: draft.binary_outcomes,
        neg_risk: draft.neg_risk,
        receipt_store_readable: readable,
        daily_posted_microusd: daily,
    };
    let checks = pm_policy::evaluate_polymarket_order(&info.policy.polymarket, &ctx);
    let deny = bloom_proto::has_deny(&checks);
    Ok((checks, deny))
}

/// The funder/maker context an order is placed under. Loaded from durable
/// onboarding state — orders are refused outright when the account is not in
/// a tradeable mode (the CLOB rejects EOA makers at POST time).
struct TradeFunder {
    /// Deposit wallet address (maker + struct signer for sigtype 3).
    funder: alloy::primitives::Address,
    signature_type: u8,
}

/// Refuse to act on onboarding state that belongs to a different key. The
/// money-moving commands load `account.json` directly (rather than through
/// `Onboarder::status`, which carries this check), so they must re-assert it
/// here: a renamed or re-imported keystore wallet must never inherit another
/// key's deposit wallet — funding it would send pUSD to an address the current
/// key cannot control.
fn ensure_onboard_owner(
    st: &bloom_polymarket::OnboardState,
    owner: alloy::primitives::Address,
) -> Result<()> {
    if st.owner.parse::<alloy::primitives::Address>().ok() != Some(owner) {
        bail!(
            "onboarding state for '{}' belongs to owner {}, not the current key {} — \
             a renamed or re-imported wallet must not inherit another key's deposit \
             wallet; re-run `bloom polymarket onboard {}`",
            st.wallet,
            st.owner,
            owner.to_checksum(None),
            st.wallet,
        );
    }
    Ok(())
}

fn trade_funder(d: &Daemon, wallet: &str) -> Result<TradeFunder> {
    let store = bloom_polymarket::OnboardStore::new(d.home.polymarket_dir());
    let st = store.load(wallet)?.with_context(|| {
        format!("wallet '{wallet}' is not onboarded; run `bloom polymarket onboard {wallet}`")
    })?;
    ensure_onboard_owner(&st, d.keystore.info(wallet)?.address)?;
    if !st.is_complete() {
        bail!(
            "onboarding for '{wallet}' is at stage '{}' — finish it with \
             `bloom polymarket onboard {wallet}` before trading",
            st.stage.as_str()
        );
    }
    Ok(TradeFunder {
        funder: st
            .deposit_wallet
            .parse()
            .context("corrupt deposit_wallet in onboarding state")?,
        signature_type: order::SIG_TYPE_POLY_1271,
    })
}

/// `bloom polymarket order` / `sell` entry: validate, draft, then execute
/// (or stop at the draft with `--dry-run`).
pub async fn place(d: &Daemon, args: PlaceArgs) -> Result<()> {
    let pm_cfg = d
        .config
        .polymarket
        .as_ref()
        .context("no [polymarket] block in config.toml")?;
    if pm_cfg.legacy_eoa_mode {
        bail!(
            "[polymarket].legacy_eoa_mode is no longer supported for trading. \
             Remove that setting and re-run `bloom polymarket onboard {}` to use \
             deposit-wallet mode.",
            args.wallet
        );
    }
    let info = d.keystore.info(&args.wallet)?;
    let tf = trade_funder(d, &args.wallet)?;

    let amount_micro = order::parse_micro(&args.amount).with_context(|| match args.side {
        Side::Buy => "parse pUSD amount",
        Side::Sell => "parse share count",
    })?;

    let marketable = args.limit_price.is_none();
    let (bound_micro, pinned_limit_micro) = match (&args.price_bound, &args.limit_price) {
        (Some(b), Some(l)) => {
            let b = order::parse_micro(b).context("parse price bound")?;
            let l = order::parse_micro(l).context("parse --limit-price")?;
            let ok = match args.side {
                Side::Buy => l <= b,
                Side::Sell => l >= b,
            };
            if !ok {
                bail!("--limit-price conflicts with the price bound");
            }
            (b, l)
        }
        (Some(b), None) => {
            let b = order::parse_micro(b).context("parse price bound")?;
            (b, b)
        }
        (None, Some(l)) => {
            let l = order::parse_micro(l).context("parse --limit-price")?;
            (l, l)
        }
        (None, None) => bail!(
            "a price bound is required ({}); bloom never trades without a user-set bound",
            match args.side {
                Side::Buy => "--max-price, or --limit-price for a resting order",
                Side::Sell => "--min-price, or --limit-price for a resting order",
            }
        ),
    };

    let order_type: OrderType = match &args.order_type {
        Some(s) => s.parse::<OrderType>().map_err(|e| anyhow::anyhow!("{e}"))?,
        // Marketable orders never rest; explicit limits rest until cancelled.
        None if marketable => OrderType::FAK,
        None => OrderType::GTC,
    };
    if order_type == OrderType::GTD {
        bail!("GTD orders are not supported (no expiration plumbing)");
    }

    let gamma = polymarket_gamma_client(pm_cfg);
    let clob = polymarket_clob_client(pm_cfg);
    let snap = trade::snapshot(&gamma, &clob, &args.slug, &args.outcome).await?;

    // Sell-to-close only: never sell more than current holdings. Positions
    // live at the funder (deposit wallet), not the owner EOA.
    if args.side == Side::Sell {
        verify_holdings(d, pm_cfg.chain_id, &tf.funder, &snap.token_id, amount_micro).await?;
    }
    let _ = &info; // policy is read in evaluate_policy; owner shown in drafts

    let limit_micro = trade::choose_limit(
        args.side,
        marketable,
        bound_micro,
        pinned_limit_micro,
        &snap,
    )?;
    let quote = trade::build_quote(args.side, amount_micro, limit_micro, &snap, order_type)?;

    let store = OrderStore::new(d.home.polymarket_dir());
    let mut draft = trade::draft_from_quote(
        &args.wallet,
        bloom_proto::checksum_address(&info.address),
        Some(bloom_proto::checksum_address(&tf.funder)),
        tf.signature_type,
        &args.slug,
        &args.outcome,
        args.side,
        order_type,
        bound_micro,
        marketable,
        now_ms(),
        &snap,
        &quote,
    );
    let (checks, _deny) = evaluate_policy(d, &store, &draft)?;
    draft.policy_checks = serde_json::to_value(&checks)?;
    let draft = store.create_draft(draft)?;

    if args.dry_run {
        println!("{}", render_plan_md(&draft));
        println!(
            "dry run: draft {} saved (also readable at polymarket/trade/{}/drafts/{}/plan.md)",
            draft.id, draft.wallet, draft.id
        );
        return Ok(());
    }

    execute(
        d,
        &store,
        draft,
        args.confirm_risk,
        args.passphrase.as_deref(),
    )
    .await
}

/// `bloom polymarket confirm <wallet> <draft-id>`: execute a reviewed draft.
pub async fn confirm(
    d: &Daemon,
    wallet: &str,
    draft_id: &str,
    confirm_risk: bool,
    passphrase: Option<&str>,
) -> Result<()> {
    let store = OrderStore::new(d.home.polymarket_dir());
    let draft = store
        .load_draft(wallet, draft_id)?
        .with_context(|| format!("no draft {draft_id} for wallet {wallet}"))?;
    if draft.status != DraftStatus::Draft {
        bail!(
            "draft {draft_id} is '{}' — only fresh drafts can be confirmed",
            draft.status.as_str()
        );
    }
    execute(d, &store, draft, confirm_risk, passphrase).await
}

/// Shared execution path: lock → revalidate → policy → plan →
/// ceremony → sign → post → receipt.
async fn execute(
    d: &Daemon,
    store: &OrderStore,
    mut draft: OrderDraft,
    confirm_risk: bool,
    passphrase: Option<&str>,
) -> Result<()> {
    let pm_cfg = d
        .config
        .polymarket
        .as_ref()
        .context("no [polymarket] block in config.toml")?;

    let _lock = store.lock(&draft.wallet)?;
    // Revalidate everything against the live market; the draft is a snapshot.
    let gamma = polymarket_gamma_client(pm_cfg);
    let clob = polymarket_clob_client(pm_cfg);
    let snap = trade::snapshot(&gamma, &clob, &draft.slug, &draft.outcome).await?;
    if snap.token_id != draft.token_id {
        bail!("token id changed between draft and confirm — refusing");
    }

    let amount_input = match draft.side {
        // For buys the durable intent is the USD budget bound by max price;
        // re-derive shares from the live book. For sells it's the share count.
        Side::Buy => draft.amount_microusd.max(1),
        Side::Sell => draft.size_micro,
    };
    let limit_micro = trade::choose_limit(
        draft.side,
        draft.marketable,
        draft.price_bound_micro,
        draft.limit_price_micro,
        &snap,
    )?;
    let quote = trade::build_quote(
        draft.side,
        amount_input,
        limit_micro,
        &snap,
        draft.order_type,
    )?;
    // Funder/mode re-resolved from durable state — refuses non-tradeable
    // modes even for drafts created under an older configuration.
    let tf = trade_funder(d, &draft.wallet)?;
    draft.funder = Some(bloom_proto::checksum_address(&tf.funder));
    draft.signature_type = tf.signature_type;
    if draft.side == Side::Sell {
        verify_holdings(
            d,
            pm_cfg.chain_id,
            &tf.funder,
            &draft.token_id,
            quote.size_micro,
        )
        .await?;
    }

    draft.limit_price_micro = quote.price_micro;
    draft.size_micro = quote.size_micro;
    // Buys keep the user's requested USD budget durable: `amount_input` above
    // re-derives shares from it, so a retry uses the same bound rather than the
    // smaller rounded realized spend. Sells record the realized proceeds.
    // (See `OrderReceipt::amount_microusd`.)
    if draft.side == Side::Sell {
        draft.amount_microusd = trade::usd_leg(&quote);
    }
    draft.tick_micro = snap.tick_micro;
    draft.min_order_size_micro = snap.min_size_micro;
    draft.neg_risk = snap.neg_risk;
    draft.active = snap.market.active;
    draft.closed = snap.market.closed;
    draft.order_book_enabled = snap.market.enable_order_book;
    draft.binary_outcomes = snap.market.is_binary();
    draft.best_ask_micro = snap.best_ask_micro;
    draft.best_bid_micro = snap.best_bid_micro;
    draft.book_snapshot_ms = now_ms();

    // Policy from *current* config and receipts; the draft snapshot is
    // display-only.
    let (checks, deny) = evaluate_policy(d, store, &draft)?;
    draft.policy_checks = serde_json::to_value(&checks)?;
    if deny {
        draft.status = DraftStatus::Rejected;
        draft.last_error = Some("policy denied".into());
        store.save_draft(&mut draft)?;
        store.audit(
            &draft.wallet,
            "policy_denied",
            serde_json::json!({ "draft_id": draft.id }),
        )?;
        println!("{}", render_plan_md(&draft));
        bail!(
            "policy denied (see checks above). Deny-level policy cannot be overridden \
             from the command line; edit the wallet's policy.toml to change it."
        );
    }
    if bloom_proto::has_warn(&checks) && !confirm_risk {
        store.save_draft(&mut draft)?;
        println!("{}", render_plan_md(&draft));
        bail!("policy warning requires explicit acknowledgement: re-run with --confirm-risk");
    }

    let creds_store = CredentialStore::new(d.home.polymarket_dir());
    let creds = creds_store.load(&draft.wallet)?.context(
        "wallet not onboarded (no CLOB credentials); run `bloom polymarket onboard` first",
    )?;
    let info = d.keystore.info(&draft.wallet)?;

    if draft.side == Side::Sell {
        verify_sell_preflight(
            d,
            pm_cfg.chain_id,
            &clob,
            &creds,
            &draft.wallet,
            info.address,
            tf.funder,
            &draft.token_id,
            draft.neg_risk,
            quote.size_micro,
        )
        .await?;
    }

    // Build the passkey review intent from the FINAL revalidated draft (market,
    // book, policy already re-checked above) — one intent per signature, built
    // immediately before unlock.
    let intent = order_review_intent(&draft);
    let review_hash = intent.intent_hash();
    // Persist the FULL reviewed intent (re-readable audit record) + carry the
    // short hash on the draft (and later the receipt) for quick queries.
    // The persisted intent is the durable audit record (the short hash alone is
    // not one). A write failure must not pass silently — warn loudly; the order
    // still proceeds because blocking an in-flight trade on an audit-log write
    // failure would be its own hazard.
    match serde_json::to_value(&intent) {
        Ok(intent_json) => {
            if let Err(e) = store.save_review_intent(&draft.wallet, &draft.id, &intent_json) {
                eprintln!(
                    "warning: failed to persist the reviewed order intent for draft {} \
                     ({e}); proceeding, but the durable audit record will be incomplete",
                    draft.id
                );
            }
        }
        Err(e) => eprintln!(
            "warning: could not serialize the review intent for draft {} ({e}); \
             the durable audit record will be incomplete",
            draft.id
        ),
    }
    draft.review_intent_hash = Some(review_hash.clone());
    store.save_draft(&mut draft)?;
    println!("{}", render_plan_md(&draft));
    println!("signing exactly the order above (passkey review hash {review_hash}).");
    if let Err(e) = store.audit(
        &draft.wallet,
        "passkey_review_presented",
        serde_json::json!({
            "draft_id": draft.id,
            "intent_hash": review_hash,
            "review_intent_path": store
                .review_intent_path(&draft.wallet, &draft.id)
                .display()
                .to_string(),
        }),
    ) {
        eprintln!(
            "warning: failed to record the passkey_review_presented audit for \
             draft {} ({e}); proceeding (the persisted review intent remains the \
             durable record)",
            draft.id
        );
    }

    // Build the order (salt + timestamp) BEFORE the ceremony so the sealed
    // approval binds the exact POLY_1271 signing hash being authorized.
    let owner = info.address;
    let signed = order::build_order(&OrderParams {
        token_id: draft.token_id.parse::<U256>().context("parse token id")?,
        // Maker/funder: the deposit wallet (sigtype 3). The owner EOA key
        // signs the wrapped POLY_1271 authorization below.
        maker: tf.funder,
        quote,
        builder_code: None,
        signature_type: tf.signature_type,
    });
    let salt: u64 = signed
        .salt
        .try_into()
        .map_err(|_| anyhow::anyhow!("internal error: order salt does not fit u64"))?;
    // Persist the salt BEFORE signing (so a lost POST can still be reconciled),
    // but do NOT claim the order is signed — the signature does not exist yet.
    // Status stays `Draft`; a `signing_prepared` marker records the checkpoint.
    draft.salt = Some(salt);
    store.save_draft(&mut draft)?;
    store.audit(
        &draft.wallet,
        "signing_prepared",
        serde_json::json!({ "draft_id": draft.id, "salt": salt, "signature_type": tf.signature_type }),
    )?;

    // Ceremony last.
    let sig = if info.kind == bloom_keystore::WalletKind::PasskeyGated {
        // Sealed-approval lane: stage the order action, run the in-band
        // browser ceremony to mint a grant, then sign through the Bloom
        // Machine host — raw keystore signer material never touches this
        // path (mirrors the EVM outbox confirm flow).
        let now = now_ms_u64();
        let action = bloom_polymarket::signing::order_action_and_hash(
            &signed,
            pm_cfg.chain_id,
            draft.neg_risk,
            draft.order_type,
        );
        let plan = pm_sealed::polymarket_order_plan(
            draft.side,
            Some(draft.slug.as_str()),
            tf.funder,
            draft.neg_risk,
            pm_cfg.chain_id,
            &action.signing_hash,
        );
        let sealed = pm_sealed::polymarket_order_sealed_action(
            &draft.wallet,
            &action.order_view,
            &action.signing_hash,
            pm_cfg.chain_id,
            draft.neg_risk,
            plan,
            now,
        )?;
        let action_id = sealed.action_id().to_string();
        ensure_sealed_polymarket_grant(d, &draft.wallet, sealed, Some(intent)).await?;
        pm_sealed::host_sign_polymarket_order_hash(
            d.auth_services
                .require_petal_host()
                .context("Sealed Approval petal host is not wired")?
                .as_ref(),
            &draft.wallet,
            &action_id,
            &signed,
            &action.signing_hash,
            pm_cfg.chain_id,
            draft.neg_risk,
            now_ms_u64(),
        )
        .await
        .context("sign order via Sealed Approval host")?
    } else {
        unlock_wallet_with_intent(d, &draft.wallet, passphrase, Some(intent)).await?;
        let signer = KeystoreSigner::new(d.keystore.signer(&draft.wallet)?);
        ensure!(
            signer.address() == owner,
            "unlocked signer address changed during order preflight"
        );
        order::sign_order_for_type(&signed, &signer, pm_cfg.chain_id, draft.neg_risk)
            .await
            .context("sign order")?
    };

    // The signature now exists — only now is the order durably "signed".
    draft.status = DraftStatus::Signed;
    store.save_draft(&mut draft)?;
    store.audit(
        &draft.wallet,
        "order_signed",
        serde_json::json!({ "draft_id": draft.id, "salt": salt, "signature_type": tf.signature_type }),
    )?;
    let body = order::OrderBody::from_signed(&signed, &sig, &creds.key, draft.order_type)
        .context("build order body")?;

    match clob.post_order(&creds, owner, &body).await {
        Ok(resp) => {
            let clob_status = resp
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("posted")
                .to_string();
            let order_id = resp
                .get("orderID")
                .or_else(|| resp.get("orderId"))
                .and_then(|s| s.as_str())
                .map(str::to_string);
            let filled = resp
                .get("takingAmount")
                .or_else(|| resp.get("makingAmount"))
                .and_then(|s| s.as_str())
                .and_then(|s| order::parse_micro(s).ok());
            write_outcome(
                store,
                &mut draft,
                DraftStatus::Posted,
                &clob_status,
                order_id.clone(),
                filled,
                resp.clone(),
                salt,
            )?;
            print_outcome(&draft, &clob_status, order_id.as_deref());
            Ok(())
        }
        // Definitive rejection from the CLOB: record it, no retry.
        Err(bloom_polymarket::PolymarketError::Api { status, body }) => {
            write_outcome(
                store,
                &mut draft,
                DraftStatus::Rejected,
                "rejected",
                None,
                None,
                serde_json::json!({ "http_status": status, "body": body }),
                salt,
            )?;
            bail!("CLOB rejected the order (HTTP {status}): {body}");
        }
        // Transport-level failure after the POST may have left the box:
        // never retry blindly. Reconcile against open orders by salt/fields.
        Err(e) => {
            eprintln!("warning: POST /order outcome unknown ({e}); reconciling via open orders");
            match reconcile(&clob, &creds, owner, &draft, salt).await {
                Ok(Some(order_id)) => {
                    write_outcome(
                        store,
                        &mut draft,
                        DraftStatus::Posted,
                        "live",
                        Some(order_id.clone()),
                        None,
                        serde_json::json!({ "reconciled": true }),
                        salt,
                    )?;
                    print_outcome(&draft, "live (reconciled)", Some(&order_id));
                    Ok(())
                }
                Ok(None) | Err(_) => {
                    write_outcome(
                        store,
                        &mut draft,
                        DraftStatus::Ambiguous,
                        "ambiguous",
                        None,
                        None,
                        serde_json::json!({ "error": e.to_string() }),
                        salt,
                    )?;
                    bail!(
                        "order outcome is AMBIGUOUS: the POST failed in transit and the order \
                         was not found among open orders. Do NOT retry blindly — check \
                         account orders.json and the receipt for draft {} first.",
                        draft.id
                    );
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_outcome(
    store: &OrderStore,
    draft: &mut OrderDraft,
    status: DraftStatus,
    clob_status: &str,
    order_id: Option<String>,
    filled_size_micro: Option<u64>,
    raw: serde_json::Value,
    salt: u64,
) -> Result<()> {
    draft.status = status;
    draft.clob_status = Some(clob_status.to_string());
    draft.clob_order_id = order_id.clone();
    if status == DraftStatus::Rejected {
        draft.last_error = Some(clob_status.to_string());
    }
    store.save_draft(draft)?;
    store.save_receipt(&OrderReceipt {
        draft_id: draft.id.clone(),
        wallet: draft.wallet.clone(),
        slug: draft.slug.clone(),
        token_id: draft.token_id.clone(),
        side: draft.side,
        order_type: draft.order_type,
        funder: draft.funder.clone(),
        signature_type: draft.signature_type,
        amount_microusd: draft.amount_microusd,
        limit_price_micro: draft.limit_price_micro,
        size_micro: draft.size_micro,
        salt,
        clob_order_id: order_id,
        clob_status: clob_status.to_string(),
        filled_size_micro,
        raw_response: raw,
        review_intent_hash: draft.review_intent_hash.clone(),
        posted_ms: now_ms(),
    })?;
    Ok(())
}

fn print_outcome(draft: &OrderDraft, clob_status: &str, order_id: Option<&str>) {
    let verdict = match clob_status {
        "matched" => "FILLED (matched immediately)",
        "delayed" => "DELAYED — not yet executed; check account orders.json",
        "unmatched" => "NOT FILLED (killed; nothing rests, nothing spent)",
        "live" | "live (reconciled)" => {
            "RESTING on the book — cancel with `bloom polymarket cancel`"
        }
        other => other,
    };
    println!(
        "order {}: {} (clob status: {clob_status}{})",
        draft.id,
        verdict,
        order_id.map(|i| format!(", id {i}")).unwrap_or_default()
    );
    println!(
        "receipt: polymarket/trade/{}/receipts/{}/receipt.json",
        draft.wallet, draft.id
    );
}

/// Look for our order among open orders after an ambiguous POST.
async fn reconcile(
    clob: &ClobClient,
    creds: &bloom_polymarket::Credentials,
    owner: alloy::primitives::Address,
    draft: &OrderDraft,
    salt: u64,
) -> Result<Option<String>> {
    let open = clob.open_orders(creds, owner).await?;
    let arr = match open.as_array() {
        Some(a) => a.as_slice(),
        None => return Ok(None),
    };
    Ok(reconcile_match(arr, draft, salt))
}

/// Pure matcher (unit-tested without network): identify *our* order among the
/// account's open orders. A `salt` echo is conclusive and wins immediately.
/// Absent a salt echo, fall back to token + side + price **+ size**, and only
/// when **exactly one** open order matches — two or more candidates at the same
/// token/side/price/size are ambiguous, so we refuse to guess (the caller marks
/// the outcome `Ambiguous` rather than attaching a possibly-wrong order id).
fn reconcile_match(arr: &[serde_json::Value], draft: &OrderDraft, salt: u64) -> Option<String> {
    let side_str = match draft.side {
        Side::Buy => "BUY",
        Side::Sell => "SELL",
    };
    let id_of = |o: &serde_json::Value| -> String {
        o.get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_default()
    };
    let token_of = |o: &serde_json::Value| {
        o.get("asset_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    let price_micro_of = |o: &serde_json::Value| {
        o.get("price")
            .and_then(|v| v.as_str())
            .and_then(|p| order::parse_micro(p).ok())
    };
    // Open orders report the full order size as `original_size` (fall back to
    // `size`); compare against the signed share size in micro-units.
    let size_micro_of = |o: &serde_json::Value| {
        o.get("original_size")
            .or_else(|| o.get("size"))
            .and_then(|v| v.as_str())
            .and_then(|s| order::parse_micro(s).ok())
    };

    // 1) Conclusive: a salt echo on an order for our token.
    for o in arr {
        if token_of(o).as_deref() != Some(draft.token_id.as_str()) {
            continue;
        }
        let salt_match = o
            .get("salt")
            .map(|v| v.as_u64() == Some(salt) || v.as_str() == Some(&salt.to_string()))
            .unwrap_or(false);
        if salt_match {
            return Some(id_of(o));
        }
    }

    // 2) Fallback: token + side + price + size, accepted only if unique.
    let mut candidates = arr.iter().filter(|o| {
        token_of(o).as_deref() == Some(draft.token_id.as_str())
            && o.get("side").and_then(|v| v.as_str()) == Some(side_str)
            && price_micro_of(o) == Some(draft.limit_price_micro)
            && size_micro_of(o) == Some(draft.size_micro)
    });
    match (candidates.next(), candidates.next()) {
        (Some(only), None) => Some(id_of(only)),
        // zero matches, or two-plus ambiguous matches → refuse to guess.
        _ => None,
    }
}

/// Holdings gate for sell-to-close. The **exact on-chain ERC-1155 balance**
/// (integer micro-units) is authoritative; the Data API (which reports sizes as
/// f64) is only a fallback for when no settlement chain client is configured,
/// and even then the size is parsed through a decimal string rather than lossy
/// float arithmetic. Holdings live at the funder (deposit wallet).
async fn verify_holdings(
    d: &Daemon,
    chain_id: u64,
    holder: &alloy::primitives::Address,
    token_id: &str,
    size_micro: u64,
) -> Result<()> {
    // Resolve the settlement chain by id, not by config name — the same rule
    // `fund` uses — so a Polygon chain configured under any `[chains.*]` name
    // still reaches the authoritative on-chain CTF balance.
    let settlement = d
        .chains
        .list_names()
        .into_iter()
        .filter_map(|n| d.chains.get(&n))
        .find(|c| c.spec().chain_id == chain_id);
    let held_micro = match settlement {
        Some(chain) => {
            let tid = U256::from_str_radix(token_id, 10)
                .with_context(|| format!("parse CTF token id {token_id}"))?;
            let held = chain
                .erc1155_balance_of(CTF, *holder, tid)
                .await
                .context("read on-chain CTF balance for the sell holdings guard")?
                .ok_or_else(|| {
                    anyhow::anyhow!("CTF balanceOf reverted while checking sell holdings")
                })?;
            u64::try_from(held).context(
                "on-chain CTF balance exceeds u64; refusing to compare sell share amount",
            )?
        }
        None => {
            // No settlement chain configured: fall back to the Data API, parsing
            // the position size through its decimal string (no float math). A
            // size that cannot be parsed reads as zero holdings — fail safe.
            let data = DataClient::new();
            let holder_str = bloom_proto::checksum_address(holder);
            let positions = data.positions(&holder_str).await.with_context(|| {
                format!(
                    "Data API holdings check failed (no [chains.*] entry with chain_id \
                     {chain_id} for the authoritative on-chain balance)"
                )
            })?;
            let held = positions
                .iter()
                .find(|p| p.asset == token_id)
                .and_then(|p| p.size)
                .unwrap_or(0.0);
            order::parse_micro(&format!("{held}")).unwrap_or(0)
        }
    };
    if held_micro < size_micro {
        bail!(
            "cannot sell {} shares: position holds only {}",
            order::format_micro(size_micro),
            order::format_micro(held_micro)
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn verify_sell_preflight(
    d: &Daemon,
    chain_id: u64,
    clob: &ClobClient,
    creds: &bloom_polymarket::Credentials,
    wallet: &str,
    owner: Address,
    deposit_wallet: Address,
    token_id: &str,
    neg_risk: bool,
    size_micro: u64,
) -> Result<()> {
    verify_holdings(d, chain_id, &deposit_wallet, token_id, size_micro).await?;

    let operator = if neg_risk {
        NEG_RISK_EXCHANGE
    } else {
        CTF_EXCHANGE
    };
    let chain = d
        .chains
        .get("polygon")
        .context("chain 'polygon' is required for Polymarket sell preflight")?;
    let approved = chain
        .is_approved_for_all(CTF, deposit_wallet, operator)
        .await
        .context("check CTF approval for sell preflight")?
        .ok_or_else(|| anyhow::anyhow!("CTF isApprovedForAll reverted during sell preflight"))?;
    if !approved {
        bail!(
            "cannot sell before passkey: deposit wallet {} has not approved {} for CTF \
             tokens. Re-run `bloom polymarket onboard {wallet}` to restore approvals.",
            bloom_proto::checksum_address(&deposit_wallet),
            bloom_proto::checksum_address(&operator)
        );
    }

    clob.update_conditional_balance_allowance(creds, owner, token_id, order::SIG_TYPE_POLY_1271)
        .await
        .with_context(|| {
            format!(
                "CLOB conditional balance/allowance update failed for token {token_id}; \
                 refusing before passkey"
            )
        })?;
    let _ = clob
        .conditional_balance_allowance(creds, owner, token_id, order::SIG_TYPE_POLY_1271)
        .await
        .with_context(|| {
            format!(
                "CLOB conditional balance/allowance read failed for token {token_id}; \
                 refusing before passkey"
            )
        })?;

    Ok(())
}

/// Passkey review intent for a Polymarket order/sell, built from the final
/// revalidated draft. BUY → `PolymarketOrder`, SELL → `PolymarketSell`. The
/// canonical (hashed) subject uses integer money (micro-USD / micro-price /
/// micro-shares) so the hash is stable and reproducible for audit.
fn order_review_intent(d: &bloom_polymarket::OrderDraft) -> bloom_proto::CeremonyIntent {
    use bloom_polymarket::order::format_micro;
    use bloom_polymarket::types::Side;
    let (kind, verb) = match d.side {
        Side::Buy => (bloom_proto::CeremonyIntentKind::PolymarketOrder, "BUY"),
        Side::Sell => (bloom_proto::CeremonyIntentKind::PolymarketSell, "SELL"),
    };
    let title = match d.side {
        Side::Buy => "Place Polymarket Order",
        Side::Sell => "Sell Polymarket Position",
    };
    let bound_label = match d.side {
        Side::Buy => "max price",
        Side::Sell => "min price",
    };
    bloom_proto::CeremonyIntent::new(&d.wallet, title, kind)
        .with_address(&d.owner)
        .summary(format!("Market: {}", d.question))
        .summary(format!("Slug: {}", d.slug))
        .summary(format!("{verb} {} (token {})", d.outcome, d.token_id))
        .summary(format!(
            "{} shares @ {} = {} pUSD ({})",
            format_micro(d.size_micro),
            format_micro(d.limit_price_micro),
            format_micro(d.amount_microusd),
            d.order_type.as_str(),
        ))
        .summary(format!(
            "{bound_label}: {}",
            format_micro(d.price_bound_micro)
        ))
        .summary(format!(
            "Maker/funder: {} (signatureType {})",
            d.funder.as_deref().unwrap_or(&d.owner),
            d.signature_type,
        ))
        .risk("This ceremony signs and posts the order shown above.")
        .artifact(format!(
            "polymarket/trade/{}/drafts/{}/plan.md",
            d.wallet, d.id
        ))
        .subject(serde_json::json!({
            "action": "polymarket_order",
            "side": verb,
            "slug": d.slug,
            "condition_id": d.condition_id,
            "token_id": d.token_id,
            "outcome": d.outcome,
            "order_type": d.order_type.as_str(),
            "neg_risk": d.neg_risk,
            "maker": d.funder.as_deref().unwrap_or(&d.owner),
            "signature_type": d.signature_type,
            "size_micro": d.size_micro,
            "limit_price_micro": d.limit_price_micro,
            "price_bound_micro": d.price_bound_micro,
            "amount_microusd": d.amount_microusd,
        }))
}

/// Unlock the wallet and, for passkey wallets, show a concrete passkey review
/// page for the specific action being authorized. One reviewed intent per
/// signature: the caller builds the intent from the **final, revalidated**
/// values immediately before this call.
async fn unlock_wallet_with_intent(
    d: &Daemon,
    wallet: &str,
    passphrase: Option<&str>,
    intent: Option<bloom_proto::CeremonyIntent>,
) -> Result<()> {
    let info = d.keystore.info(wallet)?;
    match info.kind {
        bloom_keystore::WalletKind::PasskeyGated => {
            if intent.is_some() {
                d.keystore.lock(wallet);
            } else if d.keystore.is_unlocked(wallet) {
                return Ok(());
            }
            d.keystore
                .unlock_passkey_with_intent(wallet, intent)
                .await?;
        }
        _ => {
            if d.keystore.is_unlocked(wallet) {
                return Ok(());
            }
            d.keystore.unlock(wallet, passphrase.unwrap_or(""))?;
        }
    }
    Ok(())
}

/// Stage `sealed` and ensure a live Sealed Approval grant exists for it,
/// running the in-band browser ceremony when none does — the same
/// stage → challenge → ceremony → grant flow the EVM outbox confirm loop
/// drives (main.rs `sign_outbox_sealed_approval_if_challenged`). Passkey
/// wallets only: local password wallets cannot produce sealed approvals and
/// stay on the passphrase-unlock lane at each call site.
async fn ensure_sealed_polymarket_grant(
    d: &Daemon,
    wallet: &str,
    sealed: bloom_auth_api::SealedAction,
    intent: Option<bloom_proto::CeremonyIntent>,
) -> Result<bloom_auth_api::SealedApprovalGrant> {
    use base64::Engine as _;

    let now = now_ms_u64();
    let action_id = sealed.action_id().to_string();
    let petal_id = sealed.petal_id().to_string();
    let petal_digest = sealed.petal_digest().to_string();
    let writer = d
        .auth_services
        .require_writer()
        .context("Sealed Approval auth store writer is not wired")?;
    writer
        .stage_action(sealed, now)
        .await
        .context("stage Polymarket sealed action")?;
    if let Some(grant) = d
        .auth_services
        .require_grant_store()
        .context("Sealed Approval grant store is not wired")?
        .get_active(wallet, &action_id, &petal_id, &petal_digest, now)
        .await
        .context("lookup Polymarket grant")?
    {
        return Ok(grant);
    }
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let challenge = writer
        .issue_challenge(
            pm_sealed::POLYMARKET_SURFACE,
            &action_id,
            &nonce_b64,
            now.saturating_add(pm_sealed::APPROVAL_TTL_MS),
            now,
        )
        .await
        .context("issue Polymarket approval challenge")?;
    let review_session_id = if challenge.assurance == bloom_auth_api::AssuranceLevel::Hardened {
        let review_session_id = crate::sealed_review_session_id(&challenge);
        writer
            .issue_review_session(
                &review_session_id,
                &challenge.surface,
                &challenge.action_id,
                challenge.expiry_ms,
                now,
            )
            .await
            .context("issue hardened review session")?;
        Some(review_session_id)
    } else {
        None
    };
    let unsigned = bloom_auth_api::UnsignedApproval::for_challenge(
        &challenge,
        bloom_auth_api::SignerTransport::BrowserWebauthn,
        None,
        review_session_id,
    );
    let (grant, _approval) = bloom_daemon::sealed_ceremony::run_sealed_approval_ceremony(
        &d.keystore,
        &d.auth_services,
        unsigned,
        intent,
        now,
        d.signer_cache.as_ref(),
    )
    .await
    .context("run sealed approval browser ceremony")?;
    Ok(grant)
}

/// Owner-signing adapter that signs through `PetalHost::sign_hash` under the
/// live grant for `action_id` (minted by `ensure_sealed_polymarket_grant`).
fn sealed_polymarket_signer(
    d: &Daemon,
    wallet: &str,
    action_id: String,
    kind: PolymarketSealedActionKind,
    owner: Address,
) -> Result<pm_sealed::SealedOnboardSigner> {
    let host = d
        .auth_services
        .require_petal_host()
        .context("Sealed Approval petal host is not wired")?
        .clone();
    Ok(pm_sealed::SealedOnboardSigner::new(
        host, wallet, action_id, kind, owner,
    ))
}

/// Arguments for `bloom polymarket onboard`.
pub struct OnboardArgs {
    pub wallet: String,
    /// When set, the `fund` stage is satisfied automatically by swapping
    /// native into pUSD up to this target — at most once per invocation.
    pub target_pusd: Option<String>,
    /// Input-spend bound for the auto-funding swap. Required with
    /// `--target-pusd`.
    pub max_spend: Option<String>,
    pub slippage_bps: u16,
    pub confirm_risk: bool,
    pub passphrase: Option<String>,
}

/// `bloom polymarket onboard`: run the onboarding state machine to
/// completion, optionally funding pUSD in-line (at most once). Geoblock is
/// fail-closed; the approval scope is disclosed before any ceremony.
pub async fn onboard(d: &Daemon, args: OnboardArgs) -> Result<()> {
    use bloom_vfs::handlers::polymarket::build_onboarder;

    let pm_cfg = d
        .config
        .polymarket
        .as_ref()
        .context("no [polymarket] block in config.toml")?;

    if args.target_pusd.is_some() && args.max_spend.is_none() {
        bail!("--max-spend is required with --target-pusd (it bounds the swap's input side)");
    }
    if pm_cfg.legacy_eoa_mode {
        bail!(
            "[polymarket].legacy_eoa_mode is no longer supported for trading. \
             Remove that setting and re-run `bloom polymarket onboard {}` to use \
             deposit-wallet mode.",
            args.wallet
        );
    }

    let info = d.keystore.info(&args.wallet)?;

    // Disclose what onboarding will authorize BEFORE the ceremony.
    println!("onboarding '{}' (owner {})", args.wallet, info.address);
    println!("mode: deposit wallet (signatureType 3) — the trading path");
    if pm_cfg.relayer_api_key.is_none() && pm_cfg.builder_key_mode == "auto" {
        println!(
            "relayer auth: bloom will create a Polymarket builder API key from this \
             wallet's\nCLOB credentials (no website visit). It authenticates relayer \
             SUBMISSION only —\nit can never move funds; every wallet operation still \
             carries your signature.\nRevoke anytime: `bloom polymarket builder-keys \
             revoke {}`",
            args.wallet
        );
    }
    println!(
        "approvals: the exchange approvals are granted from the deposit wallet \
         (one\nsigned relayer batch) unless on-chain reads show them already in place."
    );

    // Onboarding unlocks the key once for a multi-step run (deploy, approvals,
    // credential mint, sync) that produces several relayer/CLOB signatures.
    // The review page is labelled honestly as that whole flow; per-signature
    // review of the deposit-wallet approval batch is the deposit-wallet-batch
    // follow-up (decode the 8 known calls).
    // Onboarding is a single unlock that authorizes a MULTI-SIGNATURE run, so
    // it must read as higher-risk than a plain wallet unlock: name it as a run
    // and enumerate the operations it may request. (Each later signature still
    // gets its own intent where the command builds one; the deposit-wallet
    // approval batch's per-call labels are a tracked follow-up.)
    let mut intent = bloom_proto::CeremonyIntent::new(
        &args.wallet,
        "Unlock for Polymarket Onboarding Run",
        bloom_proto::CeremonyIntentKind::WalletUnlock,
    )
    .with_address(bloom_proto::checksum_address(&info.address))
    .summary("This unlock authorizes a multi-step run, not a single action.".to_string())
    .summary("The run may request these operations:".to_string())
    .risk("HIGHER RISK: one approval, several signatures across the run.");
    intent = intent
        .summary("  • deploy your deposit wallet (gasless relayer)".to_string())
        .summary("  • grant the 8 exchange approvals from the deposit wallet".to_string());
    if args.target_pusd.is_some() {
        intent = intent
            .summary("  • fund pUSD up to the requested target (separate review)".to_string());
    }
    let intent = intent
        .summary("  • mint CLOB API credentials (signed attestation)".to_string())
        .summary("  • sync buying power".to_string())
        .subject(serde_json::json!({
            "action": "polymarket_onboard_run",
            "owner": bloom_proto::checksum_address(&info.address),
            "mode": "deposit_wallet",
            "target_pusd": args.target_pusd.is_some(),
        }));
    let passkey_wallet = info.kind == bloom_keystore::WalletKind::PasskeyGated;
    // For passkey wallets, skip the standalone unlock ceremony — each run in
    // the loop below is authorized by an in-band sealed-approval ceremony
    // that mints an onboarding grant (max 3 signatures) and signs via
    // `PetalHost::sign_hash`. For local wallets, the passphrase unlock stays
    // the signing mechanism (they cannot produce sealed approvals).
    let signer: Box<dyn OnboardSigner> = if passkey_wallet {
        Box::new(sealed_polymarket_signer(
            d,
            &args.wallet,
            pm_sealed::polymarket_onboard_action_id(&args.wallet),
            PolymarketSealedActionKind::Onboarding,
            info.address,
        )?)
    } else {
        unlock_wallet_with_intent(
            d,
            &args.wallet,
            args.passphrase.as_deref(),
            Some(intent.clone()),
        )
        .await?;
        Box::new(KeystoreSigner::new(d.keystore.signer(&args.wallet)?))
    };

    let (_, chain) = d
        .chains
        .list_names()
        .into_iter()
        .filter_map(|n| d.chains.get(&n).map(|c| (n, c)))
        .find(|(_, c)| c.spec().chain_id == pm_cfg.chain_id)
        .with_context(|| {
            format!(
                "no [chains.*] entry with chain_id {} (Polymarket settlement chain)",
                pm_cfg.chain_id
            )
        })?;
    let state_dir = d.home.polymarket_dir();
    let onboarder = build_onboarder(pm_cfg, chain, &state_dir);

    // Progress + disclosure events printed as they happen.
    let print_events: &bloom_polymarket::onboard::OnEvent = &|e| match e {
        bloom_polymarket::OnboardEvent::BuilderKeyCreating => {
            println!(
                "creating builder API key (relayer submission auth only; cannot move \
                 funds; revocable via `bloom polymarket builder-keys revoke`)…"
            );
        }
        bloom_polymarket::OnboardEvent::BuilderKeyCreated { key } => {
            println!("builder API key created: {key} (key id only; secret stored 0600)");
        }
        bloom_polymarket::OnboardEvent::CredsMinted { api_key } => {
            println!("CLOB credentials minted (key id {api_key})");
        }
        bloom_polymarket::OnboardEvent::RelayerSubmitted { kind, tx_id } => {
            println!("relayer {kind} submitted: {tx_id}");
        }
        bloom_polymarket::OnboardEvent::RelayerConfirmed {
            kind,
            tx_id,
            tx_hash,
        } => {
            println!(
                "relayer {kind} confirmed: {tx_id}{}",
                tx_hash.map(|h| format!(" ({h})")).unwrap_or_default()
            );
        }
        bloom_polymarket::OnboardEvent::OnchainSubmitted { kind, tx_hash } => {
            println!("on-chain {kind} submitted: {tx_hash}");
        }
        bloom_polymarket::OnboardEvent::OnchainConfirmed { kind, tx_hash } => {
            println!("on-chain {kind} confirmed: {tx_hash}");
        }
        bloom_polymarket::OnboardEvent::StageDone(s) => {
            println!("stage done: {}", s.as_str());
        }
    };
    let noop: &bloom_polymarket::onboard::OnEvent = print_events;
    // At-most-once funding fuse: a second arrival at `fund` in the same
    // invocation must never trigger another swap (stale RPC reads or CLOB
    // sync lag would otherwise drain the wallet through repeat funding).
    let mut funded_this_run = false;
    loop {
        // A multi-step onboarding run can outlive one grant's TTL / signature
        // budget; re-ensure a live grant before each pass (idempotent stage,
        // ceremony only when no grant is active).
        if passkey_wallet {
            let sealed = pm_sealed::polymarket_onboard_sealed_action(
                &args.wallet,
                info.address,
                now_ms_u64(),
            )?;
            ensure_sealed_polymarket_grant(d, &args.wallet, sealed, Some(intent.clone())).await?;
        }
        let st = onboarder
            .run(&args.wallet, signer.as_ref(), noop)
            .await
            .context("onboarding run")?;
        if st.stage != bloom_polymarket::Stage::Fund {
            println!("onboarding: stage={}", st.stage.as_str());
            return Ok(());
        }

        let Some(target) = args.target_pusd.clone() else {
            println!("onboarding paused: stage=fund");
            println!("funding address: {}", st.deposit_wallet);
            println!(
                "either send pUSD there directly, or run:\n  bloom polymarket fund {} \
                 --target-pusd <amount> --max-spend <native-amount>\nthen re-run this command \
                 (or pass --target-pusd/--max-spend here to do it in one go).",
                args.wallet
            );
            return Ok(());
        };
        if funded_this_run {
            bail!(
                "onboarding returned to the 'fund' stage after a completed funding pass — \
                 refusing to swap again automatically (at-most-once guard). Check the pUSD \
                 balance of {} and CLOB sync, then re-run.",
                st.deposit_wallet
            );
        }
        // Consume the fuse before broadcasting anything.
        funded_this_run = true;
        fund(
            d,
            FundArgs {
                wallet: args.wallet.clone(),
                target_pusd: target,
                from_token: None,
                max_spend: args
                    .max_spend
                    .clone()
                    .expect("checked above: max_spend present with target_pusd"),
                slippage_bps: args.slippage_bps,
                dry_run: false,
                confirm_risk: args.confirm_risk,
                passphrase: args.passphrase.clone(),
            },
        )
        .await
        .context("auto-funding pass")?;
        // Loop: re-run the state machine (fund → approve → creds → sync).
    }
}

/// Arguments for `bloom polymarket fund`.
pub struct FundArgs {
    pub wallet: String,
    /// Target pUSD balance at the funding address (decimal). The command is
    /// target-denominated: "after this, hold at least N pUSD" — never "spend
    /// N of the input token".
    pub target_pusd: String,
    /// Input token: "native"/"POL"/"MATIC" (default) or an ERC-20 `0x…`
    /// address on the settlement chain.
    pub from_token: Option<String>,
    /// Hard bound on input spend, in input-token units (decimal). Required —
    /// the route quote decides the actual input, this caps it.
    pub max_spend: String,
    /// Route slippage bound in basis points (default 50 = 0.5%).
    pub slippage_bps: u16,
    /// Stage the swap (plan + outbox) and stop before any signature.
    pub dry_run: bool,
    /// Acknowledge EVM policy warnings on the staged transactions.
    pub confirm_risk: bool,
    pub passphrase: Option<String>,
}

/// `bloom polymarket fund`: swap into pUSD until the funding address holds
/// the target, through the standard TxEngine stage→confirm path so EVM
/// policy, plan rendering, outbox audit, and `allow_broadcast` gates all
/// apply unchanged. Works without `bloom serve` and without `defi/intents`
/// sessions.
///
/// **Boundary with the `[defi]` route policy** (B2): this command is the
/// purpose-built funding path with its own validated checks (token-out is
/// pinned to pUSD, receiver is the resolved funding address, router invariants
/// asserted here). It deliberately does **not** route through the generic
/// `DefiHandler`/`defi/intents` surface and is therefore **not** gated by
/// `[defi] enabled` — so adding the (default-disabled) `[defi]` policy never
/// breaks funding. The `[defi]` gate governs the open-ended route surface only.
/// Execute a fund request previously staged via the VFS
/// (`polymarket/fund/<wallet>/new`). Sources the swap parameters from the stored
/// request, then runs the normal value-moving [`fund`] flow — which re-reads the
/// live pUSD balance and route quote, so a stale staged number is never trusted.
/// On a non-dry-run success the request is marked `executed`. The VFS surface
/// only *stages*; this (and `fund` / `onboard --target-pusd`) is the value-mover.
pub async fn fund_from_request(
    d: &Daemon,
    wallet: &str,
    request_id: &str,
    dry_run: bool,
    confirm_risk: bool,
    passphrase: Option<String>,
) -> Result<()> {
    bloom_polymarket::validate_wallet_name(wallet).map_err(|e| anyhow::anyhow!("{e}"))?;
    // Path-traversal guard (mirrors the VFS `validate_fund_id` rules).
    if request_id.is_empty()
        || request_id.contains('/')
        || request_id.contains('\\')
        || request_id == "."
        || request_id == ".."
    {
        bail!("invalid fund request id '{request_id}'");
    }
    let path = d
        .home
        .polymarket_dir()
        .join(wallet)
        .join("fund")
        .join("requests")
        .join(format!("{request_id}.json"));
    let bytes = std::fs::read(&path).with_context(|| {
        format!(
            "no staged fund request '{request_id}' for wallet '{wallet}' (looked in {})",
            path.display()
        )
    })?;
    let mut sess: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse staged fund request")?;

    let target_pusd = sess["target_pusd"]
        .as_str()
        .context("staged request missing target_pusd")?
        .to_string();
    let max_spend = sess["max_spend"]
        .as_str()
        .context("staged request missing max_spend")?
        .to_string();
    let from_token = sess["from_token"].as_str().map(str::to_string);
    let slippage_bps = u16::try_from(sess["slippage_bps"].as_u64().unwrap_or(50)).unwrap_or(50);
    if slippage_bps > MAX_FUND_SLIPPAGE_BPS {
        bail!(
            "staged request slippage_bps {slippage_bps} is too high (max \
             {MAX_FUND_SLIPPAGE_BPS} = 10%)"
        );
    }

    println!(
        "executing staged fund request {request_id} (target {target_pusd} pUSD, \
         max-spend {max_spend}, from {})",
        from_token.as_deref().unwrap_or("native")
    );
    fund(
        d,
        FundArgs {
            wallet: wallet.to_string(),
            target_pusd,
            from_token,
            max_spend,
            slippage_bps,
            dry_run,
            confirm_risk,
            passphrase,
        },
    )
    .await?;

    // Mark the staged request executed (best-effort, atomic rewrite). Skipped on
    // dry runs, which neither sign nor broadcast.
    if !dry_run {
        if let Some(o) = sess.as_object_mut() {
            o.insert("status".into(), serde_json::json!("executed"));
            o.insert("updated_ms".into(), serde_json::json!(now_ms()));
        }
        let tmp = path.with_extension("json.tmp");
        if serde_json::to_vec_pretty(&sess)
            .ok()
            .and_then(|b| std::fs::write(&tmp, b).ok())
            .is_some()
        {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
    Ok(())
}

pub async fn fund(d: &Daemon, args: FundArgs) -> Result<()> {
    use bloom_defi::{EnsoClient, NATIVE_TOKEN, RouteRequest};
    use bloom_polymarket::eip712::PUSD;
    use bloom_proto::intent::{GasStrategy, RawIntent, RawIntentBody};
    use bloom_proto::{PlanRender, PolicyOutcome, checksum_address, units};

    let pm_cfg = d
        .config
        .polymarket
        .as_ref()
        .context("no [polymarket] block in config.toml")?;
    if args.slippage_bps > MAX_FUND_SLIPPAGE_BPS {
        bail!(
            "--slippage-bps {} is too high (max {} = 10%)",
            args.slippage_bps,
            MAX_FUND_SLIPPAGE_BPS
        );
    }

    // Settlement chain by id, same selection rule as the daemon's onboarding.
    let (chain_name, chain) = d
        .chains
        .list_names()
        .into_iter()
        .filter_map(|n| d.chains.get(&n).map(|c| (n, c)))
        .find(|(_, c)| c.spec().chain_id == pm_cfg.chain_id)
        .with_context(|| {
            format!(
                "no [chains.*] entry with chain_id {} (Polymarket settlement chain)",
                pm_cfg.chain_id
            )
        })?;
    let spec = chain.spec().clone();

    let info = d.keystore.info(&args.wallet)?;
    let owner = info.address;
    // Funding target. Deposit-wallet mode reads the address from durable
    // onboarding state — it was resolved from the live factory at deploy time
    // (the local CREATE2 estimate has disagreed with the factory). Funding an
    // unverified address is unrecoverable, so deploy-before-fund is enforced
    // here too.
    let st = bloom_polymarket::OnboardStore::new(d.home.polymarket_dir())
        .load(&args.wallet)?
        .with_context(|| {
            format!(
                "deposit-wallet mode: run `bloom polymarket onboard {}` first — the \
                 deposit wallet must be deployed (and its address confirmed against \
                 the live factory) before any funds move",
                args.wallet
            )
        })?;
    if st.stage < bloom_polymarket::Stage::Fund {
        bail!(
            "onboarding for '{}' has not passed the deploy stage yet (stage: {}) — \
             deploy before funding",
            args.wallet,
            st.stage.as_str()
        );
    }
    // The deposit wallet is a function of the owner key; refuse to fund a
    // record that belongs to a different key (unrecoverable misdirection).
    ensure_onboard_owner(&st, owner)?;
    let funding_addr = st
        .deposit_wallet
        .parse()
        .context("corrupt deposit_wallet in onboarding state")?;

    let target_micro =
        bloom_polymarket::order::parse_micro(&args.target_pusd).context("parse --target-pusd")?;
    let pusd_now = chain
        .erc20_balance(PUSD, funding_addr)
        .await
        .context("read pUSD balance")?
        .unwrap_or_default();
    let target = U256::from(target_micro);
    if pusd_now >= target {
        println!(
            "already funded: {} holds {} pUSD (target {})",
            checksum_address(&funding_addr),
            units::format_units(pusd_now, 6),
            bloom_polymarket::order::format_micro(target_micro),
        );
        return Ok(());
    }
    let missing: u64 = (target - pusd_now)
        .try_into()
        .context("missing pUSD amount overflow")?;

    // Short-circuit: when the owner EOA already holds enough pUSD (e.g. it
    // was swapped there under the legacy flow), a plain ERC-20 transfer into
    // the deposit wallet is strictly better than another swap — no route, no
    // slippage, no thin-pool impact. Goes through the same TxEngine
    // stage→confirm gates.
    if funding_addr != owner {
        let eoa_pusd = chain
            .erc20_balance(PUSD, owner)
            .await
            .context("read owner pUSD balance")?
            .unwrap_or_default();
        if eoa_pusd >= U256::from(missing) {
            println!("funding plan: direct ERC-20 transfer (no swap, no approval)");
            println!("  token:     pUSD {PUSD:#x}");
            println!(
                "  from:      {} (owner EOA, holds {})",
                checksum_address(&owner),
                units::format_units(eoa_pusd, 6)
            );
            println!(
                "  recipient: {} (your deposit wallet)",
                checksum_address(&funding_addr)
            );
            println!(
                "  amount:    {} pUSD (target {})",
                bloom_polymarket::order::format_micro(missing),
                bloom_polymarket::order::format_micro(target_micro),
            );
            println!("  (--max-spend is unused here; it bounds only the swap fallback)");
            return transfer_pusd_to_funding(
                d,
                &args,
                &chain_name,
                &chain,
                &spec,
                &info,
                owner,
                funding_addr,
                missing,
                target_micro,
            )
            .await;
        }
    }

    // Input token + decimals.
    let (token_in, in_decimals, native_in) = match args.from_token.as_deref() {
        None => (
            NATIVE_TOKEN.parse::<alloy::primitives::Address>().unwrap(),
            18u8,
            true,
        ),
        Some(s) if ["native", "pol", "matic"].contains(&s.to_ascii_lowercase().as_str()) => {
            (NATIVE_TOKEN.parse().unwrap(), 18, true)
        }
        Some(addr) => {
            let token: alloy::primitives::Address = addr
                .parse()
                .context("--from-token must be 'native' or an 0x… ERC-20 address")?;
            let decimals = chain
                .erc20_decimals(token)
                .await
                .context("read token decimals")?
                .context("token has no decimals() — not an ERC-20?")?;
            (token, decimals, false)
        }
    };
    let max_spend = units::parse_units(&args.max_spend, in_decimals)
        .map_err(|e| anyhow::anyhow!("parse --max-spend: {e}"))?;
    if max_spend.is_zero() {
        bail!("--max-spend must be > 0");
    }

    // Balance check on the input side, before any quote.
    let in_balance = if native_in {
        chain.balance(owner).await.context("read native balance")?
    } else {
        chain
            .erc20_balance(token_in, owner)
            .await
            .context("read input token balance")?
            .unwrap_or_default()
    };
    if in_balance < max_spend {
        bail!(
            "input balance {} is below --max-spend {} — lower the bound or top up",
            units::format_units(in_balance, in_decimals),
            args.max_spend
        );
    }

    let enso_cfg = d
        .config
        .enso
        .as_ref()
        .context("no [enso] block in config.toml (api_key required for swap routing)")?;
    let mut enso = EnsoClient::new(enso_cfg.api_key.clone());
    if let Ok(u) = url::Url::parse(&enso_cfg.api_url) {
        enso = enso.with_base_url(u);
    }

    // Output-denominated sizing: quote at max spend to learn the rate, then
    // route only what the missing pUSD needs (+2% curvature pad), capped at
    // the user's bound.
    let req = |amount_in: U256| RouteRequest {
        from_address: owner,
        chain_id: pm_cfg.chain_id,
        destination_chain_id: None,
        token_in,
        token_out: PUSD,
        amount_in,
        slippage_bps: args.slippage_bps,
        routing_strategy: None,
        receiver: Some(funding_addr),
    };
    let probe = enso
        .quote(req(max_spend))
        .await
        .context("Enso quote at --max-spend")?;
    let out_at_max: u128 = probe
        .amount_out
        .parse()
        .context("parse Enso quote amount_out")?;
    if out_at_max < missing as u128 {
        bail!(
            "--max-spend {} only buys ~{} pUSD but {} is missing — raise the bound or fund less",
            args.max_spend,
            units::format_units(U256::from(out_at_max), 6),
            bloom_polymarket::order::format_micro(missing),
        );
    }
    let required_in = fund_required_input(max_spend, missing, out_at_max);

    let route = enso.route(req(required_in)).await.context("Enso route")?;
    // Route invariants, enforced before anything is staged:
    let route_out: u128 = route
        .amount_out
        .parse()
        .context("parse Enso route amount_out")?;
    if route_out < missing as u128 {
        bail!(
            "route output {} pUSD is below the missing {} — market moved; re-run",
            units::format_units(U256::from(route_out), 6),
            bloom_polymarket::order::format_micro(missing),
        );
    }
    // NOTE: `price_impact` is intentionally NOT a threshold here — its Enso
    // unit is unverified (raw values like 291/15 observed), so it is
    // display-only, matching the generic route surface (S1). It is shown in
    // the plan below labelled "Enso-reported".
    if native_in && route.tx.value != required_in {
        bail!(
            "route wants tx value {} but the computed input is {} — refusing mismatched calldata",
            route.tx.value,
            required_in
        );
    }
    if !native_in && route.tx.value != U256::ZERO {
        bail!("ERC-20 route unexpectedly attaches native value — refusing");
    }
    if route.tx.from != owner {
        bail!(
            "route sender {} does not match wallet owner {} — refusing mismatched route",
            checksum_address(&route.tx.from),
            checksum_address(&owner)
        );
    }
    if route
        .destination_chain_id
        .is_some_and(|id| id != pm_cfg.chain_id)
    {
        bail!(
            "route unexpectedly targets destination chain {:?}; Polymarket funding must settle on chain {}",
            route.destination_chain_id,
            pm_cfg.chain_id
        );
    }

    // Run the SAME route evaluator as the generic defi/intents surface, with a
    // purpose-built in-code policy (NOT the user's `[defi]` toml, which stays
    // default-deny and must never gate funding). This is a documented temporary
    // carve-out — narrower than any user [defi] could express — that shares the
    // evaluation mechanism rather than re-implementing it (B2). The funding
    // receiver is the authoritative resolved deposit-wallet address.
    let (protocols, protocols_unknown) = route.protocols();
    let receiver_lc = format!("0x{:x}", funding_addr);
    let token_out_lc = format!("0x{:x}", PUSD).to_lowercase();
    let router_lc = format!("0x{:x}", route.tx.to);
    let receiver_class = bloom_proto::ReceiverClass::PolymarketDepositWallet;
    let route_ctx = bloom_proto::DefiRouteCtx {
        wallet: args.wallet.clone(),
        source_chain: chain_name.clone(),
        destination_chain: chain_name.clone(),
        cross_chain: false,
        receiver: receiver_lc.clone(),
        token_out: token_out_lc.clone(),
        receiver_class,
        router: router_lc.clone(),
        protocols,
        protocols_unknown,
        input_microusd: None,
        native_value_wei: route.tx.value,
        // Min-output floor is still the Enso quote (not yet simulated) — leave it
        // unverified so the route warns until WP3 wires `/simulate` amounts.
        min_out_enforced: false,
        // Receiver: the WP0 calldata probe showed Enso encodes the requested
        // receiver verbatim in `tx.data`, so for a same-chain route confirm the
        // deposit wallet is actually in the bytes. Cross-chain (a bridge hop)
        // stays unverified — only destination settlement (WP5) can prove that.
        receiver_verified: route.destination_chain_id.is_none()
            && route.calldata_contains_receiver(funding_addr),
    };
    let fund_policy = fund_route_policy(&chain_name, &token_out_lc, &receiver_lc, &router_lc);
    let route_checks = bloom_proto::evaluate_defi_route(&fund_policy, &route_ctx);
    if let Some(deny) = route_checks
        .iter()
        .find(|c| c.outcome == PolicyOutcome::Deny)
    {
        bail!(
            "route policy denied [{}]: {} — funding refused",
            deny.rule,
            deny.message
        );
    }

    println!("funding plan:");
    if let Some(impact) = route.price_impact {
        println!("  price impact: {impact} (Enso-reported; unit unverified)");
    }
    println!("  receiver: {} ({})", receiver_lc, receiver_class.as_str());
    for c in &route_checks {
        let tag = match c.outcome {
            PolicyOutcome::Pass => "PASS",
            PolicyOutcome::Warn => "WARN",
            PolicyOutcome::Deny => "DENY",
        };
        println!("  [{tag}] {}: {}", c.rule, c.message);
    }
    println!("  funding address: {}", checksum_address(&funding_addr));
    println!(
        "  holds {} pUSD, target {}, missing {}",
        units::format_units(pusd_now, 6),
        bloom_polymarket::order::format_micro(target_micro),
        bloom_polymarket::order::format_micro(missing),
    );
    println!(
        "  swap: {} {} -> >= {} pUSD via Enso router {} (slippage bound {} bps, max spend {})",
        units::format_units(required_in, in_decimals),
        if native_in {
            spec.native_symbol.as_str()
        } else {
            "tokens"
        },
        units::format_units(U256::from(route_out), 6),
        checksum_address(&route.tx.to),
        args.slippage_bps,
        args.max_spend,
    );
    println!(
        "  note: the router contract is subject to this wallet's EVM policy \
         allow/deny lists, evaluated at staging below."
    );
    let route_warn = route_checks
        .iter()
        .any(|c| c.outcome == PolicyOutcome::Warn);
    if route_warn && !args.confirm_risk && !args.dry_run {
        bail!(
            "route policy raised warnings above; re-run with --confirm-risk to acknowledge \
             the quote-only receiver/min-output risk, or use --dry-run to inspect without \
             signing"
        );
    }

    // Stage through the standard engine: approval first when ERC-20 input.
    let mut intents: Vec<RawIntent> = Vec::new();
    if !native_in {
        let allowance = chain
            .erc20_allowance(token_in, owner, route.tx.to)
            .await
            .context("read allowance")?
            .unwrap_or_default();
        if allowance < required_in {
            intents.push(RawIntent {
                body: RawIntentBody::Approve {
                    token: checksum_address(&token_in),
                    spender: checksum_address(&route.tx.to),
                    // Exact-amount approval: tighter than max-approve.
                    amount: units::format_units(required_in, in_decimals),
                },
                chain: Some(chain_name.clone()),
                gas: GasStrategy::Auto,
                nonce: None,
                gas_limit_hint: None,
                usd_value_hint: None,
            });
        }
    }
    intents.push(RawIntent {
        body: RawIntentBody::Raw {
            to: checksum_address(&route.tx.to),
            value: route.tx.value.to_string(),
            data: format!("0x{}", hex::encode(route.tx.data.as_ref())),
        },
        chain: Some(chain_name.clone()),
        gas: GasStrategy::Auto,
        nonce: None,
        gas_limit_hint: route.gas.as_deref().and_then(|g| g.parse().ok()),
        usd_value_hint: None,
    });

    // Any bail after staging MUST discard the staged entries: pending outbox
    // entries feed the engine's nonce assignment, so abandoned ones make
    // every later broadcast a future-nonce tx that can never mine.
    let discard = |ids: &[String]| {
        for id in ids {
            if let Err(e) = d.tx_engine.outbox.cancel(&args.wallet, &chain_name, id) {
                eprintln!("warning: could not discard staged tx {id}: {e}");
            }
        }
    };

    let mut staged_ids: Vec<String> = Vec::new();
    let mut any_warn = false;
    for intent in intents {
        let staged = match d
            .tx_engine
            .stage(
                home_write_permit(d)?,
                &args.wallet,
                owner,
                intent,
                &chain,
                &info.policy,
                Some(&d.address_book),
            )
            .await
            .context("stage funding tx")
        {
            Ok(s) => s,
            Err(e) => {
                discard(&staged_ids);
                return Err(e);
            }
        };
        println!();
        println!(
            "{}",
            PlanRender::render(&staged, &spec.native_symbol, spec.native_decimals)
        );
        if staged
            .policy_checks
            .iter()
            .any(|c| c.outcome == PolicyOutcome::Deny)
        {
            let id = staged.id.clone();
            staged_ids.push(staged.id);
            discard(&staged_ids);
            bail!(
                "EVM policy denied staged tx {id} — funding refused (deny-level policy is \
                 not CLI-bypassable)"
            );
        }
        if staged
            .policy_checks
            .iter()
            .any(|c| c.outcome == PolicyOutcome::Warn)
        {
            any_warn = true;
        }
        staged_ids.push(staged.id);
    }
    if args.dry_run {
        // The printed plans are the artifact; the staged entries are
        // discarded so repeated probes cannot poison nonce assignment.
        discard(&staged_ids);
        println!(
            "dry run: validated and rendered {} tx(s); staged entries discarded \
             (re-run without --dry-run to execute)",
            staged_ids.len(),
        );
        return Ok(());
    }
    if any_warn && !args.confirm_risk {
        discard(&staged_ids);
        bail!(
            "EVM policy raised warnings on the staged tx(s) above; re-run with \
             --confirm-risk to acknowledge"
        );
    }

    // Ceremony after every refusal opportunity above (skipped if the wallet
    // is already unlocked in this process, e.g. during onboard auto-fund).
    let intent = bloom_proto::CeremonyIntent::new(
        &args.wallet,
        "Fund pUSD (swap)",
        bloom_proto::CeremonyIntentKind::PolymarketFund,
    )
    .with_address(checksum_address(&owner))
    .summary(format!("Chain: {chain_name}"))
    .summary(format!(
        "Swap {} {} -> >= {} pUSD",
        units::format_units(required_in, in_decimals),
        if native_in {
            spec.native_symbol.as_str()
        } else {
            "tokens"
        },
        units::format_units(U256::from(route_out), 6),
    ))
    .summary(format!(
        "Target {} pUSD to {}",
        bloom_polymarket::order::format_micro(target_micro),
        checksum_address(&funding_addr),
    ))
    .summary(format!("Router: {}", checksum_address(&route.tx.to)))
    .risk("Signs the staged funding swap transaction(s).")
    .subject(serde_json::json!({
        "action": "polymarket_fund_swap",
        "chain": chain_name,
        "from": checksum_address(&owner),
        "receiver": checksum_address(&funding_addr),
        "token_out": format!("{:#x}", PUSD),
        "router": checksum_address(&route.tx.to),
        "target_microusd": target_micro,
        "input_wei_max": required_in.to_string(),
        "native_value_wei": route.tx.value.to_string(),
    }));
    println!(
        "signing the staged funding tx(s) above (passkey review hash {}).",
        intent.intent_hash()
    );
    // Persist the full reviewed intent into each staged tx's outbox dir; the
    // pending → sent transition renames the dir, so the artifact rides along.
    if let Ok(bytes) = serde_json::to_vec_pretty(&intent) {
        for id in &staged_ids {
            if let Ok(entry) = d.tx_engine.outbox.read(&args.wallet, &chain_name, id) {
                let _ = d
                    .tx_engine
                    .outbox
                    .write_artefact(&entry.dir, "review_intent.json", &bytes);
            }
        }
    }
    let passkey_wallet = info.kind == bloom_keystore::WalletKind::PasskeyGated;
    // For passkey wallets, skip the standalone unlock ceremony — the in-band
    // sealed-approval ceremony in the confirm loop below self-unlocks via
    // WebAuthn (matching the `wallet confirm` path at main.rs:2121). For local
    // wallets, the passphrase unlock is the mechanism that enables in-policy
    // auto-broadcast.
    if !passkey_wallet {
        unlock_wallet_with_intent(
            d,
            &args.wallet,
            args.passphrase.as_deref(),
            Some(intent.clone()),
        )
        .await?;
    }
    let approval_intent = Some(intent);
    let confirm_text = if any_warn {
        info.policy.override_sentinel().to_string()
    } else {
        "y".to_string()
    };

    for (i, id) in staged_ids.iter().enumerate() {
        let staged = match d
            .tx_engine
            .confirm(
                home_write_permit(d)?,
                &args.wallet,
                &chain_name,
                id,
                &chain,
                &info.policy,
                &confirm_text,
            )
            .await
        {
            Ok(s) => s,
            Err(TxEngineError::ApprovalRequired(_)) if passkey_wallet => {
                // In-band sealed-approval ceremony, mirroring `wallet confirm`
                // (main.rs): the confirm path wrote an approval_challenge.json;
                // run the browser ceremony to sign it, then retry the confirm.
                // Without this arm the catch-all below would cancel the staged
                // tx, forcing a full re-stage and re-ceremony.
                if crate::sign_outbox_sealed_approval_if_challenged(
                    d,
                    &args.wallet,
                    &chain_name,
                    id,
                    approval_intent.clone(),
                )
                .await
                .with_context(|| format!("sign sealed approval for staged tx {id}"))?
                {
                    d.tx_engine
                        .confirm(
                            home_write_permit(d)?,
                            &args.wallet,
                            &chain_name,
                            id,
                            &chain,
                            &info.policy,
                            &confirm_text,
                        )
                        .await
                        .with_context(|| format!("confirm staged tx {id} after sealed approval"))?
                } else {
                    discard(&staged_ids[i..]);
                    bail!(
                        "broadcast approval required for staged tx {id} but no \
                         approval_challenge.json was written"
                    );
                }
            }
            Err(e) => {
                // Discard this entry if it never broadcast, plus everything
                // not yet confirmed, so stale pendings can't poison nonces.
                discard(&staged_ids[i..]);
                return Err(anyhow::Error::new(e).context(format!("confirm staged tx {id}")));
            }
        };
        let hash: alloy::primitives::B256 = staged
            .tx_hash
            .as_deref()
            .context("confirmed tx has no hash")?
            .parse()
            .context("parse tx hash")?;
        println!("broadcast {id}: {hash}");
        wait_mined(&chain, hash).await?;
    }

    // Poll the pUSD balance until the target is met (route may settle in the
    // same tx; allow a short grace for RPC lag).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let now = chain
            .erc20_balance(PUSD, funding_addr)
            .await
            .context("read pUSD balance")?
            .unwrap_or_default();
        if now >= target {
            println!(
                "funded: {} now holds {} pUSD (target {})",
                checksum_address(&funding_addr),
                units::format_units(now, 6),
                bloom_polymarket::order::format_micro(target_micro),
            );
            println!(
                "next: `bloom polymarket onboard {}` to finish approvals/credentials/sync",
                args.wallet
            );
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            bail!(
                "swap broadcast and mined but pUSD balance is {} (< target {}) after 90s — \
                 check the route tx on a block explorer before retrying; do NOT blindly re-fund",
                units::format_units(now, 6),
                bloom_polymarket::order::format_micro(target_micro),
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

/// Stage and confirm a plain pUSD `transfer(funding_addr, missing)` from the
/// owner EOA through the standard TxEngine path (EVM policy, plan, outbox
/// audit, broadcast gates). Calldata is built by hand so no token-amount
/// parsing ambiguity exists between the plan and the wire.
#[allow(clippy::too_many_arguments)]
async fn transfer_pusd_to_funding(
    d: &Daemon,
    args: &FundArgs,
    chain_name: &str,
    chain: &bloom_evm::ChainClient,
    spec: &bloom_proto::ChainSpec,
    info: &bloom_keystore::WalletInfo,
    owner: alloy::primitives::Address,
    funding_addr: alloy::primitives::Address,
    missing_micro: u64,
    target_micro: u64,
) -> Result<()> {
    use bloom_polymarket::eip712::PUSD;
    use bloom_proto::intent::{GasStrategy, RawIntent, RawIntentBody};
    use bloom_proto::{PlanRender, PolicyOutcome, checksum_address, units};

    // transfer(address,uint256) selector + args.
    let mut data = Vec::with_capacity(4 + 64);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(funding_addr.as_slice());
    data.extend_from_slice(&U256::from(missing_micro).to_be_bytes::<32>());

    let intent = RawIntent {
        body: RawIntentBody::Raw {
            to: checksum_address(&PUSD),
            value: "0".into(),
            data: format!("0x{}", hex::encode(&data)),
        },
        chain: Some(chain_name.to_string()),
        gas: GasStrategy::Auto,
        nonce: None,
        gas_limit_hint: None,
        usd_value_hint: Some(units::format_units(U256::from(missing_micro), 6)),
    };
    let staged = match d
        .tx_engine
        .stage(
            home_write_permit(d)?,
            &args.wallet,
            owner,
            intent,
            chain,
            &info.policy,
            Some(&d.address_book),
        )
        .await
        .context("stage pUSD transfer")
    {
        Ok(s) => s,
        Err(e) => return Err(e),
    };
    println!(
        "{}",
        PlanRender::render(&staged, &spec.native_symbol, spec.native_decimals)
    );
    let discard = || {
        let _ = d
            .tx_engine
            .outbox
            .cancel(&args.wallet, chain_name, &staged.id);
    };
    if staged
        .policy_checks
        .iter()
        .any(|c| c.outcome == PolicyOutcome::Deny)
    {
        discard();
        bail!("EVM policy denied the pUSD transfer — funding refused");
    }
    let any_warn = staged
        .policy_checks
        .iter()
        .any(|c| c.outcome == PolicyOutcome::Warn);
    if args.dry_run {
        discard();
        println!("dry run: transfer validated and rendered; staged entry discarded");
        return Ok(());
    }
    if any_warn && !args.confirm_risk {
        discard();
        bail!("EVM policy raised warnings; re-run with --confirm-risk to acknowledge");
    }

    let intent = bloom_proto::CeremonyIntent::new(
        &args.wallet,
        "Fund pUSD (transfer)",
        bloom_proto::CeremonyIntentKind::PolymarketFund,
    )
    .with_address(checksum_address(&owner))
    .summary(format!("Chain: {chain_name}"))
    .summary("Transfer existing pUSD from owner EOA to the deposit wallet".to_string())
    .summary(format!(
        "Send {} pUSD to {} (target {})",
        bloom_polymarket::order::format_micro(missing_micro),
        checksum_address(&funding_addr),
        bloom_polymarket::order::format_micro(target_micro),
    ))
    .risk("Plain ERC-20 transfer (no swap, no approval).")
    .subject(serde_json::json!({
        "action": "polymarket_fund_transfer",
        "chain": chain_name,
        "from": checksum_address(&owner),
        "receiver": checksum_address(&funding_addr),
        "token": format!("{:#x}", PUSD),
        "amount_microusd": missing_micro,
        "target_microusd": target_micro,
    }));
    println!(
        "signing the staged pUSD transfer above (passkey review hash {}).",
        intent.intent_hash()
    );
    // Persist the full reviewed intent into the staged tx's outbox dir so it
    // rides the pending → sent rename alongside the durable tx record.
    if let Ok(bytes) = serde_json::to_vec_pretty(&intent)
        && let Ok(entry) = d
            .tx_engine
            .outbox
            .read(&args.wallet, chain_name, &staged.id)
    {
        let _ = d
            .tx_engine
            .outbox
            .write_artefact(&entry.dir, "review_intent.json", &bytes);
    }
    let passkey_wallet = info.kind == bloom_keystore::WalletKind::PasskeyGated;
    // For passkey wallets, skip the standalone unlock ceremony — the in-band
    // sealed-approval ceremony in the confirm below self-unlocks via WebAuthn
    // (matching the fund-swap path above). For local wallets, the passphrase
    // unlock is the mechanism that enables in-policy auto-broadcast.
    if !passkey_wallet {
        unlock_wallet_with_intent(
            d,
            &args.wallet,
            args.passphrase.as_deref(),
            Some(intent.clone()),
        )
        .await?;
    }
    let approval_intent = Some(intent);
    let confirm_text = if any_warn {
        info.policy.override_sentinel().to_string()
    } else {
        "y".to_string()
    };
    let confirmed = match d
        .tx_engine
        .confirm(
            home_write_permit(d)?,
            &args.wallet,
            chain_name,
            &staged.id,
            chain,
            &info.policy,
            &confirm_text,
        )
        .await
    {
        Ok(c) => c,
        Err(TxEngineError::ApprovalRequired(_)) if passkey_wallet => {
            // In-band sealed-approval ceremony, mirroring the fund-swap
            // confirm loop: the confirm path wrote an
            // approval_challenge.json; run the browser ceremony to sign it,
            // then retry the confirm. Without this arm the catch-all below
            // would cancel the staged tx.
            let signed = match crate::sign_outbox_sealed_approval_if_challenged(
                d,
                &args.wallet,
                chain_name,
                &staged.id,
                approval_intent.clone(),
            )
            .await
            .with_context(|| format!("sign sealed approval for staged tx {}", staged.id))
            {
                Ok(signed) => signed,
                Err(e) => {
                    discard();
                    return Err(e);
                }
            };
            if !signed {
                discard();
                bail!(
                    "broadcast approval required for staged tx {} but no \
                     approval_challenge.json was written",
                    staged.id
                );
            }
            match d
                .tx_engine
                .confirm(
                    home_write_permit(d)?,
                    &args.wallet,
                    chain_name,
                    &staged.id,
                    chain,
                    &info.policy,
                    &confirm_text,
                )
                .await
                .with_context(|| format!("confirm staged tx {} after sealed approval", staged.id))
            {
                Ok(c) => c,
                Err(e) => {
                    discard();
                    return Err(e);
                }
            }
        }
        Err(e) => {
            discard();
            return Err(anyhow::Error::new(e).context(format!("confirm staged tx {}", staged.id)));
        }
    };
    let hash: alloy::primitives::B256 = confirmed
        .tx_hash
        .as_deref()
        .context("confirmed tx has no hash")?
        .parse()
        .context("parse tx hash")?;
    println!("broadcast {}: {hash}", staged.id);
    wait_mined(chain, hash).await?;

    let now = chain
        .erc20_balance(PUSD, funding_addr)
        .await
        .context("read pUSD balance")?
        .unwrap_or_default();
    if now < U256::from(target_micro) {
        bail!(
            "transfer mined but funding address holds {} pUSD (< target {})",
            units::format_units(now, 6),
            bloom_polymarket::order::format_micro(target_micro),
        );
    }
    println!(
        "funded: {} now holds {} pUSD (target {})",
        checksum_address(&funding_addr),
        units::format_units(now, 6),
        bloom_polymarket::order::format_micro(target_micro),
    );
    Ok(())
}

/// Whether funding targets the owner EOA (legacy) or the deposit wallet
/// (default). The deposit-wallet **address** is never derived locally here —
/// `fund` reads it from onboarding state, where it was resolved against the
/// live factory (the local CREATE2 estimate has disagreed with the factory:
/// funding a wrong address is unrecoverable).
async fn wait_mined(chain: &bloom_evm::ChainClient, hash: alloy::primitives::B256) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        if let Some(receipt) = chain.receipt(hash).await.context("poll receipt")? {
            if receipt.status() {
                println!("mined: {hash}");
                return Ok(());
            }
            bail!("tx {hash} reverted on-chain");
        }
        if std::time::Instant::now() > deadline {
            bail!("tx {hash} not mined within 180s — check the explorer before retrying");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// `bloom polymarket obligations`: read-only operational summary for open
/// positions. This is deliberately not a trading command; it gives cold-start
/// agents the next safe action without relying on conversation memory.
pub async fn obligations(d: &Daemon, wallet: &str) -> Result<()> {
    let store = bloom_polymarket::OnboardStore::new(d.home.polymarket_dir());
    let st = store.load(wallet)?.with_context(|| {
        format!("wallet '{wallet}' is not onboarded; run `bloom polymarket onboard {wallet}`")
    })?;
    let funder = st
        .deposit_wallet
        .parse::<alloy::primitives::Address>()
        .context("corrupt deposit_wallet in onboarding state")?;
    let funder_s = bloom_proto::checksum_address(&funder);
    let data = DataClient::new();
    let positions = data
        .positions(&funder_s)
        .await
        .with_context(|| format!("fetch Polymarket positions for {funder_s}"))?;
    let open: Vec<_> = positions
        .into_iter()
        .filter(|p| p.size.unwrap_or(0.0) > 0.0)
        .collect();

    println!("polymarket obligations for wallet '{wallet}'");
    println!("mode: {:?}  tradeable: {}", st.mode, st.tradeable());
    println!("deposit wallet: {funder_s}");
    if open.is_empty() {
        println!("open positions: none");
        println!("next: no Polymarket exit action required.");
        return Ok(());
    }

    let order_store = OrderStore::new(d.home.polymarket_dir());
    let receipt_ids = order_store.list_receipts(wallet).unwrap_or_default();
    println!("open positions: {}", open.len());
    println!(
        "redemption: available after resolution when Data API reports redeemable=true; \
         before then, sell-to-close is the safe exit."
    );
    for p in open {
        let size = p.size.unwrap_or(0.0);
        let cur = p
            .cur_price
            .map(|v| format!("{v:.4}"))
            .unwrap_or_else(|| "-".into());
        let avg = p
            .avg_price
            .map(|v| format!("{v:.4}"))
            .unwrap_or_else(|| "-".into());
        let title = if p.title.is_empty() {
            "(untitled market)"
        } else {
            &p.title
        };
        println!();
        println!("- {title}");
        println!(
            "  outcome: {}",
            if p.outcome.is_empty() {
                "-"
            } else {
                &p.outcome
            }
        );
        println!("  token: {}", p.asset);
        println!("  condition: {}", p.condition_id);
        println!("  size: {size:.6}");
        println!("  avg_price: {avg}  current_price: {cur}");
        println!("  redeemable: {}", p.redeemable);
        let matching: Vec<_> = receipt_ids
            .iter()
            .filter_map(|id| {
                order_store
                    .load_receipt(wallet, id)
                    .ok()
                    .flatten()
                    .filter(|r| r.token_id == p.asset)
                    .map(|_| id.clone())
            })
            .collect();
        if matching.is_empty() {
            println!("  bloom receipts: none found (may be pre-existing/external dust)");
        } else {
            println!("  bloom receipts: {}", matching.join(", "));
        }
        if p.redeemable {
            println!(
                "  next: preflight redeem, then redeem:\n        bloom polymarket redeem {wallet} <slug> --dry-run\n        bloom polymarket redeem {wallet} <slug>"
            );
        } else {
            println!(
                "  next: if this market is nearing resolution, sell-to-close with:\n        \
                 bloom polymarket sell {wallet} <slug> {} {size:.6} --min-price <bid>",
                if p.outcome.eq_ignore_ascii_case("no") {
                    "no"
                } else {
                    "yes"
                }
            );
            println!(
                "  after the position becomes redeemable, preflight first:\n        bloom polymarket redeem {wallet} <slug> --dry-run"
            );
        }
    }
    Ok(())
}

fn relayer_for_polymarket(
    d: &Daemon,
    wallet: &str,
    pm_cfg: &bloom_proto::config::PolymarketConfig,
) -> Result<RelayerClient> {
    let relayer = RelayerClient::new(pm_cfg.chain_id).with_base_url(pm_cfg.relayer_url.clone());
    match (&pm_cfg.relayer_api_key, &pm_cfg.relayer_api_key_address) {
        (Some(key), Some(addr)) => Ok(relayer.with_api_key(key.clone(), addr.clone())),
        _ => match pm_cfg.builder_key_mode.as_str() {
            "auto" => {
                let creds = BuilderCredentialStore::new(d.home.polymarket_dir())
                    .load(wallet)?
                    .with_context(|| {
                        format!(
                            "no stored builder key for '{wallet}'; run `bloom polymarket onboard {wallet}` first"
                        )
                    })?;
                Ok(relayer.with_builder_key(creds))
            }
            "manual" => bail!(
                "builder_key_mode = \"manual\" but no relayer_api_key / relayer_api_key_address \
                 are configured; configure them or switch to builder_key_mode = \"auto\""
            ),
            "disabled" => bail!(
                "builder_key_mode = \"disabled\": relayer auth is off, so deposit-wallet \
                 redemption cannot be submitted"
            ),
            other => {
                bail!("unknown builder_key_mode '{other}' (expected auto, manual, or disabled)")
            }
        },
    }
}

/// Submit a signed deposit-wallet `WALLET` batch through the relayer and poll
/// it to confirmation, emitting `{audit_prefix}_submitted` / `_confirmed` audit
/// lines (the caller's `submit_details` / `confirm_details` get `tx_id` — and
/// `tx_hash` on confirm — merged in). Shared by `redeem` and `revoke_approvals`.
#[allow(clippy::too_many_arguments)]
async fn submit_and_confirm_wallet_batch(
    relayer: &RelayerClient,
    order_store: &OrderStore,
    wallet: &str,
    owner: Address,
    deposit_wallet: Address,
    calls: Vec<bloom_polymarket::eip712::Call>,
    signer: &dyn OnboardSigner,
    label: &str,
    audit_prefix: &str,
    mut submit_details: serde_json::Value,
    mut confirm_details: serde_json::Value,
) -> Result<bloom_polymarket::RelayerTx> {
    let nonce = relayer
        .wallet_nonce(owner)
        .await
        .context("relayer /nonce")?;
    let deadline = now_secs() + 3600;
    let tx = relayer
        .submit_wallet_batch(owner, deposit_wallet, calls, nonce, deadline, signer)
        .await
        .with_context(|| format!("submit {label} batch"))?;
    if let Some(o) = submit_details.as_object_mut() {
        o.insert("tx_id".into(), serde_json::json!(tx.id));
    }
    order_store.audit(wallet, &format!("{audit_prefix}_submitted"), submit_details)?;
    println!("{label} submitted: {}", tx.id);
    let confirmed = relayer
        .poll_confirmed(&tx, std::time::Duration::from_secs(300))
        .await
        .with_context(|| format!("wait for {label} confirmation"))?;
    if let Some(o) = confirm_details.as_object_mut() {
        o.insert("tx_id".into(), serde_json::json!(confirmed.id));
        o.insert("tx_hash".into(), serde_json::json!(confirmed.tx_hash));
    }
    order_store.audit(
        wallet,
        &format!("{audit_prefix}_confirmed"),
        confirm_details,
    )?;
    Ok(confirmed)
}

/// `bloom polymarket redeem`: after resolution, burn winning outcome tokens
/// through the pUSD collateral adapter and return pUSD to the deposit wallet.
pub async fn redeem(
    d: &Daemon,
    wallet: &str,
    slug: &str,
    dry_run: bool,
    passphrase: Option<&str>,
) -> Result<()> {
    let pm_cfg = d
        .config
        .polymarket
        .as_ref()
        .context("no [polymarket] block in config.toml")?;
    let info = d.keystore.info(wallet)?;
    let store = bloom_polymarket::OnboardStore::new(d.home.polymarket_dir());
    let st = store.load(wallet)?.with_context(|| {
        format!("wallet '{wallet}' is not onboarded; run `bloom polymarket onboard {wallet}`")
    })?;
    if !st.is_complete() {
        bail!(
            "onboarding for '{wallet}' is at stage '{}' — finish it with \
             `bloom polymarket onboard {wallet}` before redeeming",
            st.stage.as_str()
        );
    }

    let deposit_wallet: Address = st
        .deposit_wallet
        .parse()
        .context("corrupt deposit_wallet in onboarding state")?;
    let funder_s = bloom_proto::checksum_address(&deposit_wallet);
    let gamma = polymarket_gamma_client(pm_cfg);
    let market = gamma
        .market_by_slug(slug)
        .await
        .with_context(|| format!("fetch market '{slug}'"))?;
    // `redeem_positions_call` hardcodes `indexSets [1, 2]`, valid only for a true
    // binary condition; the trade path already refuses non-binary markets, so
    // guard redeem the same way (defends against externally-acquired positions).
    if !market.is_binary() {
        bail!(
            "market '{slug}' is not a binary YES/NO market (outcomes={:?}); redeem only \
             supports binary conditions",
            market.outcomes
        );
    }
    let condition_id: B256 = market
        .condition_id
        .parse()
        .with_context(|| format!("parse condition id {}", market.condition_id))?;
    let yes = market
        .yes_token_id()
        .context("market has no YES token id")?;
    let no = market.no_token_id().context("market has no NO token id")?;

    let data = polymarket_data_client(pm_cfg);
    let positions = data
        .positions(&funder_s)
        .await
        .with_context(|| format!("fetch Polymarket positions for {funder_s}"))?;
    let matching: Vec<_> = positions
        .iter()
        .filter(|p| (p.asset == yes || p.asset == no) && p.size.unwrap_or(0.0) > 0.0)
        .collect();
    if matching.is_empty() {
        bail!(
            "no open YES/NO position for '{slug}' at deposit wallet {funder_s}; \
             run `bloom polymarket obligations {wallet}` to inspect positions"
        );
    }
    if !matching.iter().any(|p| p.redeemable) {
        println!("redemption preflight for '{slug}'");
        println!("question: {}", market.question);
        println!("deposit wallet: {funder_s}");
        for p in &matching {
            println!(
                "  {} {} shares  redeemable={}",
                if p.outcome.is_empty() {
                    &p.asset
                } else {
                    &p.outcome
                },
                p.size.unwrap_or(0.0),
                p.redeemable
            );
        }
        bail!(
            "position is not redeemable yet. If the market is nearing resolution, \
             sell-to-close instead: `bloom polymarket sell {wallet} {slug} yes <shares> --min-price <bid>`"
        );
    }

    let call = bloom_polymarket::wallet::redeem_positions_call(condition_id, market.neg_risk);
    let data = call.data.as_ref();
    if data.len() < 4 || data[..4] != bloom_polymarket::wallet::REDEEM_POSITIONS_SELECTOR {
        bail!(
            "internal redeem selector mismatch: expected 0x{}, got 0x{}",
            hex::encode(bloom_polymarket::wallet::REDEEM_POSITIONS_SELECTOR),
            hex::encode(data.get(..4).unwrap_or(data))
        );
    }
    let chain = d
        .chains
        .get("polygon")
        .context("chain 'polygon' is required for redeem preflight")?;
    let req = TransactionRequest::default()
        .from(deposit_wallet)
        .to(call.target)
        .input(call.data.clone().into());
    match chain
        .eth_call_capture_revert(req, None)
        .await
        .context("redeem preflight eth_call")?
    {
        Ok(_) => {}
        Err(returndata) => {
            bail!(
                "redeem preflight reverted for adapter {} selector 0x{} (returndata 0x{}). \
                 Do not sign this redeem yet; sell-to-close if the market is still tradable, \
                 otherwise keep the tokens until redeem support is fixed.",
                bloom_proto::checksum_address(&call.target),
                hex::encode(bloom_polymarket::wallet::REDEEM_POSITIONS_SELECTOR),
                hex::encode(returndata)
            );
        }
    }
    let relayer = relayer_for_polymarket(d, wallet, pm_cfg)?;
    let order_store = OrderStore::new(d.home.polymarket_dir());
    let _lock = order_store.lock(wallet)?;

    println!("Polymarket redemption plan");
    println!("wallet: {wallet}");
    println!("owner: {}", bloom_proto::checksum_address(&info.address));
    println!("deposit wallet: {funder_s}");
    println!("market: {slug}");
    println!("question: {}", market.question);
    println!("condition: {}", market.condition_id);
    println!(
        "adapter: {} ({})",
        bloom_proto::checksum_address(&call.target),
        if market.neg_risk {
            "NegRiskCtfCollateralAdapter"
        } else {
            "CtfCollateralAdapter"
        }
    );
    println!("call: redeemPositions(pUSD, 0x00..00, condition, [1,2])");
    println!(
        "selector: 0x{}",
        hex::encode(bloom_polymarket::wallet::REDEEM_POSITIONS_SELECTOR)
    );
    println!(
        "preflight: adapter eth_call succeeded from deposit wallet (does not prove relayer execute wrapper)"
    );
    println!("positions to redeem:");
    for p in &matching {
        println!(
            "  outcome={} token={} size={} redeemable={}",
            if p.outcome.is_empty() {
                "-"
            } else {
                &p.outcome
            },
            p.asset,
            p.size.unwrap_or(0.0),
            p.redeemable
        );
    }
    println!(
        "signing exactly the deposit-wallet batch above (passkey ceremony follows if locked)."
    );
    if dry_run {
        println!("dry run: no passkey ceremony, no relayer submission");
        return Ok(());
    }

    let mut intent = bloom_proto::CeremonyIntent::new(
        wallet,
        "Redeem Polymarket Position",
        bloom_proto::CeremonyIntentKind::PolymarketRedeem,
    )
    .with_address(bloom_proto::checksum_address(&info.address))
    .summary(format!("Market: {}", market.question))
    .summary(format!("Slug: {slug}"))
    .summary(format!("Deposit wallet: {funder_s}"))
    .summary(format!(
        "Adapter: {} ({})",
        bloom_proto::checksum_address(&call.target),
        if market.neg_risk {
            "NegRiskCtfCollateralAdapter"
        } else {
            "CtfCollateralAdapter"
        }
    ))
    .summary("Call: redeemPositions(pUSD, 0x00..00, condition, [1,2])".to_string())
    .risk("This burns redeemable winning/losing conditional tokens and returns pUSD to the deposit wallet.")
    .risk("The relayer submission is gasless, but it is still a signed wallet operation.");
    for p in &matching {
        intent = intent.summary(format!(
            "Redeem {} {} shares (token {})",
            if p.outcome.is_empty() {
                "-"
            } else {
                &p.outcome
            },
            p.size.unwrap_or(0.0),
            p.asset
        ));
    }
    let intent = intent.subject(serde_json::json!({
        "action": "polymarket_redeem",
        "slug": slug,
        "condition_id": market.condition_id,
        "neg_risk": market.neg_risk,
        "deposit_wallet": funder_s,
        "adapter": bloom_proto::checksum_address(&call.target),
        "selector": format!("0x{}", hex::encode(bloom_polymarket::wallet::REDEEM_POSITIONS_SELECTOR)),
        "positions": matching.iter().map(|p| serde_json::json!({
            "outcome": p.outcome,
            "token": p.asset,
            "size": p.size,
            "redeemable": p.redeemable,
        })).collect::<Vec<_>>(),
    }));
    let review_hash = intent.intent_hash();
    println!("passkey review hash {review_hash}");

    let signer: Box<dyn OnboardSigner> = if info.kind == bloom_keystore::WalletKind::PasskeyGated {
        // Sealed-approval lane: one Standard grant covers the single relayer
        // batch signature; the host signs under it (never the raw keystore).
        let sealed = pm_sealed::polymarket_redemption_sealed_action(
            wallet,
            deposit_wallet,
            &market.condition_id,
            market.neg_risk,
            now_ms_u64(),
        )?;
        ensure_sealed_polymarket_grant(d, wallet, sealed, Some(intent)).await?;
        Box::new(sealed_polymarket_signer(
            d,
            wallet,
            pm_sealed::polymarket_redeem_action_id(wallet, &market.condition_id),
            PolymarketSealedActionKind::Redemption,
            info.address,
        )?)
    } else {
        unlock_wallet_with_intent(d, wallet, passphrase, Some(intent)).await?;
        let signer = KeystoreSigner::new(d.keystore.signer(wallet)?);
        if signer.address() != info.address {
            bail!("unlocked signer address changed during redemption preflight");
        }
        Box::new(signer)
    };

    let confirmed = submit_and_confirm_wallet_batch(
        &relayer,
        &order_store,
        wallet,
        info.address,
        deposit_wallet,
        vec![call],
        signer.as_ref(),
        "redemption",
        "redeem",
        serde_json::json!({
            "slug": slug,
            "condition_id": market.condition_id,
            "neg_risk": market.neg_risk,
            "deposit_wallet": funder_s,
        }),
        serde_json::json!({
            "slug": slug,
            "condition_id": market.condition_id,
        }),
    )
    .await?;
    println!(
        "redemption confirmed: {}{}",
        confirmed.id,
        confirmed
            .tx_hash
            .as_deref()
            .map(|h| format!(" ({h})"))
            .unwrap_or_default()
    );
    Ok(())
}

/// `bloom polymarket withdraw-pusd`: transfer pUSD from the deposit wallet
/// back to the owner EOA. This exits Polymarket buying power; it does not
/// revoke approvals.
pub async fn withdraw_pusd(
    d: &Daemon,
    wallet: &str,
    amount: &str,
    dry_run: bool,
    passphrase: Option<&str>,
) -> Result<()> {
    use bloom_polymarket::eip712::PUSD;
    use bloom_polymarket::wallet::transfer_amount_call;

    let pm_cfg = d
        .config
        .polymarket
        .as_ref()
        .context("no [polymarket] block in config.toml")?;
    let info = d.keystore.info(wallet)?;
    let owner = info.address;
    let owner_s = bloom_proto::checksum_address(&owner);
    let store = bloom_polymarket::OnboardStore::new(d.home.polymarket_dir());
    let st = store.load(wallet)?.with_context(|| {
        format!("wallet '{wallet}' is not onboarded; run `bloom polymarket onboard {wallet}`")
    })?;
    if !st.is_complete() {
        bail!(
            "onboarding for '{wallet}' is at stage '{}' — finish it with \
             `bloom polymarket onboard {wallet}` before withdrawing",
            st.stage.as_str()
        );
    }

    let deposit_wallet: Address = st
        .deposit_wallet
        .parse()
        .context("corrupt deposit_wallet in onboarding state")?;
    let funder_s = bloom_proto::checksum_address(&deposit_wallet);
    let chain = d
        .chains
        .get("polygon")
        .context("chain 'polygon' is required for pUSD withdrawal")?;
    let balance = chain
        .erc20_balance(PUSD, deposit_wallet)
        .await
        .context("read deposit-wallet pUSD balance")?
        .context("pUSD balanceOf reverted")?;
    let amount_raw = if amount.eq_ignore_ascii_case("all") {
        balance
    } else {
        bloom_proto::parse_units(amount, 6).context("parse pUSD amount")?
    };
    if amount_raw.is_zero() {
        bail!("pUSD withdrawal amount is zero");
    }
    if amount_raw > balance {
        bail!(
            "deposit wallet holds {} pUSD, below requested {} pUSD",
            bloom_proto::format_units(balance, 6),
            bloom_proto::format_units(amount_raw, 6)
        );
    }

    let call = transfer_amount_call(PUSD, owner, amount_raw);
    let relayer = relayer_for_polymarket(d, wallet, pm_cfg)?;
    let order_store = OrderStore::new(d.home.polymarket_dir());
    let _lock = order_store.lock(wallet)?;

    println!("Polymarket pUSD withdrawal plan");
    println!("wallet: {wallet}");
    println!("owner: {owner_s}");
    println!("deposit wallet: {funder_s}");
    println!("token: pUSD {PUSD:#x} on Polygon");
    println!(
        "amount: {} pUSD (raw {amount_raw})",
        bloom_proto::format_units(amount_raw, 6)
    );
    println!("call: pUSD.transfer(owner, amount) from the deposit wallet");
    println!(
        "available before withdrawal: {} pUSD",
        bloom_proto::format_units(balance, 6)
    );
    println!(
        "signing exactly the deposit-wallet batch above (passkey ceremony follows if locked)."
    );
    if dry_run {
        println!("dry run: no passkey ceremony, no relayer submission");
        return Ok(());
    }

    let intent = bloom_proto::CeremonyIntent::new(
        wallet,
        "Withdraw Polymarket pUSD",
        bloom_proto::CeremonyIntentKind::PolymarketFund,
    )
    .with_address(owner_s.clone())
    .summary(format!("Deposit wallet: {funder_s}"))
    .summary(format!("Receiver: {owner_s}"))
    .summary(format!(
        "Transfer {} pUSD from the deposit wallet to the owner wallet",
        bloom_proto::format_units(amount_raw, 6)
    ))
    .risk("This removes pUSD from Polymarket buying power.")
    .risk("The relayer submission is gasless, but it is still a signed wallet operation.")
    .subject(serde_json::json!({
        "action": "polymarket_withdraw_pusd",
        "deposit_wallet": funder_s,
        "receiver": owner_s,
        "token": format!("{:#x}", PUSD),
        "amount_raw": amount_raw.to_string(),
    }));
    let review_hash = intent.intent_hash();
    println!("passkey review hash {review_hash}");

    let signer: Box<dyn OnboardSigner> = if info.kind == bloom_keystore::WalletKind::PasskeyGated {
        // Sealed-approval lane: one Hardened grant covers the single relayer
        // batch signature; the host signs under it (never the raw keystore).
        let sealed =
            pm_sealed::polymarket_withdrawal_sealed_action(wallet, deposit_wallet, now_ms_u64())?;
        ensure_sealed_polymarket_grant(d, wallet, sealed, Some(intent)).await?;
        Box::new(sealed_polymarket_signer(
            d,
            wallet,
            pm_sealed::polymarket_withdraw_action_id(wallet),
            PolymarketSealedActionKind::Withdrawal,
            owner,
        )?)
    } else {
        unlock_wallet_with_intent(d, wallet, passphrase, Some(intent)).await?;
        let signer = KeystoreSigner::new(d.keystore.signer(wallet)?);
        if signer.address() != owner {
            bail!("unlocked signer address changed during pUSD withdrawal preflight");
        }
        Box::new(signer)
    };

    let confirmed = submit_and_confirm_wallet_batch(
        &relayer,
        &order_store,
        wallet,
        owner,
        deposit_wallet,
        vec![call],
        signer.as_ref(),
        "pUSD withdrawal",
        "withdraw_pusd",
        serde_json::json!({
            "deposit_wallet": funder_s,
            "receiver": owner_s,
            "amount_raw": amount_raw.to_string(),
        }),
        serde_json::json!({
            "deposit_wallet": funder_s,
            "receiver": owner_s,
            "amount_raw": amount_raw.to_string(),
        }),
    )
    .await?;
    println!(
        "pUSD withdrawal confirmed: {}{}",
        confirmed.id,
        confirmed
            .tx_hash
            .as_deref()
            .map(|h| format!(" ({h})"))
            .unwrap_or_default()
    );
    Ok(())
}

/// `bloom polymarket revoke-approvals`: withdraw the spending authority the
/// onboarding approval batch granted — pUSD `approve(0)` + CTF
/// `setApprovalForAll(false)` to the four contracts, via one gasless relayer
/// batch from the deposit wallet. The inverse of onboarding's approve stage.
pub async fn revoke_approvals(
    d: &Daemon,
    wallet: &str,
    dry_run: bool,
    passphrase: Option<&str>,
) -> Result<()> {
    use bloom_polymarket::eip712::{CTF_COLLATERAL_ADAPTER, NEG_RISK_CTF_COLLATERAL_ADAPTER, PUSD};

    let pm_cfg = d
        .config
        .polymarket
        .as_ref()
        .context("no [polymarket] block in config.toml")?;
    let info = d.keystore.info(wallet)?;
    let store = bloom_polymarket::OnboardStore::new(d.home.polymarket_dir());
    let st = store
        .load(wallet)?
        .with_context(|| format!("wallet '{wallet}' is not onboarded; nothing to revoke"))?;
    // The deposit wallet must be deployed for a batch to execute; require the
    // address that was resolved against the live factory (never local).
    if st.stage < bloom_polymarket::Stage::Fund {
        bail!(
            "onboarding for '{wallet}' has not passed deploy (stage: {}); there are no \
             on-chain approvals to revoke yet",
            st.stage.as_str()
        );
    }
    let deposit_wallet: Address = st
        .deposit_wallet
        .parse()
        .context("corrupt deposit_wallet in onboarding state")?;
    let funder_s = bloom_proto::checksum_address(&deposit_wallet);

    // The four spenders/operators, in the approval_calls order.
    let spenders = [
        CTF_EXCHANGE,
        NEG_RISK_EXCHANGE,
        CTF_COLLATERAL_ADAPTER,
        NEG_RISK_CTF_COLLATERAL_ADAPTER,
    ];
    let calls = bloom_polymarket::wallet::revoke_calls();

    let relayer = relayer_for_polymarket(d, wallet, pm_cfg)?;
    let order_store = OrderStore::new(d.home.polymarket_dir());
    let _lock = order_store.lock(wallet)?;

    println!("Polymarket revoke-approvals plan");
    println!("wallet: {wallet}");
    println!("owner: {}", bloom_proto::checksum_address(&info.address));
    println!("deposit wallet: {funder_s}");
    println!("revoking (gasless relayer batch from the deposit wallet):");
    println!("  pUSD approve(0)               -> CTF Exchange, Neg-Risk Exchange, + 2 adapters");
    println!("  CTF  setApprovalForAll(false) -> the same four contracts");
    println!(
        "signing exactly the deposit-wallet batch above (passkey ceremony follows if locked)."
    );
    if dry_run {
        println!("dry run: no passkey ceremony, no relayer submission");
        return Ok(());
    }

    let intent = bloom_proto::CeremonyIntent::new(
        wallet,
        "Revoke Polymarket Approvals",
        bloom_proto::CeremonyIntentKind::PolymarketRevokeApprovals,
    )
    .with_address(bloom_proto::checksum_address(&info.address))
    .summary(format!("Deposit wallet: {funder_s}"))
    .summary("pUSD approve(0) to the 2 exchanges + 2 collateral adapters".to_string())
    .summary("CTF setApprovalForAll(false) to the same four contracts".to_string())
    .risk("After this, trading needs re-onboarding to restore approvals.")
    .subject(serde_json::json!({
        "action": "polymarket_revoke_approvals",
        "deposit_wallet": funder_s,
        "spenders": spenders.iter().map(|s| format!("{s:#x}")).collect::<Vec<_>>(),
    }));
    let review_hash = intent.intent_hash();
    println!("passkey review hash {review_hash}");

    let signer: Box<dyn OnboardSigner> = if info.kind == bloom_keystore::WalletKind::PasskeyGated {
        // Sealed-approval lane: one Hardened grant covers the single relayer
        // batch signature; the host signs under it (never the raw keystore).
        let sealed =
            pm_sealed::polymarket_revocation_sealed_action(wallet, deposit_wallet, now_ms_u64())?;
        ensure_sealed_polymarket_grant(d, wallet, sealed, Some(intent)).await?;
        Box::new(sealed_polymarket_signer(
            d,
            wallet,
            pm_sealed::polymarket_revoke_action_id(wallet),
            PolymarketSealedActionKind::Revocation,
            info.address,
        )?)
    } else {
        unlock_wallet_with_intent(d, wallet, passphrase, Some(intent)).await?;
        let signer = KeystoreSigner::new(d.keystore.signer(wallet)?);
        if signer.address() != info.address {
            bail!("unlocked signer address changed during revoke preflight");
        }
        Box::new(signer)
    };

    submit_and_confirm_wallet_batch(
        &relayer,
        &order_store,
        wallet,
        info.address,
        deposit_wallet,
        calls,
        signer.as_ref(),
        "revoke",
        "revoke",
        serde_json::json!({ "deposit_wallet": funder_s }),
        serde_json::json!({}),
    )
    .await?;

    // Verify on-chain that authority is actually gone before reporting success.
    let chain = d
        .chains
        .get("polygon")
        .context("chain 'polygon' is required to verify revocation")?;
    for spender in spenders {
        let allowance = chain
            .erc20_allowance(PUSD, deposit_wallet, spender)
            .await
            .context("read pUSD allowance after revoke")?
            .context("pUSD allowance() reverted during revoke verification")?;
        if !allowance.is_zero() {
            bail!(
                "revoke confirmed but pUSD allowance to {} is still {} (expected 0)",
                bloom_proto::checksum_address(&spender),
                allowance
            );
        }
        let approved = chain
            .is_approved_for_all(CTF, deposit_wallet, spender)
            .await
            .context("read CTF approval after revoke")?
            .context("CTF isApprovedForAll reverted during revoke verification")?;
        if approved {
            bail!(
                "revoke confirmed but CTF is still approved for {} (expected false)",
                bloom_proto::checksum_address(&spender)
            );
        }
    }
    println!(
        "revoked: deposit wallet {funder_s} has zero pUSD allowance and no CTF operator \
         approval for the four contracts. Re-run `bloom polymarket onboard {wallet}` to \
         trade again."
    );
    Ok(())
}

/// `bloom polymarket builder-keys list`: builder API keys on the account
/// (CLOB L2 auth; key ids only — never secrets).
pub async fn builder_keys_list(d: &Daemon, wallet: &str) -> Result<()> {
    let pm_cfg = d
        .config
        .polymarket
        .as_ref()
        .context("no [polymarket] block in config.toml")?;
    let info = d.keystore.info(wallet)?;
    let creds = CredentialStore::new(d.home.polymarket_dir())
        .load(wallet)?
        .context("wallet not onboarded (no CLOB credentials)")?;
    let stored = bloom_polymarket::BuilderCredentialStore::new(d.home.polymarket_dir())
        .load(wallet)?
        .map(|b| b.key);

    let clob = ClobClient::new(pm_cfg.chain_id);
    let keys = clob
        .list_builder_api_keys(&creds, info.address)
        .await
        .context("list builder API keys")?;
    if keys.is_empty() {
        println!("no builder API keys on this account");
        return Ok(());
    }
    for k in keys {
        let marker = if Some(&k.key) == stored.as_ref() {
            "  <- stored by bloom (builder_creds.json)"
        } else {
            ""
        };
        println!(
            "{}  created={}  revoked={}{}",
            k.key,
            k.created_at.as_deref().unwrap_or("-"),
            k.revoked_at.as_deref().unwrap_or("-"),
            marker,
        );
    }
    Ok(())
}

/// `bloom polymarket builder-keys revoke`: revoke a builder API key
/// (`DELETE /auth/builder-api-key`). With no `key`, the official client's
/// no-body form is used. Bloom's stored creds are deleted when they match.
pub async fn builder_keys_revoke(d: &Daemon, wallet: &str, key: Option<&str>) -> Result<()> {
    let pm_cfg = d
        .config
        .polymarket
        .as_ref()
        .context("no [polymarket] block in config.toml")?;
    let info = d.keystore.info(wallet)?;
    let creds = CredentialStore::new(d.home.polymarket_dir())
        .load(wallet)?
        .context("wallet not onboarded (no CLOB credentials)")?;

    let clob = ClobClient::new(pm_cfg.chain_id);
    clob.revoke_builder_api_key(&creds, info.address, key)
        .await
        .context("revoke builder API key")?;
    println!(
        "revoked{}",
        key.map(|k| format!(": {k}")).unwrap_or_default()
    );

    let store = bloom_polymarket::BuilderCredentialStore::new(d.home.polymarket_dir());
    if let Some(stored) = store.load(wallet)?
        && (key.is_none() || key == Some(stored.key.as_str()))
    {
        store.delete(wallet)?;
        println!("deleted stored builder_creds.json (a fresh key is minted on next use)");
    }
    Ok(())
}

/// `bloom polymarket cancel`: retract a resting order. Risk-reducing;
/// needs no wallet unlock (L2 creds only).
pub async fn cancel(d: &Daemon, wallet: &str, order_id: &str) -> Result<()> {
    let pm_cfg = d
        .config
        .polymarket
        .as_ref()
        .context("no [polymarket] block in config.toml")?;

    let info = d.keystore.info(wallet)?;
    let creds = CredentialStore::new(d.home.polymarket_dir())
        .load(wallet)?
        .context("wallet not onboarded (no CLOB credentials)")?;

    let store = OrderStore::new(d.home.polymarket_dir());
    let _lock = store.lock(wallet)?;
    let clob = polymarket_clob_client(pm_cfg);
    let result = clob
        .cancel_order(&creds, info.address, order_id)
        .await
        .context("cancel order")?;
    store.audit(
        wallet,
        "order_cancelled",
        serde_json::json!({ "order_id": order_id, "response": result }),
    )?;
    println!("cancel response:");
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// Input amount the funding swap should request: target-denominated and
/// **bounded by `--max-spend`**. `exact = max_spend * missing / out_at_max`
/// (rate implied by the probe quote), padded 2% for curvature, capped at
/// `max_spend`. Pure so the cap invariant is unit-testable.
pub fn fund_required_input(
    max_spend: alloy::primitives::U256,
    missing_micro: u64,
    out_at_max_micro: u128,
) -> alloy::primitives::U256 {
    use alloy::primitives::U256;
    if out_at_max_micro == 0 {
        return max_spend;
    }
    let exact = max_spend
        .saturating_mul(U256::from(missing_micro))
        .checked_div(U256::from(out_at_max_micro))
        .unwrap_or(max_spend);
    let padded = exact.saturating_mul(U256::from(102u64)) / U256::from(100u64);
    padded.min(max_spend)
}

/// The purpose-built in-code route policy for `bloom polymarket fund` — a
/// documented temporary carve-out (B2): strictly tighter than any user
/// `[defi]` toml (one resolved receiver, one router, the settlement chain),
/// running the **same** `evaluate_defi_route` core as the generic surface.
/// The route receiver and output token are pinned by this command to the
/// resolved Polymarket deposit wallet and pUSD, so the generic
/// receiver/min-output route-fact checks are warning-only here. Wrong receiver,
/// token-out, router, or chain values still deny through the allowlists below.
/// Direct pUSD transfers do not go through this policy.
/// Args are lower-case hex / chain name.
pub fn fund_route_policy(
    chain: &str,
    token_out: &str,
    receiver: &str,
    router: &str,
) -> bloom_proto::DefiPolicy {
    let chain = chain.to_lowercase();
    bloom_proto::DefiPolicy {
        enabled: true,
        allowed_source_chains: [chain.clone()].into_iter().collect(),
        allowed_destination_chains: [chain.clone()].into_iter().collect(),
        allowed_receivers: [format!(
            "{chain}:{}:{}",
            token_out.to_lowercase(),
            receiver.to_lowercase()
        )]
        .into_iter()
        .collect(),
        denied_receivers: Default::default(),
        allowed_routers: [format!("{chain}:{}", router.to_lowercase())]
            .into_iter()
            .collect(),
        denied_protocols: Default::default(),
        allow_unknown_protocols: true,
        require_calldata_verification: false,
        max_input_usd: None,
        max_native_value_wei: None,
    }
}

#[cfg(test)]
mod tests {
    fn cfg(toml_src: &str) -> bloom_proto::config::PolymarketConfig {
        toml::from_str(toml_src).unwrap()
    }

    // The money paths (`fund`, `trade_funder`) load onboarding state directly,
    // so the owner-binding guard must reject state recorded under a different
    // key — otherwise a renamed/re-imported wallet could fund a deposit wallet
    // the current key cannot control.
    #[test]
    fn ensure_onboard_owner_rejects_a_different_key() {
        let st: bloom_polymarket::OnboardState = serde_json::from_value(serde_json::json!({
            "wallet": "w",
            "owner": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "deposit_wallet": "0x1000000000000000000000000000000000000001",
            "chain_id": 137, "stage": "complete",
            "deploy_tx_id": null, "approve_tx_id": null, "pusd_balance": null,
            "creds_present": true, "last_error": null, "updated_ms": 0
        }))
        .unwrap();
        let same: alloy::primitives::Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse()
            .unwrap();
        assert!(super::ensure_onboard_owner(&st, same).is_ok());
        let other: alloy::primitives::Address = "0x2000000000000000000000000000000000000002"
            .parse()
            .unwrap();
        let err = super::ensure_onboard_owner(&st, other).unwrap_err();
        assert!(err.to_string().contains("belongs to owner"), "{err}");
    }

    fn fund_ctx(receiver: &str, token_out: &str, router: &str) -> bloom_proto::DefiRouteCtx {
        bloom_proto::DefiRouteCtx {
            wallet: "minnow".into(),
            source_chain: "polygon".into(),
            destination_chain: "polygon".into(),
            cross_chain: false,
            receiver: receiver.into(),
            token_out: token_out.into(),
            receiver_class: bloom_proto::ReceiverClass::PolymarketDepositWallet,
            router: router.into(),
            protocols: vec!["enso".into()],
            protocols_unknown: false,
            input_microusd: None,
            native_value_wei: alloy::primitives::U256::ZERO,
            min_out_enforced: false,
            receiver_verified: false,
        }
    }

    /// The fund carve-out runs the shared evaluator but downgrades the generic
    /// quote-only receiver/min-output seam to warnings; this command already
    /// pins the receiver and token-out to the resolved deposit wallet and pUSD.
    #[test]
    fn fund_policy_ctx_warns_unverified_route_and_denies_mismatch() {
        let pusd = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";
        let recv = "0x1000000000000000000000000000000000000001";
        let router = "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf";
        let policy = super::fund_route_policy("polygon", pusd, recv, router);
        let checks = bloom_proto::evaluate_defi_route(&policy, &fund_ctx(recv, pusd, router));

        assert!(
            !bloom_proto::has_deny(&checks),
            "funding route fact gaps should warn, not deny"
        );
        assert!(
            checks.iter().any(|c| {
                c.rule == "defi.receiver_verified" && c.outcome == bloom_proto::PolicyOutcome::Warn
            }),
            "unverified receiver should remain visible as a warning"
        );
        assert!(
            checks.iter().any(|c| {
                c.rule == "defi.min_output" && c.outcome == bloom_proto::PolicyOutcome::Warn
            }),
            "quote-floor min output should remain visible as a warning"
        );

        // wrong receiver → deny
        let bad_recv = "0x000000000000000000000000000000000000dead";
        assert!(bloom_proto::has_deny(&bloom_proto::evaluate_defi_route(
            &policy,
            &fund_ctx(bad_recv, pusd, router)
        )));
        // wrong token-out → deny (receiver literal no longer matches)
        let usdc = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174";
        assert!(bloom_proto::has_deny(&bloom_proto::evaluate_defi_route(
            &policy,
            &fund_ctx(recv, usdc, router)
        )));
    }

    /// Wiring consequence: a same-chain route whose calldata encodes the deposit
    /// wallet sets `receiver_verified`, which must clear the receiver warning
    /// (min-output still warns until WP3). The unverified case still warns.
    #[test]
    fn fund_policy_calldata_verified_receiver_clears_its_warning() {
        let pusd = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";
        let recv = "0x1000000000000000000000000000000000000001";
        let router = "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf";
        let policy = super::fund_route_policy("polygon", pusd, recv, router);

        let mut verified = fund_ctx(recv, pusd, router);
        verified.receiver_verified = true; // as the fund path now sets it (same-chain)
        let checks = bloom_proto::evaluate_defi_route(&policy, &verified);
        assert!(!bloom_proto::has_deny(&checks));
        assert!(
            !checks.iter().any(|c| {
                c.rule == "defi.receiver_verified" && c.outcome == bloom_proto::PolicyOutcome::Warn
            }),
            "a calldata-verified receiver must not warn"
        );
        assert!(
            checks.iter().any(|c| {
                c.rule == "defi.min_output" && c.outcome == bloom_proto::PolicyOutcome::Warn
            }),
            "min-output stays a warning (unchanged by the receiver wiring)"
        );

        // Unverified (cross-chain / calldata mismatch) → receiver still warns.
        let unverified = fund_ctx(recv, pusd, router); // receiver_verified: false
        assert!(
            bloom_proto::evaluate_defi_route(&policy, &unverified)
                .iter()
                .any(|c| {
                    c.rule == "defi.receiver_verified"
                        && c.outcome == bloom_proto::PolicyOutcome::Warn
                })
        );
    }

    /// Target-denominated input is always capped at `--max-spend` (never
    /// over-spends), and meets the missing amount when the rate allows.
    #[test]
    fn fund_sizing_is_capped_at_max_spend() {
        use alloy::primitives::U256;
        let max = U256::from(85u64) * U256::from(10u64).pow(U256::from(18u64)); // 85 native
        // rate: 85 native buys 4.3 pUSD; missing 3.6 → ~71 native, under cap
        let req = super::fund_required_input(max, 3_600_000, 4_300_000);
        assert!(req < max, "should be under the cap");
        assert!(req > U256::ZERO);
        // pathological: rate says we'd need more than max → clamp to max
        let req2 = super::fund_required_input(max, 100_000_000, 1_000_000);
        assert_eq!(req2, max, "must never exceed --max-spend");
        // zero quote → fall back to max (caller separately rejects)
        assert_eq!(super::fund_required_input(max, 1, 0), max);
    }

    /// Deposit-wallet mode is the default; only the explicit legacy flag
    /// funds the owner EOA. The deposit-wallet address itself comes from
    /// onboarding state (factory-resolved), never from local derivation.
    #[test]
    fn funding_mode_resolution() {
        assert!(!cfg("").legacy_eoa_mode);
        let manual = cfg(
            "relayer_api_key = \"k\"\nrelayer_api_key_address = \"0xE51282BdEeeb988406B3f969a6277b02bAdc2e19\"\n",
        );
        assert!(!manual.legacy_eoa_mode);
        assert!(cfg("legacy_eoa_mode = true\n").legacy_eoa_mode);
    }

    // ── reconcile_match (R3) ─────────────────────────────────────────────────

    /// A draft fixed at token `42`, BUY, price 0.50, size 10.00 shares.
    fn reconcile_draft() -> bloom_polymarket::OrderDraft {
        use bloom_polymarket::order::OrderType;
        use bloom_polymarket::order_store::DraftStatus;
        use bloom_polymarket::types::Side;
        bloom_polymarket::OrderDraft {
            id: "0001".into(),
            wallet: "w".into(),
            owner: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            funder: None,
            signature_type: 3,
            slug: "s".into(),
            question: "?".into(),
            condition_id: "0xc".into(),
            outcome: "YES".into(),
            token_id: "42".into(),
            side: Side::Buy,
            order_type: OrderType::FAK,
            amount_microusd: 5_000_000,
            price_bound_micro: 500_000,
            marketable: true,
            limit_price_micro: 500_000,
            size_micro: 10_000_000,
            tick_micro: 10_000,
            min_order_size_micro: 0,
            neg_risk: false,
            active: true,
            closed: false,
            order_book_enabled: true,
            binary_outcomes: true,
            best_ask_micro: Some(500_000),
            best_bid_micro: Some(490_000),
            book_snapshot_ms: 0,
            policy_checks: serde_json::Value::Null,
            status: DraftStatus::Signed,
            salt: Some(777),
            clob_order_id: None,
            clob_status: None,
            last_error: None,
            review_intent_hash: None,
            created_ms: 0,
            updated_ms: 0,
        }
    }

    #[test]
    fn reconcile_salt_echo_is_conclusive() {
        let arr = vec![serde_json::json!({
            "id": "ord-1", "asset_id": "42", "side": "BUY",
            "price": "0.50", "original_size": "10", "salt": 777
        })];
        assert_eq!(
            super::reconcile_match(&arr, &reconcile_draft(), 777),
            Some("ord-1".to_string())
        );
        // salt as a string echo also matches.
        let arr = vec![serde_json::json!({
            "id": "ord-1", "asset_id": "42", "side": "BUY",
            "price": "0.50", "original_size": "10", "salt": "777"
        })];
        assert_eq!(
            super::reconcile_match(&arr, &reconcile_draft(), 777),
            Some("ord-1".to_string())
        );
    }

    #[test]
    fn reconcile_unique_field_and_size_match() {
        // No salt echo, but exactly one order matches token+side+price+size.
        let arr = vec![
            serde_json::json!({ "id": "other", "asset_id": "99", "side": "BUY",
                "price": "0.50", "original_size": "10" }),
            serde_json::json!({ "id": "ours", "asset_id": "42", "side": "BUY",
                "price": "0.50", "original_size": "10" }),
        ];
        assert_eq!(
            super::reconcile_match(&arr, &reconcile_draft(), 777),
            Some("ours".to_string())
        );
    }

    #[test]
    fn reconcile_refuses_ambiguous_duplicate() {
        // Two open orders at the same token/side/price/size and no salt echo:
        // we must NOT guess (caller marks the outcome Ambiguous).
        let arr = vec![
            serde_json::json!({ "id": "a", "asset_id": "42", "side": "BUY",
                "price": "0.50", "original_size": "10" }),
            serde_json::json!({ "id": "b", "asset_id": "42", "side": "BUY",
                "price": "0.50", "original_size": "10" }),
        ];
        assert_eq!(super::reconcile_match(&arr, &reconcile_draft(), 777), None);
    }

    #[test]
    fn reconcile_size_mismatch_is_not_a_match() {
        // Same token/side/price but a different size (a pre-existing resting
        // order) must not be claimed as ours.
        let arr = vec![serde_json::json!({ "id": "stale", "asset_id": "42",
            "side": "BUY", "price": "0.50", "original_size": "25" })];
        assert_eq!(super::reconcile_match(&arr, &reconcile_draft(), 777), None);
    }
}
