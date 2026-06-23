//! Local Polymarket handler petal.
//!
//! This petal owns `apps/polymarket/` directly. Public market/account reads go
//! through `bloom.v1::http_fetch`; staged local state goes through the
//! per-petal private `store_*` imports. It intentionally does not call the
//! native `polymarket/` VFS handler.

use std::collections::BTreeSet;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, U256};
use bloom_petal_sdk::{
    DispatchEntry, DispatchEntryKind, DispatchOp, DispatchRequest, DispatchResponse, HostStatus,
    HttpRequest, SdkError, SignRequest,
};
use bloom_polymarket::eip712::{
    Batch, CTF, CTF_COLLATERAL_ADAPTER, CTF_EXCHANGE_V2, FACTORY, NEG_RISK_CTF_COLLATERAL_ADAPTER,
    NEG_RISK_EXCHANGE_V2, PUSD, batch_signing_hash, clob_auth_signing_hash,
    derive_deposit_wallet_address,
};
use bloom_polymarket::order::{
    LimitQuote, OrderBody, OrderParams, OrderType, SIG_TYPE_POLY_1271, build_order, format_micro,
    parse_micro, poly1271_digest, wrap_poly1271_signature,
};
use bloom_polymarket::signer::{
    POLY_ADDRESS, POLY_NONCE, POLY_SIGNATURE, POLY_TIMESTAMP, l2_headers,
};
use bloom_polymarket::trade as shared_trade;
use bloom_polymarket::types::{Market, Side};
use bloom_polymarket::wallet::{V2_APPROVAL_LABELS, v2_approval_calls};
use bloom_polymarket::{
    BuilderCredentials, Credentials, OrderBook, POLYGON, Position, Trade, validate_wallet_name,
};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use url::Url;

const MAX_HTTP_BYTES: usize = 8 * 1024 * 1024;
const MAX_STORE_BYTES: usize = 1024 * 1024;
const MAX_LIST_BYTES: usize = 256 * 1024;
const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_CHAIN_METHOD_BYTES: usize = 256 * 1024;
const MAX_CHAIN_READ_BYTES: usize = 256 * 1024;
const MARKETS_LIST_LIMIT: u32 = 20;
const TRADE_LOCK_STALE_MS: u128 = 5 * 60 * 1000;

const GAMMA: &str = "https://gamma-api.polymarket.com";
const DATA: &str = "https://data-api.polymarket.com";
const CLOB: &str = "https://clob.polymarket.com";
const POLYMARKET_WEB: &str = "https://polymarket.com";
const RELAYER: &str = "https://relayer-v2.polymarket.com";
const CLOB_AUTH_NONCE: u32 = 0;
const ONBOARD_POLL_TIMEOUT_SECS: u64 = 180;
const ONBOARD_POLL_INTERVAL_SECS: u64 = 2;
const BATCH_DEADLINE_SECS: u64 = 3600;

const ROOT_DIRS: [&str; 8] = [
    "markets",
    "search",
    "positions",
    "onboard",
    "account",
    "trade",
    "fund",
    "meta",
];
const META_FILES: [&str; 1] = ["parity.json"];
const MARKET_FILES: [&str; 3] = ["market.json", "book.json", "prices.json"];
const POSITION_FILES: [&str; 3] = ["positions.json", "trades.json", "activity.json"];
const ONBOARD_FILES: [&str; 3] = ["status.json", "plan.md", "approvals.json"];
const ACCOUNT_FILES: [&str; 2] = ["portfolio.json", "orders.json"];
const FUND_FILES: [&str; 3] = ["plan.md", "request.json", "status.json"];
const DRAFT_FILES: [&str; 6] = [
    "plan.md",
    "order.json",
    "policy_check.json",
    "quote.json",
    "review_intent.json",
    "post_attempt.json",
];
const DRAFT_WRITABLE_FILES: [&str; 2] = ["revalidate", "post"];
const RECEIPT_FILES: [&str; 1] = ["receipt.json"];
const RECEIPT_WRITABLE_FILES: [&str; 1] = ["cancel"];

const BEGIN_HINT: &str =
    "write anything here to mint or derive CLOB credentials with the daemon keystore\n";
const TRADE_NEW_HINT: &str = r#"write JSON to create a reviewable draft, e.g.
{"slug":"will-canada-win-the-2026-fifa-world-cup-755","outcome":"yes","amount":"1","max_price":"0.01"}
"#;
const FUND_NEW_HINT: &str = r#"write JSON to create a reviewable pUSD funding request, e.g.
{"target_pusd":"10","max_spend":"100","from_token":"native","slippage_bps":50}
"#;
const TRADE_REVALIDATE_HINT: &str = r#"write {"revalidate":true} to revalidate this draft and stage the final review artifact. Revalidated drafts can then be posted by writing {"post":true} to post; resting GTC orders can be cancelled from their receipt.
"#;
const TRADE_POST_HINT: &str = r#"write {"post":true} to sign and post a revalidated draft, then write a private receipt. This performs a value-moving CLOB POST /order.
"#;
const TRADE_CANCEL_HINT: &str = r#"write {"cancel":true} to cancel the posted CLOB order recorded by this receipt. Cancelling uses CLOB DELETE /order and updates the private receipt/draft status.
"#;

bloom_petal_sdk::export_dispatch!(handle);

pub fn handle(req: DispatchRequest) -> DispatchResponse {
    let relative = match validate_relative_path(&req.path) {
        Ok(path) => path,
        Err(message) => return error(-3, message),
    };
    match req.op {
        DispatchOp::Lookup => lookup(relative),
        DispatchOp::List => list(relative),
        DispatchOp::Read => read(relative),
        DispatchOp::Write => write(relative, &req.body),
    }
}

fn lookup(relative: &str) -> DispatchResponse {
    match path_kind(relative) {
        Some(kind) => DispatchResponse::Lookup(entry(entry_name(relative), kind)),
        None => error(-1, "not found"),
    }
}

fn list(relative: &str) -> DispatchResponse {
    if path_kind(relative) != Some(DispatchEntryKind::Dir) {
        return error(-3, "not a directory");
    }
    let segs = split(relative);
    let names = match (segs.first().copied(), segs.len()) {
        (None, 0) => ROOT_DIRS.iter().map(|s| (*s).to_string()).collect(),
        (Some("markets"), 1) => match list_market_slugs() {
            Ok(slugs) => slugs,
            Err(resp) => return resp,
        },
        (Some("markets"), 2) => strings(&MARKET_FILES),
        (Some("meta"), 1) => strings(&META_FILES),
        (Some("positions"), 1) => vfs_wallets_or_store(""),
        (Some("positions"), 2) => strings(&POSITION_FILES),
        (Some("onboard"), 1) => vfs_wallets_or_store("onboard/"),
        (Some("onboard"), 2) => {
            let mut out = vec!["begin".to_string()];
            out.extend(strings(&ONBOARD_FILES));
            out
        }
        (Some("account"), 1) => vfs_wallets_or_store("creds/"),
        (Some("account"), 2) => strings(&ACCOUNT_FILES),
        (Some("fund"), 1) => vfs_wallets_or_store("fund/"),
        (Some("fund"), 2) => {
            let mut out = vec!["new".to_string()];
            out.extend(store_ids(&format!("fund/{}/requests/", segs[1]), ".json"));
            out
        }
        (Some("fund"), 3) if segs[2] != "new" => strings(&FUND_FILES),
        (Some("trade"), 1) => vfs_wallets_or_store("trade/"),
        (Some("trade"), 2) => vec!["new".into(), "drafts".into(), "receipts".into()],
        (Some("trade"), 3) if segs[2] == "drafts" => {
            store_ids(&format!("trade/{}/drafts/", segs[1]), "/order.json")
        }
        (Some("trade"), 3) if segs[2] == "receipts" => {
            store_ids(&format!("trade/{}/receipts/", segs[1]), "/receipt.json")
        }
        (Some("trade"), 4) if segs[2] == "drafts" => {
            let mut out = strings(&DRAFT_FILES);
            out.extend(strings(&DRAFT_WRITABLE_FILES));
            out
        }
        (Some("trade"), 4) if segs[2] == "receipts" => {
            let mut out = strings(&RECEIPT_FILES);
            out.extend(strings(&RECEIPT_WRITABLE_FILES));
            out
        }
        _ => Vec::new(),
    };
    DispatchResponse::List(
        names
            .into_iter()
            .filter(|name| is_safe_segment(name))
            .filter_map(|name| {
                let child = child_relative(relative, &name);
                path_kind(&child).map(|kind| entry(&name, kind))
            })
            .collect(),
    )
}

fn read(relative: &str) -> DispatchResponse {
    if !matches!(
        path_kind(relative),
        Some(DispatchEntryKind::File | DispatchEntryKind::WritableFile)
    ) {
        return error(-3, "not a file");
    }
    let segs = split(relative);
    match (segs.first().copied(), segs.len()) {
        (Some("markets"), 3) => read_market(segs[1], segs[2]),
        (Some("meta"), 2) => read_meta(segs[1]),
        (Some("search"), 2) => read_search(segs[1]),
        (Some("positions"), 3) => read_positions(segs[1], segs[2]),
        (Some("onboard"), 3) => read_onboard(segs[1], segs[2]),
        (Some("account"), 3) => read_account(segs[1], segs[2]),
        (Some("fund"), 3) if segs[2] == "new" => DispatchResponse::Read(FUND_NEW_HINT.into()),
        (Some("fund"), 4) => read_fund(segs[1], segs[2], segs[3]),
        (Some("trade"), 3) if segs[2] == "new" => DispatchResponse::Read(TRADE_NEW_HINT.into()),
        (Some("trade"), 5) => read_trade(segs[1], segs[2], segs[3], segs[4]),
        _ => error(-3, "not a file"),
    }
}

fn write(relative: &str, body: &[u8]) -> DispatchResponse {
    if path_kind(relative) != Some(DispatchEntryKind::WritableFile) {
        return error(-2, "path is not writable");
    }
    let segs = split(relative);
    match (segs.first().copied(), segs.len()) {
        (Some("onboard"), 3) if segs[2] == "begin" => write_onboard_begin(segs[1]),
        (Some("trade"), 3) if segs[2] == "new" => write_trade_new(segs[1], body),
        (Some("trade"), 5) if segs[2] == "drafts" && segs[4] == "revalidate" => {
            write_trade_revalidate(segs[1], segs[3], body)
        }
        (Some("trade"), 5) if segs[2] == "drafts" && segs[4] == "post" => {
            write_trade_post(segs[1], segs[3], body)
        }
        (Some("trade"), 5) if segs[2] == "receipts" && segs[4] == "cancel" => {
            write_trade_cancel(segs[1], segs[3], body)
        }
        (Some("fund"), 3) if segs[2] == "new" => write_fund_new(segs[1], body),
        _ => error(-2, "path is not writable"),
    }
}

fn read_meta(file: &str) -> DispatchResponse {
    match file {
        "parity.json" => read_json_value(&serde_json::json!({
            "kind": "polymarket_local_petal_parity",
            "mount": "apps/polymarket",
            "native_handler": "polymarket",
            "status": "ready_for_graduation",
            "graduation_ready": true,
            "no_on_chain_code_touched_by_local_petal": true,
            "secret_storage": {
                "clob_credentials": "private_store_only",
                "builder_credentials": "private_store_only",
                "public_vfs_receipts": "redacted_summaries_only"
            },
            "implemented": [
                {
                    "id": "market_reads",
                    "surface": ["markets/*/market.json", "markets/*/book.json", "markets/*/prices.json"],
                    "evidence": "HTTP via manifest allowlisted Gamma/CLOB reads"
                },
                {
                    "id": "positions_and_account_reads",
                    "surface": ["positions/*/*.json", "account/*/portfolio.json", "account/*/orders.json"],
                    "evidence": "wallet-resolved Data API and L2 CLOB account reads"
                },
                {
                    "id": "onboarding_credentials",
                    "surface": ["onboard/*/begin", "onboard/*/status.json", "onboard/*/approvals.json"],
                    "evidence": "geoblock-gated live factory deposit-wallet resolution plus CLOB auth signature through sign_hash and private credential storage"
                },
                {
                    "id": "factory_resolved_deposit_wallet",
                    "surface": ["onboard/*/status.json", "onboard/*/approvals.json", "fund/*/new", "trade/*/drafts/*/revalidate", "trade/*/drafts/*/post"],
                    "evidence": "funding and posting paths require a persisted live_factory_resolved deposit wallet instead of the display-only local CREATE2 estimate"
                },
                {
                    "id": "read_only_onboarding_stage_probes",
                    "surface": ["onboard/*/status.json", "account/*/portfolio.json", "trade/*/drafts/*/revalidate", "trade/*/drafts/*/post"],
                    "evidence": "local status recomputes deployed/funded/approved/credentialed/CLOB-synced readiness from VFS chain reads plus private credentials; posting requires stage=complete"
                },
                {
                    "id": "onboarding_relayer_deploy_approve_sync",
                    "surface": ["onboard/*/begin", "onboard/*/status.json"],
                    "evidence": "local begin auto-mints private builder credentials, submits relayer WALLET-CREATE and signed V2 approval WALLET batches when live probes show they are needed, polls confirmation, rests at fund when pUSD is absent, and calls CLOB balance-allowance update before marking complete"
                },
                {
                    "id": "buy_posting",
                    "surface": ["trade/*/drafts/*/revalidate", "trade/*/drafts/*/post"],
                    "evidence": "final-review-bound POLY_1271 buy posting with private receipt/audit records"
                },
                {
                    "id": "authoritative_sell_posting",
                    "surface": ["trade/*/drafts/*/revalidate", "trade/*/drafts/*/post"],
                    "evidence": "sell posting is gated by CLOB conditional balance and chain CTF balanceOf/isApprovedForAll reads through the host VFS; Data API holdings are recorded as corroborating evidence only"
                },
                {
                    "id": "ambiguous_post_reconciliation",
                    "surface": ["trade/*/drafts/*/post"],
                    "evidence": "lost POST outcomes reconcile only against strongly matched L2 /data/orders responses"
                },
                {
                    "id": "resting_gtc_cancel",
                    "surface": ["trade/*/receipts/*/cancel"],
                    "evidence": "GTC buy posting is paired with exact DELETE /order cancel from private receipt order id"
                },
                {
                    "id": "local_policy_and_daily_cap",
                    "surface": ["trade/*/drafts/*/policy_check.json"],
                    "evidence": "wallet policy, receipt-audit parity, and daily exposure checks fail closed"
                }
            ],
            "remaining_blockers": [],
            "graduation_evidence": [
                "compiled wasm router smoke covers apps/polymarket market, search, position, account, onboarding, funding, buy, sell, reconcile, cancel, and public redaction surfaces",
                "public VFS reads are swept for private CLOB credentials, builder credentials, API keys/passphrases, raw echoed signatures, raw CLOB response bodies, and echoed signature payloads",
                "adversarial review findings are fixed or documented in docs/reviews/2026-06-23-local-petal-plugins-closeout.md",
                "GTD order posting remains deferred because the native handler also rejects GTD orders"
            ],
            "native_unsupported_or_deferred": [
                {
                    "id": "gtd_orders",
                    "status": "not_required_for_native_parity",
                    "reason": "the current native handler rejects GTD orders; the local petal also rejects GTD pending a future expiry policy"
                }
            ],
            "graduation_requirements": [
                "all implemented surfaces pass focused and broader validation",
                "adversarial review has no unresolved findings",
                "public VFS reads contain no CLOB credential secret or raw signed order body",
                "remaining blockers are either implemented or explicitly accepted before replacing native polymarket/"
            ]
        })),
        _ => error(-3, "not a meta file"),
    }
}

fn read_market(slug: &str, file: &str) -> DispatchResponse {
    let market: Market = match get_json(&format!("{GAMMA}/markets/slug/{slug}")) {
        Ok(market) => market,
        Err(resp) => return resp,
    };
    match file {
        "market.json" => read_json_value(&market),
        "book.json" => {
            let Some(token_id) = market.yes_token_id() else {
                return error(-4, "market has no YES token id");
            };
            match get_json::<OrderBook>(&url_with_query(
                &format!("{CLOB}/book"),
                &[("token_id", token_id)],
            )) {
                Ok(book) => read_json_value(&book),
                Err(resp) => resp,
            }
        }
        "prices.json" => {
            let Some(token_id) = market.yes_token_id() else {
                return error(-4, "market has no YES token id");
            };
            let midpoint = match get_json::<serde_json::Value>(&url_with_query(
                &format!("{CLOB}/midpoint"),
                &[("token_id", token_id)],
            )) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            let spread = match get_json::<serde_json::Value>(&url_with_query(
                &format!("{CLOB}/spread"),
                &[("token_id", token_id)],
            )) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            let best_buy = match get_json::<serde_json::Value>(&url_with_query(
                &format!("{CLOB}/price"),
                &[("token_id", token_id), ("side", "BUY")],
            )) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            read_json_value(&serde_json::json!({
                "token_id": token_id,
                "midpoint": midpoint,
                "spread": spread,
                "best_buy": best_buy,
            }))
        }
        _ => error(-3, "not a market file"),
    }
}

fn read_search(query: &str) -> DispatchResponse {
    let query = query.replace('+', " ");
    match get_json::<serde_json::Value>(&url_with_query(
        &format!("{GAMMA}/public-search"),
        &[("q", &query)],
    )) {
        Ok(value) => read_json_value(&value),
        Err(resp) => resp,
    }
}

fn read_positions(user: &str, file: &str) -> DispatchResponse {
    let user = match resolve_position_user(user) {
        Ok(user) => user,
        Err(resp) => return resp,
    };
    match file {
        "positions.json" => match get_json::<Vec<Position>>(&url_with_query(
            &format!("{DATA}/positions"),
            &[("user", &user)],
        )) {
            Ok(value) => read_json_value(&value),
            Err(resp) => resp,
        },
        "trades.json" => match get_json::<Vec<Trade>>(&url_with_query(
            &format!("{DATA}/trades"),
            &[("user", &user)],
        )) {
            Ok(value) => read_json_value(&value),
            Err(resp) => resp,
        },
        "activity.json" => match get_json::<serde_json::Value>(&url_with_query(
            &format!("{DATA}/activity"),
            &[("user", &user)],
        )) {
            Ok(value) => read_json_value(&value),
            Err(resp) => resp,
        },
        _ => error(-3, "not a positions file"),
    }
}

fn resolve_position_user(segment: &str) -> Result<String, DispatchResponse> {
    if segment.starts_with("0x") || segment.starts_with("0X") {
        if let Ok(address) = segment.parse::<Address>() {
            return Ok(address.to_checksum(None));
        }
    }
    wallet_address(segment).map(|address| address.to_checksum(None))
}

fn read_onboard(wallet: &str, file: &str) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    match file {
        "begin" => DispatchResponse::Read(BEGIN_HINT.into()),
        "status.json" => {
            let status = match wallet_address(wallet) {
                Ok(owner) => match local_status_for_wallet(wallet, owner) {
                    Ok(status) => status,
                    Err(resp) => return resp,
                },
                Err(_) => serde_json::json!({
                    "wallet": wallet,
                    "stage": "not_started",
                    "running": false,
                    "tradeable": false,
                    "message": "write begin to mint or derive CLOB credentials"
                }),
            };
            read_json_value(&status)
        }
        "plan.md" => DispatchResponse::Read(render_onboard_plan(wallet).into_bytes()),
        "approvals.json" => match wallet_address(wallet) {
            Ok(owner) => read_json_value(&approval_preview(wallet, owner)),
            Err(resp) => resp,
        },
        _ => error(-3, "not an onboard file"),
    }
}

fn read_account(wallet: &str, file: &str) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    let owner = match wallet_address(wallet) {
        Ok(address) => address,
        Err(resp) => return resp,
    };
    let creds = match load_creds(wallet) {
        Ok(creds) => creds,
        Err(resp) => return resp,
    };
    match file {
        "portfolio.json" => match clob_l2_get_json(
            owner,
            &creds,
            "/balance-allowance",
            &[("asset_type", "COLLATERAL"), ("signature_type", "3")],
        ) {
            Ok(clob_balance_allowance) => {
                let status = match local_status_for_wallet(wallet, owner) {
                    Ok(status) => status,
                    Err(resp) => return resp,
                };
                read_json_value(&serde_json::json!({
                    "wallet": wallet,
                    "owner": format!("{owner:#x}"),
                    "credentials_present": true,
                    "clob_balance_allowance": clob_balance_allowance,
                    "deposit_wallet": status
                        .get("deposit_wallet")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                    "onboarding_state": {
                        "stage": status.get("stage").cloned().unwrap_or(serde_json::Value::Null),
                        "creds_present": status.get("creds_present").cloned().unwrap_or(serde_json::Value::Bool(true)),
                        "tradeable": status.get("tradeable").cloned().unwrap_or(serde_json::Value::Bool(false))
                    }
                }))
            }
            Err(resp) => resp,
        },
        "orders.json" => match clob_l2_get_json(owner, &creds, "/data/orders", &[]) {
            Ok(orders) => read_json_value(&orders),
            Err(resp) => resp,
        },
        _ => error(-3, "not an account file"),
    }
}

fn write_onboard_begin(wallet: &str) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    let owner = match wallet_address(wallet) {
        Ok(address) => address,
        Err(resp) => return resp,
    };
    if let Err(resp) = check_geoblock() {
        return resp;
    }
    let deposit = match predict_deposit_wallet(owner) {
        Ok(deposit) => deposit,
        Err(resp) => return resp,
    };
    let timestamp = now_secs();
    let hash = clob_auth_signing_hash(owner, timestamp, CLOB_AUTH_NONCE, POLYGON);
    let signature = match bloom_petal_sdk::sign_hash(&SignRequest {
        wallet: wallet.into(),
        hash32: hash.into(),
        purpose: "polymarket.clob_auth".into(),
    }) {
        Ok(sig) if sig.len() == 65 => format!("0x{}", hex::encode(sig)),
        Ok(sig) => return error(-4, format!("sign_hash returned {} bytes", sig.len())),
        Err(e) => return sdk_error(e),
    };
    let headers = [
        (POLY_ADDRESS, format!("{owner:#x}")),
        (POLY_NONCE, CLOB_AUTH_NONCE.to_string()),
        (POLY_SIGNATURE, signature),
        (POLY_TIMESTAMP, timestamp.to_string()),
    ];
    let creds = match clob_auth_request("POST", "/auth/api-key", &headers) {
        Ok(creds) => creds,
        Err(DispatchResponse::Error { code: -4, .. }) => {
            match clob_auth_request("GET", "/auth/derive-api-key", &headers) {
                Ok(creds) => creds,
                Err(resp) => return resp,
            }
        }
        Err(resp) => return resp,
    };
    if let DispatchResponse::Error { .. } =
        store_put_json(&format!("creds/{wallet}/clob.json"), &creds, true)
    {
        return error(-4, "failed to store CLOB credentials");
    }
    match run_onboard_stages(wallet, owner, deposit, &creds) {
        Ok(status) => store_put_json(&format!("onboard/{wallet}/status.json"), &status, false),
        Err(resp) => {
            let _ = persist_onboard_failure(wallet, owner, deposit, &resp);
            resp
        }
    }
}

fn check_geoblock() -> Result<(), DispatchResponse> {
    let resp = bloom_petal_sdk::http_fetch(
        &HttpRequest {
            method: "GET".into(),
            url: format!("{POLYMARKET_WEB}/api/geoblock"),
            headers: Vec::new(),
            body: Vec::new(),
        },
        MAX_HTTP_BYTES,
    )
    .map_err(|e| {
        error(
            -3,
            format!(
                "could not verify region availability (geoblock check failed: {}); refusing",
                e.message()
            ),
        )
    })?;
    if !(200..300).contains(&resp.status) {
        return Err(error(
            -3,
            format!(
                "could not verify region availability (geoblock status {}); refusing",
                resp.status
            ),
        ));
    }
    let status: GeoblockStatus = serde_json::from_slice(&resp.body).map_err(|e| {
        error(
            -3,
            format!("could not verify region availability (geoblock JSON: {e}); refusing"),
        )
    })?;
    if status.blocked {
        return Err(error(
            -3,
            format!(
                "Polymarket is unavailable in your region (country={}, region={}); refusing to onboard",
                status.country, status.region
            ),
        ));
    }
    Ok(())
}

fn local_onboard_status(
    wallet: &str,
    owner: Address,
    stage: &str,
    running: bool,
    creds_present: bool,
    message: &str,
) -> serde_json::Value {
    let deposit = derive_deposit_wallet_address(&owner, POLYGON);
    serde_json::json!({
        "wallet": wallet,
        "owner": format!("{owner:#x}"),
        "stage": stage,
        "running": running,
        "tradeable": false,
        "creds_present": creds_present,
        "deposit_wallet": {
            "address": deposit.to_checksum(None),
            "source": "local_estimate_unverified",
            "fundable": false,
            "warning": "do not fund this local estimate; full onboarding must resolve the live factory address first"
        },
        "approvals": {
            "required": true,
            "preview_path": format!("onboard/{wallet}/approvals.json")
        },
        "message": message
    })
}

struct LiveOnboardStatus<'a> {
    wallet: &'a str,
    owner: Address,
    deposit: Address,
    stage: &'a str,
    running: bool,
    creds_present: bool,
    tradeable: bool,
    message: &'a str,
    probes: serde_json::Value,
}

fn local_onboard_status_with_live_deposit(status: LiveOnboardStatus<'_>) -> serde_json::Value {
    serde_json::json!({
        "wallet": status.wallet,
        "owner": status.owner.to_checksum(None),
        "stage": status.stage,
        "running": status.running,
        "tradeable": status.tradeable,
        "creds_present": status.creds_present,
        "deposit_wallet": {
            "address": status.deposit.to_checksum(None),
            "source": "live_factory_resolved",
            "fundable": true,
            "warning": serde_json::Value::Null
        },
        "approvals": {
            "required": true,
            "preview_path": format!("onboard/{}/approvals.json", status.wallet)
        },
        "probes": status.probes,
        "message": status.message
    })
}

fn refreshed_live_onboard_status(
    wallet: &str,
    owner: Address,
    deposit: Address,
    creds_present: bool,
) -> Result<serde_json::Value, DispatchResponse> {
    let deployed = read_chain_deposit_wallet_deployed(deposit)?;
    let pusd_balance = if deployed {
        read_chain_erc20_balance(PUSD, deposit)?
    } else {
        U256::ZERO
    };
    let approvals_in_place = if deployed && !pusd_balance.is_zero() {
        read_chain_v2_approvals(deposit)?
    } else {
        false
    };
    let (clob_synced, clob_balance, clob_allowance) =
        if deployed && !pusd_balance.is_zero() && approvals_in_place && creds_present {
            let creds = load_creds(wallet)?;
            read_clob_collateral_sync(owner, &creds)?
        } else {
            (false, None, None)
        };

    let (stage, tradeable, message) = if !deployed {
        (
            "deploy",
            false,
            "deposit wallet resolved from the live factory; waiting for the native relayer deploy stage",
        )
    } else if pusd_balance.is_zero() {
        (
            "fund",
            false,
            "deposit wallet is deployed; waiting for pUSD funding",
        )
    } else if !approvals_in_place {
        (
            "approve",
            false,
            "deposit wallet holds pUSD; waiting for V2 exchange and adapter approvals",
        )
    } else if !creds_present {
        (
            "creds",
            false,
            "deposit wallet is funded and approved; write begin to mint or derive CLOB credentials",
        )
    } else if !clob_synced {
        (
            "sync",
            false,
            "deposit wallet is funded and approved; waiting for CLOB collateral balance/allowance sync",
        )
    } else {
        (
            "complete",
            true,
            "local read-only probes show the deposit wallet is deployed, funded, approved, credentialed, and CLOB-synced",
        )
    };

    Ok(local_onboard_status_with_live_deposit(LiveOnboardStatus {
        wallet,
        owner,
        deposit,
        stage,
        running: false,
        creds_present,
        tradeable,
        message,
        probes: serde_json::json!({
            "source": "vfs_chain_and_clob_read_only",
            "deposit_wallet_deployed": deployed,
            "pusd_balance_raw": pusd_balance.to_string(),
            "approvals_in_place": approvals_in_place,
            "clob_collateral_balance_raw": clob_balance.map(|v| v.to_string()),
            "clob_collateral_allowance_raw": clob_allowance.map(|v| v.to_string()),
            "clob_collateral_synced": clob_synced
        }),
    }))
}

fn run_onboard_stages(
    wallet: &str,
    owner: Address,
    deposit: Address,
    creds: &Credentials,
) -> Result<serde_json::Value, DispatchResponse> {
    let mut deploy_tx_id = stored_status_for_wallet(wallet, owner)
        .ok()
        .and_then(|status| {
            status
                .get("deploy_tx_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        });
    let mut approve_tx_id = stored_status_for_wallet(wallet, owner)
        .ok()
        .and_then(|status| {
            status
                .get("approve_tx_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        });

    if !read_chain_deposit_wallet_deployed(deposit)? {
        let _builder = ensure_builder_credentials(wallet, owner, creds)?;
        let tx = relayer_submit_with_builder_repair(
            wallet,
            owner,
            creds,
            serde_json::json!({
                "type": "WALLET-CREATE",
                "from": owner.to_checksum(None),
                "to": FACTORY.to_checksum(None),
            }),
        )?;
        deploy_tx_id = Some(tx.id.clone());
        persist_onboard_status(
            wallet,
            owner,
            deposit,
            true,
            OnboardStatusExtra {
                stage: Some("deploy"),
                deploy_tx_id: deploy_tx_id.clone(),
                approve_tx_id: approve_tx_id.clone(),
                in_flight_deadline_ms: Some(onboard_in_flight_deadline_ms()),
                relayer_auth: Some("builder_key_auto"),
                last_error: None,
            },
        )?;
        let confirmed = match relayer_poll_confirmed(&tx) {
            Ok(done) => done,
            Err(resp) => {
                let msg = dispatch_error_message(&resp);
                persist_onboard_status(
                    wallet,
                    owner,
                    deposit,
                    true,
                    OnboardStatusExtra {
                        stage: Some("deploy"),
                        deploy_tx_id,
                        approve_tx_id,
                        in_flight_deadline_ms: None,
                        relayer_auth: Some("builder_key_auto"),
                        last_error: Some(msg),
                    },
                )?;
                return Err(resp);
            }
        };
        deploy_tx_id = Some(confirmed.id);
        if !read_chain_deposit_wallet_deployed(deposit)? {
            let msg = "relayer confirmed the deploy but no proxy implementation exists at the deposit wallet".to_string();
            persist_onboard_status(
                wallet,
                owner,
                deposit,
                true,
                OnboardStatusExtra {
                    stage: Some("deploy"),
                    deploy_tx_id,
                    approve_tx_id,
                    in_flight_deadline_ms: None,
                    relayer_auth: Some("builder_key_auto"),
                    last_error: Some(msg.clone()),
                },
            )?;
            return Err(error(-4, msg));
        }
    }

    let pusd_balance = read_chain_erc20_balance(PUSD, deposit)?;
    if pusd_balance.is_zero() {
        return persist_onboard_status(
            wallet,
            owner,
            deposit,
            true,
            OnboardStatusExtra {
                stage: Some("fund"),
                deploy_tx_id,
                approve_tx_id,
                in_flight_deadline_ms: None,
                relayer_auth: Some("builder_key_auto"),
                last_error: None,
            },
        );
    }

    if !read_chain_v2_approvals(deposit)? {
        let _builder = ensure_builder_credentials(wallet, owner, creds)?;
        let nonce = relayer_wallet_nonce(owner)?;
        let deadline = now_secs().saturating_add(BATCH_DEADLINE_SECS);
        let tx = relayer_submit_with_builder_repair(
            wallet,
            owner,
            creds,
            relayer_batch_body(wallet, owner, deposit, nonce, deadline)?,
        )?;
        approve_tx_id = Some(tx.id.clone());
        persist_onboard_status(
            wallet,
            owner,
            deposit,
            true,
            OnboardStatusExtra {
                stage: Some("approve"),
                deploy_tx_id: deploy_tx_id.clone(),
                approve_tx_id: approve_tx_id.clone(),
                in_flight_deadline_ms: Some(onboard_in_flight_deadline_ms()),
                relayer_auth: Some("builder_key_auto"),
                last_error: None,
            },
        )?;
        let confirmed = match relayer_poll_confirmed(&tx) {
            Ok(done) => done,
            Err(resp) => {
                let msg = dispatch_error_message(&resp);
                persist_onboard_status(
                    wallet,
                    owner,
                    deposit,
                    true,
                    OnboardStatusExtra {
                        stage: Some("approve"),
                        deploy_tx_id,
                        approve_tx_id,
                        in_flight_deadline_ms: None,
                        relayer_auth: Some("builder_key_auto"),
                        last_error: Some(msg),
                    },
                )?;
                return Err(resp);
            }
        };
        approve_tx_id = Some(confirmed.id);
        if !read_chain_v2_approvals(deposit)? {
            let msg = "approvals confirmed but on-chain allowances are still missing".to_string();
            persist_onboard_status(
                wallet,
                owner,
                deposit,
                true,
                OnboardStatusExtra {
                    stage: Some("approve"),
                    deploy_tx_id,
                    approve_tx_id,
                    in_flight_deadline_ms: None,
                    relayer_auth: Some("builder_key_auto"),
                    last_error: Some(msg.clone()),
                },
            )?;
            return Err(error(-4, msg));
        }
    }

    persist_onboard_status(
        wallet,
        owner,
        deposit,
        true,
        OnboardStatusExtra {
            stage: Some("sync"),
            deploy_tx_id: deploy_tx_id.clone(),
            approve_tx_id: approve_tx_id.clone(),
            in_flight_deadline_ms: Some(onboard_in_flight_deadline_ms()),
            relayer_auth: Some("builder_key_auto"),
            last_error: None,
        },
    )?;
    clob_l2_get_json(
        owner,
        creds,
        "/balance-allowance/update",
        &[("asset_type", "COLLATERAL"), ("signature_type", "3")],
    )?;
    persist_onboard_status(
        wallet,
        owner,
        deposit,
        true,
        OnboardStatusExtra {
            stage: None,
            deploy_tx_id,
            approve_tx_id,
            in_flight_deadline_ms: None,
            relayer_auth: Some("builder_key_auto"),
            last_error: None,
        },
    )
}

#[derive(Default)]
struct OnboardStatusExtra {
    stage: Option<&'static str>,
    deploy_tx_id: Option<String>,
    approve_tx_id: Option<String>,
    in_flight_deadline_ms: Option<u128>,
    relayer_auth: Option<&'static str>,
    last_error: Option<String>,
}

fn persist_onboard_status(
    wallet: &str,
    owner: Address,
    deposit: Address,
    creds_present: bool,
    extra: OnboardStatusExtra,
) -> Result<serde_json::Value, DispatchResponse> {
    let mut status = refreshed_live_onboard_status(wallet, owner, deposit, creds_present)?;
    if let Some(obj) = status.as_object_mut() {
        if let Some(stage) = extra.stage {
            obj.insert("stage".into(), serde_json::Value::String(stage.into()));
            obj.insert(
                "tradeable".into(),
                serde_json::Value::Bool(stage == "complete"),
            );
        }
        obj.insert(
            "deploy_tx_id".into(),
            extra
                .deploy_tx_id
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null),
        );
        obj.insert(
            "approve_tx_id".into(),
            extra
                .approve_tx_id
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null),
        );
        obj.insert(
            "in_flight_deadline_ms".into(),
            extra
                .in_flight_deadline_ms
                .map(|v| serde_json::Value::String(v.to_string()))
                .unwrap_or(serde_json::Value::Null),
        );
        obj.insert(
            "relayer_auth".into(),
            extra
                .relayer_auth
                .map(|v| serde_json::Value::String(v.into()))
                .unwrap_or(serde_json::Value::Null),
        );
        obj.insert(
            "last_error".into(),
            extra
                .last_error
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null),
        );
        obj.insert(
            "status_updated_ms".into(),
            serde_json::Value::String(now_millis().to_string()),
        );
    }
    if let DispatchResponse::Error { .. } =
        store_put_json(&format!("onboard/{wallet}/status.json"), &status, false)
    {
        return Err(error(-4, "failed to persist onboarding status"));
    }
    Ok(status)
}

fn persist_onboard_failure(
    wallet: &str,
    owner: Address,
    deposit: Address,
    resp: &DispatchResponse,
) -> Result<serde_json::Value, DispatchResponse> {
    persist_onboard_status(
        wallet,
        owner,
        deposit,
        store_get(&format!("creds/{wallet}/clob.json")).is_some(),
        OnboardStatusExtra {
            last_error: Some(dispatch_error_message(resp)),
            ..OnboardStatusExtra::default()
        },
    )
}

fn local_status_for_wallet(
    wallet: &str,
    owner: Address,
) -> Result<serde_json::Value, DispatchResponse> {
    let status = stored_status_for_wallet(wallet, owner)?;
    let deposit_value = status.get("deposit_wallet");
    let source = deposit_value
        .and_then(|value| value.get("source"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if source != "live_factory_resolved" {
        return Ok(status);
    }
    let deposit = deposit_value
        .and_then(|value| value.get("address"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| error(-4, "stored onboarding status is missing deposit wallet"))?
        .parse::<Address>()
        .map_err(|e| error(-4, format!("stored deposit wallet parse: {e}")))?;
    let creds_present = store_get(&format!("creds/{wallet}/clob.json")).is_some();
    let mut refreshed = refreshed_live_onboard_status(wallet, owner, deposit, creds_present)?;
    preserve_onboard_metadata(&status, &mut refreshed);
    if refreshed != status {
        if let DispatchResponse::Error { .. } =
            store_put_json(&format!("onboard/{wallet}/status.json"), &refreshed, false)
        {
            return Err(error(-4, "failed to refresh onboarding status"));
        }
    }
    Ok(refreshed)
}

fn preserve_onboard_metadata(previous: &serde_json::Value, refreshed: &mut serde_json::Value) {
    let refreshed_complete =
        refreshed.get("stage").and_then(serde_json::Value::as_str) == Some("complete");
    let Some(obj) = refreshed.as_object_mut() else {
        return;
    };
    for key in [
        "deploy_tx_id",
        "approve_tx_id",
        "relayer_auth",
        "status_updated_ms",
    ] {
        if let Some(value) = previous.get(key) {
            obj.insert(key.into(), value.clone());
        }
    }
    if previous
        .get("in_flight_deadline_ms")
        .is_some_and(|value| !value.is_null())
        && !refreshed_complete
    {
        obj.insert(
            "in_flight_deadline_ms".into(),
            previous["in_flight_deadline_ms"].clone(),
        );
    }
    if previous
        .get("last_error")
        .is_some_and(|value| !value.is_null())
        && !refreshed_complete
    {
        obj.insert("last_error".into(), previous["last_error"].clone());
    }
}

fn stored_status_for_wallet(
    wallet: &str,
    owner: Address,
) -> Result<serde_json::Value, DispatchResponse> {
    match store_get(&format!("onboard/{wallet}/status.json"))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    {
        Some(status) => {
            let expected = owner.to_checksum(None);
            let Some(stored_owner) = status.get("owner").and_then(serde_json::Value::as_str) else {
                return Err(error(-4, "stored onboarding status is missing owner"));
            };
            let stored_owner = stored_owner
                .parse::<Address>()
                .map_err(|e| error(-4, format!("stored onboarding owner parse: {e}")))?
                .to_checksum(None);
            if stored_owner != expected {
                return Err(error(
                    -3,
                    "stored onboarding status belongs to a different wallet owner",
                ));
            }
            Ok(status)
        }
        None => Ok(local_onboard_status(
            wallet,
            owner,
            "not_started",
            false,
            false,
            "write begin to mint or derive CLOB credentials",
        )),
    }
}

fn fundable_deposit_wallet(wallet: &str, owner: Address) -> Result<Address, DispatchResponse> {
    let status = stored_status_for_wallet(wallet, owner)?;
    fundable_deposit_wallet_from_status(&status).ok_or_else(|| {
        error(
            -3,
            "deposit wallet is not factory-resolved; write onboard/<wallet>/begin before funding",
        )
    })
}

fn tradeable_deposit_wallet(wallet: &str, owner: Address) -> Result<Address, DispatchResponse> {
    let status = local_status_for_wallet(wallet, owner)?;
    let deposit = fundable_deposit_wallet_from_status(&status).ok_or_else(|| {
        error(
            -3,
            "deposit wallet is not factory-resolved; write onboard/<wallet>/begin before posting",
        )
    })?;
    if status.get("stage").and_then(serde_json::Value::as_str) != Some("complete")
        || !status
            .get("tradeable")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    {
        return Err(error(
            -3,
            "wallet onboarding is not complete; read onboard/<wallet>/status.json and complete deploy, fund, approve, credentials, and CLOB sync before posting",
        ));
    }
    Ok(deposit)
}

fn fundable_deposit_wallet_from_status(status: &serde_json::Value) -> Option<Address> {
    let deposit = status
        .get("deposit_wallet")
        .and_then(|value| value.get("address"))
        .and_then(serde_json::Value::as_str)?;
    let source = status
        .get("deposit_wallet")
        .and_then(|value| value.get("source"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let fundable = status
        .get("deposit_wallet")
        .and_then(|value| value.get("fundable"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if source != "live_factory_resolved" || !fundable {
        return None;
    }
    deposit.parse::<Address>().ok()
}

fn approval_preview(wallet: &str, owner: Address) -> serde_json::Value {
    let status = stored_status_for_wallet(wallet, owner).ok();
    let deposit = status
        .as_ref()
        .and_then(|status| {
            status
                .get("deposit_wallet")
                .and_then(|value| value.get("address"))
                .and_then(serde_json::Value::as_str)
        })
        .and_then(|address| address.parse::<Address>().ok())
        .unwrap_or_else(|| derive_deposit_wallet_address(&owner, POLYGON));
    let deposit_source = status
        .as_ref()
        .and_then(|status| {
            status
                .get("deposit_wallet")
                .and_then(|value| value.get("source"))
                .and_then(serde_json::Value::as_str)
        })
        .unwrap_or("local_estimate_unverified");
    let raw_deposit_fundable = status
        .as_ref()
        .and_then(|status| {
            status
                .get("deposit_wallet")
                .and_then(|value| value.get("fundable"))
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(false);
    let deposit_fundable = raw_deposit_fundable && deposit_source == "live_factory_resolved";
    let calls: Vec<serde_json::Value> = v2_approval_calls()
        .iter()
        .zip(V2_APPROVAL_LABELS)
        .map(|(call, label)| {
            serde_json::json!({
                "label": label,
                "target": format!("{:#x}", call.target),
                "value": call.value.to_string(),
                "data": format!("0x{}", hex::encode(call.data.as_ref())),
            })
        })
        .collect();
    serde_json::json!({
        "wallet": wallet,
        "owner": format!("{owner:#x}"),
        "deposit_wallet": deposit.to_checksum(None),
        "deposit_wallet_source": deposit_source,
        "deposit_wallet_fundable": deposit_fundable,
        "warning": if deposit_fundable {
            serde_json::Value::Null
        } else {
            serde_json::Value::String("do not fund this locally derived estimate; full onboarding must resolve the live factory address before funding or approvals".into())
        },
        "chain_id": POLYGON,
        "calls": calls,
        "signing": "preview_only"
    })
}

fn write_trade_new(wallet: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    let req: TradeNewRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(e) => return error(-3, format!("trade new JSON: {e}")),
    };
    let side = match req
        .side
        .as_deref()
        .unwrap_or("buy")
        .to_ascii_lowercase()
        .as_str()
    {
        "buy" => Side::Buy,
        "sell" => Side::Sell,
        other => return error(-3, format!("side must be buy or sell, got {other}")),
    };
    let amount_micro = match parse_micro(req.amount.trim()) {
        Ok(value) if value > 0 => value,
        Ok(_) => return error(-3, "amount must be > 0"),
        Err(e) => return error(-3, e.to_string()),
    };
    let bound = match side {
        Side::Buy => req.max_price.as_ref().or(req.limit_price.as_ref()),
        Side::Sell => req.min_price.as_ref().or(req.limit_price.as_ref()),
    };
    let Some(bound) = bound else {
        return error(
            -3,
            match side {
                Side::Buy => "buy requires max_price or limit_price",
                Side::Sell => "sell requires min_price or limit_price",
            },
        );
    };
    let bound_micro = match parse_micro(bound.trim()) {
        Ok(value) if value > 0 => value,
        Ok(_) => return error(-3, "price bound must be > 0"),
        Err(e) => return error(-3, e.to_string()),
    };
    let order_type = match req.order_type.as_deref() {
        Some(raw) => match raw.parse::<OrderType>() {
            Ok(OrderType::GTD) => return error(-3, "GTD orders are not supported"),
            Ok(value) => value,
            Err(e) => return error(-3, e.to_string()),
        },
        None if req.limit_price.is_some() => OrderType::GTC,
        None => OrderType::FAK,
    };
    let snapshot = match trade_snapshot(&req.slug, &req.outcome) {
        Ok(snapshot) => snapshot,
        Err(resp) => return resp,
    };
    let marketable = req.limit_price.is_none();
    let pinned_limit_micro = match req.limit_price.as_deref() {
        Some(limit) => match parse_micro(limit.trim()) {
            Ok(value) if value > 0 => value,
            Ok(_) => return error(-3, "limit_price must be > 0"),
            Err(e) => return error(-3, e.to_string()),
        },
        None => bound_micro,
    };
    if !marketable {
        match side {
            Side::Buy if pinned_limit_micro > bound_micro => {
                return error(-3, "limit_price exceeds max_price");
            }
            Side::Sell if pinned_limit_micro < bound_micro => {
                return error(-3, "limit_price is below min_price");
            }
            _ => {}
        }
    }
    let limit_micro =
        match choose_trade_limit(side, marketable, bound_micro, pinned_limit_micro, &snapshot) {
            Ok(limit) => limit,
            Err(resp) => return resp,
        };
    let quote = match build_trade_quote(side, amount_micro, limit_micro, &snapshot, order_type) {
        Ok(quote) => quote,
        Err(resp) => return resp,
    };
    let id = next_id(&format!("trade/{wallet}/drafts/"), "/order.json");
    let draft = StoreTradeDraft {
        id: id.clone(),
        wallet: wallet.into(),
        slug: req.slug,
        question: snapshot.market.question,
        condition_id: snapshot.market.condition_id,
        outcome: snapshot.outcome,
        token_id: snapshot.token_id,
        side,
        order_type,
        amount_micro,
        price_bound_micro: bound_micro,
        limit_price: req.limit_price,
        marketable,
        limit_price_micro: quote.price_micro,
        size_micro: quote.size_micro,
        maker_micro: quote.maker_micro,
        taker_micro: quote.taker_micro,
        tick_micro: snapshot.tick_micro,
        min_order_size_micro: snapshot.min_size_micro,
        neg_risk: snapshot.neg_risk,
        active: snapshot.active,
        closed: snapshot.closed,
        order_book_enabled: snapshot.order_book_enabled,
        binary_outcomes: true,
        best_ask_micro: snapshot.best_ask_micro,
        best_bid_micro: snapshot.best_bid_micro,
        book_snapshot_secs: now_secs(),
        status: "review".into(),
        salt: None,
        clob_order_id: None,
        clob_status: None,
        last_error: None,
    };
    let policy_check = match trade_policy_check(wallet, &draft) {
        Ok(check) => check,
        Err(resp) => return resp,
    };
    let base = format!("trade/{wallet}/drafts/{id}");
    if let DispatchResponse::Error { .. } =
        store_put_json(&format!("{base}/order.json"), &draft, false)
    {
        return error(-4, "failed to store draft");
    }
    if let DispatchResponse::Error { .. } =
        store_put_json(&format!("{base}/policy_check.json"), &policy_check, false)
    {
        return error(-4, "failed to store policy check");
    }
    if let DispatchResponse::Error { .. } = store_put_json(
        &format!("{base}/quote.json"),
        &serde_json::json!({
            "side": draft.side,
            "order_type": draft.order_type.as_str(),
            "marketable": draft.marketable,
            "amount_micro": draft.amount_micro,
            "amount": format_micro(draft.amount_micro),
            "price_bound_micro": draft.price_bound_micro,
            "price_bound": format_micro(draft.price_bound_micro),
            "limit_price_micro": draft.limit_price_micro,
            "limit_price": format_micro(draft.limit_price_micro),
            "size_micro": draft.size_micro,
            "size": format_micro(draft.size_micro),
            "maker_micro": draft.maker_micro,
            "maker": format_micro(draft.maker_micro),
            "taker_micro": draft.taker_micro,
            "taker": format_micro(draft.taker_micro),
            "tick_micro": draft.tick_micro,
            "tick": format_micro(draft.tick_micro),
            "min_order_size_micro": draft.min_order_size_micro,
            "min_order_size": format_micro(draft.min_order_size_micro),
            "best_ask_micro": draft.best_ask_micro,
            "best_bid_micro": draft.best_bid_micro,
            "status": "quoted"
        }),
        false,
    ) {
        return error(-4, "failed to store quote");
    }
    if let DispatchResponse::Error { .. } = store_put_json(
        &format!("{base}/review_intent.json"),
        &serde_json::json!({
            "wallet": wallet,
            "draft_id": id,
            "slug": draft.slug,
            "outcome": draft.outcome,
            "token_id": draft.token_id,
            "limit_price": format_micro(draft.limit_price_micro),
            "size": format_micro(draft.size_micro),
            "status": "created"
        }),
        false,
    ) {
        return error(-4, "failed to store review intent");
    }
    DispatchResponse::Write
}

fn trade_snapshot(slug: &str, outcome: &str) -> Result<TradeSnapshot, DispatchResponse> {
    let market: Market = get_json(&format!("{GAMMA}/markets/slug/{slug}"))?;
    if !market.is_binary() {
        return Err(error(
            -3,
            format!("market '{slug}' is not a binary YES/NO market"),
        ));
    }
    if !market.active {
        return Err(error(-3, format!("market '{slug}' is not active")));
    }
    if market.closed {
        return Err(error(-3, format!("market '{slug}' is closed")));
    }
    if !market.enable_order_book {
        return Err(error(
            -3,
            format!("market '{slug}' does not have the order book enabled"),
        ));
    }
    let outcome = match outcome.to_ascii_uppercase().as_str() {
        "YES" => "YES",
        "NO" => "NO",
        other => return Err(error(-3, format!("outcome must be YES or NO, got {other}"))),
    };
    let token_id = match outcome {
        "YES" => market.yes_token_id(),
        "NO" => market.no_token_id(),
        _ => None,
    }
    .ok_or_else(|| error(-3, format!("market '{slug}' has no {outcome} token id")))?
    .to_string();
    let book: OrderBook = get_json(&url_with_query(
        &format!("{CLOB}/book"),
        &[("token_id", &token_id)],
    ))?;
    if !book.asset_id.is_empty() && book.asset_id != token_id {
        return Err(error(
            -4,
            format!(
                "CLOB book token mismatch: requested {token_id}, received {}",
                book.asset_id
            ),
        ));
    }
    if !book.market.is_empty()
        && !market.condition_id.is_empty()
        && book.market != market.condition_id
    {
        return Err(error(
            -4,
            format!(
                "CLOB book condition mismatch: Gamma {} vs CLOB {}",
                market.condition_id, book.market
            ),
        ));
    }
    if book.neg_risk != market.neg_risk {
        return Err(error(
            -4,
            format!(
                "neg_risk mismatch for '{slug}': Gamma={} CLOB={}",
                market.neg_risk, book.neg_risk
            ),
        ));
    }
    let tick_micro = if book.tick_size.trim().is_empty() {
        match market.order_price_min_tick_size {
            Some(tick) => parse_api_float_micro(tick, "orderPriceMinTickSize")?,
            None => return Err(error(-4, "CLOB book omitted tick_size")),
        }
    } else {
        parse_micro(&book.tick_size).map_err(|e| error(-4, e.to_string()))?
    };
    let min_size_micro = if book.min_order_size.trim().is_empty() {
        match market.order_min_size {
            Some(size) => parse_api_float_micro(size, "orderMinSize")?,
            None => 0,
        }
    } else {
        parse_micro(&book.min_order_size).map_err(|e| error(-4, e.to_string()))?
    };
    let best_ask_micro = best_price(&book.asks, true)?;
    let best_bid_micro = best_price(&book.bids, false)?;
    Ok(TradeSnapshot {
        market,
        outcome: outcome.into(),
        token_id,
        neg_risk: book.neg_risk,
        tick_micro,
        min_size_micro,
        best_ask_micro,
        best_bid_micro,
        active: true,
        closed: false,
        order_book_enabled: true,
    })
}

fn best_price(
    levels: &[bloom_polymarket::types::BookLevel],
    ask: bool,
) -> Result<Option<u64>, DispatchResponse> {
    let mut best: Option<u64> = None;
    for level in levels {
        let price = parse_micro(&level.price).map_err(|e| error(-4, e.to_string()))?;
        best = Some(match best {
            None => price,
            Some(existing) if ask => existing.min(price),
            Some(existing) => existing.max(price),
        });
    }
    Ok(best)
}

fn choose_trade_limit(
    side: Side,
    marketable: bool,
    bound_micro: u64,
    pinned_limit_micro: u64,
    snapshot: &TradeSnapshot,
) -> Result<u64, DispatchResponse> {
    shared_trade::choose_limit(
        side,
        marketable,
        bound_micro,
        pinned_limit_micro,
        &snapshot.as_shared(),
    )
    .map_err(polymarket_error)
}

fn build_trade_quote(
    side: Side,
    amount_micro: u64,
    limit_micro: u64,
    snapshot: &TradeSnapshot,
    order_type: OrderType,
) -> Result<LimitQuote, DispatchResponse> {
    shared_trade::build_quote(
        side,
        amount_micro,
        limit_micro,
        &snapshot.as_shared(),
        order_type,
    )
    .map_err(polymarket_error)
}

fn trade_policy_check(
    wallet: &str,
    draft: &StoreTradeDraft,
) -> Result<serde_json::Value, DispatchResponse> {
    let policy = wallet_policy(wallet)?;
    let (receipt_store_readable, daily_posted_microusd) = daily_posted_microusd(wallet);
    let ctx = LocalPolymarketOrderCtx {
        slug: draft.slug.clone(),
        condition_id: draft.condition_id.clone(),
        side: match draft.side {
            Side::Buy => LocalPolicySide::Buy,
            Side::Sell => LocalPolicySide::Sell,
        },
        amount_microusd: draft.amount_micro,
        limit_price_micro: draft.limit_price_micro,
        active: draft.active,
        closed: draft.closed,
        order_book_enabled: draft.order_book_enabled,
        binary_outcomes: draft.binary_outcomes,
        neg_risk: draft.neg_risk,
        receipt_store_readable,
        daily_posted_microusd,
    };
    let checks = evaluate_local_polymarket_order(&policy.polymarket, &ctx);
    let deny = local_policy_has_deny(&checks);
    let warn = local_policy_has_warn(&checks);
    let policy_status = if deny {
        "denied"
    } else if warn {
        "warn"
    } else {
        "passed"
    };
    let posting_enabled = !deny && draft.side == Side::Buy && draft.order_type != OrderType::GTD;
    let reason = if draft.side == Side::Sell {
        "sell posting requires passing authoritative chain CTF balance and approval checks"
    } else if draft.order_type == OrderType::GTD {
        "GTD posting is disabled until expiry parity is ported"
    } else {
        "buy can be posted after final review by writing to the post endpoint; resting GTC orders can be cancelled from their receipt"
    };
    Ok(serde_json::json!({
        "status": "blocked",
        "reason": reason,
        "policy_status": policy_status,
        "policy_deny": deny,
        "policy_warn": warn,
        "policy_checks": checks,
        "receipt_store_readable": receipt_store_readable,
        "daily_posted_microusd": daily_posted_microusd,
        "receipt_audit_parity": true,
        "active": draft.active,
        "closed": draft.closed,
        "binary_outcomes": draft.binary_outcomes,
        "order_book_enabled": draft.order_book_enabled,
        "size_at_or_above_min": draft.size_micro >= draft.min_order_size_micro,
        "signing_enabled": posting_enabled,
        "posting_enabled": posting_enabled
    }))
}

fn enable_trade_posting(policy_check: &mut serde_json::Value, reason: &str) {
    if let Some(obj) = policy_check.as_object_mut() {
        obj.insert("status".into(), serde_json::Value::String("ready".into()));
        obj.insert("reason".into(), serde_json::Value::String(reason.into()));
        obj.insert("signing_enabled".into(), serde_json::Value::Bool(true));
        obj.insert("posting_enabled".into(), serde_json::Value::Bool(true));
    }
}

fn wallet_policy(wallet: &str) -> Result<LocalWalletPolicy, DispatchResponse> {
    let bytes =
        bloom_petal_sdk::vfs_read(&format!("wallets/{wallet}/policy.toml"), MAX_POLICY_BYTES)
            .map_err(sdk_error)?;
    let raw = core::str::from_utf8(&bytes)
        .map_err(|e| error(-4, format!("wallet policy is not utf-8: {e}")))?;
    toml::from_str(raw).map_err(|e| error(-4, format!("wallet policy parse: {e}")))
}

fn daily_posted_microusd(wallet: &str) -> (bool, Option<u64>) {
    let prefix = format!("trade/{wallet}/receipts/");
    let keys = match bloom_petal_sdk::store_list(&prefix, MAX_LIST_BYTES) {
        Ok(keys) => keys,
        Err(_) => return (false, None),
    };
    let cutoff = now_millis().saturating_sub(24 * 60 * 60 * 1000);
    let mut present = BTreeSet::new();
    for key in &keys {
        let rest = key.strip_prefix(&prefix).unwrap_or(key);
        let Some(id) = rest.strip_suffix("/receipt.json") else {
            continue;
        };
        present.insert(id.to_string());
    }
    let audited = match audited_receipt_ids_since(wallet, cutoff) {
        Ok(ids) => ids,
        Err(_) => return (false, None),
    };
    for id in audited {
        if !present.contains(&id) {
            return (false, None);
        }
    }
    let mut total = 0u64;
    for key in keys {
        if !key.ends_with("/receipt.json") {
            continue;
        }
        let Some(bytes) = store_get(&key) else {
            return (false, None);
        };
        let receipt: StoreTradeReceiptPolicy = match serde_json::from_slice(&bytes) {
            Ok(receipt) => receipt,
            Err(_) => return (false, None),
        };
        if receipt.posted_ms < cutoff || receipt.side != Side::Buy {
            continue;
        }
        if clob_status_excluded_from_daily_cap(receipt.clob_status.as_str(), receipt.order_type) {
            continue;
        }
        total = total.saturating_add(receipt.amount_microusd);
    }
    (true, Some(total))
}

fn audited_receipt_ids_since(wallet: &str, cutoff_ms: u128) -> Result<Vec<String>, SdkError> {
    let key = format!("trade/{wallet}/audit.jsonl");
    let bytes = match bloom_petal_sdk::store_get(&key, MAX_STORE_BYTES) {
        Ok(bytes) => bytes,
        Err(SdkError::Host(HostStatus::NotFound)) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let text = core::str::from_utf8(&bytes).map_err(|_| SdkError::Host(HostStatus::Invalid))?;
    let mut ids = Vec::new();
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("event").and_then(serde_json::Value::as_str) != Some("receipt_written") {
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
            .and_then(|details| details.get("draft_id"))
            .and_then(serde_json::Value::as_str)
        {
            ids.push(id.to_string());
        }
    }
    Ok(ids)
}

fn verify_sell_preflight(
    wallet: &str,
    owner: Address,
    deposit: Address,
    token_id: &str,
    size_micro: u64,
    neg_risk: bool,
) -> Result<serde_json::Value, DispatchResponse> {
    let deposit_user = deposit.to_checksum(None);
    let data_api_holding_micro = get_json::<Vec<Position>>(&url_with_query(
        &format!("{DATA}/positions"),
        &[("user", &deposit_user)],
    ))
    .ok()
    .map(|positions| {
        positions
            .iter()
            .find(|position| position.asset == token_id)
            .and_then(position_size_micro)
            .unwrap_or(0)
    });

    let creds = load_creds(wallet)?;
    let clob_balance_allowance = clob_l2_get_json(
        owner,
        &creds,
        "/balance-allowance",
        &[
            ("asset_type", "CONDITIONAL"),
            ("token_id", token_id),
            ("signature_type", "3"),
        ],
    )?;
    let clob_balance_micro = clob_balance_allowance
        .get("balance")
        .and_then(parse_clob_raw_micro)
        .ok_or_else(|| error(-4, "CLOB conditional balance response missing balance"))?;
    if clob_balance_micro < size_micro {
        return Err(error(
            -3,
            format!(
                "cannot sell {} shares: CLOB conditional balance reports only {}",
                format_micro(size_micro),
                format_micro(clob_balance_micro)
            ),
        ));
    }
    let operator = if neg_risk {
        NEG_RISK_EXCHANGE_V2
    } else {
        CTF_EXCHANGE_V2
    };
    let chain_ctf_balance = read_chain_ctf_balance(deposit, token_id)?;
    if chain_ctf_balance < size_micro {
        return Err(error(
            -3,
            format!(
                "cannot sell {} shares: on-chain CTF balance for derived deposit wallet {} is only {}",
                format_micro(size_micro),
                deposit.to_checksum(None),
                format_micro(chain_ctf_balance)
            ),
        ));
    }
    let ctf_approved = read_chain_ctf_approval(deposit, operator)?;
    if !ctf_approved {
        return Err(error(
            -3,
            format!(
                "cannot sell before passkey: deposit wallet {} has not approved {} for CTF tokens. Re-run onboarding to restore approvals.",
                deposit.to_checksum(None),
                operator.to_checksum(None)
            ),
        ));
    }

    Ok(serde_json::json!({
        "status": "pass",
        "source": "clob_conditional_balance_and_chain_ctf",
        "preflight_complete_for_posting": true,
        "chain_ctf_balance_checked": true,
        "ctf_approval_checked": true,
        "reason": "sell preflight passed CLOB conditional balance, on-chain CTF balance, and CTF operator approval checks; Data API holdings are included as corroborating evidence when available",
        "deposit_wallet": deposit.to_checksum(None),
        "deposit_wallet_source": "live_factory_resolved",
        "token_id": token_id,
        "requested_size_micro": size_micro,
        "requested_size": format_micro(size_micro),
        "data_api_holding_checked": data_api_holding_micro.is_some(),
        "data_api_holding_micro": data_api_holding_micro,
        "data_api_holding": data_api_holding_micro.map(format_micro),
        "clob_balance_micro": clob_balance_micro,
        "clob_balance": format_micro(clob_balance_micro),
        "clob_balance_allowance": clob_balance_allowance,
        "chain_ctf_contract": CTF.to_checksum(None),
        "chain_ctf_balance_micro": chain_ctf_balance,
        "chain_ctf_balance": format_micro(chain_ctf_balance),
        "ctf_operator": operator.to_checksum(None),
        "ctf_operator_kind": if neg_risk { "neg_risk_exchange_v2" } else { "ctf_exchange_v2" },
        "ctf_approved_for_all": ctf_approved,
        "signing_enabled": true,
        "posting_enabled": true
    }))
}

fn read_chain_ctf_balance(deposit: Address, token_id: &str) -> Result<u64, DispatchResponse> {
    let response = read_chain_method(
        CTF,
        "balanceOf",
        &serde_json::json!({
            "args": [deposit.to_checksum(None), token_id]
        }),
    )?;
    let decoded = response
        .get("decoded")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| error(-4, "chain CTF balanceOf response missing decoded array"))?;
    let raw = decoded
        .first()
        .ok_or_else(|| error(-4, "chain CTF balanceOf response missing balance"))?;
    parse_clob_raw_micro(raw).ok_or_else(|| error(-4, "chain CTF balance is not a u64"))
}

fn read_chain_ctf_approval(deposit: Address, operator: Address) -> Result<bool, DispatchResponse> {
    let response = read_chain_method(
        CTF,
        "isApprovedForAll",
        &serde_json::json!({
            "args": [deposit.to_checksum(None), operator.to_checksum(None)]
        }),
    )?;
    let decoded = response
        .get("decoded")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            error(
                -4,
                "chain CTF isApprovedForAll response missing decoded array",
            )
        })?;
    decoded
        .first()
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| error(-4, "chain CTF approval response is not a boolean"))
}

fn read_chain_deposit_wallet_deployed(address: Address) -> Result<bool, DispatchResponse> {
    let path = format!(
        "chains/polygon/contracts/{}/proxy/implementation",
        address.to_checksum(None)
    );
    let bytes = bloom_petal_sdk::vfs_read(&path, MAX_CHAIN_READ_BYTES)
        .map_err(|e| sdk_error_with_context("read deposit wallet proxy implementation", e))?;
    let text = core::str::from_utf8(&bytes)
        .map_err(|_| error(-4, "chain proxy implementation response is not UTF-8"))?;
    let text = text.trim();
    if text == "not a proxy" {
        return Ok(false);
    }
    text.parse::<Address>().map(|_| true).map_err(|e| {
        error(
            -4,
            format!("chain proxy implementation response is not an address: {e}"),
        )
    })
}

fn read_chain_erc20_balance(token: Address, holder: Address) -> Result<U256, DispatchResponse> {
    let response = read_chain_method(
        token,
        "balanceOf",
        &serde_json::json!({
            "args": [holder.to_checksum(None)]
        }),
    )?;
    read_decoded_u256(&response, "chain ERC20 balanceOf")
}

fn read_chain_erc20_allowance(
    token: Address,
    owner: Address,
    spender: Address,
) -> Result<U256, DispatchResponse> {
    let response = read_chain_method(
        token,
        "allowance",
        &serde_json::json!({
            "args": [owner.to_checksum(None), spender.to_checksum(None)]
        }),
    )?;
    read_decoded_u256(&response, "chain ERC20 allowance")
}

fn read_chain_v2_approvals(deposit: Address) -> Result<bool, DispatchResponse> {
    let floor = allowance_floor();
    for spender in v2_spenders() {
        if read_chain_erc20_allowance(PUSD, deposit, spender)? < floor {
            return Ok(false);
        }
    }
    for operator in v2_spenders() {
        if !read_chain_ctf_approval(deposit, operator)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn read_clob_collateral_sync(
    owner: Address,
    creds: &Credentials,
) -> Result<(bool, Option<U256>, Option<U256>), DispatchResponse> {
    let value = clob_l2_get_json(
        owner,
        creds,
        "/balance-allowance",
        &[("asset_type", "COLLATERAL"), ("signature_type", "3")],
    )?;
    let balance = value.get("balance").and_then(parse_json_u256);
    let allowance = value.get("allowance").and_then(parse_json_u256);
    Ok((
        balance.map(|v| !v.is_zero()).unwrap_or(false)
            && allowance.map(|v| !v.is_zero()).unwrap_or(false),
        balance,
        allowance,
    ))
}

fn read_decoded_u256(response: &serde_json::Value, label: &str) -> Result<U256, DispatchResponse> {
    let decoded = response
        .get("decoded")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| error(-4, format!("{label} response missing decoded array")))?;
    let raw = decoded
        .first()
        .ok_or_else(|| error(-4, format!("{label} response missing value")))?;
    parse_json_u256(raw).ok_or_else(|| error(-4, format!("{label} response is not a uint256")))
}

fn parse_json_u256(value: &serde_json::Value) -> Option<U256> {
    match value {
        serde_json::Value::String(s) => s.trim().parse::<U256>().ok(),
        serde_json::Value::Number(n) => n.as_u64().map(U256::from),
        _ => None,
    }
}

fn allowance_floor() -> U256 {
    U256::from(1) << 160
}

fn v2_spenders() -> [Address; 4] {
    [
        CTF_EXCHANGE_V2,
        NEG_RISK_EXCHANGE_V2,
        CTF_COLLATERAL_ADAPTER,
        NEG_RISK_CTF_COLLATERAL_ADAPTER,
    ]
}

fn predict_deposit_wallet(owner: Address) -> Result<Address, DispatchResponse> {
    let implementation = read_chain_address(
        FACTORY,
        "implementation",
        &serde_json::json!({ "args": [] }),
        "factory implementation",
    )?;
    let wallet_id = format!("0x{}{}", "00".repeat(12), hex::encode(owner.as_slice()));
    read_chain_address(
        FACTORY,
        "predictWalletAddress",
        &serde_json::json!({
            "args": [implementation.to_checksum(None), wallet_id]
        }),
        "factory predictWalletAddress",
    )
}

fn read_chain_address(
    contract: Address,
    method: &str,
    body: &serde_json::Value,
    label: &str,
) -> Result<Address, DispatchResponse> {
    let response = read_chain_method(contract, method, body)?;
    let decoded = response
        .get("decoded")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| error(-4, format!("{label} response missing decoded array")))?;
    decoded
        .first()
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| error(-4, format!("{label} response is not an address")))?
        .parse::<Address>()
        .map_err(|e| error(-4, format!("{label} address parse: {e}")))
}

fn read_chain_method(
    contract: Address,
    method: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, DispatchResponse> {
    let nonce = chain_method_nonce();
    let path = format!(
        "chains/polygon/contracts/{}/methods/{method}@{nonce}.read",
        contract.to_checksum(None)
    );
    let bytes =
        serde_json::to_vec(body).map_err(|e| error(-4, format!("chain method body: {e}")))?;
    bloom_petal_sdk::vfs_write(&path, &bytes)
        .map_err(|e| sdk_error_with_context("stage chain method read", e))?;
    let response = bloom_petal_sdk::vfs_read(&path, MAX_CHAIN_METHOD_BYTES)
        .map_err(|e| sdk_error_with_context("read chain method result", e))?;
    serde_json::from_slice(&response).map_err(|e| error(-4, format!("chain method JSON: {e}")))
}

fn chain_method_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn position_size_micro(position: &Position) -> Option<u64> {
    position
        .size
        .and_then(|size| parse_json_f64_micro(size).ok())
}

fn parse_clob_raw_micro(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Some(u)
            } else {
                n.as_f64().and_then(|f| parse_json_f64_micro(f).ok())
            }
        }
        _ => None,
    }
}

fn parse_json_f64_micro(value: f64) -> Result<u64, DispatchResponse> {
    if !value.is_finite() || value < 0.0 {
        return Err(error(-4, "decimal value is not a non-negative number"));
    }
    parse_micro(&format!("{value}")).map_err(|e| error(-4, e.to_string()))
}

fn evaluate_local_polymarket_order(
    policy: &LocalPolymarketPolicy,
    ctx: &LocalPolymarketOrderCtx,
) -> Vec<LocalPolicyCheck> {
    let mut out = Vec::new();
    if !policy.enabled {
        out.push(local_policy_check(
            "enabled",
            LocalPolicyOutcome::Deny,
            "Polymarket trading is disabled for this wallet; set [polymarket] enabled = true in the wallet policy to opt in",
        ));
    } else {
        out.push(local_policy_check(
            "enabled",
            LocalPolicyOutcome::Pass,
            "trading enabled",
        ));
    }

    if ctx.closed || !ctx.active {
        out.push(local_policy_check(
            "market",
            LocalPolicyOutcome::Deny,
            format!(
                "market is not tradable (active={}, closed={})",
                ctx.active, ctx.closed
            ),
        ));
    } else if !ctx.order_book_enabled {
        out.push(local_policy_check(
            "market",
            LocalPolicyOutcome::Deny,
            "market has no order book enabled",
        ));
    } else if !ctx.binary_outcomes {
        out.push(local_policy_check(
            "market",
            LocalPolicyOutcome::Deny,
            "market is malformed or not a binary YES/NO market",
        ));
    } else {
        out.push(local_policy_check(
            "market",
            LocalPolicyOutcome::Pass,
            "active, order book enabled, binary outcomes",
        ));
    }

    out.push(local_policy_list_check(
        "slug",
        &ctx.slug,
        &policy.allowed_slugs,
        &policy.denied_slugs,
    ));
    out.push(local_policy_list_check(
        "condition_id",
        &ctx.condition_id,
        &policy.allowed_condition_ids,
        &policy.denied_condition_ids,
    ));

    if ctx.neg_risk && !policy.allow_neg_risk {
        out.push(local_policy_check(
            "neg_risk",
            LocalPolicyOutcome::Deny,
            "neg-risk markets are disabled by policy (allow_neg_risk = false)",
        ));
    } else {
        out.push(local_policy_check(
            "neg_risk",
            LocalPolicyOutcome::Pass,
            format!("neg_risk={} permitted", ctx.neg_risk),
        ));
    }

    if ctx.side == LocalPolicySide::Sell {
        out.push(local_policy_check(
            "caps",
            LocalPolicyOutcome::Pass,
            "sell orders are risk-reducing; USD caps not applied",
        ));
        return out;
    }

    if let Some(cap) = policy.max_order_usd {
        if ctx.amount_microusd > cap {
            out.push(local_policy_check(
                "max_order_usd",
                LocalPolicyOutcome::Deny,
                format!(
                    "order {} USD exceeds max_order_usd {}",
                    format_micro(ctx.amount_microusd),
                    format_micro(cap)
                ),
            ));
        } else {
            out.push(local_policy_check(
                "max_order_usd",
                LocalPolicyOutcome::Pass,
                format!(
                    "{} <= {}",
                    format_micro(ctx.amount_microusd),
                    format_micro(cap)
                ),
            ));
        }
    }

    if let Some(cap) = policy.max_daily_usd {
        match (ctx.receipt_store_readable, ctx.daily_posted_microusd) {
            (false, _) | (_, None) => out.push(local_policy_check(
                "max_daily_usd",
                LocalPolicyOutcome::Deny,
                "daily cap configured but posted exposure is unknown (receipt store unreadable) - refusing rather than trading uncapped",
            )),
            (true, Some(daily)) => {
                let total = daily.saturating_add(ctx.amount_microusd);
                if total > cap {
                    out.push(local_policy_check(
                        "max_daily_usd",
                        LocalPolicyOutcome::Deny,
                        format!(
                            "posted {} USD + order {} USD exceeds max_daily_usd {}",
                            format_micro(daily),
                            format_micro(ctx.amount_microusd),
                            format_micro(cap)
                        ),
                    ));
                } else {
                    out.push(local_policy_check(
                        "max_daily_usd",
                        LocalPolicyOutcome::Pass,
                        format!(
                            "{} + {} <= {}",
                            format_micro(daily),
                            format_micro(ctx.amount_microusd),
                            format_micro(cap)
                        ),
                    ));
                }
            }
        }
    }

    if let Some(maxp) = policy.max_price {
        if ctx.limit_price_micro > maxp {
            out.push(local_policy_check(
                "max_price",
                LocalPolicyOutcome::Deny,
                format!(
                    "limit price {} exceeds policy max_price {}",
                    format_micro(ctx.limit_price_micro),
                    format_micro(maxp)
                ),
            ));
        } else {
            out.push(local_policy_check(
                "max_price",
                LocalPolicyOutcome::Pass,
                format!(
                    "{} <= {}",
                    format_micro(ctx.limit_price_micro),
                    format_micro(maxp)
                ),
            ));
        }
    }

    if let Some(threshold) = policy.require_flag_above_usd
        && ctx.amount_microusd > threshold
    {
        out.push(local_policy_check(
            "require_flag_above_usd",
            LocalPolicyOutcome::Warn,
            format!(
                "order {} USD is above {} - acknowledge before value-moving post",
                format_micro(ctx.amount_microusd),
                format_micro(threshold)
            ),
        ));
    }

    out
}

fn local_policy_check(
    rule: &str,
    outcome: LocalPolicyOutcome,
    message: impl Into<String>,
) -> LocalPolicyCheck {
    LocalPolicyCheck {
        rule: format!("polymarket.{rule}"),
        outcome,
        message: message.into(),
    }
}

fn local_policy_list_check(
    name: &str,
    value: &str,
    allowed: &BTreeSet<String>,
    denied: &BTreeSet<String>,
) -> LocalPolicyCheck {
    if denied.contains(value) {
        local_policy_check(
            name,
            LocalPolicyOutcome::Deny,
            format!("'{value}' is denylisted"),
        )
    } else if !allowed.is_empty() && !allowed.contains(value) {
        local_policy_check(
            name,
            LocalPolicyOutcome::Deny,
            format!("'{value}' is not on the allowlist (allowlist-only mode)"),
        )
    } else {
        local_policy_check(
            name,
            LocalPolicyOutcome::Pass,
            format!("'{value}' permitted"),
        )
    }
}

fn local_policy_has_deny(checks: &[LocalPolicyCheck]) -> bool {
    checks
        .iter()
        .any(|check| check.outcome == LocalPolicyOutcome::Deny)
}

fn local_policy_has_warn(checks: &[LocalPolicyCheck]) -> bool {
    checks
        .iter()
        .any(|check| check.outcome == LocalPolicyOutcome::Warn)
}

fn parse_api_float_micro(value: f64, field: &str) -> Result<u64, DispatchResponse> {
    if !value.is_finite() || value < 0.0 {
        return Err(error(-4, format!("{field} is not a non-negative number")));
    }
    parse_micro(&format!("{value:.6}")).map_err(|e| error(-4, e.to_string()))
}

fn read_trade(wallet: &str, kind: &str, id: &str, file: &str) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    match (kind, file) {
        ("drafts", "plan.md") => {
            let Some(bytes) = store_get(&format!("trade/{wallet}/drafts/{id}/order.json")) else {
                return error(-1, "not found");
            };
            let draft: StoreTradeDraft = match serde_json::from_slice(&bytes) {
                Ok(draft) => draft,
                Err(e) => return error(-4, format!("corrupt draft: {e}")),
            };
            DispatchResponse::Read(render_trade_plan(&draft).into_bytes())
        }
        (
            "drafts",
            "order.json" | "policy_check.json" | "quote.json" | "review_intent.json"
            | "post_attempt.json",
        ) => read_store(&format!("trade/{wallet}/drafts/{id}/{file}")),
        ("drafts", "revalidate") => DispatchResponse::Read(TRADE_REVALIDATE_HINT.into()),
        ("drafts", "post") => DispatchResponse::Read(TRADE_POST_HINT.into()),
        ("receipts", "receipt.json") => {
            read_store(&format!("trade/{wallet}/receipts/{id}/receipt.json"))
        }
        ("receipts", "cancel") => DispatchResponse::Read(TRADE_CANCEL_HINT.into()),
        _ => error(-3, "not a trade file"),
    }
}

fn load_trade_draft(
    wallet: &str,
    id: &str,
    base: &str,
) -> Result<StoreTradeDraft, DispatchResponse> {
    let Some(bytes) = store_get(&format!("{base}/order.json")) else {
        return Err(error(-1, "draft not found"));
    };
    let draft: StoreTradeDraft =
        serde_json::from_slice(&bytes).map_err(|e| error(-4, format!("corrupt draft: {e}")))?;
    if draft.wallet != wallet || draft.id != id {
        return Err(error(-4, "draft identity mismatch"));
    }
    Ok(draft)
}

fn write_trade_revalidate(wallet: &str, id: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    if !is_safe_segment(id) {
        return error(-3, "invalid draft id");
    }
    let req: TradeRevalidateRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(e) => return error(-3, format!("revalidate JSON: {e}")),
    };
    if !req.revalidate {
        return error(-3, "revalidate must be true");
    }
    let base = format!("trade/{wallet}/drafts/{id}");
    let _lock = match acquire_trade_lock(wallet, id) {
        Ok(lock) => lock,
        Err(resp) => return resp,
    };
    let mut draft = match load_trade_draft(wallet, id, &base) {
        Ok(draft) => draft,
        Err(resp) => return resp,
    };
    if draft.status != "review" && draft.status != "revalidated" {
        return error(
            -3,
            format!("draft {id} is '{}' and cannot be revalidated", draft.status),
        );
    }
    if draft.order_type == OrderType::GTD {
        return error(-3, "posting GTD orders is pending expiry parity");
    }
    if let Err(resp) = check_geoblock() {
        return resp;
    }

    let snapshot = match trade_snapshot(&draft.slug, &draft.outcome) {
        Ok(snapshot) => snapshot,
        Err(resp) => return resp,
    };
    if snapshot.token_id != draft.token_id {
        return error(
            -3,
            "token id changed between draft and revalidate; refusing",
        );
    }
    if snapshot.market.condition_id != draft.condition_id {
        return error(
            -3,
            "condition id changed between draft and revalidate; refusing",
        );
    }
    if snapshot.neg_risk != draft.neg_risk {
        return error(
            -3,
            "neg-risk changed between draft and revalidate; refusing",
        );
    }
    let amount_input = match draft.side {
        Side::Buy => draft.amount_micro.max(1),
        Side::Sell => draft.size_micro,
    };
    let limit_micro = match choose_trade_limit(
        draft.side,
        draft.marketable,
        draft.price_bound_micro,
        draft.limit_price_micro,
        &snapshot,
    ) {
        Ok(limit) => limit,
        Err(resp) => return resp,
    };
    let quote = match build_trade_quote(
        draft.side,
        amount_input,
        limit_micro,
        &snapshot,
        draft.order_type,
    ) {
        Ok(quote) => quote,
        Err(resp) => return resp,
    };

    let owner = match wallet_address(wallet) {
        Ok(address) => address,
        Err(resp) => return resp,
    };
    let funder = match tradeable_deposit_wallet(wallet, owner) {
        Ok(funder) => funder,
        Err(resp) => return resp,
    };

    draft.limit_price_micro = quote.price_micro;
    draft.size_micro = quote.size_micro;
    draft.maker_micro = quote.maker_micro;
    draft.taker_micro = quote.taker_micro;
    if draft.side == Side::Sell {
        draft.amount_micro = draft.taker_micro;
    }
    draft.tick_micro = snapshot.tick_micro;
    draft.min_order_size_micro = snapshot.min_size_micro;
    draft.neg_risk = snapshot.neg_risk;
    draft.active = snapshot.active;
    draft.closed = snapshot.closed;
    draft.order_book_enabled = snapshot.order_book_enabled;
    draft.binary_outcomes = snapshot.market.is_binary();
    draft.best_ask_micro = snapshot.best_ask_micro;
    draft.best_bid_micro = snapshot.best_bid_micro;
    draft.book_snapshot_secs = now_secs();
    draft.status = "revalidated".into();
    let mut policy_check = match trade_policy_check(wallet, &draft) {
        Ok(check) => check,
        Err(resp) => return resp,
    };
    let policy_deny = policy_check
        .get("policy_deny")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let policy_status = policy_check
        .get("policy_status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    if let DispatchResponse::Error { .. } = store_put_json(
        &format!("{base}/quote.json"),
        &serde_json::json!({
            "side": draft.side,
            "order_type": draft.order_type.as_str(),
            "marketable": draft.marketable,
            "amount_micro": draft.amount_micro,
            "amount": format_micro(draft.amount_micro),
            "price_bound_micro": draft.price_bound_micro,
            "price_bound": format_micro(draft.price_bound_micro),
            "limit_price_micro": draft.limit_price_micro,
            "limit_price": format_micro(draft.limit_price_micro),
            "size_micro": draft.size_micro,
            "size": format_micro(draft.size_micro),
            "maker_micro": draft.maker_micro,
            "maker": format_micro(draft.maker_micro),
            "taker_micro": draft.taker_micro,
            "taker": format_micro(draft.taker_micro),
            "tick_micro": draft.tick_micro,
            "tick": format_micro(draft.tick_micro),
            "min_order_size_micro": draft.min_order_size_micro,
            "min_order_size": format_micro(draft.min_order_size_micro),
            "best_ask_micro": draft.best_ask_micro,
            "best_bid_micro": draft.best_bid_micro,
            "status": "revalidated"
        }),
        false,
    ) {
        return error(-4, "failed to store quote");
    }
    if policy_deny {
        if let DispatchResponse::Error { .. } =
            store_put_json(&format!("{base}/policy_check.json"), &policy_check, false)
        {
            return error(-4, "failed to store policy check");
        }
        match bloom_petal_sdk::store_del(&format!("{base}/review_intent.json")) {
            Ok(()) | Err(SdkError::Host(HostStatus::NotFound)) => {}
            Err(_) => return error(-4, "failed to clear stale review intent"),
        }
        draft.status = "policy_denied".into();
        if let DispatchResponse::Error { .. } =
            store_put_json(&format!("{base}/order.json"), &draft, false)
        {
            return error(-4, "failed to store denied draft");
        }
        return error(-3, "Polymarket policy denied; see policy_check.json");
    }
    let sell_preflight = if draft.side == Side::Sell {
        match verify_sell_preflight(
            wallet,
            owner,
            funder,
            &draft.token_id,
            draft.size_micro,
            draft.neg_risk,
        ) {
            Ok(preflight) => {
                enable_trade_posting(
                    &mut policy_check,
                    "sell can be posted after final review because chain CTF balance and approval checks passed",
                );
                Some(preflight)
            }
            Err(resp) => {
                match bloom_petal_sdk::store_del(&format!("{base}/review_intent.json")) {
                    Ok(()) | Err(SdkError::Host(HostStatus::NotFound)) => {}
                    Err(_) => return error(-4, "failed to clear stale review intent"),
                }
                draft.status = "preflight_denied".into();
                if let DispatchResponse::Error { .. } =
                    store_put_json(&format!("{base}/order.json"), &draft, false)
                {
                    return error(-4, "failed to store denied draft");
                }
                return resp;
            }
        }
    } else {
        None
    };
    if let DispatchResponse::Error { .. } =
        store_put_json(&format!("{base}/policy_check.json"), &policy_check, false)
    {
        return error(-4, "failed to store policy check");
    }
    let posting_enabled = policy_check
        .get("posting_enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if let DispatchResponse::Error { .. } = store_put_json(
        &format!("{base}/review_intent.json"),
        &serde_json::json!({
            "wallet": wallet,
            "draft_id": id,
            "owner": owner.to_checksum(None),
            "funder": funder.to_checksum(None),
            "slug": draft.slug,
            "condition_id": draft.condition_id,
            "outcome": draft.outcome,
            "token_id": draft.token_id,
            "side": draft.side,
            "order_type": draft.order_type.as_str(),
            "limit_price": format_micro(draft.limit_price_micro),
            "size": format_micro(draft.size_micro),
            "maker": format_micro(draft.maker_micro),
            "taker": format_micro(draft.taker_micro),
            "neg_risk": draft.neg_risk,
            "policy_status": policy_status,
            "sell_preflight": sell_preflight,
            "status": "final_review_staged",
            "signing_enabled": posting_enabled,
            "posting_enabled": posting_enabled
        }),
        false,
    ) {
        return error(-4, "failed to store review intent");
    }
    store_put_json(&format!("{base}/order.json"), &draft, false)
}

fn refresh_trade_post_inputs(
    wallet: &str,
    base: &str,
    draft: &mut StoreTradeDraft,
    owner: Address,
) -> Result<(serde_json::Value, Option<serde_json::Value>), DispatchResponse> {
    let snapshot = trade_snapshot(&draft.slug, &draft.outcome)?;
    if snapshot.token_id != draft.token_id {
        return Err(error(
            -3,
            "token id changed between draft and post; refusing",
        ));
    }
    if snapshot.market.condition_id != draft.condition_id {
        return Err(error(
            -3,
            "condition id changed between draft and post; refusing",
        ));
    }
    if snapshot.neg_risk != draft.neg_risk {
        return Err(error(
            -3,
            "neg-risk changed between draft and post; refusing",
        ));
    }
    let amount_input = match draft.side {
        Side::Buy => draft.amount_micro.max(1),
        Side::Sell => draft.size_micro,
    };
    let limit_micro = choose_trade_limit(
        draft.side,
        draft.marketable,
        draft.price_bound_micro,
        draft.limit_price_micro,
        &snapshot,
    )?;
    let quote = build_trade_quote(
        draft.side,
        amount_input,
        limit_micro,
        &snapshot,
        draft.order_type,
    )?;
    draft.limit_price_micro = quote.price_micro;
    draft.size_micro = quote.size_micro;
    draft.maker_micro = quote.maker_micro;
    draft.taker_micro = quote.taker_micro;
    if draft.side == Side::Sell {
        draft.amount_micro = draft.taker_micro;
    }
    draft.tick_micro = snapshot.tick_micro;
    draft.min_order_size_micro = snapshot.min_size_micro;
    draft.neg_risk = snapshot.neg_risk;
    draft.active = snapshot.active;
    draft.closed = snapshot.closed;
    draft.order_book_enabled = snapshot.order_book_enabled;
    draft.binary_outcomes = snapshot.market.is_binary();
    draft.best_ask_micro = snapshot.best_ask_micro;
    draft.best_bid_micro = snapshot.best_bid_micro;
    draft.book_snapshot_secs = now_secs();
    let mut policy_check = trade_policy_check(wallet, draft)?;
    let policy_deny = policy_check
        .get("policy_deny")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    if let DispatchResponse::Error { .. } = store_put_json(
        &format!("{base}/quote.json"),
        &serde_json::json!({
            "side": draft.side,
            "order_type": draft.order_type.as_str(),
            "marketable": draft.marketable,
            "amount_micro": draft.amount_micro,
            "amount": format_micro(draft.amount_micro),
            "price_bound_micro": draft.price_bound_micro,
            "price_bound": format_micro(draft.price_bound_micro),
            "limit_price_micro": draft.limit_price_micro,
            "limit_price": format_micro(draft.limit_price_micro),
            "size_micro": draft.size_micro,
            "size": format_micro(draft.size_micro),
            "maker_micro": draft.maker_micro,
            "maker": format_micro(draft.maker_micro),
            "taker_micro": draft.taker_micro,
            "taker": format_micro(draft.taker_micro),
            "tick_micro": draft.tick_micro,
            "tick": format_micro(draft.tick_micro),
            "min_order_size_micro": draft.min_order_size_micro,
            "min_order_size": format_micro(draft.min_order_size_micro),
            "best_ask_micro": draft.best_ask_micro,
            "best_bid_micro": draft.best_bid_micro,
            "status": "post_revalidated"
        }),
        false,
    ) {
        return Err(error(-4, "failed to store quote"));
    }
    if policy_deny {
        if let DispatchResponse::Error { .. } =
            store_put_json(&format!("{base}/policy_check.json"), &policy_check, false)
        {
            return Err(error(-4, "failed to store policy check"));
        }
        match bloom_petal_sdk::store_del(&format!("{base}/review_intent.json")) {
            Ok(()) | Err(SdkError::Host(HostStatus::NotFound)) => {}
            Err(_) => return Err(error(-4, "failed to clear stale review intent")),
        }
        draft.status = "policy_denied".into();
        if let DispatchResponse::Error { .. } =
            store_put_json(&format!("{base}/order.json"), draft, false)
        {
            return Err(error(-4, "failed to store denied draft"));
        }
        return Err(error(-3, "Polymarket policy denied; see policy_check.json"));
    }
    let sell_preflight = if draft.side == Side::Sell {
        let funder = tradeable_deposit_wallet(wallet, owner)?;
        let preflight = verify_sell_preflight(
            wallet,
            owner,
            funder,
            &draft.token_id,
            draft.size_micro,
            draft.neg_risk,
        )?;
        enable_trade_posting(
            &mut policy_check,
            "sell can be posted after final review because chain CTF balance and approval checks passed",
        );
        Some(preflight)
    } else {
        None
    };
    if let DispatchResponse::Error { .. } =
        store_put_json(&format!("{base}/policy_check.json"), &policy_check, false)
    {
        return Err(error(-4, "failed to store policy check"));
    }
    Ok((policy_check, sell_preflight))
}

fn review_intent_matches_draft(
    review: &serde_json::Value,
    draft: &StoreTradeDraft,
    owner: Address,
    funder: Address,
    policy_check: &serde_json::Value,
    sell_preflight: Option<&serde_json::Value>,
) -> Result<(), String> {
    let side = match draft.side {
        Side::Buy => "BUY",
        Side::Sell => "SELL",
    };
    let policy_status = policy_check
        .get("policy_status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    for (field, expected) in [
        ("wallet", draft.wallet.clone()),
        ("draft_id", draft.id.clone()),
        ("owner", owner.to_checksum(None)),
        ("funder", funder.to_checksum(None)),
        ("slug", draft.slug.clone()),
        ("condition_id", draft.condition_id.clone()),
        ("outcome", draft.outcome.clone()),
        ("token_id", draft.token_id.clone()),
        ("side", side.to_string()),
        ("order_type", draft.order_type.as_str().to_string()),
        ("limit_price", format_micro(draft.limit_price_micro)),
        ("size", format_micro(draft.size_micro)),
        ("maker", format_micro(draft.maker_micro)),
        ("taker", format_micro(draft.taker_micro)),
        ("policy_status", policy_status.to_string()),
    ] {
        if review.get(field).and_then(serde_json::Value::as_str) != Some(expected.as_str()) {
            return Err(format!(
                "final review field '{field}' no longer matches live post inputs"
            ));
        }
    }
    if review.get("neg_risk").and_then(serde_json::Value::as_bool) != Some(draft.neg_risk) {
        return Err("final review field 'neg_risk' no longer matches live post inputs".into());
    }
    if draft.side == Side::Sell {
        let Some(fresh) = sell_preflight else {
            return Err("final review field 'sell_preflight' is missing live post evidence".into());
        };
        if review.get("sell_preflight") != Some(fresh) {
            return Err(
                "final review field 'sell_preflight' no longer matches live post inputs".into(),
            );
        }
    }
    Ok(())
}

fn write_trade_post(wallet: &str, id: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    if !is_safe_segment(id) {
        return error(-3, "invalid draft id");
    }
    let req: TradePostRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(e) => return error(-3, format!("post JSON: {e}")),
    };
    if !req.post {
        return error(-3, "post must be true");
    }
    let base = format!("trade/{wallet}/drafts/{id}");
    let _lock = match acquire_trade_lock(wallet, id) {
        Ok(lock) => lock,
        Err(resp) => return resp,
    };
    let mut draft = match load_trade_draft(wallet, id, &base) {
        Ok(draft) => draft,
        Err(resp) => return resp,
    };
    if draft.status != "revalidated" {
        return error(
            -3,
            format!(
                "draft {id} is '{}' and cannot be posted; write revalidate first",
                draft.status
            ),
        );
    }
    if draft.order_type == OrderType::GTD {
        return error(-3, "posting GTD orders is pending expiry parity");
    }
    if let Err(resp) = check_geoblock() {
        return resp;
    }
    let owner = match wallet_address(wallet) {
        Ok(address) => address,
        Err(resp) => return resp,
    };
    let funder = match tradeable_deposit_wallet(wallet, owner) {
        Ok(funder) => funder,
        Err(resp) => return resp,
    };
    let (policy_check, sell_preflight) =
        match refresh_trade_post_inputs(wallet, &base, &mut draft, owner) {
            Ok(inputs) => inputs,
            Err(resp) => return resp,
        };
    let review_intent_bytes =
        match bloom_petal_sdk::store_get(&format!("{base}/review_intent.json"), MAX_STORE_BYTES) {
            Ok(bytes) => bytes,
            Err(SdkError::Host(HostStatus::NotFound)) => {
                return error(-3, "missing final review intent; write revalidate first");
            }
            Err(e) => return sdk_error(e),
        };
    let review_intent: serde_json::Value = match serde_json::from_slice(&review_intent_bytes) {
        Ok(value) => value,
        Err(e) => return error(-4, format!("corrupt review intent: {e}")),
    };
    if review_intent
        .get("status")
        .and_then(serde_json::Value::as_str)
        != Some("final_review_staged")
        || review_intent
            .get("posting_enabled")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return error(-3, "final review intent does not enable posting");
    }
    if let Err(message) = review_intent_matches_draft(
        &review_intent,
        &draft,
        owner,
        funder,
        &policy_check,
        sell_preflight.as_ref(),
    ) {
        return error(
            -3,
            format!("{message}; write revalidate again before posting"),
        );
    }
    let review_intent_hash = blake3_hex(&review_intent_bytes);
    let creds = match load_creds(wallet) {
        Ok(creds) => creds,
        Err(resp) => return resp,
    };
    let token_id = match draft.token_id.parse::<U256>() {
        Ok(token_id) => token_id,
        Err(e) => return error(-4, format!("token id parse: {e}")),
    };
    let order = build_order(&OrderParams {
        token_id,
        maker: funder,
        quote: LimitQuote {
            side: draft.side,
            price_micro: draft.limit_price_micro,
            size_micro: draft.size_micro,
            maker_micro: draft.maker_micro,
            taker_micro: draft.taker_micro,
        },
        builder_code: None,
        signature_type: SIG_TYPE_POLY_1271,
    });
    let salt = match u64::try_from(order.salt) {
        Ok(salt) => salt,
        Err(_) => return error(-4, "order salt does not fit in u64"),
    };
    draft.salt = Some(salt);
    draft.status = "signing_prepared".into();
    draft.last_error = None;
    let digest = poly1271_digest(&order, POLYGON, draft.neg_risk);
    let digest_hash = blake3_hex(digest.as_slice());
    if let DispatchResponse::Error { .. } =
        store_put_json(&format!("{base}/order.json"), &draft, false)
    {
        return error(-4, "failed to store signing-prepared draft");
    }
    if let DispatchResponse::Error { .. } = store_put_json(
        &format!("{base}/post_attempt.json"),
        &serde_json::json!({
            "wallet": wallet,
            "draft_id": id,
            "owner": owner.to_checksum(None),
            "funder": funder.to_checksum(None),
            "salt": salt,
            "review_intent_hash": review_intent_hash.clone(),
            "poly1271_digest_blake3": digest_hash,
            "prepared_ms": now_millis(),
            "status": "signing_prepared"
        }),
        false,
    ) {
        return error(-4, "failed to store signing-prepared post attempt");
    }
    let inner_sig = match bloom_petal_sdk::sign_hash(&SignRequest {
        wallet: wallet.into(),
        hash32: digest.into(),
        purpose: "polymarket.order.poly1271".into(),
    }) {
        Ok(sig) if sig.len() == 65 => sig,
        Ok(sig) => return error(-4, format!("sign_hash returned {} bytes", sig.len())),
        Err(e) => return sdk_error(e),
    };
    let signature = match wrap_poly1271_signature(&order, &inner_sig, POLYGON, draft.neg_risk) {
        Ok(signature) => signature,
        Err(e) => return polymarket_error(e),
    };
    let order_body = match OrderBody::from_signed(&order, &signature, &creds.key, draft.order_type)
    {
        Ok(body) => body,
        Err(e) => return polymarket_error(e),
    };
    let body_str = match serde_json::to_string(&order_body) {
        Ok(body) => body,
        Err(e) => return error(-4, format!("order body json: {e}")),
    };
    let body_hash = blake3_hex(body_str.as_bytes());
    if let DispatchResponse::Error { .. } = store_put_json(
        &format!("{base}/post_attempt.json"),
        &serde_json::json!({
            "wallet": wallet,
            "draft_id": id,
            "owner": owner.to_checksum(None),
            "funder": funder.to_checksum(None),
            "salt": salt,
            "review_intent_hash": review_intent_hash.clone(),
            "order_body_blake3": body_hash.clone(),
            "signed_ms": now_millis(),
            "status": "signed"
        }),
        false,
    ) {
        return error(-4, "failed to store post attempt");
    }
    draft.status = "signed".into();
    if let DispatchResponse::Error { .. } =
        store_put_json(&format!("{base}/order.json"), &draft, false)
    {
        return error(-4, "failed to store signed draft");
    }
    match clob_l2_post_json(owner, &creds, "/order", &body_str) {
        Ok(raw_response) => {
            let status = clob_response_status(&raw_response);
            let clob_order_id = clob_response_order_id(&raw_response);
            let filled_size_micro = clob_response_filled_size_micro(&raw_response);
            let posted_ms = now_millis();
            let receipt = StoreTradeReceipt {
                draft_id: id.into(),
                wallet: wallet.into(),
                slug: draft.slug.clone(),
                token_id: draft.token_id.clone(),
                side: draft.side,
                order_type: draft.order_type,
                funder: Some(funder.to_checksum(None)),
                signature_type: SIG_TYPE_POLY_1271,
                amount_microusd: draft.amount_micro,
                limit_price_micro: draft.limit_price_micro,
                size_micro: draft.size_micro,
                salt,
                clob_order_id: clob_order_id.clone(),
                clob_status: status.clone(),
                filled_size_micro,
                raw_response: clob_response_public_summary(
                    &status,
                    &clob_order_id,
                    filled_size_micro,
                ),
                review_intent_hash: Some(review_intent_hash),
                posted_ms,
            };
            if let DispatchResponse::Error { .. } = store_trade_receipt(wallet, id, &receipt) {
                return error(-4, "failed to store receipt");
            }
            draft.status =
                if clob_status_excluded_from_daily_cap(status.as_str(), Some(draft.order_type)) {
                    "rejected".into()
                } else {
                    "posted".into()
                };
            draft.clob_order_id = clob_order_id;
            draft.clob_status = Some(status);
            draft.last_error = None;
            store_put_json(&format!("{base}/order.json"), &draft, false)
        }
        Err(resp) => {
            if let Some(raw_response) =
                reconcile_ambiguous_post(owner, &creds, &draft, funder, salt)
            {
                let status = clob_response_status(&raw_response);
                let clob_order_id = clob_response_order_id(&raw_response);
                let filled_size_micro = clob_response_filled_size_micro(&raw_response);
                let posted_ms = now_millis();
                let receipt = StoreTradeReceipt {
                    draft_id: id.into(),
                    wallet: wallet.into(),
                    slug: draft.slug.clone(),
                    token_id: draft.token_id.clone(),
                    side: draft.side,
                    order_type: draft.order_type,
                    funder: Some(funder.to_checksum(None)),
                    signature_type: SIG_TYPE_POLY_1271,
                    amount_microusd: draft.amount_micro,
                    limit_price_micro: draft.limit_price_micro,
                    size_micro: draft.size_micro,
                    salt,
                    clob_order_id: clob_order_id.clone(),
                    clob_status: status.clone(),
                    filled_size_micro,
                    raw_response: clob_reconciled_public_summary(
                        &status,
                        &clob_order_id,
                        filled_size_micro,
                    ),
                    review_intent_hash: Some(review_intent_hash),
                    posted_ms,
                };
                if let DispatchResponse::Error { .. } = store_put_json(
                    &format!("{base}/post_attempt.json"),
                    &serde_json::json!({
                        "wallet": wallet,
                        "draft_id": id,
                        "owner": owner.to_checksum(None),
                        "funder": funder.to_checksum(None),
                        "salt": salt,
                        "review_intent_hash": receipt.review_intent_hash.clone(),
                        "order_body_blake3": body_hash,
                        "reconciled_ms": posted_ms,
                        "status": "reconciled_open_order",
                        "clob_order_id": clob_order_id,
                        "clob_status": status
                    }),
                    false,
                ) {
                    return error(-4, "failed to store reconciled post attempt");
                }
                if let DispatchResponse::Error { .. } = store_trade_receipt(wallet, id, &receipt) {
                    return error(-4, "failed to store reconciled receipt");
                }
                draft.status = if clob_status_excluded_from_daily_cap(
                    receipt.clob_status.as_str(),
                    Some(draft.order_type),
                ) {
                    "rejected".into()
                } else {
                    "posted".into()
                };
                draft.clob_order_id = receipt.clob_order_id;
                draft.clob_status = Some(receipt.clob_status);
                draft.last_error = None;
                return store_put_json(&format!("{base}/order.json"), &draft, false);
            }
            let posted_ms = now_millis();
            let receipt = StoreTradeReceipt {
                draft_id: id.into(),
                wallet: wallet.into(),
                slug: draft.slug.clone(),
                token_id: draft.token_id.clone(),
                side: draft.side,
                order_type: draft.order_type,
                funder: Some(funder.to_checksum(None)),
                signature_type: SIG_TYPE_POLY_1271,
                amount_microusd: draft.amount_micro,
                limit_price_micro: draft.limit_price_micro,
                size_micro: draft.size_micro,
                salt,
                clob_order_id: None,
                clob_status: "ambiguous".into(),
                filled_size_micro: None,
                raw_response: serde_json::json!({
                    "error": "post outcome unknown after signing",
                    "body_hash": body_hash
                }),
                review_intent_hash: Some(review_intent_hash),
                posted_ms,
            };
            draft.status = "ambiguous".into();
            draft.clob_status = Some("ambiguous".into());
            draft.last_error = Some("post outcome unknown after signing".into());
            if let DispatchResponse::Error { .. } =
                store_put_json(&format!("{base}/order.json"), &draft, false)
            {
                return error(-4, "post outcome ambiguous and failed to store draft state");
            }
            if let DispatchResponse::Error { .. } = store_trade_receipt(wallet, id, &receipt) {
                return error(
                    -4,
                    "post outcome ambiguous and failed to persist receipt/audit",
                );
            }
            let _ = resp;
            error(
                -4,
                "CLOB post outcome unknown after signing; ambiguous receipt written",
            )
        }
    }
}

fn write_trade_cancel(wallet: &str, id: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    if !is_safe_segment(id) {
        return error(-3, "invalid receipt id");
    }
    let req: TradeCancelRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(e) => return error(-3, format!("cancel JSON: {e}")),
    };
    if !req.cancel {
        return error(-3, "cancel must be true");
    }
    let _lock = match acquire_trade_lock(wallet, id) {
        Ok(lock) => lock,
        Err(resp) => return resp,
    };
    let receipt_key = format!("trade/{wallet}/receipts/{id}/receipt.json");
    let Some(bytes) = store_get(&receipt_key) else {
        return error(-1, "receipt not found");
    };
    let mut receipt: StoreTradeReceipt = match serde_json::from_slice(&bytes) {
        Ok(receipt) => receipt,
        Err(e) => return error(-4, format!("corrupt receipt: {e}")),
    };
    if receipt.wallet != wallet || receipt.draft_id != id {
        return error(-4, "receipt identity mismatch");
    }
    if receipt.clob_status == "cancelled" {
        if let Err(resp) = mark_trade_draft_cancelled(wallet, id) {
            return resp;
        }
        return DispatchResponse::Write;
    }
    let Some(order_id) = receipt.clob_order_id.clone() else {
        return error(-3, "receipt has no CLOB order id to cancel");
    };
    let owner = match wallet_address(wallet) {
        Ok(address) => address,
        Err(resp) => return resp,
    };
    let creds = match load_creds(wallet) {
        Ok(creds) => creds,
        Err(resp) => return resp,
    };
    let body = serde_json::json!({ "orderID": order_id }).to_string();
    let raw = match clob_l2_delete_json(owner, &creds, "/order", &body) {
        Ok(raw) => raw,
        Err(resp) => return resp,
    };
    if !clob_cancel_confirmed(&raw, &order_id) {
        return error(-4, "CLOB cancel response did not confirm cancellation");
    }
    receipt.clob_status = "cancelled".into();
    receipt.raw_response = serde_json::json!({
        "status": "cancelled",
        "order_id": order_id,
        "response_redacted": true
    });
    if let DispatchResponse::Error { .. } = append_trade_audit(
        wallet,
        "order_cancelled",
        serde_json::json!({
            "draft_id": id,
            "clob_order_id": order_id,
        }),
    ) {
        return error(-4, "failed to write cancel audit");
    }
    if let DispatchResponse::Error { .. } = store_put_json(&receipt_key, &receipt, false) {
        return error(-4, "failed to update receipt");
    }
    if let Err(resp) = mark_trade_draft_cancelled(wallet, id) {
        return resp;
    }
    DispatchResponse::Write
}

fn mark_trade_draft_cancelled(wallet: &str, id: &str) -> Result<(), DispatchResponse> {
    let draft_key = format!("trade/{wallet}/drafts/{id}/order.json");
    if let Some(bytes) = store_get(&draft_key) {
        let mut draft: StoreTradeDraft = match serde_json::from_slice(&bytes) {
            Ok(draft) => draft,
            Err(e) => return Err(error(-4, format!("corrupt draft: {e}"))),
        };
        if draft.wallet != wallet || draft.id != id {
            return Err(error(-4, "draft identity mismatch"));
        }
        draft.status = "cancelled".into();
        draft.clob_status = Some("cancelled".into());
        draft.last_error = None;
        if let DispatchResponse::Error { .. } = store_put_json(&draft_key, &draft, false) {
            return Err(error(-4, "failed to update draft"));
        }
    }
    Ok(())
}

fn write_fund_new(wallet: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    let owner = match wallet_address(wallet) {
        Ok(address) => address,
        Err(resp) => return resp,
    };
    let deposit = match fundable_deposit_wallet(wallet, owner) {
        Ok(deposit) => deposit,
        Err(resp) => return resp,
    };
    let req: FundNewRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(e) => return error(-3, format!("fund request JSON: {e}")),
    };
    if req.slippage_bps > 1000 {
        return error(-3, "slippage_bps too high (max 1000)");
    }
    if parse_micro(req.target_pusd.trim()).unwrap_or(0) == 0 {
        return error(-3, "target_pusd must be > 0");
    }
    if parse_micro(req.max_spend.trim()).unwrap_or(0) == 0 {
        return error(-3, "max_spend must be > 0");
    }
    let id = next_id(&format!("fund/{wallet}/requests/"), ".json");
    let session = StoreFundSession {
        id: id.clone(),
        wallet: wallet.into(),
        target_pusd: req.target_pusd,
        max_spend: req.max_spend,
        from_token: req.from_token.unwrap_or_else(|| "native".into()),
        slippage_bps: req.slippage_bps,
        deposit_wallet: deposit.to_checksum(None),
        deposit_wallet_source: "live_factory_resolved".into(),
        status: "draft".into(),
    };
    store_put_json(
        &format!("fund/{wallet}/requests/{id}.json"),
        &session,
        false,
    )
}

fn read_fund(wallet: &str, id: &str, file: &str) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    let Some(bytes) = store_get(&format!("fund/{wallet}/requests/{id}.json")) else {
        return error(-1, "not found");
    };
    let session: StoreFundSession = match serde_json::from_slice(&bytes) {
        Ok(session) => session,
        Err(e) => return error(-4, format!("corrupt fund request: {e}")),
    };
    match file {
        "request.json" | "status.json" => read_json_value(&session),
        "plan.md" => DispatchResponse::Read(render_fund_plan(&session).into_bytes()),
        _ => error(-3, "not a fund file"),
    }
}

fn list_market_slugs() -> Result<Vec<String>, DispatchResponse> {
    let url = url_with_query(
        &format!("{GAMMA}/markets"),
        &[
            ("closed", "false"),
            ("limit", &MARKETS_LIST_LIMIT.to_string()),
            ("order", "volumeNum"),
            ("ascending", "false"),
        ],
    );
    let markets: Vec<Market> = get_json(&url)?;
    Ok(markets
        .into_iter()
        .filter_map(|market| (!market.slug.is_empty()).then_some(market.slug))
        .collect())
}

fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, DispatchResponse> {
    let resp = http("GET", url, &[], Vec::new())?;
    if !(200..300).contains(&resp.status) {
        return Err(error(
            -4,
            format!(
                "polymarket api error (status {}): {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ),
        ));
    }
    serde_json::from_slice(&resp.body).map_err(|e| error(-4, format!("json: {e}")))
}

fn clob_auth_request(
    method: &str,
    path: &str,
    headers: &[(&str, String)],
) -> Result<Credentials, DispatchResponse> {
    let resp = bloom_petal_sdk::http_fetch(
        &HttpRequest {
            method: method.into(),
            url: format!("{CLOB}{path}"),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).into(), value.clone()))
                .collect(),
            body: Vec::new(),
        },
        MAX_HTTP_BYTES,
    )
    .map_err(sdk_error)?;
    if !(200..300).contains(&resp.status) {
        return Err(error(
            -4,
            format!("CLOB auth error (status {})", resp.status),
        ));
    }
    let mut creds: Credentials =
        serde_json::from_slice(&resp.body).map_err(|e| error(-4, format!("json: {e}")))?;
    creds.nonce = CLOB_AUTH_NONCE;
    Ok(creds)
}

fn load_creds(wallet: &str) -> Result<Credentials, DispatchResponse> {
    let Some(bytes) = store_get(&format!("creds/{wallet}/clob.json")) else {
        return Err(error(
            -3,
            format!("wallet '{wallet}' is not onboarded; write onboard/{wallet}/begin first"),
        ));
    };
    serde_json::from_slice(&bytes).map_err(|e| error(-4, format!("corrupt credentials: {e}")))
}

fn load_builder_credentials(wallet: &str) -> Result<Option<BuilderCredentials>, DispatchResponse> {
    match bloom_petal_sdk::store_get(&format!("creds/{wallet}/builder.json"), MAX_STORE_BYTES) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| error(-4, format!("corrupt builder credentials: {e}"))),
        Err(SdkError::Host(HostStatus::NotFound)) => Ok(None),
        Err(e) => Err(sdk_error(e)),
    }
}

fn save_builder_credentials(
    wallet: &str,
    creds: &BuilderCredentials,
) -> Result<(), DispatchResponse> {
    if let DispatchResponse::Error { .. } =
        store_put_json(&format!("creds/{wallet}/builder.json"), creds, true)
    {
        return Err(error(-4, "failed to store builder credentials"));
    }
    Ok(())
}

fn delete_builder_credentials(wallet: &str) -> Result<(), DispatchResponse> {
    match bloom_petal_sdk::store_del(&format!("creds/{wallet}/builder.json")) {
        Ok(()) | Err(SdkError::Host(HostStatus::NotFound)) => Ok(()),
        Err(e) => Err(sdk_error(e)),
    }
}

fn ensure_builder_credentials(
    wallet: &str,
    owner: Address,
    clob_creds: &Credentials,
) -> Result<BuilderCredentials, DispatchResponse> {
    if let Some(creds) = load_builder_credentials(wallet)? {
        return Ok(creds);
    }
    let raw = clob_l2_post_json(owner, clob_creds, "/auth/builder-api-key", "")?;
    let mut creds: BuilderCredentials =
        serde_json::from_value(raw).map_err(|e| error(-4, format!("builder key JSON: {e}")))?;
    creds.created_at_ms = now_millis();
    creds.source = "clob_l2_auth".into();
    save_builder_credentials(wallet, &creds)?;
    Ok(creds)
}

#[derive(Debug, Clone)]
struct LocalRelayerTx {
    id: String,
    state: String,
}

impl LocalRelayerTx {
    fn is_confirmed(&self) -> bool {
        self.state == "STATE_CONFIRMED"
    }

    fn is_failed(&self) -> bool {
        let state = self.state.to_ascii_uppercase();
        state.contains("FAIL") || state.contains("INVALID")
    }
}

fn relayer_submit_with_builder_repair(
    wallet: &str,
    owner: Address,
    clob_creds: &Credentials,
    body: serde_json::Value,
) -> Result<LocalRelayerTx, DispatchResponse> {
    let mut builder = ensure_builder_credentials(wallet, owner, clob_creds)?;
    match relayer_submit(&builder, &body) {
        Ok(tx) => Ok(tx),
        Err(RelayerHttpError {
            status: 401 | 403, ..
        }) => {
            delete_builder_credentials(wallet)?;
            builder = ensure_builder_credentials(wallet, owner, clob_creds)?;
            relayer_submit(&builder, &body).map_err(relayer_http_error)
        }
        Err(err) => Err(relayer_http_error(err)),
    }
}

#[derive(Debug)]
struct RelayerHttpError {
    status: u16,
    body: String,
}

fn relayer_submit(
    builder: &BuilderCredentials,
    body: &serde_json::Value,
) -> Result<LocalRelayerTx, RelayerHttpError> {
    let body = serde_json::to_string(body).map_err(|e| RelayerHttpError {
        status: 0,
        body: format!("relayer body JSON: {e}"),
    })?;
    let headers =
        builder_headers(builder, "POST", "/submit", &body).map_err(|message| RelayerHttpError {
            status: 0,
            body: message,
        })?;
    let mut headers: Vec<(String, String)> = headers
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect();
    headers.push(("content-type".into(), "application/json".into()));
    let resp = bloom_petal_sdk::http_fetch(
        &HttpRequest {
            method: "POST".into(),
            url: format!("{RELAYER}/submit"),
            headers,
            body: body.into_bytes(),
        },
        MAX_HTTP_BYTES,
    )
    .map_err(|e| RelayerHttpError {
        status: 0,
        body: e.message().to_string(),
    })?;
    if !(200..300).contains(&resp.status) {
        return Err(RelayerHttpError {
            status: resp.status,
            body: format!(
                "relayer /submit response body redacted ({} bytes)",
                resp.body.len()
            ),
        });
    }
    let value: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|e| RelayerHttpError {
            status: resp.status,
            body: format!("relayer submit JSON: {e}"),
        })?;
    parse_relayer_submit_response(&value).map_err(|body| RelayerHttpError {
        status: resp.status,
        body,
    })
}

fn relayer_wallet_nonce(owner: Address) -> Result<u64, DispatchResponse> {
    let value = relayer_get_json(&url_with_query(
        &format!("{RELAYER}/nonce"),
        &[("address", &format!("{owner:#x}")), ("type", "WALLET")],
    ))?;
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .or_else(|| value.get("nonce").and_then(parse_json_u64))
        .ok_or_else(|| error(-4, format!("relayer /nonce response unparsable: {value}")))
}

fn relayer_poll_confirmed(tx: &LocalRelayerTx) -> Result<LocalRelayerTx, DispatchResponse> {
    let deadline = now_secs().saturating_add(ONBOARD_POLL_TIMEOUT_SECS);
    loop {
        let cur = relayer_transaction(&tx.id)?;
        if cur.is_confirmed() {
            return Ok(cur);
        }
        if cur.is_failed() {
            return Err(error(-4, format!("relayer tx {} {}", cur.id, cur.state)));
        }
        if now_secs() >= deadline {
            return Err(error(
                -4,
                format!(
                    "relayer tx {} not confirmed before timeout (last: {})",
                    cur.id, cur.state
                ),
            ));
        }
        std::thread::sleep(Duration::from_secs(ONBOARD_POLL_INTERVAL_SECS));
    }
}

fn relayer_transaction(id: &str) -> Result<LocalRelayerTx, DispatchResponse> {
    let value = relayer_get_json(&url_with_query(
        &format!("{RELAYER}/transaction"),
        &[("id", id)],
    ))?;
    parse_relayer_transaction_response(id, &value).map_err(|message| error(-4, message))
}

fn relayer_get_json(url: &str) -> Result<serde_json::Value, DispatchResponse> {
    let resp = bloom_petal_sdk::http_fetch(
        &HttpRequest {
            method: "GET".into(),
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        },
        MAX_HTTP_BYTES,
    )
    .map_err(sdk_error)?;
    if !(200..300).contains(&resp.status) {
        return Err(error(
            -4,
            format!(
                "relayer error (status {}): {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ),
        ));
    }
    serde_json::from_slice(&resp.body).map_err(|e| error(-4, format!("relayer JSON: {e}")))
}

fn relayer_batch_body(
    wallet: &str,
    owner: Address,
    deposit: Address,
    nonce: u64,
    deadline: u64,
) -> Result<serde_json::Value, DispatchResponse> {
    let calls = v2_approval_calls();
    let batch = Batch {
        wallet: deposit,
        nonce: U256::from(nonce),
        deadline: U256::from(deadline),
        calls: calls.clone(),
    };
    let hash = batch_signing_hash(&batch, POLYGON, deposit);
    let signature = sign_hash_hex(wallet, "polymarket.relayer_batch", hash)?;
    let calls_json: Vec<serde_json::Value> = calls
        .iter()
        .map(|call| {
            serde_json::json!({
                "target": call.target.to_checksum(None),
                "value": call.value.to_string(),
                "data": format!("0x{}", hex::encode(call.data.as_ref())),
            })
        })
        .collect();
    Ok(serde_json::json!({
        "type": "WALLET",
        "from": owner.to_checksum(None),
        "to": FACTORY.to_checksum(None),
        "nonce": nonce.to_string(),
        "signature": signature,
        "depositWalletParams": {
            "depositWallet": deposit.to_checksum(None),
            "deadline": deadline.to_string(),
            "calls": calls_json,
        },
    }))
}

fn sign_hash_hex(wallet: &str, purpose: &str, hash: B256) -> Result<String, DispatchResponse> {
    match bloom_petal_sdk::sign_hash(&SignRequest {
        wallet: wallet.into(),
        hash32: hash.into(),
        purpose: purpose.into(),
    }) {
        Ok(sig) if sig.len() == 65 => Ok(format!("0x{}", hex::encode(sig))),
        Ok(sig) => Err(error(-4, format!("sign_hash returned {} bytes", sig.len()))),
        Err(e) => Err(sdk_error(e)),
    }
}

fn builder_headers(
    creds: &BuilderCredentials,
    method: &str,
    path: &str,
    body: &str,
) -> Result<Vec<(&'static str, String)>, String> {
    let timestamp = now_secs().to_string();
    let signature = builder_hmac_signature(&creds.secret, &timestamp, method, path, body)?;
    Ok(vec![
        ("POLY_BUILDER_API_KEY", creds.key.clone()),
        ("POLY_BUILDER_TIMESTAMP", timestamp),
        ("POLY_BUILDER_PASSPHRASE", creds.passphrase.clone()),
        ("POLY_BUILDER_SIGNATURE", signature),
    ])
}

fn builder_hmac_signature(
    secret: &str,
    timestamp: &str,
    method: &str,
    path: &str,
    body: &str,
) -> Result<String, String> {
    use base64::Engine as _;
    use hmac::Mac as _;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(secret)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(secret))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(secret))
        .map_err(|e| format!("builder secret base64: {e}"))?;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&decoded)
        .map_err(|e| format!("builder hmac key: {e}"))?;
    mac.update(format!("{timestamp}{method}{path}{body}").as_bytes());
    let out = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    Ok(out.replace('+', "-").replace('/', "_"))
}

fn parse_relayer_submit_response(value: &serde_json::Value) -> Result<LocalRelayerTx, String> {
    let id = ["transactionID", "transactionId", "transaction_id", "id"]
        .iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .ok_or_else(|| format!("relayer /submit response missing transaction id: {value}"))?;
    let state = value
        .get("state")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("STATE_NEW");
    Ok(LocalRelayerTx {
        id: id.into(),
        state: state.into(),
    })
}

fn parse_relayer_transaction_response(
    id: &str,
    value: &serde_json::Value,
) -> Result<LocalRelayerTx, String> {
    let tx = match value {
        serde_json::Value::Array(items) => items
            .iter()
            .find(|item| relayer_tx_id_matches(item, id))
            .or_else(|| items.first())
            .ok_or_else(|| format!("empty relayer /transaction response for {id}"))?,
        other => other,
    };
    let state = tx
        .get("state")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("relayer /transaction response for {id} missing state: {value}"))?;
    let parsed_id = ["transactionID", "transactionId", "transaction_id", "id"]
        .iter()
        .find_map(|key| tx.get(*key).and_then(serde_json::Value::as_str))
        .unwrap_or(id);
    Ok(LocalRelayerTx {
        id: parsed_id.into(),
        state: state.into(),
    })
}

fn relayer_tx_id_matches(value: &serde_json::Value, id: &str) -> bool {
    ["transactionID", "transactionId", "transaction_id", "id"]
        .iter()
        .any(|key| value.get(*key).and_then(serde_json::Value::as_str) == Some(id))
}

fn relayer_http_error(err: RelayerHttpError) -> DispatchResponse {
    if err.status == 401 || err.status == 403 {
        return error(
            -4,
            format!(
                "relayer rejected builder authentication (status {}): {}",
                err.status, err.body
            ),
        );
    }
    if err.status == 0 {
        error(-4, err.body)
    } else {
        error(
            -4,
            format!("relayer error (status {}): {}", err.status, err.body),
        )
    }
}

fn parse_json_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

fn onboard_in_flight_deadline_ms() -> u128 {
    now_millis().saturating_add((ONBOARD_POLL_TIMEOUT_SECS as u128).saturating_mul(1000))
}

fn dispatch_error_message(resp: &DispatchResponse) -> String {
    match resp {
        DispatchResponse::Error { message, .. } => message.clone(),
        other => format!("{other:?}"),
    }
}

fn clob_l2_get_json(
    owner: Address,
    creds: &Credentials,
    path: &str,
    query: &[(&str, &str)],
) -> Result<serde_json::Value, DispatchResponse> {
    let timestamp = now_secs();
    let headers = l2_headers(
        owner,
        &creds.key,
        &creds.passphrase,
        &creds.secret,
        timestamp,
        "GET",
        path,
        "",
    )
    .map_err(|e| error(-4, e.to_string()))?;
    let url = url_with_query(&format!("{CLOB}{path}"), query);
    let resp = bloom_petal_sdk::http_fetch(
        &HttpRequest {
            method: "GET".into(),
            url,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into(), value))
                .collect(),
            body: Vec::new(),
        },
        MAX_HTTP_BYTES,
    )
    .map_err(sdk_error)?;
    if !(200..300).contains(&resp.status) {
        return Err(error(
            -4,
            format!(
                "CLOB account error (status {}): response body redacted ({} bytes)",
                resp.status,
                resp.body.len()
            ),
        ));
    }
    if resp.body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_slice(&resp.body).map_err(|e| error(-4, format!("json: {e}")))
}

fn clob_l2_post_json(
    owner: Address,
    creds: &Credentials,
    path: &str,
    body: &str,
) -> Result<serde_json::Value, DispatchResponse> {
    let timestamp = now_secs();
    let headers = l2_headers(
        owner,
        &creds.key,
        &creds.passphrase,
        &creds.secret,
        timestamp,
        "POST",
        path,
        body,
    )
    .map_err(|e| error(-4, e.to_string()))?;
    let resp = bloom_petal_sdk::http_fetch(
        &HttpRequest {
            method: "POST".into(),
            url: format!("{CLOB}{path}"),
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into(), value))
                .collect(),
            body: body.as_bytes().to_vec(),
        },
        MAX_HTTP_BYTES,
    )
    .map_err(sdk_error)?;
    if !(200..300).contains(&resp.status) {
        return Err(error(
            -4,
            format!("CLOB post error (status {})", resp.status),
        ));
    }
    if resp.body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(serde_json::json!({ "status": "posted" }));
    }
    serde_json::from_slice(&resp.body).map_err(|e| error(-4, format!("json: {e}")))
}

fn clob_l2_delete_json(
    owner: Address,
    creds: &Credentials,
    path: &str,
    body: &str,
) -> Result<serde_json::Value, DispatchResponse> {
    let timestamp = now_secs();
    let headers = l2_headers(
        owner,
        &creds.key,
        &creds.passphrase,
        &creds.secret,
        timestamp,
        "DELETE",
        path,
        body,
    )
    .map_err(|e| error(-4, e.to_string()))?;
    let resp = bloom_petal_sdk::http_fetch(
        &HttpRequest {
            method: "DELETE".into(),
            url: format!("{CLOB}{path}"),
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into(), value))
                .collect(),
            body: body.as_bytes().to_vec(),
        },
        MAX_HTTP_BYTES,
    )
    .map_err(sdk_error)?;
    if !(200..300).contains(&resp.status) {
        return Err(error(
            -4,
            format!("CLOB cancel error (status {})", resp.status),
        ));
    }
    if resp.body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(serde_json::json!({ "status": "empty" }));
    }
    serde_json::from_slice(&resp.body).map_err(|e| error(-4, format!("json: {e}")))
}

fn wallet_address(wallet: &str) -> Result<Address, DispatchResponse> {
    let path = format!("wallets/{wallet}/address");
    let bytes = bloom_petal_sdk::vfs_read(&path, 128).map_err(sdk_error)?;
    let raw = core::str::from_utf8(&bytes)
        .map_err(|e| error(-4, format!("wallet address is not utf-8: {e}")))?
        .trim();
    raw.parse::<Address>()
        .map_err(|e| error(-4, format!("wallet address parse: {e}")))
}

fn http(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Result<bloom_petal_sdk::HttpResponse, DispatchResponse> {
    bloom_petal_sdk::http_fetch(
        &HttpRequest {
            method: method.into(),
            url: url.into(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into()))
                .collect(),
            body,
        },
        MAX_HTTP_BYTES,
    )
    .map_err(sdk_error)
}

fn read_store(key: &str) -> DispatchResponse {
    match bloom_petal_sdk::store_get(key, MAX_STORE_BYTES) {
        Ok(bytes) => DispatchResponse::Read(bytes),
        Err(SdkError::Host(HostStatus::NotFound)) => error(-1, "not found"),
        Err(e) => sdk_error(e),
    }
}

fn acquire_trade_lock(wallet: &str, draft_id: &str) -> Result<StoreTradeLock, DispatchResponse> {
    let key = format!("trade/{wallet}/.lock");
    for attempt in 0..2 {
        let bytes = trade_lock_body(wallet, draft_id)?;
        match bloom_petal_sdk::store_put_new(&key, &bytes, false) {
            Ok(()) => {
                return Ok(StoreTradeLock {
                    key,
                    expected: bytes,
                });
            }
            Err(SdkError::Host(HostStatus::Denied)) if attempt == 0 => {
                let Some(stale_bytes) = trade_lock_stale_bytes(&key) else {
                    return Err(error(
                        -3,
                        format!("another trade operation holds the lock for wallet '{wallet}'"),
                    ));
                };
                match bloom_petal_sdk::store_del_if_value(&key, &stale_bytes) {
                    Ok(()) | Err(SdkError::Host(HostStatus::NotFound)) => continue,
                    Err(SdkError::Host(HostStatus::Denied)) => {
                        return Err(error(
                            -3,
                            format!(
                                "another trade operation refreshed the lock for wallet '{wallet}'"
                            ),
                        ));
                    }
                    Err(e) => return Err(sdk_error(e)),
                }
            }
            Err(SdkError::Host(HostStatus::Denied)) => {
                return Err(error(
                    -3,
                    format!("another trade operation holds the lock for wallet '{wallet}'"),
                ));
            }
            Err(e) => return Err(sdk_error(e)),
        }
    }
    Err(error(
        -3,
        format!("another trade operation holds the lock for wallet '{wallet}'"),
    ))
}

fn trade_lock_body(wallet: &str, draft_id: &str) -> Result<Vec<u8>, DispatchResponse> {
    let mut token = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut token)
        .map_err(|e| error(-4, format!("trade lock random token: {e}")))?;
    let body = serde_json::json!({
        "wallet": wallet,
        "draft_id": draft_id,
        "acquired_ms": now_millis(),
        "token": hex::encode(token)
    });
    serde_json::to_vec(&body).map_err(|e| error(-4, format!("json: {e}")))
}

fn trade_lock_stale_bytes(key: &str) -> Option<Vec<u8>> {
    match bloom_petal_sdk::store_get(key, MAX_STORE_BYTES) {
        Ok(bytes) => {
            let stale = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.get("acquired_ms").and_then(serde_json::Value::as_u64))
                .map(|acquired| now_millis().saturating_sub(acquired as u128) > TRADE_LOCK_STALE_MS)
                .unwrap_or(true);
            stale.then_some(bytes)
        }
        Err(_) => None,
    }
}

struct StoreTradeLock {
    key: String,
    expected: Vec<u8>,
}

impl Drop for StoreTradeLock {
    fn drop(&mut self) {
        let _ = bloom_petal_sdk::store_del_if_value(&self.key, &self.expected);
    }
}

fn store_get(key: &str) -> Option<Vec<u8>> {
    bloom_petal_sdk::store_get(key, MAX_STORE_BYTES).ok()
}

fn store_put_json<T: Serialize>(key: &str, value: &T, secret: bool) -> DispatchResponse {
    let bytes = match serde_json::to_vec_pretty(value) {
        Ok(bytes) => bytes,
        Err(e) => return error(-4, format!("json: {e}")),
    };
    match bloom_petal_sdk::store_put(key, &bytes, secret) {
        Ok(()) => DispatchResponse::Write,
        Err(e) => sdk_error(e),
    }
}

fn store_trade_receipt(wallet: &str, id: &str, receipt: &StoreTradeReceipt) -> DispatchResponse {
    let audit_resp = append_trade_audit(
        wallet,
        "receipt_written",
        serde_json::json!({
            "draft_id": id,
            "clob_status": receipt.clob_status,
            "amount_microusd": receipt.amount_microusd,
        }),
    );
    if let DispatchResponse::Error { .. } = audit_resp {
        return audit_resp;
    }
    store_put_json(
        &format!("trade/{wallet}/receipts/{id}/receipt.json"),
        receipt,
        false,
    )
}

fn append_trade_audit(wallet: &str, event: &str, details: serde_json::Value) -> DispatchResponse {
    let key = format!("trade/{wallet}/audit.jsonl");
    let mut text = match bloom_petal_sdk::store_get(&key, MAX_STORE_BYTES) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(SdkError::Host(HostStatus::NotFound)) => String::new(),
        Err(e) => return sdk_error(e),
    };
    let line = serde_json::json!({
        "ts_ms": now_millis(),
        "event": event,
        "details": details,
    });
    text.push_str(&line.to_string());
    text.push('\n');
    match bloom_petal_sdk::store_put(&key, text.as_bytes(), false) {
        Ok(()) => DispatchResponse::Write,
        Err(e) => sdk_error(e),
    }
}

fn clob_response_status(raw: &serde_json::Value) -> String {
    raw.get("status")
        .or_else(|| raw.get("orderStatus"))
        .or_else(|| raw.get("order_status"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("posted")
        .to_ascii_lowercase()
}

fn clob_status_excluded_from_daily_cap(status: &str, order_type: Option<OrderType>) -> bool {
    status == "rejected"
        || (status == "unmatched" && order_type.is_some_and(|order_type| !order_type.can_rest()))
}

fn reconcile_ambiguous_post(
    owner: Address,
    creds: &Credentials,
    draft: &StoreTradeDraft,
    funder: Address,
    salt: u64,
) -> Option<serde_json::Value> {
    let open_orders = clob_l2_get_json(owner, creds, "/data/orders", &[]).ok()?;
    find_matching_open_order(&open_orders, draft, funder, salt)
}

fn find_matching_open_order(
    raw: &serde_json::Value,
    draft: &StoreTradeDraft,
    funder: Address,
    salt: u64,
) -> Option<serde_json::Value> {
    match raw {
        serde_json::Value::Array(items) => items
            .iter()
            .find(|item| open_order_matches_draft(item, draft, funder, salt))
            .cloned(),
        serde_json::Value::Object(map) => ["orders", "data", "results"]
            .iter()
            .filter_map(|key| map.get(*key))
            .find_map(|value| find_matching_open_order(value, draft, funder, salt)),
        _ => None,
    }
}

fn open_order_matches_draft(
    item: &serde_json::Value,
    draft: &StoreTradeDraft,
    funder: Address,
    salt: u64,
) -> bool {
    if clob_response_order_id(item).is_none() {
        return false;
    }
    if matches!(
        clob_response_status(item).as_str(),
        "rejected" | "cancelled" | "canceled"
    ) {
        return false;
    }
    let Some(salts) = (match clob_order_field_u64s(item, &["salt"]) {
        Ok(values) => values,
        Err(()) => return false,
    }) else {
        return false;
    };
    if salts.iter().any(|value| *value != salt) {
        return false;
    }

    let mut matched_fields = 0usize;
    if let Some(values) = match clob_order_field_strings(
        item,
        &["asset_id", "assetId", "token_id", "tokenId", "tokenID"],
    ) {
        Ok(values) => values,
        Err(()) => return false,
    } {
        if values.iter().any(|value| value != &draft.token_id) {
            return false;
        }
        matched_fields += 1;
    }
    if let Some(values) = match clob_order_field_strings(item, &["maker", "signer", "funder"]) {
        Ok(values) => values,
        Err(()) => return false,
    } {
        let expected = funder.to_checksum(None);
        if values
            .iter()
            .any(|value| !address_strings_equal(value, &expected))
        {
            return false;
        }
        matched_fields += 1;
    }
    if clob_order_fields(item, &["side"])
        .into_iter()
        .try_fold(false, |_, value| clob_side_value_matches(value, draft.side))
        .unwrap_or(false)
    {
        matched_fields += 1;
    } else if !clob_order_fields(item, &["side"]).is_empty() {
        return false;
    }
    if let Some(values) = match clob_order_field_strings(item, &["orderType", "order_type"]) {
        Ok(values) => values,
        Err(()) => return false,
    } {
        if values
            .iter()
            .any(|value| !value.eq_ignore_ascii_case(draft.order_type.as_str()))
        {
            return false;
        }
        matched_fields += 1;
    }
    if let Some(values) = match clob_order_field_u64s(item, &["makerAmount", "maker_amount"]) {
        Ok(values) => values,
        Err(()) => return false,
    } {
        if values.iter().any(|value| *value != draft.maker_micro) {
            return false;
        }
        matched_fields += 1;
    }
    if let Some(values) = match clob_order_field_u64s(item, &["takerAmount", "taker_amount"]) {
        Ok(values) => values,
        Err(()) => return false,
    } {
        if values.iter().any(|value| *value != draft.taker_micro) {
            return false;
        }
        matched_fields += 1;
    }

    matched_fields >= 2
}

fn clob_order_fields<'a>(
    item: &'a serde_json::Value,
    names: &[&str],
) -> Vec<&'a serde_json::Value> {
    let mut values = Vec::new();
    for name in names {
        if let Some(value) = item.get(*name) {
            values.push(value);
        }
    }
    if let Some(order) = item.get("order") {
        for name in names {
            if let Some(value) = order.get(*name) {
                values.push(value);
            }
        }
    }
    values
}

fn clob_order_field_strings(
    item: &serde_json::Value,
    names: &[&str],
) -> Result<Option<Vec<String>>, ()> {
    let mut values = Vec::new();
    for value in clob_order_fields(item, names) {
        match value {
            serde_json::Value::String(s) => values.push(s.clone()),
            serde_json::Value::Number(n) => values.push(n.to_string()),
            _ => return Err(()),
        }
    }
    Ok((!values.is_empty()).then_some(values))
}

fn clob_order_field_u64s(item: &serde_json::Value, names: &[&str]) -> Result<Option<Vec<u64>>, ()> {
    let mut values = Vec::new();
    for value in clob_order_fields(item, names) {
        let Some(parsed) = (match value {
            serde_json::Value::Number(n) => n.as_u64(),
            serde_json::Value::String(s) => s.parse::<u64>().ok(),
            _ => None,
        }) else {
            return Err(());
        };
        values.push(parsed);
    }
    Ok((!values.is_empty()).then_some(values))
}

fn address_strings_equal(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

fn clob_side_value_matches(value: &serde_json::Value, side: Side) -> Result<bool, bool> {
    let matches = match value {
        serde_json::Value::String(s) => {
            let normalized = s.trim().to_ascii_uppercase();
            match side {
                Side::Buy => normalized == "BUY" || normalized == "0",
                Side::Sell => normalized == "SELL" || normalized == "1",
            }
        }
        serde_json::Value::Number(n) => n
            .as_u64()
            .is_some_and(|value| matches!((value, side), (0, Side::Buy) | (1, Side::Sell))),
        _ => return Err(false),
    };
    matches.then_some(true).ok_or(false)
}

fn clob_response_order_id(raw: &serde_json::Value) -> Option<String> {
    raw.get("orderID")
        .or_else(|| raw.get("orderId"))
        .or_else(|| raw.get("order_id"))
        .or_else(|| raw.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

fn clob_response_filled_size_micro(raw: &serde_json::Value) -> Option<u64> {
    raw.get("size_matched")
        .or_else(|| raw.get("matched_size"))
        .or_else(|| raw.get("filled_size"))
        .and_then(|value| match value {
            serde_json::Value::String(s) => parse_micro(s).ok(),
            serde_json::Value::Number(n) => n
                .as_f64()
                .and_then(|f| parse_api_float_micro(f, "filled_size").ok()),
            _ => None,
        })
}

fn clob_cancel_confirmed(raw: &serde_json::Value, order_id: &str) -> bool {
    let status_cancelled = raw
        .get("status")
        .and_then(serde_json::Value::as_str)
        .map(|status| {
            let status = status.to_ascii_lowercase();
            status == "cancelled" || status == "canceled"
        })
        .unwrap_or(false);
    let status_order_matches = raw
        .get("orderID")
        .or_else(|| raw.get("orderId"))
        .or_else(|| raw.get("order_id"))
        .or_else(|| raw.get("id"))
        .and_then(serde_json::Value::as_str)
        == Some(order_id);
    let listed_cancelled = raw
        .get("canceled")
        .or_else(|| raw.get("cancelled"))
        .and_then(serde_json::Value::as_array)
        .map(|items| items.iter().any(|item| item.as_str() == Some(order_id)))
        .unwrap_or(false);
    listed_cancelled || (status_cancelled && status_order_matches)
}

fn clob_response_public_summary(
    status: &str,
    order_id: &Option<String>,
    filled_size_micro: Option<u64>,
) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "order_id": order_id,
        "filled_size_micro": filled_size_micro,
        "response_redacted": true
    })
}

fn clob_reconciled_public_summary(
    status: &str,
    order_id: &Option<String>,
    filled_size_micro: Option<u64>,
) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "order_id": order_id,
        "filled_size_micro": filled_size_micro,
        "reconciled_from": "open_orders",
        "response_redacted": true
    })
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn store_wallets(prefix: &str) -> Vec<String> {
    let Ok(keys) = bloom_petal_sdk::store_list(prefix, MAX_LIST_BYTES) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in keys {
        let rest = key.strip_prefix(prefix).unwrap_or(&key);
        if let Some(wallet) = rest.split('/').next()
            && is_safe_segment(wallet)
            && !out.iter().any(|existing| existing == wallet)
        {
            out.push(wallet.to_string());
        }
    }
    out.sort();
    out
}

fn vfs_wallets_or_store(store_prefix: &str) -> Vec<String> {
    match bloom_petal_sdk::vfs_list("wallets", MAX_LIST_BYTES) {
        Ok(names) => safe_wallet_names(names),
        Err(_) if store_prefix.is_empty() => Vec::new(),
        Err(_) => store_wallets(store_prefix),
    }
}

fn safe_wallet_names(names: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for name in names {
        if name != "new" && is_safe_segment(&name) && !out.iter().any(|existing| existing == &name)
        {
            out.push(name);
        }
    }
    out.sort();
    out
}

fn store_ids(prefix: &str, suffix: &str) -> Vec<String> {
    let Ok(keys) = bloom_petal_sdk::store_list(prefix, MAX_LIST_BYTES) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in keys {
        if let Some(rest) = key.strip_prefix(prefix)
            && let Some(id) = rest.strip_suffix(suffix)
            && !id.contains('/')
            && is_safe_segment(id)
            && !out.iter().any(|existing| existing == id)
        {
            out.push(id.to_string());
        }
    }
    out.sort();
    out
}

fn next_id(prefix: &str, suffix: &str) -> String {
    let next = store_ids(prefix, suffix)
        .into_iter()
        .filter_map(|id| id.parse::<u64>().ok())
        .max()
        .unwrap_or(0)
        + 1;
    format!("{next:04}")
}

fn read_json_value<T: Serialize>(value: &T) -> DispatchResponse {
    match serde_json::to_vec_pretty(value) {
        Ok(bytes) => DispatchResponse::Read(bytes),
        Err(e) => error(-4, format!("json: {e}")),
    }
}

fn render_onboard_plan(wallet: &str) -> String {
    format!(
        "# Polymarket onboarding\n\nWallet: {wallet}\n\nWrite `begin` to request daemon-keystore signatures for CLOB auth and any required deposit-wallet approval batch, store CLOB and builder credentials in the private petal store, deploy the live-factory deposit wallet when needed, rest at `fund` until pUSD arrives, then approve and sync CLOB buying power before marking the wallet tradeable.\n"
    )
}

fn render_trade_plan(draft: &StoreTradeDraft) -> String {
    format!(
        "# Polymarket order draft {}\n\nWallet: {}\nMarket: {}\nQuestion: {}\nOutcome: {}\nToken: {}\nSide: {:?}\nOrder type: {}\nAmount: {}\nPrice bound: {}\nLimit price: {}\nSize: {}\nStatus: {}\n\nThe draft is live-quoted from Gamma/CLOB and ready for review. Signing and posting are still pending.\n",
        draft.id,
        draft.wallet,
        draft.slug,
        draft.question,
        draft.outcome,
        draft.token_id,
        draft.side,
        draft.order_type.as_str(),
        format_micro(draft.amount_micro),
        format_micro(draft.price_bound_micro),
        format_micro(draft.limit_price_micro),
        format_micro(draft.size_micro),
        draft.status
    )
}

fn render_fund_plan(session: &StoreFundSession) -> String {
    format!(
        "# Polymarket funding request {}\n\nWallet: {}\nReceiver: {} ({})\nTarget pUSD: {}\nMax spend: {}\nFrom token: {}\nSlippage bps: {}\nStatus: {}\n",
        session.id,
        session.wallet,
        session.deposit_wallet,
        session.deposit_wallet_source,
        session.target_pusd,
        session.max_spend,
        session.from_token,
        session.slippage_bps,
        session.status
    )
}

fn validate_relative_path(relative: &str) -> Result<&str, String> {
    if relative.is_empty() {
        return Ok(relative);
    }
    for segment in relative.split('/') {
        if !is_safe_segment(segment) {
            return Err(format!("invalid path segment '{segment}'"));
        }
    }
    Ok(relative)
}

fn is_safe_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains('\\')
        && !segment.bytes().any(|byte| byte == 0)
}

fn path_kind(relative: &str) -> Option<DispatchEntryKind> {
    let segs = split(relative);
    match (segs.first().copied(), segs.len()) {
        (None, 0) => Some(DispatchEntryKind::Dir),
        (Some("markets"), 1) => Some(DispatchEntryKind::Dir),
        (Some("markets"), 2) => Some(DispatchEntryKind::Dir),
        (Some("markets"), 3) if MARKET_FILES.contains(&segs[2]) => Some(DispatchEntryKind::File),
        (Some("meta"), 1) => Some(DispatchEntryKind::Dir),
        (Some("meta"), 2) if META_FILES.contains(&segs[1]) => Some(DispatchEntryKind::File),
        (Some("search"), 1) => Some(DispatchEntryKind::Dir),
        (Some("search"), 2) => Some(DispatchEntryKind::File),
        (Some("positions"), 1) => Some(DispatchEntryKind::Dir),
        (Some("positions"), 2) => Some(DispatchEntryKind::Dir),
        (Some("positions"), 3) if POSITION_FILES.contains(&segs[2]) => {
            Some(DispatchEntryKind::File)
        }
        (Some("onboard"), 1) => Some(DispatchEntryKind::Dir),
        (Some("onboard"), 2) => Some(DispatchEntryKind::Dir),
        (Some("onboard"), 3) if segs[2] == "begin" => Some(DispatchEntryKind::WritableFile),
        (Some("onboard"), 3) if ONBOARD_FILES.contains(&segs[2]) => Some(DispatchEntryKind::File),
        (Some("account"), 1) => Some(DispatchEntryKind::Dir),
        (Some("account"), 2) => Some(DispatchEntryKind::Dir),
        (Some("account"), 3) if ACCOUNT_FILES.contains(&segs[2]) => Some(DispatchEntryKind::File),
        (Some("fund"), 1) => Some(DispatchEntryKind::Dir),
        (Some("fund"), 2) => Some(DispatchEntryKind::Dir),
        (Some("fund"), 3) if segs[2] == "new" => Some(DispatchEntryKind::WritableFile),
        (Some("fund"), 3) => Some(DispatchEntryKind::Dir),
        (Some("fund"), 4) if FUND_FILES.contains(&segs[3]) => Some(DispatchEntryKind::File),
        (Some("trade"), 1) => Some(DispatchEntryKind::Dir),
        (Some("trade"), 2) => Some(DispatchEntryKind::Dir),
        (Some("trade"), 3) if segs[2] == "new" => Some(DispatchEntryKind::WritableFile),
        (Some("trade"), 3) if segs[2] == "drafts" || segs[2] == "receipts" => {
            Some(DispatchEntryKind::Dir)
        }
        (Some("trade"), 4) if segs[2] == "drafts" || segs[2] == "receipts" => {
            Some(DispatchEntryKind::Dir)
        }
        (Some("trade"), 5) if segs[2] == "drafts" && DRAFT_FILES.contains(&segs[4]) => {
            Some(DispatchEntryKind::File)
        }
        (Some("trade"), 5) if segs[2] == "drafts" && DRAFT_WRITABLE_FILES.contains(&segs[4]) => {
            Some(DispatchEntryKind::WritableFile)
        }
        (Some("trade"), 5) if segs[2] == "receipts" && RECEIPT_FILES.contains(&segs[4]) => {
            Some(DispatchEntryKind::File)
        }
        (Some("trade"), 5)
            if segs[2] == "receipts" && RECEIPT_WRITABLE_FILES.contains(&segs[4]) =>
        {
            Some(DispatchEntryKind::WritableFile)
        }
        _ => None,
    }
}

fn split(relative: &str) -> Vec<&str> {
    if relative.is_empty() {
        Vec::new()
    } else {
        relative.split('/').collect()
    }
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).into()).collect()
}

fn child_relative(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.into()
    } else {
        format!("{parent}/{child}")
    }
}

fn entry_name(relative: &str) -> &str {
    relative
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("")
}

fn entry(name: &str, kind: DispatchEntryKind) -> DispatchEntry {
    let mode = match kind {
        DispatchEntryKind::Dir => 0o755,
        DispatchEntryKind::WritableFile => 0o644,
        _ => 0o444,
    };
    DispatchEntry {
        name: name.into(),
        kind,
        size: 0,
        mode,
        ttl_hint_ms: None,
        link_target: None,
    }
}

fn url_with_query(base: &str, pairs: &[(&str, &str)]) -> String {
    let mut url = Url::parse(base).expect("hard-coded Polymarket URL must parse");
    for (key, value) in pairs {
        url.query_pairs_mut().append_pair(key, value);
    }
    url.to_string()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn sdk_error(e: SdkError) -> DispatchResponse {
    match e {
        SdkError::Host(HostStatus::NotFound) => error(-1, "not found"),
        SdkError::Host(HostStatus::Denied) => error(-2, "denied"),
        SdkError::Host(HostStatus::Invalid) => error(-3, "invalid"),
        SdkError::Host(HostStatus::Backend) => error(-4, "backend error"),
        SdkError::Host(HostStatus::BufferTooSmall { needed }) => {
            error(-5, format!("response too large: needs {needed} bytes"))
        }
        other => error(-4, other.message()),
    }
}

fn sdk_error_with_context(context: &str, e: SdkError) -> DispatchResponse {
    let code = match &e {
        SdkError::Host(HostStatus::NotFound) => -1,
        SdkError::Host(HostStatus::Denied) => -2,
        SdkError::Host(HostStatus::Invalid) => -3,
        SdkError::Host(HostStatus::Backend) => -4,
        SdkError::Host(HostStatus::BufferTooSmall { .. }) => -5,
        _ => -4,
    };
    error(code, format!("{context}: {}", e.message()))
}

fn polymarket_error(e: bloom_polymarket::PolymarketError) -> DispatchResponse {
    match e {
        bloom_polymarket::PolymarketError::Invalid(message) => error(-3, message),
        other => error(-4, other.to_string()),
    }
}

fn error(code: i32, message: impl Into<String>) -> DispatchResponse {
    DispatchResponse::Error {
        code,
        message: message.into(),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct TradeNewRequest {
    slug: String,
    outcome: String,
    amount: String,
    #[serde(default)]
    side: Option<String>,
    #[serde(default)]
    max_price: Option<String>,
    #[serde(default)]
    min_price: Option<String>,
    #[serde(default)]
    limit_price: Option<String>,
    #[serde(default)]
    order_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GeoblockStatus {
    #[serde(default)]
    blocked: bool,
    #[serde(default)]
    country: String,
    #[serde(default)]
    region: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct LocalWalletPolicy {
    #[serde(default)]
    polymarket: LocalPolymarketPolicy,
}

#[derive(Debug, Clone, Deserialize)]
struct LocalPolymarketPolicy {
    #[serde(default)]
    enabled: bool,
    #[serde(default, with = "local_micro_opt")]
    max_order_usd: Option<u64>,
    #[serde(default, with = "local_micro_opt")]
    max_daily_usd: Option<u64>,
    #[serde(default, with = "local_micro_opt")]
    require_flag_above_usd: Option<u64>,
    #[serde(default, with = "local_micro_opt")]
    max_price: Option<u64>,
    #[serde(default = "default_true")]
    allow_neg_risk: bool,
    #[serde(default)]
    allowed_slugs: BTreeSet<String>,
    #[serde(default)]
    denied_slugs: BTreeSet<String>,
    #[serde(default)]
    allowed_condition_ids: BTreeSet<String>,
    #[serde(default)]
    denied_condition_ids: BTreeSet<String>,
}

impl Default for LocalPolymarketPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_order_usd: None,
            max_daily_usd: None,
            require_flag_above_usd: None,
            max_price: None,
            allow_neg_risk: true,
            allowed_slugs: BTreeSet::new(),
            denied_slugs: BTreeSet::new(),
            allowed_condition_ids: BTreeSet::new(),
            denied_condition_ids: BTreeSet::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

mod local_micro_opt {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            S(String),
            I(i64),
            F(f64),
        }
        match Option::<Raw>::deserialize(d)? {
            None => Ok(None),
            Some(Raw::S(s)) => super::parse_micro(s.trim())
                .map(Some)
                .map_err(D::Error::custom),
            Some(Raw::I(i)) => {
                if i < 0 {
                    return Err(D::Error::custom("USD amount cannot be negative"));
                }
                (i as u64)
                    .checked_mul(1_000_000)
                    .map(Some)
                    .ok_or_else(|| D::Error::custom("USD amount too large"))
            }
            Some(Raw::F(f)) => super::parse_micro(&format!("{f}"))
                .map(Some)
                .map_err(D::Error::custom),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalPolicySide {
    Buy,
    Sell,
}

#[derive(Debug, Clone)]
struct LocalPolymarketOrderCtx {
    slug: String,
    condition_id: String,
    side: LocalPolicySide,
    amount_microusd: u64,
    limit_price_micro: u64,
    active: bool,
    closed: bool,
    order_book_enabled: bool,
    binary_outcomes: bool,
    neg_risk: bool,
    receipt_store_readable: bool,
    daily_posted_microusd: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LocalPolicyOutcome {
    Pass,
    Warn,
    Deny,
}

#[derive(Debug, Clone, Serialize)]
struct LocalPolicyCheck {
    rule: String,
    outcome: LocalPolicyOutcome,
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TradeRevalidateRequest {
    revalidate: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct TradePostRequest {
    post: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct TradeCancelRequest {
    cancel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreTradeDraft {
    id: String,
    wallet: String,
    slug: String,
    question: String,
    condition_id: String,
    outcome: String,
    token_id: String,
    side: Side,
    order_type: OrderType,
    amount_micro: u64,
    price_bound_micro: u64,
    limit_price: Option<String>,
    marketable: bool,
    limit_price_micro: u64,
    size_micro: u64,
    maker_micro: u64,
    taker_micro: u64,
    tick_micro: u64,
    min_order_size_micro: u64,
    neg_risk: bool,
    active: bool,
    closed: bool,
    order_book_enabled: bool,
    binary_outcomes: bool,
    best_ask_micro: Option<u64>,
    best_bid_micro: Option<u64>,
    book_snapshot_secs: u64,
    status: String,
    #[serde(default)]
    salt: Option<u64>,
    #[serde(default)]
    clob_order_id: Option<String>,
    #[serde(default)]
    clob_status: Option<String>,
    #[serde(default)]
    last_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct StoreTradeReceiptPolicy {
    side: Side,
    #[serde(default)]
    order_type: Option<OrderType>,
    amount_microusd: u64,
    clob_status: String,
    posted_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreTradeReceipt {
    draft_id: String,
    wallet: String,
    slug: String,
    token_id: String,
    side: Side,
    order_type: OrderType,
    funder: Option<String>,
    signature_type: u8,
    amount_microusd: u64,
    limit_price_micro: u64,
    size_micro: u64,
    salt: u64,
    clob_order_id: Option<String>,
    clob_status: String,
    filled_size_micro: Option<u64>,
    raw_response: serde_json::Value,
    review_intent_hash: Option<String>,
    posted_ms: u128,
}

#[derive(Debug, Clone)]
struct TradeSnapshot {
    market: Market,
    outcome: String,
    token_id: String,
    neg_risk: bool,
    tick_micro: u64,
    min_size_micro: u64,
    best_ask_micro: Option<u64>,
    best_bid_micro: Option<u64>,
    active: bool,
    closed: bool,
    order_book_enabled: bool,
}

impl TradeSnapshot {
    fn as_shared(&self) -> shared_trade::Snapshot {
        shared_trade::Snapshot {
            market: self.market.clone(),
            token_id: self.token_id.clone(),
            neg_risk: self.neg_risk,
            tick_micro: self.tick_micro,
            min_size_micro: self.min_size_micro,
            best_ask_micro: self.best_ask_micro,
            best_bid_micro: self.best_bid_micro,
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreFundSession {
    id: String,
    wallet: String,
    target_pusd: String,
    max_spend: String,
    from_token: String,
    slippage_bps: u16,
    #[serde(default)]
    deposit_wallet: String,
    #[serde(default)]
    deposit_wallet_source: String,
    status: String,
}

fn default_slippage_bps() -> u16 {
    50
}

#[cfg(test)]
mod tests {
    use super::*;

    fn market() -> Market {
        Market {
            id: "1".into(),
            slug: "example".into(),
            question: "Example?".into(),
            condition_id: "0xabc".into(),
            clob_token_ids: vec!["111".into(), "222".into()],
            outcomes: vec!["Yes".into(), "No".into()],
            outcome_prices: Vec::new(),
            active: true,
            closed: false,
            enable_order_book: true,
            order_price_min_tick_size: None,
            order_min_size: None,
            neg_risk: false,
        }
    }

    fn snapshot(best_ask_micro: Option<u64>, best_bid_micro: Option<u64>) -> TradeSnapshot {
        TradeSnapshot {
            market: market(),
            outcome: "YES".into(),
            token_id: "111".into(),
            neg_risk: false,
            tick_micro: 10_000,
            min_size_micro: 5_000_000,
            best_ask_micro,
            best_bid_micro,
            active: true,
            closed: false,
            order_book_enabled: true,
        }
    }

    fn policy_ctx() -> LocalPolymarketOrderCtx {
        LocalPolymarketOrderCtx {
            slug: "example".into(),
            condition_id: "0xabc".into(),
            side: LocalPolicySide::Buy,
            amount_microusd: 10_000_000,
            limit_price_micro: 695_000,
            active: true,
            closed: false,
            order_book_enabled: true,
            binary_outcomes: true,
            neg_risk: false,
            receipt_store_readable: true,
            daily_posted_microusd: Some(0),
        }
    }

    fn draft() -> StoreTradeDraft {
        StoreTradeDraft {
            id: "0001".into(),
            wallet: "alice".into(),
            slug: "example".into(),
            question: "Example?".into(),
            condition_id: "0xabc".into(),
            outcome: "YES".into(),
            token_id: "111".into(),
            side: Side::Buy,
            order_type: OrderType::FAK,
            amount_micro: 1_000_000,
            price_bound_micro: 100_000,
            limit_price: None,
            marketable: true,
            limit_price_micro: 90_000,
            size_micro: 11_111_100,
            maker_micro: 1_000_000,
            taker_micro: 11_111_100,
            tick_micro: 10_000,
            min_order_size_micro: 1_000_000,
            neg_risk: false,
            active: true,
            closed: false,
            order_book_enabled: true,
            binary_outcomes: true,
            best_ask_micro: Some(90_000),
            best_bid_micro: Some(80_000),
            book_snapshot_secs: 1,
            status: "signed".into(),
            salt: Some(42),
            clob_order_id: None,
            clob_status: None,
            last_error: None,
        }
    }

    #[test]
    fn path_validation_rejects_escape_segments() {
        assert!(validate_relative_path("").is_ok());
        assert!(validate_relative_path("markets/example/market.json").is_ok());
        assert!(validate_relative_path("../wallets").is_err());
        assert!(validate_relative_path("markets//book.json").is_err());
        assert!(validate_relative_path("markets\\evil").is_err());
    }

    #[test]
    fn path_shapes_are_static_and_expected() {
        assert_eq!(path_kind(""), Some(DispatchEntryKind::Dir));
        assert_eq!(path_kind("markets/foo"), Some(DispatchEntryKind::Dir));
        assert_eq!(
            path_kind("markets/foo/book.json"),
            Some(DispatchEntryKind::File)
        );
        assert_eq!(path_kind("meta"), Some(DispatchEntryKind::Dir));
        assert_eq!(path_kind("meta/parity.json"), Some(DispatchEntryKind::File));
        assert_eq!(
            path_kind("onboard/alice/begin"),
            Some(DispatchEntryKind::WritableFile)
        );
        assert_eq!(
            path_kind("trade/alice/drafts/0001/plan.md"),
            Some(DispatchEntryKind::File)
        );
        assert_eq!(
            path_kind("trade/alice/drafts/0001/revalidate"),
            Some(DispatchEntryKind::WritableFile)
        );
        assert_eq!(
            path_kind("trade/alice/receipts/0001/receipt.json"),
            Some(DispatchEntryKind::File)
        );
        assert_eq!(
            path_kind("trade/alice/receipts/0001/cancel"),
            Some(DispatchEntryKind::WritableFile)
        );
        assert_eq!(path_kind("trade/alice/new/extra"), None);
    }

    #[test]
    fn completed_onboard_refresh_clears_stale_in_flight_marker() {
        let previous = serde_json::json!({
            "deploy_tx_id": "tx-d",
            "approve_tx_id": "tx-a",
            "relayer_auth": "builder_key_auto",
            "in_flight_deadline_ms": "123",
            "last_error": "old error",
            "status_updated_ms": "456"
        });
        let mut refreshed = serde_json::json!({
            "stage": "complete",
            "tradeable": true
        });

        preserve_onboard_metadata(&previous, &mut refreshed);

        assert_eq!(refreshed["deploy_tx_id"], "tx-d");
        assert_eq!(refreshed["approve_tx_id"], "tx-a");
        assert_eq!(refreshed["relayer_auth"], "builder_key_auto");
        assert_eq!(refreshed["status_updated_ms"], "456");
        assert!(refreshed.get("in_flight_deadline_ms").is_none());
        assert!(refreshed.get("last_error").is_none());
    }

    #[test]
    fn unmatched_resting_receipts_still_count_as_exposure() {
        assert!(clob_status_excluded_from_daily_cap(
            "unmatched",
            Some(OrderType::FAK)
        ));
        assert!(!clob_status_excluded_from_daily_cap(
            "unmatched",
            Some(OrderType::GTC)
        ));
        assert!(!clob_status_excluded_from_daily_cap("unmatched", None));
        assert!(clob_status_excluded_from_daily_cap(
            "rejected",
            Some(OrderType::GTC)
        ));
    }

    #[test]
    fn open_order_reconciliation_requires_salt_and_stable_fields() {
        let draft = draft();
        let funder: Address = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
            .parse()
            .unwrap();
        let matched = serde_json::json!({
            "id": "order-1",
            "status": "live",
            "salt": 42,
            "maker": funder.to_checksum(None),
            "asset_id": "111",
            "side": "BUY",
            "orderType": "FAK",
            "makerAmount": "1000000",
            "takerAmount": "11111100"
        });
        assert!(open_order_matches_draft(&matched, &draft, funder, 42));

        let wrong_token = serde_json::json!({
            "id": "order-1",
            "status": "live",
            "salt": 42,
            "maker": funder.to_checksum(None),
            "asset_id": "222",
            "side": "BUY"
        });
        assert!(!open_order_matches_draft(&wrong_token, &draft, funder, 42));

        let weak = serde_json::json!({
            "id": "order-1",
            "status": "live",
            "salt": 42,
            "asset_id": "111"
        });
        assert!(!open_order_matches_draft(&weak, &draft, funder, 42));

        let cancelled = serde_json::json!({
            "id": "order-1",
            "status": "cancelled",
            "salt": 42,
            "maker": funder.to_checksum(None),
            "asset_id": "111",
            "side": "BUY"
        });
        assert!(!open_order_matches_draft(&cancelled, &draft, funder, 42));

        let contradictory_nested = serde_json::json!({
            "id": "order-1",
            "status": "live",
            "salt": 42,
            "maker": funder.to_checksum(None),
            "asset_id": "111",
            "side": "BUY",
            "order": {
                "tokenId": "222",
                "side": "SELL"
            }
        });
        assert!(!open_order_matches_draft(
            &contradictory_nested,
            &draft,
            funder,
            42
        ));

        let malformed_nested = serde_json::json!({
            "id": "order-1",
            "status": "live",
            "salt": 42,
            "maker": funder.to_checksum(None),
            "asset_id": "111",
            "side": "BUY",
            "order": {
                "salt": "wrong"
            }
        });
        assert!(!open_order_matches_draft(
            &malformed_nested,
            &draft,
            funder,
            42
        ));

        let empty_id = serde_json::json!({
            "id": "   ",
            "status": "live",
            "salt": 42,
            "maker": funder.to_checksum(None),
            "asset_id": "111",
            "side": "BUY"
        });
        assert!(!open_order_matches_draft(&empty_id, &draft, funder, 42));

        let nested = serde_json::json!({
            "id": "order-1",
            "status": "live",
            "order": {
                "salt": "42",
                "maker": funder.to_checksum(None),
                "tokenId": "111"
            }
        });
        assert_eq!(
            find_matching_open_order(&serde_json::json!({"data": [nested]}), &draft, funder, 42)
                .and_then(|order| clob_response_order_id(&order)),
            Some("order-1".into())
        );
    }

    #[test]
    fn url_query_encoding_is_canonical() {
        let url = url_with_query(
            "https://gamma-api.polymarket.com/public-search",
            &[("q", "hello world")],
        );
        assert_eq!(
            url,
            "https://gamma-api.polymarket.com/public-search?q=hello+world"
        );
    }

    #[test]
    fn trade_quote_uses_live_best_ask_and_market_buy_rounding() {
        let snap = snapshot(Some(695_000), Some(690_000));
        let limit = choose_trade_limit(Side::Buy, true, 700_000, 700_000, &snap).unwrap();
        assert_eq!(limit, 690_000);

        let quote =
            build_trade_quote(Side::Buy, 10_000_000, limit, &snap, OrderType::FAK).expect("quote");
        assert_eq!(quote.side, Side::Buy);
        assert_eq!(quote.price_micro, 690_000);
        assert_eq!(quote.maker_micro, 10_000_000);
        assert!(quote.size_micro >= snap.min_size_micro);
    }

    #[test]
    fn trade_limit_rejects_sell_when_tick_rounding_breaks_min_price() {
        let snap = snapshot(Some(700_000), Some(695_000));
        let err = choose_trade_limit(Side::Sell, true, 691_000, 691_000, &snap)
            .expect_err("tick rounding should fall below min price");
        assert!(matches!(err, DispatchResponse::Error { code: -3, .. }));
    }

    #[test]
    fn local_policy_defaults_to_disabled() {
        let policy: LocalWalletPolicy = toml::from_str("").unwrap();
        let checks = evaluate_local_polymarket_order(&policy.polymarket, &policy_ctx());
        assert!(local_policy_has_deny(&checks));
        assert!(checks.iter().any(|check| {
            check.rule == "polymarket.enabled" && check.outcome == LocalPolicyOutcome::Deny
        }));
    }

    #[test]
    fn local_policy_parses_decimal_caps() {
        let policy: LocalWalletPolicy = toml::from_str(
            r#"
[polymarket]
enabled = true
max_order_usd = "10"
max_daily_usd = "25.5"
require_flag_above_usd = 5
max_price = "0.75"
allow_neg_risk = false
denied_slugs = ["blocked-market"]
"#,
        )
        .unwrap();
        assert!(policy.polymarket.enabled);
        assert_eq!(policy.polymarket.max_order_usd, Some(10_000_000));
        assert_eq!(policy.polymarket.max_daily_usd, Some(25_500_000));
        assert_eq!(policy.polymarket.require_flag_above_usd, Some(5_000_000));
        assert_eq!(policy.polymarket.max_price, Some(750_000));
        assert!(!policy.polymarket.allow_neg_risk);
        assert!(policy.polymarket.denied_slugs.contains("blocked-market"));

        let float_policy: LocalWalletPolicy =
            toml::from_str("[polymarket]\nenabled = true\nmax_price = 0.1\n").unwrap();
        assert_eq!(float_policy.polymarket.max_price, Some(100_000));
    }

    #[test]
    fn local_policy_daily_cap_fails_closed_when_receipts_unknown() {
        let policy: LocalWalletPolicy = toml::from_str(
            r#"
[polymarket]
enabled = true
max_daily_usd = "100"
"#,
        )
        .unwrap();
        let mut ctx = policy_ctx();
        ctx.receipt_store_readable = false;
        let checks = evaluate_local_polymarket_order(&policy.polymarket, &ctx);
        assert!(checks.iter().any(|check| {
            check.rule == "polymarket.max_daily_usd" && check.outcome == LocalPolicyOutcome::Deny
        }));

        ctx.receipt_store_readable = true;
        ctx.daily_posted_microusd = None;
        let checks = evaluate_local_polymarket_order(&policy.polymarket, &ctx);
        assert!(checks.iter().any(|check| {
            check.rule == "polymarket.max_daily_usd" && check.outcome == LocalPolicyOutcome::Deny
        }));
    }
}
