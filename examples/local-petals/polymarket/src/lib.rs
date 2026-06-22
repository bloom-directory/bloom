//! Local Polymarket handler petal.
//!
//! This petal owns `apps/polymarket/` directly. Public market/account reads go
//! through `bloom.v1::http_fetch`; staged local state goes through the
//! per-petal private `store_*` imports. It intentionally does not call the
//! native `polymarket/` VFS handler.

use bloom_petal_sdk::{
    DispatchEntry, DispatchEntryKind, DispatchOp, DispatchRequest, DispatchResponse, HostStatus,
    HttpRequest, SdkError,
};
use bloom_polymarket::order::{OrderType, parse_micro};
use bloom_polymarket::types::{Market, Side};
use bloom_polymarket::{OrderBook, Position, Trade, validate_wallet_name};
use serde::{Deserialize, Serialize};
use url::Url;

const MAX_HTTP_BYTES: usize = 8 * 1024 * 1024;
const MAX_STORE_BYTES: usize = 1024 * 1024;
const MAX_LIST_BYTES: usize = 256 * 1024;
const MARKETS_LIST_LIMIT: u32 = 20;

const GAMMA: &str = "https://gamma-api.polymarket.com";
const DATA: &str = "https://data-api.polymarket.com";
const CLOB: &str = "https://clob.polymarket.com";

const ROOT_DIRS: [&str; 7] = [
    "markets",
    "search",
    "positions",
    "onboard",
    "account",
    "trade",
    "fund",
];
const MARKET_FILES: [&str; 3] = ["market.json", "book.json", "prices.json"];
const POSITION_FILES: [&str; 3] = ["positions.json", "trades.json", "activity.json"];
const ONBOARD_FILES: [&str; 3] = ["status.json", "plan.md", "approvals.json"];
const ACCOUNT_FILES: [&str; 2] = ["portfolio.json", "orders.json"];
const FUND_FILES: [&str; 3] = ["plan.md", "request.json", "status.json"];
const DRAFT_FILES: [&str; 5] = [
    "plan.md",
    "order.json",
    "policy_check.json",
    "quote.json",
    "review_intent.json",
];

const BEGIN_HINT: &str =
    "write anything here to record an onboarding attempt; signing is still pending\n";
const TRADE_NEW_HINT: &str = r#"write JSON to create a reviewable draft, e.g.
{"slug":"will-canada-win-the-2026-fifa-world-cup-755","outcome":"yes","amount":"1","max_price":"0.01"}
"#;
const FUND_NEW_HINT: &str = r#"write JSON to create a reviewable pUSD funding request, e.g.
{"target_pusd":"10","max_spend":"100","from_token":"native","slippage_bps":50}
"#;

#[cfg_attr(target_family = "wasm", unsafe(link_section = "bloom_petal_manifest"))]
#[used]
pub static BLOOM_LOCAL_MANIFEST: [u8; include_bytes!("../Petal.toml").len()] =
    *include_bytes!("../Petal.toml");

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
        (Some("positions"), 1) => Vec::new(),
        (Some("positions"), 2) => strings(&POSITION_FILES),
        (Some("onboard"), 1) => store_wallets("onboard/"),
        (Some("onboard"), 2) => {
            let mut out = vec!["begin".to_string()];
            out.extend(strings(&ONBOARD_FILES));
            out
        }
        (Some("account"), 1) => store_wallets("creds/"),
        (Some("account"), 2) => strings(&ACCOUNT_FILES),
        (Some("fund"), 1) => store_wallets("fund/"),
        (Some("fund"), 2) => {
            let mut out = vec!["new".to_string()];
            out.extend(store_ids(&format!("fund/{}/requests/", segs[1]), ".json"));
            out
        }
        (Some("fund"), 3) if segs[2] != "new" => strings(&FUND_FILES),
        (Some("trade"), 1) => store_wallets("trade/"),
        (Some("trade"), 2) => vec!["new".into(), "drafts".into(), "receipts".into()],
        (Some("trade"), 3) if segs[2] == "drafts" => {
            store_ids(&format!("trade/{}/drafts/", segs[1]), "/order.json")
        }
        (Some("trade"), 3) if segs[2] == "receipts" => {
            store_ids(&format!("trade/{}/receipts/", segs[1]), "/receipt.json")
        }
        (Some("trade"), 4) if segs[2] == "drafts" => strings(&DRAFT_FILES),
        (Some("trade"), 4) if segs[2] == "receipts" => vec!["receipt.json".into()],
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
        (Some("fund"), 3) if segs[2] == "new" => write_fund_new(segs[1], body),
        _ => error(-2, "path is not writable"),
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

fn read_positions(address: &str, file: &str) -> DispatchResponse {
    match file {
        "positions.json" => match get_json::<Vec<Position>>(&url_with_query(
            &format!("{DATA}/positions"),
            &[("user", address)],
        )) {
            Ok(value) => read_json_value(&value),
            Err(resp) => resp,
        },
        "trades.json" => match get_json::<Vec<Trade>>(&url_with_query(
            &format!("{DATA}/trades"),
            &[("user", address)],
        )) {
            Ok(value) => read_json_value(&value),
            Err(resp) => resp,
        },
        "activity.json" => match get_json::<serde_json::Value>(&url_with_query(
            &format!("{DATA}/activity"),
            &[("user", address)],
        )) {
            Ok(value) => read_json_value(&value),
            Err(resp) => resp,
        },
        _ => error(-3, "not a positions file"),
    }
}

fn read_onboard(wallet: &str, file: &str) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    match file {
        "begin" => DispatchResponse::Read(BEGIN_HINT.into()),
        "status.json" => read_store_json_or_default(
            &format!("onboard/{wallet}/status.json"),
            serde_json::json!({
                "wallet": wallet,
                "stage": "not_started",
                "running": false,
                "tradeable": false,
                "message": "write begin to start local-petal onboarding; signing flow pending"
            }),
        ),
        "plan.md" => DispatchResponse::Read(render_onboard_plan(wallet).into_bytes()),
        "approvals.json" => read_json_value(&serde_json::json!({
            "wallet": wallet,
            "approvals": [],
            "signing": "pending"
        })),
        _ => error(-3, "not an onboard file"),
    }
}

fn read_account(wallet: &str, file: &str) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    match file {
        "portfolio.json" => read_store_json_or_default(
            &format!("account/{wallet}/portfolio.json"),
            serde_json::json!({
                "wallet": wallet,
                "credentials_present": store_get(&format!("creds/{wallet}/clob.json")).is_some(),
                "message": "authenticated CLOB account view pending sign/store credential flow"
            }),
        ),
        "orders.json" => read_store_json_or_default(
            &format!("account/{wallet}/orders.json"),
            serde_json::json!({
                "wallet": wallet,
                "orders": [],
                "message": "authenticated CLOB order read pending sign/store credential flow"
            }),
        ),
        _ => error(-3, "not an account file"),
    }
}

fn write_onboard_begin(wallet: &str) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
    let status = serde_json::json!({
        "wallet": wallet,
        "stage": "started",
        "running": false,
        "tradeable": false,
        "message": "local-petal onboarding state created; sign_hash integration pending"
    });
    store_put_json(&format!("onboard/{wallet}/status.json"), &status, false)
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
    let id = next_id(&format!("trade/{wallet}/drafts/"), "/order.json");
    let draft = StoreTradeDraft {
        id: id.clone(),
        wallet: wallet.into(),
        slug: req.slug,
        outcome: req.outcome,
        side,
        order_type,
        amount_micro,
        price_bound_micro: bound_micro,
        limit_price: req.limit_price,
        status: "review".into(),
    };
    let base = format!("trade/{wallet}/drafts/{id}");
    if let DispatchResponse::Error { .. } =
        store_put_json(&format!("{base}/order.json"), &draft, false)
    {
        return error(-4, "failed to store draft");
    }
    if let DispatchResponse::Error { .. } = store_put_json(
        &format!("{base}/policy_check.json"),
        &serde_json::json!({
            "status": "pending",
            "message": "policy evaluation remains in the native daemon until full signing port"
        }),
        false,
    ) {
        return error(-4, "failed to store policy check");
    }
    if let DispatchResponse::Error { .. } = store_put_json(
        &format!("{base}/quote.json"),
        &serde_json::json!({
            "side": draft.side,
            "order_type": draft.order_type.as_str(),
            "amount_micro": draft.amount_micro,
            "price_bound_micro": draft.price_bound_micro,
            "status": "staged"
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
            "status": "created"
        }),
        false,
    ) {
        return error(-4, "failed to store review intent");
    }
    DispatchResponse::Write
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
        ("drafts", "order.json" | "policy_check.json" | "quote.json" | "review_intent.json") => {
            read_store(&format!("trade/{wallet}/drafts/{id}/{file}"))
        }
        ("receipts", "receipt.json") => {
            read_store(&format!("trade/{wallet}/receipts/{id}/receipt.json"))
        }
        _ => error(-3, "not a trade file"),
    }
}

fn write_fund_new(wallet: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = validate_wallet_name(wallet) {
        return error(-3, e.to_string());
    }
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

fn read_store_json_or_default(key: &str, default: serde_json::Value) -> DispatchResponse {
    match store_get(key) {
        Some(bytes) => DispatchResponse::Read(bytes),
        None => read_json_value(&default),
    }
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
        "# Polymarket onboarding\n\nWallet: {wallet}\n\nStatus: local-petal state is staged. The sign_hash-backed onboarding run is pending.\n"
    )
}

fn render_trade_plan(draft: &StoreTradeDraft) -> String {
    format!(
        "# Polymarket order draft {}\n\nWallet: {}\nMarket: {}\nOutcome: {}\nSide: {:?}\nAmount micro: {}\nPrice bound micro: {}\nStatus: {}\n\nSigning and posting are pending the full sign_hash port.\n",
        draft.id,
        draft.wallet,
        draft.slug,
        draft.outcome,
        draft.side,
        draft.amount_micro,
        draft.price_bound_micro,
        draft.status
    )
}

fn render_fund_plan(session: &StoreFundSession) -> String {
    format!(
        "# Polymarket funding request {}\n\nWallet: {}\nTarget pUSD: {}\nMax spend: {}\nFrom token: {}\nSlippage bps: {}\nStatus: {}\n",
        session.id,
        session.wallet,
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
        (Some("trade"), 5) if segs[2] == "receipts" && segs[4] == "receipt.json" => {
            Some(DispatchEntryKind::File)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreTradeDraft {
    id: String,
    wallet: String,
    slug: String,
    outcome: String,
    side: Side,
    order_type: OrderType,
    amount_micro: u64,
    price_bound_micro: u64,
    limit_price: Option<String>,
    status: String,
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
    status: String,
}

fn default_slippage_bps() -> u16 {
    50
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            path_kind("onboard/alice/begin"),
            Some(DispatchEntryKind::WritableFile)
        );
        assert_eq!(
            path_kind("trade/alice/drafts/0001/plan.md"),
            Some(DispatchEntryKind::File)
        );
        assert_eq!(
            path_kind("trade/alice/receipts/0001/receipt.json"),
            Some(DispatchEntryKind::File)
        );
        assert_eq!(path_kind("trade/alice/new/extra"), None);
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
}
