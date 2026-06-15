//! Shared trade primitives: the live market snapshot + quote building used by
//! both the CLI (`bloom polymarket order/confirm/sell`) and the VFS trade
//! surface. These two callers previously carried byte-identical copies that
//! differed only in error type; this is the single source of truth. It returns
//! [`PolymarketError`]; each caller maps it (anyhow `?` / VFS `err_be`).

use crate::clob::ClobClient;
use crate::gamma::GammaClient;
use crate::order::{self, LimitQuote, OrderType};
use crate::order_store::{DraftStatus, OrderDraft};
use crate::types::{BookLevel, Market, Side};
use crate::{PolymarketError, Result};

/// Live market view used at both draft and confirm time.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub market: Market,
    pub token_id: String,
    pub neg_risk: bool,
    pub tick_micro: u64,
    pub min_size_micro: u64,
    pub best_ask_micro: Option<u64>,
    pub best_bid_micro: Option<u64>,
}

/// Fetch and cross-check the live market for `slug`/`outcome`. Refuses anything
/// that must not be signed against: a non-V2 CLOB, a non-binary market, an
/// unknown outcome, or a CLOB↔Gamma disagreement on neg-risk / condition id.
pub async fn snapshot(
    gamma: &GammaClient,
    clob: &ClobClient,
    slug: &str,
    outcome: &str,
) -> Result<Snapshot> {
    let version = clob.server_version().await?;
    if version != 2 {
        return Err(PolymarketError::invalid(format!(
            "CLOB reports order version {version}; bloom only posts V2 orders"
        )));
    }

    let market = gamma.market_by_slug(slug).await?;
    // Hard market invariant: bloom only trades true binary YES/NO markets.
    // `yes_token_id`/`no_token_id` index by position, so a multi-outcome market
    // would otherwise be silently traded as binary (and redeem's indexSets=[1,2]
    // is only valid for binary). Refuse before resolving a token.
    if !market.is_binary() {
        return Err(PolymarketError::invalid(format!(
            "market '{slug}' is not a binary YES/NO market (outcomes={:?}); \
             bloom only trades binary markets",
            market.outcomes
        )));
    }
    let token_id = match outcome.to_ascii_uppercase().as_str() {
        "YES" => market.yes_token_id(),
        "NO" => market.no_token_id(),
        other => {
            return Err(PolymarketError::invalid(format!(
                "outcome must be YES or NO, got {other}"
            )));
        }
    }
    .ok_or_else(|| {
        PolymarketError::invalid(format!(
            "market '{slug}' has no token for outcome {outcome}"
        ))
    })?
    .to_string();

    // Data-integrity cross-checks (hard failures, not policy): the CLOB is
    // authoritative for neg-risk and token→condition mapping and must agree
    // with Gamma before anything is signed.
    let neg_risk = clob.neg_risk(&token_id).await?;
    if neg_risk != market.neg_risk {
        return Err(PolymarketError::invalid(format!(
            "neg_risk mismatch for '{slug}': CLOB={neg_risk} Gamma={} — refusing",
            market.neg_risk
        )));
    }
    let tm = clob.markets_by_token(&token_id).await?;
    if tm.condition_id != market.condition_id {
        return Err(PolymarketError::invalid(format!(
            "condition id mismatch: CLOB {} vs Gamma {} — refusing",
            tm.condition_id, market.condition_id
        )));
    }

    let tick_micro = clob.tick_size_micro(&token_id).await?;
    let book = clob.book(&token_id).await?;
    let min_size_micro = if book.min_order_size.is_empty() {
        0
    } else {
        order::parse_micro(&book.min_order_size)?
    };
    // Don't trust level ordering (the live CLOB returns asks descending and bids
    // ascending, i.e. best-last): compute the best price directly.
    let parse_levels = |levels: &[BookLevel]| -> Result<Vec<u64>> {
        levels
            .iter()
            .map(|l| order::parse_micro(&l.price))
            .collect()
    };
    let best_ask_micro = parse_levels(&book.asks)?.into_iter().min();
    let best_bid_micro = parse_levels(&book.bids)?.into_iter().max();

    Ok(Snapshot {
        market,
        token_id,
        neg_risk,
        tick_micro,
        min_size_micro,
        best_ask_micro,
        best_bid_micro,
    })
}

/// Resolve the limit price for this attempt. Marketable orders re-derive the
/// limit from the live book under the user's bound; explicit limit orders pin it.
pub fn choose_limit(
    side: Side,
    marketable: bool,
    bound_micro: u64,
    pinned_limit_micro: u64,
    snap: &Snapshot,
) -> Result<u64> {
    if !marketable {
        return Ok(order::quantize_price(
            pinned_limit_micro,
            snap.tick_micro,
            side,
        ));
    }
    match side {
        Side::Buy => {
            let ask = snap
                .best_ask_micro
                .ok_or_else(|| PolymarketError::invalid("order book has no asks (no liquidity)"))?;
            if ask > bound_micro {
                return Err(PolymarketError::invalid(format!(
                    "best ask {} exceeds max price {} — refusing",
                    order::format_micro(ask),
                    order::format_micro(bound_micro)
                )));
            }
            Ok(order::quantize_marketable_limit(
                ask,
                snap.tick_micro,
                Side::Buy,
            ))
        }
        Side::Sell => {
            let bid = snap
                .best_bid_micro
                .ok_or_else(|| PolymarketError::invalid("order book has no bids (no liquidity)"))?;
            if bid < bound_micro {
                return Err(PolymarketError::invalid(format!(
                    "best bid {} is below min price {} — refusing",
                    order::format_micro(bid),
                    order::format_micro(bound_micro)
                )));
            }
            let limit = order::quantize_marketable_limit(bid, snap.tick_micro, Side::Sell);
            if limit < bound_micro {
                return Err(PolymarketError::invalid(format!(
                    "best bid {} is above min price {}, but tick quantization gives {} below \
                     your minimum — lower the min price or pin an explicit limit price",
                    order::format_micro(bid),
                    order::format_micro(bound_micro),
                    order::format_micro(limit)
                )));
            }
            Ok(limit)
        }
    }
}

/// Build the integer quote. `amount_micro` is the USD spend for buys and the
/// share size for sells. Market-class buys (FAK/FOK) use the CLOB's market-order
/// precision rules (maker ≤ 2 dp, taker ≤ 4 dp), which differ from limit orders.
pub fn build_quote(
    side: Side,
    amount_micro: u64,
    limit_micro: u64,
    snap: &Snapshot,
    order_type: OrderType,
) -> Result<LimitQuote> {
    let market_class = matches!(order_type, OrderType::FAK | OrderType::FOK);
    let quote = match (side, market_class) {
        (Side::Buy, true) => {
            LimitQuote::market_buy_from_spend(amount_micro, limit_micro, snap.tick_micro)
        }
        (Side::Buy, false) => {
            LimitQuote::buy_from_spend(amount_micro, limit_micro, snap.tick_micro)
        }
        (Side::Sell, _) => LimitQuote::sell_from_shares(amount_micro, limit_micro, snap.tick_micro),
    }?;
    if quote.size_micro < snap.min_size_micro {
        return Err(PolymarketError::invalid(format!(
            "order size {} shares is below the market minimum {} — increase the amount",
            order::format_micro(quote.size_micro),
            order::format_micro(snap.min_size_micro)
        )));
    }
    Ok(quote)
}

/// USD leg of a quote (what the per-order / daily policy caps look at).
pub fn usd_leg(q: &LimitQuote) -> u64 {
    match q.side {
        Side::Buy => q.maker_micro,
        Side::Sell => q.taker_micro,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn draft_from_quote(
    wallet: &str,
    owner: String,
    funder: Option<String>,
    signature_type: u8,
    slug: &str,
    outcome: &str,
    side: Side,
    order_type: OrderType,
    price_bound_micro: u64,
    marketable: bool,
    book_snapshot_ms: u128,
    snap: &Snapshot,
    quote: &LimitQuote,
) -> OrderDraft {
    OrderDraft {
        id: String::new(),
        wallet: wallet.to_string(),
        owner,
        funder,
        signature_type,
        slug: slug.to_string(),
        question: snap.market.question.clone(),
        condition_id: snap.market.condition_id.clone(),
        outcome: outcome.to_ascii_uppercase(),
        token_id: snap.token_id.clone(),
        side,
        order_type,
        amount_microusd: usd_leg(quote),
        price_bound_micro,
        marketable,
        limit_price_micro: quote.price_micro,
        size_micro: quote.size_micro,
        tick_micro: snap.tick_micro,
        min_order_size_micro: snap.min_size_micro,
        neg_risk: snap.neg_risk,
        active: snap.market.active,
        closed: snap.market.closed,
        order_book_enabled: snap.market.enable_order_book,
        binary_outcomes: snap.market.is_binary(),
        best_ask_micro: snap.best_ask_micro,
        best_bid_micro: snap.best_bid_micro,
        book_snapshot_ms,
        policy_checks: serde_json::Value::Null,
        status: DraftStatus::Draft,
        salt: None,
        clob_order_id: None,
        clob_status: None,
        last_error: None,
        review_intent_hash: None,
        created_ms: 0,
        updated_ms: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(best_ask: Option<u64>, best_bid: Option<u64>) -> Snapshot {
        Snapshot {
            market: serde_json::from_value(serde_json::json!({})).unwrap(),
            token_id: "1".into(),
            neg_risk: false,
            tick_micro: 10_000,
            min_size_micro: 5_000_000,
            best_ask_micro: best_ask,
            best_bid_micro: best_bid,
        }
    }

    #[test]
    fn choose_limit_marketable_buy_respects_bound_and_quantizes() {
        let s = snap(Some(695_000), Some(690_000));
        assert!(choose_limit(Side::Buy, true, 690_000, 0, &s).is_err());
        assert_eq!(
            choose_limit(Side::Buy, true, 700_000, 0, &s).unwrap(),
            690_000
        );
    }

    #[test]
    fn choose_limit_marketable_sell_refuses_below_min() {
        let s = snap(Some(695_000), Some(690_000));
        assert!(choose_limit(Side::Sell, true, 700_000, 0, &s).is_err());
        assert_eq!(
            choose_limit(Side::Sell, true, 680_000, 0, &s).unwrap(),
            690_000
        );
    }

    #[test]
    fn choose_limit_pinned_quantizes_without_book() {
        let s = snap(None, None);
        assert_eq!(
            choose_limit(Side::Buy, false, 0, 695_500, &s).unwrap(),
            690_000
        );
    }

    #[test]
    fn build_quote_enforces_min_size() {
        let s = snap(Some(500_000), Some(490_000));
        assert!(build_quote(Side::Buy, 2_000_000, 500_000, &s, OrderType::FAK).is_err());
        let q = build_quote(Side::Buy, 5_000_000, 500_000, &s, OrderType::FAK).unwrap();
        assert!(q.size_micro >= s.min_size_micro);
        assert_eq!(usd_leg(&q), q.maker_micro);
    }
}
