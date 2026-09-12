//! `views/...` — read-only HTML pages meant for a person, not an agent.
//!
//! Paths handled:
//! - `views/`                 — list the available pages
//! - `views/index.html`       — Today: what you hold, and what needs you
//! - `views/wallets.html`     — native balances per wallet, with valuation
//! - `views/receive.html`     — receiving addresses grouped by wallet
//! - `views/next-moves.html`  — staged operations awaiting your review
//! - `views/activity.html`    — what completed, failed, or is still staged
//! - `views/access.html`      — what each wallet is allowed to do
//! - `views/bloom.css`        — the shared Bloom stylesheet (compiled in)
//! - `views/AGENTS.md`        — how an agent should use these pages
//!
//! These pages observe. Nothing here stages, approves, or executes an action,
//! and they carry no script: the mount serves them as ordinary files, so a
//! browser opens one straight off the filesystem. Matching Bloom's visual
//! language does not make a page a trusted authorization surface — passkeys
//! and private input stay in Broker's own page.
//!
//! A page always renders. An unavailable source becomes visible prose or an
//! "Unavailable" cell, never a fabricated zero and never an `EIO` that makes
//! `cat` of the whole page fail. A missing price leaves a row unpriced rather
//! than valuing it at zero, and a quote older than an hour does not price
//! anything at all.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bloom_evm::ChainRegistry;
use bloom_machine_client::{ProjectionFreshness, WalletProjection, WalletProjectionReader};
use bloom_prices::{CoinId, PricesClient};

use super::outbox::OutboxHandler;
use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const BLOOM_CSS: &str = include_str!("../assets/bloom.css");
const VIEWS_AGENTS_MD: &str = include_str!("../docs/views-agents.md");

const INDEX_HTML: &str = "index.html";
const WALLETS_HTML: &str = "wallets.html";
const RECEIVE_HTML: &str = "receive.html";
const NEXT_MOVES_HTML: &str = "next-moves.html";
const ACTIVITY_HTML: &str = "activity.html";
const ACCESS_HTML: &str = "access.html";
const BLOOM_CSS_NAME: &str = "bloom.css";
const AGENTS_MD_NAME: &str = "AGENTS.md";

/// Every page, in reading order. Drives both the directory listing and the
/// navigation, so a link can never point at a page that is not served.
const PAGES: &[(&str, &str)] = &[
    (INDEX_HTML, "Today"),
    (WALLETS_HTML, "Wallets"),
    (RECEIVE_HTML, "Receive"),
    (NEXT_MOVES_HTML, "Next moves"),
    (ACTIVITY_HTML, "Activity"),
    (ACCESS_HTML, "Access"),
];

/// The mount re-reads on every browser access (`actimeo=0`), so a short
/// router TTL keeps a reload burst from re-reading balances per request.
/// The compiled-in assets need no cache entry at all.
const PAGE_TTL: Duration = Duration::from_secs(5);

/// One unreachable chain must not hold up a page. Each balance read gets its
/// own budget and an expired one renders as "Unavailable".
const BALANCE_TIMEOUT: Duration = Duration::from_secs(2);

/// Valuation is optional; the page is still useful unpriced.
const PRICE_TIMEOUT: Duration = Duration::from_secs(3);

/// A valuation bound, not a claim that every provider updates hourly. Past
/// this, a quote does not price anything.
const QUOTE_MAX_AGE_SECS: u64 = 3600;

/// Content-Security-Policy for every page. `style-src 'self'` is what lets a
/// page link the sibling `bloom.css` instead of carrying a copy that drifts;
/// `img-src 'self'` lets it show a QR code the VFS already renders. There is
/// deliberately no `script-src`: these pages must work with no script at all.
const CSP: &str = "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; \
                   base-uri 'none'; form-action 'none'";

/// Central outbox lifecycle directories, newest concern first.
const ACTION_STATES: [&str; 3] = ["pending", "sent", "failed"];

#[derive(Clone)]
pub struct ViewsHandler {
    projections: Arc<dyn WalletProjectionReader>,
    chains: ChainRegistry,
    prices: Arc<PricesClient>,
    outbox: Arc<OutboxHandler>,
}

impl ViewsHandler {
    pub fn new(
        projections: Arc<dyn WalletProjectionReader>,
        chains: ChainRegistry,
        prices: PricesClient,
        outbox: Arc<OutboxHandler>,
    ) -> Self {
        Self {
            projections,
            chains,
            prices: Arc::new(prices),
            outbox,
        }
    }
}

#[async_trait]
impl Handler for ViewsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "views.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "views.read_err");
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "views.list_err");
        }
        r
    }

    fn cache_ttl(&self, path: &VfsPath) -> Option<Duration> {
        match path.segments() {
            [s] if is_page(s) => Some(PAGE_TTL),
            _ => None,
        }
    }
}

impl ViewsHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        match path.segments() {
            [] => Ok(Entry::dir("")),
            [s] if is_page(s) => Ok(Entry::file(s)),
            [s] if s == BLOOM_CSS_NAME => Ok(css_entry()),
            [s] if s == AGENTS_MD_NAME => Ok(agents_entry()),
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let page = match path.segments() {
            [s] if s == BLOOM_CSS_NAME => return Ok(BLOOM_CSS.as_bytes().to_vec()),
            [s] if s == AGENTS_MD_NAME => return Ok(VIEWS_AGENTS_MD.as_bytes().to_vec()),
            [s] if is_page(s) => s.clone(),
            _ => return Err(HandlerError::NotAFile(path.to_string_path())),
        };
        let html = match page.as_str() {
            INDEX_HTML => self.render_index().await,
            WALLETS_HTML => self.render_wallets().await,
            RECEIVE_HTML => self.render_receive().await,
            NEXT_MOVES_HTML => self.render_next_moves().await,
            ACTIVITY_HTML => self.render_activity().await,
            ACCESS_HTML => self.render_access().await,
            _ => return Err(HandlerError::NotAFile(path.to_string_path())),
        };
        Ok(html.into_bytes())
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if path.is_root() {
            // `ls -l` does not render children, so give the static assets a
            // real size hint here; pages are sized by the mount at getattr.
            let mut entries = vec![agents_entry(), css_entry()];
            for (name, _) in PAGES {
                entries.push(Entry::file(name));
            }
            Ok(entries)
        } else {
            Err(HandlerError::NotADir(path.to_string_path()))
        }
    }

    /// Wallet projections, degrading the way `/next.md` does: live read first,
    /// then the cache, then an explicit "unavailable" flag. Enumerating
    /// wallets is navigation, not an authority decision, so it never errors.
    async fn wallet_projections(&self) -> (Vec<WalletProjection>, bool) {
        match self.projections.list_wallets().await {
            Ok(wallets) => (wallets, false),
            Err(error) => {
                tracing::debug!(error = %error, "views.projections_live_unavailable");
                match self.projections.cached_wallets() {
                    Ok(wallets) => (wallets, false),
                    Err(error) => {
                        tracing::debug!(error = %error, "views.projections_unavailable");
                        (Vec::new(), true)
                    }
                }
            }
        }
    }

    /// Human label for a configured chain: its own display name when the spec
    /// carries one, otherwise the path segment the VFS uses.
    fn network_label(&self, chain: &str) -> String {
        self.chains
            .get(chain)
            .and_then(|client| client.spec().display_name.clone())
            .unwrap_or_else(|| chain.to_owned())
    }

    fn sorted_chains(&self) -> Vec<String> {
        let mut chains = self.chains.list_names();
        chains.sort();
        chains
    }

    /// Read every wallet's native balance on every configured chain, then
    /// price what can be priced. Balance reads run concurrently per wallet so
    /// one slow endpoint costs one budget, not the sum of them.
    async fn portfolio(&self) -> Portfolio {
        let (projections, projections_unavailable) = self.wallet_projections().await;
        let chains = self.sorted_chains();
        let mut portfolio = Portfolio {
            projections_unavailable,
            ..Portfolio::default()
        };

        for projection in &projections {
            let wallet = projection.wallet_id().as_str().to_owned();
            portfolio.wallets.push(wallet.clone());
            if projection.freshness == ProjectionFreshness::Stale {
                portfolio.stale = true;
            }
            let address_text = match projection.primary_address() {
                Ok(address) => address.to_owned(),
                Err(error) => {
                    tracing::debug!(wallet = %wallet, error = %error, "views.address_unavailable");
                    continue;
                }
            };
            let address = match address_text.parse::<alloy::primitives::Address>() {
                Ok(address) => address,
                Err(error) => {
                    tracing::debug!(wallet = %wallet, error = %error, "views.address_unparsed");
                    continue;
                }
            };

            let mut reads = tokio::task::JoinSet::new();
            for chain in &chains {
                let Some(client) = self.chains.get(chain) else {
                    continue;
                };
                let name = chain.clone();
                reads.spawn(async move {
                    let symbol = client.spec().native_symbol.clone();
                    let decimals = client.spec().native_decimals;
                    let chain_id = client.spec().chain_id;
                    let raw = match tokio::time::timeout(BALANCE_TIMEOUT, client.balance(address))
                        .await
                    {
                        Ok(Ok(raw)) => Some(raw),
                        Ok(Err(error)) => {
                            tracing::debug!(chain = %name, error = %error, "views.balance_unavailable");
                            None
                        }
                        Err(_) => {
                            tracing::debug!(chain = %name, "views.balance_timeout");
                            None
                        }
                    };
                    (name, raw, symbol, decimals, chain_id)
                });
            }
            while let Some(joined) = reads.join_next().await {
                let Ok((chain, raw, symbol, decimals, chain_id)) = joined else {
                    continue;
                };
                match raw {
                    // A zero balance is a fact, not a holding. Listing every
                    // configured chain at zero would bury the real rows.
                    Some(raw) if raw.is_zero() => {}
                    Some(raw) => {
                        let quantity = bloom_proto::format_units(raw, decimals);
                        let amount = quantity.parse::<f64>().unwrap_or(0.0);
                        portfolio.holdings.push(Holding {
                            label: self.network_label(&chain),
                            wallet: wallet.clone(),
                            chain,
                            chain_id,
                            symbol,
                            quantity,
                            amount,
                            value: None,
                        });
                    }
                    None => portfolio.unavailable.push((wallet.clone(), chain)),
                }
            }
        }

        self.price(&mut portfolio).await;
        portfolio
            .holdings
            .sort_by(|a, b| match b.value.partial_cmp(&a.value) {
                Some(std::cmp::Ordering::Equal) | None => {
                    (&a.wallet, &a.label).cmp(&(&b.wallet, &b.label))
                }
                Some(order) => order,
            });
        portfolio
    }

    /// Value what can be valued. A native asset is priced only on a chain
    /// where that asset *is* the market asset: a development chain whose
    /// native symbol happens to read "ETH" must never be valued at ether's
    /// price. A stale quote prices nothing.
    async fn price(&self, portfolio: &mut Portfolio) {
        let mut symbols: Vec<String> = portfolio
            .holdings
            .iter()
            .filter(|holding| native_asset_has_market(holding.chain_id))
            .map(|holding| holding.symbol.to_ascii_lowercase())
            .collect();
        symbols.sort();
        symbols.dedup();

        let now = now_secs();
        let mut quotes: BTreeMap<String, f64> = BTreeMap::new();
        for symbol in symbols {
            let coin = CoinId::Symbol(symbol.clone());
            match tokio::time::timeout(PRICE_TIMEOUT, self.prices.current(coin)).await {
                Ok(Ok(quote)) if quote.price >= 0.0 && fresh_quote(quote.timestamp, now) => {
                    quotes.insert(symbol, quote.price);
                }
                Ok(Ok(_)) => {
                    tracing::debug!(symbol = %symbol, "views.quote_stale");
                    portfolio.price_coverage_gap = true;
                }
                Ok(Err(error)) => {
                    tracing::debug!(symbol = %symbol, error = %error, "views.price_unavailable");
                    portfolio.price_coverage_gap = true;
                }
                Err(_) => {
                    tracing::debug!(symbol = %symbol, "views.price_timeout");
                    portfolio.price_coverage_gap = true;
                }
            }
        }

        for holding in &mut portfolio.holdings {
            if !native_asset_has_market(holding.chain_id) {
                continue;
            }
            if let Some(price) = quotes.get(&holding.symbol.to_ascii_lowercase()) {
                holding.value = Some(holding.amount * price);
            }
        }
    }

    /// Central outbox actions across every lifecycle state, newest first.
    /// Reached through the outbox handler's own trait, so this page cannot
    /// drift from what `/outbox` reports.
    async fn actions(&self) -> Vec<Action> {
        let mut actions = Vec::new();
        for state in ACTION_STATES {
            let listing = match Handler::list(&*self.outbox, &state_path(state)).await {
                Ok(entries) => entries,
                Err(error) => {
                    tracing::debug!(state = %state, error = %error, "views.outbox_list_unavailable");
                    continue;
                }
            };
            for entry in listing {
                let id = entry.name.clone();
                let modified_ms = entry.modified.and_then(|time| {
                    time.duration_since(UNIX_EPOCH)
                        .ok()
                        .map(|since| since.as_millis() as u64)
                });
                let plan = self.action_file(state, &id, "plan.md").await;
                let status = self.action_file(state, &id, "status.json").await;
                let petal = status.as_deref().and_then(petal_id);
                actions.push(Action {
                    summary: plan.as_deref().map(plan_summary).unwrap_or_else(|| {
                        format!("Operation {}", id.split('-').next().unwrap_or(&id))
                    }),
                    chain: plan.as_deref().and_then(|text| plan_field(text, "Chain:")),
                    wallet: plan.as_deref().and_then(|text| plan_field(text, "Wallet:")),
                    denial: plan.as_deref().and_then(plan_denial),
                    id,
                    state,
                    modified_ms,
                    petal,
                });
            }
        }
        actions.sort_by(|a, b| {
            b.modified_ms
                .cmp(&a.modified_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        actions
    }

    async fn action_file(&self, state: &str, id: &str, file: &str) -> Option<String> {
        let path = VfsPath::parse(&format!("{state}/{id}/{file}")).ok()?;
        match Handler::read(&*self.outbox, &path).await {
            Ok(bytes) => String::from_utf8(bytes).ok(),
            Err(error) => {
                tracing::debug!(state = %state, id = %id, file = %file, error = %error, "views.outbox_read_unavailable");
                None
            }
        }
    }

    async fn render_index(&self) -> String {
        let portfolio = self.portfolio().await;
        let actions = self.actions().await;
        let pending = actions.iter().filter(|a| a.state == "pending").count();
        let failed = actions.iter().filter(|a| a.state == "failed").count();

        let priced: Vec<&Holding> = portfolio
            .holdings
            .iter()
            .filter(|h| h.value.is_some())
            .collect();
        let total: f64 = priced.iter().filter_map(|h| h.value).sum();
        let unpriced = portfolio.holdings.len() - priced.len();

        let mut body = String::new();
        body.push_str(&portfolio.notices());

        // An absence is not a headline. When nothing carries a price the
        // metric stays a dash and the reason goes in the supporting line,
        // rather than setting "No market valuation" in 80px serif.
        let (metric, support, caveat) = if portfolio.holdings.is_empty() {
            (
                "—".to_owned(),
                "No balance was read from the configured networks.".to_owned(),
                "Nothing is counted here yet.".to_owned(),
            )
        } else if priced.is_empty() {
            (
                "—".to_owned(),
                format!(
                    "{held}, none of it priced.",
                    held = count_noun(portfolio.holdings.len(), "holding", "holdings"),
                ),
                "Nothing here carries a dollar value. The quantities are what the chains \
                 reported; Wallets says why each row is unpriced."
                    .to_owned(),
            )
        } else {
            (
                money(Some(total)),
                format!(
                    "Across {wallets} · {priced}",
                    wallets = count_noun(portfolio.wallets.len(), "wallet", "wallets"),
                    priced = count_noun(priced.len(), "priced holding", "priced holdings"),
                ),
                format!(
                    "{unpriced} unpriced. Test funds and sources that did not answer are \
                     excluded from this total, so it is not your net worth.",
                    unpriced = count_noun(unpriced, "holding is", "holdings are"),
                ),
            )
        };
        let mut by_chain: BTreeMap<String, (String, f64)> = BTreeMap::new();
        for holding in &priced {
            let entry = by_chain
                .entry(holding.chain.clone())
                .or_insert_with(|| (holding.label.clone(), 0.0));
            entry.1 += holding.value.unwrap_or(0.0);
        }
        let mut split: Vec<(String, f64)> = by_chain.into_values().collect();
        split.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let allocation =
            if split.is_empty() {
                "<p class=\"lede\">Nothing is priced yet, so there is no split to show.</p>"
                    .to_owned()
            } else {
                let rows: String = split
                .iter()
                .map(|(label, value)| {
                    let share = if total > 0.0 { value / total * 100.0 } else { 0.0 };
                    format!(
                        "<li><div>{label}<strong>{value}</strong><small>{share:.1}%</small></div>\
                         <div class=\"allocation-bar\" aria-hidden=\"true\">\
                         <span style=\"width:{share:.2}%\"></span></div></li>",
                        label = asset_label(label),
                        value = money(Some(*value)),
                    )
                })
                .collect();
                format!("<ul class=\"allocation-list\">{rows}</ul>")
            };

        body.push_str(&format!(
            "<section class=\"wallet-dashboard\" aria-label=\"Wallet snapshot\">\
             <div class=\"balance-panel\"><p class=\"eyebrow\">Your observed priced assets</p>\
             <div class=\"metric\">{metric}</div>\
             <p>{support}</p>\
             <div class=\"capture-stamp\">Read when you opened this page<br>\
             Observation · not a live balance</div>\
             <a class=\"button\" href=\"wallets.html\">Explore your holdings →</a>\
             <small>{caveat}</small></div>\
             <div class=\"allocation-panel\"><p class=\"eyebrow\">Where your priced assets live</p>\
             <h2>Your network split</h2>{allocation}</div></section>",
            metric = html_escape(&metric),
            support = html_escape(&support),
            caveat = html_escape(&caveat),
        ));

        body.push_str(&format!(
            "<div class=\"stats\"><div class=\"stat\"><span class=\"label\">Networks read</span>\
             <div class=\"metric\">{chains}</div></div>\
             <div class=\"stat\"><span class=\"label\">Waiting for you</span>\
             <div class=\"metric\">{pending}</div></div>\
             <div class=\"stat\"><span class=\"label\">Unsuccessful records</span>\
             <div class=\"metric\">{failed}</div></div></div>",
            chains = self.sorted_chains().len(),
        ));

        body.push_str(&attention_strip(pending, true));
        body.push_str(
            "<section class=\"callout\"><strong>Doing nothing is a valid outcome.</strong>\
             <p>This page reports what Bloom observed. It never suggests a trade, and no \
             number here is a recommendation.</p></section>",
        );

        page(
            "Today",
            "Your wallets, at a glance.",
            "What you hold, where it lives, and what needs you. Read when you opened this \
             page; it does not refresh on its own.",
            INDEX_HTML,
            &body,
        )
    }

    async fn render_wallets(&self) -> String {
        let portfolio = self.portfolio().await;
        let total: f64 = portfolio.holdings.iter().filter_map(|h| h.value).sum();
        let priced = portfolio
            .holdings
            .iter()
            .filter(|h| h.value.is_some())
            .count();

        let mut body = String::new();
        body.push_str(&portfolio.notices());
        let (metric, support) = if portfolio.holdings.is_empty() {
            (
                "—".to_owned(),
                "No non-zero native balance was read from the networks that answered.".to_owned(),
            )
        } else if priced == 0 {
            (
                "—".to_owned(),
                format!(
                    "No price for {rows} below.",
                    rows = count_noun(portfolio.holdings.len(), "the row", "any of the rows"),
                ),
            )
        } else {
            (
                money(Some(total)),
                format!(
                    "{priced} of {} rows carry a price.",
                    portfolio.holdings.len()
                ),
            )
        };
        body.push_str(&format!(
            "<section class=\"hero\"><div><span class=\"label\">Observed priced assets</span>\
             <div class=\"metric\">{metric}</div>\
             <p>{support}</p></div>\
             <div class=\"hero-aside\"><h3>Coverage stays visible.</h3>\
             <p>Native balances only: token and Petal positions are not read here yet. A \
             missing quote leaves a row unpriced rather than valuing it at zero, and test \
             networks are never priced.</p></div></section>",
            metric = html_escape(&metric),
            support = html_escape(&support),
        ));

        for wallet in &portfolio.wallets {
            let rows: Vec<&Holding> = portfolio
                .holdings
                .iter()
                .filter(|holding| &holding.wallet == wallet)
                .collect();
            let wallet_total: f64 = rows.iter().filter_map(|h| h.value).sum();
            let subtitle = if rows.is_empty() {
                "No balance read".to_owned()
            } else if rows.iter().any(|h| h.value.is_some()) {
                money(Some(wallet_total))
            } else {
                "No priced balance".to_owned()
            };
            body.push_str(&format!(
                "<section id=\"wallet-{id}\"><div class=\"section-head\"><h2>{name}</h2>\
                 <p>{subtitle}</p></div>",
                id = html_escape(wallet),
                name = html_escape(wallet),
                subtitle = html_escape(&subtitle),
            ));
            if rows.is_empty() {
                body.push_str(
                    "<p class=\"lede\">No non-zero native balance in the networks that \
                     answered.</p>",
                );
            } else {
                let cells: String = rows
                    .iter()
                    .map(|holding| {
                        format!(
                            "<tr><td data-label=\"Asset\"><span class=\"asset-label\">\
                             {mark}<span><strong>{symbol}</strong><small>{quantity} {symbol}\
                             </small></span></span></td>\
                             <td data-label=\"Network\">{label}</td>\
                             <td class=\"numeric money\" data-label=\"Observed value\">{value}</td>\
                             <td data-label=\"Evidence\"><details><summary>Details</summary>\
                             <p>{note}</p><p><code>{source}</code></p></details></td></tr>",
                            mark = monogram(&holding.symbol),
                            symbol = html_escape(&holding.symbol),
                            quantity = html_escape(&holding.quantity),
                            label = html_escape(&holding.label),
                            value = html_escape(&money(holding.value)),
                            note = html_escape(&holding.note()),
                            source = html_escape(&format!(
                                "/wallets/{}/chains/{}/balance.json",
                                holding.wallet, holding.chain
                            )),
                        )
                    })
                    .collect();
                body.push_str(&format!(
                    "<div class=\"table-wrap\"><table><caption>Native balances read through \
                     Bloom</caption><thead><tr><th scope=\"col\">Asset / quantity</th>\
                     <th scope=\"col\">Network</th><th scope=\"col\">Observed value</th>\
                     <th scope=\"col\">Evidence</th></tr></thead><tbody>{cells}</tbody>\
                     </table></div>"
                ));
            }
            body.push_str("</section>");
        }

        page(
            "Wallets",
            "Your actual holdings.",
            "Native balances read from your own daemon, valued where a fresh quote exists. \
             Missing quotes stay unpriced.",
            WALLETS_HTML,
            &body,
        )
    }

    async fn render_receive(&self) -> String {
        let (wallets, unavailable) = self.wallet_projections().await;
        let (mainnets, testnets): (Vec<String>, Vec<String>) = self
            .sorted_chains()
            .into_iter()
            .partition(|name| !is_test_network(name));

        let mut body = String::new();
        if unavailable {
            body.push_str(
                "<section class=\"callout warn\"><strong>Receiving addresses unavailable</strong>\
                 <p>Broker is offline and no cached wallet projection is available, so no \
                 receiving address can be shown. Nothing about your wallets has changed.</p>\
                 </section>",
            );
        } else if wallets.is_empty() {
            body.push_str(
                "<section class=\"callout\"><strong>No wallets yet</strong>\
                 <p>Register a wallet first; a receiving address appears here once one \
                 exists.</p></section>",
            );
        }

        let mut stale = false;
        for wallet in &wallets {
            if wallet.freshness == ProjectionFreshness::Stale {
                stale = true;
            }
            body.push_str(&self.render_wallet_section(wallet, &mainnets, &testnets));
        }
        if stale {
            body.push_str(&stale_notice());
        }

        page(
            "Receive",
            "Receive.",
            "Scan a wallet's address, or copy it. Select the matching network in the sending \
             wallet: the code encodes an address, not a network.",
            RECEIVE_HTML,
            &body,
        )
    }

    fn render_wallet_section(
        &self,
        wallet: &WalletProjection,
        mainnets: &[String],
        testnets: &[String],
    ) -> String {
        let id = wallet.wallet_id().as_str();
        let (card, addresses) = match wallet.primary_address() {
            Ok(address) => (
                self.render_address_card(id, address, mainnets, testnets),
                1usize,
            ),
            Err(error) => {
                tracing::debug!(wallet = %id, error = %error, "views.address_unavailable");
                (
                    format!(
                        "<article class=\"card receiving-card\"><p class=\"eyebrow\">{} · \
                         receiving address</p><h3>Unavailable</h3><p>This wallet's projection \
                         carries no receiving address. Nothing can be received until it does.\
                         </p></article>",
                        html_escape(id)
                    ),
                    0usize,
                )
            }
        };
        // One EVM address per wallet today. The plural arm is what a wallet
        // with distinct Solana accounts will use, once `accounts.json` exists.
        let subtitle = match addresses {
            0 => "No receiving address".to_owned(),
            1 => "1 receiving address".to_owned(),
            n => format!("{n} receiving addresses"),
        };
        format!(
            "<section class=\"receiving-wallet\" aria-label=\"{id_attr} receiving addresses\">\
             <div class=\"section-head\"><h2>{id_text}</h2><p>{subtitle}</p></div>\
             <div class=\"grid\">{card}</div></section>",
            id_attr = html_escape(id),
            id_text = html_escape(id),
            subtitle = html_escape(&subtitle),
        )
    }

    fn render_address_card(
        &self,
        wallet: &str,
        address: &str,
        mainnets: &[String],
        testnets: &[String],
    ) -> String {
        let chips: String = mainnets
            .iter()
            .map(|name| format!("<li>{}</li>", asset_label(&self.network_label(name))))
            .collect();
        let networks = if chips.is_empty() {
            "<p class=\"receiving-network\">No networks are configured for this address yet.</p>"
                .to_owned()
        } else {
            format!(
                "<ul class=\"receiving-networks\">{chips}</ul>\
                 <p class=\"receiving-network\">One address across these networks. Funds stay \
                 on the network the sender chooses.</p>"
            )
        };
        let testing = if testnets.is_empty() {
            String::new()
        } else {
            let items: String = testnets
                .iter()
                .map(|name| format!("<li>{}</li>", html_escape(name)))
                .collect();
            format!(
                "<details><summary>Test networks · {count}</summary><p>The same address is \
                 also configured on these test networks. Test funds are not main-network \
                 funds.</p><ul class=\"receiving-networks\">{items}</ul></details>",
                count = testnets.len(),
            )
        };

        // The QR image is the leaf the wallets handler already renders, reached
        // by relative path on the mount. `img-src 'self'` permits it, and there
        // is no second QR encoder to keep in step with the first.
        format!(
            "<article class=\"card receiving-card\"><p class=\"eyebrow\">{wallet} · receiving \
             address</p><h3>Ethereum &amp; EVM</h3><figure class=\"receiving-qr\"><div>\
             <img src=\"../wallets/{wallet_path}/address.qr.svg\" width=\"222\" height=\"222\" \
             alt=\"{wallet} receiving address as a QR code\"></div>\
             <figcaption>Scan this address</figcaption></figure>\
             <code class=\"address\">{address}</code><div class=\"receiving-network-list\">\
             <p class=\"label\">Networks for this address</p>{networks}{testing}</div></article>",
            wallet = html_escape(wallet),
            wallet_path = html_escape(wallet),
            address = html_escape(address),
        )
    }

    async fn render_next_moves(&self) -> String {
        let actions = self.actions().await;
        let pending: Vec<&Action> = actions.iter().filter(|a| a.state == "pending").collect();
        let failed = actions.iter().filter(|a| a.state == "failed").count();

        let mut body = String::new();
        body.push_str(&attention_strip(pending.len(), false));

        if pending.is_empty() {
            body.push_str(
                "<section class=\"callout\"><strong>Nothing needs you right now</strong>\
                 <p>No staged operation is waiting for your review in the outbox that was \
                 checked. That is a complete answer, not an empty one.</p></section>",
            );
        } else {
            let rows: String = pending.iter().map(|action| action.row()).collect();
            body.push_str(&format!("<div class=\"activity-ledger\">{rows}</div>"));
            body.push_str(
                "<section class=\"callout warn\"><strong>Approving happens in Bloom, not \
                 here.</strong><p>This page shows what is staged. Confirm through the outbox \
                 so Broker can hold the approval; nothing on this page can authorize a \
                 transaction.</p></section>",
            );
        }

        if failed > 0 {
            body.push_str(&format!(
                "<section class=\"attention-strip\"><div><h3>Review unsuccessful \
                 operations</h3><p>{failed} failed or reverted {record} in the captured \
                 history. Check the receipt before trying again.</p></div>\
                 <a href=\"activity.html\">Inspect failures →</a></section>",
                record = if failed == 1 { "record" } else { "records" },
            ));
        }

        page(
            "Next moves",
            "What needs you.",
            "Staged operations awaiting your review come first. Past failures are available to \
             investigate, without being turned into automatic retries.",
            NEXT_MOVES_HTML,
            &body,
        )
    }

    async fn render_activity(&self) -> String {
        let actions = self.actions().await;
        let counts = |state: &str| actions.iter().filter(|a| a.state == state).count();
        let (sent, pending, failed) = (counts("sent"), counts("pending"), counts("failed"));

        let mut body = String::new();
        body.push_str(&format!(
            "<section class=\"outcome-overview\" aria-label=\"Outcome summary\">\
             <a href=\"#ledger\"><span class=\"mini-outcome\">✓</span><strong>{sent}</strong>\
             <span>Recorded as sent</span></a>\
             <a href=\"#ledger\"><span class=\"mini-outcome\">◷</span><strong>{pending}</strong>\
             <span>Staged, awaiting you</span></a>\
             <a href=\"#ledger\"><span class=\"mini-outcome\">!</span><strong>{failed}</strong>\
             <span>Failed or reverted</span></a></section>"
        ));

        body.push_str(
            "<section class=\"callout\"><strong>Sent is not the same as settled.</strong>\
             <p>These are Bloom's own records. A record marked sent means Bloom submitted it \
             and kept the result; read the receipt for the chain's own answer.</p></section>",
        );

        if actions.is_empty() {
            body.push_str(
                "<section class=\"callout\"><strong>No recorded operations</strong>\
                 <p>The outbox that was checked holds no staged, sent, or failed record.</p>\
                 </section>",
            );
        } else {
            let rows: String = actions.iter().map(|action| action.row()).collect();
            body.push_str(&format!(
                "<div class=\"section-head\" id=\"ledger\"><h2>Every record</h2>\
                 <p>Newest first</p></div><div class=\"activity-ledger\">{rows}</div>"
            ));
        }

        page(
            "Activity",
            "Your activity.",
            "What completed, what failed, and what is still staged. Newest first; this is the \
             history Bloom itself recorded.",
            ACTIVITY_HTML,
            &body,
        )
    }

    async fn render_access(&self) -> String {
        let (wallets, unavailable) = self.wallet_projections().await;
        let chains = self.sorted_chains();

        let mut body = String::new();
        if unavailable {
            body.push_str(
                "<section class=\"callout warn\"><strong>Policy unavailable</strong>\
                 <p>Broker is offline and no cached projection is available, so no policy can \
                 be shown. Authority operations remain fail-closed.</p></section>",
            );
        }
        body.push_str(
            "<section class=\"callout\"><strong>Broker enforces this, not this page.</strong>\
             <p>What follows is a public projection of each wallet's signed policy. Reading it \
             authorizes nothing, and it is not a complete inventory of approvals you may have \
             granted elsewhere.</p></section>",
        );

        let mut stale = false;
        for wallet in &wallets {
            if wallet.freshness == ProjectionFreshness::Stale {
                stale = true;
            }
            let id = wallet.wallet_id().as_str();
            let destinations = destinations_by_chain(wallet);
            let rows: String = chains
                .iter()
                .map(|chain| {
                    let allowed = destinations.get(chain).copied().unwrap_or(0);
                    let verdict = if allowed == 0 {
                        "<span class=\"badge warn\">Every send denied</span>".to_owned()
                    } else {
                        format!(
                            "<span class=\"badge good\">{allowed} allowed {noun}</span>",
                            noun = if allowed == 1 {
                                "destination"
                            } else {
                                "destinations"
                            },
                        )
                    };
                    format!(
                        "<tr><td data-label=\"Network\">{label}{test}</td>\
                         <td data-label=\"Sending\">{verdict}</td></tr>",
                        label = html_escape(&self.network_label(chain)),
                        // A test network beside main ones must say which it is.
                        test = if is_test_network(chain) {
                            "<small>Test network</small>"
                        } else {
                            ""
                        },
                    )
                })
                .collect();
            let total: usize = destinations.values().sum();
            body.push_str(&format!(
                "<section><div class=\"section-head\"><h2>{name}</h2>\
                 <p>Policy version {version} · {kind}</p></div>\
                 <p>{summary}</p>\
                 <div class=\"table-wrap\"><table><caption>Where this wallet may send, per \
                 network</caption><thead><tr><th scope=\"col\">Network</th>\
                 <th scope=\"col\">Sending</th></tr></thead><tbody>{rows}</tbody></table></div>\
                 <details><summary>Exact policy</summary><p>The canonical signed policy is at \
                 <code>{path}</code>. Approvals are bounded by a maximum lifetime that Broker \
                 checks on every use.</p></details></section>",
                name = html_escape(id),
                version = html_escape(wallet.wallet.policy_version.as_str()),
                kind = html_escape(wallet.wallet.wallet_kind.as_str()),
                summary = html_escape(&if total == 0 {
                    "No destination is allowed on any configured network, so every send is \
                     denied until the policy is updated."
                        .to_owned()
                } else {
                    format!(
                        "{total} allowed {noun} across the configured networks. Anything not \
                         listed is denied.",
                        noun = if total == 1 {
                            "destination"
                        } else {
                            "destinations"
                        },
                    )
                }),
                path = html_escape(&format!("/wallets/{id}/policy.json")),
            ));
        }
        if stale {
            body.push_str(&stale_notice());
        }

        page(
            "Access",
            "Your current access.",
            "What each wallet is allowed to do, read from its signed policy. Not a complete \
             inventory of external approvals.",
            ACCESS_HTML,
            &body,
        )
    }
}

#[derive(Default)]
struct Portfolio {
    holdings: Vec<Holding>,
    /// `(wallet, chain)` pairs whose balance could not be read.
    unavailable: Vec<(String, String)>,
    wallets: Vec<String>,
    projections_unavailable: bool,
    price_coverage_gap: bool,
    stale: bool,
}

impl Portfolio {
    /// Everything the reader must know about what is missing, stated rather
    /// than implied. Silence would read as "nothing to report".
    fn notices(&self) -> String {
        let mut out = String::new();
        if self.projections_unavailable {
            out.push_str(
                "<section class=\"callout warn\"><strong>Wallet projections unavailable</strong>\
                 <p>Broker is offline and no cached projection is available, so no balance can \
                 be read. Authority operations remain fail-closed.</p></section>",
            );
        }
        if !self.unavailable.is_empty() {
            let mut names: Vec<&str> = self
                .unavailable
                .iter()
                .map(|(_, chain)| chain.as_str())
                .collect();
            names.sort();
            names.dedup();
            out.push_str(&format!(
                "<section class=\"callout warn\"><strong>Some networks did not answer</strong>\
                 <p>{count} read did not return a balance ({names}). Those holdings are \
                 missing from this page rather than counted as zero.</p></section>",
                count = self.unavailable.len(),
                names = html_escape(&names.join(", ")),
            ));
        }
        if self.price_coverage_gap {
            out.push_str(
                "<section class=\"callout\"><strong>Some prices are missing</strong>\
                 <p>A quote was unavailable or older than an hour, so those rows stay \
                 unpriced instead of carrying a stale valuation.</p></section>",
            );
        }
        if self.stale {
            out.push_str(&stale_notice());
        }
        out
    }
}

struct Holding {
    wallet: String,
    chain: String,
    chain_id: u64,
    label: String,
    symbol: String,
    quantity: String,
    amount: f64,
    value: Option<f64>,
}

impl Holding {
    fn note(&self) -> String {
        if is_test_network(&self.chain) {
            "Test network. Test funds are not main-network funds and are never priced.".to_owned()
        } else if !native_asset_has_market(self.chain_id) {
            format!(
                "This network's native unit is not the traded {} asset, so it carries no \
                 dollar value here. The quantity is what the chain reported.",
                self.symbol
            )
        } else if self.value.is_some() {
            "Native balance, valued with a quote observed within the last hour.".to_owned()
        } else {
            "Native balance. No fresh quote was available, so it carries no dollar value."
                .to_owned()
        }
    }
}

struct Action {
    id: String,
    state: &'static str,
    modified_ms: Option<u64>,
    summary: String,
    wallet: Option<String>,
    chain: Option<String>,
    petal: Option<String>,
    denial: Option<String>,
}

impl Action {
    fn status_class(&self) -> &'static str {
        match self.state {
            "sent" => "status-success",
            "failed" => "status-failed",
            _ => "status-pending",
        }
    }

    fn glyph(&self) -> &'static str {
        match self.state {
            "sent" => "✓",
            "failed" => "!",
            _ => "◷",
        }
    }

    fn label(&self) -> &'static str {
        match self.state {
            "sent" => "✓ Recorded as sent",
            "failed" => "! Failed",
            _ => "◷ Staged · needs you",
        }
    }

    fn row(&self) -> String {
        let mut meta = String::new();
        if let Some(wallet) = &self.wallet {
            meta.push_str(&format!("<span>{}</span>", html_escape(wallet)));
        }
        if let Some(chain) = &self.chain {
            meta.push_str(&format!("<span>{}</span>", html_escape(chain)));
        }
        meta.push_str(&format!(
            "<span>{}</span>",
            html_escape(&match self.modified_ms {
                Some(ms) => format_utc_ms(ms),
                None => "Time unavailable".to_owned(),
            })
        ));
        if let Some(petal) = &self.petal {
            meta.push_str(&format!("<span>{}</span>", html_escape(petal)));
        }

        let denial = match &self.denial {
            Some(reason) => format!("<p>{}</p>", html_escape(reason)),
            None => String::new(),
        };

        format!(
            "<article class=\"activity-row {class}\">\
             <div class=\"outcome-symbol\" aria-hidden=\"true\">{glyph}</div>\
             <div class=\"activity-description\"><h3>{summary}</h3>\
             <div class=\"activity-meta\">{meta}</div>{denial}\
             <details><summary>Operation details</summary><dl class=\"receipt-facts\">\
             <div><dt>State</dt><dd>{state}</dd></div>\
             <div><dt>Operation</dt><dd><code>{id}</code></dd></div>\
             <div><dt>Plan</dt><dd><code>{path}</code></dd></div></dl></details></div>\
             <div class=\"activity-outcome\"><span class=\"outcome-label\">{label}</span>\
             </div></article>",
            class = self.status_class(),
            glyph = self.glyph(),
            summary = html_escape(&self.summary),
            state = html_escape(self.state),
            id = html_escape(&self.id),
            path = html_escape(&format!("/outbox/{}/{}/plan.md", self.state, self.id)),
            label = html_escape(self.label()),
        )
    }
}

fn state_path(state: &str) -> VfsPath {
    VfsPath::parse(state).unwrap_or_else(|_| VfsPath::root())
}

/// `petal_id` out of an outbox `status.json`, when it carries one.
fn petal_id(status: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(status).ok()?;
    let petal = value.get("petal_id")?.as_str()?;
    (!petal.is_empty()).then(|| petal.to_owned())
}

/// A staged plan's own title, so a row reads like the operation rather than
/// like an identifier.
fn plan_summary(plan: &str) -> String {
    plan.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.trim_start_matches('#').trim().to_owned())
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| "Staged operation".to_owned())
}

/// A single `Key: value` fact out of a staged plan, without parsing Markdown.
fn plan_field(plan: &str, key: &str) -> Option<String> {
    plan.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(key))
        .map(|rest| {
            let value = rest.trim();
            match value.split_once(" (") {
                Some((head, _)) => head.trim().to_owned(),
                None => value.to_owned(),
            }
        })
        .filter(|value| !value.is_empty())
}

/// A policy denial recorded in the plan. Worth surfacing on the row: it is
/// the reason the operation will not proceed as staged.
fn plan_denial(plan: &str) -> Option<String> {
    plan.lines()
        .map(str::trim)
        .find(|line| line.starts_with("- [Deny]"))
        .map(|line| {
            let text = line.trim_start_matches("- [Deny]").trim();
            match text.split_once(": ") {
                Some((_, reason)) => reason.trim().to_owned(),
                None => text.to_owned(),
            }
        })
        .filter(|reason| !reason.is_empty())
}

/// Allowed destinations per chain, from the wallet's own signed policy. The
/// canonical bytes are parsed the same way advisory planning parses them.
fn destinations_by_chain(projection: &WalletProjection) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    let canonical: bloom_broker_api::CanonicalWalletPolicy =
        match serde_json::from_slice(&projection.policy.canonical_policy.decode()) {
            Ok(canonical) => canonical,
            Err(error) => {
                tracing::debug!(error = %error, "views.policy_unparsed");
                return counts;
            }
        };
    if canonical.wallet_id != projection.wallet.wallet_id {
        tracing::debug!("views.policy_wallet_mismatch");
        return counts;
    }
    for destination in &canonical.allowed_destinations {
        *counts
            .entry(destination.chain.as_str().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn attention_strip(pending: usize, offer_review: bool) -> String {
    let (heading, detail) = if pending == 0 {
        (
            "Nothing is waiting for you".to_owned(),
            "No staged operation needs your review in the outbox that was checked.".to_owned(),
        )
    } else {
        (
            format!(
                "{pending} staged {noun}",
                noun = if pending == 1 {
                    "operation"
                } else {
                    "operations"
                }
            ),
            "Review the staged details in Bloom before approving.".to_owned(),
        )
    };
    format!(
        "<section class=\"attention-strip\"><div><p class=\"eyebrow\">Your next step</p>\
         <h3>{heading}</h3><p>{detail}</p></div>\
         {action}</section>",
        heading = html_escape(&heading),
        detail = html_escape(&detail),
        // The page that *is* the review must not offer a link to itself.
        action = if offer_review {
            "<a class=\"button secondary\" href=\"next-moves.html\">Review next steps →</a>"
        } else {
            ""
        },
    )
}

fn stale_notice() -> String {
    "<section class=\"callout warn\"><strong>Some projections are stale</strong>\
     <p>At least one wallet below comes from cached data rather than a live Broker read. \
     Confirm in Bloom before acting on it.</p></section>"
        .to_owned()
}

fn css_entry() -> Entry {
    Entry::file(BLOOM_CSS_NAME).with_size(BLOOM_CSS.len() as u64)
}

fn agents_entry() -> Entry {
    Entry::file(AGENTS_MD_NAME).with_size(VIEWS_AGENTS_MD.len() as u64)
}

fn is_page(name: &str) -> bool {
    PAGES.iter().any(|(page, _)| *page == name)
}

/// Chains whose native unit is the asset a quote for that symbol actually
/// prices. Keyed on chain id, never on the symbol string: a chain is free to
/// call its native unit "ETH" without it being ether, and a development or
/// app chain handing out a faucet balance must not be valued at ether's
/// price. An unlisted chain reports its quantity and stays unpriced, which is
/// the same rule as a missing quote.
const NATIVE_ASSET_MARKETS: &[u64] = &[
    1,      // Ethereum
    10,     // OP Mainnet
    56,     // BNB Smart Chain
    100,    // Gnosis
    137,    // Polygon
    8453,   // Base
    42161,  // Arbitrum One
    43114,  // Avalanche C-Chain
    59144,  // Linea
    81457,  // Blast
    534352, // Scroll
];

fn native_asset_has_market(chain_id: u64) -> bool {
    NATIVE_ASSET_MARKETS.contains(&chain_id)
}

/// A test network is named as one. No chain spec carries a testnet flag, so
/// the name is the only signal available — the same rule the design prototype
/// used. Being wrong in the safe direction means a main network is disclosed
/// as a test one, never the reverse.
fn is_test_network(chain: &str) -> bool {
    let name = chain.to_ascii_lowercase();
    name.contains("devnet") || name.contains("testnet")
}

fn fresh_quote(timestamp: u64, now: u64) -> bool {
    now.checked_sub(timestamp)
        .map(|age| age <= QUOTE_MAX_AGE_SECS)
        // A quote stamped in the future is not evidence of freshness.
        .unwrap_or(false)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// `$1,234.56`, or an explicit absence. A missing price is never a zero.
fn money(value: Option<f64>) -> String {
    match value {
        None => "Not priced".to_owned(),
        Some(value) => format!("${}", thousands(value)),
    }
}

fn thousands(value: f64) -> String {
    let text = format!("{:.2}", value.abs());
    let (whole, fraction) = text.split_once('.').unwrap_or((text.as_str(), "00"));
    let mut grouped = String::new();
    for (index, digit) in whole.chars().enumerate() {
        if index > 0 && (whole.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    format!(
        "{sign}{grouped}.{fraction}",
        sign = if value < 0.0 { "-" } else { "" }
    )
}

fn count_noun(count: usize, singular: &str, plural: &str) -> String {
    format!(
        "{count} {noun}",
        noun = if count == 1 { singular } else { plural }
    )
}

/// A two-letter mark for a network or asset. The design's icon set came from
/// provider CDNs, which `img-src 'self'` blocks, so every mark is drawn from
/// the name itself.
fn monogram(name: &str) -> String {
    let initials: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(2)
        .collect::<String>()
        .to_ascii_uppercase();
    format!(
        "<span class=\"asset-mark monogram\" aria-hidden=\"true\">{}</span>",
        html_escape(&initials)
    )
}

fn asset_label(name: &str) -> String {
    format!(
        "<span class=\"asset-label\">{mark}<span>{name}</span></span>",
        mark = monogram(name),
        name = html_escape(name),
    )
}

/// `11 Sep 2026 · 20:30 UTC`, from epoch milliseconds.
fn format_utc_ms(ms: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let seconds_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let month_name = MONTHS
        .get((month.saturating_sub(1)) as usize)
        .copied()
        .unwrap_or("???");
    format!(
        "{day:02} {month_name} {year} · {hour:02}:{minute:02} UTC",
        hour = seconds_of_day / 3600,
        minute = (seconds_of_day % 3600) / 60,
    )
}

/// Days since the Unix epoch to a civil date (Howard Hinnant's algorithm).
/// Rendering a timestamp must not pull in a date library.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_position + 2) / 5 + 1) as u32;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Escape text for HTML body and attribute contexts. `&` first, so an escape
/// is never double-escaped.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The shared page shell: one stylesheet link, no script, and a masthead that
/// says plainly that this is an observation.
fn page(title: &str, heading: &str, lede: &str, current: &str, body: &str) -> String {
    let nav: String = PAGES
        .iter()
        .map(|(href, label)| {
            let aria = if *href == current {
                " aria-current=\"page\""
            } else {
                ""
            };
            format!("<a href=\"{href}\"{aria}>{label}</a>")
        })
        .collect();
    format!(
        "<!doctype html>\n\
         <html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{csp}\">\
         <title>{title} · Bloom</title>\
         <link rel=\"stylesheet\" href=\"bloom.css\"></head>\
         <body class=\"personal-dashboard\">\
         <a class=\"skip\" href=\"#main\">Skip to content</a>\
         <div class=\"demo snapshot-banner\"><strong>YOUR WALLET</strong>\
         <span>Read-only view · no automatic refresh</span>\
         <span>This page observes; it never approves or executes an action.</span></div>\
         <div class=\"shell\"><header class=\"masthead\">\
         <a class=\"brand\" href=\"index.html\"><strong>/bloom</strong></a>\
         <span class=\"edition\">Personal wallet views</span></header>\
         <nav aria-label=\"Wallet views\">{nav}</nav>\
         <main id=\"main\"><div class=\"intro\"><div>\
         <p class=\"eyebrow\">Your place in the ecosystem</p><h1>{heading}</h1></div>\
         <p class=\"lede\">{lede}</p></div>{body}</main>\
         <footer><span>Read-only projection · nothing here authorizes an action</span>\
         <span><a href=\"AGENTS.md\">How to use these pages</a></span></footer>\
         </div></body></html>\n",
        csp = CSP,
        title = html_escape(title),
        heading = html_escape(heading),
        lede = html_escape(lede),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::EntryKind;

    const ADDRESS: &str = "0x000000000000000000000000000000000000dEaD";

    struct Fixture {
        handler: ViewsHandler,
        _tmp: tempfile::TempDir,
        outbox_root: std::path::PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let outbox_root = tmp.path().join("central_outbox");
        let outbox = Arc::new(super::super::outbox::OutboxHandler::new(
            super::super::outbox::CentralOutbox::new(outbox_root.clone()),
        ));
        let handler = ViewsHandler::new(
            crate::test_support::wallet_projection_reader("alice", ADDRESS),
            ChainRegistry::default(),
            // An unroutable base URL: valuation must degrade, never hang the
            // page or invent a number.
            bloom_prices::PricesClient::with_base_url("http://127.0.0.1:1"),
            outbox,
        );
        Fixture {
            handler,
            _tmp: tmp,
            outbox_root,
        }
    }

    /// Stage an action the way the outbox stores one, so the pages read it
    /// through the outbox handler exactly as they would in production.
    fn stage(fixture: &Fixture, state: &str, id: &str, plan: &str) {
        let dir = fixture.outbox_root.join(state).join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plan.md"), plan).unwrap();
        std::fs::write(
            dir.join("status.json"),
            format!("{{\"action_id\":\"{id}\",\"state\":\"{state}\"}}"),
        )
        .unwrap();
    }

    async fn render(handler: &ViewsHandler, page: &str) -> String {
        String::from_utf8(handler.read(&VfsPath::parse(page).unwrap()).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn every_listed_page_renders_and_every_nav_link_is_served() {
        let fixture = fixture();
        let entries = fixture.handler.list(&VfsPath::root()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&AGENTS_MD_NAME));
        assert!(names.contains(&BLOOM_CSS_NAME));
        for (page, _) in PAGES {
            assert!(names.contains(page), "{page} must be listed");
            let html = render(&fixture.handler, page).await;
            assert!(html.starts_with("<!doctype html>"), "{page}: {html:.40}");
            assert!(html.contains("</html>"), "{page} must be a whole document");
            // A nav that points at an unserved page is a dead link.
            for (href, _) in PAGES {
                assert!(
                    html.contains(&format!("href=\"{href}\"")),
                    "{page} must link {href}"
                );
            }
        }
        for e in &entries {
            assert_eq!(e.kind, EntryKind::File);
            assert_eq!(e.mode, 0o444, "views pages must be read-only");
        }
    }

    #[tokio::test]
    async fn no_page_carries_script_and_all_declare_the_same_policy() {
        let fixture = fixture();
        for (page, _) in PAGES {
            let html = render(&fixture.handler, page).await;
            assert!(html.contains("Content-Security-Policy"), "{page}");
            assert!(html.contains("style-src 'self'"), "{page}");
            assert!(
                !html.contains("script-src"),
                "{page} must not permit script"
            );
            assert!(!html.contains("<script"), "{page} must emit no script");
            assert!(html.contains("stylesheet\" href=\"bloom.css\""), "{page}");
        }
    }

    #[tokio::test]
    async fn static_assets_report_a_real_size_for_ls() {
        let entries = fixture().handler.list(&VfsPath::root()).await.unwrap();
        let css = entries
            .iter()
            .find(|e| e.name == BLOOM_CSS_NAME)
            .expect("bloom.css listed");
        assert_eq!(css.size, BLOOM_CSS.len() as u64);
        assert!(css.size > 0, "an empty stylesheet would render unstyled");
    }

    #[tokio::test]
    async fn stylesheet_is_served_and_reaches_for_nothing_external() {
        let css = String::from_utf8(
            fixture()
                .handler
                .read(&VfsPath::parse(BLOOM_CSS_NAME).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(css.contains(":root"));
        // `default-src 'none'` blocks every fetch, silently. A stylesheet that
        // reached for a font or an image would simply render wrong.
        for forbidden in ["url(", "@import", "@font-face", "http"] {
            assert!(!css.contains(forbidden), "must not reference {forbidden:?}");
        }
    }

    #[tokio::test]
    async fn receive_shows_the_address_and_links_the_rendered_qr() {
        let html = render(&fixture().handler, RECEIVE_HTML).await;
        assert!(html.contains(ADDRESS));
        assert!(
            html.contains("<img src=\"../wallets/alice/address.qr.svg\""),
            "the QR must reuse the wallets leaf, not a second encoder"
        );
        assert!(html.contains("1 receiving address"));
    }

    #[tokio::test]
    async fn unpriced_holdings_are_never_valued_at_zero() {
        // No chain is configured and prices are unroutable, so nothing can be
        // priced. The page must say so rather than showing $0.00.
        let html = render(&fixture().handler, WALLETS_HTML).await;
        assert!(
            html.contains("No non-zero native balance was read"),
            "{html}"
        );
        assert!(
            !html.contains("$0.00"),
            "an absent price must not read as zero"
        );
        // An absence belongs in the supporting line, not in the headline.
        assert!(
            html.contains("<div class=\"metric\">—</div>"),
            "an unpriced page must not set prose as its metric: {html}"
        );
        assert_eq!(money(None), "Not priced");
        assert_ne!(money(Some(0.0)), money(None));
    }

    #[tokio::test]
    async fn today_shows_an_absence_as_a_dash_not_a_number() {
        let html = render(&fixture().handler, INDEX_HTML).await;
        assert!(
            html.contains("<div class=\"metric\">—</div>"),
            "an empty read must not headline a number or prose: {html}"
        );
        assert!(
            html.contains("No balance was read from the configured networks"),
            "{html}"
        );
        assert!(
            !html.contains("$0.00"),
            "nothing read must not read as zero"
        );
        assert!(html.contains("Doing nothing is a valid outcome"));
    }

    #[tokio::test]
    async fn staged_operations_reach_next_moves_and_activity() {
        let fixture = fixture();
        stage(
            &fixture,
            "pending",
            "evm-0001",
            "# Staged tx 0001-62058\n\nWallet: primary\nChain:  ethereum (id 1)\n\n## Policy\n\
             - [Deny] balance.native_funds: account has 0 ETH; fund it before approving.\n",
        );
        stage(
            &fixture,
            "sent",
            "evm-0002",
            "# Send 0.05 ETH\n\nChain:  base (id 8453)\n",
        );
        stage(
            &fixture,
            "failed",
            "evm-0003",
            "# Enso operation\n\nChain:  ethereum (id 1)\n",
        );

        let next = render(&fixture.handler, NEXT_MOVES_HTML).await;
        assert!(next.contains("Staged tx 0001-62058"), "{next}");
        assert!(next.contains("1 staged operation"), "{next}");
        assert!(
            next.contains("fund it before approving"),
            "a policy denial is the reason it will not proceed: {next}"
        );
        assert!(next.contains("1 failed or reverted record"), "{next}");
        // A staged row must never be dressed up as an approval control.
        assert!(next.contains("Approving happens in Bloom, not here"));

        let activity = render(&fixture.handler, ACTIVITY_HTML).await;
        for summary in ["Staged tx 0001-62058", "Send 0.05 ETH", "Enso operation"] {
            assert!(activity.contains(summary), "{summary} missing: {activity}");
        }
        assert!(activity.contains("status-success"));
        assert!(activity.contains("status-failed"));
        assert!(activity.contains("status-pending"));
        assert!(activity.contains("Sent is not the same as settled"));
    }

    #[tokio::test]
    async fn an_empty_outbox_answers_rather_than_showing_nothing() {
        let fixture = fixture();
        let next = render(&fixture.handler, NEXT_MOVES_HTML).await;
        assert!(next.contains("Nothing needs you right now"), "{next}");
        let activity = render(&fixture.handler, ACTIVITY_HTML).await;
        assert!(activity.contains("No recorded operations"), "{activity}");
    }

    #[tokio::test]
    async fn access_reports_a_deny_all_policy_as_denied() {
        // The test projection carries an empty destination allow-set, which is
        // Broker's fail-closed state, not an absence of policy.
        let html = render(&fixture().handler, ACCESS_HTML).await;
        assert!(html.contains("every send is denied"), "{html}");
        assert!(html.contains("Broker enforces this, not this page"));
        assert!(html.contains("Policy version 1"), "{html}");
    }

    #[tokio::test]
    async fn tables_label_every_cell_for_narrow_screens() {
        let fixture = fixture();
        stage(
            &fixture,
            "pending",
            "evm-0001",
            "# Staged tx\n\nChain:  ethereum (id 1)\n",
        );
        for page in [WALLETS_HTML, ACCESS_HTML] {
            let html = render(&fixture.handler, page).await;
            let cells = html.matches("<td").count();
            let labelled = html.matches("<td data-label=").count()
                + html
                    .matches("<td class=\"numeric money\" data-label=")
                    .count();
            assert_eq!(
                cells, labelled,
                "{page}: every cell needs data-label or 320px loses its column headers"
            );
        }
    }

    #[tokio::test]
    async fn unknown_page_is_not_found_and_a_page_is_not_a_dir() {
        let handler = fixture().handler;
        let missing = VfsPath::parse("markets.html").unwrap();
        assert!(matches!(
            handler.lookup(&missing).await,
            Err(HandlerError::NotFound(_))
        ));
        assert!(matches!(
            handler.read(&missing).await,
            Err(HandlerError::NotAFile(_))
        ));
        assert!(matches!(
            handler.list(&VfsPath::parse(INDEX_HTML).unwrap()).await,
            Err(HandlerError::NotADir(_))
        ));
    }

    #[tokio::test]
    async fn lookup_root_is_a_dir_that_lists() {
        let handler = fixture().handler;
        let root = handler.lookup(&VfsPath::root()).await.unwrap();
        assert_eq!(root.kind, EntryKind::Dir);
        // If lookup calls it a directory, list must agree or mounts emit
        // ENOTDIR for every `find` over the tree.
        assert!(handler.list(&VfsPath::root()).await.is_ok());
    }

    #[tokio::test]
    async fn pages_are_cached_briefly_and_assets_are_not() {
        let handler = fixture().handler;
        for (page, _) in PAGES {
            assert_eq!(
                handler.cache_ttl(&VfsPath::parse(page).unwrap()),
                Some(PAGE_TTL),
                "{page}"
            );
        }
        assert_eq!(
            handler.cache_ttl(&VfsPath::parse(BLOOM_CSS_NAME).unwrap()),
            None
        );
    }

    #[tokio::test]
    async fn agents_doc_is_served_beside_the_pages() {
        let doc = String::from_utf8(
            fixture()
                .handler
                .read(&VfsPath::parse(AGENTS_MD_NAME).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(doc.contains("receive.html"));
        assert!(doc.contains("never"));
    }

    #[test]
    fn only_a_chain_whose_native_unit_is_the_traded_asset_is_priced() {
        // Ethereum and its rollups price their native ether.
        for chain_id in [1u64, 10, 8453, 42161, 59144] {
            assert!(native_asset_has_market(chain_id), "{chain_id}");
        }
        // A development or app chain may call its native unit "ETH" and hand
        // out an enormous faucet balance. Valuing that at ether's price
        // produced a nonsense headline total; it must stay unpriced.
        for chain_id in [4217u64, 31337, 4663] {
            assert!(
                !native_asset_has_market(chain_id),
                "chain {chain_id} must not be valued at another asset's price"
            );
        }
    }

    #[test]
    fn test_networks_are_recognised_by_name() {
        for name in ["solana-devnet", "sepolia-testnet", "Base-Devnet"] {
            assert!(is_test_network(name), "{name} is a test network");
        }
        for name in ["ethereum", "base", "arbitrum", "solana-mainnet"] {
            assert!(!is_test_network(name), "{name} is a main network");
        }
    }

    #[test]
    fn a_stale_or_future_quote_prices_nothing() {
        let now = 1_000_000u64;
        assert!(fresh_quote(now, now));
        assert!(fresh_quote(now - QUOTE_MAX_AGE_SECS, now));
        assert!(!fresh_quote(now - QUOTE_MAX_AGE_SECS - 1, now));
        assert!(
            !fresh_quote(now + 1, now),
            "a future stamp is not freshness"
        );
    }

    #[test]
    fn money_groups_thousands_and_keeps_absence_distinct() {
        assert_eq!(money(Some(1234.5)), "$1,234.50");
        assert_eq!(money(Some(1_234_567.891)), "$1,234,567.89");
        assert_eq!(money(Some(0.0)), "$0.00");
        assert_eq!(money(None), "Not priced");
    }

    #[test]
    fn timestamps_render_without_a_date_library() {
        // 2026-09-11T20:30:00Z
        assert_eq!(format_utc_ms(1_789_158_600_000), "11 Sep 2026 · 20:30 UTC");
        assert_eq!(format_utc_ms(0), "01 Jan 1970 · 00:00 UTC");
    }

    #[test]
    fn plan_text_yields_a_title_facts_and_a_denial() {
        let plan = "# Staged tx 0001-62058\n\nWallet: primary\nChain:  ethereum (id 1)\n\n\
                    ## Policy\n- [Deny] balance.native_funds: account has 0 ETH.\n";
        assert_eq!(plan_summary(plan), "Staged tx 0001-62058");
        assert_eq!(plan_field(plan, "Chain:").as_deref(), Some("ethereum"));
        assert_eq!(plan_field(plan, "Wallet:").as_deref(), Some("primary"));
        assert_eq!(plan_denial(plan).as_deref(), Some("account has 0 ETH."));
        assert_eq!(plan_summary(""), "Staged operation");
        assert!(plan_field("", "Chain:").is_none());
        assert!(plan_denial("# no policy section\n").is_none());
    }

    #[test]
    fn escaping_neutralises_markup_and_never_double_escapes() {
        assert_eq!(
            html_escape("<script src='x'>\"&"),
            "&lt;script src=&#39;x&#39;&gt;&quot;&amp;"
        );
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn a_monogram_is_drawn_from_the_name_not_a_remote_icon() {
        assert!(monogram("Ethereum").contains(">ET<"));
        assert!(monogram("solana-devnet").contains(">SO<"));
        assert!(asset_label("Base").contains("class=\"asset-label\""));
    }

    /// Write every page to `$VIEWS_DUMP/` for visual review. Ignored: a
    /// development aid for looking at the pages, not an assertion.
    #[tokio::test]
    #[ignore]
    async fn dump_pages() {
        let Ok(out) = std::env::var("VIEWS_DUMP") else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let outbox_root = tmp.path().join("central_outbox");
        let outbox = Arc::new(super::super::outbox::OutboxHandler::new(
            super::super::outbox::CentralOutbox::new(outbox_root.clone()),
        ));
        let chains = ChainRegistry::new();
        for (name, chain_id, display) in [
            ("arbitrum", 42161u64, "Arbitrum One"),
            ("base", 8453, "Base"),
            ("ethereum", 1, "Ethereum"),
            ("robinhood", 4663, "Robinhood Chain"),
            ("sepolia-testnet", 11155111, "Sepolia"),
        ] {
            let spec = bloom_proto::ChainSpec {
                name: name.into(),
                chain_id,
                rpc_urls: vec!["http://127.0.0.1:1".into()],
                rpc_endpoints: Vec::new(),
                allow_broadcast: false,
                etherscan_api_url: None,
                display_name: Some(display.to_owned()),
                native_symbol: "ETH".into(),
                native_decimals: 18,
                legacy_tx: false,
                op_stack: false,
            };
            chains.add(bloom_evm::ChainClient::new(spec).unwrap());
        }
        let handler = ViewsHandler::new(
            crate::test_support::wallet_projection_reader("everyday", ADDRESS),
            chains,
            bloom_prices::PricesClient::with_base_url("http://127.0.0.1:1"),
            outbox,
        );
        let staged = Fixture {
            handler: handler.clone(),
            _tmp: tmp,
            outbox_root,
        };
        stage(
            &staged,
            "pending",
            "evm-54ea2d13844badc5fb1082c036711257",
            "# Staged tx 0001-62058\n\nWallet: everyday\nChain:  ethereum (id 1)\n\n## Policy\n\
             - [Deny] balance.native_funds: account has 0 ETH on Ethereum Mainnet; requires up \
             to 0.010084679918 ETH. Fund the account and restage this transaction before \
             approving.\n",
        );
        stage(
            &staged,
            "sent",
            "evm-75fb67132a5af7ffb607c2590b60c414",
            "# Send 0.05 ETH\n\nWallet: everyday\nChain:  base (id 8453)\n",
        );
        stage(
            &staged,
            "failed",
            "evm-9c1f0aa2b6d34e7f8a5b2c3d4e5f6071",
            "# Enso operation\n\nWallet: everyday\nChain:  ethereum (id 1)\n",
        );

        std::fs::create_dir_all(&out).unwrap();
        for (page, _) in PAGES {
            let html = render(&staged.handler, page).await;
            std::fs::write(std::path::Path::new(&out).join(page), html).unwrap();
        }
        std::fs::write(std::path::Path::new(&out).join(BLOOM_CSS_NAME), BLOOM_CSS).unwrap();
    }
}
