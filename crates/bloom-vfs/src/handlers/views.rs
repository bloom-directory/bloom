//! `views/...` — read-only HTML pages meant for a person, not an agent.
//!
//! Paths handled:
//! - `views/`                 — list the available pages
//! - `views/index.html`       — Today: what you hold, and what needs you
//! - `views/wallets.html`     — native balances per wallet, with valuation
//! - `views/receive.html`     — receiving addresses grouped by wallet
//! - `views/next-moves.html`  — staged operations awaiting your review
//! - `views/activity.html`    — what completed, failed, or is still staged
//! - `views/policy.html`      — what each wallet is allowed to do
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

use super::market_data::{self, MarketData, TokenMarket};
use super::outbox::OutboxHandler;
use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const BLOOM_CSS: &str = include_str!("../assets/bloom.css");
const VIEWS_AGENTS_MD: &str = include_str!("../docs/views-agents.md");

const INDEX_HTML: &str = "index.html";
const MARKETS_HTML: &str = "markets.html";
const CHAINS_HTML: &str = "chains.html";
const FEES_HTML: &str = "fees.html";
const WALLETS_HTML: &str = "wallets.html";
const RECEIVE_HTML: &str = "receive.html";
const NEXT_MOVES_HTML: &str = "next-moves.html";
const ACTIVITY_HTML: &str = "activity.html";
const POLICY_HTML: &str = "policy.html";
const BLOOM_CSS_NAME: &str = "bloom.css";
const AGENTS_MD_NAME: &str = "AGENTS.md";

/// Every page, in reading order. Drives both the directory listing and the
/// navigation, so a link can never point at a page that is not served.
const PAGES: &[(&str, &str)] = &[
    (INDEX_HTML, "Today"),
    (MARKETS_HTML, "Markets"),
    (CHAINS_HTML, "Chains"),
    (FEES_HTML, "Fees"),
    (WALLETS_HTML, "Wallets"),
    (NEXT_MOVES_HTML, "Next moves"),
    (ACTIVITY_HTML, "Activity"),
    (RECEIVE_HTML, "Receive"),
    (POLICY_HTML, "Policy"),
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
    market: MarketData,
    /// The `petals/` router, when one is mounted. Positions are read back
    /// through its own trait so a page cannot drift from what `/petals`
    /// reports, and absent it the section simply does not appear.
    petals: Option<Arc<dyn Handler>>,
}

impl ViewsHandler {
    pub fn new(
        projections: Arc<dyn WalletProjectionReader>,
        chains: ChainRegistry,
        prices: PricesClient,
        outbox: Arc<OutboxHandler>,
        market: MarketData,
    ) -> Self {
        Self {
            projections,
            chains,
            prices: Arc::new(prices),
            outbox,
            market,
            petals: None,
        }
    }

    /// Read Petal positions through the mounted `petals/` router.
    pub fn with_petals(mut self, petals: Arc<dyn Handler>) -> Self {
        self.petals = Some(petals);
        self
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
            MARKETS_HTML => self.render_markets().await,
            CHAINS_HTML => self.render_chains().await,
            FEES_HTML => self.render_fees().await,
            WALLETS_HTML => self.render_wallets().await,
            RECEIVE_HTML => self.render_receive().await,
            NEXT_MOVES_HTML => self.render_next_moves().await,
            ACTIVITY_HTML => self.render_activity().await,
            POLICY_HTML => self.render_policy().await,
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
            portfolio.wallets.push(WalletSummary {
                id: wallet.clone(),
                address: projection.primary_address().ok().map(str::to_owned),
                kind: projection.wallet.wallet_kind.as_str().to_owned(),
                policy_version: projection.wallet.policy_version.as_str().to_owned(),
            });
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

            let (holdings, unavailable) = self.read_balances(&wallet, address, &chains).await;
            portfolio.holdings.extend(holdings);
            portfolio.unavailable.extend(unavailable);
        }

        self.price(&mut portfolio).await;
        // Funded rows first and most valuable at the top; the empty networks
        // keep a stable alphabetical tail rather than interleaving.
        portfolio.holdings.sort_by(|a, b| {
            b.is_funded()
                .cmp(&a.is_funded())
                .then(
                    b.value
                        .partial_cmp(&a.value)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then_with(|| (&a.wallet, &a.label).cmp(&(&b.wallet, &b.label)))
        });
        portfolio
    }

    /// Native balance on every configured chain for one address. The reads
    /// run concurrently, so one slow endpoint costs a single budget rather
    /// than the sum of them.
    async fn read_balances(
        &self,
        owner: &str,
        address: alloy::primitives::Address,
        chains: &[String],
    ) -> (Vec<Holding>, Vec<(String, String)>) {
        let mut reads = tokio::task::JoinSet::new();
        for chain in chains {
            let Some(client) = self.chains.get(chain) else {
                continue;
            };
            let name = chain.clone();
            reads.spawn(async move {
                let symbol = client.spec().native_symbol.clone();
                let decimals = client.spec().native_decimals;
                let chain_id = client.spec().chain_id;
                let raw = match tokio::time::timeout(BALANCE_TIMEOUT, client.balance(address)).await
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
        let (mut holdings, mut unavailable) = (Vec::new(), Vec::new());
        while let Some(joined) = reads.join_next().await {
            let Ok((chain, raw, symbol, decimals, chain_id)) = joined else {
                continue;
            };
            match raw {
                // A zero balance is kept. "You hold nothing on Base" is an
                // answer; dropping the row leaves the reader unable to tell
                // it apart from a network that was never read.
                Some(raw) => {
                    let quantity = bloom_proto::format_units(raw, decimals);
                    let amount = quantity.parse::<f64>().unwrap_or(0.0);
                    holdings.push(Holding {
                        label: self.network_label(&chain),
                        wallet: owner.to_owned(),
                        chain,
                        chain_id,
                        symbol,
                        quantity,
                        amount,
                        value: None,
                    });
                }
                None => unavailable.push((owner.to_owned(), chain)),
            }
        }
        (holdings, unavailable)
    }

    /// Balances for the addresses that sent your own recorded operations,
    /// excluding wallets already projected.
    ///
    /// The funds are observable and worth seeing. The ownership claim is
    /// deliberately not made: no projection backs these addresses here, so
    /// they are reported as observations and never as wallets.
    async fn history_portfolio(&self, exclude: &[String]) -> Portfolio {
        let chains = self.sorted_chains();
        let mut portfolio = Portfolio::default();
        let mut seen: Vec<String> = Vec::new();
        for action in self.actions().await {
            let Some(from) = action
                .intent
                .as_ref()
                .and_then(|intent| intent.from.clone())
            else {
                continue;
            };
            let lowered = from.to_ascii_lowercase();
            if exclude.contains(&lowered) || seen.contains(&lowered) {
                continue;
            }
            seen.push(lowered);
            let Ok(address) = from.parse::<alloy::primitives::Address>() else {
                continue;
            };
            let label = short_hex(&from);
            portfolio.wallets.push(WalletSummary {
                id: label.clone(),
                address: Some(from.clone()),
                kind: "observed address".to_owned(),
                policy_version: "none projected".to_owned(),
            });
            let (holdings, _) = self.read_balances(&label, address, &chains).await;
            portfolio.holdings.extend(holdings);
        }
        self.price(&mut portfolio).await;
        portfolio
    }

    /// One leaf out of the `petals/` subtree, absent when the Petal is not
    /// onboarded or the leaf cannot be computed. Several Petal leaves are
    /// derived rather than stored, and answer with an error until their
    /// credentials exist; that is an absence, not a fault.
    async fn petal_file(&self, path: &str) -> Option<String> {
        let petals = self.petals.as_ref()?;
        let parsed = VfsPath::parse(path).ok()?;
        match Handler::read(petals.as_ref(), &parsed).await {
            Ok(bytes) => String::from_utf8(bytes).ok(),
            Err(error) => {
                tracing::debug!(path, error = %error, "views.petal_read_unavailable");
                None
            }
        }
    }

    async fn petal_list(&self, path: &str) -> Vec<String> {
        let Some(petals) = self.petals.as_ref() else {
            return Vec::new();
        };
        let Ok(parsed) = VfsPath::parse(path) else {
            return Vec::new();
        };
        match Handler::list(petals.as_ref(), &parsed).await {
            Ok(entries) => entries.into_iter().map(|entry| entry.name).collect(),
            Err(error) => {
                tracing::debug!(path, error = %error, "views.petal_list_unavailable");
                Vec::new()
            }
        }
    }

    /// Value held inside an app rather than as a native balance. A balance
    /// read cannot see any of this, so a wallet with funds in a Petal
    /// otherwise reads as empty.
    async fn petal_positions(&self, addresses: &[String]) -> Vec<PetalPosition> {
        if self.petals.is_none() {
            return Vec::new();
        }
        let mut positions = Vec::new();

        // Venue account equity, per address the daemon knows about.
        let mut seen: Vec<String> = Vec::new();
        for address in addresses {
            let lowered = address.to_ascii_lowercase();
            if seen.contains(&lowered) {
                continue;
            }
            seen.push(lowered.clone());
            let path = format!("hyperliquid/mainnet/users/{lowered}/clearinghouse.json");
            let Some(text) = self.petal_file(&path).await else {
                continue;
            };
            let equity = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/marginSummary/accountValue")
                        .and_then(|field| field.as_str())
                        .and_then(|text| text.parse::<f64>().ok())
                });
            let Some(equity) = equity.filter(|equity| *equity > 0.0) else {
                continue;
            };
            positions.push(PetalPosition {
                petal: "hyperliquid".to_owned(),
                label: "Trading account equity".to_owned(),
                scope: short_hex(address),
                quantity: format!("{} USDC", trim_trailing_zeros(&format!("{equity:.6}"))),
                // The venue denominates equity in dollars itself, so this
                // needs no quote of ours.
                value: Some(equity),
                source: format!("/petals/{path}"),
                note: "Account equity as the venue reports it, including unrealised profit \
                       and loss. Open position notional is not counted again."
                    .to_owned(),
            });
        }

        // Privacy-pool deposits that are confirmed and still unspent.
        let ether = self.ether_price().await;
        for wallet in self.petal_list("privacy-pools/notes").await {
            let mut wei = 0.0_f64;
            let mut notes = 0usize;
            for note in self
                .petal_list(&format!("privacy-pools/notes/{wallet}"))
                .await
            {
                let path = format!("privacy-pools/notes/{wallet}/{note}");
                let Some(text) = self.petal_file(&path).await else {
                    continue;
                };
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                    continue;
                };
                // A spent note is gone, and a pending one is not yours to
                // count yet. Either would overstate the balance.
                let spent = value
                    .get("spent")
                    .and_then(|field| field.as_bool())
                    .unwrap_or(true);
                let confirmed =
                    value.get("status").and_then(|field| field.as_str()) == Some("confirmed");
                if spent || !confirmed {
                    continue;
                }
                let Some(amount) = value
                    .get("value")
                    .and_then(|field| field.as_str())
                    .and_then(|text| text.parse::<f64>().ok())
                else {
                    continue;
                };
                wei += amount;
                notes += 1;
            }
            if notes == 0 {
                continue;
            }
            let ether_amount = wei / 1e18;
            positions.push(PetalPosition {
                petal: "privacy-pools".to_owned(),
                label: count_noun(notes, "unspent deposit", "unspent deposits"),
                scope: wallet.clone(),
                quantity: format!(
                    "{} ETH",
                    trim_trailing_zeros(&format!("{ether_amount:.18}"))
                ),
                value: ether.map(|price| ether_amount * price),
                source: format!("/petals/privacy-pools/notes/{wallet}/"),
                note: "Confirmed deposits that have not been withdrawn. Spent and pending \
                       notes are excluded."
                    .to_owned(),
            });
        }
        positions
    }

    /// A fresh ether quote, for Petal positions denominated in ether.
    async fn ether_price(&self) -> Option<f64> {
        let coin = CoinId::parse("coingecko:ethereum").ok()?;
        let quote = tokio::time::timeout(PRICE_TIMEOUT, self.prices.current(coin))
            .await
            .ok()?
            .ok()?;
        fresh_quote(quote.timestamp, now_secs()).then_some(quote.price)
    }

    /// Value what can be valued. A native asset is priced only on a chain
    /// where that asset *is* the market asset: a development chain whose
    /// native symbol happens to read "ETH" must never be valued at ether's
    /// price. A stale quote prices nothing.
    async fn price(&self, portfolio: &mut Portfolio) {
        let mut keys: Vec<&'static str> = portfolio
            .holdings
            .iter()
            .filter(|holding| holding.is_funded())
            .filter_map(|holding| native_asset_market(holding.chain_id))
            .collect();
        keys.sort_unstable();
        keys.dedup();

        let now = now_secs();
        let mut quotes: BTreeMap<&'static str, f64> = BTreeMap::new();
        for key in keys {
            let coin = match CoinId::parse(key) {
                Ok(coin) => coin,
                Err(error) => {
                    tracing::debug!(key, error = %error, "views.price_key_invalid");
                    portfolio.price_coverage_gap = true;
                    continue;
                }
            };
            match tokio::time::timeout(PRICE_TIMEOUT, self.prices.current(coin)).await {
                Ok(Ok(quote)) if quote.price >= 0.0 && fresh_quote(quote.timestamp, now) => {
                    quotes.insert(key, quote.price);
                }
                Ok(Ok(_)) => {
                    tracing::debug!(key, "views.quote_stale");
                    portfolio.price_coverage_gap = true;
                }
                Ok(Err(error)) => {
                    tracing::debug!(key, error = %error, "views.price_unavailable");
                    portfolio.price_coverage_gap = true;
                }
                Err(_) => {
                    tracing::debug!(key, "views.price_timeout");
                    portfolio.price_coverage_gap = true;
                }
            }
        }

        for holding in &mut portfolio.holdings {
            let Some(key) = native_asset_market(holding.chain_id) else {
                continue;
            };
            if let Some(price) = quotes.get(key) {
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
                let intent = self
                    .action_file(state, &id, "intent.json")
                    .await
                    .as_deref()
                    .and_then(parse_intent);
                // The broadcast hash is the result's own field; `status.json`
                // repeats it. Either answers, and neither invents one.
                let result = self.action_file(state, &id, "result.json").await;
                let tx_hash = result
                    .as_deref()
                    .and_then(|text| json_field(text, "tx_hash"))
                    .or_else(|| {
                        status
                            .as_deref()
                            .and_then(|text| json_field(text, "tx_hash"))
                    });
                // A challenge file means the operation reached an approval
                // ceremony. With no result beside it, it never got past one.
                let awaited_approval = self
                    .action_file(state, &id, "approval_challenge.json")
                    .await
                    .is_some();
                let chain = intent
                    .as_ref()
                    .and_then(|i| i.chain.clone())
                    .or_else(|| plan.as_deref().and_then(|text| plan_field(text, "Chain:")));
                // Only a transfer of value gets an amount. A zero-value
                // contract call is not a payment and must not read as one.
                let amount = intent
                    .as_ref()
                    .and_then(|i| i.value_wei.as_deref())
                    .filter(|wei| *wei != "0")
                    .map(|wei| self.native_amount(chain.as_deref(), wei));
                actions.push(Action {
                    summary: plan.as_deref().map(plan_summary).unwrap_or_else(|| {
                        format!("Operation {}", id.split('-').next().unwrap_or(&id))
                    }),
                    wallet: intent
                        .as_ref()
                        .and_then(|i| i.wallet.clone())
                        .or_else(|| plan.as_deref().and_then(|text| plan_field(text, "Wallet:"))),
                    denial: plan.as_deref().and_then(plan_denial),
                    petal: status.as_deref().and_then(petal_id),
                    chain,
                    amount,
                    tx_hash,
                    awaited_approval,
                    intent,
                    id,
                    state,
                    modified_ms,
                });
            }
        }
        // Newest first, by when the intent was created rather than when its
        // directory was last touched: a retry must not reorder history.
        actions.sort_by(|a, b| b.when().cmp(&a.when()).then_with(|| a.id.cmp(&b.id)));
        actions
    }

    /// A native-unit amount on a chain this daemon has configured. Without
    /// that chain's own decimals the raw wei figure is the honest answer:
    /// assuming 18 would silently mis-scale a chain that does not use them.
    fn native_amount(&self, chain: Option<&str>, wei: &str) -> String {
        let Ok(raw) = wei.parse::<alloy::primitives::U256>() else {
            return format!("{wei} wei");
        };
        match chain.and_then(|name| self.chains.get(name)) {
            Some(client) => {
                let spec = client.spec();
                format!(
                    "{} {}",
                    trim_trailing_zeros(&bloom_proto::format_units(raw, spec.native_decimals)),
                    spec.native_symbol,
                )
            }
            None => format!("{wei} wei"),
        }
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

        let funded = portfolio.funded();
        let priced: Vec<&&Holding> = funded.iter().filter(|h| h.value.is_some()).collect();
        let total: f64 = funded.iter().filter_map(|h| h.value).sum();
        let unpriced = funded.len() - priced.len();

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
        } else if funded.is_empty() {
            (
                "—".to_owned(),
                // Not "none holds anything": a faucet balance on an off-market
                // chain is something, and Wallets shows it a click away.
                format!(
                    "{read} answered; none holds a priced asset.",
                    read = count_noun(portfolio.holdings.len(), "network", "networks"),
                ),
                "Holding nothing is a complete answer. Wallets lists every network that was \
                 read, so an empty balance stays distinct from one never checked."
                    .to_owned(),
            )
        } else if priced.is_empty() {
            (
                "—".to_owned(),
                format!(
                    "{held}, none of it priced.",
                    held = count_noun(funded.len(), "funded holding", "funded holdings"),
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
            // Three, not four: the row is a three-column grid, and a fourth
            // tile wraps onto a line of its own looking like a mistake. What
            // is held is already the headline above.
            "<div class=\"stats\">\
             <div class=\"stat\"><span class=\"label\">Networks answered</span>\
             <div class=\"metric\">{answered}</div></div>\
             <div class=\"stat\"><span class=\"label\">Waiting for you</span>\
             <div class=\"metric\">{pending}</div></div>\
             <div class=\"stat\"><span class=\"label\">Never broadcast</span>\
             <div class=\"metric\">{failed}</div></div></div>",
            answered = portfolio.holdings.len(),
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
        let funded = portfolio.funded();
        let off_market = portfolio.off_market();
        let empty = portfolio.empty_networks();
        let priced: Vec<&&Holding> = funded.iter().filter(|h| h.value.is_some()).collect();
        let total: f64 = funded.iter().filter_map(|h| h.value).sum();

        let mut body = String::new();
        body.push_str(&portfolio.notices());
        let (metric, support) = if portfolio.holdings.is_empty() {
            (
                "—".to_owned(),
                "No non-zero native balance was read from the networks that answered.".to_owned(),
            )
        } else if funded.is_empty() {
            (
                "—".to_owned(),
                // Claiming every balance is empty while a faucet row sits
                // below it would be plainly contradicted by the page itself.
                if off_market.is_empty() {
                    format!(
                        "Every network that answered reported an empty balance. {} read, none \
                         holding anything.",
                        count_noun(portfolio.holdings.len(), "network", "networks"),
                    )
                } else {
                    // Not `count_noun`: it prefixes the count, which would
                    // read as "1 One network".
                    format!(
                        "No network holds a priced asset. {subject} below {verb} a balance on \
                         a chain with no market for its native unit.",
                        subject = if off_market.len() == 1 {
                            "One network".to_owned()
                        } else {
                            format!("{} networks", off_market.len())
                        },
                        verb = if off_market.len() == 1 {
                            "carries"
                        } else {
                            "carry"
                        },
                    )
                },
            )
        } else if priced.is_empty() {
            (
                "—".to_owned(),
                // Not `count_noun`: that helper prefixes the count, which
                // reads as "1 the row".
                if funded.len() == 1 {
                    "No price for the funded row below.".to_owned()
                } else {
                    format!(
                        "No price for any of the {} funded rows below.",
                        funded.len()
                    )
                },
            )
        } else {
            (
                money(Some(total)),
                format!(
                    "{} of {} funded rows carry a price.",
                    priced.len(),
                    funded.len()
                ),
            )
        };
        body.push_str(&format!(
            "<section class=\"hero\"><div><span class=\"label\">Observed priced assets</span>\
             <div class=\"metric\">{metric}</div>\
             <p>{support}</p></div>\
             <div class=\"hero-aside\"><h3>Coverage stays visible.</h3>\
             <p>Native balances, plus value held inside Petals. Token balances are not read here yet. A \
             missing quote leaves a row unpriced rather than valuing it at zero, and a chain \
             whose native unit has no market of its own is never priced.</p></div></section>",
            metric = html_escape(&metric),
            support = html_escape(&support),
        ));

        for wallet in &portfolio.wallets {
            let wallet_funded: Vec<&Holding> = funded
                .iter()
                .copied()
                .filter(|holding| holding.wallet == wallet.id)
                .collect();
            let wallet_off_market: Vec<&Holding> = off_market
                .iter()
                .copied()
                .filter(|holding| holding.wallet == wallet.id)
                .collect();
            let wallet_empty: Vec<&Holding> = empty
                .iter()
                .copied()
                .filter(|holding| holding.wallet == wallet.id)
                .collect();
            let wallet_total: f64 = wallet_funded.iter().filter_map(|h| h.value).sum();
            let subtitle = if wallet_funded.iter().any(|h| h.value.is_some()) {
                money(Some(wallet_total))
            } else if wallet_funded.is_empty() {
                "Holds nothing on any network that answered".to_owned()
            } else {
                "No priced balance".to_owned()
            };
            body.push_str(&format!(
                "<section id=\"wallet-{id}\"><div class=\"section-head\"><h2>{name}</h2>\
                 <p>{subtitle}</p></div>\
                 <dl class=\"receipt-facts\">\
                 <div><dt>Address</dt><dd><code>{address}</code></dd></div>\
                 <div><dt>Kind</dt><dd>{kind}</dd></div>\
                 <div><dt>Policy</dt><dd>version {version}</dd></div></dl>",
                id = html_escape(&wallet.id),
                name = html_escape(&wallet.id),
                subtitle = html_escape(&subtitle),
                address = html_escape(wallet.address.as_deref().unwrap_or("Unavailable")),
                kind = html_escape(&wallet.kind),
                version = html_escape(&wallet.policy_version),
            ));

            if !wallet_funded.is_empty() {
                body.push_str(&holdings_table(
                    &wallet_funded,
                    "Native balances read through Bloom",
                ));
            }

            // Faucet and development balances get their own table. Sharing one
            // with real funds is how an enormous test quantity ends up reading
            // as a portfolio.
            if !wallet_off_market.is_empty() {
                body.push_str(
                    "<div class=\"section-head\"><h3>Test and development networks</h3>\
                     <p>Quantities here are not money</p></div>",
                );
                body.push_str(&holdings_table(
                    &wallet_off_market,
                    "Balances on chains with no market for their native unit",
                ));
            }

            // An empty network is reported, not dropped: otherwise "you hold
            // nothing on Base" is indistinguishable from "Base was not read".
            if !wallet_empty.is_empty() {
                let chips: String = wallet_empty
                    .iter()
                    .map(|holding| format!("<li>{}</li>", asset_label(&holding.label)))
                    .collect();
                body.push_str(&format!(
                    "<details><summary>Holds nothing · {count}</summary>\
                     <p>These networks answered and reported an empty balance. They are listed \
                     so that holding nothing stays distinguishable from never having been \
                     read.</p><ul class=\"receiving-networks\">{chips}</ul></details>",
                    count = wallet_empty.len(),
                ));
            }
            body.push_str("</section>");
        }

        // The wallets above are what Broker projects. These addresses are
        // what actually sent your recorded operations, and a reader looking
        // for "where is my money" is otherwise told nothing at all.
        let projected: Vec<String> = portfolio
            .wallets
            .iter()
            .filter_map(|wallet| wallet.address.as_ref())
            .map(|address| address.to_ascii_lowercase())
            .collect();
        let history = self.history_portfolio(&projected).await;
        let observed = history.funded();
        if !observed.is_empty() {
            body.push_str(
                "<div class=\"section-head\"><h2>Seen in your history</h2>\
                 <p>Observed addresses · not projected wallets</p></div>\
                 <p class=\"lede\">These addresses sent operations recorded in your outbox. \
                 Bloom projects no policy or key for them here, so they are reported as \
                 observations only and are not counted in the total above.</p>",
            );
            for summary in &history.wallets {
                let rows: Vec<&Holding> = observed
                    .iter()
                    .copied()
                    .filter(|holding| holding.wallet == summary.id)
                    .collect();
                if rows.is_empty() {
                    continue;
                }
                let total: f64 = rows.iter().filter_map(|holding| holding.value).sum();
                body.push_str(&format!(
                    "<section><div class=\"section-head\"><h3>{id}</h3><p>{total}</p></div>\
                     <dl class=\"receipt-facts\"><div><dt>Address</dt>\
                     <dd><code>{address}</code></dd></div></dl>{table}</section>",
                    id = html_escape(&summary.id),
                    address = html_escape(summary.address.as_deref().unwrap_or("Unavailable")),
                    total = html_escape(&if total > 0.0 {
                        money(Some(total))
                    } else {
                        "No priced balance".to_owned()
                    }),
                    table = holdings_table(&rows, "Observed balances"),
                ));
            }
        }

        // Value held inside an app is invisible to a balance read, so a
        // wallet whose funds sit in a Petal otherwise reads as empty.
        let mut petal_addresses: Vec<String> = portfolio
            .wallets
            .iter()
            .filter_map(|wallet| wallet.address.clone())
            .collect();
        petal_addresses.extend(
            history
                .wallets
                .iter()
                .filter_map(|wallet| wallet.address.clone()),
        );
        let positions = self.petal_positions(&petal_addresses).await;
        if !positions.is_empty() {
            let cells: String = positions
                .iter()
                .map(|position| {
                    format!(
                        "<tr><td data-label=\"Position\"><span class=\"asset-label\">{mark}\
                         <span><strong>{label}</strong><small>{quantity}</small></span></span>\
                         </td>\
                         <td data-label=\"Petal\">{petal}</td>\
                         <td data-label=\"Scope\"><code>{scope}</code></td>\
                         <td class=\"numeric money\" data-label=\"Observed value\">{value}</td>\
                         <td data-label=\"Evidence\"><details><summary>Details</summary>\
                         <p>{note}</p><p><code>{source}</code></p></details></td></tr>",
                        mark = monogram(&position.petal),
                        label = html_escape(&position.label),
                        quantity = html_escape(&short_quantity_with_unit(&position.quantity)),
                        petal = html_escape(&position.petal),
                        scope = html_escape(&position.scope),
                        value = html_escape(&money(position.value)),
                        note = html_escape(&position.note),
                        source = html_escape(&position.source),
                    )
                })
                .collect();
            let total: f64 = positions.iter().filter_map(|position| position.value).sum();
            body.push_str(&format!(
                "<div class=\"section-head\"><h2>Petal positions</h2>\
                 <p>{count} · {total}</p></div>\
                 <p class=\"lede\">Value held inside an app rather than as a native balance. \
                 A balance read cannot see any of this, and these figures come from each \
                 Petal's own records.</p>\
                 <div class=\"table-wrap\"><table><caption>Positions reported by Petals\
                 </caption><thead><tr><th scope=\"col\">Position</th>\
                 <th scope=\"col\">Petal</th><th scope=\"col\">Scope</th>\
                 <th scope=\"col\">Observed value</th><th scope=\"col\">Evidence</th></tr>\
                 </thead><tbody>{cells}</tbody></table></div>",
                count = count_noun(positions.len(), "position", "positions"),
                total = html_escape(&if total > 0.0 {
                    money(Some(total))
                } else {
                    "No priced value".to_owned()
                }),
            ));
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

        // "Failed" overstates what these records show. They carry no result
        // and no transaction hash, so what is known is that nothing was sent.
        if failed > 0 {
            let one = failed == 1;
            body.push_str(&format!(
                "<section class=\"attention-strip\"><div><h3>Review what never sent</h3>\
                 <p>{count} in the captured history {verb} never broadcast, so no transaction \
                 for {pronoun} exists on any chain. Read the record before staging \
                 another.</p></div>\
                 <a href=\"activity.html\">Inspect {pronoun} →</a></section>",
                count = if one {
                    "One record".to_owned()
                } else {
                    format!("{failed} records")
                },
                verb = if one { "was" } else { "were" },
                pronoun = if one { "it" } else { "them" },
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

        let broadcast = actions.iter().filter(|a| a.tx_hash.is_some()).count();

        let mut body = String::new();
        body.push_str(&format!(
            "<section class=\"outcome-overview\" aria-label=\"Outcome summary\">\
             <a href=\"#ledger\"><span class=\"mini-outcome\">✓</span><strong>{sent}</strong>\
             <span>Broadcast by Bloom</span></a>\
             <a href=\"#ledger\"><span class=\"mini-outcome\">◷</span><strong>{pending}</strong>\
             <span>Staged, awaiting you</span></a>\
             <a href=\"#ledger\"><span class=\"mini-outcome\">✗</span><strong>{failed}</strong>\
             <span>Never broadcast</span></a></section>"
        ));

        body.push_str(&format!(
            "<section class=\"callout\"><strong>Broadcast is not the same as settled.</strong>\
             <p>These are Bloom's own records of what it submitted. {carry} a transaction \
             hash, which is evidence Bloom sent it — not evidence the chain accepted it. \
             These pages contact no block explorer, so no confirmation, receipt, or revert \
             reason is read here.</p></section>",
            carry = match broadcast {
                0 => "None of them carries".to_owned(),
                1 => "One of them carries".to_owned(),
                n => format!("{n} of them carry"),
            },
        ));

        if actions.is_empty() {
            body.push_str(
                "<section class=\"callout\"><strong>No recorded operations</strong>\
                 <p>The outbox that was checked holds no staged, sent, or failed record.</p>\
                 </section>",
            );
        } else {
            // Grouped by the day the intent was created: a ledger of 22 rows
            // is a wall of text without a date to anchor each run against.
            let mut ledger = String::new();
            let mut open_day: Option<String> = None;
            for action in &actions {
                let day = action
                    .when()
                    .map(format_utc_day)
                    .unwrap_or_else(|| "Undated".to_owned());
                if open_day.as_deref() != Some(day.as_str()) {
                    if open_day.is_some() {
                        ledger.push_str("</div>");
                    }
                    ledger.push_str(&format!(
                        "<div class=\"section-head\"><h3>{}</h3></div>\
                         <div class=\"activity-ledger\">",
                        html_escape(&day),
                    ));
                    open_day = Some(day);
                }
                ledger.push_str(&action.row());
            }
            if open_day.is_some() {
                ledger.push_str("</div>");
            }
            body.push_str(&format!(
                "<div class=\"section-head\" id=\"ledger\"><h2>Every record</h2>\
                 <p>{count}, newest first</p></div>{ledger}",
                count = count_noun(actions.len(), "operation", "operations"),
            ));
        }

        page(
            "Activity",
            "Your activity.",
            "Every transaction Bloom staged, broadcast, or never sent — read from its own \
             records, newest first.",
            ACTIVITY_HTML,
            &body,
        )
    }

    /// Public market context: what the provider reports is moving, and the
    /// full sample it was drawn from. Exposure is deliberately not implied —
    /// a row here is not a holding.
    async fn render_markets(&self) -> String {
        let mut body = String::new();
        let Some(rows) = self.market.markets().await else {
            body.push_str(
                "<section class=\"callout warn\"><strong>The market provider did not \
                 answer</strong><p>No rows were returned, so none are shown. A provider that \
                 does not answer is not a flat market.</p></section>",
            );
            return page(
                "Markets",
                "What is moving?",
                "Public provider observations, read by your daemon. Nothing here is a holding \
                 of yours, and nothing here is advice.",
                MARKETS_HTML,
                &body,
            );
        };

        let mut movers: Vec<&TokenMarket> =
            rows.iter().filter(|row| row.change_24h.is_some()).collect();
        movers.sort_by(|a, b| {
            b.change_24h
                .partial_cmp(&a.change_24h)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        if !movers.is_empty() {
            let tiles: String = movers
                .iter()
                .take(3)
                .map(|row| {
                    format!(
                        "<div class=\"mover-tile\"><h3>{symbol}</h3><strong>{change}</strong>\
                         <small>{volume} reported volume · 24h</small></div>",
                        symbol = html_escape(&row.symbol),
                        change = html_escape(&signed_percent(row.change_24h)),
                        volume = html_escape(
                            &row.volume_24h.map(compact_usd).unwrap_or("No".to_owned())
                        ),
                    )
                })
                .collect();
            body.push_str(&format!(
                "<div class=\"section-head\"><h2>What is moving around you</h2>\
                 <p>Largest signed 24h changes in the provider sample</p></div>\
                 <div class=\"mover-grid\">{tiles}</div>\
                 <p class=\"chart-note\">A price move shows direction, not its cause. Volume \
                 adds context; neither creates a required trade.</p>"
            ));
        }

        let cells: String = rows
            .iter()
            .map(|row| {
                format!(
                    "<tr><td data-label=\"Token\"><span class=\"asset-label\">{mark}\
                     <span><strong>{name}</strong><small>{symbol}</small></span></span></td>\
                     <td class=\"numeric\" data-label=\"Price\">{price}</td>\
                     <td class=\"numeric\" data-label=\"24h change\">{change}</td>\
                     <td class=\"numeric money\" data-label=\"24h volume\">{volume}</td></tr>",
                    mark = monogram(&row.symbol),
                    name = html_escape(&row.name),
                    symbol = html_escape(&row.symbol),
                    price = html_escape(&row.price.map(money_precise).unwrap_or("—".to_owned())),
                    change = html_escape(&signed_percent(row.change_24h)),
                    volume =
                        html_escape(&row.volume_24h.map(compact_usd).unwrap_or("—".to_owned())),
                )
            })
            .collect();
        body.push_str(&format!(
            "<div class=\"section-head\"><h2>Most traded in the provider sample</h2>\
             <p>{count} · 24h reported volume</p></div>\
             <div class=\"table-wrap\"><table><caption>Provider market sample</caption>\
             <thead><tr><th scope=\"col\">Token</th><th scope=\"col\">Price</th>\
             <th scope=\"col\">24h change</th><th scope=\"col\">24h volume</th></tr></thead>\
             <tbody>{cells}</tbody></table></div>",
            count = count_noun(rows.len(), "row", "rows"),
        ));
        body.push_str(
            "<section class=\"callout\"><strong>Price movement is not your personal \
             return.</strong><p>Volume is aggregate trading reported by the provider, not \
             liquidity available to you. Stablecoins stay in this ranking, and none of these \
             rows is a holding of yours.</p></section>",
        );

        page(
            "Markets",
            "What is moving?",
            "Public provider observations, read by your daemon. Nothing here is a holding of \
             yours, and nothing here is advice.",
            MARKETS_HTML,
            &body,
        )
    }

    /// Where the configured networks stand: whether each answered your own
    /// daemon, and what the public provider reports for its trading activity.
    async fn render_chains(&self) -> String {
        let portfolio = self.portfolio().await;
        let mut body = String::new();
        body.push_str(&portfolio.notices());

        let mut cells = String::new();
        for chain in self.sorted_chains() {
            let Some(client) = self.chains.get(&chain) else {
                continue;
            };
            let chain_id = client.spec().chain_id;
            let answered = portfolio
                .holdings
                .iter()
                .any(|holding| holding.chain == chain);
            let held: f64 = portfolio
                .holdings
                .iter()
                .filter(|holding| holding.chain == chain)
                .filter_map(|holding| holding.value)
                .sum();
            let volume = match market_data::chain_slug(chain_id) {
                Some(slug) => self.market.volume(slug).await,
                None => None,
            };
            cells.push_str(&format!(
                "<tr><td data-label=\"Network\">{label}</td>\
                 <td data-label=\"Read\">{read}</td>\
                 <td class=\"numeric money\" data-label=\"DEX volume\">{volume}</td>\
                 <td class=\"numeric\" data-label=\"Vs previous day\">{change}</td>\
                 <td class=\"numeric money\" data-label=\"Your priced assets\">{held}</td></tr>",
                label = asset_label(&self.network_label(&chain)),
                read = if answered {
                    "<span class=\"badge good\">Answered</span>"
                } else {
                    "<span class=\"badge warn\">No answer</span>"
                },
                volume = html_escape(
                    &volume
                        .as_ref()
                        .and_then(|v| v.total_24h)
                        .map(compact_usd)
                        .unwrap_or("Unavailable".to_owned())
                ),
                change = html_escape(&signed_percent(volume.as_ref().and_then(|v| v.change_1d))),
                held = html_escape(&if held > 0.0 {
                    money(Some(held))
                } else {
                    "—".to_owned()
                }),
            ));
        }

        body.push_str(&format!(
            "<div class=\"section-head\"><h2>Your configured networks</h2>\
             <p>Provider-reported 24h DEX volume; not a global chain ranking</p></div>\
             <div class=\"table-wrap\"><table><caption>Configured networks</caption><thead><tr>\
             <th scope=\"col\">Network</th><th scope=\"col\">Read</th>\
             <th scope=\"col\">DEX volume</th><th scope=\"col\">Vs previous day</th>\
             <th scope=\"col\">Your priced assets</th></tr></thead><tbody>{cells}</tbody>\
             </table></div>"
        ));
        body.push_str(
            "<section class=\"callout\"><strong>Different sources keep different \
             clocks.</strong><p>Trading activity is a provider's rolling aggregate, not a \
             synchronised UTC-day comparison with your own reads. Missing coverage is \
             \"Unavailable\", never zero, and a chain with no market for its native unit is \
             never valued.</p></section>",
        );

        page(
            "Chains",
            "Where your assets live.",
            "Connection comes from your own daemon; trading activity comes from a public \
             provider. Neither grants this wallet permission to transact.",
            CHAINS_HTML,
            &body,
        )
    }

    /// What everyone pays to use a network, over time, beside what a single
    /// operation currently costs.
    async fn render_fees(&self) -> String {
        let mut body = String::new();
        let mut collected: Vec<(String, market_data::FeeSeries)> = Vec::new();
        for chain in self.sorted_chains() {
            let Some(client) = self.chains.get(&chain) else {
                continue;
            };
            let chain_id = client.spec().chain_id;
            let Some(slug) = market_data::chain_slug(chain_id) else {
                continue;
            };
            let Some(series) = self.market.fees(slug).await else {
                continue;
            };
            if series.points.is_empty() && series.total_all_time.is_none() {
                continue;
            }
            collected.push((self.network_label(&chain), series));
        }
        // Ranked by the cumulative total, because that is the question worth
        // asking: how much use has this chain been worth paying for at all.
        collected.sort_by(|a, b| {
            b.1.total_all_time
                .partial_cmp(&a.1.total_all_time)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let total = |value: Option<f64>| match value {
            Some(value) => compact_usd(value),
            None => "Unavailable".to_owned(),
        };

        if collected.is_empty() {
            body.push_str(
                "<section class=\"callout warn\"><strong>No fee totals were returned</strong>\
                 <p>The public provider returned nothing for the configured networks, so none \
                 are shown. Missing history is not reported as zero.</p></section>",
            );
        } else {
            let rows: String = collected
                .iter()
                .map(|(label, series)| {
                    format!(
                        "<tr><td data-label=\"Network\">{label}</td>\
                         <td class=\"numeric money\" data-label=\"All time\"><strong>{all}\
                         </strong></td>\
                         <td class=\"numeric money\" data-label=\"Past year\">{year}</td>\
                         <td class=\"numeric money\" data-label=\"30 days\">{month}</td>\
                         <td class=\"numeric money\" data-label=\"7 days\">{week}</td>\
                         <td class=\"numeric money\" data-label=\"24 hours\">{day}</td></tr>",
                        label = asset_label(label),
                        all = html_escape(&total(series.total_all_time)),
                        year = html_escape(&total(series.total_1y)),
                        month = html_escape(&total(series.total_30d)),
                        week = html_escape(&total(series.total_7d)),
                        day = html_escape(&total(series.total_24h)),
                    )
                })
                .collect();
            body.push_str(&format!(
                "<div class=\"section-head\"><h2>Total paid to use each network</h2>\
                 <p>Cumulative fees · USD · most paid-for first</p></div>\
                 <div class=\"table-wrap\"><table><caption>Cumulative network fees</caption>\
                 <thead><tr><th scope=\"col\">Network</th><th scope=\"col\">All time</th>\
                 <th scope=\"col\">Past year</th><th scope=\"col\">30 days</th>\
                 <th scope=\"col\">7 days</th><th scope=\"col\">24 hours</th></tr></thead>\
                 <tbody>{rows}</tbody></table></div>\
                 <section class=\"callout\"><strong>This is what people paid, willingly, to \
                 use a chain.</strong><p>Cumulative fees are the clearest measure of whether \
                 a network has been worth using: every dollar here is someone choosing to pay \
                 for a block of its capacity. It says nothing about what your own next \
                 transaction will cost.</p></section>"
            ));

            let panels: String = collected
                .iter()
                .map(|(label, series)| {
                    format!(
                        "<section class=\"chart-panel\"><div class=\"chart-heading\">\
                         <div><p class=\"eyebrow\">Paid to use this network, all time</p>\
                         <h3>{label}</h3></div>\
                         <div class=\"chart-latest\"><strong>{all}</strong><br>\
                         <small>cumulative fees</small></div></div>\
                         <p class=\"eyebrow\">Daily totals · last 30 completed days</p>{chart}\
                         <p class=\"chart-note\">Total fees paid by everyone using this \
                         network, not your own transaction price.</p>{method}</section>",
                        label = html_escape(label),
                        all = html_escape(&total(series.total_all_time)),
                        chart = line_chart(
                            &series.points,
                            &format!("{label} daily network fees, 30 days"),
                            "USD / day",
                        ),
                        method = match &series.methodology {
                            Some(text) => format!(
                                "<details><summary>How these fees are measured</summary>\
                                 <p>{}</p><p>Provider totals. The current UTC day is excluded \
                                 from the daily chart because it is still accruing; gaps \
                                 remain gaps.</p></details>",
                                html_escape(text)
                            ),
                            None => String::new(),
                        },
                    )
                })
                .collect();
            body.push_str(&format!(
                "<div class=\"section-head\"><h2>How that accumulated</h2>\
                 <p>Daily totals behind each cumulative figure</p></div>{panels}"
            ));
        }

        body.push_str(
            "<section class=\"attention-strip\"><div><h3>Your own execution fees</h3>\
             <p>Activity records the gas limit and fee cap each operation was staged with. \
             These network totals are what everyone paid, not what you paid.</p></div>\
             <a href=\"activity.html\">Inspect your transactions →</a></section>",
        );

        page(
            "Fees",
            "Network fees, over time.",
            "What everyone pays to use a network. This is paid network usage, not a quote for \
             your next transaction.",
            FEES_HTML,
            &body,
        )
    }

    async fn render_policy(&self) -> String {
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
            "Policy",
            "Your signed policy.",
            "What each wallet is allowed to do, read from its signed policy. Not a complete \
             inventory of external approvals.",
            POLICY_HTML,
            &body,
        )
    }
}

/// A position a Petal reports, valued where the Petal's own units allow it.
struct PetalPosition {
    petal: String,
    label: String,
    scope: String,
    quantity: String,
    value: Option<f64>,
    source: String,
    note: String,
}

/// Shorten the numeric part of a `"<quantity> <UNIT>"` pair, leaving the unit
/// alone. Eighteen decimals swamp a cell whether or not a symbol follows.
fn short_quantity_with_unit(text: &str) -> String {
    match text.split_once(' ') {
        Some((quantity, unit)) => format!("{} {unit}", short_quantity(quantity)),
        None => short_quantity(text),
    }
}

/// Who a wallet is, as its own projection reports it. Carried alongside the
/// balances so the page can name a wallet without a second Broker read.
struct WalletSummary {
    id: String,
    address: Option<String>,
    kind: String,
    policy_version: String,
}

#[derive(Default)]
struct Portfolio {
    holdings: Vec<Holding>,
    /// `(wallet, chain)` pairs whose balance could not be read.
    unavailable: Vec<(String, String)>,
    wallets: Vec<WalletSummary>,
    projections_unavailable: bool,
    price_coverage_gap: bool,
    stale: bool,
}

/// One table of holdings, with every cell labelled for a narrow screen.
fn holdings_table(rows: &[&Holding], caption: &str) -> String {
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
                 <p>{note}</p><p>Exact quantity: <code>{exact}</code></p>\
                 <p><code>{source}</code></p></details></td></tr>",
                mark = monogram(&holding.symbol),
                symbol = html_escape(&holding.symbol),
                quantity = html_escape(&short_quantity(&holding.quantity)),
                exact = html_escape(&trim_trailing_zeros(&holding.quantity)),
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
    format!(
        "<div class=\"table-wrap\"><table><caption>{caption}</caption><thead><tr>\
         <th scope=\"col\">Asset / quantity</th><th scope=\"col\">Network</th>\
         <th scope=\"col\">Observed value</th><th scope=\"col\">Evidence</th></tr></thead>\
         <tbody>{cells}</tbody></table></div>",
        caption = html_escape(caption),
    )
}

impl Portfolio {
    /// Rows that hold something on a network whose native unit is a traded
    /// asset. These are the only rows that can carry a dollar value.
    fn funded(&self) -> Vec<&Holding> {
        self.holdings
            .iter()
            .filter(|holding| holding.is_funded() && !holding.is_off_market())
            .collect()
    }

    /// Rows holding a quantity on a chain with no market for its native unit:
    /// faucet and development balances, kept well away from money.
    fn off_market(&self) -> Vec<&Holding> {
        self.holdings
            .iter()
            .filter(|holding| holding.is_funded() && holding.is_off_market())
            .collect()
    }

    /// Networks that answered and reported nothing held.
    fn empty_networks(&self) -> Vec<&Holding> {
        self.holdings
            .iter()
            .filter(|holding| !holding.is_funded())
            .collect()
    }

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
    /// Whether this row holds anything at all. A network read successfully
    /// and found empty is reported, but it is not a holding to count or
    /// value.
    fn is_funded(&self) -> bool {
        self.amount > 0.0
    }

    /// Whether the native unit here is an asset with a market. A development
    /// or app chain may name its unit "ETH" and hand out an enormous faucet
    /// balance; that quantity is real but it is not money, and it must never
    /// share a table with funds that are.
    fn is_off_market(&self) -> bool {
        !native_asset_has_market(self.chain_id)
    }

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

/// What a staged intent recorded about a transaction, read from the outbox's
/// own `intent.json`. Parsed permissively out of generic JSON: an intent
/// written by a newer daemon must leave the row poorer, never blank.
#[derive(Default)]
struct Intent {
    wallet: Option<String>,
    chain: Option<String>,
    chain_id: Option<u64>,
    from: Option<String>,
    to: Option<String>,
    value_wei: Option<String>,
    action_kind: Option<String>,
    nonce: Option<u64>,
    gas_limit: Option<u64>,
    created_ms: Option<u64>,
    usd_value: Option<f64>,
    data_bytes: usize,
    petal_version: Option<String>,
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
    /// The facts the intent recorded, when one was readable.
    intent: Option<Intent>,
    /// Formatted native amount, present only when the intent moved value.
    amount: Option<String>,
    /// The broadcast hash Bloom kept. Its presence is what separates an
    /// operation that reached the network from one that never did.
    tx_hash: Option<String>,
    /// Whether this operation reached an approval ceremony.
    awaited_approval: bool,
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

    /// The outcome, stated as narrowly as the records support. "Failed" is
    /// not "reverted": these records carry no receipt at all, so what is
    /// known is that nothing was ever broadcast.
    fn label(&self) -> &'static str {
        match self.state {
            "sent" => "✓ Broadcast",
            "failed" if self.awaited_approval => "✗ Not approved",
            "failed" => "✗ Never broadcast",
            _ => "◷ Staged · needs you",
        }
    }

    /// A block-explorer link for this operation's broadcast hash, when the
    /// chain it ran on has a known explorer.
    fn explorer_url(&self) -> Option<String> {
        let hash = self.tx_hash.as_deref()?;
        let chain_id = self.intent.as_ref().and_then(|intent| intent.chain_id)?;
        explorer_tx_url(chain_id, hash)
    }

    /// When this operation happened, preferring the intent's own creation
    /// stamp over the mtime of the directory holding it.
    fn when(&self) -> Option<u64> {
        self.intent
            .as_ref()
            .and_then(|i| i.created_ms)
            .or(self.modified_ms)
    }

    /// A plain-language description of what the transaction does, built from
    /// the intent rather than the plan's title line.
    fn headline(&self) -> String {
        let Some(intent) = &self.intent else {
            return self.summary.clone();
        };
        let kind = intent.action_kind.as_deref().unwrap_or_default();
        let head = match (kind, &self.amount) {
            ("native_transfer", Some(amount)) => format!("Send {amount}"),
            ("native_transfer", None) => "Send (zero value)".to_owned(),
            ("contract_call", Some(amount)) => format!("Contract call with {amount}"),
            ("contract_call", None) => "Contract call".to_owned(),
            (_, Some(amount)) => format!("Move {amount}"),
            _ => self.summary.clone(),
        };
        match &intent.to {
            Some(to) => format!("{head} → {}", short_hex(to)),
            None => head,
        }
    }

    /// Why this row reads the way it does. The distinction that matters is
    /// whether anything reached the network, and only a broadcast hash
    /// settles that question.
    fn outcome_note(&self) -> &'static str {
        match self.state {
            "sent" if self.tx_hash.is_some() => {
                "Bloom broadcast this and kept the hash. Broadcast is not settled: read the \
                 chain's own receipt for the final outcome."
            }
            "sent" => "Bloom recorded this as sent but kept no transaction hash.",
            "failed" if self.awaited_approval => {
                "This reached an approval ceremony and was never approved, so it was never \
                 broadcast. No transaction for it exists on any chain."
            }
            "failed" => {
                "This never reached the network: the record carries no result and no \
                 transaction hash. Nothing was broadcast."
            }
            _ => "Staged and waiting for your review. Nothing has been broadcast.",
        }
    }

    fn row(&self) -> String {
        let mut meta = String::new();
        let mut fact = |text: String| {
            meta.push_str(&format!("<span>{}</span>", html_escape(&text)));
        };
        if let Some(wallet) = &self.wallet {
            fact(format!("wallet {wallet}"));
        }
        if let Some(chain) = &self.chain {
            fact(chain.clone());
        }
        fact(match self.when() {
            Some(ms) => format_utc_ms(ms),
            None => "Time unavailable".to_owned(),
        });
        if let Some(petal) = &self.petal {
            fact(petal.clone());
        }
        // The hash belongs in the row itself, not buried in the details: it
        // is the one value a person takes elsewhere to look the tx up.
        if let Some(hash) = &self.tx_hash {
            let short = html_escape(&short_hex(hash));
            match self.explorer_url() {
                Some(url) => meta.push_str(&format!(
                    "<span><a href=\"{url}\" rel=\"noreferrer noopener\"><code>{short}</code></a>\
                     </span>",
                    url = html_escape(&url),
                )),
                None => meta.push_str(&format!("<span><code>{short}</code></span>")),
            }
        }

        let denial = match &self.denial {
            Some(reason) => format!("<p>{}</p>", html_escape(reason)),
            None => String::new(),
        };

        let mut facts = String::new();
        let mut row_fact = |label: &str, value: String| {
            facts.push_str(&format!(
                "<div><dt>{}</dt><dd>{}</dd></div>",
                html_escape(label),
                value,
            ));
        };
        row_fact("Outcome", html_escape(self.outcome_note()));
        if let Some(hash) = &self.tx_hash {
            row_fact(
                "Transaction hash",
                format!("<code>{}</code>", html_escape(hash)),
            );
            if let Some(url) = self.explorer_url() {
                row_fact(
                    "Block explorer",
                    format!(
                        "<a href=\"{url}\" rel=\"noreferrer noopener\">View transaction ↗</a>",
                        url = html_escape(&url),
                    ),
                );
            }
        }
        if let Some(intent) = &self.intent {
            if let Some(from) = &intent.from {
                row_fact("From", format!("<code>{}</code>", html_escape(from)));
            }
            if let Some(to) = &intent.to {
                row_fact("To", format!("<code>{}</code>", html_escape(to)));
            }
            row_fact(
                "Value",
                html_escape(self.amount.as_deref().unwrap_or("None — zero value")),
            );
            if let Some(kind) = &intent.action_kind {
                row_fact("Kind", html_escape(kind));
            }
            if intent.data_bytes > 0 {
                row_fact(
                    "Calldata",
                    html_escape(&count_noun(intent.data_bytes, "byte", "bytes")),
                );
            }
            if let Some(nonce) = intent.nonce {
                row_fact("Nonce", nonce.to_string());
            }
            if let Some(gas) = intent.gas_limit {
                row_fact("Gas limit", html_escape(&thousands_int(gas)));
            }
            if let Some(usd) = intent.usd_value {
                row_fact("Value when staged", html_escape(&money(Some(usd))));
            }
            if let Some(version) = &intent.petal_version {
                row_fact("Petal version", html_escape(version));
            }
        }
        row_fact("State", html_escape(self.state));
        row_fact(
            "Operation",
            format!("<code>{}</code>", html_escape(&self.id)),
        );
        row_fact(
            "Record",
            format!(
                "<code>{}</code>",
                html_escape(&format!("/outbox/{}/{}/", self.state, self.id))
            ),
        );

        format!(
            "<article class=\"activity-row {class}\">\
             <div class=\"outcome-symbol\" aria-hidden=\"true\">{glyph}</div>\
             <div class=\"activity-description\"><h3>{headline}</h3>\
             <div class=\"activity-meta\">{meta}</div>{denial}\
             <details><summary>Operation details</summary>\
             <dl class=\"receipt-facts\">{facts}</dl></details></div>\
             <div class=\"activity-outcome\"><span class=\"outcome-label\">{label}</span>\
             </div></article>",
            class = self.status_class(),
            glyph = self.glyph(),
            headline = html_escape(&self.headline()),
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
/// One string field out of a JSON document, absent when the document does not
/// parse or the field is empty. Read as generic JSON so these pages do not
/// bind themselves to another crate's schema.
fn json_field(text: &str, key: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value
        .get(key)
        .and_then(|field| field.as_str())
        .map(str::to_owned)
        .filter(|found| !found.is_empty())
}

/// The facts an outbox `intent.json` records. Every field is optional: a
/// record written by a newer daemon must make a row poorer, never blank.
fn parse_intent(text: &str) -> Option<Intent> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let string = |key: &str| {
        value
            .get(key)
            .and_then(|field| field.as_str())
            .map(str::to_owned)
            .filter(|found| !found.is_empty())
    };
    let number = |key: &str| value.get(key).and_then(|field| field.as_u64());
    Some(Intent {
        wallet: string("wallet"),
        chain: string("chain"),
        chain_id: number("chain_id"),
        from: string("from"),
        to: string("to"),
        value_wei: string("value_wei"),
        action_kind: string("action_kind"),
        nonce: number("nonce"),
        gas_limit: number("gas_limit"),
        created_ms: number("created_ms"),
        usd_value: value.get("usd_value").and_then(|field| field.as_f64()),
        // Calldata is reported as a size. Rendering the bytes themselves
        // invites squinting at hex that the plan already summarises.
        data_bytes: string("data_hex")
            .map(|hex| hex.trim_start_matches("0x").len() / 2)
            .unwrap_or(0),
        petal_version: value
            .pointer("/execution_origin/petal_version")
            .and_then(|field| field.as_str())
            .map(str::to_owned),
    })
}

/// `0.010000000000000000` reads as noise. Trim what a fixed-decimal
/// rendering leaves, without turning an integer into `1.`.
fn trim_trailing_zeros(text: &str) -> String {
    if !text.contains('.') {
        return text.to_owned();
    }
    let trimmed = text.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// A quantity short enough to sit in a table cell. A faucet chain can hand out
/// a balance sixty digits long, and an ordinary native balance carries
/// eighteen decimals; both wrap into a blob that swamps every real row. The
/// exact figure stays in the row's evidence.
fn short_quantity(text: &str) -> String {
    let trimmed = trim_trailing_zeros(text);
    if !trimmed.is_ascii() {
        return trimmed;
    }
    let (whole, fraction) = match trimmed.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (trimmed.as_str(), ""),
    };
    // A faucet quantity becomes a magnitude: sixty digits of precision say
    // nothing that a power of ten does not.
    if whole.len() > 15 {
        let lead: String = whole.chars().take(3).collect();
        return format!("≈{}.{} × 10^{}", &lead[..1], &lead[1..], whole.len() - 1);
    }
    // Otherwise keep six *significant* fractional digits, counted from the
    // first non-zero. Cutting at six decimal places instead would round a
    // small native balance away to nothing.
    const SIGNIFICANT: usize = 6;
    let leading_zeros = fraction.len() - fraction.trim_start_matches('0').len();
    let keep = leading_zeros
        .saturating_add(SIGNIFICANT)
        .min(fraction.len());
    if keep == fraction.len() {
        return trimmed;
    }
    format!(
        "≈{}",
        trim_trailing_zeros(&format!("{whole}.{}", &fraction[..keep]))
    )
}

/// A line chart as static SVG, in the shape the stylesheet already ships: a
/// 600×170 viewBox, three grid rules, one path, a dot per observation, and a
/// cursor on the latest point. These pages carry no script, so the chart is
/// drawn once, here.
///
/// A gap wider than two days starts a new subpath. Joining across missing
/// days with a straight line would draw observations that were never made.
fn line_chart(points: &[(u64, f64)], label: &str, unit: &str) -> String {
    if points.is_empty() {
        return "<p class=\"chart-note\">No historical observations were returned. Missing \
                data is not drawn as zero.</p>"
            .to_owned();
    }
    let peak = points
        .iter()
        .map(|(_, value)| *value)
        .fold(0.0_f64, f64::max)
        * 1.1;
    let top = if peak > 0.0 { peak } else { 1.0 };
    let start = points.first().map(|(ts, _)| *ts).unwrap_or(0);
    let end = points.last().map(|(ts, _)| *ts).unwrap_or(start);
    let span = end.saturating_sub(start).max(1) as f64;
    const GAP_SECS: u64 = 2 * 86_400;

    let coords: Vec<(f64, f64)> = points
        .iter()
        .map(|(ts, value)| {
            (
                (ts.saturating_sub(start) as f64) / span * 600.0,
                160.0 - (value / top) * 150.0,
            )
        })
        .collect();

    let mut path = String::new();
    let mut previous: Option<u64> = None;
    for ((ts, _), (x, y)) in points.iter().zip(&coords) {
        let command = match previous {
            Some(last) if ts.saturating_sub(last) <= GAP_SECS => 'L',
            _ => 'M',
        };
        path.push_str(&format!("{command}{x:.2},{y:.2} "));
        previous = Some(*ts);
    }
    let dots: String = coords
        .iter()
        .map(|(x, y)| format!("<circle cx=\"{x:.2}\" cy=\"{y:.2}\" r=\"2.5\"/>"))
        .collect();
    let (last_x, last_y) = coords.last().copied().unwrap_or((0.0, 0.0));
    let rows: String = points
        .iter()
        .map(|(ts, value)| {
            format!(
                "<tr><td data-label=\"Date\">{date} UTC</td>\
                 <td class=\"numeric\" data-label=\"{unit}\">{value}</td></tr>",
                date = html_escape(&format_utc_day(ts * 1000)),
                unit = html_escape(unit),
                value = html_escape(&chart_value(*value, unit)),
            )
        })
        .collect();

    format!(
        "<div class=\"history-chart\"><div class=\"chart-scale\"><span>{peak}</span>\
         <span>{unit}</span></div>\
         <svg class=\"time-chart\" viewBox=\"0 0 600 170\" preserveAspectRatio=\"none\" \
         role=\"img\" aria-label=\"{label}\">\
         <path class=\"chart-grid\" d=\"M0 10H600 M0 85H600 M0 160H600\"/>\
         <path class=\"chart-line\" d=\"{path}\"/>\
         <g class=\"chart-dots\">{dots}</g>\
         <line class=\"chart-cursor\" x1=\"{last_x:.2}\" x2=\"{last_x:.2}\" y1=\"0\" y2=\"160\"/>\
         <circle class=\"chart-selected\" cx=\"{last_x:.2}\" cy=\"{last_y:.2}\" r=\"5\"/></svg>\
         <span class=\"chart-zero\">0</span>\
         <div class=\"chart-axis\"><span>{first_day}</span><span>{last_day} UTC</span></div>\
         <output class=\"chart-readout\">{readout}</output>\
         <details><summary>Exact observations · {count}</summary>\
         <div class=\"table-wrap\"><table><caption>{label}</caption><thead><tr>\
         <th scope=\"col\">Date</th><th scope=\"col\">{unit}</th></tr></thead>\
         <tbody>{rows}</tbody></table></div></details></div>",
        peak = html_escape(&chart_value(top, unit)),
        unit = html_escape(unit),
        label = html_escape(label),
        first_day = html_escape(&format_utc_day(start * 1000)),
        last_day = html_escape(&format_utc_day(end * 1000)),
        readout = html_escape(&format!(
            "{} UTC · {}",
            format_utc_day(end * 1000),
            chart_value(points.last().map(|(_, value)| *value).unwrap_or(0.0), unit),
        )),
        count = points.len(),
    )
}

/// One chart value, in whatever unit the axis is labelled with.
fn chart_value(value: f64, unit: &str) -> String {
    if unit.starts_with("USD") {
        compact_usd(value)
    } else {
        trim_trailing_zeros(&format!("{value:.4}"))
    }
}

/// `$254.84K`. A daily fee total runs to seven figures, which does not fit a
/// chart axis; the exact figure stays in the observations table.
fn compact_usd(value: f64) -> String {
    let abs = value.abs();
    let (scaled, suffix) = if abs >= 1e12 {
        (value / 1e12, "T")
    } else if abs >= 1e9 {
        (value / 1e9, "B")
    } else if abs >= 1e6 {
        (value / 1e6, "M")
    } else if abs >= 1e3 {
        (value / 1e3, "K")
    } else {
        (value, "")
    };
    format!("${scaled:.2}{suffix}")
}

/// `+45.78%`, or an explicit absence. A change the provider did not report is
/// not a flat market.
fn signed_percent(value: Option<f64>) -> String {
    match value {
        Some(value) => format!(
            "{sign}{value:.2}%",
            sign = if value >= 0.0 { "+" } else { "" }
        ),
        None => "Not available".to_owned(),
    }
}

/// A price, which unlike a total needs sub-cent resolution to say anything
/// honest about an asset trading below a dollar.
fn money_precise(value: f64) -> String {
    if value != 0.0 && value.abs() < 1.0 {
        format!("${value:.4}")
    } else {
        money(Some(value))
    }
}

/// `0x4b81a384…eb1748` — enough to recognise, short enough to sit in a row;
/// the full value stays in the row's details. A non-ASCII value is returned
/// whole, because slicing it by byte could split a character.
fn short_hex(value: &str) -> String {
    let clean = value.trim();
    if !clean.is_ascii() || clean.len() <= 16 {
        return clean.to_owned();
    }
    format!("{}…{}", &clean[..8], &clean[clean.len() - 6..])
}

/// Group an integer for reading: `535693` → `535,693`.
fn thousands_int(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// `11 Sep 2026`, for grouping a ledger by day.
fn format_utc_day(ms: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (year, month, day) = civil_from_days(((ms / 1000) as i64).div_euclid(86_400));
    format!(
        "{day:02} {month} {year}",
        month = MONTHS
            .get((month.saturating_sub(1)) as usize)
            .copied()
            .unwrap_or("???"),
    )
}

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
const NATIVE_ASSET_MARKETS: &[(u64, &str)] = &[
    (1, "coingecko:ethereum"),                  // Ethereum
    (10, "coingecko:ethereum"),                 // OP Mainnet
    (56, "coingecko:binancecoin"),              // BNB Smart Chain
    (100, "coingecko:xdai"),                    // Gnosis
    (137, "coingecko:polygon-ecosystem-token"), // Polygon
    (999, "coingecko:hyperliquid"),             // HyperEVM
    (8453, "coingecko:ethereum"),               // Base
    (42161, "coingecko:ethereum"),              // Arbitrum One
    (43114, "coingecko:avalanche-2"),           // Avalanche C-Chain
    (59144, "coingecko:ethereum"),              // Linea
    (81457, "coingecko:ethereum"),              // Blast
    (534352, "coingecko:ethereum"),             // Scroll
];

/// The market key for a chain's native unit, when that unit is a traded asset.
///
/// A bare symbol is not a usable key: asking the price source for `eth`
/// answers with no coin at all, which left every row silently unpriced. Every
/// entry here is a `coingecko:` slug, which the source does resolve.
fn native_asset_market(chain_id: u64) -> Option<&'static str> {
    NATIVE_ASSET_MARKETS
        .iter()
        .find(|(id, _)| *id == chain_id)
        .map(|(_, key)| *key)
}

fn native_asset_has_market(chain_id: u64) -> bool {
    native_asset_market(chain_id).is_some()
}

/// Block explorers, keyed on chain id. The hash is the one value a person
/// carries elsewhere, and without a link they have to go and find the right
/// explorer themselves. Following one is the reader's own choice: these pages
/// never fetch from an explorer, and `referrer=no-referrer` keeps the visit
/// unattributed.
const EXPLORERS: &[(u64, &str)] = &[
    (1, "https://etherscan.io/tx/"),
    (10, "https://optimistic.etherscan.io/tx/"),
    (56, "https://bscscan.com/tx/"),
    (100, "https://gnosisscan.io/tx/"),
    (137, "https://polygonscan.com/tx/"),
    (4663, "https://robinhoodchain.blockscout.com/tx/"),
    (8453, "https://basescan.org/tx/"),
    (42161, "https://arbiscan.io/tx/"),
    (43114, "https://snowtrace.io/tx/"),
    (59144, "https://lineascan.build/tx/"),
];

fn explorer_tx_url(chain_id: u64, hash: &str) -> Option<String> {
    EXPLORERS
        .iter()
        .find(|(id, _)| *id == chain_id)
        .map(|(_, base)| format!("{base}{hash}"))
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
            // Likewise for public market context: an unreachable provider
            // must leave a panel saying so, never a zero.
            MarketData::with_base_url("http://127.0.0.1:1"),
        );
        Fixture {
            handler,
            _tmp: tmp,
            outbox_root,
        }
    }

    /// A stand-in for the `petals/` router serving two Petals' leaves.
    /// Positions are read through the `Handler` trait, so a stub proves the
    /// reader and the rendering without standing up a Petal runtime.
    struct StubPetals;

    #[async_trait]
    impl Handler for StubPetals {
        async fn lookup(&self, _path: &VfsPath) -> Result<Entry, HandlerError> {
            Ok(Entry::dir(""))
        }

        async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            let text = path.to_string_path();
            let body = if text.ends_with("clearinghouse.json") {
                "{\"marginSummary\":{\"accountValue\":\"5.259383\"}}"
            } else if text.ends_with("unspent.json") {
                "{\"asset\":\"eth\",\"value\":\"9950000000000000\",\
                 \"status\":\"confirmed\",\"spent\":false}"
            } else if text.ends_with("spent.json") {
                "{\"asset\":\"eth\",\"value\":\"9950000000000000\",\
                 \"status\":\"confirmed\",\"spent\":true}"
            } else {
                return Err(HandlerError::not_found(text));
            };
            Ok(body.as_bytes().to_vec())
        }

        async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            let text = path.to_string_path();
            // Deepest first: "notes/dev" also ends with "notes" prefixes.
            let names: &[&str] = if text.ends_with("notes/dev") {
                &["unspent.json", "spent.json"]
            } else if text.ends_with("privacy-pools/notes") {
                &["dev"]
            } else {
                return Err(HandlerError::not_found(text));
            };
            Ok(names.iter().map(|name| Entry::file(name)).collect())
        }
    }

    /// A read-only view of a real `petals/` directory on disk, so the pages
    /// can be rendered against a live Bloom home. Development aid only: in
    /// production the section reads the mounted router, which computes leaves
    /// this cannot.
    struct FsPetals(std::path::PathBuf);

    #[async_trait]
    impl Handler for FsPetals {
        async fn lookup(&self, _path: &VfsPath) -> Result<Entry, HandlerError> {
            Ok(Entry::dir(""))
        }

        async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            let target = self.0.join(path.segments().join("/"));
            std::fs::read(&target).map_err(|error| HandlerError::not_found(error.to_string()))
        }

        async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            let target = self.0.join(path.segments().join("/"));
            let listing = std::fs::read_dir(&target)
                .map_err(|error| HandlerError::not_found(error.to_string()))?;
            let mut entries = Vec::new();
            for entry in listing {
                let entry = entry.map_err(|error| HandlerError::backend(error.to_string()))?;
                let name = entry.file_name().to_string_lossy().to_string();
                entries.push(if entry.path().is_dir() {
                    Entry::dir(&name)
                } else {
                    Entry::file(&name)
                });
            }
            Ok(entries)
        }
    }

    #[tokio::test]
    async fn petal_positions_reach_the_wallets_page() {
        let fixture = fixture();
        let handler = fixture.handler.clone().with_petals(Arc::new(StubPetals));
        let html = render(&handler, WALLETS_HTML).await;
        assert!(html.contains("Petal positions"), "{html}");
        // The venue denominates equity in dollars itself, so it is priced
        // even though no quote source is reachable in this fixture.
        assert!(html.contains("Trading account equity"), "{html}");
        assert!(html.contains("$5.26"), "{html}");
        // One unspent deposit. A spent note is gone and must not be counted.
        assert!(html.contains("1 unspent deposit"), "{html}");
        assert!(html.contains("0.00995 ETH"), "{html}");
        assert!(
            !html.contains("2 unspent deposits"),
            "a spent note must not be counted: {html}"
        );
    }

    #[tokio::test]
    async fn without_a_petals_mount_no_position_section_appears() {
        // Absent the mount the section is simply not there, rather than an
        // empty table implying there are no positions.
        let html = render(&fixture().handler, WALLETS_HTML).await;
        assert!(
            !html.contains("Positions reported by Petals"),
            "with no mount there is no position table: {html}"
        );
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

    /// Stage an action together with the extra records a real outbox keeps
    /// beside the plan.
    fn stage_files(fixture: &Fixture, state: &str, id: &str, plan: &str, files: &[(&str, &str)]) {
        stage(fixture, state, id, plan);
        let dir = fixture.outbox_root.join(state).join(id);
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
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
        // "Failed" would overstate it: these records carry no result and no
        // hash, so the honest claim is that nothing was ever sent.
        assert!(
            next.contains("One record in the captured history was never broadcast"),
            "a single record must agree in number: {next}"
        );
        // A staged row must never be dressed up as an approval control.
        assert!(next.contains("Approving happens in Bloom, not here"));

        let activity = render(&fixture.handler, ACTIVITY_HTML).await;
        for summary in ["Staged tx 0001-62058", "Send 0.05 ETH", "Enso operation"] {
            assert!(activity.contains(summary), "{summary} missing: {activity}");
        }
        assert!(activity.contains("status-success"));
        assert!(activity.contains("status-failed"));
        assert!(activity.contains("status-pending"));
        assert!(activity.contains("Broadcast is not the same as settled"));
    }

    #[tokio::test]
    async fn a_broadcast_record_surfaces_the_hash_it_kept() {
        let fixture = fixture();
        stage_files(
            &fixture,
            "sent",
            "evm-0100",
            "# Send 0.01 ETH\n\nWallet: primary\nChain:  ethereum (id 1)\n",
            &[
                (
                    "intent.json",
                    "{\"chain\":\"ethereum\",\"from\":\"0x5c3d61167D9dfa2E4171416D084842\
                     20F1374456\",\"to\":\"0x6818809EefCe719E480a7526D76bD3e561526b46\",\
                     \"value_wei\":\"10000000000000000\",\"action_kind\":\"native_transfer\",\
                     \"nonce\":2,\"gas_limit\":535693}",
                ),
                (
                    "result.json",
                    "{\"tx_hash\":\"0x4b81a384e07d30624b9dc420b0f1c12e4f9a1d3cf027bdd4a1ab8\
                     68225eb1748\"}",
                ),
            ],
        );
        let html = render(&fixture.handler, ACTIVITY_HTML).await;
        // The hash is the one value a person carries elsewhere: short in the
        // row, whole in the record.
        assert!(html.contains("0x4b81a3…eb1748"), "{html}");
        assert!(
            html.contains("0x4b81a384e07d30624b9dc420b0f1c12e4f9a1d3cf027bdd4a1ab868225eb1748"),
            "the full hash belongs in the details: {html}"
        );
        assert!(html.contains("Broadcast by Bloom"), "{html}");
        // Counterparty and nonce come from the intent, not the plan title.
        assert!(
            html.contains("0x6818809EefCe719E480a7526D76bD3e561526b46"),
            "{html}"
        );
    }

    #[tokio::test]
    async fn a_record_that_never_sent_is_never_called_reverted() {
        let fixture = fixture();
        stage_files(
            &fixture,
            "failed",
            "evm-0200",
            "# Enso operation\n\nChain:  ethereum (id 1)\n",
            &[("approval_challenge.json", "{\"action_id\":\"evm-0200\"}")],
        );
        let html = render(&fixture.handler, ACTIVITY_HTML).await;
        // These records carry no result and no hash. "Reverted" would claim
        // the chain rejected something that was never submitted to it.
        assert!(
            !html.contains("reverted"),
            "nothing here is evidence of a revert: {html}"
        );
        assert!(html.contains("Not approved"), "{html}");
        assert!(html.contains("never broadcast"), "{html}");
    }

    #[test]
    fn a_hash_is_short_in_a_row_and_quantities_lose_their_padding() {
        let hash = "0x4b81a384e07d30624b9dc420b0f1c12e4f9a1d3cf027bdd4a1ab868225eb1748";
        assert_eq!(short_hex(hash), "0x4b81a3…eb1748");
        // Short enough to read whole is left alone.
        assert_eq!(short_hex("0xabc"), "0xabc");
        assert_eq!(trim_trailing_zeros("0.010000000000000000"), "0.01");
        assert_eq!(trim_trailing_zeros("1.000000"), "1");
        assert_eq!(trim_trailing_zeros("42"), "42");
        assert_eq!(thousands_int(535_693), "535,693");
        assert_eq!(format_utc_day(1_789_158_600_000), "11 Sep 2026");
        // A faucet chain hands out balances sixty digits long. Left whole,
        // one row wraps into a blob that swamps every real holding.
        assert_eq!(
            short_quantity(
                "4242424242424242424242424242424242424242424242424242424242.424242424242424242"
            ),
            "≈4.24 × 10^57"
        );
        assert_eq!(short_quantity("42"), "42");
        assert_eq!(short_quantity("0.010000000000000000"), "0.01");
        // Eighteen decimals is the ordinary case, and it swamps a cell just
        // as thoroughly. Six significant digits is enough to recognise.
        assert_eq!(short_quantity("4.295587231758644167"), "≈4.295587");
        // Counted from the first non-zero: cutting at six decimal places
        // would round a small native balance away to 0.000019.
        assert_eq!(short_quantity("0.000019577151776"), "≈0.0000195771");
        // Already short enough is left exactly as it is, with no "≈".
        assert_eq!(short_quantity("1.5"), "1.5");
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
    async fn policy_reports_a_deny_all_policy_as_denied() {
        // The test projection carries an empty destination allow-set, which is
        // Broker's fail-closed state, not an absence of policy.
        let html = render(&fixture().handler, POLICY_HTML).await;
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
        for page in [WALLETS_HTML, POLICY_HTML] {
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
        // Deliberately not a page: these views observe, and never offer a
        // send surface, so `send.html` must stay unserved.
        let missing = VfsPath::parse("send.html").unwrap();
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
    fn every_market_key_is_one_the_price_source_can_resolve() {
        // Asking the price source for a bare symbol answers with no coin at
        // all, which left every row silently unpriced. Only `coingecko:`
        // slugs resolve, so every entry must be one and must parse.
        for (chain_id, key) in NATIVE_ASSET_MARKETS {
            assert!(
                key.starts_with("coingecko:"),
                "chain {chain_id} uses {key}, which the price source cannot resolve"
            );
            assert!(
                CoinId::parse(key).is_ok(),
                "chain {chain_id} key {key} must parse"
            );
        }
        assert_eq!(native_asset_market(1), Some("coingecko:ethereum"));
        assert_eq!(native_asset_market(43114), Some("coingecko:avalanche-2"));
        // A faucet chain naming its unit "ETH" is still not ether.
        assert_eq!(native_asset_market(4217), None);
    }

    #[test]
    fn a_broadcast_hash_links_to_its_own_chain_explorer() {
        assert_eq!(
            explorer_tx_url(1, "0xabc").as_deref(),
            Some("https://etherscan.io/tx/0xabc")
        );
        assert_eq!(
            explorer_tx_url(8453, "0xabc").as_deref(),
            Some("https://basescan.org/tx/0xabc")
        );
        // An unknown chain gets no link rather than one pointing at the
        // wrong chain's explorer.
        assert_eq!(explorer_tx_url(4217, "0xabc"), None);
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
        // Optional real sources, so these pages can be reviewed against a
        // real Bloom home rather than a synthetic wallet:
        //   VIEWS_OUTBOX=~/.bloom/central_outbox
        //   VIEWS_PROJECTION=~/bloom/wallets/<wallet>/projection.json
        //   VIEWS_CONFIG=~/.bloom/config.toml   (real chains, real balances)
        //   VIEWS_REAL_PRICES=1                 (reach the live price source)
        let real_outbox = std::env::var("VIEWS_OUTBOX").ok();
        let tmp = tempfile::tempdir().unwrap();
        let outbox_root = match &real_outbox {
            Some(path) => std::path::PathBuf::from(path),
            None => tmp.path().join("central_outbox"),
        };
        let outbox = Arc::new(super::super::outbox::OutboxHandler::new(
            super::super::outbox::CentralOutbox::new(outbox_root.clone()),
        ));
        let chains = ChainRegistry::new();
        match std::env::var("VIEWS_CONFIG") {
            Ok(path) => {
                let config = bloom_proto::Config::load(std::path::Path::new(&path)).unwrap();
                for spec in config.chains.values() {
                    if let Ok(client) = bloom_evm::ChainClient::new(spec.clone()) {
                        chains.add(client);
                    }
                }
            }
            Err(_) => {
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
            }
        }
        let projections = match std::env::var("VIEWS_PROJECTION") {
            Ok(path) => crate::test_support::wallet_projection_reader_from(
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap(),
            ),
            Err(_) => crate::test_support::wallet_projection_reader("everyday", ADDRESS),
        };
        let prices = match std::env::var("VIEWS_REAL_PRICES") {
            Ok(_) => bloom_prices::PricesClient::new(),
            Err(_) => bloom_prices::PricesClient::with_base_url("http://127.0.0.1:1"),
        };
        let market = match std::env::var("VIEWS_REAL_MARKETS") {
            Ok(_) => MarketData::new(),
            Err(_) => MarketData::with_base_url("http://127.0.0.1:1"),
        };
        let handler = ViewsHandler::new(projections, chains, prices, outbox, market);
        // VIEWS_PETALS=~/bloom/petals renders Petal positions from a live
        // home. Several Petal leaves are computed by the router rather than
        // stored, so a filesystem read sees fewer of them than production.
        let handler = match std::env::var("VIEWS_PETALS") {
            Ok(root) => handler.with_petals(Arc::new(FsPetals(root.into()))),
            Err(_) => handler,
        };
        let staged = Fixture {
            handler: handler.clone(),
            _tmp: tmp,
            outbox_root,
        };
        // A real outbox brings its own records; only the synthetic run needs
        // these staged in.
        if real_outbox.is_none() {
            stage(
                &staged,
                "pending",
                "evm-54ea2d13844badc5fb1082c036711257",
                "# Staged tx 0001-62058\n\nWallet: everyday\nChain:  ethereum (id 1)\n\n\
                 ## Policy\n- [Deny] balance.native_funds: account has 0 ETH on Ethereum \
                 Mainnet; requires up to 0.010084679918 ETH. Fund the account and restage \
                 this transaction before approving.\n",
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
        }

        std::fs::create_dir_all(&out).unwrap();
        for (page, _) in PAGES {
            let html = render(&staged.handler, page).await;
            std::fs::write(std::path::Path::new(&out).join(page), html).unwrap();
        }
        std::fs::write(std::path::Path::new(&out).join(BLOOM_CSS_NAME), BLOOM_CSS).unwrap();
    }
}
