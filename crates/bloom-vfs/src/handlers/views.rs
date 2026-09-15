//! `views/...` — read-only HTML pages meant for a person, not an agent.
//!
//! Paths handled:
//! - `views/`                 — list the available pages
//! - `views/index.html`       — Today: what you hold, what needs you, what
//!   happened recently
//! - `views/wallets.html`     — native balances per wallet, with valuation
//! - `views/receive.html`     — receiving addresses grouped by wallet
//! - `views/next-moves.html`  — staged operations awaiting your review
//! - `views/activity.html`    — what completed, failed, or is still staged
//! - `views/chains.html`      — Networks: usage, fees, and balances in one
//! - `views/fees.html`        — an alias of the Networks page, for bookmarks
//! - `views/markets.html`     — public market context, not your holdings
//! - `views/contacts.html`    — saved contacts and observed transfer recipients
//! - `views/policy.html`      — what each wallet is allowed to do
//! - `views/bloom.css`        — the shared Bloom stylesheet (compiled in)
//! - `views/bloom.js`         — local, optional sorting for Networks
//! - `views/AGENTS.md`        — how an agent should use these pages
//!
//! These pages observe. Nothing here stages, approves, or executes an action,
//! and their only script is a local Networks sorter: the mount serves them as ordinary files, so a
//! browser opens one straight off the filesystem. Matching Bloom's visual
//! language does not make a page a trusted authorization surface — passkeys
//! and private input stay in Broker's own page.
//!
//! A page always renders. An unavailable source becomes visible prose or an
//! "Unavailable" cell, never a fabricated zero and never an `EIO` that makes
//! `cat` of the whole page fail. A missing price leaves a row unpriced rather
//! than valuing it at zero, and a quote older than an hour does not price
//! anything at all.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bloom_evm::ChainRegistry;
use bloom_machine_client::{ProjectionFreshness, WalletProjection, WalletProjectionReader};
use bloom_prices::{CoinId, PricesClient};
use bloom_proto::{AddressBook, checksum_address, parse_address};

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
const CONTACTS_HTML: &str = "contacts.html";
const BLOOM_CSS_NAME: &str = "bloom.css";
const BLOOM_JS_NAME: &str = "bloom.js";
const BLOOM_JS: &str = include_str!("../assets/bloom.js");
const AGENTS_MD_NAME: &str = "AGENTS.md";
const ICONS_DIR: &str = "icons";

/// Every page, in reading order. Drives both the directory listing and the
/// navigation, so a link can never point at a page that is not served.
const PAGES: &[(&str, &str)] = &[
    (INDEX_HTML, "Today"),
    (WALLETS_HTML, "Wallets"),
    (ACTIVITY_HTML, "Activity"),
    (CHAINS_HTML, "Networks"),
    (MARKETS_HTML, "Markets"),
    (NEXT_MOVES_HTML, "Next moves"),
    (CONTACTS_HTML, "Contacts"),
    (RECEIVE_HTML, "Receive"),
    (POLICY_HTML, "Policy"),
];

/// The mount re-reads on every browser access (`actimeo=0`), so a short
/// router TTL keeps a reload burst from re-reading balances per request.
/// The compiled-in assets need no cache entry at all.
const PAGE_TTL: Duration = Duration::from_secs(5);

/// One unreachable chain must not hold up a page. Each balance read gets its
/// own budget and an expired one renders as "Unavailable".
// Allow the transport's 200/400/800 ms backoffs plus actual network latency.
const BALANCE_TIMEOUT: Duration = Duration::from_secs(8);

/// Valuation is optional; the page is still useful unpriced.
const PRICE_TIMEOUT: Duration = Duration::from_secs(3);

/// A valuation bound, not a claim that every provider updates hourly. Past
/// this, a quote does not price anything.
const QUOTE_MAX_AGE_SECS: u64 = 3600;

/// Content-Security-Policy for every page. `style-src 'self'` is what lets a
/// page link the sibling `bloom.css` instead of carrying a copy that drifts;
/// `img-src 'self'` lets it show a QR code the VFS already renders and the
/// bundled icon artwork served beside the pages. The only script permitted is
/// the bundled, same-origin sorter; every page remains useful without it.
const CSP: &str = "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; \
                   script-src 'self'; base-uri 'none'; form-action 'none'";

/// Central outbox lifecycle directories, newest concern first.
const ACTION_STATES: [&str; 3] = ["pending", "sent", "failed"];

#[derive(Clone)]
pub struct ViewsHandler {
    projections: Arc<dyn WalletProjectionReader>,
    chains: ChainRegistry,
    prices: Arc<PricesClient>,
    outbox: Arc<OutboxHandler>,
    market: MarketData,
    address_book: Arc<AddressBook>,
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
            address_book: Arc::new(AddressBook::default()),
            petals: None,
        }
    }

    /// Read Petal positions through the mounted `petals/` router.
    pub fn with_petals(mut self, petals: Arc<dyn Handler>) -> Self {
        self.petals = Some(petals);
        self
    }

    /// Reuse the daemon's canonical local petnames. Views never mutate them.
    pub fn with_address_book(mut self, address_book: Arc<AddressBook>) -> Self {
        self.address_book = address_book;
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
            [s] if s == BLOOM_JS_NAME => Ok(js_entry()),
            [s] if s == AGENTS_MD_NAME => Ok(agents_entry()),
            [s] if s == ICONS_DIR => Ok(Entry::dir(ICONS_DIR)),
            [s, file] if s == ICONS_DIR => match icon_by_name(file) {
                Some(icon) => Ok(icon_entry(icon)),
                None => Err(HandlerError::not_found(path.to_string_path())),
            },
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let page = match path.segments() {
            [s] if s == BLOOM_CSS_NAME => return Ok(BLOOM_CSS.as_bytes().to_vec()),
            [s] if s == BLOOM_JS_NAME => return Ok(BLOOM_JS.as_bytes().to_vec()),
            [s] if s == AGENTS_MD_NAME => return Ok(VIEWS_AGENTS_MD.as_bytes().to_vec()),
            [s, file] if s == ICONS_DIR => {
                return match icon_by_name(file) {
                    Some(icon) => Ok(icon.bytes.to_vec()),
                    None => Err(HandlerError::NotAFile(path.to_string_path())),
                };
            }
            [s] if is_page(s) => s.clone(),
            _ => return Err(HandlerError::NotAFile(path.to_string_path())),
        };
        let html = match page.as_str() {
            INDEX_HTML => self.render_index().await,
            MARKETS_HTML => self.render_markets().await,
            CHAINS_HTML => self.render_chains().await,
            FEES_HTML => self.render_chains().await,
            WALLETS_HTML => self.render_wallets().await,
            RECEIVE_HTML => self.render_receive().await,
            NEXT_MOVES_HTML => self.render_next_moves().await,
            ACTIVITY_HTML => self.render_activity().await,
            POLICY_HTML => self.render_policy().await,
            CONTACTS_HTML => self.render_contacts().await,
            _ => return Err(HandlerError::NotAFile(path.to_string_path())),
        };
        Ok(html.into_bytes())
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if path.is_root() {
            // `ls -l` does not render children, so give the static assets a
            // real size hint here; pages are sized by the mount at getattr.
            let mut entries = vec![agents_entry(), css_entry(), js_entry()];
            for (name, _) in PAGES {
                entries.push(Entry::file(name));
            }
            entries.push(Entry::dir(ICONS_DIR));
            Ok(entries)
        } else if path.segments() == [ICONS_DIR] {
            Ok(ICON_FILES.iter().map(|icon| icon_entry(icon)).collect())
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
            let Some(intent) = action.intent.as_ref() else {
                continue;
            };
            let Some(from) = intent.from.clone() else {
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
            let label = intent
                .wallet
                .as_deref()
                .filter(|name| !name.is_empty())
                .map(|name| format!("{name} · historical record"))
                .unwrap_or_else(|| short_hex(&from));
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
                owner: Some(address.clone()),
                quantity: format!("{} USDC", trim_trailing_zeros(&format!("{equity:.6}"))),
                // The venue denominates equity in dollars itself, so this
                // needs no quote of ours.
                value: Some(equity),
                source: format!("/petals/{path}"),
                note: "Account equity as the venue reports it, including unrealised profit \
                       and loss. Open position notional is not counted again."
                    .to_owned(),
                url: Some(format!(
                    "https://app.hyperliquid.xyz/explorer/address/{address}"
                )),
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
                owner: Some(wallet.clone()),
                quantity: format!(
                    "{} ETH",
                    trim_trailing_zeros(&format!("{ether_amount:.18}"))
                ),
                value: ether.map(|price| ether_amount * price),
                source: format!("/petals/privacy-pools/notes/{wallet}/"),
                note: "Confirmed deposits that have not been withdrawn. Spent and pending \
                       notes are excluded."
                    .to_owned(),
                url: None,
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

        let funded = portfolio.funded();
        let priced: Vec<&&Holding> = funded.iter().filter(|h| h.value.is_some()).collect();
        let total: f64 = funded.iter().filter_map(|h| h.value).sum();
        let unpriced = funded.len() - priced.len();

        let mut body = String::new();
        body.push_str(&portfolio.notices());

        // A completed set of zero-balance reads has a known dollar value. Keep
        // a dash for missing reads or funded holdings without a price, but do
        // not make an answered, empty wallet look unavailable.
        let (metric, support, caveat) = if portfolio.holdings.is_empty() {
            (
                "—".to_owned(),
                "No balance was read from the configured networks.".to_owned(),
                "Nothing is counted here yet.".to_owned(),
            )
        } else if funded.is_empty() {
            (
                "$0.00".to_owned(),
                format!(
                    "No native funds on {read} that answered.",
                    read = count_noun(portfolio.holdings.len(), "network", "networks"),
                ),
                "Wallets lists every network that was read, so an empty balance stays \
                 distinct from one never checked."
                    .to_owned(),
            )
        } else if priced.is_empty() {
            (
                "—".to_owned(),
                format!(
                    "{held}, none of it priced.",
                    held = count_noun(funded.len(), "funded holding", "funded holdings"),
                ),
                "The quantities are what the chains reported; Wallets explains why each row \
                 is unpriced."
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
                    "{unpriced} unpriced, and left out of this total. Not your net worth.",
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

        // An empty wallet needs no allocation chart pretending to be one. The
        // panel only appears once something is priced; otherwise the balance
        // panel spans the row on its own.
        let (dashboard, dashboard_class) =
            if split.is_empty() {
                (String::new(), " solo")
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
                (
                    format!(
                        "<div class=\"allocation-panel\"><p class=\"eyebrow\">Allocation</p>\
                     <h2>By network</h2><ul class=\"allocation-list\">{rows}</ul></div>"
                    ),
                    "",
                )
            };

        if split.is_empty() {
            body.push_str(&format!(
                "<section class=\"balance-summary\" aria-label=\"Wallet snapshot\"><div><p class=\"eyebrow\">Native balance</p><strong>{metric}</strong><span>{support}</span></div><a href=\"wallets.html\">Wallet details →</a><details><summary>Coverage</summary><p>{caveat}</p></details></section>",
                metric = html_escape(&metric),
                support = html_escape(&support),
                caveat = html_escape(&caveat),
            ));
        } else {
            body.push_str(&format!(
                "<section class=\"wallet-dashboard{class}\" aria-label=\"Wallet snapshot\">\
                 <div class=\"balance-panel\"><p class=\"eyebrow\">Wallet balances</p>\
                 <div class=\"metric\">{metric}</div><p>{support}</p>\
                 <a class=\"button\" href=\"wallets.html\">Wallet details →</a>\
                 <small>{caveat}</small></div>{dashboard}</section>",
                class = dashboard_class,
                metric = html_escape(&metric),
                support = html_escape(&support),
                caveat = html_escape(&caveat),
            ));
        }

        if pending > 0 {
            body.push_str(&attention_strip(pending, true));
        }
        // Wallets reads positions for addresses observed in recorded history
        // as well as projected ones. Use the same coverage here, or the two
        // pages would disagree about what your apps hold.
        let mut addresses = portfolio
            .wallets
            .iter()
            .filter_map(|w| w.address.clone())
            .collect::<Vec<_>>();
        addresses.extend(
            actions
                .iter()
                .filter_map(|action| action.intent.as_ref().and_then(|i| i.from.clone())),
        );
        let positions = self.petal_positions(&addresses).await;
        if !positions.is_empty() {
            let production: Vec<&PetalPosition> = positions
                .iter()
                .filter(|position| !is_development_scope(&position.scope))
                .collect();
            let development: Vec<&PetalPosition> = positions
                .iter()
                .filter(|position| is_development_scope(&position.scope))
                .collect();
            let production_rows = petal_position_rows(&production);
            let development_rows = petal_position_rows(&development);
            body.push_str(&format!("<section><div class=\"section-head\"><h2>In your apps</h2><a href=\"wallets.html\">Details →</a></div>{production}<p class=\"chart-note\">Reported by Petals; separate from native balances.</p>{development}</section>",
                production = if production_rows.is_empty() { "<p class=\"empty-state\">No production app positions.</p>".to_owned() } else { format!("<ul class=\"position-list\">{production_rows}</ul>") },
                development = if development_rows.is_empty() { String::new() } else { format!("<details class=\"development-positions\"><summary>Development positions · {count}</summary><p>Development records are not production value.</p><ul class=\"position-list\">{development_rows}</ul></details>", count = development.len()) },
            ));
        }
        let recent: String = actions.iter().take(4).map(|action| format!(
            "<li><span class=\"recent-state {}\">{}</span><span><strong>{}</strong><small>{}</small></span><span>{}</span></li>",
            action.status_class(), action.glyph(), html_escape(&action.headline(&self.address_book)),
            html_escape(action.label()), action.chain_label(&self.chains)
        )).collect();
        body.push_str(&format!("<section><div class=\"section-head\"><h2>Recent activity</h2><a href=\"activity.html\">All activity →</a></div>{}</section>",
            if recent.is_empty() { "<p class=\"empty-state\">No activity yet.</p>".to_owned() } else { format!("<ul class=\"position-list\">{recent}</ul>") }
        ));

        page(
            "Today",
            "Overview",
            "Your balances, app positions, and recent activity.",
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

        let projected_addresses: Vec<String> = portfolio
            .wallets
            .iter()
            .filter_map(|wallet| wallet.address.as_ref())
            .map(|address| address.to_ascii_lowercase())
            .collect();
        let history = self.history_portfolio(&projected_addresses).await;
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

        let mut body = String::new();
        let current_native = if !portfolio.holdings.iter().any(|h| !h.is_off_market())
            || priced.is_empty() && !funded.is_empty()
        {
            "—".to_owned()
        } else if funded.is_empty() {
            "$0.00".to_owned()
        } else {
            money(Some(total))
        };
        body.push_str(&format!(
            "<section class=\"inventory-summary\"><div><p class=\"eyebrow\">Wallet inventory</p>\
             <strong>{count}</strong><span>{coverage}</span></div><div class=\"inventory-value\" {single}>\
             <strong>{value}</strong><span>Native balances{partial}</span></div></section>",
            count = html_escape(&count_noun(
                portfolio.wallets.len(),
                "wallet loaded",
                "wallets loaded"
            )),
            coverage = if portfolio.projections_unavailable {
                "Inventory incomplete: live and cached projections were unavailable."
            } else {
                "Available in Bloom · expand a wallet to see its accounts"
            },
            value = html_escape(&current_native),
            single = if portfolio.wallets.len() == 1 { "hidden" } else { "" },
            partial = if !portfolio.unavailable.is_empty() || portfolio.price_coverage_gap {
                " · partial"
            } else {
                ""
            },
        ));
        body.push_str(&portfolio.notices());
        body.push_str("<p class=\"directory-note\">Only wallets in Bloom’s current listing appear here. Older names and addresses may no longer be connected. Balances cover native coins; token holdings are not scanned.</p><div class=\"wallet-directory\">");

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
                if !portfolio
                    .holdings
                    .iter()
                    .any(|h| h.wallet == wallet.id && !h.is_off_market())
                {
                    "—".to_owned()
                } else {
                    "$0.00".to_owned()
                }
            } else {
                "No priced balance".to_owned()
            };
            let wallet_positions: Vec<&PetalPosition> = positions
                .iter()
                .filter(|position| position_belongs_to_wallet(position, wallet))
                .collect();
            let production_positions: Vec<&PetalPosition> = wallet_positions
                .iter()
                .copied()
                .filter(|position| !is_development_scope(&position.scope))
                .collect();
            let development_positions: Vec<&PetalPosition> = wallet_positions
                .iter()
                .copied()
                .filter(|position| is_development_scope(&position.scope))
                .collect();
            let wallet_holdings: Vec<&Holding> = portfolio
                .holdings
                .iter()
                .filter(|holding| holding.wallet == wallet.id)
                .collect();
            let chain_marks: String = wallet_holdings
                .iter()
                .filter(|holding| !holding.is_off_market())
                .take(8)
                .map(|holding| network_mark(holding.chain_id, &holding.label))
                .collect();
            let explorer_links = wallet
                .address
                .as_deref()
                .map(|address| explorer_links_for_holdings(&wallet_holdings, address))
                .unwrap_or_default();
            let unavailable_count = portfolio
                .unavailable
                .iter()
                .filter(|(id, _)| id == &wallet.id)
                .count();
            body.push_str(&format!(
                "<details class=\"wallet-card directory-entry\" id=\"wallet-{id}\"><summary class=\"directory-row\">\
                 <span class=\"directory-icon\" aria-hidden=\"true\">▱</span>\
                 <span class=\"directory-identity\"><strong>{name}</strong><span>{kind} wallet</span>\
                 <code class=\"wallet-address\">{short_address}</code></span>\
                 <span class=\"wallet-worth\"><strong>{subtitle}</strong><span>Native balance{partial}</span>{apps}</span>\
                 </summary><div class=\"directory-content\"><code class=\"wallet-address\">{address}</code>\
                 <div class=\"wallet-account-line\"><span class=\"chain-stack\">{chain_marks}</span>\
                 <span>{answered} networks answered{unavailable}</span></div>\
                 <nav class=\"wallet-actions\" aria-label=\"{name} actions\"><a href=\"receive.html#wallet-{id}\">Receive</a>\
                 <a href=\"policy.html#wallet-{id}\">Policy</a>{explorers}</nav>\
                 <details><summary>Account evidence</summary><dl class=\"receipt-facts\">\
                 <div><dt>Address</dt><dd><code>{address}</code></dd></div>\
                 <div><dt>Wallet kind</dt><dd>{kind}</dd></div>\
                 <div><dt>Policy</dt><dd>version {version}</dd></div></dl></details>",
                id = html_escape(&wallet.id),
                name = html_escape(&wallet.id),
                subtitle = html_escape(&subtitle),
                address = html_escape(wallet.address.as_deref().unwrap_or("Unavailable")),
                short_address = html_escape(&short_hex(wallet.address.as_deref().unwrap_or("Unavailable"))),
                partial = if unavailable_count > 0 { " · partial" } else { "" },
                apps = if production_positions.is_empty() { String::new() } else {
                    format!("<span>App positions · {}</span>", html_escape(&money(production_positions.iter().map(|p| p.value).collect::<Option<Vec<_>>>().map(|values| values.iter().sum()))))
                },
                kind = html_escape(&wallet.kind),
                version = html_escape(&wallet.policy_version),
                chain_marks = chain_marks,
                answered = wallet_holdings.len(),
                unavailable = if unavailable_count == 0 {
                    String::new()
                } else {
                    format!(" · {unavailable_count} unavailable")
                },
                explorers = explorer_links,
            ));

            if !wallet_funded.is_empty() {
                body.push_str(&holdings_table(
                    &wallet_funded,
                    "Native balances read through Bloom",
                ));
            }

            // Faucet and development balances get their own table, under a
            // disclosure. Sharing one with real funds is how an enormous test
            // quantity ends up reading as a portfolio.
            if !wallet_off_market.is_empty() {
                body.push_str(&format!(
                    "<details><summary>Test and development balances · {count}</summary>\
                     <p>Quantities here are not money: these chains have no market for their \
                     native unit.</p>{table}</details>",
                    count = wallet_off_market.len(),
                    table = holdings_table(
                        &wallet_off_market,
                        "Balances on chains with no market for their native unit",
                    ),
                ));
            }

            // An empty network is reported, not dropped: otherwise "you hold
            // nothing on Base" is indistinguishable from "Base was not read".
            if !wallet_empty.is_empty() {
                let chips: String = wallet_empty
                    .iter()
                    .map(|holding| {
                        format!(
                            "<li>{}</li>",
                            asset_label_with(
                                network_mark(holding.chain_id, &holding.label),
                                &holding.label
                            )
                        )
                    })
                    .collect();
                body.push_str(&format!(
                    "<details><summary>Empty networks · {count}</summary>\
                     <ul class=\"receiving-networks\">{chips}</ul></details>",
                    count = wallet_empty.len(),
                ));
            }
            if !production_positions.is_empty() {
                body.push_str(&format!(
                    "<div class=\"wallet-subsection\"><div class=\"section-head\"><h3>App positions</h3><p>{}</p></div><ul class=\"position-list\">{}</ul></div>",
                    html_escape(&money(Some(
                        production_positions.iter().filter_map(|position| position.value).sum()
                    ))),
                    petal_position_rows(&production_positions),
                ));
            }
            if !development_positions.is_empty() {
                body.push_str(&format!(
                    "<details><summary>Development positions · {}</summary><ul class=\"position-list\">{}</ul></details>",
                    development_positions.len(),
                    petal_position_rows(&development_positions),
                ));
            }
            body.push_str("</div></details>");
        }
        body.push_str("</div>");

        // The wallets above are what Broker projects. These addresses are
        // what actually sent your recorded operations, and a reader looking
        // for "where is my money" is otherwise told nothing at all.
        let observed = history.funded();
        if !observed.is_empty() {
            body.push_str(
                "<section class=\"historical-accounts\"><div class=\"section-head\"><h2>Historical accounts</h2>\
                 <p>Not connected to a current wallet</p></div>",
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
                let address = summary.address.as_deref().unwrap_or("Unavailable");
                let links = explorer_links_for_holdings(&rows, address);
                let account_positions: Vec<&PetalPosition> = positions
                    .iter()
                    .filter(|position| position_belongs_to_wallet(position, summary))
                    .collect();
                body.push_str(&format!(
                    "<details class=\"historical-account directory-entry\"><summary class=\"directory-row\">\
                     <span class=\"directory-icon\" aria-hidden=\"true\">↗</span>\
                     <span class=\"directory-identity\"><strong>{id}</strong><span>Observed address · control unverified</span>\
                     <code class=\"wallet-address\">{short_address}</code></span>\
                     <span class=\"wallet-worth\"><strong>{total}</strong><span>Observed native balance</span>{apps}</span>\
                     </summary><div class=\"directory-content\"><code class=\"wallet-address\">{address}</code>\
                     <p>Seen as a sender in recorded activity. No current Broker projection proves control. App positions are shown separately from native balances.</p>\
                     <div class=\"wallet-actions\">{links}</div>{table}{positions}</div></details>",
                    id = html_escape(&summary.id),
                    address = html_escape(address),
                    short_address = html_escape(&short_hex(address)),
                    apps = if account_positions.iter().all(|p| is_development_scope(&p.scope)) { String::new() } else {
                        format!("<span>App positions · {}</span>", html_escape(&money(account_positions.iter().filter(|p| !is_development_scope(&p.scope)).map(|p| p.value).collect::<Option<Vec<_>>>().map(|values| values.iter().sum()))))
                    },
                    total = html_escape(&if total > 0.0 {
                        money(Some(total))
                    } else {
                        "No priced balance".to_owned()
                    }),
                    table = holdings_table(&rows, "Observed balances"),
                    links = links,
                    positions = if account_positions.is_empty() {
                        String::new()
                    } else {
                        format!("<div class=\"wallet-subsection\"><h3>Observed app positions</h3><ul class=\"position-list\">{}</ul></div>", petal_position_rows(&account_positions))
                    },
                ));
            }
            body.push_str("</section>");
        }

        let unassigned_positions: Vec<&PetalPosition> = positions
            .iter()
            .filter(|position| {
                !portfolio
                    .wallets
                    .iter()
                    .chain(history.wallets.iter())
                    .any(|wallet| position_belongs_to_wallet(position, wallet))
            })
            .collect();
        if !unassigned_positions.is_empty() {
            body.push_str(&format!(
                "<details class=\"unassigned-positions\"><summary>Positions without a current wallet match · {}</summary>\
                 <p>These Petal records identify an account that is absent from the current wallet listing. They are not counted as a controlled wallet.</p>\
                 <ul class=\"position-list\">{}</ul></details>",
                unassigned_positions.len(),
                petal_position_rows(&unassigned_positions),
            ));
        }

        page("Wallets", "Wallets", "", WALLETS_HTML, &body)
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
            "Receive",
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
        let (mut card, mut addresses) = match wallet
            .primary_address()
            .ok()
            .filter(|address| address.parse::<alloy::primitives::Address>().is_ok())
        {
            Some(address) => (
                self.render_address_card(id, address, mainnets, testnets),
                1usize,
            ),
            None => (
                format!(
                    "<article class=\"card receiving-card\"><p class=\"eyebrow\">{} · \
                         receiving address</p><h3>Ethereum &amp; EVM</h3><p>No EVM receiving address in this wallet’s projection.\
                         </p></article>",
                    html_escape(id)
                ),
                0usize,
            ),
        };
        let mut solana_addresses = std::collections::BTreeSet::new();
        for key in &wallet.keys {
            if key
                .supported_crypto_suites
                .contains(&bloom_broker_api::CryptoSuite::Ed25519Message)
            {
                for address in &key.addresses {
                    // Ed25519 alone does not identify a chain. Require an
                    // explicit Solana CAIP-10 identity from the projection.
                    if let Some((network, address)) = address
                        .strip_prefix("solana:")
                        .and_then(|account| account.split_once(':'))
                        && !network.is_empty()
                        && (32..=44).contains(&address.len())
                        && address.bytes().all(|byte| {
                            b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                                .contains(&byte)
                        })
                    {
                        solana_addresses.insert(address);
                    }
                }
            }
        }
        if solana_addresses.is_empty() {
            card.push_str(&format!(
                "<article class=\"card receiving-card receiving-unavailable\"><h3>{}</h3>\
                 <p>No Solana receiving address in this wallet’s projection.</p>\
                 <small>Use your Solana account’s address in Bloom.</small></article>",
                asset_label("Solana"),
            ));
        }
        for address in solana_addresses {
            addresses += 1;
            card.push_str(&format!(
                "<article class=\"card receiving-card\"><h3>{mark}</h3>{qr}\
                 <code class=\"address\">{address}</code>\
                 <p class=\"receiving-network\">Send on Solana only.</p>\
                 <a class=\"external-link\" href=\"https://explorer.solana.com/address/{address}\" rel=\"noreferrer noopener\">View on Solana Explorer ↗</a></article>",
                mark = asset_label("Solana"),
                qr = receiving_qr(address),
                address = html_escape(address),
            ));
        }
        let subtitle = match addresses {
            0 => "No receiving address".to_owned(),
            1 => "1 receiving address".to_owned(),
            n => format!("{n} receiving addresses"),
        };
        format!(
            "<section class=\"receiving-wallet\" id=\"wallet-{id_attr}\" aria-label=\"{id_attr} receiving addresses\">\
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
            .map(|name| {
                let label = self.network_label(name);
                let mark = self
                    .chains
                    .get(name)
                    .map(|client| network_mark(client.spec().chain_id, &label))
                    .unwrap_or_else(|| monogram(&label));
                format!("<li>{}</li>", asset_label_with(mark, &label))
            })
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

        // Inline QR artwork travels with a saved page and always encodes the
        // exact displayed address, including non-primary accounts.
        format!(
            "<article class=\"card receiving-card\"><p class=\"eyebrow\">{wallet} · receiving \
             address</p><h3>{mark}</h3>{qr}\
             <code class=\"address\">{address}</code><div class=\"receiving-network-list\">\
             <p class=\"label\">Networks for this address</p>{networks}{testing}</div></article>",
            wallet = html_escape(wallet),
            mark = asset_label_with(monogram("ETH"), "Ethereum & EVM"),
            qr = receiving_qr(address),
            address = html_escape(address),
        )
    }

    async fn render_next_moves(&self) -> String {
        let actions = self.actions().await;
        let pending: Vec<&Action> = actions.iter().filter(|a| a.state == "pending").collect();
        let failed = actions.iter().filter(|a| a.state == "failed").count();

        let mut body = String::new();

        if pending.is_empty() {
            body.push_str("<p class=\"empty-state\">Nothing needs you right now.</p>");
        } else {
            body.push_str(&format!(
                "<div class=\"section-head\"><h2>{}</h2><p>Current actions</p></div>",
                count_noun(pending.len(), "next move", "next moves")
            ));
            let rows: String = pending
                .iter()
                .map(|action| action.row(&self.address_book, &self.chains))
                .collect();
            body.push_str(&format!("<div class=\"activity-ledger\">{rows}</div>"));
        }

        // "Failed" overstates what these records show. They carry no result
        // and no transaction hash, so what is known is that nothing was sent.
        if failed > 0 {
            let one = failed == 1;
            body.push_str(&format!(
                "<details class=\"past-failures\"><summary>{count} never broadcast</summary>\
                 <p>Historical records only. <a href=\"activity.html\">Inspect {pronoun} →</a></p></details>",
                count = if one {
                    "One record".to_owned()
                } else {
                    format!("{failed} records")
                },
                pronoun = if one { "it" } else { "them" },
            ));
        }

        page(
            "Next moves",
            "Next moves",
            "Pending actions and their blockers.",
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
             <a href=\"#ledger\"><span class=\"mini-outcome\">↗</span><strong>{sent}</strong>\
             <span>Broadcast</span></a>\
             <a href=\"#ledger\"><span class=\"mini-outcome\">◷</span><strong>{pending}</strong>\
             <span>Awaiting review</span></a>\
             <a href=\"#ledger\"><span class=\"mini-outcome\">✗</span><strong>{failed}</strong>\
             <span>Not sent</span></a></section>"
        ));

        body.push_str(
            "<p class=\"coverage\">Broadcast records show submission, not confirmation.</p>",
        );

        if actions.is_empty() {
            body.push_str(
                "<section class=\"callout\" id=\"ledger\"><strong>No activity yet</strong>\
                 <p>Your transactions will appear here.</p>\
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
                ledger.push_str(&action.row(&self.address_book, &self.chains));
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

        page("Activity", "Activity", "", ACTIVITY_HTML, &body)
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
                        symbol = asset_label(&row.symbol),
                        change = html_escape(&signed_percent(row.change_24h)),
                        volume = html_escape(
                            &row.volume_24h.map(compact_usd).unwrap_or("No".to_owned())
                        ),
                    )
                })
                .collect();
            body.push_str(&format!(
                "<div class=\"section-head\"><h2>Top movers</h2>\
                 <p>24h · provider sample</p></div>\
                 <div class=\"mover-grid\">{tiles}</div>"
            ));
        }

        let cells: String = rows
            .iter()
            .map(|row| {
                let name_link = format!(
                    "<a class=\"external-link\" href=\"{}\" rel=\"noreferrer noopener\">{} ↗</a>",
                    html_escape(&coingecko_market_url(&row.id)),
                    html_escape(&row.name),
                );
                format!(
                    "<tr><td data-label=\"Token\"><span class=\"asset-label\">{mark}\
                     <span><strong>{name}</strong><small>{symbol}</small></span></span></td>\
                     <td class=\"numeric\" data-label=\"Price\">{price}</td>\
                     <td class=\"numeric\" data-label=\"24h change\">{change}</td>\
                     <td class=\"numeric money\" data-label=\"24h volume\">{volume}</td></tr>",
                    mark = monogram(&row.symbol),
                    name = name_link,
                    symbol = html_escape(&row.symbol),
                    price = html_escape(&row.price.map(money_precise).unwrap_or("—".to_owned())),
                    change = html_escape(&signed_percent(row.change_24h)),
                    volume =
                        html_escape(&row.volume_24h.map(compact_usd).unwrap_or("—".to_owned())),
                )
            })
            .collect();
        body.push_str(&format!(
            "<div class=\"section-head\"><h2>Market overview</h2>\
             <p>{count} · 24h reported volume</p></div>\
             <div class=\"table-wrap\"><table class=\"market-table\">\
             <thead><tr><th scope=\"col\">Token</th><th class=\"numeric\" scope=\"col\">Price</th>\
             <th class=\"numeric\" scope=\"col\">24h change</th><th class=\"numeric\" scope=\"col\">24h volume</th></tr></thead>\
             <tbody>{cells}</tbody></table></div>",
            count = count_noun(rows.len(), "row", "rows"),
        ));
        body.push_str(
            "<p class=\"chart-note\">Public provider context, stablecoins included. None of \
             these rows is a holding of yours, and volume is not liquidity available to you.</p>",
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

    /// One comparison surface for network usage and wallet balances.
    /// Fee history is disclosed per network, keeping the default view short.
    async fn render_chains(&self) -> String {
        let portfolio = self.portfolio().await;
        let mut networks = Vec::new();
        for chain in self.sorted_chains() {
            let Some(client) = self.chains.get(&chain) else {
                continue;
            };
            let chain_id = client.spec().chain_id;
            let slug = market_data::chain_slug(chain_id);
            let (volume, fees) = match slug {
                Some(slug) => tokio::join!(self.market.volume(slug), self.market.fees(slug)),
                None => (None, None),
            };
            networks.push((Some(chain), Some(chain_id), slug, volume, fees));
        }
        // Solana's public network metrics do not depend on an EVM chain spec
        // or on whether Broker currently projects a Solana wallet account.
        // Keeping it here avoids inventing an EVM chain id merely to make the
        // public comparison complete.
        let (solana_volume, solana_fees) =
            tokio::join!(self.market.volume("solana"), self.market.fees("solana"));
        networks.push((None, None, Some("solana"), solana_volume, solana_fees));
        networks.sort_by(|a, b| {
            compare_optional_f64_desc(
                a.4.as_ref().and_then(|f| f.total_all_time),
                b.4.as_ref().and_then(|f| f.total_all_time),
            )
            .then_with(|| {
                network_view_label(self, a.0.as_deref())
                    .cmp(&network_view_label(self, b.0.as_deref()))
            })
        });
        let mut body = portfolio.notices();
        if networks.is_empty() {
            body.push_str(
                "<section class=\"callout\"><strong>No networks are configured</strong>\
                 <p>Add a chain to the daemon configuration and it will be compared here: \
                 its fee totals, trading activity, and what your wallets hold on it.</p>\
                 </section>",
            );
            return page("Networks", "Networks", "", CHAINS_HTML, &body);
        }
        body.push_str("<p class=\"coverage\">Network-wide totals · USD</p>");
        body.push_str("<section class=\"network-list\" data-network-list aria-label=\"Network comparison\"><div class=\"network-columns\" role=\"group\" aria-label=\"Sort networks\"><button type=\"button\" data-sort=\"name\" aria-pressed=\"false\">Network <span aria-hidden=\"true\">↕</span></button><button type=\"button\" data-sort=\"fees-all\" aria-pressed=\"true\" data-direction=\"desc\">Fees · all time <span aria-hidden=\"true\">↓</span></button><button type=\"button\" data-sort=\"fees-day\" aria-pressed=\"false\">Fees · 24h <span aria-hidden=\"true\">↕</span></button><button type=\"button\" data-sort=\"dex-day\" aria-pressed=\"false\">DEX volume · 24h <span aria-hidden=\"true\">↕</span></button></div><p class=\"sort-status\" aria-live=\"polite\">Sorted by Fees · all time, descending.</p><div data-network-rows>");
        for (chain, chain_id, slug, volume, fees) in networks {
            let label = network_view_label(self, chain.as_deref());
            let total = |value: Option<f64>| value.map(compact_usd).unwrap_or("—".to_owned());
            let chain_holdings: Vec<&Holding> = portfolio
                .holdings
                .iter()
                .filter(|h| chain.as_ref().is_some_and(|chain| h.chain == *chain))
                .collect();
            let history = match &fees {
                Some(series) => format!(
                    "<div class=\"network-detail\"><div><dl class=\"fee-periods\"><div><dt>Past year</dt><dd>{}</dd></div><div><dt>30 days</dt><dd>{}</dd></div><div><dt>7 days</dt><dd>{}</dd></div></dl><p class=\"chart-note\">{}</p></div><div>{}</div></div>",
                    total(series.total_1y),
                    total(series.total_30d),
                    total(series.total_7d),
                    html_escape(series.methodology.as_deref().unwrap_or(
                        "Provider-reported network fees. The current UTC day \
                                        is excluded from the chart because it is still \
                                        accruing."
                    )),
                    line_chart(
                        &series.points,
                        &format!("{label} daily network fees, 30 days"),
                        "USD / day"
                    ),
                ),
                None => "<div class=\"network-detail\"><p class=\"chart-note\">Fee history is \
                     unavailable for this network.</p></div>"
                    .to_owned(),
            };
            let fees_all = fees.as_ref().and_then(|f| f.total_all_time);
            let fees_day = fees.as_ref().and_then(|f| f.total_24h);
            let dex_day = volume.as_ref().and_then(|v| v.total_24h);
            let mark = match chain_id {
                Some(chain_id) => network_mark(chain_id, &label),
                None => asset_mark("SOL", true),
            };
            let held = if chain.is_some() {
                held_value_label(&chain_holdings)
            } else {
                "Wallet account unavailable".to_owned()
            };
            let source = slug.map(network_source_link).unwrap_or_default();
            body.push_str(&format!(
                "<details class=\"network-row\" data-name=\"{name_raw}\" data-fees-all=\"{fees_all_raw}\" data-fees-day=\"{fees_day_raw}\" data-dex-day=\"{dex_day_raw}\"><summary><span class=\"network-name\">{label}</span><span class=\"network-number\"><small>All-time fees</small><strong>{all}</strong></span><span class=\"network-number\"><small>24h fees</small>{day}</span><span class=\"network-number\"><small>24h DEX volume</small>{volume}</span></summary><div class=\"network-context\"><span>Your priced native assets <strong>{held}</strong></span><span>DEX volume change · 24h <strong>{change}</strong></span>{source}</div>{history}</details>",
                name_raw = html_escape(&label.to_ascii_lowercase()),
                fees_all_raw = optional_number_attribute(fees_all),
                fees_day_raw = optional_number_attribute(fees_day),
                dex_day_raw = optional_number_attribute(dex_day),
                label = asset_label_with(mark, &label),
                all = total(fees_all),
                day = total(fees_day),
                volume = total(dex_day),
                held = html_escape(&held),
                change = signed_percent(volume.as_ref().and_then(|v| v.change_1d)),
                source = source,
            ));
        }
        body.push_str("</div></section><p class=\"chart-note\">Open a row for other periods and 30-day history. Public data: DefiLlama.</p>");
        page("Networks", "Networks", "", CHAINS_HTML, &body)
    }

    async fn render_contacts(&self) -> String {
        let actions = self.actions().await;
        let (wallets, _) = self.wallet_projections().await;
        let own_addresses: BTreeSet<String> = wallets
            .iter()
            .filter_map(|wallet| wallet.primary_address().ok())
            .filter_map(normalized_evm_address)
            .map(|address| address.to_ascii_lowercase())
            .collect();
        let mut recipients: BTreeMap<(String, String), RecipientHistory> = BTreeMap::new();
        let mut contract_targets = 0usize;
        let mut unknown_targets = 0usize;

        for action in &actions {
            match action.target_classification() {
                Some("contract") => contract_targets += 1,
                Some("unknown") => unknown_targets += 1,
                _ => {}
            }
            let Some(address) = action.recipient() else {
                continue;
            };
            let chain = action.chain.as_deref().unwrap_or("unknown").to_owned();
            let key = (chain.to_ascii_lowercase(), address.to_ascii_lowercase());
            let entry = recipients.entry(key).or_insert_with(|| RecipientHistory {
                chain: chain.clone(),
                address: address.clone(),
                ..RecipientHistory::default()
            });
            entry.count += 1;
            entry.last_ms = entry.last_ms.max(action.when());
            entry.operations.push((action.id.clone(), action.label()));
        }

        let mut history: Vec<&RecipientHistory> = recipients.values().collect();
        history.sort_by(|a, b| {
            b.last_ms
                .cmp(&a.last_ms)
                .then_with(|| b.count.cmp(&a.count))
                .then_with(|| (&a.chain, &a.address).cmp(&(&b.chain, &b.address)))
        });

        let mut body = String::new();
        let saved: String = self
            .address_book
            .iter()
            .map(|(name, address)| {
                let matches: Vec<&RecipientHistory> = history
                    .iter()
                    .copied()
                    .filter(|item| item.address.eq_ignore_ascii_case(address))
                    .collect();
                let explorers = contact_explorer_links(&self.chains, &matches);
                saved_contact_row(name, address, &matches, &explorers)
            })
            .collect();
        body.push_str(&format!(
            "<section><div class=\"section-head\"><h2>Saved contacts</h2><p>{count}</p></div>{saved}</section>",
            count = count_noun(self.address_book.entries.len(), "contact", "contacts"),
            saved = if saved.is_empty() {
                "<p class=\"empty-state\">No named contacts are saved. Add one through <code>/addressbook/new</code>.</p>".to_owned()
            } else {
                format!("<div class=\"contact-list\">{saved}</div>")
            }
        ));

        let suggestions: String = history
            .iter()
            .copied()
            .filter(|item| item.count > 1)
            .filter(|item| address_alias(&self.address_book, &item.address).is_none())
            .filter(|item| !own_addresses.contains(&item.address.to_ascii_lowercase()))
            .map(|item| {
                let explorers = contact_explorer_links(&self.chains, &[item]);
                contact_history_row(item, true, &explorers)
            })
            .collect();
        body.push_str(&format!(
            "<section><div class=\"section-head\"><h2>Suggested contacts</h2><p>Repeated recipients</p></div>{suggestions}</section>",
            suggestions = if suggestions.is_empty() {
                "<p class=\"empty-state\">No unnamed recipient appears more than once.</p>".to_owned()
            } else {
                format!("<div class=\"contact-list\">{suggestions}</div>")
            }
        ));

        let recent: String = history
            .iter()
            .copied()
            .filter(|item| item.count == 1)
            .filter(|item| address_alias(&self.address_book, &item.address).is_none())
            .filter(|item| !own_addresses.contains(&item.address.to_ascii_lowercase()))
            .map(|item| {
                let explorers = contact_explorer_links(&self.chains, &[item]);
                contact_history_row(item, false, &explorers)
            })
            .collect();
        if !recent.is_empty() {
            body.push_str(&format!(
                "<details><summary>One-time recipients</summary><div class=\"contact-list\">{recent}</div></details>"
            ));
        }
        if contract_targets > 0 || unknown_targets > 0 {
            body.push_str(&format!(
                "<details><summary>Excluded targets · {count}</summary><p>{contracts} contract-call {contract_noun} and {unknown} unclassified {unknown_noun} were not suggested as contacts. A call target is not necessarily its recipient; unknown stays unknown.</p></details>",
                count = contract_targets + unknown_targets,
                contracts = contract_targets,
                contract_noun = if contract_targets == 1 { "target" } else { "targets" },
                unknown = unknown_targets,
                unknown_noun = if unknown_targets == 1 { "target" } else { "targets" },
            ));
        }

        page(
            "Contacts",
            "Contacts",
            "Named contacts and recipients proven by recorded transfers.",
            CONTACTS_HTML,
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
        let mut stale = false;
        for wallet in &wallets {
            if wallet.freshness == ProjectionFreshness::Stale {
                stale = true;
            }
            let id = wallet.wallet_id().as_str();
            let Some(policy) = canonical_policy(wallet) else {
                body.push_str(&format!(
                    "<section><div class=\"section-head\"><h2>{}</h2><p>Policy unreadable</p></div></section>",
                    html_escape(id)
                ));
                continue;
            };
            let destinations = destinations_by_chain(&policy);
            let rows: String = destinations
                .iter()
                .flat_map(|(chain, addresses)| {
                    addresses.iter().map(move |address| {
                        let label = self.network_label(chain);
                        let client = self.chains.get(chain);
                        let mark = client
                            .as_ref()
                            .map(|client| network_mark(client.spec().chain_id, &label))
                            .unwrap_or_else(|| monogram(&label));
                        let name = address_alias(&self.address_book, address);
                        let explorer = client
                            .as_ref()
                            .and_then(|client| explorer_address_url(client.spec().chain_id, address))
                            .map(|url| format!(
                                "<a class=\"external-link\" href=\"{}\" rel=\"noreferrer noopener\">View address ↗</a>",
                                html_escape(&url),
                            ))
                            .unwrap_or_default();
                        format!(
                            "<article class=\"policy-exception\"><div>{network}<span class=\"badge good\">Listed destination</span></div><h3>{contact}</h3><code>{address}</code>{explorer}<p>This address passes the destination check on {chain}. The app, request, available funds, and approval window are checked separately.</p></article>",
                            network = asset_label_with(mark, &label),
                            contact = html_escape(name.unwrap_or("Unnamed destination")),
                            address = html_escape(address),
                            explorer = explorer,
                            chain = html_escape(&label),
                        )
                    })
                })
                .collect();
            let total: usize = destinations.values().map(Vec::len).sum();
            let denied_networks = chains
                .iter()
                .filter(|chain| !destinations.contains_key(*chain))
                .count();
            let packages: String = policy
                .allowed_petal_packages
                .iter()
                .map(|package| {
                    format!(
                        "<li><code>{}</code></li>",
                        html_escape(&package.to_string())
                    )
                })
                .collect();
            let destinations_label = if total == 0 {
                "No listed destination".to_owned()
            } else {
                count_noun(total, "listed address", "listed addresses")
            };
            let app_access = if policy.allowed_petal_packages.is_empty() {
                "No app package".to_owned()
            } else {
                count_noun(
                    policy.allowed_petal_packages.len(),
                    "package fingerprint",
                    "package fingerprints",
                )
            };
            let verifier_text = if policy.required_verifiers.is_empty() {
                "No additional verifier is required by this policy.".to_owned()
            } else {
                format!(
                    "{} required.",
                    count_noun(
                        policy.required_verifiers.len(),
                        "additional verifier",
                        "additional verifiers"
                    )
                )
            };
            let other_networks =
                format!("{denied_networks} other configured networks have no listed destination.");
            body.push_str(&format!(
                "<section id=\"wallet-{name}\"><div class=\"section-head\"><h2>{name}</h2>\
                 <p>Policy version {version} · {kind}</p></div>\
                 <p class=\"policy-summary\">{summary}</p>{rows}\
                 <dl class=\"policy-limits\"><div><dt>Where it may send</dt><dd>{destinations}</dd></div><div><dt>Allowed app</dt><dd>{app_access}</dd></div><div><dt>Amount cap</dt><dd>None expressed here</dd></div><div><dt>Approval window</dt><dd>Up to {lifetime}</dd></div></dl>\
                 <p class=\"policy-plain\">A listed address and app are prerequisites, not permission to execute. Bloom still checks the exact request and available funds before asking for approval. {verifier_text} {other_networks}</p>\
                 <details><summary>Exact policy and scope</summary><p>The canonical signed policy is at <code>{path}</code>. Allowed app package fingerprints:</p><ul class=\"exact-list\">{packages}</ul><p>External token approvals are outside this projection.</p></details></section>",
                name = html_escape(id),
                version = html_escape(wallet.wallet.policy_version.as_str()),
                kind = html_escape(wallet.wallet.wallet_kind.as_str()),
                summary = html_escape(&if total == 0 {
                    "No destination is permitted by this policy.".to_owned()
                } else {
                    format!(
                        "This wallet may send only to the {total} listed {noun} below, through an allowed app and within the approval window.",
                        noun = if total == 1 {
                            "destination"
                        } else {
                            "destinations"
                        },
                    )
                }),
                rows = if rows.is_empty() {
                    "<p class=\"empty-state\">No destination exceptions.</p>".to_owned()
                } else {
                    format!("<div class=\"policy-exceptions\">{rows}</div>")
                },
                lifetime = html_escape(&duration_ms(policy.maximum_approval_lifetime_ms)),
                destinations = destinations_label,
                app_access = app_access,
                verifier_text = verifier_text,
                other_networks = other_networks,
                path = html_escape(&format!("/wallets/{id}/policy.json")),
                packages = packages,
            ));
        }
        if stale {
            body.push_str(&stale_notice());
        }

        page(
            "Policy",
            "Policy",
            "Where each wallet may send, which app may ask, and how long approval may last.",
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
    /// Wallet id or full address carried by the Petal record itself.
    owner: Option<String>,
    quantity: String,
    value: Option<f64>,
    source: String,
    note: String,
    url: Option<String>,
}

fn is_development_scope(scope: &str) -> bool {
    let scope = scope.to_ascii_lowercase();
    scope == "dev"
        || scope.contains("devnet")
        || scope.contains("testnet")
        || scope.contains("staging")
        || scope.contains("localhost")
}

fn petal_position_rows(positions: &[&PetalPosition]) -> String {
    positions
        .iter()
        .map(|position| {
            format!(
                "<li>{mark}<span><strong>{label}</strong><small>{petal} · {scope} · {quantity}</small>{link}<details><summary>Position evidence</summary><p>{note}</p><code>{source}</code></details></span><strong>{value}</strong></li>",
                mark = monogram(&position.petal),
                label = html_escape(&position.label),
                petal = html_escape(&position.petal),
                scope = html_escape(&short_hex(&position.scope)),
                quantity = html_escape(&short_quantity_with_unit(&position.quantity)),
                link = position.url.as_deref().map(|url| format!(
                    "<a class=\"external-link\" href=\"{}\" rel=\"noreferrer noopener\">Open app account ↗</a>",
                    html_escape(url),
                )).unwrap_or_default(),
                note = html_escape(&position.note),
                source = html_escape(&position.source),
                value = html_escape(&money(position.value)),
            )
        })
        .collect()
}

/// Shorten the numeric part of a `"<quantity> <UNIT>"` pair, leaving the unit
/// alone. Eighteen decimals swamp a cell whether or not a symbol follows.
fn short_quantity_with_unit(text: &str) -> String {
    match text.split_once(' ') {
        Some((quantity, unit)) => format!("{} {unit}", short_quantity(quantity)),
        None => short_quantity(text),
    }
}

fn short_activity_amount(text: &str) -> String {
    let Some((quantity, unit)) = text.split_once(' ') else {
        return short_quantity(text);
    };
    let Ok(value) = quantity.parse::<f64>() else {
        return short_quantity_with_unit(text);
    };
    if value != 0.0 && value.abs() < 0.000001 {
        let scientific = format!("{value:.2e}")
            .replace(".00e", "e")
            .replace(".0e", "e");
        format!("{scientific} {unit}")
    } else {
        short_quantity_with_unit(text)
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

fn position_belongs_to_wallet(position: &PetalPosition, wallet: &WalletSummary) -> bool {
    let Some(owner) = position.owner.as_deref() else {
        return false;
    };
    owner.eq_ignore_ascii_case(&wallet.id)
        || wallet
            .address
            .as_deref()
            .is_some_and(|address| owner.eq_ignore_ascii_case(address))
}

fn explorer_links_for_holdings(holdings: &[&Holding], address: &str) -> String {
    let mut networks = BTreeMap::new();
    for holding in holdings {
        if explorer_address_url(holding.chain_id, address).is_some() {
            networks
                .entry(holding.chain_id)
                .or_insert_with(|| holding.label.clone());
        }
    }
    networks
        .into_iter()
        .take(4)
        .filter_map(|(chain_id, label)| {
            explorer_address_url(chain_id, address).map(|url| {
                format!(
                    "<a class=\"external-link\" href=\"{}\" rel=\"noreferrer noopener\">{} ↗</a>",
                    html_escape(&url),
                    html_escape(&label),
                )
            })
        })
        .collect()
}

#[derive(Default)]
struct RecipientHistory {
    chain: String,
    address: String,
    count: usize,
    last_ms: Option<u64>,
    operations: Vec<(String, &'static str)>,
}

fn activity_links(items: &[&RecipientHistory]) -> String {
    let links: String = items
        .iter()
        .flat_map(|item| item.operations.iter())
        .take(6)
        .map(|(id, state)| {
            format!(
                "<li><a href=\"activity.html#operation-{id}\">{state} · {short}</a></li>",
                id = html_escape(id),
                state = html_escape(state),
                short = html_escape(&short_hex(id)),
            )
        })
        .collect();
    format!("<ul class=\"contact-links\">{links}</ul>")
}

fn saved_contact_row(
    name: &str,
    address: &str,
    history: &[&RecipientHistory],
    explorers: &str,
) -> String {
    let count: usize = history.iter().map(|item| item.count).sum();
    let last = history.iter().filter_map(|item| item.last_ms).max();
    let networks: BTreeSet<&str> = history.iter().map(|item| item.chain.as_str()).collect();
    format!(
        "<article class=\"contact-row\"><div><span class=\"badge good\">Saved</span><h3>{name}</h3><p>{networks}</p></div><div class=\"contact-stats\"><span><strong>{count}</strong> transfers</span><span>{last}</span></div><details><summary>Address and activity</summary><code>{address}</code><div class=\"quiet-links\">{explorers}</div>{links}</details></article>",
        name = html_escape(name),
        networks = html_escape(&if networks.is_empty() {
            "All EVM networks · no recorded transfer".to_owned()
        } else {
            networks.into_iter().collect::<Vec<_>>().join(", ")
        }),
        count = count,
        last = last
            .map(format_utc_ms)
            .unwrap_or_else(|| "No activity".to_owned()),
        address = html_escape(address),
        explorers = explorers,
        links = activity_links(history),
    )
}

fn contact_history_row(item: &RecipientHistory, suggested: bool, explorers: &str) -> String {
    format!(
        "<article class=\"contact-row\"><div>{badge}<h3>{address}</h3><p>{chain}</p></div><div class=\"contact-stats\"><span><strong>{count}</strong> transfers</span><span>{last}</span></div><details><summary>Full address and activity</summary><code>{full}</code><div class=\"quiet-links\">{explorers}</div>{links}</details></article>",
        badge = if suggested {
            "<span class=\"badge\">Suggested</span>"
        } else {
            "<span class=\"badge\">Observed once</span>"
        },
        address = html_escape(&short_hex(&item.address)),
        chain = html_escape(&item.chain),
        count = item.count,
        last = item
            .last_ms
            .map(format_utc_ms)
            .unwrap_or_else(|| "Time unavailable".to_owned()),
        full = html_escape(&item.address),
        explorers = explorers,
        links = activity_links(&[item]),
    )
}

fn contact_explorer_links(chains: &ChainRegistry, history: &[&RecipientHistory]) -> String {
    let mut links = BTreeMap::new();
    for item in history {
        let Some(client) = chains.get(&item.chain) else {
            continue;
        };
        let chain_id = client.spec().chain_id;
        let Some(url) = explorer_address_url(chain_id, &item.address) else {
            continue;
        };
        let label = client
            .spec()
            .display_name
            .as_deref()
            .unwrap_or(&item.chain)
            .to_owned();
        links.insert((chain_id, item.address.clone()), (label, url));
    }
    links
        .into_values()
        .map(|(label, url)| {
            format!(
                "<a class=\"external-link\" href=\"{}\" rel=\"noreferrer noopener\">{} explorer ↗</a>",
                html_escape(&url),
                html_escape(&label),
            )
        })
        .collect()
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
                 <td class=\"numeric money\" data-label=\"Value\">{value}</td>\
                 <td data-label=\"Evidence\"><details><summary>Details</summary>\
                 <p>{note}</p><p>Exact quantity: <code>{exact}</code></p>\
                 <p><code>{source}</code></p></details></td></tr>",
                // An off-market unit keeps initials even when its spelling is
                // familiar: the logo belongs to the traded asset, not to a
                // development chain that borrowed the name.
                mark = asset_mark(&holding.symbol, !holding.is_off_market()),
                symbol = html_escape(&holding.symbol),
                quantity = html_escape(&short_quantity(&holding.quantity)),
                exact = html_escape(&trim_trailing_zeros(&holding.quantity)),
                label = asset_label_with(
                    network_mark(holding.chain_id, &holding.label),
                    &holding.label
                ),
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
        "<div class=\"table-wrap\"><table class=\"holdings-table\"><caption>{caption}</caption><thead><tr>\
         <th scope=\"col\">Asset / quantity</th><th scope=\"col\">Network</th>\
         <th class=\"numeric\" scope=\"col\">Value</th><th scope=\"col\">Evidence</th></tr></thead>\
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
    /// than implied. Routine partial coverage stays a quiet status line; a
    /// fully unavailable source remains an alert.
    fn notices(&self) -> String {
        let mut out = String::new();
        if self.projections_unavailable {
            out.push_str(
                "<section class=\"callout warn\"><strong>Wallet data unavailable</strong>\
                 <p>No cached wallet data. Reload when Broker is available.</p></section>",
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
                "<p class=\"coverage-notice\"><strong>Partial balance coverage</strong> · \
                 {names} unavailable and excluded from totals.</p>",
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
    /// Explicit decoded recipient when the producer records one.
    recipient: Option<String>,
    value_wei: Option<String>,
    action_kind: Option<String>,
    nonce: Option<u64>,
    gas_limit: Option<u64>,
    created_ms: Option<u64>,
    usd_value: Option<f64>,
    data_bytes: usize,
    data_hex: Option<String>,
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
    fn chain_label(&self, chains: &ChainRegistry) -> String {
        let Some(chain) = self.chain.as_deref() else {
            return "—".to_owned();
        };
        let client = chains.get(chain);
        let label = client
            .as_ref()
            .and_then(|client| client.spec().display_name.as_deref())
            .unwrap_or(chain);
        let chain_id = client
            .as_ref()
            .map(|client| client.spec().chain_id)
            .or_else(|| self.intent.as_ref().and_then(|intent| intent.chain_id));
        asset_label_with(
            chain_id
                .map(|id| network_mark(id, label))
                .unwrap_or_else(|| monogram(label)),
            label,
        )
    }

    /// The account receiving value, only when the intent or a standard
    /// transfer selector identifies one. A contract target is never used as a
    /// recipient fallback.
    fn recipient(&self) -> Option<String> {
        let intent = self.intent.as_ref()?;
        if let Some(recipient) = intent.recipient.as_deref() {
            return normalized_evm_address(recipient);
        }
        match intent.action_kind.as_deref() {
            Some("native_transfer") => intent.to.as_deref().and_then(normalized_evm_address),
            Some("contract_call") => intent
                .data_hex
                .as_deref()
                .and_then(decoded_evm_transfer_recipient),
            _ => None,
        }
    }

    fn target_classification(&self) -> Option<&'static str> {
        let intent = self.intent.as_ref()?;
        intent.to.as_ref()?;
        Some(match intent.action_kind.as_deref() {
            Some("native_transfer") => "recipient",
            Some("contract_call") => "contract",
            _ => "unknown",
        })
    }

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
    fn headline(&self, address_book: &AddressBook) -> String {
        let Some(intent) = &self.intent else {
            return self.summary.clone();
        };
        let kind = intent.action_kind.as_deref().unwrap_or_default();
        let display_amount = self.amount.as_deref().map(short_activity_amount);
        let head = match (kind, &display_amount) {
            ("native_transfer", Some(amount)) => format!("Send {amount}"),
            ("native_transfer", None) => "Send (zero value)".to_owned(),
            ("contract_call", Some(amount)) => format!("Contract call with {amount}"),
            ("contract_call", None) => "Contract call".to_owned(),
            (_, Some(amount)) => format!("Move {amount}"),
            _ => self.summary.clone(),
        };
        let named_target = self.recipient().or_else(|| intent.to.clone());
        match named_target {
            Some(to) => format!("{head} → {}", address_label(address_book, &to)),
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

    fn row(&self, address_book: &AddressBook, chains: &ChainRegistry) -> String {
        let mut meta = String::new();
        let mut fact = |text: String| {
            meta.push_str(&format!("<span>{}</span>", html_escape(&text)));
        };
        if let Some(wallet) = &self.wallet {
            fact(wallet.clone());
        }
        fact(match self.when() {
            Some(ms) => format_utc_ms(ms),
            None => "Time unavailable".to_owned(),
        });
        if let Some(petal) = &self.petal {
            fact(petal.clone());
        }
        if self.chain.is_some() {
            meta.push_str(&self.chain_label(chains));
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
            Some(reason) => format!(
                "<details class=\"denial-detail\"><summary>Why it stopped</summary><p>{}</p></details>",
                html_escape(reason)
            ),
            None => String::new(),
        };
        let blocker = if self.state == "pending" {
            self.denial
                .as_deref()
                .map(denial_summary)
                .map(|summary| format!("<p class=\"action-blocker\">{}</p>", html_escape(&summary)))
                .unwrap_or_else(|| {
                    "<p class=\"action-blocker\">Ready for review in Bloom.</p>".to_owned()
                })
        } else {
            String::new()
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
                let classification = self.target_classification().unwrap_or("unknown");
                row_fact(
                    "To",
                    format!(
                        "{} <code>{}</code> <small>({classification})</small>",
                        html_escape(&address_label(address_book, to)),
                        html_escape(to),
                    ),
                );
            }
            if let Some(recipient) = self.recipient() {
                row_fact(
                    "Recipient",
                    format!(
                        "{} <code>{}</code>",
                        html_escape(&address_label(address_book, &recipient)),
                        html_escape(&recipient),
                    ),
                );
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
            "<article class=\"activity-row {class}\" id=\"operation-{id}\">\
             <div class=\"outcome-symbol\" aria-hidden=\"true\">{glyph}</div>\
             <div class=\"activity-description\"><h3>{headline}</h3>{blocker}\
             <div class=\"activity-meta\">{meta}</div>{denial}\
             <details><summary>Operation details</summary>\
             <dl class=\"receipt-facts\">{facts}</dl></details></div>\
             <div class=\"activity-outcome\"><span class=\"outcome-label\">{label}</span>\
             </div></article>",
            class = self.status_class(),
            glyph = self.glyph(),
            headline = html_escape(&self.headline(address_book)),
            blocker = blocker,
            label = html_escape(self.label()),
            id = html_escape(&self.id),
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
    let data_hex = string("data_hex");
    Some(Intent {
        wallet: string("wallet"),
        chain: string("chain"),
        chain_id: number("chain_id"),
        from: string("from"),
        to: string("to"),
        recipient: string("recipient"),
        value_wei: string("value_wei"),
        action_kind: string("action_kind"),
        nonce: number("nonce"),
        gas_limit: number("gas_limit"),
        created_ms: number("created_ms"),
        usd_value: value.get("usd_value").and_then(|field| field.as_f64()),
        // Calldata is reported as a size. Rendering the bytes themselves
        // invites squinting at hex that the plan already summarises.
        data_bytes: data_hex
            .as_deref()
            .map(|hex| hex.trim_start_matches("0x").len() / 2)
            .unwrap_or(0),
        data_hex,
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

fn compare_optional_f64_desc(a: Option<f64>, b: Option<f64>) -> std::cmp::Ordering {
    match (a, b) {
        (Some(a), Some(b)) => b.partial_cmp(&a).unwrap_or(std::cmp::Ordering::Equal),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn optional_number_attribute(value: Option<f64>) -> String {
    value
        .filter(|number| number.is_finite())
        .map(|number| number.to_string())
        .unwrap_or_default()
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

fn normalized_evm_address(value: &str) -> Option<String> {
    parse_address(value)
        .ok()
        .map(|address| checksum_address(&address))
}

fn address_alias<'a>(book: &'a AddressBook, value: &str) -> Option<&'a str> {
    parse_address(value)
        .ok()
        .and_then(|address| book.alias_for(&address))
}

fn address_label(book: &AddressBook, value: &str) -> String {
    match address_alias(book, value) {
        Some(alias) => alias.to_owned(),
        None => short_hex(value),
    }
}

/// Decode the recipient from common EVM transfer calldata. The contract at
/// `intent.to` remains the token/NFT contract and is never mistaken for the
/// recipient. Unknown selectors stay unknown.
fn decoded_evm_transfer_recipient(data: &str) -> Option<String> {
    let hex = data.strip_prefix("0x").unwrap_or(data);
    if !hex.is_ascii() {
        return None;
    }
    let selector = hex.get(..8)?;
    let word = match selector {
        "a9059cbb" => 0,                           // transfer(address,uint256)
        "23b872dd" | "42842e0e" | "b88d4fde" => 1, // transferFrom / safeTransferFrom
        _ => return None,
    };
    let start = 8 + word * 64 + 24;
    let address = format!("0x{}", hex.get(start..start + 40)?);
    normalized_evm_address(&address)
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

fn denial_summary(reason: &str) -> String {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("has 0")
        && (lower.contains("gas") || lower.contains("fee") || lower.contains("fund"))
    {
        "Blocked: fund the sending account, then restage.".to_owned()
    } else if lower.contains("not on allowlist") || lower.contains("not allowlisted") {
        "Blocked: the destination is outside this wallet's policy.".to_owned()
    } else if lower.contains("approval") {
        "Blocked: approval did not complete.".to_owned()
    } else {
        "Blocked before approval. Open the reason below.".to_owned()
    }
}

fn canonical_policy(
    projection: &WalletProjection,
) -> Option<bloom_broker_api::CanonicalWalletPolicy> {
    let canonical: bloom_broker_api::CanonicalWalletPolicy =
        match serde_json::from_slice(&projection.policy.canonical_policy.decode()) {
            Ok(canonical) => canonical,
            Err(error) => {
                tracing::debug!(error = %error, "views.policy_unparsed");
                return None;
            }
        };
    if canonical.wallet_id != projection.wallet.wallet_id {
        tracing::debug!("views.policy_wallet_mismatch");
        return None;
    }
    Some(canonical)
}

/// Exact permitted destinations per chain. Counts hide the useful exception
/// and cannot resolve a saved contact label.
fn destinations_by_chain(
    canonical: &bloom_broker_api::CanonicalWalletPolicy,
) -> BTreeMap<String, Vec<String>> {
    let mut destinations = BTreeMap::new();
    for destination in &canonical.allowed_destinations {
        destinations
            .entry(destination.chain.as_str().to_owned())
            .or_insert_with(Vec::new)
            .push(
                normalized_evm_address(&destination.destination)
                    .unwrap_or_else(|| destination.destination.clone()),
            );
    }
    for addresses in destinations.values_mut() {
        addresses.sort_by_key(|address| address.to_ascii_lowercase());
        addresses.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    }
    destinations
}

fn duration_ms(ms: u64) -> String {
    if ms.is_multiple_of(86_400_000) {
        count_noun((ms / 86_400_000) as usize, "day", "days")
    } else if ms.is_multiple_of(3_600_000) {
        count_noun((ms / 3_600_000) as usize, "hour", "hours")
    } else if ms.is_multiple_of(60_000) {
        count_noun((ms / 60_000) as usize, "minute", "minutes")
    } else {
        format!("{ms} ms")
    }
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
            "<a class=\"button secondary\" href=\"next-moves.html\">Open next moves →</a>"
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

fn js_entry() -> Entry {
    Entry::file(BLOOM_JS_NAME).with_size(BLOOM_JS.len() as u64)
}

fn agents_entry() -> Entry {
    Entry::file(AGENTS_MD_NAME).with_size(VIEWS_AGENTS_MD.len() as u64)
}

fn icon_entry(icon: &IconFile) -> Entry {
    Entry::file(icon.name).with_size(icon.bytes.len() as u64)
}

fn is_page(name: &str) -> bool {
    if name == FEES_HTML {
        return true;
    } // Preserve bookmarks to the merged page.
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
    (1, "https://etherscan.io"),
    (10, "https://optimistic.etherscan.io"),
    (56, "https://bscscan.com"),
    (100, "https://gnosisscan.io"),
    (137, "https://polygonscan.com"),
    (999, "https://hyperevmscan.io"),
    (4663, "https://robinhoodchain.blockscout.com"),
    (8453, "https://basescan.org"),
    (42161, "https://arbiscan.io"),
    (43114, "https://snowtrace.io"),
    (59144, "https://lineascan.build"),
    (81457, "https://blastscan.io"),
    (534352, "https://scrollscan.com"),
];

fn explorer_tx_url(chain_id: u64, hash: &str) -> Option<String> {
    EXPLORERS
        .iter()
        .find(|(id, _)| *id == chain_id)
        .map(|(_, base)| format!("{base}/tx/{hash}"))
}

fn explorer_address_url(chain_id: u64, address: &str) -> Option<String> {
    EXPLORERS
        .iter()
        .find(|(id, _)| *id == chain_id)
        .map(|(_, base)| format!("{base}/address/{address}"))
}

fn coingecko_market_url(id: &str) -> String {
    format!("https://www.coingecko.com/en/coins/{id}")
}

fn network_source_link(slug: &str) -> String {
    format!(
        "<a class=\"external-link\" href=\"https://defillama.com/chain/{slug}\" \
         rel=\"noreferrer noopener\">Network data ↗</a>",
        slug = html_escape(slug),
    )
}

fn network_view_label(handler: &ViewsHandler, chain: Option<&str>) -> String {
    chain
        .map(|chain| handler.network_label(chain))
        .unwrap_or_else(|| "Solana".to_owned())
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

/// Bundled artwork, served as sibling files under `icons/`, keeps icons
/// available offline without contacting a CDN and without duplicating the
/// bytes into the HTML for every row that shows one. Provenance is
/// documented beside the images. An unknown name keeps an initials fallback
/// rather than borrowing another asset's logo.
struct IconFile {
    /// Served path below `views/`, and the only name a page may ask for.
    name: &'static str,
    bytes: &'static [u8],
}

macro_rules! icon {
    ($const_name:ident, $file:literal) => {
        const $const_name: IconFile = IconFile {
            name: $file,
            bytes: include_bytes!(concat!("../assets/icons/", $file)),
        };
    };
}

icon!(ARBITRUM_CHAIN, "chain-arbitrum.webp");
icon!(AVALANCHE_CHAIN, "chain-avalanche.jpg");
icon!(BASE_CHAIN, "chain-base.webp");
icon!(BLAST_CHAIN, "chain-blast.jpg");
icon!(GNOSIS_CHAIN, "chain-gnosis.jpg");
icon!(HYPERLIQUID_CHAIN, "chain-Hyperliquid.webp");
icon!(LINEA_CHAIN, "chain-linea.jpg");
icon!(OPTIMISM_CHAIN, "chain-optimism.jpg");
icon!(POLYGON_CHAIN, "chain-polygon.jpg");
icon!(ROBINHOOD_CHAIN, "chain-robinhood.webp");
icon!(SCROLL_CHAIN, "chain-scroll.jpg");
icon!(ARBITRUM_TOKEN, "token-arbitrum.jpg");
icon!(BINANCECOIN, "token-binancecoin.png");
icon!(BITCOIN, "token-bitcoin.png");
icon!(CARDANO, "token-cardano.png");
icon!(DASH, "token-dash.png");
icon!(DOGECOIN, "token-dogecoin.png");
icon!(ETHENA, "token-ethena.png");
icon!(ETHEREUM, "token-ethereum.png");
icon!(GLOBAL_DOLLAR, "token-global-dollar.png");
icon!(HYPERLIQUID_TOKEN, "token-hyperliquid.jpg");
icon!(LITECOIN, "token-litecoin.png");
icon!(NEAR, "token-near.jpg");
icon!(RIPPLE, "token-ripple.png");
icon!(SOLANA, "token-solana.png");
icon!(SUI, "token-sui.png");
icon!(TETHER, "token-tether.png");
icon!(UNISWAP, "token-uniswap.png");
icon!(USD1_WLFI, "token-usd1-wlfi.png");
icon!(USD_COIN, "token-usd-coin.png");
icon!(WETH, "token-weth.png");
icon!(ZCASH, "token-zcash.png");

/// Everything a browser may fetch from `icons/`. Requests for any other name
/// are refused, so a path can never escape into the filesystem, and the dump
/// helper writes exactly this set.
const ICON_FILES: &[&IconFile] = &[
    &ARBITRUM_CHAIN,
    &AVALANCHE_CHAIN,
    &BASE_CHAIN,
    &BLAST_CHAIN,
    &GNOSIS_CHAIN,
    &HYPERLIQUID_CHAIN,
    &LINEA_CHAIN,
    &OPTIMISM_CHAIN,
    &POLYGON_CHAIN,
    &ROBINHOOD_CHAIN,
    &SCROLL_CHAIN,
    &ARBITRUM_TOKEN,
    &BINANCECOIN,
    &BITCOIN,
    &CARDANO,
    &DASH,
    &DOGECOIN,
    &ETHENA,
    &ETHEREUM,
    &GLOBAL_DOLLAR,
    &HYPERLIQUID_TOKEN,
    &LITECOIN,
    &NEAR,
    &RIPPLE,
    &SOLANA,
    &SUI,
    &TETHER,
    &UNISWAP,
    &USD1_WLFI,
    &USD_COIN,
    &WETH,
    &ZCASH,
];

/// The only names a request may serve. Anything else under `icons/` is
/// refused, so a path can never escape into the filesystem.
fn icon_by_name(name: &str) -> Option<&'static IconFile> {
    ICON_FILES.iter().copied().find(|icon| icon.name == name)
}

/// The served mark: a real file below `icons/`, so a page never carries a
/// copy of the bytes and a browser caches one image across every row.
fn icon_img(icon: &'static IconFile) -> String {
    format!(
        "<img class=\"asset-mark\" src=\"icons/{}\" alt=\"\" width=\"28\" height=\"28\">",
        icon.name
    )
}

fn initials_mark(name: &str) -> String {
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

/// Asset artwork, matched on the symbol or display name the renderer has.
/// `hype` gets the token mark, not the chain's, because the venue and its
/// token are different things.
fn token_icon(name: &str) -> Option<&'static IconFile> {
    match name.to_ascii_lowercase().as_str() {
        "eth" | "ethereum" | "ethereum mainnet" => Some(&ETHEREUM),
        "weth" => Some(&WETH),
        "btc" | "bitcoin" => Some(&BITCOIN),
        "usdc" => Some(&USD_COIN),
        "usdt" => Some(&TETHER),
        "sol" | "solana" => Some(&SOLANA),
        "bnb" | "bnb chain" | "binance smart chain" | "binancecoin" => Some(&BINANCECOIN),
        "base" => Some(&BASE_CHAIN),
        "arbitrum" | "arbitrum one" => Some(&ARBITRUM_CHAIN),
        "arb" => Some(&ARBITRUM_TOKEN),
        "hyperliquid" | "hyperevm" => Some(&HYPERLIQUID_CHAIN),
        "hype" => Some(&HYPERLIQUID_TOKEN),
        "robinhood" | "robinhood chain" => Some(&ROBINHOOD_CHAIN),
        "xrp" => Some(&RIPPLE),
        "doge" | "dogecoin" => Some(&DOGECOIN),
        "ada" | "cardano" => Some(&CARDANO),
        "sui" => Some(&SUI),
        "ltc" | "litecoin" => Some(&LITECOIN),
        "uni" | "uniswap" => Some(&UNISWAP),
        "near" => Some(&NEAR),
        "zec" | "zcash" => Some(&ZCASH),
        "dash" => Some(&DASH),
        "ena" | "ethena" => Some(&ETHENA),
        "usdg" | "global dollar" => Some(&GLOBAL_DOLLAR),
        "usd1" => Some(&USD1_WLFI),
        _ => None,
    }
}

/// Network artwork, keyed on the chain id rather than a display name: a name
/// can be spelled many ways, but an id has exactly one meaning.
fn chain_icon(chain_id: u64) -> Option<&'static IconFile> {
    match chain_id {
        1 => Some(&ETHEREUM),
        10 => Some(&OPTIMISM_CHAIN),
        56 => Some(&BINANCECOIN),
        100 => Some(&GNOSIS_CHAIN),
        137 => Some(&POLYGON_CHAIN),
        999 => Some(&HYPERLIQUID_CHAIN),
        4663 => Some(&ROBINHOOD_CHAIN),
        8453 => Some(&BASE_CHAIN),
        43114 => Some(&AVALANCHE_CHAIN),
        42161 => Some(&ARBITRUM_CHAIN),
        59144 => Some(&LINEA_CHAIN),
        81457 => Some(&BLAST_CHAIN),
        534352 => Some(&SCROLL_CHAIN),
        _ => None,
    }
}

/// The mark for a named asset. `branded` is false for a unit that is not the
/// traded asset — a development chain that calls its faucet unit "ETH" keeps
/// initials, however familiar the spelling.
fn asset_mark(name: &str, branded: bool) -> String {
    if let Some(icon) = branded.then(|| token_icon(name)).flatten() {
        return icon_img(icon);
    }
    initials_mark(name)
}

fn monogram(name: &str) -> String {
    asset_mark(name, true)
}

/// A mark for a network row: its own id first, then its display name.
fn network_mark(chain_id: u64, label: &str) -> String {
    match chain_icon(chain_id) {
        Some(icon) => icon_img(icon),
        None => monogram(label),
    }
}

fn asset_label(name: &str) -> String {
    asset_label_with(monogram(name), name)
}

fn asset_label_with(mark: String, name: &str) -> String {
    format!(
        "<span class=\"asset-label\">{mark}<span>{name}</span></span>",
        mark = mark,
        name = html_escape(name),
    )
}

/// What a network row says about the reader's own holdings on it. Three
/// states must stay distinct: never read (—), read and known empty ($0.00),
/// and read but unpriced (Not priced) — a funded row with no fresh quote is
/// an unknown value, not a zero.
fn held_value_label(holdings: &[&Holding]) -> String {
    if holdings.is_empty() {
        return "—".to_owned();
    }
    let funded: Vec<&&Holding> = holdings.iter().filter(|h| h.is_funded()).collect();
    if funded.is_empty() {
        return money(Some(0.0));
    }
    match funded.iter().any(|h| h.value.is_some()) {
        true => {
            let priced: f64 = funded.iter().filter_map(|h| h.value).sum();
            money(Some(priced))
        }
        false => money(None),
    }
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
fn receiving_qr(address: &str) -> String {
    let Ok(code) = qrcode::QrCode::new(address.as_bytes()) else {
        return "<p class=\"muted\">QR unavailable. Use the address below.</p>".to_owned();
    };
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(222, 222)
        .quiet_zone(true)
        .build();
    // The renderer emits an XML declaration intended for standalone files.
    let svg = svg.find("<svg").map(|start| &svg[start..]).unwrap_or(&svg);
    format!(
        "<figure class=\"receiving-qr\" aria-label=\"Receiving address QR code\"><div>{svg}</div><figcaption>Scan to receive</figcaption></figure>"
    )
}

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
         <link rel=\"stylesheet\" href=\"bloom.css\">{script}</head>\
         <body class=\"personal-dashboard\">\
         <a class=\"skip\" href=\"#main\">Skip to content</a>\
         <div class=\"shell\"><header class=\"masthead\">\
         <a class=\"brand\" href=\"index.html\"><strong>/bloom</strong></a>\
         <span class=\"edition\">Read-only · reload to refresh</span></header>\
         <nav aria-label=\"Wallet views\">{nav}</nav>\
         <main id=\"main\"><div class=\"intro\"><div>\
         <h1>{heading}</h1></div>\
         {lede}</div>{body}</main>\
         <footer><span>Read-only projection · nothing here authorizes an action</span>\
         <span><a href=\"AGENTS.md\">How to use these pages</a></span></footer>\
         </div></body></html>\n",
        csp = CSP,
        script = if current == CHAINS_HTML {
            "<script src=\"bloom.js\" defer></script>"
        } else {
            ""
        },
        title = html_escape(title),
        heading = html_escape(heading),
        lede = if lede.is_empty() {
            String::new()
        } else {
            format!("<p class=\"lede\">{}</p>", html_escape(lede))
        },
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
        assert!(html.contains("App positions"), "{html}");
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
    async fn wallets_page_renders_every_projected_wallet() {
        let mut fixture = fixture();
        let reader = crate::test_support::wallet_projection_reader("first", ADDRESS);
        let first = reader.list_wallets().await.unwrap().remove(0);
        let mut second = first.clone();
        second.wallet.wallet_id = bloom_broker_api::Token::new("second").unwrap();
        second.keys[0].addresses = vec!["0x000000000000000000000000000000000000bEEF".to_owned()];
        fixture.handler.projections =
            crate::test_support::wallet_projection_reader_from_many(vec![first, second]);

        let html = render(&fixture.handler, WALLETS_HTML).await;
        assert!(html.contains("2 wallets loaded"), "{html}");
        assert!(html.contains("id=\"wallet-first\""), "{html}");
        assert!(html.contains("id=\"wallet-second\""), "{html}");
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
            if e.name == ICONS_DIR {
                assert_eq!(e.kind, EntryKind::Dir, "the icon set is a directory");
                continue;
            }
            assert_eq!(e.kind, EntryKind::File);
            assert_eq!(e.mode, 0o444, "views pages must be read-only");
        }
    }

    #[tokio::test]
    async fn pages_only_allow_the_bundled_sorter() {
        let fixture = fixture();
        for (page, _) in PAGES {
            let html = render(&fixture.handler, page).await;
            assert!(html.contains("Content-Security-Policy"), "{page}");
            assert!(html.contains("style-src 'self'"), "{page}");
            assert!(html.contains("script-src 'self'"), "{page}");
            assert_eq!(
                html.contains("<script src=\"bloom.js\" defer>"),
                *page == CHAINS_HTML,
                "only Networks needs the sorter: {page}"
            );
            assert!(
                !html.contains("<script>"),
                "{page} must not emit inline code"
            );
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
    async fn receive_shows_the_address_and_embeds_a_portable_qr() {
        let html = render(&fixture().handler, RECEIVE_HTML).await;
        assert!(html.contains(ADDRESS));
        assert!(
            html.contains("<figure class=\"receiving-qr\"") && html.contains("<svg"),
            "the QR must travel with a saved Receive page: {html}"
        );
        assert!(
            !html.contains("../wallets/"),
            "the QR must not depend on the mounted wallet tree"
        );
        assert!(html.contains("1 receiving address"));
    }

    #[tokio::test]
    async fn receive_discovers_only_explicit_solana_identities() {
        const SOLANA: &str = "7Ec4G7dS8v8Y5JvVX8E5S7jvk8eJzEqJqgWkpz6xA4r9";
        let fixture = fixture();
        let mut projection = fixture
            .handler
            .projections
            .list_wallets()
            .await
            .unwrap()
            .remove(0);
        let mut solana_key = projection.keys[0].clone();
        solana_key.key_ref.key_spec = bloom_broker_api::KeySpec::Ed25519;
        solana_key.supported_crypto_suites = vec![bloom_broker_api::CryptoSuite::Ed25519Message];
        solana_key.addresses = vec![
            SOLANA.to_owned(),
            format!("solana:mainnet:{SOLANA}"),
            format!("solana:mainnet:{SOLANA}"),
        ];
        projection.keys.push(solana_key);
        let handler = ViewsHandler::new(
            crate::test_support::wallet_projection_reader_from(projection),
            ChainRegistry::default(),
            bloom_prices::PricesClient::with_base_url("http://127.0.0.1:1"),
            fixture.handler.outbox,
            MarketData::with_base_url("http://127.0.0.1:1"),
        );

        let html = render(&handler, RECEIVE_HTML).await;
        assert!(html.contains("2 receiving addresses"), "{html}");
        assert_eq!(
            html.matches(&format!("class=\"address\">{SOLANA}</code>"))
                .count(),
            1,
            "duplicate CAIP identities must render one Solana card: {html}"
        );
        assert!(html.contains("Send on Solana only."), "{html}");
    }

    #[tokio::test]
    async fn receive_does_not_reinterpret_an_ed25519_key_as_solana() {
        const PLAIN_BASE58: &str = "7Ec4G7dS8v8Y5JvVX8E5S7jvk8eJzEqJqgWkpz6xA4r9";
        let fixture = fixture();
        let mut projection = fixture
            .handler
            .projections
            .list_wallets()
            .await
            .unwrap()
            .remove(0);
        let mut ambiguous_key = projection.keys[0].clone();
        ambiguous_key.key_ref.key_spec = bloom_broker_api::KeySpec::Ed25519;
        ambiguous_key.supported_crypto_suites = vec![bloom_broker_api::CryptoSuite::Ed25519Message];
        ambiguous_key.addresses = vec![PLAIN_BASE58.to_owned()];
        projection.keys.push(ambiguous_key);
        let handler = ViewsHandler::new(
            crate::test_support::wallet_projection_reader_from(projection),
            ChainRegistry::default(),
            bloom_prices::PricesClient::with_base_url("http://127.0.0.1:1"),
            fixture.handler.outbox,
            MarketData::with_base_url("http://127.0.0.1:1"),
        );

        let html = render(&handler, RECEIVE_HTML).await;
        assert!(html.contains("No Solana receiving address"), "{html}");
        assert!(!html.contains(&format!("class=\"address\">{PLAIN_BASE58}</code>")));
    }

    #[tokio::test]
    async fn unpriced_holdings_are_never_valued_at_zero() {
        // No chain is configured, so no balance was read. The page must say so
        // rather than turning missing coverage into $0.00.
        let html = render(&fixture().handler, WALLETS_HTML).await;
        assert!(html.contains("Native balances"), "{html}");
        assert!(html.contains("0 networks answered"), "{html}");
        assert!(html.contains("<strong>—</strong>"), "{html}");
        assert!(
            !html.contains("$0.00"),
            "an absent price must not read as zero"
        );
        // An absence belongs in the supporting line, not in the headline.
        assert!(
            html.contains("<strong>—</strong>"),
            "an unpriced page must not set prose as its metric: {html}"
        );
        assert_eq!(money(None), "Not priced");
        assert_ne!(money(Some(0.0)), money(None));
    }

    #[tokio::test]
    async fn today_shows_an_absence_as_a_dash_not_a_number() {
        let html = render(&fixture().handler, INDEX_HTML).await;
        assert!(
            html.contains("<strong>—</strong>"),
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
        assert!(html.contains("No activity yet."));
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
        assert!(next.contains("1 next move"), "{next}");
        assert!(
            next.contains("fund it before approving"),
            "a policy denial is the reason it will not proceed: {next}"
        );
        // "Failed" would overstate it: these records carry no result and no
        // hash, so the honest claim is that nothing was ever sent.
        assert!(
            next.contains("One record never broadcast"),
            "a single record must agree in number: {next}"
        );
        assert!(next.contains("Why it stopped"));

        let activity = render(&fixture.handler, ACTIVITY_HTML).await;
        for summary in ["Staged tx 0001-62058", "Send 0.05 ETH", "Enso operation"] {
            assert!(activity.contains(summary), "{summary} missing: {activity}");
        }
        assert!(activity.contains("status-success"));
        assert!(activity.contains("status-failed"));
        assert!(activity.contains("status-pending"));
        assert!(activity.contains("Broadcast records show submission, not confirmation"));
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
        assert!(
            html.contains("Bloom broadcast this and kept the hash"),
            "{html}"
        );
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
        assert_eq!(
            short_activity_amount("0.000000000000000001 ETH"),
            "1e-18 ETH"
        );
    }

    #[tokio::test]
    async fn an_empty_outbox_answers_rather_than_showing_nothing() {
        let fixture = fixture();
        let next = render(&fixture.handler, NEXT_MOVES_HTML).await;
        assert!(next.contains("Nothing needs you right now"), "{next}");
        let activity = render(&fixture.handler, ACTIVITY_HTML).await;
        assert!(activity.contains("No activity yet"), "{activity}");
    }

    #[tokio::test]
    async fn policy_reports_a_deny_all_policy_as_denied() {
        // The test projection carries an empty destination allow-set, which is
        // Broker's fail-closed state, not an absence of policy.
        let html = render(&fixture().handler, POLICY_HTML).await;
        assert!(html.contains("No destination is permitted"), "{html}");
        assert!(!html.contains("Every send denied"), "{html}");
        assert!(html.contains("prerequisites, not permission to execute"));
        assert!(html.contains("Policy version 1"), "{html}");
    }

    #[tokio::test]
    async fn contacts_deduplicate_normalized_transfer_recipients_and_use_saved_names() {
        let mut fixture = fixture();
        let recipient = "0x000000000000000000000000000000000000bEEF";
        for (id, address) in [
            ("evm-contact-1", recipient),
            (
                "evm-contact-2",
                "0x000000000000000000000000000000000000beef",
            ),
        ] {
            stage_files(
                &fixture,
                "sent",
                id,
                "# Send\n",
                &[(
                    "intent.json",
                    &format!(
                        "{{\"wallet\":\"alice\",\"chain\":\"base\",\"chain_id\":8453,\"action_kind\":\"native_transfer\",\"to\":\"{address}\",\"value_wei\":\"1\",\"data_hex\":\"0x\",\"created_ms\":1}}"
                    ),
                )],
            );
        }
        let contacts = render(&fixture.handler, CONTACTS_HTML).await;
        assert!(contacts.contains("Suggested"), "{contacts}");
        assert!(
            contacts.contains("<strong>2</strong> transfers"),
            "{contacts}"
        );
        assert_eq!(contacts.matches("Full address and activity").count(), 1);

        let mut book = AddressBook::default();
        book.set("treasury", parse_address(recipient).unwrap());
        fixture.handler = fixture.handler.with_address_book(Arc::new(book));
        let activity = render(&fixture.handler, ACTIVITY_HTML).await;
        assert!(
            activity.contains("Send 0.000000000000000001 wei → treasury")
                || activity.contains("→ treasury"),
            "{activity}"
        );
        let contacts = render(&fixture.handler, CONTACTS_HTML).await;
        assert!(contacts.contains("<h3>treasury</h3>"), "{contacts}");
        assert!(!contacts.contains("Suggested</span><h3>"), "{contacts}");
    }

    #[tokio::test]
    async fn contract_and_unknown_targets_never_become_suggested_contacts() {
        let fixture = fixture();
        for (id, kind) in [("call-1", "contract_call"), ("call-2", "mystery")] {
            stage_files(
                &fixture,
                "sent",
                id,
                "# Call\n",
                &[(
                    "intent.json",
                    &format!(
                        "{{\"chain\":\"ethereum\",\"chain_id\":1,\"action_kind\":\"{kind}\",\"to\":\"0x000000000000000000000000000000000000cafe\",\"data_hex\":\"0x12345678\"}}"
                    ),
                )],
            );
        }
        let contacts = render(&fixture.handler, CONTACTS_HTML).await;
        assert!(contacts.contains("1 contract-call target"), "{contacts}");
        assert!(contacts.contains("1 unclassified target"), "{contacts}");
        assert!(contacts.contains("unknown stays unknown"), "{contacts}");
        assert!(contacts.contains("No unnamed recipient appears more than once"));
    }

    #[test]
    fn standard_transfer_calldata_yields_the_recipient_only() {
        let calldata = "0xa9059cbb0000000000000000000000004e2d8ba106d008f653de18ce5ee660ec150fddd700000000000000000000000000000000000000000000000000000000000f4240";
        assert_eq!(
            decoded_evm_transfer_recipient(calldata),
            Some("0x4e2D8bA106D008f653de18CE5EE660Ec150Fddd7".to_owned())
        );
        assert!(decoded_evm_transfer_recipient("0x12345678").is_none());
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
        assert_eq!(
            explorer_address_url(81457, "0xabc").as_deref(),
            Some("https://blastscan.io/address/0xabc")
        );
        assert_eq!(
            explorer_address_url(534352, "0xabc").as_deref(),
            Some("https://scrollscan.com/address/0xabc")
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
    fn known_icons_come_from_the_mount_and_unknown_names_have_a_fallback() {
        // A file reference, so an icon's bytes are served once rather than
        // duplicated into the HTML for every row that shows one.
        assert!(
            monogram("Ethereum")
                .contains("<img class=\"asset-mark\" src=\"icons/token-ethereum.png\"")
        );
        assert!(!monogram("Ethereum").contains("https://"));
        assert!(!monogram("Ethereum").contains("data:"));
        assert!(monogram("solana-devnet").contains(">SO<"));
        assert!(asset_label("Base").contains("class=\"asset-label\""));
    }

    #[test]
    fn chain_marks_follow_the_chain_id_not_its_display_name() {
        // Any display name spelling must land on the same artwork.
        assert!(network_mark(1, "Anything").contains("src=\"icons/token-ethereum.png\""));
        assert!(network_mark(10, "Anything").contains("src=\"icons/chain-optimism.jpg\""));
        assert!(network_mark(59144, "Anything").contains("src=\"icons/chain-linea.jpg\""));
        assert!(network_mark(81457, "Anything").contains("src=\"icons/chain-blast.jpg\""));
        assert!(network_mark(534352, "Anything").contains("src=\"icons/chain-scroll.jpg\""));
        assert!(network_mark(8453, "Base").contains("src=\"icons/chain-base.webp\""));
        assert!(network_mark(137, "Polygon").contains("src=\"icons/chain-polygon.jpg\""));
        // The venue token and its chain are different things.
        assert!(monogram("hype").contains("src=\"icons/token-hyperliquid.jpg\""));
        assert!(monogram("hyperevm").contains("src=\"icons/chain-Hyperliquid.webp\""));
    }

    #[tokio::test]
    async fn the_icon_set_is_served_as_files_and_nothing_else() {
        let handler = fixture().handler;
        let png = handler
            .read(&VfsPath::parse("icons/token-ethereum.png").unwrap())
            .await
            .unwrap();
        assert_eq!(&png[..4], b"\x89PNG", "a real PNG is served");
        let listed = handler
            .list(&VfsPath::parse(ICONS_DIR).unwrap())
            .await
            .unwrap();
        assert!(listed.iter().any(|e| e.name == "token-ethereum.png"));
        assert_eq!(listed.len(), ICON_FILES.len());
        // Any other name under `icons/` is refused. Dot segments are resolved
        // by the path layer before they get here, so a lookup can only ever
        // land on one of the bundled names.
        let stranger = VfsPath::parse("icons/nope.png").unwrap();
        assert!(handler.read(&stranger).await.is_err());
        assert!(handler.lookup(&stranger).await.is_err());
    }

    #[test]
    fn an_off_market_unit_keeps_initials_even_when_the_spelling_is_familiar() {
        let mut faucet = holding_fixture("tempo", 4217, "ETH", 4.2e57, None);
        assert!(
            asset_mark(&faucet.symbol, !faucet.is_off_market()).contains(">ET<"),
            "a development chain's ETH must not wear ether's logo"
        );
        faucet.chain_id = 1;
        assert!(
            asset_mark(&faucet.symbol, !faucet.is_off_market())
                .contains("src=\"icons/token-ethereum.png\""),
            "real ether is the branded asset"
        );
    }

    fn holding_fixture(
        chain: &str,
        chain_id: u64,
        symbol: &str,
        amount: f64,
        value: Option<f64>,
    ) -> Holding {
        Holding {
            wallet: "w".into(),
            chain: chain.into(),
            chain_id,
            label: chain.into(),
            symbol: symbol.into(),
            quantity: format!("{amount}"),
            amount,
            value,
        }
    }

    #[test]
    fn a_network_holding_reads_as_unread_empty_unpriced_or_valued() {
        // Never read.
        assert_eq!(held_value_label(&[]), "—");
        // Read, and known to hold nothing.
        let empty = holding_fixture("base", 8453, "ETH", 0.0, None);
        assert_eq!(held_value_label(&[&empty]), "$0.00");
        // Read and funded, but no fresh quote: unknown, not zero.
        let unpriced = holding_fixture("base", 8453, "ETH", 1.5, None);
        assert_eq!(held_value_label(&[&unpriced]), "Not priced");
        // Priced.
        let priced = holding_fixture("base", 8453, "ETH", 1.5, Some(3000.0));
        assert_eq!(held_value_label(&[&priced]), "$3,000.00");
        // Partly priced: the priced part is counted, the rest stays absent.
        assert_eq!(held_value_label(&[&unpriced, &priced]), "$3,000.00");
    }

    /// A registry of configured but unreachable chains, so the Networks page
    /// can be exercised the way a real daemon with a down provider would be.
    fn fixture_with_unreachable_chains() -> Fixture {
        let mut base = fixture();
        let chains = ChainRegistry::default();
        for (name, chain_id, display) in [
            ("ethereum", 1u64, "Ethereum"),
            ("base", 8453, "Base"),
            ("tempo", 4217, "Tempo"),
        ] {
            chains.add(
                bloom_evm::ChainClient::new(bloom_proto::ChainSpec {
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
                })
                .unwrap(),
            );
        }
        base.handler = ViewsHandler::new(
            crate::test_support::wallet_projection_reader("alice", ADDRESS),
            chains,
            bloom_prices::PricesClient::with_base_url("http://127.0.0.1:1"),
            Arc::new(super::super::outbox::OutboxHandler::new(
                super::super::outbox::CentralOutbox::new(base.outbox_root.clone()),
            )),
            MarketData::with_base_url("http://127.0.0.1:1"),
        );
        base
    }

    #[tokio::test]
    async fn fees_html_is_the_networks_page_for_old_bookmarks() {
        let fixture = fixture();
        let fees = render(&fixture.handler, FEES_HTML).await;
        let networks = render(&fixture.handler, CHAINS_HTML).await;
        assert_eq!(fees, networks, "the alias must serve the merged page");
        assert!(fees.contains("Networks"), "{fees:.200}");
    }

    #[tokio::test]
    async fn a_network_without_answers_shows_dashes_never_zeros() {
        let fixture = fixture_with_unreachable_chains();
        let html = render(&fixture.handler, CHAINS_HTML).await;
        // No chain answered and no provider returned: every total is a dash.
        assert!(html.contains("Partial balance coverage"), "{html}");
        assert!(
            html.contains("Your priced native assets <strong>—</strong>"),
            "{html}"
        );
        assert!(!html.contains("$0.00"), "unavailable is not zero: {html}");
        assert!(!html.contains("Not priced"), "{html}");
        // The ranked rows still appear, one per configured chain.
        assert!(html.contains("Ethereum"), "{html:.400}");
        assert!(html.contains("Tempo"), "{html:.400}");
    }

    #[tokio::test]
    async fn solana_network_data_does_not_require_an_evm_configuration() {
        let html = render(&fixture().handler, CHAINS_HTML).await;
        assert!(html.contains("data-name=\"solana\""), "{html}");
        assert!(html.contains("Wallet account unavailable"), "{html}");
        assert!(html.contains("network-columns"), "{html}");
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
        //   VIEWS_PROJECTIONS=~/bloom/wallets
        //     (loads every direct <wallet>/projection.json; preferred)
        //   VIEWS_PROJECTION=~/bloom/wallets/<wallet>/projection.json
        //     (one-file compatibility input)
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
        let projections = match std::env::var("VIEWS_PROJECTIONS") {
            Ok(root) => {
                let mut paths = std::fs::read_dir(&root)
                    .unwrap()
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter_map(|path| {
                        if path.is_dir() {
                            Some(path.join("projection.json"))
                        } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                            Some(path)
                        } else {
                            None
                        }
                    })
                    .filter(|path| path.is_file())
                    .collect::<Vec<_>>();
                paths.sort();
                let loaded = paths
                    .iter()
                    .map(|path| {
                        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
                    })
                    .collect::<Vec<_>>();
                assert!(
                    !loaded.is_empty(),
                    "VIEWS_PROJECTIONS contained no projection.json files"
                );
                crate::test_support::wallet_projection_reader_from_many(loaded)
            }
            Err(_) => match std::env::var("VIEWS_PROJECTION") {
                Ok(path) => crate::test_support::wallet_projection_reader_from(
                    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap(),
                ),
                Err(_) => crate::test_support::wallet_projection_reader("everyday", ADDRESS),
            },
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
        let handler = match std::env::var("VIEWS_ADDRESS_BOOK") {
            Ok(path) => handler.with_address_book(Arc::new(
                AddressBook::load(std::path::Path::new(&path)).unwrap(),
            )),
            Err(_) => handler,
        };
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
        // `fees.html` is no longer in `PAGES` but is still served as an alias
        // of the Networks page. A dump that omits it would leave an old fee
        // dashboard visible to anyone following a stale bookmark.
        let alias = render(&staged.handler, CHAINS_HTML).await;
        std::fs::write(std::path::Path::new(&out).join(FEES_HTML), alias).unwrap();
        std::fs::write(std::path::Path::new(&out).join(BLOOM_CSS_NAME), BLOOM_CSS).unwrap();
        std::fs::write(std::path::Path::new(&out).join(BLOOM_JS_NAME), BLOOM_JS).unwrap();
        let icons = std::path::Path::new(&out).join(ICONS_DIR);
        std::fs::create_dir_all(&icons).unwrap();
        for icon in ICON_FILES {
            std::fs::write(icons.join(icon.name), icon.bytes).unwrap();
        }
    }
}
