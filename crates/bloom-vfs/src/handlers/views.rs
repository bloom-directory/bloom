//! `views/...` — read-only pages for a person to open in a browser.
//!
//! Paths handled:
//! - `views/`                 — list the available pages
//! - `views/wallets.html`     — native balances per wallet, with valuation
//! - `views/receive.html`     — receiving addresses grouped by wallet
//! - `views/activity.html`    — what completed, failed, or is still staged
//! - `views/bloom.css`        — the shared Bloom stylesheet (compiled in)
//! - `views/bloom.js`         — opens the Receive wallet a link points at
//! - `views/AGENTS.md`        — how an agent should use these pages
//!
//! These pages observe. Nothing here stages, approves, or executes an action,
//! and their only script is the bundled local one: the mount serves them as
//! ordinary files, so a browser opens one straight off the filesystem.
//! Matching Bloom's visual language does not make a page a trusted
//! authorization surface — passkeys and private input stay in Broker's own
//! page.
//!
//! A page always renders. An unavailable source becomes visible prose or an
//! "Unavailable" cell, never a fabricated zero and never an `EIO` that makes
//! `cat` of the whole page fail. A missing price leaves a row unpriced rather
//! than valuing it at zero, and a quote older than an hour does not price
//! anything at all.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bloom_evm::ChainRegistry;
use bloom_machine_client::{ProjectionFreshness, WalletProjection, WalletProjectionReader};
use bloom_prices::{CoinId, PricesClient};
use bloom_proto::{AddressBook, checksum_address, parse_address};

use super::outbox::OutboxHandler;
use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const BLOOM_CSS: &str = include_str!("../assets/bloom.css");
const VIEWS_AGENTS_MD: &str = include_str!("../docs/views-agents.md");

const WALLETS_HTML: &str = "wallets.html";
const RECEIVE_HTML: &str = "receive.html";
const ACTIVITY_HTML: &str = "activity.html";
const BLOOM_CSS_NAME: &str = "bloom.css";
const BLOOM_JS_NAME: &str = "bloom.js";
const BLOOM_JS: &str = include_str!("../assets/bloom.js");
const AGENTS_MD_NAME: &str = "AGENTS.md";

/// Every page, in reading order. Drives both the directory listing and the
/// navigation, so a link can never point at a page that is not served.
const PAGES: &[(&str, &str)] = &[
    (WALLETS_HTML, "Wallets"),
    (RECEIVE_HTML, "Receive"),
    (ACTIVITY_HTML, "Activity"),
];

/// The mount re-reads on every browser access (`actimeo=0`), so a short
/// router TTL keeps a reload burst from re-reading balances per request.
/// The compiled-in assets need no cache entry at all.
const PAGE_TTL: Duration = Duration::from_secs(5);

/// One unreachable chain must not hold up a page. Each balance read gets its
/// own budget and an expired one renders as "Unavailable".
// Allow the transport's 200/400/800 ms backoffs plus actual network latency.
const BALANCE_TIMEOUT: Duration = Duration::from_secs(8);

/// All balance reads for one page share this budget. Accounts are read at
/// most `PORTFOLIO_CONCURRENCY` at a time, so many HD accounts against a
/// stalled endpoint cost one budget rather than one `BALANCE_TIMEOUT` each.
/// An account still unread when it expires is reported, never shown as empty.
const PORTFOLIO_BUDGET: Duration = Duration::from_secs(10);
const PORTFOLIO_CONCURRENCY: usize = 8;
/// One outbox state can accumulate every operation ever recorded. Read the
/// newest directories and say the rest were omitted.
const ACTION_SCAN_LIMIT: usize = 256;
/// Keep the last successful native-balance observation briefly. A transient
/// RPC failure must not make a wallet appear to lose funds between reloads;
/// older observations expire rather than becoming an indefinite estimate.
const BALANCE_CACHE_MAX_AGE: Duration = Duration::from_secs(5 * 60);

/// Valuation is optional; the page is still useful unpriced.
const PRICE_TIMEOUT: Duration = Duration::from_secs(3);

/// A valuation bound, not a claim that every provider updates hourly. Past
/// this, a quote does not price anything.
const QUOTE_MAX_AGE_SECS: u64 = 3600;

/// Content-Security-Policy for every page. `style-src 'self'` is what lets a
/// page link the sibling `bloom.css` instead of carrying a copy that drifts;
/// `img-src 'self'` is kept for same-origin images. The only script permitted
/// is the bundled, same-origin one; every page remains useful without it.
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
    address_book: Arc<AddressBook>,
    /// Read-only Solana clients keyed by chain name, for native SOL balances.
    /// Separate from the EVM registry: a chain readable here but absent from
    /// the transfer engines is readable but cannot stage, and the pages only
    /// read. Absent it, Solana rows simply do not appear.
    solana: Option<bloom_solana::SolanaChainRegistry>,
    /// Recent successful native-balance reads, shared by cloned handlers.
    /// Values are re-priced on each render; only the observed quantity is
    /// retained, and every fallback is disclosed in the page's coverage data.
    balance_cache: Arc<parking_lot::RwLock<BTreeMap<BalanceCacheKey, CachedHolding>>>,
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
            address_book: Arc::new(AddressBook::default()),
            solana: None,
            balance_cache: Arc::new(parking_lot::RwLock::new(BTreeMap::new())),
        }
    }

    /// Attach the read-only Solana client registry so the pages can read
    /// native SOL balances beside the EVM ones. Independent of the transfer
    /// engines: chain listing and balance reads resolve here.
    pub fn with_solana_reads(mut self, chains: bloom_solana::SolanaChainRegistry) -> Self {
        self.solana = Some(chains);
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
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let page = match path.segments() {
            [s] if s == BLOOM_CSS_NAME => return Ok(BLOOM_CSS.as_bytes().to_vec()),
            [s] if s == BLOOM_JS_NAME => return Ok(BLOOM_JS.as_bytes().to_vec()),
            [s] if s == AGENTS_MD_NAME => return Ok(VIEWS_AGENTS_MD.as_bytes().to_vec()),
            [s] if is_page(s) => s.clone(),
            _ => return Err(HandlerError::NotAFile(path.to_string_path())),
        };
        let rendered = match page.as_str() {
            WALLETS_HTML => self.render_wallets().await,
            RECEIVE_HTML => self.render_receive().await,
            ACTIVITY_HTML => self.render_activity().await,
            _ => return Err(HandlerError::NotAFile(path.to_string_path())),
        };
        Ok(rendered.into_bytes())
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if path.is_root() {
            // `ls -l` does not render children, so give the static assets a
            // real size hint here; pages are sized by the mount at getattr.
            let mut entries = vec![agents_entry(), css_entry(), js_entry()];
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
                    Ok(mut wallets) => {
                        for wallet in &mut wallets {
                            wallet.freshness = ProjectionFreshness::Stale;
                        }
                        (wallets, false)
                    }
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
    /// price what can be priced. Every account's reads run concurrently under
    /// one shared budget, so a slow endpoint costs one budget per page rather
    /// than one per account.
    async fn portfolio(&self) -> Portfolio {
        let (projections, projections_unavailable) = self.wallet_projections().await;
        let evm_chains = self.distinct_evm_chains();
        let solana_chains = self.solana_chain_names();
        let mut portfolio = Portfolio {
            projections_unavailable,
            ..Portfolio::default()
        };

        let mut jobs = Vec::new();
        for projection in &projections {
            let wallet = projection.wallet_id().as_str().to_owned();
            // Every address the projection reports: the primary EVM key plus
            // each numbered account's EVM and Solana addresses. One wallet
            // holds across accounts, so every balance row carries the wallet
            // id and names its account separately.
            let inventory = wallet_addresses(projection);
            portfolio.wallets.push(WalletSummary {
                id: wallet.clone(),
                address: projection.primary_address().ok().map(str::to_owned),
                kind: projection.wallet.wallet_kind.as_str().to_owned(),
            });
            if projection.freshness == ProjectionFreshness::Stale {
                portfolio.stale = true;
            }
            if inventory.evm.is_empty() && inventory.solana.is_empty() {
                tracing::debug!(wallet = %wallet, "views.address_unavailable");
            }
            for (account, address_text) in inventory.evm {
                let Ok(address) = address_text.parse::<alloy::primitives::Address>() else {
                    tracing::debug!(wallet = %wallet, "views.address_unparsed");
                    continue;
                };
                jobs.push(BalanceJob::Evm {
                    wallet: wallet.clone(),
                    account,
                    address,
                });
            }
            for (account, address) in inventory.solana {
                jobs.push(BalanceJob::Solana {
                    wallet: wallet.clone(),
                    account,
                    address,
                });
            }
        }
        self.read_all_balances(&mut portfolio, jobs, &evm_chains, &solana_chains)
            .await;

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
                .then_with(|| {
                    (&a.wallet, &a.label, &a.account).cmp(&(&b.wallet, &b.label, &b.account))
                })
        });
        portfolio
    }

    /// Run every account's balance reads, `PORTFOLIO_CONCURRENCY` at a time,
    /// within `PORTFOLIO_BUDGET`. Only that many tasks exist, however many
    /// accounts were projected. Holdings arrive as each read finishes; the
    /// caller sorts. An account that has not answered when the budget expires
    /// has every network it would have read marked unavailable and is counted
    /// in `accounts_unread`, so totals say they are partial.
    async fn read_all_balances(
        &self,
        portfolio: &mut Portfolio,
        jobs: Vec<BalanceJob>,
        evm_chains: &[String],
        solana_chains: &[String],
    ) {
        let deadline = tokio::time::Instant::now() + PORTFOLIO_BUDGET;
        let this = Arc::new(self.clone());
        let evm: Arc<[String]> = evm_chains.into();
        let solana: Arc<[String]> = solana_chains.into();
        let jobs = Arc::new(jobs);
        let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut reads = tokio::task::JoinSet::new();
        let workers = PORTFOLIO_CONCURRENCY.min(jobs.len());
        for _ in 0..workers {
            let (this, evm, solana, jobs, next, tx) = (
                this.clone(),
                evm.clone(),
                solana.clone(),
                jobs.clone(),
                next.clone(),
                tx.clone(),
            );
            reads.spawn(async move {
                loop {
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if index >= jobs.len() {
                        break;
                    }
                    let mut read = match &jobs[index] {
                        BalanceJob::Evm {
                            wallet,
                            account,
                            address,
                        } => {
                            let mut read = this.read_balances(wallet, *address, &evm).await;
                            for holding in &mut read.holdings {
                                holding.account.clone_from(account);
                            }
                            read
                        }
                        BalanceJob::Solana {
                            wallet,
                            account,
                            address,
                        } => {
                            this.read_solana_balances(wallet, account, address, &solana)
                                .await
                        }
                    };
                    read.cached.sort();
                    read.cached.dedup();
                    if tx.send((index, read)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);

        let mut answered = vec![false; jobs.len()];
        loop {
            let incoming = match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(incoming)) => Some(incoming),
                Ok(None) => break,
                Err(_) => {
                    tracing::debug!("views.portfolio_budget_expired");
                    reads.abort_all();
                    while let Ok(incoming) = rx.try_recv() {
                        Self::record_balance(portfolio, &mut answered, incoming);
                    }
                    break;
                }
            };
            if let Some(incoming) = incoming {
                Self::record_balance(portfolio, &mut answered, incoming);
            }
        }
        for (index, job) in jobs.iter().enumerate() {
            if answered[index] {
                continue;
            }
            let (wallet, account, address, chains) = match job {
                BalanceJob::Evm {
                    wallet,
                    account,
                    address,
                } => (wallet, account, format!("{address:#x}"), evm_chains),
                BalanceJob::Solana {
                    wallet,
                    account,
                    address,
                } => (wallet, account, address.clone(), solana_chains),
            };
            let mut has_unavailable = false;
            for chain in chains {
                if let Some(mut holding) = self.cached_balance(wallet, chain, &address) {
                    holding.account = account.clone();
                    portfolio.holdings.push(holding);
                    portfolio
                        .cached_balances
                        .push((wallet.clone(), chain.clone()));
                } else {
                    has_unavailable = true;
                    portfolio.unavailable.push((wallet.clone(), chain.clone()));
                }
            }
            portfolio.accounts_unread += usize::from(has_unavailable);
        }
    }

    fn record_balance(
        portfolio: &mut Portfolio,
        answered: &mut [bool],
        incoming: (usize, BalanceRead),
    ) {
        let (index, read) = incoming;
        answered[index] = true;
        portfolio.holdings.extend(read.holdings);
        portfolio.unavailable.extend(read.unavailable);
        portfolio.cached_balances.extend(read.cached);
    }

    /// Configured EVM chain names, one per chain id, in name order. This is
    /// the set `read_balances` reads, so an unread account can name exactly
    /// the networks it is missing.
    fn distinct_evm_chains(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        self.sorted_chains()
            .into_iter()
            .filter(|chain| {
                self.chains
                    .get(chain)
                    .is_some_and(|client| seen.insert(client.spec().chain_id))
            })
            .collect()
    }

    fn remember_balance(&self, wallet: &str, chain: &str, address: &str, holding: &Holding) {
        let key = BalanceCacheKey::new(wallet, chain, address);
        self.balance_cache.write().insert(
            key,
            CachedHolding {
                observed_at: Instant::now(),
                holding: holding.clone(),
            },
        );
    }

    fn cached_balance(&self, wallet: &str, chain: &str, address: &str) -> Option<Holding> {
        let key = BalanceCacheKey::new(wallet, chain, address);
        let mut cache = self.balance_cache.write();
        let cached = cache.get(&key)?;
        if cached.observed_at.elapsed() <= BALANCE_CACHE_MAX_AGE {
            return Some(cached.holding.clone());
        }
        cache.remove(&key);
        None
    }

    /// Native balance on every configured chain for one address. The reads
    /// run concurrently, so one slow endpoint costs a single budget rather
    /// than the sum of them.
    async fn read_balances(
        &self,
        owner: &str,
        address: alloy::primitives::Address,
        chains: &[String],
    ) -> BalanceRead {
        let mut reads = tokio::task::JoinSet::new();
        let mut seen_chains = BTreeSet::new();
        for chain in chains {
            let Some(client) = self.chains.get(chain) else {
                continue;
            };
            if !client.spec().has_native_token() || !seen_chains.insert(client.spec().chain_id) {
                continue;
            }
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
        let mut read = BalanceRead::default();
        let address_text = format!("{address:#x}");
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
                    let holding = Holding {
                        label: self.network_label(&chain),
                        wallet: owner.to_owned(),
                        chain,
                        price_key: native_asset_market(chain_id),
                        account: String::new(),
                        symbol,
                        quantity,
                        amount,
                        value: None,
                    };
                    self.remember_balance(owner, &holding.chain, &address_text, &holding);
                    read.holdings.push(holding);
                }
                None => {
                    if let Some(holding) = self.cached_balance(owner, &chain, &address_text) {
                        read.holdings.push(holding);
                        read.cached.push((owner.to_owned(), chain));
                    } else {
                        read.unavailable.push((owner.to_owned(), chain));
                    }
                }
            }
        }
        read
    }

    /// Configured Solana chain names, sorted. Empty when no Solana registry
    /// is attached or no Solana chain is configured: Solana rows then simply
    /// do not appear.
    fn solana_chain_names(&self) -> Vec<String> {
        let mut chains = self
            .solana
            .as_ref()
            .map(|registry| registry.list_names())
            .unwrap_or_default();
        chains.sort();
        chains
    }

    /// Native SOL balance on every configured Solana chain for one address.
    /// Lamports become SOL at nine decimals with exact integer math; a zero
    /// balance is kept for the same reason as on EVM. A test-network chain
    /// carries no market key, so faucet lamports are never valued as SOL.
    async fn read_solana_balances(
        &self,
        owner: &str,
        account: &str,
        address: &str,
        chains: &[String],
    ) -> BalanceRead {
        let Some(registry) = self.solana.clone() else {
            return BalanceRead::default();
        };
        let mut reads = tokio::task::JoinSet::new();
        for chain in chains {
            let Some(client) = registry.get(chain) else {
                continue;
            };
            let name = chain.clone();
            let address = address.to_owned();
            reads.spawn(async move {
                let lamports =
                    match tokio::time::timeout(BALANCE_TIMEOUT, client.get_balance(&address)).await
                    {
                        Ok(Ok(lamports)) => Some(lamports),
                        Ok(Err(error)) => {
                            tracing::debug!(chain = %name, error = %error, "views.solana_balance_unavailable");
                            None
                        }
                        Err(_) => {
                            tracing::debug!(chain = %name, "views.solana_balance_timeout");
                            None
                        }
                    };
                (name, lamports)
            });
        }
        let mut read = BalanceRead::default();
        while let Some(joined) = reads.join_next().await {
            let Ok((chain, lamports)) = joined else {
                continue;
            };
            match lamports {
                Some(raw) => {
                    let quantity = format!("{}.{:09}", raw / 1_000_000_000, raw % 1_000_000_000);
                    let amount = quantity.parse::<f64>().unwrap_or(0.0);
                    // A test network's lamports are faucet funds, never SOL.
                    let price_key = if is_test_network(&chain) {
                        None
                    } else {
                        Some("coingecko:solana")
                    };
                    let holding = Holding {
                        label: solana_network_label(&chain),
                        wallet: owner.to_owned(),
                        chain,
                        price_key,
                        account: account.to_owned(),
                        symbol: "SOL".to_owned(),
                        quantity,
                        amount,
                        value: None,
                    };
                    self.remember_balance(owner, &holding.chain, address, &holding);
                    read.holdings.push(holding);
                }
                None => {
                    if let Some(holding) = self.cached_balance(owner, &chain, address) {
                        read.holdings.push(holding);
                        read.cached.push((owner.to_owned(), chain));
                    } else {
                        read.unavailable.push((owner.to_owned(), chain));
                    }
                }
            }
        }
        read
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
            .filter_map(|holding| holding.price_key)
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
                Ok(Ok(quote))
                    if quote.price.is_finite()
                        && quote.price >= 0.0
                        && fresh_quote(quote.timestamp, now) =>
                {
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

        let mut priced_total = 0.0_f64;
        for holding in &mut portfolio.holdings {
            let Some(key) = holding.price_key else {
                continue;
            };
            if let Some(price) = quotes.get(key) {
                holding.value = Some(holding.amount * price)
                    .filter(|value| value.is_finite() && (priced_total + value).is_finite());
                priced_total += holding.value.unwrap_or(0.0);
                portfolio.price_coverage_gap |= holding.value.is_none();
            }
        }
    }

    /// Central outbox actions across every lifecycle state, newest first.
    /// Reached through the outbox handler's own trait, so this page cannot
    /// drift from what `/outbox` reports.
    async fn actions(&self) -> (Vec<Action>, bool) {
        let mut actions = Vec::new();
        let mut incomplete = false;
        for state in ACTION_STATES {
            let mut listing = match Handler::list(&*self.outbox, &state_path(state)).await {
                Ok(entries) => entries,
                Err(error) => {
                    tracing::debug!(state = %state, error = %error, "views.outbox_list_unavailable");
                    incomplete = true;
                    continue;
                }
            };
            if listing.len() > ACTION_SCAN_LIMIT {
                incomplete = true;
                listing.sort_by_key(|entry| std::cmp::Reverse(entry.modified));
                listing.truncate(ACTION_SCAN_LIMIT);
            }
            for entry in listing {
                let id = entry.name.clone();
                let modified_ms = entry.modified.and_then(|time| {
                    time.duration_since(UNIX_EPOCH)
                        .ok()
                        .map(|since| since.as_millis() as u64)
                });
                let plan = self
                    .action_file(state, &id, "plan.md", &mut incomplete)
                    .await;
                let status = self
                    .action_file(state, &id, "status.json", &mut incomplete)
                    .await;
                let intent = self
                    .action_file(state, &id, "intent.json", &mut incomplete)
                    .await
                    .as_deref()
                    .and_then(parse_intent);
                // The broadcast hash is the result's own field; `status.json`
                // repeats it. Either answers, and neither invents one.
                let result = self
                    .action_file(state, &id, "result.json", &mut incomplete)
                    .await;
                let tx_hash = result
                    .as_deref()
                    .and_then(|text| json_field(text, "tx_hash"))
                    .or_else(|| {
                        status
                            .as_deref()
                            .and_then(|text| json_field(text, "tx_hash"))
                    });
                // A challenge proves a ceremony was prepared, not its outcome.
                let awaited_approval = self
                    .action_file(state, &id, "approval_challenge.json", &mut incomplete)
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
                    .map(|wei| {
                        self.native_amount(
                            chain.as_deref(),
                            intent.as_ref().and_then(|i| i.chain_id),
                            wei,
                        )
                    });
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
                    fee: None,
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
        (actions, incomplete)
    }

    /// The paid gas fee for every action whose receipt resolves, read from
    /// the chain itself through this daemon's own registry. Receipts fetch
    /// concurrently under one budget each, like balances; an unresolvable
    /// receipt leaves the row without a fee rather than with a guess.
    async fn resolve_fees(&self, actions: &mut [Action]) {
        let mut reads = tokio::task::JoinSet::new();
        // Only the activity page needs receipts. Bound requests independently
        // of the size of durable history; older records remain available.
        for (n, action) in actions.iter().enumerate().take(64) {
            let (Some(chain), Some(hash)) = (action.chain.clone(), action.tx_hash.clone()) else {
                continue;
            };
            let Some(client) = self.chains.get(&chain) else {
                continue;
            };
            if action.intent.as_ref().and_then(|intent| intent.chain_id)
                != Some(client.spec().chain_id)
            {
                continue;
            }
            let Ok(hash) = hash.parse::<alloy::primitives::B256>() else {
                continue;
            };
            reads.spawn(async move {
                let receipt =
                    match tokio::time::timeout(BALANCE_TIMEOUT, client.receipt(hash)).await {
                        Ok(Ok(receipt)) => receipt.filter(|receipt| receipt.transaction_hash == hash),
                        Ok(Err(error)) => {
                            tracing::debug!(chain = %chain, error = %error, "views.receipt_unavailable");
                            None
                        }
                        Err(_) => {
                            tracing::debug!(chain = %chain, "views.receipt_timeout");
                            None
                        }
                    };
                (n, receipt, client.spec().native_decimals, client.spec().native_symbol.clone())
            });
        }
        while let Some(joined) = reads.join_next().await {
            let Ok((n, receipt, decimals, symbol)) = joined else {
                continue;
            };
            let Some(receipt) = receipt else {
                continue;
            };
            actions[n].fee = Some(format_fee(
                receipt.gas_used,
                receipt.effective_gas_price,
                decimals,
                &symbol,
            ));
        }
    }

    /// A native-unit amount on a chain this daemon has configured. Without
    /// that chain's own decimals the raw wei figure is the honest answer:
    /// assuming 18 would silently mis-scale a chain that does not use them.
    fn native_amount(&self, chain: Option<&str>, recorded_id: Option<u64>, wei: &str) -> String {
        let Ok(raw) = wei.parse::<alloy::primitives::U256>() else {
            return format!("{wei} wei");
        };
        match chain
            .and_then(|name| self.chains.get(name))
            .filter(|client| recorded_id.is_some_and(|id| id == client.spec().chain_id))
        {
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

    async fn action_file(
        &self,
        state: &str,
        id: &str,
        file: &str,
        incomplete: &mut bool,
    ) -> Option<String> {
        let path = VfsPath::parse(&format!("{state}/{id}/{file}")).ok()?;
        match Handler::read(&*self.outbox, &path).await {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text)
                    if !file.ends_with(".json")
                        || serde_json::from_str::<serde_json::Value>(&text).is_ok() =>
                {
                    Some(text)
                }
                _ => {
                    *incomplete = true;
                    None
                }
            },
            Err(HandlerError::NotFound(_)) => None,
            Err(error) => {
                tracing::debug!(state = %state, id = %id, file = %file, error = %error, "views.outbox_read_unavailable");
                *incomplete = true;
                None
            }
        }
    }

    async fn render_wallets(&self) -> String {
        let portfolio = self.portfolio().await;
        let funded = portfolio.funded();
        let off_market = portfolio.off_market();
        let empty = portfolio.empty_networks();
        let priced: Vec<&&Holding> = funded.iter().filter(|h| h.value.is_some()).collect();
        let total: f64 = funded.iter().filter_map(|h| h.value).sum();

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
            "<section class=\"inventory-summary\"><div>\
             <strong>{count}</strong></div><div class=\"inventory-value\" {single}>\
             <strong>{value}</strong><span>Native balances{partial}</span></div></section>",
            count = html_escape(&count_noun(
                portfolio.wallets.len(),
                "wallet loaded",
                "wallets loaded"
            )),
            value = html_escape(&current_native),
            single = if portfolio.wallets.len() == 1 {
                "hidden"
            } else {
                ""
            },
            partial = if !portfolio.unavailable.is_empty() || portfolio.price_coverage_gap {
                " · partial"
            } else {
                ""
            },
        ));
        body.push_str(&portfolio.notices());
        body.push_str("<p class=\"directory-note\">Only wallets in Bloom’s current listing. Balances cover native coins; token holdings are not scanned.</p><div class=\"wallet-directory\">");

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
            let wallet_holdings: Vec<&Holding> = portfolio
                .holdings
                .iter()
                .filter(|holding| holding.wallet == wallet.id)
                .collect();
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
                 <span class=\"wallet-worth\"><strong>{subtitle}</strong><span>Native balance{partial}</span></span>\
                 </summary><div class=\"directory-content\"><code class=\"wallet-address\">{address}</code>\
                 <p class=\"crumbs\">wallets/{path}/</p>\
                 <p>{answered} networks answered{unavailable}</p>\
                 <nav class=\"wallet-actions\" aria-label=\"{name} actions\"><a href=\"receive.html#wallet-{id}\">Receive</a></nav>",
                id = html_escape(&wallet.id),
                name = html_escape(&wallet.id),
                path = html_escape(&wallet.id),
                subtitle = html_escape(&subtitle),
                address = html_escape(wallet.address.as_deref().unwrap_or("Unavailable")),
                short_address = html_escape(&short_hex(wallet.address.as_deref().unwrap_or("Unavailable"))),
                partial = if unavailable_count > 0 { " · partial" } else { "" },
                kind = html_escape(&wallet.kind),
                answered = wallet_holdings.len(),
                unavailable = if unavailable_count == 0 {
                    String::new()
                } else {
                    format!(" · {unavailable_count} unavailable")
                },
            ));

            if !wallet_funded.is_empty() {
                body.push_str(&holdings_table(
                    &wallet_funded,
                    "Native balances read through Bloom",
                ));
            }

            // Balances without a configured native-asset market get their own
            // table. This includes unpriced mainnets as well as development
            // chains, so the label must not guess which environment they use.
            if !wallet_off_market.is_empty() {
                body.push_str(&format!(
                    "<details><summary>Unpriced balances · {count}</summary>\
                     {table}</details>",
                    count = wallet_off_market.len(),
                    table = holdings_table(
                        &wallet_off_market,
                        "No market price is configured for these native assets. \
                         They are excluded from dollar totals.",
                    ),
                ));
            }

            // An empty network is reported, not dropped: otherwise "you hold
            // nothing on Base" is indistinguishable from "Base was not read".
            // The count carries that distinction; the names add nothing.
            if !wallet_empty.is_empty() {
                body.push_str(&format!(
                    "<p class=\"muted\">Empty on {}.</p>",
                    html_escape(&count_noun(
                        wallet_empty.len(),
                        "read network",
                        "read networks"
                    )),
                ));
            }
            body.push_str("</div></details>");
        }
        body.push_str("</div>");

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
            "Choose a wallet to see its receiving addresses.",
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
        // Numbered accounts first: the primary key is account zero's address,
        // and every further account gets its own card labelled by derivation
        // path. The primary card keeps its network sentence; extras name the
        // account they belong to.
        let inventory = wallet_addresses(wallet);
        let mut card = match inventory.evm.first() {
            Some((_, address)) => self.render_address_card(address, mainnets, testnets),
            None => "<article class=\"card receiving-card\"><h3>Ethereum &amp; EVM</h3><p>No EVM receiving address in this wallet’s projection.\
                         </p></article>"
                .to_owned(),
        };
        for (account, address) in inventory.evm.iter().skip(1) {
            card.push_str(&format!(
                "<article class=\"card receiving-card\"><h3>{mark}</h3>{qr}\
                 <code class=\"address\">{address}</code>\
                 <p class=\"receiving-network\">Account <code>{account}</code>. One address across the EVM networks above.</p></article>",
                mark = asset_label("Ethereum & EVM"),
                qr = receiving_qr(address),
                address = html_escape(address),
                account = html_escape(account),
            ));
        }
        if wallet.account_inventory().is_err() {
            card.push_str(
                "<article class=\"card receiving-card receiving-unavailable\"><h3>Additional accounts unavailable</h3>\
                 <p>Bloom could not load this wallet’s account inventory. Some receiving addresses may be missing.</p></article>",
            );
        }
        if inventory.solana.is_empty() && wallet.account_inventory().is_ok() {
            card.push_str(&format!(
                "<article class=\"card receiving-card receiving-unavailable\"><h3>{}</h3>\
                 <p>No Solana receiving address in this wallet’s projection.</p>\
                 <small>Use your Solana account’s address in Bloom.</small></article>",
                asset_label("Solana"),
            ));
        }
        for (account, address) in &inventory.solana {
            card.push_str(&format!(
                "<article class=\"card receiving-card\"><h3>{mark}</h3>{qr}\
                 <code class=\"address\">{address}</code>\
                 <p class=\"receiving-network\">Account <code>{account}</code>. Send on Solana only.</p>\
                 <a class=\"external-link\" href=\"https://explorer.solana.com/address/{address}\" rel=\"noreferrer noopener\">View on Solana Explorer ↗</a></article>",
                mark = asset_label("Solana"),
                qr = receiving_qr(address),
                address = html_escape(address),
                account = html_escape(account),
            ));
        }
        let families = match (inventory.evm.is_empty(), inventory.solana.is_empty()) {
            (false, false) => "Ethereum & EVM · Solana",
            (false, true) => "Ethereum & EVM",
            (true, false) => "Solana",
            (true, true) => "Addresses unavailable",
        };
        format!(
            "<details class=\"receiving-wallet\" name=\"receiving-wallet\" id=\"wallet-{id_attr}\">\
             <summary><span class=\"wallet-identity\"><strong>{id_text}</strong><small>{families}</small></span>\
             <span class=\"wallet-count\">{count}</span></summary>\
             <div class=\"grid\">{card}</div></details>",
            id_attr = html_escape(id),
            id_text = html_escape(id),
            families = html_escape(families),
            count = count_noun(
                inventory.evm.len() + inventory.solana.len(),
                "address",
                "addresses"
            ),
        )
    }

    fn render_address_card(
        &self,
        address: &str,
        mainnets: &[String],
        testnets: &[String],
    ) -> String {
        // One sentence names every network; a chip per network repeated the
        // same address thirteen times without adding meaning.
        let names: Vec<String> = mainnets
            .iter()
            .map(|name| self.network_label(name))
            .collect();
        let networks = match names.as_slice() {
            [] => "<p class=\"receiving-network\">No networks are configured for this address yet.</p>"
                .to_owned(),
            [only] => format!(
                "<p class=\"receiving-network\">One address on {}.</p>",
                html_escape(only)
            ),
            _ => {
                let (last, rest) = names.split_last().expect("at least two networks");
                format!(
                    "<p class=\"receiving-network\">One address across {} and {}.</p>",
                    html_escape(&rest.join(", ")),
                    html_escape(last),
                )
            }
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
        // exact displayed address, including non-primary accounts. The
        // section heading names the wallet; every card names its address family.
        format!(
            "<article class=\"card receiving-card\"><h3>{mark}</h3>{qr}\
             <code class=\"address\">{address}</code><div class=\"receiving-network-list\">\
             {networks}{testing}</div></article>",
            mark = asset_label("Ethereum & EVM"),
            qr = receiving_qr(address),
            address = html_escape(address),
        )
    }

    async fn render_activity(&self) -> String {
        let (mut actions, incomplete) = self.actions().await;
        self.resolve_fees(&mut actions).await;
        let counts = |state: &str| actions.iter().filter(|a| a.state == state).count();
        let (sent, pending, failed) = (counts("sent"), counts("pending"), counts("failed"));

        let mut body = String::new();
        body.push_str(activity_coverage_notice(incomplete));
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
}

/// Shorten the numeric part of a `"<quantity> <UNIT>"` pair, leaving the unit
/// alone. Eighteen decimals swamp a cell whether or not a symbol follows.
fn short_quantity_with_unit(text: &str) -> String {
    match text.split_once(' ') {
        Some((quantity, unit)) => format!("{} {unit}", short_quantity(quantity)),
        None => short_quantity(text),
    }
}

fn activity_coverage_notice(incomplete: bool) -> &'static str {
    if incomplete {
        "<p class=\"coverage-notice\"><strong>Activity coverage incomplete</strong> · Some records were omitted or could not be read. Counts cover available records only.</p>"
    } else {
        ""
    }
}

/// A Solana chain's display name. The spec carries a filesystem-friendly
/// name only, so the three known clusters map to the same "X Mainnet"
/// shape the EVM specs display with; anything else shows as configured.
fn solana_network_label(chain: &str) -> String {
    match chain {
        "solana-mainnet" => "Solana Mainnet".to_owned(),
        "solana-devnet" => "Solana Devnet".to_owned(),
        "solana-testnet" => "Solana Testnet".to_owned(),
        _ => chain.to_owned(),
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
}

#[derive(Default)]
struct Portfolio {
    holdings: Vec<Holding>,
    /// `(wallet, chain)` pairs whose balance could not be read.
    unavailable: Vec<(String, String)>,
    wallets: Vec<WalletSummary>,
    projections_unavailable: bool,
    /// Accounts whose balance reads had not finished when the page's
    /// `PORTFOLIO_BUDGET` expired.
    accounts_unread: usize,
    /// `(wallet, chain)` pairs using a recent successful observation because
    /// the current RPC read failed or exceeded the page budget.
    cached_balances: Vec<(String, String)>,
    price_coverage_gap: bool,
    stale: bool,
}

#[derive(Default)]
struct BalanceRead {
    holdings: Vec<Holding>,
    unavailable: Vec<(String, String)>,
    cached: Vec<(String, String)>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct BalanceCacheKey {
    wallet: String,
    chain: String,
    address: String,
}

impl BalanceCacheKey {
    fn new(wallet: &str, chain: &str, address: &str) -> Self {
        Self {
            wallet: wallet.to_owned(),
            chain: chain.to_owned(),
            address: address.to_owned(),
        }
    }
}

#[derive(Clone)]
struct CachedHolding {
    observed_at: Instant,
    holding: Holding,
}

/// One account address whose native balances a page reads.
#[derive(Clone)]
enum BalanceJob {
    Evm {
        wallet: String,
        account: String,
        address: alloy::primitives::Address,
    },
    Solana {
        wallet: String,
        account: String,
        address: String,
    },
}

/// One table of holdings, with every cell labelled for a narrow screen.
fn holdings_table(rows: &[&Holding], caption: &str) -> String {
    let cells: String = rows
        .iter()
        .map(|holding| {
            format!(
                "<tr><td data-label=\"Asset\"><span class=\"asset-label\">\
                 <span><strong>{symbol}</strong><small title=\"Exact quantity: {exact} {symbol}\">{quantity} {symbol}\
                 </small></span></span></td>\
                 <td data-label=\"Network\">{label}</td>\
                 <td class=\"numeric money\" data-label=\"Value\">{value}</td></tr>",
                // The source leaf stays out of this person-facing table:
                // agents already know where the canonical values live.
                symbol = html_escape(&holding.symbol),
                quantity = html_escape(&short_quantity(&holding.quantity)),
                exact = html_escape(&trim_trailing_zeros(&holding.quantity)),
                label = asset_label(&if holding.account.is_empty() {
                    holding.label.clone()
                } else {
                    format!("{} · {}", holding.label, holding.account)
                }),
                value = html_escape(&money(holding.value)),
            )
        })
        .collect();
    format!(
        "<div class=\"table-wrap\"><table class=\"holdings-table\"><caption>{caption}</caption><thead><tr>\
         <th scope=\"col\">Asset / quantity</th><th scope=\"col\">Network</th>\
         <th class=\"numeric\" scope=\"col\">Value</th></tr></thead>\
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

    /// Rows holding a quantity with no configured market for the native unit.
    /// This says nothing about whether the chain is mainnet or development.
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
        if self.accounts_unread > 0 {
            out.push_str(&format!(
                "<p class=\"coverage-notice\"><strong>Balance reads ran out of time</strong> · \
                 {} not read and excluded from totals. Reload to try again.</p>",
                html_escape(&count_noun(self.accounts_unread, "account", "accounts")),
            ));
        }
        if !self.cached_balances.is_empty() {
            let mut names: Vec<&str> = self
                .cached_balances
                .iter()
                .map(|(_, chain)| chain.as_str())
                .collect();
            names.sort();
            names.dedup();
            out.push_str(&format!(
                "<section class=\"callout warn\"><strong>Using recent balances</strong>\
                 <p>{names} could not be read live. Their last successful observations, \
                 no more than five minutes old, remain in the total.</p></section>",
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

/// Every address one wallet projection reports, grouped by family. The
/// primary EVM key comes first (it predates the account inventory), then each
/// numbered account's addresses in projection order. Duplicates collapse so a
/// primary key that is also account zero reads once.
#[derive(Debug)]
struct WalletAddresses {
    /// `(account label, EVM address)`. The primary entry carries an empty
    /// label; numbered accounts carry their derivation path.
    evm: Vec<(String, String)>,
    /// `(account label, Solana base58 address)`, labelled by derivation path
    /// or by the projected key they came from.
    solana: Vec<(String, String)>,
}

fn wallet_addresses(projection: &WalletProjection) -> WalletAddresses {
    let mut out = WalletAddresses {
        evm: Vec::new(),
        solana: Vec::new(),
    };
    let mut seen_evm = BTreeSet::new();
    let mut seen_sol = BTreeSet::new();
    if let Ok(primary) = projection.primary_address()
        && primary.parse::<alloy::primitives::Address>().is_ok()
        && seen_evm.insert(primary.to_ascii_lowercase())
    {
        out.evm.push((String::new(), primary.to_owned()));
    }
    if let Ok(inventory) = projection.account_inventory() {
        for account in &inventory.accounts {
            let label = account.path.clone();
            for chain in &account.chain_projections {
                if chain.chain_family.as_str() == "solana" {
                    if is_solana_address(&chain.address) && seen_sol.insert(chain.address.clone()) {
                        out.solana.push((label.clone(), chain.address.clone()));
                    }
                } else if chain.address.parse::<alloy::primitives::Address>().is_ok()
                    && seen_evm.insert(chain.address.to_ascii_lowercase())
                {
                    out.evm.push((label.clone(), chain.address.clone()));
                }
            }
        }
    }
    // Projections cached from before the account inventory still carry
    // explicit Solana identities on their Ed25519 keys; keep reading those so
    // an older Broker does not lose its Solana receive cards.
    for key in &projection.keys {
        if !key
            .supported_crypto_suites
            .contains(&bloom_broker_api::CryptoSuite::Ed25519Message)
        {
            continue;
        }
        for address in &key.addresses {
            if let Some(solana) = explicit_solana_identity(address)
                && seen_sol.insert(solana.clone())
            {
                out.solana.push(("projected key".to_owned(), solana));
            }
        }
    }
    out
}

/// A `solana:<network>:<base58>` CAIP-10 identity from a key projection.
/// Ed25519 alone does not identify a chain, so a bare key never qualifies.
fn explicit_solana_identity(address: &str) -> Option<String> {
    let (network, address) = address.strip_prefix("solana:")?.split_once(':')?;
    if network.is_empty() || !is_solana_address(address) {
        return None;
    }
    Some(address.to_owned())
}

fn is_solana_address(address: &str) -> bool {
    (32..=44).contains(&address.len())
        && bs58::decode(address)
            .into_vec()
            .is_ok_and(|bytes| bytes.len() == 32)
}

#[derive(Clone)]
struct Holding {
    wallet: String,
    chain: String,
    /// Which numbered account (derivation path) or key reported this row, so
    /// two accounts holding on the same chain stay distinguishable. Empty for
    /// rows that predate the account inventory.
    account: String,
    /// Market key for the native unit, when that unit is a traded asset. A
    /// development chain whose unit happens to read "ETH" carries none, and
    /// neither does a chain with no market for its unit.
    price_key: Option<&'static str>,
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

    /// Whether Bloom has a market mapping for the native unit. This is a
    /// valuation property, not a mainnet/testnet classification.
    fn is_off_market(&self) -> bool {
        self.price_key.is_none()
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
    created_ms: Option<u64>,
    usd_value: Option<f64>,
    data_hex: Option<String>,
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
    /// The paid gas fee as read from the on-chain receipt, formatted with
    /// the chain's native unit ("0.00042 ETH"). Present only when the
    /// receipt resolved; a staged cap never stands in for it.
    fee: Option<String>,
    /// Whether this operation reached an approval ceremony.
    awaited_approval: bool,
}

impl Action {
    fn chain_label(&self, chains: &ChainRegistry) -> String {
        let recorded_id = self.intent.as_ref().and_then(|intent| intent.chain_id);
        let fallback = recorded_id
            .map(|id| format!("EVM chain {id}"))
            .unwrap_or_else(|| "—".to_owned());
        let chain = self.chain.as_deref().unwrap_or(&fallback);
        let client = chains
            .get(chain)
            .filter(|client| recorded_id.is_none_or(|id| id == client.spec().chain_id));
        let label = client
            .as_ref()
            .and_then(|client| client.spec().display_name.as_deref())
            .unwrap_or(if recorded_id.is_some() {
                &fallback
            } else {
                chain
            });
        asset_label(label)
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
    /// not "reverted": absence of a receipt or hash cannot prove no broadcast.
    fn label(&self) -> &'static str {
        match self.state {
            "sent" => "✓ Broadcast",
            "failed" if self.tx_hash.is_some() => "✗ Stopped · transaction hash recorded",
            "failed" if self.awaited_approval => "✗ Approval interrupted",
            "failed" => "✗ No broadcast recorded",
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
            ("native_transfer", None) if intent.value_wei.as_deref() == Some("0") => {
                "Send (zero value)".to_owned()
            }
            ("native_transfer", None) => "Send (amount unavailable)".to_owned(),
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
    /// what Bloom recorded; chain settlement requires a receipt.
    fn outcome_note(&self) -> &'static str {
        match self.state {
            "sent" if self.tx_hash.is_some() => {
                "Bloom broadcast this and kept the hash. Broadcast is not settled: read the \
                 chain's own receipt for the final outcome."
            }
            "sent" => "Bloom recorded this as sent but kept no transaction hash.",
            "failed" if self.tx_hash.is_some() => {
                "This operation stopped with a transaction hash recorded. Check the chain's receipt for its outcome."
            }
            "failed" if self.awaited_approval => {
                "This reached an approval ceremony before stopping. The available record does not establish whether approval or broadcast completed."
            }
            "failed" => {
                "This operation stopped without a recorded transaction hash. That does not prove no transaction reached the network."
            }
            _ => "Staged operation. No completed broadcast is recorded here.",
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
            // The chain this action ran on, when the record names one the
            // daemon knows: contract targets link to its explorer.
            let chain_id = self.intent.as_ref().and_then(|intent| intent.chain_id);
            if let Some(to) = &intent.to {
                let classification = self.target_classification().unwrap_or("unknown");
                // A saved name earns a prefix; otherwise the full address is
                // already shown and a shortened echo would only repeat it.
                let named = address_alias(address_book, to)
                    .map(|alias| format!("{} ", html_escape(alias)))
                    .unwrap_or_default();
                row_fact(
                    "To",
                    format!(
                        "{named}<code>{}</code> <small>({classification})</small>{explorer}",
                        html_escape(to),
                        explorer = explorer_address_link(chain_id, to),
                    ),
                );
            }
            // The recipient only earns its own row when the target is not
            // the recipient: for a plain transfer they are the same address.
            if let Some(recipient) = self.recipient() {
                let same_as_target = intent
                    .to
                    .as_deref()
                    .and_then(normalized_evm_address)
                    .is_some_and(|to| to.eq_ignore_ascii_case(&recipient));
                if !same_as_target {
                    row_fact(
                        "Recipient",
                        format!(
                            "{} <code>{}</code>{explorer}",
                            html_escape(&address_label(address_book, &recipient)),
                            html_escape(&recipient),
                            explorer = explorer_address_link(chain_id, &recipient),
                        ),
                    );
                }
            }
            row_fact(
                "Value",
                html_escape(self.amount.as_deref().unwrap_or(
                    if intent.value_wei.as_deref() == Some("0") {
                        "None — zero value"
                    } else {
                        "Unavailable"
                    },
                )),
            );
            // The paid fee from the on-chain receipt, never the staged cap:
            // a limit is what the operation might have burned, the receipt
            // is what it did. Absent until the receipt resolves.
            if let Some(fee) = &self.fee {
                row_fact("Execution gas fee", html_escape(fee));
            }
            if let Some(usd) = intent.usd_value {
                row_fact("Value when staged", html_escape(&money(Some(usd))));
            }
        }

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
        created_ms: number("created_ms"),
        usd_value: value.get("usd_value").and_then(|field| field.as_f64()),
        data_hex,
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

/// A paid gas fee from receipt fields: units burned times the effective
/// price, in the chain's native unit. Exact integer math; the row trims it.
fn format_fee(used: u64, price_wei: u128, decimals: u8, symbol: &str) -> String {
    let wei = alloy::primitives::U256::from(used) * alloy::primitives::U256::from(price_wei);
    let quantity = bloom_proto::format_units(wei, decimals);
    format!("{} {symbol}", trim_trailing_zeros(&quantity))
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
    (5042, "coingecko:usd-coin"),               // Arc native USDC (18 decimals)
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

/// Test-only shorthand: production rows carry their own `price_key`.
#[cfg(test)]
fn native_asset_has_market(chain_id: u64) -> bool {
    native_asset_market(chain_id).is_some()
}

/// Block explorers, keyed on chain id. The hash is the one value a person
/// carries elsewhere, and without a link they have to go and find the right
/// explorer themselves. Following one is the reader's own choice: these pages
/// never fetch from an explorer, and `referrer=no-referrer` keeps the visit
/// unattributed.
const EXPLORERS: &[(u64, &str, &str)] = &[
    (1, "https://etherscan.io", "Etherscan"),
    (10, "https://optimistic.etherscan.io", "Optimism Etherscan"),
    (56, "https://bscscan.com", "BscScan"),
    (100, "https://gnosisscan.io", "Gnosisscan"),
    (137, "https://polygonscan.com", "Polygonscan"),
    (999, "https://hyperevmscan.io", "HyperEVMScan"),
    (5042, "https://explorer.arc.io", "Arc Explorer"),
    (
        4663,
        "https://robinhoodchain.blockscout.com",
        "Robinhood Blockscout",
    ),
    (8453, "https://basescan.org", "Basescan"),
    (42161, "https://arbiscan.io", "Arbiscan"),
    (43114, "https://snowtrace.io", "Snowtrace"),
    (59144, "https://lineascan.build", "Lineascan"),
    (81457, "https://blastscan.io", "Blastscan"),
    (534352, "https://scrollscan.com", "Scrollscan"),
];

fn explorer_tx_url(chain_id: u64, hash: &str) -> Option<String> {
    let hex = hash.strip_prefix("0x")?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    EXPLORERS
        .iter()
        .find(|(id, _, _)| *id == chain_id)
        .map(|(_, base, _)| format!("{base}/tx/{hash}"))
}

fn explorer_address_url(chain_id: u64, address: &str) -> Option<String> {
    normalized_evm_address(address)?;
    EXPLORERS
        .iter()
        .find(|(id, _, _)| *id == chain_id)
        .map(|(_, base, _)| format!("{base}/address/{address}"))
}

/// A "View on {explorer} ↗" link for an address on a known chain, or nothing
/// when the chain is unknown: a link to the wrong explorer is worse than
/// none.
fn explorer_address_link(chain_id: Option<u64>, address: &str) -> String {
    let Some(chain_id) = chain_id else {
        return String::new();
    };
    let Some((_, _, name)) = EXPLORERS.iter().find(|(id, _, _)| *id == chain_id) else {
        return String::new();
    };
    let Some(url) = explorer_address_url(chain_id, address) else {
        return String::new();
    };
    format!(
        " <a class=\"external-link\" href=\"{}\" rel=\"noreferrer noopener\">View on {} ↗</a>",
        html_escape(&url),
        html_escape(name),
    )
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
    match value.filter(|value| value.is_finite()) {
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

fn asset_label(name: &str) -> String {
    format!(
        "<span class=\"asset-label\"><span>{}</span></span>",
        html_escape(name)
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
        "<figure class=\"receiving-qr\" aria-label=\"Receiving address QR code\"><div>{svg}</div></figure>"
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
         <link rel=\"stylesheet\" href=\"bloom.css\">\
         {script}</head>\
         <body class=\"personal-dashboard\">\
         <a class=\"skip\" href=\"#main\">Skip to content</a>\
         <div class=\"shell\"><header class=\"masthead\"><div>\
         <a class=\"brand\" href=\"wallets.html\"><strong>/bloom</strong></a>\
         <p class=\"crumbs\"><a href=\"wallets.html\">views</a> / {current}</p></div>\
         <span class=\"edition\">Read-only · reload to refresh</span></header>\
         <nav aria-label=\"Wallet views\">{nav}</nav>\
         <main id=\"main\"><div class=\"intro\"><div>\
         <h1>{heading}</h1></div>\
         {lede}</div>{body}</main>\
         <footer><span>Read-only projection · nothing here authorizes an action</span>\
         <span><a href=\"AGENTS.md\">How to use these pages</a></span></footer>\
         </div></body></html>\n",
        csp = CSP,
        // The only script permitted anywhere is the bundled local one: the
        // Receive deep links. Every page remains fully usable without it.
        script = if current == RECEIVE_HTML {
            "<script src=\"bloom.js\" defer></script>"
        } else {
            ""
        },
        title = html_escape(title),
        heading = html_escape(heading),
        current = html_escape(current),
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
        );
        Fixture {
            handler,
            _tmp: tmp,
            outbox_root,
        }
    }

    #[tokio::test]
    async fn recorded_network_controls_activity_links_and_currency() {
        let fixture = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        fixture.handler.chains.add(
            bloom_evm::ChainClient::new(bloom_proto::ChainSpec {
                name: "ethereum".into(),
                chain_id: 1,
                rpc_urls: vec![format!("http://{}", listener.local_addr().unwrap())],
                rpc_endpoints: Vec::new(),
                etherscan_api_url: None,
                display_name: Some("Ethereum".into()),
                native_symbol: "ETH".into(),
                native_decimals: 18,
                legacy_tx: false,
                op_stack: false,
            })
            .unwrap(),
        );
        stage_files(
            &fixture,
            "sent",
            "evm-network",
            "# Payment\n\nChain: ethereum (id 1)\n",
            &[
                (
                    "intent.json",
                    "{\"chain\":\"ethereum\",\"chain_id\":8453,\"value_wei\":\"1000000000000000000\",\"action_kind\":\"native_transfer\"}",
                ),
                (
                    "result.json",
                    "{\"tx_hash\":\"0xabababababababababababababababababababababababababababababababab\"}",
                ),
            ],
        );
        let (mut actions, _) = fixture.handler.actions().await;
        tokio::time::timeout(
            Duration::from_millis(100),
            fixture.handler.resolve_fees(&mut actions),
        )
        .await
        .expect("a changed chain mapping must not request a receipt");
        assert!(actions[0].fee.is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        assert_eq!(
            actions[0].amount.as_deref(),
            Some("1000000000000000000 wei")
        );
        assert!(
            actions[0]
                .chain_label(&fixture.handler.chains)
                .contains("EVM chain 8453")
        );
        assert!(
            actions[0]
                .explorer_url()
                .unwrap()
                .starts_with("https://basescan.org/tx/")
        );
    }

    #[tokio::test]
    async fn malformed_activity_does_not_claim_nothing_needs_review() {
        let fixture = fixture();
        stage_files(
            &fixture,
            "pending",
            "evm-broken",
            "# Pending\n",
            &[("intent.json", "{broken")],
        );
        let (_, incomplete) = fixture.handler.actions().await;
        assert!(incomplete);
        let html = render(&fixture.handler, ACTIVITY_HTML).await;
        assert!(html.contains("Activity coverage incomplete"), "{html}");
    }

    #[tokio::test]
    async fn stopped_transaction_with_hash_does_not_claim_no_broadcast() {
        let fixture = fixture();
        stage_files(
            &fixture,
            "failed",
            "evm-stopped",
            "# Stopped\n",
            &[(
                "result.json",
                "{\"tx_hash\":\"0xabababababababababababababababababababababababababababababababab\"}",
            )],
        );
        let (actions, _) = fixture.handler.actions().await;
        assert!(actions[0].label().contains("transaction hash recorded"));
        assert!(
            actions[0]
                .outcome_note()
                .contains("Check the chain's receipt")
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
    async fn pages_only_allow_the_bundled_script() {
        let fixture = fixture();
        for (page, _) in PAGES {
            let html = render(&fixture.handler, page).await;
            assert!(html.contains("Content-Security-Policy"), "{page}");
            assert!(html.contains("style-src 'self'"), "{page}");
            assert!(html.contains("script-src 'self'"), "{page}");
            assert_eq!(
                html.contains("<script src=\"bloom.js\" defer>"),
                *page == RECEIVE_HTML,
                "only Receive loads the bundled script: {page}"
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
        assert!(html.contains("Ethereum &amp; EVM</span></span></h3>"));
        assert!(
            html.contains("<figure class=\"receiving-qr\"") && html.contains("<svg"),
            "the QR must travel with a saved Receive page: {html}"
        );
        assert!(
            !html.contains("../wallets/"),
            "the QR must not depend on the mounted wallet tree"
        );
        assert!(!html.contains("The code encodes an address, not a network"));
    }

    #[test]
    fn solana_receive_requires_a_32_byte_public_key() {
        assert!(is_solana_address("11111111111111111111111111111111"));
        assert!(!is_solana_address(&"1".repeat(33)));
        assert!(!is_solana_address(&"z".repeat(44)));
        assert!(!is_solana_address(&"0".repeat(32)));
    }

    #[tokio::test]
    async fn receive_discloses_an_unavailable_account_inventory() {
        let fixture = fixture();
        let mut projection = fixture
            .handler
            .projections
            .list_wallets()
            .await
            .unwrap()
            .remove(0);
        projection.accounts_unavailable = Some("unavailable".into());
        let mut handler = fixture.handler;
        handler.projections = crate::test_support::wallet_projection_reader_from(projection);
        let html = render(&handler, RECEIVE_HTML).await;
        assert!(html.contains("Additional accounts unavailable"));
        assert!(!html.contains("No Solana receiving address"));
        assert!(html.contains(ADDRESS));
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
        );

        let html = render(&handler, RECEIVE_HTML).await;
        assert!(
            html.contains(ADDRESS),
            "the EVM card still renders: {html:.300}"
        );
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
        );

        let html = render(&handler, RECEIVE_HTML).await;
        assert!(html.contains("No Solana receiving address"), "{html}");
        assert!(!html.contains(&format!("class=\"address\">{PLAIN_BASE58}</code>")));
    }

    /// A numbered Solana account from the account inventory: derivation path,
    /// chain family, and base58 address straight from the projection.
    fn solana_numbered_account(address: &str) -> bloom_broker_api::DerivedAccountPublic {
        bloom_broker_api::DerivedAccountPublic {
            key_ref: bloom_broker_api::KeyRef {
                backend: bloom_broker_api::Token::new("test").unwrap(),
                backend_instance: bloom_broker_api::Token::new("projection").unwrap(),
                locator: "alice/solana-0".into(),
                key_spec: bloom_broker_api::KeySpec::Ed25519,
                public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([7; 32]),
                derivation: None,
            },
            wallet_seed_profile: bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
            derivation_profile: bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            path: "m/44'/501'/0'/0'".into(),
            canonical_public_key: bloom_broker_api::Base64UrlBytes::from_bytes(&[8; 32]),
            public_key_encoding: bloom_broker_api::PublicKeyEncoding::Ed25519SpkiDer,
            public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([7; 32]),
            supported_crypto_suites: vec![bloom_broker_api::CryptoSuite::Ed25519Message],
            chain_projections: vec![bloom_broker_api::ChainAccountProjection {
                chain_family: bloom_broker_api::Token::new("solana").unwrap(),
                caip2: "solana:mainnet".into(),
                caip10: format!("solana:mainnet:{address}"),
                address: address.to_owned(),
                address_encoding: bloom_broker_api::AddressEncoding::Base58,
            }],
            lifecycle: bloom_broker_api::AccountLifecycleState::Active,
        }
    }

    fn evm_numbered_account(index: u8) -> bloom_broker_api::DerivedAccountPublic {
        let address = alloy::primitives::Address::repeat_byte(index).to_string();
        let mut account = solana_numbered_account("unused");
        account.key_ref.locator = format!("alice/evm-{index}");
        account.key_ref.key_spec = bloom_broker_api::KeySpec::Secp256k1;
        account.derivation_profile = bloom_broker_api::DerivationProfile::Bip44EvmSecp256k1V1;
        account.path = format!("m/44'/60'/0'/0/{index}");
        account.supported_crypto_suites =
            vec![bloom_broker_api::CryptoSuite::Secp256k1Keccak256Recoverable];
        account.chain_projections = vec![bloom_broker_api::ChainAccountProjection {
            chain_family: bloom_broker_api::Token::new("evm").unwrap(),
            caip2: "eip155:1".into(),
            caip10: format!("eip155:1:{address}"),
            address,
            address_encoding: bloom_broker_api::AddressEncoding::Hex0x,
        }];
        account
    }

    /// An RPC endpoint that accepts connections and never answers.
    async fn stalled_rpc() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        url
    }

    #[tokio::test]
    async fn recent_balance_survives_a_transient_rpc_failure() {
        let fixture = fixture_with_unreachable_chains();
        let address = ADDRESS.parse::<alloy::primitives::Address>().unwrap();
        let address_text = format!("{address:#x}");
        fixture.handler.remember_balance(
            "alice",
            "ethereum",
            &address_text,
            &Holding {
                wallet: "alice".into(),
                chain: "ethereum".into(),
                account: String::new(),
                price_key: Some("coingecko:ethereum"),
                label: "Ethereum".into(),
                symbol: "ETH".into(),
                quantity: "1.25".into(),
                amount: 1.25,
                value: None,
            },
        );

        let read = fixture
            .handler
            .read_balances("alice", address, &["ethereum".into()])
            .await;

        assert!(read.unavailable.is_empty(), "recent observation is usable");
        assert_eq!(read.cached, vec![("alice".into(), "ethereum".into())]);
        assert_eq!(read.holdings.len(), 1);
        assert_eq!(read.holdings[0].quantity, "1.25");
        let portfolio = Portfolio {
            cached_balances: read.cached,
            ..Portfolio::default()
        };
        assert!(portfolio.notices().contains("Using recent balances"));

        let key = BalanceCacheKey::new("alice", "ethereum", &address_text);
        fixture
            .handler
            .balance_cache
            .write()
            .get_mut(&key)
            .unwrap()
            .observed_at = Instant::now() - BALANCE_CACHE_MAX_AGE - Duration::from_secs(1);
        assert!(
            fixture
                .handler
                .cached_balance("alice", "ethereum", &address_text)
                .is_none(),
            "expired observations must not become indefinite estimates"
        );
    }

    #[tokio::test]
    async fn many_stalled_accounts_share_one_portfolio_budget() {
        // More accounts than read slots, so a serial or per-account budget
        // would take several BALANCE_TIMEOUTs.
        let accounts = 2 * PORTFOLIO_CONCURRENCY as u8 + 1;
        let fixture = fixture();
        let mut projection = fixture
            .handler
            .projections
            .list_wallets()
            .await
            .unwrap()
            .remove(0);
        projection.accounts = bloom_broker_api::WalletAccountsPublic {
            wallet_id: bloom_broker_api::Token::new("alice").unwrap(),
            seed_profile: bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
            accounts: (1..=accounts).map(evm_numbered_account).collect(),
        };
        assert_eq!(
            super::wallet_addresses(&projection).evm.len(),
            usize::from(accounts) + 1,
            "primary key plus every numbered account"
        );
        let mut spec = bloom_proto::ChainSpec::anvil_default();
        spec.rpc_urls = vec![stalled_rpc().await];
        let chains = ChainRegistry::new();
        chains.add(bloom_evm::ChainClient::new(spec).unwrap());
        let handler = ViewsHandler::new(
            crate::test_support::wallet_projection_reader_from(projection),
            chains,
            bloom_prices::PricesClient::with_base_url("http://127.0.0.1:1"),
            fixture.handler.outbox,
        );

        let started = std::time::Instant::now();
        let portfolio = handler.portfolio().await;
        let elapsed = started.elapsed();
        assert!(
            elapsed <= PORTFOLIO_BUDGET + Duration::from_secs(2),
            "portfolio took {elapsed:?}"
        );
        assert!(portfolio.holdings.is_empty(), "nothing answered");
        // Every account is missing, whether its read timed out or never
        // started before the budget ran out, and none is shown as empty.
        assert_eq!(portfolio.unavailable.len(), usize::from(accounts) + 1);
        assert!(portfolio.accounts_unread > 0, "the budget cut reads short");
        let notices = portfolio.notices();
        assert!(notices.contains("Partial balance coverage"), "{notices}");
        assert!(
            notices.contains("Balance reads ran out of time"),
            "{notices}"
        );
    }

    #[tokio::test]
    async fn activity_scan_omits_records_past_the_limit() {
        let fixture = fixture();
        for n in 0..=ACTION_SCAN_LIMIT {
            stage(&fixture, "sent", &format!("op-{n:04}"), "# Sent\n");
        }
        let (actions, incomplete) = fixture.handler.actions().await;
        assert!(incomplete);
        assert_eq!(actions.len(), ACTION_SCAN_LIMIT);
        let html = render(&fixture.handler, ACTIVITY_HTML).await;
        assert!(html.contains("Activity coverage incomplete"), "{html}");
    }

    #[tokio::test]
    async fn receive_lists_a_numbered_solana_account_with_its_path() {
        const SOLANA: &str = "7Ec4G7dS8v8Y5JvVX8E5S7jvk8eJzEqJqgWkpz6xA4r9";
        let fixture = fixture();
        let mut projection = fixture
            .handler
            .projections
            .list_wallets()
            .await
            .unwrap()
            .remove(0);
        projection.accounts = bloom_broker_api::WalletAccountsPublic {
            wallet_id: bloom_broker_api::Token::new("alice").unwrap(),
            seed_profile: bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
            accounts: vec![solana_numbered_account(SOLANA)],
        };
        // The inventory names the derivation path and the address family.
        let inventory = super::wallet_addresses(&projection);
        assert_eq!(inventory.evm.len(), 1, "primary EVM address: {inventory:?}");
        assert_eq!(
            inventory.solana,
            vec![("m/44'/501'/0'/0'".to_owned(), SOLANA.to_owned())]
        );
        let handler = ViewsHandler::new(
            crate::test_support::wallet_projection_reader_from(projection),
            ChainRegistry::default(),
            bloom_prices::PricesClient::with_base_url("http://127.0.0.1:1"),
            fixture.handler.outbox,
        );

        let html = render(&handler, RECEIVE_HTML).await;
        assert!(html.contains(ADDRESS), "the EVM card still renders");
        assert!(
            html.contains("m/44&#39;/501&#39;/0&#39;/0&#39;"),
            "the Solana card names its derivation path: {html}"
        );
        assert_eq!(
            html.matches(&format!("class=\"address\">{SOLANA}</code>"))
                .count(),
            1,
            "one Solana card for the numbered account: {html}"
        );
        assert!(html.contains("Send on Solana only."), "{html}");
    }

    #[test]
    fn a_paid_fee_reads_as_native_not_as_a_limit() {
        assert_eq!(
            super::format_fee(u64::MAX, u128::MAX, 0, "UNIT"),
            "6277101735386680763495507056286727952620534092958556749825 UNIT"
        );
        assert_eq!(
            super::format_fee(21_000, 1_000_000_000, 18, "ETH"),
            "0.000021 ETH"
        );
        assert_eq!(super::format_fee(0, 1_000_000_000, 18, "ETH"), "0 ETH");
    }

    #[test]
    fn explorer_links_name_the_chain_or_nothing() {
        assert!(
            super::explorer_address_link(Some(8453), "0x000000000000000000000000000000000000dEaD")
                .contains("basescan.org")
        );
        assert_eq!(super::explorer_address_link(Some(31337), "0xabc"), "");
        assert_eq!(super::explorer_address_link(None, "0xabc"), "");
    }

    #[tokio::test]
    async fn a_contract_target_links_to_its_chain_explorer() {
        let fixture = fixture();
        stage_files(
            &fixture,
            "sent",
            "evm-0300",
            "# Approve spend\\n\\nWallet: primary\\nChain:  base (id 8453)\\n",
            &[
                (
                    "intent.json",
                    "{\"chain\":\"base\",\"chain_id\":8453,\"from\":\"0x5c3d61167D9dfa2E4171416D08484220F1374456\",\"to\":\"0x6818809EefCe719E480a7526D76bD3e561526b46\",\"value_wei\":\"0\",\"action_kind\":\"contract_call\"}",
                ),
                (
                    "result.json",
                    "{\"tx_hash\":\"0x4b81a384e07d30624b9dc420b0f1c12e4f9a1d3cf027bdd4a1ab868225eb1748\"}",
                ),
            ],
        );
        let html = render(&fixture.handler, ACTIVITY_HTML).await;
        assert!(
            html.contains("basescan.org/address/0x6818809EefCe719E480a7526D76bD3e561526b46"),
            "the contract target links to its explorer: {html}"
        );
        // No staged cap stands in for the paid fee: the fixture registry
        // cannot resolve a receipt, so no fee row renders at all.
        assert!(!html.contains("Gas limit"), "{html}");
        assert!(!html.contains("Gas fee"), "{html}");
    }

    #[tokio::test]
    async fn receive_starts_with_every_wallet_collapsed() {
        let mut fixture = fixture();
        let reader = crate::test_support::wallet_projection_reader("first", ADDRESS);
        let first = reader.list_wallets().await.unwrap().remove(0);
        let mut second = first.clone();
        second.wallet.wallet_id = bloom_broker_api::Token::new("second").unwrap();
        second.keys[0].addresses = vec!["0x000000000000000000000000000000000000bEEF".to_owned()];
        fixture.handler.projections =
            crate::test_support::wallet_projection_reader_from_many(vec![first, second]);

        let html = render(&fixture.handler, RECEIVE_HTML).await;
        assert_eq!(
            html.matches("<details class=\"receiving-wallet\" name=\"receiving-wallet\"")
                .count(),
            2
        );
        assert!(!html.contains(" open"));
        assert!(html.contains("id=\"wallet-first\"") && html.contains("id=\"wallet-second\""));
    }

    #[tokio::test]
    async fn receive_also_collapses_a_single_wallet() {
        let html = render(&fixture().handler, RECEIVE_HTML).await;
        assert_eq!(
            html.matches("<details class=\"receiving-wallet\"").count(),
            1
        );
        assert!(!html.contains(" open"));
    }

    #[tokio::test]
    async fn every_page_names_its_place_in_the_mount() {
        for (page, file) in [
            (WALLETS_HTML, "wallets.html"),
            (RECEIVE_HTML, "receive.html"),
        ] {
            let html = render(&fixture().handler, page).await;
            assert!(html.contains(">views</a> /"), "{page}");
            assert!(html.contains(&format!("/ {file}</p>")), "{page}");
        }
    }

    #[tokio::test]
    async fn wallet_cards_name_their_directory() {
        let html = render(&fixture().handler, WALLETS_HTML).await;
        assert!(html.contains("wallets/alice/"), "{html:.300}");
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
    async fn staged_operations_reach_activity() {
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

        let activity = render(&fixture.handler, ACTIVITY_HTML).await;
        for summary in ["Staged tx 0001-62058", "Send 0.05 ETH", "Enso operation"] {
            assert!(activity.contains(summary), "{summary} missing: {activity}");
        }
        assert!(activity.contains("status-success"));
        assert!(activity.contains("status-failed"));
        assert!(activity.contains("status-pending"));
        assert!(activity.contains("fund it before approving"), "{activity}");
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
                    "{\"chain\":\"ethereum\",\"chain_id\":1,\"from\":\"0x5c3d61167D9dfa2E4171416D084842\
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
        // The counterparty comes from the intent, not the plan title.
        assert!(
            html.contains("0x6818809EefCe719E480a7526D76bD3e561526b46"),
            "{html}"
        );
        assert!(html.contains("https://etherscan.io/tx/0x4b81a384e07d30624b9dc420b0f1c12e4f9a1d3cf027bdd4a1ab868225eb1748"));
        assert!(html.contains("View transaction ↗"));
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
        assert!(html.contains("Approval interrupted"), "{html}");
        assert!(
            html.contains("does not establish whether approval or broadcast completed"),
            "{html}"
        );
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
        let activity = render(&fixture.handler, ACTIVITY_HTML).await;
        assert!(activity.contains("No activity yet"), "{activity}");
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
        for page in [WALLETS_HTML] {
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
            handler.list(&VfsPath::parse(WALLETS_HTML).unwrap()).await,
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
        // A chain may call its native unit "ETH" without that unit being the
        // market asset priced as ether. It must stay unpriced until Bloom has
        // an explicit market mapping.
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
        assert_eq!(native_asset_market(5042), Some("coingecko:usd-coin"));
        assert_eq!(native_asset_market(5042002), None);
        // A native unit named "ETH" is not enough to identify the asset.
        assert_eq!(native_asset_market(4217), None);
    }

    #[test]
    fn a_broadcast_hash_links_to_its_own_chain_explorer() {
        let hash = format!("0x{}", "ab".repeat(32));
        assert_eq!(
            explorer_tx_url(1, &hash),
            Some(format!("https://etherscan.io/tx/{hash}"))
        );
        assert_eq!(
            explorer_tx_url(8453, &hash),
            Some(format!("https://basescan.org/tx/{hash}"))
        );
        assert_eq!(
            explorer_tx_url(137, &hash),
            Some(format!("https://polygonscan.com/tx/{hash}"))
        );
        assert_eq!(
            explorer_tx_url(56, &hash),
            Some(format!("https://bscscan.com/tx/{hash}"))
        );
        assert_eq!(explorer_tx_url(1, "0xabc"), None);
        assert_eq!(explorer_tx_url(1, &format!("{hash}/../elsewhere")), None);
        assert_eq!(
            explorer_address_url(81457, ADDRESS),
            Some(format!("https://blastscan.io/address/{ADDRESS}"))
        );
        assert_eq!(
            explorer_address_url(534352, ADDRESS),
            Some(format!("https://scrollscan.com/address/{ADDRESS}"))
        );
        assert_eq!(explorer_address_url(1, "0xabc"), None);
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

    /// A registry of configured but unreachable chains, so the Networks page
    /// can be exercised the way a real daemon with a down provider would be.
    fn fixture_with_unreachable_chains() -> Fixture {
        let mut base = fixture();
        let chains = ChainRegistry::default();
        for (name, chain_id, display) in [
            ("ethereum", 1u64, "Ethereum"),
            ("base", 8453, "Base"),
            ("tempo", 4217, "Tempo"),
            ("robinhood", 4663, "Robinhood Chain"),
        ] {
            chains.add(
                bloom_evm::ChainClient::new(bloom_proto::ChainSpec {
                    name: name.into(),
                    chain_id,
                    rpc_urls: vec!["http://127.0.0.1:1".into()],
                    rpc_endpoints: Vec::new(),
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
        );
        base
    }

    #[tokio::test]
    async fn an_unpriced_mainnet_is_not_presented_as_a_development_network() {
        let fixture = fixture_with_unreachable_chains();
        let address = ADDRESS.parse::<alloy::primitives::Address>().unwrap();
        fixture.handler.remember_balance(
            "alice",
            "robinhood",
            &format!("{address:#x}"),
            &Holding {
                wallet: "alice".into(),
                chain: "robinhood".into(),
                account: String::new(),
                price_key: None,
                label: "Robinhood Chain".into(),
                symbol: "ETH".into(),
                quantity: "1.25".into(),
                amount: 1.25,
                value: None,
            },
        );

        let html = render(&fixture.handler, WALLETS_HTML).await;
        assert!(html.contains("Unpriced balances · 1"), "{html}");
        assert!(html.contains("excluded from dollar totals"), "{html}");
        assert!(!html.contains("Test and development"), "{html}");
    }

    #[tokio::test]
    async fn a_chain_without_a_native_token_shows_no_native_balance() {
        let fixture = fixture_with_unreachable_chains();
        let address = ADDRESS.parse::<alloy::primitives::Address>().unwrap();
        // Even a remembered placeholder from an older build stays hidden.
        fixture.handler.remember_balance(
            "alice",
            "tempo",
            &format!("{address:#x}"),
            &Holding {
                wallet: "alice".into(),
                chain: "tempo".into(),
                account: String::new(),
                price_key: None,
                label: "Tempo".into(),
                symbol: "ETH".into(),
                quantity: "4242424242424242424242424242424242424242424242424242424242".into(),
                amount: 4.24e57,
                value: None,
            },
        );

        let html = render(&fixture.handler, WALLETS_HTML).await;
        assert!(!html.contains("4242424242"), "{html}");
        assert!(!html.contains("Tempo"), "{html}");
    }
}
