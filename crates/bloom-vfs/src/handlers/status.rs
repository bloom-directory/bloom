//! `status/` — daemon health, chain registry summary, audit/cache/policy
//! observability.
//!
//! Paths handled:
//! - `status/version`                            — daemon version (text)
//! - `status/uptime`                             — `Ns\n` or `HH:MM:SS\n`
//! - `status/started_at`                         — RFC3339 timestamp
//! - `status/home`                               — absolute home dir path
//! - `status/daemon.json`                        — combined summary
//! - `status/chains/`                            — list of chain names
//! - `status/chains/<chain>/chain_id`            — numeric chain id
//! - `status/chains/<chain>/connected`           — `true`/`false` from RPC ping
//! - `status/chains/<chain>/block_number`        — latest block (cached briefly)
//! - `status/chains/<chain>/rpc_url`             — first configured RPC URL (redacted)
//! - `status/chains/<chain>/endpoints/`          — list of endpoint indices
//! - `status/chains/<chain>/endpoints/<idx>/`    — leaves per endpoint health snapshot
//!   - `url` (redacted), `score`, `cooldown_until`, `latency_ms`,
//!     `success_rate`, `last_block`
//! - `status/audit/head`                         — hex of head record digest
//! - `status/audit/count`                        — total entries (decimal)
//! - `status/audit/last`                         — JSON of the most recent N=10 entries
//! - `status/cache/etherscan_entries`            — count of cached etherscan files
//! - `status/cache/prices_entries`               — count of cached price responses
//! - `status/policies/block_mainnet_broadcast`   — `true`/`false`
//! - `status/wallets/count`                      — number of wallets
//! - `status/outbox/pending_count`               — total pending tx ids
//! - `status/backends/<feature>`                 — declared backend per feature
//!   (`contract_metadata`, `address_history`, `event_logs`, `storage_reads`,
//!   `proxy_detection`); each returns one of `etherscan`, `rpc`, `indexer`.
//! - `status/backends/summary.json`              — JSON map of all of the above

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::Serialize;
use tokio::time::timeout;

use bloom_chain::ChainRegistry;
use bloom_keystore::Keystore;
use bloom_prices::PricesClient;
use bloom_proto::{AuditLog, BackendsConfig};
use bloom_rpc::EndpointHealthSnapshot;
use bloom_tx::tx_engine::TxEngine;

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

/// Tunables for status reads.
const PING_TIMEOUT: Duration = Duration::from_millis(750);
const CHAIN_CACHE_TTL: Duration = Duration::from_secs(2);
/// Cap on how many recent audit entries `status/audit/last` returns.
const AUDIT_LAST_N: usize = 10;

#[derive(Clone)]
pub struct StatusHandler {
    pub chains: ChainRegistry,
    pub keystore: Keystore,
    pub tx_engine: TxEngine,
    pub audit: Arc<AuditLog>,
    pub prices: Option<PricesClient>,
    pub etherscan_cache_dir: Option<PathBuf>,
    pub etherscan_configured: bool,
    pub backends: BackendsConfig,
    pub home: PathBuf,
    pub started_at: SystemTime,
    pub version: String,
    chain_cache: Arc<RwLock<std::collections::HashMap<String, ChainProbeCache>>>,
}

#[derive(Clone)]
struct ChainProbeCache {
    fetched: Instant,
    connected: bool,
    block_number: Option<u64>,
}

impl StatusHandler {
    /// Construct a fully-wired handler. `etherscan_cache_dir` is the
    /// directory whose entries should be counted for the
    /// `cache/etherscan_entries` field; pass `None` if no etherscan cache
    /// has ever been wired. `etherscan_configured` reports whether the
    /// daemon's config provides etherscan credentials.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chains: ChainRegistry,
        keystore: Keystore,
        tx_engine: TxEngine,
        audit: Arc<AuditLog>,
        prices: Option<PricesClient>,
        etherscan_cache_dir: Option<PathBuf>,
        etherscan_configured: bool,
        home: PathBuf,
        started_at: SystemTime,
        version: impl Into<String>,
    ) -> Self {
        Self::with_backends(
            chains,
            keystore,
            tx_engine,
            audit,
            prices,
            etherscan_cache_dir,
            etherscan_configured,
            BackendsConfig::default(),
            home,
            started_at,
            version,
        )
    }

    /// Variant of [`Self::new`] that takes the per-feature backend
    /// declaration. Used by the daemon so `status/backends/...` reflects
    /// the live config; tests can call [`Self::new`] for the default.
    #[allow(clippy::too_many_arguments)]
    pub fn with_backends(
        chains: ChainRegistry,
        keystore: Keystore,
        tx_engine: TxEngine,
        audit: Arc<AuditLog>,
        prices: Option<PricesClient>,
        etherscan_cache_dir: Option<PathBuf>,
        etherscan_configured: bool,
        backends: BackendsConfig,
        home: PathBuf,
        started_at: SystemTime,
        version: impl Into<String>,
    ) -> Self {
        Self {
            chains,
            keystore,
            tx_engine,
            audit,
            prices,
            etherscan_cache_dir,
            etherscan_configured,
            backends,
            home,
            started_at,
            version: version.into(),
            chain_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn started_unix_ms(&self) -> u128 {
        self.started_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }

    fn uptime_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.started_at)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn uptime_string(&self) -> String {
        let secs = self.uptime_secs();
        if secs >= 60 {
            let h = secs / 3600;
            let m = (secs % 3600) / 60;
            let s = secs % 60;
            format!("{:02}:{:02}:{:02}", h, m, s)
        } else {
            format!("{}s", secs)
        }
    }

    fn started_at_rfc3339(&self) -> String {
        // Hand-rolled RFC3339 (UTC) to avoid pulling in chrono.
        let dur = self
            .started_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = dur.as_secs();
        let (y, mo, d, h, mi, se) = unix_to_civil(secs);
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, se)
    }

    async fn probe_chain(&self, name: &str) -> ChainProbeCache {
        if let Some(cached) = self.chain_cache.read().get(name).cloned()
            && cached.fetched.elapsed() < CHAIN_CACHE_TTL
        {
            return cached;
        }
        let mut probe = ChainProbeCache {
            fetched: Instant::now(),
            connected: false,
            block_number: None,
        };
        if let Some(client) = self.chains.get(name) {
            // Health-registry fast path: the per-endpoint active probe
            // loop in `bloom-rpc` is the source of truth for endpoint
            // reachability. If at least one endpoint has had a recent
            // successful probe (`last_block` populated) and is not
            // currently parked in cooldown, the chain is connected and
            // we report the highest observed `last_block` rather than
            // issuing a fresh live call.
            //
            // This makes "≥1 healthy endpoint → connected=true" robust
            // against the live-call path's pathologies: a refused
            // sibling endpoint racing inside the alloy `FallbackLayer`
            // can push the aggregate `block_number()` past
            // `PING_TIMEOUT` even when one endpoint would respond
            // cleanly on its own.
            let snaps = client.endpoints();
            if let Some(b) = aggregate_healthy_block(&snaps) {
                probe.connected = true;
                probe.block_number = Some(b);
                self.chain_cache
                    .write()
                    .insert(name.to_string(), probe.clone());
                return probe;
            }
            // Bootstrap path: the active probe loop hasn't populated
            // the registry yet (cold start; the loop sleeps
            // `PROBE_INTERVAL` before its first round). Fall back to a
            // live block-number call through the layered transport so
            // status reads in the first ~15 s after daemon launch
            // aren't artificially `connected=false`.
            match timeout(PING_TIMEOUT, client.block_number()).await {
                Ok(Ok(n)) => {
                    probe.connected = true;
                    probe.block_number = Some(n);
                }
                _ => {
                    probe.connected = false;
                }
            }
        }
        self.chain_cache
            .write()
            .insert(name.to_string(), probe.clone());
        probe
    }

    fn redact_url(raw: &str) -> String {
        // Strip api keys appearing as the final URL path segment or as
        // common query params. Best-effort; on parse failure we return
        // the original.
        let mut redacted = match url::Url::parse(raw) {
            Ok(u) => u,
            Err(_) => return raw.to_string(),
        };
        // Redact suspicious query params.
        let q: Vec<(String, String)> = redacted
            .query_pairs()
            .map(|(k, v)| {
                let lower = k.to_ascii_lowercase();
                let val = if matches!(
                    lower.as_str(),
                    "apikey" | "api_key" | "key" | "token" | "access_token"
                ) && !v.is_empty()
                {
                    "***".to_string()
                } else {
                    v.into_owned()
                };
                (k.into_owned(), val)
            })
            .collect();
        if !q.is_empty() {
            redacted.query_pairs_mut().clear();
            for (k, v) in q {
                redacted.query_pairs_mut().append_pair(&k, &v);
            }
        }
        // Redact long opaque trailing path segments (Alchemy/Infura style:
        // `/v2/<key>` or `/<key>`). Heuristic: ≥20 chars, alnum/_-.
        let path = redacted.path().to_string();
        let mut segs: Vec<&str> = path.split('/').collect();
        if let Some(last) = segs.last_mut() {
            let s = *last;
            if s.len() >= 20
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                *last = "***";
            }
        }
        let new_path = segs.join("/");
        redacted.set_path(&new_path);
        redacted.to_string()
    }

    fn etherscan_entries(&self) -> u64 {
        let dir = match &self.etherscan_cache_dir {
            Some(d) => d.clone(),
            None => return 0,
        };
        if !self.etherscan_configured {
            return 0;
        }
        count_files_recursive(&dir)
    }

    fn prices_entries(&self) -> u64 {
        // PricesClient keeps an in-memory cache; we don't have a getter for
        // its size today and shouldn't add one without owning that crate's
        // public surface for this task. Report 0 when no client is wired
        // and otherwise expose the only signal we can produce safely: 0
        // until a price-cache size accessor is added. Tracked as a TODO.
        let _ = &self.prices;
        0
    }

    fn wallet_count(&self) -> u64 {
        self.keystore.list().map(|v| v.len() as u64).unwrap_or(0)
    }

    fn outbox_pending_count(&self) -> u64 {
        let root = self.tx_engine.outbox.root();
        if !root.exists() {
            return 0;
        }
        let mut total: u64 = 0;
        let wallets = match std::fs::read_dir(root) {
            Ok(it) => it,
            Err(_) => return 0,
        };
        for w in wallets.flatten() {
            let wname = match w.file_name().to_str() {
                Some(n) => n.to_string(),
                None => continue,
            };
            let chains = match std::fs::read_dir(w.path()) {
                Ok(it) => it,
                Err(_) => continue,
            };
            for c in chains.flatten() {
                let cname = match c.file_name().to_str() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let pending_dir = c.path().join("pending");
                if !pending_dir.exists() {
                    continue;
                }
                let n = self
                    .tx_engine
                    .outbox
                    .list(&wname, &cname, bloom_tx::outbox::OutboxState::Pending)
                    .map(|v| v.len() as u64)
                    .unwrap_or(0);
                total += n;
            }
        }
        total
    }
}

/// Pure helper: given a snapshot of every endpoint's health, return
/// the highest `last_block` observed by an endpoint that is currently
/// out of cooldown. Returns `None` when no endpoint qualifies — either
/// the probe loop hasn't populated the registry yet (cold start) or
/// every endpoint is parked / never succeeded.
///
/// Extracted from `StatusHandler::probe_chain` so the unit tests can
/// exercise the aggregation rule without spinning up real RPC
/// transports. The rule is the load-bearing one for the `connected`
/// leaf: "≥1 healthy endpoint → connected=true, last_block populated".
fn aggregate_healthy_block(snaps: &[EndpointHealthSnapshot]) -> Option<u64> {
    let mut best: Option<u64> = None;
    for s in snaps {
        if s.cooldown_until.is_some() {
            continue;
        }
        if let Some(b) = s.last_block {
            best = Some(best.map_or(b, |prev| prev.max(b)));
        }
    }
    best
}

#[derive(Serialize)]
struct DaemonInfo {
    version: String,
    started_unix_ms: u128,
    started_at: String,
    uptime_secs: u64,
    home: String,
    chains: Vec<String>,
}

#[async_trait]
impl Handler for StatusHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "status.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "status.read_err");
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "status.list_err");
        }
        r
    }

    fn cache_ttl(&self, path: &VfsPath) -> Option<Duration> {
        self.cache_ttl_inner(path)
    }
}

impl StatusHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        match path.segments() {
            [] => Ok(Entry::dir("")),
            [s] if s == "daemon.json"
                || s == "version"
                || s == "uptime"
                || s == "started_at"
                || s == "home" =>
            {
                Ok(Entry::file(s))
            }
            [s] if s == "chains"
                || s == "audit"
                || s == "cache"
                || s == "policies"
                || s == "wallets"
                || s == "outbox"
                || s == "backends" =>
            {
                Ok(Entry::dir(s))
            }
            [a, name] if a == "chains" => {
                if self.chains.get(name).is_none() {
                    return Err(HandlerError::not_found(name.clone()));
                }
                Ok(Entry::dir(name))
            }
            [a, name, leaf] if a == "chains" => {
                if self.chains.get(name).is_none() {
                    return Err(HandlerError::not_found(name.clone()));
                }
                if matches!(
                    leaf.as_str(),
                    "chain_id" | "connected" | "block_number" | "rpc_url"
                ) {
                    Ok(Entry::file(leaf))
                } else if leaf == "endpoints" {
                    Ok(Entry::dir(leaf))
                } else {
                    Err(HandlerError::not_found(path.to_string_path()))
                }
            }
            [a, name, eps, idx] if a == "chains" && eps == "endpoints" => {
                let client = self
                    .chains
                    .get(name)
                    .ok_or_else(|| HandlerError::not_found(name.clone()))?;
                let i: usize = idx
                    .parse()
                    .map_err(|_| HandlerError::not_found(path.to_string_path()))?;
                if i >= client.endpoints().len() {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                Ok(Entry::dir(idx))
            }
            [a, name, eps, idx, leaf] if a == "chains" && eps == "endpoints" => {
                let client = self
                    .chains
                    .get(name)
                    .ok_or_else(|| HandlerError::not_found(name.clone()))?;
                let i: usize = idx
                    .parse()
                    .map_err(|_| HandlerError::not_found(path.to_string_path()))?;
                if i >= client.endpoints().len() {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                if matches!(
                    leaf.as_str(),
                    "url"
                        | "score"
                        | "cooldown_until"
                        | "latency_ms"
                        | "success_rate"
                        | "last_block"
                ) {
                    Ok(Entry::file(leaf))
                } else {
                    Err(HandlerError::not_found(path.to_string_path()))
                }
            }
            [a, leaf] if a == "audit" && matches!(leaf.as_str(), "head" | "count" | "last") => {
                Ok(Entry::file(leaf))
            }
            [a, leaf]
                if a == "cache"
                    && matches!(leaf.as_str(), "etherscan_entries" | "prices_entries") =>
            {
                Ok(Entry::file(leaf))
            }
            [a, leaf] if a == "policies" && leaf == "block_mainnet_broadcast" => {
                Ok(Entry::file(leaf))
            }
            [a, leaf] if a == "wallets" && leaf == "count" => Ok(Entry::file(leaf)),
            [a, leaf] if a == "outbox" && leaf == "pending_count" => Ok(Entry::file(leaf)),
            [a, leaf] if a == "backends" => {
                if leaf == "summary.json" || self.backends.get(leaf).is_some() {
                    Ok(Entry::file(leaf))
                } else {
                    Err(HandlerError::not_found(path.to_string_path()))
                }
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        match path.segments() {
            [s] if s == "version" => Ok(format!("{}\n", self.version).into_bytes()),
            [s] if s == "uptime" => Ok(format!("{}\n", self.uptime_string()).into_bytes()),
            [s] if s == "started_at" => Ok(format!("{}\n", self.started_at_rfc3339()).into_bytes()),
            [s] if s == "home" => Ok(format!("{}\n", self.home.display()).into_bytes()),
            [s] if s == "daemon.json" => {
                let info = DaemonInfo {
                    version: self.version.clone(),
                    started_unix_ms: self.started_unix_ms(),
                    started_at: self.started_at_rfc3339(),
                    uptime_secs: self.uptime_secs(),
                    home: self.home.display().to_string(),
                    chains: self.chains.list_names(),
                };
                Ok(serde_json::to_vec_pretty(&info).unwrap())
            }
            [a, name, leaf] if a == "chains" => {
                let client = self
                    .chains
                    .get(name)
                    .ok_or_else(|| HandlerError::not_found(name.clone()))?;
                match leaf.as_str() {
                    "chain_id" => Ok(format!("{}\n", client.spec().chain_id).into_bytes()),
                    "rpc_url" => {
                        let raw = client.spec().rpc_urls.first().cloned().unwrap_or_default();
                        Ok(format!("{}\n", Self::redact_url(&raw)).into_bytes())
                    }
                    "connected" => {
                        let probe = self.probe_chain(name).await;
                        Ok(format!("{}\n", probe.connected).into_bytes())
                    }
                    "block_number" => {
                        let probe = self.probe_chain(name).await;
                        match probe.block_number {
                            Some(n) => Ok(format!("{}\n", n).into_bytes()),
                            None => Err(HandlerError::backend(format!(
                                "chain '{}' unreachable",
                                name
                            ))),
                        }
                    }
                    _ => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
            [a, name, eps, idx, leaf] if a == "chains" && eps == "endpoints" => {
                let client = self
                    .chains
                    .get(name)
                    .ok_or_else(|| HandlerError::not_found(name.clone()))?;
                let i: usize = idx
                    .parse()
                    .map_err(|_| HandlerError::not_found(path.to_string_path()))?;
                let snaps = client.endpoints();
                let snap = snaps
                    .get(i)
                    .ok_or_else(|| HandlerError::not_found(path.to_string_path()))?;
                match leaf.as_str() {
                    "url" => Ok(format!("{}\n", Self::redact_url(&snap.url)).into_bytes()),
                    "score" => Ok(format!("{:.3}\n", snap.score).into_bytes()),
                    "latency_ms" => Ok(format!("{}\n", snap.latency_ms).into_bytes()),
                    "success_rate" => Ok(format!("{:.3}\n", snap.success_rate).into_bytes()),
                    "last_block" => match snap.last_block {
                        Some(b) => Ok(format!("{}\n", b).into_bytes()),
                        None => Ok(b"\n".to_vec()),
                    },
                    "cooldown_until" => match snap.cooldown_until {
                        Some(t) => {
                            // Render as Unix-seconds for stability;
                            // human-readable RFC3339 is built from
                            // the same source via `started_at` style
                            // helpers if a future leaf wants it.
                            let secs = t
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            Ok(format!("{}\n", secs).into_bytes())
                        }
                        None => Ok(b"\n".to_vec()),
                    },
                    _ => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
            [a, leaf] if a == "audit" && leaf == "head" => {
                Ok(format!("{}\n", self.audit.head_hash()).into_bytes())
            }
            [a, leaf] if a == "audit" && leaf == "count" => {
                let n = self
                    .audit
                    .count()
                    .map_err(|e| HandlerError::backend(e.to_string()))?;
                Ok(format!("{}\n", n).into_bytes())
            }
            [a, leaf] if a == "audit" && leaf == "last" => {
                let recs = self
                    .audit
                    .tail(AUDIT_LAST_N)
                    .map_err(|e| HandlerError::backend(e.to_string()))?;
                Ok(serde_json::to_vec_pretty(&recs).unwrap())
            }
            [a, leaf] if a == "cache" && leaf == "etherscan_entries" => {
                Ok(format!("{}\n", self.etherscan_entries()).into_bytes())
            }
            [a, leaf] if a == "cache" && leaf == "prices_entries" => {
                Ok(format!("{}\n", self.prices_entries()).into_bytes())
            }
            [a, leaf] if a == "policies" && leaf == "block_mainnet_broadcast" => {
                Ok(format!("{}\n", self.tx_engine.block_mainnet_broadcast).into_bytes())
            }
            [a, leaf] if a == "wallets" && leaf == "count" => {
                Ok(format!("{}\n", self.wallet_count()).into_bytes())
            }
            [a, leaf] if a == "outbox" && leaf == "pending_count" => {
                Ok(format!("{}\n", self.outbox_pending_count()).into_bytes())
            }
            [a, leaf] if a == "backends" && leaf == "summary.json" => {
                let map: serde_json::Map<String, serde_json::Value> = self
                    .backends
                    .entries()
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.as_str().into())))
                    .collect();
                Ok(serde_json::to_vec_pretty(&serde_json::Value::Object(map)).unwrap())
            }
            [a, leaf] if a == "backends" => match self.backends.get(leaf) {
                Some(b) => Ok(format!("{}\n", b.as_str()).into_bytes()),
                None => Err(HandlerError::NotAFile(path.to_string_path())),
            },
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        match path.segments() {
            [] => Ok(vec![
                Entry::file("daemon.json"),
                Entry::file("version"),
                Entry::file("uptime"),
                Entry::file("started_at"),
                Entry::file("home"),
                Entry::dir("chains"),
                Entry::dir("audit"),
                Entry::dir("cache"),
                Entry::dir("policies"),
                Entry::dir("wallets"),
                Entry::dir("outbox"),
                Entry::dir("backends"),
            ]),
            [a] if a == "chains" => Ok(self
                .chains
                .list_names()
                .into_iter()
                .map(|n| Entry::dir(&n))
                .collect()),
            [a, name] if a == "chains" => {
                if self.chains.get(name).is_none() {
                    return Err(HandlerError::not_found(name.clone()));
                }
                Ok(vec![
                    Entry::file("chain_id"),
                    Entry::file("connected"),
                    Entry::file("block_number"),
                    Entry::file("rpc_url"),
                    Entry::dir("endpoints"),
                ])
            }
            [a, name, eps] if a == "chains" && eps == "endpoints" => {
                let client = self
                    .chains
                    .get(name)
                    .ok_or_else(|| HandlerError::not_found(name.clone()))?;
                Ok((0..client.endpoints().len())
                    .map(|i| Entry::dir(&i.to_string()))
                    .collect())
            }
            [a, name, eps, idx] if a == "chains" && eps == "endpoints" => {
                let client = self
                    .chains
                    .get(name)
                    .ok_or_else(|| HandlerError::not_found(name.clone()))?;
                let i: usize = idx
                    .parse()
                    .map_err(|_| HandlerError::not_found(path.to_string_path()))?;
                if i >= client.endpoints().len() {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                Ok(vec![
                    Entry::file("url"),
                    Entry::file("score"),
                    Entry::file("cooldown_until"),
                    Entry::file("latency_ms"),
                    Entry::file("success_rate"),
                    Entry::file("last_block"),
                ])
            }
            [a] if a == "audit" => Ok(vec![
                Entry::file("head"),
                Entry::file("count"),
                Entry::file("last"),
            ]),
            [a] if a == "cache" => Ok(vec![
                Entry::file("etherscan_entries"),
                Entry::file("prices_entries"),
            ]),
            [a] if a == "policies" => Ok(vec![Entry::file("block_mainnet_broadcast")]),
            [a] if a == "wallets" => Ok(vec![Entry::file("count")]),
            [a] if a == "outbox" => Ok(vec![Entry::file("pending_count")]),
            [a] if a == "backends" => {
                let mut entries: Vec<Entry> = self
                    .backends
                    .entries()
                    .iter()
                    .map(|(k, _)| Entry::file(k))
                    .collect();
                entries.push(Entry::file("summary.json"));
                Ok(entries)
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }

    /// Per-path TTL hints for the router cache. Status fields are
    /// cheap but RPC-heavy (chain probes), so 5s smooths burst polling
    /// without making the data feel stale.
    fn cache_ttl_inner(&self, path: &VfsPath) -> Option<Duration> {
        let segs = path.segments();
        match segs.first().map(|s| s.as_str()) {
            // `audit/last` walks the file but is otherwise pure I/O;
            // we don't want to cache it because users tail it for live
            // events. Same for `audit/head`/`count` — keep them live.
            Some("audit") => None,
            // Chain probes hit RPC; the handler also has its own
            // 2s probe cache, but caching at the router avoids even
            // the JSON re-serialisation cost.
            Some("chains") => Some(Duration::from_secs(5)),
            // Filesystem counts. Cheap, but cap polling.
            Some("cache" | "wallets" | "outbox") => Some(Duration::from_secs(5)),
            // Daemon-static fields.
            Some("version" | "started_at" | "home") => Some(Duration::from_secs(86_400)),
            Some("uptime" | "daemon.json") => Some(Duration::from_secs(2)),
            Some("policies") => Some(Duration::from_secs(60)),
            // Backend declarations are static for the daemon's lifetime.
            Some("backends") => Some(Duration::from_secs(86_400)),
            _ => None,
        }
    }
}

fn count_files_recursive(dir: &std::path::Path) -> u64 {
    if !dir.exists() {
        return 0;
    }
    let mut total: u64 = 0;
    let entries = match std::fs::read_dir(dir) {
        Ok(it) => it,
        Err(_) => return 0,
    };
    for ent in entries.flatten() {
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            total += count_files_recursive(&ent.path());
        } else if ft.is_file() {
            total += 1;
        }
    }
    total
}

/// Convert a Unix timestamp (seconds since 1970-01-01 UTC) to (Y, M, D, h, m, s).
/// Algorithm from Howard Hinnant's date library (public domain).
fn unix_to_civil(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let z = (secs / 86_400) as i64; // days since epoch
    let secs_of_day = secs % 86_400;
    let h = (secs_of_day / 3600) as u32;
    let m = ((secs_of_day % 3600) / 60) as u32;
    let s = (secs_of_day % 60) as u32;
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let mo = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h, m, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_proto::{AuditLog, AuditRecord};
    use bloom_tx::outbox::Outbox;
    use std::time::Duration as StdDuration;

    fn make_handler(home: &std::path::Path) -> StatusHandler {
        let chains = ChainRegistry::default();
        let keystore = Keystore::new(home.join("keystore")).unwrap();
        let outbox = Outbox::new(home.join("outbox")).unwrap();
        let tx_engine = TxEngine::new(outbox, 60_000, true);
        let audit = Arc::new(AuditLog::open(home.join("audit.jsonl")).unwrap());
        StatusHandler::new(
            chains,
            keystore,
            tx_engine,
            audit,
            None,
            None,
            false,
            home.to_path_buf(),
            SystemTime::now() - StdDuration::from_secs(3),
            "0.0.0-test",
        )
    }

    #[tokio::test]
    async fn uptime_reports_seconds_or_hms() {
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        let p = VfsPath::parse("uptime").unwrap();
        let body = h.read(&p).await.unwrap();
        let s = String::from_utf8(body).unwrap();
        assert!(s.ends_with('\n'));
        let trimmed = s.trim_end();
        // We slept ~3 seconds so should be like "3s" or "Ns".
        assert!(
            trimmed.ends_with('s') || trimmed.contains(':'),
            "unexpected uptime: {trimmed:?}"
        );
    }

    #[tokio::test]
    async fn audit_head_reflects_appended_record() {
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        // Empty log → head is empty string (still terminated with \n).
        let p = VfsPath::parse("audit/head").unwrap();
        let empty = h.read(&p).await.unwrap();
        assert_eq!(empty, b"\n");
        // Append a record and check the head changes.
        let rec = h
            .audit
            .append(AuditRecord {
                ts_ms: 0,
                kind: "test".into(),
                wallet: None,
                chain: None,
                data: serde_json::json!({"k": 1}),
                prev: String::new(),
                digest: String::new(),
            })
            .unwrap();
        let body = h.read(&p).await.unwrap();
        let s = String::from_utf8(body).unwrap();
        assert_eq!(s, format!("{}\n", rec.digest));
        // count should also be 1.
        let count = h
            .read(&VfsPath::parse("audit/count").unwrap())
            .await
            .unwrap();
        assert_eq!(count, b"1\n");
    }

    #[tokio::test]
    async fn wallet_count_tracks_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        let p = VfsPath::parse("wallets/count").unwrap();
        // Empty keystore.
        let body = h.read(&p).await.unwrap();
        assert_eq!(body, b"0\n");
        // Add one watch wallet.
        let addr: alloy::primitives::Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        h.keystore.add_watch("alice", addr).unwrap();
        let body = h.read(&p).await.unwrap();
        assert_eq!(body, b"1\n");
    }

    #[tokio::test]
    async fn lists_top_level_entries() {
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        let entries = h.list(&VfsPath::parse("").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        for required in [
            "version",
            "uptime",
            "started_at",
            "home",
            "chains",
            "audit",
            "cache",
            "policies",
            "wallets",
            "outbox",
            "backends",
        ] {
            assert!(names.contains(&required), "missing top-level: {required}");
        }
    }

    #[tokio::test]
    async fn backends_surface_lists_each_feature_and_summary() {
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());

        // Each feature is a readable file with one of the three backend names.
        for feature in [
            "contract_metadata",
            "address_history",
            "event_logs",
            "storage_reads",
            "proxy_detection",
        ] {
            let p = VfsPath::parse(&format!("backends/{feature}")).unwrap();
            let body = h.read(&p).await.unwrap();
            let s = String::from_utf8(body).unwrap();
            let trimmed = s.trim_end();
            assert!(
                matches!(trimmed, "etherscan" | "rpc" | "indexer"),
                "unexpected backend label for {feature}: {trimmed:?}"
            );
        }

        // summary.json carries the same data as a JSON object.
        let p = VfsPath::parse("backends/summary.json").unwrap();
        let body = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        for feature in [
            "contract_metadata",
            "address_history",
            "event_logs",
            "storage_reads",
            "proxy_detection",
        ] {
            assert!(v[feature].is_string(), "summary missing {feature}");
        }

        // Listing the directory advertises each entry plus summary.json.
        let entries = h.list(&VfsPath::parse("backends").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        for required in [
            "contract_metadata",
            "address_history",
            "event_logs",
            "storage_reads",
            "proxy_detection",
            "summary.json",
        ] {
            assert!(names.contains(&required), "missing entry: {required}");
        }
    }

    fn snap(url: &str, last_block: Option<u64>, in_cooldown: bool) -> EndpointHealthSnapshot {
        // Only the fields `aggregate_healthy_block` reads matter for
        // these tests; latency/score/success_rate are filled with
        // plausible-but-arbitrary values so the snapshot would
        // round-trip through serde unchanged.
        let cooldown_until = if in_cooldown {
            // Twelve seconds in the future — well past any reasonable
            // probe round but still inside `Duration::from_secs(60)`
            // worth of room.
            Some(SystemTime::now() + StdDuration::from_secs(12))
        } else {
            None
        };
        EndpointHealthSnapshot {
            url: url.into(),
            score: if last_block.is_some() { 0.9 } else { 0.0 },
            cooldown_until,
            latency_ms: if last_block.is_some() { 120 } else { 0 },
            success_rate: if last_block.is_some() { 1.0 } else { 0.0 },
            last_block,
        }
    }

    #[test]
    fn aggregate_healthy_block_picks_good_endpoint_when_other_refused() {
        // Mirrors the user-reported scenario: one endpoint refuses
        // connection (recorded as a string of failures → cooldown,
        // last_block empty), another responded cleanly.
        let snaps = vec![
            snap("https://0xrpc.io/eth", Some(22_000_001), false),
            snap("https://eth.llamarpc.com", None, true),
        ];
        let block = aggregate_healthy_block(&snaps);
        assert_eq!(
            block,
            Some(22_000_001),
            "must report the healthy endpoint's last_block even when the sibling is in cooldown"
        );
    }

    #[test]
    fn aggregate_healthy_block_none_when_all_endpoints_down() {
        // Every endpoint either has no successful probe yet or is
        // parked in cooldown (or both). The aggregate must yield None
        // so `connected` reads as false.
        let snaps = vec![
            snap("https://eth.llamarpc.com", None, true),
            snap("https://busted.example", None, true),
            snap("https://never-probed.example", None, false),
        ];
        assert_eq!(aggregate_healthy_block(&snaps), None);
    }

    #[test]
    fn aggregate_healthy_block_recovers_when_endpoint_clears_cooldown() {
        // (1) Initial state: both endpoints cooled down → aggregate is None.
        let cooled = vec![
            snap("https://0xrpc.io/eth", None, true),
            snap("https://eth.llamarpc.com", None, true),
        ];
        assert_eq!(aggregate_healthy_block(&cooled), None);

        // (2) Probe loop records two consecutive successes for the
        //     first endpoint; the registry clears its cooldown and
        //     records `last_block`. The aggregate must flip back to
        //     Some(block) — i.e. `connected` recovers automatically.
        let recovered = vec![
            snap("https://0xrpc.io/eth", Some(22_000_002), false),
            snap("https://eth.llamarpc.com", None, true),
        ];
        assert_eq!(aggregate_healthy_block(&recovered), Some(22_000_002));
    }

    #[test]
    fn aggregate_healthy_block_takes_max_when_multiple_endpoints_healthy() {
        // Defensive: when more than one endpoint is healthy we report
        // the freshest block we've seen so a slightly-laggy endpoint
        // doesn't make the chain look behind tip.
        let snaps = vec![
            snap("https://primary.example", Some(22_000_010), false),
            snap("https://secondary.example", Some(22_000_007), false),
        ];
        assert_eq!(aggregate_healthy_block(&snaps), Some(22_000_010));
    }

    #[test]
    fn redacts_obvious_api_key() {
        let red = StatusHandler::redact_url(
            "https://eth-mainnet.g.alchemy.com/v2/abcdefghij1234567890ZZZZZZ",
        );
        assert!(!red.contains("abcdefghij1234567890"), "got: {red}");
        assert!(red.contains("***"), "expected redaction marker: {red}");

        let red2 = StatusHandler::redact_url("https://api.example.com/api?apikey=topsecret123");
        assert!(!red2.contains("topsecret123"), "got: {red2}");
    }

    #[tokio::test]
    async fn endpoints_leaf_url_is_redacted() {
        use bloom_chain::ChainClient;
        use bloom_proto::ChainSpec;
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        // Configure a chain with a key-shaped URL so we can verify
        // the leaf surfaces the redacted form rather than the raw
        // string. The key must be ≥20 alnum chars to trip
        // `redact_url`'s trailing-segment heuristic.
        let mut spec = ChainSpec::anvil_default();
        spec.name = "redact-test".into();
        spec.rpc_urls =
            vec!["https://eth-mainnet.g.alchemy.com/v2/abcdefghij1234567890ZZZZZZ".into()];
        let client = ChainClient::new(spec).unwrap();
        h.chains.add(client);

        let body = h
            .read(&VfsPath::parse("chains/redact-test/endpoints/0/url").unwrap())
            .await
            .unwrap();
        let s = String::from_utf8(body).unwrap();
        assert!(s.ends_with('\n'));
        // Redaction either drops the path or replaces it with `***`.
        assert!(!s.contains("abcdefghij1234567890"), "got: {s}");
        assert!(s.contains("eth-mainnet.g.alchemy.com"), "got: {s}");

        // Listing the chains/<n> dir should advertise the new
        // `endpoints` directory alongside the legacy leaves.
        let entries = h
            .list(&VfsPath::parse("chains/redact-test").unwrap())
            .await
            .unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"endpoints"), "missing endpoints dir");
        assert!(names.contains(&"rpc_url"), "missing rpc_url leaf");
    }
}
