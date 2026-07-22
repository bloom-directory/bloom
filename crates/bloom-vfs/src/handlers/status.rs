//! `status/` — daemon health, chain registry summary, audit/cache/policy
//! observability.
//!
//! Paths handled:
//! - `status/version`                            — daemon version (text)
//! - `status/uptime`                             — `Ns\n` or `HH:MM:SS\n`
//! - `status/started_at`                         — RFC3339 timestamp
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
//! - `status/cache/etherscan_entries`            — count of cached etherscan files
//! - `status/cache/prices_entries`               — count of cached price responses
//! - `status/wallets/count`                      — number of wallets
//! - `status/outbox/pending_count`               — total pending tx ids
//! - `status/backends/<feature>`                 — declared backend per feature
//!   (`contract_metadata`, `address_history`, `event_logs`, `storage_reads`,
//!   `proxy_detection`); each returns one of `etherscan`, `rpc`, `indexer`.
//! - `status/backends/summary.json`              — JSON map of all of the above
//! - `status/update/`                            — only present when the
//!   daemon wired an update snapshot producer (see
//!   [`StatusHandler::with_update_snapshot_fn`]). The subtree
//!   exposes the installed version, the latest known GitHub release,
//!   a computed `available` verdict, the `behind_by` patch diff,
//!   the `checked_at` timestamp, the `release_url`, and a
//!   `summary.json` bundling them all.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::Serialize;
use tokio::time::timeout;

use bloom_evm::ChainRegistry;
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MempoolBackendStatus {
    pub provider: String,
    pub subscribed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_to: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrivateRpcBackendStatus {
    pub last_status: String, // "healthy" | "degraded" | "unhealthy"
    pub last_probed_at: u64, // unix secs
}

/// Flat DTO mirroring the daemon's [`UpdateSnapshot`](bloom_update::UpdateSnapshot),
/// kept in `bloom-vfs` so the VFS handler can stay decoupled from
/// the `bloom-update` crate (the daemon converts at the closure
/// boundary). The VFS only reads these fields; nothing here is
/// `pub` for mutation beyond construction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateSnapshot {
    /// The version this binary was compiled with.
    pub installed: String,
    /// The latest known release tag from GitHub (e.g. `Some("0.2.0")`).
    pub latest: Option<String>,
    /// Computed verdict: are we behind, up to date, or unknown?
    pub available: UpdateAvailable,
    /// Patch-equivalent difference (see `bloom_update::cache::behind_by`).
    pub behind_by: Option<u64>,
    /// When the last successful refresh happened.
    pub checked_at: Option<SystemTime>,
    /// HTML URL of the latest release.
    pub release_url: Option<String>,
}

/// Verdicts the VFS can render for the `update/available` leaf and
/// the `summary.json.available` field. Re-exported from
/// `bloom-update` so the VFS handler and the upstream checker share
/// a single source of truth — adding a new verdict in one place
/// would silently desync the JSON payload otherwise.
pub use bloom_update::UpdateAvailable;

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
    /// Snapshot producer for the `status/update/*` subtree. The
    /// daemon wires this in via
    /// [`StatusHandler::with_update_snapshot_fn`]; when `None`, the
    /// `update/` directory is not advertised (existing tests that
    /// don't care about update info see no `update` entry in the
    /// top-level listing).
    pub update_snapshot_fn: Option<Arc<dyn Fn() -> Option<UpdateSnapshot> + Send + Sync>>,
    chain_cache: Arc<RwLock<std::collections::HashMap<String, ChainProbeCache>>>,
    mempool_statuses: Arc<RwLock<BTreeMap<String, MempoolBackendStatus>>>,
    private_rpc_healths: Arc<RwLock<BTreeMap<(String, String), PrivateRpcBackendStatus>>>,
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
            update_snapshot_fn: None,
            chain_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
            mempool_statuses: Arc::new(RwLock::new(BTreeMap::new())),
            private_rpc_healths: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Wire the closure that produces the `update/*` subtree's
    /// snapshot. The daemon passes a closure that calls
    /// `bloom_update::UpdateChecker::snapshot` and converts to the
    /// VFS DTO. When this is not called, the `update/` directory is
    /// not advertised in `ls /status`.
    pub fn with_update_snapshot_fn(
        mut self,
        f: Arc<dyn Fn() -> Option<UpdateSnapshot> + Send + Sync>,
    ) -> Self {
        self.update_snapshot_fn = Some(f);
        self
    }

    /// Replace the per-chain mempool status snapshot. Used by the daemon
    /// to publish what `MempoolStream` is doing (Task 4.6).
    pub fn with_mempool_statuses(self, map: BTreeMap<String, MempoolBackendStatus>) -> Self {
        *self.mempool_statuses.write() = map;
        self
    }

    /// Replace the per-(chain, provider) private-RPC health snapshot.
    pub fn with_private_rpc_healths(
        self,
        map: BTreeMap<(String, String), PrivateRpcBackendStatus>,
    ) -> Self {
        *self.private_rpc_healths.write() = map;
        self
    }

    /// Live update of the per-chain mempool status snapshot from a
    /// background probe task. The inner field is already shared, so an
    /// existing `Arc<StatusHandler>` mount picks up the change on the
    /// next read.
    pub fn replace_mempool_statuses(&self, map: BTreeMap<String, MempoolBackendStatus>) {
        *self.mempool_statuses.write() = map;
    }

    /// Live update of the per-(chain, provider) private-RPC health snapshot.
    pub fn replace_private_rpc_healths(
        &self,
        map: BTreeMap<(String, String), PrivateRpcBackendStatus>,
    ) {
        *self.private_rpc_healths.write() = map;
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
        // Strip api keys appearing in URL userinfo, as the final URL path
        // segment, or as common query params. Best-effort; on parse failure we
        // return the original.
        let mut redacted = match url::Url::parse(raw) {
            Ok(u) => u,
            Err(_) => return raw.to_string(),
        };
        if !redacted.username().is_empty() {
            let _ = redacted.set_username("***");
        }
        if redacted.password().is_some() {
            let _ = redacted.set_password(Some("***"));
        }
        // Redact suspicious query params.
        let q: Vec<(String, String)> = redacted
            .query_pairs()
            .map(|(k, v)| {
                let lower = k.to_ascii_lowercase();
                let secret_like = matches!(
                    lower.as_str(),
                    "apikey"
                        | "api_key"
                        | "key"
                        | "token"
                        | "access_token"
                        | "auth"
                        | "authorization"
                        | "password"
                        | "passwd"
                        | "pwd"
                        | "signature"
                        | "sig"
                ) || lower.ends_with("_key")
                    || lower.ends_with("-key")
                    || lower.contains("token")
                    || lower.contains("secret")
                    || lower.contains("signature");
                let val = if secret_like && !v.is_empty() {
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
            [s] if s == "daemon.json" || s == "version" || s == "uptime" || s == "started_at" => {
                Ok(Entry::file(s))
            }
            [s] if s == "chains"
                || s == "audit"
                || s == "cache"
                || s == "wallets"
                || s == "outbox"
                || s == "backends"
                || s == "private_rpc" =>
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
            [a, leaf] if a == "audit" && matches!(leaf.as_str(), "head" | "count") => {
                Ok(Entry::file(leaf))
            }
            [a, leaf]
                if a == "cache"
                    && matches!(leaf.as_str(), "etherscan_entries" | "prices_entries") =>
            {
                Ok(Entry::file(leaf))
            }
            [a, leaf] if a == "wallets" && leaf == "count" => Ok(Entry::file(leaf)),
            [a, leaf] if a == "outbox" && leaf == "pending_count" => Ok(Entry::file(leaf)),
            [a, leaf] if a == "backends" => {
                let extra = matches!(leaf.as_str(), "mempool" | "private_rpc");
                if leaf == "summary.json" || extra || self.backends.get(leaf).is_some() {
                    Ok(Entry::file(leaf))
                } else {
                    Err(HandlerError::not_found(path.to_string_path()))
                }
            }
            [a, leaf] if a == "private_rpc" => {
                let map = self.private_rpc_healths.read();
                if map.iter().any(|((_, prov), _)| prov == leaf) {
                    Ok(Entry::file(leaf))
                } else {
                    Err(HandlerError::not_found(path.to_string_path()))
                }
            }
            [a] if a == "update" => {
                if self.update_snapshot_fn.is_some() {
                    Ok(Entry::dir("update"))
                } else {
                    Err(HandlerError::not_found(path.to_string_path()))
                }
            }
            [a, leaf] if a == "update" => {
                if self.update_snapshot_fn.is_none() {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                if matches!(
                    leaf.as_str(),
                    "installed"
                        | "latest"
                        | "available"
                        | "behind_by"
                        | "checked_at"
                        | "release_url"
                        | "summary.json"
                ) {
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
            [s] if s == "daemon.json" => {
                let info = DaemonInfo {
                    version: self.version.clone(),
                    started_unix_ms: self.started_unix_ms(),
                    started_at: self.started_at_rfc3339(),
                    uptime_secs: self.uptime_secs(),
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
            [a, leaf] if a == "cache" && leaf == "etherscan_entries" => {
                Ok(format!("{}\n", self.etherscan_entries()).into_bytes())
            }
            [a, leaf] if a == "cache" && leaf == "prices_entries" => {
                Ok(format!("{}\n", self.prices_entries()).into_bytes())
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
            [a, leaf] if a == "backends" && leaf == "mempool" => {
                let map = self.mempool_statuses.read().clone();
                serde_json::to_vec_pretty(&map).map_err(|e| HandlerError::backend(e.to_string()))
            }
            [a, leaf] if a == "backends" && leaf == "private_rpc" => {
                let map = self.private_rpc_healths.read();
                let mut nested: BTreeMap<String, BTreeMap<String, PrivateRpcBackendStatus>> =
                    BTreeMap::new();
                for ((chain, prov), v) in map.iter() {
                    nested
                        .entry(chain.clone())
                        .or_default()
                        .insert(prov.clone(), v.clone());
                }
                serde_json::to_vec_pretty(&nested).map_err(|e| HandlerError::backend(e.to_string()))
            }
            [a, leaf] if a == "backends" => match self.backends.get(leaf) {
                Some(b) => Ok(format!("{}\n", b.as_str()).into_bytes()),
                None => Err(HandlerError::NotAFile(path.to_string_path())),
            },
            [a, provider] if a == "private_rpc" => {
                // Return a deterministic, per-chain view for this
                // provider rather than the first matching entry across
                // all chains. The map is keyed by chain name so
                // callers can see how the same provider behaves on
                // each configured chain. `BTreeMap` keeps the output
                // ordering stable across reads.
                let map = self.private_rpc_healths.read();
                let by_chain: BTreeMap<String, PrivateRpcBackendStatus> = map
                    .iter()
                    .filter(|((_, p), _)| p == provider)
                    .map(|((chain, _), v)| (chain.clone(), v.clone()))
                    .collect();
                if by_chain.is_empty() {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                serde_json::to_vec_pretty(&by_chain)
                    .map_err(|e| HandlerError::backend(e.to_string()))
            }
            [a] if a == "update" => {
                // Reading the directory as a file is invalid; the
                // VFS caller should use list instead.
                Err(HandlerError::NotAFile(path.to_string_path()))
            }
            [a, leaf] if a == "update" => {
                // Every update leaf reads from the snapshot. The
                // daemon's closure always produces a snapshot, so
                // `installed` is always populated (with the
                // compile-time version) even when no GitHub refresh
                // has happened yet. When no snapshot producer is
                // wired at all (e.g. some VFS tests), all leaves
                // are not-found.
                if self.update_snapshot_fn.is_none() {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                let snap = match self.update_snapshot_fn.as_ref().and_then(|f| f()) {
                    Some(s) => s,
                    None => return Err(HandlerError::not_found(path.to_string_path())),
                };
                match leaf.as_str() {
                    "installed" => Ok(format!("{}\n", snap.installed).into_bytes()),
                    "latest" => {
                        Ok(format!("{}\n", snap.latest.as_deref().unwrap_or("")).into_bytes())
                    }
                    "available" => Ok(match snap.available {
                        UpdateAvailable::OutOfDate => b"out_of_date\n".to_vec(),
                        UpdateAvailable::UpToDate => b"up_to_date\n".to_vec(),
                        UpdateAvailable::Unknown => b"unknown\n".to_vec(),
                    }),
                    "behind_by" => Ok(format!("{}\n", snap.behind_by.unwrap_or(0)).into_bytes()),
                    "checked_at" => {
                        Ok(format!("{}\n", format_update_checked_at(snap.checked_at)).into_bytes())
                    }
                    "release_url" => {
                        Ok(format!("{}\n", snap.release_url.as_deref().unwrap_or("")).into_bytes())
                    }
                    "summary.json" => serde_json::to_vec_pretty(&serde_json::json!({
                        "installed": snap.installed,
                        "latest": snap.latest.as_deref().unwrap_or(""),
                        "available": update_available_label(snap.available),
                        "behind_by": snap.behind_by.unwrap_or(0),
                        "checked_at": format_update_checked_at(snap.checked_at),
                        "release_url": snap.release_url.as_deref().unwrap_or(""),
                    }))
                    .map_err(|e| HandlerError::backend(e.to_string())),
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
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
                Entry::dir("chains"),
                Entry::dir("audit"),
                Entry::dir("cache"),
                Entry::dir("wallets"),
                Entry::dir("outbox"),
                Entry::dir("backends"),
                Entry::dir("private_rpc"),
            ]
            .into_iter()
            // `update/` is only advertised when the daemon wired a
            // snapshot producer. Existing tests that don't care
            // about update info continue to see no `update` entry.
            .chain(if self.update_snapshot_fn.is_some() {
                vec![Entry::dir("update")]
            } else {
                vec![]
            })
            .collect()),
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
            [a] if a == "audit" => Ok(vec![Entry::file("head"), Entry::file("count")]),
            [a] if a == "cache" => Ok(vec![
                Entry::file("etherscan_entries"),
                Entry::file("prices_entries"),
            ]),
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
                entries.push(Entry::file("mempool"));
                entries.push(Entry::file("private_rpc"));
                Ok(entries)
            }
            [a] if a == "private_rpc" => {
                // Deduplicate provider names across chains: one entry
                // per unique provider, since `private_rpc/<provider>`
                // returns a per-chain map for that provider rather
                // than a single chain's status.
                let map = self.private_rpc_healths.read();
                let unique: std::collections::BTreeSet<String> =
                    map.keys().map(|(_, prov)| prov.clone()).collect();
                Ok(unique.into_iter().map(|p| Entry::file(&p)).collect())
            }
            [a] if a == "update" => {
                if self.update_snapshot_fn.is_some() {
                    Ok(vec![
                        Entry::file("installed"),
                        Entry::file("latest"),
                        Entry::file("available"),
                        Entry::file("behind_by"),
                        Entry::file("checked_at"),
                        Entry::file("release_url"),
                        Entry::file("summary.json"),
                    ])
                } else {
                    Err(HandlerError::NotADir(path.to_string_path()))
                }
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
            // Keep audit counters live; raw audit records are intentionally
            // not exposed through the mounted status VFS.
            Some("audit") => None,
            // Chain probes hit RPC; the handler also has its own
            // 2s probe cache, but caching at the router avoids even
            // the JSON re-serialisation cost.
            Some("chains") => Some(Duration::from_secs(5)),
            // Filesystem counts. Cheap, but cap polling.
            Some("cache" | "wallets" | "outbox") => Some(Duration::from_secs(5)),
            // Daemon-static fields.
            Some("version" | "started_at") => Some(Duration::from_secs(86_400)),
            Some("uptime" | "daemon.json") => Some(Duration::from_secs(2)),
            // `backends/*` is mostly static config (per-feature backend
            // declaration + `summary.json`), but `backends/mempool` and
            // `backends/private_rpc` are live JSON snapshots updated at
            // runtime by the daemon — keep those on the same 5s cap as
            // the chain probes so they don't go stale behind a 24h TTL.
            Some("backends") => match segs.get(1).map(|s| s.as_str()) {
                Some("mempool" | "private_rpc") => Some(Duration::from_secs(5)),
                _ => Some(Duration::from_secs(86_400)),
            },
            // Per-provider private RPC status is live, matching the
            // `backends/private_rpc` JSON view above so cached reads
            // can't diverge between the two surfaces.
            Some("private_rpc") => Some(Duration::from_secs(5)),
            // `update/installed` is daemon-static (compile-time
            // version); everything else in the subtree is bounded
            // by the underlying 5-minute background refresh, so 5s
            // is the right router-level ceiling.
            Some("update") => match segs.get(1).map(|s| s.as_str()) {
                Some("installed") => Some(Duration::from_secs(86_400)),
                _ => Some(Duration::from_secs(5)),
            },
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

fn format_update_checked_at(time: Option<SystemTime>) -> String {
    let Some(secs) = time
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
    else {
        return String::new();
    };
    let (y, mo, d, h, mi, se) = unix_to_civil(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, se)
}

fn update_available_label(available: UpdateAvailable) -> &'static str {
    match available {
        UpdateAvailable::OutOfDate => "out_of_date",
        UpdateAvailable::UpToDate => "up_to_date",
        UpdateAvailable::Unknown => "unknown",
    }
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
        let tx_engine = TxEngine::new(outbox, 60_000);
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
            "chains",
            "audit",
            "cache",
            "wallets",
            "outbox",
            "backends",
        ] {
            assert!(names.contains(&required), "missing top-level: {required}");
        }
        // No update snapshot wired in this test → no `update` entry.
        assert!(
            !names.contains(&"update"),
            "update must not be advertised when snapshot_fn is None"
        );
    }

    /// Build a `StatusHandler` with a canned update snapshot wired in.
    /// Used by the update-subtree tests below.
    fn make_handler_with_update(home: &std::path::Path, snap: UpdateSnapshot) -> StatusHandler {
        let mut h = make_handler(home);
        h.update_snapshot_fn = Some(Arc::new(move || Some(snap.clone())));
        h
    }

    #[tokio::test]
    async fn update_dir_listed_when_snapshot_fn_wired() {
        let dir = tempfile::tempdir().unwrap();
        let snap = UpdateSnapshot {
            installed: "0.1.0".into(),
            latest: Some("0.2.0".into()),
            available: UpdateAvailable::OutOfDate,
            behind_by: Some(100),
            checked_at: Some(std::time::SystemTime::UNIX_EPOCH),
            release_url: Some(
                "https://github.com/bloom-directory/bloom/releases/tag/v0.2.0".into(),
            ),
        };
        let h = make_handler_with_update(dir.path(), snap);
        let entries = h.list(&VfsPath::parse("").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"update"), "update must be advertised");
        let leaves = h.list(&VfsPath::parse("update").unwrap()).await.unwrap();
        let leaf_names: Vec<&str> = leaves.iter().map(|e| e.name.as_str()).collect();
        for required in [
            "installed",
            "latest",
            "available",
            "behind_by",
            "checked_at",
            "release_url",
            "summary.json",
        ] {
            assert!(
                leaf_names.contains(&required),
                "missing update leaf: {required}"
            );
        }
    }

    #[tokio::test]
    async fn update_leaves_render_for_known_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let snap = UpdateSnapshot {
            installed: "0.1.0".into(),
            latest: Some("0.2.0".into()),
            available: UpdateAvailable::OutOfDate,
            behind_by: Some(100),
            checked_at: Some(std::time::SystemTime::UNIX_EPOCH),
            release_url: Some(
                "https://github.com/bloom-directory/bloom/releases/tag/v0.2.0".into(),
            ),
        };
        let h = make_handler_with_update(dir.path(), snap);

        // Plain text leaves.
        let installed = h
            .read(&VfsPath::parse("update/installed").unwrap())
            .await
            .unwrap();
        assert_eq!(installed, b"0.1.0\n");
        let latest = h
            .read(&VfsPath::parse("update/latest").unwrap())
            .await
            .unwrap();
        assert_eq!(latest, b"0.2.0\n");
        let available = h
            .read(&VfsPath::parse("update/available").unwrap())
            .await
            .unwrap();
        assert_eq!(available, b"out_of_date\n");
        let behind = h
            .read(&VfsPath::parse("update/behind_by").unwrap())
            .await
            .unwrap();
        assert_eq!(behind, b"100\n");
        let url = h
            .read(&VfsPath::parse("update/release_url").unwrap())
            .await
            .unwrap();
        assert_eq!(
            url,
            b"https://github.com/bloom-directory/bloom/releases/tag/v0.2.0\n"
        );

        // summary.json
        let body = h
            .read(&VfsPath::parse("update/summary.json").unwrap())
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["installed"], serde_json::json!("0.1.0"));
        assert_eq!(v["latest"], serde_json::json!("0.2.0"));
        assert_eq!(v["available"], serde_json::json!("out_of_date"));
        assert_eq!(v["behind_by"], serde_json::json!(100));
        assert_eq!(v["checked_at"], serde_json::json!("1970-01-01T00:00:00Z"));
        assert_eq!(
            v["release_url"],
            serde_json::json!("https://github.com/bloom-directory/bloom/releases/tag/v0.2.0")
        );
    }

    #[tokio::test]
    async fn update_leaves_render_for_unknown_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let snap = UpdateSnapshot {
            installed: "0.1.0".into(),
            latest: None,
            available: UpdateAvailable::Unknown,
            behind_by: None,
            checked_at: None,
            release_url: None,
        };
        let h = make_handler_with_update(dir.path(), snap);
        assert_eq!(
            h.read(&VfsPath::parse("update/latest").unwrap())
                .await
                .unwrap(),
            b"\n",
            "unknown latest should be an empty line, not 404"
        );
        assert_eq!(
            h.read(&VfsPath::parse("update/available").unwrap())
                .await
                .unwrap(),
            b"unknown\n"
        );
        assert_eq!(
            h.read(&VfsPath::parse("update/behind_by").unwrap())
                .await
                .unwrap(),
            b"0\n",
            "unknown behind_by should be 0, not 404"
        );
        assert_eq!(
            h.read(&VfsPath::parse("update/checked_at").unwrap())
                .await
                .unwrap(),
            b"\n",
            "unknown checked_at should be an empty line, not the Unix epoch"
        );
        let body = h
            .read(&VfsPath::parse("update/summary.json").unwrap())
            .await
            .unwrap();
        let summary: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(summary["latest"], serde_json::json!(""));
        assert_eq!(summary["available"], serde_json::json!("unknown"));
        assert_eq!(summary["behind_by"], serde_json::json!(0));
        assert_eq!(summary["checked_at"], serde_json::json!(""));
        assert_eq!(summary["release_url"], serde_json::json!(""));
    }

    #[tokio::test]
    async fn update_leaves_not_found_when_snapshot_fn_unwired() {
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        // No update dir at top level.
        let entries = h.list(&VfsPath::parse("").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&"update"));
        // Direct lookup of an update leaf should be NotFound.
        let err = h
            .read(&VfsPath::parse("update/installed").unwrap())
            .await
            .expect_err("must not find update leaf without snapshot_fn");
        let _ = err;
    }

    #[tokio::test]
    async fn status_does_not_expose_home_or_raw_audit_tail() {
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());

        assert!(h.read(&VfsPath::parse("home").unwrap()).await.is_err());
        assert!(
            h.read(&VfsPath::parse("audit/last").unwrap())
                .await
                .is_err()
        );

        let daemon = h
            .read(&VfsPath::parse("daemon.json").unwrap())
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&daemon).unwrap();
        assert!(value.get("home").is_none());
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

    #[test]
    fn redacts_url_userinfo_and_secret_query_params() {
        let red = StatusHandler::redact_url(
            "https://rpc_user:rpc_password@rpc.example.com/path?auth=letmein&signature=abc123&chain=base",
        );

        assert!(!red.contains("rpc_user"), "got: {red}");
        assert!(!red.contains("rpc_password"), "got: {red}");
        assert!(!red.contains("letmein"), "got: {red}");
        assert!(!red.contains("abc123"), "got: {red}");
        assert!(red.contains("***:***@"), "got: {red}");
        assert!(red.contains("auth=***"), "got: {red}");
        assert!(red.contains("signature=***"), "got: {red}");
        assert!(red.contains("chain=base"), "got: {red}");
    }

    #[tokio::test]
    async fn endpoints_leaf_url_is_redacted() {
        use bloom_evm::ChainClient;
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

    #[tokio::test]
    async fn backends_mempool_returns_provider_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        let mut map = BTreeMap::new();
        map.insert(
            "ethereum".to_string(),
            MempoolBackendStatus {
                provider: "alchemy".into(),
                subscribed: true,
                fallback_to: None,
            },
        );
        let h = h.with_mempool_statuses(map);
        let body = h
            .read(&VfsPath::parse("backends/mempool").unwrap())
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ethereum"]["provider"], "alchemy");
        assert_eq!(v["ethereum"]["subscribed"], true);
    }

    #[tokio::test]
    async fn backends_private_rpc_returns_nested_per_chain_provider() {
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        let mut map = BTreeMap::new();
        map.insert(
            ("ethereum".to_string(), "mev_blocker".to_string()),
            PrivateRpcBackendStatus {
                last_status: "healthy".into(),
                last_probed_at: 1_700_000_000,
            },
        );
        map.insert(
            ("ethereum".to_string(), "flashbots".to_string()),
            PrivateRpcBackendStatus {
                last_status: "degraded".into(),
                last_probed_at: 1_700_000_001,
            },
        );
        let h = h.with_private_rpc_healths(map);
        let body = h
            .read(&VfsPath::parse("backends/private_rpc").unwrap())
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ethereum"]["mev_blocker"]["last_status"], "healthy");
        assert_eq!(v["ethereum"]["flashbots"]["last_status"], "degraded");
        assert_eq!(
            v["ethereum"]["mev_blocker"]["last_probed_at"],
            1_700_000_000
        );
    }

    #[tokio::test]
    async fn private_rpc_provider_leaf_returns_per_chain_map_or_not_found() {
        // `private_rpc/<provider>` must return a deterministic
        // `BTreeMap<chain, PrivateRpcBackendStatus>` so per-chain
        // differences aren't hidden when the same provider is
        // configured on multiple chains. Missing providers still
        // yield `NotFound`.
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        let mut map = BTreeMap::new();
        map.insert(
            ("ethereum".to_string(), "flashbots".to_string()),
            PrivateRpcBackendStatus {
                last_status: "healthy".into(),
                last_probed_at: 1_700_000_000,
            },
        );
        map.insert(
            ("sepolia".to_string(), "flashbots".to_string()),
            PrivateRpcBackendStatus {
                last_status: "degraded".into(),
                last_probed_at: 1_700_000_002,
            },
        );
        map.insert(
            ("ethereum".to_string(), "mev_blocker".to_string()),
            PrivateRpcBackendStatus {
                last_status: "degraded".into(),
                last_probed_at: 1_700_000_001,
            },
        );
        let h = h.with_private_rpc_healths(map);

        let body = h
            .read(&VfsPath::parse("private_rpc/flashbots").unwrap())
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ethereum"]["last_status"], "healthy");
        assert_eq!(v["ethereum"]["last_probed_at"], 1_700_000_000);
        assert_eq!(v["sepolia"]["last_status"], "degraded");
        assert_eq!(v["sepolia"]["last_probed_at"], 1_700_000_002);
        // Other providers must not leak into this provider's view.
        assert!(v.get("mev_blocker").is_none());

        // Single-chain provider still returns a map (with one entry),
        // not a bare status object, so the shape is uniform.
        let body = h
            .read(&VfsPath::parse("private_rpc/mev_blocker").unwrap())
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ethereum"]["last_status"], "degraded");

        let err = h
            .read(&VfsPath::parse("private_rpc/unknown").unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(err, HandlerError::NotFound(_)),
            "expected NotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn backends_list_includes_mempool_and_private_rpc() {
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        let entries = h.list(&VfsPath::parse("backends").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"mempool"), "missing mempool entry");
        assert!(names.contains(&"private_rpc"), "missing private_rpc entry");
    }

    #[tokio::test]
    async fn top_level_list_includes_private_rpc() {
        // The `private_rpc/` subtree is navigable independently of
        // `backends/private_rpc`, so it must appear in the root listing
        // alongside the other status surfaces.
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        let entries = h.list(&VfsPath::parse("").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"private_rpc"),
            "missing private_rpc top-level entry; got: {names:?}"
        );
    }

    #[tokio::test]
    async fn private_rpc_lists_providers_deduped_across_chains() {
        // `private_rpc/<provider>` reads return the first matching
        // entry regardless of chain, so listing the directory must
        // return one entry per *unique provider name* — not one per
        // (chain, provider) tuple.
        let dir = tempfile::tempdir().unwrap();
        let h = make_handler(dir.path());
        let mut map = BTreeMap::new();
        for ((chain, prov), ts) in [
            (("ethereum".to_string(), "flashbots".to_string()), 1u64),
            (("ethereum".to_string(), "mev_blocker".to_string()), 2u64),
            (("polygon".to_string(), "flashbots".to_string()), 3u64),
        ] {
            map.insert(
                (chain, prov),
                PrivateRpcBackendStatus {
                    last_status: "healthy".into(),
                    last_probed_at: ts,
                },
            );
        }
        let h = h.with_private_rpc_healths(map);

        let entries = h
            .list(&VfsPath::parse("private_rpc").unwrap())
            .await
            .unwrap();
        let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["flashbots", "mev_blocker"]);
    }
}
