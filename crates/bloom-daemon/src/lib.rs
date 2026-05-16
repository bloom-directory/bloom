//! Daemon library — wires the engines (keystore, chain, tx, vfs) into a
//! single runtime that can serve VFS calls. The actual NFS mount lives
//! in `bloom-mount` and is feature-gated; this library always exposes the
//! VFS via [`Daemon`] for in-process consumers like the CLI.

#![forbid(unsafe_code)]

pub mod ipc;

mod ens_resolver;
mod price_oracle;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bloom_chain::{ChainClient, ChainRegistry};
use bloom_defi::EnsoClient;
use bloom_ens::EnsClient;
use bloom_etherscan::EtherscanClient;
use bloom_keystore::Keystore;
use bloom_prices::PricesClient;
use bloom_proto::{AddressBook, AuditLog, Config, HomeDir};
use bloom_revert::{
    AbiSource, BuiltinDecoder, DecoderChain, EtherscanAbiDecoder, EtherscanAbiSource,
    OpenchainDecoder, boxed,
};
use bloom_tx::outbox::Outbox;
use bloom_tx::tx_engine::TxEngine;
use bloom_vfs::handlers::status::{MempoolBackendStatus, PrivateRpcBackendStatus};
use bloom_vfs::handlers::{
    AddressBookHandler, ChainsHandler, DefiHandler, DocsHandler, EnsHandler, PricesHandler,
    SimulateHandler, StatusHandler, ToolsHandler, WalletsHandler, WatchHandler,
};
use bloom_vfs::{PathCache, Vfs};
use bloom_watch::{WatchExecutor, WatchRegistry};
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("home: {0}")]
    Home(#[from] bloom_proto::HomeError),
    #[error("config: {0}")]
    Config(#[from] bloom_proto::ConfigError),
    #[error("keystore: {0}")]
    Keystore(String),
    #[error("chain: {0}")]
    Chain(#[from] bloom_chain::ChainError),
    #[error("outbox: {0}")]
    Outbox(String),
    #[error("audit: {0}")]
    Audit(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("watch: {0}")]
    Watch(String),
}

/// All wired-up state the daemon owns. Cheap to clone (everything is
/// behind Arc/clone-safe inner types).
#[derive(Clone)]
pub struct Daemon {
    pub home: HomeDir,
    pub config: Config,
    pub chains: ChainRegistry,
    pub keystore: Keystore,
    pub tx_engine: TxEngine,
    pub address_book: Arc<AddressBook>,
    pub audit: Arc<AuditLog>,
    pub vfs: Vfs,
    pub watch_registry: Arc<WatchRegistry>,
    pub watch_executor: Arc<WatchExecutor>,
    /// Shutdown handles for spawned mempool subscription tasks. Dropping
    /// these signals each task to exit at its next iteration.
    pub mempool_shutdown: Arc<parking_lot::Mutex<Vec<tokio::sync::oneshot::Sender<()>>>>,
    /// Shutdown handles for the bump scanner and the backends probe task.
    /// Sent on shutdown; safe even when no scanner / probe was spawned.
    pub bump_shutdown: Arc<parking_lot::Mutex<Vec<tokio::sync::oneshot::Sender<()>>>>,
    pub probe_shutdown: Arc<parking_lot::Mutex<Vec<tokio::sync::oneshot::Sender<()>>>>,
}

impl Daemon {
    /// Build a fully-wired daemon from the home directory, materialising
    /// any missing subdirs as needed.
    pub fn from_home(home: HomeDir) -> Result<Self, DaemonError> {
        home.ensure()?;
        let config_path = home.config_path();
        let config_existed = config_path.exists();
        let config = Config::load_or_init(&config_path)?;
        if config_existed {
            debug!(path = %config_path.display(), chains = config.chains.len(), default_chain = %config.default_chain, "config.loaded");
        } else {
            debug!(path = %config_path.display(), "config.initialised_default");
        }

        let mut clients: Vec<ChainClient> = Vec::new();
        for spec in config.chains.values() {
            match ChainClient::new(spec.clone()) {
                Ok(c) => clients.push(c),
                Err(e) => warn!(chain = %spec.name, error = %e, "daemon.chain_skipped"),
            }
        }
        let chains = ChainRegistry::default();
        for c in clients {
            chains.add(c);
        }

        // Build per-chain mempool indexes + handlers from [mempool.<chain>]
        // config. Each entry creates an LRU index, a VFS handler, and
        // spawns a long-lived subscription task. Handles are kept in
        // `mempool_shutdown` and signaled when the daemon's
        // BackgroundTasks is dropped.
        let mut mempool_indexes: std::collections::BTreeMap<
            String,
            Arc<bloom_mempool::PendingTxIndex>,
        > = Default::default();
        let mut mempool_handlers: std::collections::BTreeMap<
            String,
            Arc<bloom_vfs::handlers::MempoolHandler>,
        > = Default::default();
        let mut mempool_shutdown: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();

        for (chain_name, mc) in &config.mempool {
            // Skip chains not in the registry — we warn but don't fail
            // because a stale config entry shouldn't tank daemon boot.
            if chains.get(chain_name).is_none() {
                warn!(chain = %chain_name, "daemon.mempool_skipped: chain not configured");
                continue;
            }

            // Resolve the provider before allocating any state, so an
            // unknown provider id doesn't leave a half-mounted handler.
            //
            // `generic_eth_subscribe` exists at the crate level but isn't
            // enabled here: it's hash-only, and without tx-body enrichment
            // via `eth_getTransactionByHash` (a follow-up) it would push
            // zeroed `from/nonce/fees/input` records into the index,
            // breaking by-address filtering and nonce-conflict detection.
            // The defensive `delivers_bodies()` check below would refuse
            // it anyway; refusing here at the match keeps the failure
            // mode obvious from the config surface.
            let provider: Arc<dyn bloom_mempool::MempoolProvider> = match mc.provider.as_str() {
                "alchemy" => Arc::new(bloom_mempool::providers::alchemy::AlchemyProvider::new(
                    mc.ws_url.clone(),
                )),
                other => {
                    warn!(
                        chain = %chain_name,
                        provider = %other,
                        "daemon.mempool_skipped: unknown or unsupported provider \
                         (only \"alchemy\" is currently enabled at the daemon layer; \
                         hash-only providers like generic_eth_subscribe are pending \
                         tx-body enrichment)"
                    );
                    continue;
                }
            };

            // Defence in depth: even though the match above only admits
            // body-delivering providers today, this guards against a
            // future provider being added to the match without honouring
            // the `delivers_bodies()` contract. A hash-only provider
            // would push zeroed records into the index and break
            // by-address filtering and nonce-conflict detection.
            if !provider.delivers_bodies() {
                warn!(
                    chain = %chain_name,
                    provider = %mc.provider,
                    "daemon.mempool_skipped: provider does not deliver full tx bodies; \
                     by-address index and nonce-conflict detection would be broken. \
                     Configure a body-delivering provider (e.g. \"alchemy\")."
                );
                continue;
            }

            // Clamp max_index_size = 0 → 1 so PendingTxIndex::new never
            // asserts. A zero value in config is almost certainly a mistake.
            let size = mc.max_index_size.max(1);
            if size != mc.max_index_size {
                warn!(
                    chain = %chain_name,
                    configured = mc.max_index_size,
                    "daemon.mempool_max_index_size_clamped_to_1"
                );
            }
            let idx = bloom_mempool::PendingTxIndex::new(size);
            let handler = Arc::new(bloom_vfs::handlers::MempoolHandler::new(
                chain_name.clone(),
                mc.provider.clone(),
                idx.clone(),
            ));
            mempool_indexes.insert(chain_name.clone(), idx.clone());
            mempool_handlers.insert(chain_name.clone(), handler.clone());

            // Spawning the stream needs a tokio runtime; mirror the
            // watch-executor pattern and only spawn when one is current.
            if tokio::runtime::Handle::try_current().is_ok() {
                let sink: Arc<dyn bloom_mempool::stream::MempoolSink> = handler.clone();
                let shutdown = bloom_mempool::stream::spawn(chain_name.clone(), provider, sink);
                mempool_shutdown.push(shutdown);
                debug!(chain = %chain_name, provider = %mc.provider, "daemon.mempool_spawned");
            } else {
                debug!(chain = %chain_name, "daemon.mempool_spawn_deferred: no tokio runtime");
            }
        }

        let keystore =
            Keystore::new(home.keystore_dir()).map_err(|e| DaemonError::Keystore(e.to_string()))?;

        let outbox =
            Outbox::new(home.outbox_dir()).map_err(|e| DaemonError::Outbox(e.to_string()))?;
        let mut tx_engine = TxEngine::new(
            outbox,
            config.stage_ttl.as_millis(),
            config.block_mainnet_broadcast,
        );

        // Wire ENS resolver into TxEngine when a mainnet-style chain is
        // configured. We pick the first chain with id 1 / 11155111 / 5 /
        // 17000 (the ENS canonical-registry chains) for resolution.
        let ens_client = pick_ens_client(&chains);
        if let Some(c) = ens_client.clone() {
            debug!("daemon.ens_resolver_wired");
            tx_engine = tx_engine.with_resolver(Arc::new(ens_resolver::EnsAdapter::new(c)) as _);
        } else {
            debug!("daemon.ens_resolver_skipped: no ENS-capable chain configured");
        }

        let address_book_path = home.root().join("addressbook.toml");
        let address_book = match AddressBook::load(&address_book_path) {
            Ok(b) => {
                debug!(path = %address_book_path.display(), entries = b.entries.len(), "addressbook.loaded");
                b
            }
            Err(e) => {
                debug!(path = %address_book_path.display(), error = %e, "addressbook.load_failed_using_empty");
                AddressBook::default()
            }
        };
        let address_book_arc = Arc::new(address_book.clone());

        let audit =
            AuditLog::open(home.audit_path()).map_err(|e| DaemonError::Audit(e.to_string()))?;
        let audit_arc = Arc::new(audit.clone());
        let path_cache = Arc::new(PathCache::new());

        let watch_registry = Arc::new(
            WatchRegistry::new(home.watch_dir()).map_err(|e| DaemonError::Watch(e.to_string()))?,
        );
        let watch_executor = Arc::new(WatchExecutor::new(
            chains.clone(),
            watch_registry.clone(),
            home.clone(),
        ));

        let etherscan = config
            .etherscan
            .as_ref()
            .map(|c| match url::Url::parse(&c.api_url) {
                Ok(url) => {
                    debug!(api_url = %url, "daemon.etherscan_configured");
                    EtherscanClient::with_base_url(c.api_key.clone(), url)
                }
                Err(e) => {
                    warn!(api_url = %c.api_url, error = %e, "daemon.etherscan_url_invalid_using_default");
                    EtherscanClient::new(c.api_key.clone())
                }
            });
        if etherscan.is_none() {
            debug!("daemon.etherscan_skipped: no [etherscan] config");
        }
        let etherscan_arc = etherscan.map(Arc::new);

        let prices = PricesClient::new();

        // Wire the prices client into the policy USD-cap path. The trait
        // lives in bloom-tx; the adapter is in this crate so bloom-tx
        // doesn't pull reqwest+rustls.
        tx_engine =
            tx_engine.with_price_oracle(Arc::new(price_oracle::PricesOracle::new(prices.clone())));

        // Wire mempool indexes into TxEngine (drives nonce-conflict
        // checks + cancel.tx targeting). Done before private-RPC
        // registration so any future ordering invariants hold.
        for (chain_name, idx) in &mempool_indexes {
            tx_engine.set_mempool_index(chain_name.clone(), idx.clone());
        }

        // Build per-chain private RPC providers from [private_rpc.<chain>].
        // We also stash each successfully-registered provider so the
        // backends probe task can call `health()` on them every 60s
        // and publish results into the StatusHandler.
        let mut private_rpc_probes: Vec<(String, Arc<dyn bloom_mempool::PrivateRpcProvider>)> =
            Vec::new();
        for (chain_name, rc) in &config.private_rpc {
            let Some(client) = chains.get(chain_name) else {
                warn!(chain = %chain_name, "daemon.private_rpc_skipped: chain not configured");
                continue;
            };
            let chain_id = client.spec().chain_id;
            if let Some(url) = &rc.mev_blocker_url {
                match bloom_mempool::providers::mev_blocker::MevBlockerProvider::new(url.clone()) {
                    Ok(p) => {
                        let arc_p: Arc<dyn bloom_mempool::PrivateRpcProvider> = Arc::new(p);
                        if let Err(e) = tx_engine.register_private_rpc(chain_id, arc_p.clone()) {
                            warn!(chain = %chain_name, error = %e, "daemon.private_rpc_register_failed");
                        } else {
                            debug!(chain = %chain_name, provider = "mev_blocker", "daemon.private_rpc_registered");
                            private_rpc_probes.push((chain_name.clone(), arc_p));
                        }
                    }
                    Err(e) => {
                        warn!(chain = %chain_name, error = %e, "daemon.mev_blocker_init_failed")
                    }
                }
            }
            if let Some(url) = &rc.flashbots_url {
                match bloom_mempool::providers::flashbots::FlashbotsProvider::new(url.clone()) {
                    Ok(p) => {
                        let arc_p: Arc<dyn bloom_mempool::PrivateRpcProvider> = Arc::new(p);
                        if let Err(e) = tx_engine.register_private_rpc(chain_id, arc_p.clone()) {
                            warn!(chain = %chain_name, error = %e, "daemon.private_rpc_register_failed");
                        } else {
                            debug!(chain = %chain_name, provider = "flashbots", "daemon.private_rpc_registered");
                            private_rpc_probes.push((chain_name.clone(), arc_p));
                        }
                    }
                    Err(e) => {
                        warn!(chain = %chain_name, error = %e, "daemon.flashbots_init_failed")
                    }
                }
            }
        }

        // Build the tiered revert decoder once and share it across every
        // handler that needs to attribute revert returndata. Builtin
        // decoders (Solidity Error/Panic) are always installed; the
        // Etherscan-driven ABI decoder is layered on top when an
        // Etherscan client is configured. Stages 4 and 5 (Openchain,
        // Heimdall) plug in by appending more decoders here.
        let mut decoder_chain = DecoderChain::new().with(boxed(BuiltinDecoder));
        debug!("revert.decoder.builtin_pushed");
        if let Some(es) = etherscan_arc.clone() {
            let abi_source: Arc<dyn AbiSource> = Arc::new(EtherscanAbiSource::new(es));
            decoder_chain = decoder_chain.with(boxed(EtherscanAbiDecoder::new(abi_source)));
            debug!("revert.decoder.etherscan_pushed");
        } else {
            debug!("revert.decoder.etherscan_skipped: no etherscan client");
        }
        decoder_chain = decoder_chain.with(boxed(OpenchainDecoder::default()));
        debug!("revert.decoder.openchain_pushed");
        #[cfg(feature = "bytecode-decompile")]
        {
            let bytecode_source: Arc<dyn bloom_revert::BytecodeSource> = Arc::new(
                bloom_revert::ChainRegistryBytecodeSource::new(chains.clone()),
            );
            let cache_dir = home.cache_dir().join("heimdall");
            decoder_chain = decoder_chain.with(boxed(
                bloom_revert::HeimdallDecompileDecoder::new(bytecode_source)
                    .with_cache_dir(cache_dir),
            ));
            debug!(cache_dir = %home.cache_dir().join("heimdall").display(), "revert.decoder.heimdall_pushed");
        }
        #[cfg(not(feature = "bytecode-decompile"))]
        debug!("revert.decoder.heimdall_skipped: feature 'bytecode-decompile' off");
        let decoder_chain = Arc::new(decoder_chain);

        // Seed initial mempool backend statuses from the handlers we just
        // built. Subsequent live updates come from the probe task below.
        let mut initial_mempool_statuses: std::collections::BTreeMap<String, MempoolBackendStatus> =
            std::collections::BTreeMap::new();
        for (chain_name, handler) in &mempool_handlers {
            initial_mempool_statuses.insert(
                chain_name.clone(),
                MempoolBackendStatus {
                    provider: handler.provider_id().to_string(),
                    subscribed: handler.is_subscribed(),
                    fallback_to: None,
                },
            );
        }

        let status_handler = Arc::new(
            StatusHandler::with_backends(
                chains.clone(),
                keystore.clone(),
                tx_engine.clone(),
                audit_arc.clone(),
                Some(prices.clone()),
                Some(home.cache_dir().join("etherscan")),
                config
                    .etherscan
                    .as_ref()
                    .map(|c| !c.api_key.is_empty())
                    .unwrap_or(false),
                config.backends,
                home.root().to_path_buf(),
                SystemTime::now(),
                env!("CARGO_PKG_VERSION"),
            )
            .with_mempool_statuses(initial_mempool_statuses),
        );

        let mut vfs_builder = Vfs::builder()
            .mount(
                "chains",
                Arc::new(
                    ChainsHandler::new(chains.clone())
                        .with_etherscan(etherscan_arc.clone())
                        .with_ens(ens_client.clone())
                        .with_backends(config.backends)
                        .with_mempool_handlers(mempool_handlers.clone())
                        .with_revert_decoder(decoder_chain.clone()),
                ) as _,
            )
            .mount(
                "wallets",
                Arc::new(
                    WalletsHandler::new(
                        keystore.clone(),
                        chains.clone(),
                        tx_engine.clone(),
                        address_book.clone(),
                    )
                    .with_mempool_indexes(mempool_indexes.clone()),
                ) as _,
            )
            .mount("tools", Arc::new(ToolsHandler::new()) as _)
            .mount("status", status_handler.clone() as _)
            .mount("docs", Arc::new(DocsHandler::new()) as _)
            .mount(
                "simulate",
                Arc::new(SimulateHandler::new(
                    chains.clone(),
                    address_book_arc.clone(),
                )) as _,
            )
            .mount(
                "watch",
                Arc::new(WatchHandler::new(
                    watch_registry.clone(),
                    watch_executor.clone(),
                    home.clone(),
                )) as _,
            )
            .mount("ens", Arc::new(EnsHandler::new(ens_client.clone())) as _)
            .mount("prices", Arc::new(PricesHandler::new(prices)) as _)
            .mount(
                "addressbook",
                Arc::new(
                    AddressBookHandler::open(&address_book_path)
                        .map_err(|e| DaemonError::Audit(e.to_string()))?,
                ) as _,
            );

        // DeFi: Enso's public REST works without an API key for chains
        // they support keyless (currently quote+route on Base mainnet).
        // Mount whenever an `[enso]` block exists in config; an empty
        // api_key just means unauthenticated calls (rate-limited).
        if let Some(enso_cfg) = &config.enso {
            let mut enso = EnsoClient::new(&enso_cfg.api_key);
            match url::Url::parse(&enso_cfg.api_url) {
                Ok(url) => {
                    debug!(api_url = %url, "daemon.enso_configured");
                    enso = enso.with_base_url(url);
                }
                Err(e) => {
                    warn!(api_url = %enso_cfg.api_url, error = %e, "daemon.enso_url_invalid_using_default");
                }
            }
            if enso_cfg.api_key.is_empty() {
                warn!("enso api_key empty; mounting defi/ for keyless access (rate-limited)");
            }
            debug!("daemon.defi_mounted");
            vfs_builder = vfs_builder.mount(
                "defi",
                Arc::new(
                    DefiHandler::new(
                        enso,
                        chains.clone(),
                        keystore.clone(),
                        tx_engine.clone(),
                        address_book_arc.clone(),
                    )
                    .with_default_chain(config.default_chain.clone())
                    .with_revert_decoder(decoder_chain.clone()),
                ) as _,
            );
        } else {
            debug!("daemon.defi_skipped: no [enso] config");
        }

        let vfs = vfs_builder
            .with_audit(audit_arc.clone())
            .with_cache(path_cache)
            .build();

        // Start the watch executor so any pre-existing specs on disk are
        // sampled and any new ones registered by the WatchHandler get
        // picked up on the next tick. Idempotent so repeat boots are safe.
        //
        // `tokio::spawn` (used internally by `start`) requires an active
        // runtime; the daemon may be constructed from a synchronous test
        // helper, so we only attempt to start if a runtime is currently
        // installed. Production paths (`#[tokio::main]` in the CLI, the
        // mount serve loop) always have one.
        if tokio::runtime::Handle::try_current().is_ok() {
            if let Err(e) = watch_executor.start() {
                warn!(error = %e, "watch.executor.start_failed");
            }
        } else {
            warn!("watch.executor.skipped: no tokio runtime; call Daemon::start_workers later");
        }

        // Spawn the bump scanner if any chain has a mempool index. The
        // scanner walks the outbox every 30s and emits `bump.tx` /
        // `cancel.tx` / `bump_advice.json` artefacts next to stuck txs.
        //
        // Per-wallet `policy.bump.stuck_after_secs` and `basefee_overrun_pct`
        // are honoured via a lookup closure that reads each tx entry's
        // wallet's `policy.toml` at scan time. Unknown wallets fall back
        // to the scanner's global defaults (the same values exposed by
        // `BumpPolicy::default()` — they're kept in sync). Reading on
        // each scan tick (rather than caching at startup) means policy
        // edits take effect on the next pass without a daemon restart.
        let mut bump_shutdown: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();
        if !mempool_indexes.is_empty() && tokio::runtime::Handle::try_current().is_ok() {
            let shared_indexes: bloom_tx::bump_scanner::MempoolIndexes =
                Arc::new(parking_lot::RwLock::new(mempool_indexes.clone()));
            let basefee: Arc<dyn bloom_tx::bump_scanner::BasefeeProvider> =
                Arc::new(ChainBasefeeProvider {
                    chains: chains.clone(),
                });
            let cfg = bloom_tx::bump_scanner::BumpScannerConfig::default();
            let default_stuck_after = cfg.stuck_after;
            let default_overrun = cfg.basefee_overrun_pct;
            let ks_for_lookup = keystore.clone();
            let wallet_policy: bloom_tx::bump_scanner::WalletPolicyLookup =
                Arc::new(move |wallet: &str| {
                    match ks_for_lookup.info(wallet) {
                        Ok(info) => (
                            Duration::from_secs(info.policy.bump.stuck_after_secs),
                            info.policy.bump.basefee_overrun_pct,
                        ),
                        // Unknown wallet / missing policy.toml / parse error:
                        // fall back to global defaults rather than skipping
                        // the entry. A bad policy.toml shouldn't disable
                        // bump detection for that wallet's stuck txs.
                        Err(_) => (default_stuck_after, default_overrun),
                    }
                });
            let scanner = Arc::new(
                bloom_tx::bump_scanner::BumpScanner::new(
                    tx_engine.outbox.clone(),
                    shared_indexes,
                    basefee,
                    cfg,
                )
                .with_wallet_policy(wallet_policy),
            );
            let shutdown = scanner.spawn();
            bump_shutdown.push(shutdown);
            debug!("daemon.bump_scanner_spawned");
        }

        // Spawn the backends probe task. Every 60s it:
        //   * refreshes `status/backends/mempool` from the live handler state
        //   * calls `health()` on each registered private RPC and writes the
        //     result into `status/backends/private_rpc`.
        let mut probe_shutdown: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();
        let probe_needed = !mempool_handlers.is_empty() || !private_rpc_probes.is_empty();
        if probe_needed && tokio::runtime::Handle::try_current().is_ok() {
            let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
            probe_shutdown.push(tx);
            let status_for_probe = status_handler.clone();
            let mempool_handlers_for_probe = mempool_handlers.clone();
            let probes = private_rpc_probes.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(60));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                // `tokio::time::interval` fires its first `tick()` immediately;
                // consume that initial tick here so the loop body's "do work
                // then await tick" structure doesn't double-fire at boot
                // (probe → immediate-tick-returns → probe again).
                // The first iteration of the loop below still runs the probe
                // at boot — we just don't queue an immediate second pass.
                ticker.tick().await;
                loop {
                    // Refresh mempool snapshot from handler state.
                    let mut mempool_map: std::collections::BTreeMap<String, MempoolBackendStatus> =
                        std::collections::BTreeMap::new();
                    for (chain_name, h) in &mempool_handlers_for_probe {
                        mempool_map.insert(
                            chain_name.clone(),
                            MempoolBackendStatus {
                                provider: h.provider_id().to_string(),
                                subscribed: h.is_subscribed(),
                                fallback_to: None,
                            },
                        );
                    }
                    status_for_probe.replace_mempool_statuses(mempool_map);

                    // Probe private RPC health.
                    let mut health_map: std::collections::BTreeMap<
                        (String, String),
                        PrivateRpcBackendStatus,
                    > = std::collections::BTreeMap::new();
                    for (chain, provider) in &probes {
                        let probed_at = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let status = match provider.health().await {
                            Ok(bloom_mempool::HealthStatus::Healthy) => "healthy".to_string(),
                            Ok(bloom_mempool::HealthStatus::Degraded) => "degraded".to_string(),
                            Ok(bloom_mempool::HealthStatus::Unhealthy) => "unhealthy".to_string(),
                            Err(_) => "unhealthy".to_string(),
                        };
                        health_map.insert(
                            (chain.clone(), provider.id().to_string()),
                            PrivateRpcBackendStatus {
                                last_status: status,
                                last_probed_at: probed_at,
                            },
                        );
                    }
                    status_for_probe.replace_private_rpc_healths(health_map);

                    tokio::select! {
                        _ = &mut rx => return,
                        _ = ticker.tick() => {}
                    }
                }
            });
            debug!("daemon.backends_probe_spawned");
        }

        info!(
            home = %home.root().display(),
            chains = ?config.chains.keys().collect::<Vec<_>>(),
            etherscan = etherscan_arc.is_some(),
            enso = config.enso.is_some(),
            ens_resolver = ens_client.is_some(),
            heimdall = cfg!(feature = "bytecode-decompile"),
            block_mainnet_broadcast = config.block_mainnet_broadcast,
            "daemon.built"
        );

        Ok(Self {
            home,
            config,
            chains,
            keystore,
            tx_engine,
            address_book: address_book_arc,
            audit: audit_arc,
            vfs,
            watch_registry,
            watch_executor,
            mempool_shutdown: Arc::new(parking_lot::Mutex::new(mempool_shutdown)),
            bump_shutdown: Arc::new(parking_lot::Mutex::new(bump_shutdown)),
            probe_shutdown: Arc::new(parking_lot::Mutex::new(probe_shutdown)),
        })
    }

    /// Idempotent: ensure background workers are running. Already
    /// invoked by [`from_home`] when a tokio runtime is available; call
    /// this after entering an async context if construction happened
    /// outside one.
    pub fn start_workers(&self) {
        if let Err(e) = self.watch_executor.start() {
            warn!(error = %e, "watch.executor.start_failed");
        }
    }

    /// Stop background workers cleanly. Signals all spawned mempool
    /// subscription tasks, the bump scanner, and the backends probe,
    /// then shuts down the watch executor's polling task. Safe to call
    /// multiple times.
    pub async fn shutdown(&self) {
        for s in self.mempool_shutdown.lock().drain(..) {
            let _ = s.send(());
        }
        for s in self.bump_shutdown.lock().drain(..) {
            let _ = s.send(());
        }
        for s in self.probe_shutdown.lock().drain(..) {
            let _ = s.send(());
        }
        self.watch_executor.stop().await;
    }

    /// Convenience for the default home dir (`~/.bloom`).
    pub fn from_default_home() -> Result<Self, DaemonError> {
        let home = HomeDir::resolve("~/.bloom")?;
        Self::from_home(home)
    }

    /// Spawn long-lived background tasks: currently the outbox expiry
    /// sweeper that runs every 60s and moves any pending entry past its
    /// `expires_ms` into `failed/` (fix #3). Caller keeps the returned
    /// [`BackgroundTasks`] alive; dropping it triggers graceful shutdown.
    ///
    /// Safe to call multiple times — each call spawns a fresh task and
    /// returns its own handle. Short-lived CLI commands generally don't
    /// need this; it's primarily for `bloom serve` and the in-process
    /// daemon used by integration tests.
    pub fn spawn_background_tasks(&self) -> BackgroundTasks {
        let outbox = self.tx_engine.outbox.clone();
        let (tx, mut rx) = watch::channel(false);
        let interval = Duration::from_secs(60);
        let handle = tokio::spawn(async move {
            // Tick at `interval`, but exit promptly when the cancel
            // channel flips. We use `tokio::select!` so a long sleep
            // doesn't delay shutdown.
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0);
                        match outbox.sweep_expired(now_ms) {
                            Ok(0) => tracing::trace!("outbox.sweep_expired.empty"),
                            Ok(n) => info!(swept = n, "outbox.sweep_expired"),
                            Err(e) => warn!(error = %e, "outbox.sweep_expired_failed"),
                        }
                    }
                    _ = rx.changed() => {
                        if *rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        BackgroundTasks {
            cancel: tx,
            handle: Some(handle),
        }
    }

    /// Mount this daemon's [`Vfs`] over NFS at `path`.
    ///
    /// Only available with `--features mount` on this crate (which in
    /// turn enables `bloom-mount/mount`). Requires that `path` exists
    /// and is an empty directory; the platform mount command is
    /// invoked synchronously, so on Linux the kernel NFS client must
    /// be available (`nfs-common` package).
    ///
    /// Returns a handle whose `unmount` runs the platform `umount`
    /// command and aborts the embedded server. Drop also triggers a
    /// best-effort cleanup so a panicked test doesn't leak a mount.
    #[cfg(feature = "mount")]
    pub async fn mount(
        &self,
        path: &std::path::Path,
    ) -> Result<bloom_mount::NfsMountHandle, bloom_mount::MountError> {
        bloom_mount::serve_nfs(self.vfs.clone(), path).await
    }
}

/// Handle to background tasks owned by a running [`Daemon`]. Drop to
/// signal shutdown; the spawned tasks read the watch and exit at the
/// next tick. Holding this past daemon lifetime keeps the sweeper alive.
pub struct BackgroundTasks {
    cancel: watch::Sender<bool>,
    handle: Option<JoinHandle<()>>,
}

impl BackgroundTasks {
    /// Trigger graceful shutdown and wait for the sweeper task to exit.
    pub async fn shutdown(mut self) {
        let _ = self.cancel.send(true);
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        // Best-effort fire-and-forget cancel. If the runtime is still up
        // the task will see the flip and exit; if the runtime is being
        // torn down, abort the join handle to avoid a leak.
        let _ = self.cancel.send(true);
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

/// Pick an ENS-capable chain client from the registry. Prefers chain id 1
/// (mainnet); falls back to Sepolia / Goerli / Holesky.
/// Adapter that reads the current basefee for a chain via the
/// registered RPC pool. Used by the bump scanner's stuck-tx trigger.
struct ChainBasefeeProvider {
    chains: ChainRegistry,
}

#[async_trait::async_trait]
impl bloom_tx::bump_scanner::BasefeeProvider for ChainBasefeeProvider {
    async fn basefee_wei(&self, chain: &str) -> Option<u128> {
        let client = self.chains.get(chain)?;
        let fh = client.fee_history(1).await.ok()?;
        fh.base_fee_per_gas.last().copied()
    }
}

fn pick_ens_client(chains: &ChainRegistry) -> Option<EnsClient> {
    for name in chains.list_names() {
        let Some(c) = chains.get(&name) else {
            continue;
        };
        let id = c.spec().chain_id;
        if matches!(id, 1 | 5 | 11155111 | 17000) {
            debug!(chain = %name, chain_id = id, "ens.picker.matched");
            return Some(EnsClient::mainnet(c));
        }
    }
    debug!("ens.picker.no_match: no chain with id 1/5/11155111/17000 configured");
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_vfs::VfsPath;
    use bloom_vfs::handler::Handler;

    #[test]
    fn builds_from_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let home = HomeDir::at(dir.path());
        let d = Daemon::from_home(home).unwrap();
        assert!(!d.config.chains.is_empty());
        assert!(d.vfs.handler("tools").is_some());
        assert!(d.vfs.handler("wallets").is_some());
        assert!(d.vfs.handler("chains").is_some());
        assert!(d.vfs.handler("simulate").is_some());
        assert!(d.vfs.handler("watch").is_some());
        assert!(d.vfs.handler("prices").is_some());
        assert!(d.vfs.handler("addressbook").is_some());
        assert!(d.vfs.handler("ens").is_some());
    }

    /// A pre-existing watch spec on disk should be loaded into the
    /// registry and the executor should start polling it on boot. We
    /// register an event-style spec (which keys off block number) and
    /// rely on the executor's tick loop creating the per-watch directory
    /// — the easiest deterministic signal in a no-network test. We
    /// can't actually hit RPC here, so we verify the executor is
    /// running and the registry exposes the seeded spec; the live-file
    /// content path is exercised in `crates/bloom-watch/tests/`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watch_executor_starts_with_preexisting_spec() {
        use bloom_watch::{WatchKind, WatchSpec};
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let home = HomeDir::at(dir.path());
        home.ensure().unwrap();

        // Seed a spec on disk *before* daemon construction.
        let registry = Arc::new(WatchRegistry::new(home.watch_dir()).unwrap());
        registry
            .add(WatchSpec {
                id: "w-0001".into(),
                wallet: "alice".into(),
                created_ms: 1,
                kind: WatchKind::Block {
                    chain: "anvil".into(),
                },
                note: None,
            })
            .unwrap();
        drop(registry);

        let d = Daemon::from_home(home.clone()).unwrap();
        // The handler picks up specs scanned at registry construction time.
        let entries = d
            .vfs
            .list(&VfsPath::parse("/watch").unwrap())
            .await
            .unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"w-0001"),
            "expected pre-seeded spec to appear: {names:?}"
        );

        // Drive a tick directly to prove the executor's loop logic is
        // wired (the auto-spawned task may not hit RPC in this offline
        // test environment, but tick_once fails silently on missing
        // chain). After the tick the executor should still be running;
        // shutdown should stop it cleanly.
        let mut state = bloom_watch::executor::ExecutorState::default();
        let _ = d.watch_executor.tick_once(&mut state).await;
        // shutdown is idempotent and should complete promptly.
        tokio::time::timeout(Duration::from_secs(2), d.shutdown())
            .await
            .expect("shutdown timed out");
    }

    #[test]
    fn daemon_boots_without_mempool_config() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = HomeDir::at(tmp.path());
        let daemon = Daemon::from_home(home).expect("daemon boots");
        assert!(daemon.config.mempool.is_empty());
        assert!(daemon.config.private_rpc.is_empty());
    }

    #[tokio::test]
    async fn daemon_skips_mempool_for_unknown_chain() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = HomeDir::at(tmp.path());
        home.ensure().unwrap();
        // Write a config with a mempool entry pointing at a chain not in [chains.*]
        let config_toml = r#"
default_chain = "ethereum"
[chains.ethereum]
name = "ethereum"
chain_id = 1
rpc_urls = ["http://127.0.0.1:8545"]
native_symbol = "ETH"
native_decimals = 18

[mempool.bogus_chain]
provider = "alchemy"
ws_url = "wss://example.invalid"
"#;
        std::fs::write(home.config_path(), config_toml).unwrap();
        // The chain has no real RPC; daemon still boots because chain
        // creation is best-effort (see existing chain_skipped path).
        let daemon = Daemon::from_home(home).expect("daemon boots");
        // Confirm the config was actually parsed with the bogus_chain entry
        // (so we know the skip path was exercised, not just absent).
        assert!(
            daemon.config.mempool.contains_key("bogus_chain"),
            "expected bogus_chain in parsed config"
        );
        // No mempool shutdown handle: the bogus chain was skipped because
        // it doesn't appear in [chains.*].
        assert!(daemon.mempool_shutdown.lock().is_empty());
    }

    /// Boots a daemon with one valid mempool chain and verifies that the
    /// bump scanner and backends probe tasks were both spawned (their
    /// shutdown senders are non-empty), and that the StatusHandler's
    /// `status/backends/mempool` reads back a non-empty snapshot.
    #[tokio::test]
    async fn daemon_wires_bump_scanner_and_backends_probe_for_mempool_chain() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = HomeDir::at(tmp.path());
        home.ensure().unwrap();
        let config_toml = r#"
default_chain = "ethereum"
[chains.ethereum]
name = "ethereum"
chain_id = 1
rpc_urls = ["http://127.0.0.1:8545"]
native_symbol = "ETH"
native_decimals = 18

[mempool.ethereum]
provider = "alchemy"
ws_url = "wss://example.invalid"
"#;
        std::fs::write(home.config_path(), config_toml).unwrap();
        let daemon = Daemon::from_home(home).expect("daemon boots");

        assert!(
            !daemon.bump_shutdown.lock().is_empty(),
            "bump scanner should be spawned when at least one mempool chain is configured"
        );
        assert!(
            !daemon.probe_shutdown.lock().is_empty(),
            "backends probe should be spawned when at least one mempool chain is configured"
        );

        let path = bloom_vfs::VfsPath::parse("status/backends/mempool").unwrap();
        let body = daemon
            .vfs
            .read(&path)
            .await
            .expect("status/backends/mempool readable");
        let s = std::str::from_utf8(&body).unwrap();
        assert!(
            s.contains("ethereum") && s.contains("alchemy"),
            "expected mempool snapshot to mention ethereum + alchemy; got: {s}"
        );

        tokio::time::timeout(Duration::from_secs(2), daemon.shutdown())
            .await
            .expect("shutdown timed out");
    }

    /// Fix #3: the spawned sweeper drops expired pending entries into
    /// `failed/` on its own. We don't wait for the natural 60s tick;
    /// instead the test calls `outbox.sweep_expired` itself to keep
    /// runtime short, but verifies that `spawn_background_tasks` returns
    /// a guard that cleans up cleanly when shut down.
    #[tokio::test]
    async fn sweep_background_task_handles_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let home = HomeDir::at(dir.path());
        let d = Daemon::from_home(home).unwrap();
        let tasks = d.spawn_background_tasks();
        // Seed an already-expired pending entry; the foreground call
        // exercises the same code the spawned task runs.
        let staged = bloom_proto::StagedTx {
            id: "0001-test".into(),
            wallet: "alice".into(),
            chain: "anvil".into(),
            chain_id: 31337,
            from: "0x0000000000000000000000000000000000000001".into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            value_wei: "0".into(),
            data_hex: "0x".into(),
            gas_limit: 21000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas_price: None,
            nonce: 0,
            policy_checks: vec![],
            created_ms: 0,
            expires_ms: 1,
            status: bloom_proto::TxStatus::Pending,
            tx_hash: None,
            token: None,
            nft: None,
            usd_value: None,
        };
        d.tx_engine.outbox.write_pending(&staged, "p").unwrap();
        let n = d.tx_engine.outbox.sweep_expired(2).unwrap();
        assert_eq!(n, 1);

        // Shutdown completes promptly.
        tokio::time::timeout(std::time::Duration::from_secs(2), tasks.shutdown())
            .await
            .expect("background task did not honour shutdown signal");
    }
}
