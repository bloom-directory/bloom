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
use bloom_chain_node::rpc::{RpcChainAdapter, RpcClient};
use bloom_chain_types::ssz::Encode;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address as ChainAddress, PubKeyBytes, SigBytes};
use bloom_defi::EnsoClient;
use bloom_ens::EnsClient;
use bloom_etherscan::EtherscanClient;
use bloom_hyperliquid::{HyperliquidClient, HyperliquidNetwork};
use bloom_keystore::Keystore;
use bloom_paid_http::PaidHttpChainRpcResolver;
use bloom_petals::{NameRegistry, PetalRunner, PetalStore, PetalVm, PetalsHandler};
use bloom_polymarket::{ClobClient, CredentialStore, DataClient, GammaClient, GeoblockClient};
use bloom_prices::PricesClient;
use bloom_proto::{AddressBook, AuditLog, ChainSpec, Config, HomeDir, HomeWritePermit};
use bloom_revert::{
    AbiSource, BuiltinDecoder, DecoderChain, EtherscanAbiDecoder, EtherscanAbiSource,
    OpenchainDecoder, boxed,
};
use bloom_script::{ChainStateIface, PqSignature, PtbTx};
use bloom_tx::outbox::Outbox;
use bloom_tx::tx_engine::TxEngine;
use bloom_vfs::handlers::polymarket::{ChainClientReader, PolymarketOnboarding, build_onboarder};
use bloom_vfs::handlers::status::{MempoolBackendStatus, PrivateRpcBackendStatus};
use bloom_vfs::handlers::{
    AddressBookHandler, ChainsHandler, DefiHandler, DocsHandler, EnsHandler, HyperliquidHandler,
    PolymarketHandler, PricesHandler, RequestsHandler, SimulateHandler, StatusHandler,
    ToolsHandler, WalletsHandler, WatchHandler,
};
use bloom_vfs::tx_handler::PtbSubmitter;
use bloom_vfs::{HandlerError, PathCache, Vfs};
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
    pub home_write_permit: Option<Arc<HomeWritePermit>>,
    pub address_book: Arc<AddressBook>,
    pub audit: Arc<AuditLog>,
    pub vfs: Vfs,
    pub petals: PetalRunner,
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
        Self::from_home_inner(home, None)
    }

    /// Build a daemon with a held home write permit. VFS write surfaces use
    /// this permit for TxEngine mutations; callers that omit it get a daemon
    /// suitable for reads/tests but not outbox writes.
    pub fn from_home_with_permit(
        home: HomeDir,
        permit: Arc<HomeWritePermit>,
    ) -> Result<Self, DaemonError> {
        Self::from_home_inner(home, Some(permit))
    }

    fn from_home_inner(
        home: HomeDir,
        home_write_permit: Option<Arc<HomeWritePermit>>,
    ) -> Result<Self, DaemonError> {
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
        let paid_http_rpc_resolver: Arc<dyn PaidHttpChainRpcResolver> =
            Arc::new(ConfigPaidHttpRpcResolver::from_config(&config));

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

        // Build the petals runtime: content-addressed store under
        // `~/.bloom/petals/store`, name registry under
        // `~/.bloom/petals/registry`, and a wasmtime engine. The handler
        // exposed at `public/` reads from both, while the runner glues
        // them together for IPC-driven install/run.
        let petals_root = home.root().join("petals");
        let petal_store = PetalStore::open(petals_root.join("store"))
            .map_err(|e| DaemonError::Audit(format!("petals store: {e}")))?;
        let petal_registry = Arc::new(
            NameRegistry::open(petals_root.join("registry"))
                .map_err(|e| DaemonError::Audit(format!("petals registry: {e}")))?,
        );
        let petal_vm = PetalVm::new().map_err(|e| DaemonError::Audit(format!("petals vm: {e}")))?;
        let petals = PetalRunner::new(petal_store.clone(), petal_registry.clone(), petal_vm);
        debug!(root = %petals_root.display(), "daemon.petals_initialised");

        let mut vfs_builder = Vfs::builder()
            .mount(
                "public",
                Arc::new(PetalsHandler::new(petal_store, petal_registry)) as _,
            )
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
            );

        let hyperliquid_handler: Option<Arc<HyperliquidHandler>> = if let Some(hl_cfg) =
            &config.hyperliquid
        {
            let hl_url = |raw: &str| match url::Url::parse(raw) {
                Ok(u) => Some(u),
                Err(e) => {
                    warn!(url = %raw, error = %e, "daemon.hyperliquid_url_invalid_using_default");
                    None
                }
            };
            let mut mainnet = HyperliquidClient::new(HyperliquidNetwork::Mainnet);
            if let Some(u) = hl_url(&hl_cfg.mainnet_url) {
                mainnet = mainnet.with_base_url(u);
            }
            let mut testnet = HyperliquidClient::new(HyperliquidNetwork::Testnet);
            if let Some(u) = hl_url(&hl_cfg.testnet_url) {
                testnet = testnet.with_base_url(u);
            }
            debug!("daemon.hyperliquid_mounted");
            let handler = Arc::new(
                HyperliquidHandler::new(mainnet, testnet, keystore.clone())
                    .with_store_root(home.root().join("hyperliquid")),
            );
            handler.clone().start_monitoring();
            Some(handler)
        } else {
            debug!("daemon.hyperliquid_skipped: no [hyperliquid] config");
            None
        };

        if let Some(ref hl) = hyperliquid_handler {
            vfs_builder = vfs_builder.mount("hyperliquid", hl.clone() as _);
        }

        vfs_builder = vfs_builder
            .mount(
                "wallets",
                Arc::new(
                    WalletsHandler::new(
                        keystore.clone(),
                        chains.clone(),
                        tx_engine.clone(),
                        address_book.clone(),
                    )
                    .with_home_write_permit_opt(home_write_permit.clone())
                    .with_mempool_indexes(mempool_indexes.clone())
                    .with_polymarket_root(home.polymarket_dir())
                    .with_hyperliquid_handler(hyperliquid_handler.clone()),
                ) as _,
            )
            .mount("tools", Arc::new(ToolsHandler::new()) as _)
            .mount(
                "requests",
                Arc::new(
                    RequestsHandler::new(
                        home.root().to_path_buf(),
                        keystore.clone(),
                        config.default_wallet.clone(),
                    )
                    .with_paid_http_rpc_resolver(paid_http_rpc_resolver.clone()),
                ) as _,
            )
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

        if let Some(chain_state) = tx_chain_state_adapter(&home) {
            let rpc_sock = home.root().join("chain").join("rpc.sock");
            let rpc_client = match std::env::var("BLOOM_RPC_TCP") {
                Ok(addr) if !addr.is_empty() => RpcClient::tcp(addr),
                _ => RpcClient::new(&rpc_sock),
            };
            let submitter = Arc::new(RpcPtbSubmitter::new(home.clone(), rpc_client));
            vfs_builder = vfs_builder.mount(
                "petals",
                Arc::new(bloom_vfs::PetalsEndpointHandler::new(chain_state.clone())) as _,
            );
            vfs_builder = vfs_builder.mount(
                "tx",
                Arc::new(bloom_vfs::TxHandler::new(chain_state).with_submitter(submitter)) as _,
            );
        } else {
            debug!("daemon.tx_skipped: no ChainStateIface adapter available");
        }

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
            // Hyperliquid deposit goal: bridge address + deposit chain, from
            // `[hyperliquid]` config when present, else the mainnet defaults.
            let (hl_bridge, hl_deposit_chain_id) = {
                let cfg = config.hyperliquid.clone().unwrap_or_default();
                let bridge = cfg.bridge_address.parse().unwrap_or_else(|_| {
                    warn!(addr = %cfg.bridge_address, "daemon.hyperliquid_bridge_invalid_using_default");
                    bloom_proto::hyperliquid::MAINNET_BRIDGE
                        .parse()
                        .expect("valid bridge const")
                });
                (bridge, cfg.deposit_chain_id)
            };
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
                    .with_home_write_permit_opt(home_write_permit.clone())
                    .with_default_chain(config.default_chain.clone())
                    .with_store_root(home.root().join("defi"))
                    .with_polymarket_root(home.polymarket_dir())
                    .with_revert_decoder(decoder_chain.clone())
                    .with_hyperliquid(hl_bridge, hl_deposit_chain_id),
                ) as _,
            );
        } else {
            debug!("daemon.defi_skipped: no [enso] config");
        }

        // Polymarket: public read surface (Gamma/Data/CLOB) plus, when a
        // `[chains]` entry matches the Polymarket chain id (Polygon 137), the
        // onboarding state machine and L2 account views. Mount whenever a
        // `[polymarket]` block exists; a bare block uses the public defaults.
        // Signing never leaves the daemon (Keystore::signer → KeystoreSigner);
        // the geoblock refuse-line is deliberately not configurable.
        if let Some(pm_cfg) = &config.polymarket {
            let pm_url = |raw: &str| match url::Url::parse(raw) {
                Ok(u) => Some(u),
                Err(e) => {
                    warn!(url = %raw, error = %e, "daemon.polymarket_url_invalid_using_default");
                    None
                }
            };
            let mut gamma = GammaClient::new();
            if let Some(u) = pm_url(&pm_cfg.gamma_url) {
                gamma = gamma.with_base_url(u);
            }
            let mut data = DataClient::new();
            if let Some(u) = pm_url(&pm_cfg.data_url) {
                data = data.with_base_url(u);
            }
            let mut clob = ClobClient::new(pm_cfg.chain_id);
            if let Some(u) = pm_url(&pm_cfg.clob_url) {
                clob = clob.with_base_url(u);
            }

            let mut handler = PolymarketHandler::new(gamma, data, clob.clone(), keystore.clone())
                .with_order_store(bloom_polymarket::OrderStore::new(home.polymarket_dir()))
                .with_fund_store(home.polymarket_dir());
            // Resolve the settlement chain by id — onboarding needs RPC reads
            // (code/balances/allowances) for its idempotency probes.
            let polygon = chains
                .list_names()
                .into_iter()
                .filter_map(|n| chains.get(&n))
                .find(|c| c.spec().chain_id == pm_cfg.chain_id);
            match polygon {
                Some(chain_client) => {
                    let state_dir = home.polymarket_dir();
                    let chain: Arc<dyn bloom_polymarket::ChainReader> =
                        Arc::new(ChainClientReader(chain_client.clone()));
                    // Factory selects the path (relayer_api_key present ⇒
                    // deposit-wallet, else EOA) and applies the configured URLs.
                    let onboarder = build_onboarder(pm_cfg, chain_client, &state_dir);
                    debug!(
                        chain_id = pm_cfg.chain_id,
                        "daemon.polymarket_onboarding_wired"
                    );
                    handler = handler
                        .with_onboarding(PolymarketOnboarding {
                            onboarder: Arc::new(onboarder),
                            geoblock: Arc::new(GeoblockClient::new()),
                            creds: CredentialStore::new(&state_dir),
                            chain,
                        })
                        .with_audit(audit_arc.clone());
                }
                None => warn!(
                    chain_id = pm_cfg.chain_id,
                    "polymarket onboarding disabled: no [chains.*] entry with this chain_id; \
                     mounting the read surface only"
                ),
            }
            debug!(chain_id = pm_cfg.chain_id, "daemon.polymarket_mounted");
            vfs_builder = vfs_builder.mount("polymarket", Arc::new(handler) as _);
        } else {
            debug!("daemon.polymarket_skipped: no [polymarket] config");
        }

        // /next.md — brutally-scoped next-action aggregator for agents.
        // Answers: what wallets need attention, what confirms are pending,
        // what capabilities are active/expired/orphaned, what risk data is stale.
        let next_keystore = keystore.clone();
        let next_tx_engine = tx_engine.clone();
        let next_hl = hyperliquid_handler.clone();
        let next_renderer: Arc<dyn Fn() -> Vec<u8> + Send + Sync> = Arc::new(move || {
            let mut md = String::from("# Next Actions\n\n");
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);

            // 1. Unsigned-policy passkey wallets
            let mut unsigned = Vec::new();
            if let Ok(infos) = next_keystore.list() {
                for info in &infos {
                    let status = next_keystore
                        .policy_status(&info.name)
                        .unwrap_or(bloom_keystore::PolicyStatus::NotApplicable);
                    if status == bloom_keystore::PolicyStatus::Unsigned
                        || status == bloom_keystore::PolicyStatus::Stale
                    {
                        unsigned.push(format!(
                            "- `{}`: policy is **{:?}** — run `bloom wallet sign-policy {}` to enable agent trading",
                            info.name, status, info.name
                        ));
                    }
                }
            }
            if !unsigned.is_empty() {
                md.push_str("## Unsigned Policies\n\n");
                for u in &unsigned {
                    md.push_str(u);
                    md.push('\n');
                }
                md.push('\n');
            }

            // 2. Pending outbox confirms
            let mut pending_confirms = Vec::new();
            if let Ok(infos) = next_keystore.list() {
                for info in &infos {
                    let sessions = next_tx_engine.session_store().active(now_ms);
                    let has_session = sessions.iter().any(|s| s.wallet == info.name);
                    if has_session {
                        for s in &sessions {
                            if s.wallet != info.name {
                                continue;
                            }
                            if s.expires_ms > now_ms {
                                pending_confirms.push(format!(
                                    "- `{}`: {} pending tx ids, session `{}` active (expires in {}s)",
                                    info.name,
                                    s.allowed_pending_ids.len(),
                                    s.id,
                                    ((s.expires_ms - now_ms) / 1000)
                                ));
                            }
                        }
                    }
                }
            }
            if !pending_confirms.is_empty() {
                md.push_str("## Pending Outbox Confirms\n\n");
                for p in &pending_confirms {
                    md.push_str(p);
                    md.push('\n');
                }
                md.push('\n');
            }

            // 3. Capability status (HL sessions)
            if let Some(ref hl) = next_hl {
                let mut expired = Vec::new();
                let mut orphaned = Vec::new();
                let mut stale = Vec::new();
                if let Ok(infos) = next_keystore.list() {
                    for info in &infos {
                        let views = hl.capability_views_for(&info.name);
                        for v in &views {
                            match v.status {
                                bloom_proto::CapabilityStatus::Expired => {
                                    expired.push(format!(
                                        "- `{}` session `{}`: **expired** — no new orders accepted",
                                        info.name, v.id
                                    ));
                                }
                                bloom_proto::CapabilityStatus::Orphaned => {
                                    orphaned.push(format!(
                                        "- `{}` session `{}`: **orphaned** — daemon lost the agent key after restart. Owner must recover via `orphan_cancel_all` or `orphan_close_all` at `{}`",
                                        info.name, v.id, v.revoke_path
                                    ));
                                }
                                bloom_proto::CapabilityStatus::Active => {
                                    if let Some(secs) = v.expires_in_secs
                                        && secs < 300
                                    {
                                        stale.push(format!(
                                            "- `{}` session `{}`: expiring in {}s",
                                            info.name, v.id, secs
                                        ));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if !expired.is_empty() {
                    md.push_str("## Expired Sessions\n\n");
                    for e in &expired {
                        md.push_str(e);
                        md.push('\n');
                    }
                    md.push('\n');
                }
                if !orphaned.is_empty() {
                    md.push_str("## Orphaned Sessions (Needs Owner)\n\n");
                    for o in &orphaned {
                        md.push_str(o);
                        md.push('\n');
                    }
                    md.push('\n');
                }
                if !stale.is_empty() {
                    md.push_str("## Expiring Soon\n\n");
                    for s in &stale {
                        md.push_str(s);
                        md.push('\n');
                    }
                    md.push('\n');
                }
            }

            if unsigned.is_empty() && pending_confirms.is_empty() && next_hl.is_none() {
                md.push_str("No wallets with pending actions.\n\n");
                md.push_str("All policies are signed, no outbox confirms await review, and no Hyperliquid sessions are active.\n");
            }
            md.into_bytes()
        });
        vfs_builder = vfs_builder.with_root_dynamic("next.md", next_renderer);

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

        // Spawn the receipt reconciler: every ~15s it walks sent/ entries and
        // records each broadcast tx's mined outcome (success/reverted) as a
        // `receipt.json` sibling. The same-chain dependency gate and the bump
        // scanner read it. Runs regardless of mempool config.
        if tokio::runtime::Handle::try_current().is_ok() {
            let reconciler = Arc::new(bloom_tx::reconcile::Reconciler::new(
                tx_engine.outbox.clone(),
                chains.clone(),
            ));
            bump_shutdown.push(reconciler.spawn());
            debug!("daemon.reconciler_spawned");
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

        // `debug!`, not `info!`: the CLI builds a daemon in-process for
        // every `vfs cat`/`ls`, so at default verbosity this line would
        // print before each value and clutter agent/visual output.
        debug!(
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
            home_write_permit,
            address_book: address_book_arc,
            audit: audit_arc,
            vfs,
            petals,
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

#[derive(Debug, Clone)]
struct ConfigPaidHttpRpcResolver {
    by_chain_id: std::collections::BTreeMap<u64, Vec<String>>,
}

impl ConfigPaidHttpRpcResolver {
    fn from_config(config: &Config) -> Self {
        let by_chain_id = config
            .chains
            .values()
            .filter_map(|spec| {
                let urls = http_rpc_urls(spec);
                (!urls.is_empty()).then_some((spec.chain_id, urls))
            })
            .collect();
        Self { by_chain_id }
    }
}

impl PaidHttpChainRpcResolver for ConfigPaidHttpRpcResolver {
    fn http_rpc_urls_for_chain_id(&self, chain_id: u64) -> Vec<String> {
        self.by_chain_id.get(&chain_id).cloned().unwrap_or_default()
    }
}

fn http_rpc_urls(spec: &ChainSpec) -> Vec<String> {
    let mut endpoints = spec.endpoints();
    endpoints.sort_by_key(|endpoint| std::cmp::Reverse(endpoint.weight));
    endpoints
        .into_iter()
        .map(|endpoint| endpoint.url)
        .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
        .collect()
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

#[derive(Clone)]
struct RpcPtbSubmitter {
    home: HomeDir,
    client: RpcClient,
}

impl RpcPtbSubmitter {
    fn new(home: HomeDir, client: RpcClient) -> Self {
        Self { home, client }
    }

    fn chain_dir(&self) -> std::path::PathBuf {
        self.home.root().join("chain")
    }

    fn load_validator_key(
        &self,
    ) -> Result<
        (
            bloom_keystore::xdsa::XdsaSecretKey,
            bloom_keystore::xdsa::XdsaPublicKey,
            ChainAddress,
        ),
        HandlerError,
    > {
        let key_path = self.chain_dir().join("keystore").join("validator.xdsa");
        let key_bytes = std::fs::read(&key_path)
            .map_err(|e| HandlerError::backend(format!("read {}: {e}", key_path.display())))?;
        let sk = bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&key_bytes)
            .map_err(|e| HandlerError::backend(format!("decode validator key: {e}")))?;
        let pk = sk.public_key();
        let sender = ChainAddress::from_pubkey_bytes(&pk.0);
        Ok((sk, pk, sender))
    }

    fn load_chain_id(&self) -> Result<String, HandlerError> {
        let path = self.chain_dir().join("genesis.toml");
        let text = std::fs::read_to_string(&path)
            .map_err(|e| HandlerError::backend(format!("read {}: {e}", path.display())))?;
        let parsed: bloom_chain_node::genesis::GenesisFile = toml::from_str(&text)
            .map_err(|e| HandlerError::backend(format!("parse {}: {e}", path.display())))?;
        Ok(parsed.chain_id)
    }

    async fn fetch_nonce(&self, sender: ChainAddress) -> Result<u64, HandlerError> {
        let value = self
            .client
            .call(
                "chain_query_account",
                serde_json::json!({ "address": hex::encode(sender.0) }),
            )
            .await
            .map_err(err_he)?;
        Ok(value.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0))
    }

    async fn poll_receipt(
        &self,
        tx_hash: bloom_chain_types::types::Hash32,
    ) -> Result<serde_json::Value, HandlerError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let value = self
                .client
                .call(
                    "chain_query_tx",
                    serde_json::json!({ "tx_hash": hex::encode(tx_hash.0) }),
                )
                .await
                .map_err(err_he)?;
            if !value.is_null() {
                return Ok(value);
            }
            if std::time::Instant::now() >= deadline {
                return Err(HandlerError::backend(format!(
                    "timed out waiting for tx {}",
                    hex::encode(tx_hash.0)
                )));
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    fn build_outer_tx(
        &self,
        sk: &bloom_keystore::xdsa::XdsaSecretKey,
        pk: &bloom_keystore::xdsa::XdsaPublicKey,
        sender: ChainAddress,
        chain_id: String,
        nonce: u64,
        ptb_bytes: Vec<u8>,
    ) -> Tx {
        let mut tx = Tx {
            chain_id,
            sender,
            nonce,
            max_fuel: 10_000_000,
            fee_per_unit: 1,
            kind: TxKind::SubmitPtb { ptb_bytes },
            pubkey: PubKeyBytes(pk.to_bytes()),
            sig: SigBytes(vec![]),
        };
        let digest = tx.signing_digest();
        let sig = sk.sign(&digest.0);
        tx.sig = SigBytes(sig.to_bytes());
        tx
    }
}

#[async_trait::async_trait]
impl PtbSubmitter for RpcPtbSubmitter {
    async fn select_gas_payer(
        &self,
        signers: &[[u8; 32]],
    ) -> Result<bloom_objects::ObjectId, HandlerError> {
        let signer = signers
            .first()
            .ok_or_else(|| HandlerError::invalid("no signers set"))?;
        bloom_chain_node::gas_select::select_loom_gas_payer_rpc(&self.client, *signer, 1_000_000)
            .await
            .map_err(|e| HandlerError::invalid(e.to_string()))
    }

    async fn submit_ptb(
        &self,
        _session_id: bloom_ptb_builder::session::SessionId,
        mut tx: PtbTx,
        _status: bloom_ptb_builder::SessionStatus,
    ) -> Result<Vec<serde_json::Value>, HandlerError> {
        let (sk, pk, sender) = self.load_validator_key()?;
        if tx.signers != vec![sender.0] {
            return Err(HandlerError::invalid(
                "tx commit can sign exactly one signer: the validator key's xDSA address",
            ));
        }
        let ptb_digest = tx.signing_digest();
        tx.signatures = vec![PqSignature(sk.sign(&ptb_digest).to_bytes())];
        let ptb_bytes = bloom_script::encode_ptb(&tx)
            .map_err(|e| HandlerError::backend(format!("encode signed PTB: {e}")))?;

        let chain_id = self.load_chain_id()?;
        let nonce = self.fetch_nonce(sender).await? + 1;
        let outer = self.build_outer_tx(&sk, &pk, sender, chain_id, nonce, ptb_bytes);
        let outer_hash = outer.tx_hash();
        self.client
            .call(
                "chain_submit_tx",
                serde_json::json!({ "tx_hex": hex::encode(outer.as_ssz_bytes()) }),
            )
            .await
            .map_err(err_he)?;
        let receipt = self.poll_receipt(outer_hash).await?;
        Ok(vec![
            serde_json::json!({
                "kind": "submit",
                "tx_hash": format!("0x{}", hex::encode(outer_hash.0)),
            }),
            serde_json::json!({
                "kind": "receipt",
                "tx_hash": format!("0x{}", hex::encode(outer_hash.0)),
                "receipt": receipt,
            }),
        ])
    }
}

fn err_he(e: impl std::fmt::Display) -> HandlerError {
    HandlerError::backend(e.to_string())
}

/// Integration seam for the tx-session VFS front door.
///
/// `bloom_vfs::TxHandler` needs the petal/PTB read model exposed as
/// `ChainStateIface`. The authoritative sovereign-chain `State` lives in the
/// validator, so the daemon mounts `tx/` through the chain JSON-RPC read model.
fn tx_chain_state_adapter(home: &HomeDir) -> Option<Arc<dyn ChainStateIface + Send + Sync>> {
    let rpc_sock = home.root().join("chain").join("rpc.sock");
    Some(Arc::new(RpcChainAdapter::from_env_or_socket(&rpc_sock)))
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
        assert!(d.vfs.handler("public").is_some());
        assert!(d.vfs.handler("petals").is_some());
    }

    #[test]
    fn tx_front_door_mounts_chain_rpc_adapter() {
        let dir = tempfile::tempdir().unwrap();
        let home = HomeDir::at(dir.path());
        let d = Daemon::from_home(home).unwrap();
        assert!(tx_chain_state_adapter(&d.home).is_some());
        assert!(d.vfs.handler("tx").is_some());
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
            depends_on: None,
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
