//! Daemon configuration loaded from `~/.bloom/config.toml`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::chain::ChainSpec;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("toml serialise error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default mount path (informational; the kernel mount is opt-in).
    #[serde(default = "default_mount_path")]
    pub mount_path: String,
    /// Address the NFS server listens on. Loopback only by default.
    #[serde(default = "default_nfs_listen")]
    pub nfs_listen_addr: String,
    /// Default wallet used when a request/command omits an explicit wallet.
    #[serde(default)]
    pub default_wallet: Option<String>,
    /// Default chain to use when an intent omits `chain`.
    #[serde(default = "default_chain_name")]
    pub default_chain: String,
    /// Outbox stage TTL.
    #[serde(default = "default_stage_ttl", with = "humantime_serde")]
    pub stage_ttl: std::time::Duration,
    /// Map of chain name -> spec.
    #[serde(default)]
    pub chains: BTreeMap<String, ChainSpec>,
    #[serde(default)]
    pub etherscan: Option<EtherscanConfig>,
    #[serde(default)]
    pub enso: Option<EnsoConfig>,
    /// Polymarket read surface. Presence of `[polymarket]` opts the
    /// `polymarket/` VFS subtree in (like `[enso]` opts in `defi/`).
    #[serde(default)]
    pub polymarket: Option<PolymarketConfig>,
    /// Trusted, daemon-owned runtime settings for installed Petals.
    /// Endpoint overrides are matched to named manifest bindings and may only
    /// replace the HTTPS authority; the signed method/path policy remains the
    /// upper bound.
    #[serde(default)]
    pub petals: PetalsConfig,
    /// Hyperliquid HyperCore read/write surface. Presence of `[hyperliquid]`
    /// opts the `hyperliquid/` VFS subtree in.
    #[serde(default)]
    pub hyperliquid: Option<HyperliquidConfig>,
    #[serde(default)]
    pub mempool: BTreeMap<String, MempoolChainConfig>,
    #[serde(default)]
    pub private_rpc: BTreeMap<String, PrivateRpcChainConfig>,
    /// Kill-switch: never permit broadcast to mainnet chain ids regardless
    /// of per-chain `allow_broadcast`.
    #[serde(default = "default_mainnet_block")]
    pub block_mainnet_broadcast: bool,
    /// Per-feature backend selection. Makes the data-source boundary
    /// between Etherscan, raw RPC, and a future embedded indexer
    /// explicit. Defaults match the historical behaviour: Etherscan for
    /// metadata + history, RPC for everything else.
    #[serde(default)]
    pub backends: BackendsConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PetalsConfig {
    #[serde(default)]
    pub runtime: BTreeMap<String, PetalRuntimeConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PetalRuntimeConfig {
    #[serde(default)]
    pub endpoints: BTreeMap<String, String>,
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

/// Where a given feature sources its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// Etherscan multichain API. Requires an `[etherscan]` block.
    Etherscan,
    /// Raw JSON-RPC against the configured chain endpoints.
    Rpc,
    /// Embedded local block/log indexer. Not yet implemented; selecting
    /// this surfaces a clear "not yet available" error at read time.
    Indexer,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Etherscan => "etherscan",
            Backend::Rpc => "rpc",
            Backend::Indexer => "indexer",
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Declares which backend serves each feature surface. The defaults
/// preserve historical behaviour: contract metadata and address history
/// come from Etherscan; everything else is RPC-native.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BackendsConfig {
    /// `chains/<c>/contracts/<a>/{source,abi}` and the ABI feed used by
    /// the contract methods/events surfaces.
    #[serde(default = "default_contract_metadata_backend")]
    pub contract_metadata: Backend,
    /// `chains/<c>/addresses/<a>/{txs,internal_txs,erc20_txs,erc721_txs}`.
    #[serde(default = "default_address_history_backend")]
    pub address_history: Backend,
    /// `chains/<c>/contracts/<a>/events/<name>/{recent,query,live}`.
    #[serde(default = "default_event_logs_backend")]
    pub event_logs: Backend,
    /// `chains/<c>/contracts/<a>/storage/<slot>` (eth_getStorageAt).
    #[serde(default = "default_storage_reads_backend")]
    pub storage_reads: Backend,
    /// `chains/<c>/contracts/<a>/proxy/{implementation,admin,beacon}`
    /// (well-known EIP-1967 / EIP-1822 / beacon slot reads).
    #[serde(default = "default_proxy_detection_backend")]
    pub proxy_detection: Backend,
}

impl Default for BackendsConfig {
    fn default() -> Self {
        Self {
            contract_metadata: default_contract_metadata_backend(),
            address_history: default_address_history_backend(),
            event_logs: default_event_logs_backend(),
            storage_reads: default_storage_reads_backend(),
            proxy_detection: default_proxy_detection_backend(),
        }
    }
}

impl BackendsConfig {
    /// Iterate over (feature_name, backend) pairs. Order is stable; used
    /// to render `status/backends/*` and `summary.json`.
    pub fn entries(&self) -> [(&'static str, Backend); 5] {
        [
            ("contract_metadata", self.contract_metadata),
            ("address_history", self.address_history),
            ("event_logs", self.event_logs),
            ("storage_reads", self.storage_reads),
            ("proxy_detection", self.proxy_detection),
        ]
    }

    pub fn get(&self, feature: &str) -> Option<Backend> {
        self.entries()
            .into_iter()
            .find(|(name, _)| *name == feature)
            .map(|(_, b)| b)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherscanConfig {
    /// Etherscan multi-chain API key.
    pub api_key: String,
    #[serde(default = "default_etherscan_url")]
    pub api_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsoConfig {
    pub api_key: String,
    #[serde(default = "default_enso_url")]
    pub api_url: String,
}

/// Polymarket client configuration. Every field has a default so a bare
/// `[polymarket]` TOML table parses to the public-endpoint defaults on Polygon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolymarketConfig {
    #[serde(default = "default_gamma_url")]
    pub gamma_url: String,
    #[serde(default = "default_data_url")]
    pub data_url: String,
    #[serde(default = "default_clob_url")]
    pub clob_url: String,
    /// Relayer for gasless deposit-wallet deploys/batches (onboarding).
    #[serde(default = "default_relayer_url")]
    pub relayer_url: String,
    /// Settlement chain id (Polygon mainnet by default).
    #[serde(default = "default_polymarket_chain_id")]
    pub chain_id: u64,
    /// Optional builder code for order attribution (unused by the read surface).
    #[serde(default)]
    pub builder_code: Option<String>,
    /// Manual relayer API key + the address that owns it — sent as
    /// `RELAYER_API_KEY` / `RELAYER_API_KEY_ADDRESS` headers on relayer calls.
    /// Create one at `polymarket.com/settings?tab=api-keys`. Optional advanced
    /// override: the default path auto-creates a **builder API key** instead
    /// (see `builder_key_mode`). When set, it takes precedence over the
    /// builder key.
    #[serde(default)]
    pub relayer_api_key: Option<String>,
    #[serde(default)]
    pub relayer_api_key_address: Option<String>,
    /// How the relayer credential is obtained for the (default) deposit-wallet
    /// trading mode:
    /// - `"auto"` (default): bloom creates a **builder API key** from the
    ///   wallet's CLOB credentials (`POST /auth/builder-api-key`) and uses it
    ///   for relayer submission auth. Disclosed during onboarding; revocable
    ///   with `bloom polymarket builder-keys revoke`. Submission auth only —
    ///   it never holds wallet authority.
    /// - `"manual"`: only the `relayer_api_key`/`relayer_api_key_address`
    ///   pair is used; refuse with setup instructions when absent.
    /// - `"disabled"`: never create or use relayer auth automatically;
    ///   deposit-wallet trading is unavailable.
    #[serde(default = "default_builder_key_mode")]
    pub builder_key_mode: String,
    /// Explicit opt-in to the legacy EOA onboarding mode (signatureType 0).
    /// The CLOB rejects EOA makers at order placement ("maker address not
    /// allowed"), so this mode cannot trade — it exists for read/creds-only
    /// setups and backward compatibility.
    #[serde(default)]
    pub legacy_eoa_mode: bool,
}

fn default_builder_key_mode() -> String {
    "auto".into()
}

/// Hyperliquid HyperCore API configuration. Every field has a default so a
/// bare `[hyperliquid]` TOML table uses the official public endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperliquidConfig {
    #[serde(default = "default_hyperliquid_mainnet_url")]
    pub mainnet_url: String,
    #[serde(default = "default_hyperliquid_testnet_url")]
    pub testnet_url: String,
    /// Bridge2 contract that credits deposits (native USDC on Arbitrum).
    /// Defaults to the mainnet bridge; not a magic literal in the route code.
    #[serde(default = "default_hyperliquid_bridge")]
    pub bridge_address: String,
    /// Chain whose native USDC the bridge credits (Arbitrum One).
    #[serde(default = "default_hyperliquid_deposit_chain_id")]
    pub deposit_chain_id: u64,
}

impl Default for HyperliquidConfig {
    fn default() -> Self {
        Self {
            mainnet_url: default_hyperliquid_mainnet_url(),
            testnet_url: default_hyperliquid_testnet_url(),
            bridge_address: default_hyperliquid_bridge(),
            deposit_chain_id: default_hyperliquid_deposit_chain_id(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MempoolChainConfig {
    /// Provider id — must match a `bloom_mempool::providers::*` adapter
    /// id: `"alchemy"` or `"generic_eth_subscribe"`.
    pub provider: String,
    pub ws_url: String,
    #[serde(default = "default_max_index_size")]
    pub max_index_size: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrivateRpcChainConfig {
    #[serde(default)]
    pub mev_blocker_url: Option<String>,
    #[serde(default)]
    pub flashbots_url: Option<String>,
}

fn default_mount_path() -> String {
    "/bloom".to_string()
}
fn default_nfs_listen() -> String {
    "127.0.0.1:12049".to_string()
}
fn default_chain_name() -> String {
    "ethereum".to_string()
}
fn default_stage_ttl() -> std::time::Duration {
    std::time::Duration::from_secs(3600)
}
fn default_etherscan_url() -> String {
    "https://api.etherscan.io/v2/api".to_string()
}
fn default_enso_url() -> String {
    "https://api.enso.finance".to_string()
}
fn default_gamma_url() -> String {
    "https://gamma-api.polymarket.com".to_string()
}
fn default_data_url() -> String {
    "https://data-api.polymarket.com".to_string()
}
fn default_clob_url() -> String {
    "https://clob.polymarket.com".to_string()
}
fn default_relayer_url() -> String {
    "https://relayer-v2.polymarket.com".to_string()
}
fn default_hyperliquid_mainnet_url() -> String {
    "https://api.hyperliquid.xyz".to_string()
}
fn default_hyperliquid_testnet_url() -> String {
    "https://api.hyperliquid-testnet.xyz".to_string()
}
fn default_hyperliquid_bridge() -> String {
    crate::hyperliquid::MAINNET_BRIDGE.to_string()
}
fn default_hyperliquid_deposit_chain_id() -> u64 {
    crate::hyperliquid::DEPOSIT_CHAIN_ID
}
fn default_polymarket_chain_id() -> u64 {
    137
}
fn default_mainnet_block() -> bool {
    true
}
fn default_max_index_size() -> usize {
    50_000
}
fn default_contract_metadata_backend() -> Backend {
    Backend::Etherscan
}
fn default_address_history_backend() -> Backend {
    Backend::Etherscan
}
fn default_event_logs_backend() -> Backend {
    Backend::Rpc
}
fn default_storage_reads_backend() -> Backend {
    Backend::Rpc
}
fn default_proxy_detection_backend() -> Backend {
    Backend::Rpc
}

fn evm_chain(
    name: &str,
    chain_id: u64,
    rpc_urls: &[&str],
    display_name: &str,
    native_symbol: &str,
) -> ChainSpec {
    ChainSpec {
        name: name.to_string(),
        chain_id,
        rpc_urls: rpc_urls.iter().map(|u| (*u).to_string()).collect(),
        rpc_endpoints: Vec::new(),
        allow_broadcast: false,
        etherscan_api_url: None,
        display_name: Some(display_name.to_string()),
        native_symbol: native_symbol.to_string(),
        native_decimals: 18,
        legacy_tx: false,
    }
}

fn default_chains() -> BTreeMap<String, ChainSpec> {
    let mut chains = BTreeMap::new();
    for spec in [
        evm_chain(
            "ethereum",
            1,
            &[
                "https://ethereum-rpc.publicnode.com",
                "https://eth.llamarpc.com",
            ],
            "Ethereum Mainnet",
            "ETH",
        ),
        evm_chain(
            "base",
            8453,
            &["https://mainnet.base.org", "https://base.llamarpc.com"],
            "Base Mainnet",
            "ETH",
        ),
        evm_chain(
            "tempo",
            4217,
            &["https://rpc.tempo.xyz"],
            "Tempo Mainnet",
            "ETH",
        ),
        evm_chain(
            "arbitrum",
            42161,
            &[
                "https://arb1.arbitrum.io/rpc",
                "https://arbitrum-one-rpc.publicnode.com",
            ],
            "Arbitrum One",
            "ETH",
        ),
        evm_chain(
            "optimism",
            10,
            &[
                "https://mainnet.optimism.io",
                "https://optimism-rpc.publicnode.com",
            ],
            "OP Mainnet",
            "ETH",
        ),
        evm_chain(
            "polygon",
            137,
            &[
                "https://polygon-rpc.com",
                "https://polygon-bor-rpc.publicnode.com",
            ],
            "Polygon PoS",
            "POL",
        ),
        evm_chain(
            "bsc",
            56,
            &[
                "https://bsc-dataseed.binance.org",
                "https://bsc-rpc.publicnode.com",
            ],
            "BNB Smart Chain",
            "BNB",
        ),
        evm_chain(
            "avalanche",
            43114,
            &[
                "https://api.avax.network/ext/bc/C/rpc",
                "https://avalanche-c-chain-rpc.publicnode.com",
            ],
            "Avalanche C-Chain",
            "AVAX",
        ),
        evm_chain(
            "gnosis",
            100,
            &[
                "https://rpc.gnosischain.com",
                "https://gnosis-rpc.publicnode.com",
            ],
            "Gnosis Chain",
            "xDAI",
        ),
        evm_chain(
            "linea",
            59144,
            &[
                "https://rpc.linea.build",
                "https://linea-rpc.publicnode.com",
            ],
            "Linea",
            "ETH",
        ),
        evm_chain(
            "hyperliquid",
            999,
            &["https://rpc.hyperliquid.xyz/evm"],
            "HyperEVM",
            "HYPE",
        ),
        ChainSpec::anvil_default(),
    ] {
        chains.insert(spec.name.clone(), spec);
    }
    chains
}

impl Config {
    /// A safe agentic-wallet default: read-ready public EVM networks, Anvil,
    /// and the Hyperliquid HyperCore VFS using its official public endpoints.
    ///
    /// Live networks default to read-only (`allow_broadcast = false`) and the
    /// global mainnet broadcast kill-switch stays enabled. Users can inspect
    /// balances, contracts, ENS, prices, and stage plans immediately with zero
    /// config, then opt into live broadcasts deliberately.
    pub fn local_default() -> Self {
        let chains = default_chains();
        Config {
            mount_path: default_mount_path(),
            nfs_listen_addr: default_nfs_listen(),
            default_wallet: None,
            default_chain: default_chain_name(),
            stage_ttl: default_stage_ttl(),
            chains,
            etherscan: None,
            enso: None,
            polymarket: None,
            petals: PetalsConfig::default(),
            hyperliquid: Some(HyperliquidConfig::default()),
            mempool: BTreeMap::new(),
            private_rpc: BTreeMap::new(),
            block_mainnet_broadcast: true,
            backends: BackendsConfig::default(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let s = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, s)?;
        Ok(())
    }

    pub fn load_or_init(path: &Path) -> Result<Self, ConfigError> {
        if path.exists() {
            Self::load(path)
        } else {
            let cfg = Self::local_default();
            cfg.save(path)?;
            Ok(cfg)
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.chains.is_empty() {
            return Err(ConfigError::Invalid(
                "config.chains must contain at least one entry".into(),
            ));
        }
        if !self.chains.contains_key(&self.default_chain) {
            return Err(ConfigError::Invalid(format!(
                "default_chain={} not in chains",
                self.default_chain
            )));
        }
        if self
            .default_wallet
            .as_deref()
            .map(|w| w.trim().is_empty())
            .unwrap_or(false)
        {
            return Err(ConfigError::Invalid(
                "default_wallet must not be empty".into(),
            ));
        }
        for (k, c) in &self.chains {
            if k != &c.name {
                return Err(ConfigError::Invalid(format!(
                    "chain key '{}' != name '{}'",
                    k, c.name
                )));
            }
            if c.rpc_urls.is_empty() && c.rpc_endpoints.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "chain '{}' has no rpc_urls or rpc_endpoints",
                    k
                )));
            }
        }
        for (app_name, app) in &self.petals.runtime {
            validate_petal_runtime_name("app", app_name)?;
            for (binding, origin) in &app.endpoints {
                validate_petal_runtime_name("endpoint binding", binding)?;
                validate_petal_endpoint_origin(origin)?;
            }
            for key in app.values.keys() {
                validate_petal_runtime_name("runtime value", key)?;
            }
            match (app.values.get("chain"), app.values.get("chain_id")) {
                (Some(chain), Some(chain_id)) => {
                    let parsed = chain_id.parse::<u64>().map_err(|_| {
                        ConfigError::Invalid(format!(
                            "petals.runtime.{app_name}.values.chain_id must be a u64"
                        ))
                    })?;
                    let spec = self.chains.get(chain).ok_or_else(|| {
                        ConfigError::Invalid(format!(
                            "petals.runtime.{app_name}.values.chain={chain:?} is not configured"
                        ))
                    })?;
                    if spec.chain_id != parsed {
                        return Err(ConfigError::Invalid(format!(
                            "petals.runtime.{app_name} chain {chain:?} has id {}, not {parsed}",
                            spec.chain_id
                        )));
                    }
                }
                (None, None) => {}
                _ => {
                    return Err(ConfigError::Invalid(format!(
                        "petals.runtime.{app_name} must set values.chain and values.chain_id together"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn chain(&self, name: &str) -> Option<&ChainSpec> {
        self.chains.get(name)
    }

    /// Is this chain id one we *consider* mainnet for the kill-switch?
    pub fn is_mainnet_id(chain_id: u64) -> bool {
        matches!(
            chain_id,
            1 | 10 | 56 | 100 | 137 | 250 | 324 | 999 | 8453 | 42161 | 43114 | 59144 | 534352
        )
    }

    /// Whether broadcast is ultimately allowed on this chain.
    pub fn broadcast_permitted(&self, c: &ChainSpec) -> bool {
        if self.block_mainnet_broadcast && Self::is_mainnet_id(c.chain_id) {
            return false;
        }
        c.allow_broadcast
    }
}

fn validate_petal_runtime_name(kind: &str, name: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ConfigError::Invalid(format!(
            "petal {kind} {name:?} must contain only ASCII letters, digits, '-' or '_'"
        )));
    }
    Ok(())
}

fn validate_petal_endpoint_origin(origin: &str) -> Result<(), ConfigError> {
    let url = url::Url::parse(origin).map_err(|err| {
        ConfigError::Invalid(format!("invalid petal endpoint origin {origin:?}: {err}"))
    })?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err(ConfigError::Invalid(format!(
            "petal endpoint {origin:?} must be an HTTPS origin using the default port"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn assert_configs_equivalent(a: &Config, b: &Config) {
        // Config doesn't derive PartialEq (chains has custom inner types
        // that do). Compare via a stable serialised form.
        let sa = toml::to_string_pretty(a).unwrap();
        let sb = toml::to_string_pretty(b).unwrap();
        assert_eq!(sa, sb);
    }

    #[test]
    fn local_default_shape() {
        let cfg = Config::local_default();
        assert_eq!(cfg.default_chain, "ethereum");
        assert!(cfg.default_wallet.is_none());
        assert_eq!(cfg.mount_path, "/bloom");
        assert_eq!(cfg.nfs_listen_addr, "127.0.0.1:12049");
        assert!(cfg.block_mainnet_broadcast);
        assert!(cfg.etherscan.is_none());
        assert!(cfg.enso.is_none());
        let hyperliquid = cfg
            .hyperliquid
            .as_ref()
            .expect("Hyperliquid is enabled by default");
        assert_eq!(hyperliquid.mainnet_url, "https://api.hyperliquid.xyz");
        assert_eq!(
            hyperliquid.testnet_url,
            "https://api.hyperliquid-testnet.xyz"
        );
        assert_eq!(cfg.chains.len(), 12);
        let ethereum = cfg.chains.get("ethereum").expect("ethereum entry");
        assert_eq!(ethereum.chain_id, 1);
        assert!(!ethereum.allow_broadcast);
        assert!(!ethereum.rpc_urls.is_empty());
        let base = cfg.chains.get("base").expect("base entry");
        assert_eq!(base.chain_id, 8453);
        let tempo = cfg.chains.get("tempo").expect("tempo entry");
        assert_eq!(tempo.chain_id, 4217);
        assert_eq!(tempo.rpc_urls, vec!["https://rpc.tempo.xyz"]);
        let hyperliquid = cfg.chains.get("hyperliquid").expect("hyperliquid entry");
        assert_eq!(hyperliquid.chain_id, 999);
        let anvil = cfg.chains.get("anvil").expect("anvil entry");
        assert_eq!(anvil.chain_id, 31337);
        assert!(!anvil.rpc_urls.is_empty());
        // Default backends: metadata + history -> Etherscan, rest -> RPC.
        assert_eq!(cfg.backends.contract_metadata, Backend::Etherscan);
        assert_eq!(cfg.backends.address_history, Backend::Etherscan);
        assert_eq!(cfg.backends.event_logs, Backend::Rpc);
        assert_eq!(cfg.backends.storage_reads, Backend::Rpc);
        assert_eq!(cfg.backends.proxy_detection, Backend::Rpc);
    }

    #[test]
    fn local_default_validates() {
        Config::local_default().validate().unwrap();
    }

    #[test]
    fn petal_runtime_endpoints_and_chain_are_operator_validated() {
        let mut cfg = Config::local_default();
        cfg.petals.runtime.insert(
            "polymarket".into(),
            PetalRuntimeConfig {
                endpoints: BTreeMap::from([(
                    "clob".into(),
                    "https://clob.internal.example".into(),
                )]),
                values: BTreeMap::from([
                    ("chain".into(), "polygon".into()),
                    ("chain_id".into(), "137".into()),
                ]),
            },
        );
        cfg.validate().unwrap();

        cfg.petals
            .runtime
            .get_mut("polymarket")
            .expect("polymarket app was inserted above")
            .endpoints
            .insert(
                "clob".into(),
                "https://clob.internal.example/credential-sink".into(),
            );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn petal_runtime_names_use_the_package_name_grammar() {
        for valid in ["echo", "Echo2", "my-petal", "my_petal"] {
            validate_petal_runtime_name("app", valid).unwrap();
        }
        for invalid in ["", "foo.bar", "foo/bar", "foo\\bar", "petal💮"] {
            let err = validate_petal_runtime_name("app", invalid).unwrap_err();
            assert!(
                err.to_string()
                    .contains("must contain only ASCII letters, digits, '-' or '_'")
            );
        }
    }

    #[test]
    fn legacy_petals_apps_config_is_rejected() {
        let err = toml::from_str::<PetalsConfig>(
            r#"
[apps.demo]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `apps`"), "{err}");
    }

    #[test]
    fn toml_round_trip_default() {
        let cfg = Config::local_default();
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_configs_equivalent(&cfg, &back);
    }

    #[test]
    fn bare_polymarket_block_parses_to_public_defaults() {
        let pm: PolymarketConfig = toml::from_str("").unwrap();
        assert_eq!(pm.gamma_url, "https://gamma-api.polymarket.com");
        assert_eq!(pm.data_url, "https://data-api.polymarket.com");
        assert_eq!(pm.clob_url, "https://clob.polymarket.com");
        assert_eq!(pm.relayer_url, "https://relayer-v2.polymarket.com");
        assert_eq!(pm.chain_id, 137);
        assert!(pm.builder_code.is_none());
        // Absent relayer key → EOA path is selected downstream.
        assert!(pm.relayer_api_key.is_none() && pm.relayer_api_key_address.is_none());

        // Overrides stick and round-trip.
        let pm: PolymarketConfig =
            toml::from_str("relayer_url = \"http://localhost:1\"\nchain_id = 80002\n").unwrap();
        assert_eq!(pm.relayer_url, "http://localhost:1");
        assert_eq!(pm.chain_id, 80_002);
        let back: PolymarketConfig = toml::from_str(&toml::to_string(&pm).unwrap()).unwrap();
        assert_eq!(back.relayer_url, pm.relayer_url);

        // Relayer key present → deposit-wallet path is selected downstream.
        let pm: PolymarketConfig =
            toml::from_str("relayer_api_key = \"k-123\"\nrelayer_api_key_address = \"0xabc\"\n")
                .unwrap();
        assert_eq!(pm.relayer_api_key.as_deref(), Some("k-123"));
        assert_eq!(pm.relayer_api_key_address.as_deref(), Some("0xabc"));
    }

    #[test]
    fn bare_hyperliquid_block_parses_to_public_defaults() {
        let hl: HyperliquidConfig = toml::from_str("").unwrap();
        assert_eq!(hl.mainnet_url, "https://api.hyperliquid.xyz");
        assert_eq!(hl.testnet_url, "https://api.hyperliquid-testnet.xyz");

        let hl: HyperliquidConfig =
            toml::from_str("mainnet_url = \"http://localhost:3001\"\n").unwrap();
        assert_eq!(hl.mainnet_url, "http://localhost:3001");
        assert_eq!(hl.testnet_url, "https://api.hyperliquid-testnet.xyz");
    }

    #[test]
    fn save_and_load_round_trip() {
        let td = tempdir().unwrap();
        let path = td.path().join("nested").join("config.toml");
        let cfg = Config::local_default();
        cfg.save(&path).unwrap();
        assert!(path.exists());
        let loaded = Config::load(&path).unwrap();
        assert_configs_equivalent(&cfg, &loaded);
    }

    #[test]
    fn load_missing_file_returns_io_error() {
        let td = tempdir().unwrap();
        let path = td.path().join("does-not-exist.toml");
        let err = Config::load(&path).unwrap_err();
        match err {
            ConfigError::Io(_) => {}
            other => panic!("expected Io error for missing file, got {other:?}"),
        }
    }

    #[test]
    fn load_malformed_toml_returns_toml_error() {
        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        std::fs::write(&path, "this is not valid toml = = =").unwrap();
        let err = Config::load(&path).unwrap_err();
        match err {
            ConfigError::Toml(_) => {}
            other => panic!("expected Toml error, got {other:?}"),
        }
    }

    #[test]
    fn load_or_init_creates_default_when_missing() {
        let td = tempdir().unwrap();
        let path = td.path().join("subdir").join("config.toml");
        assert!(!path.exists());
        let cfg = Config::load_or_init(&path).unwrap();
        assert!(path.exists());
        assert_eq!(cfg.default_chain, "ethereum");
        // Second call should load, not overwrite — round-trip equivalent.
        let cfg2 = Config::load_or_init(&path).unwrap();
        assert_configs_equivalent(&cfg, &cfg2);
    }

    #[test]
    fn validate_rejects_empty_chains() {
        let mut cfg = Config::local_default();
        cfg.chains.clear();
        let err = cfg.validate().unwrap_err();
        match err {
            ConfigError::Invalid(m) => assert!(m.contains("at least one"), "msg: {m}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_default_chain_not_in_chains() {
        let mut cfg = Config::local_default();
        cfg.default_chain = "ghost".to_string();
        let err = cfg.validate().unwrap_err();
        match err {
            ConfigError::Invalid(m) => assert!(m.contains("default_chain=ghost"), "msg: {m}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn default_wallet_round_trips_and_empty_is_rejected() {
        let mut cfg = Config::local_default();
        cfg.default_wallet = Some("alice".to_string());
        let s = toml::to_string_pretty(&cfg).unwrap();
        assert!(s.contains("default_wallet = \"alice\""));
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(back.default_wallet.as_deref(), Some("alice"));

        cfg.default_wallet = Some("   ".to_string());
        let err = cfg.validate().unwrap_err();
        match err {
            ConfigError::Invalid(m) => assert!(m.contains("default_wallet"), "msg: {m}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn older_config_without_default_wallet_parses() {
        let cfg: Config = toml::from_str(
            r#"
mount_path = "/bloom"
nfs_listen_addr = "127.0.0.1:12049"
default_chain = "anvil"
stage_ttl = "30m"
block_mainnet_broadcast = true

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]
native_symbol = "ETH"
allow_broadcast = true
"#,
        )
        .unwrap();
        assert!(cfg.default_wallet.is_none());
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_key_name_mismatch() {
        let mut cfg = Config::local_default();
        let mut spec = cfg.chains.remove("anvil").unwrap();
        spec.name = "renamed".to_string();
        cfg.chains.insert("anvil".to_string(), spec);
        let err = cfg.validate().unwrap_err();
        match err {
            ConfigError::Invalid(m) => {
                assert!(m.contains("anvil") && m.contains("renamed"), "msg: {m}")
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_when_both_empty() {
        let mut cfg = Config::local_default();
        let entry = cfg.chains.get_mut("anvil").unwrap();
        entry.rpc_urls.clear();
        entry.rpc_endpoints.clear();
        let err = cfg.validate().unwrap_err();
        match err {
            ConfigError::Invalid(m) => {
                assert!(m.contains("no rpc_urls or rpc_endpoints"), "msg: {m}")
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn config_validates_with_only_endpoints() {
        // Empty `rpc_urls` is fine as long as `rpc_endpoints` carries
        // at least one entry — the new richer schema is allowed to
        // stand on its own.
        use crate::chain::EndpointSpec;
        let mut cfg = Config::local_default();
        let entry = cfg.chains.get_mut("anvil").unwrap();
        entry.rpc_urls.clear();
        entry.rpc_endpoints.push(EndpointSpec {
            url: "http://127.0.0.1:8545".into(),
            weight: 100,
            cu_per_sec: None,
            max_rps: None,
            http_only: false,
        });
        cfg.validate()
            .expect("validation passes when only endpoints present");
    }

    #[test]
    fn chain_lookup_by_name() {
        let cfg = Config::local_default();
        assert!(cfg.chain("anvil").is_some());
        assert!(cfg.chain("ethereum").is_some());
        assert!(cfg.chain("hyperliquid").is_some());
        assert!(cfg.chain("ghost").is_none());
    }

    #[test]
    fn is_mainnet_id_matches_known_ids() {
        for id in [
            1, 10, 56, 100, 137, 250, 324, 999, 8453, 42161, 43114, 59144, 534352,
        ] {
            assert!(Config::is_mainnet_id(id), "{id} should be mainnet");
        }
        assert!(!Config::is_mainnet_id(31337));
        assert!(!Config::is_mainnet_id(11155111)); // sepolia
        assert!(!Config::is_mainnet_id(0));
    }

    #[test]
    fn broadcast_permitted_blocked_on_mainnet_when_killswitch_on() {
        let cfg = Config::local_default(); // block_mainnet_broadcast = true
        let mainnet = ChainSpec {
            name: "ethereum".to_string(),
            chain_id: 1,
            rpc_urls: vec!["https://x".into()],
            rpc_endpoints: Vec::new(),
            allow_broadcast: true,
            etherscan_api_url: None,
            display_name: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            legacy_tx: false,
        };
        assert!(!cfg.broadcast_permitted(&mainnet));
    }

    #[test]
    fn broadcast_permitted_when_killswitch_off_and_chain_allows() {
        let mut cfg = Config::local_default();
        cfg.block_mainnet_broadcast = false;
        let mainnet = ChainSpec {
            name: "ethereum".to_string(),
            chain_id: 1,
            rpc_urls: vec!["https://x".into()],
            rpc_endpoints: Vec::new(),
            allow_broadcast: true,
            etherscan_api_url: None,
            display_name: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            legacy_tx: false,
        };
        assert!(cfg.broadcast_permitted(&mainnet));
    }

    #[test]
    fn broadcast_permitted_respects_chain_allow_flag_on_testnet() {
        let cfg = Config::local_default();
        let mut anvil = ChainSpec::anvil_default();
        anvil.allow_broadcast = false;
        assert!(!cfg.broadcast_permitted(&anvil));
        anvil.allow_broadcast = true;
        assert!(cfg.broadcast_permitted(&anvil));
    }

    #[test]
    fn backend_kebab_case_serde() {
        // Serde rename_all = "kebab-case" → indexer/etherscan/rpc.
        assert_eq!(
            serde_json::to_string(&Backend::Etherscan).unwrap(),
            "\"etherscan\""
        );
        assert_eq!(serde_json::to_string(&Backend::Rpc).unwrap(), "\"rpc\"");
        assert_eq!(
            serde_json::to_string(&Backend::Indexer).unwrap(),
            "\"indexer\""
        );
        assert_eq!(Backend::Etherscan.as_str(), "etherscan");
        assert_eq!(Backend::Etherscan.to_string(), "etherscan");
        let b: Backend = serde_json::from_str("\"rpc\"").unwrap();
        assert_eq!(b, Backend::Rpc);
    }

    #[test]
    fn backends_config_entries_and_get() {
        let b = BackendsConfig::default();
        let entries = b.entries();
        let names: Vec<&'static str> = entries.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec![
                "contract_metadata",
                "address_history",
                "event_logs",
                "storage_reads",
                "proxy_detection",
            ]
        );
        assert_eq!(b.get("event_logs"), Some(Backend::Rpc));
        assert_eq!(b.get("contract_metadata"), Some(Backend::Etherscan));
        assert_eq!(b.get("does_not_exist"), None);
    }

    #[test]
    fn parses_explicit_per_feature_backend_overrides() {
        let toml_text = r#"
default_chain = "anvil"

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]
allow_broadcast = true

[backends]
contract_metadata = "rpc"
address_history = "indexer"
event_logs = "etherscan"
storage_reads = "indexer"
proxy_detection = "etherscan"
"#;
        let cfg: Config = toml::from_str(toml_text).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.backends.contract_metadata, Backend::Rpc);
        assert_eq!(cfg.backends.address_history, Backend::Indexer);
        assert_eq!(cfg.backends.event_logs, Backend::Etherscan);
        assert_eq!(cfg.backends.storage_reads, Backend::Indexer);
        assert_eq!(cfg.backends.proxy_detection, Backend::Etherscan);
    }

    #[test]
    fn missing_backends_block_uses_defaults() {
        let toml_text = r#"
default_chain = "anvil"

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]
"#;
        let cfg: Config = toml::from_str(toml_text).unwrap();
        assert_eq!(cfg.backends.contract_metadata, Backend::Etherscan);
        assert_eq!(cfg.backends.event_logs, Backend::Rpc);
    }

    #[test]
    fn etherscan_and_enso_blocks_parse() {
        let toml_text = r#"
default_chain = "anvil"

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]

[etherscan]
api_key = "ESKEY"

[enso]
api_key = "ENKEY"
"#;
        let cfg: Config = toml::from_str(toml_text).unwrap();
        let es = cfg.etherscan.expect("etherscan parsed");
        assert_eq!(es.api_key, "ESKEY");
        assert_eq!(es.api_url, "https://api.etherscan.io/v2/api");
        let en = cfg.enso.expect("enso parsed");
        assert_eq!(en.api_key, "ENKEY");
        assert_eq!(en.api_url, "https://api.enso.finance");
    }

    #[test]
    fn mempool_chain_config_round_trips_through_toml() {
        let mut cfg = Config::local_default();
        cfg.mempool.insert(
            "ethereum".to_string(),
            MempoolChainConfig {
                provider: "alchemy".into(),
                ws_url: "wss://eth-mainnet.example/v2/key".into(),
                max_index_size: 25_000,
            },
        );
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_configs_equivalent(&cfg, &back);
        let m = back.mempool.get("ethereum").unwrap();
        assert_eq!(m.provider, "alchemy");
        assert_eq!(m.max_index_size, 25_000);
    }

    #[test]
    fn private_rpc_chain_config_round_trips_through_toml() {
        let mut cfg = Config::local_default();
        cfg.private_rpc.insert(
            "ethereum".to_string(),
            PrivateRpcChainConfig {
                mev_blocker_url: Some("https://rpc.mevblocker.io".into()),
                flashbots_url: Some("https://rpc.flashbots.net/fast".into()),
            },
        );
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_configs_equivalent(&cfg, &back);
        let r = back.private_rpc.get("ethereum").unwrap();
        assert_eq!(
            r.mev_blocker_url.as_deref(),
            Some("https://rpc.mevblocker.io")
        );
        assert_eq!(
            r.flashbots_url.as_deref(),
            Some("https://rpc.flashbots.net/fast")
        );
    }

    #[test]
    fn mempool_max_index_size_uses_default_when_omitted() {
        let toml_src = r#"
mount_path = "/eth"
nfs_listen_addr = "127.0.0.1:12049"
default_chain = "anvil"
stage_ttl = "1h"
block_mainnet_broadcast = true

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]
allow_broadcast = true

[mempool.ethereum]
provider = "alchemy"
ws_url = "wss://example"
"#;
        let cfg: Config = toml::from_str(toml_src).unwrap();
        let m = cfg.mempool.get("ethereum").unwrap();
        assert_eq!(m.max_index_size, 50_000);
    }
}
