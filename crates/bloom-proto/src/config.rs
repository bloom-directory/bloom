//! Daemon configuration loaded from `~/.bloom/config.toml`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::chain::ChainSpec;
use crate::chain::SolanaSpec;

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
    /// How long mounted wallet reads reuse one Broker projection refresh.
    /// Each refresh costs several Broker requests per wallet, so a shorter
    /// window spends Broker's request quota faster. Mounted wallet files may
    /// be this stale; authority always comes from Broker.
    #[serde(
        default = "default_wallet_projection_max_age",
        with = "humantime_serde"
    )]
    pub wallet_projection_max_age: std::time::Duration,
    /// Where an earlier build kept `main`'s persona. Read so such a home
    /// still loads, and moved to `main`'s [`WalletSetup`] on load; never
    /// written.
    #[serde(
        default,
        skip_serializing,
        rename = "persona",
        deserialize_with = "lenient_persona"
    )]
    legacy_persona: Option<crate::persona::PersonaConfig>,
    /// Map of chain name -> spec.
    #[serde(default)]
    pub chains: BTreeMap<String, ChainSpec>,
    /// Map of Solana chain name -> spec.
    #[serde(default)]
    pub solana_chains: BTreeMap<String, SolanaSpec>,
    #[serde(default)]
    pub etherscan: Option<EtherscanConfig>,
    /// Trusted, daemon-owned runtime settings for installed Petals.
    /// Endpoint overrides are matched to named manifest bindings and may only
    /// replace the HTTPS authority; the signed method/path policy remains the
    /// upper bound.
    #[serde(default)]
    pub petals: PetalsConfig,
    /// What `bloom init` setup chose.
    #[serde(default, skip_serializing_if = "SetupConfig::is_empty")]
    pub setup: SetupConfig,
    #[serde(default)]
    pub mempool: BTreeMap<String, MempoolChainConfig>,
    #[serde(default)]
    pub private_rpc: BTreeMap<String, PrivateRpcChainConfig>,
    /// Per-feature backend selection. Makes the data-source boundary
    /// between Etherscan, raw RPC, and a future embedded indexer
    /// explicit. Defaults use Etherscan for indexed data and RPC for live
    /// reads.
    #[serde(default)]
    pub backends: BackendsConfig,
    /// Local Model Context Protocol proxy over the VFS command surface.
    /// Disabled by default; nothing starts an MCP server without an
    /// explicit `[mcp] enabled = true`.
    #[serde(default)]
    pub mcp: McpConfig,
}

/// Gate for the `bloom mcp serve` stdio proxy.
///
/// The proxy exposes the same `lookup`/`read`/`write`/`write_with_lookup`/
/// `list` command surface the CLI uses, so it is off unless an operator turns
/// it on. Absent `[mcp]` block, absent `enabled` key, and a fresh
/// [`Config::local_default`] all mean disabled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    /// Whether an MCP server may start at all. Disabled by default.
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PetalsConfig {
    /// Ignored legacy setting. Bloom provisions its canonical Petal catalog.
    #[serde(default, skip_serializing)]
    pub preinstalled: Vec<String>,
    #[serde(default)]
    pub runtime: BTreeMap<String, PetalRuntimeConfig>,
    /// Where an earlier build of setup kept its choices. Read so such a home
    /// still loads, and moved to [`Config::setup`] on load; never written.
    #[serde(default, skip_serializing, rename = "setup")]
    legacy_setup: BTreeMap<String, PetalSetupConfig>,
    #[serde(default, skip_serializing, rename = "setup_complete")]
    legacy_setup_complete: bool,
    /// Whether load found those keys, so the file still holds them until it
    /// is saved.
    #[serde(skip)]
    legacy_setup_loaded: bool,
}

/// What setup chose, as the top-level `[setup]` table. It is not part of
/// `[petals]`: a Bloom release refuses unknown keys there, but ignores an
/// unknown top-level table, so a home this setup ran on still starts with an
/// older Bloom. Unknown keys are ignored here for the same reason, so a later
/// Bloom's additions never stop this one from starting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SetupConfig {
    /// Written when `bloom init` finished. This, not an empty `main`, is what
    /// tells a later run that setup already happened: declining every Petal
    /// is a valid choice, and `bloom serve` or an interrupted menu can leave a
    /// config with no choices in it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub complete: bool,
    /// Each wallet's setup, by wallet name: `bloom init` writes `main`'s, and
    /// `bloom wallet persona` any wallet's.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub wallets: BTreeMap<String, WalletSetup>,
    /// Where an earlier build kept `main`'s Petal choices. Read so such a home
    /// still loads, and moved to `main` on load; never written.
    #[serde(default, skip_serializing, rename = "petals")]
    legacy_petals: BTreeMap<String, PetalSetupConfig>,
}

/// One wallet's setup: its persona, and the Petals its policy allows with
/// the values their settings need. Bloom provisions its canonical Petals
/// regardless; the wallet's default policy proposes exactly these. Nothing
/// here grants authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSetup {
    /// A persona that does not parse or validate is set aside on load
    /// (see [`lenient_persona`]) rather than failing the whole config.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient_persona"
    )]
    pub persona: Option<crate::persona::PersonaConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub petals: BTreeMap<String, PetalSetupConfig>,
}

impl WalletSetup {
    fn is_empty(&self) -> bool {
        self.persona.is_none() && self.petals.is_empty()
    }
}

/// The setup of a wallet that has none.
static NO_WALLET_SETUP: WalletSetup = WalletSetup {
    persona: None,
    petals: BTreeMap::new(),
};

impl SetupConfig {
    fn is_empty(&self) -> bool {
        !self.complete && self.wallets.is_empty()
    }

    /// `wallet`'s setup, empty when it has none.
    pub fn wallet(&self, wallet: &str) -> &WalletSetup {
        self.wallets.get(wallet).unwrap_or(&NO_WALLET_SETUP)
    }

    /// `wallet`'s setup, to change.
    pub fn wallet_mut(&mut self, wallet: &str) -> &mut WalletSetup {
        self.wallets.entry(wallet.to_owned()).or_default()
    }

    /// The default wallet's setup, which `bloom init` chooses.
    pub fn main(&self) -> &WalletSetup {
        self.wallet(DEFAULT_POLICY_WALLET)
    }

    /// The default wallet's setup, to change.
    pub fn main_mut(&mut self) -> &mut WalletSetup {
        self.wallet_mut(DEFAULT_POLICY_WALLET)
    }
}

/// Wallet whose default policy allows the Petals chosen during setup.
pub const DEFAULT_POLICY_WALLET: &str = "main";

/// Canonical Petals setup does not offer, so no persona or default policy
/// allows them, even when a config names one; the owner allows one with their
/// own policy change.
///
/// Safe signs a Safe transaction's confirmation and stages its execution.
/// Broker refuses that signature unless the policy allows exact destinations
/// on its chain, and Machine refuses the execution unless the policy lists the
/// Safe's address. Neither is a fixed contract setup could propose:
/// exact destinations would let any staged transaction deploy a contract, and
/// the Safe is the owner's own. Allowing only its package would let setup
/// say Safe is allowed while every use of it is refused.
pub const PETALS_NOT_IN_SETUP: &[&str] = &["safe"];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetalSetupConfig {
    /// Named values substituted into the catalog's settings template.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub values: BTreeMap<String, String>,
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

/// Write `bytes` over `path` atomically: a sibling is written, synced and
/// renamed over it, keeping the permissions of the file it replaces.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::metadata(path).ok();
    let (mut file, temporary) = create_sibling(path, existing.as_ref())?;
    let written = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        if let Some(existing) = &existing {
            std::fs::set_permissions(&temporary, existing.permissions())?;
        }
        std::fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// Create the sibling [`write_atomically`] renames over `path`, with the
/// mode of the file it replaces, which the umask can only narrow, so it is
/// never readable by more than that file is, even before its permissions
/// are copied.
fn create_sibling(
    path: &Path,
    existing: Option<&std::fs::Metadata>,
) -> std::io::Result<(std::fs::File, PathBuf)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SAVES: AtomicU64 = AtomicU64::new(0);

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.toml");
    let temporary = path.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        SAVES.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if let Some(existing) = existing {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        options.mode(existing.permissions().mode() & 0o777);
    }
    #[cfg(not(unix))]
    let _ = existing;
    Ok((options.open(&temporary)?, temporary))
}

/// Where saving the config at `path` writes: the file a symbolic link at
/// `path` points to, followed to its end, so the link itself is kept.
fn save_target(path: &Path) -> std::io::Result<PathBuf> {
    let mut target = path.to_path_buf();
    // Bounded, so a loop of links fails instead of spinning.
    for _ in 0..40 {
        match std::fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let link = std::fs::read_link(&target)?;
                target = match target.parent() {
                    Some(parent) => parent.join(link),
                    None => link,
                };
            }
            _ => return Ok(target),
        }
    }
    Err(std::io::Error::other(format!(
        "{} is a loop of symbolic links",
        path.display()
    )))
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
fn default_wallet_projection_max_age() -> std::time::Duration {
    std::time::Duration::from_secs(1)
}
fn default_etherscan_url() -> String {
    "https://api.etherscan.io/v2/api".to_string()
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

/// Read a saved persona without letting it fail the whole config. A persona that
/// does not parse (a missing or unknown field, a newer schema) or does not
/// validate is set aside with a warning and the home behaves as Institutional,
/// which grants the least. Every other setting still loads, so Machine starts
/// and `bloom wallet persona` can choose one again. Writing a persona stays
/// strict: [`Config::validate`] refuses an invalid one.
fn lenient_persona<'de, D>(
    deserializer: D,
) -> Result<Option<crate::persona::PersonaConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<toml::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    let persona = value
        .try_into::<crate::persona::PersonaConfig>()
        .map_err(|error| error.to_string())
        .and_then(|persona| persona.validate().map(|()| persona));
    match persona {
        Ok(persona) => Ok(Some(persona)),
        Err(reason) => {
            tracing::warn!(
                %reason,
                "config.persona_ignored: a saved persona is not usable and is treated as institutional; choose one again with `bloom wallet persona <wallet> <institutional|trader|degen>`"
            );
            Ok(None)
        }
    }
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
        etherscan_api_url: None,
        display_name: Some(display_name.to_string()),
        native_symbol: native_symbol.to_string(),
        native_decimals: 18,
        legacy_tx: false,
        op_stack: false,
    }
}

/// Keyless access was retired by the provider; authenticated/custom URLs stay.
const RETIRED_POLYGON_RPC_URL: &str = "https://polygon-rpc.com";

/// Independent providers, rather than several aliases of the same service.
/// PublicNode's original hostname remains valid; local DNS failure is not
/// evidence that a provider has retired an endpoint.
const POLYGON_RPC_URLS: [&str; 3] = [
    "https://polygon.drpc.org",
    "https://polygon-bor-rpc.publicnode.com",
    "https://tenderly.rpc.polygon.community",
];

fn default_chains() -> BTreeMap<String, ChainSpec> {
    let mut chains = BTreeMap::new();
    for spec in [
        evm_chain(
            "ethereum",
            1,
            &[
                "https://ethereum-rpc.publicnode.com",
                "https://ethereum.drpc.org",
            ],
            "Ethereum Mainnet",
            "ETH",
        ),
        evm_chain(
            "base",
            8453,
            &[
                "https://base-rpc.publicnode.com",
                "https://base.drpc.org",
                "https://base.gateway.tenderly.co",
                "https://mainnet.base.org",
            ],
            "Base Mainnet",
            "ETH",
        )
        .with_op_stack(),
        evm_chain(
            "tempo",
            4217,
            &["https://rpc.tempo.xyz"],
            "Tempo Mainnet",
            "ETH",
        ),
        evm_chain(
            "robinhood",
            4663,
            &["https://rpc.mainnet.chain.robinhood.com"],
            "Robinhood Chain",
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
        )
        .with_op_stack(),
        evm_chain("polygon", 137, &POLYGON_RPC_URLS, "Polygon PoS", "POL"),
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
        evm_chain("arc", 5_042, &["https://rpc.arc-scan.org"], "Arc", "USDC"),
    ] {
        chains.insert(spec.name.clone(), spec);
    }
    chains
}

/// Repair configs containing the exact retired default and add missing fallback
/// providers. Preserve custom entries and their relative order; custom-only
/// lists and explicit `rpc_endpoints` remain operator-controlled.
fn replace_retired_polygon_urls(urls: &mut Vec<String>) {
    let Some(i) = urls.iter().position(|u| u == RETIRED_POLYGON_RPC_URL) else {
        return;
    };
    if !urls.iter().any(|u| u == POLYGON_RPC_URLS[0]) {
        urls[i] = POLYGON_RPC_URLS[0].to_string();
    }
    urls.retain(|u| u != RETIRED_POLYGON_RPC_URL);
    for url in POLYGON_RPC_URLS {
        if !urls.iter().any(|u| u == url) {
            urls.push(url.to_string());
        }
    }
}

impl Config {
    /// An agentic-wallet default: public EVM networks and Solana mainnet. A local
    /// Anvil node is opt-in; an unreachable default endpoint stalls every read of
    /// its chain files.
    ///
    /// Broadcast is enabled by default on every chain. Signing, policy,
    /// confirmation, and Sealed Approval gates still apply to value-moving
    /// actions.
    pub fn local_default() -> Self {
        let chains = default_chains();
        Config {
            mount_path: default_mount_path(),
            nfs_listen_addr: default_nfs_listen(),
            default_wallet: None,
            default_chain: default_chain_name(),
            stage_ttl: default_stage_ttl(),
            wallet_projection_max_age: default_wallet_projection_max_age(),
            legacy_persona: None,
            chains,
            solana_chains: BTreeMap::from([(
                "solana-mainnet".into(),
                SolanaSpec {
                    name: "solana-mainnet".into(),
                    endpoints: vec![crate::chain::EndpointSpec {
                        url: "https://api.mainnet.solana.com".into(),
                        weight: 100,
                        cu_per_sec: None,
                        max_rps: None,
                        http_only: true,
                    }],
                    expected_genesis_base58: Some(
                        crate::chain::SOLANA_MAINNET_BETA_GENESIS_HASH.into(),
                    ),
                },
            )]),
            etherscan: None,
            petals: PetalsConfig::default(),
            setup: SetupConfig::default(),
            mempool: BTreeMap::new(),
            private_rpc: BTreeMap::new(),
            backends: BackendsConfig::default(),
            mcp: McpConfig::default(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path)?;
        let mut cfg: Self = toml::from_str(&s)?;
        cfg.migrate();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Whether the file this config was loaded from keeps `main`'s setup in a
    /// layout an earlier build wrote, such as under `[petals]`, where a Bloom
    /// release refuses it, until the file is saved.
    pub fn holds_legacy_setup_keys(&self) -> bool {
        self.petals.legacy_setup_loaded
    }

    /// Write the config atomically: a sibling file is written, synced and
    /// renamed over `path`, so a reader never sees a partly written config
    /// and a crash leaves the old one. The file keeps the config's
    /// permissions, and the sibling is never readable by more than the
    /// config is. A `path` that is a symbolic link is kept: the file it
    /// points to is replaced. If that file cannot be replaced, as one a Nix
    /// store or home-manager keeps read-only, the link itself is replaced,
    /// as saving did before it followed links.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let s = toml::to_string_pretty(self)?;
        let target = save_target(path)?;
        match write_atomically(&target, s.as_bytes()) {
            Err(error)
                if target != path
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::PermissionDenied
                            | std::io::ErrorKind::ReadOnlyFilesystem
                    ) =>
            {
                Ok(write_atomically(path, s.as_bytes())?)
            }
            written => Ok(written?),
        }
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

    /// Apply post-load migrations for backwards compatibility.
    ///
    /// Add the release's new networks without replacing operator configuration,
    /// and swap retired default endpoints that a saved config still holds verbatim.
    /// Like other load migrations, this updates the effective config; save persists it.
    fn migrate(&mut self) {
        // Earlier builds kept `main`'s setup under `[petals]`, then in
        // `[setup] petals` and a top-level `[persona]`. Each moves to
        // `[setup.wallets.main]` unless that already holds it.
        self.petals.legacy_setup_loaded = self.petals.legacy_setup_complete
            || !self.petals.legacy_setup.is_empty()
            || !self.setup.legacy_petals.is_empty()
            || self.legacy_persona.is_some();
        if self.petals.legacy_setup_complete {
            self.setup.complete = true;
        }
        let legacy_petals = if self.setup.legacy_petals.is_empty() {
            std::mem::take(&mut self.petals.legacy_setup)
        } else {
            std::mem::take(&mut self.setup.legacy_petals)
        };
        let legacy_persona = self.legacy_persona.take();
        let main = self.setup.main_mut();
        if main.petals.is_empty() {
            main.petals = legacy_petals;
        }
        if main.persona.is_none() {
            main.persona = legacy_persona;
        }
        if main.is_empty() {
            self.setup.wallets.remove(DEFAULT_POLICY_WALLET);
        }
        self.petals.legacy_setup.clear();
        self.petals.legacy_setup_complete = false;
        self.setup.legacy_petals.clear();
        let mut defaults = Self::local_default();
        // Respect names already assigned to either family; never create a collision.
        if !self.chains.contains_key("arc") && !self.solana_chains.contains_key("arc") {
            self.chains
                .insert("arc".into(), defaults.chains.remove("arc").unwrap());
        }
        if !self.solana_chains.contains_key("solana-mainnet")
            && !self.chains.contains_key("solana-mainnet")
        {
            self.solana_chains.insert(
                "solana-mainnet".into(),
                defaults.solana_chains.remove("solana-mainnet").unwrap(),
            );
        }
        for spec in self.chains.values_mut() {
            spec.infer_op_stack();
            if spec.chain_id == 137 {
                replace_retired_polygon_urls(&mut spec.rpc_urls);
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for setup in self.setup.wallets.values() {
            if let Some(persona) = &setup.persona {
                persona.validate().map_err(ConfigError::Invalid)?;
            }
        }
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
        // A name configured in both `chains` (EVM) and `solana_chains` is
        // ambiguous: per the wallets VFS dispatch order (Solana checked
        // first), it would silently make the EVM chain of that name
        // completely unreachable, with no error anywhere else.
        for name in self.solana_chains.keys() {
            if self.chains.contains_key(name) {
                return Err(ConfigError::Invalid(format!(
                    "chain name '{name}' is configured in both chains and solana_chains"
                )));
            }
        }
        // The Solana read registry, transfer engines, and outbox entries all
        // key a chain by its map entry, while the runtime registry is keyed
        // by `spec.name`; and the HTTP-only read client silently skips
        // non-HTTP endpoints. Accepting a drifted or endpoint-less spec here
        // would postpone the failure to a degraded or split runtime surface,
        // so every entry must be coherent at load time.
        for (key, spec) in &self.solana_chains {
            if key != &spec.name {
                return Err(ConfigError::Invalid(format!(
                    "solana_chains key '{key}' != name '{}': reads and transfers would split \
                     one configured chain across two namespaces",
                    spec.name
                )));
            }
            if spec.endpoints.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "solana chain '{key}' has no endpoints"
                )));
            }
            for endpoint in &spec.endpoints {
                let Some((scheme, _)) = endpoint.url.split_once("://") else {
                    return Err(ConfigError::Invalid(format!(
                        "solana chain '{key}' endpoint '{}' has no URL scheme",
                        endpoint.url
                    )));
                };
                if !matches!(scheme, "http" | "https") {
                    return Err(ConfigError::Invalid(format!(
                        "solana chain '{key}' endpoint scheme '{scheme}' is not supported: the \
                         Solana read client speaks http(s) only",
                    )));
                }
            }
            if spec.expected_genesis_base58.is_some() {
                let pin = spec.expected_genesis_base58.as_deref().unwrap_or("");
                let valid_pin = !pin.is_empty()
                    && bs58::decode(pin)
                        .into_vec()
                        .is_ok_and(|bytes| bytes.len() == 32);
                if !valid_pin {
                    return Err(ConfigError::Invalid(format!(
                        "solana chain '{key}' has an invalid 32-byte base58 \
                         expected_genesis_base58 pin",
                    )));
                }
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
    use crate::chain::EndpointSpec;
    use tempfile::tempdir;

    fn http_endpoint() -> EndpointSpec {
        EndpointSpec {
            url: "http://127.0.0.1:8899".into(),
            weight: 1,
            cu_per_sec: None,
            max_rps: None,
            http_only: false,
        }
    }

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
        assert!(cfg.etherscan.is_none());
        assert!(cfg.petals.preinstalled.is_empty());
        assert!(!toml::to_string(&cfg).unwrap().contains("allow_broadcast"));
        assert_eq!(cfg.chains.len(), 13);
        assert_eq!(cfg.solana_chains.len(), 1);
        let solana = cfg
            .solana_chains
            .get("solana-mainnet")
            .expect("Solana mainnet entry");
        assert_eq!(solana.name, "solana-mainnet");
        assert_eq!(
            solana.expected_genesis_base58.as_deref(),
            Some(crate::chain::SOLANA_MAINNET_BETA_GENESIS_HASH)
        );
        assert_eq!(solana.endpoints[0].url, "https://api.mainnet.solana.com");
        let ethereum = cfg.chains.get("ethereum").expect("ethereum entry");
        assert_eq!(ethereum.chain_id, 1);
        assert!(!ethereum.rpc_urls.is_empty());
        let base = cfg.chains.get("base").expect("base entry");
        assert_eq!(base.chain_id, 8453);
        // Base carried one reachable endpoint and it rate-limits: 11 of 25
        // sequential `eth_call`s to `mainnet.base.org` return -32016, which
        // reads as a broken Petal rather than a thin endpoint list. Keep it
        // last, behind spares that survive the same burst, and pin the list so
        // a revert is caught here.
        assert_eq!(
            base.rpc_urls,
            vec![
                "https://base-rpc.publicnode.com",
                "https://base.drpc.org",
                "https://base.gateway.tenderly.co",
                "https://mainnet.base.org",
            ]
        );
        assert!(
            !cfg.chains
                .values()
                .any(|spec| spec.rpc_urls.iter().any(|url| url.contains("llamarpc"))),
            "llamarpc endpoints stopped resolving; no default chain should depend on one"
        );
        let tempo = cfg.chains.get("tempo").expect("tempo entry");
        assert_eq!(tempo.chain_id, 4217);
        assert_eq!(tempo.rpc_urls, vec!["https://rpc.tempo.xyz"]);
        let robinhood = cfg.chains.get("robinhood").expect("robinhood entry");
        assert_eq!(robinhood.chain_id, 4663);
        assert_eq!(
            robinhood.rpc_urls,
            vec!["https://rpc.mainnet.chain.robinhood.com"]
        );
        assert_eq!(robinhood.display_name.as_deref(), Some("Robinhood Chain"));
        assert_eq!(robinhood.native_symbol, "ETH");
        let hyperliquid = cfg.chains.get("hyperliquid").expect("hyperliquid entry");
        assert_eq!(hyperliquid.chain_id, 999);
        let arc = cfg.chains.get("arc").expect("Arc entry");
        assert_eq!(arc.chain_id, 5_042);
        assert_eq!(arc.rpc_urls, vec!["https://rpc.arc-scan.org"]);
        assert_eq!(arc.display_name.as_deref(), Some("Arc"));
        assert_eq!(arc.native_symbol, "USDC");
        assert_eq!(arc.native_decimals, 18);
        assert!(
            !cfg.chains.contains_key("anvil"),
            "a local Anvil node is opt-in, not a default chain"
        );
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

    // Fix G (PLAN-SOLANA-PR-FIXES.md): a name configured in both `chains`
    // and `solana_chains` silently made the EVM chain of that name
    // unreachable (Solana is checked first in the wallets VFS dispatch
    // order), with no error at config load and no error at runtime.
    #[test]
    fn colliding_solana_and_evm_chain_names_are_refused() {
        let mut cfg = Config::local_default();
        assert!(
            cfg.chains.contains_key("ethereum"),
            "test assumes the default config has an 'ethereum' EVM chain"
        );
        cfg.solana_chains.insert(
            "ethereum".into(),
            SolanaSpec {
                name: "ethereum".into(),
                endpoints: vec![],
                expected_genesis_base58: None,
            },
        );
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("ethereum"),
            "error should name the colliding chain: {err}"
        );
    }

    #[test]
    fn non_colliding_solana_chain_with_coherent_endpoints_validates() {
        let mut cfg = Config::local_default();
        cfg.solana_chains.insert(
            "solana-devnet".into(),
            SolanaSpec {
                name: "solana-devnet".into(),
                endpoints: vec![http_endpoint()],
                expected_genesis_base58: None,
            },
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn solana_chain_key_and_name_must_agree() {
        let mut cfg = Config::local_default();
        cfg.solana_chains.insert(
            "solana-devnet".into(),
            SolanaSpec {
                name: "solana-testnet".into(),
                endpoints: vec![http_endpoint()],
                expected_genesis_base58: None,
            },
        );
        let error = cfg.validate().unwrap_err().to_string();
        assert!(
            error.contains("solana_chains key 'solana-devnet' != name 'solana-testnet'"),
            "{error}"
        );
    }

    #[test]
    fn solana_chain_requires_at_least_one_http_endpoint() {
        let mut cfg = Config::local_default();
        cfg.solana_chains.insert(
            "solana-devnet".into(),
            SolanaSpec {
                name: "solana-devnet".into(),
                endpoints: vec![],
                expected_genesis_base58: None,
            },
        );
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("solana chain 'solana-devnet' has no endpoints")
        );

        // A WebSocket-only list is equally unusable: the read client speaks
        // HTTP(S) and would silently skip every configured endpoint.
        let mut cfg = Config::local_default();
        cfg.solana_chains.insert(
            "solana-devnet".into(),
            SolanaSpec {
                name: "solana-devnet".into(),
                endpoints: vec![EndpointSpec {
                    url: "ws://127.0.0.1:8900".into(),
                    weight: 1,
                    cu_per_sec: None,
                    max_rps: None,
                    http_only: false,
                }],
                expected_genesis_base58: None,
            },
        );
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("endpoint scheme 'ws' is not supported")
        );
    }

    #[test]
    fn solana_broadcast_requires_a_valid_genesis_pin() {
        let mut cfg = Config::local_default();
        cfg.solana_chains.insert(
            "solana-devnet".into(),
            SolanaSpec {
                name: "solana-devnet".into(),
                endpoints: vec![http_endpoint()],
                expected_genesis_base58: Some("not-base58-$$$".into()),
            },
        );
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("has an invalid 32-byte base58")
        );

        let mut cfg = Config::local_default();
        cfg.solana_chains.insert(
            "solana-devnet".into(),
            SolanaSpec {
                name: "solana-devnet".into(),
                endpoints: vec![http_endpoint()],
                // Valid base58, but not 32 bytes: not a genesis hash.
                expected_genesis_base58: Some("abc".into()),
            },
        );
        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("has an invalid 32-byte base58")
        );
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
    fn legacy_preinstalled_values_are_ignored_without_migration() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        for value in [
            "[]",
            "[\"polymarket\", \"near-intents\", \"enso\"]",
            "[\"unknown\", \"unknown\"]",
        ] {
            let mut document = toml::Value::try_from(Config::local_default()).unwrap();
            document["petals"].as_table_mut().unwrap().insert(
                "preinstalled".into(),
                toml::from_str::<toml::Value>(&format!("value = {value}")).unwrap()["value"]
                    .clone(),
            );
            let original = toml::to_string_pretty(&document).unwrap();
            std::fs::write(&path, &original).unwrap();
            let loaded = Config::load(&path).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
            assert!(
                !toml::to_string_pretty(&loaded)
                    .unwrap()
                    .contains("preinstalled")
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
    fn mcp_is_disabled_by_default_and_on_configs_predating_the_block() {
        assert!(!McpConfig::default().enabled);
        assert!(!Config::local_default().mcp.enabled);

        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        // A config written before `[mcp]` existed must keep loading, disabled.
        std::fs::write(
            &path,
            r#"
default_chain = "ethereum"

[chains.ethereum]
name = "ethereum"
chain_id = 1
rpc_urls = ["https://ethereum-rpc.publicnode.com"]
"#,
        )
        .unwrap();
        assert!(!Config::load(&path).unwrap().mcp.enabled);

        // An empty `[mcp]` block is still "off"; enabling has to be explicit.
        std::fs::write(
            &path,
            r#"
default_chain = "ethereum"

[mcp]

[chains.ethereum]
name = "ethereum"
chain_id = 1
rpc_urls = ["https://ethereum-rpc.publicnode.com"]
"#,
        )
        .unwrap();
        assert!(!Config::load(&path).unwrap().mcp.enabled);
    }

    #[test]
    fn mcp_enablement_is_explicit_and_survives_save_load() {
        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        let mut cfg = Config::local_default();
        cfg.mcp.enabled = true;
        cfg.save(&path).unwrap();
        assert!(
            std::fs::read_to_string(&path).unwrap().contains("enabled"),
            "saved config must spell out the mcp flag"
        );
        assert!(Config::load(&path).unwrap().mcp.enabled);
    }

    #[test]
    fn unknown_mcp_key_is_rejected() {
        let err = toml::from_str::<McpConfig>("enabled = true\ntransport = \"tcp\"\n").unwrap_err();
        assert!(
            err.to_string().contains("unknown field `transport`"),
            "{err}"
        );
    }

    #[test]
    fn toml_round_trip_default() {
        let cfg = Config::local_default();
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_configs_equivalent(&cfg, &back);
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
        assert!(cfg.solana_chains.contains_key("solana-mainnet"));
        let cfg2 = Config::load_or_init(&path).unwrap();
        assert_configs_equivalent(&cfg, &cfg2);
    }

    /// Saving replaces the config in one step: no partly written file is
    /// ever visible, no temporary file is left, and the config keeps its
    /// permissions.
    #[cfg(unix)]
    #[test]
    fn saving_replaces_the_config_atomically_and_keeps_its_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        let mut cfg = Config::local_default();
        cfg.save(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        cfg.setup.complete = true;
        cfg.save(&path).unwrap();
        assert!(Config::load(&path).unwrap().setup.complete);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let names: Vec<String> = std::fs::read_dir(td.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["config.toml"]);

        // Readers racing saves always see a whole config.
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            for _ in 0..500 {
                Config::load(&reader_path).unwrap();
            }
        });
        for round in 0..200 {
            cfg.setup.complete = round % 2 == 0;
            cfg.save(&path).unwrap();
        }
        reader.join().unwrap();
    }

    /// A config reached through a symbolic link, as a dotfiles checkout
    /// keeps it, stays a link: the file it points to is replaced.
    #[cfg(unix)]
    #[test]
    fn saving_through_a_symbolic_link_keeps_the_link() {
        use std::os::unix::fs::PermissionsExt as _;

        let td = tempdir().unwrap();
        let real = td.path().join("dotfiles").join("bloom.toml");
        let mut cfg = Config::local_default();
        cfg.save(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let path = td.path().join("config.toml");
        std::os::unix::fs::symlink("dotfiles/bloom.toml", &path).unwrap();

        cfg.setup.complete = true;
        cfg.save(&path).unwrap();
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(Config::load(&real).unwrap().setup.complete);
        assert_eq!(
            std::fs::metadata(&real).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let names: Vec<String> = std::fs::read_dir(real.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["bloom.toml"]);

        let looped = td.path().join("loop.toml");
        std::os::unix::fs::symlink("loop.toml", &looped).unwrap();
        assert!(cfg.save(&looped).is_err());
    }

    /// A link to a file Bloom cannot replace, as a Nix store or home-manager
    /// keeps one, is replaced itself, so saving still works.
    #[cfg(unix)]
    #[test]
    fn saving_through_a_link_to_an_unwritable_file_replaces_the_link() {
        use std::os::unix::fs::PermissionsExt as _;

        let td = tempdir().unwrap();
        let store = td.path().join("store");
        let real = store.join("bloom.toml");
        let mut cfg = Config::local_default();
        cfg.save(&real).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o555)).unwrap();
        let path = td.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &path).unwrap();

        cfg.setup.complete = true;
        let saved = cfg.save(&path);
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();
        saved.unwrap();
        assert!(
            !std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(Config::load(&path).unwrap().setup.complete);
        assert!(!Config::load(&real).unwrap().setup.complete);
    }

    /// The sibling a save writes first is never readable by more than the
    /// config it replaces, before its permissions are copied too.
    #[cfg(unix)]
    #[test]
    fn a_save_sibling_is_never_more_readable_than_the_config() {
        use std::os::unix::fs::PermissionsExt as _;

        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let existing = std::fs::metadata(&path).unwrap();
        let (_file, sibling) = create_sibling(&path, Some(&existing)).unwrap();
        let mode = std::fs::metadata(&sibling).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & !0o600, 0, "sibling mode {mode:o}");
    }

    #[test]
    fn setup_completion_is_written_only_once_recorded() {
        let mut cfg = Config::local_default();
        assert!(!cfg.setup.complete);
        let encoded = toml::to_string_pretty(&cfg).unwrap();
        assert!(!encoded.contains("[setup"), "{encoded}");

        // Petal tables alone do not mean setup finished.
        cfg.setup
            .main_mut()
            .petals
            .insert("hyperliquid".into(), PetalSetupConfig::default());
        let decoded: Config = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert!(decoded.setup.main().petals.contains_key("hyperliquid"));
        assert!(!decoded.setup.complete);

        cfg.setup.complete = true;
        let decoded: Config = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert!(decoded.setup.complete);
    }

    /// Each wallet keeps its own setup: a persona and the Petals its policy
    /// allows. A wallet without one reads as empty.
    #[test]
    fn each_wallet_keeps_its_own_setup() {
        use crate::persona::{PersonaConfig, PersonaPreset};

        let mut cfg = Config::local_default();
        cfg.setup.complete = true;
        cfg.setup.main_mut().persona = Some(PersonaConfig::suggested(PersonaPreset::Trader));
        let trading = cfg.setup.wallet_mut("trading");
        trading.persona = Some(PersonaConfig::suggested(PersonaPreset::Degen));
        trading.petals.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "10000".into())]),
            },
        );
        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        cfg.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.setup.wallets, cfg.setup.wallets);
        assert!(!loaded.holds_legacy_setup_keys());
        assert_eq!(
            loaded.setup.main().persona.as_ref().unwrap().preset,
            PersonaPreset::Trader
        );
        assert!(loaded.setup.main().petals.is_empty());
        assert_eq!(
            loaded.setup.wallet("trading"),
            &cfg.setup.wallets["trading"]
        );
        assert_eq!(loaded.setup.wallet("savings"), &WalletSetup::default());
    }

    /// Setup's choices sit outside `[petals]`, whose unknown keys a Bloom
    /// release refuses, so going back to a release still loads the config.
    #[test]
    fn setup_choices_stay_out_of_the_table_releases_refuse_unknown_keys_in() {
        let mut cfg = Config::local_default();
        cfg.setup.complete = true;
        cfg.setup.main_mut().petals.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "100".into())]),
            },
        );
        cfg.setup.main_mut().persona = Some(crate::persona::PersonaConfig::suggested(
            crate::persona::PersonaPreset::Degen,
        ));
        let encoded = toml::to_string_pretty(&cfg).unwrap();
        let document: toml::Value = toml::from_str(&encoded).unwrap();
        assert_eq!(
            document["petals"]
                .as_table()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["runtime"],
            "{encoded}"
        );
        assert!(document.get("persona").is_none(), "{encoded}");
        // A release's `[petals]` table: only these keys, unknown ones refused.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct ReleasePetals {
            #[serde(default)]
            preinstalled: Vec<String>,
            #[serde(default)]
            runtime: BTreeMap<String, PetalRuntimeConfig>,
        }
        document["petals"]
            .clone()
            .try_into::<ReleasePetals>()
            .unwrap();
    }

    /// Earlier builds kept `main`'s setup under `[petals]`, then in `[setup]
    /// petals` and a top-level `[persona]`. Each still loads into `main`'s
    /// setup and moves to `[setup.wallets.main]` when the config is saved.
    #[test]
    fn earlier_setup_layouts_load_into_main() {
        use crate::persona::{PersonaConfig, PersonaPreset};

        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        let polymarket = BTreeMap::from([(
            "polymarket".to_owned(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "100".into())]),
            },
        )]);
        let base = || toml::Value::try_from(Config::local_default()).unwrap();
        let polymarket_table = || toml::Value::try_from(&polymarket).unwrap();
        let degen = toml::Value::try_from(PersonaConfig::suggested(PersonaPreset::Degen)).unwrap();

        // Under `[petals]`.
        let mut under_petals = base();
        let petals = under_petals["petals"].as_table_mut().unwrap();
        petals.insert("setup_complete".into(), true.into());
        petals.insert("setup".into(), polymarket_table());
        // In `[setup] petals`, with the persona at the top level.
        let mut in_setup = base();
        let table = in_setup.as_table_mut().unwrap();
        table.insert(
            "setup".into(),
            toml::Value::Table(toml::map::Map::from_iter([
                ("complete".to_owned(), true.into()),
                ("petals".to_owned(), polymarket_table()),
            ])),
        );
        table.insert("persona".into(), degen.clone());

        for (legacy, persona) in [(under_petals, None), (in_setup, Some(PersonaPreset::Degen))] {
            std::fs::write(&path, toml::to_string_pretty(&legacy).unwrap()).unwrap();
            let loaded = Config::load(&path).unwrap();
            assert!(loaded.holds_legacy_setup_keys());
            assert!(loaded.setup.complete);
            assert_eq!(loaded.setup.main().petals, polymarket);
            assert_eq!(
                loaded
                    .setup
                    .main()
                    .persona
                    .as_ref()
                    .map(|persona| persona.preset),
                persona
            );
            loaded.save(&path).unwrap();
            let saved = std::fs::read_to_string(&path).unwrap();
            let document: toml::Value = toml::from_str(&saved).unwrap();
            assert_eq!(
                document["petals"]
                    .as_table()
                    .unwrap()
                    .keys()
                    .collect::<Vec<_>>(),
                ["runtime"],
                "{saved}"
            );
            assert!(document.get("persona").is_none(), "{saved}");
            assert!(document["setup"].get("petals").is_none(), "{saved}");
            let reloaded = Config::load(&path).unwrap();
            assert!(!reloaded.holds_legacy_setup_keys());
            assert_eq!(reloaded.setup.wallets, loaded.setup.wallets);
        }
        assert!(
            !Config::load_or_init(&td.path().join("fresh.toml"))
                .unwrap()
                .holds_legacy_setup_keys()
        );
    }

    /// A saved persona that is not usable is set aside on load instead of
    /// failing every command, and saving the config drops it. Writing one
    /// stays strict.
    #[test]
    fn an_unusable_saved_persona_does_not_stop_the_config_loading() {
        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        let mut cfg = Config::local_default();
        cfg.setup.main_mut().persona = Some(crate::persona::PersonaConfig::suggested(
            crate::persona::PersonaPreset::Degen,
        ));
        let valid = toml::to_string(&cfg).unwrap();
        assert!(valid.contains("window_secs = 604800"), "{valid}");
        for edited in [
            valid.replace("window_secs = 604800", "window_secs = 3600"),
            valid.replace("schema_version = 2", "schema_version = 3"),
            valid.replace("window_secs = 604800", "window_secs = 604800\nbudget = 5"),
            valid.replace("preset = \"degen\"", "preset = \"whale\""),
            valid.replace("window_secs = 604800\n", ""),
        ] {
            assert_ne!(edited, valid);
            std::fs::write(&path, &edited).unwrap();
            let loaded = Config::load(&path).unwrap_or_else(|error| panic!("{error}: {edited}"));
            assert_eq!(loaded.setup.main().persona, None, "{edited}");
            assert_eq!(loaded.chains, cfg.chains, "every other setting still loads");
            loaded.save(&path).unwrap();
            assert!(!std::fs::read_to_string(&path).unwrap().contains("preset"));
        }
        std::fs::write(&path, &valid).unwrap();
        assert_eq!(
            Config::load(&path).unwrap().setup.main().persona,
            cfg.setup.main().persona
        );

        let mut invalid = cfg.clone();
        invalid
            .setup
            .main_mut()
            .persona
            .as_mut()
            .unwrap()
            .window_secs = 3600;
        assert!(
            invalid.validate().is_err(),
            "writing an invalid persona is refused"
        );
    }

    #[test]
    fn load_or_init_adds_missing_networks_and_ignores_legacy_broadcast() {
        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        let existing = r#"
default_chain = "anvil"

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]
allow_broadcast = false
"#;
        std::fs::write(&path, existing).unwrap();

        let cfg = Config::load_or_init(&path).unwrap();

        assert_eq!(cfg.chains.len(), 2);
        assert_eq!(cfg.chains["arc"], Config::local_default().chains["arc"]);
        assert_eq!(cfg.solana_chains, Config::local_default().solana_chains);
        assert!(
            !toml::to_string_pretty(&cfg)
                .unwrap()
                .contains("allow_broadcast")
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), existing);
    }

    #[test]
    fn migration_preserves_custom_networks_and_is_idempotent() {
        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        let mut expected = Config::local_default();
        let arc = expected.chains.get_mut("arc").unwrap();
        arc.chain_id = 12345;
        arc.rpc_urls = vec!["https://custom-arc.example".into()];
        let solana = expected.solana_chains.get_mut("solana-mainnet").unwrap();
        solana.endpoints[0].url = "https://custom-solana.example".into();
        solana.expected_genesis_base58 = Some(bs58::encode([7_u8; 32]).into_string());
        let mut custom = solana.clone();
        custom.name = "custom-solana".into();
        expected.solana_chains.insert(custom.name.clone(), custom);
        let existing = expected.clone();
        existing.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_configs_equivalent(&loaded, &expected);
        loaded.save(&path).unwrap();
        assert_configs_equivalent(&Config::load(&path).unwrap(), &expected);
    }

    fn migrated_polygon_urls(urls: &[&str]) -> Vec<String> {
        let mut cfg = Config::local_default();
        let polygon = cfg.chains.get_mut("polygon").unwrap();
        polygon.rpc_urls = urls.iter().map(|u| (*u).to_string()).collect();
        polygon.rpc_endpoints = vec![EndpointSpec {
            url: "https://polygon-rpc.com".into(),
            ..http_endpoint()
        }];
        cfg.migrate();
        let once = cfg.chains["polygon"].clone();
        cfg.migrate();
        assert_eq!(cfg.chains["polygon"], once, "migration must be idempotent");
        // Bloom never wrote defaults to the richer form; leave it to the operator.
        assert_eq!(once.rpc_endpoints[0].url, "https://polygon-rpc.com");
        once.rpc_urls
    }

    #[test]
    fn polygon_defaults_avoid_retired_endpoints() {
        let fresh = Config::local_default();
        assert_eq!(fresh.chains["polygon"].rpc_urls, POLYGON_RPC_URLS);
        let mut migrated = fresh.clone();
        migrated.migrate();
        assert_configs_equivalent(&migrated, &fresh);
    }

    #[test]
    fn migration_replaces_exact_retired_polygon_defaults() {
        assert_eq!(
            migrated_polygon_urls(&[
                "https://polygon-rpc.com",
                "https://polygon-bor-rpc.publicnode.com",
            ]),
            Config::local_default().chains["polygon"].rpc_urls
        );
    }

    #[test]
    fn migration_keeps_custom_polygon_urls_and_order() {
        // Mixed: custom entries keep their place; a replacement already present
        // is not duplicated.
        assert_eq!(
            migrated_polygon_urls(&[
                "https://polygon.publicnode.com",
                "https://user:secret@rpc.example/polygon",
                "https://polygon-bor-rpc.publicnode.com",
                "https://polygon-rpc.com",
                "https://polygon.drpc.org",
                "https://polygon-rpc.com",
            ]),
            [
                "https://polygon.publicnode.com",
                "https://user:secret@rpc.example/polygon",
                "https://polygon-bor-rpc.publicnode.com",
                "https://polygon.drpc.org",
                "https://tenderly.rpc.polygon.community",
            ]
        );
        // Custom-only, including near-misses of the retired values.
        let custom = [
            "https://polygon-bor-rpc.publicnode.com",
            "https://polygon-bor.publicnode.com",
            "https://polygon-rpc.com/?key=abc",
            "https://polygon-rpc.com/",
            "https://polygon-mainnet.g.alchemy.com/v2/KEY",
        ];
        assert_eq!(migrated_polygon_urls(&custom), custom);
    }

    #[test]
    fn migration_replaces_duplicate_retired_urls_once() {
        assert_eq!(
            migrated_polygon_urls(&[RETIRED_POLYGON_RPC_URL, RETIRED_POLYGON_RPC_URL]),
            POLYGON_RPC_URLS
        );
    }

    #[test]
    fn migration_replaces_polygon_defaults_in_a_saved_config() {
        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        let existing = r#"
default_chain = "polygon"

[chains.polygon]
name = "polygon"
chain_id = 137
rpc_urls = ["https://polygon-rpc.com", "https://polygon-bor-rpc.publicnode.com"]
native_symbol = "POL"
"#;
        std::fs::write(&path, existing).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(
            loaded.chains["polygon"].rpc_urls,
            Config::local_default().chains["polygon"].rpc_urls
        );
        loaded.save(&path).unwrap();
        assert_configs_equivalent(&Config::load(&path).unwrap(), &loaded);
    }

    #[test]
    fn migration_respects_names_in_the_other_chain_family() {
        let mut cfg = Config::local_default();
        let mut evm = cfg.chains.remove("arc").unwrap();
        evm.name = "solana-mainnet".into();
        cfg.chains.insert(evm.name.clone(), evm);
        let mut solana = cfg.solana_chains.remove("solana-mainnet").unwrap();
        solana.name = "arc".into();
        cfg.solana_chains.insert(solana.name.clone(), solana);
        let expected = cfg.clone();
        cfg.migrate();
        cfg.validate().unwrap();
        assert_configs_equivalent(&cfg, &expected);
    }

    #[test]
    fn migration_does_not_invent_genesis_for_existing_solana_network() {
        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        let mut cfg = Config::local_default();
        let solana = cfg.solana_chains.get_mut("solana-mainnet").unwrap();
        solana.expected_genesis_base58 = None;
        cfg.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert!(
            loaded.solana_chains["solana-mainnet"]
                .expected_genesis_base58
                .is_none()
        );
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
        assert_eq!(
            cfg.wallet_projection_max_age,
            std::time::Duration::from_secs(1)
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn wallet_projection_max_age_accepts_durations_including_zero() {
        for (value, expected) in [("250ms", 250), ("0s", 0)] {
            let cfg: Config =
                toml::from_str(&format!("wallet_projection_max_age = \"{value}\"")).unwrap();
            assert_eq!(
                cfg.wallet_projection_max_age,
                std::time::Duration::from_millis(expected)
            );
        }
    }

    #[test]
    fn validate_rejects_key_name_mismatch() {
        let mut cfg = Config::local_default();
        let mut spec = cfg.chains.remove("ethereum").unwrap();
        spec.name = "renamed".to_string();
        cfg.chains.insert("ethereum".to_string(), spec);
        let err = cfg.validate().unwrap_err();
        match err {
            ConfigError::Invalid(m) => {
                assert!(m.contains("ethereum") && m.contains("renamed"), "msg: {m}")
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_when_both_empty() {
        let mut cfg = Config::local_default();
        let entry = cfg.chains.get_mut("ethereum").unwrap();
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
        let entry = cfg.chains.get_mut("ethereum").unwrap();
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
        assert!(cfg.chain("anvil").is_none(), "a local Anvil node is opt-in");
        assert!(cfg.chain("ethereum").is_some());
        assert!(cfg.chain("hyperliquid").is_some());
        assert!(cfg.chain("ghost").is_none());
    }

    #[test]
    fn solana_broadcast_accepts_pinned_mainnet_genesis() {
        let mut cfg = Config::local_default();
        cfg.solana_chains.insert(
            "solana-mainnet".into(),
            SolanaSpec {
                name: "solana-mainnet".into(),
                endpoints: vec![crate::EndpointSpec {
                    url: "https://example.invalid".into(),
                    weight: 100,
                    cu_per_sec: None,
                    max_rps: None,
                    http_only: false,
                }],
                expected_genesis_base58: Some(
                    crate::chain::SOLANA_MAINNET_BETA_GENESIS_HASH.into(),
                ),
            },
        );
        cfg.validate().unwrap();
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
    fn etherscan_block_parses() {
        let toml_text = r#"
default_chain = "anvil"

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]

[etherscan]
api_key = "ESKEY"
"#;
        let cfg: Config = toml::from_str(toml_text).unwrap();
        let es = cfg.etherscan.expect("etherscan parsed");
        assert_eq!(es.api_key, "ESKEY");
        assert_eq!(es.api_url, "https://api.etherscan.io/v2/api");
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

    #[test]
    fn load_migrates_op_stack_for_known_chain_ids() {
        let toml_src = r#"
default_chain = "base"

[chains.base]
name = "base"
chain_id = 8453
rpc_urls = ["https://mainnet.base.org"]

[chains.ethereum]
name = "ethereum"
chain_id = 1
rpc_urls = ["https://ethereum-rpc.publicnode.com"]

[chains.optimism]
name = "optimism"
chain_id = 10
rpc_urls = ["https://mainnet.optimism.io"]
"#;
        let td = tempdir().unwrap();
        let path = td.path().join("config.toml");
        std::fs::write(&path, toml_src).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert!(
            cfg.chains["base"].op_stack,
            "base should be op_stack after migration"
        );
        assert!(
            cfg.chains["optimism"].op_stack,
            "optimism should be op_stack after migration"
        );
        assert!(
            !cfg.chains["ethereum"].op_stack,
            "ethereum should not be op_stack"
        );
    }
}
