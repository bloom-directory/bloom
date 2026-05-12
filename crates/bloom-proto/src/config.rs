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

/// Where a given feature sources its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// Etherscan v2 multichain API. Requires an `[etherscan]` block.
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
    /// Etherscan v2 multi-chain API key.
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

fn default_mount_path() -> String {
    "/bloom".to_string()
}
fn default_nfs_listen() -> String {
    "127.0.0.1:12049".to_string()
}
fn default_chain_name() -> String {
    "anvil".to_string()
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
fn default_mainnet_block() -> bool {
    true
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

impl Config {
    /// A safe local-dev default: Anvil only, no broadcast on mainnet ids.
    pub fn local_default() -> Self {
        let mut chains = BTreeMap::new();
        chains.insert("anvil".to_string(), ChainSpec::anvil_default());
        Config {
            mount_path: default_mount_path(),
            nfs_listen_addr: default_nfs_listen(),
            default_chain: "anvil".to_string(),
            stage_ttl: default_stage_ttl(),
            chains,
            etherscan: None,
            enso: None,
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
        Ok(())
    }

    pub fn chain(&self, name: &str) -> Option<&ChainSpec> {
        self.chains.get(name)
    }

    /// Is this chain id one we *consider* mainnet for the kill-switch?
    pub fn is_mainnet_id(chain_id: u64) -> bool {
        matches!(
            chain_id,
            1 | 10 | 137 | 8453 | 42161 | 56 | 43114 | 100 | 250 | 324 | 59144 | 534352
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
        assert_eq!(cfg.default_chain, "anvil");
        assert_eq!(cfg.mount_path, "/bloom");
        assert_eq!(cfg.nfs_listen_addr, "127.0.0.1:12049");
        assert!(cfg.block_mainnet_broadcast);
        assert!(cfg.etherscan.is_none());
        assert!(cfg.enso.is_none());
        assert_eq!(cfg.chains.len(), 1);
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
        assert_eq!(cfg.default_chain, "anvil");
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
        assert!(cfg.chain("ethereum").is_none());
    }

    #[test]
    fn is_mainnet_id_matches_known_ids() {
        for id in [
            1, 10, 137, 8453, 42161, 56, 43114, 100, 250, 324, 59144, 534352,
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
}
