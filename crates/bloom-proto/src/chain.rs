//! Chain identifiers and per-chain config.

use serde::{Deserialize, Serialize};

/// The numeric EVM chainId. `1`, `10`, `8453`, …
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(pub u64);

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for ChainId {
    fn from(n: u64) -> Self {
        ChainId(n)
    }
}

/// A user-facing chain name (e.g. "ethereum", "base", "anvil").
///
/// Stored alongside the numeric chainId so the FS path layout is the
/// human-readable name while the JSON-RPC layer uses the number.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainRef(pub String);

impl ChainRef {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ChainRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Rich per-endpoint config.
///
/// Used by `bloom-rpc` to build the layered transport stack. The legacy
/// flat `rpc_urls` list still works — `ChainSpec::endpoints()` maps it
/// onto this shape with sensible defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointSpec {
    /// Endpoint URL. One of `http://`, `https://`, `ws://`, `wss://`.
    pub url: String,
    /// Higher number = preferred. The legacy `rpc_urls` form maps the
    /// list-index to a descending weight starting at 100 so the first
    /// entry stays the default winner.
    #[serde(default = "default_endpoint_weight")]
    pub weight: u32,
    /// Compute-units-per-second budget (Alchemy/Infura convention).
    /// Used by the retry layer for per-endpoint pacing.
    #[serde(default)]
    pub cu_per_sec: Option<u64>,
    /// Optional throttle ceiling. None = disabled (no throttle layer).
    #[serde(default)]
    pub max_rps: Option<u32>,
    /// If true, this endpoint is excluded from `subscribe_*` and only
    /// used for HTTP RPC. Useful when a vendor charges WS separately.
    #[serde(default)]
    pub http_only: bool,
}

/// Default weight for a freshly-declared endpoint when `weight` is
/// omitted. Picked to sit above the descending sequence the back-compat
/// shim derives from `rpc_urls` (which starts at 100 and goes down).
pub fn default_endpoint_weight() -> u32 {
    100
}

/// Per-chain configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSpec {
    /// Filesystem-friendly name (e.g. "ethereum", "anvil", "base").
    pub name: String,
    /// EVM chainId.
    pub chain_id: u64,
    /// Legacy: flat URL list. If `rpc_endpoints` is empty, every entry
    /// here is mapped to a default `EndpointSpec` ordered by index.
    pub rpc_urls: Vec<String>,
    /// New: rich endpoint schema. Wins over `rpc_urls` when non-empty.
    #[serde(default)]
    pub rpc_endpoints: Vec<EndpointSpec>,
    /// Whether broadcasts are allowed on this chain. **False by default
    /// on mainnet/L2** to enforce the "never broadcast to mainnet
    /// without explicit operator config" rule.
    #[serde(default)]
    pub allow_broadcast: bool,
    /// Etherscan-compatible API base URL (optional).
    #[serde(default)]
    pub etherscan_api_url: Option<String>,
    /// Display name for plan.md (e.g. "Ethereum Mainnet").
    #[serde(default)]
    pub display_name: Option<String>,
    /// Symbol of the native token, e.g. "ETH", "MATIC". Defaults to "ETH".
    #[serde(default = "default_native")]
    pub native_symbol: String,
    /// Decimals of the native token. Defaults to 18.
    #[serde(default = "default_native_decimals")]
    pub native_decimals: u8,
    /// When true, build legacy (pre-EIP-1559) transactions on this
    /// chain — populating `gas_price` instead of `max_fee_per_gas` /
    /// `max_priority_fee_per_gas`. Defaults to false (EIP-1559).
    #[serde(default)]
    pub legacy_tx: bool,
    /// When true, this chain is part of the OP Stack (Base, Optimism,
    /// …) and produces deposit/system transactions (type `0x7e`) and
    /// receipts with L1-fee fields. The EVM client uses `op-alloy`
    /// typed decoders so these are parsed correctly.
    #[serde(default)]
    pub op_stack: bool,
}

fn default_native() -> String {
    "ETH".to_string()
}
fn default_native_decimals() -> u8 {
    18
}

impl ChainSpec {
    /// A safe default Anvil chain spec for local development.
    pub fn anvil_default() -> Self {
        ChainSpec {
            name: "anvil".to_string(),
            chain_id: 31337,
            rpc_urls: vec!["http://127.0.0.1:8545".to_string()],
            rpc_endpoints: Vec::new(),
            allow_broadcast: true,
            etherscan_api_url: None,
            display_name: Some("Anvil (local)".to_string()),
            native_symbol: "ETH".to_string(),
            native_decimals: 18,
            legacy_tx: false,
            op_stack: false,
        }
    }

    pub fn id(&self) -> ChainId {
        ChainId(self.chain_id)
    }
    pub fn r#ref(&self) -> ChainRef {
        ChainRef::new(&self.name)
    }

    /// Builder helper: marks this chain as an OP Stack chain.
    pub fn with_op_stack(mut self) -> Self {
        self.op_stack = true;
        self
    }

    /// Known OP-stack chain IDs (Optimism, Base, and their testnets).
    pub fn is_known_op_stack_chain_id(chain_id: u64) -> bool {
        matches!(chain_id, 10 | 8453 | 11155420 | 84532)
    }

    /// Infer `op_stack` from the chain ID when the field was absent in
    /// an older config file. Only upgrades falseâtrue for well-known
    /// OP-stack chain IDs; never downgrades.
    pub fn infer_op_stack(&mut self) -> bool {
        if !self.op_stack && Self::is_known_op_stack_chain_id(self.chain_id) {
            self.op_stack = true;
            true
        } else {
            false
        }
    }

    /// Single source of truth for the RPC layer.
    ///
    /// Returns `rpc_endpoints` verbatim when non-empty. Otherwise maps
    /// every `rpc_urls` entry into an `EndpointSpec` whose weight
    /// descends from 100 (so the first URL keeps winning ties under the
    /// fallback layer's score-then-tie-break ordering).
    pub fn endpoints(&self) -> Vec<EndpointSpec> {
        if !self.rpc_endpoints.is_empty() {
            return self.rpc_endpoints.clone();
        }
        self.rpc_urls
            .iter()
            .enumerate()
            .map(|(i, u)| EndpointSpec {
                url: u.clone(),
                weight: 100u32.saturating_sub(i as u32),
                cu_per_sec: None,
                max_rps: None,
                http_only: false,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_id_display_and_from() {
        let id: ChainId = 8453u64.into();
        assert_eq!(id.0, 8453);
        assert_eq!(id.to_string(), "8453");
    }

    #[test]
    fn chain_ref_new_and_display() {
        let r = ChainRef::new("ethereum");
        assert_eq!(r.as_str(), "ethereum");
        assert_eq!(r.to_string(), "ethereum");
    }

    #[test]
    fn chain_id_serializes_transparently_as_number() {
        let id = ChainId(1);
        let s = serde_json::to_string(&id).unwrap();
        assert_eq!(s, "1");
        let back: ChainId = serde_json::from_str("1").unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn chain_ref_serializes_transparently_as_string() {
        let r = ChainRef::new("base");
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, "\"base\"");
        let back: ChainRef = serde_json::from_str("\"base\"").unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn anvil_default_shape() {
        let c = ChainSpec::anvil_default();
        assert_eq!(c.name, "anvil");
        assert_eq!(c.chain_id, 31337);
        assert_eq!(c.id(), ChainId(31337));
        assert_eq!(c.r#ref().as_str(), "anvil");
        assert!(c.allow_broadcast);
        assert_eq!(c.rpc_urls, vec!["http://127.0.0.1:8545".to_string()]);
        assert_eq!(c.native_symbol, "ETH");
        assert_eq!(c.native_decimals, 18);
        assert!(!c.legacy_tx);
        assert!(!c.op_stack);
        assert!(c.etherscan_api_url.is_none());
    }

    #[test]
    fn chain_spec_toml_round_trip() {
        let original = ChainSpec::anvil_default();
        let s = toml::to_string(&original).unwrap();
        let back: ChainSpec = toml::from_str(&s).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn chain_spec_json_round_trip() {
        let original = ChainSpec {
            name: "ethereum".to_string(),
            chain_id: 1,
            rpc_urls: vec!["https://rpc.example".to_string()],
            rpc_endpoints: Vec::new(),
            allow_broadcast: false,
            etherscan_api_url: Some("https://api.etherscan.io/v2/api".to_string()),
            display_name: Some("Ethereum Mainnet".to_string()),
            native_symbol: "ETH".to_string(),
            native_decimals: 18,
            legacy_tx: false,
            op_stack: false,
        };
        let s = serde_json::to_string(&original).unwrap();
        let back: ChainSpec = serde_json::from_str(&s).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn chain_spec_endpoints_back_compat() {
        // Legacy form: only `rpc_urls`. The shim must produce one
        // EndpointSpec per URL with descending weights and Nones in the
        // optional knobs.
        let spec = ChainSpec {
            name: "back-compat".to_string(),
            chain_id: 1,
            rpc_urls: vec!["a".into(), "b".into(), "c".into()],
            rpc_endpoints: Vec::new(),
            allow_broadcast: false,
            etherscan_api_url: None,
            display_name: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            legacy_tx: false,
            op_stack: false,
        };
        let eps = spec.endpoints();
        assert_eq!(eps.len(), 3);
        assert_eq!(eps[0].url, "a");
        assert_eq!(eps[1].url, "b");
        assert_eq!(eps[2].url, "c");
        assert_eq!(eps[0].weight, 100);
        assert_eq!(eps[1].weight, 99);
        assert_eq!(eps[2].weight, 98);
        for e in &eps {
            assert!(e.cu_per_sec.is_none());
            assert!(e.max_rps.is_none());
            assert!(!e.http_only);
        }
    }

    #[test]
    fn chain_spec_endpoints_prefers_rich_form() {
        // Rich form non-empty wins verbatim — `rpc_urls` content is
        // ignored when both are present.
        let rich = vec![
            EndpointSpec {
                url: "wss://rich.example".to_string(),
                weight: 200,
                cu_per_sec: Some(660),
                max_rps: Some(50),
                http_only: false,
            },
            EndpointSpec {
                url: "https://other.example".to_string(),
                weight: 50,
                cu_per_sec: None,
                max_rps: None,
                http_only: true,
            },
        ];
        let spec = ChainSpec {
            name: "rich".to_string(),
            chain_id: 1,
            rpc_urls: vec!["https://legacy.example".into()],
            rpc_endpoints: rich.clone(),
            allow_broadcast: false,
            etherscan_api_url: None,
            display_name: None,
            native_symbol: "ETH".into(),
            native_decimals: 18,
            legacy_tx: false,
            op_stack: false,
        };
        assert_eq!(spec.endpoints(), rich);
    }

    #[test]
    fn endpoints_round_trip_toml() {
        // A chain declared with only `rpc_endpoints` must round-trip
        // losslessly through TOML.
        let toml_text = r#"
            name = "rt"
            chain_id = 1
            rpc_urls = []

            [[rpc_endpoints]]
            url = "wss://primary.example"
            weight = 200
            cu_per_sec = 660
            max_rps = 25

            [[rpc_endpoints]]
            url = "https://secondary.example"
        "#;
        let parsed: ChainSpec = toml::from_str(toml_text).unwrap();
        assert_eq!(parsed.rpc_endpoints.len(), 2);
        assert_eq!(parsed.rpc_endpoints[0].url, "wss://primary.example");
        assert_eq!(parsed.rpc_endpoints[0].weight, 200);
        assert_eq!(parsed.rpc_endpoints[0].cu_per_sec, Some(660));
        assert_eq!(parsed.rpc_endpoints[0].max_rps, Some(25));
        assert!(!parsed.rpc_endpoints[0].http_only);
        // Unspecified knobs use the schema defaults.
        assert_eq!(parsed.rpc_endpoints[1].weight, default_endpoint_weight());
        assert!(parsed.rpc_endpoints[1].cu_per_sec.is_none());
        assert!(parsed.rpc_endpoints[1].max_rps.is_none());
        assert!(!parsed.rpc_endpoints[1].http_only);

        let s = toml::to_string(&parsed).unwrap();
        let back: ChainSpec = toml::from_str(&s).unwrap();
        assert_eq!(back, parsed);
    }

    #[test]
    fn chain_spec_defaults_apply_when_missing_fields() {
        let toml_text = r#"
            name = "minimal"
            chain_id = 42
            rpc_urls = ["http://x"]
        "#;
        let c: ChainSpec = toml::from_str(toml_text).unwrap();
        assert_eq!(c.name, "minimal");
        assert_eq!(c.chain_id, 42);
        // serde defaults should fill in everything else
        assert!(!c.allow_broadcast);
        assert_eq!(c.native_symbol, "ETH");
        assert_eq!(c.native_decimals, 18);
        assert!(!c.legacy_tx);
        assert!(c.etherscan_api_url.is_none());
        assert!(c.display_name.is_none());
    }
}
