//! Stage-time MEV/sandwich heuristic. Pure function over a staged tx.

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolCall;
use serde::{Deserialize, Serialize};

sol! {
    #[allow(missing_docs)]
    interface IUniswapV2Router {
        function swapExactTokensForTokens(
            uint256 amountIn,
            uint256 amountOutMin,
            address[] calldata path,
            address to,
            uint256 deadline
        ) external returns (uint256[] memory amounts);

        function swapExactETHForTokens(
            uint256 amountOutMin,
            address[] calldata path,
            address to,
            uint256 deadline
        ) external payable returns (uint256[] memory amounts);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MevRisk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevRiskReport {
    pub risk: MevRisk,
    pub checks: Vec<String>,
    pub advice: String,
}

#[derive(Debug, Clone, Copy)]
pub struct HeuristicConfig {
    /// Warn if `(quoted - amountOutMin) / quoted` exceeds this (bps).
    pub max_slippage_bps: u32,
    /// Always flag high when amountIn (in wei or token units) exceeds
    /// this AND amountOutMin is zero.
    pub zero_min_amount_in_threshold: U256,
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        Self {
            max_slippage_bps: 100,
            zero_min_amount_in_threshold: U256::from(10u64).pow(U256::from(18u64)),
        }
    }
}

/// Quote oracle — abstracted so tests can inject a deterministic
/// quoter. Production wires this to `bloom-prices` or a direct
/// `eth_call` against a known quoter contract.
pub trait QuoteOracle: Send + Sync {
    /// Returns the expected output amount for `amount_in` of `path[0]`
    /// swapped along `path`, at the current block.
    fn quote(&self, amount_in: U256, path: &[Address]) -> Option<U256>;
}

pub struct StaticQuoter(pub U256);

impl QuoteOracle for StaticQuoter {
    fn quote(&self, _amount_in: U256, _path: &[Address]) -> Option<U256> {
        Some(self.0)
    }
}

/// If the calldata decodes as a known DEX swap, return the addresses
/// in the path. `path[0]` is the input token; the router address
/// itself is the contract being called and is not in this list.
pub fn decode_swap_path(calldata: &Bytes) -> Option<Vec<Address>> {
    if let Ok(c) = IUniswapV2Router::swapExactTokensForTokensCall::abi_decode(calldata) {
        return Some(c.path);
    }
    if let Ok(c) = IUniswapV2Router::swapExactETHForTokensCall::abi_decode(calldata) {
        return Some(c.path);
    }
    None
}

pub fn evaluate(
    calldata: &Bytes,
    value: U256,
    cfg: &HeuristicConfig,
    quoter: &dyn QuoteOracle,
) -> MevRiskReport {
    // Try Uniswap V2 swapExactTokensForTokens.
    if let Ok(c) = IUniswapV2Router::swapExactTokensForTokensCall::abi_decode(calldata) {
        return evaluate_swap(c.amountIn, c.amountOutMin, &c.path, cfg, quoter);
    }
    // Try Uniswap V2 swapExactETHForTokens — amountIn comes from `value`.
    if let Ok(c) = IUniswapV2Router::swapExactETHForTokensCall::abi_decode(calldata) {
        return evaluate_swap(value, c.amountOutMin, &c.path, cfg, quoter);
    }

    MevRiskReport {
        risk: MevRisk::Low,
        checks: vec!["calldata_not_a_known_swap".to_string()],
        advice: String::new(),
    }
}

fn evaluate_swap(
    amount_in: U256,
    amount_out_min: U256,
    path: &[Address],
    cfg: &HeuristicConfig,
    quoter: &dyn QuoteOracle,
) -> MevRiskReport {
    let mut checks = Vec::new();
    let mut risk = MevRisk::Low;
    let mut advice = String::new();

    // Check 2 first (cheap, no oracle call).
    if amount_out_min.is_zero() && amount_in >= cfg.zero_min_amount_in_threshold {
        checks.push("amount_out_min_zero".to_string());
        risk = MevRisk::High;
        advice = format!(
            "amountOutMin is zero for amountIn = {}; the swap accepts any output. \
             Set amountOutMin to at least 99% of the current quote.",
            amount_in
        );
        return MevRiskReport {
            risk,
            checks,
            advice,
        };
    }

    // Check 1: slippage exposure vs current quote.
    if let Some(quote) = quoter.quote(amount_in, path) {
        if quote.is_zero() {
            checks.push("quote_unavailable".to_string());
        } else if amount_out_min < quote {
            let diff = quote - amount_out_min;
            // bps = diff * 10_000 / quote
            let bps = diff.saturating_mul(U256::from(10_000u64)) / quote;
            checks.push("slippage_exposure".to_string());
            if bps > U256::from(cfg.max_slippage_bps) {
                risk = MevRisk::High;
                advice = format!(
                    "amountOutMin is {} bps below current quote (threshold {}); \
                     tighten slippage or route through a private RPC.",
                    bps, cfg.max_slippage_bps
                );
            }
        }
    } else {
        checks.push("quote_unavailable".to_string());
    }

    MevRiskReport {
        risk,
        checks,
        advice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::hex;

    fn load_fixture(name: &str) -> Bytes {
        let path = format!("tests/fixtures/{name}");
        let hex_str = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        Bytes::from(hex::decode(hex_str.trim()).unwrap())
    }

    #[test]
    fn unknown_calldata_is_low_risk() {
        let cfg = HeuristicConfig::default();
        let q = StaticQuoter(U256::ZERO);
        let r = evaluate(
            &Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            U256::ZERO,
            &cfg,
            &q,
        );
        assert_eq!(r.risk, MevRisk::Low);
        assert!(r.checks.iter().any(|s| s == "calldata_not_a_known_swap"));
    }

    #[test]
    fn uniswap_v2_swap_with_500bps_slippage_is_high_at_default_threshold() {
        let cfg = HeuristicConfig::default(); // max_slippage_bps = 100
        let quoted: U256 = U256::from(10u64).pow(U256::from(18u64)); // 1e18 expected out
        let q = StaticQuoter(quoted);
        let cd = load_fixture("uniswap_v2_swap.hex");
        let r = evaluate(&cd, U256::ZERO, &cfg, &q);
        assert_eq!(r.risk, MevRisk::High);
        assert!(r.checks.iter().any(|s| s == "slippage_exposure"));
    }

    #[test]
    fn uniswap_v2_swap_with_500bps_slippage_is_low_when_threshold_relaxed() {
        let cfg = HeuristicConfig {
            max_slippage_bps: 1_000,
            ..HeuristicConfig::default()
        };
        let quoted: U256 = U256::from(10u64).pow(U256::from(18u64));
        let q = StaticQuoter(quoted);
        let cd = load_fixture("uniswap_v2_swap.hex");
        let r = evaluate(&cd, U256::ZERO, &cfg, &q);
        assert_eq!(r.risk, MevRisk::Low);
    }

    #[test]
    fn zero_amount_out_min_above_threshold_is_high() {
        let cfg = HeuristicConfig::default();
        let q = StaticQuoter(U256::ZERO);
        let cd = load_fixture("uniswap_v2_zero_min.hex");
        let r = evaluate(&cd, U256::ZERO, &cfg, &q);
        assert_eq!(r.risk, MevRisk::High);
        assert!(r.checks.iter().any(|s| s == "amount_out_min_zero"));
    }

    #[test]
    fn decode_swap_path_returns_path_addresses() {
        let cd = load_fixture("uniswap_v2_swap.hex");
        let path = decode_swap_path(&cd).unwrap();
        assert_eq!(path.len(), 2);
        let mut a1 = [0u8; 20];
        a1[19] = 1;
        let mut a2 = [0u8; 20];
        a2[19] = 2;
        assert_eq!(path[0], Address::from(a1));
        assert_eq!(path[1], Address::from(a2));
    }
}
