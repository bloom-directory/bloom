//! Canonical well-known ERC-20 token table, shared across crates.
//!
//! Bloom has no per-chain token registry in config, so this small,
//! deliberately-minimal table (majors only) is the single source of truth
//! for symbol→address and symbol→decimals resolution. It lives in
//! `bloom-proto` so the send path (`bloom-tx`), the route path
//! the enso petal, and the VFS token surface (`bloom-vfs`) all resolve from
//! the *same* data instead of three hand-maintained tables that drift.
//!
//! Addresses are stored lowercase and re-checksummed by callers at display
//! time, so casing here can never be wrong.

/// A statically-known token for a given chain.
pub struct KnownToken {
    pub address: &'static str,
    pub symbol: &'static str,
    pub decimals: u8,
}

/// Well-known majors for `chain_id`. Empty slice for chains we don't have a
/// curated list for.
pub fn for_chain(chain_id: u64) -> &'static [KnownToken] {
    match chain_id {
        1 => ETHEREUM,
        8453 => BASE,
        10 => OPTIMISM,
        42161 => ARBITRUM,
        137 => POLYGON,
        _ => &[],
    }
}

/// Resolve a token by (chain, uppercased symbol). The caller is expected to
/// pass an already-uppercased symbol; matching is case-insensitive anyway.
pub fn resolve_symbol(chain_id: u64, symbol: &str) -> Option<&'static KnownToken> {
    for_chain(chain_id)
        .iter()
        .find(|t| t.symbol.eq_ignore_ascii_case(symbol))
}

const ETHEREUM: &[KnownToken] = &[
    KnownToken {
        address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        symbol: "USDC",
        decimals: 6,
    },
    KnownToken {
        address: "0xdac17f958d2ee523a2206206994597c13d831ec7",
        symbol: "USDT",
        decimals: 6,
    },
    KnownToken {
        address: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        symbol: "WETH",
        decimals: 18,
    },
    KnownToken {
        address: "0x6b175474e89094c44da98b954eedeac495271d0f",
        symbol: "DAI",
        decimals: 18,
    },
    KnownToken {
        address: "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
        symbol: "WBTC",
        decimals: 8,
    },
];

const BASE: &[KnownToken] = &[
    KnownToken {
        address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        symbol: "USDC",
        decimals: 6,
    },
    KnownToken {
        address: "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2",
        symbol: "USDT",
        decimals: 6,
    },
    KnownToken {
        address: "0x4200000000000000000000000000000000000006",
        symbol: "WETH",
        decimals: 18,
    },
    KnownToken {
        address: "0x50c5725949a6f0c72e6c4a641f24049a917db0cb",
        symbol: "DAI",
        decimals: 18,
    },
];

const OPTIMISM: &[KnownToken] = &[
    KnownToken {
        address: "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
        symbol: "USDC",
        decimals: 6,
    },
    KnownToken {
        address: "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58",
        symbol: "USDT",
        decimals: 6,
    },
    KnownToken {
        address: "0x4200000000000000000000000000000000000006",
        symbol: "WETH",
        decimals: 18,
    },
    KnownToken {
        address: "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1",
        symbol: "DAI",
        decimals: 18,
    },
];

const ARBITRUM: &[KnownToken] = &[
    KnownToken {
        address: "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
        symbol: "USDC",
        decimals: 6,
    },
    KnownToken {
        address: "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
        symbol: "USDT",
        decimals: 6,
    },
    KnownToken {
        address: "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
        symbol: "WETH",
        decimals: 18,
    },
    KnownToken {
        address: "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1",
        symbol: "DAI",
        decimals: 18,
    },
];

const POLYGON: &[KnownToken] = &[
    KnownToken {
        address: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
        symbol: "USDC",
        decimals: 6,
    },
    KnownToken {
        address: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
        symbol: "USDT",
        decimals: 6,
    },
    KnownToken {
        address: "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619",
        symbol: "WETH",
        decimals: 18,
    },
    KnownToken {
        address: "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063",
        symbol: "DAI",
        decimals: 18,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrum_usdc_resolves_to_6_decimals() {
        let t = resolve_symbol(42161, "USDC").expect("arbitrum usdc");
        assert_eq!(t.address, "0xaf88d065e77c8cc2239327c5edb3a432268e5831");
        assert_eq!(t.decimals, 6);
    }

    #[test]
    fn usdc_is_six_decimals_on_every_listed_chain() {
        for chain in [1u64, 8453, 10, 42161, 137] {
            let t = resolve_symbol(chain, "usdc").expect("usdc present");
            assert_eq!(t.decimals, 6, "chain {chain}");
        }
    }

    #[test]
    fn unknown_symbol_is_none() {
        assert!(resolve_symbol(42161, "FOOBAR").is_none());
        assert!(resolve_symbol(999, "USDC").is_none());
    }
}
