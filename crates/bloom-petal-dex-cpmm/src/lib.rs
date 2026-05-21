//! `/bloom/dex/strategy/cpmm` — ConstantProduct swap strategy petal.
//!
//! This petal's primary purpose is to define `ConstantProduct` as an
//! on-chain *type* with a stable `petal_hash`, so other petals can
//! reference `Pool<A, B, ConstantProduct>` in their type tags.
//!
//! `ConstantProduct` is a phantom witness type — it is never instantiated,
//! never owned, and never stored. It is declared via `#[object(no_abilities)]`
//! (zero abilities: can't be stored, transferred, copied, or dropped),
//! which makes it an effective phantom type tag in the manifest while
//! remaining a concrete Rust type usable in generics.
//!
//! The actual math lives in `bloom-dex-math` (a normal workspace library,
//! not a petal) — see `ConstantProduct::quote` / `apply_swap` etc. there.

#![deny(missing_docs)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use bloom_resource_macros as bloom;

pub use bloom_dex_math::{ConstantProduct, ConstantProductParams, MathError, SwapStrategy};

/// Petal body for `/bloom/dex/strategy/cpmm`.
///
/// Every `pub fn` inside this module becomes a `__petal_<name>` wasm
/// export. The `#[bloom::petal]` macro embeds a `PetalManifestV0`
/// custom section (spec §8) listing the types and entry points below.
#[bloom::petal(path = "/bloom/dex/strategy/cpmm", version = "0.1.0")]
pub mod cpmm {
    use bloom_dex_math::SwapStrategy as _;
    #[allow(unused_imports)]
    use bloom_resource_macros::{capability, object};

    // -----------------------------------------------------------------
    // Type declarations
    // -----------------------------------------------------------------

    /// Phantom witness type for the constant-product (x·y = k) AMM strategy.
    ///
    /// Declared with `no_abilities` so it can never be stored, transferred,
    /// copied, or dropped — it exists solely as a type-tag anchor. Other
    /// petals use `Pool<A, B, ConstantProduct>` in their type tags; the
    /// `petal_hash` of this petal pins the `ConstantProduct` type identity
    /// in the chain's object store.
    ///
    /// The actual swap math is in `bloom-dex-math::ConstantProduct` (via the
    /// `SwapStrategy` impl); this declaration is purely a manifest entry.
    #[object(no_abilities)]
    pub struct ConstantProductMarker;

    // -----------------------------------------------------------------
    // Entry points
    // -----------------------------------------------------------------

    /// Returns the petal version as a `u32`.
    ///
    /// This is the minimum required wasm export — every petal must have at
    /// least one entry point so the chain VM has a callable symbol to
    /// validate the petal at deploy time.
    pub fn version() -> u32 {
        1
    }

    /// Preview the output of a constant-product swap without modifying state.
    ///
    /// Delegates to `bloom_dex_math::ConstantProduct::quote`. Useful for
    /// indexers and wallets to compute expected output before submitting a
    /// transaction.
    ///
    /// # Arguments
    ///
    /// - `reserve_in` — current reserve of the input token.
    /// - `reserve_out` — current reserve of the output token.
    /// - `amount_in` — amount of the input token to swap.
    /// - `fee_bps` — fee in basis points (e.g. `30` = 0.30%).
    ///
    /// # Returns
    ///
    /// The expected output amount, or `0` if the math fails (zero reserves,
    /// zero amount, overflow, or insufficient liquidity).
    pub fn cpmm_quote_preview(
        reserve_in: u128,
        reserve_out: u128,
        amount_in: u128,
        fee_bps: u16,
    ) -> u128 {
        let params = bloom_dex_math::ConstantProductParams { fee_bps };
        bloom_dex_math::ConstantProduct::quote(reserve_in, reserve_out, amount_in, &params)
            .unwrap_or(0)
    }
}

// -----------------------------------------------------------------------------
// Unit tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use bloom_dex_math::{ConstantProduct, ConstantProductParams, MathError, SwapStrategy};

    use crate::cpmm;

    #[test]
    fn version_returns_1() {
        assert_eq!(cpmm::version(), 1);
    }

    #[test]
    fn cpmm_quote_preview_matches_math_happy_path() {
        // Use the same values as the bloom-dex-math basic test:
        // reserve_in=1000, reserve_out=1000, amount_in=100, fee=30bps → 90
        let preview = cpmm::cpmm_quote_preview(1000, 1000, 100, 30);
        let expected =
            ConstantProduct::quote(1000, 1000, 100, &ConstantProductParams { fee_bps: 30 })
                .unwrap();
        assert_eq!(preview, expected);
        assert_eq!(preview, 90);
    }

    #[test]
    fn cpmm_quote_preview_zero_amount_returns_zero() {
        // amount_in == 0 → MathError::ZeroAmountIn → preview returns 0
        let preview = cpmm::cpmm_quote_preview(1000, 1000, 0, 30);
        assert_eq!(preview, 0);
    }

    #[test]
    fn cpmm_quote_preview_zero_reserves_returns_zero() {
        let preview = cpmm::cpmm_quote_preview(0, 1000, 100, 30);
        assert_eq!(preview, 0);
        let preview2 = cpmm::cpmm_quote_preview(1000, 0, 100, 30);
        assert_eq!(preview2, 0);
    }

    #[test]
    fn cpmm_quote_preview_large_values() {
        let one_eth = 1_000_000_000_000_000_000u128;
        let one_usdc = 1_000_000u128;
        let reserve_eth = 1_000 * one_eth;
        let reserve_usdc = 1_600_000 * one_usdc;

        let preview = cpmm::cpmm_quote_preview(reserve_eth, reserve_usdc, one_eth, 30);
        let expected = ConstantProduct::quote(
            reserve_eth,
            reserve_usdc,
            one_eth,
            &ConstantProductParams { fee_bps: 30 },
        )
        .unwrap();
        assert_eq!(preview, expected);
        assert!(preview > 1_590 * one_usdc);
        assert!(preview < 1_602 * one_usdc);
    }

    /// Compile-time test: `ConstantProduct` (from bloom-dex-math) is usable
    /// as a strategy generic parameter without extra bounds. This exercises
    /// the pattern `Pool<A, B, ConstantProduct>` that bloom-petal-dex-pool
    /// will use. The stub `Pool` here stands in for the real one.
    #[test]
    fn constant_product_usable_as_strategy_type_param() {
        // Minimal stub for Pool<A, B, S> — no bounds on S beyond what we use.
        struct Pool<A, B, S> {
            reserve_a: u128,
            reserve_b: u128,
            _marker: core::marker::PhantomData<(A, B, S)>,
        }

        struct TokenA;
        struct TokenB;

        // This must compile: Pool<TokenA, TokenB, ConstantProduct>
        let pool = Pool::<TokenA, TokenB, ConstantProduct> {
            reserve_a: 1_000,
            reserve_b: 2_000,
            _marker: core::marker::PhantomData,
        };

        // And we can call the strategy via the associated function:
        let out = ConstantProduct::quote(
            pool.reserve_a,
            pool.reserve_b,
            100,
            &ConstantProductParams { fee_bps: 30 },
        )
        .unwrap();
        assert!(out > 0);
    }

    #[test]
    fn math_error_variants_accessible() {
        // Verify MathError is re-exported and usable
        let e: MathError = MathError::ZeroReserves;
        assert_eq!(format!("{e}"), "zero reserves");
    }
}
