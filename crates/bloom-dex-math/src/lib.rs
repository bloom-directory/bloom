//! Pure swap math for the bloom DEX petals.
//!
//! This crate is a normal workspace library (not a petal). It is linked at
//! compile time by `bloom-petal-dex-cpmm` and `bloom-petal-dex-router` so
//! that multi-hop math stays self-contained without cross-petal calls.

mod sqrt;

pub use sqrt::integer_sqrt;

// ─── Error type ──────────────────────────────────────────────────────────────

/// Errors that can arise from DEX math operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MathError {
    #[error("insufficient liquidity")]
    InsufficientLiquidity,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("zero reserves")]
    ZeroReserves,
    #[error("zero amount in")]
    ZeroAmountIn,
    #[error("output exceeds maximum allowed")]
    MaxOutExceeded,
    #[error("zero LP supply")]
    ZeroLpSupply,
}

// ─── SwapStrategy trait ───────────────────────────────────────────────────────

/// A pure, zero-allocation swap strategy.
///
/// All functions are associated (no `&self`); the strategy is a zero-sized
/// marker type. Strategy-specific configuration is passed through `Params`.
pub trait SwapStrategy {
    /// Strategy-specific configuration (e.g. fee tier).
    type Params;

    /// Compute the output amount for a given input *without* changing state.
    fn quote(
        reserve_in: u128,
        reserve_out: u128,
        amount_in: u128,
        params: &Self::Params,
    ) -> Result<u128, MathError>;

    /// Compute the swap and return the updated reserves plus the output amount.
    ///
    /// Returns `(new_reserve_in, new_reserve_out, amount_out)`.
    fn apply_swap(
        reserve_in: u128,
        reserve_out: u128,
        amount_in: u128,
        params: &Self::Params,
    ) -> Result<(u128, u128, u128), MathError>;

    /// Compute how much of each token to take and how many LP tokens to mint.
    ///
    /// Returns `(amount_a_taken, amount_b_taken, lp_minted)`.
    fn add_liquidity(
        reserve_a: u128,
        reserve_b: u128,
        amount_a: u128,
        amount_b: u128,
        lp_supply: u128,
    ) -> Result<(u128, u128, u128), MathError>;

    /// Compute how much of each token to return when burning LP tokens.
    ///
    /// Returns `(amount_a_out, amount_b_out)`.
    fn remove_liquidity(
        reserve_a: u128,
        reserve_b: u128,
        lp_supply: u128,
        lp_burned: u128,
    ) -> Result<(u128, u128), MathError>;
}

// ─── ConstantProduct strategy ─────────────────────────────────────────────────

/// Marker type for the constant-product (x·y = k) AMM strategy.
pub struct ConstantProduct;

/// Parameters for the constant-product strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstantProductParams {
    /// Fee in basis points (e.g. 30 = 0.30%).
    pub fee_bps: u16,
}

impl SwapStrategy for ConstantProduct {
    type Params = ConstantProductParams;

    fn quote(
        reserve_in: u128,
        reserve_out: u128,
        amount_in: u128,
        params: &ConstantProductParams,
    ) -> Result<u128, MathError> {
        if reserve_in == 0 || reserve_out == 0 {
            return Err(MathError::ZeroReserves);
        }
        if amount_in == 0 {
            return Err(MathError::ZeroAmountIn);
        }

        // amount_in_with_fee = amount_in * (10_000 - fee_bps) / 10_000
        let fee_factor = 10_000u128 - u128::from(params.fee_bps);
        let amount_in_with_fee = amount_in
            .checked_mul(fee_factor)
            .ok_or(MathError::Overflow)?
            / 10_000;

        // amount_out = reserve_out * amount_in_with_fee / (reserve_in + amount_in_with_fee)
        let numerator = reserve_out
            .checked_mul(amount_in_with_fee)
            .ok_or(MathError::Overflow)?;
        let denominator = reserve_in
            .checked_add(amount_in_with_fee)
            .ok_or(MathError::Overflow)?;

        let amount_out = numerator / denominator;

        if amount_out == 0 {
            return Err(MathError::InsufficientLiquidity);
        }
        if amount_out >= reserve_out {
            return Err(MathError::MaxOutExceeded);
        }

        Ok(amount_out)
    }

    fn apply_swap(
        reserve_in: u128,
        reserve_out: u128,
        amount_in: u128,
        params: &ConstantProductParams,
    ) -> Result<(u128, u128, u128), MathError> {
        let amount_out = Self::quote(reserve_in, reserve_out, amount_in, params)?;

        let new_reserve_in = reserve_in
            .checked_add(amount_in)
            .ok_or(MathError::Overflow)?;
        let new_reserve_out = reserve_out
            .checked_sub(amount_out)
            .ok_or(MathError::Overflow)?;

        Ok((new_reserve_in, new_reserve_out, amount_out))
    }

    fn add_liquidity(
        reserve_a: u128,
        reserve_b: u128,
        amount_a: u128,
        amount_b: u128,
        lp_supply: u128,
    ) -> Result<(u128, u128, u128), MathError> {
        if lp_supply == 0 {
            // Initial deposit: mint = sqrt(amount_a * amount_b)
            let product = amount_a.checked_mul(amount_b).ok_or(MathError::Overflow)?;
            let lp_minted = integer_sqrt(product);
            if lp_minted == 0 {
                return Err(MathError::InsufficientLiquidity);
            }
            Ok((amount_a, amount_b, lp_minted))
        } else {
            // Subsequent deposit: mint proportional to existing supply.
            // mint = min(amount_a * lp_supply / reserve_a,
            //            amount_b * lp_supply / reserve_b)
            if reserve_a == 0 || reserve_b == 0 {
                return Err(MathError::ZeroReserves);
            }

            let mint_a = amount_a.checked_mul(lp_supply).ok_or(MathError::Overflow)? / reserve_a;
            let mint_b = amount_b.checked_mul(lp_supply).ok_or(MathError::Overflow)? / reserve_b;

            let lp_minted = mint_a.min(mint_b);
            if lp_minted == 0 {
                return Err(MathError::InsufficientLiquidity);
            }

            // Pull proportional amounts; the caller deposits at most the
            // amounts corresponding to the limiting side.
            let taken_a = lp_minted
                .checked_mul(reserve_a)
                .ok_or(MathError::Overflow)?
                / lp_supply;
            let taken_b = lp_minted
                .checked_mul(reserve_b)
                .ok_or(MathError::Overflow)?
                / lp_supply;

            Ok((taken_a, taken_b, lp_minted))
        }
    }

    fn remove_liquidity(
        reserve_a: u128,
        reserve_b: u128,
        lp_supply: u128,
        lp_burned: u128,
    ) -> Result<(u128, u128), MathError> {
        if lp_supply == 0 {
            return Err(MathError::ZeroLpSupply);
        }
        if lp_burned == 0 {
            return Err(MathError::ZeroAmountIn);
        }
        if lp_burned > lp_supply {
            return Err(MathError::InsufficientLiquidity);
        }

        // amount_a = reserve_a * lp_burned / lp_supply
        let amount_a = reserve_a
            .checked_mul(lp_burned)
            .ok_or(MathError::Overflow)?
            / lp_supply;
        let amount_b = reserve_b
            .checked_mul(lp_burned)
            .ok_or(MathError::Overflow)?
            / lp_supply;

        Ok((amount_a, amount_b))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Convenience alias
    fn params(fee_bps: u16) -> ConstantProductParams {
        ConstantProductParams { fee_bps }
    }

    // ── integer_sqrt ──────────────────────────────────────────────────────────

    #[test]
    fn sqrt_zero() {
        assert_eq!(integer_sqrt(0), 0);
    }

    #[test]
    fn sqrt_one() {
        assert_eq!(integer_sqrt(1), 1);
    }

    #[test]
    fn sqrt_four() {
        assert_eq!(integer_sqrt(4), 2);
    }

    #[test]
    fn sqrt_hundred() {
        assert_eq!(integer_sqrt(100), 10);
    }

    #[test]
    fn sqrt_non_perfect_square() {
        // floor(sqrt(2)) = 1
        assert_eq!(integer_sqrt(2), 1);
        // floor(sqrt(8)) = 2
        assert_eq!(integer_sqrt(8), 2);
        // floor(sqrt(99)) = 9
        assert_eq!(integer_sqrt(99), 9);
    }

    #[test]
    fn sqrt_large() {
        // floor(sqrt(u64::MAX)) = u32::MAX
        let n = u128::from(u64::MAX);
        let s = integer_sqrt(n);
        assert!(s * s <= n);
        assert!((s + 1) * (s + 1) > n);
    }

    #[test]
    fn sqrt_near_u128_max() {
        // u128::MAX = 2^128 - 1; floor(sqrt) = 2^64 - 1
        let n = u128::MAX;
        let s = integer_sqrt(n);
        assert!(s * s <= n);
        // (s+1)^2 would overflow u128, which is expected — just check s^2 ≤ n
        let (sq_plus_one, overflow) = (s + 1).overflowing_mul(s + 1);
        assert!(overflow || sq_plus_one > n);
    }

    // ── CPMM quote ────────────────────────────────────────────────────────────

    #[test]
    fn quote_no_fee_basic() {
        // reserve_in=1000, reserve_out=1000, amount_in=100, fee=0
        // expected: 1000*100/(1000+100) = 100000/1100 ≈ 90
        let out = ConstantProduct::quote(1000, 1000, 100, &params(0)).unwrap();
        assert_eq!(out, 90);
    }

    #[test]
    fn quote_uniswap_v2_30bps() {
        // Classic Uniswap V2 example: reserve_in=1000, reserve_out=1000,
        // amount_in=100, fee=30bps (0.3%)
        // amount_in_with_fee = 100 * 9970 / 10000 = 99 (integer div)
        // amount_out = 1000 * 99 / (1000 + 99) = 99000 / 1099 ≈ 90
        let out = ConstantProduct::quote(1000, 1000, 100, &params(30)).unwrap();
        assert_eq!(out, 90);
    }

    #[test]
    fn quote_large_reserves_uniswap_style() {
        // Simulate 1 ETH in, reserves of 1000 ETH / 1_600_000 USDC (1 ETH = 1600 USDC),
        // fee = 30bps. Use 6-decimal precision (1 USDC = 1_000_000) to stay in u128 range.
        // Note: 1_600_000e6 * 1e6 = 1.6e18 which is well under u128::MAX (~3.4e38).
        let one_eth = 1_000_000_000_000_000_000u128; // 1e18 (18-decimal ETH)
        let one_usdc = 1_000_000u128; // 1e6 (6-decimal USDC)
        let reserve_eth = 1_000 * one_eth; // 1000 ETH
        let reserve_usdc = 1_600_000 * one_usdc; // 1_600_000 USDC
        let amount_in = one_eth; // 1 ETH

        // reserve_usdc (1.6e12) * amount_in_with_fee (~1e18) = ~1.6e30 < u128::MAX (3.4e38) ✓
        let out =
            ConstantProduct::quote(reserve_eth, reserve_usdc, amount_in, &params(30)).unwrap();

        // amount_in_with_fee = 1e18 * 9970 / 10000 = 997_000_000_000_000_000
        // numerator = 1_600_000_000_000 * 997_000_000_000_000_000 ≈ 1.595e30
        // denominator = 1_000_000_000_000_000_000_000 + 9.97e17 ≈ 1.0009970e21
        // out ≈ 1_594 USDC (in units of 1e6), i.e. ~1594_000_000 raw
        // Approximately 1 ETH at market = 1597 USDC with 0.3% fee taken.
        assert!(out > 1_590 * one_usdc, "out={out}");
        assert!(out < 1_602 * one_usdc, "out={out}");
    }

    #[test]
    fn quote_zero_reserves_error() {
        assert_eq!(
            ConstantProduct::quote(0, 1000, 100, &params(30)),
            Err(MathError::ZeroReserves)
        );
        assert_eq!(
            ConstantProduct::quote(1000, 0, 100, &params(30)),
            Err(MathError::ZeroReserves)
        );
    }

    #[test]
    fn quote_zero_amount_in_error() {
        assert_eq!(
            ConstantProduct::quote(1000, 1000, 0, &params(30)),
            Err(MathError::ZeroAmountIn)
        );
    }

    #[test]
    fn quote_overflow_error() {
        // amount_in near u128::MAX causes overflow in amount_in * fee_factor
        assert_eq!(
            ConstantProduct::quote(u128::MAX / 2, u128::MAX / 2, u128::MAX, &params(0)),
            Err(MathError::Overflow)
        );
    }

    // ── CPMM apply_swap ───────────────────────────────────────────────────────

    #[test]
    fn apply_swap_updates_reserves() {
        let reserve_in = 1_000_000u128;
        let reserve_out = 1_000_000u128;
        let amount_in = 1_000u128;

        let (new_ri, new_ro, amount_out) =
            ConstantProduct::apply_swap(reserve_in, reserve_out, amount_in, &params(30)).unwrap();

        // new_reserve_in = reserve_in + amount_in
        assert_eq!(new_ri, reserve_in + amount_in);
        // new_reserve_out = reserve_out - amount_out
        assert_eq!(new_ro, reserve_out - amount_out);
        // k should be approximately preserved (or slightly higher due to fee)
        let k_before = reserve_in * reserve_out;
        let k_after = new_ri * new_ro;
        assert!(
            k_after >= k_before,
            "k decreased: before={k_before} after={k_after}"
        );
    }

    #[test]
    fn apply_swap_k_invariant_no_fee() {
        // With fee=0, k should be exactly preserved modulo integer rounding.
        let ri = 100_000u128;
        let ro = 200_000u128;
        let ai = 500u128;

        let (new_ri, new_ro, _) = ConstantProduct::apply_swap(ri, ro, ai, &params(0)).unwrap();

        let k_before = ri * ro;
        let k_after = new_ri * new_ro;
        // Due to integer division the invariant can only go up slightly.
        assert!(k_after >= k_before);
        // The increase should be small (≤ reserve_out units).
        assert!(k_after - k_before <= ro);
    }

    #[test]
    fn apply_swap_zero_amount_in_error() {
        assert_eq!(
            ConstantProduct::apply_swap(1000, 1000, 0, &params(30)),
            Err(MathError::ZeroAmountIn)
        );
    }

    // ── CPMM add_liquidity ────────────────────────────────────────────────────

    #[test]
    fn add_liquidity_initial_mint_uses_sqrt() {
        // lp_supply == 0 → mint = sqrt(amount_a * amount_b)
        let (taken_a, taken_b, lp_minted) =
            ConstantProduct::add_liquidity(0, 0, 400, 900, 0).unwrap();
        assert_eq!(taken_a, 400);
        assert_eq!(taken_b, 900);
        // sqrt(400 * 900) = sqrt(360_000) = 600
        assert_eq!(lp_minted, 600);
    }

    #[test]
    fn add_liquidity_initial_non_square() {
        let (_, _, lp_minted) = ConstantProduct::add_liquidity(0, 0, 100, 200, 0).unwrap();
        // sqrt(100 * 200) = sqrt(20_000) = 141 (floor)
        assert_eq!(lp_minted, 141);
    }

    #[test]
    fn add_liquidity_subsequent_proportional() {
        // Existing pool: reserve_a=1000, reserve_b=2000, lp_supply=1000
        // Deposit amount_a=100, amount_b=300 — only 100 A and 200 B should be taken
        // (A is the limiting side: mint_a=100*1000/1000=100, mint_b=300*1000/2000=150)
        let (taken_a, taken_b, lp_minted) =
            ConstantProduct::add_liquidity(1000, 2000, 100, 300, 1000).unwrap();
        // Limiting side: mint_a=100, mint_b=150 → min=100
        assert_eq!(lp_minted, 100);
        // taken proportional to lp_minted/lp_supply
        assert_eq!(taken_a, 100); // 100 * 1000 / 1000
        assert_eq!(taken_b, 200); // 100 * 2000 / 1000
    }

    #[test]
    fn add_liquidity_subsequent_b_limiting() {
        // reserve_a=1000, reserve_b=1000, lp_supply=500
        // Deposit 200 A, 100 B → mint_a=200*500/1000=100, mint_b=100*500/1000=50
        let (taken_a, taken_b, lp_minted) =
            ConstantProduct::add_liquidity(1000, 1000, 200, 100, 500).unwrap();
        assert_eq!(lp_minted, 50);
        assert_eq!(taken_a, 100); // 50 * 1000 / 500
        assert_eq!(taken_b, 100); // 50 * 1000 / 500
    }

    #[test]
    fn add_liquidity_zero_reserve_subsequent_error() {
        assert_eq!(
            ConstantProduct::add_liquidity(0, 1000, 100, 100, 500),
            Err(MathError::ZeroReserves)
        );
    }

    // ── CPMM remove_liquidity ─────────────────────────────────────────────────

    #[test]
    fn remove_liquidity_proportional() {
        // reserve_a=1000, reserve_b=2000, lp_supply=500, lp_burned=100
        // amount_a = 1000 * 100 / 500 = 200
        // amount_b = 2000 * 100 / 500 = 400
        let (a, b) = ConstantProduct::remove_liquidity(1000, 2000, 500, 100).unwrap();
        assert_eq!(a, 200);
        assert_eq!(b, 400);
    }

    #[test]
    fn remove_liquidity_full_burn() {
        // Burn all LP → get all reserves back
        let (a, b) = ConstantProduct::remove_liquidity(1234, 5678, 1000, 1000).unwrap();
        assert_eq!(a, 1234);
        assert_eq!(b, 5678);
    }

    #[test]
    fn remove_liquidity_zero_lp_supply_error() {
        assert_eq!(
            ConstantProduct::remove_liquidity(1000, 1000, 0, 100),
            Err(MathError::ZeroLpSupply)
        );
    }

    #[test]
    fn remove_liquidity_zero_burned_error() {
        assert_eq!(
            ConstantProduct::remove_liquidity(1000, 1000, 500, 0),
            Err(MathError::ZeroAmountIn)
        );
    }

    #[test]
    fn remove_liquidity_burn_exceeds_supply_error() {
        assert_eq!(
            ConstantProduct::remove_liquidity(1000, 1000, 500, 600),
            Err(MathError::InsufficientLiquidity)
        );
    }

    // ── Overflow path ─────────────────────────────────────────────────────────

    #[test]
    fn add_liquidity_initial_overflow() {
        // amount_a * amount_b overflows u128
        let huge = u128::MAX / 2 + 1;
        assert_eq!(
            ConstantProduct::add_liquidity(0, 0, huge, huge, 0),
            Err(MathError::Overflow)
        );
    }

    #[test]
    fn remove_liquidity_overflow() {
        // reserve_a=u128::MAX, lp_supply=2, lp_burned=2
        // reserve_a * lp_burned = u128::MAX * 2 overflows
        let result = ConstantProduct::remove_liquidity(u128::MAX, 1, 2, 2);
        assert_eq!(result, Err(MathError::Overflow));

        // Another case: reserve slightly above half of u128::MAX, lp_burned=2
        let result2 = ConstantProduct::remove_liquidity(u128::MAX / 2 + 1, 1, 2, 2);
        // (u128::MAX/2+1) * 2 overflows
        assert_eq!(result2, Err(MathError::Overflow));
    }
}
