#![deprecated(
    since = "0.2.0",
    note = "use bloom-resource framework — see docs/specs/2026-05-20-bloom-native-contracts-design.md"
)]
#![allow(deprecated)]
//! bloom-dex-router — stateless Uniswap-v2-style router petal for bloom-chain.
//!
//! Phase 7e of the bloom-rust-contracts migration. The router was the last
//! DEX surface still bound to the legacy `bloom_chain_abi::contract!` DSL; it
//! now declares its ABI through the framework primitives (`#[bloom::contract]`,
//! `#[bloom::interface]`, `#[storage]`) like the other DEX petals.
//!
//! Three config slots are written once at init time:
//!   - `factory`   — factory petal address (slot tag `"router.factory"`)
//!   - `wloom`     — wrapped-LOOM petal address (slot tag `"router.wloom"`)
//!   - `self_addr` — router's own pre-computed address, slot tag
//!                   `"router.self"` (needed by LOOM-output swaps which
//!                   temporarily receive wLOOM into the router before
//!                   unwrapping to native LOOM)
//!
//! Init calldata is the 96-byte `factory || wloom || router_self` blob,
//! decoded into [`InitConfig`]. Strict decoding rejects any other length.
//!
//! Several methods have multi-value return shapes. Unlike the legacy
//! `contract!` DSL, the framework natively encodes tuples and `Vec<T>` from
//! the handler return type:
//!   - `add_liquidity` / `add_liquidity_loom` → `(U256, U256, U256)` (96 bytes)
//!   - `remove_liquidity` / `remove_liquidity_loom` → `(U256, U256)` (64 bytes)
//!   - `swap_*` and `get_amounts_*` → `Vec<U256>` (`u16 length || 32*n bytes`)
//!
//! Wire encoding matches the pre-migration router byte-for-byte so off-chain
//! tools (dex CLI) continue to deserialize unchanged.
//!
//! # ABI
//!
//! Selector strings follow the framework's canonical form:
//! `router.method(lowercase_types)` where generic args are recursed
//! (`Vec<Address>` → `vec<address>`). They are not byte-compatible with the
//! legacy router's selectors (which used `Vec<Address>` PascalCase). All
//! consumers — CLI, integration tests, peer contracts — read the typed
//! `Router` interface or the `calls` module below rather than rebuilding
//! signature strings by hand.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![allow(clippy::doc_overindented_list_items, clippy::too_many_arguments)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use bloom_contract::context::LoomValue;
use bloom_contract::prelude::*;
use bloom_dex_erc20::{Erc20, Erc20Calls};
use bloom_dex_factory::{Factory, FactoryCalls};
use bloom_dex_pair::{Pair, PairCalls};
use bloom_dex_wloom::{Wloom, WloomCalls};

// ---------------------------------------------------------------------------
// Router interface — DEX spec §4.1 surface.
// ---------------------------------------------------------------------------

#[bloom_contract::interface(domain = "router")]
pub trait Router {
    // Pure quoting helpers — single u256 returns.
    fn quote(amount_a: U256, reserve_a: U256, reserve_b: U256) -> Result<U256>;
    fn get_amount_out(amount_in: U256, reserve_in: U256, reserve_out: U256) -> Result<U256>;
    fn get_amount_in(amount_out: U256, reserve_in: U256, reserve_out: U256) -> Result<U256>;

    // Pure quoting (multi-hop) — Vec<U256> packed return.
    fn get_amounts_out(amount_in: U256, path: Vec<Address>) -> Result<Vec<U256>>;
    fn get_amounts_in(amount_out: U256, path: Vec<Address>) -> Result<Vec<U256>>;

    // Liquidity — multi-u256 returns.
    fn add_liquidity(
        token_a: Address,
        token_b: Address,
        amount_a_desired: U256,
        amount_b_desired: U256,
        amount_a_min: U256,
        amount_b_min: U256,
        to: Address,
        deadline: u64,
    ) -> Result<(U256, U256, U256)>;

    fn add_liquidity_loom(
        token: Address,
        amount_token_desired: U256,
        amount_token_min: U256,
        amount_loom_min: U256,
        to: Address,
        deadline: u64,
    ) -> Result<(U256, U256, U256)>;

    fn remove_liquidity(
        token_a: Address,
        token_b: Address,
        liquidity: U256,
        amount_a_min: U256,
        amount_b_min: U256,
        to: Address,
        deadline: u64,
    ) -> Result<(U256, U256)>;

    fn remove_liquidity_loom(
        token: Address,
        liquidity: U256,
        amount_token_min: U256,
        amount_loom_min: U256,
        to: Address,
        deadline: u64,
    ) -> Result<(U256, U256)>;

    // Swaps — Vec<U256> packed return.
    fn swap_exact_tokens_for_tokens(
        amount_in: U256,
        amount_out_min: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>>;

    fn swap_tokens_for_exact_tokens(
        amount_out: U256,
        amount_in_max: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>>;

    fn swap_exact_loom_for_tokens(
        amount_out_min: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>>;

    fn swap_tokens_for_exact_loom(
        amount_out: U256,
        amount_in_max: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>>;

    fn swap_exact_tokens_for_loom(
        amount_in: U256,
        amount_out_min: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>>;

    fn swap_loom_for_exact_tokens(
        amount_out: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>>;
}

// ---------------------------------------------------------------------------
// Init config — 96 bytes: factory || wloom || router_self.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, AbiEncode, AbiDecode, AbiType)]
pub struct InitConfig {
    pub factory_addr: Address,
    pub wloom_addr: Address,
    pub router_self_addr: Address,
}

// ---------------------------------------------------------------------------
// Pure math helpers (DEX spec §9.3). Free `pub fn` so host-side unit tests
// can call them directly; the contract handlers re-export them through
// `router::*` arms below.
// ---------------------------------------------------------------------------

/// `quote(amountA, reserveA, reserveB) = amountA * reserveB / reserveA`.
pub fn quote(amount_a: U256, reserve_a: U256, reserve_b: U256) -> Result<U256> {
    if amount_a.is_zero() {
        return Err(ContractError::from_str("router: quote: zero amount"));
    }
    if reserve_a.is_zero() || reserve_b.is_zero() {
        return Err(ContractError::from_str("router: quote: zero reserves"));
    }
    amount_a
        .checked_mul(reserve_b)
        .and_then(|v| v.checked_div(reserve_a))
        .ok_or_else(|| ContractError::from_str("router: quote: overflow"))
}

/// `getAmountOut(amountIn, reserveIn, reserveOut) = (amountIn * 997 * reserveOut)
/// / (reserveIn * 1000 + amountIn * 997)`.
pub fn get_amount_out(amount_in: U256, reserve_in: U256, reserve_out: U256) -> Result<U256> {
    if amount_in.is_zero() {
        return Err(ContractError::from_str(
            "router: getAmountOut: zero amountIn",
        ));
    }
    if reserve_in.is_zero() || reserve_out.is_zero() {
        return Err(ContractError::from_str(
            "router: getAmountOut: zero reserves",
        ));
    }
    let n997 = U256::from_u64(997);
    let n1000 = U256::from_u64(1000);

    let amount_in_with_fee = amount_in
        .checked_mul(n997)
        .ok_or_else(|| ContractError::from_str("router: getAmountOut: overflow"))?;
    let numerator = amount_in_with_fee
        .checked_mul(reserve_out)
        .ok_or_else(|| ContractError::from_str("router: getAmountOut: overflow"))?;
    let denominator = reserve_in
        .checked_mul(n1000)
        .and_then(|v| v.checked_add(amount_in_with_fee))
        .ok_or_else(|| ContractError::from_str("router: getAmountOut: overflow"))?;

    numerator
        .checked_div(denominator)
        .ok_or_else(|| ContractError::from_str("router: getAmountOut: div by zero"))
}

/// `getAmountIn(amountOut, reserveIn, reserveOut) =
///   (reserveIn * amountOut * 1000) / ((reserveOut - amountOut) * 997) + 1`.
pub fn get_amount_in(amount_out: U256, reserve_in: U256, reserve_out: U256) -> Result<U256> {
    if amount_out.is_zero() {
        return Err(ContractError::from_str(
            "router: getAmountIn: zero amountOut",
        ));
    }
    if reserve_in.is_zero() || reserve_out.is_zero() {
        return Err(ContractError::from_str(
            "router: getAmountIn: zero reserves",
        ));
    }
    if amount_out >= reserve_out {
        return Err(ContractError::from_str(
            "router: getAmountIn: amountOut >= reserveOut",
        ));
    }
    let n997 = U256::from_u64(997);
    let n1000 = U256::from_u64(1000);

    let numerator = reserve_in
        .checked_mul(amount_out)
        .and_then(|v| v.checked_mul(n1000))
        .ok_or_else(|| ContractError::from_str("router: getAmountIn: overflow"))?;
    let denominator = reserve_out
        .checked_sub(amount_out)
        .and_then(|v| v.checked_mul(n997))
        .ok_or_else(|| ContractError::from_str("router: getAmountIn: overflow"))?;

    let div = numerator
        .checked_div(denominator)
        .ok_or_else(|| ContractError::from_str("router: getAmountIn: div by zero"))?;
    div.checked_add(U256::from_u64(1))
        .ok_or_else(|| ContractError::from_str("router: getAmountIn: overflow"))
}

/// Compute the optimal (amountA, amountB) for adding liquidity given existing
/// reserves and desired/min amounts. Pure — exposed for host-side testing.
pub fn compute_liquidity_amounts(
    amount_a_desired: U256,
    amount_b_desired: U256,
    amount_a_min: U256,
    amount_b_min: U256,
    reserve_a: U256,
    reserve_b: U256,
) -> Result<(U256, U256)> {
    if reserve_a.is_zero() && reserve_b.is_zero() {
        return Ok((amount_a_desired, amount_b_desired));
    }
    let amount_b_optimal = quote(amount_a_desired, reserve_a, reserve_b)?;
    if amount_b_optimal <= amount_b_desired {
        if amount_b_optimal < amount_b_min {
            return Err(ContractError::from_str(
                "router: addLiquidity: insufficient B amount",
            ));
        }
        return Ok((amount_a_desired, amount_b_optimal));
    }
    let amount_a_optimal = quote(amount_b_desired, reserve_b, reserve_a)?;
    if amount_a_optimal > amount_a_desired {
        return Err(ContractError::from_str(
            "router: addLiquidity: optimal A exceeds desired",
        ));
    }
    if amount_a_optimal < amount_a_min {
        return Err(ContractError::from_str(
            "router: addLiquidity: insufficient A amount",
        ));
    }
    Ok((amount_a_optimal, amount_b_desired))
}

// ---------------------------------------------------------------------------
// Contract module — storage, init, and handler arms.
// ---------------------------------------------------------------------------

#[bloom_contract::contract(domain = "router", interfaces(Router))]
pub mod router {
    use super::*;

    // -----------------------------------------------------------------------
    // Storage — three Address scalars with compat_tag slots preserved from
    // the legacy contract.
    // -----------------------------------------------------------------------

    #[bloom_contract::storage(domain = "router")]
    pub struct State {
        #[storage(compat_tag = "router.factory")]
        pub factory: StorageValue<Address>,
        #[storage(compat_tag = "router.wloom")]
        pub wloom: StorageValue<Address>,
        #[storage(compat_tag = "router.self")]
        pub self_addr: StorageValue<Address>,
    }

    // -----------------------------------------------------------------------
    // Init — writes the three bootstrap config slots.
    // -----------------------------------------------------------------------

    #[init]
    pub fn init(ctx: &mut Context, cfg: InitConfig) -> Result<()> {
        let state = State::load(ctx)?;
        state.factory.store(ctx, &cfg.factory_addr);
        state.wloom.store(ctx, &cfg.wloom_addr);
        state.self_addr.store(ctx, &cfg.router_self_addr);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Pure quoting — single u256 returns. `#[view]` because they touch no
    // storage and don't dispatch to peer petals.
    // -----------------------------------------------------------------------

    #[view]
    pub fn quote(_ctx: &Context, amount_a: U256, reserve_a: U256, reserve_b: U256) -> Result<U256> {
        super::quote(amount_a, reserve_a, reserve_b)
    }

    #[view]
    pub fn get_amount_out(
        _ctx: &Context,
        amount_in: U256,
        reserve_in: U256,
        reserve_out: U256,
    ) -> Result<U256> {
        super::get_amount_out(amount_in, reserve_in, reserve_out)
    }

    #[view]
    pub fn get_amount_in(
        _ctx: &Context,
        amount_out: U256,
        reserve_in: U256,
        reserve_out: U256,
    ) -> Result<U256> {
        super::get_amount_in(amount_out, reserve_in, reserve_out)
    }

    // -----------------------------------------------------------------------
    // Multi-hop quoting — Vec<U256> returns. Reads factory only, no writes,
    // but they cross the petal boundary so we don't mark them `#[view]`.
    // -----------------------------------------------------------------------

    pub fn get_amounts_out(
        ctx: &mut Context,
        amount_in: U256,
        path: Vec<Address>,
    ) -> Result<Vec<U256>> {
        let factory = State::load(ctx)?.factory.load(ctx);
        compute_amounts_out(ctx, &factory, amount_in, &path)
    }

    pub fn get_amounts_in(
        ctx: &mut Context,
        amount_out: U256,
        path: Vec<Address>,
    ) -> Result<Vec<U256>> {
        let factory = State::load(ctx)?.factory.load(ctx);
        compute_amounts_in(ctx, &factory, amount_out, &path)
    }

    // -----------------------------------------------------------------------
    // Liquidity — token/token and token/LOOM pairs.
    // -----------------------------------------------------------------------

    pub fn add_liquidity(
        ctx: &mut Context,
        token_a: Address,
        token_b: Address,
        amount_a_desired: U256,
        amount_b_desired: U256,
        amount_a_min: U256,
        amount_b_min: U256,
        to: Address,
        deadline: u64,
    ) -> Result<(U256, U256, U256)> {
        check_deadline(ctx, deadline)?;

        let factory = State::load(ctx)?.factory.load(ctx);
        let pair = ensure_pair(ctx, &factory, &token_a, &token_b)?;

        let (reserve_a, reserve_b) = reserves_in_order(ctx, &pair, &token_a)?;
        let (amount_a, amount_b) = super::compute_liquidity_amounts(
            amount_a_desired,
            amount_b_desired,
            amount_a_min,
            amount_b_min,
            reserve_a,
            reserve_b,
        )?;

        let sender = ctx.sender();
        token_transfer_from(ctx, &token_a, &sender, &pair, amount_a)?;
        token_transfer_from(ctx, &token_b, &sender, &pair, amount_b)?;

        let liquidity = pair_mint(ctx, &pair, &to)?;

        Ok((amount_a, amount_b, liquidity))
    }

    #[payable]
    pub fn add_liquidity_loom(
        ctx: &mut Context,
        token: Address,
        amount_token_desired: U256,
        amount_token_min: U256,
        amount_loom_min: U256,
        to: Address,
        deadline: u64,
    ) -> Result<(U256, U256, U256)> {
        check_deadline(ctx, deadline)?;

        let state = State::load(ctx)?;
        let factory = state.factory.load(ctx);
        let wloom = state.wloom.load(ctx);

        let value = ctx.value();
        let amount_loom_desired = U256::from(value);

        // Wrap all msg.value into wLOOM (minted to router).
        wloom_deposit(ctx, &wloom, value)?;

        let pair = ensure_pair(ctx, &factory, &token, &wloom)?;
        let (reserve_token, reserve_loom) = reserves_in_order(ctx, &pair, &token)?;
        let (amount_token, amount_loom) = super::compute_liquidity_amounts(
            amount_token_desired,
            amount_loom_desired,
            amount_token_min,
            amount_loom_min,
            reserve_token,
            reserve_loom,
        )?;

        let sender = ctx.sender();
        token_transfer_from(ctx, &token, &sender, &pair, amount_token)?;

        // Router already holds the wrapped LOOM — transfer it onward to the pair.
        ctx.call::<Erc20>(wloom)
            .transfer(ctx, pair, amount_loom)
            .map_err(|_| ContractError::from_str("router: wloom transfer to pair failed"))?;

        let liquidity = pair_mint(ctx, &pair, &to)?;

        let refund = amount_loom_desired
            .checked_sub(amount_loom)
            .unwrap_or(U256::ZERO);
        if !refund.is_zero() {
            wloom_withdraw(ctx, &wloom, refund)?;
            send_loom(ctx, &sender, refund)?;
        }

        Ok((amount_token, amount_loom, liquidity))
    }

    pub fn remove_liquidity(
        ctx: &mut Context,
        token_a: Address,
        token_b: Address,
        liquidity: U256,
        amount_a_min: U256,
        amount_b_min: U256,
        to: Address,
        deadline: u64,
    ) -> Result<(U256, U256)> {
        check_deadline(ctx, deadline)?;

        let factory = State::load(ctx)?.factory.load(ctx);
        let pair = factory_get_pair(ctx, &factory, &token_a, &token_b)?;
        if pair == Address::ZERO {
            return Err(ContractError::from_str(
                "router: removeLiquidity: pair not found",
            ));
        }

        let sender = ctx.sender();
        transfer_lp_to_pair(ctx, &pair, &sender, liquidity)?;

        let (burn0, burn1) = pair_burn(ctx, &pair, &to)?;
        let token0 = pair_token0(ctx, &pair)?;
        let (amount_a, amount_b) = if token_a == token0 {
            (burn0, burn1)
        } else {
            (burn1, burn0)
        };

        if amount_a < amount_a_min {
            return Err(ContractError::from_str(
                "router: removeLiquidity: insufficient A",
            ));
        }
        if amount_b < amount_b_min {
            return Err(ContractError::from_str(
                "router: removeLiquidity: insufficient B",
            ));
        }

        Ok((amount_a, amount_b))
    }

    pub fn remove_liquidity_loom(
        ctx: &mut Context,
        token: Address,
        liquidity: U256,
        amount_token_min: U256,
        amount_loom_min: U256,
        to: Address,
        deadline: u64,
    ) -> Result<(U256, U256)> {
        check_deadline(ctx, deadline)?;

        let state = State::load(ctx)?;
        let factory = state.factory.load(ctx);
        let wloom = state.wloom.load(ctx);
        let router_self = state.self_addr.load(ctx);

        let pair = factory_get_pair(ctx, &factory, &token, &wloom)?;
        if pair == Address::ZERO {
            return Err(ContractError::from_str(
                "router: removeLiquidityLOOM: pair not found",
            ));
        }

        let sender = ctx.sender();
        transfer_lp_to_pair(ctx, &pair, &sender, liquidity)?;

        // Burn to the router so we can unwrap wLOOM into native LOOM.
        let (burn0, burn1) = pair_burn(ctx, &pair, &router_self)?;
        let token0 = pair_token0(ctx, &pair)?;
        let (amount_token, amount_wloom) = if token == token0 {
            (burn0, burn1)
        } else {
            (burn1, burn0)
        };

        if amount_token < amount_token_min {
            return Err(ContractError::from_str(
                "router: removeLiquidityLOOM: insufficient token",
            ));
        }
        if amount_wloom < amount_loom_min {
            return Err(ContractError::from_str(
                "router: removeLiquidityLOOM: insufficient LOOM",
            ));
        }

        // Forward tokens directly to `to`.
        ctx.call::<Erc20>(token)
            .transfer(ctx, to, amount_token)
            .map_err(|_| ContractError::from_str("router: token transfer to `to` failed"))?;

        wloom_withdraw(ctx, &wloom, amount_wloom)?;
        send_loom(ctx, &to, amount_wloom)?;

        Ok((amount_token, amount_wloom))
    }

    // -----------------------------------------------------------------------
    // Swaps — token ↔ token, token ↔ LOOM.
    // -----------------------------------------------------------------------

    pub fn swap_exact_tokens_for_tokens(
        ctx: &mut Context,
        amount_in: U256,
        amount_out_min: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>> {
        check_deadline(ctx, deadline)?;

        let factory = State::load(ctx)?.factory.load(ctx);
        let amounts = compute_amounts_out(ctx, &factory, amount_in, &path)?;

        let last = *amounts
            .last()
            .ok_or_else(|| ContractError::from_str("router: swapExact: empty amounts"))?;
        if last < amount_out_min {
            return Err(ContractError::from_str(
                "router: swapExact: insufficient output",
            ));
        }

        let first_pair = factory_get_pair(ctx, &factory, &path[0], &path[1])?;
        if first_pair == Address::ZERO {
            return Err(ContractError::from_str(
                "router: swapExact: first pair not found",
            ));
        }
        let sender = ctx.sender();
        token_transfer_from(ctx, &path[0], &sender, &first_pair, amounts[0])?;

        internal_swap(ctx, &factory, &amounts, &path, &to)?;

        Ok(amounts)
    }

    pub fn swap_tokens_for_exact_tokens(
        ctx: &mut Context,
        amount_out: U256,
        amount_in_max: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>> {
        check_deadline(ctx, deadline)?;

        let factory = State::load(ctx)?.factory.load(ctx);
        let amounts = compute_amounts_in(ctx, &factory, amount_out, &path)?;

        if amounts[0] > amount_in_max {
            return Err(ContractError::from_str(
                "router: swapForExact: excessive input",
            ));
        }

        let first_pair = factory_get_pair(ctx, &factory, &path[0], &path[1])?;
        if first_pair == Address::ZERO {
            return Err(ContractError::from_str(
                "router: swapForExact: first pair not found",
            ));
        }
        let sender = ctx.sender();
        token_transfer_from(ctx, &path[0], &sender, &first_pair, amounts[0])?;

        internal_swap(ctx, &factory, &amounts, &path, &to)?;

        Ok(amounts)
    }

    #[payable]
    pub fn swap_exact_loom_for_tokens(
        ctx: &mut Context,
        amount_out_min: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>> {
        check_deadline(ctx, deadline)?;

        let state = State::load(ctx)?;
        let wloom = state.wloom.load(ctx);
        let factory = state.factory.load(ctx);

        if path.is_empty() || path[0] != wloom {
            return Err(ContractError::from_str(
                "router: swapExactLOOM: path[0] must be wloom",
            ));
        }

        let value = ctx.value();
        let amount_in = U256::from(value);

        wloom_deposit(ctx, &wloom, value)?;

        let amounts = compute_amounts_out(ctx, &factory, amount_in, &path)?;
        let last = *amounts
            .last()
            .ok_or_else(|| ContractError::from_str("router: swapExactLOOM: empty amounts"))?;
        if last < amount_out_min {
            return Err(ContractError::from_str(
                "router: swapExactLOOM: insufficient output",
            ));
        }

        let first_pair = factory_get_pair(ctx, &factory, &path[0], &path[1])?;
        if first_pair == Address::ZERO {
            return Err(ContractError::from_str(
                "router: swapExactLOOM: first pair not found",
            ));
        }
        ctx.call::<Erc20>(wloom)
            .transfer(ctx, first_pair, amounts[0])
            .map_err(|_| ContractError::from_str("router: wloom transfer failed"))?;

        internal_swap(ctx, &factory, &amounts, &path, &to)?;

        Ok(amounts)
    }

    pub fn swap_tokens_for_exact_loom(
        ctx: &mut Context,
        amount_out: U256,
        amount_in_max: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>> {
        check_deadline(ctx, deadline)?;

        let state = State::load(ctx)?;
        let wloom = state.wloom.load(ctx);
        let factory = state.factory.load(ctx);
        let router_self = state.self_addr.load(ctx);

        if path.is_empty() || *path.last().unwrap() != wloom {
            return Err(ContractError::from_str(
                "router: swapForExactLOOM: path[-1] must be wloom",
            ));
        }

        let amounts = compute_amounts_in(ctx, &factory, amount_out, &path)?;

        if amounts[0] > amount_in_max {
            return Err(ContractError::from_str(
                "router: swapForExactLOOM: excessive input",
            ));
        }

        let first_pair = factory_get_pair(ctx, &factory, &path[0], &path[1])?;
        if first_pair == Address::ZERO {
            return Err(ContractError::from_str(
                "router: swapForExactLOOM: first pair not found",
            ));
        }
        let sender = ctx.sender();
        token_transfer_from(ctx, &path[0], &sender, &first_pair, amounts[0])?;

        internal_swap(ctx, &factory, &amounts, &path, &router_self)?;

        let wloom_amount = *amounts.last().unwrap();
        wloom_withdraw(ctx, &wloom, wloom_amount)?;
        send_loom(ctx, &to, wloom_amount)?;

        Ok(amounts)
    }

    pub fn swap_exact_tokens_for_loom(
        ctx: &mut Context,
        amount_in: U256,
        amount_out_min: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>> {
        check_deadline(ctx, deadline)?;

        let state = State::load(ctx)?;
        let wloom = state.wloom.load(ctx);
        let factory = state.factory.load(ctx);
        let router_self = state.self_addr.load(ctx);

        if path.is_empty() || *path.last().unwrap() != wloom {
            return Err(ContractError::from_str(
                "router: swapExactForLOOM: path[-1] must be wloom",
            ));
        }

        let amounts = compute_amounts_out(ctx, &factory, amount_in, &path)?;
        let wloom_amount = *amounts
            .last()
            .ok_or_else(|| ContractError::from_str("router: swapExactForLOOM: empty amounts"))?;
        if wloom_amount < amount_out_min {
            return Err(ContractError::from_str(
                "router: swapExactForLOOM: insufficient output",
            ));
        }

        let first_pair = factory_get_pair(ctx, &factory, &path[0], &path[1])?;
        if first_pair == Address::ZERO {
            return Err(ContractError::from_str(
                "router: swapExactForLOOM: first pair not found",
            ));
        }
        let sender = ctx.sender();
        token_transfer_from(ctx, &path[0], &sender, &first_pair, amounts[0])?;

        internal_swap(ctx, &factory, &amounts, &path, &router_self)?;

        wloom_withdraw(ctx, &wloom, wloom_amount)?;
        send_loom(ctx, &to, wloom_amount)?;

        Ok(amounts)
    }

    #[payable]
    pub fn swap_loom_for_exact_tokens(
        ctx: &mut Context,
        amount_out: U256,
        path: Vec<Address>,
        to: Address,
        deadline: u64,
    ) -> Result<Vec<U256>> {
        check_deadline(ctx, deadline)?;

        let state = State::load(ctx)?;
        let wloom = state.wloom.load(ctx);
        let factory = state.factory.load(ctx);

        if path.is_empty() || path[0] != wloom {
            return Err(ContractError::from_str(
                "router: swapLOOMForExact: path[0] must be wloom",
            ));
        }

        let value = ctx.value();
        let msg_value = U256::from(value);

        let amounts = compute_amounts_in(ctx, &factory, amount_out, &path)?;
        let loom_needed = amounts[0];
        if loom_needed > msg_value {
            return Err(ContractError::from_str(
                "router: swapLOOMForExact: insufficient msg.value",
            ));
        }

        let loom_needed_value = loom_value_from_u256(loom_needed)?;
        wloom_deposit(ctx, &wloom, loom_needed_value)?;

        let first_pair = factory_get_pair(ctx, &factory, &path[0], &path[1])?;
        if first_pair == Address::ZERO {
            return Err(ContractError::from_str(
                "router: swapLOOMForExact: first pair not found",
            ));
        }
        ctx.call::<Erc20>(wloom)
            .transfer(ctx, first_pair, loom_needed)
            .map_err(|_| ContractError::from_str("router: wloom transfer failed"))?;

        internal_swap(ctx, &factory, &amounts, &path, &to)?;

        let refund = msg_value.checked_sub(loom_needed).unwrap_or(U256::ZERO);
        if !refund.is_zero() {
            let sender = ctx.sender();
            send_loom(ctx, &sender, refund)?;
        }

        Ok(amounts)
    }

    // -----------------------------------------------------------------------
    // Internal helpers — cross-petal calls and per-hop swap orchestration.
    // -----------------------------------------------------------------------

    pub(crate) fn check_deadline(ctx: &Context, deadline: u64) -> Result<()> {
        let now_secs = ctx.block_timestamp() / 1000;
        if now_secs > deadline {
            return Err(ContractError::from_str("router: expired"));
        }
        Ok(())
    }

    pub(crate) fn factory_get_pair(
        ctx: &mut Context,
        factory: &Address,
        token_a: &Address,
        token_b: &Address,
    ) -> Result<Address> {
        ctx.call::<Factory>(*factory)
            .get_pair(ctx, *token_a, *token_b)
            .map_err(|_| ContractError::from_str("router: factory.get_pair failed"))
    }

    pub(crate) fn factory_create_pair(
        ctx: &mut Context,
        factory: &Address,
        token_a: &Address,
        token_b: &Address,
    ) -> Result<Address> {
        ctx.call::<Factory>(*factory)
            .create_pair(ctx, *token_a, *token_b)
            .map_err(|_| ContractError::from_str("router: factory.create_pair failed"))
    }

    pub(crate) fn ensure_pair(
        ctx: &mut Context,
        factory: &Address,
        token_a: &Address,
        token_b: &Address,
    ) -> Result<Address> {
        let pair = factory_get_pair(ctx, factory, token_a, token_b)?;
        if pair == Address::ZERO {
            factory_create_pair(ctx, factory, token_a, token_b)
        } else {
            Ok(pair)
        }
    }

    pub(crate) fn pair_get_reserves(ctx: &mut Context, pair: &Address) -> Result<(u128, u128)> {
        let (r0, r1, _ts) = ctx
            .call::<Pair>(*pair)
            .get_reserves(ctx)
            .map_err(|_| ContractError::from_str("router: pair.get_reserves failed"))?;
        Ok((r0, r1))
    }

    pub(crate) fn pair_token0(ctx: &mut Context, pair: &Address) -> Result<Address> {
        ctx.call::<Pair>(*pair)
            .token0(ctx)
            .map_err(|_| ContractError::from_str("router: pair.token0 failed"))
    }

    pub(crate) fn token_transfer_from(
        ctx: &mut Context,
        token: &Address,
        from: &Address,
        to: &Address,
        amount: U256,
    ) -> Result<()> {
        ctx.call::<Erc20>(*token)
            .transfer_from(ctx, *from, *to, amount)
            .map_err(|_| ContractError::from_str("router: transferFrom failed"))?;
        Ok(())
    }

    pub(crate) fn pair_mint(ctx: &mut Context, pair: &Address, to: &Address) -> Result<U256> {
        ctx.call::<Pair>(*pair)
            .mint(ctx, *to)
            .map_err(|_| ContractError::from_str("router: pair.mint failed"))
    }

    pub(crate) fn pair_burn(
        ctx: &mut Context,
        pair: &Address,
        to: &Address,
    ) -> Result<(U256, U256)> {
        ctx.call::<Pair>(*pair)
            .burn(ctx, *to)
            .map_err(|_| ContractError::from_str("router: pair.burn failed"))
    }

    pub(crate) fn pair_swap(
        ctx: &mut Context,
        pair: &Address,
        amount0_out: U256,
        amount1_out: U256,
        to: &Address,
    ) -> Result<()> {
        ctx.call::<Pair>(*pair)
            .swap(ctx, amount0_out, amount1_out, *to)
            .map_err(|_| ContractError::from_str("router: pair.swap failed"))
    }

    pub(crate) fn transfer_lp_to_pair(
        ctx: &mut Context,
        pair: &Address,
        from: &Address,
        liquidity: U256,
    ) -> Result<()> {
        // LP tokens live on the pair petal itself.
        ctx.call::<Erc20>(*pair)
            .transfer_from(ctx, *from, *pair, liquidity)
            .map_err(|_| ContractError::from_str("router: LP transferFrom failed"))?;
        Ok(())
    }

    pub(crate) fn wloom_deposit(
        ctx: &mut Context,
        wloom: &Address,
        value: LoomValue,
    ) -> Result<()> {
        ctx.call::<Wloom>(*wloom)
            .with_value(value)
            .deposit(ctx)
            .map_err(|_| ContractError::from_str("router: wloom.deposit failed"))
    }

    pub(crate) fn wloom_withdraw(ctx: &mut Context, wloom: &Address, amount: U256) -> Result<()> {
        ctx.call::<Wloom>(*wloom)
            .withdraw(ctx, amount)
            .map_err(|_| ContractError::from_str("router: wloom.withdraw failed"))
    }

    pub(crate) fn loom_value_from_u256(amount: U256) -> Result<LoomValue> {
        LoomValue::try_from(amount)
            .map_err(|_| ContractError::from_str("router: LOOM value exceeds u128"))
    }

    pub(crate) fn send_loom(ctx: &mut Context, to: &Address, amount: U256) -> Result<()> {
        // Native LOOM transfers go through `__call_raw` with empty calldata —
        // there's no interface to mediate "send value to address", so this is
        // the one sanctioned use of the raw escape hatch in the router.
        let v = loom_value_from_u256(amount)?;
        ctx.__call_raw(to, &[], v)
            .map_err(|_| ContractError::from_str("router: LOOM transfer failed"))?;
        Ok(())
    }

    pub(crate) fn reserves_in_order(
        ctx: &mut Context,
        pair: &Address,
        token_a: &Address,
    ) -> Result<(U256, U256)> {
        let (r0, r1) = pair_get_reserves(ctx, pair)?;
        let token0 = pair_token0(ctx, pair)?;
        if *token_a == token0 {
            Ok((U256::from_u128(r0), U256::from_u128(r1)))
        } else {
            Ok((U256::from_u128(r1), U256::from_u128(r0)))
        }
    }

    pub(crate) fn compute_amounts_out(
        ctx: &mut Context,
        factory: &Address,
        amount_in: U256,
        path: &[Address],
    ) -> Result<Vec<U256>> {
        if path.len() < 2 {
            return Err(ContractError::from_str(
                "router: getAmountsOut: path too short",
            ));
        }
        let mut amounts = Vec::with_capacity(path.len());
        amounts.push(amount_in);
        for i in 0..path.len() - 1 {
            let pair = factory_get_pair(ctx, factory, &path[i], &path[i + 1])?;
            if pair == Address::ZERO {
                return Err(ContractError::from_str(
                    "router: getAmountsOut: pair not found",
                ));
            }
            let (r_in, r_out) = reserves_in_order(ctx, &pair, &path[i])?;
            let out = super::get_amount_out(amounts[i], r_in, r_out)?;
            amounts.push(out);
        }
        Ok(amounts)
    }

    pub(crate) fn compute_amounts_in(
        ctx: &mut Context,
        factory: &Address,
        amount_out: U256,
        path: &[Address],
    ) -> Result<Vec<U256>> {
        if path.len() < 2 {
            return Err(ContractError::from_str(
                "router: getAmountsIn: path too short",
            ));
        }
        let n = path.len();
        let mut amounts = vec![U256::ZERO; n];
        amounts[n - 1] = amount_out;
        let mut i = n - 1;
        while i > 0 {
            let pair = factory_get_pair(ctx, factory, &path[i - 1], &path[i])?;
            if pair == Address::ZERO {
                return Err(ContractError::from_str(
                    "router: getAmountsIn: pair not found",
                ));
            }
            let (r_in, r_out) = reserves_in_order(ctx, &pair, &path[i - 1])?;
            amounts[i - 1] = super::get_amount_in(amounts[i], r_in, r_out)?;
            i -= 1;
        }
        Ok(amounts)
    }

    pub(crate) fn internal_swap(
        ctx: &mut Context,
        factory: &Address,
        amounts: &[U256],
        path: &[Address],
        to: &Address,
    ) -> Result<()> {
        let n = path.len();
        for i in 0..n - 1 {
            let pair = factory_get_pair(ctx, factory, &path[i], &path[i + 1])?;
            if pair == Address::ZERO {
                return Err(ContractError::from_str("router: swap: pair not found"));
            }
            let token0 = pair_token0(ctx, &pair)?;
            let (amount0_out, amount1_out) = if path[i + 1] == token0 {
                (amounts[i + 1], U256::ZERO)
            } else {
                (U256::ZERO, amounts[i + 1])
            };
            let next_to = if i < n - 2 {
                factory_get_pair(ctx, factory, &path[i + 1], &path[i + 2])?
            } else {
                *to
            };
            pair_swap(ctx, &pair, amount0_out, amount1_out, &next_to)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Hand-rolled calldata builders for off-chain tools (dex CLI).
// ---------------------------------------------------------------------------

pub mod calls {
    use super::*;
    use alloc::vec::Vec;
    use bloom_chain_abi::Encoder;

    /// Build `router.quote(amount_a, reserve_a, reserve_b)` calldata.
    pub fn quote(amount_a: U256, reserve_a: U256, reserve_b: U256) -> Vec<u8> {
        let mut e = Encoder::with_selector(Router::SEL_QUOTE);
        e.push_u256(amount_a);
        e.push_u256(reserve_a);
        e.push_u256(reserve_b);
        e.finish()
    }

    /// Build `router.get_amount_out(...)` calldata.
    pub fn get_amount_out(amount_in: U256, reserve_in: U256, reserve_out: U256) -> Vec<u8> {
        let mut e = Encoder::with_selector(Router::SEL_GET_AMOUNT_OUT);
        e.push_u256(amount_in);
        e.push_u256(reserve_in);
        e.push_u256(reserve_out);
        e.finish()
    }

    /// Build `router.get_amount_in(...)` calldata.
    pub fn get_amount_in(amount_out: U256, reserve_in: U256, reserve_out: U256) -> Vec<u8> {
        let mut e = Encoder::with_selector(Router::SEL_GET_AMOUNT_IN);
        e.push_u256(amount_out);
        e.push_u256(reserve_in);
        e.push_u256(reserve_out);
        e.finish()
    }

    /// Build `router.add_liquidity(...)` calldata.
    #[allow(clippy::too_many_arguments)]
    pub fn add_liquidity(
        token_a: &[u8; 32],
        token_b: &[u8; 32],
        amount_a_desired: U256,
        amount_b_desired: U256,
        amount_a_min: U256,
        amount_b_min: U256,
        to: &[u8; 32],
        deadline: u64,
    ) -> Vec<u8> {
        let mut e = Encoder::with_selector(Router::SEL_ADD_LIQUIDITY);
        e.push_address(token_a);
        e.push_address(token_b);
        e.push_u256(amount_a_desired);
        e.push_u256(amount_b_desired);
        e.push_u256(amount_a_min);
        e.push_u256(amount_b_min);
        e.push_address(to);
        e.push_u64(deadline);
        e.finish()
    }

    /// Build `router.remove_liquidity(...)` calldata.
    #[allow(clippy::too_many_arguments)]
    pub fn remove_liquidity(
        token_a: &[u8; 32],
        token_b: &[u8; 32],
        liquidity: U256,
        amount_a_min: U256,
        amount_b_min: U256,
        to: &[u8; 32],
        deadline: u64,
    ) -> Vec<u8> {
        let mut e = Encoder::with_selector(Router::SEL_REMOVE_LIQUIDITY);
        e.push_address(token_a);
        e.push_address(token_b);
        e.push_u256(liquidity);
        e.push_u256(amount_a_min);
        e.push_u256(amount_b_min);
        e.push_address(to);
        e.push_u64(deadline);
        e.finish()
    }

    /// Build `router.swap_exact_tokens_for_tokens(...)` calldata.
    pub fn swap_exact_tokens_for_tokens(
        amount_in: U256,
        amount_out_min: U256,
        path: &[[u8; 32]],
        to: &[u8; 32],
        deadline: u64,
    ) -> ::core::result::Result<Vec<u8>, ::bloom_chain_abi::AbiEncodeError> {
        let mut e = Encoder::with_selector(Router::SEL_SWAP_EXACT_TOKENS_FOR_TOKENS);
        e.push_u256(amount_in);
        e.push_u256(amount_out_min);
        e.push_address_vec(path)?;
        e.push_address(to);
        e.push_u64(deadline);
        Ok(e.finish())
    }
}

// ---------------------------------------------------------------------------
// Build the 96-byte router init payload from typed inputs.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub fn encode_init_payload(
    factory_addr: [u8; 32],
    wloom_addr: [u8; 32],
    router_self_addr: [u8; 32],
) -> ::core::result::Result<alloc::vec::Vec<u8>, ::bloom_contract::abi::AbiEncodeError> {
    let cfg = InitConfig {
        factory_addr: Address::from(factory_addr),
        wloom_addr: Address::from(wloom_addr),
        router_self_addr: Address::from(router_self_addr),
    };
    cfg.encode()
}

// ---------------------------------------------------------------------------
// Host-target unit tests — pure math + ABI byte-parity.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn u256(v: u128) -> U256 {
        U256::from_u128(v)
    }

    fn blake3_4(sig: &str) -> [u8; 4] {
        let h = blake3::hash(sig.as_bytes());
        let b = h.as_bytes();
        [b[0], b[1], b[2], b[3]]
    }

    // --- quote ---

    #[test]
    fn quote_basic() {
        assert_eq!(quote(u256(1), u256(1), u256(2)).unwrap(), u256(2));
    }

    #[test]
    fn quote_proportional() {
        assert_eq!(quote(u256(100), u256(1000), u256(2000)).unwrap(), u256(200));
    }

    #[test]
    fn quote_zero_amount_errs() {
        assert!(quote(u256(0), u256(1000), u256(2000)).is_err());
    }

    #[test]
    fn quote_zero_reserve_a_errs() {
        assert!(quote(u256(100), u256(0), u256(2000)).is_err());
    }

    #[test]
    fn quote_zero_reserve_b_errs() {
        assert!(quote(u256(100), u256(1000), u256(0)).is_err());
    }

    // --- get_amount_out ---

    #[test]
    fn get_amount_out_basic() {
        let out = get_amount_out(u256(1000), u256(1_000_000), u256(1_000_000)).unwrap();
        assert_eq!(out, u256(996));
    }

    #[test]
    fn get_amount_out_fee_check() {
        let one_e18: u128 = 1_000_000_000_000_000_000;
        let one_e21: u128 = 1_000_000_000_000_000_000_000;
        let out = get_amount_out(u256(one_e18), u256(one_e21), u256(one_e21)).unwrap();
        let expected: u128 = 996_006_981_039_903_216;
        let diff = if out.to_u128_checked().unwrap() > expected {
            out.to_u128_checked().unwrap() - expected
        } else {
            expected - out.to_u128_checked().unwrap()
        };
        assert!(diff <= 1, "expected ~{}, got {:?}", expected, out);
    }

    #[test]
    fn get_amount_out_zero_in_errs() {
        assert!(get_amount_out(u256(0), u256(1000), u256(1000)).is_err());
    }

    #[test]
    fn get_amount_out_zero_reserves_errs() {
        assert!(get_amount_out(u256(100), u256(0), u256(1000)).is_err());
    }

    // --- get_amount_in ---

    #[test]
    fn get_amount_in_basic() {
        let amt_in = get_amount_in(u256(996), u256(1_000_000), u256(1_000_000)).unwrap();
        assert_eq!(amt_in, u256(1000));
    }

    #[test]
    fn get_amount_in_amount_out_gte_reserve_errs() {
        assert!(get_amount_in(u256(1000), u256(1000), u256(1000)).is_err());
    }

    #[test]
    fn get_amount_in_zero_out_errs() {
        assert!(get_amount_in(u256(0), u256(1000), u256(1000)).is_err());
    }

    // --- compute_liquidity_amounts ---

    #[test]
    fn compute_liquidity_amounts_empty_pool() {
        let (a, b) = compute_liquidity_amounts(
            u256(1000),
            u256(2000),
            u256(0),
            u256(0),
            U256::ZERO,
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(a, u256(1000));
        assert_eq!(b, u256(2000));
    }

    #[test]
    fn compute_liquidity_amounts_b_optimal() {
        let (a, b) = compute_liquidity_amounts(
            u256(100),
            u256(300),
            u256(0),
            u256(0),
            u256(1000),
            u256(2000),
        )
        .unwrap();
        assert_eq!(a, u256(100));
        assert_eq!(b, u256(200));
    }

    #[test]
    fn compute_liquidity_amounts_a_optimal() {
        let (a, b) = compute_liquidity_amounts(
            u256(300),
            u256(100),
            u256(0),
            u256(0),
            u256(1000),
            u256(2000),
        )
        .unwrap();
        assert_eq!(a, u256(50));
        assert_eq!(b, u256(100));
    }

    #[test]
    fn compute_liquidity_amounts_insufficient_b_errs() {
        assert!(
            compute_liquidity_amounts(
                u256(100),
                u256(300),
                u256(0),
                u256(250),
                u256(1000),
                u256(2000),
            )
            .is_err()
        );
    }

    // --- Selector parity — pins macro-emitted selectors to canonical strings.
    //
    // The framework's `#[bloom::interface]` macro emits the canonical
    // signature using lowercase last-segment idents with generic args
    // recursed: `Vec<Address>` becomes `vec<address>`. This is a deliberate
    // shift from the legacy `contract!` DSL's mixed-case `Vec<Address>` —
    // it eliminates an inconsistency where scalars were lowercase but
    // collections kept their Rust casing.

    #[test]
    fn router_selectors_match_canonical_strings() {
        assert_eq!(Router::SEL_QUOTE, blake3_4("router.quote(u256,u256,u256)"));
        assert_eq!(
            Router::SEL_GET_AMOUNT_OUT,
            blake3_4("router.get_amount_out(u256,u256,u256)")
        );
        assert_eq!(
            Router::SEL_GET_AMOUNT_IN,
            blake3_4("router.get_amount_in(u256,u256,u256)")
        );
        assert_eq!(
            Router::SEL_GET_AMOUNTS_OUT,
            blake3_4("router.get_amounts_out(u256,vec<address>)")
        );
        assert_eq!(
            Router::SEL_GET_AMOUNTS_IN,
            blake3_4("router.get_amounts_in(u256,vec<address>)")
        );
        assert_eq!(
            Router::SEL_ADD_LIQUIDITY,
            blake3_4("router.add_liquidity(address,address,u256,u256,u256,u256,address,u64)")
        );
        assert_eq!(
            Router::SEL_ADD_LIQUIDITY_LOOM,
            blake3_4("router.add_liquidity_loom(address,u256,u256,u256,address,u64)")
        );
        assert_eq!(
            Router::SEL_REMOVE_LIQUIDITY,
            blake3_4("router.remove_liquidity(address,address,u256,u256,u256,address,u64)")
        );
        assert_eq!(
            Router::SEL_REMOVE_LIQUIDITY_LOOM,
            blake3_4("router.remove_liquidity_loom(address,u256,u256,u256,address,u64)")
        );
        assert_eq!(
            Router::SEL_SWAP_EXACT_TOKENS_FOR_TOKENS,
            blake3_4("router.swap_exact_tokens_for_tokens(u256,u256,vec<address>,address,u64)")
        );
        assert_eq!(
            Router::SEL_SWAP_TOKENS_FOR_EXACT_TOKENS,
            blake3_4("router.swap_tokens_for_exact_tokens(u256,u256,vec<address>,address,u64)")
        );
        assert_eq!(
            Router::SEL_SWAP_EXACT_LOOM_FOR_TOKENS,
            blake3_4("router.swap_exact_loom_for_tokens(u256,vec<address>,address,u64)")
        );
        assert_eq!(
            Router::SEL_SWAP_TOKENS_FOR_EXACT_LOOM,
            blake3_4("router.swap_tokens_for_exact_loom(u256,u256,vec<address>,address,u64)")
        );
        assert_eq!(
            Router::SEL_SWAP_EXACT_TOKENS_FOR_LOOM,
            blake3_4("router.swap_exact_tokens_for_loom(u256,u256,vec<address>,address,u64)")
        );
        assert_eq!(
            Router::SEL_SWAP_LOOM_FOR_EXACT_TOKENS,
            blake3_4("router.swap_loom_for_exact_tokens(u256,vec<address>,address,u64)")
        );
    }

    #[test]
    fn router_selectors_are_unique() {
        let sels = [
            Router::SEL_QUOTE,
            Router::SEL_GET_AMOUNT_OUT,
            Router::SEL_GET_AMOUNT_IN,
            Router::SEL_GET_AMOUNTS_OUT,
            Router::SEL_GET_AMOUNTS_IN,
            Router::SEL_ADD_LIQUIDITY,
            Router::SEL_ADD_LIQUIDITY_LOOM,
            Router::SEL_REMOVE_LIQUIDITY,
            Router::SEL_REMOVE_LIQUIDITY_LOOM,
            Router::SEL_SWAP_EXACT_TOKENS_FOR_TOKENS,
            Router::SEL_SWAP_TOKENS_FOR_EXACT_TOKENS,
            Router::SEL_SWAP_EXACT_LOOM_FOR_TOKENS,
            Router::SEL_SWAP_TOKENS_FOR_EXACT_LOOM,
            Router::SEL_SWAP_EXACT_TOKENS_FOR_LOOM,
            Router::SEL_SWAP_LOOM_FOR_EXACT_TOKENS,
        ];
        let mut seen: Vec<[u8; 4]> = Vec::new();
        for s in sels {
            assert!(!seen.contains(&s), "duplicate selector {:?}", s);
            seen.push(s);
        }
    }

    #[test]
    fn init_payload_is_exactly_96_bytes() {
        let factory = [0x11u8; 32];
        let wloom = [0x22u8; 32];
        let self_addr = [0x33u8; 32];
        let payload = encode_init_payload(factory, wloom, self_addr).unwrap();
        assert_eq!(payload.len(), 96);
        assert_eq!(&payload[0..32], &factory);
        assert_eq!(&payload[32..64], &wloom);
        assert_eq!(&payload[64..96], &self_addr);
    }

    #[test]
    fn init_payload_rejects_wrong_length() {
        let bad = [0u8; 95];
        assert!(InitConfig::decode_from(&bad).is_err());
        let bad = [0u8; 97];
        assert!(InitConfig::decode_from(&bad).is_err());
    }

    #[test]
    fn quote_call_layout() {
        let a = U256::from_u64(1);
        let b = U256::from_u64(2);
        let c = U256::from_u64(3);
        let cd = calls::quote(a, b, c);
        assert_eq!(cd.len(), 4 + 32 * 3);
        assert_eq!(&cd[0..4], &Router::SEL_QUOTE);
    }

    #[test]
    fn swap_exact_tokens_for_tokens_call_layout() {
        let path = [[0xAAu8; 32], [0xBBu8; 32]];
        let cd = calls::swap_exact_tokens_for_tokens(
            U256::from_u64(100),
            U256::from_u64(99),
            &path,
            &[0xCCu8; 32],
            42,
        )
        .unwrap();
        // selector (4) || amount_in (32) || min_out (32) || vec len (2)
        //  || 2*addresses (64) || to (32) || deadline (8) = 174
        assert_eq!(cd.len(), 4 + 32 + 32 + 2 + 64 + 32 + 8);
        assert_eq!(&cd[0..4], &Router::SEL_SWAP_EXACT_TOKENS_FOR_TOKENS);
        // vec length sits at offset 4 + 32 + 32 = 68
        assert_eq!(&cd[68..70], &2u16.to_be_bytes());
    }
}
