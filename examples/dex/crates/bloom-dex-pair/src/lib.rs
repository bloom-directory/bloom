//! bloom-dex-pair — Uniswap-v2-style AMM pair petal.
//!
//! The pair is both the AMM and its own LP token (ERC-20 surface inlined into
//! the contract). Migrated from `bloom_chain_abi::contract!` onto
//! `#[bloom::contract]`. Preserves byte-for-byte parity at the consensus
//! boundary:
//!
//! - All `pair.*` and `erc20.*` selectors hash to the same 4 bytes — both
//!   the [`Pair`] and [`Erc20`] interfaces are declared so the contract's
//!   dispatcher accepts callers using either prefix. ERC-20 selectors flow
//!   through the same handlers as the LP token's surface (the `interfaces`
//!   fallthrough routes them to local handlers by name).
//! - Storage slots match exactly via `#[storage(compat_tag = "..." )]`.
//!   `pair.*` slots and the shared `erc20.*` namespace (`total_supply`,
//!   `balance:`, `allowance:`) both keep their legacy byte layouts.
//! - Init calldata is the same 96-byte `token0 || token1 || pair_self_addr`
//!   blob — strict-length-rejected by the framework decoder.
//!
//! ## Reentrancy guard
//!
//! `mint` / `burn` / `swap` carry `#[nonreentrant]`. The framework's lock
//! slot is at `blake3("bloom::reentrancy")` (vs. the legacy
//! `blake3("__macro.nonreentrant.pair")`); this is purely runtime — the lock
//! is cleared on success and rolled back on revert, never persisted between
//! transactions, so no storage-migration concern.
//!
//! ## Event topic-0 (intentional change)
//!
//! Event topic-0 is now the full 32-byte `blake3(signature)` instead of the
//! 4-byte-prefix zero-padded legacy format, and the signature includes the
//! domain (`erc20::Transfer(...)`, `pair::Mint(...)`, …). LP `Transfer` and
//! `Approval` events keep the `erc20` domain so they are byte-identical to
//! real ERC-20 token transfers, matching the wLOOM convention.
//!
//! ## decimals() return shape (intentional change)
//!
//! `decimals()` now returns the single-byte `u8` value (1 byte), matching the
//! migrated `bloom-dex-erc20`. The legacy `contract!` macro returned a
//! left-padded 32-byte slot; readers must treat the new 1-byte return like
//! the migrated ERC-20 surface.

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use bloom_contract::prelude::*;
use bloom_dex_erc20::{Erc20, Erc20Calls};

// ---------------------------------------------------------------------------
// Pair interface — AMM-specific surface (separate from the ERC-20 interface
// re-used for the LP token surface).
// ---------------------------------------------------------------------------

/// Typed pair interface. Sibling petals (router) reach the pair through
/// [`calls`] (hand-rolled calldata builders) or via `ContractRef<Pair>`
/// once they import the generated `PairCalls` extension trait.
///
/// Selectors hash from `pair.<method>(<types>)` so they match every legacy
/// `bloom_chain_abi::contract! { contract Pair { ... } }` deployment.
#[bloom_contract::interface(domain = "pair")]
pub trait Pair {
    fn token0() -> Result<Address>;
    fn token1() -> Result<Address>;
    fn get_reserves() -> Result<(u128, u128, u64)>;
    fn mint(to: Address) -> Result<U256>;
    fn burn(to: Address) -> Result<(U256, U256)>;
    fn swap(amount0_out: U256, amount1_out: U256, to: Address) -> Result<()>;
    fn skim(to: Address) -> Result<()>;
    fn sync() -> Result<()>;
}

// ---------------------------------------------------------------------------
// Init payload — byte-compatible with the legacy 96-byte format
// ---------------------------------------------------------------------------

/// Constructor arguments. The on-the-wire layout is:
///
/// ```text
/// token0          : [u8; 32]   (Address)
/// token1          : [u8; 32]   (Address)
/// pair_self_addr  : [u8; 32]   (Address)
/// ```
///
/// Three fixed-width 32-byte fields, no length prefixes — strict decoding
/// rejects payloads of any other size via the framework's EOF check.
#[derive(AbiEncode, AbiDecode, AbiType)]
pub struct InitConfig {
    pub token0: Address,
    pub token1: Address,
    pub pair_self_addr: Address,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum liquidity permanently locked to address(0) on the first mint.
const MINIMUM_LIQUIDITY: u128 = 1_000;

/// `u256::MAX` sentinel: an allowance equal to this is treated as unlimited.
const U256_MAX: U256 = U256([0xff; 32]);

/// LP token decimals.
const DECIMALS: u8 = 18;

/// LP token name (right-padded into a 32-byte slot — pair's convention:
/// ASCII first, zeros trailing. Mirror of wLOOM's left-padded layout).
const NAME_SLOT: Bytes32String = Bytes32String::pad_right("BloomDexPair LP");

/// LP token symbol (right-padded into a 32-byte slot).
const SYMBOL_SLOT: Bytes32String = Bytes32String::pad_right("BDPL");

// ---------------------------------------------------------------------------
// Contract body
// ---------------------------------------------------------------------------

#[bloom_contract::contract(domain = "pair", interfaces(Erc20, Pair))]
pub mod pair {
    use super::*;
    use bloom_petal_sdk::block;

    // -----------------------------------------------------------------------
    // Storage — every slot keeps its legacy tag for byte-for-byte parity.
    // The `pair.*` keys are pair-specific; the `erc20.*` keys are shared
    // with `bloom-dex-erc20` so the LP-token surface reads/writes the same
    // namespace any ERC-20 petal would.
    // -----------------------------------------------------------------------

    #[bloom_contract::storage(domain = "pair")]
    pub struct State {
        #[storage(compat_tag = "pair.token0")]
        pub token0: StorageValue<Address>,
        #[storage(compat_tag = "pair.token1")]
        pub token1: StorageValue<Address>,
        #[storage(compat_tag = "pair.reserve0")]
        pub reserve0: StorageValue<u128>,
        #[storage(compat_tag = "pair.reserve1")]
        pub reserve1: StorageValue<u128>,
        #[storage(compat_tag = "pair.k_last")]
        pub k_last: StorageValue<U256>,
        #[storage(compat_tag = "pair.self")]
        pub self_addr: StorageValue<Address>,

        #[storage(compat_tag = "erc20.total_supply")]
        pub total_supply: StorageValue<U256>,
        #[storage(compat_tag = "erc20.balance:")]
        pub balances: Map<Address, U256>,
        #[storage(compat_tag = "erc20.allowance:")]
        pub allowances: Map<(Address, Address), U256>,
    }

    // -----------------------------------------------------------------------
    // Events
    //
    // `Transfer` and `Approval` use `domain = "erc20"` so their topic-0
    // matches a real ERC-20 transfer (indexers can't tell LP from token
    // transfers, exactly as for wLOOM).
    // -----------------------------------------------------------------------

    #[bloom_contract::event(domain = "erc20")]
    pub struct Transfer {
        #[indexed]
        pub from: Address,
        #[indexed]
        pub to: Address,
        pub value: U256,
    }

    #[bloom_contract::event(domain = "erc20")]
    pub struct Approval {
        #[indexed]
        pub owner: Address,
        #[indexed]
        pub spender: Address,
        pub value: U256,
    }

    #[bloom_contract::event(domain = "pair")]
    pub struct Mint {
        #[indexed]
        pub sender: Address,
        pub amount0: U256,
        pub amount1: U256,
    }

    #[bloom_contract::event(domain = "pair")]
    pub struct Burn {
        #[indexed]
        pub sender: Address,
        pub amount0: U256,
        pub amount1: U256,
        #[indexed]
        pub to: Address,
    }

    #[bloom_contract::event(domain = "pair")]
    pub struct Swap {
        #[indexed]
        pub sender: Address,
        pub a0_in: U256,
        pub a1_in: U256,
        pub a0_out: U256,
        pub a1_out: U256,
        #[indexed]
        pub to: Address,
    }

    #[bloom_contract::event(domain = "pair")]
    pub struct Sync {
        pub reserve0: u128,
        pub reserve1: u128,
    }

    // -----------------------------------------------------------------------
    // Init — writes the bootstrap config slots.
    // -----------------------------------------------------------------------

    #[init]
    pub fn init(ctx: &mut Context, cfg: InitConfig) -> Result<()> {
        let state = State::load(ctx)?;
        state.token0.store(ctx, &cfg.token0);
        state.token1.store(ctx, &cfg.token1);
        state.self_addr.store(ctx, &cfg.pair_self_addr);
        state.reserve0.store(ctx, &0u128);
        state.reserve1.store(ctx, &0u128);
        state.total_supply.store(ctx, &U256::ZERO);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // ERC-20 view surface (LP token)
    // -----------------------------------------------------------------------

    #[view]
    pub fn name(_ctx: &Context) -> Result<Hash32> {
        Ok(NAME_SLOT.into())
    }

    #[view]
    pub fn symbol(_ctx: &Context) -> Result<Hash32> {
        Ok(SYMBOL_SLOT.into())
    }

    #[view]
    pub fn decimals(_ctx: &Context) -> Result<u8> {
        Ok(DECIMALS)
    }

    #[view]
    pub fn total_supply(ctx: &Context) -> Result<U256> {
        Ok(State::load(ctx)?.total_supply.load(ctx))
    }

    #[view]
    pub fn balance_of(ctx: &Context, owner: Address) -> Result<U256> {
        State::load(ctx)?.balances.get(ctx, &owner)
    }

    #[view]
    pub fn allowance(ctx: &Context, owner: Address, spender: Address) -> Result<U256> {
        State::load(ctx)?.allowances.get(ctx, &(owner, spender))
    }

    // -----------------------------------------------------------------------
    // ERC-20 mutating surface (LP token)
    // -----------------------------------------------------------------------

    pub fn transfer(ctx: &mut Context, to: Address, amount: U256) -> Result<bool> {
        let state = State::load(ctx)?;
        let sender = ctx.sender();
        erc20_do_transfer(ctx, &state, &sender, &to, amount)?;
        Transfer { from: sender, to, value: amount }.emit(ctx)?;
        Ok(true)
    }

    pub fn transfer_from(
        ctx: &mut Context,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<bool> {
        let state = State::load(ctx)?;
        let caller = ctx.sender();

        if caller != from {
            let current = state.allowances.get(ctx, &(from, caller))?;
            if current != U256_MAX {
                let new_allow = current
                    .checked_sub(amount)
                    .ok_or_else(|| ContractError::from_str("pair: insufficient allowance"))?;
                state.allowances.set(ctx, &(from, caller), &new_allow)?;
            }
        }

        erc20_do_transfer(ctx, &state, &from, &to, amount)?;
        Transfer { from, to, value: amount }.emit(ctx)?;
        Ok(true)
    }

    pub fn approve(ctx: &mut Context, spender: Address, value: U256) -> Result<bool> {
        let state = State::load(ctx)?;
        let owner = ctx.sender();
        state.allowances.set(ctx, &(owner, spender), &value)?;
        Approval { owner, spender, value }.emit(ctx)?;
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Pair view surface
    // -----------------------------------------------------------------------

    #[view]
    pub fn token0(ctx: &Context) -> Result<Address> {
        Ok(State::load(ctx)?.token0.load(ctx))
    }

    #[view]
    pub fn token1(ctx: &Context) -> Result<Address> {
        Ok(State::load(ctx)?.token1.load(ctx))
    }

    /// Returns `(reserve0, reserve1, block_timestamp_low64)` — encoded as 40
    /// bytes via `AbiEncode for (u128, u128, u64)` (16 BE + 16 BE + 8 BE).
    /// Byte-identical to the legacy hand-packed `get_reserves` return.
    #[view]
    pub fn get_reserves(ctx: &Context) -> Result<(u128, u128, u64)> {
        let state = State::load(ctx)?;
        Ok((
            state.reserve0.load(ctx),
            state.reserve1.load(ctx),
            block::timestamp(),
        ))
    }

    // -----------------------------------------------------------------------
    // Pair mutating surface
    // -----------------------------------------------------------------------

    #[nonreentrant]
    pub fn mint(ctx: &mut Context, to: Address) -> Result<U256> {
        let state = State::load(ctx)?;
        let token0 = state.token0.load(ctx);
        let token1 = state.token1.load(ctx);
        let self_addr = state.self_addr.load(ctx);

        // Balances after the user deposited tokens (caller transferred in
        // before calling mint).
        let bal0 = token_balance_of(ctx, &token0, &self_addr)?;
        let bal1 = token_balance_of(ctx, &token1, &self_addr)?;

        let r0 = state.reserve0.load(ctx);
        let r1 = state.reserve1.load(ctx);
        let r0_u = U256::from_u128(r0);
        let r1_u = U256::from_u128(r1);

        let amount0 = bal0
            .checked_sub(r0_u)
            .ok_or_else(|| ContractError::from_str("pair: mint amount0 underflow"))?;
        let amount1 = bal1
            .checked_sub(r1_u)
            .ok_or_else(|| ContractError::from_str("pair: mint amount1 underflow"))?;

        let total_supply = state.total_supply.load(ctx);

        let liquidity = if total_supply.is_zero() {
            // First mint: liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY.
            let product = amount0
                .checked_mul(amount1)
                .ok_or_else(|| ContractError::from_str("pair: mint product overflow"))?;
            let sqrt_prod = product.sqrt();
            let min_liq = U256::from_u128(MINIMUM_LIQUIDITY);
            let liq = sqrt_prod
                .checked_sub(min_liq)
                .ok_or_else(|| ContractError::from_str("pair: insufficient liquidity minted"))?;

            // Lock MINIMUM_LIQUIDITY to address(0).
            erc20_mint_internal(&state, ctx, &Address::ZERO, min_liq)?;
            liq
        } else {
            // Subsequent mints: min(amount0 * totalSupply / r0,
            //                       amount1 * totalSupply / r1).
            let liq0 = amount0
                .checked_mul(total_supply)
                .ok_or_else(|| ContractError::from_str("pair: mint liq0 overflow"))?
                .checked_div(r0_u)
                .ok_or_else(|| ContractError::from_str("pair: mint liq0 div zero"))?;
            let liq1 = amount1
                .checked_mul(total_supply)
                .ok_or_else(|| ContractError::from_str("pair: mint liq1 overflow"))?
                .checked_div(r1_u)
                .ok_or_else(|| ContractError::from_str("pair: mint liq1 div zero"))?;
            liq0.min(liq1)
        };

        if liquidity.is_zero() {
            return Err(ContractError::from_str("pair: insufficient liquidity minted"));
        }

        erc20_mint_internal(&state, ctx, &to, liquidity)?;

        let new_r0 = bal0
            .to_u128_checked()
            .ok_or_else(|| ContractError::from_str("pair: reserve0 overflow u128"))?;
        let new_r1 = bal1
            .to_u128_checked()
            .ok_or_else(|| ContractError::from_str("pair: reserve1 overflow u128"))?;
        update_reserves(ctx, &state, new_r0, new_r1);
        Sync { reserve0: new_r0, reserve1: new_r1 }.emit(ctx)?;

        let sender = ctx.sender();
        Mint { sender, amount0, amount1 }.emit(ctx)?;

        Ok(liquidity)
    }

    #[nonreentrant]
    pub fn burn(ctx: &mut Context, to: Address) -> Result<(U256, U256)> {
        let state = State::load(ctx)?;
        let token0 = state.token0.load(ctx);
        let token1 = state.token1.load(ctx);
        let self_addr = state.self_addr.load(ctx);

        let bal0 = token_balance_of(ctx, &token0, &self_addr)?;
        let bal1 = token_balance_of(ctx, &token1, &self_addr)?;

        let lp_bal = state.balances.get(ctx, &self_addr)?;
        if lp_bal.is_zero() {
            return Err(ContractError::from_str("pair: burn insufficient LP"));
        }

        let total_supply = state.total_supply.load(ctx);

        let amount0 = lp_bal
            .checked_mul(bal0)
            .ok_or_else(|| ContractError::from_str("pair: burn amount0 overflow"))?
            .checked_div(total_supply)
            .ok_or_else(|| ContractError::from_str("pair: burn div zero"))?;
        let amount1 = lp_bal
            .checked_mul(bal1)
            .ok_or_else(|| ContractError::from_str("pair: burn amount1 overflow"))?
            .checked_div(total_supply)
            .ok_or_else(|| ContractError::from_str("pair: burn div zero"))?;

        if amount0.is_zero() || amount1.is_zero() {
            return Err(ContractError::from_str(
                "pair: burn insufficient liquidity burned",
            ));
        }

        erc20_burn_internal(&state, ctx, &self_addr, lp_bal)?;

        token_transfer(ctx, &token0, &to, amount0)?;
        token_transfer(ctx, &token1, &to, amount1)?;

        let new_r0 = token_balance_of(ctx, &token0, &self_addr)?
            .to_u128_checked()
            .ok_or_else(|| ContractError::from_str("pair: post-burn reserve0 overflow"))?;
        let new_r1 = token_balance_of(ctx, &token1, &self_addr)?
            .to_u128_checked()
            .ok_or_else(|| ContractError::from_str("pair: post-burn reserve1 overflow"))?;
        update_reserves(ctx, &state, new_r0, new_r1);
        Sync { reserve0: new_r0, reserve1: new_r1 }.emit(ctx)?;

        let sender = ctx.sender();
        Burn { sender, amount0, amount1, to }.emit(ctx)?;

        Ok((amount0, amount1))
    }

    #[nonreentrant]
    pub fn swap(
        ctx: &mut Context,
        amount0_out: U256,
        amount1_out: U256,
        to: Address,
    ) -> Result<()> {
        if amount0_out.is_zero() && amount1_out.is_zero() {
            return Err(ContractError::from_str("pair: insufficient output amount"));
        }

        let state = State::load(ctx)?;
        let r0 = state.reserve0.load(ctx);
        let r1 = state.reserve1.load(ctx);
        let r0_u = U256::from_u128(r0);
        let r1_u = U256::from_u128(r1);

        if amount0_out >= r0_u || amount1_out >= r1_u {
            return Err(ContractError::from_str("pair: insufficient liquidity"));
        }

        let token0 = state.token0.load(ctx);
        let token1 = state.token1.load(ctx);
        let self_addr = state.self_addr.load(ctx);

        // Optimistic transfer-out before invariant check.
        if !amount0_out.is_zero() {
            token_transfer(ctx, &token0, &to, amount0_out)?;
        }
        if !amount1_out.is_zero() {
            token_transfer(ctx, &token1, &to, amount1_out)?;
        }

        let bal0 = token_balance_of(ctx, &token0, &self_addr)?;
        let bal1 = token_balance_of(ctx, &token1, &self_addr)?;

        // amount_in = balance - (reserve - amount_out), clamped to 0.
        let bal0_expected = r0_u.checked_sub(amount0_out).unwrap_or(U256::ZERO);
        let bal1_expected = r1_u.checked_sub(amount1_out).unwrap_or(U256::ZERO);
        let amount0_in = if bal0 > bal0_expected {
            bal0.checked_sub(bal0_expected).unwrap_or(U256::ZERO)
        } else {
            U256::ZERO
        };
        let amount1_in = if bal1 > bal1_expected {
            bal1.checked_sub(bal1_expected).unwrap_or(U256::ZERO)
        } else {
            U256::ZERO
        };

        if amount0_in.is_zero() && amount1_in.is_zero() {
            return Err(ContractError::from_str("pair: insufficient input amount"));
        }

        // Invariant: (b0*1000 - a0in*3) * (b1*1000 - a1in*3) >= r0*r1*1_000_000
        let k1000 = U256::from_u64(1000);
        let k3 = U256::from_u64(3);
        let k1m = U256::from_u64(1_000_000);

        let bal0_adj = bal0
            .checked_mul(k1000)
            .and_then(|v| {
                let fee = amount0_in.checked_mul(k3)?;
                v.checked_sub(fee)
            })
            .ok_or_else(|| ContractError::from_str("pair: K adj0 overflow"))?;
        let bal1_adj = bal1
            .checked_mul(k1000)
            .and_then(|v| {
                let fee = amount1_in.checked_mul(k3)?;
                v.checked_sub(fee)
            })
            .ok_or_else(|| ContractError::from_str("pair: K adj1 overflow"))?;

        let lhs = bal0_adj
            .checked_mul(bal1_adj)
            .ok_or_else(|| ContractError::from_str("pair: K"))?;
        let rhs = r0_u
            .checked_mul(r1_u)
            .and_then(|v| v.checked_mul(k1m))
            .ok_or_else(|| ContractError::from_str("pair: K rhs overflow"))?;

        if lhs < rhs {
            return Err(ContractError::from_str("pair: K"));
        }

        let new_r0 = bal0
            .to_u128_checked()
            .ok_or_else(|| ContractError::from_str("pair: swap reserve0 overflow u128"))?;
        let new_r1 = bal1
            .to_u128_checked()
            .ok_or_else(|| ContractError::from_str("pair: swap reserve1 overflow u128"))?;
        update_reserves(ctx, &state, new_r0, new_r1);
        Sync { reserve0: new_r0, reserve1: new_r1 }.emit(ctx)?;

        let sender = ctx.sender();
        Swap {
            sender,
            a0_in: amount0_in,
            a1_in: amount1_in,
            a0_out: amount0_out,
            a1_out: amount1_out,
            to,
        }
        .emit(ctx)?;

        Ok(())
    }

    pub fn skim(ctx: &mut Context, to: Address) -> Result<()> {
        let state = State::load(ctx)?;
        let token0 = state.token0.load(ctx);
        let token1 = state.token1.load(ctx);
        let self_addr = state.self_addr.load(ctx);
        let r0_u = U256::from_u128(state.reserve0.load(ctx));
        let r1_u = U256::from_u128(state.reserve1.load(ctx));

        let bal0 = token_balance_of(ctx, &token0, &self_addr)?;
        let bal1 = token_balance_of(ctx, &token1, &self_addr)?;

        if bal0 > r0_u {
            let surplus = bal0.checked_sub(r0_u).unwrap_or(U256::ZERO);
            if !surplus.is_zero() {
                token_transfer(ctx, &token0, &to, surplus)?;
            }
        }
        if bal1 > r1_u {
            let surplus = bal1.checked_sub(r1_u).unwrap_or(U256::ZERO);
            if !surplus.is_zero() {
                token_transfer(ctx, &token1, &to, surplus)?;
            }
        }
        Ok(())
    }

    pub fn sync(ctx: &mut Context) -> Result<()> {
        let state = State::load(ctx)?;
        let token0 = state.token0.load(ctx);
        let token1 = state.token1.load(ctx);
        let self_addr = state.self_addr.load(ctx);

        let bal0 = token_balance_of(ctx, &token0, &self_addr)?;
        let bal1 = token_balance_of(ctx, &token1, &self_addr)?;

        let new_r0 = bal0
            .to_u128_checked()
            .ok_or_else(|| ContractError::from_str("pair: sync reserve0 overflow"))?;
        let new_r1 = bal1
            .to_u128_checked()
            .ok_or_else(|| ContractError::from_str("pair: sync reserve1 overflow"))?;
        update_reserves(ctx, &state, new_r0, new_r1);
        Sync { reserve0: new_r0, reserve1: new_r1 }.emit(ctx)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers — `pub(crate)` keeps them out of dispatch.
    // -----------------------------------------------------------------------

    pub(crate) fn erc20_do_transfer(
        ctx: &mut Context,
        state: &State,
        from: &Address,
        to: &Address,
        amount: U256,
    ) -> Result<()> {
        if from == to {
            return Ok(());
        }
        let bal_from = state.balances.get(ctx, from)?;
        let new_from = bal_from
            .checked_sub(amount)
            .ok_or_else(|| ContractError::from_str("pair: transfer exceeds balance"))?;
        state.balances.set(ctx, from, &new_from)?;
        let bal_to = state.balances.get(ctx, to)?;
        let new_to = bal_to
            .checked_add(amount)
            .ok_or_else(|| ContractError::from_str("pair: transfer overflow"))?;
        state.balances.set(ctx, to, &new_to)?;
        Ok(())
    }

    pub(crate) fn erc20_mint_internal(
        state: &State,
        ctx: &mut Context,
        to: &Address,
        amount: U256,
    ) -> Result<()> {
        let total = state.total_supply.load(ctx);
        let new_total = total
            .checked_add(amount)
            .ok_or_else(|| ContractError::from_str("pair: mint overflow"))?;
        state.total_supply.store(ctx, &new_total);

        let bal = state.balances.get(ctx, to)?;
        let new_bal = bal
            .checked_add(amount)
            .ok_or_else(|| ContractError::from_str("pair: mint balance overflow"))?;
        state.balances.set(ctx, to, &new_bal)?;

        Transfer { from: Address::ZERO, to: *to, value: amount }.emit(ctx)?;
        Ok(())
    }

    pub(crate) fn erc20_burn_internal(
        state: &State,
        ctx: &mut Context,
        from: &Address,
        amount: U256,
    ) -> Result<()> {
        let total = state.total_supply.load(ctx);
        let new_total = total
            .checked_sub(amount)
            .ok_or_else(|| ContractError::from_str("pair: burn underflow total"))?;
        state.total_supply.store(ctx, &new_total);

        let bal = state.balances.get(ctx, from)?;
        let new_bal = bal
            .checked_sub(amount)
            .ok_or_else(|| ContractError::from_str("pair: burn exceeds balance"))?;
        state.balances.set(ctx, from, &new_bal)?;

        Transfer { from: *from, to: Address::ZERO, value: amount }.emit(ctx)?;
        Ok(())
    }

    pub(crate) fn update_reserves(ctx: &mut Context, state: &State, r0: u128, r1: u128) {
        state.reserve0.store(ctx, &r0);
        state.reserve1.store(ctx, &r1);
        // k_last = r0 * r1 (stored as U256 for future feeTo reactivation).
        let k = U256::from_u128(r0)
            .checked_mul(U256::from_u128(r1))
            .unwrap_or(U256::ZERO);
        state.k_last.store(ctx, &k);
    }

    /// Query `token.balance_of(target_addr)` via a cross-contract call.
    pub(crate) fn token_balance_of(
        ctx: &mut Context,
        token_addr: &Address,
        target_addr: &Address,
    ) -> Result<U256> {
        ctx.call::<Erc20>(*token_addr)
            .balance_of(ctx, *target_addr)
            .map_err(|_| ContractError::from_str("pair: token.balance_of call failed"))
    }

    /// Transfer `amount` of `token` to `to` via ERC-20 `transfer`.
    pub(crate) fn token_transfer(
        ctx: &mut Context,
        token_addr: &Address,
        to: &Address,
        amount: U256,
    ) -> Result<()> {
        ctx.call::<Erc20>(*token_addr)
            .transfer(ctx, *to, amount)
            .map(|_| ())
            .map_err(|_| ContractError::from_str("pair: token.transfer failed"))
    }
}

// ---------------------------------------------------------------------------
// Hand-rolled calldata builders for sibling petals (router).
// ---------------------------------------------------------------------------

pub mod calls {
    use super::*;
    use alloc::vec::Vec;
    use bloom_chain_abi::Encoder;

    /// Build `pair.token0()` calldata.
    pub fn token0() -> Vec<u8> {
        Encoder::with_selector(Pair::SEL_TOKEN0).finish()
    }

    /// Build `pair.token1()` calldata.
    pub fn token1() -> Vec<u8> {
        Encoder::with_selector(Pair::SEL_TOKEN1).finish()
    }

    /// Build `pair.get_reserves()` calldata.
    pub fn get_reserves() -> Vec<u8> {
        Encoder::with_selector(Pair::SEL_GET_RESERVES).finish()
    }

    /// Build `pair.mint(to)` calldata.
    pub fn mint(to: &[u8; 32]) -> Vec<u8> {
        let mut e = Encoder::with_selector(Pair::SEL_MINT);
        e.push_address(to);
        e.finish()
    }

    /// Build `pair.burn(to)` calldata.
    pub fn burn(to: &[u8; 32]) -> Vec<u8> {
        let mut e = Encoder::with_selector(Pair::SEL_BURN);
        e.push_address(to);
        e.finish()
    }

    /// Build `pair.swap(amount0_out, amount1_out, to)` calldata.
    pub fn swap(amount0_out: U256, amount1_out: U256, to: &[u8; 32]) -> Vec<u8> {
        let mut e = Encoder::with_selector(Pair::SEL_SWAP);
        e.push_u256(amount0_out);
        e.push_u256(amount1_out);
        e.push_address(to);
        e.finish()
    }
}

// ---------------------------------------------------------------------------
// Build the legacy 96-byte pair init payload from typed inputs. Used by
// `bloom-dex-factory::create_pair` (constructed inline there to avoid an
// rlib dep) and by host-side tests.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub fn encode_init_payload(
    token0: [u8; 32],
    token1: [u8; 32],
    pair_self_addr: [u8; 32],
) -> ::core::result::Result<alloc::vec::Vec<u8>, ::bloom_contract::abi::AbiEncodeError> {
    let cfg = InitConfig {
        token0: Address::from(token0),
        token1: Address::from(token1),
        pair_self_addr: Address::from(pair_self_addr),
    };
    cfg.encode()
}

// ---------------------------------------------------------------------------
// Host-target unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn blake3_selector(sig: &str) -> [u8; 4] {
        let h = blake3::hash(sig.as_bytes());
        let b = h.as_bytes();
        [b[0], b[1], b[2], b[3]]
    }

    // ---- Selector parity ----

    #[test]
    fn pair_selectors_match_dex_v0_canonical_strings() {
        assert_eq!(Pair::SEL_TOKEN0,       blake3_selector("pair.token0()"));
        assert_eq!(Pair::SEL_TOKEN1,       blake3_selector("pair.token1()"));
        assert_eq!(Pair::SEL_GET_RESERVES, blake3_selector("pair.get_reserves()"));
        assert_eq!(Pair::SEL_MINT,         blake3_selector("pair.mint(address)"));
        assert_eq!(Pair::SEL_BURN,         blake3_selector("pair.burn(address)"));
        assert_eq!(Pair::SEL_SWAP,         blake3_selector("pair.swap(u256,u256,address)"));
        assert_eq!(Pair::SEL_SKIM,         blake3_selector("pair.skim(address)"));
        assert_eq!(Pair::SEL_SYNC,         blake3_selector("pair.sync()"));
    }

    #[test]
    fn erc20_selectors_anchored_via_dex_erc20() {
        // The LP-token surface routes through the shared `bloom_dex_erc20::Erc20`
        // interface, so the pair gets the same selectors any ERC-20 petal
        // does. The dedicated bloom-dex-erc20 tests pin the full byte-for-byte
        // parity; here we just sanity-check the entry points the pair handlers
        // are matched against.
        assert_eq!(Erc20::SEL_TRANSFER,      blake3_selector("erc20.transfer(address,u256)"));
        assert_eq!(Erc20::SEL_TRANSFER_FROM, blake3_selector("erc20.transfer_from(address,address,u256)"));
        assert_eq!(Erc20::SEL_BALANCE_OF,    blake3_selector("erc20.balance_of(address)"));
    }

    #[test]
    fn selectors_are_unique() {
        let sels = [
            Pair::SEL_TOKEN0,
            Pair::SEL_TOKEN1,
            Pair::SEL_GET_RESERVES,
            Pair::SEL_MINT,
            Pair::SEL_BURN,
            Pair::SEL_SWAP,
            Pair::SEL_SKIM,
            Pair::SEL_SYNC,
            Erc20::SEL_TOTAL_SUPPLY,
            Erc20::SEL_BALANCE_OF,
            Erc20::SEL_ALLOWANCE,
            Erc20::SEL_TRANSFER,
            Erc20::SEL_TRANSFER_FROM,
            Erc20::SEL_APPROVE,
            Erc20::SEL_NAME,
            Erc20::SEL_SYMBOL,
            Erc20::SEL_DECIMALS,
        ];
        let mut deduped = sels.to_vec();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), sels.len(), "selector collision");
    }

    // ---- Storage slot byte-equality parity ----

    fn blake3_slot(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for p in parts {
            h.update(p);
        }
        *h.finalize().as_bytes()
    }

    #[test]
    fn storage_slot_parity_scalars() {
        use bloom_contract::storage::slot_for_compat_tag;
        for tag in [
            "pair.token0",
            "pair.token1",
            "pair.reserve0",
            "pair.reserve1",
            "pair.k_last",
            "pair.self",
            "erc20.total_supply",
        ] {
            let exp = blake3::hash(tag.as_bytes());
            assert_eq!(&slot_for_compat_tag(tag)[..], &exp.as_bytes()[..]);
        }
    }

    #[test]
    fn storage_slot_parity_balance_mapping() {
        let addr = Address::from([0x42u8; 32]);
        let expected = blake3_slot(&[b"erc20.balance:", addr.as_bytes()]);
        let m: Map<Address, U256> = Map::new(b"erc20.balance:");
        assert_eq!(m.slot(&addr).expect("slot ok"), expected);
    }

    #[test]
    fn storage_slot_parity_allowance_mapping() {
        let owner = Address::from([0x11u8; 32]);
        let spender = Address::from([0x22u8; 32]);
        let expected = blake3_slot(&[
            b"erc20.allowance:",
            owner.as_bytes(),
            spender.as_bytes(),
        ]);
        let m: Map<(Address, Address), U256> = Map::new(b"erc20.allowance:");
        assert_eq!(m.slot(&(owner, spender)).expect("slot ok"), expected);
    }

    // ---- Init payload ----

    #[test]
    fn init_payload_is_exactly_96_bytes() {
        let t0 = [0x01u8; 32];
        let t1 = [0x02u8; 32];
        let sa = [0x04u8; 32];
        let payload = encode_init_payload(t0, t1, sa).unwrap();
        assert_eq!(payload.len(), 96, "pair init must be 96 bytes");
        assert_eq!(&payload[0..32],  &t0);
        assert_eq!(&payload[32..64], &t1);
        assert_eq!(&payload[64..96], &sa);

        let parsed = InitConfig::decode_from(&payload).unwrap();
        assert_eq!(parsed.token0, Address::from(t0));
        assert_eq!(parsed.token1, Address::from(t1));
        assert_eq!(parsed.pair_self_addr, Address::from(sa));
    }

    #[test]
    fn init_payload_rejects_wrong_length() {
        let short = [0u8; 95];
        assert!(InitConfig::decode_from(&short).is_err());
        let long = [0u8; 97];
        assert!(InitConfig::decode_from(&long).is_err());
    }

    // ---- Calls builder layouts ----

    #[test]
    fn calls_get_reserves_is_just_the_selector() {
        let cd = calls::get_reserves();
        assert_eq!(cd, Pair::SEL_GET_RESERVES.to_vec());
    }

    #[test]
    fn calls_mint_layout() {
        let to = [0x77u8; 32];
        let cd = calls::mint(&to);
        assert_eq!(cd.len(), 4 + 32);
        assert_eq!(&cd[..4], &Pair::SEL_MINT);
        assert_eq!(&cd[4..], &to);
    }

    #[test]
    fn calls_swap_layout() {
        let to = [0x33u8; 32];
        let a0 = U256::from_u64(111);
        let a1 = U256::from_u64(222);
        let cd = calls::swap(a0, a1, &to);
        assert_eq!(cd.len(), 4 + 32 + 32 + 32);
        assert_eq!(&cd[..4], &Pair::SEL_SWAP);
        assert_eq!(&cd[4..36], &a0.0);
        assert_eq!(&cd[36..68], &a1.0);
        assert_eq!(&cd[68..100], &to);
    }

    // ---- Name / symbol slot layout ----

    #[test]
    fn name_slot_is_right_aligned_ascii() {
        // First 15 bytes hold "BloomDexPair LP"; trailing 17 are zero.
        assert_eq!(&NAME_SLOT.0[..15], b"BloomDexPair LP");
        assert!(NAME_SLOT.0[15..].iter().all(|&b| b == 0));
    }

    #[test]
    fn symbol_slot_is_right_aligned_ascii() {
        assert_eq!(&SYMBOL_SLOT.0[..4], b"BDPL");
        assert!(SYMBOL_SLOT.0[4..].iter().all(|&b| b == 0));
    }

    // ---- AMM math (Uniswap v2 formula) ----

    fn swap_out(a_in: u128, r_in: u128, r_out: u128) -> u128 {
        let a_in_u   = U256::from_u128(a_in);
        let r_in_u   = U256::from_u128(r_in);
        let r_out_u  = U256::from_u128(r_out);
        let k997     = U256::from_u64(997);
        let k1000    = U256::from_u64(1000);

        let a_in_fee = a_in_u.checked_mul(k997).unwrap();
        let numerator = a_in_fee.checked_mul(r_out_u).unwrap();
        let denominator = r_in_u
            .checked_mul(k1000).unwrap()
            .checked_add(a_in_fee).unwrap();
        let result = numerator.checked_div(denominator).unwrap();
        result.to_u128_checked().unwrap()
    }

    fn invariant_holds_after_swap(r_in: u128, r_out: u128, a_in: u128, a_out: u128) -> bool {
        let bal_in = r_in + a_in;
        let bal_out = r_out - a_out;

        let bal_in_u = U256::from_u128(bal_in);
        let bal_out_u = U256::from_u128(bal_out);
        let a_in_u = U256::from_u128(a_in);
        let k1000 = U256::from_u64(1000);
        let k3 = U256::from_u64(3);
        let k1m = U256::from_u64(1_000_000);
        let r_in_u = U256::from_u128(r_in);
        let r_out_u = U256::from_u128(r_out);

        let adj_in = bal_in_u
            .checked_mul(k1000).unwrap()
            .checked_sub(a_in_u.checked_mul(k3).unwrap()).unwrap();
        let adj_out = bal_out_u.checked_mul(k1000).unwrap();

        let lhs = adj_in.checked_mul(adj_out).unwrap();
        let rhs = r_in_u.checked_mul(r_out_u).unwrap().checked_mul(k1m).unwrap();
        lhs >= rhs
    }

    #[test]
    fn swap_formula_reference_vector_1() {
        let a_in = 100u128;
        let r_in = 1000u128;
        let r_out = 1000u128;
        let expected = (a_in * 997 * r_out) / (r_in * 1000 + a_in * 997);
        let got = swap_out(a_in, r_in, r_out);
        assert_eq!(got, expected, "swap formula mismatch");
        assert!(got > 0, "expected non-zero output");
        assert!(invariant_holds_after_swap(r_in, r_out, a_in, got));
    }

    #[test]
    fn swap_formula_reference_vector_2() {
        let a_in = 1_000_000_000_000_000u128;
        let r_in = 1_000_000_000_000_000_000u128;
        let r_out = 1_000_000_000_000_000_000u128;

        let got = swap_out(a_in, r_in, r_out);
        assert!(got > 0);
        assert!(got < a_in, "output should be less than input (fee)");
        let approx_no_slippage = a_in * 997 / 1000;
        let tolerance = a_in / 1000;
        assert!(
            got >= approx_no_slippage - tolerance,
            "swap output too low: got {got}, expected ~{approx_no_slippage}"
        );
        assert!(invariant_holds_after_swap(r_in, r_out, a_in, got));
    }

    #[test]
    fn swap_formula_reference_vector_3() {
        let a_in = 1_000_000_000_000_000_000u128;
        let r_in  = 1_000_000_000_000_000_000_000u128;
        let r_out = 1_000_000_000_000_000_000_000u128;

        let got = swap_out(a_in, r_in, r_out);

        let approx = 996_006_981_039_903_216u128;
        assert!(
            (got as i128 - approx as i128).abs() <= 1,
            "expected ≈{approx}, got {got}"
        );
        assert!(invariant_holds_after_swap(r_in, r_out, a_in, got));
    }

    #[test]
    fn swap_invariant_check_u256() {
        let r_in = 1_000_000u128;
        let r_out = 2_000_000u128;
        let a_in = 500u128;
        let a_out = swap_out(a_in, r_in, r_out);

        assert!(invariant_holds_after_swap(r_in, r_out, a_in, a_out));

        let a_out_too_much = a_out + 1;
        if r_out > a_out_too_much {
            assert!(!invariant_holds_after_swap(r_in, r_out, a_in, a_out_too_much));
        }
    }

    // ---- Babylonian sqrt corner cases ----

    #[test]
    fn sqrt_zero() {
        assert_eq!(U256::ZERO.sqrt(), U256::ZERO);
    }

    #[test]
    fn sqrt_one() {
        assert_eq!(U256::from_u64(1).sqrt(), U256::from_u64(1));
    }

    #[test]
    fn sqrt_four() {
        assert_eq!(U256::from_u64(4).sqrt(), U256::from_u64(2));
    }

    #[test]
    fn sqrt_perfect_squares() {
        for n in [0u64, 1, 2, 3, 4, 9, 16, 25, 100, 1024, 65536, 1_000_000] {
            let sq = U256::from_u128(n as u128 * n as u128);
            let root = sq.sqrt();
            assert_eq!(root, U256::from_u64(n), "sqrt({n}^2) should be {n}");
        }
    }

    #[test]
    fn sqrt_non_perfect() {
        assert_eq!(U256::from_u64(2).sqrt(), U256::from_u64(1));
        assert_eq!(U256::from_u64(3).sqrt(), U256::from_u64(1));
        assert_eq!(U256::from_u64(8).sqrt(), U256::from_u64(2));
        assert_eq!(U256::from_u64(10).sqrt(), U256::from_u64(3));
        assert_eq!(U256::from_u64(15).sqrt(), U256::from_u64(3));
    }

    #[test]
    fn sqrt_large_number() {
        let r: u128 = 1_000_000_000_000_000_000_000;
        let sq = U256::from_u128(r).checked_mul(U256::from_u128(r)).expect("no overflow");
        let root = sq.sqrt();
        assert_eq!(root, U256::from_u128(r), "sqrt(1e21^2) should be 1e21");
    }

    #[test]
    fn sqrt_min_liquidity_scenario() {
        let amount0 = U256::from_u128(1_000_000_000_000_000_000_000u128);
        let amount1 = U256::from_u128(1_000_000_000_000_000_000_000u128);
        let product = amount0.checked_mul(amount1).unwrap();
        let sqrt_prod = product.sqrt();
        let min_liq = U256::from_u128(MINIMUM_LIQUIDITY);
        let liq = sqrt_prod.checked_sub(min_liq).unwrap();

        let expected = U256::from_u128(1_000_000_000_000_000_000_000u128 - 1000);
        assert_eq!(liq, expected);
    }

    // ---- LP math ----

    #[test]
    fn mint_liquidity_second_mint() {
        let r0 = 1_000_000_000_000_000_000u128;
        let r1 = 1_000_000_000_000_000_000u128;
        let ts = r0 - 1000;
        let amount0 = 500_000_000_000_000_000u128;
        let amount1 = 500_000_000_000_000_000u128;

        let ts_u = U256::from_u128(ts);
        let r0_u = U256::from_u128(r0);
        let r1_u = U256::from_u128(r1);
        let a0_u = U256::from_u128(amount0);
        let a1_u = U256::from_u128(amount1);

        let liq0 = a0_u.checked_mul(ts_u).unwrap().checked_div(r0_u).unwrap();
        let liq1 = a1_u.checked_mul(ts_u).unwrap().checked_div(r1_u).unwrap();
        let liq = liq0.min(liq1);

        let expected = U256::from_u128(amount0 * ts / r0);
        assert_eq!(liq, expected);
        assert!(liq > U256::ZERO);
    }

    #[test]
    fn burn_amounts() {
        let total = U256::from_u128(1_000_000_000_000_000_000u128 - 1000);
        let lp = U256::from_u128(100_000_000_000_000_000u128);
        let bal0 = U256::from_u128(1_000_000_000_000_000_000_000u128);
        let bal1 = bal0;

        let amt0 = lp.checked_mul(bal0).unwrap().checked_div(total).unwrap();
        let amt1 = lp.checked_mul(bal1).unwrap().checked_div(total).unwrap();

        let approx = U256::from_u128(100_000_000_000_000_100_000u128);
        assert!(amt0 <= approx);
        assert!(amt0 >= U256::from_u128(99_999_999_000_000_000_000u128));
        assert_eq!(amt0, amt1);
    }
}
