//! bloom-dex-wloom — Wrapped LOOM (wLOOM) petal for bloom-chain DEX.
//!
//! Mirrors WETH9 semantics: wraps native LOOM as an ERC-20 token. Single
//! global deployment per DEX; its address is baked into router init.
//!
//! ## Constants
//! - `name`    = "Wrapped LOOM"
//! - `symbol`  = "wLOOM"
//! - `decimals` = 18
//!
//! ## ABI surface
//!
//! - The standard ERC-20 surface (`name`/`symbol`/`decimals`/`total_supply`/
//!   `balance_of`/`allowance`/`transfer`/`transfer_from`/`approve`) is
//!   inherited from the [`bloom_dex_erc20::Erc20`] interface, so callers reach
//!   wLOOM with the exact same selectors and calldata they use for any other
//!   ERC-20 petal.
//! - Wrapping-specific methods live on the [`Wloom`] interface:
//!   `wloom.deposit()` and `wloom.withdraw(u256)`. The dispatcher also routes
//!   *empty* calldata (typical for bare-LOOM transfers) into `deposit`, via
//!   the `#[fallback]` marker on that handler.
//!
//! ## Storage layout (byte-for-byte legacy parity)
//! - `wloom.total_supply`               → U256
//! - `wloom.balance:` || addr           → U256
//! - `wloom.allowance:` || owner || sp  → U256
//!
//! ## Events
//! - `Transfer` and `Approval` are re-used from `bloom-dex-erc20` so wLOOM
//!   logs are indistinguishable from a normal ERC-20 transfer to indexers
//!   (same domain, same TOPIC0).
//! - `Deposit` and `Withdrawal` live in the `wloom` event domain.
//!   `Deposit` is paired with a `Transfer(0x0, dst, value)` mint signal and
//!   `Withdrawal` with a `Transfer(src, 0x0, value)` burn signal.

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use bloom_contract::context::LoomValue;
use bloom_contract::prelude::*;
use bloom_dex_erc20::Erc20;
use bloom_dex_erc20::erc20::{Approval, Transfer};

// ---------------------------------------------------------------------------
// Wrapping-specific interface
// ---------------------------------------------------------------------------

/// Typed interface for the wLOOM-specific surface. Lives outside the generic
/// ERC-20 interface so contracts that only implement plain ERC-20 don't have
/// to also expose `deposit`/`withdraw`.
///
/// Selectors hash from `wloom.<method>(<types>)` so they match every legacy
/// `bloom_chain_abi::contract! { contract Wloom { ... } }` deployment.
#[bloom_contract::interface(domain = "wloom")]
pub trait Wloom {
    fn deposit() -> Result<()>;
    fn withdraw(amount: U256) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `u256::MAX` sentinel: an allowance equal to this is treated as unlimited
/// and is not decremented by `transfer_from` (standard ERC-20 convention).
const U256_MAX: U256 = U256([0xff; 32]);

/// ASCII bytes of the on-chain name (right-padded into a `Hash32` slot).
const NAME_BYTES: &[u8] = b"Wrapped LOOM";

/// ASCII bytes of the on-chain symbol (right-padded into a `Hash32` slot).
const SYMBOL_BYTES: &[u8] = b"wLOOM";

/// Token decimal places. Returned as a single byte via `AbiEncode for u8`.
const DECIMALS: u8 = 18;

/// Right-align `bytes` (≤ 32 bytes) into a 32-byte slot so the trailing
/// bytes hold the ASCII data (zeros to the left). Matches the legacy
/// `name_bytes32` / `symbol_bytes32` layout used by the chain-ABI macro.
const fn pad_left_32(bytes: &[u8]) -> Hash32 {
    let mut slot = [0u8; 32];
    let offset = 32 - bytes.len();
    let mut i = 0;
    while i < bytes.len() {
        slot[offset + i] = bytes[i];
        i += 1;
    }
    Hash32(slot)
}

const NAME_SLOT: Hash32 = pad_left_32(NAME_BYTES);
const SYMBOL_SLOT: Hash32 = pad_left_32(SYMBOL_BYTES);

// ---------------------------------------------------------------------------
// Contract body
// ---------------------------------------------------------------------------

#[bloom_contract::contract(domain = "erc20", interfaces(Erc20, Wloom))]
pub mod wloom {
    use super::*;

    // -----------------------------------------------------------------------
    // Storage — every slot keeps its legacy `wloom.*` tag for byte-for-byte
    // parity with the pre-migration deployment.
    // -----------------------------------------------------------------------

    #[bloom_contract::storage(domain = "wloom")]
    pub struct State {
        #[storage(compat_tag = "wloom.total_supply")]
        pub total_supply: StorageValue<U256>,
        #[storage(compat_tag = "wloom.balance:")]
        pub balances: Map<Address, U256>,
        #[storage(compat_tag = "wloom.allowance:")]
        pub allowances: Map<(Address, Address), U256>,
    }

    // -----------------------------------------------------------------------
    // Events — wLOOM-specific. ERC-20 `Transfer`/`Approval` are inherited
    // verbatim from bloom-dex-erc20 so log topic-0 stays identical to plain
    // ERC-20 transfers.
    // -----------------------------------------------------------------------

    #[bloom_contract::event(domain = "wloom")]
    pub struct Deposit {
        #[indexed]
        pub dst: Address,
        pub value: U256,
    }

    #[bloom_contract::event(domain = "wloom")]
    pub struct Withdrawal {
        #[indexed]
        pub src: Address,
        pub value: U256,
    }

    // -----------------------------------------------------------------------
    // Init — no parameters. Writes `total_supply = 0` to mark the petal as
    // initialised. Name/symbol/decimals are hardcoded constants and not
    // stored.
    // -----------------------------------------------------------------------

    #[init]
    pub fn init(ctx: &mut Context) -> Result<()> {
        let state = State::load(ctx)?;
        state.total_supply.store(&U256::ZERO);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // ERC-20 view surface
    // -----------------------------------------------------------------------

    #[view]
    pub fn name(_ctx: &Context) -> Result<Hash32> {
        Ok(NAME_SLOT)
    }

    #[view]
    pub fn symbol(_ctx: &Context) -> Result<Hash32> {
        Ok(SYMBOL_SLOT)
    }

    #[view]
    pub fn decimals(_ctx: &Context) -> Result<u8> {
        Ok(DECIMALS)
    }

    #[view]
    pub fn total_supply(ctx: &Context) -> Result<U256> {
        Ok(State::load(ctx)?.total_supply.load())
    }

    #[view]
    pub fn balance_of(ctx: &Context, owner: Address) -> Result<U256> {
        State::load(ctx)?.balances.get(&owner)
    }

    #[view]
    pub fn allowance(ctx: &Context, owner: Address, spender: Address) -> Result<U256> {
        State::load(ctx)?.allowances.get(&(owner, spender))
    }

    // -----------------------------------------------------------------------
    // ERC-20 mutating surface
    // -----------------------------------------------------------------------

    pub fn transfer(ctx: &mut Context, to: Address, amount: U256) -> Result<bool> {
        let state = State::load(ctx)?;
        let sender = ctx.sender();
        do_transfer(&state, &sender, &to, amount)?;
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

        let current = state.allowances.get(&(from, caller))?;
        if current != U256_MAX {
            let new_allow = current
                .checked_sub(amount)
                .ok_or_else(|| ContractError::from_str("wloom: insufficient allowance"))?;
            state.allowances.set(&(from, caller), &new_allow)?;
        }

        do_transfer(&state, &from, &to, amount)?;
        Transfer { from, to, value: amount }.emit(ctx)?;
        Ok(true)
    }

    pub fn approve(ctx: &mut Context, spender: Address, value: U256) -> Result<bool> {
        let state = State::load(ctx)?;
        let owner = ctx.sender();
        state.allowances.set(&(owner, spender), &value)?;
        Approval { owner, spender, value }.emit(ctx)?;
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // wLOOM wrapping surface
    // -----------------------------------------------------------------------

    /// `wloom.deposit()` — payable.
    ///
    /// Credits `ctx.sender()` with `ctx.value()` wLOOM and increments total
    /// supply. Emits `Deposit(sender, value)` plus `Transfer(0x0, sender,
    /// value)` as a mint signal. Zero-value calls are a no-op.
    ///
    /// `#[fallback]` routes bare-LOOM transfers (calldata shorter than the
    /// 4-byte selector window) into this handler too.
    #[payable]
    #[fallback]
    pub fn deposit(ctx: &mut Context) -> Result<()> {
        let sender = ctx.sender();
        let value = ctx.value();
        let amount = U256::from_u128(value.to_u128());

        if !amount.is_zero() {
            let state = State::load(ctx)?;

            let ts = state.total_supply.load();
            let new_ts = ts
                .checked_add(amount)
                .ok_or_else(|| ContractError::from_str("wloom: total supply overflow"))?;
            state.total_supply.store(&new_ts);

            let bal = state.balances.get(&sender)?;
            let new_bal = bal
                .checked_add(amount)
                .ok_or_else(|| ContractError::from_str("wloom: balance overflow"))?;
            state.balances.set(&sender, &new_bal)?;

            Deposit { dst: sender, value: amount }.emit(ctx)?;
            Transfer { from: Address::ZERO, to: sender, value: amount }.emit(ctx)?;
        }
        Ok(())
    }

    /// `wloom.withdraw(amount: u256)`.
    ///
    /// Debits `amount` from the caller, decrements total supply, emits
    /// `Withdrawal(sender, amount)` and `Transfer(sender, 0x0, amount)`
    /// (burn signal), then sends native LOOM to the caller via empty-calldata
    /// `ctx.raw_call`. Reverts on insufficient balance, on a >u128 amount,
    /// or if the native LOOM transfer fails.
    pub fn withdraw(ctx: &mut Context, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }
        let sender = ctx.sender();
        let state = State::load(ctx)?;

        let bal = state.balances.get(&sender)?;
        let new_bal = bal
            .checked_sub(amount)
            .ok_or_else(|| ContractError::from_str("wloom: insufficient balance"))?;
        state.balances.set(&sender, &new_bal)?;

        let ts = state.total_supply.load();
        let new_ts = ts
            .checked_sub(amount)
            .ok_or_else(|| ContractError::from_str("wloom: total supply underflow"))?;
        state.total_supply.store(&new_ts);

        Withdrawal { src: sender, value: amount }.emit(ctx)?;
        Transfer { from: sender, to: Address::ZERO, value: amount }.emit(ctx)?;

        // wLOOM mints are gated through deposits, so any in-supply balance
        // fits in u128 (the native LOOM type). The explicit conversion guards
        // any future path that could put a >u128 amount here.
        let value = LoomValue::try_from_be_u256_bytes(&amount.0)
            .map_err(|_| ContractError::from_str("wloom: withdraw amount exceeds u128"))?;
        ctx.raw_call(&sender, &[], value)
            .map_err(|_| ContractError::from_str("wloom: native LOOM transfer failed"))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers — `pub(crate)` keeps them out of dispatch but reachable
    // from sibling `super::calls` builders.
    // -----------------------------------------------------------------------

    pub(crate) fn do_transfer(
        state: &State,
        from: &Address,
        to: &Address,
        amount: U256,
    ) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }
        let bal_from = state.balances.get(from)?;
        let new_from = bal_from
            .checked_sub(amount)
            .ok_or_else(|| ContractError::from_str("wloom: insufficient balance"))?;
        state.balances.set(from, &new_from)?;
        let bal_to = state.balances.get(to)?;
        let new_to = bal_to
            .checked_add(amount)
            .ok_or_else(|| ContractError::from_str("wloom: balance overflow"))?;
        state.balances.set(to, &new_to)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Hand-rolled calldata builders for sibling petals (router).
// ---------------------------------------------------------------------------

pub mod calls {
    use super::*;
    use alloc::vec::Vec;
    use bloom_chain_abi::Encoder;

    /// Build `wloom.deposit()` calldata.
    pub fn deposit() -> Vec<u8> {
        Encoder::with_selector(Wloom::SEL_DEPOSIT).finish()
    }

    /// Build `wloom.withdraw(amount)` calldata.
    pub fn withdraw(amount: U256) -> Vec<u8> {
        let mut e = Encoder::with_selector(Wloom::SEL_WITHDRAW);
        e.push_u256(amount);
        e.finish()
    }
}

// ---------------------------------------------------------------------------
// Host-target unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
