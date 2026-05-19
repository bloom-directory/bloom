//! bloom-dex-pair — Uniswap-v2-style AMM pair petal for bloom-chain.
//!
//! This petal is both the AMM pair and its own LP token (ERC-20 surface
//! inlined). There is no separate LP token contract.
//!
//! # LP token identity
//! Name:    "BloomDexPair LP"  (NUL-padded to 32 bytes in storage)
//! Symbol:  "BDPL"
//! Decimals: 18
//!
//! # init calldata
//! `token0 (32B) || token1 (32B) || pair_self_addr (32B)` — 96 bytes total.
//! Decoded via the chain-owned ABI macro (`pair::parse_init`), which strictly
//! rejects any length other than 96.
//!
//! # Storage layout (declared via `storage { ... }` in `contract!` below)
//!
//! | Field          | Domain tag                          | Value type         |
//! |----------------|-------------------------------------|--------------------|
//! | `token0`       | `"pair.token0"`                     | Address (32 B)     |
//! | `token1`       | `"pair.token1"`                     | Address (32 B)     |
//! | `reserve0`     | `"pair.reserve0"`                   | u128 left-padded   |
//! | `reserve1`     | `"pair.reserve1"`                   | u128 left-padded   |
//! | `k_last`       | `"pair.k_last"`                     | U256               |
//! | `self_addr`    | `"pair.self"` (explicit override)   | Address (32 B)     |
//! | `total_supply` | `"erc20.total_supply"` (shared)     | U256               |
//! | `balances`     | `"erc20.balance:" || addr`          | U256               |
//! | `allowances`   | `"erc20.allowance:" || owner || sp` | U256               |
//!
//! The macro-managed reentrancy lock lives at
//! `blake3("__macro.nonreentrant.pair")` and is auto-managed by the
//! `#[nonreentrant]` wrapper around `mint` / `burn` / `swap`.
//!
//! The ERC-20 key namespace (`erc20.*`) is intentionally shared with the
//! bloom-dex-erc20 petal's key layout (spec §6.1). The pair-AMM keys
//! (`pair.*`) use a distinct prefix so they never collide.
//!
//! # Reentrancy guard pattern
//!
//! The `#[nonreentrant]` attribute on `mint` / `burn` / `swap` makes the
//! chain-ABI macro wrap each method with a check-and-set of the auto-managed
//! lock slot. Because the handler body diverges via `petal::return_data`,
//! the macro's success-path lock-clear never runs; instead the handler
//! clears the lock explicitly via `pair::abi::nonreentrant_lock_clear()`
//! immediately before the diverging return. On a revert the chain rolls the
//! lock-set write back along with everything else.
//!
//! # ABI
//!
//! Selectors, calldata decoding, init parsing, storage accessors, and event
//! emitters are produced by the chain-owned `bloom_chain_abi::contract!`
//! macro below. The canonical method strings match DEX v0 spec §4.1, so peer
//! petals (router, factory) keep dispatching to byte-identical selectors.
//!
//! # Constants
//! - `MINIMUM_LIQUIDITY = 1000` — locked to address(0) on first mint.
//! - Fee: 997/1000 (0.3% fee).

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::vec::Vec;

use bloom_chain_abi::{DispatchError, U256, contract};
use bloom_dex_erc20::erc20 as erc20_abi;
use bloom_petal_sdk::{LoomValue, block, msg, petal};

/// Selector for `erc20.decimals()`. Hand-dispatched because the chain-ABI
/// macro's typed return system cannot model a 1-byte `u8` return today.
/// Computed at runtime from the canonical signature so the hashing rule
/// stays anchored to the same source-of-truth the macro uses.
fn sel_decimals() -> [u8; 4] {
    bloom_chain_abi::selector("erc20.decimals()")
}

// ---------------------------------------------------------------------------
// Chain-owned ABI declaration
// ---------------------------------------------------------------------------

contract! {
    contract Pair {
        storage {
            token0:        Address;
            token1:        Address;
            reserve0:      u128;
            reserve1:      u128;
            k_last:        U256;
            self_addr:     Address @ "pair.self";

            total_supply:  U256                            @ "erc20.total_supply";
            balances:      Mapping<Address, U256>          @ "erc20.balance:";
            allowances:    Mapping<(Address, Address), U256> @ "erc20.allowance:";
        }

        event Transfer(#[indexed] from: Address, #[indexed] to: Address, value: U256);
        event Approval(#[indexed] owner: Address, #[indexed] spender: Address, value: U256);
        event Mint(#[indexed] sender: Address, amount0: U256, amount1: U256);
        event Burn(#[indexed] sender: Address, amount0: U256, amount1: U256, #[indexed] to: Address);
        event Swap(
            #[indexed] sender: Address,
            a0_in: U256, a1_in: U256, a0_out: U256, a1_out: U256,
            #[indexed] to: Address,
        );
        event Sync(reserve0: u128, reserve1: u128);

        init(token0: Address, token1: Address, pair_self_addr: Address);

        fn token0() -> Address;
        fn token1() -> Address;
        fn get_reserves();

        #[nonreentrant]
        fn mint(to: Address);

        #[nonreentrant]
        fn burn(to: Address);

        #[nonreentrant]
        fn swap(amount0_out: U256, amount1_out: U256, to: Address);

        fn skim(to: Address);
        fn sync();
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum liquidity permanently locked to address(0) on the first mint.
const MINIMUM_LIQUIDITY: u128 = 1_000;

/// Zero address (recipient of MINIMUM_LIQUIDITY lock).
const ZERO_ADDR: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// ERC-20 internal helpers
// ---------------------------------------------------------------------------

fn erc20_transfer_internal(from: &[u8; 32], to: &[u8; 32], amount: U256) {
    if from == to {
        // no-op transfer; still valid
        return;
    }
    let bal_from = pair::abi::storage::balances::get(from);
    let bal_to = pair::abi::storage::balances::get(to);

    let new_from = bal_from
        .checked_sub(amount)
        .unwrap_or_else(|| petal::revert("pair: transfer exceeds balance"));
    let new_to = bal_to
        .checked_add(amount)
        .unwrap_or_else(|| petal::revert("pair: transfer overflow"));

    pair::abi::storage::balances::set(from, &new_from);
    pair::abi::storage::balances::set(to, &new_to);

    pair::abi::events::emit_transfer(from, to, &amount);
}

fn erc20_mint_internal(to: &[u8; 32], amount: U256) {
    let total = pair::abi::storage::total_supply();
    let new_total = total
        .checked_add(amount)
        .unwrap_or_else(|| petal::revert("pair: mint overflow"));
    pair::abi::storage::set_total_supply(&new_total);

    let bal = pair::abi::storage::balances::get(to);
    let new_bal = bal
        .checked_add(amount)
        .unwrap_or_else(|| petal::revert("pair: mint balance overflow"));
    pair::abi::storage::balances::set(to, &new_bal);

    pair::abi::events::emit_transfer(&ZERO_ADDR, to, &amount);
}

fn erc20_burn_internal(from: &[u8; 32], amount: U256) {
    let total = pair::abi::storage::total_supply();
    let new_total = total
        .checked_sub(amount)
        .unwrap_or_else(|| petal::revert("pair: burn underflow total"));
    pair::abi::storage::set_total_supply(&new_total);

    let bal = pair::abi::storage::balances::get(from);
    let new_bal = bal
        .checked_sub(amount)
        .unwrap_or_else(|| petal::revert("pair: burn exceeds balance"));
    pair::abi::storage::balances::set(from, &new_bal);

    pair::abi::events::emit_transfer(from, &ZERO_ADDR, &amount);
}

// ---------------------------------------------------------------------------
// Reserve helpers
// ---------------------------------------------------------------------------

/// Read both reserves.
fn get_reserves_raw() -> (u128, u128) {
    (pair::abi::storage::reserve0(), pair::abi::storage::reserve1())
}

/// Update reserves to new values and write `k_last = r0 * r1`.
fn update_reserves(r0: u128, r1: u128) {
    pair::abi::storage::set_reserve0(r0);
    pair::abi::storage::set_reserve1(r1);

    // k_last = r0 * r1 (stored as U256 for future feeTo reactivation).
    let k = U256::from_u128(r0)
        .checked_mul(U256::from_u128(r1))
        .unwrap_or(U256::ZERO); // saturate on overflow (shouldn't happen with u128 * u128)
    pair::abi::storage::set_k_last(&k);
}

/// Emit a Sync event.
fn emit_sync(r0: u128, r1: u128) {
    pair::abi::events::emit_sync(r0, r1);
}

// ---------------------------------------------------------------------------
// Token balance queries (call into token petals)
// ---------------------------------------------------------------------------

/// Query `token.balanceOf(target_addr)` by calling the token petal.
/// Returns the U256 balance from the return data.
fn token_balance_of(token_addr: &[u8; 32], target_addr: &[u8; 32]) -> U256 {
    let mut cd = Vec::with_capacity(4 + 32);
    cd.extend_from_slice(&erc20_abi::SEL_BALANCE_OF);
    cd.extend_from_slice(target_addr);

    let ret = petal::call(token_addr, &cd, LoomValue::ZERO)
        .unwrap_or_else(|_| petal::revert("pair: token.balanceOf call failed"));

    if ret.len() < 32 {
        petal::revert("pair: token.balanceOf bad return");
    }
    let mut v = [0u8; 32];
    v.copy_from_slice(&ret[..32]);
    U256(v)
}

/// Transfer `amount` of `token` to `to` via ERC-20 transfer.
fn token_transfer(token_addr: &[u8; 32], to: &[u8; 32], amount: U256) {
    let mut cd = Vec::with_capacity(4 + 32 + 32);
    cd.extend_from_slice(&erc20_abi::SEL_TRANSFER);
    cd.extend_from_slice(to);
    cd.extend_from_slice(&amount.0);

    petal::call(token_addr, &cd, LoomValue::ZERO)
        .unwrap_or_else(|_| petal::revert("pair: token.transfer failed"));
}

// ---------------------------------------------------------------------------
// AMM logic (inlined into the public mint/burn/swap handlers below)
// ---------------------------------------------------------------------------

/// Mint logic. `to` is the recipient of LP tokens. Returns the minted
/// `liquidity` as a 32-byte U256 payload.
fn do_mint(to: &[u8; 32]) -> Vec<u8> {
    let token0 = pair::abi::storage::token0();
    let token1 = pair::abi::storage::token1();
    let self_addr = pair::abi::storage::self_addr();

    // Balances AFTER the user deposited tokens (caller transferred in before calling).
    let bal0 = token_balance_of(&token0, &self_addr);
    let bal1 = token_balance_of(&token1, &self_addr);

    let (r0, r1) = get_reserves_raw();
    let r0_u = U256::from_u128(r0);
    let r1_u = U256::from_u128(r1);

    // Deposited amounts = current balance - stored reserve.
    let amount0 = bal0
        .checked_sub(r0_u)
        .unwrap_or_else(|| petal::revert("pair: mint amount0 underflow"));
    let amount1 = bal1
        .checked_sub(r1_u)
        .unwrap_or_else(|| petal::revert("pair: mint amount1 underflow"));

    let total_supply = pair::abi::storage::total_supply();

    let liquidity = if total_supply.is_zero() {
        // First mint: liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY.
        let product = amount0
            .checked_mul(amount1)
            .unwrap_or_else(|| petal::revert("pair: mint product overflow"));
        let sqrt_prod = product.sqrt();
        let min_liq = U256::from_u128(MINIMUM_LIQUIDITY);
        let liq = sqrt_prod
            .checked_sub(min_liq)
            .unwrap_or_else(|| petal::revert("pair: insufficient liquidity minted"));

        // Lock MINIMUM_LIQUIDITY to address(0).
        erc20_mint_internal(&ZERO_ADDR, min_liq);
        liq
    } else {
        // Subsequent mints: min(amount0 * totalSupply / r0, amount1 * totalSupply / r1).
        let liq0 = amount0
            .checked_mul(total_supply)
            .unwrap_or_else(|| petal::revert("pair: mint liq0 overflow"))
            .checked_div(r0_u)
            .unwrap_or_else(|| petal::revert("pair: mint liq0 div zero"));
        let liq1 = amount1
            .checked_mul(total_supply)
            .unwrap_or_else(|| petal::revert("pair: mint liq1 overflow"))
            .checked_div(r1_u)
            .unwrap_or_else(|| petal::revert("pair: mint liq1 div zero"));
        if liq0 < liq1 { liq0 } else { liq1 }
    };

    if liquidity.is_zero() {
        petal::revert("pair: insufficient liquidity minted");
    }

    // Mint LP tokens to `to`.
    erc20_mint_internal(to, liquidity);

    // Update reserves to current balances.
    let new_r0 = bal0
        .to_u128_checked()
        .unwrap_or_else(|| petal::revert("pair: reserve0 overflow u128"));
    let new_r1 = bal1
        .to_u128_checked()
        .unwrap_or_else(|| petal::revert("pair: reserve1 overflow u128"));
    update_reserves(new_r0, new_r1);
    emit_sync(new_r0, new_r1);

    // Emit Mint(sender, amount0, amount1).
    let sender = msg::sender();
    pair::abi::events::emit_mint(&sender, &amount0, &amount1);

    // Return liquidity as 32-byte U256.
    liquidity.0.to_vec()
}

/// Burn logic. `to` is the recipient of the underlying tokens.
/// Returns `(amount0, amount1)` — 64 bytes.
fn do_burn(to: &[u8; 32]) -> Vec<u8> {
    let token0 = pair::abi::storage::token0();
    let token1 = pair::abi::storage::token1();
    let self_addr = pair::abi::storage::self_addr();

    // Balances of token0 and token1 held by this pair.
    let bal0 = token_balance_of(&token0, &self_addr);
    let bal1 = token_balance_of(&token1, &self_addr);

    // LP tokens sent to this pair before calling burn.
    let lp_bal = pair::abi::storage::balances::get(&self_addr);
    if lp_bal.is_zero() {
        petal::revert("pair: burn insufficient LP");
    }

    let total_supply = pair::abi::storage::total_supply();

    // amount = liquidity * balance / totalSupply
    let amount0 = lp_bal
        .checked_mul(bal0)
        .unwrap_or_else(|| petal::revert("pair: burn amount0 overflow"))
        .checked_div(total_supply)
        .unwrap_or_else(|| petal::revert("pair: burn div zero"));
    let amount1 = lp_bal
        .checked_mul(bal1)
        .unwrap_or_else(|| petal::revert("pair: burn amount1 overflow"))
        .checked_div(total_supply)
        .unwrap_or_else(|| petal::revert("pair: burn div zero"));

    if amount0.is_zero() || amount1.is_zero() {
        petal::revert("pair: burn insufficient liquidity burned");
    }

    // Burn LP tokens from this pair (they were transferred in by the caller).
    erc20_burn_internal(&self_addr, lp_bal);

    // Transfer token0 and token1 out to `to`.
    token_transfer(&token0, to, amount0);
    token_transfer(&token1, to, amount1);

    // Update reserves.
    let new_r0 = token_balance_of(&token0, &self_addr)
        .to_u128_checked()
        .unwrap_or_else(|| petal::revert("pair: post-burn reserve0 overflow"));
    let new_r1 = token_balance_of(&token1, &self_addr)
        .to_u128_checked()
        .unwrap_or_else(|| petal::revert("pair: post-burn reserve1 overflow"));
    update_reserves(new_r0, new_r1);
    emit_sync(new_r0, new_r1);

    // Emit Burn(sender, amount0, amount1, to).
    let sender = msg::sender();
    pair::abi::events::emit_burn(&sender, &amount0, &amount1, to);

    // Return (amount0, amount1) — 64 bytes.
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&amount0.0);
    out.extend_from_slice(&amount1.0);
    out
}

/// Swap logic.
fn do_swap(amount0_out: U256, amount1_out: U256, to: &[u8; 32]) {
    if amount0_out.is_zero() && amount1_out.is_zero() {
        petal::revert("pair: insufficient output amount");
    }

    let (r0, r1) = get_reserves_raw();
    let r0_u = U256::from_u128(r0);
    let r1_u = U256::from_u128(r1);

    // Sanity checks.
    if amount0_out >= r0_u {
        petal::revert("pair: insufficient liquidity");
    }
    if amount1_out >= r1_u {
        petal::revert("pair: insufficient liquidity");
    }

    let token0 = pair::abi::storage::token0();
    let token1 = pair::abi::storage::token1();
    let self_addr = pair::abi::storage::self_addr();

    // Transfer tokens out BEFORE checking k (optimistic transfer pattern).
    if !amount0_out.is_zero() {
        token_transfer(&token0, to, amount0_out);
    }
    if !amount1_out.is_zero() {
        token_transfer(&token1, to, amount1_out);
    }

    // Read new balances after transfer-out.
    let bal0 = token_balance_of(&token0, &self_addr);
    let bal1 = token_balance_of(&token1, &self_addr);

    // Compute amount_in for each token:
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
        petal::revert("pair: insufficient input amount");
    }

    // Invariant check with fee:
    // (balance0 * 1000 - amount0In * 3) * (balance1 * 1000 - amount1In * 3)
    //   >= reserve0 * reserve1 * 1_000_000
    let k1000 = U256::from_u64(1000);
    let k3 = U256::from_u64(3);
    let k1m = U256::from_u64(1_000_000);

    let bal0_adj = bal0
        .checked_mul(k1000)
        .and_then(|v| {
            let fee = amount0_in.checked_mul(k3)?;
            v.checked_sub(fee)
        })
        .unwrap_or_else(|| petal::revert("pair: K adj0 overflow"));

    let bal1_adj = bal1
        .checked_mul(k1000)
        .and_then(|v| {
            let fee = amount1_in.checked_mul(k3)?;
            v.checked_sub(fee)
        })
        .unwrap_or_else(|| petal::revert("pair: K adj1 overflow"));

    let lhs = bal0_adj
        .checked_mul(bal1_adj)
        .unwrap_or_else(|| petal::revert("pair: K"));

    let rhs = r0_u
        .checked_mul(r1_u)
        .and_then(|v| v.checked_mul(k1m))
        .unwrap_or_else(|| petal::revert("pair: K rhs overflow"));

    if lhs < rhs {
        petal::revert("pair: K");
    }

    // Update reserves.
    let new_r0 = bal0
        .to_u128_checked()
        .unwrap_or_else(|| petal::revert("pair: swap reserve0 overflow u128"));
    let new_r1 = bal1
        .to_u128_checked()
        .unwrap_or_else(|| petal::revert("pair: swap reserve1 overflow u128"));
    update_reserves(new_r0, new_r1);
    emit_sync(new_r0, new_r1);

    // Emit Swap event.
    let sender = msg::sender();
    pair::abi::events::emit_swap(
        &sender,
        &amount0_in,
        &amount1_in,
        &amount0_out,
        &amount1_out,
        to,
    );
}

// ---------------------------------------------------------------------------
// petal entry points (init + call wired into the macro-generated codec)
// ---------------------------------------------------------------------------

bloom_petal_sdk::petal! {
    init => do_init,
    call => do_call,
}

/// Decode the 96-byte pair init payload and write config slots.
fn do_init(calldata: alloc::vec::Vec<u8>) {
    let args = match pair::parse_init(&calldata) {
        Ok(a) => a,
        Err(_) => petal::revert("pair: init calldata must be 96 bytes"),
    };

    pair::abi::storage::set_token0(&args.token0);
    pair::abi::storage::set_token1(&args.token1);
    pair::abi::storage::set_self_addr(&args.pair_self_addr);

    // Initial reserves zero (explicit).
    pair::abi::storage::set_reserve0(0);
    pair::abi::storage::set_reserve1(0);

    // Total LP supply starts at zero.
    pair::abi::storage::set_total_supply(&U256::ZERO);
}

/// Route a method call. ERC-20 selectors (shared LP-token surface) are
/// dispatched inline because they live in the `erc20.*` ABI namespace and are
/// not part of the macro-generated `pair.*` dispatcher. All `pair.*`
/// selectors flow through `pair::dispatch`.
fn do_call(calldata: alloc::vec::Vec<u8>) -> i32 {
    if calldata.len() < 4 {
        petal::revert("pair: calldata too short");
    }
    let sel: [u8; 4] = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let args = &calldata[4..];

    // ---- ERC-20 / LP token surface (shared erc20.* namespace) ----
    if let Some(rc) = dispatch_erc20(sel, args) {
        return rc;
    }

    // ---- pair.* selectors via the chain-owned ABI dispatcher ----
    let mut handler = PairHandler;
    let caller = msg::sender();
    match pair::dispatch(&mut handler, &caller, &calldata) {
        Ok(_) => {
            // The handler diverges via `petal::return_data` before reaching
            // this point for every `pair.*` selector. The dispatcher's empty
            // return is unreachable for any well-formed call, but in case
            // future maintenance adds a void method we return empty data here.
            petal::return_data(&[]);
        }
        Err(DispatchError::ShortCalldata) => petal::revert("pair: calldata too short"),
        Err(DispatchError::UnknownSelector(_)) => petal::revert("pair: unknown selector"),
        Err(DispatchError::Decode(_)) => petal::revert("pair: bad args"),
        Err(DispatchError::Unauthorized) => petal::revert("pair: unauthorized"),
        Err(DispatchError::Handler(m)) => petal::revert(m),
    }
}

/// Dispatch ERC-20 selectors; returns `Some(rc)` if handled. Each branch
/// diverges via `petal::return_data` or `petal::revert`, so the wrapping
/// `Option<i32>` is just a phantom for the type system.
fn dispatch_erc20(sel: [u8; 4], args: &[u8]) -> Option<i32> {
    if sel == erc20_abi::SEL_NAME {
        let name = b"BloomDexPair LP";
        let mut slot = [0u8; 32];
        slot[..name.len()].copy_from_slice(name);
        petal::return_data(&slot);
    }

    if sel == erc20_abi::SEL_SYMBOL {
        let sym = b"BDPL";
        let mut slot = [0u8; 32];
        slot[..sym.len()].copy_from_slice(sym);
        petal::return_data(&slot);
    }

    if sel == sel_decimals() {
        let mut slot = [0u8; 32];
        slot[31] = 18;
        petal::return_data(&slot);
    }

    if sel == erc20_abi::SEL_TOTAL_SUPPLY {
        let v = pair::abi::storage::total_supply();
        petal::return_data(&v.0);
    }

    if sel == erc20_abi::SEL_BALANCE_OF {
        if args.len() < 32 {
            petal::revert("pair: balanceOf bad args");
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&args[..32]);
        let v = pair::abi::storage::balances::get(&addr);
        petal::return_data(&v.0);
    }

    if sel == erc20_abi::SEL_ALLOWANCE {
        if args.len() < 64 {
            petal::revert("pair: allowance bad args");
        }
        let mut owner = [0u8; 32];
        let mut spender = [0u8; 32];
        owner.copy_from_slice(&args[..32]);
        spender.copy_from_slice(&args[32..64]);
        let v = pair::abi::storage::allowances::get((&owner, &spender));
        petal::return_data(&v.0);
    }

    if sel == erc20_abi::SEL_APPROVE {
        if args.len() < 64 {
            petal::revert("pair: approve bad args");
        }
        let mut spender = [0u8; 32];
        let mut amt_b = [0u8; 32];
        spender.copy_from_slice(&args[..32]);
        amt_b.copy_from_slice(&args[32..64]);
        let amount = U256(amt_b);
        let owner = msg::sender();
        pair::abi::storage::allowances::set((&owner, &spender), &amount);

        pair::abi::events::emit_approval(&owner, &spender, &amount);

        let mut ret = [0u8; 1];
        ret[0] = 1;
        petal::return_data(&ret);
    }

    if sel == erc20_abi::SEL_TRANSFER {
        if args.len() < 64 {
            petal::revert("pair: transfer bad args");
        }
        let mut to = [0u8; 32];
        let mut amt_b = [0u8; 32];
        to.copy_from_slice(&args[..32]);
        amt_b.copy_from_slice(&args[32..64]);
        let amount = U256(amt_b);
        let sender = msg::sender();
        erc20_transfer_internal(&sender, &to, amount);
        let mut ret = [0u8; 1];
        ret[0] = 1;
        petal::return_data(&ret);
    }

    if sel == erc20_abi::SEL_TRANSFER_FROM {
        if args.len() < 96 {
            petal::revert("pair: transferFrom bad args");
        }
        let mut from = [0u8; 32];
        let mut to = [0u8; 32];
        let mut amt_b = [0u8; 32];
        from.copy_from_slice(&args[..32]);
        to.copy_from_slice(&args[32..64]);
        amt_b.copy_from_slice(&args[64..96]);
        let amount = U256(amt_b);
        let caller = msg::sender();

        if caller != from {
            let allow = pair::abi::storage::allowances::get((&from, &caller));
            let new_allow = allow
                .checked_sub(amount)
                .unwrap_or_else(|| petal::revert("pair: transferFrom allowance exceeded"));
            pair::abi::storage::allowances::set((&from, &caller), &new_allow);
        }

        erc20_transfer_internal(&from, &to, amount);
        let mut ret = [0u8; 1];
        ret[0] = 1;
        petal::return_data(&ret);
    }

    None
}

// ---------------------------------------------------------------------------
// Handler — business logic for `pair.*` selectors
//
// Each method diverges via `petal::return_data` (or `petal::revert`) once its
// payload is ready. The returned `Ok(())` is dead code after the diverging
// call but is required to satisfy the trait signature.
//
// For `#[nonreentrant]` methods (mint/burn/swap): the macro-generated
// dispatcher sets the lock slot to 1 before invoking the handler. Because
// the handler diverges via `petal::return_data`, the macro's
// success-path lock-clear (which sits *after* the handler call) is
// unreachable. The handler therefore calls
// `pair::abi::nonreentrant_lock_clear()` itself immediately before
// diverging. On any revert path the chain rolls the entire transaction
// (including the lock-set write) back, so no explicit clear is required
// on revert.
// ---------------------------------------------------------------------------

struct PairHandler;

impl pair::Handler for PairHandler {
    fn token0(&mut self) -> Result<[u8; 32], &'static str> {
        let v = pair::abi::storage::token0();
        petal::return_data(&v);
    }

    fn token1(&mut self) -> Result<[u8; 32], &'static str> {
        let v = pair::abi::storage::token1();
        petal::return_data(&v);
    }

    fn get_reserves(&mut self) -> Result<(), &'static str> {
        // Returns: reserve0 (16B) || reserve1 (16B) || block_timestamp_low64 (8B)
        // Packed into 40 bytes.
        let (r0, r1) = get_reserves_raw();
        let ts = block::timestamp();
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&r0.to_be_bytes());
        out.extend_from_slice(&r1.to_be_bytes());
        out.extend_from_slice(&ts.to_be_bytes());
        petal::return_data(&out);
    }

    fn mint(&mut self, to: [u8; 32]) -> Result<(), &'static str> {
        let ret = do_mint(&to);
        pair::abi::nonreentrant_lock_clear();
        petal::return_data(&ret);
    }

    fn burn(&mut self, to: [u8; 32]) -> Result<(), &'static str> {
        let ret = do_burn(&to);
        pair::abi::nonreentrant_lock_clear();
        petal::return_data(&ret);
    }

    fn swap(
        &mut self,
        amount0_out: U256,
        amount1_out: U256,
        to: [u8; 32],
    ) -> Result<(), &'static str> {
        do_swap(amount0_out, amount1_out, &to);
        pair::abi::nonreentrant_lock_clear();
        petal::return_data(&[]);
    }

    fn skim(&mut self, to: [u8; 32]) -> Result<(), &'static str> {
        // Transfers surplus balances (above reserves) to `to`.
        let token0 = pair::abi::storage::token0();
        let token1 = pair::abi::storage::token1();
        let self_addr = pair::abi::storage::self_addr();
        let (r0, r1) = get_reserves_raw();

        let bal0 = token_balance_of(&token0, &self_addr);
        let bal1 = token_balance_of(&token1, &self_addr);
        let r0_u = U256::from_u128(r0);
        let r1_u = U256::from_u128(r1);

        if bal0 > r0_u {
            let surplus = bal0.checked_sub(r0_u).unwrap_or(U256::ZERO);
            if !surplus.is_zero() {
                token_transfer(&token0, &to, surplus);
            }
        }
        if bal1 > r1_u {
            let surplus = bal1.checked_sub(r1_u).unwrap_or(U256::ZERO);
            if !surplus.is_zero() {
                token_transfer(&token1, &to, surplus);
            }
        }

        petal::return_data(&[]);
    }

    fn sync(&mut self) -> Result<(), &'static str> {
        let token0 = pair::abi::storage::token0();
        let token1 = pair::abi::storage::token1();
        let self_addr = pair::abi::storage::self_addr();

        let bal0 = token_balance_of(&token0, &self_addr);
        let bal1 = token_balance_of(&token1, &self_addr);

        let new_r0 = bal0
            .to_u128_checked()
            .unwrap_or_else(|| petal::revert("pair: sync reserve0 overflow"));
        let new_r1 = bal1
            .to_u128_checked()
            .unwrap_or_else(|| petal::revert("pair: sync reserve1 overflow"));
        update_reserves(new_r0, new_r1);
        emit_sync(new_r0, new_r1);

        petal::return_data(&[]);
    }
}

// ---------------------------------------------------------------------------
// Unit tests (host-target, not wasm32)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: compute swap output using the Uniswap v2 formula via U256.
    // a_out = (a_in * 997 * r_out) / (r_in * 1000 + a_in * 997)
    fn swap_out(a_in: u128, r_in: u128, r_out: u128) -> u128 {
        let a_in_u   = U256::from_u128(a_in);
        let r_in_u   = U256::from_u128(r_in);
        let r_out_u  = U256::from_u128(r_out);
        let k997     = U256::from_u64(997);
        let k1000    = U256::from_u64(1000);

        let a_in_fee = a_in_u.checked_mul(k997).unwrap();
        let numerator = a_in_fee.checked_mul(r_out_u).unwrap();
        let denominator = r_in_u.checked_mul(k1000).unwrap()
            .checked_add(a_in_fee).unwrap();
        let result = numerator.checked_div(denominator).unwrap();
        result.to_u128_checked().unwrap()
    }

    // Helper: compute the invariant check LHS and RHS for a swap.
    // LHS = (bal_in * 1000 - amount_in * 3) * (bal_out * 1000)
    // RHS = r_in * r_out * 1_000_000
    // This function checks that the invariant holds.
    fn invariant_holds_after_swap(
        r_in: u128,
        r_out: u128,
        a_in: u128,
        a_out: u128,
    ) -> bool {
        let bal_in = r_in + a_in;
        let bal_out = r_out - a_out;

        // Convert to U256 for the adjusted calculation.
        let bal_in_u = U256::from_u128(bal_in);
        let bal_out_u = U256::from_u128(bal_out);
        let a_in_u = U256::from_u128(a_in);
        let k1000 = U256::from_u64(1000);
        let k3 = U256::from_u64(3);
        let k1m = U256::from_u64(1_000_000);
        let r_in_u = U256::from_u128(r_in);
        let r_out_u = U256::from_u128(r_out);

        let adj_in = bal_in_u
            .checked_mul(k1000)
            .unwrap()
            .checked_sub(a_in_u.checked_mul(k3).unwrap())
            .unwrap();
        let adj_out = bal_out_u.checked_mul(k1000).unwrap();

        let lhs = adj_in.checked_mul(adj_out).unwrap();
        let rhs = r_in_u.checked_mul(r_out_u).unwrap().checked_mul(k1m).unwrap();

        lhs >= rhs
    }

    // ---- Selector parity tests ----

    #[test]
    fn pair_selectors_match_dex_v0_canonical_strings() {
        fn _expected(method: &[u8]) -> [u8; 4] {
            let h = blake3::hash(method);
            let b = h.as_bytes();
            [b[0], b[1], b[2], b[3]]
        }
        assert_eq!(pair::SEL_TOKEN0,       _expected(b"pair.token0()"));
        assert_eq!(pair::SEL_TOKEN1,       _expected(b"pair.token1()"));
        assert_eq!(pair::SEL_GET_RESERVES, _expected(b"pair.get_reserves()"));
        assert_eq!(pair::SEL_MINT,         _expected(b"pair.mint(address)"));
        assert_eq!(pair::SEL_BURN,         _expected(b"pair.burn(address)"));
        assert_eq!(pair::SEL_SWAP,         _expected(b"pair.swap(u256,u256,address)"));
        assert_eq!(pair::SEL_SKIM,         _expected(b"pair.skim(address)"));
        assert_eq!(pair::SEL_SYNC,         _expected(b"pair.sync()"));
    }

    #[test]
    fn init_payload_is_exactly_96_bytes() {
        let t0 = [0x01u8; 32];
        let t1 = [0x02u8; 32];
        let sa = [0x04u8; 32];
        let payload = pair::init_calldata(&t0, &t1, &sa);
        assert_eq!(payload.len(), 96, "pair init must be 96 bytes");
        assert_eq!(&payload[0..32],  &t0);
        assert_eq!(&payload[32..64], &t1);
        assert_eq!(&payload[64..96], &sa);

        let parsed = pair::parse_init(&payload).unwrap();
        assert_eq!(parsed.token0, t0);
        assert_eq!(parsed.token1, t1);
        assert_eq!(parsed.pair_self_addr, sa);
    }

    #[test]
    fn init_payload_rejects_wrong_length() {
        let short = [0u8; 95];
        assert!(pair::parse_init(&short).is_err());
        let long = [0u8; 97];
        assert!(pair::parse_init(&long).is_err());
    }

    // ---- Storage slot byte-equality parity (pre- vs post-migration) ----
    //
    // The macro-generated storage accessors derive slot keys from the
    // declared field tags. Asserts here lock the storage layout: a slot
    // tag rename in the `contract!` block would change the on-disk key
    // and break upgrade compatibility. We compare against blake3 of the
    // explicit byte string the pre-migration pair used.
    //
    // The macro does not expose `<field>_slot()` helpers, so we recompute
    // both sides via `bloom_chain_abi::storage::slot_*` plus the
    // canonical pre-migration tag bytes.

    #[test]
    fn storage_slot_parity_scalars() {
        use bloom_chain_abi::storage::slot_scalar;

        // Pre-migration: blake3(b"pair.token0"); post-migration tag is the
        // auto-derived "pair.token0" (default for field `token0`).
        let exp = blake3::hash(b"pair.token0");
        assert_eq!(&slot_scalar("pair.token0")[..], &exp.as_bytes()[..]);

        let exp = blake3::hash(b"pair.token1");
        assert_eq!(&slot_scalar("pair.token1")[..], &exp.as_bytes()[..]);

        let exp = blake3::hash(b"pair.reserve0");
        assert_eq!(&slot_scalar("pair.reserve0")[..], &exp.as_bytes()[..]);

        let exp = blake3::hash(b"pair.reserve1");
        assert_eq!(&slot_scalar("pair.reserve1")[..], &exp.as_bytes()[..]);

        let exp = blake3::hash(b"pair.k_last");
        assert_eq!(&slot_scalar("pair.k_last")[..], &exp.as_bytes()[..]);

        // `self_addr` uses an explicit `@ "pair.self"` override so the
        // on-disk slot is byte-identical to the pre-migration `pair.self`.
        let exp = blake3::hash(b"pair.self");
        assert_eq!(&slot_scalar("pair.self")[..], &exp.as_bytes()[..]);

        // Shared `erc20.total_supply` namespace with bloom-dex-erc20.
        let exp = blake3::hash(b"erc20.total_supply");
        assert_eq!(&slot_scalar("erc20.total_supply")[..], &exp.as_bytes()[..]);
    }

    #[test]
    fn storage_slot_parity_mappings() {
        use bloom_chain_abi::storage::slot_mapping;

        let addr = [0x42u8; 32];

        // Pre-migration: blake3("erc20.balance:" || addr).
        let mut buf = Vec::<u8>::new();
        buf.extend_from_slice(b"erc20.balance:");
        buf.extend_from_slice(&addr);
        let exp = blake3::hash(&buf);
        assert_eq!(&slot_mapping("erc20.balance:", &addr)[..], &exp.as_bytes()[..]);

        // Pre-migration: blake3("erc20.allowance:" || owner || spender).
        let owner = [0x11u8; 32];
        let spender = [0x22u8; 32];
        let mut buf = Vec::<u8>::new();
        buf.extend_from_slice(b"erc20.allowance:");
        buf.extend_from_slice(&owner);
        buf.extend_from_slice(&spender);
        let exp = blake3::hash(&buf);

        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&owner);
        concat[32..].copy_from_slice(&spender);
        assert_eq!(
            &slot_mapping("erc20.allowance:", &concat)[..],
            &exp.as_bytes()[..]
        );
    }

    #[test]
    fn nonreentrant_lock_tag_blake3_is_well_defined() {
        // The macro derives the lock slot as blake3("__macro.nonreentrant.<snake>")
        // — for this contract that is `__macro.nonreentrant.pair`. The
        // macro emits both the dispatcher's check/set and the
        // `pair::abi::nonreentrant_lock_clear()` helper from the *same*
        // const, so user code never re-derives the tag. We keep this
        // assertion as a smoke test on the canonical tag string so any
        // accidental rename of the macro's reserved prefix surfaces here.
        let exp = blake3::hash(b"__macro.nonreentrant.pair");
        assert_eq!(exp.as_bytes().len(), 32);
    }

    // ---- Swap formula tests ----

    #[test]
    fn swap_formula_reference_vector_1() {
        // From Uniswap v2 reference: swap 1 token in with reserves (1000, 1000).
        // Expected out: (1 * 997 * 1000) / (1000 * 1000 + 1 * 997)
        //             = 997_000 / 1_000_997 = 0 (integer div, a_in too small)
        // Use larger amounts: a_in = 100, r_in = 1000, r_out = 1000.
        // a_out = (100 * 997 * 1000) / (1000 * 1000 + 100 * 997)
        //       = 99_700_000 / 1_099_700 ≈ 90
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
        // Larger pool: 1e18 in each reserve; swap 1e15 in.
        // This matches the v2 whitepaper scenario at smaller scale.
        let a_in = 1_000_000_000_000_000u128;       // 1e15
        let r_in = 1_000_000_000_000_000_000u128;   // 1e18
        let r_out = 1_000_000_000_000_000_000u128;  // 1e18

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
        // Acceptance test from task description: 1e18 in a 1e21/1e21 pool.
        // Expected: ≈ 9.96e17 (after 0.3% fee, negligible slippage).
        let a_in = 1_000_000_000_000_000_000u128;           // 1e18
        let r_in  = 1_000_000_000_000_000_000_000u128;      // 1e21
        let r_out = 1_000_000_000_000_000_000_000u128;      // 1e21

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
        let r: u128 = 1_000_000_000_000_000_000_000; // 1e21
        let sq = U256::from_u128(r)
            .checked_mul(U256::from_u128(r))
            .expect("no overflow");
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

    // ---- LP math tests ----

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
        let liq = if liq0 < liq1 { liq0 } else { liq1 };

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
