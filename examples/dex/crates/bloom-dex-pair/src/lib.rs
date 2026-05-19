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
//! `token0 (32B) || token1 (32B) || reentrancy_addr (32B) || pair_self_addr (32B)` — 128 bytes total.
//! Decoded via the chain-owned ABI macro (`pair::parse_init`), which strictly
//! rejects any length other than 128.
//!
//! # Storage keys (all are `blake3(domain_tag)` or `blake3(domain_tag || args)`)
//!
//! | Name            | Domain tag                          | Value              |
//! |-----------------|-------------------------------------|--------------------|
//! | `K_TOKEN0`      | `"pair.token0"`                     | Address (32 B)     |
//! | `K_TOKEN1`      | `"pair.token1"`                     | Address (32 B)     |
//! | `K_RESERVE0`    | `"pair.reserve0"`                   | u128 left-padded   |
//! | `K_RESERVE1`    | `"pair.reserve1"`                   | u128 left-padded   |
//! | `K_K_LAST`      | `"pair.k_last"`                     | U256               |
//! | `K_LOCK`        | `"pair.lock"`                       | u8 (0 or 1)        |
//! | `K_REENTRANCY`  | `"pair.reentrancy"`                 | Address (32 B)     |
//! | `K_SELF`        | `"pair.self"`                       | Address (32 B)     |
//! | `K_TOTAL`       | `"erc20.total_supply"`              | U256               |
//! | `K_BAL(addr)`   | `"erc20.balance:" || addr`          | U256               |
//! | `K_ALLOW(o,s)`  | `"erc20.allowance:" || owner || sp` | U256               |
//!
//! The ERC-20 key namespace (`erc20.*`) is intentionally shared with the
//! bloom-dex-erc20 petal's key layout (spec §6.1). The pair-AMM keys
//! (`pair.*`) use a distinct prefix so they never collide.
//!
//! # Reentrancy guard pattern (spec §8)
//! At the top of `mint`, `burn`, `swap` the pair calls:
//!   `reentrancy.enter(self_addr, original_calldata)` via `petal::call`.
//! The reentrancy petal calls back into the pair via:
//!   `pair.lock_check_and_set()` — reverts if lock==1, else sets lock=1.
//!   `pair._mint_inner / _burn_inner / _swap_inner` (the real logic).
//!   `pair.lock_clear()` — clears lock=0.
//!
//! These three internal selectors are declared `#[internal]` in the
//! `contract!` block, so the macro-generated dispatcher rejects calls whose
//! `msg::sender()` is not the configured reentrancy petal address.
//!
//! # ABI
//!
//! Selectors, calldata decoding, and init parsing are produced by the
//! chain-owned `bloom_chain_abi::contract!` macro below. The canonical method
//! strings match DEX v0 spec §4.1, so peer petals (router, reentrancy) keep
//! dispatching to byte-identical selectors.
//!
//! # Constants
//! - `MINIMUM_LIQUIDITY = 1000` — locked to address(0) on first mint.
//! - Fee: 997/1000 (0.3% fee).

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::vec::Vec;

use bloom_chain_abi::{DispatchError, U256, contract};
use bloom_dex_abi::{events, selectors};
use bloom_petal_sdk::{LoomValue, block, crypto, log, msg, petal, state};

// ---------------------------------------------------------------------------
// Chain-owned ABI declaration
// ---------------------------------------------------------------------------

contract! {
    contract Pair {
        init(token0: Address, token1: Address, reentrancy_addr: Address, pair_self_addr: Address);

        fn token0() -> Address;
        fn token1() -> Address;
        fn get_reserves();
        fn mint(to: Address);
        fn burn(to: Address);
        fn swap(amount0_out: U256, amount1_out: U256, to: Address);
        fn skim(to: Address);
        fn sync();

        #[internal]
        fn lock_check_and_set();
        #[internal]
        fn lock_clear();
        #[internal]
        fn _mint_inner(to: Address);
        #[internal]
        fn _burn_inner(to: Address);
        #[internal]
        fn _swap_inner(amount0_out: U256, amount1_out: U256, to: Address);
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
// Storage key derivation
// ---------------------------------------------------------------------------

fn key(tag: &[u8]) -> [u8; 32] {
    crypto::blake3(tag)
}

fn k_token0() -> [u8; 32] {
    key(b"pair.token0")
}
fn k_token1() -> [u8; 32] {
    key(b"pair.token1")
}
fn k_reserve0() -> [u8; 32] {
    key(b"pair.reserve0")
}
fn k_reserve1() -> [u8; 32] {
    key(b"pair.reserve1")
}
fn k_k_last() -> [u8; 32] {
    key(b"pair.k_last")
}
fn k_lock() -> [u8; 32] {
    key(b"pair.lock")
}
fn k_reentrancy() -> [u8; 32] {
    key(b"pair.reentrancy")
}
fn k_self() -> [u8; 32] {
    key(b"pair.self")
}

// ERC-20 / LP token keys — shared namespace with bloom-dex-erc20 (spec §6.1).
fn k_total() -> [u8; 32] {
    key(b"erc20.total_supply")
}
fn k_balance(addr: &[u8; 32]) -> [u8; 32] {
    let mut tag = Vec::with_capacity(16 + 32);
    tag.extend_from_slice(b"erc20.balance:");
    tag.extend_from_slice(addr);
    key(&tag)
}
fn k_allowance(owner: &[u8; 32], spender: &[u8; 32]) -> [u8; 32] {
    let mut tag = Vec::with_capacity(18 + 64);
    tag.extend_from_slice(b"erc20.allowance:");
    tag.extend_from_slice(owner);
    tag.extend_from_slice(spender);
    key(&tag)
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

fn read_u256(skey: &[u8; 32]) -> U256 {
    match state::read(skey) {
        Some(v) => U256(v),
        None => U256::ZERO,
    }
}

fn write_u256(skey: &[u8; 32], v: U256) {
    state::write(skey, &v.0);
}

fn read_u128(skey: &[u8; 32]) -> u128 {
    match state::read(skey) {
        Some(v) => {
            // Value is left-padded to 32 bytes; low 16 bytes are the u128.
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&v[16..32]);
            u128::from_be_bytes(buf)
        }
        None => 0u128,
    }
}

fn write_u128(skey: &[u8; 32], v: u128) {
    let mut slot = [0u8; 32];
    slot[16..32].copy_from_slice(&v.to_be_bytes());
    state::write(skey, &slot);
}

fn read_addr(skey: &[u8; 32]) -> [u8; 32] {
    match state::read(skey) {
        Some(v) => v,
        None => [0u8; 32],
    }
}

fn read_bool(skey: &[u8; 32]) -> bool {
    match state::read(skey) {
        Some(v) => v[31] != 0,
        None => false,
    }
}

fn write_bool(skey: &[u8; 32], v: bool) {
    let mut slot = [0u8; 32];
    slot[31] = v as u8;
    state::write(skey, &slot);
}

// ---------------------------------------------------------------------------
// ERC-20 internal helpers
// ---------------------------------------------------------------------------

fn erc20_transfer_internal(from: &[u8; 32], to: &[u8; 32], amount: U256) {
    if from == to {
        // no-op transfer; still valid
        return;
    }
    let bal_from = read_u256(&k_balance(from));
    let bal_to = read_u256(&k_balance(to));

    let new_from = bal_from
        .checked_sub(amount)
        .unwrap_or_else(|| petal::revert("pair: transfer exceeds balance"));
    let new_to = bal_to
        .checked_add(amount)
        .unwrap_or_else(|| petal::revert("pair: transfer overflow"));

    write_u256(&k_balance(from), new_from);
    write_u256(&k_balance(to), new_to);

    // Emit Transfer event.
    let data = events::pack_transfer(from, to, &amount.0);
    log::emit(&[events::ERC20_TRANSFER_EVENT], &data);
}

fn erc20_mint_internal(to: &[u8; 32], amount: U256) {
    let total = read_u256(&k_total());
    let new_total = total
        .checked_add(amount)
        .unwrap_or_else(|| petal::revert("pair: mint overflow"));
    write_u256(&k_total(), new_total);

    let bal = read_u256(&k_balance(to));
    let new_bal = bal
        .checked_add(amount)
        .unwrap_or_else(|| petal::revert("pair: mint balance overflow"));
    write_u256(&k_balance(to), new_bal);

    // Emit Transfer(ZERO_ADDR -> to, amount).
    let data = events::pack_transfer(&ZERO_ADDR, to, &amount.0);
    log::emit(&[events::ERC20_TRANSFER_EVENT], &data);
}

fn erc20_burn_internal(from: &[u8; 32], amount: U256) {
    let total = read_u256(&k_total());
    let new_total = total
        .checked_sub(amount)
        .unwrap_or_else(|| petal::revert("pair: burn underflow total"));
    write_u256(&k_total(), new_total);

    let bal = read_u256(&k_balance(from));
    let new_bal = bal
        .checked_sub(amount)
        .unwrap_or_else(|| petal::revert("pair: burn exceeds balance"));
    write_u256(&k_balance(from), new_bal);

    // Emit Transfer(from -> ZERO_ADDR, amount).
    let data = events::pack_transfer(from, &ZERO_ADDR, &amount.0);
    log::emit(&[events::ERC20_TRANSFER_EVENT], &data);
}

// ---------------------------------------------------------------------------
// Reserve helpers
// ---------------------------------------------------------------------------

/// Read both reserves.
fn get_reserves_raw() -> (u128, u128) {
    (read_u128(&k_reserve0()), read_u128(&k_reserve1()))
}

/// Update reserves to new values and write `k_last = r0 * r1`.
fn update_reserves(r0: u128, r1: u128) {
    write_u128(&k_reserve0(), r0);
    write_u128(&k_reserve1(), r1);

    // k_last = r0 * r1 (stored as U256 for future feeTo reactivation).
    let k = U256::from_u128(r0)
        .checked_mul(U256::from_u128(r1))
        .unwrap_or(U256::ZERO); // saturate on overflow (shouldn't happen with u128 * u128)
    write_u256(&k_k_last(), k);
}

/// Emit a Sync event.
fn emit_sync(r0: u128, r1: u128) {
    let data = events::pack_sync(r0, r1);
    log::emit(&[events::PAIR_SYNC_EVENT], &data);
}

// ---------------------------------------------------------------------------
// Token balance queries (call into token petals)
// ---------------------------------------------------------------------------

/// Query `token.balanceOf(target_addr)` by calling the token petal.
/// Returns the U256 balance from the return data.
fn token_balance_of(token_addr: &[u8; 32], target_addr: &[u8; 32]) -> U256 {
    let mut cd = Vec::with_capacity(4 + 32);
    cd.extend_from_slice(&selectors::ERC20_BALANCE_OF);
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
    cd.extend_from_slice(&selectors::ERC20_TRANSFER);
    cd.extend_from_slice(to);
    cd.extend_from_slice(&amount.0);

    petal::call(token_addr, &cd, LoomValue::ZERO)
        .unwrap_or_else(|_| petal::revert("pair: token.transfer failed"));
}

// ---------------------------------------------------------------------------
// Reentrancy guard helpers
// ---------------------------------------------------------------------------

fn read_reentrancy_addr() -> [u8; 32] {
    read_addr(&k_reentrancy())
}

/// Acquire the reentrancy lock by calling `reentrancy.enter(self_addr, calldata)`.
///
/// The reentrancy petal will:
///   1. Call back `pair.lock_check_and_set()` — reverts if already locked.
///   2. Call the `_*_inner` selector with the forwarded calldata.
///   3. Call `pair.lock_clear()`.
///
/// Returns the inner method's raw return data so the caller can forward it.
fn reentrancy_enter(self_addr: &[u8; 32], calldata: &[u8]) -> Vec<u8> {
    let raddr = read_reentrancy_addr();

    // Calldata for reentrancy.enter(address callee, bytes calldata):
    // selector(4) || callee(32) || calldata_bytes
    let mut cd = Vec::with_capacity(4 + 32 + calldata.len());
    cd.extend_from_slice(&selectors::REENTRANCY_ENTER);
    cd.extend_from_slice(self_addr);
    cd.extend_from_slice(calldata);

    petal::call(&raddr, &cd, LoomValue::ZERO)
        .unwrap_or_else(|_| petal::revert("pair: reentrancy.enter failed"))
}

// ---------------------------------------------------------------------------
// AMM logic (inner — called by reentrancy petal via _*_inner selectors)
// ---------------------------------------------------------------------------

/// Inner mint logic. `to` is the recipient of LP tokens.
/// Returns the minted `liquidity` as U256 (32 bytes).
fn do_mint_inner(to: &[u8; 32]) -> Vec<u8> {
    let token0 = read_addr(&k_token0());
    let token1 = read_addr(&k_token1());
    let self_addr = read_addr(&k_self());

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

    let total_supply = read_u256(&k_total());

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
    let data = events::pack_mint(&sender, &amount0.0, &amount1.0);
    log::emit(&[events::PAIR_MINT_EVENT], &data);

    // Return liquidity as 32-byte U256.
    liquidity.0.to_vec()
}

/// Inner burn logic. `to` is the recipient of the underlying tokens.
/// Returns `(amount0, amount1)` — 64 bytes.
fn do_burn_inner(to: &[u8; 32]) -> Vec<u8> {
    let token0 = read_addr(&k_token0());
    let token1 = read_addr(&k_token1());
    let self_addr = read_addr(&k_self());

    // Balances of token0 and token1 held by this pair.
    let bal0 = token_balance_of(&token0, &self_addr);
    let bal1 = token_balance_of(&token1, &self_addr);

    // LP tokens sent to this pair before calling burn.
    let lp_bal = read_u256(&k_balance(&self_addr));
    if lp_bal.is_zero() {
        petal::revert("pair: burn insufficient LP");
    }

    let total_supply = read_u256(&k_total());

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
    let data = events::pack_burn(&sender, &amount0.0, &amount1.0, to);
    log::emit(&[events::PAIR_BURN_EVENT], &data);

    // Return (amount0, amount1) — 64 bytes.
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&amount0.0);
    out.extend_from_slice(&amount1.0);
    out
}

/// Inner swap logic.
fn do_swap_inner(amount0_out: U256, amount1_out: U256, to: &[u8; 32]) {
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

    let token0 = read_addr(&k_token0());
    let token1 = read_addr(&k_token1());
    let self_addr = read_addr(&k_self());

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
    let data = events::pack_swap(
        &sender,
        &amount0_in.0,
        &amount1_in.0,
        &amount0_out.0,
        &amount1_out.0,
        to,
    );
    log::emit(&[events::PAIR_SWAP_EVENT], &data);
}

// ---------------------------------------------------------------------------
// petal entry points (init + call wired into the macro-generated codec)
// ---------------------------------------------------------------------------

bloom_petal_sdk::petal! {
    init => do_init,
    call => do_call,
}

/// Decode the 128-byte pair init payload and write config slots.
fn do_init(calldata: alloc::vec::Vec<u8>) {
    let args = match pair::parse_init(&calldata) {
        Ok(a) => a,
        Err(_) => petal::revert("pair: init calldata must be 128 bytes"),
    };

    state::write(&k_token0(), &args.token0);
    state::write(&k_token1(), &args.token1);
    state::write(&k_reentrancy(), &args.reentrancy_addr);
    state::write(&k_self(), &args.pair_self_addr);

    // Initial reserves zero (explicit).
    write_u128(&k_reserve0(), 0);
    write_u128(&k_reserve1(), 0);

    // Total LP supply starts at zero.
    write_u256(&k_total(), U256::ZERO);

    // Lock starts clear.
    write_bool(&k_lock(), false);
}

/// Route a method call. ERC-20 selectors (shared LP-token surface) are
/// dispatched inline because they live in the `erc20.*` ABI namespace and are
/// not part of the macro-generated `pair.*` dispatcher. All `pair.*` and
/// `pair._*_inner` / `pair.lock_*` selectors flow through `pair::dispatch`.
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
    if sel == selectors::ERC20_NAME {
        let name = b"BloomDexPair LP";
        let mut slot = [0u8; 32];
        slot[..name.len()].copy_from_slice(name);
        petal::return_data(&slot);
    }

    if sel == selectors::ERC20_SYMBOL {
        let sym = b"BDPL";
        let mut slot = [0u8; 32];
        slot[..sym.len()].copy_from_slice(sym);
        petal::return_data(&slot);
    }

    if sel == selectors::ERC20_DECIMALS {
        let mut slot = [0u8; 32];
        slot[31] = 18;
        petal::return_data(&slot);
    }

    if sel == selectors::ERC20_TOTAL_SUPPLY {
        let v = read_u256(&k_total());
        petal::return_data(&v.0);
    }

    if sel == selectors::ERC20_BALANCE_OF {
        if args.len() < 32 {
            petal::revert("pair: balanceOf bad args");
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&args[..32]);
        let v = read_u256(&k_balance(&addr));
        petal::return_data(&v.0);
    }

    if sel == selectors::ERC20_ALLOWANCE {
        if args.len() < 64 {
            petal::revert("pair: allowance bad args");
        }
        let mut owner = [0u8; 32];
        let mut spender = [0u8; 32];
        owner.copy_from_slice(&args[..32]);
        spender.copy_from_slice(&args[32..64]);
        let v = read_u256(&k_allowance(&owner, &spender));
        petal::return_data(&v.0);
    }

    if sel == selectors::ERC20_APPROVE {
        if args.len() < 64 {
            petal::revert("pair: approve bad args");
        }
        let mut spender = [0u8; 32];
        let mut amt_b = [0u8; 32];
        spender.copy_from_slice(&args[..32]);
        amt_b.copy_from_slice(&args[32..64]);
        let amount = U256(amt_b);
        let owner = msg::sender();
        write_u256(&k_allowance(&owner, &spender), amount);

        let data = events::pack_approval(&owner, &spender, &amount.0);
        log::emit(&[events::ERC20_APPROVAL_EVENT], &data);

        let mut ret = [0u8; 1];
        ret[0] = 1;
        petal::return_data(&ret);
    }

    if sel == selectors::ERC20_TRANSFER {
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

    if sel == selectors::ERC20_TRANSFER_FROM {
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
            let allow = read_u256(&k_allowance(&from, &caller));
            let new_allow = allow
                .checked_sub(amount)
                .unwrap_or_else(|| petal::revert("pair: transferFrom allowance exceeded"));
            write_u256(&k_allowance(&from, &caller), new_allow);
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
// ---------------------------------------------------------------------------

struct PairHandler;

impl pair::Handler for PairHandler {
    fn reentrancy_addr(&self) -> [u8; 32] {
        read_reentrancy_addr()
    }

    fn token0(&mut self) -> Result<[u8; 32], &'static str> {
        let v = read_addr(&k_token0());
        petal::return_data(&v);
    }

    fn token1(&mut self) -> Result<[u8; 32], &'static str> {
        let v = read_addr(&k_token1());
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
        // Route through reentrancy petal: builds _mint_inner(to) calldata.
        let self_addr = read_addr(&k_self());
        let mut inner_cd = Vec::with_capacity(4 + 32);
        inner_cd.extend_from_slice(&pair::SEL__MINT_INNER);
        inner_cd.extend_from_slice(&to);
        let ret = reentrancy_enter(&self_addr, &inner_cd);
        petal::return_data(&ret);
    }

    fn burn(&mut self, to: [u8; 32]) -> Result<(), &'static str> {
        let self_addr = read_addr(&k_self());
        let mut inner_cd = Vec::with_capacity(4 + 32);
        inner_cd.extend_from_slice(&pair::SEL__BURN_INNER);
        inner_cd.extend_from_slice(&to);
        let ret = reentrancy_enter(&self_addr, &inner_cd);
        petal::return_data(&ret);
    }

    fn swap(
        &mut self,
        amount0_out: U256,
        amount1_out: U256,
        to: [u8; 32],
    ) -> Result<(), &'static str> {
        let self_addr = read_addr(&k_self());
        let mut inner_cd = Vec::with_capacity(4 + 32 + 32 + 32);
        inner_cd.extend_from_slice(&pair::SEL__SWAP_INNER);
        inner_cd.extend_from_slice(&amount0_out.0);
        inner_cd.extend_from_slice(&amount1_out.0);
        inner_cd.extend_from_slice(&to);
        reentrancy_enter(&self_addr, &inner_cd);
        petal::return_data(&[]);
    }

    fn skim(&mut self, to: [u8; 32]) -> Result<(), &'static str> {
        // Transfers surplus balances (above reserves) to `to`.
        let token0 = read_addr(&k_token0());
        let token1 = read_addr(&k_token1());
        let self_addr = read_addr(&k_self());
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
        let token0 = read_addr(&k_token0());
        let token1 = read_addr(&k_token1());
        let self_addr = read_addr(&k_self());

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

    // ---- #[internal] reentrancy gate selectors ----

    fn lock_check_and_set(&mut self) -> Result<(), &'static str> {
        if read_bool(&k_lock()) {
            petal::revert("pair: locked");
        }
        write_bool(&k_lock(), true);
        petal::return_data(&[1u8]);
    }

    fn lock_clear(&mut self) -> Result<(), &'static str> {
        write_bool(&k_lock(), false);
        petal::return_data(&[1u8]);
    }

    // ---- #[internal] inner methods (full AMM logic) ----

    fn _mint_inner(&mut self, to: [u8; 32]) -> Result<(), &'static str> {
        let ret = do_mint_inner(&to);
        petal::return_data(&ret);
    }

    fn _burn_inner(&mut self, to: [u8; 32]) -> Result<(), &'static str> {
        let ret = do_burn_inner(&to);
        petal::return_data(&ret);
    }

    fn _swap_inner(
        &mut self,
        amount0_out: U256,
        amount1_out: U256,
        to: [u8; 32],
    ) -> Result<(), &'static str> {
        do_swap_inner(amount0_out, amount1_out, &to);
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
        bloom_dex_abi::assert_selector_parity! {
            pair::SEL_TOKEN0             => b"pair.token0()",
            pair::SEL_TOKEN1             => b"pair.token1()",
            pair::SEL_GET_RESERVES       => b"pair.get_reserves()",
            pair::SEL_MINT               => b"pair.mint(address)",
            pair::SEL_BURN               => b"pair.burn(address)",
            pair::SEL_SWAP               => b"pair.swap(u256,u256,address)",
            pair::SEL_SKIM               => b"pair.skim(address)",
            pair::SEL_SYNC               => b"pair.sync()",
            pair::SEL_LOCK_CHECK_AND_SET => b"pair.lock_check_and_set()",
            pair::SEL_LOCK_CLEAR         => b"pair.lock_clear()",
            pair::SEL__MINT_INNER        => b"pair._mint_inner(address)",
            pair::SEL__BURN_INNER        => b"pair._burn_inner(address)",
            pair::SEL__SWAP_INNER        => b"pair._swap_inner(u256,u256,address)",
        }
    }

    #[test]
    fn pair_selectors_match_legacy_dex_abi_constants() {
        // The chain-ABI macro must emit byte-identical selectors to the old
        // bloom-dex-abi build.rs table so peer contracts (router, reentrancy)
        // keep dispatching to the same handlers without code changes.
        assert_eq!(pair::SEL_TOKEN0,             bloom_dex_abi::selectors::PAIR_TOKEN0);
        assert_eq!(pair::SEL_TOKEN1,             bloom_dex_abi::selectors::PAIR_TOKEN1);
        assert_eq!(pair::SEL_GET_RESERVES,       bloom_dex_abi::selectors::PAIR_GET_RESERVES);
        assert_eq!(pair::SEL_MINT,               bloom_dex_abi::selectors::PAIR_MINT);
        assert_eq!(pair::SEL_BURN,               bloom_dex_abi::selectors::PAIR_BURN);
        assert_eq!(pair::SEL_SWAP,               bloom_dex_abi::selectors::PAIR_SWAP);
        assert_eq!(pair::SEL_SKIM,               bloom_dex_abi::selectors::PAIR_SKIM);
        assert_eq!(pair::SEL_SYNC,               bloom_dex_abi::selectors::PAIR_SYNC);
        assert_eq!(pair::SEL_LOCK_CHECK_AND_SET, bloom_dex_abi::selectors::PAIR_LOCK_CHECK_AND_SET);
        assert_eq!(pair::SEL_LOCK_CLEAR,         bloom_dex_abi::selectors::PAIR_LOCK_CLEAR);
        assert_eq!(pair::SEL__MINT_INNER,        bloom_dex_abi::selectors::PAIR_MINT_INNER);
        assert_eq!(pair::SEL__BURN_INNER,        bloom_dex_abi::selectors::PAIR_BURN_INNER);
        assert_eq!(pair::SEL__SWAP_INNER,        bloom_dex_abi::selectors::PAIR_SWAP_INNER);
    }

    #[test]
    fn init_payload_is_exactly_128_bytes() {
        let t0 = [0x01u8; 32];
        let t1 = [0x02u8; 32];
        let ra = [0x03u8; 32];
        let sa = [0x04u8; 32];
        let payload = pair::init_calldata(&t0, &t1, &ra, &sa);
        assert_eq!(payload.len(), 128, "pair init must be 128 bytes");
        assert_eq!(&payload[0..32],   &t0);
        assert_eq!(&payload[32..64],  &t1);
        assert_eq!(&payload[64..96],  &ra);
        assert_eq!(&payload[96..128], &sa);

        let parsed = pair::parse_init(&payload).unwrap();
        assert_eq!(parsed.token0, t0);
        assert_eq!(parsed.token1, t1);
        assert_eq!(parsed.reentrancy_addr, ra);
        assert_eq!(parsed.pair_self_addr, sa);
    }

    #[test]
    fn init_payload_rejects_wrong_length() {
        let short = [0u8; 127];
        assert!(pair::parse_init(&short).is_err());
        let long = [0u8; 129];
        assert!(pair::parse_init(&long).is_err());
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
