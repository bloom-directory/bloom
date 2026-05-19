//! bloom-dex-router — stateless Uniswap-v2-style router petal for bloom-chain.
//!
//! Implements the full router surface (DEX spec §4.1): liquidity ops,
//! multi-hop token swaps, and ETH-equivalent (LOOM) swap variants via the
//! `bloom-dex-wloom` petal. Pure quoting helpers (`quote`, `getAmountOut`,
//! `getAmountIn`, `getAmountsOut`, `getAmountsIn`) are computed in-petal
//! without state writes.
//!
//! The router stores exactly three config values at `init` time:
//!   - `K_FACTORY` — the factory petal address
//!   - `K_WLOOM`   — the wrapped-LOOM petal address
//!   - `K_SELF`    — the router's own pre-computed address (required for LOOM-output
//!                   swaps which temporarily receive wLOOM into the router before unwrapping)
//!
//! # init calldata
//!
//! `factory_addr (32B) || wloom_addr (32B) || router_self_addr (32B)` — 96 bytes total.
//! The 96-byte layout is mandatory (DEX spec §6.5). Shorter calldata reverts
//! with `"router: bad init"`. The `deploy-suite` CLI MUST pass 96 bytes with
//! the router's CREATE2-precomputed address as the third field.

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use bloom_dex_abi::{
    decode::Buf,
    encode::Encoder,
    selectors,
    u256::U256,
};
use bloom_petal_sdk::{block, crypto, msg, petal, state};

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

fn k_factory() -> [u8; 32] {
    crypto::blake3(b"router.factory")
}

fn k_wloom() -> [u8; 32] {
    crypto::blake3(b"router.wloom")
}

fn k_self() -> [u8; 32] {
    crypto::blake3(b"router.self")
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

fn load_factory() -> [u8; 32] {
    state::read(&k_factory()).unwrap_or([0u8; 32])
}

fn load_wloom() -> [u8; 32] {
    state::read(&k_wloom()).unwrap_or([0u8; 32])
}

// ---------------------------------------------------------------------------
// Entry points (via petal! macro)
// ---------------------------------------------------------------------------

bloom_petal_sdk::petal! {
    init => router_init,
    call => router_call,
}

fn router_init(calldata: Vec<u8>) {
    // Mandatory: factory_addr (32B) || wloom_addr (32B) || router_self_addr (32B) = 96 bytes.
    // The 64-byte form is rejected: router_self_addr is required for LOOM-output swaps.
    // The deploy-suite CLI MUST pass 96 bytes with the router's CREATE2-precomputed address.
    if calldata.len() != 96 {
        petal::revert("router: bad init");
    }
    let mut factory = [0u8; 32];
    let mut wloom = [0u8; 32];
    let mut self_addr = [0u8; 32];
    factory.copy_from_slice(&calldata[..32]);
    wloom.copy_from_slice(&calldata[32..64]);
    self_addr.copy_from_slice(&calldata[64..96]);
    state::write(&k_factory(), &factory);
    state::write(&k_wloom(), &wloom);
    state::write(&k_self(), &self_addr);
}

fn router_call(calldata: Vec<u8>) -> i32 {
    if calldata.len() < 4 {
        petal::revert("router: calldata too short");
    }
    let sel: [u8; 4] = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let args = &calldata[4..];

    // Dispatch on selector.
    if sel == selectors::ROUTER_QUOTE {
        handle_quote(args);
    } else if sel == selectors::ROUTER_GET_AMOUNT_OUT {
        handle_get_amount_out(args);
    } else if sel == selectors::ROUTER_GET_AMOUNT_IN {
        handle_get_amount_in(args);
    } else if sel == selectors::ROUTER_GET_AMOUNTS_OUT {
        handle_get_amounts_out(args);
    } else if sel == selectors::ROUTER_GET_AMOUNTS_IN {
        handle_get_amounts_in(args);
    } else if sel == selectors::ROUTER_ADD_LIQUIDITY {
        handle_add_liquidity(args);
    } else if sel == selectors::ROUTER_ADD_LIQUIDITY_LOOM {
        handle_add_liquidity_loom(args);
    } else if sel == selectors::ROUTER_REMOVE_LIQUIDITY {
        handle_remove_liquidity(args);
    } else if sel == selectors::ROUTER_REMOVE_LIQUIDITY_LOOM {
        handle_remove_liquidity_loom(args);
    } else if sel == selectors::ROUTER_SWAP_EXACT_TOKENS_FOR_TOKENS {
        handle_swap_exact_tokens_for_tokens(args);
    } else if sel == selectors::ROUTER_SWAP_TOKENS_FOR_EXACT_TOKENS {
        handle_swap_tokens_for_exact_tokens(args);
    } else if sel == selectors::ROUTER_SWAP_EXACT_LOOM_FOR_TOKENS {
        handle_swap_exact_loom_for_tokens(args);
    } else if sel == selectors::ROUTER_SWAP_TOKENS_FOR_EXACT_LOOM {
        handle_swap_tokens_for_exact_loom(args);
    } else if sel == selectors::ROUTER_SWAP_EXACT_TOKENS_FOR_LOOM {
        handle_swap_exact_tokens_for_loom(args);
    } else if sel == selectors::ROUTER_SWAP_LOOM_FOR_EXACT_TOKENS {
        handle_swap_loom_for_exact_tokens(args);
    } else {
        petal::revert("router: unknown selector");
    }
    0
}

// ---------------------------------------------------------------------------
// Pure math helpers (DEX spec §9.3)
// ---------------------------------------------------------------------------

/// `quote(amountA, reserveA, reserveB) = amountA * reserveB / reserveA`
///
/// Reverts on zero amount or zero reserves.
pub fn quote(amount_a: U256, reserve_a: U256, reserve_b: U256) -> U256 {
    if amount_a.is_zero() {
        petal::revert("router: quote: zero amount");
    }
    if reserve_a.is_zero() || reserve_b.is_zero() {
        petal::revert("router: quote: zero reserves");
    }
    amount_a
        .checked_mul(reserve_b)
        .and_then(|v| v.checked_div(reserve_a))
        .unwrap_or_else(|| petal::revert("router: quote: overflow"))
}

/// `getAmountOut(amountIn, reserveIn, reserveOut)`
///
/// Computes `(amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)`.
/// Reverts on zero amount or zero reserves.
pub fn get_amount_out(amount_in: U256, reserve_in: U256, reserve_out: U256) -> U256 {
    if amount_in.is_zero() {
        petal::revert("router: getAmountOut: zero amountIn");
    }
    if reserve_in.is_zero() || reserve_out.is_zero() {
        petal::revert("router: getAmountOut: zero reserves");
    }
    let n997 = U256::from_u64(997);
    let n1000 = U256::from_u64(1000);

    let amount_in_with_fee = amount_in
        .checked_mul(n997)
        .unwrap_or_else(|| petal::revert("router: getAmountOut: overflow"));
    let numerator = amount_in_with_fee
        .checked_mul(reserve_out)
        .unwrap_or_else(|| petal::revert("router: getAmountOut: overflow"));
    let denominator = reserve_in
        .checked_mul(n1000)
        .and_then(|v| v.checked_add(amount_in_with_fee))
        .unwrap_or_else(|| petal::revert("router: getAmountOut: overflow"));

    numerator
        .checked_div(denominator)
        .unwrap_or_else(|| petal::revert("router: getAmountOut: div by zero"))
}

/// `getAmountIn(amountOut, reserveIn, reserveOut)`
///
/// Computes `(reserveIn * amountOut * 1000) / ((reserveOut - amountOut) * 997) + 1`.
/// Reverts if `amountOut >= reserveOut`.
pub fn get_amount_in(amount_out: U256, reserve_in: U256, reserve_out: U256) -> U256 {
    if amount_out.is_zero() {
        petal::revert("router: getAmountIn: zero amountOut");
    }
    if reserve_in.is_zero() || reserve_out.is_zero() {
        petal::revert("router: getAmountIn: zero reserves");
    }
    if amount_out >= reserve_out {
        petal::revert("router: getAmountIn: amountOut >= reserveOut");
    }
    let n997 = U256::from_u64(997);
    let n1000 = U256::from_u64(1000);

    let numerator = reserve_in
        .checked_mul(amount_out)
        .and_then(|v| v.checked_mul(n1000))
        .unwrap_or_else(|| petal::revert("router: getAmountIn: overflow"));
    let denominator = reserve_out
        .checked_sub(amount_out)
        .and_then(|v| v.checked_mul(n997))
        .unwrap_or_else(|| petal::revert("router: getAmountIn: overflow"));

    let div = numerator
        .checked_div(denominator)
        .unwrap_or_else(|| petal::revert("router: getAmountIn: div by zero"));
    div.checked_add(U256::from_u64(1))
        .unwrap_or_else(|| petal::revert("router: getAmountIn: overflow"))
}

// ---------------------------------------------------------------------------
// Inter-petal call helpers
// ---------------------------------------------------------------------------

/// Zero-value 32-byte LOOM attachment.
const ZERO_VALUE: [u8; 32] = [0u8; 32];

/// Call `factory.get_pair(tokenA, tokenB)` and return the pair address.
fn factory_get_pair(factory: &[u8; 32], token_a: &[u8; 32], token_b: &[u8; 32]) -> [u8; 32] {
    let mut cd = Encoder::with_selector(selectors::FACTORY_GET_PAIR);
    cd.push_address(token_a);
    cd.push_address(token_b);
    let ret = petal::call(factory, &cd.finish(), &ZERO_VALUE)
        .unwrap_or_else(|_| petal::revert("router: factory.get_pair failed"));
    if ret.len() < 32 {
        petal::revert("router: factory.get_pair bad return");
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&ret[..32]);
    addr
}

/// Call `factory.create_pair(tokenA, tokenB)` and return the new pair address.
fn factory_create_pair(factory: &[u8; 32], token_a: &[u8; 32], token_b: &[u8; 32]) -> [u8; 32] {
    let mut cd = Encoder::with_selector(selectors::FACTORY_CREATE_PAIR);
    cd.push_address(token_a);
    cd.push_address(token_b);
    let ret = petal::call(factory, &cd.finish(), &ZERO_VALUE)
        .unwrap_or_else(|_| petal::revert("router: factory.create_pair failed"));
    if ret.len() < 32 {
        petal::revert("router: factory.create_pair bad return");
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&ret[..32]);
    addr
}

/// Get or create a pair, returning its address.
fn ensure_pair(
    factory: &[u8; 32],
    token_a: &[u8; 32],
    token_b: &[u8; 32],
) -> [u8; 32] {
    let pair = factory_get_pair(factory, token_a, token_b);
    if pair == [0u8; 32] {
        factory_create_pair(factory, token_a, token_b)
    } else {
        pair
    }
}

/// Call `pair.get_reserves()` — returns `(reserve0: u128, reserve1: u128)`.
/// The return is packed: 16 bytes reserve0 | 16 bytes reserve1 | 8 bytes timestamp.
fn pair_get_reserves(pair: &[u8; 32]) -> (u128, u128) {
    let cd = Encoder::with_selector(selectors::PAIR_GET_RESERVES).finish();
    let ret = petal::call(pair, &cd, &ZERO_VALUE)
        .unwrap_or_else(|_| petal::revert("router: pair.get_reserves failed"));
    if ret.len() < 32 {
        petal::revert("router: pair.get_reserves bad return");
    }
    let mut r0_bytes = [0u8; 16];
    let mut r1_bytes = [0u8; 16];
    r0_bytes.copy_from_slice(&ret[..16]);
    r1_bytes.copy_from_slice(&ret[16..32]);
    (u128::from_be_bytes(r0_bytes), u128::from_be_bytes(r1_bytes))
}

/// Call `pair.token0()` — returns the canonical token0 address.
fn pair_token0(pair: &[u8; 32]) -> [u8; 32] {
    let cd = Encoder::with_selector(selectors::PAIR_TOKEN0).finish();
    let ret = petal::call(pair, &cd, &ZERO_VALUE)
        .unwrap_or_else(|_| petal::revert("router: pair.token0 failed"));
    if ret.len() < 32 {
        petal::revert("router: pair.token0 bad return");
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&ret[..32]);
    addr
}

/// Call `token.transferFrom(from, to, amount)`.
fn token_transfer_from(
    token: &[u8; 32],
    from: &[u8; 32],
    to: &[u8; 32],
    amount: U256,
) {
    let mut cd = Encoder::with_selector(selectors::ERC20_TRANSFER_FROM);
    cd.push_address(from);
    cd.push_address(to);
    cd.push_u256(amount);
    petal::call(token, &cd.finish(), &ZERO_VALUE)
        .unwrap_or_else(|_| petal::revert("router: transferFrom failed"));
}

/// Call `pair.mint(to)` — returns `u256 liquidity`.
fn pair_mint(pair: &[u8; 32], to: &[u8; 32]) -> U256 {
    let mut cd = Encoder::with_selector(selectors::PAIR_MINT);
    cd.push_address(to);
    let ret = petal::call(pair, &cd.finish(), &ZERO_VALUE)
        .unwrap_or_else(|_| petal::revert("router: pair.mint failed"));
    if ret.len() < 32 {
        petal::revert("router: pair.mint bad return");
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&ret[..32]);
    U256(buf)
}

/// Call `pair.burn(to)` — returns `(u256 amount0, u256 amount1)`.
fn pair_burn(pair: &[u8; 32], to: &[u8; 32]) -> (U256, U256) {
    let mut cd = Encoder::with_selector(selectors::PAIR_BURN);
    cd.push_address(to);
    let ret = petal::call(pair, &cd.finish(), &ZERO_VALUE)
        .unwrap_or_else(|_| petal::revert("router: pair.burn failed"));
    if ret.len() < 64 {
        petal::revert("router: pair.burn bad return");
    }
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&ret[..32]);
    b.copy_from_slice(&ret[32..64]);
    (U256(a), U256(b))
}

/// Call `pair.swap(amount0Out, amount1Out, to)`.
fn pair_swap(pair: &[u8; 32], amount0_out: U256, amount1_out: U256, to: &[u8; 32]) {
    let mut cd = Encoder::with_selector(selectors::PAIR_SWAP);
    cd.push_u256(amount0_out);
    cd.push_u256(amount1_out);
    cd.push_address(to);
    petal::call(pair, &cd.finish(), &ZERO_VALUE)
        .unwrap_or_else(|_| petal::revert("router: pair.swap failed"));
}

/// Transfer LP tokens from `from` to `pair` (LP is represented by pair itself).
fn transfer_lp_to_pair(pair: &[u8; 32], from: &[u8; 32], liquidity: U256) {
    // LP token is the pair itself; use ERC20_TRANSFER_FROM.
    let mut cd = Encoder::with_selector(selectors::ERC20_TRANSFER_FROM);
    cd.push_address(from);
    cd.push_address(pair);
    cd.push_u256(liquidity);
    petal::call(pair, &cd.finish(), &ZERO_VALUE)
        .unwrap_or_else(|_| petal::revert("router: LP transferFrom failed"));
}

/// Call `wloom.deposit()` with `value_loom`.
fn wloom_deposit(wloom: &[u8; 32], value_loom: &[u8; 32]) {
    let cd = Encoder::with_selector(selectors::WLOOM_DEPOSIT).finish();
    petal::call(wloom, &cd, value_loom)
        .unwrap_or_else(|_| petal::revert("router: wloom.deposit failed"));
}

/// Call `wloom.withdraw(amount)`.
fn wloom_withdraw(wloom: &[u8; 32], amount: U256) {
    let mut cd = Encoder::with_selector(selectors::WLOOM_WITHDRAW);
    cd.push_u256(amount);
    petal::call(wloom, &cd.finish(), &ZERO_VALUE)
        .unwrap_or_else(|_| petal::revert("router: wloom.withdraw failed"));
}

/// Send native LOOM to `to` by calling with empty calldata and value.
fn send_loom(to: &[u8; 32], amount: U256) {
    petal::call(to, &[], amount.as_bytes())
        .unwrap_or_else(|_| petal::revert("router: LOOM transfer failed"));
}

// ---------------------------------------------------------------------------
// v2 optimal-amount decision (used in addLiquidity)
// ---------------------------------------------------------------------------

/// Compute the optimal (amountA, amountB) for adding liquidity given existing
/// reserves and desired/min amounts.
fn compute_liquidity_amounts(
    amount_a_desired: U256,
    amount_b_desired: U256,
    amount_a_min: U256,
    amount_b_min: U256,
    reserve_a: U256,
    reserve_b: U256,
) -> (U256, U256) {
    if reserve_a.is_zero() && reserve_b.is_zero() {
        return (amount_a_desired, amount_b_desired);
    }
    let amount_b_optimal = quote(amount_a_desired, reserve_a, reserve_b);
    if amount_b_optimal <= amount_b_desired {
        if amount_b_optimal < amount_b_min {
            petal::revert("router: addLiquidity: insufficient B amount");
        }
        (amount_a_desired, amount_b_optimal)
    } else {
        let amount_a_optimal = quote(amount_b_desired, reserve_b, reserve_a);
        if amount_a_optimal > amount_a_desired {
            petal::revert("router: addLiquidity: optimal A exceeds desired");
        }
        if amount_a_optimal < amount_a_min {
            petal::revert("router: addLiquidity: insufficient A amount");
        }
        (amount_a_optimal, amount_b_desired)
    }
}

/// Check block timestamp against deadline. Block timestamp is in ms; deadline
/// is in seconds (u64). Compare as ms to seconds is off — spec says u64
/// deadline; block::timestamp() returns ms. We convert ms to seconds.
fn check_deadline(deadline: u64) {
    // block::timestamp() is in milliseconds per the SDK; divide by 1000.
    let now_secs = block::timestamp() / 1000;
    if now_secs > deadline {
        petal::revert("router: expired");
    }
}

/// Get the reserve pair (reserveA, reserveB) in the direction of (tokenA, tokenB)
/// by querying pair.token0() and normalising.
fn reserves_in_order(
    pair: &[u8; 32],
    token_a: &[u8; 32],
) -> (U256, U256) {
    let (r0, r1) = pair_get_reserves(pair);
    let token0 = pair_token0(pair);
    if *token_a == token0 {
        (U256::from_u128(r0), U256::from_u128(r1))
    } else {
        (U256::from_u128(r1), U256::from_u128(r0))
    }
}

// ---------------------------------------------------------------------------
// Multi-hop amounts helpers
// ---------------------------------------------------------------------------

/// Compute `getAmountsOut` — forward multi-hop.
fn compute_amounts_out(
    factory: &[u8; 32],
    amount_in: U256,
    path: &[[u8; 32]],
) -> Vec<U256> {
    if path.len() < 2 {
        petal::revert("router: getAmountsOut: path too short");
    }
    let mut amounts = Vec::with_capacity(path.len());
    amounts.push(amount_in);
    for i in 0..path.len() - 1 {
        let pair = factory_get_pair(factory, &path[i], &path[i + 1]);
        if pair == [0u8; 32] {
            petal::revert("router: getAmountsOut: pair not found");
        }
        let (r_in, r_out) = reserves_in_order(&pair, &path[i]);
        let out = get_amount_out(amounts[i], r_in, r_out);
        amounts.push(out);
    }
    amounts
}

/// Compute `getAmountsIn` — reverse multi-hop.
fn compute_amounts_in(
    factory: &[u8; 32],
    amount_out: U256,
    path: &[[u8; 32]],
) -> Vec<U256> {
    if path.len() < 2 {
        petal::revert("router: getAmountsIn: path too short");
    }
    let n = path.len();
    let mut amounts = vec![U256::ZERO; n];
    amounts[n - 1] = amount_out;
    let mut i = n - 1;
    while i > 0 {
        let pair = factory_get_pair(factory, &path[i - 1], &path[i]);
        if pair == [0u8; 32] {
            petal::revert("router: getAmountsIn: pair not found");
        }
        let (r_in, r_out) = reserves_in_order(&pair, &path[i - 1]);
        amounts[i - 1] = get_amount_in(amounts[i], r_in, r_out);
        i -= 1;
    }
    amounts
}

/// Encode a `Vec<U256>` as `u16 length || 32-byte entries`.
fn encode_amounts(amounts: &[U256]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + amounts.len() * 32);
    let len = amounts.len() as u16;
    out.extend_from_slice(&len.to_be_bytes());
    for a in amounts {
        out.extend_from_slice(&a.0);
    }
    out
}

// ---------------------------------------------------------------------------
// Internal `_swap` helper
// ---------------------------------------------------------------------------

/// Execute a multi-hop swap. `amounts[i]` is the amount at path[i].
/// Tokens must already be in the first pair before this call.
fn internal_swap(
    factory: &[u8; 32],
    amounts: &[U256],
    path: &[[u8; 32]],
    to: &[u8; 32],
) {
    let n = path.len();
    for i in 0..n - 1 {
        let pair = factory_get_pair(factory, &path[i], &path[i + 1]);
        if pair == [0u8; 32] {
            petal::revert("router: swap: pair not found");
        }
        // Determine which amount goes to amount0Out vs amount1Out.
        let token0 = pair_token0(&pair);
        let (amount0_out, amount1_out) = if path[i + 1] == token0 {
            // Output token is token0 → amount0Out = amounts[i+1], amount1Out = 0
            (amounts[i + 1], U256::ZERO)
        } else {
            // Output token is token1 → amount1Out = amounts[i+1], amount0Out = 0
            (U256::ZERO, amounts[i + 1])
        };

        // Next recipient: if this is the last hop → `to`; else the next pair.
        let next_to: [u8; 32] = if i < n - 2 {
            factory_get_pair(factory, &path[i + 1], &path[i + 2])
        } else {
            *to
        };

        pair_swap(&pair, amount0_out, amount1_out, &next_to);
    }
}

// ---------------------------------------------------------------------------
// Handler: quote
// ---------------------------------------------------------------------------

fn handle_quote(args: &[u8]) {
    let mut buf = Buf::new(args);
    let amount_a = buf.read_u256().unwrap_or_else(|_| petal::revert("router: quote: bad args"));
    let reserve_a = buf.read_u256().unwrap_or_else(|_| petal::revert("router: quote: bad args"));
    let reserve_b = buf.read_u256().unwrap_or_else(|_| petal::revert("router: quote: bad args"));
    let result = quote(amount_a, reserve_a, reserve_b);
    petal::return_data(&result.0);
}

fn handle_get_amount_out(args: &[u8]) {
    let mut buf = Buf::new(args);
    let amount_in  = buf.read_u256().unwrap_or_else(|_| petal::revert("router: getAmountOut: bad args"));
    let reserve_in = buf.read_u256().unwrap_or_else(|_| petal::revert("router: getAmountOut: bad args"));
    let reserve_out = buf.read_u256().unwrap_or_else(|_| petal::revert("router: getAmountOut: bad args"));
    let result = get_amount_out(amount_in, reserve_in, reserve_out);
    petal::return_data(&result.0);
}

fn handle_get_amount_in(args: &[u8]) {
    let mut buf = Buf::new(args);
    let amount_out  = buf.read_u256().unwrap_or_else(|_| petal::revert("router: getAmountIn: bad args"));
    let reserve_in  = buf.read_u256().unwrap_or_else(|_| petal::revert("router: getAmountIn: bad args"));
    let reserve_out = buf.read_u256().unwrap_or_else(|_| petal::revert("router: getAmountIn: bad args"));
    let result = get_amount_in(amount_out, reserve_in, reserve_out);
    petal::return_data(&result.0);
}

fn handle_get_amounts_out(args: &[u8]) {
    let factory = load_factory();
    let mut buf = Buf::new(args);
    let amount_in = buf.read_u256().unwrap_or_else(|_| petal::revert("router: getAmountsOut: bad args"));
    let path = buf.read_address_vec().unwrap_or_else(|_| petal::revert("router: getAmountsOut: bad path"));
    let amounts = compute_amounts_out(&factory, amount_in, &path);
    petal::return_data(&encode_amounts(&amounts));
}

fn handle_get_amounts_in(args: &[u8]) {
    let factory = load_factory();
    let mut buf = Buf::new(args);
    let amount_out = buf.read_u256().unwrap_or_else(|_| petal::revert("router: getAmountsIn: bad args"));
    let path = buf.read_address_vec().unwrap_or_else(|_| petal::revert("router: getAmountsIn: bad path"));
    let amounts = compute_amounts_in(&factory, amount_out, &path);
    petal::return_data(&encode_amounts(&amounts));
}

// ---------------------------------------------------------------------------
// Handler: addLiquidity
// ---------------------------------------------------------------------------

fn handle_add_liquidity(args: &[u8]) {
    let mut buf = Buf::new(args);
    let token_a          = buf.read_address().unwrap_or_else(|_| petal::revert("router: addLiquidity: bad args"));
    let token_b          = buf.read_address().unwrap_or_else(|_| petal::revert("router: addLiquidity: bad args"));
    let amount_a_desired = buf.read_u256().unwrap_or_else(|_| petal::revert("router: addLiquidity: bad args"));
    let amount_b_desired = buf.read_u256().unwrap_or_else(|_| petal::revert("router: addLiquidity: bad args"));
    let amount_a_min     = buf.read_u256().unwrap_or_else(|_| petal::revert("router: addLiquidity: bad args"));
    let amount_b_min     = buf.read_u256().unwrap_or_else(|_| petal::revert("router: addLiquidity: bad args"));
    let to               = buf.read_address().unwrap_or_else(|_| petal::revert("router: addLiquidity: bad args"));
    let deadline         = buf.read_u64().unwrap_or_else(|_| petal::revert("router: addLiquidity: bad args"));

    check_deadline(deadline);

    let factory = load_factory();
    let pair = ensure_pair(&factory, &token_a, &token_b);

    // Get reserves in tokenA/tokenB direction.
    let (reserve_a, reserve_b) = reserves_in_order(&pair, &token_a);

    let (amount_a, amount_b) = compute_liquidity_amounts(
        amount_a_desired,
        amount_b_desired,
        amount_a_min,
        amount_b_min,
        reserve_a,
        reserve_b,
    );

    let sender = msg::sender();
    token_transfer_from(&token_a, &sender, &pair, amount_a);
    token_transfer_from(&token_b, &sender, &pair, amount_b);

    let liquidity = pair_mint(&pair, &to);

    // Return (amountA: u256, amountB: u256, liquidity: u256).
    let mut ret = [0u8; 96];
    ret[..32].copy_from_slice(&amount_a.0);
    ret[32..64].copy_from_slice(&amount_b.0);
    ret[64..96].copy_from_slice(&liquidity.0);
    petal::return_data(&ret);
}

// ---------------------------------------------------------------------------
// Handler: addLiquidityLOOM
// ---------------------------------------------------------------------------

fn handle_add_liquidity_loom(args: &[u8]) {
    let mut buf = Buf::new(args);
    let token               = buf.read_address().unwrap_or_else(|_| petal::revert("router: addLiquidityLOOM: bad args"));
    let amount_token_desired = buf.read_u256().unwrap_or_else(|_| petal::revert("router: addLiquidityLOOM: bad args"));
    let amount_token_min    = buf.read_u256().unwrap_or_else(|_| petal::revert("router: addLiquidityLOOM: bad args"));
    let amount_loom_min     = buf.read_u256().unwrap_or_else(|_| petal::revert("router: addLiquidityLOOM: bad args"));
    let to                  = buf.read_address().unwrap_or_else(|_| petal::revert("router: addLiquidityLOOM: bad args"));
    let deadline            = buf.read_u64().unwrap_or_else(|_| petal::revert("router: addLiquidityLOOM: bad args"));

    check_deadline(deadline);

    let factory = load_factory();
    let wloom   = load_wloom();

    // msg.value is the LOOM to deposit.
    let value = msg::value();
    let amount_loom_desired = U256(value);

    // Deposit all msg.value into wLOOM (mints wLOOM to router).
    wloom_deposit(&wloom, &value);

    let pair = ensure_pair(&factory, &token, &wloom);

    // Reserves in (token, wloom) direction.
    let (reserve_token, reserve_loom) = reserves_in_order(&pair, &token);

    let (amount_token, amount_loom) = compute_liquidity_amounts(
        amount_token_desired,
        amount_loom_desired,
        amount_token_min,
        amount_loom_min,
        reserve_token,
        reserve_loom,
    );

    let sender = msg::sender();
    token_transfer_from(&token, &sender, &pair, amount_token);

    // Transfer wLOOM from router (self) to pair — router already holds the deposit.
    // We need to send wLOOM from router to pair; use erc20.transfer on wloom.
    {
        let mut cd = Encoder::with_selector(selectors::ERC20_TRANSFER);
        cd.push_address(&pair);
        cd.push_u256(amount_loom);
        petal::call(&wloom, &cd.finish(), &ZERO_VALUE)
            .unwrap_or_else(|_| petal::revert("router: wloom transfer to pair failed"));
    }

    let liquidity = pair_mint(&pair, &to);

    // Refund excess LOOM if any.
    let refund = amount_loom_desired
        .checked_sub(amount_loom)
        .unwrap_or(U256::ZERO);
    if !refund.is_zero() {
        // Withdraw excess wLOOM → native LOOM in router, then send to sender.
        wloom_withdraw(&wloom, refund);
        send_loom(&sender, refund);
    }

    // Return (amountToken: u256, amountLOOM: u256, liquidity: u256).
    let mut ret = [0u8; 96];
    ret[..32].copy_from_slice(&amount_token.0);
    ret[32..64].copy_from_slice(&amount_loom.0);
    ret[64..96].copy_from_slice(&liquidity.0);
    petal::return_data(&ret);
}

// ---------------------------------------------------------------------------
// Handler: removeLiquidity
// ---------------------------------------------------------------------------

fn handle_remove_liquidity(args: &[u8]) {
    let mut buf = Buf::new(args);
    let token_a      = buf.read_address().unwrap_or_else(|_| petal::revert("router: removeLiquidity: bad args"));
    let token_b      = buf.read_address().unwrap_or_else(|_| petal::revert("router: removeLiquidity: bad args"));
    let liquidity    = buf.read_u256().unwrap_or_else(|_| petal::revert("router: removeLiquidity: bad args"));
    let amount_a_min = buf.read_u256().unwrap_or_else(|_| petal::revert("router: removeLiquidity: bad args"));
    let amount_b_min = buf.read_u256().unwrap_or_else(|_| petal::revert("router: removeLiquidity: bad args"));
    let to           = buf.read_address().unwrap_or_else(|_| petal::revert("router: removeLiquidity: bad args"));
    let deadline     = buf.read_u64().unwrap_or_else(|_| petal::revert("router: removeLiquidity: bad args"));

    check_deadline(deadline);

    let factory = load_factory();
    let pair = factory_get_pair(&factory, &token_a, &token_b);
    if pair == [0u8; 32] {
        petal::revert("router: removeLiquidity: pair not found");
    }

    // Transfer LP tokens from sender to pair (LP token IS the pair).
    let sender = msg::sender();
    transfer_lp_to_pair(&pair, &sender, liquidity);

    // Burn — returns (amount0, amount1) in token0/token1 ordering.
    let (burn0, burn1) = pair_burn(&pair, &to);

    // Determine which is tokenA and which is tokenB.
    let token0 = pair_token0(&pair);
    let (amount_a, amount_b) = if token_a == token0 {
        (burn0, burn1)
    } else {
        (burn1, burn0)
    };

    if amount_a < amount_a_min {
        petal::revert("router: removeLiquidity: insufficient A");
    }
    if amount_b < amount_b_min {
        petal::revert("router: removeLiquidity: insufficient B");
    }

    // Return (amountA: u256, amountB: u256).
    let mut ret = [0u8; 64];
    ret[..32].copy_from_slice(&amount_a.0);
    ret[32..64].copy_from_slice(&amount_b.0);
    petal::return_data(&ret);
}

// ---------------------------------------------------------------------------
// Handler: removeLiquidityLOOM
// ---------------------------------------------------------------------------

fn handle_remove_liquidity_loom(args: &[u8]) {
    let mut buf = Buf::new(args);
    let token            = buf.read_address().unwrap_or_else(|_| petal::revert("router: removeLiquidityLOOM: bad args"));
    let liquidity        = buf.read_u256().unwrap_or_else(|_| petal::revert("router: removeLiquidityLOOM: bad args"));
    let amount_token_min = buf.read_u256().unwrap_or_else(|_| petal::revert("router: removeLiquidityLOOM: bad args"));
    let amount_loom_min  = buf.read_u256().unwrap_or_else(|_| petal::revert("router: removeLiquidityLOOM: bad args"));
    let to               = buf.read_address().unwrap_or_else(|_| petal::revert("router: removeLiquidityLOOM: bad args"));
    let deadline         = buf.read_u64().unwrap_or_else(|_| petal::revert("router: removeLiquidityLOOM: bad args"));

    check_deadline(deadline);

    let factory = load_factory();
    let wloom   = load_wloom();

    let pair = factory_get_pair(&factory, &token, &wloom);
    if pair == [0u8; 32] {
        petal::revert("router: removeLiquidityLOOM: pair not found");
    }

    // Transfer LP from sender to pair.
    let sender = msg::sender();
    transfer_lp_to_pair(&pair, &sender, liquidity);

    // Burn to self (router) so we can unwrap wLOOM.
    let self_addr = self_address();
    let (burn0, burn1) = pair_burn(&pair, &self_addr);

    // Determine which is token and which is wloom.
    let token0 = pair_token0(&pair);
    let (amount_token, amount_wloom) = if token == token0 {
        (burn0, burn1)
    } else {
        (burn1, burn0)
    };

    if amount_token < amount_token_min {
        petal::revert("router: removeLiquidityLOOM: insufficient token");
    }
    if amount_wloom < amount_loom_min {
        petal::revert("router: removeLiquidityLOOM: insufficient LOOM");
    }

    // Transfer tokens directly to `to`.
    {
        let mut cd = Encoder::with_selector(selectors::ERC20_TRANSFER);
        cd.push_address(&to);
        cd.push_u256(amount_token);
        petal::call(&token, &cd.finish(), &ZERO_VALUE)
            .unwrap_or_else(|_| petal::revert("router: token transfer to `to` failed"));
    }

    // Unwrap wLOOM → native LOOM and send to `to`.
    wloom_withdraw(&wloom, amount_wloom);
    send_loom(&to, amount_wloom);

    // Return (amountToken: u256, amountLOOM: u256).
    let mut ret = [0u8; 64];
    ret[..32].copy_from_slice(&amount_token.0);
    ret[32..64].copy_from_slice(&amount_wloom.0);
    petal::return_data(&ret);
}

// ---------------------------------------------------------------------------
// Swap handlers
// ---------------------------------------------------------------------------

fn handle_swap_exact_tokens_for_tokens(args: &[u8]) {
    let mut buf = Buf::new(args);
    let amount_in     = buf.read_u256().unwrap_or_else(|_| petal::revert("router: swapExact: bad args"));
    let amount_out_min = buf.read_u256().unwrap_or_else(|_| petal::revert("router: swapExact: bad args"));
    let path          = buf.read_address_vec().unwrap_or_else(|_| petal::revert("router: swapExact: bad path"));
    let to            = buf.read_address().unwrap_or_else(|_| petal::revert("router: swapExact: bad args"));
    let deadline      = buf.read_u64().unwrap_or_else(|_| petal::revert("router: swapExact: bad args"));

    check_deadline(deadline);

    let factory = load_factory();
    let amounts = compute_amounts_out(&factory, amount_in, &path);

    let last = *amounts.last().unwrap_or_else(|| petal::revert("router: swapExact: empty amounts"));
    if last < amount_out_min {
        petal::revert("router: swapExact: insufficient output");
    }

    // Transfer input tokens from sender to first pair.
    let first_pair = factory_get_pair(&factory, &path[0], &path[1]);
    if first_pair == [0u8; 32] {
        petal::revert("router: swapExact: first pair not found");
    }
    let sender = msg::sender();
    token_transfer_from(&path[0], &sender, &first_pair, amounts[0]);

    internal_swap(&factory, &amounts, &path, &to);

    petal::return_data(&encode_amounts(&amounts));
}

fn handle_swap_tokens_for_exact_tokens(args: &[u8]) {
    let mut buf = Buf::new(args);
    let amount_out    = buf.read_u256().unwrap_or_else(|_| petal::revert("router: swapForExact: bad args"));
    let amount_in_max = buf.read_u256().unwrap_or_else(|_| petal::revert("router: swapForExact: bad args"));
    let path          = buf.read_address_vec().unwrap_or_else(|_| petal::revert("router: swapForExact: bad path"));
    let to            = buf.read_address().unwrap_or_else(|_| petal::revert("router: swapForExact: bad args"));
    let deadline      = buf.read_u64().unwrap_or_else(|_| petal::revert("router: swapForExact: bad args"));

    check_deadline(deadline);

    let factory = load_factory();
    let amounts = compute_amounts_in(&factory, amount_out, &path);

    if amounts[0] > amount_in_max {
        petal::revert("router: swapForExact: excessive input");
    }

    let first_pair = factory_get_pair(&factory, &path[0], &path[1]);
    if first_pair == [0u8; 32] {
        petal::revert("router: swapForExact: first pair not found");
    }
    let sender = msg::sender();
    token_transfer_from(&path[0], &sender, &first_pair, amounts[0]);

    internal_swap(&factory, &amounts, &path, &to);

    petal::return_data(&encode_amounts(&amounts));
}

fn handle_swap_exact_loom_for_tokens(args: &[u8]) {
    // payable: path[0] must be wloom
    let mut buf = Buf::new(args);
    let amount_out_min = buf.read_u256().unwrap_or_else(|_| petal::revert("router: swapExactLOOM: bad args"));
    let path           = buf.read_address_vec().unwrap_or_else(|_| petal::revert("router: swapExactLOOM: bad path"));
    let to             = buf.read_address().unwrap_or_else(|_| petal::revert("router: swapExactLOOM: bad args"));
    let deadline       = buf.read_u64().unwrap_or_else(|_| petal::revert("router: swapExactLOOM: bad args"));

    check_deadline(deadline);

    let wloom = load_wloom();
    if path.is_empty() || path[0] != wloom {
        petal::revert("router: swapExactLOOM: path[0] must be wloom");
    }

    let value = msg::value();
    let amount_in = U256(value);

    // Deposit LOOM into wLOOM. wLOOM is minted to router.
    wloom_deposit(&wloom, &value);

    let factory = load_factory();
    let amounts = compute_amounts_out(&factory, amount_in, &path);

    let last = *amounts.last().unwrap_or_else(|| petal::revert("router: swapExactLOOM: empty amounts"));
    if last < amount_out_min {
        petal::revert("router: swapExactLOOM: insufficient output");
    }

    // Transfer wLOOM from router to first pair.
    let first_pair = factory_get_pair(&factory, &path[0], &path[1]);
    if first_pair == [0u8; 32] {
        petal::revert("router: swapExactLOOM: first pair not found");
    }
    {
        let mut cd = Encoder::with_selector(selectors::ERC20_TRANSFER);
        cd.push_address(&first_pair);
        cd.push_u256(amounts[0]);
        petal::call(&wloom, &cd.finish(), &ZERO_VALUE)
            .unwrap_or_else(|_| petal::revert("router: wloom transfer failed"));
    }

    internal_swap(&factory, &amounts, &path, &to);

    petal::return_data(&encode_amounts(&amounts));
}

fn handle_swap_tokens_for_exact_loom(args: &[u8]) {
    // path[-1] must be wloom
    let mut buf = Buf::new(args);
    let amount_out    = buf.read_u256().unwrap_or_else(|_| petal::revert("router: swapForExactLOOM: bad args"));
    let amount_in_max = buf.read_u256().unwrap_or_else(|_| petal::revert("router: swapForExactLOOM: bad args"));
    let path          = buf.read_address_vec().unwrap_or_else(|_| petal::revert("router: swapForExactLOOM: bad path"));
    let to            = buf.read_address().unwrap_or_else(|_| petal::revert("router: swapForExactLOOM: bad args"));
    let deadline      = buf.read_u64().unwrap_or_else(|_| petal::revert("router: swapForExactLOOM: bad args"));

    check_deadline(deadline);

    let wloom = load_wloom();
    if path.is_empty() || *path.last().unwrap() != wloom {
        petal::revert("router: swapForExactLOOM: path[-1] must be wloom");
    }

    let factory = load_factory();
    let amounts = compute_amounts_in(&factory, amount_out, &path);

    if amounts[0] > amount_in_max {
        petal::revert("router: swapForExactLOOM: excessive input");
    }

    // Transfer input from sender to first pair. Swap to self (router).
    let first_pair = factory_get_pair(&factory, &path[0], &path[1]);
    if first_pair == [0u8; 32] {
        petal::revert("router: swapForExactLOOM: first pair not found");
    }
    let sender = msg::sender();
    token_transfer_from(&path[0], &sender, &first_pair, amounts[0]);

    let self_addr = self_address();
    internal_swap(&factory, &amounts, &path, &self_addr);

    // Unwrap wLOOM and send native LOOM to `to`.
    let wloom_amount = *amounts.last().unwrap();
    wloom_withdraw(&wloom, wloom_amount);
    send_loom(&to, wloom_amount);

    petal::return_data(&encode_amounts(&amounts));
}

fn handle_swap_exact_tokens_for_loom(args: &[u8]) {
    // path[-1] must be wloom
    let mut buf = Buf::new(args);
    let amount_in      = buf.read_u256().unwrap_or_else(|_| petal::revert("router: swapExactForLOOM: bad args"));
    let amount_out_min = buf.read_u256().unwrap_or_else(|_| petal::revert("router: swapExactForLOOM: bad args"));
    let path           = buf.read_address_vec().unwrap_or_else(|_| petal::revert("router: swapExactForLOOM: bad path"));
    let to             = buf.read_address().unwrap_or_else(|_| petal::revert("router: swapExactForLOOM: bad args"));
    let deadline       = buf.read_u64().unwrap_or_else(|_| petal::revert("router: swapExactForLOOM: bad args"));

    check_deadline(deadline);

    let wloom = load_wloom();
    if path.is_empty() || *path.last().unwrap() != wloom {
        petal::revert("router: swapExactForLOOM: path[-1] must be wloom");
    }

    let factory = load_factory();
    let amounts = compute_amounts_out(&factory, amount_in, &path);

    let wloom_amount = *amounts.last().unwrap_or_else(|| petal::revert("router: swapExactForLOOM: empty amounts"));
    if wloom_amount < amount_out_min {
        petal::revert("router: swapExactForLOOM: insufficient output");
    }

    let first_pair = factory_get_pair(&factory, &path[0], &path[1]);
    if first_pair == [0u8; 32] {
        petal::revert("router: swapExactForLOOM: first pair not found");
    }
    let sender = msg::sender();
    token_transfer_from(&path[0], &sender, &first_pair, amounts[0]);

    let self_addr = self_address();
    internal_swap(&factory, &amounts, &path, &self_addr);

    wloom_withdraw(&wloom, wloom_amount);
    send_loom(&to, wloom_amount);

    petal::return_data(&encode_amounts(&amounts));
}

fn handle_swap_loom_for_exact_tokens(args: &[u8]) {
    // payable; path[0] must be wloom
    let mut buf = Buf::new(args);
    let amount_out = buf.read_u256().unwrap_or_else(|_| petal::revert("router: swapLOOMForExact: bad args"));
    let path       = buf.read_address_vec().unwrap_or_else(|_| petal::revert("router: swapLOOMForExact: bad path"));
    let to         = buf.read_address().unwrap_or_else(|_| petal::revert("router: swapLOOMForExact: bad args"));
    let deadline   = buf.read_u64().unwrap_or_else(|_| petal::revert("router: swapLOOMForExact: bad args"));

    check_deadline(deadline);

    let wloom = load_wloom();
    if path.is_empty() || path[0] != wloom {
        petal::revert("router: swapLOOMForExact: path[0] must be wloom");
    }

    let value = msg::value();
    let msg_value = U256(value);

    let factory = load_factory();
    let amounts = compute_amounts_in(&factory, amount_out, &path);

    let loom_needed = amounts[0];
    if loom_needed > msg_value {
        petal::revert("router: swapLOOMForExact: insufficient msg.value");
    }

    // Deposit exactly what's needed.
    let loom_needed_bytes = loom_needed.0;
    wloom_deposit(&wloom, &loom_needed_bytes);

    let first_pair = factory_get_pair(&factory, &path[0], &path[1]);
    if first_pair == [0u8; 32] {
        petal::revert("router: swapLOOMForExact: first pair not found");
    }
    {
        let mut cd = Encoder::with_selector(selectors::ERC20_TRANSFER);
        cd.push_address(&first_pair);
        cd.push_u256(loom_needed);
        petal::call(&wloom, &cd.finish(), &ZERO_VALUE)
            .unwrap_or_else(|_| petal::revert("router: wloom transfer failed"));
    }

    internal_swap(&factory, &amounts, &path, &to);

    // Refund excess LOOM to sender.
    let refund = msg_value
        .checked_sub(loom_needed)
        .unwrap_or(U256::ZERO);
    if !refund.is_zero() {
        let sender = msg::sender();
        send_loom(&sender, refund);
    }

    petal::return_data(&encode_amounts(&amounts));
}

// ---------------------------------------------------------------------------
// Self address helper (router calls burn-to-self for LOOM unwrap)
// ---------------------------------------------------------------------------

/// Return this petal's own address, stored at init time (K_SELF slot).
/// The init calldata may supply it as a third 32-byte field (96B form).
/// When performing removeLiquidityLOOM / LOOM-output swaps, the router must
/// temporarily receive wLOOM before unwrapping it to native LOOM.
fn self_address() -> [u8; 32] {
    state::read(&k_self()).unwrap_or([0u8; 32])
}

// ---------------------------------------------------------------------------
// Unit tests (host-target, no wasm32)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn u256(v: u128) -> U256 {
        U256::from_u128(v)
    }

    // --- quote ---

    #[test]
    fn quote_basic() {
        // amountA=1, reserveA=1, reserveB=2 → amountA * reserveB / reserveA = 2
        assert_eq!(quote(u256(1), u256(1), u256(2)), u256(2));
    }

    #[test]
    fn quote_proportional() {
        // amountA=100, reserveA=1000, reserveB=2000 → 200
        assert_eq!(quote(u256(100), u256(1000), u256(2000)), u256(200));
    }

    #[test]
    #[should_panic]
    fn quote_zero_amount() {
        quote(u256(0), u256(1000), u256(2000));
    }

    #[test]
    #[should_panic]
    fn quote_zero_reserve_a() {
        quote(u256(100), u256(0), u256(2000));
    }

    #[test]
    #[should_panic]
    fn quote_zero_reserve_b() {
        quote(u256(100), u256(1000), u256(0));
    }

    // --- get_amount_out ---

    #[test]
    fn get_amount_out_basic() {
        // Uniswap v2 reference: amountIn=1000, reserveIn=1000000, reserveOut=1000000
        // a_in_with_fee = 1000 * 997 = 997000
        // numerator = 997000 * 1000000 = 997_000_000_000
        // denominator = 1000000 * 1000 + 997000 = 1_000_997_000
        // amountOut = 997_000_000_000 / 1_000_997_000 = 996 (truncated)
        let out = get_amount_out(u256(1000), u256(1_000_000), u256(1_000_000));
        assert_eq!(out, u256(996));
    }

    #[test]
    fn get_amount_out_fee_check() {
        // 1e18 in, 1e21 / 1e21 balanced pool
        // fee = 0.3%, so out ≈ 1e18 * 997/(1000 + 997) * something
        // Exact: amountIn=1e18, reserveIn=1e21, reserveOut=1e21
        // a_in_fee = 1e18 * 997 = 997e18
        // num = 997e18 * 1e21 = 997e39
        // den = 1e21 * 1e3 + 997e18 = 1e24 + 997e18 ≈ 1_000_997e18
        // out = 997e39 / 1_000_997e18 ≈ 996006981054...
        let one_e18: u128 = 1_000_000_000_000_000_000;
        let one_e21: u128 = 1_000_000_000_000_000_000_000;
        let out = get_amount_out(u256(one_e18), u256(one_e21), u256(one_e21));
        // Expected ≈ 996006981054 (roughly 0.996e12)... let's just check > 0.99e18 and < 1e18.
        // Actually with 1e21 pools the price is 1:1 after fee ≈ 9.96e17
        let expected: u128 = 996_006_981_039_903_216; // precomputed reference
        // Allow ±1 for integer division rounding
        let diff = if out.to_u128_checked().unwrap() > expected {
            out.to_u128_checked().unwrap() - expected
        } else {
            expected - out.to_u128_checked().unwrap()
        };
        assert!(diff <= 1, "expected ~{}, got {:?}", expected, out);
    }

    #[test]
    #[should_panic]
    fn get_amount_out_zero_in() {
        get_amount_out(u256(0), u256(1000), u256(1000));
    }

    #[test]
    #[should_panic]
    fn get_amount_out_zero_reserves() {
        get_amount_out(u256(100), u256(0), u256(1000));
    }

    // --- get_amount_in ---

    #[test]
    fn get_amount_in_basic() {
        // Inverse of get_amount_out (rounding may differ by 1).
        // We want amountOut=996 with the same pool.
        // reserveIn=1000000, reserveOut=1000000
        // den = (1000000 - 996) * 997 = 999004 * 997 = 996,012,988
        // num = 1000000 * 996 * 1000 = 996_000_000_000
        // div = 996_000_000_000 / 996_012_988 = 999 (approx)
        // result = 999 + 1 = 1000
        let amt_in = get_amount_in(u256(996), u256(1_000_000), u256(1_000_000));
        assert_eq!(amt_in, u256(1000));
    }

    #[test]
    #[should_panic]
    fn get_amount_in_amount_out_gte_reserve() {
        get_amount_in(u256(1000), u256(1000), u256(1000));
    }

    #[test]
    #[should_panic]
    fn get_amount_in_zero_out() {
        get_amount_in(u256(0), u256(1000), u256(1000));
    }

    // --- compute_liquidity_amounts ---

    #[test]
    fn compute_liquidity_amounts_empty_pool() {
        // No reserves → use desired amounts directly.
        let (a, b) = compute_liquidity_amounts(
            u256(1000),
            u256(2000),
            u256(0),
            u256(0),
            U256::ZERO,
            U256::ZERO,
        );
        assert_eq!(a, u256(1000));
        assert_eq!(b, u256(2000));
    }

    #[test]
    fn compute_liquidity_amounts_b_optimal() {
        // Pool has rA=1000, rB=2000; we want A=100, B=300.
        // bOptimal = quote(100, 1000, 2000) = 200. 200 <= 300 → use (100, 200).
        let (a, b) = compute_liquidity_amounts(
            u256(100),
            u256(300),
            u256(0),
            u256(0),
            u256(1000),
            u256(2000),
        );
        assert_eq!(a, u256(100));
        assert_eq!(b, u256(200));
    }

    #[test]
    fn compute_liquidity_amounts_a_optimal() {
        // Pool has rA=1000, rB=2000; we want A=300, B=100.
        // bOptimal = quote(300, 1000, 2000) = 600. 600 > 100 (desired_b).
        // aOptimal = quote(100, 2000, 1000) = 50. 50 <= 300 → use (50, 100).
        let (a, b) = compute_liquidity_amounts(
            u256(300),
            u256(100),
            u256(0),
            u256(0),
            u256(1000),
            u256(2000),
        );
        assert_eq!(a, u256(50));
        assert_eq!(b, u256(100));
    }

    #[test]
    #[should_panic]
    fn compute_liquidity_amounts_insufficient_b() {
        // bOptimal = 200, but amountBMin = 250.
        compute_liquidity_amounts(
            u256(100),
            u256(300),
            u256(0),
            u256(250), // amountBMin = 250 > bOptimal=200
            u256(1000),
            u256(2000),
        );
    }
}
