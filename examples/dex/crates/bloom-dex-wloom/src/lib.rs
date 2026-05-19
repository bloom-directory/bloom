//! bloom-dex-wloom — Wrapped LOOM (wLOOM) petal for bloom-chain DEX.
//!
//! Mirrors WETH9 semantics: wraps native LOOM as an ERC-20 token.
//! Single global deployment per DEX; its address is baked into router init.
//!
//! ## Constants
//! - name    = "Wrapped LOOM"
//! - symbol  = "wLOOM"
//! - decimals = 18
//!
//! ## init
//! No parameters expected. Writes `total_supply = 0` to storage (idempotent
//! no-op, since unset slots default to zero — this just marks the petal as
//! deployed). Name/symbol/decimals are hardcoded constants; they do not need
//! to be stored.
//!
//! ## Storage layout (DEX spec §6.4)
//! All keys are 32-byte BLAKE3 digests:
//! - `K_TOTAL      = blake3("wloom.total_supply")`
//! - `K_BAL(a)     = blake3("wloom.balance:" || a)`           a = 32-byte address
//! - `K_ALLOW(o,s) = blake3("wloom.allowance:" || o || s)`   o,s = 32-byte addresses
//!
//! ## Events (DEX spec §11)
//! - `Transfer(from, to, value)` — ERC-20 mint/burn/transfer; topic0 is the
//!   4-byte blake3 prefix of `"Transfer(address,address,u256)"`.
//! - `Approval(owner, spender, value)`.
//! - `Deposit(dst, value)` — topic0 = blake3("Deposit(address,u256)")[..4],
//!   topic1 = dst (32B), data = value (32B).
//! - `Withdrawal(src, value)` — topic0 = blake3("Withdrawal(address,u256)")[..4],
//!   topic1 = src (32B), data = value (32B).
//!
//! Deposit also emits `Transfer(0x0, dst, value)` (mint signal).
//! Withdrawal also emits `Transfer(src, 0x0, value)` (burn signal).
//!
//! ## dispatch
//! `call` entry point:
//! - If `calldata.len() < 4` (empty or too-short, including bare value transfers),
//!   route to `deposit()` — the receive-LOOM fallback per DEX spec §7.
//! - Otherwise dispatch on the 4-byte selector per DEX spec §4.1.

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::vec::Vec;

use bloom_dex_abi::{
    decode::{AbiError, Buf},
    selectors,
    u256::U256,
};
use bloom_petal_sdk::{crypto, log, msg, petal, state};

// ---------------------------------------------------------------------------
// Storage key derivation
// ---------------------------------------------------------------------------

/// Storage key for `total_supply`.
fn k_total() -> [u8; 32] {
    crypto::blake3(b"wloom.total_supply")
}

/// Storage key for `balance_of(addr)`.
fn k_bal(addr: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(14 + 32);
    buf.extend_from_slice(b"wloom.balance:");
    buf.extend_from_slice(addr);
    crypto::blake3(&buf)
}

/// Storage key for `allowance(owner, spender)`.
fn k_allow(owner: &[u8; 32], spender: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(16 + 64);
    buf.extend_from_slice(b"wloom.allowance:");
    buf.extend_from_slice(owner);
    buf.extend_from_slice(spender);
    crypto::blake3(&buf)
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

fn read_u256(key: &[u8; 32]) -> U256 {
    match state::read(key) {
        Some(v) => U256(v),
        None => U256::ZERO,
    }
}

fn write_u256(key: &[u8; 32], v: U256) {
    state::write(key, &v.0);
}

// ---------------------------------------------------------------------------
// ABI decoder helpers
// ---------------------------------------------------------------------------

fn parse<T>(res: Result<T, AbiError>, msg: &str) -> T {
    res.unwrap_or_else(|_| petal::revert(msg))
}

// ---------------------------------------------------------------------------
// ERC-20 metadata constants
// ---------------------------------------------------------------------------

/// Name "Wrapped LOOM" as a NUL-right-padded bytes32.
fn name_bytes32() -> [u8; 32] {
    let s = b"Wrapped LOOM";
    let mut b = [0u8; 32];
    b[..s.len()].copy_from_slice(s);
    b
}

/// Symbol "wLOOM" as a NUL-right-padded bytes32.
fn symbol_bytes32() -> [u8; 32] {
    let s = b"wLOOM";
    let mut b = [0u8; 32];
    b[..s.len()].copy_from_slice(s);
    b
}

/// Decimals = 18 in a 32-byte slot (low byte).
fn decimals_bytes32() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = 18;
    b
}

// ---------------------------------------------------------------------------
// Event topic helpers — 4-byte blake3 prefix of each event signature.
// ---------------------------------------------------------------------------

fn topic_transfer() -> [u8; 4] {
    let h = crypto::blake3(b"Transfer(address,address,u256)");
    [h[0], h[1], h[2], h[3]]
}

fn topic_approval() -> [u8; 4] {
    let h = crypto::blake3(b"Approval(address,address,u256)");
    [h[0], h[1], h[2], h[3]]
}

fn topic_deposit() -> [u8; 4] {
    let h = crypto::blake3(b"Deposit(address,u256)");
    [h[0], h[1], h[2], h[3]]
}

fn topic_withdrawal() -> [u8; 4] {
    let h = crypto::blake3(b"Withdrawal(address,u256)");
    [h[0], h[1], h[2], h[3]]
}

// ---------------------------------------------------------------------------
// Log helpers
// ---------------------------------------------------------------------------

/// Emit `Transfer(from, to, value)` — ERC-20 style, 1 topic, data = from||to||value.
fn emit_transfer(from: &[u8; 32], to: &[u8; 32], value: &[u8; 32]) {
    let mut data: Vec<u8> = Vec::with_capacity(96);
    data.extend_from_slice(from);
    data.extend_from_slice(to);
    data.extend_from_slice(value);
    log::emit(&[topic_transfer()], &data);
}

/// Emit `Approval(owner, spender, value)`.
fn emit_approval(owner: &[u8; 32], spender: &[u8; 32], value: &[u8; 32]) {
    let mut data: Vec<u8> = Vec::with_capacity(96);
    data.extend_from_slice(owner);
    data.extend_from_slice(spender);
    data.extend_from_slice(value);
    log::emit(&[topic_approval()], &data);
}

/// Emit `Deposit(dst, value)`.
///
/// Per DEX spec §11: topic0 = blake3("Deposit(address,u256)")[..4],
/// topic1 = dst (32B address as raw topic), data = value (32B).
///
/// The host `log.emit` expects `topic_count * 32` contiguous bytes at `topic_ptr`.
/// We build a 64-byte topic buffer manually: [topic0_padded_32 || dst_32].
fn emit_deposit(dst: &[u8; 32], value: &[u8; 32]) {
    let td = topic_deposit();
    let mut topics = [0u8; 64];
    topics[0..4].copy_from_slice(&td);
    // bytes 4..32 remain zero (left-zero-pad of the 4-byte prefix to 32 bytes)
    topics[32..64].copy_from_slice(dst);
    emit_raw_2topics(&topics, value);
}

/// Emit `Withdrawal(src, value)`.
fn emit_withdrawal(src: &[u8; 32], value: &[u8; 32]) {
    let tw = topic_withdrawal();
    let mut topics = [0u8; 64];
    topics[0..4].copy_from_slice(&tw);
    topics[32..64].copy_from_slice(src);
    emit_raw_2topics(&topics, value);
}

/// Emit a log entry with a pre-built 64-byte topics buffer (2 × 32-byte topics)
/// and 32-byte data, calling the `log.emit` host import directly.
fn emit_raw_2topics(topics_buf: &[u8; 64], data: &[u8; 32]) {
    use bloom_petal_sdk::imports;
    let result = unsafe {
        imports::log_emit(
            topics_buf.as_ptr() as i32,
            2, // topic_count = 2
            data.as_ptr() as i32,
            32,
        )
    };
    if result < 0 {
        petal::revert("wloom: log_emit failed");
    }
}

// ---------------------------------------------------------------------------
// Internal raw transfer (balance accounting, no events)
// ---------------------------------------------------------------------------

fn transfer_raw(from: &[u8; 32], to: &[u8; 32], amount: U256) {
    let from_bal = read_u256(&k_bal(from));
    let new_from = from_bal
        .checked_sub(amount)
        .unwrap_or_else(|| petal::revert("wloom: insufficient balance"));
    write_u256(&k_bal(from), new_from);

    let to_bal = read_u256(&k_bal(to));
    let new_to = to_bal
        .checked_add(amount)
        .unwrap_or_else(|| petal::revert("wloom: balance overflow"));
    write_u256(&k_bal(to), new_to);
}

// ---------------------------------------------------------------------------
// ERC-20 handlers (called from do_call)
// ---------------------------------------------------------------------------

fn handle_total_supply() {
    let ts = read_u256(&k_total());
    petal::return_data(&ts.0);
}

fn handle_balance_of(buf: &mut Buf) {
    let addr = parse(buf.read_address(), "wloom: bad address arg");
    let bal = read_u256(&k_bal(&addr));
    petal::return_data(&bal.0);
}

fn handle_allowance(buf: &mut Buf) {
    let owner = parse(buf.read_address(), "wloom: bad owner arg");
    let spender = parse(buf.read_address(), "wloom: bad spender arg");
    let allow = read_u256(&k_allow(&owner, &spender));
    petal::return_data(&allow.0);
}

fn handle_name() {
    petal::return_data(&name_bytes32());
}

fn handle_symbol() {
    petal::return_data(&symbol_bytes32());
}

fn handle_decimals() {
    petal::return_data(&decimals_bytes32());
}

fn handle_approve(buf: &mut Buf) {
    let spender = parse(buf.read_address(), "wloom: bad spender arg");
    let amount = parse(buf.read_u256(), "wloom: bad amount arg");
    let owner = msg::sender();
    write_u256(&k_allow(&owner, &spender), amount);
    emit_approval(&owner, &spender, &amount.0);
    petal::return_data(&[1u8]);
}

fn handle_transfer(buf: &mut Buf) {
    let to = parse(buf.read_address(), "wloom: bad to arg");
    let amount = parse(buf.read_u256(), "wloom: bad amount arg");
    let from = msg::sender();
    transfer_raw(&from, &to, amount);
    emit_transfer(&from, &to, &amount.0);
    petal::return_data(&[1u8]);
}

fn handle_transfer_from(buf: &mut Buf) {
    let from = parse(buf.read_address(), "wloom: bad from arg");
    let to = parse(buf.read_address(), "wloom: bad to arg");
    let amount = parse(buf.read_u256(), "wloom: bad amount arg");
    let spender = msg::sender();

    // Check and reduce allowance. U256::MAX = infinite (skip deduction).
    let allow_key = k_allow(&from, &spender);
    let allow = read_u256(&allow_key);
    if allow != U256([0xff; 32]) {
        let new_allow = allow
            .checked_sub(amount)
            .unwrap_or_else(|| petal::revert("wloom: insufficient allowance"));
        write_u256(&allow_key, new_allow);
    }

    transfer_raw(&from, &to, amount);
    emit_transfer(&from, &to, &amount.0);
    petal::return_data(&[1u8]);
}

// ---------------------------------------------------------------------------
// wLOOM-specific: deposit
// ---------------------------------------------------------------------------

/// `wloom.deposit()` — payable.
///
/// Credits `msg.sender` with `msg.value` wLOOM and increments `total_supply`.
/// Emits:
/// - `Deposit(sender, value)` with sender as topic1, value as data.
/// - `Transfer(0x0, sender, value)` — mint signal for ERC-20 indexers.
///
/// If `msg.value == 0`, the function returns immediately without any storage
/// writes or events (no-op zero deposit).
fn handle_deposit() {
    let sender = msg::sender();
    let value_bytes = msg::value(); // 32-byte BE u256
    let amount = U256(value_bytes);

    if !amount.is_zero() {
        // total_supply += amount
        let ts_key = k_total();
        let ts = read_u256(&ts_key);
        let new_ts = ts
            .checked_add(amount)
            .unwrap_or_else(|| petal::revert("wloom: total supply overflow"));
        write_u256(&ts_key, new_ts);

        // balance_of(sender) += amount
        let bal_key = k_bal(&sender);
        let bal = read_u256(&bal_key);
        let new_bal = bal
            .checked_add(amount)
            .unwrap_or_else(|| petal::revert("wloom: balance overflow"));
        write_u256(&bal_key, new_bal);

        // Emit Deposit(sender, amount)
        emit_deposit(&sender, &amount.0);

        // Emit Transfer(0x0, sender, amount) — mint signal.
        emit_transfer(&[0u8; 32], &sender, &amount.0);
    }

    petal::return_data(&[]);
}

// ---------------------------------------------------------------------------
// wLOOM-specific: withdraw
// ---------------------------------------------------------------------------

/// `wloom.withdraw(amount: u256)`.
///
/// Debits `amount` from `msg.sender`, decrements `total_supply`, emits
/// `Withdrawal(sender, amount)` and `Transfer(sender, 0x0, amount)` (burn),
/// then sends native LOOM to `msg.sender` via
/// `petal::call(msg.sender, calldata=[], value=amount)`.
///
/// Reverts on insufficient balance or if the native LOOM transfer fails.
fn handle_withdraw(buf: &mut Buf) {
    let amount = parse(buf.read_u256(), "wloom: bad amount arg");

    if amount.is_zero() {
        petal::return_data(&[]);
    }

    let sender = msg::sender();

    // Debit sender balance.
    let bal_key = k_bal(&sender);
    let bal = read_u256(&bal_key);
    let new_bal = bal
        .checked_sub(amount)
        .unwrap_or_else(|| petal::revert("wloom: insufficient balance"));
    write_u256(&bal_key, new_bal);

    // Decrement total_supply.
    let ts_key = k_total();
    let ts = read_u256(&ts_key);
    let new_ts = ts
        .checked_sub(amount)
        .unwrap_or_else(|| petal::revert("wloom: total supply underflow"));
    write_u256(&ts_key, new_ts);

    // Emit Withdrawal(sender, amount).
    emit_withdrawal(&sender, &amount.0);

    // Emit Transfer(sender, 0x0, amount) — burn signal.
    emit_transfer(&sender, &[0u8; 32], &amount.0);

    // Send native LOOM to sender via empty-calldata petal.call with value.
    // petal::call takes value_loom as a 32-byte big-endian u256.
    let result = petal::call(&sender, &[], &amount.0);
    if result.is_err() {
        petal::revert("wloom: native LOOM transfer failed");
    }

    petal::return_data(&[]);
}

// ---------------------------------------------------------------------------
// Petal entry points
// ---------------------------------------------------------------------------

/// `init` — no parameters. Writes `total_supply = 0` to mark the petal
/// as initialised. Name/symbol/decimals are hardcoded and not stored.
fn do_init(_calldata: Vec<u8>) {
    write_u256(&k_total(), U256::ZERO);
}

/// `call` — dispatches on the 4-byte selector.
///
/// Special case: if `calldata.len() < 4` (empty calldata, including bare
/// value-transfer calls), routes to `handle_deposit()` per DEX spec §7.
///
/// Returns 0 on success (handlers diverge via `petal::return_data`).
/// Calls `petal::revert` on error (no return).
fn do_call(calldata: Vec<u8>) -> i32 {
    if calldata.len() < 4 {
        // Empty/short calldata → deposit fallback (receive-LOOM behaviour).
        handle_deposit();
    }

    let sel: [u8; 4] = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let mut buf = Buf::new(&calldata[4..]);

    match sel {
        s if s == selectors::ERC20_TOTAL_SUPPLY  => handle_total_supply(),
        s if s == selectors::ERC20_BALANCE_OF    => handle_balance_of(&mut buf),
        s if s == selectors::ERC20_ALLOWANCE     => handle_allowance(&mut buf),
        s if s == selectors::ERC20_NAME          => handle_name(),
        s if s == selectors::ERC20_SYMBOL        => handle_symbol(),
        s if s == selectors::ERC20_DECIMALS      => handle_decimals(),
        s if s == selectors::ERC20_APPROVE       => handle_approve(&mut buf),
        s if s == selectors::ERC20_TRANSFER      => handle_transfer(&mut buf),
        s if s == selectors::ERC20_TRANSFER_FROM => handle_transfer_from(&mut buf),
        s if s == selectors::WLOOM_DEPOSIT       => handle_deposit(),
        s if s == selectors::WLOOM_WITHDRAW      => handle_withdraw(&mut buf),
        _                                        => petal::revert("wloom: unknown selector"),
    }
    // All match arms diverge via petal::return_data / petal::revert (both `-> !`).
    // The `0` is unreachable but satisfies the `-> i32` return type.
    0
}

// ---------------------------------------------------------------------------
// Wasm entry points
// ---------------------------------------------------------------------------
//
// Defined directly rather than via the `petal!` macro because edition 2024
// requires `#[unsafe(no_mangle)]` and the macro emits the older `#[no_mangle]`.

#[unsafe(no_mangle)]
pub extern "C" fn init(calldata_ptr: i32, calldata_len: i32) -> i32 {
    let _ = (calldata_ptr, calldata_len);
    let cd = msg::calldata();
    do_init(cd);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn call(calldata_ptr: i32, calldata_len: i32) -> i32 {
    let _ = (calldata_ptr, calldata_len);
    let cd = msg::calldata();
    do_call(cd)
}

// ---------------------------------------------------------------------------
// Host-target unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
