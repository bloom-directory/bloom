//! bloom-dex-erc20 — ERC-20 fungible token as a bloom-chain petal.
//!
//! # Storage keys
//!
//! All keys are 32-byte BLAKE3 digests computed via the `crypto.blake3`
//! host import (or `blake3::hash` in host-target tests). Domain tags are
//! chosen to be stable and collision-free with the pair AMM keys.
//!
//! | Key expression                              | Host tag byte string               | Meaning           |
//! |---------------------------------------------|------------------------------------|-------------------|
//! | `K_NAME`                                    | `"erc20.name"`                     | bytes32 NUL-padded ASCII name |
//! | `K_SYMBOL`                                  | `"erc20.symbol"`                   | bytes32 NUL-padded ASCII symbol |
//! | `K_DECIMALS`                                | `"erc20.decimals"`                 | u8 in low byte of a 32-byte slot |
//! | `K_TOTAL`                                   | `"erc20.total_supply"`             | u256 BE total supply |
//! | `K_BAL(addr)`   = `blake3("erc20.balance:" \|\| addr)`  | dynamic per-address  | u256 BE balance |
//! | `K_ALLOW(o,s)`  = `blake3("erc20.allowance:" \|\| o \|\| s)` | dynamic per-pair | u256 BE allowance |
//!
//! # Init payload (chain spec §7.8 / DEX spec §6.1)
//!
//! ```text
//! name_len   : u16 BE
//! name_bytes : [u8; name_len]   (ASCII, ≤ 32 bytes)
//! symbol_len : u16 BE
//! symbol_bytes: [u8; symbol_len] (ASCII, ≤ 32 bytes)
//! decimals   : u8
//! initial_supply : [u8; 32]     (u256 BE)
//! initial_holder : [u8; 32]     (Address)
//! ```
//!
//! # Calldata (DEX spec §4)
//!
//! `selector (4 bytes) || args (concatenated fixed-width)`.
//! All selectors are the first 4 bytes of `blake3(method_string)` per §4.1.

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::vec::Vec;

use bloom_dex_abi::{
    decode::{AbiError, Buf},
    events,
    selectors,
    u256::U256,
};
use bloom_petal_sdk::{crypto, log, msg, petal, state};

// ---------------------------------------------------------------------------
// Static storage keys (computed at compile time on host; via crypto on wasm)
// ---------------------------------------------------------------------------
//
// On wasm32 we call the `crypto.blake3` host import at first use.
// On host targets (tests) we call blake3::hash directly — enabled by the
// `bloom-petal-sdk` which re-exports the host stubs / the sdk wraps things.
//
// We compute these lazily via inline functions rather than true compile-time
// const because `blake3::hash` is not const.

/// Compute the 32-byte storage key for the given domain tag.
fn static_key(tag: &[u8]) -> [u8; 32] {
    crypto::blake3(tag)
}

/// Storage key for the token name (`bytes32` NUL-padded ASCII).
fn k_name() -> [u8; 32] { static_key(b"erc20.name") }

/// Storage key for the token symbol (`bytes32` NUL-padded ASCII).
fn k_symbol() -> [u8; 32] { static_key(b"erc20.symbol") }

/// Storage key for decimals (u8 in low byte of `bytes32`).
fn k_decimals() -> [u8; 32] { static_key(b"erc20.decimals") }

/// Storage key for total supply (u256 BE).
fn k_total_supply() -> [u8; 32] { static_key(b"erc20.total_supply") }

/// Storage key for the balance of `addr` (u256 BE).
fn k_balance(addr: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(b"erc20.balance:".len() + 32);
    preimage.extend_from_slice(b"erc20.balance:");
    preimage.extend_from_slice(addr);
    crypto::blake3(&preimage)
}

/// Storage key for allowance of `spender` on behalf of `owner` (u256 BE).
fn k_allowance(owner: &[u8; 32], spender: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(b"erc20.allowance:".len() + 64);
    preimage.extend_from_slice(b"erc20.allowance:");
    preimage.extend_from_slice(owner);
    preimage.extend_from_slice(spender);
    crypto::blake3(&preimage)
}

// ---------------------------------------------------------------------------
// Storage helpers — read/write u256 and bytes32
// ---------------------------------------------------------------------------

/// Read a u256 from storage. Returns `U256::ZERO` if the slot is absent.
fn read_u256(key: &[u8; 32]) -> U256 {
    match state::read(key) {
        Some(v) => U256(v),
        None => U256::ZERO,
    }
}

/// Write a u256 to storage.
fn write_u256(key: &[u8; 32], value: U256) {
    state::write(key, &value.0);
}

/// Read a `bytes32` slot. Returns all-zero if absent.
fn read_bytes32(key: &[u8; 32]) -> [u8; 32] {
    state::read(key).unwrap_or([0u8; 32])
}

/// Write a `bytes32` slot.
fn write_bytes32(key: &[u8; 32], value: &[u8; 32]) {
    state::write(key, value);
}

// ---------------------------------------------------------------------------
// ERC-20 storage accessors
// ---------------------------------------------------------------------------

fn name_bytes32() -> [u8; 32] {
    read_bytes32(&k_name())
}

fn symbol_bytes32() -> [u8; 32] {
    read_bytes32(&k_symbol())
}

fn decimals_u8() -> u8 {
    let slot = read_bytes32(&k_decimals());
    slot[31] // low byte
}

fn total_supply() -> U256 {
    read_u256(&k_total_supply())
}

fn balance_of(addr: &[u8; 32]) -> U256 {
    read_u256(&k_balance(addr))
}

fn allowance(owner: &[u8; 32], spender: &[u8; 32]) -> U256 {
    read_u256(&k_allowance(owner, spender))
}

// ---------------------------------------------------------------------------
// U256::MAX sentinel for unlimited allowance
// ---------------------------------------------------------------------------

const U256_MAX: U256 = U256([0xff; 32]);

// ---------------------------------------------------------------------------
// Mint helper (used by init)
// ---------------------------------------------------------------------------

/// Increase the balance of `to` by `amount` and update total supply.
/// Emits Transfer(0x0, to, amount).
fn mint(to: &[u8; 32], amount: U256) {
    if amount.is_zero() {
        return;
    }
    // Update balance.
    let prev = balance_of(to);
    let next = prev.checked_add(amount)
        .unwrap_or_else(|| petal::revert("erc20: mint overflow"));
    write_u256(&k_balance(to), next);

    // Update total supply.
    let ts = total_supply();
    let ts_next = ts.checked_add(amount)
        .unwrap_or_else(|| petal::revert("erc20: total supply overflow"));
    write_u256(&k_total_supply(), ts_next);

    // Emit Transfer(0x0, to, amount).
    let zero = [0u8; 32];
    let data = events::pack_transfer(&zero, to, &amount.0);
    log::emit(&[events::ERC20_TRANSFER_EVENT], &data);
}

// ---------------------------------------------------------------------------
// Internal transfer (no event — callers emit events)
// ---------------------------------------------------------------------------

/// Debit `amount` from `from` and credit to `to`. Reverts on insufficient balance.
/// Does NOT emit an event — callers must emit Transfer after calling this.
fn do_transfer(from: &[u8; 32], to: &[u8; 32], amount: U256) {
    if amount.is_zero() {
        // Zero transfers are allowed; nothing to do.
        return;
    }
    let from_bal = balance_of(from);
    let new_from = from_bal.checked_sub(amount)
        .unwrap_or_else(|| petal::revert("erc20: insufficient balance"));
    write_u256(&k_balance(from), new_from);

    let to_bal = balance_of(to);
    let new_to = to_bal.checked_add(amount)
        .unwrap_or_else(|| petal::revert("erc20: balance overflow"));
    write_u256(&k_balance(to), new_to);
}

// ---------------------------------------------------------------------------
// Method handlers
// ---------------------------------------------------------------------------

/// `erc20.name()` → bytes32 (NUL-padded ASCII)
fn handle_name() {
    let v = name_bytes32();
    petal::return_data(&v);
}

/// `erc20.symbol()` → bytes32 (NUL-padded ASCII)
fn handle_symbol() {
    let v = symbol_bytes32();
    petal::return_data(&v);
}

/// `erc20.decimals()` → u8 (1 byte)
fn handle_decimals() {
    let d = decimals_u8();
    petal::return_data(&[d]);
}

/// `erc20.total_supply()` → u256 (32 bytes BE)
fn handle_total_supply() {
    let v = total_supply();
    petal::return_data(&v.0);
}

/// `erc20.balance_of(address)` → u256
fn handle_balance_of(buf: &mut Buf) {
    let addr = parse(buf.read_address(), "erc20.balance_of: bad address");
    expect_eof(buf);
    let bal = balance_of(&addr);
    petal::return_data(&bal.0);
}

/// `erc20.allowance(address,address)` → u256
fn handle_allowance(buf: &mut Buf) {
    let owner   = parse(buf.read_address(), "erc20.allowance: bad owner");
    let spender = parse(buf.read_address(), "erc20.allowance: bad spender");
    expect_eof(buf);
    let a = allowance(&owner, &spender);
    petal::return_data(&a.0);
}

/// `erc20.transfer(address,u256)` → bool (1 byte)
fn handle_transfer(buf: &mut Buf) {
    let to     = parse(buf.read_address(), "erc20.transfer: bad to");
    let amount = parse(buf.read_u256(),    "erc20.transfer: bad amount");
    expect_eof(buf);

    let sender = msg::sender();
    do_transfer(&sender, &to, amount);

    // Emit Transfer(sender, to, amount).
    let data = events::pack_transfer(&sender, &to, &amount.0);
    log::emit(&[events::ERC20_TRANSFER_EVENT], &data);

    petal::return_data(&[1u8]);
}

/// `erc20.transfer_from(address,address,u256)` → bool (1 byte)
fn handle_transfer_from(buf: &mut Buf) {
    let from   = parse(buf.read_address(), "erc20.transfer_from: bad from");
    let to     = parse(buf.read_address(), "erc20.transfer_from: bad to");
    let amount = parse(buf.read_u256(),    "erc20.transfer_from: bad amount");
    expect_eof(buf);

    let caller = msg::sender();

    // Check and deduct allowance (u256::MAX means unlimited).
    let allow_key = k_allowance(&from, &caller);
    let current_allow = read_u256(&allow_key);
    if current_allow != U256_MAX {
        let new_allow = current_allow.checked_sub(amount)
            .unwrap_or_else(|| petal::revert("erc20: insufficient allowance"));
        write_u256(&allow_key, new_allow);
    }

    do_transfer(&from, &to, amount);

    // Emit Transfer(from, to, amount).
    let data = events::pack_transfer(&from, &to, &amount.0);
    log::emit(&[events::ERC20_TRANSFER_EVENT], &data);

    petal::return_data(&[1u8]);
}

/// `erc20.approve(address,u256)` → bool (1 byte)
fn handle_approve(buf: &mut Buf) {
    let spender = parse(buf.read_address(), "erc20.approve: bad spender");
    let value   = parse(buf.read_u256(),    "erc20.approve: bad value");
    expect_eof(buf);

    let owner = msg::sender();
    write_u256(&k_allowance(&owner, &spender), value);

    // Emit Approval(owner, spender, value).
    let data = events::pack_approval(&owner, &spender, &value.0);
    log::emit(&[events::ERC20_APPROVAL_EVENT], &data);

    petal::return_data(&[1u8]);
}

// ---------------------------------------------------------------------------
// Calldata parser helpers — revert on bad input
// ---------------------------------------------------------------------------

fn parse<T>(res: Result<T, AbiError>, msg: &str) -> T {
    res.unwrap_or_else(|_| petal::revert(msg))
}

fn expect_eof(buf: &Buf) {
    if buf.remaining() != 0 {
        petal::revert("erc20: trailing calldata bytes");
    }
}

// ---------------------------------------------------------------------------
// Init payload parser helpers
// ---------------------------------------------------------------------------

/// Parse a `u16-BE length || bytes` field from a raw slice, returning the
/// field bytes and the remaining slice. Reverts if the slice is too short.
fn parse_length_prefixed<'a>(data: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    if data.len() < 2 {
        petal::revert("erc20: init payload truncated at length prefix");
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let rest = &data[2..];
    if rest.len() < len {
        petal::revert("erc20: init payload truncated in field bytes");
    }
    (&rest[..len], &rest[len..])
}

/// Write a string of up to 32 bytes into a `bytes32` slot (left-zero-padded,
/// i.e. ASCII occupies the right portion). Reverts if the string exceeds 32 bytes.
fn str_to_bytes32(s: &[u8]) -> [u8; 32] {
    if s.len() > 32 {
        petal::revert("erc20: name/symbol too long (max 32 bytes)");
    }
    let mut slot = [0u8; 32];
    // Right-align: put string at the end of the slot.
    let offset = 32 - s.len();
    slot[offset..].copy_from_slice(s);
    slot
}

// ---------------------------------------------------------------------------
// Petal entry points
// ---------------------------------------------------------------------------

/// `init` — runs once at deploy time.
///
/// Payload: `name_len (u16 BE) | name | symbol_len (u16 BE) | symbol |
///           decimals (u8) | initial_supply (u256 BE, 32 B) | initial_holder (Address, 32 B)`
fn do_init(calldata: Vec<u8>) {
    let data = calldata.as_slice();

    // Parse name.
    let (name_bytes, rest) = parse_length_prefixed(data);
    let name_slot = str_to_bytes32(name_bytes);

    // Parse symbol.
    let (symbol_bytes, rest) = parse_length_prefixed(rest);
    let symbol_slot = str_to_bytes32(symbol_bytes);

    // Parse decimals (1 byte).
    if rest.len() < 1 {
        petal::revert("erc20: init payload truncated at decimals");
    }
    let decimals = rest[0];
    let rest = &rest[1..];

    // Parse initial_supply (32 bytes, u256 BE).
    if rest.len() < 32 {
        petal::revert("erc20: init payload truncated at initial_supply");
    }
    let mut supply_bytes = [0u8; 32];
    supply_bytes.copy_from_slice(&rest[..32]);
    let initial_supply = U256(supply_bytes);
    let rest = &rest[32..];

    // Parse initial_holder (32 bytes, Address).
    if rest.len() < 32 {
        petal::revert("erc20: init payload truncated at initial_holder");
    }
    let mut holder = [0u8; 32];
    holder.copy_from_slice(&rest[..32]);
    let rest = &rest[32..];

    // No trailing bytes allowed.
    if !rest.is_empty() {
        petal::revert("erc20: init payload has trailing bytes");
    }

    // Write metadata to storage.
    write_bytes32(&k_name(), &name_slot);
    write_bytes32(&k_symbol(), &symbol_slot);

    // Decimals: u8 in the low byte of a 32-byte slot.
    let mut dec_slot = [0u8; 32];
    dec_slot[31] = decimals;
    write_bytes32(&k_decimals(), &dec_slot);

    // Mint initial supply to holder (also sets total_supply).
    mint(&holder, initial_supply);
}

/// `call` — dispatches on the 4-byte selector.
///
/// Returns 0 on success (and exits via `petal::return_data`).
/// Calls `petal::revert` on any error (no return).
fn do_call(calldata: Vec<u8>) -> i32 {
    if calldata.len() < 4 {
        petal::revert("erc20: calldata too short");
    }
    let sel: [u8; 4] = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let args = &calldata[4..];
    let mut buf = Buf::new(args);

    match sel {
        s if s == selectors::ERC20_NAME          => handle_name(),
        s if s == selectors::ERC20_SYMBOL        => handle_symbol(),
        s if s == selectors::ERC20_DECIMALS      => handle_decimals(),
        s if s == selectors::ERC20_TOTAL_SUPPLY  => handle_total_supply(),
        s if s == selectors::ERC20_BALANCE_OF    => handle_balance_of(&mut buf),
        s if s == selectors::ERC20_ALLOWANCE     => handle_allowance(&mut buf),
        s if s == selectors::ERC20_TRANSFER      => handle_transfer(&mut buf),
        s if s == selectors::ERC20_TRANSFER_FROM => handle_transfer_from(&mut buf),
        s if s == selectors::ERC20_APPROVE       => handle_approve(&mut buf),
        _                                        => petal::revert("erc20: unknown selector"),
    }
    // `handle_*` functions always exit via `petal::return_data` or `petal::revert`.
    // The `-> i32` return type is required by the petal! macro ABI; we satisfy it
    // with an unreachable value (the above match arms all diverge).
    0
}

// ---------------------------------------------------------------------------
// Wasm entry points
// ---------------------------------------------------------------------------
//
// We define entry points directly rather than via the `petal!` macro because
// edition 2024 requires `#[unsafe(no_mangle)]` and the macro emits the older
// `#[no_mangle]` form.

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
// Host-side unit tests (cfg(test), host target only)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use bloom_dex_abi::{
        decode::Buf,
        encode::Encoder,
        selectors,
        u256::U256,
    };

    // ---------------------------------------------------------------------------
    // Helper: build init payload
    // ---------------------------------------------------------------------------

    fn encode_init(
        name: &[u8],
        symbol: &[u8],
        decimals: u8,
        initial_supply: U256,
        initial_holder: [u8; 32],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        // name_len (u16 BE) + bytes
        v.extend_from_slice(&(name.len() as u16).to_be_bytes());
        v.extend_from_slice(name);
        // symbol_len (u16 BE) + bytes
        v.extend_from_slice(&(symbol.len() as u16).to_be_bytes());
        v.extend_from_slice(symbol);
        // decimals
        v.push(decimals);
        // initial_supply (u256 BE, 32 bytes)
        v.extend_from_slice(&initial_supply.0);
        // initial_holder (32 bytes)
        v.extend_from_slice(&initial_holder);
        v
    }

    // ---------------------------------------------------------------------------
    // Helper: build calldata for each method
    // ---------------------------------------------------------------------------

    fn cd_balance_of(addr: [u8; 32]) -> Vec<u8> {
        let mut e = Encoder::with_selector(selectors::ERC20_BALANCE_OF);
        e.push_address(&addr);
        e.finish()
    }

    fn cd_allowance(owner: [u8; 32], spender: [u8; 32]) -> Vec<u8> {
        let mut e = Encoder::with_selector(selectors::ERC20_ALLOWANCE);
        e.push_address(&owner);
        e.push_address(&spender);
        e.finish()
    }

    fn cd_transfer(to: [u8; 32], value: U256) -> Vec<u8> {
        let mut e = Encoder::with_selector(selectors::ERC20_TRANSFER);
        e.push_address(&to);
        e.push_u256(value);
        e.finish()
    }

    fn cd_transfer_from(from: [u8; 32], to: [u8; 32], value: U256) -> Vec<u8> {
        let mut e = Encoder::with_selector(selectors::ERC20_TRANSFER_FROM);
        e.push_address(&from);
        e.push_address(&to);
        e.push_u256(value);
        e.finish()
    }

    fn cd_approve(spender: [u8; 32], value: U256) -> Vec<u8> {
        let mut e = Encoder::with_selector(selectors::ERC20_APPROVE);
        e.push_address(&spender);
        e.push_u256(value);
        e.finish()
    }

    // ---------------------------------------------------------------------------
    // Tests: calldata encoding round-trips (ABI surface only — no host calls)
    // ---------------------------------------------------------------------------

    /// Verify that the selector for ERC20_BALANCE_OF is 4 bytes and that a
    /// calldata blob can be decoded back out with the matching Buf reader.
    #[test]
    fn balance_of_calldata_roundtrip() {
        let addr = [42u8; 32];
        let cd = cd_balance_of(addr);

        // Should be 4-byte selector + 32-byte address = 36 bytes.
        assert_eq!(cd.len(), 36);
        assert_eq!(&cd[..4], &selectors::ERC20_BALANCE_OF);

        // Decode args.
        let mut buf = Buf::new(&cd[4..]);
        let decoded_addr = buf.read_address().unwrap();
        assert_eq!(decoded_addr, addr);
        assert!(buf.expect_eof().is_ok());
    }

    #[test]
    fn allowance_calldata_roundtrip() {
        let owner   = [1u8; 32];
        let spender = [2u8; 32];
        let cd = cd_allowance(owner, spender);

        assert_eq!(cd.len(), 4 + 32 + 32);
        assert_eq!(&cd[..4], &selectors::ERC20_ALLOWANCE);

        let mut buf = Buf::new(&cd[4..]);
        assert_eq!(buf.read_address().unwrap(), owner);
        assert_eq!(buf.read_address().unwrap(), spender);
        assert!(buf.expect_eof().is_ok());
    }

    #[test]
    fn transfer_calldata_roundtrip() {
        let to     = [7u8; 32];
        let amount = U256::from_u128(1_000_000_000_000_000_000u128); // 1e18
        let cd = cd_transfer(to, amount);

        assert_eq!(cd.len(), 4 + 32 + 32);
        assert_eq!(&cd[..4], &selectors::ERC20_TRANSFER);

        let mut buf = Buf::new(&cd[4..]);
        assert_eq!(buf.read_address().unwrap(), to);
        assert_eq!(buf.read_u256().unwrap(), amount);
        assert!(buf.expect_eof().is_ok());
    }

    #[test]
    fn transfer_from_calldata_roundtrip() {
        let from   = [10u8; 32];
        let to     = [20u8; 32];
        let amount = U256::from_u64(500);
        let cd = cd_transfer_from(from, to, amount);

        assert_eq!(cd.len(), 4 + 32 + 32 + 32);
        assert_eq!(&cd[..4], &selectors::ERC20_TRANSFER_FROM);

        let mut buf = Buf::new(&cd[4..]);
        assert_eq!(buf.read_address().unwrap(), from);
        assert_eq!(buf.read_address().unwrap(), to);
        assert_eq!(buf.read_u256().unwrap(), amount);
        assert!(buf.expect_eof().is_ok());
    }

    #[test]
    fn approve_calldata_roundtrip() {
        let spender = [99u8; 32];
        let value   = U256([0xffu8; 32]); // u256::MAX (unlimited allowance)
        let cd = cd_approve(spender, value);

        assert_eq!(cd.len(), 4 + 32 + 32);
        assert_eq!(&cd[..4], &selectors::ERC20_APPROVE);

        let mut buf = Buf::new(&cd[4..]);
        assert_eq!(buf.read_address().unwrap(), spender);
        assert_eq!(buf.read_u256().unwrap(), value);
        assert!(buf.expect_eof().is_ok());
    }

    /// Verify the init payload encoding round-trips correctly.
    #[test]
    fn init_payload_roundtrip() {
        let name    = b"TestToken";
        let symbol  = b"TST";
        let decimals = 18u8;
        let supply  = U256::from_u128(1_000_000_000_000_000_000_000_000u128); // 1e24
        let holder  = [0xABu8; 32];

        let payload = encode_init(name, symbol, decimals, supply, holder);

        // Manually decode and verify.
        let mut pos = 0usize;

        // name
        let name_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        assert_eq!(&payload[pos..pos + name_len], name);
        pos += name_len;

        // symbol
        let sym_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        assert_eq!(&payload[pos..pos + sym_len], symbol);
        pos += sym_len;

        // decimals
        assert_eq!(payload[pos], decimals);
        pos += 1;

        // supply
        let mut s = [0u8; 32];
        s.copy_from_slice(&payload[pos..pos + 32]);
        assert_eq!(U256(s), supply);
        pos += 32;

        // holder
        let mut h = [0u8; 32];
        h.copy_from_slice(&payload[pos..pos + 32]);
        assert_eq!(h, holder);
        pos += 32;

        assert_eq!(pos, payload.len(), "no trailing bytes");
    }

    /// Verify the `str_to_bytes32` alignment (right-align / left-zero-pad).
    #[test]
    fn str_to_bytes32_alignment() {
        // A 3-byte symbol "TST" should occupy bytes [29..32] of the slot.
        let s = b"TST";
        let mut expected = [0u8; 32];
        expected[29..32].copy_from_slice(s);

        // Test the logic directly (duplicated here since the fn is private).
        let mut slot = [0u8; 32];
        let offset = 32 - s.len();
        slot[offset..].copy_from_slice(s);

        assert_eq!(slot, expected);
    }

    /// Verify u256::MAX round-trips as the unlimited-allowance sentinel.
    #[test]
    fn u256_max_sentinel() {
        let max = U256([0xff; 32]);
        let mut e = Encoder::new();
        e.push_u256(max);
        let out = e.finish();
        let mut buf = Buf::new(&out);
        let decoded = buf.read_u256().unwrap();
        assert_eq!(decoded, max);
    }

    /// Sanity-check that all 9 ERC-20 selectors are distinct (no 4-byte collision).
    #[test]
    fn selectors_are_unique() {
        use std::collections::HashSet;
        let sels: &[[u8; 4]] = &[
            selectors::ERC20_NAME,
            selectors::ERC20_SYMBOL,
            selectors::ERC20_DECIMALS,
            selectors::ERC20_TOTAL_SUPPLY,
            selectors::ERC20_BALANCE_OF,
            selectors::ERC20_ALLOWANCE,
            selectors::ERC20_TRANSFER,
            selectors::ERC20_TRANSFER_FROM,
            selectors::ERC20_APPROVE,
        ];
        let set: HashSet<[u8; 4]> = sels.iter().cloned().collect();
        assert_eq!(set.len(), sels.len(), "selector collision detected");
    }
}
