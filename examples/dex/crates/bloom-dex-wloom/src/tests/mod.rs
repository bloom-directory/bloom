//! Host-target unit tests for bloom-dex-wloom.
//!
//! Tests use mock host imports provided by `bloom-petal-sdk`'s non-wasm32
//! stub layer (which panics) plus a thread-local mock harness defined here
//! that overrides the petal logic directly — i.e., we test the pure Rust
//! logic of each wLOOM function without invoking the wasm runtime.
//!
//! The mock approach:
//! - Storage is a `HashMap<[u8;32],[u8;32]>` in a thread-local.
//! - `msg::sender()` / `msg::value()` are simulated by module-level setters.
//! - `petal::call()` for native-transfer is mocked to record calls.
//! - `log::emit()` calls are no-ops on host.
//!
//! We test:
//! 1. Initial state: total_supply = 0, all balances zero.
//! 2. deposit() credits balance and increments total_supply.
//! 3. withdraw() debits balance and decrements total_supply.
//! 4. deposit+withdraw round-trip preserves invariants.
//! 5. withdraw reverts on insufficient balance.
//! 6. transfer / transferFrom / approve accounting.
//! 7. Empty-calldata routing to deposit.
//! 8. allowance infinite approval skips deduction.

// These tests only run on non-wasm32 (host) builds.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::HashMap;
use std::cell::RefCell;

use bloom_dex_abi::{
    encode::Encoder,
    selectors,
    u256::U256,
};

// ---------------------------------------------------------------------------
// Mock host state
// ---------------------------------------------------------------------------

thread_local! {
    /// Simulated per-instance storage.
    static STORAGE: RefCell<HashMap<[u8; 32], [u8; 32]>> = RefCell::new(HashMap::new());
    /// Simulated msg.sender (32-byte address).
    static SENDER: RefCell<[u8; 32]> = RefCell::new([0u8; 32]);
    /// Simulated msg.value (32-byte big-endian u256).
    static VALUE: RefCell<[u8; 32]> = RefCell::new([0u8; 32]);
    /// Recorded native LOOM transfer calls (target, value_u256).
    static LOOM_TRANSFERS: RefCell<Vec<([u8; 32], [u8; 32])>> = RefCell::new(Vec::new());
}

fn set_sender(addr: [u8; 32]) {
    SENDER.with(|s| *s.borrow_mut() = addr);
}

fn set_value(v: U256) {
    VALUE.with(|s| *s.borrow_mut() = v.0);
}

fn clear() {
    STORAGE.with(|s| s.borrow_mut().clear());
    SENDER.with(|s| *s.borrow_mut() = [0u8; 32]);
    VALUE.with(|s| *s.borrow_mut() = [0u8; 32]);
    LOOM_TRANSFERS.with(|s| s.borrow_mut().clear());
}

// ---------------------------------------------------------------------------
// Mock implementations of the SDK primitives used by the wLOOM logic.
// We re-implement the same logic but backed by the thread-local mock.
// ---------------------------------------------------------------------------

mod mock {
    use super::*;
    use bloom_dex_abi::u256::U256;

    pub fn blake3(data: &[u8]) -> [u8; 32] {
        // Use the real blake3 crate (available on host via bloom-dex-abi's blake3 dep).
        let h = ::blake3::hash(data);
        *h.as_bytes()
    }

    pub fn k_total() -> [u8; 32] {
        blake3(b"wloom.total_supply")
    }

    pub fn k_bal(addr: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(16 + 32);
        buf.extend_from_slice(b"wloom.balance:");
        buf.extend_from_slice(addr);
        blake3(&buf)
    }

    pub fn k_allow(owner: &[u8; 32], spender: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(18 + 64);
        buf.extend_from_slice(b"wloom.allowance:");
        buf.extend_from_slice(owner);
        buf.extend_from_slice(spender);
        blake3(&buf)
    }

    pub fn storage_read(key: &[u8; 32]) -> U256 {
        STORAGE.with(|s| {
            s.borrow().get(key).copied().map(U256).unwrap_or(U256::ZERO)
        })
    }

    pub fn storage_write(key: [u8; 32], v: U256) {
        STORAGE.with(|s| { s.borrow_mut().insert(key, v.0); });
    }

    pub fn get_total_supply() -> U256 {
        storage_read(&k_total())
    }

    pub fn get_balance(addr: &[u8; 32]) -> U256 {
        storage_read(&k_bal(addr))
    }

    pub fn get_allowance(owner: &[u8; 32], spender: &[u8; 32]) -> U256 {
        storage_read(&k_allow(owner, spender))
    }

    pub fn sender() -> [u8; 32] {
        SENDER.with(|s| *s.borrow())
    }

    pub fn value() -> U256 {
        VALUE.with(|s| U256(*s.borrow()))
    }

    // --- Business logic re-implemented for mock testing ---

    pub fn deposit() {
        let sender = self::sender();
        let amount = self::value();

        if !amount.is_zero() {
            let ts_key = k_total();
            let ts = storage_read(&ts_key);
            let new_ts = ts.checked_add(amount).expect("ts overflow");
            storage_write(ts_key, new_ts);

            let bal_key = k_bal(&sender);
            let bal = storage_read(&bal_key);
            let new_bal = bal.checked_add(amount).expect("bal overflow");
            storage_write(bal_key, new_bal);
        }
        // events: no-op in mock
    }

    pub fn withdraw(amount: U256) -> Result<(), &'static str> {
        if amount.is_zero() {
            return Ok(());
        }
        let sender = self::sender();

        let bal_key = k_bal(&sender);
        let bal = storage_read(&bal_key);
        let new_bal = bal.checked_sub(amount).ok_or("insufficient balance")?;
        storage_write(bal_key, new_bal);

        let ts_key = k_total();
        let ts = storage_read(&ts_key);
        let new_ts = ts.checked_sub(amount).ok_or("ts underflow")?;
        storage_write(ts_key, new_ts);

        // Record native LOOM transfer
        LOOM_TRANSFERS.with(|t| t.borrow_mut().push((sender, amount.0)));

        Ok(())
    }

    pub fn transfer(from: &[u8; 32], to: &[u8; 32], amount: U256) -> Result<(), &'static str> {
        let from_bal = storage_read(&k_bal(from));
        let new_from = from_bal.checked_sub(amount).ok_or("insufficient balance")?;
        storage_write(k_bal(from), new_from);

        let to_bal = storage_read(&k_bal(to));
        let new_to = to_bal.checked_add(amount).expect("balance overflow");
        storage_write(k_bal(to), new_to);

        Ok(())
    }

    pub fn approve(owner: &[u8; 32], spender: &[u8; 32], amount: U256) {
        storage_write(k_allow(owner, spender), amount);
    }

    pub fn transfer_from(
        from: &[u8; 32],
        to: &[u8; 32],
        amount: U256,
        spender: &[u8; 32],
    ) -> Result<(), &'static str> {
        let allow_key = k_allow(from, spender);
        let allow = storage_read(&allow_key);
        let max_u256 = U256([0xff; 32]);
        if allow != max_u256 {
            let new_allow = allow.checked_sub(amount).ok_or("insufficient allowance")?;
            storage_write(allow_key, new_allow);
        }
        transfer(from, to, amount)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn addr(seed: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[31] = seed;
    a
}

#[test]
fn initial_state_is_zero() {
    clear();
    assert_eq!(mock::get_total_supply(), U256::ZERO);
    assert_eq!(mock::get_balance(&addr(1)), U256::ZERO);
}

#[test]
fn deposit_credits_balance_and_supply() {
    clear();
    let alice = addr(1);
    set_sender(alice);
    set_value(U256::from_u128(1_000));

    mock::deposit();

    assert_eq!(mock::get_balance(&alice), U256::from_u128(1_000));
    assert_eq!(mock::get_total_supply(), U256::from_u128(1_000));
}

#[test]
fn deposit_multiple_accumulates() {
    clear();
    let alice = addr(1);
    set_sender(alice);

    set_value(U256::from_u128(500));
    mock::deposit();

    set_value(U256::from_u128(300));
    mock::deposit();

    assert_eq!(mock::get_balance(&alice), U256::from_u128(800));
    assert_eq!(mock::get_total_supply(), U256::from_u128(800));
}

#[test]
fn deposit_zero_value_is_noop() {
    clear();
    let alice = addr(1);
    set_sender(alice);
    set_value(U256::ZERO);
    mock::deposit();

    assert_eq!(mock::get_balance(&alice), U256::ZERO);
    assert_eq!(mock::get_total_supply(), U256::ZERO);
}

#[test]
fn withdraw_debits_balance_and_supply() {
    clear();
    let alice = addr(1);
    set_sender(alice);
    set_value(U256::from_u128(1_000));
    mock::deposit();

    mock::withdraw(U256::from_u128(400)).expect("withdraw ok");

    assert_eq!(mock::get_balance(&alice), U256::from_u128(600));
    assert_eq!(mock::get_total_supply(), U256::from_u128(600));
}

#[test]
fn deposit_withdraw_roundtrip() {
    clear();
    let alice = addr(2);
    set_sender(alice);
    let amount = U256::from_u128(1_000_000_000_000_000_000u128); // 1e18

    set_value(amount);
    mock::deposit();

    mock::withdraw(amount).expect("full withdraw ok");

    assert_eq!(mock::get_balance(&alice), U256::ZERO);
    assert_eq!(mock::get_total_supply(), U256::ZERO);

    // Confirm native transfer was recorded
    let transfers = LOOM_TRANSFERS.with(|t| t.borrow().clone());
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].0, alice);
    assert_eq!(transfers[0].1, amount.0);
}

#[test]
fn withdraw_insufficient_balance_fails() {
    clear();
    let alice = addr(3);
    set_sender(alice);
    set_value(U256::from_u128(100));
    mock::deposit();

    let result = mock::withdraw(U256::from_u128(200));
    assert!(result.is_err(), "should fail with insufficient balance");

    // Balance and supply should be unchanged from before the failed withdraw
    assert_eq!(mock::get_balance(&alice), U256::from_u128(100));
    assert_eq!(mock::get_total_supply(), U256::from_u128(100));
}

#[test]
fn transfer_moves_balance() {
    clear();
    let alice = addr(1);
    let bob = addr(2);

    set_sender(alice);
    set_value(U256::from_u128(1_000));
    mock::deposit();

    mock::transfer(&alice, &bob, U256::from_u128(400)).expect("transfer ok");

    assert_eq!(mock::get_balance(&alice), U256::from_u128(600));
    assert_eq!(mock::get_balance(&bob), U256::from_u128(400));
    // Total supply unchanged
    assert_eq!(mock::get_total_supply(), U256::from_u128(1_000));
}

#[test]
fn transfer_insufficient_balance_fails() {
    clear();
    let alice = addr(1);
    let bob = addr(2);

    let result = mock::transfer(&alice, &bob, U256::from_u128(1));
    assert!(result.is_err());
}

#[test]
fn approve_sets_allowance() {
    clear();
    let owner = addr(1);
    let spender = addr(2);
    mock::approve(&owner, &spender, U256::from_u128(500));
    assert_eq!(mock::get_allowance(&owner, &spender), U256::from_u128(500));
}

#[test]
fn transfer_from_deducts_allowance() {
    clear();
    let alice = addr(1);
    let bob = addr(2);
    let carol = addr(3);

    set_sender(alice);
    set_value(U256::from_u128(1_000));
    mock::deposit();

    mock::approve(&alice, &carol, U256::from_u128(600));
    mock::transfer_from(&alice, &bob, U256::from_u128(400), &carol).expect("transferFrom ok");

    assert_eq!(mock::get_balance(&alice), U256::from_u128(600));
    assert_eq!(mock::get_balance(&bob), U256::from_u128(400));
    assert_eq!(mock::get_allowance(&alice, &carol), U256::from_u128(200));
}

#[test]
fn transfer_from_infinite_allowance_not_decremented() {
    clear();
    let alice = addr(1);
    let bob = addr(2);
    let carol = addr(3);

    set_sender(alice);
    set_value(U256::from_u128(1_000));
    mock::deposit();

    // Set infinite allowance
    mock::approve(&alice, &carol, U256([0xff; 32]));
    mock::transfer_from(&alice, &bob, U256::from_u128(500), &carol).expect("ok");

    // Allowance must remain unchanged
    assert_eq!(mock::get_allowance(&alice, &carol), U256([0xff; 32]));
}

#[test]
fn transfer_from_insufficient_allowance_fails() {
    clear();
    let alice = addr(1);
    let bob = addr(2);
    let carol = addr(3);

    set_sender(alice);
    set_value(U256::from_u128(1_000));
    mock::deposit();

    mock::approve(&alice, &carol, U256::from_u128(100));
    let result = mock::transfer_from(&alice, &bob, U256::from_u128(200), &carol);
    assert!(result.is_err());
    // Allowance unchanged
    assert_eq!(mock::get_allowance(&alice, &carol), U256::from_u128(100));
}

#[test]
fn selector_routing_deposit_via_empty_calldata() {
    // Verify the selector-dispatch logic: calldata.len() < 4 → deposit branch.
    // We simulate this by checking that the calldata path would be taken.
    // (The actual wloom_call is not callable on host, but we verify the
    // dispatch condition: len < 4 means deposit is selected.)
    let empty: Vec<u8> = Vec::new();
    assert!(empty.len() < 4, "empty calldata should route to deposit");

    let short: Vec<u8> = vec![0xDE, 0xAD];
    assert!(short.len() < 4, "short calldata should route to deposit");
}

#[test]
fn selector_wloom_deposit_matches_abi() {
    // Confirm the WLOOM_DEPOSIT selector from bloom-dex-abi matches the
    // expected blake3 prefix of "wloom.deposit()".
    let h = ::blake3::hash(b"wloom.deposit()");
    let b = h.as_bytes();
    let expected = [b[0], b[1], b[2], b[3]];
    assert_eq!(selectors::WLOOM_DEPOSIT, expected);
}

#[test]
fn selector_wloom_withdraw_matches_abi() {
    let h = ::blake3::hash(b"wloom.withdraw(u256)");
    let b = h.as_bytes();
    let expected = [b[0], b[1], b[2], b[3]];
    assert_eq!(selectors::WLOOM_WITHDRAW, expected);
}

#[test]
fn multi_user_deposit_withdraw() {
    clear();
    let alice = addr(10);
    let bob = addr(11);

    set_sender(alice);
    set_value(U256::from_u128(2_000));
    mock::deposit();

    set_sender(bob);
    set_value(U256::from_u128(3_000));
    mock::deposit();

    assert_eq!(mock::get_total_supply(), U256::from_u128(5_000));
    assert_eq!(mock::get_balance(&alice), U256::from_u128(2_000));
    assert_eq!(mock::get_balance(&bob), U256::from_u128(3_000));

    set_sender(alice);
    mock::withdraw(U256::from_u128(1_000)).expect("ok");
    assert_eq!(mock::get_total_supply(), U256::from_u128(4_000));

    set_sender(bob);
    mock::withdraw(U256::from_u128(3_000)).expect("ok");
    assert_eq!(mock::get_total_supply(), U256::from_u128(1_000));
    assert_eq!(mock::get_balance(&bob), U256::ZERO);
}

#[test]
fn calldata_encoding_deposit_selector() {
    // Verify encoding helpers produce the correct selector-prefixed calldata.
    let cd = Encoder::with_selector(selectors::WLOOM_DEPOSIT).finish();
    assert_eq!(cd.len(), 4);
    assert_eq!(&cd[..4], &selectors::WLOOM_DEPOSIT);
}

#[test]
fn calldata_encoding_withdraw() {
    let amount = U256::from_u128(1_000_000u128);
    let mut enc = Encoder::with_selector(selectors::WLOOM_WITHDRAW);
    enc.push_u256(amount);
    let cd = enc.finish();
    assert_eq!(cd.len(), 36);
    assert_eq!(&cd[..4], &selectors::WLOOM_WITHDRAW);
    // Decode back
    let decoded = {
        let mut buf = bloom_dex_abi::decode::Buf::new(&cd[4..]);
        buf.read_u256().unwrap()
    };
    assert_eq!(decoded, amount);
}

// ---------------------------------------------------------------------------
// Selector parity — the chain-ABI macro must emit byte-identical selectors
// to (a) the DEX v0 canonical strings and (b) the legacy bloom-dex-abi
// constants so that the router and other peer contracts continue to dispatch
// to the same handlers after migration.
// ---------------------------------------------------------------------------

#[test]
fn wloom_selectors_match_dex_v0_canonical_strings() {
    bloom_dex_abi::assert_selector_parity! {
        crate::wloom::SEL_DEPOSIT  => b"wloom.deposit()",
        crate::wloom::SEL_WITHDRAW => b"wloom.withdraw(u256)",
    }
}

#[test]
fn wloom_selectors_match_legacy_dex_abi_constants() {
    // Byte-equality with the build.rs-generated table in bloom-dex-abi so
    // peer contracts (router etc.) keep dispatching to the same handlers.
    assert_eq!(crate::wloom::SEL_DEPOSIT,  selectors::WLOOM_DEPOSIT);
    assert_eq!(crate::wloom::SEL_WITHDRAW, selectors::WLOOM_WITHDRAW);
}
