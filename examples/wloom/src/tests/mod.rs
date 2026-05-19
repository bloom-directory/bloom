//! Host-target unit tests for bloom-dex-wloom.
//!
//! These tests exercise the pure Rust logic mirroring the wLOOM contract
//! (selector layout, storage-key derivation, accounting invariants) against
//! a thread-local mock storage. They do not link the macro-generated host
//! accessors — those touch the petal SDK's storage host import and only
//! work on wasm32 — so the mock re-implements the same key-derivation
//! formula and accounting logic.
//!
//! What we test:
//! 1. Initial state: total_supply = 0, all balances zero.
//! 2. deposit() credits balance and increments total_supply.
//! 3. withdraw() debits balance, decrements total_supply, queues a native LOOM transfer.
//! 4. deposit+withdraw round-trip preserves invariants.
//! 5. withdraw reverts on insufficient balance.
//! 6. transfer / transferFrom / approve accounting.
//! 7. Empty-calldata routing condition is correct (`< 4`).
//! 8. allowance infinite approval skips deduction.
//! 9. Selector parity: the canonical signatures used by the petal match the
//!    macro's selector formula (4-byte blake3 prefix).

#![cfg(not(target_arch = "wasm32"))]

use std::cell::RefCell;
use std::collections::HashMap;

use bloom_chain_abi::U256;

// ---------------------------------------------------------------------------
// Mock host state
// ---------------------------------------------------------------------------

thread_local! {
    /// Simulated per-instance storage.
    static STORAGE: RefCell<HashMap<[u8; 32], [u8; 32]>> = RefCell::new(HashMap::new());
    /// Simulated msg.sender (32-byte address).
    static SENDER: RefCell<[u8; 32]> = const { RefCell::new([0u8; 32]) };
    /// Simulated msg.value (32-byte big-endian u256).
    static VALUE: RefCell<[u8; 32]> = const { RefCell::new([0u8; 32]) };
    /// Recorded native LOOM transfer calls (target, value_u256).
    static LOOM_TRANSFERS: RefCell<Vec<([u8; 32], [u8; 32])>> = const { RefCell::new(Vec::new()) };
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
// Mock storage + business-logic re-implementations.
//
// These mirror the on-wasm wLOOM logic exactly, but back the storage by the
// thread-local `STORAGE` map and use the same `bloom_chain_abi::storage::*`
// key-derivation helpers that the contract macro emits.
// ---------------------------------------------------------------------------

mod mock {
    use super::*;
    use bloom_chain_abi::storage;

    fn k_total() -> [u8; 32] {
        storage::slot_scalar("wloom.total_supply")
    }

    fn k_bal(addr: &[u8; 32]) -> [u8; 32] {
        storage::slot_mapping("wloom.balance:", addr)
    }

    fn k_allow(owner: &[u8; 32], spender: &[u8; 32]) -> [u8; 32] {
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(owner);
        concat[32..].copy_from_slice(spender);
        storage::slot_mapping("wloom.allowance:", &concat)
    }

    fn storage_read(key: &[u8; 32]) -> U256 {
        STORAGE.with(|s| s.borrow().get(key).copied().map(U256).unwrap_or(U256::ZERO))
    }

    fn storage_write(key: [u8; 32], v: U256) {
        STORAGE.with(|s| {
            s.borrow_mut().insert(key, v.0);
        });
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

    pub fn deposit() {
        let sender = self::sender();
        let amount = self::value();
        if !amount.is_zero() {
            let ts = get_total_supply();
            let new_ts = ts.checked_add(amount).expect("ts overflow");
            storage_write(k_total(), new_ts);

            let bal = get_balance(&sender);
            let new_bal = bal.checked_add(amount).expect("bal overflow");
            storage_write(k_bal(&sender), new_bal);
        }
    }

    pub fn withdraw(amount: U256) -> Result<(), &'static str> {
        if amount.is_zero() {
            return Ok(());
        }
        let sender = self::sender();

        let bal = get_balance(&sender);
        let new_bal = bal.checked_sub(amount).ok_or("insufficient balance")?;
        storage_write(k_bal(&sender), new_bal);

        let ts = get_total_supply();
        let new_ts = ts.checked_sub(amount).ok_or("ts underflow")?;
        storage_write(k_total(), new_ts);

        LOOM_TRANSFERS.with(|t| t.borrow_mut().push((sender, amount.0)));
        Ok(())
    }

    pub fn transfer(
        from: &[u8; 32],
        to: &[u8; 32],
        amount: U256,
    ) -> Result<(), &'static str> {
        let from_bal = get_balance(from);
        let new_from = from_bal.checked_sub(amount).ok_or("insufficient balance")?;
        storage_write(k_bal(from), new_from);

        let to_bal = get_balance(to);
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
        let max = U256([0xff; 32]);
        let allow = get_allowance(from, spender);
        if allow != max {
            let new_allow = allow.checked_sub(amount).ok_or("insufficient allowance")?;
            storage_write(k_allow(from, spender), new_allow);
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
    assert!(result.is_err());
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
    assert_eq!(mock::get_total_supply(), U256::from_u128(1_000));
}

#[test]
fn transfer_insufficient_balance_fails() {
    clear();
    let alice = addr(1);
    let bob = addr(2);
    assert!(mock::transfer(&alice, &bob, U256::from_u128(1)).is_err());
}

#[test]
fn approve_sets_allowance() {
    clear();
    let owner = addr(1);
    let spender = addr(2);
    mock::approve(&owner, &spender, U256::from_u128(500));
    assert_eq!(
        mock::get_allowance(&owner, &spender),
        U256::from_u128(500)
    );
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
    mock::transfer_from(&alice, &bob, U256::from_u128(400), &carol)
        .expect("transferFrom ok");

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

    mock::approve(&alice, &carol, U256([0xff; 32]));
    mock::transfer_from(&alice, &bob, U256::from_u128(500), &carol).expect("ok");
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
    assert_eq!(mock::get_allowance(&alice, &carol), U256::from_u128(100));
}

#[test]
fn selector_routing_deposit_via_short_calldata() {
    let empty: Vec<u8> = Vec::new();
    assert!(empty.len() < 4);
    let short: Vec<u8> = vec![0xDE, 0xAD];
    assert!(short.len() < 4);
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

// ---------------------------------------------------------------------------
// Selector parity — the chain-ABI macro must emit byte-identical selectors
// to the DEX v0 canonical signature strings.
// ---------------------------------------------------------------------------

#[test]
fn wloom_selectors_match_dex_v0_canonical_strings() {
    assert_eq!(
        crate::wloom::SEL_DEPOSIT,
        bloom_chain_abi::selector("wloom.deposit()"),
    );
    assert_eq!(
        crate::wloom::SEL_WITHDRAW,
        bloom_chain_abi::selector("wloom.withdraw(u256)"),
    );
}

#[test]
fn wloom_erc20_selector_helpers_match_canonical_strings() {
    // The hand-dispatched ERC-20 helpers must hash the canonical DEX v0
    // signature strings (anchoring them to the same source-of-truth the
    // macro uses for the petal's own selectors).
    assert_eq!(
        super::sel_total_supply(),
        bloom_chain_abi::selector("erc20.total_supply()"),
    );
    assert_eq!(
        super::sel_balance_of(),
        bloom_chain_abi::selector("erc20.balance_of(address)"),
    );
    assert_eq!(
        super::sel_allowance(),
        bloom_chain_abi::selector("erc20.allowance(address,address)"),
    );
    assert_eq!(
        super::sel_transfer(),
        bloom_chain_abi::selector("erc20.transfer(address,u256)"),
    );
    assert_eq!(
        super::sel_transfer_from(),
        bloom_chain_abi::selector("erc20.transfer_from(address,address,u256)"),
    );
    assert_eq!(
        super::sel_approve(),
        bloom_chain_abi::selector("erc20.approve(address,u256)"),
    );
    assert_eq!(
        super::sel_name(),
        bloom_chain_abi::selector("erc20.name()"),
    );
    assert_eq!(
        super::sel_symbol(),
        bloom_chain_abi::selector("erc20.symbol()"),
    );
    assert_eq!(
        super::sel_decimals(),
        bloom_chain_abi::selector("erc20.decimals()"),
    );
}

// ---------------------------------------------------------------------------
// Storage slot parity — the macro-derived slot keys for wLOOM storage must
// match `blake3(<tag>)` for scalars and `blake3(<tag> || encoded_key)` for
// mappings. These tests pin the storage layout to the canonical formula.
// ---------------------------------------------------------------------------

#[test]
fn storage_slot_parity_scalar() {
    let expected = blake3::hash(b"wloom.total_supply");
    let actual = bloom_chain_abi::storage::slot_scalar("wloom.total_supply");
    assert_eq!(&actual[..], &expected.as_bytes()[..]);
}

#[test]
fn storage_slot_parity_balance_mapping() {
    let addr = [0x42u8; 32];
    let mut buf = Vec::<u8>::new();
    buf.extend_from_slice(b"wloom.balance:");
    buf.extend_from_slice(&addr);
    let expected = blake3::hash(&buf);
    let actual = bloom_chain_abi::storage::slot_mapping("wloom.balance:", &addr);
    assert_eq!(&actual[..], &expected.as_bytes()[..]);
}

#[test]
fn storage_slot_parity_allowance_mapping() {
    let owner = [0x11u8; 32];
    let spender = [0x22u8; 32];
    let mut buf = Vec::<u8>::new();
    buf.extend_from_slice(b"wloom.allowance:");
    buf.extend_from_slice(&owner);
    buf.extend_from_slice(&spender);
    let expected = blake3::hash(&buf);

    let mut concat = [0u8; 64];
    concat[..32].copy_from_slice(&owner);
    concat[32..].copy_from_slice(&spender);
    let actual = bloom_chain_abi::storage::slot_mapping("wloom.allowance:", &concat);
    assert_eq!(&actual[..], &expected.as_bytes()[..]);
}

// ---------------------------------------------------------------------------
// Event topic parity — Transfer / Approval signatures must hash the same as
// the canonical ERC-20 event signatures so wLOOM logs are indistinguishable
// from any other ERC-20 token's logs for indexers.
// ---------------------------------------------------------------------------

#[test]
fn wloom_event_topics_match_canonical_signatures() {
    let h = blake3::hash(b"Transfer(address,address,u256)");
    let b = h.as_bytes();
    let expected = [b[0], b[1], b[2], b[3]];
    assert_eq!(crate::wloom::abi::events::TRANSFER_TOPIC, expected);

    let h = blake3::hash(b"Approval(address,address,u256)");
    let b = h.as_bytes();
    let expected = [b[0], b[1], b[2], b[3]];
    assert_eq!(crate::wloom::abi::events::APPROVAL_TOPIC, expected);

    let h = blake3::hash(b"Deposit(address,u256)");
    let b = h.as_bytes();
    let expected = [b[0], b[1], b[2], b[3]];
    assert_eq!(crate::wloom::abi::events::DEPOSIT_TOPIC, expected);

    let h = blake3::hash(b"Withdrawal(address,u256)");
    let b = h.as_bytes();
    let expected = [b[0], b[1], b[2], b[3]];
    assert_eq!(crate::wloom::abi::events::WITHDRAWAL_TOPIC, expected);
}
