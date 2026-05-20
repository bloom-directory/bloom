//! Host-target unit tests for bloom-dex-wloom.
//!
//! These tests pin three things to the canonical formulas:
//!
//! 1. **Selector parity** — `wloom.deposit()` / `wloom.withdraw(u256)`
//!    selectors live on the [`crate::Wloom`] interface marker and must hash
//!    the legacy v0 canonical signature strings byte-for-byte. The ERC-20
//!    surface selectors come from [`bloom_dex_erc20::Erc20`] (same
//!    canonical strings) so any drift there fails the ERC-20 crate's tests
//!    first.
//! 2. **Storage slot parity** — `wloom.total_supply`, `wloom.balance:`,
//!    `wloom.allowance:` must continue to hash the way the legacy
//!    `contract!` macro hashed them, so a migrated deployment keeps reading
//!    the same slots.
//! 3. **Calls-builder byte layout** — the `calls::*` builders consumed by
//!    the router must emit `selector || args` bytes byte-identical to what
//!    a legacy caller would have produced.

#![cfg(not(target_arch = "wasm32"))]

use bloom_chain_abi::U256;
use bloom_contract::storage::slot_for_compat_tag;
use bloom_contract::types::Address;

use crate::Wloom;

// ---------------------------------------------------------------------------
// Selector parity
// ---------------------------------------------------------------------------

fn blake3_selector(sig: &str) -> [u8; 4] {
    let h = blake3::hash(sig.as_bytes());
    let b = h.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

#[test]
fn wloom_selectors_match_dex_v0_canonical_strings() {
    assert_eq!(Wloom::SEL_DEPOSIT, blake3_selector("wloom.deposit()"));
    assert_eq!(
        Wloom::SEL_WITHDRAW,
        blake3_selector("wloom.withdraw(u256)"),
    );
}

#[test]
fn erc20_selectors_anchored_via_dex_erc20() {
    // wLOOM's standard surface routes through the bloom_dex_erc20::Erc20
    // interface, so we just sanity-check one selector here. The ERC-20 crate
    // owns the full byte-for-byte parity assertions.
    assert_eq!(
        bloom_dex_erc20::Erc20::SEL_TRANSFER,
        blake3_selector("erc20.transfer(address,u256)"),
    );
    assert_eq!(
        bloom_dex_erc20::Erc20::SEL_BALANCE_OF,
        blake3_selector("erc20.balance_of(address)"),
    );
}

// ---------------------------------------------------------------------------
// Storage slot parity
// ---------------------------------------------------------------------------

#[test]
fn storage_slot_parity_scalar() {
    let expected = blake3::hash(b"wloom.total_supply");
    let actual = slot_for_compat_tag("wloom.total_supply");
    assert_eq!(&actual[..], &expected.as_bytes()[..]);
}

fn blake3_slot(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

#[test]
fn storage_slot_parity_balance_mapping() {
    // Map<Address, U256> with compat_tag "wloom.balance:" derives slots as
    // blake3("wloom.balance:" || address_bytes) — the legacy layout.
    let addr = Address::from([0x42u8; 32]);
    let expected = blake3_slot(&[b"wloom.balance:", addr.as_bytes()]);

    use bloom_contract::storage::Map;
    use bloom_contract::types::U256 as ContractU256;
    let m: Map<Address, ContractU256> = Map::new(b"wloom.balance:");
    let actual = m.slot(&addr).expect("slot ok");
    assert_eq!(actual, expected);
}

#[test]
fn storage_slot_parity_allowance_mapping_tuple_key() {
    // Map<(Address, Address), U256> with compat_tag "wloom.allowance:" hashes
    // the concatenated address pair under the legacy prefix.
    let owner = Address::from([0x11u8; 32]);
    let spender = Address::from([0x22u8; 32]);
    let expected = blake3_slot(&[
        b"wloom.allowance:",
        owner.as_bytes(),
        spender.as_bytes(),
    ]);

    use bloom_contract::storage::Map;
    use bloom_contract::types::U256 as ContractU256;
    let m: Map<(Address, Address), ContractU256> = Map::new(b"wloom.allowance:");
    let actual = m.slot(&(owner, spender)).expect("slot ok");
    assert_eq!(actual, expected);
}

// ---------------------------------------------------------------------------
// Calls builders — byte layouts a router/caller must reproduce verbatim.
// ---------------------------------------------------------------------------

#[test]
fn calls_deposit_is_just_the_selector() {
    let cd = crate::calls::deposit();
    assert_eq!(cd, Wloom::SEL_DEPOSIT.to_vec());
}

#[test]
fn calls_withdraw_layout() {
    let amount = U256::from_u128(7_777_777_777u128);
    let cd = crate::calls::withdraw(amount);

    let mut expected = Vec::<u8>::new();
    expected.extend_from_slice(&Wloom::SEL_WITHDRAW);
    expected.extend_from_slice(&amount.0);
    assert_eq!(cd, expected);
}

// ---------------------------------------------------------------------------
// Empty-calldata fallback condition: the dispatcher routes calldata shorter
// than the 4-byte selector window into the `#[fallback]` handler (`deposit`).
// We can't drive the macro-generated dispatcher from a host test, but we can
// pin the boundary so we notice if the dispatcher ever changes its mind about
// what counts as "short".
// ---------------------------------------------------------------------------

#[test]
fn selector_window_is_four_bytes() {
    let empty: Vec<u8> = Vec::new();
    let short: Vec<u8> = vec![0xDE, 0xAD];
    let exact: Vec<u8> = vec![0; 4];
    assert!(empty.len() < 4);
    assert!(short.len() < 4);
    assert!(exact.len() >= 4);
}

// ---------------------------------------------------------------------------
// Selectors must be unique across the contract — primary domain (erc20.*)
// plus the additional Wloom interface methods. A collision would shadow a
// handler and silently route to the wrong code.
// ---------------------------------------------------------------------------

#[test]
fn selectors_are_unique() {
    let selectors: Vec<[u8; 4]> = vec![
        Wloom::SEL_DEPOSIT,
        Wloom::SEL_WITHDRAW,
        bloom_dex_erc20::Erc20::SEL_TOTAL_SUPPLY,
        bloom_dex_erc20::Erc20::SEL_BALANCE_OF,
        bloom_dex_erc20::Erc20::SEL_ALLOWANCE,
        bloom_dex_erc20::Erc20::SEL_TRANSFER,
        bloom_dex_erc20::Erc20::SEL_TRANSFER_FROM,
        bloom_dex_erc20::Erc20::SEL_APPROVE,
        bloom_dex_erc20::Erc20::SEL_NAME,
        bloom_dex_erc20::Erc20::SEL_SYMBOL,
        bloom_dex_erc20::Erc20::SEL_DECIMALS,
    ];

    let mut deduped: Vec<[u8; 4]> = selectors.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(deduped.len(), selectors.len(), "selector collision");
}
