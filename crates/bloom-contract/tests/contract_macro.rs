#![allow(dead_code)]
//! Integration tests for the `#[bloom::contract]` attribute macro.
//!
//! Host-side tests can't actually exercise `__dispatch_call` because the
//! dispatcher calls `petal.return_data` / `petal.revert` host imports that
//! panic on non-wasm targets. What we *can* verify is the surface the macro
//! emits:
//!
//! - the `__bloom` submodule exists and exposes `DOMAIN`, `MODULE_NAME`,
//!   `INTERFACES`, `SELECTORS`, `SELECTOR_COUNT`
//! - every `pub fn` handler (minus `#[internal]`) gets a selector const +
//!   `SelectorEntry`
//! - selectors are the leading 4 bytes of
//!   `blake3("<domain>.<method>(<arg_types>)")`
//! - `#[view]` / `#[payable]` / `#[nonreentrant]` markers flow through into
//!   the descriptor's mutability + nonreentrant flags
//! - the wasm export shims (`__bloom_init_<mod>`, `__bloom_call_<mod>`) are
//!   reachable by their pub item names — we can take a function pointer to
//!   them without invoking them
//!
//! The wasm-side smoke tests for an end-to-end dispatch live in the runtime
//! integration crate once a contract example has been migrated.

use bloom_contract::dispatch::{Mutability, SelectorEntry};
use bloom_contract::interface::ContractInterface;
use bloom_contract::prelude::*;

#[error(domain = "demo")]
#[derive(Debug, PartialEq, Eq)]
pub enum DemoError {
    BadInput,
    Frozen(u64),
}

#[contract(domain = "demo")]
mod demo {
    use super::DemoError;
    use bloom_contract::prelude::*;

    #[storage]
    pub struct State {
        pub counter: StorageValue<U256>,
    }

    #[init]
    pub fn init(_ctx: &mut Context, _seed: U256) -> Result<(), DemoError> {
        Ok(())
    }

    #[view]
    pub fn total(_ctx: &Context) -> Result<U256, DemoError> {
        Ok(U256::from_u128(0))
    }

    pub fn bump(_ctx: &mut Context, amount: U256) -> Result<U256, DemoError> {
        Ok(amount)
    }

    #[payable]
    pub fn fund(_ctx: &mut Context) -> Result<(), DemoError> {
        Ok(())
    }

    #[nonreentrant]
    pub fn withdraw(_ctx: &mut Context, to: Address) -> Result<bool, DemoError> {
        let _ = to;
        Ok(true)
    }

    #[internal]
    pub fn helper(_ctx: &Context) -> Result<(), DemoError> {
        Ok(())
    }
}

// -- Module metadata ---------------------------------------------------------

#[test]
fn module_metadata_is_present() {
    assert_eq!(demo::__bloom::DOMAIN, "demo");
    assert_eq!(demo::__bloom::MODULE_NAME, "demo");
    assert!(demo::__bloom::INTERFACES.is_empty());
}

#[test]
fn selector_count_excludes_init_and_internal() {
    // Handlers: total, bump, fund, withdraw.
    // Init is a separate entry point; #[internal] helpers are not exposed.
    assert_eq!(demo::__bloom::SELECTORS.len(), 4);
    assert_eq!(demo::__bloom::SELECTOR_COUNT, 4);
}

// -- Selector derivation -----------------------------------------------------

fn expected_selector(sig: &str) -> [u8; 4] {
    let h = blake3::hash(sig.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&h.as_bytes()[..4]);
    out
}

fn entry(name: &str) -> &'static SelectorEntry {
    demo::__bloom::SELECTORS
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no selector entry for {name}"))
}

#[test]
fn total_selector_matches_canonical_signature() {
    let e = entry("total");
    assert_eq!(e.signature, "demo.total()");
    assert_eq!(e.selector, expected_selector(e.signature));
    assert_eq!(e.mutability, Mutability::View);
    assert!(!e.nonreentrant);
}

#[test]
fn bump_selector_includes_argument_types() {
    let e = entry("bump");
    assert_eq!(e.signature, "demo.bump(u256)");
    assert_eq!(e.selector, expected_selector(e.signature));
    assert_eq!(e.mutability, Mutability::Mutating);
}

#[test]
fn payable_flag_flows_through_to_mutability() {
    let e = entry("fund");
    assert_eq!(e.signature, "demo.fund()");
    assert_eq!(e.mutability, Mutability::Payable);
    assert!(!e.nonreentrant);
}

#[test]
fn nonreentrant_flag_is_recorded() {
    let e = entry("withdraw");
    assert_eq!(e.signature, "demo.withdraw(address)");
    assert!(e.nonreentrant);
    assert_eq!(e.mutability, Mutability::Mutating);
}

#[test]
fn selectors_are_distinct_across_handlers() {
    let sels: alloc::vec::Vec<[u8; 4]> =
        demo::__bloom::SELECTORS.iter().map(|e| e.selector).collect();
    for i in 0..sels.len() {
        for j in (i + 1)..sels.len() {
            assert_ne!(sels[i], sels[j], "selectors collide at {i}/{j}");
        }
    }
}

#[test]
fn per_handler_selector_consts_match_table() {
    assert_eq!(demo::__bloom::SEL_TOTAL, entry("total").selector);
    assert_eq!(demo::__bloom::SEL_BUMP, entry("bump").selector);
    assert_eq!(demo::__bloom::SEL_FUND, entry("fund").selector);
    assert_eq!(demo::__bloom::SEL_WITHDRAW, entry("withdraw").selector);
}

#[test]
fn internal_handler_does_not_appear_in_selector_table() {
    assert!(
        !demo::__bloom::SELECTORS.iter().any(|e| e.name == "helper"),
        "#[internal] handlers must be excluded from the dispatch table"
    );
}

// -- Export symbols ----------------------------------------------------------

#[test]
fn wasm_export_symbols_exist() {
    // The macro emits top-level `pub extern "C" fn __bloom_init_<mod>()` and
    // `__bloom_call_<mod>()`. Taking a function pointer is enough to confirm
    // they were generated — we don't call them (they would invoke host
    // imports that panic on non-wasm targets).
    let _init: extern "C" fn() = __bloom_init_demo;
    let _call: extern "C" fn() = __bloom_call_demo;
}

// ---------------------------------------------------------------------------
// Interface integration — a contract that declares `interfaces(...)` folds
// every listed interface's METHODS into a runtime fallthrough table so
// callers can reach handlers through either the contract's own domain or
// any declared interface domain. The dispatcher's runtime behaviour is
// covered by the wasm integration suite — here we just verify the metadata
// the macro emits is plumbed correctly.
// ---------------------------------------------------------------------------

#[interface(domain = "minttoken")]
pub trait Mintable {
    fn mint(to: Address, amount: U256) -> Result<bool>;
    fn burn(amount: U256) -> Result<bool>;
}

#[contract(domain = "vault", interfaces(Mintable))]
mod vault {
    use super::{DemoError, Mintable};
    use bloom_contract::prelude::*;

    #[storage]
    pub struct State {
        pub _placeholder: StorageValue<U256>,
    }

    #[init]
    pub fn init(_ctx: &mut Context) -> Result<(), DemoError> {
        Ok(())
    }

    pub fn mint(_ctx: &mut Context, _to: Address, _amount: U256) -> Result<bool, DemoError> {
        Ok(true)
    }

    pub fn burn(_ctx: &mut Context, _amount: U256) -> Result<bool, DemoError> {
        Ok(true)
    }
}

#[test]
fn declared_interfaces_appear_in_metadata_table() {
    assert_eq!(vault::__bloom::INTERFACES, &["Mintable"]);
    assert_eq!(vault::__bloom::INTERFACE_METHODS.len(), 1);

    let methods = vault::__bloom::INTERFACE_METHODS[0];
    assert_eq!(methods.len(), 2);
    assert_eq!(methods[0].name, "mint");
    assert_eq!(methods[1].name, "burn");
    assert_eq!(methods, <Mintable as ContractInterface>::METHODS);
}

#[test]
fn vault_handlers_remain_addressable_under_native_selectors() {
    // The contract's own selectors are derived from `vault.method(types)`,
    // independent of any interface aliasing — verified here so a regression
    // that folds the interface domain into the primary table would fail.
    let mint = vault::__bloom::SELECTORS.iter().find(|e| e.name == "mint").unwrap();
    assert_eq!(mint.signature, "vault.mint(address,u256)");
    let h = blake3::hash(mint.signature.as_bytes());
    assert_eq!(mint.selector, h.as_bytes()[..4]);
}

extern crate alloc;
