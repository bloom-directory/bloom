#![allow(dead_code)]
#![allow(deprecated)]
//! Integration tests for the `#[bloom::interface]` attribute macro.
//!
//! We can't run `ContractRef::method(ctx, ...)` host-side — `ctx.raw_call`
//! eventually hits `petal.call` which panics on non-wasm targets. What we
//! *can* verify:
//!
//! - The trait gets `ContractInterface` with the right `ABI_DOMAIN` and a
//!   `METHODS` slice whose entries match `blake3("domain.method(types)")`
//!   in source order.
//! - Per-method `SEL_<NAME>: [u8; 4]` constants are emitted on the trait.
//! - The `ContractRef<Trait>` inherent impl is reachable — the typed call
//!   methods compile and are bound to the right `&mut Context` signature.
//!
//! The behavioural side (encode → call → decode) lands in the wasm
//! integration suite once a contract example consumes one of these traits.

use bloom_contract::interface::{ContractInterface, ContractRef, InterfaceMethod};
use bloom_contract::prelude::*;

#[interface(domain = "erc20")]
pub trait Erc20 {
    fn balance_of(owner: Address) -> Result<U256>;
    fn total_supply() -> Result<U256>;
    fn transfer(to: Address, amount: U256) -> Result<bool>;
    fn approve(spender: Address, amount: U256) -> Result<bool>;
}

fn expected_selector(sig: &str) -> [u8; 4] {
    let h = blake3::hash(sig.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&h.as_bytes()[..4]);
    out
}

#[test]
fn abi_domain_matches_attribute_argument() {
    assert_eq!(<Erc20 as ContractInterface>::ABI_DOMAIN, "erc20");
}

#[test]
fn methods_slice_has_one_entry_per_trait_method() {
    let m: &[InterfaceMethod] = <Erc20 as ContractInterface>::METHODS;
    assert_eq!(m.len(), 4);
    assert_eq!(m[0].name, "balance_of");
    assert_eq!(m[1].name, "total_supply");
    assert_eq!(m[2].name, "transfer");
    assert_eq!(m[3].name, "approve");
}

#[test]
fn signatures_are_lowercase_dotted_domain_method_types() {
    let m = <Erc20 as ContractInterface>::METHODS;
    assert_eq!(m[0].signature, "erc20.balance_of(address)");
    assert_eq!(m[1].signature, "erc20.total_supply()");
    assert_eq!(m[2].signature, "erc20.transfer(address,u256)");
    assert_eq!(m[3].signature, "erc20.approve(address,u256)");
}

#[test]
fn selectors_match_blake3_of_signature() {
    let m = <Erc20 as ContractInterface>::METHODS;
    for entry in m {
        assert_eq!(entry.selector, expected_selector(entry.signature));
    }
}

#[test]
fn per_method_const_matches_descriptor_table() {
    assert_eq!(Erc20::SEL_BALANCE_OF, expected_selector("erc20.balance_of(address)"));
    assert_eq!(Erc20::SEL_TOTAL_SUPPLY, expected_selector("erc20.total_supply()"));
    assert_eq!(Erc20::SEL_TRANSFER, expected_selector("erc20.transfer(address,u256)"));
    assert_eq!(Erc20::SEL_APPROVE, expected_selector("erc20.approve(address,u256)"));
}

#[test]
fn selectors_are_all_distinct() {
    let m = <Erc20 as ContractInterface>::METHODS;
    for i in 0..m.len() {
        for j in (i + 1)..m.len() {
            assert_ne!(m[i].selector, m[j].selector);
        }
    }
}

#[test]
fn contract_ref_constructs_and_exposes_address() {
    let addr = Address::from([7u8; 32]);
    let r: ContractRef<Erc20> = ContractRef::new(addr);
    assert_eq!(r.address(), &addr);
}

// Compile-time check: the typed methods exist on `ContractRef<Erc20>` via
// the generated `Erc20Calls` extension trait with the expected signatures.
// Taking a function pointer is enough — calling them would invoke
// `petal.call`, which panics off-wasm.
#[test]
fn typed_call_methods_are_implemented_via_calls_trait() {
    let _balance_of: fn(
        &ContractRef<Erc20>,
        &mut Context,
        Address,
    ) -> Result<U256> = <ContractRef<Erc20> as Erc20Calls>::balance_of;

    let _transfer: fn(
        &ContractRef<Erc20>,
        &mut Context,
        Address,
        U256,
    ) -> Result<bool> = <ContractRef<Erc20> as Erc20Calls>::transfer;

    let _total_supply: fn(
        &ContractRef<Erc20>,
        &mut Context,
    ) -> Result<U256> = <ContractRef<Erc20> as Erc20Calls>::total_supply;
}
