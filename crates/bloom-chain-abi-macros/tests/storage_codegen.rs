//! Storage-codegen smoke test: the macro emits compiling `abi::storage`
//! accessors with the correct shape.
//!
//! We don't actually invoke the storage getters/setters at runtime — they
//! would call `bloom_petal_sdk::state::read` which panics on the host. We
//! verify the module exists and exposes the expected items by taking
//! function-pointer references.

use bloom_chain_abi::contract;

contract! {
    contract Foo {
        storage {
            owner:       Address;
            count:       u64;
            balance:     u128;
            flag:        bool;
            total:       U256;
            tag_override: u64 @ "custom.tag";
            balances:    Mapping<Address, U256> @ "erc20.balance:";
            allowances:  Mapping<(Address, Address), U256> @ "erc20.allowance:";
        }
    }
}

struct FooStub;
impl foo::Handler for FooStub {}

#[test]
fn storage_module_emits_expected_accessors() {
    // Scalar getters/setters: take fn-pointer references so the compiler
    // forces them to exist with the documented signatures.
    let _: fn() -> [u8; 32] = foo::abi::storage::owner;
    let _: fn(&[u8; 32]) = foo::abi::storage::set_owner;
    let _: fn() -> u64 = foo::abi::storage::count;
    let _: fn(u64) = foo::abi::storage::set_count;
    let _: fn() -> u128 = foo::abi::storage::balance;
    let _: fn(u128) = foo::abi::storage::set_balance;
    let _: fn() -> bool = foo::abi::storage::flag;
    let _: fn(bool) = foo::abi::storage::set_flag;
    let _: fn() -> bloom_chain_abi::U256 = foo::abi::storage::total;
    let _: fn(&bloom_chain_abi::U256) = foo::abi::storage::set_total;
    let _: fn() -> u64 = foo::abi::storage::tag_override;
    let _: fn(u64) = foo::abi::storage::set_tag_override;

    // Mapping getters/setters.
    let _: fn(&[u8; 32]) -> bloom_chain_abi::U256 = foo::abi::storage::balances::get;
    let _: fn(&[u8; 32], &bloom_chain_abi::U256) = foo::abi::storage::balances::set;
    let _: fn((&[u8; 32], &[u8; 32])) -> bloom_chain_abi::U256 =
        foo::abi::storage::allowances::get;
    let _: fn((&[u8; 32], &[u8; 32]), &bloom_chain_abi::U256) =
        foo::abi::storage::allowances::set;
}

#[allow(dead_code)]
fn _ensure_stub_compiles() -> FooStub {
    FooStub
}
