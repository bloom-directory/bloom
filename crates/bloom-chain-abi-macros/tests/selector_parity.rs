//! Selector parity self-test for the `contract!` macro.
//!
//! Compile-time: the macro emits a `(SIG_X, SEL_X)` pair per declared method.
//! This test runs at execution time and asserts `SEL_X == blake3(SIG_X)[..4]`
//! for every emitted constant on a representative contract — the macro is
//! internally consistent.
//!
//! Run-time fuzz (proptest): for any random snake-case method name + arg type
//! list, the canonical signature string follows the documented recipe and
//! `bloom_chain_abi::selector(s) == blake3(s)[..4]`. This proves the shared
//! recipe is correct across ≥1000 generated cases, matching what the macro
//! invokes at expand time.

use bloom_chain_abi::contract;
use proptest::prelude::*;

contract! {
    contract Fixture {
        init(creator: Address);

        fn ping() -> u64;
        fn echo_addr(a: Address) -> Address;
        fn sum(a: U256, b: U256) -> U256;
        fn flag(b: bool);
        fn path(p: Vec<Address>) -> u64;
        fn forward(target: Address, inner: bytes) -> u64;
        fn many(a: Address, b: u64, c: u128, d: bool, e: U256);

        #[internal]
        fn _bump(by: u64) -> u64;
    }
}

// Stub Handler so dispatch is callable (selectors test doesn't need it,
// but the trait must exist).
struct FixtureStub;
impl fixture::Handler for FixtureStub {
    fn ping(&mut self) -> Result<u64, &'static str> {
        Ok(0)
    }
    fn echo_addr(&mut self, a: [u8; 32]) -> Result<[u8; 32], &'static str> {
        Ok(a)
    }
    fn sum(
        &mut self,
        a: bloom_chain_abi::U256,
        b: bloom_chain_abi::U256,
    ) -> Result<bloom_chain_abi::U256, &'static str> {
        a.checked_add(b).ok_or("ov")
    }
    fn flag(&mut self, _b: bool) -> Result<(), &'static str> {
        Ok(())
    }
    fn path(&mut self, p: Vec<[u8; 32]>) -> Result<u64, &'static str> {
        Ok(p.len() as u64)
    }
    fn forward(&mut self, _t: [u8; 32], inner: Vec<u8>) -> Result<u64, &'static str> {
        Ok(inner.len() as u64)
    }
    fn many(
        &mut self,
        _a: [u8; 32],
        _b: u64,
        _c: u128,
        _d: bool,
        _e: bloom_chain_abi::U256,
    ) -> Result<(), &'static str> {
        Ok(())
    }
    fn _bump(&mut self, by: u64) -> Result<u64, &'static str> {
        Ok(by)
    }
    fn reentrancy_addr(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

#[test]
fn every_emitted_selector_matches_blake3_of_sig() {
    let pairs: &[(&[u8; 4], &str)] = &[
        (&fixture::SEL_PING, fixture::SIG_PING),
        (&fixture::SEL_ECHO_ADDR, fixture::SIG_ECHO_ADDR),
        (&fixture::SEL_SUM, fixture::SIG_SUM),
        (&fixture::SEL_FLAG, fixture::SIG_FLAG),
        (&fixture::SEL_PATH, fixture::SIG_PATH),
        (&fixture::SEL_FORWARD, fixture::SIG_FORWARD),
        (&fixture::SEL_MANY, fixture::SIG_MANY),
        (&fixture::SEL__BUMP, fixture::SIG__BUMP),
    ];
    for (sel, sig) in pairs {
        let full = blake3::hash(sig.as_bytes());
        assert_eq!(
            &sel[..],
            &full.as_bytes()[..4],
            "selector for `{sig}` doesn't match blake3 prefix",
        );
    }
}

#[test]
fn canonical_sig_strings_are_correct() {
    assert_eq!(fixture::SIG_PING, "fixture.ping()");
    assert_eq!(fixture::SIG_ECHO_ADDR, "fixture.echo_addr(address)");
    assert_eq!(fixture::SIG_SUM, "fixture.sum(u256,u256)");
    assert_eq!(fixture::SIG_FLAG, "fixture.flag(bool)");
    assert_eq!(fixture::SIG_PATH, "fixture.path(Vec<Address>)");
    assert_eq!(fixture::SIG_FORWARD, "fixture.forward(address,bytes)");
    assert_eq!(
        fixture::SIG_MANY,
        "fixture.many(address,u64,u128,bool,u256)",
    );
    assert_eq!(fixture::SIG__BUMP, "fixture._bump(u64)");
}

// ---- proptest fuzz: ≥1000 random method-sig strings ----------------------

fn arb_snake_ident() -> impl Strategy<Value = String> {
    // 1 leading lowercase letter, followed by lowercase/digit/underscore
    // (the actual identifier rule the macro accepts; we keep it simple).
    "[a-z][a-z0-9_]{0,15}".prop_map(|s| s)
}

fn arb_arg_type() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("address"),
        Just("u256"),
        Just("u128"),
        Just("u64"),
        Just("bool"),
        Just("Vec<Address>"),
        Just("bytes"),
        Just("bytes32"),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// For every synthesised canonical method-sig string the
    /// `bloom_chain_abi::selector` runtime helper agrees with `blake3[..4]`,
    /// which is the same recipe the macro uses at expand time.
    #[test]
    fn fuzz_selector_recipe_parity(
        domain in arb_snake_ident(),
        method in arb_snake_ident(),
        arg_types in proptest::collection::vec(arb_arg_type(), 0..6),
    ) {
        let mut sig = String::new();
        sig.push_str(&domain);
        sig.push('.');
        sig.push_str(&method);
        sig.push('(');
        for (i, t) in arg_types.iter().enumerate() {
            if i > 0 { sig.push(','); }
            sig.push_str(t);
        }
        sig.push(')');

        let sel = bloom_chain_abi::selector(&sig);
        let full = blake3::hash(sig.as_bytes());
        prop_assert_eq!(&sel[..], &full.as_bytes()[..4]);
    }
}

// ---- exercise call-builders and dispatcher to be sure the macro wiring is
// intact (not "selector parity" per se but cheap smoke coverage). -----------

#[test]
fn dispatcher_routes_to_correct_handler() {
    let cd = fixture::calls::ping();
    assert_eq!(&cd[..4], &fixture::SEL_PING);
    let mut s = FixtureStub;
    let caller = [0u8; 32];
    let ret = fixture::dispatch(&mut s, &caller, &cd).unwrap();
    assert_eq!(u64::from_be_bytes(ret.try_into().unwrap()), 0);
}

#[test]
fn abi_call_module_emits_same_bytes_as_legacy_calls_module() {
    // The macro emits both `fixture::calls::ping()` (legacy) and
    // `fixture::abi::call::ping()` (new). They must be byte-identical.
    let a = fixture::calls::ping();
    let b = fixture::abi::call::ping();
    assert_eq!(a, b);

    let addr = [0x42u8; 32];
    let a = fixture::calls::echo_addr(&addr);
    let b = fixture::abi::call::echo_addr(&addr);
    assert_eq!(a, b);
}
