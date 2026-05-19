//! Compile-fail self-tests: verify the macro emits structured diagnostics for
//! the cases the spec calls out — reserved tag prefixes, bytes in storage,
//! bytes in events, `#[indexed] bytes`, and the `#[internal]` +
//! `#[nonreentrant]` combination.

#[test]
fn compile_fail_diagnostics() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/reserved_macro_prefix.rs");
    t.compile_fail("tests/ui/bytes_in_storage.rs");
    t.compile_fail("tests/ui/bytes_in_event.rs");
    t.compile_fail("tests/ui/indexed_bytes.rs");
    t.compile_fail("tests/ui/internal_plus_nonreentrant.rs");
}
