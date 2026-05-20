//! Fixture-driven integration tests. Each `#[test]` `include!`s a
//! fixture file at the top level, exercising the macros end-to-end on
//! a self-contained petal.
//!
//! Note: `include!` semantics mean every fixture's `pub mod foo` is
//! merged into this test crate's namespace. To avoid name collisions
//! each fixture uses a distinct mod name (`minimal`, `cap`, `inv_test`).

#![allow(dead_code)] // fixture petal structs/fns are exercised purely by their
                     // macro expansion; we don't call them at runtime.

mod minimal_test {
    include!("fixtures/minimal_petal.rs");

    #[test]
    fn manifest_bytes_present() {
        let bytes = minimal::__bloom_manifest_bytes();
        assert!(!bytes.is_empty());
    }
}

mod capability_test {
    include!("fixtures/capability_petal.rs");

    #[test]
    fn manifest_bytes_present() {
        let bytes = cap::__bloom_manifest_bytes();
        assert!(!bytes.is_empty());
    }
}

mod invariant_test {
    include!("fixtures/invariant_petal.rs");

    #[test]
    fn manifest_bytes_present() {
        let bytes = inv_test::__bloom_manifest_bytes();
        assert!(!bytes.is_empty());
    }
}
