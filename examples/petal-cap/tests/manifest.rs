//! Manifest-shape tests for the `/bloom/petals/core/cap` petal.
//!
//! These tests decode the wasm `bloom_petal_manifest` custom-section
//! blob that `#[bloom::petal]` emits into a `static [u8; N]` and assert
//! the petal's user-visible surface (object types, capability types,
//! function entries, required-capability lists) match spec §5 + §18.
//!
use bloom_objects::{AccessMode, TypeTag};
use bloom_petal_cap::cap;
use bloom_petal_manifest::PetalManifest;
use bloom_petal_manifest::types::{ArgKind, TypeParamKind};

fn decode(bytes: &[u8]) -> PetalManifest {
    bloom_petal_manifest::codec::decode(bytes).unwrap()
}

// ===========================================================================
// Tests
// ===========================================================================

#[test]
fn manifest_bytes_present() {
    let bytes = cap::__bloom_manifest_bytes();
    assert!(!bytes.is_empty(), "manifest custom-section blob is empty");
}

#[test]
fn manifest_module_path_is_bloom_core_cap() {
    let bytes = cap::__bloom_manifest_bytes();
    let m = decode(bytes);
    assert_eq!(m.module_path, "/bloom/petals/core/cap");
}

#[test]
fn manifest_exposes_cap_object_type() {
    let bytes = cap::__bloom_manifest_bytes();
    let m = decode(bytes);
    let cap_obj = m
        .object_types
        .iter()
        .find(|o| o.name == "Cap")
        .expect("manifest must declare `Cap` as an #[object]");
    assert!(cap_obj.abilities.has_key(), "Cap must have `key` ability");
    assert!(
        cap_obj.abilities.has_store(),
        "Cap must have `store` ability"
    );
    // The single generic `T` is declared as phantom.
    let t = cap_obj
        .type_params
        .iter()
        .find(|p| p.name == "T")
        .expect("Cap must have a `T` generic param");
    assert_eq!(t.kind, TypeParamKind::Phantom, "`T` must be phantom");
}

#[test]
fn manifest_exposes_revoke_cap_capability() {
    let bytes = cap::__bloom_manifest_bytes();
    let m = decode(bytes);
    let rc = m
        .capability_types
        .iter()
        .find(|c| c.name == "RevokeCap")
        .expect("manifest must declare `RevokeCap` as a #[capability]");
    let t = rc
        .type_params
        .iter()
        .find(|p| p.name == "T")
        .expect("RevokeCap must have a `T` generic param");
    assert_eq!(t.kind, TypeParamKind::Phantom, "`T` must be phantom");
}

#[test]
fn manifest_exposes_required_capabilities_on_revoke() {
    let bytes = cap::__bloom_manifest_bytes();
    let m = decode(bytes);
    let revoke = m
        .functions
        .iter()
        .find(|f| f.name == "revoke")
        .expect("manifest must declare `revoke` fn");
    // `revoke<T>(_rc: &Capability<RevokeCap<T>>, cap: &mut Cap<T>)`
    // → required_capabilities should contain the inner `RevokeCap<T>`
    // tag (the macro unwraps `Capability<inner>` and pushes `inner`).
    assert_eq!(
        revoke.required_capabilities.len(),
        1,
        "revoke must declare exactly one required capability, got {:?}",
        revoke.required_capabilities
    );
    match &revoke.required_capabilities[0] {
        TypeTag::Concrete { type_name, .. } => {
            assert_eq!(type_name, "RevokeCap");
        }
        other => panic!("expected Concrete RevokeCap tag, got {:?}", other),
    }
}

#[test]
fn manifest_records_required_signer_on_new() {
    let bytes = cap::__bloom_manifest_bytes();
    let m = decode(bytes);
    let new_fn = m
        .functions
        .iter()
        .find(|f| f.name == "new")
        .expect("manifest must declare `new` fn");
    assert_eq!(
        new_fn.required_signers, 1,
        "new<T>(_signer: &Signer, ...) must declare 1 required signer"
    );
    assert!(
        matches!(new_fn.args.first(), Some(a) if matches!(a.kind, ArgKind::Signer)),
        "first arg of `new` must be the Signer"
    );
}

#[test]
fn manifest_records_mutable_borrow_on_lock() {
    let bytes = cap::__bloom_manifest_bytes();
    let m = decode(bytes);
    let f = m
        .functions
        .iter()
        .find(|f| f.name == "lock")
        .expect("manifest must declare `lock` fn");
    let arg = &f.args[0];
    match &arg.kind {
        ArgKind::Object { mode, .. } => assert_eq!(
            *mode,
            AccessMode::Mutable,
            "first arg of `lock` must be borrowed Mutable"
        ),
        other => panic!("first arg of `lock` must be an Object arg, got {other:?}"),
    }
}

#[test]
fn manifest_lists_all_public_functions() {
    let bytes = cap::__bloom_manifest_bytes();
    let m = decode(bytes);
    let names: std::collections::BTreeSet<&str> =
        m.functions.iter().map(|f| f.name.as_str()).collect();
    for expected in [
        "new",
        "lock",
        "unlock",
        "set_expiry",
        "revoke",
        "is_active",
        "transfer",
        "destroy",
    ] {
        assert!(
            names.contains(expected),
            "manifest must list `{expected}` (got {:?})",
            names
        );
    }
}
