//! Probe test to inspect the real fungible petal's macro-emitted
//! manifest. Used during development to verify that
//! `real_fungible_manifest_bytes()` returns canonical-codec bytes that
//! round-trip through `bloom_petal_manifest::codec::decode`.

use bloom_petal_it::harness::real_fungible_manifest_bytes;
use bloom_petal_manifest::codec::decode;

#[test]
fn real_fungible_manifest_decodes() {
    let bytes = real_fungible_manifest_bytes();
    assert!(!bytes.is_empty(), "manifest blob must be non-empty");
    let m = decode(bytes).expect("real fungible manifest must decode");
    assert_eq!(m.module_path, "/bloom/core/fungible");
    // Spec §14.1 — every public petal fn in the fungible module must
    // appear in the manifest.
    let names: Vec<&str> = m.functions.iter().map(|f| f.name.as_str()).collect();
    for expected in [
        "create_currency",
        "mint",
        "burn",
        "split",
        "merge",
        "transfer",
        "value",
        "mint_genesis",
    ] {
        assert!(
            names.contains(&expected),
            "real manifest must declare `{expected}` (got {:?})",
            names
        );
    }
    // mint_genesis takes a Capability<EpochZero> object arg.
    let mint_genesis = m
        .functions
        .iter()
        .find(|f| f.name == "mint_genesis")
        .expect("mint_genesis present");
    let first_arg = &mint_genesis.args[0];
    use bloom_petal_manifest::types::ArgKind;
    match &first_arg.kind {
        ArgKind::Object { ty, .. } => {
            // Should be `Capability<EpochZero>`.
            let label = format!("{ty:?}");
            assert!(
                label.contains("Capability") && label.contains("EpochZero"),
                "first arg must be Capability<EpochZero>; got {label}"
            );
        }
        other => panic!("first arg of mint_genesis must be Object; got {other:?}"),
    }

    // Lock in the full arg shape of mint_genesis so the
    // real_mintcap_revert tests (which build a PTB against this exact
    // signature) don't silently desync if the petal changes:
    //   [0] epoch     — Object{ Capability<EpochZero>, ReadOnly }
    //   [1] amount    — Const(u128)
    //   [2] recipient — Const(Address)
    assert_eq!(mint_genesis.args.len(), 3, "mint_genesis must take 3 args");
    assert!(
        matches!(mint_genesis.args[0].kind, ArgKind::Object { .. }),
        "mint_genesis arg[0] must be Object"
    );
    assert!(
        matches!(mint_genesis.args[1].kind, ArgKind::Const(_)),
        "mint_genesis arg[1] (amount) must be Const"
    );
    assert!(
        matches!(mint_genesis.args[2].kind, ArgKind::Const(_)),
        "mint_genesis arg[2] (recipient) must be Const"
    );
}
