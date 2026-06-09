use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_node::petal_executor::ChainPetalExecutor;
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_petal_manifest::codec;
use bloom_petal_manifest::types::{FunctionDecl, PetalManifest, SCHEMA_VERSION, SemVer};

fn deploy_tx(wasm_bytes: Vec<u8>) -> Tx {
    Tx {
        chain_id: "test".to_string(),
        sender: Address([0x11; 32]),
        nonce: 1,
        max_fuel: 1_000_000,
        fee_per_unit: 1,
        kind: TxKind::DeployPetal { wasm_bytes },
        pubkey: PubKeyBytes(vec![0x22; 32]),
        sig: SigBytes(vec![0x33; 64]),
    }
}

fn manifest(path: &str) -> Vec<u8> {
    codec::encode(&PetalManifest {
        schema_version: SCHEMA_VERSION,
        module_path: path.to_string(),
        framework_version: SemVer::new(0, 1, 0),
        ..Default::default()
    })
    .expect("manifest encodes")
}

fn manifest_with_function(path: &str, function: &str) -> Vec<u8> {
    codec::encode(&PetalManifest {
        schema_version: SCHEMA_VERSION,
        module_path: path.to_string(),
        framework_version: SemVer::new(0, 1, 0),
        functions: vec![FunctionDecl {
            name: function.to_string(),
            ..Default::default()
        }],
        ..Default::default()
    })
    .expect("manifest encodes")
}

fn leb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn section(out: &mut Vec<u8>, id: u8, body: &[u8]) {
    out.push(id);
    leb128(out, body.len() as u64);
    out.extend_from_slice(body);
}

fn custom_section(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    leb128(&mut body, name.len() as u64);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(payload);
    body
}

fn wasm_with_disallowed_import_and_manifest(path: &str) -> Vec<u8> {
    let mut wasm = Vec::new();
    wasm.extend_from_slice(b"\0asm");
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    section(&mut wasm, 1, &[0x01, 0x60, 0x00, 0x00]);

    let mut imports = Vec::new();
    imports.push(0x01);
    imports.push(0x03);
    imports.extend_from_slice(b"env");
    imports.push(0x03);
    imports.extend_from_slice(b"bad");
    imports.push(0x00);
    imports.push(0x00);
    section(&mut wasm, 2, &imports);

    let custom = custom_section("bloom_petal_manifest", &manifest(path));
    section(&mut wasm, 0, &custom);
    wasm
}

fn wasm_with_unknown_allowed_module_import_and_manifest(path: &str) -> Vec<u8> {
    let mut wasm = Vec::new();
    wasm.extend_from_slice(b"\0asm");
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    // type 0: (i32) -> i32
    section(&mut wasm, 1, &[0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f]);

    let mut imports = Vec::new();
    imports.push(0x01);
    imports.push(0x06);
    imports.extend_from_slice(b"object");
    imports.push(0x07);
    imports.extend_from_slice(b"missing");
    imports.push(0x00);
    imports.push(0x00);
    section(&mut wasm, 2, &imports);

    let custom = custom_section("bloom_petal_manifest", &manifest(path));
    section(&mut wasm, 0, &custom);
    wasm
}

fn wasm_with_non_function_import_and_manifest(path: &str, import_kind: u8) -> Vec<u8> {
    let mut wasm = Vec::new();
    wasm.extend_from_slice(b"\0asm");
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    let mut imports = Vec::new();
    imports.push(0x01);
    imports.push(0x06);
    imports.extend_from_slice(b"object");
    imports.push(0x06);
    imports.extend_from_slice(b"borrow");
    imports.push(import_kind);
    match import_kind {
        // table: funcref, min 1
        0x01 => imports.extend_from_slice(&[0x70, 0x00, 0x01]),
        // memory: min 1
        0x02 => imports.extend_from_slice(&[0x00, 0x01]),
        // global: immutable i32
        0x03 => imports.extend_from_slice(&[0x7f, 0x00]),
        _ => panic!("unsupported import kind"),
    }
    section(&mut wasm, 2, &imports);

    let custom = custom_section("bloom_petal_manifest", &manifest(path));
    section(&mut wasm, 0, &custom);
    wasm
}

fn wasm_with_manifest(path: &str) -> Vec<u8> {
    let mut wasm = Vec::new();
    wasm.extend_from_slice(b"\0asm");
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    let custom = custom_section("bloom_petal_manifest", &manifest(path));
    section(&mut wasm, 0, &custom);
    wasm
}

fn wasm_with_function_manifest_missing_export(path: &str, function: &str) -> Vec<u8> {
    let mut wasm = Vec::new();
    wasm.extend_from_slice(b"\0asm");
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    let custom = custom_section(
        "bloom_petal_manifest",
        &manifest_with_function(path, function),
    );
    section(&mut wasm, 0, &custom);
    wasm
}

fn wasm_with_chain_return_import_and_function(path: &str, function: &str) -> Vec<u8> {
    let mut wasm = Vec::new();
    wasm.extend_from_slice(b"\0asm");
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    // type 0: (i32, i32) -> ()
    // type 1: (i32, i32) -> i32
    section(
        &mut wasm,
        1,
        &[
            0x02, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
        ],
    );

    let mut imports = Vec::new();
    imports.push(0x01);
    imports.push(0x05);
    imports.extend_from_slice(b"chain");
    imports.push(0x0c);
    imports.extend_from_slice(b"petal.return");
    imports.push(0x00);
    imports.push(0x00);
    section(&mut wasm, 2, &imports);

    // One defined function using type 1. Imported function index 0,
    // defined function index 1.
    section(&mut wasm, 3, &[0x01, 0x01]);

    let export_name = format!("__petal_{function}");
    let mut exports = Vec::new();
    exports.push(0x01);
    leb128(&mut exports, export_name.len() as u64);
    exports.extend_from_slice(export_name.as_bytes());
    exports.push(0x00);
    exports.push(0x01);
    section(&mut wasm, 7, &exports);

    // Body: no locals; i32.const 0; end.
    section(&mut wasm, 10, &[0x01, 0x04, 0x00, 0x41, 0x00, 0x0b]);

    let custom = custom_section(
        "bloom_petal_manifest",
        &manifest_with_function(path, function),
    );
    section(&mut wasm, 0, &custom);
    wasm
}

#[test]
fn deploy_missing_manifest_fails_without_writes() {
    let mut state = State::new();
    let out = ChainPetalExecutor.execute_tx(
        &deploy_tx(b"\0asm\x01\0\0\0".to_vec()),
        &mut state,
        1,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );

    assert!(!out.success);
    assert!(out.write_set.is_none());
    assert!(state.vfs_lookup("/missing").is_none());
}

#[test]
fn deploy_disallowed_import_fails_without_writes() {
    let mut state = State::new();
    let path = "/bloom/petals/bad/import";
    let out = ChainPetalExecutor.execute_tx(
        &deploy_tx(wasm_with_disallowed_import_and_manifest(path)),
        &mut state,
        1,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );

    assert!(!out.success);
    assert!(out.write_set.is_none());
    assert!(state.vfs_lookup(path).is_none());
    let reason = String::from_utf8_lossy(&out.return_data);
    assert!(
        reason.contains("disallowed module") || reason.contains("unknown host function"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn deploy_unknown_host_import_fails_without_writes() {
    let mut state = State::new();
    let path = "/bloom/petals/bad/import-name";
    let out = ChainPetalExecutor.execute_tx(
        &deploy_tx(wasm_with_unknown_allowed_module_import_and_manifest(path)),
        &mut state,
        1,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );

    assert!(!out.success);
    assert!(out.write_set.is_none());
    assert!(state.vfs_lookup(path).is_none());
    assert!(String::from_utf8_lossy(&out.return_data).contains("unknown host function"));
}

#[test]
fn deploy_non_function_imports_from_allowed_modules_fail_without_writes() {
    for (kind, label) in [(0x01, "table"), (0x02, "memory"), (0x03, "global")] {
        let mut state = State::new();
        let path = format!("/bloom/petals/bad/non-func-{label}");
        let out = ChainPetalExecutor.execute_tx(
            &deploy_tx(wasm_with_non_function_import_and_manifest(&path, kind)),
            &mut state,
            1,
            1_700_000_000_000,
            Address([0xAA; 32]),
            Hash32([0; 32]),
        );

        assert!(!out.success, "{label} import must reject");
        assert!(out.write_set.is_none());
        assert!(state.vfs_lookup(&path).is_none());
        let reason = String::from_utf8_lossy(&out.return_data);
        assert!(
            reason.contains("must be a function import"),
            "unexpected {label} reject reason: {reason}"
        );
    }
}

#[test]
fn deploy_manifest_function_missing_export_fails_without_writes() {
    let mut state = State::new();
    let path = "/bloom/petals/bad/missing-export";
    let out = ChainPetalExecutor.execute_tx(
        &deploy_tx(wasm_with_function_manifest_missing_export(path, "swap")),
        &mut state,
        1,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );

    assert!(!out.success);
    assert!(out.write_set.is_none());
    assert!(state.vfs_lookup(path).is_none());
    assert!(String::from_utf8_lossy(&out.return_data).contains("__petal_swap"));
}

#[test]
fn deploy_allowed_chain_return_import_succeeds() {
    let mut state = State::new();
    let path = "/bloom/petals/ok/chain-return";
    let out = ChainPetalExecutor.execute_tx(
        &deploy_tx(wasm_with_chain_return_import_and_function(path, "ping")),
        &mut state,
        1,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );

    assert!(
        out.success,
        "expected deploy to succeed, got: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    let ws = out.write_set.expect("successful deploy emits writes");
    state.apply(ws).expect("deploy writes apply");
    assert!(state.vfs_lookup(path).is_some());
}

#[test]
fn deploy_existing_path_fails_without_rebinding() {
    let mut state = State::new();
    let path = "/bloom/petals/existing";
    let existing_hash = Hash32([0x44; 32]);
    state.set_vfs_binding(path.to_string(), existing_hash);

    let out = ChainPetalExecutor.execute_tx(
        &deploy_tx(wasm_with_manifest(path)),
        &mut state,
        1,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );

    assert!(!out.success);
    assert!(out.write_set.is_none());
    assert_eq!(state.vfs_lookup(path), Some(existing_hash));
    assert!(String::from_utf8_lossy(&out.return_data).contains("already bound"));
}

#[test]
fn deploy_path_function_collision_fails_without_writes() {
    let mut state = State::new();
    let parent_path = "/bloom/petals/dex";
    let child_path = "/bloom/petals/dex/pool";

    let parent = ChainPetalExecutor.execute_tx(
        &deploy_tx(wasm_with_chain_return_import_and_function(
            parent_path,
            "pool",
        )),
        &mut state,
        1,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );
    assert!(
        parent.success,
        "parent deploy failed: {}",
        String::from_utf8_lossy(&parent.return_data)
    );
    state
        .apply(parent.write_set.expect("parent deploy emits writes"))
        .expect("parent deploy applies");

    let child = ChainPetalExecutor.execute_tx(
        &deploy_tx(wasm_with_manifest(child_path)),
        &mut state,
        2,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );
    assert!(!child.success);
    assert!(child.write_set.is_none());
    assert!(state.vfs_lookup(child_path).is_none());
    assert!(String::from_utf8_lossy(&child.return_data).contains("collides"));
}

#[test]
fn deploy_function_descendant_collision_fails_without_writes() {
    let mut state = State::new();
    let parent_path = "/bloom/petals/dex";
    let child_path = "/bloom/petals/dex/pool";

    let child = ChainPetalExecutor.execute_tx(
        &deploy_tx(wasm_with_manifest(child_path)),
        &mut state,
        1,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );
    assert!(
        child.success,
        "child deploy failed: {}",
        String::from_utf8_lossy(&child.return_data)
    );
    state
        .apply(child.write_set.expect("child deploy emits writes"))
        .expect("child deploy applies");

    let parent = ChainPetalExecutor.execute_tx(
        &deploy_tx(wasm_with_chain_return_import_and_function(
            parent_path,
            "pool",
        )),
        &mut state,
        2,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );
    assert!(!parent.success);
    assert!(parent.write_set.is_none());
    assert!(state.vfs_lookup(parent_path).is_none());
    assert!(String::from_utf8_lossy(&parent.return_data).contains("collides"));
}

#[test]
fn deploy_outside_petals_prefix_fails_without_writes() {
    let mut state = State::new();
    let path = "/bloom/dex/pool";
    let out = ChainPetalExecutor.execute_tx(
        &deploy_tx(wasm_with_manifest(path)),
        &mut state,
        1,
        1_700_000_000_000,
        Address([0xAA; 32]),
        Hash32([0; 32]),
    );

    assert!(!out.success);
    assert!(out.write_set.is_none());
    assert!(state.vfs_lookup(path).is_none());
    assert!(String::from_utf8_lossy(&out.return_data).contains("/bloom/petals/"));
}

#[test]
fn deploy_dot_prefixed_path_fails_without_writes() {
    for path in [
        "/bloom/petals/.pipe",
        "/bloom/petals/.pipe/foo",
        "/bloom/petals/dex/.state",
        "/bloom/petals/dex/.foo",
    ] {
        let mut state = State::new();
        let out = ChainPetalExecutor.execute_tx(
            &deploy_tx(wasm_with_manifest(path)),
            &mut state,
            1,
            1_700_000_000_000,
            Address([0xAA; 32]),
            Hash32([0; 32]),
        );

        assert!(!out.success, "{path} should fail admission");
        assert!(out.write_set.is_none(), "{path} should not emit writes");
        assert!(state.vfs_lookup(path).is_none());
        assert!(
            String::from_utf8_lossy(&out.return_data).contains("dot-prefixed"),
            "unexpected error for {path}: {}",
            String::from_utf8_lossy(&out.return_data)
        );
    }
}

#[test]
fn deploy_reserved_page_path_fails_without_writes() {
    for path in ["/bloom/petals/page", "/bloom/petals/dex/page"] {
        let mut state = State::new();
        let out = ChainPetalExecutor.execute_tx(
            &deploy_tx(wasm_with_manifest(path)),
            &mut state,
            1,
            1_700_000_000_000,
            Address([0xAA; 32]),
            Hash32([0; 32]),
        );

        assert!(!out.success, "{path} should fail admission");
        assert!(out.write_set.is_none(), "{path} should not emit writes");
        assert!(state.vfs_lookup(path).is_none());
        assert!(
            String::from_utf8_lossy(&out.return_data).contains("page"),
            "unexpected error for {path}: {}",
            String::from_utf8_lossy(&out.return_data)
        );
    }
}

#[test]
fn deploy_vfs_invalid_path_segment_fails_without_writes() {
    for path in [
        "/bloom/petals/dex\\pool",
        "/bloom/petals/dex/\0pool",
        "/bloom/petals/my app/pool",
        "/bloom/petals/dex/\tpool",
    ] {
        let mut state = State::new();
        let out = ChainPetalExecutor.execute_tx(
            &deploy_tx(wasm_with_manifest(path)),
            &mut state,
            1,
            1_700_000_000_000,
            Address([0xAA; 32]),
            Hash32([0; 32]),
        );

        assert!(!out.success, "{path:?} should fail admission");
        assert!(out.write_set.is_none(), "{path:?} should not emit writes");
        assert!(state.vfs_lookup(path).is_none());
        assert!(
            String::from_utf8_lossy(&out.return_data).contains("VFS-invalid"),
            "unexpected error for {path:?}: {}",
            String::from_utf8_lossy(&out.return_data)
        );
    }
}

#[test]
fn deploy_vfs_invalid_function_name_fails_without_writes() {
    let path = "/bloom/petals/dex/bad-function";
    for function in [
        "foo/bar",
        "foo\\bar",
        "foo\0bar",
        "page",
        ".state",
        ".pipe",
        "set counter",
        "set\tcounter",
    ] {
        let mut state = State::new();
        let out = ChainPetalExecutor.execute_tx(
            &deploy_tx(wasm_with_function_manifest_missing_export(path, function)),
            &mut state,
            1,
            1_700_000_000_000,
            Address([0xAA; 32]),
            Hash32([0; 32]),
        );

        assert!(!out.success, "{function:?} should fail admission");
        assert!(
            out.write_set.is_none(),
            "{function:?} should not emit writes"
        );
        assert!(state.vfs_lookup(path).is_none());
        assert!(
            String::from_utf8_lossy(&out.return_data).contains("VFS path segment"),
            "unexpected error for {function:?}: {}",
            String::from_utf8_lossy(&out.return_data)
        );
    }
}
