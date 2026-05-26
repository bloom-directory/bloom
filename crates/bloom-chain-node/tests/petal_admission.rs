use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_node::petal_executor::ChainPetalExecutor;
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_petal_manifest::codec;
use bloom_petal_manifest::types::{PetalManifestV0, SCHEMA_VERSION, SemVer};

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
    codec::encode(&PetalManifestV0 {
        schema_version: SCHEMA_VERSION,
        module_path: path.to_string(),
        framework_version: SemVer::new(0, 1, 0),
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

    let custom = custom_section("bloom_petal_manifest_v0", &manifest(path));
    section(&mut wasm, 0, &custom);
    wasm
}

fn wasm_with_manifest(path: &str) -> Vec<u8> {
    let mut wasm = Vec::new();
    wasm.extend_from_slice(b"\0asm");
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    let custom = custom_section("bloom_petal_manifest_v0", &manifest(path));
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
    let path = "/bad/import";
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
    assert!(String::from_utf8_lossy(&out.return_data).contains("disallowed module"));
}

#[test]
fn deploy_existing_path_fails_without_rebinding() {
    let mut state = State::new();
    let path = "/bloom/existing";
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
