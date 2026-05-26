//! End-to-end wasm32 check for generic-dispatch monomorphization
//! (Phase A, spec §5).
//!
//! ## What this proves
//!
//! Compiling the `identity` petal to `wasm32-unknown-unknown` emits a
//! *real* `__petal_identity` / `__petal_echo_tag` wasm export for the
//! generic fns — **not** a `NotImplemented` stub. The shim is a single
//! non-generic export per fn (the user's `T` is monomorphized over
//! `bloom_resource::Erased`); the concrete `T` arrives at runtime as the
//! leading `Arg::TypeArg(TypeTag)` slot of the calldata and is bound into
//! the per-call `bloom_resource::TypeArgs` context.
//!
//! ## Why it is `#[ignore]`-gated
//!
//! It shells out to `cargo build --target wasm32-unknown-unknown`, which
//! requires the wasm target to be installed and is too slow /
//! environment-dependent for the default `cargo test` run.
//!
//! ## How to run
//!
//! ```text
//! cargo test -p bloom-petal-identity -- --ignored
//! ```

use std::path::PathBuf;
use std::process::Command;

use bloom_chain_node::chain_petal_runner::ChainPetalRunner;
use bloom_chain_state::State;
use bloom_chain_types::{Hash32, types::Address};
use bloom_objects::TypeTag;
use bloom_petals::BlockCtx;
use bloom_resource::abi::ArgReader;
use bloom_script::{executor::PetalRunner, host_ctx::PtbHostCtx};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Build this petal for `wasm32-unknown-unknown` and return the path to
/// the emitted `.wasm` artifact.
fn build_wasm() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "-p",
            "bloom-petal-identity",
            "--target",
            "wasm32-unknown-unknown",
        ])
        .current_dir(manifest_dir)
        .status()
        .expect("failed to spawn cargo build for wasm32");
    assert!(status.success(), "wasm32 build failed");

    // Walk up to the workspace root and locate the artifact under the
    // shared target dir. The cdylib output uses the lib name
    // (`bloom_petal_identity`), underscored.
    let workspace_root = PathBuf::from(manifest_dir)
        .ancestors()
        .nth(2)
        .expect("workspace root two levels above example crate")
        .to_path_buf();
    let artifact = workspace_root
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("debug")
        .join("bloom_petal_identity.wasm");
    assert!(
        artifact.exists(),
        "expected wasm artifact at {}",
        artifact.display()
    );
    artifact
}

/// Collect the export names of a wasm module.
fn wasm_export_names(bytes: &[u8]) -> Vec<String> {
    use wasmparser::{Parser, Payload};
    let mut names = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::ExportSection(reader) = payload.expect("valid wasm payload") {
            for export in reader {
                let export = export.expect("valid export entry");
                names.push(export.name.to_string());
            }
        }
    }
    names
}

#[test]
#[ignore = "compiles to wasm32; run with `cargo test -p bloom-petal-identity -- --ignored`"]
fn generic_fns_emit_real_wasm_exports() {
    let artifact = build_wasm();
    let bytes = std::fs::read(&artifact).expect("read wasm artifact");
    let exports = wasm_export_names(&bytes);

    assert!(
        exports.iter().any(|n| n == "__petal_identity"),
        "generic `identity<T>` must emit a real `__petal_identity` export; got {exports:?}"
    );
    assert!(
        exports.iter().any(|n| n == "__petal_echo_tag"),
        "generic `echo_tag<T>` must emit a real `__petal_echo_tag` export; got {exports:?}"
    );
}

#[test]
#[ignore = "compiles to wasm32; run with `cargo test -p bloom-petal-identity -- --ignored`"]
fn real_wasm_echo_tag_receives_runner_type_args() {
    let artifact = build_wasm();
    let bytes = std::fs::read(&artifact).expect("read wasm artifact");
    let hash = Hash32(blake3::hash(&bytes).into());
    let usdc = TypeTag::Concrete {
        petal_hash: [0x11; 32],
        type_name: "USDC".to_string(),
        type_args: vec![],
    };
    let expected_len = usdc.encode_canonical().unwrap().len() as u128;

    let mut petals = BTreeMap::new();
    petals.insert(hash, bytes);
    let runner = ChainPetalRunner::new(
        petals,
        Arc::new(Mutex::new(PtbHostCtx::new())),
        State::new().snapshot(),
        BlockCtx {
            number: 1,
            timestamp_ms: 1_700_000_000_000,
            prevhash: Hash32([0; 32]),
        },
        Address([0; 32]),
    );

    let result = runner
        .call(&hash, "echo_tag", &[usdc], &0u32.to_be_bytes(), 1_000_000)
        .expect("real wasm generic echo_tag should run");

    let mut r = ArgReader::new(&result.ret_buf);
    assert_eq!(r.read_u32().unwrap(), 1);
    let bytes = r.read_bytes().unwrap();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&bytes);
    assert_eq!(u128::from_be_bytes(raw), expected_len);
    r.expect_eof().unwrap();
}
