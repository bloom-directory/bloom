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
//! Two reasons:
//!
//! 1. It shells out to `cargo build --target wasm32-unknown-unknown`,
//!    which requires the wasm target to be installed and is too slow /
//!    environment-dependent for the default `cargo test` run.
//! 2. A *full* call-through (instantiate the wasm, feed it a PTB carrying
//!    `Arg::TypeArg` + `Arg::Object(Coin)`, assert the output object's
//!    runtime type-tag) additionally depends on the calldata wire-format
//!    reconciliation between the chain VM (`bloom-petals::chain_vm`, which
//!    invokes `__petal_*` as `(i32, i32) -> i32` and feeds calldata via
//!    the `msg.calldata.read` import) and the macro-emitted 4-arg
//!    `(args_ptr, args_len, ret_ptr, ret_cap)` ABI. That reconciliation
//!    is Phase E/F, not Phase A. The host-shim unit tests in
//!    `crates/bloom-resource-macros/tests/compile_pass.rs`
//!    (`generic_dispatch_test`) already drive the dispatch path directly
//!    in the canonical `ArgReader` wire format and assert the runtime
//!    type-erased dispatch, runtime-tag resolution, output-object tag
//!    stamping, and linearity.
//!
//! ## Intended end-to-end flow (Phase E/F)
//!
//! Once the calldata path is reconciled, this test should additionally:
//!
//! 1. Publish the compiled wasm at `/bloom/test/identity`.
//! 2. Build a PTB with a single `Command::Move` for `identity` whose
//!    `type_args = [Concrete{ "USDC" }]` and `args = [Arg::Object(coin)]`.
//! 3. Execute it through `ChainPetalRunner` / `PetalVm` and assert the
//!    returned coin object carries the runtime tag `USDC` (taken from the
//!    `Arg::TypeArg`, not a compile-time const) and that the input coin
//!    was consumed exactly once (linearity).
//!
//! ## How to run
//!
//! ```text
//! cargo test -p bloom-petal-identity -- --ignored
//! ```

use std::path::PathBuf;
use std::process::Command;

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
