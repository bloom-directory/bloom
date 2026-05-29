use bloom_petal_manifest::{
    codec,
    types::{FunctionDecl, MANIFEST_CUSTOM_SECTION, PetalManifestV0},
};
use bloom_petals::chain_vm::validate_chain_wasm;

fn wasm_with_manifest(wat_src: &str, functions: Vec<FunctionDecl>) -> Vec<u8> {
    let mut wasm = wat::parse_str(wat_src).expect("wat parses");
    let manifest = PetalManifestV0 {
        module_path: "/bloom/test/view".to_string(),
        functions,
        ..Default::default()
    };
    append_custom_section(
        &mut wasm,
        MANIFEST_CUSTOM_SECTION,
        &codec::encode(&manifest).expect("manifest encodes"),
    );
    wasm
}

fn append_custom_section(wasm: &mut Vec<u8>, name: &str, data: &[u8]) {
    wasm.push(0);
    let mut body = Vec::new();
    leb128(&mut body, name.len() as u64);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(data);
    leb128(wasm, body.len() as u64);
    wasm.extend_from_slice(&body);
}

fn leb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            return;
        }
    }
}

fn func(name: &str, view: bool) -> FunctionDecl {
    FunctionDecl {
        name: name.to_string(),
        view,
        ..Default::default()
    }
}

#[test]
fn view_reaching_direct_mutating_import_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (import "object" "create" (func $create))
            (func $__petal_quote (call $create))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("view function 'quote'"));
    assert!(err.contains("object.create"));
}

#[test]
fn view_reaching_transitive_mutating_import_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (import "object" "delete" (func $delete))
            (func $helper (call $delete))
            (func $__petal_quote (call $helper))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("view function 'quote'"));
    assert!(err.contains("object.delete"));
}

#[test]
fn reachable_call_indirect_in_view_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (type $t (func))
            (table 1 funcref)
            (func $helper)
            (elem (i32.const 0) $helper)
            (func $__petal_quote
              (i32.const 0)
              (call_indirect (type $t)))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("call_indirect"));
}

#[test]
fn reachable_return_call_to_mutating_import_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (import "object" "mutate" (func $mutate))
            (func $__petal_quote
              (return_call $mutate))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("return_call"));
}

#[test]
fn reachable_return_call_indirect_in_view_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (type $t (func))
            (table 1 funcref)
            (func $helper)
            (elem (i32.const 0) $helper)
            (func $__petal_quote
              (i32.const 0)
              (return_call_indirect (type $t)))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("return_call_indirect"));
}

#[test]
fn tail_call_in_non_view_export_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (func $helper)
            (func $__petal_update
              (return_call $helper))
            (export "__petal_update" (func $__petal_update))
        )"#,
        vec![func("update", false)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("return_call"));
}

#[test]
fn start_section_is_rejected_before_view_purity_claims() {
    let wasm = wasm_with_manifest(
        r#"(module
            (import "object" "mutate" (func $mutate))
            (func $start (call $mutate))
            (start $start)
            (func $__petal_quote)
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("start function"));
    assert!(err.contains("not allowed"));
}

#[test]
fn pure_view_passes_and_mixed_mutating_non_view_deploys() {
    let wasm = wasm_with_manifest(
        r#"(module
            (import "object" "mutate" (func $mutate))
            (func $__petal_quote)
            (func $__petal_update (call $mutate))
            (export "__petal_quote" (func $__petal_quote))
            (export "__petal_update" (func $__petal_update))
        )"#,
        vec![func("quote", true), func("update", false)],
    );

    validate_chain_wasm(&wasm).expect("pure view plus mutating non-view should pass");
}
