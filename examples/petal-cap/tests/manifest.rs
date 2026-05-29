//! Manifest-shape tests for the `/bloom/petals/core/cap` petal.
//!
//! These tests decode the wasm `bloom_petal_manifest_v0` custom-section
//! blob that `#[bloom::petal]` emits into a `static [u8; N]` and assert
//! the petal's user-visible surface (object types, capability types,
//! function entries, required-capability lists) match spec §5 + §18.
//!
//! We can't depend on `bloom-resource-macros` as a normal crate
//! (it's `proc-macro = true`), so we inline a small decoder that walks
//! the encoding documented in `bloom-resource-macros/src/manifest_codec.rs`.
//! The decoder only walks far enough to answer each test's question.

use bloom_objects::codec::{read_bytes32, read_string, read_u8, read_u16_be, read_u32_be};
use bloom_objects::{AccessMode, TypeTag};
use bloom_petal_cap::cap;

// ===========================================================================
// Inline minimal manifest decoder
// ===========================================================================

#[derive(Debug)]
struct Manifest {
    module_path: String,
    object_types: Vec<ObjectType>,
    capability_types: Vec<Capability>,
    functions: Vec<Function>,
}

#[derive(Debug)]
struct ObjectType {
    name: String,
    abilities: u8,
    type_params: Vec<TypeParam>,
}

#[derive(Debug)]
struct Capability {
    name: String,
    type_params: Vec<TypeParam>,
}

#[derive(Debug)]
struct TypeParam {
    name: String,
    /// 0 = Phantom, 1 = Resource.
    kind: u8,
}

#[derive(Debug)]
struct Function {
    name: String,
    args: Vec<Arg>,
    required_signers: u8,
    required_capabilities: Vec<TypeTag>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct Arg {
    name: String,
    /// 0 = Signer, 1 = Const, 2 = Object, 3 = TypeArg.
    kind: u8,
    object_ty: Option<TypeTag>,
    object_mode: Option<AccessMode>,
}

fn decode(bytes: &[u8]) -> Manifest {
    let mut r = bytes;
    let schema_version = read_u32_be(&mut r).unwrap();
    let module_path = read_string(&mut r).unwrap();
    // semver (3 x u16)
    let _ = read_u16_be(&mut r).unwrap();
    let _ = read_u16_be(&mut r).unwrap();
    let _ = read_u16_be(&mut r).unwrap();
    // parent_version Option<[u8;32]>
    let pv = read_u8(&mut r).unwrap();
    if pv == 1 {
        let _ = read_bytes32(&mut r).unwrap();
    }

    let object_types = decode_list(&mut r, decode_object_type);
    let capability_types = decode_list(&mut r, decode_capability);
    let functions = decode_list(&mut r, |r| decode_function(r, schema_version));

    Manifest {
        module_path,
        object_types,
        capability_types,
        functions,
    }
}

fn decode_list<T>(r: &mut &[u8], mut f: impl FnMut(&mut &[u8]) -> T) -> Vec<T> {
    let n = read_u32_be(r).unwrap() as usize;
    (0..n).map(|_| f(r)).collect()
}

fn decode_type_param(r: &mut &[u8]) -> TypeParam {
    let name = read_string(r).unwrap();
    let kind = read_u8(r).unwrap();
    // bounds: list of TypeTag (each consumes self-delimited bytes)
    let n = read_u32_be(r).unwrap() as usize;
    for _ in 0..n {
        let _ = TypeTag::decode_from(r, 0).unwrap();
    }
    TypeParam { name, kind }
}

fn decode_field(r: &mut &[u8]) {
    let _name = read_string(r).unwrap();
    let _ty = TypeTag::decode_from(r, 0).unwrap();
}

fn decode_object_type(r: &mut &[u8]) -> ObjectType {
    let name = read_string(r).unwrap();
    let abilities = read_u8(r).unwrap();
    let type_params = decode_list(r, decode_type_param);
    let _fields = decode_list(r, decode_field);
    ObjectType {
        name,
        abilities,
        type_params,
    }
}

fn decode_capability(r: &mut &[u8]) -> Capability {
    let name = read_string(r).unwrap();
    let type_params = decode_list(r, decode_type_param);
    Capability { name, type_params }
}

fn decode_arg(r: &mut &[u8]) -> Arg {
    let name = read_string(r).unwrap();
    let kind = read_u8(r).unwrap();
    let mut object_ty = None;
    let mut object_mode = None;
    match kind {
        0 => {} // Signer
        1 => {
            // Const(ty)
            let _ = TypeTag::decode_from(r, 0).unwrap();
        }
        2 => {
            // Object { ty, mode }
            object_ty = Some(TypeTag::decode_from(r, 0).unwrap());
            object_mode = Some(AccessMode::from_byte(read_u8(r).unwrap()).unwrap());
        }
        3 => {
            // TypeArg(u16)
            let _ = read_u16_be(r).unwrap();
        }
        other => panic!("unknown ArgKind discriminant {other}"),
    }
    Arg {
        name,
        kind,
        object_ty,
        object_mode,
    }
}

fn decode_function(r: &mut &[u8], schema_version: u32) -> Function {
    let name = read_string(r).unwrap();
    let _type_params = decode_list(r, decode_type_param);
    let args = decode_list(r, decode_arg);
    let _returns = decode_list(r, |r| {
        TypeTag::decode_from(r, 0).unwrap();
    });
    let required_signers = read_u8(r).unwrap();
    let required_capabilities = decode_list(r, |r| TypeTag::decode_from(r, 0).unwrap());
    // attached_invariants
    let n = read_u32_be(r).unwrap() as usize;
    for _ in 0..n {
        let _ = read_u16_be(r).unwrap();
    }
    if schema_version >= 2 {
        let _view = read_u8(r).unwrap();
    }
    Function {
        name,
        args,
        required_signers,
        required_capabilities,
    }
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
    // abilities = key | store -> 0b0011 = 3 (per `AbilitySet::from_str_list`).
    assert_ne!(cap_obj.abilities & 0b01, 0, "Cap must have `key` ability");
    assert_ne!(cap_obj.abilities & 0b10, 0, "Cap must have `store` ability");
    // The single generic `T` is declared as phantom.
    let t = cap_obj
        .type_params
        .iter()
        .find(|p| p.name == "T")
        .expect("Cap must have a `T` generic param");
    assert_eq!(t.kind, 0, "`T` must be phantom (kind = 0)");
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
    assert_eq!(t.kind, 0, "`T` must be phantom (kind = 0)");
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
        matches!(new_fn.args.first(), Some(a) if a.kind == 0),
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
    assert_eq!(arg.kind, 2, "first arg of `lock` must be an Object arg");
    assert_eq!(
        arg.object_mode,
        Some(AccessMode::Mutable),
        "first arg of `lock` must be borrowed Mutable"
    );
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
