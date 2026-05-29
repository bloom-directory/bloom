use bloom_petal_manifest::types::{FunctionDecl, SemVer};
use bloom_petal_manifest::{PetalManifestV0, SCHEMA_VERSION, codec};

fn write_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_u16_be(out, value.len() as u16);
    out.extend_from_slice(value.as_bytes());
}

fn write_empty_list(out: &mut Vec<u8>) {
    write_u32_be(out, 0);
}

fn legacy_schema_v1_manifest_bytes_with_one_function() -> Vec<u8> {
    let mut out = Vec::new();

    write_u32_be(&mut out, 1); // schema_version
    write_string(&mut out, "/bloom/test/legacy-view");
    write_u16_be(&mut out, 0); // framework_version.major
    write_u16_be(&mut out, 1); // framework_version.minor
    write_u16_be(&mut out, 0); // framework_version.patch
    write_u8(&mut out, 0); // parent_version = None

    write_empty_list(&mut out); // object_types
    write_empty_list(&mut out); // capability_types

    write_u32_be(&mut out, 1); // functions
    write_string(&mut out, "read_counter");
    write_empty_list(&mut out); // type_params
    write_empty_list(&mut out); // args
    write_empty_list(&mut out); // returns
    write_u8(&mut out, 0); // required_signers
    write_empty_list(&mut out); // required_capabilities
    write_empty_list(&mut out); // attached_invariants

    write_empty_list(&mut out); // invariants
    write_empty_list(&mut out); // required_host_imports
    write_empty_list(&mut out); // external_type_refs
    write_empty_list(&mut out); // fuel_hints.per_function
    write_u8(&mut out, 0); // fuel_hints.default = None

    out
}

#[test]
fn schema_v1_manifest_fixture_decodes_after_view_schema_bump() {
    let decoded = codec::decode(&legacy_schema_v1_manifest_bytes_with_one_function())
        .expect("schema-v1 manifests must remain decodable");

    assert_eq!(decoded.schema_version, 1);
    assert_eq!(decoded.module_path, "/bloom/test/legacy-view");
    assert_eq!(decoded.functions.len(), 1);
    assert_eq!(decoded.functions[0].name, "read_counter");
    assert!(!decoded.functions[0].view);
}

#[test]
fn manifest_encoder_uses_declared_schema_version_prefix() {
    let manifest = PetalManifestV0 {
        schema_version: SCHEMA_VERSION,
        module_path: "/bloom/test/schema-prefix".to_string(),
        ..Default::default()
    };

    let encoded = codec::encode(&manifest).expect("manifest encodes");

    assert_eq!(&encoded[..4], &SCHEMA_VERSION.to_be_bytes());
}

#[test]
fn function_decl_view_flag_round_trips() {
    let manifest = PetalManifestV0 {
        schema_version: SCHEMA_VERSION,
        module_path: "/bloom/test/view-roundtrip".to_string(),
        framework_version: SemVer::new(0, 1, 0),
        functions: vec![
            FunctionDecl {
                name: "read_counter".to_string(),
                view: true,
                ..Default::default()
            },
            FunctionDecl {
                name: "increment".to_string(),
                view: false,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let decoded = codec::decode(&codec::encode(&manifest).expect("manifest encodes"))
        .expect("manifest decodes");

    assert_eq!(decoded.functions[0].name, "read_counter");
    assert!(decoded.functions[0].view);
    assert_eq!(decoded.functions[1].name, "increment");
    assert!(!decoded.functions[1].view);
}

#[test]
fn schema_version_is_bumped_for_view_function_layout() {
    let manifest = PetalManifestV0::default();

    assert!(
        manifest.schema_version >= 2,
        "adding FunctionDecl.view changes the positional manifest layout"
    );
}
