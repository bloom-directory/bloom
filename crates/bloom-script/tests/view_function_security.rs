use std::collections::HashMap;

use bloom_chain_types::types::Hash32;
use bloom_objects::{Object, ObjectId, Owner, TypeTag};
use bloom_script::chain_iface::{
    ArgDeclStub, ChainStateIface, FunctionDeclStub, PetalManifestStub,
};
use bloom_script::encode::{decode_ptb, encode_ptb};
use bloom_script::validator::{AlwaysOkVerifier, ValidationContext, ValidationMode, validate_ptb};
use bloom_script::{
    Command, MoveCmd, PetalRef, PqSignature, PtbTx,
    types::{Arg, ExpectedVersion, UseRef},
};

static ALWAYS_OK: AlwaysOkVerifier = AlwaysOkVerifier;

fn sample_view_marked_move_shape_ptb() -> PtbTx {
    PtbTx {
        signers: vec![[0x11; 32]],
        commands: vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: "/bloom/test/view".to_string(),
                hash: Some(Hash32([0x22; 32])),
            },
            function: "read_counter".to_string(),
            type_args: vec![],
            args: vec![Arg::Object {
                id: ObjectId([0x33; 32]),
                expected_version: ExpectedVersion(7),
                access_mode: bloom_objects::AccessMode::ReadOnly,
            }],
        })],
        gas_payer: ObjectId([0x44; 32]),
        gas_budget: 1_000,
        gas_price: 1,
        expiry_block: 99,
        signatures: vec![PqSignature(vec![0x55; 64])],
    }
}

#[derive(Default)]
struct TestChain {
    block: u64,
    objects: HashMap<ObjectId, Object>,
    petals: HashMap<Hash32, Vec<u8>>,
    manifests: HashMap<Hash32, PetalManifestStub>,
    paths: HashMap<String, Hash32>,
}

impl ChainStateIface for TestChain {
    fn load_object(&self, id: &ObjectId) -> Option<Object> {
        self.objects.get(id).cloned()
    }

    fn load_petal(&self, hash: &Hash32) -> Option<Vec<u8>> {
        self.petals.get(hash).cloned()
    }

    fn load_manifest(&self, hash: &Hash32) -> Option<PetalManifestStub> {
        self.manifests.get(hash).cloned()
    }

    fn resolve_path(&self, path: &str) -> Option<Hash32> {
        self.paths.get(path).copied()
    }

    fn current_block(&self) -> u64 {
        self.block
    }
}

fn counter_type() -> TypeTag {
    TypeTag::Concrete {
        petal_hash: [0x22; 32],
        type_name: "Counter".to_string(),
        type_args: vec![],
    }
}

fn loom_coin_type() -> TypeTag {
    bloom_script::loom_coin_type_tag(Hash32([0; 32]))
}

fn readonly_validation_ctx<'a>(chain: &'a TestChain) -> ValidationContext<'a> {
    ValidationContext {
        mode: ValidationMode::ReadOnly,
        current_block: chain.current_block(),
        chain,
        verifier: &ALWAYS_OK,
        loom_coin_type: loom_coin_type(),
    }
}

fn readonly_manifest(args: Vec<ArgDeclStub>) -> PetalManifestStub {
    PetalManifestStub {
        module_path: "/bloom/test/view".to_string(),
        functions: vec![FunctionDeclStub {
            view: true,
            name: "read_counter".to_string(),
            args,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn readonly_ptb(args: Vec<Arg>) -> PtbTx {
    PtbTx {
        signers: vec![],
        commands: vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: "/bloom/test/view".to_string(),
                hash: Some(Hash32([0x22; 32])),
            },
            function: "read_counter".to_string(),
            type_args: vec![],
            args,
        })],
        gas_payer: ObjectId([0xFE; 32]),
        gas_budget: 0,
        gas_price: 0,
        expiry_block: 10,
        signatures: vec![],
    }
}

#[test]
fn committed_ptb_wire_rejects_trailing_at_block_height() {
    let ptb = sample_view_marked_move_shape_ptb();
    let mut encoded = encode_ptb(&ptb).expect("ptb encodes");

    encoded.extend_from_slice(&42u64.to_be_bytes());

    assert!(
        decode_ptb(&encoded).is_err(),
        "committed PTB decoding must reject any out-of-band at_block payload"
    );
}

#[test]
fn committed_ptb_round_trip_has_no_snapshot_selector() {
    let ptb = sample_view_marked_move_shape_ptb();

    let decoded = decode_ptb(&encode_ptb(&ptb).expect("ptb encodes")).expect("ptb decodes");

    assert_eq!(decoded, ptb);
    assert_eq!(decoded.expiry_block, 99);
    assert_eq!(decoded.commands.len(), 1);
}

#[test]
fn ptb_wire_types_do_not_define_at_block() {
    let types_rs = include_str!("../src/types.rs");
    let encode_rs = include_str!("../src/encode.rs");

    assert!(!types_rs.contains("at_block"));
    assert!(!encode_rs.contains("at_block"));
}

#[test]
fn readonly_validation_allows_absent_signatures_and_no_gas_payer_coin() {
    let mut chain = TestChain {
        block: 1,
        ..Default::default()
    };
    chain
        .petals
        .insert(Hash32([0x22; 32]), vec![0, 97, 115, 109]);
    chain
        .manifests
        .insert(Hash32([0x22; 32]), readonly_manifest(vec![]));
    chain
        .paths
        .insert("/bloom/test/view".to_string(), Hash32([0x22; 32]));

    let validated = validate_ptb(&readonly_ptb(vec![]), &readonly_validation_ctx(&chain))
        .expect("ReadOnly validation should not require signatures or a gas coin");

    assert!(validated.tx.signers.is_empty());
    assert!(validated.tx.signatures.is_empty());
    assert!(!validated.objects.contains_key(&[0xFE; 32]));
}

#[test]
fn readonly_validation_coerces_object_args_to_readonly() {
    let mut chain = TestChain {
        block: 1,
        ..Default::default()
    };
    let object_id = ObjectId([0x33; 32]);
    chain.objects.insert(
        object_id,
        Object {
            id: object_id,
            type_tag: counter_type(),
            owner: Owner::Address([0xAA; 32]),
            version: 7,
            payload: vec![],
        },
    );
    chain
        .petals
        .insert(Hash32([0x22; 32]), vec![0, 97, 115, 109]);
    chain.manifests.insert(
        Hash32([0x22; 32]),
        readonly_manifest(vec![ArgDeclStub::Object {
            ty: counter_type(),
            mode: bloom_objects::AccessMode::ReadOnly,
        }]),
    );
    chain
        .paths
        .insert("/bloom/test/view".to_string(), Hash32([0x22; 32]));

    let validated = validate_ptb(
        &readonly_ptb(vec![Arg::Object {
            id: object_id,
            expected_version: ExpectedVersion(7),
            access_mode: bloom_objects::AccessMode::Mutable,
        }]),
        &readonly_validation_ctx(&chain),
    )
    .expect("ReadOnly validation should coerce object args to ReadOnly");

    let Command::Move(move_cmd) = &validated.tx.commands[0] else {
        panic!("expected Move command");
    };
    let Arg::Object { access_mode, .. } = &move_cmd.args[0] else {
        panic!("expected object arg");
    };
    assert_eq!(*access_mode, bloom_objects::AccessMode::ReadOnly);
}

#[test]
fn readonly_mode_rejects_transfer_objects() {
    let mut chain = TestChain {
        block: 1,
        ..Default::default()
    };
    chain
        .petals
        .insert(Hash32([0x22; 32]), vec![0, 97, 115, 109]);
    chain
        .manifests
        .insert(Hash32([0x22; 32]), readonly_manifest(vec![]));
    chain
        .paths
        .insert("/bloom/test/view".to_string(), Hash32([0x22; 32]));

    let tx = PtbTx {
        signers: vec![],
        commands: vec![
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/test/view".to_string(),
                    hash: Some(Hash32([0x22; 32])),
                },
                function: "read_counter".to_string(),
                type_args: vec![],
                args: vec![],
            }),
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: bloom_objects::Owner::Address([0xAA; 32]),
            },
        ],
        gas_payer: ObjectId([0xFE; 32]),
        gas_budget: 0,
        gas_price: 0,
        expiry_block: 10,
        signatures: vec![],
    };

    let err = validate_ptb(&tx, &readonly_validation_ctx(&chain)).unwrap_err();
    assert!(
        err.to_string().contains("read-only"),
        "TransferObjects must be rejected in read-only mode, got: {err}"
    );
}

#[test]
fn type_tag_json_codec_round_trips_supported_values_and_degrades_unknown_returns() {
    let u128_tag = TypeTag::Concrete {
        petal_hash: [0; 32],
        type_name: "u128".to_string(),
        type_args: vec![],
    };
    let bytes = bloom_script::decode_json_const(&u128_tag, &serde_json::json!("42")).unwrap();
    assert_eq!(bytes, 42u128.to_be_bytes());
    assert_eq!(
        bloom_script::decode_return_json(&u128_tag, &bytes).unwrap(),
        Some(serde_json::json!("42"))
    );

    let unknown = TypeTag::Concrete {
        petal_hash: [0; 32],
        type_name: "Opaque".to_string(),
        type_args: vec![],
    };
    assert_eq!(
        bloom_script::decode_return_json(&unknown, &[1, 2, 3]).unwrap(),
        None
    );
}
