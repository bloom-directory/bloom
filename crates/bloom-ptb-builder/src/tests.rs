//! Test suite for the front-door builder.
//!
//! Mirrors the `bloom_script::validator` test style: an in-memory
//! [`MockChain`] (path → hash → manifest + objects) and a battery of
//! grammar / pipe / resolver / error tests.

use std::cell::RefCell;
use std::collections::HashMap;

use bloom_chain_types::Hash32;
use bloom_objects::{AccessMode, Object, ObjectId, Owner, TypeTag};
use bloom_script::{
    Arg, ArgDeclStub, CORE_FUNGIBLE_PATH, ChainStateIface, Command, DEFAULT_FUNGIBLE_PETAL_HASH,
    ExpectedVersion, FunctionDeclStub, PetalManifestStub, TypeParamDeclStub,
};

use crate::error::{BuildError, ResolveError};
use crate::pipe::lower_pipe_expr;
use crate::resolver::{resolve_endpoint, split_endpoint_path};
use crate::session::PtbSession;

// ---------------------------------------------------------------------------
// Mock chain (modelled on validator.rs MockChain / put_petal)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockChain {
    objects: RefCell<HashMap<[u8; 32], Object>>,
    petals: RefCell<HashMap<[u8; 32], Vec<u8>>>,
    manifests: RefCell<HashMap<[u8; 32], PetalManifestStub>>,
    paths: RefCell<HashMap<String, Hash32>>,
    block: u64,
}

impl MockChain {
    fn new() -> Self {
        Self {
            block: 1,
            ..Default::default()
        }
    }
    fn put_object(&self, obj: Object) {
        self.objects.borrow_mut().insert(obj.id.0, obj);
    }
    fn put_petal(&self, hash: Hash32, manifest: PetalManifestStub) {
        self.petals.borrow_mut().insert(hash.0, vec![0]);
        self.manifests.borrow_mut().insert(hash.0, manifest);
    }
    fn put_path(&self, path: &str, hash: Hash32) {
        self.paths.borrow_mut().insert(path.to_string(), hash);
    }
}

impl ChainStateIface for MockChain {
    fn load_object(&self, id: &ObjectId) -> Option<Object> {
        self.objects.borrow().get(&id.0).cloned()
    }
    fn load_petal(&self, hash: &Hash32) -> Option<Vec<u8>> {
        self.petals.borrow().get(&hash.0).cloned()
    }
    fn load_manifest(&self, hash: &Hash32) -> Option<PetalManifestStub> {
        self.manifests.borrow().get(&hash.0).cloned()
    }
    fn resolve_path(&self, path: &str) -> Option<Hash32> {
        self.paths.borrow().get(path).copied()
    }
    fn current_block(&self) -> u64 {
        self.block
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const POOL_HASH: Hash32 = Hash32([0xAB; 32]);
const POOL_PATH: &str = "/bloom/petals/dex/pool";

fn concrete(name: &str) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: name.to_string(),
        type_args: vec![],
    }
}

fn func(name: &str, args: Vec<ArgDeclStub>, returns: Vec<TypeTag>) -> FunctionDeclStub {
    FunctionDeclStub {
        view: false,
        name: name.to_string(),
        type_params: vec![],
        args,
        returns,
        required_signers: 0,
        required_capabilities: vec![],
        attached_invariants: vec![],
    }
}

/// A chain with a pool petal carrying a battery of test functions.
fn chain_with_pool(funcs: Vec<FunctionDeclStub>) -> MockChain {
    let chain = MockChain::new();
    let manifest = PetalManifestStub {
        module_path: POOL_PATH.to_string(),
        functions: funcs,
        object_types: vec![],
        external_type_refs: vec![],
    };
    chain.put_petal(POOL_HASH, manifest);
    chain.put_path(POOL_PATH, POOL_HASH);
    chain
}

/// Set up a session with signer + gas payer + a `Coin<LOOM>` object so
/// `build_unsigned` can run the full validator.
fn ready_session(chain: &MockChain, signer: [u8; 32]) -> PtbSession<'_> {
    let gas_id = ObjectId([0xFE; 32]);
    chain.put_path(CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH);
    // 48-byte coin payload: [id placeholder (32)] || [value BE (16)]
    let mut payload = vec![0u8; 32];
    payload.extend_from_slice(&1_000_000u128.to_be_bytes());
    chain.put_object(Object {
        id: gas_id,
        type_tag: bloom_script::loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
        owner: Owner::Address(signer),
        version: 0,
        payload,
    });
    let mut s = PtbSession::new(chain);
    s.set_signers(vec![signer]);
    s.set_gas_payer(gas_id);
    s.set_expiry_block(100);
    s
}

// ===========================================================================
// Endpoint resolver
// ===========================================================================

#[test]
fn split_endpoint_path_basic() {
    assert_eq!(
        split_endpoint_path("/bloom/petals/dex/pool/swap").unwrap(),
        ("/bloom/petals/dex/pool", "swap")
    );
}

#[test]
fn split_endpoint_path_rejects_no_function() {
    assert!(matches!(
        split_endpoint_path("swap"),
        Err(ResolveError::MalformedPath { .. })
    ));
    // Trailing slash → empty function.
    assert!(matches!(
        split_endpoint_path("/bloom/petals/dex/pool/"),
        Err(ResolveError::MalformedPath { .. })
    ));
}

#[test]
fn resolve_endpoint_returns_hash_fn_abi() {
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let ep = resolve_endpoint(&chain, "/bloom/petals/dex/pool/swap").unwrap();
    assert_eq!(ep.petal_path, POOL_PATH);
    assert_eq!(ep.petal_hash, POOL_HASH);
    assert_eq!(ep.function, "swap");
    // The abi (signature) is reachable and correct.
    assert_eq!(ep.signature().name, "swap");
    assert_eq!(ep.signature().args.len(), 1);
}

#[test]
fn resolve_endpoint_unknown_path_fails_closed() {
    let chain = chain_with_pool(vec![func("swap", vec![], vec![])]);
    let err = resolve_endpoint(&chain, "/bloom/nope/swap").unwrap_err();
    assert!(matches!(err, ResolveError::UnknownPath { .. }));
}

#[test]
fn resolve_endpoint_unknown_function_fails_closed() {
    let chain = chain_with_pool(vec![func("swap", vec![], vec![])]);
    let err = resolve_endpoint(&chain, "/bloom/petals/dex/pool/absent").unwrap_err();
    assert!(matches!(err, ResolveError::UnknownFunction { .. }));
}

#[test]
fn resolve_endpoint_manifest_missing_fails_closed() {
    // Path resolves to a hash, but no manifest is stored under it.
    let chain = MockChain::new();
    chain.put_path(POOL_PATH, POOL_HASH);
    let err = resolve_endpoint(&chain, "/bloom/petals/dex/pool/swap").unwrap_err();
    assert!(matches!(err, ResolveError::ManifestNotFound { .. }));
}

// ===========================================================================
// Command-line grammar → expected commands (append_command)
// ===========================================================================

#[test]
fn append_signer_only_command() {
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let mut s = PtbSession::new(&chain);
    let idx = s
        .append_command("/bloom/petals/dex/pool/swap signer:0")
        .unwrap();
    assert_eq!(idx, 0);
    match &s.commands()[0] {
        Command::Move(m) => {
            assert_eq!(m.function, "swap");
            assert_eq!(m.petal.hash, Some(POOL_HASH));
            assert_eq!(m.args, vec![Arg::Signer(0)]);
        }
        _ => panic!("expected Move"),
    }
}

#[test]
fn append_const_literal_u64() {
    let chain = chain_with_pool(vec![func(
        "set",
        vec![ArgDeclStub::Const(concrete("u64"))],
        vec![],
    )]);
    let mut s = PtbSession::new(&chain);
    // positional form.
    s.append_command("/bloom/petals/dex/pool/set 980").unwrap();
    match &s.commands()[0] {
        Command::Move(m) => {
            assert_eq!(m.args, vec![Arg::Const(980u64.to_be_bytes().to_vec())]);
        }
        _ => panic!(),
    }

    // key=value form.
    let mut s2 = PtbSession::new(&chain);
    s2.append_command("/bloom/petals/dex/pool/set min-out=980")
        .unwrap();
    match &s2.commands()[0] {
        Command::Move(m) => {
            assert_eq!(m.args, vec![Arg::Const(980u64.to_be_bytes().to_vec())]);
        }
        _ => panic!(),
    }
}

#[test]
fn append_raw_const_bytes_preserves_abi_hex() {
    let chain = chain_with_pool(vec![func(
        "set",
        vec![ArgDeclStub::Const(concrete("u64"))],
        vec![],
    )]);
    let mut s = PtbSession::new(&chain);
    s.append_command("/bloom/petals/dex/pool/set const:0x00000000000003d4")
        .unwrap();
    match &s.commands()[0] {
        Command::Move(m) => {
            assert_eq!(m.args, vec![Arg::Const(980u64.to_be_bytes().to_vec())]);
        }
        _ => panic!(),
    }
}

#[test]
fn append_object_arg_with_version_and_mode() {
    let pool_obj = ObjectId([0x55; 32]);
    let chain = chain_with_pool(vec![func(
        "touch",
        vec![ArgDeclStub::Object {
            ty: concrete("Pool"),
            mode: AccessMode::Mutable,
        }],
        vec![],
    )]);
    chain.put_object(Object {
        id: pool_obj,
        type_tag: concrete("Pool"),
        owner: Owner::Shared,
        version: 3,
        payload: vec![],
    });
    let mut s = PtbSession::new(&chain);
    let id_hex = "55".repeat(32);
    s.append_command(&format!("/bloom/petals/dex/pool/touch obj:{id_hex}@3"))
        .unwrap();
    match &s.commands()[0] {
        Command::Move(m) => {
            assert_eq!(
                m.args,
                vec![Arg::Object {
                    id: pool_obj,
                    expected_version: ExpectedVersion(3),
                    access_mode: AccessMode::Mutable, // taken from the decl
                }]
            );
        }
        _ => panic!(),
    }
}

#[test]
fn append_type_arg_for_generic_endpoint() {
    let chain = chain_with_pool(vec![FunctionDeclStub {
        view: false,
        name: "identity".to_string(),
        type_params: vec![TypeParamDeclStub {
            name: "T".to_string(),
            phantom: false,
        }],
        args: vec![ArgDeclStub::TypeArg(0)],
        returns: vec![],
        required_signers: 0,
        required_capabilities: vec![],
        attached_invariants: vec![],
    }]);
    let mut s = PtbSession::new(&chain);
    s.append_command("/bloom/petals/dex/pool/identity type:USDC")
        .unwrap();
    match &s.commands()[0] {
        Command::Move(m) => {
            assert_eq!(m.type_args, vec![concrete("USDC")]);
            assert_eq!(m.args, vec![Arg::TypeArg(concrete("USDC"))]);
        }
        _ => panic!(),
    }
}

#[test]
fn append_call_type_arg_for_generic_endpoint_without_type_arg_value() {
    let chain = chain_with_pool(vec![FunctionDeclStub {
        view: false,
        name: "identity".to_string(),
        type_params: vec![TypeParamDeclStub {
            name: "T".to_string(),
            phantom: false,
        }],
        args: vec![],
        returns: vec![],
        required_signers: 0,
        required_capabilities: vec![],
        attached_invariants: vec![],
    }]);
    let mut s = PtbSession::new(&chain);
    s.append_command("/bloom/petals/dex/pool/identity type:USDC")
        .unwrap();
    match &s.commands()[0] {
        Command::Move(m) => {
            assert_eq!(m.type_args, vec![concrete("USDC")]);
            assert_eq!(m.args, vec![]);
        }
        _ => panic!(),
    }
}

#[test]
fn append_with_label_records_label() {
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let mut s = PtbSession::new(&chain);
    s.append_command("/bloom/petals/dex/pool/swap signer:0 as hop1")
        .unwrap();
    let status = s.status();
    assert_eq!(status.labels, vec![("hop1".to_string(), 0)]);
}

// ===========================================================================
// Use-edges: explicit @cmd.ret, label refs, linear chaining
// ===========================================================================

#[test]
fn explicit_use_edge_typechecks_against_upstream_return() {
    let chain = chain_with_pool(vec![
        func("producer", vec![], vec![concrete("u64")]),
        func(
            "consumer",
            vec![ArgDeclStub::Const(concrete("u64"))],
            vec![],
        ),
    ]);
    let mut s = PtbSession::new(&chain);
    s.append_command("/bloom/petals/dex/pool/producer").unwrap();
    let idx = s
        .append_command("/bloom/petals/dex/pool/consumer @0.0")
        .unwrap();
    assert_eq!(idx, 1);
    match &s.commands()[1] {
        Command::Move(m) => assert_eq!(
            m.args,
            vec![Arg::Use {
                cmd_idx: 0,
                ret_idx: 0
            }]
        ),
        _ => panic!(),
    }
}

#[test]
fn label_use_edge_resolves_to_producing_command() {
    let chain = chain_with_pool(vec![
        func("producer", vec![], vec![concrete("u64")]),
        func(
            "consumer",
            vec![ArgDeclStub::Const(concrete("u64"))],
            vec![],
        ),
    ]);
    let mut s = PtbSession::new(&chain);
    s.append_command("/bloom/petals/dex/pool/producer as p")
        .unwrap();
    s.append_command("/bloom/petals/dex/pool/consumer @p")
        .unwrap();
    match &s.commands()[1] {
        Command::Move(m) => assert_eq!(
            m.args,
            vec![Arg::Use {
                cmd_idx: 0,
                ret_idx: 0
            }]
        ),
        _ => panic!(),
    }
}

// ===========================================================================
// Error cases: each fails closed AND leaves the session unchanged
// ===========================================================================

#[test]
fn dangling_use_forward_ref_rejected_session_unchanged() {
    let chain = chain_with_pool(vec![func(
        "consumer",
        vec![ArgDeclStub::Const(concrete("u64"))],
        vec![],
    )]);
    let mut s = PtbSession::new(&chain);
    // @0.0 refers to a command that does not exist yet (this is cmd 0).
    let err = s
        .append_command("/bloom/petals/dex/pool/consumer @0.0")
        .unwrap_err();
    assert!(matches!(err, BuildError::DanglingUse { .. }));
    assert!(s.is_empty(), "session must be unchanged after a bad append");
}

#[test]
fn dangling_use_out_of_range_after_one_command() {
    let chain = chain_with_pool(vec![
        func("producer", vec![], vec![concrete("u64")]),
        func(
            "consumer",
            vec![ArgDeclStub::Const(concrete("u64"))],
            vec![],
        ),
    ]);
    let mut s = PtbSession::new(&chain);
    s.append_command("/bloom/petals/dex/pool/producer").unwrap();
    // @5.0 — no such command.
    let err = s
        .append_command("/bloom/petals/dex/pool/consumer @5.0")
        .unwrap_err();
    assert!(matches!(err, BuildError::DanglingUse { .. }));
    assert_eq!(s.len(), 1, "only the good command remains");
}

#[test]
fn unknown_label_rejected() {
    let chain = chain_with_pool(vec![func(
        "consumer",
        vec![ArgDeclStub::Const(concrete("u64"))],
        vec![],
    )]);
    let mut s = PtbSession::new(&chain);
    let err = s
        .append_command("/bloom/petals/dex/pool/consumer @nope")
        .unwrap_err();
    assert!(matches!(err, BuildError::UnknownLabel(ref l) if l == "nope"));
    assert!(s.is_empty());
}

#[test]
fn use_edge_type_mismatch_rejected() {
    // producer returns u64; consumer wants u128 — mismatch.
    let chain = chain_with_pool(vec![
        func("producer", vec![], vec![concrete("u64")]),
        func(
            "consumer",
            vec![ArgDeclStub::Const(concrete("u128"))],
            vec![],
        ),
    ]);
    let mut s = PtbSession::new(&chain);
    s.append_command("/bloom/petals/dex/pool/producer").unwrap();
    let err = s
        .append_command("/bloom/petals/dex/pool/consumer @0.0")
        .unwrap_err();
    match err {
        BuildError::Validation(bloom_script::PtbError::TypeMismatch { reason, .. }) => {
            assert!(
                reason.contains("u64") && reason.contains("u128"),
                "{reason}"
            );
        }
        other => panic!("expected TypeMismatch, got {other:?}"),
    }
    assert_eq!(s.len(), 1);
}

#[test]
fn const_type_mismatch_rejected() {
    let chain = chain_with_pool(vec![func(
        "set",
        vec![ArgDeclStub::Const(concrete("ObjectId"))],
        vec![],
    )]);
    let mut s = PtbSession::new(&chain);
    // ObjectId requires 32 bytes; "0xAA" is 1 byte.
    let err = s
        .append_command("/bloom/petals/dex/pool/set 0xAA")
        .unwrap_err();
    // Length is caught at literal-encoding time (Parse) — fails closed.
    assert!(matches!(err, BuildError::Parse(_)));
    assert!(s.is_empty());
}

#[test]
fn const_bytes_invalid_caught_by_validator() {
    // A `u64` declared arg but a too-short hex literal that the literal
    // encoder accepts as opaque-ish — exercise the validator path by
    // declaring an unknown type so the literal encoder defers and the
    // validator's canonical check is the gate. Here we use a vector<u64>
    // const fed wrong bytes through hex so the validator rejects length.
    let chain = chain_with_pool(vec![func(
        "set",
        vec![ArgDeclStub::Const(TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "vector".to_string(),
            type_args: vec![concrete("u64")],
        })],
        vec![],
    )]);
    let mut s = PtbSession::new(&chain);
    // 0x000000 03 claims 3 elements but provides none → validator Invalid.
    let err = s
        .append_command("/bloom/petals/dex/pool/set 0x00000003")
        .unwrap_err();
    assert!(matches!(
        err,
        BuildError::Validation(bloom_script::PtbError::TypeMismatch { .. })
    ));
    assert!(s.is_empty());
}

#[test]
fn unknown_path_rejected_session_unchanged() {
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let mut s = PtbSession::new(&chain);
    let err = s.append_command("/bloom/nope/swap signer:0").unwrap_err();
    assert!(matches!(
        err,
        BuildError::Resolve(ResolveError::UnknownPath { .. })
    ));
    assert!(s.is_empty());
}

#[test]
fn unknown_function_rejected() {
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let mut s = PtbSession::new(&chain);
    let err = s
        .append_command("/bloom/petals/dex/pool/absent signer:0")
        .unwrap_err();
    assert!(matches!(
        err,
        BuildError::Resolve(ResolveError::UnknownFunction { .. })
    ));
    assert!(s.is_empty());
}

#[test]
fn arity_mismatch_rejected() {
    let chain = chain_with_pool(vec![func(
        "swap",
        vec![ArgDeclStub::Signer, ArgDeclStub::Const(concrete("u64"))],
        vec![],
    )]);
    let mut s = PtbSession::new(&chain);
    // Only one arg given; function wants two.
    let err = s
        .append_command("/bloom/petals/dex/pool/swap signer:0")
        .unwrap_err();
    assert!(matches!(err, BuildError::Parse(_)));
    assert!(s.is_empty());

    // Too many args.
    let err2 = s
        .append_command("/bloom/petals/dex/pool/swap signer:0 980 990")
        .unwrap_err();
    assert!(matches!(err2, BuildError::Parse(_)));
    assert!(s.is_empty());
}

#[test]
fn arg_kind_mismatch_rejected() {
    // Function wants a Signer; we pass a literal.
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let mut s = PtbSession::new(&chain);
    let err = s
        .append_command("/bloom/petals/dex/pool/swap 980")
        .unwrap_err();
    assert!(matches!(err, BuildError::Parse(_)));
    assert!(s.is_empty());
}

#[test]
fn empty_line_rejected() {
    let chain = chain_with_pool(vec![func("swap", vec![], vec![])]);
    let mut s = PtbSession::new(&chain);
    assert!(matches!(s.append_command("   "), Err(BuildError::Parse(_))));
}

// ===========================================================================
// status() + abort()
// ===========================================================================

#[test]
fn status_reports_endpoints_returns_and_gas() {
    let chain = chain_with_pool(vec![
        func("producer", vec![], vec![concrete("u64")]),
        func(
            "consumer",
            vec![ArgDeclStub::Const(concrete("u64"))],
            vec![],
        ),
    ]);
    let mut s = PtbSession::new(&chain);
    s.append_command("/bloom/petals/dex/pool/producer as p")
        .unwrap();
    s.append_command("/bloom/petals/dex/pool/consumer @p")
        .unwrap();
    let st = s.status();
    assert_eq!(st.commands.len(), 2);
    assert_eq!(
        st.commands[0].endpoint_path,
        "/bloom/petals/dex/pool/producer"
    );
    assert_eq!(st.commands[0].return_types, vec![concrete("u64")]);
    assert_eq!(st.commands[0].label, Some("p".to_string()));
    assert_eq!(st.commands[1].return_types, vec![]);
    assert_eq!(st.estimated_gas, 1_000_000);
    assert!(!st.gas_payer_set);
    assert_eq!(st.signer_count, 0);
}

#[test]
fn abort_discards_state() {
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let mut s = PtbSession::new(&chain);
    s.append_command("/bloom/petals/dex/pool/swap signer:0 as x")
        .unwrap();
    assert_eq!(s.len(), 1);
    s.abort();
    assert!(s.is_empty());
    assert!(s.status().labels.is_empty());
    // The label table is cleared, so a fresh append starts at index 0.
    let idx = s
        .append_command("/bloom/petals/dex/pool/swap signer:0")
        .unwrap();
    assert_eq!(idx, 0);
}

// ===========================================================================
// build_unsigned (commit/sign seam) + readiness gating
// ===========================================================================

#[test]
fn build_unsigned_requires_signers_and_gas_payer() {
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let mut s = PtbSession::new(&chain);
    // No commands yet.
    assert!(matches!(s.build_unsigned(), Err(BuildError::NotReady(_))));
    s.append_command("/bloom/petals/dex/pool/swap signer:0")
        .unwrap();
    // No signers / gas payer.
    assert!(matches!(s.build_unsigned(), Err(BuildError::NotReady(_))));
}

#[test]
fn build_unsigned_assembles_and_validates() {
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let signer = [0x11; 32];
    let mut s = ready_session(&chain, signer);
    s.append_command("/bloom/petals/dex/pool/swap signer:0")
        .unwrap();
    let tx = s.build_unsigned().unwrap();
    assert_eq!(tx.signers, vec![signer]);
    assert_eq!(tx.commands.len(), 1);
    assert!(tx.signatures.is_empty(), "unsigned: Phase D fills sigs");
    // The digest is computable (what Phase D signs).
    let _digest = tx.signing_digest();
}

#[test]
fn build_unsigned_derives_fungible_hash_from_chain_vfs() {
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let signer = [0x11; 32];
    let fungible_hash = Hash32([0x44; 32]);
    chain.put_path(CORE_FUNGIBLE_PATH, fungible_hash);

    let gas_id = ObjectId([0xFE; 32]);
    let mut payload = vec![0u8; 32];
    payload.extend_from_slice(&1_000_000u128.to_be_bytes());
    chain.put_object(Object {
        id: gas_id,
        type_tag: bloom_script::loom_coin_type_tag(fungible_hash),
        owner: Owner::Address(signer),
        version: 0,
        payload,
    });

    let mut s = PtbSession::new(&chain);
    s.set_signers(vec![signer]);
    s.set_gas_payer(gas_id);
    s.set_expiry_block(100);
    s.append_command("/bloom/petals/dex/pool/swap signer:0")
        .unwrap();

    let tx = s.build_unsigned().unwrap();
    assert_eq!(tx.gas_payer, gas_id);
}

#[test]
fn build_unsigned_requires_fungible_vfs_binding_without_override() {
    let chain = chain_with_pool(vec![func("swap", vec![ArgDeclStub::Signer], vec![])]);
    let signer = [0x11; 32];
    let gas_id = ObjectId([0xFE; 32]);
    let mut payload = vec![0u8; 32];
    payload.extend_from_slice(&1_000_000u128.to_be_bytes());
    chain.put_object(Object {
        id: gas_id,
        type_tag: bloom_script::loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
        owner: Owner::Address(signer),
        version: 0,
        payload,
    });

    let mut s = PtbSession::new(&chain);
    s.set_signers(vec![signer]);
    s.set_gas_payer(gas_id);
    s.set_expiry_block(100);
    s.append_command("/bloom/petals/dex/pool/swap signer:0")
        .unwrap();

    let err = s.build_unsigned().unwrap_err();
    assert!(
        matches!(err, BuildError::NotReady(ref msg) if msg.contains(CORE_FUNGIBLE_PATH)),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// Pipe-expression lowering (§3.5)
// ===========================================================================

#[test]
fn lower_linear_pipe_inserts_use_edges() {
    let lines = lower_pipe_expr(
        "/bloom/petals/dex/pool/a | /bloom/petals/dex/pool/b | /bloom/petals/dex/pool/c",
    )
    .unwrap();
    assert_eq!(
        lines,
        vec![
            "/bloom/petals/dex/pool/a".to_string(),
            "/bloom/petals/dex/pool/b @0.0".to_string(),
            "/bloom/petals/dex/pool/c @1.0".to_string(),
        ]
    );
}

#[test]
fn lower_linear_pipe_keeps_stage_args() {
    let lines = lower_pipe_expr(
        "/bloom/petals/dex/pool/spend 1000 | /bloom/petals/dex/pool/swap min-out=980",
    )
    .unwrap();
    assert_eq!(
        lines,
        vec![
            "/bloom/petals/dex/pool/spend 1000".to_string(),
            "/bloom/petals/dex/pool/swap @0.0 min-out=980".to_string(),
        ]
    );
}

#[test]
fn lower_named_dag_inputs() {
    // add-liquidity DAG (litmus 5.3): two sub-pipes feed --a and --b.
    let lines = lower_pipe_expr(
        "/bloom/petals/dex/pool/add-liquidity --a <(/bloom/petals/dex/pool/spend-eth)> --b <(/bloom/petals/dex/pool/spend-usdc)> min-lp=10 | /bloom/wallet/receive",
    )
    .unwrap();
    // Sub-expressions lower first (cmd 0, cmd 1), then the main stage
    // (cmd 2) binds --a/--b to them, then receive (cmd 3) chains.
    assert_eq!(
        lines,
        vec![
            "/bloom/petals/dex/pool/spend-eth".to_string(),
            "/bloom/petals/dex/pool/spend-usdc".to_string(),
            "/bloom/petals/dex/pool/add-liquidity min-lp=10 a=@0.0 b=@1.0".to_string(),
            "/bloom/wallet/receive @2.0".to_string(),
        ]
    );
}

#[test]
fn lower_named_dag_inputs_are_name_ordered() {
    let lines = lower_pipe_expr(
        "/bloom/petals/dex/pool/add-liquidity --b <(/bloom/petals/dex/pool/spend-usdc)> --a <(/bloom/petals/dex/pool/spend-eth)> --min-lp 10",
    )
    .unwrap();
    assert_eq!(
        lines,
        vec![
            "/bloom/petals/dex/pool/spend-usdc".to_string(),
            "/bloom/petals/dex/pool/spend-eth".to_string(),
            "/bloom/petals/dex/pool/add-liquidity min-lp=10 a=@1.0 b=@0.0".to_string(),
        ]
    );
}

#[test]
fn lower_pipe_accepts_scalar_flags_next_to_named_inputs() {
    let lines = lower_pipe_expr(
        "/bloom/petals/dex/pool/add-liquidity --min-lp 10 --a <(/bloom/petals/dex/pool/spend-eth)>",
    )
    .unwrap();
    assert_eq!(
        lines,
        vec![
            "/bloom/petals/dex/pool/spend-eth".to_string(),
            "/bloom/petals/dex/pool/add-liquidity min-lp=10 a=@0.0".to_string(),
        ]
    );
}

#[test]
fn lower_pipe_rejects_unbalanced_subexpr() {
    let err = lower_pipe_expr("/bloom/x --a <(/bloom/y").unwrap_err();
    assert!(matches!(err, BuildError::Parse(_)));
}

#[test]
fn lower_pipe_rejects_empty_stage() {
    let err = lower_pipe_expr("/bloom/x | | /bloom/y").unwrap_err();
    assert!(matches!(err, BuildError::Parse(_)));
}

// ===========================================================================
// End-to-end: pipe expr → session → validated PtbTx (linear + DAG)
// ===========================================================================

#[test]
fn pipe_to_session_linear_two_hop() {
    // spend() -> Coin<LOOM>; swap(Coin<LOOM>) -> Coin<LOOM>; receive(Coin<LOOM>).
    let coin = TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: "Coin".to_string(),
        type_args: vec![concrete("LOOM")],
    };
    let chain = chain_with_pool(vec![
        func("spend", vec![], vec![coin.clone()]),
        func(
            "swap",
            vec![ArgDeclStub::Object {
                ty: coin.clone(),
                mode: AccessMode::Consume,
            }],
            vec![coin.clone()],
        ),
        func(
            "receive",
            vec![ArgDeclStub::Object {
                ty: coin.clone(),
                mode: AccessMode::Consume,
            }],
            vec![],
        ),
    ]);
    let signer = [0x11; 32];
    let mut s = ready_session(&chain, signer);
    let lines =
        lower_pipe_expr("/bloom/petals/dex/pool/spend | /bloom/petals/dex/pool/swap | /bloom/petals/dex/pool/receive")
            .unwrap();
    for line in &lines {
        s.append_command(line).unwrap();
    }
    assert_eq!(s.len(), 3);
    // Verify the use-edges wired up: swap consumes spend's output, etc.
    match &s.commands()[1] {
        Command::Move(m) => assert_eq!(
            m.args,
            vec![Arg::Use {
                cmd_idx: 0,
                ret_idx: 0
            }]
        ),
        _ => panic!(),
    }
    match &s.commands()[2] {
        Command::Move(m) => assert_eq!(
            m.args,
            vec![Arg::Use {
                cmd_idx: 1,
                ret_idx: 0
            }]
        ),
        _ => panic!(),
    }
    // Full plan validates.
    let tx = s.build_unsigned().unwrap();
    assert_eq!(tx.commands.len(), 3);
}

#[test]
fn pipe_to_session_dag_add_liquidity() {
    // spend_eth() -> Coin<ETH>; spend_usdc() -> Coin<USDC>;
    // add_liquidity(min_lp:u64, a:Coin<ETH>, b:Coin<USDC>) -> Coin<LP>.
    let coin = |inner: &str| TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: "Coin".to_string(),
        type_args: vec![concrete(inner)],
    };
    let chain = chain_with_pool(vec![
        func("spend_eth", vec![], vec![coin("ETH")]),
        func("spend_usdc", vec![], vec![coin("USDC")]),
        func(
            "add_liquidity",
            vec![
                ArgDeclStub::Const(concrete("u64")),
                ArgDeclStub::Object {
                    ty: coin("ETH"),
                    mode: AccessMode::Consume,
                },
                ArgDeclStub::Object {
                    ty: coin("USDC"),
                    mode: AccessMode::Consume,
                },
            ],
            vec![coin("LP")],
        ),
    ]);
    let signer = [0x22; 32];
    let mut s = ready_session(&chain, signer);
    let lines = lower_pipe_expr(
        "/bloom/petals/dex/pool/add_liquidity --b <(/bloom/petals/dex/pool/spend_usdc)> --a <(/bloom/petals/dex/pool/spend_eth)> --min-lp 10",
    )
    .unwrap();
    // Sub-pipes first, then add_liquidity.
    for line in &lines {
        s.append_command(line).unwrap();
    }
    assert_eq!(s.len(), 3);
    match &s.commands()[2] {
        Command::Move(m) => {
            assert_eq!(m.function, "add_liquidity");
            // min-lp const, then the two consumed-coin use-edges.
            assert_eq!(
                m.args,
                vec![
                    Arg::Const(10u64.to_be_bytes().to_vec()),
                    Arg::Use {
                        cmd_idx: 1,
                        ret_idx: 0
                    },
                    Arg::Use {
                        cmd_idx: 0,
                        ret_idx: 0
                    },
                ]
            );
        }
        _ => panic!(),
    }
    let tx = s.build_unsigned().unwrap();
    assert_eq!(tx.commands.len(), 3);
}
