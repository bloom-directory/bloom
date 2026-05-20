//! Pre-execution PTB validator (spec §7.2 steps 1–6).
//!
//! Inputs are immutable. On success the validator returns a
//! [`ValidatedPtb`] that bundles the original [`PtbTx`] with
//! pre-loaded chain artefacts (objects, petals, manifests) the
//! executor would otherwise refetch.

use std::collections::HashMap;

use bloom_objects::{AccessMode, Object, ObjectId, Owner, TypeTag};

use crate::chain_iface::{ArgDeclStub, ChainStateIface, FunctionDeclStub, PetalManifestStub};
use crate::error::PtbError;
use crate::types::{Arg, Command, ExpectedVersion, MoveCmd, PtbTx};

/// Verifies an xDSA signature against (`digest`, `pubkey`).
///
/// The real implementation lives in `bloom-keystore` (composite
/// ML-DSA-65 + Ed25519). Tests use [`AlwaysOkVerifier`] /
/// [`ProgrammedVerifier`].
pub trait SignatureVerifier {
    /// Returns `true` iff `signature` is a valid xDSA signature over
    /// `digest` by the key whose 32-byte identifier is `pubkey`.
    fn verify(&self, digest: &[u8; 32], pubkey: &[u8; 32], signature: &[u8]) -> bool;
}

/// Verifier that accepts every signature. Useful in tests where the
/// focus is the validator's structural checks, not crypto.
#[derive(Default)]
pub struct AlwaysOkVerifier;

impl SignatureVerifier for AlwaysOkVerifier {
    fn verify(&self, _digest: &[u8; 32], _pubkey: &[u8; 32], _signature: &[u8]) -> bool {
        true
    }
}

/// Per-PTB validation context.
///
/// Holds the current block height (for expiry), the chain interface
/// (for object/petal/manifest lookups), a signature verifier, and the
/// well-known `Coin<LOOM>` type tag the validator uses to recognise
/// the gas payer.
pub struct ValidationContext<'a> {
    /// Current block height.
    pub current_block: u64,
    /// Chain reader.
    pub chain: &'a dyn ChainStateIface,
    /// Signature verifier.
    pub verifier: &'a dyn SignatureVerifier,
    /// Well-known `Coin<LOOM>` type tag (spec §9.4).
    pub loom_coin_type: TypeTag,
}

/// Output of [`validate_ptb`]: the original transaction plus the
/// pre-loaded chain artefacts needed by the executor.
#[derive(Debug)]
pub struct ValidatedPtb {
    /// Original transaction (unchanged).
    pub tx: PtbTx,
    /// Pre-loaded objects keyed by id (covers every `Arg::Object`
    /// reference *and* the gas-payer).
    pub objects: HashMap<[u8; 32], Object>,
    /// Pre-loaded petal wasm bytes keyed by content hash.
    pub petals: HashMap<[u8; 32], Vec<u8>>,
    /// Pre-loaded manifests keyed by content hash.
    pub manifests: HashMap<[u8; 32], PetalManifestStub>,
    /// First-signer address (used by the executor's gas accounting).
    pub first_signer_addr: [u8; 32],
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the full validation pipeline (spec §7.2 steps 1–6).
pub fn validate_ptb(tx: &PtbTx, ctx: &ValidationContext<'_>) -> Result<ValidatedPtb, PtbError> {
    // Step 1: signature check.
    if tx.signers.is_empty() {
        return Err(PtbError::NoSigners);
    }
    if tx.signatures.len() != tx.signers.len() {
        return Err(PtbError::SignatureCountMismatch {
            expected: tx.signers.len(),
            got: tx.signatures.len(),
        });
    }
    let digest = tx.signing_digest();
    for (i, (pk, sig)) in tx.signers.iter().zip(tx.signatures.iter()).enumerate() {
        if !ctx.verifier.verify(&digest, pk, &sig.0) {
            return Err(PtbError::BadSignature {
                signer_idx: i as u16,
            });
        }
    }

    // Step 2: expiry.
    if ctx.current_block > tx.expiry_block {
        return Err(PtbError::Expired {
            current_block: ctx.current_block,
            expiry_block: tx.expiry_block,
        });
    }

    // Step 3: petal resolution.
    let mut petals: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    let mut manifests: HashMap<[u8; 32], PetalManifestStub> = HashMap::new();
    for cmd in &tx.commands {
        match cmd {
            Command::Move(m) => resolve_petal(&m.petal, ctx, &mut petals, &mut manifests)?,
            Command::UpgradePetal(_) | Command::Publish(_) => {
                // Publish / Upgrade don't require a pre-resolved petal;
                // the executor handles them directly.
            }
            _ => {}
        }
    }

    // Step 4: function-signature typecheck (after manifests are loaded).
    for (cmd_idx, cmd) in tx.commands.iter().enumerate() {
        if let Command::Move(m) = cmd {
            // Safety: step 3 above already inserted a manifest for any
            // pinned-hash MoveCmd. Unpinned refs already returned
            // PetalNotPinned.
            let hash = m
                .petal
                .hash
                .ok_or_else(|| PtbError::PetalNotPinned {
                    path: m.petal.path.clone(),
                })?;
            let manifest = manifests.get(&hash.0).ok_or(PtbError::PetalNotFound { hash })?;
            typecheck_move_cmd(m, manifest, cmd_idx)?;
        }
    }

    // Step 5: object version + access check.
    let mut objects: HashMap<[u8; 32], Object> = HashMap::new();
    let first_signer_addr = tx.signers[0];
    for cmd in &tx.commands {
        if let Command::Move(m) = cmd {
            for arg in &m.args {
                if let Arg::Object {
                    id,
                    expected_version,
                    access_mode,
                } = arg
                {
                    check_object_arg(
                        ctx.chain,
                        id,
                        *expected_version,
                        *access_mode,
                        &first_signer_addr,
                        &mut objects,
                    )?;
                }
            }
        }
    }

    // Step 6: gas-payer prep.
    let gas_obj = ctx
        .chain
        .load_object(&tx.gas_payer)
        .ok_or(PtbError::ObjectNotFound { id: tx.gas_payer })?;
    if gas_obj.owner != Owner::Address(first_signer_addr) {
        return Err(PtbError::InvalidGasPayer {
            id: tx.gas_payer,
            reason: format!(
                "gas payer is not owned by first signer ({})",
                hex_encode(&first_signer_addr)
            ),
        });
    }
    if gas_obj.type_tag != ctx.loom_coin_type {
        return Err(PtbError::InvalidGasPayer {
            id: tx.gas_payer,
            reason: "gas payer is not a Coin<LOOM>".to_string(),
        });
    }
    let coin_value = decode_coin_value(&gas_obj.payload)?;
    let needed = tx.required_gas_reservation();
    if coin_value < needed {
        return Err(PtbError::InsufficientGas {
            needed,
            available: coin_value,
        });
    }
    objects.insert(gas_obj.id.0, gas_obj);

    Ok(ValidatedPtb {
        tx: tx.clone(),
        objects,
        petals,
        manifests,
        first_signer_addr,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_petal(
    petal: &crate::types::PetalRef,
    ctx: &ValidationContext<'_>,
    petals: &mut HashMap<[u8; 32], Vec<u8>>,
    manifests: &mut HashMap<[u8; 32], PetalManifestStub>,
) -> Result<(), PtbError> {
    let hash = petal.hash.ok_or_else(|| PtbError::PetalNotPinned {
        path: petal.path.clone(),
    })?;
    if let std::collections::hash_map::Entry::Vacant(entry) = petals.entry(hash.0) {
        let wasm = ctx
            .chain
            .load_petal(&hash)
            .ok_or(PtbError::PetalNotFound { hash })?;
        entry.insert(wasm);
    }
    if let std::collections::hash_map::Entry::Vacant(entry) = manifests.entry(hash.0) {
        let manifest = ctx
            .chain
            .load_manifest(&hash)
            .ok_or(PtbError::PetalNotFound { hash })?;
        entry.insert(manifest);
    }

    // If the petal also names a path, verify the on-chain VFS binding
    // resolves to the same hash. An unbound path is permissive — v0
    // allows pure-hash publishing.
    if !petal.path.is_empty()
        && let Some(bound) = ctx.chain.resolve_path(&petal.path)
        && bound != hash
    {
        return Err(PtbError::PetalPathHashMismatch {
            path: petal.path.clone(),
            expected: hash,
            found: bound,
        });
    }
    Ok(())
}

fn typecheck_move_cmd(
    cmd: &MoveCmd,
    manifest: &PetalManifestStub,
    _cmd_idx: usize,
) -> Result<(), PtbError> {
    let hash = cmd
        .petal
        .hash
        .ok_or_else(|| PtbError::PetalNotPinned {
            path: cmd.petal.path.clone(),
        })?;
    let f: &FunctionDeclStub = manifest.function(&cmd.function).ok_or_else(|| {
        PtbError::UnknownFunction {
            function: cmd.function.clone(),
            petal_hash: hash,
        }
    })?;

    if cmd.type_args.len() != f.type_params.len() {
        return Err(PtbError::TypeArgCountMismatch {
            function: cmd.function.clone(),
            expected: f.type_params.len(),
            got: cmd.type_args.len(),
        });
    }

    if cmd.args.len() != f.args.len() {
        return Err(PtbError::ArgCountMismatch {
            function: cmd.function.clone(),
            expected: f.args.len(),
            got: cmd.args.len(),
        });
    }

    for (i, (arg, decl)) in cmd.args.iter().zip(f.args.iter()).enumerate() {
        match (arg, decl) {
            (Arg::Signer(_), ArgDeclStub::Signer) => {}
            (Arg::Const(_), ArgDeclStub::Const(_)) => {
                // Type-checking the bytes against the declared TypeTag
                // is the petal runtime's job — at PTB-validation time
                // we only know it's "a Const" vs. "not a Const".
            }
            (
                Arg::Object {
                    access_mode: amode,
                    ..
                },
                ArgDeclStub::Object { mode, .. },
            ) => {
                if amode != mode {
                    return Err(PtbError::TypeMismatch {
                        function: cmd.function.clone(),
                        arg_idx: i,
                        reason: format!(
                            "access mode {amode:?} does not match declared {mode:?}"
                        ),
                    });
                }
            }
            (Arg::Use { .. }, ArgDeclStub::Object { .. } | ArgDeclStub::Const(_)) => {
                // A `Use` may stand in for an Object or a Const arg
                // (it's the result of an earlier command). Detailed
                // type matching happens once the executor has produced
                // the upstream value; here we accept the shape.
            }
            (Arg::TypeArg(_), ArgDeclStub::TypeArg(_)) => {}
            (a, d) => {
                return Err(PtbError::TypeMismatch {
                    function: cmd.function.clone(),
                    arg_idx: i,
                    reason: format!("got {}, expected {}", arg_label(a), decl_label(d)),
                });
            }
        }
    }

    Ok(())
}

fn arg_label(a: &Arg) -> &'static str {
    match a {
        Arg::Signer(_) => "Signer",
        Arg::Const(_) => "Const",
        Arg::Object { .. } => "Object",
        Arg::Use { .. } => "Use",
        Arg::TypeArg(_) => "TypeArg",
    }
}

fn decl_label(d: &ArgDeclStub) -> &'static str {
    match d {
        ArgDeclStub::Signer => "Signer",
        ArgDeclStub::Const(_) => "Const",
        ArgDeclStub::Object { .. } => "Object",
        ArgDeclStub::TypeArg(_) => "TypeArg",
    }
}

fn check_object_arg(
    chain: &dyn ChainStateIface,
    id: &ObjectId,
    expected_version: ExpectedVersion,
    mode: AccessMode,
    first_signer_addr: &[u8; 32],
    objects: &mut HashMap<[u8; 32], Object>,
) -> Result<(), PtbError> {
    let obj = match objects.get(&id.0) {
        Some(o) => o.clone(),
        None => {
            let loaded = chain
                .load_object(id)
                .ok_or(PtbError::ObjectNotFound { id: *id })?;
            objects.insert(id.0, loaded.clone());
            loaded
        }
    };
    if obj.version != expected_version.0 {
        return Err(PtbError::ObjectVersionMismatch {
            id: *id,
            expected: expected_version.0,
            found: obj.version,
        });
    }
    check_access_mode(&obj.owner, mode, first_signer_addr, id)?;
    Ok(())
}

fn check_access_mode(
    owner: &Owner,
    mode: AccessMode,
    first_signer_addr: &[u8; 32],
    id: &ObjectId,
) -> Result<(), PtbError> {
    match (owner, mode) {
        (Owner::Immutable, AccessMode::ReadOnly) => Ok(()),
        (Owner::Immutable, _) => Err(PtbError::AccessDenied {
            id: *id,
            mode,
            reason: "immutable objects support ReadOnly only".to_string(),
        }),
        (Owner::Shared, _) => Ok(()),
        (Owner::Address(addr), AccessMode::Mutable | AccessMode::Consume) => {
            if addr == first_signer_addr {
                Ok(())
            } else {
                Err(PtbError::AccessDenied {
                    id: *id,
                    mode,
                    reason: "only the owning address may take Mutable/Consume".to_string(),
                })
            }
        }
        (Owner::Address(_), AccessMode::ReadOnly) => Ok(()),
        (Owner::Object(_), _) => {
            // v0 stub: object-owned access requires walking the borrow
            // chain (spec §4.3). The detailed walk is implemented by
            // the executor once it loads the parent. At validate-time
            // we accept all modes; the executor enforces the chain.
            Ok(())
        }
    }
}

/// Lowercase hex-encode a byte slice (no external dep).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Extract a `Coin<T>::value` from a `Coin` payload. The fungible
/// petal's canonical payload layout in v0 is `u128 BE value`; later
/// fields (e.g. metadata) append after. The chain only needs the
/// first 16 bytes for the gas check.
pub fn decode_coin_value(payload: &[u8]) -> Result<u128, PtbError> {
    if payload.len() < 16 {
        return Err(PtbError::InvalidGasPayer {
            id: ObjectId([0; 32]),
            reason: format!("coin payload too short ({} bytes)", payload.len()),
        });
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&payload[..16]);
    Ok(u128::from_be_bytes(a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_iface::{ArgDeclStub, FunctionDeclStub};
    use crate::types::{Arg, Command, ExpectedVersion, MoveCmd, PetalRef, PqSignature, PtbTx};
    use bloom_chain_types::Hash32;
    use bloom_objects::{Owner, TypeTag};
    use std::cell::RefCell;
    use std::collections::HashMap;

    // -----------------------------------------------------------------
    // Test scaffolding: mock chain + verifiers
    // -----------------------------------------------------------------

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
        fn put_petal(&self, hash: Hash32, wasm: Vec<u8>, manifest: PetalManifestStub) {
            self.petals.borrow_mut().insert(hash.0, wasm);
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

    fn loom_coin_tt() -> TypeTag {
        crate::types::loom_coin_type_tag(Hash32([0; 32]))
    }

    fn coin_obj(id_byte: u8, owner: [u8; 32], value: u128, version: u64) -> Object {
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: loom_coin_tt(),
            owner: Owner::Address(owner),
            version,
            payload: value.to_be_bytes().to_vec(),
        }
    }

    fn sample_manifest() -> PetalManifestStub {
        PetalManifestStub {
            module_path: "/bloom/dex/pool".to_string(),
            functions: vec![FunctionDeclStub {
                name: "swap".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Signer],
                returns: vec![],
                attached_invariants: vec![],
            }],
            object_types: vec![],
            external_type_refs: vec![],
        }
    }

    fn sample_ptb(signer: [u8; 32], gas_payer_id: ObjectId, expiry: u64) -> PtbTx {
        PtbTx {
            signers: vec![signer],
            commands: vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(Hash32([0xAB; 32])),
                },
                function: "swap".to_string(),
                type_args: vec![],
                args: vec![Arg::Signer(0)],
            })],
            gas_payer: gas_payer_id,
            gas_budget: 100,
            gas_price: 1,
            expiry_block: expiry,
            signatures: vec![PqSignature(vec![0xCC; 8])],
        }
    }

    fn setup() -> (MockChain, [u8; 32], ObjectId) {
        let chain = MockChain::new();
        let signer = [0x11; 32];
        let gas_id = ObjectId([0xFE; 32]);
        chain.put_object(coin_obj(0xFE, signer, 1_000_000, 0));
        chain.put_petal(Hash32([0xAB; 32]), vec![1, 2, 3], sample_manifest());
        chain.put_path("/bloom/dex/pool", Hash32([0xAB; 32]));
        (chain, signer, gas_id)
    }

    fn ctx<'a>(chain: &'a MockChain, verifier: &'a dyn SignatureVerifier) -> ValidationContext<'a> {
        ValidationContext {
            current_block: chain.block,
            chain,
            verifier,
            loom_coin_type: loom_coin_tt(),
        }
    }

    // -----------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------

    #[test]
    fn accepts_valid_ptb() {
        let (chain, signer, gas_id) = setup();
        let tx = sample_ptb(signer, gas_id, 100);
        let verifier = AlwaysOkVerifier;
        let validated = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap();
        assert_eq!(validated.tx, tx);
        assert!(validated.objects.contains_key(&gas_id.0));
    }

    #[test]
    fn rejects_empty_signers() {
        let (chain, _, gas_id) = setup();
        let mut tx = sample_ptb([0; 32], gas_id, 100);
        tx.signers.clear();
        tx.signatures.clear();
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::NoSigners)
        ));
    }

    #[test]
    fn rejects_signature_count_mismatch() {
        let (chain, signer, gas_id) = setup();
        let mut tx = sample_ptb(signer, gas_id, 100);
        tx.signatures.clear();
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::SignatureCountMismatch { .. })
        ));
    }

    #[test]
    fn rejects_bad_signature() {
        struct DenyVerifier;
        impl SignatureVerifier for DenyVerifier {
            fn verify(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> bool {
                false
            }
        }
        let (chain, signer, gas_id) = setup();
        let tx = sample_ptb(signer, gas_id, 100);
        let verifier = DenyVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::BadSignature { signer_idx: 0 })
        ));
    }

    #[test]
    fn rejects_expired() {
        let (mut chain, signer, gas_id) = setup();
        chain.block = 500;
        let tx = sample_ptb(signer, gas_id, 100);
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        match err {
            PtbError::Expired {
                current_block,
                expiry_block,
            } => {
                assert_eq!(current_block, 500);
                assert_eq!(expiry_block, 100);
            }
            _ => panic!("expected Expired"),
        }
    }

    #[test]
    fn rejects_unpinned_petal_ref() {
        let (chain, signer, gas_id) = setup();
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.petal.hash = None;
        }
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::PetalNotPinned { .. })
        ));
    }

    #[test]
    fn rejects_unknown_petal_hash() {
        let (chain, signer, gas_id) = setup();
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.petal.hash = Some(Hash32([0xFF; 32]));
        }
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::PetalNotFound { .. })
        ));
    }

    #[test]
    fn rejects_path_hash_mismatch() {
        let (chain, signer, gas_id) = setup();
        // Re-bind the path to a different hash than what's in the PTB.
        chain.put_path("/bloom/dex/pool", Hash32([0xCD; 32]));
        let tx = sample_ptb(signer, gas_id, 100);
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::PetalPathHashMismatch { .. })
        ));
    }

    #[test]
    fn rejects_unknown_function() {
        let (chain, signer, gas_id) = setup();
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.function = "absent".to_string();
        }
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::UnknownFunction { .. })
        ));
    }

    #[test]
    fn rejects_type_arg_count_mismatch() {
        let (chain, signer, gas_id) = setup();
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.type_args = vec![TypeTag::Generic { idx: 0 }];
        }
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::TypeArgCountMismatch { .. })
        ));
    }

    #[test]
    fn rejects_arg_count_mismatch() {
        let (chain, signer, gas_id) = setup();
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.args.clear();
        }
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::ArgCountMismatch { .. })
        ));
    }

    #[test]
    fn rejects_arg_kind_mismatch() {
        let (chain, signer, gas_id) = setup();
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.args = vec![Arg::Const(vec![1, 2, 3])];
        }
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn rejects_object_version_mismatch() {
        let (chain, signer, gas_id) = setup();
        let target_id = ObjectId([0xAA; 32]);
        chain.put_object(Object {
            id: target_id,
            type_tag: TypeTag::Generic { idx: 0 },
            owner: Owner::Address(signer),
            version: 1,
            payload: vec![],
        });
        // Add a function with an Object arg to swap into the manifest.
        let mut manifest = sample_manifest();
        manifest.functions.push(FunctionDeclStub {
            name: "use_obj".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: TypeTag::Generic { idx: 0 },
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], manifest);
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.function = "use_obj".to_string();
            m.args = vec![Arg::Object {
                id: target_id,
                expected_version: ExpectedVersion(99),
                access_mode: AccessMode::Mutable,
            }];
        }
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::ObjectVersionMismatch { .. })
        ));
    }

    #[test]
    fn rejects_access_mode_violation_on_immutable() {
        let (chain, signer, gas_id) = setup();
        let target_id = ObjectId([0xAA; 32]);
        chain.put_object(Object {
            id: target_id,
            type_tag: TypeTag::Generic { idx: 0 },
            owner: Owner::Immutable,
            version: 0,
            payload: vec![],
        });
        let mut manifest = sample_manifest();
        manifest.functions.push(FunctionDeclStub {
            name: "mutate".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: TypeTag::Generic { idx: 0 },
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], manifest);
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.function = "mutate".to_string();
            m.args = vec![Arg::Object {
                id: target_id,
                expected_version: ExpectedVersion(0),
                access_mode: AccessMode::Mutable,
            }];
        }
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::AccessDenied { .. })
        ));
    }

    #[test]
    fn rejects_insufficient_gas() {
        let (chain, signer, gas_id) = setup();
        // Replace the gas payer with one that has insufficient balance.
        chain.put_object(coin_obj(0xFE, signer, 50, 0));
        let mut tx = sample_ptb(signer, gas_id, 100);
        tx.gas_budget = 1_000;
        tx.gas_price = 1;
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::InsufficientGas { .. })
        ));
    }

    #[test]
    fn rejects_wrong_gas_payer_owner() {
        let (chain, signer, gas_id) = setup();
        // Owner mismatch.
        chain.put_object(coin_obj(0xFE, [0x99; 32], 100_000, 0));
        let tx = sample_ptb(signer, gas_id, 100);
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(matches!(err, PtbError::InvalidGasPayer { .. }));
    }

    #[test]
    fn rejects_wrong_gas_payer_type() {
        let (chain, signer, gas_id) = setup();
        // Type mismatch.
        chain.put_object(Object {
            id: gas_id,
            type_tag: TypeTag::Generic { idx: 0 },
            owner: Owner::Address(signer),
            version: 0,
            payload: 1_000_000u128.to_be_bytes().to_vec(),
        });
        let tx = sample_ptb(signer, gas_id, 100);
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(matches!(err, PtbError::InvalidGasPayer { .. }));
    }

    #[test]
    fn accepts_shared_object_in_mutable_mode() {
        let (chain, signer, gas_id) = setup();
        let target_id = ObjectId([0xAA; 32]);
        chain.put_object(Object {
            id: target_id,
            type_tag: TypeTag::Generic { idx: 0 },
            owner: Owner::Shared,
            version: 0,
            payload: vec![],
        });
        let mut manifest = sample_manifest();
        manifest.functions.push(FunctionDeclStub {
            name: "touch".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: TypeTag::Generic { idx: 0 },
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], manifest);
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.function = "touch".to_string();
            m.args = vec![Arg::Object {
                id: target_id,
                expected_version: ExpectedVersion(0),
                access_mode: AccessMode::Mutable,
            }];
        }
        let verifier = AlwaysOkVerifier;
        assert!(validate_ptb(&tx, &ctx(&chain, &verifier)).is_ok());
    }

    #[test]
    fn decode_coin_value_too_short() {
        assert!(matches!(
            decode_coin_value(&[0u8; 4]),
            Err(PtbError::InvalidGasPayer { .. })
        ));
    }

    #[test]
    fn decode_coin_value_extracts_first_16_bytes() {
        let v: u128 = 0xDEAD_BEEF_CAFE_F00Du128;
        let mut payload = v.to_be_bytes().to_vec();
        payload.extend_from_slice(b"metadata");
        assert_eq!(decode_coin_value(&payload).unwrap(), v);
    }
}
