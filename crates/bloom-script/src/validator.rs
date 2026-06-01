//! Pre-execution PTB validator (spec §7.2 steps 1–6).
//!
//! Inputs are immutable. On success the validator returns a
//! [`ValidatedPtb`] that bundles the original [`PtbTx`] with
//! pre-loaded chain artefacts (objects, petals, manifests) the
//! executor would otherwise refetch.

use std::collections::{HashMap, HashSet};

use bloom_objects::{
    AccessMode, Object, ObjectId, Owner, TypeTag, ValidationOutcome, validate_canonical_bytes,
};

use crate::chain_iface::{ArgDeclStub, ChainStateIface, FunctionDeclStub, PetalManifestStub};
use crate::error::PtbError;
use crate::types::{Arg, Command, ExpectedVersion, MoveCmd, PtbTx, UseRef};

/// Validation policy for a PTB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationMode {
    /// Validate a PTB that may be committed to chain state.
    Commit,
    /// Validate a PTB for read-only execution against an existing snapshot.
    ReadOnly,
}

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
    /// Whether validation is for commit or read-only execution.
    pub mode: ValidationMode,
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
    let tx = match ctx.mode {
        ValidationMode::Commit => tx.clone(),
        ValidationMode::ReadOnly => read_only_ptb(tx),
    };

    // Step 1: signature check.
    if ctx.mode == ValidationMode::Commit {
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

    // Steps 4 + 5 (unified): strict typecheck + object version/access.
    //
    // We walk commands in order so that every `Arg::Use { cmd_idx, ret_idx }`
    // can be checked against the upstream command's declared return
    // slot type. Per-command return types are tracked in
    // `cmd_return_types` (one outer entry per executed command; inner
    // `Option<TypeTag>` per return slot — `None` means "unknown / opaque
    // built-in output" and cannot be consumed where a concrete type is
    // required).
    let mut objects: HashMap<[u8; 32], Object> = HashMap::new();
    let first_signer_addr = tx.signers.first().copied().unwrap_or([0; 32]);
    let mut cmd_return_types: Vec<Vec<Option<TypeTag>>> = Vec::with_capacity(tx.commands.len());
    let mut consumed_use_refs: HashSet<UseRef> = HashSet::new();
    for (cmd_idx, cmd) in tx.commands.iter().enumerate() {
        match cmd {
            Command::Move(m) => {
                let hash = m.petal.hash.ok_or_else(|| PtbError::PetalNotPinned {
                    path: m.petal.path.clone(),
                })?;
                let manifest = manifests
                    .get(&hash.0)
                    .ok_or(PtbError::PetalNotFound { hash })?;
                let object_scope_modes: HashMap<ObjectId, AccessMode> = m
                    .args
                    .iter()
                    .filter_map(|arg| {
                        if let Arg::Object {
                            id, access_mode, ..
                        } = arg
                        {
                            Some((*id, *access_mode))
                        } else {
                            None
                        }
                    })
                    .collect();
                // Pre-load every Object arg for both shape-check and
                // type-against-manifest matching.
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
                            &object_scope_modes,
                        )?;
                    }
                }
                typecheck_move_cmd(
                    m,
                    manifest,
                    cmd_idx,
                    &cmd_return_types,
                    &objects,
                    tx.signers.len(),
                )?;
                reject_duplicate_move_linear_use_refs(
                    m,
                    manifest,
                    cmd_idx as u16,
                    &mut consumed_use_refs,
                )?;
                // Record the declared return types of this command so
                // later `Use` references can typecheck against them.
                let f = manifest
                    .function(&m.function)
                    .expect("function presence verified by typecheck_move_cmd");
                cmd_return_types.push(
                    f.returns
                        .iter()
                        .map(|t| {
                            Some(resolve_self_type_refs(
                                &substitute_type_args(t, &m.type_args),
                                hash.0,
                            ))
                        })
                        .collect(),
                );
            }
            Command::TransferObjects { uses, .. } => {
                for u in uses {
                    consume_linear_use_ref(&mut consumed_use_refs, *u, cmd_idx as u16)?;
                }
                cmd_return_types.push(vec![]);
            }
            Command::MergeCoins(uses) => {
                for u in uses {
                    consume_linear_use_ref(&mut consumed_use_refs, *u, cmd_idx as u16)?;
                }
                let Some((first, rest)) = uses.split_first() else {
                    return Err(PtbError::BuiltinFailed {
                        cmd_idx: cmd_idx as u16,
                        reason: "MergeCoins requires at least one Use".to_string(),
                    });
                };
                let coin_type = resolve_required_use_type(
                    &cmd_return_types,
                    *first,
                    cmd_idx,
                    "MergeCoins input",
                )?;
                if !is_coin_type_tag(&coin_type) {
                    return Err(PtbError::BuiltinFailed {
                        cmd_idx: cmd_idx as u16,
                        reason: "MergeCoins input is not a Coin<T>".to_string(),
                    });
                }
                for u in rest {
                    let next = resolve_required_use_type(
                        &cmd_return_types,
                        *u,
                        cmd_idx,
                        "MergeCoins input",
                    )?;
                    if next != coin_type {
                        return Err(PtbError::BuiltinFailed {
                            cmd_idx: cmd_idx as u16,
                            reason: "MergeCoins: heterogeneous coin types".to_string(),
                        });
                    }
                }
                cmd_return_types.push(vec![Some(coin_type)]);
            }
            Command::SplitCoins { amounts, .. } => {
                let Command::SplitCoins { src, .. } = cmd else {
                    unreachable!("matched SplitCoins")
                };
                consume_linear_use_ref(&mut consumed_use_refs, *src, cmd_idx as u16)?;
                let coin_type =
                    resolve_required_use_type(&cmd_return_types, *src, cmd_idx, "SplitCoins src")?;
                if !is_coin_type_tag(&coin_type) {
                    return Err(PtbError::BuiltinFailed {
                        cmd_idx: cmd_idx as u16,
                        reason: "SplitCoins source is not a Coin<T>".to_string(),
                    });
                }
                cmd_return_types.push(vec![Some(coin_type); amounts.len()]);
            }
            Command::MakeMoveVec { ty, uses } => {
                for u in uses {
                    consume_linear_use_ref(&mut consumed_use_refs, *u, cmd_idx as u16)?;
                }
                for u in uses {
                    let actual = resolve_required_use_type(
                        &cmd_return_types,
                        *u,
                        cmd_idx,
                        "MakeMoveVec input",
                    )?;
                    if actual != *ty {
                        return Err(PtbError::BuiltinFailed {
                            cmd_idx: cmd_idx as u16,
                            reason: format!(
                                "MakeMoveVec: element {} does not match declared vector element type {}",
                                type_tag_label(&actual),
                                type_tag_label(ty),
                            ),
                        });
                    }
                }
                cmd_return_types.push(vec![Some(vector_type_tag(ty.clone()))]);
            }
            Command::Publish(p) => {
                if p.publisher_cap.is_some() {
                    return Err(PtbError::BuiltinFailed {
                        cmd_idx: cmd_idx as u16,
                        reason: "publish with OwnerCap is disabled until owner-cap authority is enforced".to_string(),
                    });
                }
                cmd_return_types.push(vec![None, None]);
            }
            Command::UpgradePetal(_) => {
                return Err(PtbError::BuiltinFailed {
                    cmd_idx: cmd_idx as u16,
                    reason: "UpgradePetal is disabled until owner-cap authority is enforced"
                        .to_string(),
                });
            }
        }
    }

    // Step 6: gas-payer prep.
    if ctx.mode == ValidationMode::Commit {
        let gas_obj = ctx
            .chain
            .load_object(&tx.gas_payer)
            .ok_or(PtbError::ObjectNotFound { id: tx.gas_payer })?;
        if objects.contains_key(&tx.gas_payer.0) {
            return Err(PtbError::InvalidGasPayer {
                id: tx.gas_payer,
                reason: "gas payer cannot also be used as a PTB object input".to_string(),
            });
        }
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
        let needed = tx
            .checked_gas_reservation()
            .ok_or(PtbError::GasReservationOverflow {
                gas_budget: tx.gas_budget,
                gas_price: tx.gas_price,
            })?;
        if coin_value < needed {
            return Err(PtbError::InsufficientGas {
                needed,
                available: coin_value,
            });
        }
        objects.insert(gas_obj.id.0, gas_obj);
    }

    Ok(ValidatedPtb {
        tx,
        objects,
        petals,
        manifests,
        first_signer_addr,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_only_ptb(tx: &PtbTx) -> PtbTx {
    let mut tx = tx.clone();
    for cmd in &mut tx.commands {
        if let Command::Move(m) = cmd {
            for arg in &mut m.args {
                if let Arg::Object { access_mode, .. } = arg {
                    *access_mode = AccessMode::ReadOnly;
                }
            }
        }
    }
    tx
}

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
    cmd_idx: usize,
    cmd_return_types: &[Vec<Option<TypeTag>>],
    objects: &HashMap<[u8; 32], Object>,
    signer_count: usize,
) -> Result<(), PtbError> {
    let hash = cmd.petal.hash.ok_or_else(|| PtbError::PetalNotPinned {
        path: cmd.petal.path.clone(),
    })?;
    let f: &FunctionDeclStub =
        manifest
            .function(&cmd.function)
            .ok_or_else(|| PtbError::UnknownFunction {
                function: cmd.function.clone(),
                petal_hash: hash,
            })?;
    let local_object_types: HashSet<&str> = manifest
        .object_types
        .iter()
        .map(|object_type| object_type.name.as_str())
        .collect();

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

    if signer_count < usize::from(f.required_signers) {
        return Err(PtbError::TypeMismatch {
            function: cmd.function.clone(),
            arg_idx: 0,
            reason: format!(
                "manifest requires {} signer(s), but PTB has {signer_count}",
                f.required_signers
            ),
        });
    }
    if !f.required_capabilities.is_empty() {
        return Err(PtbError::TypeMismatch {
            function: cmd.function.clone(),
            arg_idx: 0,
            reason: "manifest required_capabilities are not supported by PTB validation".into(),
        });
    }

    for (i, (arg, decl)) in cmd.args.iter().zip(f.args.iter()).enumerate() {
        match (arg, decl) {
            (Arg::Signer(idx), ArgDeclStub::Signer) => {
                if (*idx as usize) >= signer_count {
                    return Err(PtbError::TypeMismatch {
                        function: cmd.function.clone(),
                        arg_idx: i,
                        reason: format!(
                            "signer index {idx} is outside signed signer set of length {signer_count}"
                        ),
                    });
                }
            }
            (Arg::Const(bytes), ArgDeclStub::Const(declared_tag)) => {
                // Apply generic substitution so a `Const T` in the
                // manifest is checked against the concrete `T` the
                // caller chose for this MoveCmd.
                let expected = substitute_type_args(declared_tag, &cmd.type_args);
                match validate_canonical_bytes(&expected, bytes) {
                    ValidationOutcome::Ok | ValidationOutcome::Unknown => {}
                    ValidationOutcome::Invalid(reason) => {
                        return Err(PtbError::TypeMismatch {
                            function: cmd.function.clone(),
                            arg_idx: i,
                            reason: format!(
                                "Const bytes do not match declared type {}: {reason}",
                                type_tag_label(&expected)
                            ),
                        });
                    }
                }
            }
            (
                Arg::Object {
                    id,
                    access_mode: amode,
                    ..
                },
                ArgDeclStub::Object {
                    ty: declared_ty,
                    mode,
                },
            ) => {
                if amode != mode {
                    return Err(PtbError::TypeMismatch {
                        function: cmd.function.clone(),
                        arg_idx: i,
                        reason: format!("access mode {amode:?} does not match declared {mode:?}"),
                    });
                }
                // Compare the on-chain object's type_tag against the
                // declared arg type, applying the caller's
                // type_args substitution. `objects` has been
                // pre-populated by the caller for every Arg::Object.
                let Some(obj) = objects.get(&id.0) else {
                    return Err(PtbError::ObjectNotFound { id: *id });
                };
                let expected = substitute_type_args(declared_ty, &cmd.type_args);
                if !type_tags_match(&obj.type_tag, &expected, hash.0, &local_object_types) {
                    return Err(PtbError::TypeMismatch {
                        function: cmd.function.clone(),
                        arg_idx: i,
                        reason: format!(
                            "object {} has type {}, declared arg type is {}",
                            hex_encode(&id.0),
                            type_tag_label(&obj.type_tag),
                            type_tag_label(&expected),
                        ),
                    });
                }
            }
            (
                Arg::Use {
                    cmd_idx: u_cmd,
                    ret_idx: u_ret,
                },
                ArgDeclStub::Object {
                    ty: declared_ty, ..
                },
            )
            | (
                Arg::Use {
                    cmd_idx: u_cmd,
                    ret_idx: u_ret,
                },
                ArgDeclStub::Const(declared_ty),
            ) => {
                let actual = resolve_required_use_type(
                    cmd_return_types,
                    UseRef {
                        cmd_idx: *u_cmd,
                        ret_idx: *u_ret,
                    },
                    cmd_idx,
                    "Move argument",
                )?;
                let expected = substitute_type_args(declared_ty, &cmd.type_args);
                if !type_tags_match(&actual, &expected, hash.0, &local_object_types) {
                    return Err(PtbError::TypeMismatch {
                        function: cmd.function.clone(),
                        arg_idx: i,
                        reason: format!(
                            "Use({u_cmd},{u_ret}) returns {}, declared arg type is {}",
                            type_tag_label(&actual),
                            type_tag_label(&expected),
                        ),
                    });
                }
            }
            (Arg::TypeArg(actual), ArgDeclStub::TypeArg(idx)) => {
                let Some(expected) = cmd.type_args.get(*idx as usize) else {
                    return Err(PtbError::TypeMismatch {
                        function: cmd.function.clone(),
                        arg_idx: i,
                        reason: format!("TypeArg declaration index {idx} has no matching type arg"),
                    });
                };
                if actual != expected {
                    return Err(PtbError::TypeMismatch {
                        function: cmd.function.clone(),
                        arg_idx: i,
                        reason: format!(
                            "TypeArg value {} does not match type_args[{idx}] {}",
                            type_tag_label(actual),
                            type_tag_label(expected),
                        ),
                    });
                }
            }
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

/// Resolve a `Use` reference to its upstream return type slot.
///
/// Returns `Ok(Some(_))` if the upstream command has a typed return
/// slot at that position; `Ok(None)` if the upstream is a built-in
/// command whose slot is opaque to the validator; `Err(DanglingUse)`
/// if the (cmd_idx, ret_idx) pair does not name a real slot.
fn resolve_use_type(
    cmd_return_types: &[Vec<Option<TypeTag>>],
    u: UseRef,
    referring_cmd_idx: usize,
) -> Result<Option<TypeTag>, PtbError> {
    // Forward / self references are not allowed; only earlier commands
    // can be referenced.
    if (u.cmd_idx as usize) >= referring_cmd_idx {
        return Err(PtbError::DanglingUse {
            cmd_idx: u.cmd_idx,
            ret_idx: u.ret_idx,
        });
    }
    let slots = cmd_return_types
        .get(u.cmd_idx as usize)
        .ok_or(PtbError::DanglingUse {
            cmd_idx: u.cmd_idx,
            ret_idx: u.ret_idx,
        })?;
    let slot = slots.get(u.ret_idx as usize).ok_or(PtbError::DanglingUse {
        cmd_idx: u.cmd_idx,
        ret_idx: u.ret_idx,
    })?;
    Ok(slot.clone())
}

fn reject_duplicate_move_linear_use_refs(
    cmd: &MoveCmd,
    manifest: &PetalManifestStub,
    cmd_idx: u16,
    consumed: &mut HashSet<UseRef>,
) -> Result<(), PtbError> {
    let hash = cmd.petal.hash.ok_or_else(|| PtbError::PetalNotPinned {
        path: cmd.petal.path.clone(),
    })?;
    let f = manifest
        .function(&cmd.function)
        .ok_or_else(|| PtbError::UnknownFunction {
            function: cmd.function.clone(),
            petal_hash: hash,
        })?;
    for (arg, decl) in cmd.args.iter().zip(f.args.iter()) {
        if matches!(decl, ArgDeclStub::Object { .. })
            && let Arg::Use {
                cmd_idx: use_cmd_idx,
                ret_idx,
            } = arg
        {
            consume_linear_use_ref(
                consumed,
                UseRef {
                    cmd_idx: *use_cmd_idx,
                    ret_idx: *ret_idx,
                },
                cmd_idx,
            )?;
        }
    }
    Ok(())
}

fn consume_linear_use_ref(
    consumed: &mut HashSet<UseRef>,
    u: UseRef,
    referring_cmd: u16,
) -> Result<(), PtbError> {
    if consumed.insert(u) {
        Ok(())
    } else {
        Err(PtbError::BuiltinFailed {
            cmd_idx: referring_cmd,
            reason: format!(
                "duplicate linear Use({}, {}) consumption",
                u.cmd_idx, u.ret_idx
            ),
        })
    }
}

fn resolve_required_use_type(
    cmd_return_types: &[Vec<Option<TypeTag>>],
    u: UseRef,
    referring_cmd_idx: usize,
    context: &str,
) -> Result<TypeTag, PtbError> {
    resolve_use_type(cmd_return_types, u, referring_cmd_idx)?.ok_or_else(|| {
        PtbError::BuiltinFailed {
            cmd_idx: referring_cmd_idx as u16,
            reason: format!("{context} must reference a typed object output"),
        }
    })
}

fn is_coin_type_tag(t: &TypeTag) -> bool {
    matches!(
        t,
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } if type_name == "Coin" && type_args.len() == 1
    )
}

fn vector_type_tag(elem: TypeTag) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: "vector".to_string(),
        type_args: vec![elem],
    }
}

/// Apply a function-level type-arg substitution to a `TypeTag`,
/// replacing each `TypeTag::Generic { idx }` with `type_args[idx]`.
/// Generics with `idx >= type_args.len()` are left as-is (the validator
/// already rejects arity mismatches before reaching here, but
/// substitution stays total).
fn substitute_type_args(t: &TypeTag, type_args: &[TypeTag]) -> TypeTag {
    match t {
        TypeTag::Generic { idx } => type_args
            .get(*idx as usize)
            .cloned()
            .unwrap_or_else(|| t.clone()),
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args: inner,
        } => TypeTag::Concrete {
            petal_hash: *petal_hash,
            type_name: type_name.clone(),
            type_args: inner
                .iter()
                .map(|x| substitute_type_args(x, type_args))
                .collect(),
        },
        TypeTag::External { .. } => t.clone(),
    }
}

/// Structural compare between two `TypeTag`s.
///
/// Equality is exact except that a self-referential `petal_hash` of
/// `[0u8; 32]` on the declared side resolves to the currently executing
/// petal's hash. The `Coin<T>` wrapper is intentionally provenance-neutral:
/// several petals can mint and consume coins carrying the same inner `T`.
fn type_tags_match(
    actual: &TypeTag,
    declared: &TypeTag,
    self_hash: [u8; 32],
    local_object_types: &HashSet<&str>,
) -> bool {
    type_tags_match_inner(actual, declared, self_hash, local_object_types, true)
}

fn type_tags_match_inner(
    actual: &TypeTag,
    declared: &TypeTag,
    self_hash: [u8; 32],
    local_object_types: &HashSet<&str>,
    allow_top_level_import: bool,
) -> bool {
    match (actual, declared) {
        (
            TypeTag::Concrete {
                petal_hash: ah,
                type_name: an,
                type_args: aa,
            },
            TypeTag::Concrete {
                petal_hash: dh,
                type_name: dn,
                type_args: da,
            },
        ) => {
            if an != dn || aa.len() != da.len() {
                return false;
            }
            if dh == &[0u8; 32] {
                let imported_object_arg = allow_top_level_import
                    && da.is_empty()
                    && dn != "Capability"
                    && !local_object_types.contains(dn.as_str());
                if dn != "Coin" && !imported_object_arg && ah != &[0u8; 32] && ah != &self_hash {
                    return false;
                }
            } else if ah != dh {
                return false;
            }
            aa.iter()
                .zip(da.iter())
                .all(|(a, d)| type_tags_match_inner(a, d, self_hash, local_object_types, false))
        }
        (TypeTag::Generic { idx: a }, TypeTag::Generic { idx: b }) => a == b,
        (TypeTag::External { ref_idx: a }, TypeTag::External { ref_idx: b }) => a == b,
        _ => false,
    }
}

fn resolve_self_type_refs(t: &TypeTag, self_hash: [u8; 32]) -> TypeTag {
    match t {
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args,
        } => TypeTag::Concrete {
            petal_hash: if petal_hash == &[0u8; 32] && type_name != "Coin" {
                self_hash
            } else {
                *petal_hash
            },
            type_name: type_name.clone(),
            type_args: if type_name == "Coin" {
                type_args.clone()
            } else {
                type_args
                    .iter()
                    .map(|x| resolve_self_type_refs(x, self_hash))
                    .collect()
            },
        },
        TypeTag::Generic { .. } | TypeTag::External { .. } => t.clone(),
    }
}

/// Compact human-readable label for diagnostic messages.
fn type_tag_label(t: &TypeTag) -> String {
    match t {
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } => {
            if type_args.is_empty() {
                type_name.clone()
            } else {
                let inner = type_args
                    .iter()
                    .map(type_tag_label)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{type_name}<{inner}>")
            }
        }
        TypeTag::Generic { idx } => format!("T{idx}"),
        TypeTag::External { ref_idx } => format!("$external_{ref_idx}"),
    }
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
    object_scope_modes: &HashMap<ObjectId, AccessMode>,
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
    let mut seen = HashSet::new();
    let mut ctx = AccessCheckContext {
        chain,
        first_signer_addr,
        objects,
        object_scope_modes,
        seen: &mut seen,
    };
    check_access_mode(&mut ctx, &obj.owner, mode, id)?;
    Ok(())
}

struct AccessCheckContext<'a> {
    chain: &'a dyn ChainStateIface,
    first_signer_addr: &'a [u8; 32],
    objects: &'a mut HashMap<[u8; 32], Object>,
    object_scope_modes: &'a HashMap<ObjectId, AccessMode>,
    seen: &'a mut HashSet<ObjectId>,
}

fn check_access_mode(
    ctx: &mut AccessCheckContext<'_>,
    owner: &Owner,
    mode: AccessMode,
    id: &ObjectId,
) -> Result<(), PtbError> {
    match (owner, mode) {
        (Owner::Immutable, AccessMode::ReadOnly) => Ok(()),
        (Owner::Immutable, _) => Err(PtbError::AccessDenied {
            id: *id,
            mode,
            reason: "immutable objects support ReadOnly only".to_string(),
        }),
        (Owner::Shared, AccessMode::ReadOnly | AccessMode::Mutable) => Ok(()),
        (Owner::Shared, AccessMode::Consume) => Err(PtbError::AccessDenied {
            id: *id,
            mode,
            reason: "shared objects cannot be consumed".to_string(),
        }),
        (Owner::Address(addr), AccessMode::Mutable | AccessMode::Consume) => {
            if addr == ctx.first_signer_addr {
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
        (Owner::Object(parent_id), _) => {
            if !ctx.seen.insert(*id) {
                return Err(PtbError::AccessDenied {
                    id: *id,
                    mode,
                    reason: "object-owner cycle detected".to_string(),
                });
            }
            let parent_mode = ctx
                .object_scope_modes
                .get(parent_id)
                .copied()
                .ok_or_else(|| PtbError::AccessDenied {
                    id: *id,
                    mode,
                    reason: format!(
                        "object-owned child requires owning parent {} in command scope",
                        hex_encode(&parent_id.0)
                    ),
                })?;
            if !parent_mode_authorizes_child(parent_mode, mode) {
                return Err(PtbError::AccessDenied {
                    id: *id,
                    mode,
                    reason: format!(
                        "object-owned child mode {mode:?} requires stronger parent authority than {parent_mode:?}"
                    ),
                });
            }
            let parent = match ctx.objects.get(&parent_id.0) {
                Some(o) => o.clone(),
                None => {
                    let loaded = ctx
                        .chain
                        .load_object(parent_id)
                        .ok_or(PtbError::ObjectNotFound { id: *parent_id })?;
                    ctx.objects.insert(parent_id.0, loaded.clone());
                    loaded
                }
            };
            check_access_mode(ctx, &parent.owner, parent_mode, parent_id)
        }
    }
}

fn parent_mode_authorizes_child(parent_mode: AccessMode, child_mode: AccessMode) -> bool {
    match child_mode {
        AccessMode::ReadOnly => true,
        AccessMode::Mutable | AccessMode::Consume => {
            matches!(parent_mode, AccessMode::Mutable | AccessMode::Consume)
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

/// Extract a `Coin<T>::value` from a `Coin` payload.
///
/// The canonical on-chain layout (spec §coin-encoding) is:
/// `[ObjectId (32 bytes, zeroed at create-time)] || [u128 value BE (16 bytes)]`
/// — total 48 bytes. The value lives at `payload[32..48]`.
pub fn decode_coin_value(payload: &[u8]) -> Result<u128, PtbError> {
    if payload.len() < 48 {
        return Err(PtbError::InvalidGasPayer {
            id: ObjectId([0; 32]),
            reason: format!("coin payload too short ({} bytes, need 48)", payload.len()),
        });
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&payload[32..48]);
    Ok(u128::from_be_bytes(a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_iface::{ArgDeclStub, FunctionDeclStub, ObjectTypeDeclStub};
    use crate::types::{
        Arg, Command, ExpectedVersion, MoveCmd, PetalRef, PqSignature, PtbTx, UseRef,
    };
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
        // 48-byte canonical payload: [ObjectId placeholder (32 bytes)] || [value BE (16 bytes)]
        let mut payload = vec![0u8; 32];
        payload.extend_from_slice(&value.to_be_bytes());
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: loom_coin_tt(),
            owner: Owner::Address(owner),
            version,
            payload,
        }
    }

    fn pool_tt() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0xAB; 32],
            type_name: "Pool".to_string(),
            type_args: vec![],
        }
    }

    fn pool_obj(id_byte: u8, owner: Owner, version: u64) -> Object {
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: pool_tt(),
            owner,
            version,
            payload: vec![0xCA, 0xFE],
        }
    }

    fn sample_manifest() -> PetalManifestStub {
        PetalManifestStub {
            module_path: "/bloom/petals/dex/pool".to_string(),
            functions: vec![FunctionDeclStub {
                view: false,
                name: "swap".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Signer],
                returns: vec![],
                required_signers: 0,
                required_capabilities: vec![],
                attached_invariants: vec![],
            }],
            object_types: vec![ObjectTypeDeclStub {
                name: "Pool".to_string(),
                abilities: bloom_objects::AbilitySet::from_bits(
                    bloom_objects::AbilitySet::KEY | bloom_objects::AbilitySet::STORE,
                ),
            }],
            external_type_refs: vec![],
        }
    }

    fn object_manifest(mode: AccessMode) -> PetalManifestStub {
        let mut manifest = sample_manifest();
        manifest.functions = vec![FunctionDeclStub {
            view: false,
            name: "inspect".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: TypeTag::Concrete {
                    petal_hash: [0; 32],
                    type_name: "Pool".to_string(),
                    type_args: vec![],
                },
                mode,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        }];
        manifest
    }

    fn sample_ptb(signer: [u8; 32], gas_payer_id: ObjectId, expiry: u64) -> PtbTx {
        PtbTx {
            signers: vec![signer],
            commands: vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/petals/dex/pool".to_string(),
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
        chain.put_path("/bloom/petals/dex/pool", Hash32([0xAB; 32]));
        (chain, signer, gas_id)
    }

    fn ctx<'a>(chain: &'a MockChain, verifier: &'a dyn SignatureVerifier) -> ValidationContext<'a> {
        ValidationContext {
            mode: ValidationMode::Commit,
            current_block: chain.block,
            chain,
            verifier,
            loom_coin_type: loom_coin_tt(),
        }
    }

    fn read_only_ctx<'a>(
        chain: &'a MockChain,
        verifier: &'a dyn SignatureVerifier,
    ) -> ValidationContext<'a> {
        ValidationContext {
            mode: ValidationMode::ReadOnly,
            current_block: chain.block,
            chain,
            verifier,
            loom_coin_type: loom_coin_tt(),
        }
    }

    struct PanicVerifier;

    impl SignatureVerifier for PanicVerifier {
        fn verify(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> bool {
            panic!("read-only validation must not verify signatures")
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
    fn read_only_accepts_absent_signatures_and_no_gas_payer_coin() {
        let chain = MockChain::new();
        let obj = pool_obj(0x44, Owner::Address([0x99; 32]), 7);
        chain.put_object(obj.clone());
        chain.put_petal(
            Hash32([0xAB; 32]),
            vec![1, 2, 3],
            object_manifest(AccessMode::ReadOnly),
        );
        chain.put_path("/bloom/petals/dex/pool", Hash32([0xAB; 32]));
        let tx = PtbTx {
            signers: vec![],
            commands: vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/petals/dex/pool".to_string(),
                    hash: Some(Hash32([0xAB; 32])),
                },
                function: "inspect".to_string(),
                type_args: vec![],
                args: vec![Arg::Object {
                    id: obj.id,
                    expected_version: ExpectedVersion(7),
                    access_mode: AccessMode::Mutable,
                }],
            })],
            gas_payer: ObjectId([0xFE; 32]),
            gas_budget: 100,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![],
        };

        let validated = validate_ptb(&tx, &read_only_ctx(&chain, &PanicVerifier)).unwrap();
        assert!(validated.objects.contains_key(&obj.id.0));
        assert!(!validated.objects.contains_key(&tx.gas_payer.0));
        let Command::Move(m) = &validated.tx.commands[0] else {
            panic!("expected Move command");
        };
        let Arg::Object { access_mode, .. } = &m.args[0] else {
            panic!("expected Object arg");
        };
        assert_eq!(*access_mode, AccessMode::ReadOnly);
    }

    #[test]
    fn read_only_allows_supplied_signer_without_signature_verification() {
        let (chain, signer, gas_id) = setup();
        let mut tx = sample_ptb(signer, gas_id, 100);
        tx.signatures.clear();

        assert!(validate_ptb(&tx, &read_only_ctx(&chain, &PanicVerifier)).is_ok());
    }

    #[test]
    fn read_only_coercion_rejects_mutable_object_declarations() {
        let chain = MockChain::new();
        let obj = pool_obj(0x44, Owner::Address([0x99; 32]), 7);
        chain.put_object(obj.clone());
        chain.put_petal(
            Hash32([0xAB; 32]),
            vec![1, 2, 3],
            object_manifest(AccessMode::Mutable),
        );
        chain.put_path("/bloom/petals/dex/pool", Hash32([0xAB; 32]));
        let tx = PtbTx {
            signers: vec![],
            commands: vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/petals/dex/pool".to_string(),
                    hash: Some(Hash32([0xAB; 32])),
                },
                function: "inspect".to_string(),
                type_args: vec![],
                args: vec![Arg::Object {
                    id: obj.id,
                    expected_version: ExpectedVersion(7),
                    access_mode: AccessMode::Mutable,
                }],
            })],
            gas_payer: ObjectId([0xFE; 32]),
            gas_budget: 100,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![],
        };

        let err = validate_ptb(&tx, &read_only_ctx(&chain, &PanicVerifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { reason, .. } if reason.contains("access mode ReadOnly"))
        );
    }

    #[test]
    fn rejects_duplicate_linear_use_ref_consumption() {
        let (chain, signer, gas_id) = setup();
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "mint".to_string(),
            type_params: vec![],
            args: vec![],
            returns: vec![loom_coin_tt()],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![1, 2, 3], m);
        let tx = PtbTx {
            signers: vec![signer],
            commands: vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "mint".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                Command::TransferObjects {
                    uses: vec![
                        UseRef {
                            cmd_idx: 0,
                            ret_idx: 0,
                        },
                        UseRef {
                            cmd_idx: 0,
                            ret_idx: 0,
                        },
                    ],
                    owner: Owner::Address([0x22; 32]),
                },
            ],
            gas_payer: gas_id,
            gas_budget: 100,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![PqSignature(vec![0xCC; 8])],
        };
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(matches!(
            err,
            PtbError::BuiltinFailed { reason, .. }
                if reason.contains("duplicate linear Use(0, 0)")
        ));
    }

    #[test]
    fn rejects_manifest_required_signers_not_present() {
        let (chain, signer, gas_id) = setup();
        let mut manifest = sample_manifest();
        manifest.functions[0].required_signers = 2;
        chain.put_petal(Hash32([0xAB; 32]), vec![1, 2, 3], manifest);
        let tx = sample_ptb(signer, gas_id, 100);

        let err = validate_ptb(&tx, &ctx(&chain, &AlwaysOkVerifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { ref reason, .. } if reason.contains("requires 2 signer")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn rejects_manifest_required_capabilities_until_supported() {
        let (chain, signer, gas_id) = setup();
        let mut manifest = sample_manifest();
        manifest.functions[0].required_capabilities = vec![pool_tt()];
        chain.put_petal(Hash32([0xAB; 32]), vec![1, 2, 3], manifest);
        let tx = sample_ptb(signer, gas_id, 100);

        let err = validate_ptb(&tx, &ctx(&chain, &AlwaysOkVerifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { ref reason, .. } if reason.contains("required_capabilities")),
            "unexpected error: {err:?}"
        );
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
        chain.put_path("/bloom/petals/dex/pool", Hash32([0xCD; 32]));
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
            view: false,
            name: "use_obj".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: TypeTag::Generic { idx: 0 },
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
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
    fn rejects_object_owned_child_without_parent_in_scope() {
        let (chain, signer, gas_id) = setup();
        let parent_id = ObjectId([0x44; 32]);
        let child_id = ObjectId([0x45; 32]);
        let mut parent = coin_obj(0x44, signer, 10, 0);
        parent.id = parent_id;
        parent.owner = Owner::Shared;
        let mut child = coin_obj(0x45, signer, 10, 0);
        child.id = child_id;
        child.owner = Owner::Object(parent_id);
        chain.put_object(parent);
        chain.put_object(child);

        let mut manifest = sample_manifest();
        manifest.functions.push(FunctionDeclStub {
            view: false,
            name: "touch_child".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: loom_coin_tt(),
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], manifest);
        let mut tx = sample_ptb(signer, gas_id, 100);
        tx.commands = vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: "/bloom/petals/dex/pool".to_string(),
                hash: Some(Hash32([0xAB; 32])),
            },
            function: "touch_child".to_string(),
            type_args: vec![],
            args: vec![Arg::Object {
                id: child_id,
                expected_version: ExpectedVersion(0),
                access_mode: AccessMode::Mutable,
            }],
        })];
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::AccessDenied { .. })
        ));
    }

    #[test]
    fn accepts_object_owned_child_when_parent_authority_in_scope() {
        let (chain, signer, gas_id) = setup();
        let parent_id = ObjectId([0x54; 32]);
        let child_id = ObjectId([0x55; 32]);
        let mut parent = coin_obj(0x54, signer, 10, 0);
        parent.id = parent_id;
        parent.owner = Owner::Shared;
        let mut child = coin_obj(0x55, signer, 10, 0);
        child.id = child_id;
        child.owner = Owner::Object(parent_id);
        chain.put_object(parent);
        chain.put_object(child);

        let mut manifest = sample_manifest();
        manifest.functions.push(FunctionDeclStub {
            view: false,
            name: "touch_pair".to_string(),
            type_params: vec![],
            args: vec![
                ArgDeclStub::Object {
                    ty: loom_coin_tt(),
                    mode: AccessMode::Mutable,
                },
                ArgDeclStub::Object {
                    ty: loom_coin_tt(),
                    mode: AccessMode::Mutable,
                },
            ],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], manifest);
        let mut tx = sample_ptb(signer, gas_id, 100);
        tx.commands = vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: "/bloom/petals/dex/pool".to_string(),
                hash: Some(Hash32([0xAB; 32])),
            },
            function: "touch_pair".to_string(),
            type_args: vec![],
            args: vec![
                Arg::Object {
                    id: parent_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::Mutable,
                },
                Arg::Object {
                    id: child_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::Mutable,
                },
            ],
        })];
        let verifier = AlwaysOkVerifier;
        let validated = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap();
        assert!(validated.objects.contains_key(&parent_id.0));
        assert!(validated.objects.contains_key(&child_id.0));
    }

    #[test]
    fn rejects_mutable_object_owned_child_when_parent_is_readonly() {
        let (chain, signer, gas_id) = setup();
        let parent_id = ObjectId([0x64; 32]);
        let child_id = ObjectId([0x65; 32]);
        let mut parent = coin_obj(0x64, signer, 10, 0);
        parent.id = parent_id;
        parent.owner = Owner::Address(signer);
        let mut child = coin_obj(0x65, signer, 10, 0);
        child.id = child_id;
        child.owner = Owner::Object(parent_id);
        chain.put_object(parent);
        chain.put_object(child);

        let mut manifest = sample_manifest();
        manifest.functions.push(FunctionDeclStub {
            view: false,
            name: "read_parent_mutate_child".to_string(),
            type_params: vec![],
            args: vec![
                ArgDeclStub::Object {
                    ty: loom_coin_tt(),
                    mode: AccessMode::ReadOnly,
                },
                ArgDeclStub::Object {
                    ty: loom_coin_tt(),
                    mode: AccessMode::Mutable,
                },
            ],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], manifest);
        let mut tx = sample_ptb(signer, gas_id, 100);
        tx.commands = vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: "/bloom/petals/dex/pool".to_string(),
                hash: Some(Hash32([0xAB; 32])),
            },
            function: "read_parent_mutate_child".to_string(),
            type_args: vec![],
            args: vec![
                Arg::Object {
                    id: parent_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::ReadOnly,
                },
                Arg::Object {
                    id: child_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::Mutable,
                },
            ],
        })];
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier))
            .expect_err("ReadOnly parent must not authorize Mutable child");
        assert!(matches!(err, PtbError::AccessDenied { .. }));
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
            view: false,
            name: "mutate".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: TypeTag::Generic { idx: 0 },
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
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
        let mut wrong_type_payload = vec![0u8; 32];
        wrong_type_payload.extend_from_slice(&1_000_000u128.to_be_bytes());
        chain.put_object(Object {
            id: gas_id,
            type_tag: TypeTag::Generic { idx: 0 },
            owner: Owner::Address(signer),
            version: 0,
            payload: wrong_type_payload,
        });
        let tx = sample_ptb(signer, gas_id, 100);
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(matches!(err, PtbError::InvalidGasPayer { .. }));
    }

    #[test]
    fn rejects_gas_payer_as_object_input() {
        let (chain, signer, gas_id) = setup();
        let mut manifest = sample_manifest();
        manifest.functions[0].args = vec![ArgDeclStub::Object {
            ty: loom_coin_tt(),
            mode: AccessMode::Mutable,
        }];
        chain.put_petal(Hash32([0xAB; 32]), vec![1, 2, 3], manifest);

        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.args = vec![Arg::Object {
                id: gas_id,
                expected_version: ExpectedVersion(0),
                access_mode: AccessMode::Mutable,
            }];
        }

        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(matches!(
            err,
            PtbError::InvalidGasPayer { reason, .. } if reason.contains("object input")
        ));
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
            view: false,
            name: "touch".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: TypeTag::Generic { idx: 0 },
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
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
        // 47 bytes is one byte short of the required 48.
        assert!(matches!(
            decode_coin_value(&[0u8; 47]),
            Err(PtbError::InvalidGasPayer { .. })
        ));
    }

    #[test]
    fn decode_coin_value_reads_value_after_id() {
        let v: u128 = 0xDEAD_BEEF_CAFE_F00Du128;
        // Canonical 48-byte layout: [id placeholder (32)] || [value BE (16)]
        let mut payload = vec![0u8; 32];
        payload.extend_from_slice(&v.to_be_bytes());
        assert_eq!(decode_coin_value(&payload).unwrap(), v);
    }

    // -----------------------------------------------------------------
    // P1-3: strict typecheck (Const bytes, Use slots, Object types)
    // -----------------------------------------------------------------

    fn concrete(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: vec![],
        }
    }

    fn install_fn(chain: &MockChain, name: &str, args: Vec<ArgDeclStub>, returns: Vec<TypeTag>) {
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: name.to_string(),
            type_params: vec![],
            args,
            returns,
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
    }

    /// Const bytes whose length matches the declared `u64` shape are
    /// accepted; bytes of the wrong length are rejected with
    /// `TypeMismatch`.
    #[test]
    fn strict_typecheck_const_u64_correct_length_accepted() {
        let (chain, signer, gas_id) = setup();
        install_fn(
            &chain,
            "f",
            vec![ArgDeclStub::Const(concrete("u64"))],
            vec![],
        );
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.function = "f".to_string();
            m.args = vec![Arg::Const(vec![0u8; 8])];
        }
        let verifier = AlwaysOkVerifier;
        assert!(validate_ptb(&tx, &ctx(&chain, &verifier)).is_ok());
    }

    #[test]
    fn strict_typecheck_const_u64_too_short_rejected() {
        let (chain, signer, gas_id) = setup();
        install_fn(
            &chain,
            "f",
            vec![ArgDeclStub::Const(concrete("u64"))],
            vec![],
        );
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.function = "f".to_string();
            // 4 bytes — too short for u64 (8 bytes).
            m.args = vec![Arg::Const(vec![0u8; 4])];
        }
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { ref reason, .. } if reason.contains("u64")),
            "expected TypeMismatch mentioning u64, got {err:?}"
        );
    }

    #[test]
    fn strict_typecheck_const_object_id_wrong_length_rejected() {
        let (chain, signer, gas_id) = setup();
        install_fn(
            &chain,
            "f",
            vec![ArgDeclStub::Const(concrete("ObjectId"))],
            vec![],
        );
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.function = "f".to_string();
            m.args = vec![Arg::Const(vec![0u8; 31])];
        }
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { .. }),
            "expected TypeMismatch, got {err:?}"
        );
    }

    /// Unknown (petal-defined) Const types are accepted unconditionally
    /// — the runtime is the final arbiter.
    #[test]
    fn strict_typecheck_const_unknown_type_accepts_any_bytes() {
        let (chain, signer, gas_id) = setup();
        install_fn(
            &chain,
            "f",
            vec![ArgDeclStub::Const(concrete("Pool"))],
            vec![],
        );
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.function = "f".to_string();
            m.args = vec![Arg::Const(vec![1, 2, 3])];
        }
        let verifier = AlwaysOkVerifier;
        assert!(validate_ptb(&tx, &ctx(&chain, &verifier)).is_ok());
    }

    /// A `Use` slot referring to a non-existent command (forward
    /// reference) is rejected with `DanglingUse`.
    #[test]
    fn strict_typecheck_use_forward_reference_rejected() {
        let (chain, signer, gas_id) = setup();
        install_fn(
            &chain,
            "f",
            vec![ArgDeclStub::Const(concrete("u64"))],
            vec![],
        );
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.function = "f".to_string();
            m.args = vec![Arg::Use {
                cmd_idx: 5,
                ret_idx: 0,
            }];
        }
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::DanglingUse { .. })
        ));
    }

    /// A `Use` slot referring to a real upstream command whose declared
    /// return type does not match the downstream arg's declared type
    /// is rejected.
    #[test]
    fn strict_typecheck_use_slot_type_mismatch_rejected() {
        let (chain, signer, gas_id) = setup();
        // Function "producer" returns u64; function "consumer" takes a
        // Const u128. Hooking them up with a Use should fail.
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "producer".to_string(),
            type_params: vec![],
            args: vec![],
            returns: vec![concrete("u64")],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "consumer".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Const(concrete("u128"))],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let tx = PtbTx {
            signers: vec![signer],
            commands: vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "producer".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "consumer".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Use {
                        cmd_idx: 0,
                        ret_idx: 0,
                    }],
                }),
            ],
            gas_payer: gas_id,
            gas_budget: 100,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![PqSignature(vec![0xCC; 8])],
        };
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { ref reason, .. } if reason.contains("u64") && reason.contains("u128")),
            "expected TypeMismatch citing u64/u128, got {err:?}"
        );
    }

    /// A `Use` slot whose upstream type matches the consumer's declared
    /// type is accepted.
    #[test]
    fn strict_typecheck_use_slot_type_match_accepted() {
        let (chain, signer, gas_id) = setup();
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "producer".to_string(),
            type_params: vec![],
            args: vec![],
            returns: vec![concrete("u64")],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "consumer".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Const(concrete("u64"))],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let tx = PtbTx {
            signers: vec![signer],
            commands: vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "producer".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "consumer".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Use {
                        cmd_idx: 0,
                        ret_idx: 0,
                    }],
                }),
            ],
            gas_payer: gas_id,
            gas_budget: 100,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![PqSignature(vec![0xCC; 8])],
        };
        let verifier = AlwaysOkVerifier;
        assert!(validate_ptb(&tx, &ctx(&chain, &verifier)).is_ok());
    }

    #[test]
    fn rejects_signer_arg_outside_signed_set() {
        let (chain, signer, gas_id) = setup();
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.args = vec![Arg::Signer(1)];
        }
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { ref reason, .. } if reason.contains("outside signed signer set")),
            "expected signer bounds TypeMismatch, got {err:?}"
        );
    }

    #[test]
    fn rejects_type_arg_value_that_does_not_match_declared_slot() {
        let (chain, signer, gas_id) = setup();
        let usdc = TypeTag::Concrete {
            petal_hash: [0x22; 32],
            type_name: "USDC".to_string(),
            type_args: vec![],
        };
        let loom = TypeTag::Concrete {
            petal_hash: [0x33; 32],
            type_name: "LOOM".to_string(),
            type_args: vec![],
        };
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "generic".to_string(),
            type_params: vec![crate::chain_iface::TypeParamDeclStub {
                name: "T".to_string(),
                phantom: true,
            }],
            args: vec![ArgDeclStub::TypeArg(0)],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.function = "generic".to_string();
            m.type_args = vec![usdc];
            m.args = vec![Arg::TypeArg(loom)];
        }
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { ref reason, .. } if reason.contains("TypeArg value")),
            "expected TypeArg value mismatch, got {err:?}"
        );
    }

    #[test]
    fn rejects_opaque_builtin_output_as_typed_move_arg() {
        let (chain, signer, gas_id) = setup();
        install_fn(
            &chain,
            "consumer",
            vec![ArgDeclStub::Const(concrete("u64"))],
            vec![],
        );
        let tx = PtbTx {
            signers: vec![signer],
            commands: vec![
                Command::Publish(crate::types::PublishCmd {
                    wasm_bytes: vec![0],
                    module_path: "/new".to_string(),
                    publisher_cap: None,
                }),
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "consumer".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Use {
                        cmd_idx: 0,
                        ret_idx: 0,
                    }],
                }),
            ],
            gas_payer: gas_id,
            gas_budget: 100,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![PqSignature(vec![0xCC; 8])],
        };
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::BuiltinFailed { ref reason, .. } if reason.contains("typed")),
            "expected opaque Use rejection, got {err:?}"
        );
    }

    #[test]
    fn split_coin_output_preserves_type_across_use_edge() {
        let (chain, signer, gas_id) = setup();
        let erased_coin = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "Coin".to_string(),
            type_args: vec![concrete("Erased")],
        };
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "producer".to_string(),
            type_params: vec![],
            args: vec![],
            returns: vec![loom_coin_tt()],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "consumer".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: erased_coin,
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let tx = PtbTx {
            signers: vec![signer],
            commands: vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "producer".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                Command::SplitCoins {
                    src: UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    },
                    amounts: vec![1],
                },
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "consumer".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Use {
                        cmd_idx: 1,
                        ret_idx: 0,
                    }],
                }),
            ],
            gas_payer: gas_id,
            gas_budget: 100,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![PqSignature(vec![0xCC; 8])],
        };
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { ref reason, .. } if reason.contains("LOOM") && reason.contains("Erased")),
            "expected split output type mismatch, got {err:?}"
        );
    }

    #[test]
    fn make_move_vec_output_cannot_be_consumed_as_scalar_object() {
        let (chain, signer, gas_id) = setup();
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "producer".to_string(),
            type_params: vec![],
            args: vec![],
            returns: vec![loom_coin_tt()],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "consumer".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: loom_coin_tt(),
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let tx = PtbTx {
            signers: vec![signer],
            commands: vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "producer".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                Command::MakeMoveVec {
                    ty: loom_coin_tt(),
                    uses: vec![UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    }],
                },
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "consumer".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Use {
                        cmd_idx: 1,
                        ret_idx: 0,
                    }],
                }),
            ],
            gas_payer: gas_id,
            gas_budget: 100,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![PqSignature(vec![0xCC; 8])],
        };
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { ref reason, .. } if reason.contains("vector") && reason.contains("Coin")),
            "expected vector/scalar TypeMismatch, got {err:?}"
        );
    }

    #[test]
    fn make_move_vec_rejects_elements_that_do_not_match_declared_type() {
        let (chain, signer, gas_id) = setup();
        let erased_coin = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "Coin".to_string(),
            type_args: vec![concrete("Erased")],
        };
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "producer".to_string(),
            type_params: vec![],
            args: vec![],
            returns: vec![loom_coin_tt()],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let tx = PtbTx {
            signers: vec![signer],
            commands: vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "producer".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                Command::MakeMoveVec {
                    ty: erased_coin,
                    uses: vec![UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    }],
                },
            ],
            gas_payer: gas_id,
            gas_budget: 100,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![PqSignature(vec![0xCC; 8])],
        };
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::BuiltinFailed { ref reason, .. } if reason.contains("MakeMoveVec") && reason.contains("LOOM") && reason.contains("Erased")),
            "expected MakeMoveVec element type failure, got {err:?}"
        );
    }

    /// An Object arg whose on-chain `type_tag` does not match the
    /// manifest's declared arg type is rejected with `TypeMismatch`.
    #[test]
    fn strict_typecheck_object_type_mismatch_rejected() {
        let (chain, signer, gas_id) = setup();
        let target_id = ObjectId([0xAA; 32]);
        chain.put_object(Object {
            id: target_id,
            type_tag: concrete("Pool"),
            owner: Owner::Shared,
            version: 0,
            payload: vec![],
        });
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "touch".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: concrete("Vault"), // wrong type vs. on-chain "Pool"
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(mc) = &mut tx.commands[0] {
            mc.function = "touch".to_string();
            mc.args = vec![Arg::Object {
                id: target_id,
                expected_version: ExpectedVersion(0),
                access_mode: AccessMode::Mutable,
            }];
        }
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { ref reason, .. } if reason.contains("Pool") && reason.contains("Vault")),
            "expected TypeMismatch citing Pool/Vault, got {err:?}"
        );
    }

    /// An Object arg whose on-chain type matches the manifest's declared
    /// type is accepted. Self-petal-hash (`[0u8; 32]`) in the manifest
    /// resolves to the executing petal's concrete hash.
    #[test]
    fn strict_typecheck_object_self_petal_hash_matches_current_petal() {
        let (chain, signer, gas_id) = setup();
        let target_id = ObjectId([0xAA; 32]);
        chain.put_object(Object {
            id: target_id,
            // Object emitted by some real petal — non-zero hash.
            type_tag: TypeTag::Concrete {
                petal_hash: [0xAB; 32],
                type_name: "Pool".to_string(),
                type_args: vec![],
            },
            owner: Owner::Shared,
            version: 0,
            payload: vec![],
        });
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "touch".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                // Self-referential manifest entry: hash = zero.
                ty: concrete("Pool"),
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(mc) = &mut tx.commands[0] {
            mc.function = "touch".to_string();
            mc.args = vec![Arg::Object {
                id: target_id,
                expected_version: ExpectedVersion(0),
                access_mode: AccessMode::Mutable,
            }];
        }
        let verifier = AlwaysOkVerifier;
        assert!(validate_ptb(&tx, &ctx(&chain, &verifier)).is_ok());
    }

    #[test]
    fn strict_typecheck_object_self_petal_hash_rejects_other_petal() {
        let (chain, signer, gas_id) = setup();
        let target_id = ObjectId([0xAA; 32]);
        chain.put_object(Object {
            id: target_id,
            type_tag: TypeTag::Concrete {
                petal_hash: [0xCD; 32],
                type_name: "Pool".to_string(),
                type_args: vec![],
            },
            owner: Owner::Shared,
            version: 0,
            payload: vec![],
        });
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "touch".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: concrete("Pool"),
                mode: AccessMode::Mutable,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(mc) = &mut tx.commands[0] {
            mc.function = "touch".to_string();
            mc.args = vec![Arg::Object {
                id: target_id,
                expected_version: ExpectedVersion(0),
                access_mode: AccessMode::Mutable,
            }];
        }
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn strict_typecheck_imported_top_level_object_accepts_other_petal() {
        let (chain, signer, gas_id) = setup();
        let target_id = ObjectId([0xAA; 32]);
        chain.put_object(Object {
            id: target_id,
            type_tag: TypeTag::Concrete {
                petal_hash: [0xCD; 32],
                type_name: "Pool".to_string(),
                type_args: vec![],
            },
            owner: Owner::Shared,
            version: 0,
            payload: vec![],
        });
        let mut m = sample_manifest();
        m.object_types.clear();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "quote".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: concrete("Pool"),
                mode: AccessMode::ReadOnly,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(mc) = &mut tx.commands[0] {
            mc.function = "quote".to_string();
            mc.args = vec![Arg::Object {
                id: target_id,
                expected_version: ExpectedVersion(0),
                access_mode: AccessMode::ReadOnly,
            }];
        }
        let verifier = AlwaysOkVerifier;
        assert!(validate_ptb(&tx, &ctx(&chain, &verifier)).is_ok());
    }

    #[test]
    fn strict_typecheck_use_self_petal_return_rejects_other_petal() {
        let (chain, signer, gas_id) = setup();

        let mut producer = PetalManifestStub {
            module_path: "/evil".to_string(),
            functions: vec![FunctionDeclStub {
                view: false,
                name: "forge".to_string(),
                type_params: vec![],
                args: vec![],
                returns: vec![concrete("Capability")],
                required_signers: 0,
                required_capabilities: vec![],
                attached_invariants: vec![],
            }],
            object_types: vec![],
            external_type_refs: vec![],
        };
        if let TypeTag::Concrete { type_args, .. } = &mut producer.functions[0].returns[0] {
            type_args.push(concrete("FaucetAdmin"));
        }
        chain.put_petal(Hash32([0xCD; 32]), vec![], producer);
        chain.put_path("/evil", Hash32([0xCD; 32]));

        let mut consumer = sample_manifest();
        let mut cap = concrete("Capability");
        if let TypeTag::Concrete { type_args, .. } = &mut cap {
            type_args.push(concrete("FaucetAdmin"));
        }
        consumer.functions.push(FunctionDeclStub {
            view: false,
            name: "mint".to_string(),
            type_params: vec![],
            args: vec![ArgDeclStub::Object {
                ty: cap,
                mode: AccessMode::ReadOnly,
            }],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], consumer);

        let tx = PtbTx {
            signers: vec![signer],
            commands: vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/evil".to_string(),
                        hash: Some(Hash32([0xCD; 32])),
                    },
                    function: "forge".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/bloom/petals/dex/pool".to_string(),
                        hash: Some(Hash32([0xAB; 32])),
                    },
                    function: "mint".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Use {
                        cmd_idx: 0,
                        ret_idx: 0,
                    }],
                }),
            ],
            gas_payer: gas_id,
            gas_budget: 100,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![PqSignature(vec![0xCC; 8])],
        };
        let verifier = AlwaysOkVerifier;
        assert!(matches!(
            validate_ptb(&tx, &ctx(&chain, &verifier)),
            Err(PtbError::TypeMismatch { .. })
        ));
    }

    /// Generic substitution works: a `Const T` decl with `T = u64` and
    /// 8 bytes is accepted; the same with 4 bytes is rejected.
    #[test]
    fn strict_typecheck_generic_substitution_match() {
        let (chain, signer, gas_id) = setup();
        let mut m = sample_manifest();
        m.functions.push(FunctionDeclStub {
            view: false,
            name: "gf".to_string(),
            type_params: vec![crate::chain_iface::TypeParamDeclStub {
                name: "T".to_string(),
                phantom: false,
            }],
            args: vec![ArgDeclStub::Const(TypeTag::Generic { idx: 0 })],
            returns: vec![],
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        });
        chain.put_petal(Hash32([0xAB; 32]), vec![], m);
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(mc) = &mut tx.commands[0] {
            mc.function = "gf".to_string();
            mc.type_args = vec![concrete("u64")];
            mc.args = vec![Arg::Const(vec![0u8; 8])];
        }
        let verifier = AlwaysOkVerifier;
        assert!(validate_ptb(&tx, &ctx(&chain, &verifier)).is_ok());

        // Now break it: same generic substitution but wrong byte length.
        if let Command::Move(mc) = &mut tx.commands[0] {
            mc.args = vec![Arg::Const(vec![0u8; 4])];
        }
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        assert!(
            matches!(err, PtbError::TypeMismatch { ref reason, .. } if reason.contains("u64")),
            "expected TypeMismatch citing u64 after substitution, got {err:?}"
        );
    }

    /// A tampered `PetalRef` — correct path, mutated hash — is rejected
    /// once the chain's VFS binds the path to a different hash.
    /// (P0-1 cross-check: hash pinning must be honoured.)
    #[test]
    fn rejects_tampered_petal_ref_with_correct_path() {
        let (chain, signer, gas_id) = setup();
        // Chain VFS binds the path to 0xAB; the PTB embeds 0xCC for the
        // same path.
        let mut tx = sample_ptb(signer, gas_id, 100);
        if let Command::Move(m) = &mut tx.commands[0] {
            m.petal.hash = Some(Hash32([0xCC; 32]));
        }
        let verifier = AlwaysOkVerifier;
        let err = validate_ptb(&tx, &ctx(&chain, &verifier)).unwrap_err();
        // Either we hit PetalNotFound (the chain doesn't know 0xCC)
        // or PetalPathHashMismatch (the binding contradicts). Both
        // count as "tampering rejected".
        assert!(
            matches!(
                err,
                PtbError::PetalNotFound { .. } | PtbError::PetalPathHashMismatch { .. }
            ),
            "expected PetalNotFound or PetalPathHashMismatch, got {err:?}"
        );
    }
}
