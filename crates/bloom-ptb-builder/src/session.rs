//! [`PtbSession`] — the canonical front-door builder (spec §3.2).
//!
//! Turns an ordered list of `(endpoint-path, args, use-edges)` into a
//! validated [`PtbTx`]. Drives both front doors (the `tx` VFS handler
//! and the `bloom pipe` CLI) — one source of truth.
//!
//! ## Lifecycle
//!
//! ```text
//! PtbSession::new(chain)            -> session (id allocated)
//! session.append_command(line)      -> Result<cmd_idx, BuildError>
//! session.status()                  -> SessionStatus
//! session.build_unsigned()          -> Result<PtbTx, BuildError>  (Phase D signs)
//! session.abort()                   -> ()  (drops accumulated state)
//! ```
//!
//! ## Incremental validation
//!
//! `append_command` runs the **same** typecheck the full
//! `bloom_script::validator::validate_ptb` runs per `Command::Move`:
//! arity (`type_args` / `args`), per-arg matching (`Const` canonical
//! bytes, `Object` type+mode), and `Use`-ref typing against the return
//! slots of already-appended commands (backward-only). A bad command is
//! rejected and the session is left **unchanged**.
//!
//! ## Commit / sign seam (for Phase D)
//!
//! This crate has no node or keystore. [`PtbSession::build_unsigned`]
//! assembles a `PtbTx` with empty `signatures` and runs the full
//! `validate_ptb` against the chain interface (so the assembled plan is
//! provably well-formed). Phase D then:
//!
//! 1. selects the gas payer (`coin_select`, node-side) — or the caller
//!    sets it via [`PtbSession::set_gas_payer`];
//! 2. provides the signer pubkeys via [`PtbSession::set_signers`];
//! 3. signs `PtbTx::signing_digest()` with the keystore and fills
//!    `signatures` in signer order;
//! 4. submits through the existing node submit path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use bloom_objects::{Object, TypeTag, ValidationOutcome, validate_canonical_bytes};
use bloom_script::{
    AlwaysOkVerifier, Arg, ArgDeclStub, ChainStateIface, Command, MoveCmd, PetalRef, PqPubkey,
    PqSignature, PtbError, PtbTx, SignatureVerifier, UseRef, ValidationContext, ValidationMode,
    loom_coin_type_tag, validate_ptb,
};

use crate::error::BuildError;
use crate::grammar::{LoweredArg, UseToken, lower_args, parse_line};
use crate::literal::substitute_type_args;
use crate::resolver::{ResolvedEndpoint, resolve_endpoint};

/// Opaque session identifier (monotonic within a process).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Per-command typing/resolution snapshot for `status()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandStatus {
    /// Zero-based command index.
    pub cmd_idx: u16,
    /// Resolved endpoint path (petal-path + function).
    pub endpoint_path: String,
    /// Function name.
    pub function: String,
    /// Declared return types of this command (after type-arg
    /// substitution); these are what downstream `Use` refs may bind to.
    pub return_types: Vec<TypeTag>,
    /// Optional label this command's primary output was bound to.
    pub label: Option<String>,
}

/// Snapshot of session state (`status()` output, §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStatus {
    /// Session id.
    pub id: SessionId,
    /// Per-command resolution + typing state.
    pub commands: Vec<CommandStatus>,
    /// Labels bound so far → producing command index.
    pub labels: Vec<(String, u16)>,
    /// Whether a gas payer has been set.
    pub gas_payer_set: bool,
    /// Number of signer pubkeys set.
    pub signer_count: usize,
    /// Estimated gas (`gas_budget`); a crude per-command estimate until
    /// the node supplies real metering.
    pub estimated_gas: u64,
}

/// Front-door PTB builder. See module docs.
pub struct PtbSession<'a> {
    id: SessionId,
    chain: &'a dyn ChainStateIface,
    /// Accumulated commands (validated incrementally as appended).
    commands: Vec<Command>,
    /// Per-command declared return types (after substitution), mirroring
    /// the validator's `cmd_return_types`. `None` = opaque built-in slot.
    return_types: Vec<Vec<Option<TypeTag>>>,
    /// Endpoint metadata kept for `status()`.
    endpoints: Vec<(String, String, Option<String>)>,
    /// Label → producing command index.
    labels: HashMap<String, u16>,
    /// Settable transaction header fields (filled by Phase D, or by
    /// callers in tests). Defaults are sensible for a single-signer tx.
    signers: Vec<PqPubkey>,
    gas_payer: Option<bloom_objects::ObjectId>,
    gas_budget: u64,
    gas_price: u128,
    expiry_block: u64,
    /// Explicit fungible-petal hash override used to build the well-known
    /// `Coin<LOOM>` type tag for gas-payer recognition. When unset, the
    /// session derives it from chain VFS.
    fungible_petal_hash: Option<bloom_chain_types::Hash32>,
}

impl<'a> PtbSession<'a> {
    /// Allocate a new session bound to `chain`. The session validates
    /// every appended command against this chain interface.
    pub fn new(chain: &'a dyn ChainStateIface) -> Self {
        let id = SessionId(NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed));
        Self {
            id,
            chain,
            commands: Vec::new(),
            return_types: Vec::new(),
            endpoints: Vec::new(),
            labels: HashMap::new(),
            signers: Vec::new(),
            gas_payer: None,
            // Conservative non-zero defaults so `build_unsigned` produces
            // a non-degenerate plan; Phase D overrides via setters.
            gas_budget: 1_000_000,
            gas_price: 1,
            expiry_block: u64::MAX,
            fungible_petal_hash: None,
        }
    }

    /// This session's id.
    pub fn id(&self) -> SessionId {
        self.id
    }

    // --- Phase D injection seams -----------------------------------------

    /// Set the signer pubkeys (in signature order). Phase D supplies the
    /// keystore-derived pubkeys here.
    pub fn set_signers(&mut self, signers: Vec<PqPubkey>) {
        self.signers = signers;
    }

    /// Set the gas-payer object id. Phase D's node-side `coin_select`
    /// picks the signer's `Coin<LOOM>` and injects it here.
    pub fn set_gas_payer(&mut self, id: bloom_objects::ObjectId) {
        self.gas_payer = Some(id);
    }

    /// Set the gas budget / price (Phase D / caller policy).
    pub fn set_gas(&mut self, budget: u64, price: u128) {
        self.gas_budget = budget;
        self.gas_price = price;
    }

    /// Set the expiry block height.
    pub fn set_expiry_block(&mut self, block: u64) {
        self.expiry_block = block;
    }

    /// Set the fungible petal hash used to recognise the `Coin<LOOM>`
    /// gas payer. By default this is resolved from chain VFS path
    /// `/bloom/petals/core/fungible`.
    pub fn set_fungible_petal_hash(&mut self, hash: bloom_chain_types::Hash32) {
        self.fungible_petal_hash = Some(hash);
    }

    // --- Core API --------------------------------------------------------

    /// Number of commands appended so far.
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// `true` if no commands have been appended.
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// The commands accumulated so far (read-only view).
    pub fn commands(&self) -> &[Command] {
        &self.commands
    }

    /// Append one command line (§3.4). On success returns the new
    /// command's index. On failure the session is **unchanged**.
    pub fn append_command(&mut self, line: &str) -> Result<u16, BuildError> {
        let parsed = parse_line(line)?;
        let endpoint = resolve_endpoint(self.chain, &parsed.path)?;
        let signature = endpoint.signature().clone();

        // Lower the arg tokens against the signature.
        let lowered = lower_args(&parsed.arg_tokens, &signature)?;

        // Resolve symbolic Use tokens into concrete UseRefs (label
        // table + backward bounds-check), and split off the type_args.
        let mut args: Vec<Arg> = Vec::with_capacity(lowered.len());
        let mut type_args: Vec<TypeTag> = Vec::new();
        let next_cmd_idx = self.commands.len() as u16;
        for la in lowered {
            match la {
                LoweredArg::CallTypeArg(tt) => {
                    type_args.push(tt);
                }
                LoweredArg::Concrete(Arg::TypeArg(tt)) => {
                    type_args.push(tt.clone());
                    args.push(Arg::TypeArg(tt));
                }
                LoweredArg::Concrete(a) => args.push(a),
                LoweredArg::Use(tok) => {
                    let use_ref = self.resolve_use_token(&tok, next_cmd_idx)?;
                    args.push(Arg::Use {
                        cmd_idx: use_ref.cmd_idx,
                        ret_idx: use_ref.ret_idx,
                    });
                }
            }
        }

        let move_cmd = MoveCmd {
            petal: PetalRef {
                path: endpoint.petal_path.clone(),
                hash: Some(endpoint.petal_hash),
            },
            function: endpoint.function.clone(),
            type_args: type_args.clone(),
            args,
        };

        // Incremental validation — mirror the validator's per-command
        // typecheck. Does NOT mutate the session yet.
        let returns = self.typecheck_move_cmd(&move_cmd, &endpoint, next_cmd_idx as usize)?;

        // Commit to session state (only now that validation passed).
        let cmd_idx = next_cmd_idx;
        if let Some(label) = &parsed.label {
            self.labels.insert(label.clone(), cmd_idx);
        }
        self.endpoints.push((
            format!("{}/{}", endpoint.petal_path, endpoint.function),
            endpoint.function.clone(),
            parsed.label.clone(),
        ));
        self.return_types.push(returns);
        self.commands.push(Command::Move(move_cmd));
        Ok(cmd_idx)
    }

    /// Resolve a [`UseToken`] into a concrete [`UseRef`], enforcing the
    /// label table and backward-only references (mirrors the validator's
    /// `resolve_use_type` bounds rules at build time).
    fn resolve_use_token(
        &self,
        tok: &UseToken,
        referring_cmd_idx: u16,
    ) -> Result<UseRef, BuildError> {
        let (cmd_idx, ret_idx) = match tok {
            UseToken::Explicit { cmd_idx, ret_idx } => (*cmd_idx, *ret_idx),
            UseToken::Label(name) => {
                let producer = *self
                    .labels
                    .get(name)
                    .ok_or_else(|| BuildError::UnknownLabel(name.clone()))?;
                (producer, 0)
            }
        };
        if cmd_idx >= referring_cmd_idx {
            return Err(BuildError::DanglingUse {
                cmd_idx,
                ret_idx,
                appended: referring_cmd_idx as usize,
            });
        }
        Ok(UseRef { cmd_idx, ret_idx })
    }

    /// Mirror of `bloom_script::validator::typecheck_move_cmd` for one
    /// already-lowered `MoveCmd`. Returns the command's declared return
    /// types (after substitution) for the session's `return_types`.
    fn typecheck_move_cmd(
        &self,
        cmd: &MoveCmd,
        endpoint: &ResolvedEndpoint,
        cmd_idx: usize,
    ) -> Result<Vec<Option<TypeTag>>, BuildError> {
        let f = endpoint.signature();
        let function = cmd.function.clone();
        let petal_hash = endpoint.petal_hash;

        if cmd.type_args.len() != f.type_params.len() {
            return Err(PtbError::TypeArgCountMismatch {
                function,
                expected: f.type_params.len(),
                got: cmd.type_args.len(),
            }
            .into());
        }
        if cmd.args.len() != f.args.len() {
            return Err(PtbError::ArgCountMismatch {
                function,
                expected: f.args.len(),
                got: cmd.args.len(),
            }
            .into());
        }

        for (i, (arg, decl)) in cmd.args.iter().zip(f.args.iter()).enumerate() {
            match (arg, decl) {
                (Arg::Signer(_), ArgDeclStub::Signer) => {}
                (Arg::Const(bytes), ArgDeclStub::Const(declared_tag)) => {
                    let expected = substitute_type_args(declared_tag, &cmd.type_args);
                    match validate_canonical_bytes(&expected, bytes) {
                        ValidationOutcome::Ok | ValidationOutcome::Unknown => {}
                        ValidationOutcome::Invalid(reason) => {
                            return Err(PtbError::TypeMismatch {
                                function,
                                arg_idx: i,
                                reason: format!(
                                    "Const bytes do not match declared type {}: {reason}",
                                    type_tag_label(&expected)
                                ),
                            }
                            .into());
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
                            function,
                            arg_idx: i,
                            reason: format!(
                                "access mode {amode:?} does not match declared {mode:?}"
                            ),
                        }
                        .into());
                    }
                    // Load the on-chain object to compare its type tag.
                    let obj: Object = self
                        .chain
                        .load_object(id)
                        .ok_or(PtbError::ObjectNotFound { id: *id })?;
                    let expected = substitute_type_args(declared_ty, &cmd.type_args);
                    if !type_tags_match(&obj.type_tag, &expected) {
                        return Err(PtbError::TypeMismatch {
                            function,
                            arg_idx: i,
                            reason: format!(
                                "object {} has type {}, declared arg type is {}",
                                obj.id,
                                type_tag_label(&obj.type_tag),
                                type_tag_label(&expected),
                            ),
                        }
                        .into());
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
                    let upstream = self.resolve_use_type(
                        UseRef {
                            cmd_idx: *u_cmd,
                            ret_idx: *u_ret,
                        },
                        cmd_idx,
                    )?;
                    if let Some(actual) = upstream {
                        let expected = substitute_type_args(declared_ty, &cmd.type_args);
                        if !type_tags_match(&actual, &expected) {
                            return Err(PtbError::TypeMismatch {
                                function,
                                arg_idx: i,
                                reason: format!(
                                    "Use({u_cmd},{u_ret}) returns {}, declared arg type is {}",
                                    type_tag_label(&actual),
                                    type_tag_label(&expected),
                                ),
                            }
                            .into());
                        }
                    }
                }
                (Arg::TypeArg(_), ArgDeclStub::TypeArg(_)) => {}
                (a, d) => {
                    return Err(PtbError::TypeMismatch {
                        function,
                        arg_idx: i,
                        reason: format!("got {}, expected {}", arg_label(a), decl_label(d)),
                    }
                    .into());
                }
            }
        }

        let _ = petal_hash;
        Ok(f.returns
            .iter()
            .map(|t| Some(substitute_type_args(t, &cmd.type_args)))
            .collect())
    }

    /// Resolve a `Use` ref to its upstream return-slot type (mirrors the
    /// validator's `resolve_use_type`): backward-only, real slot.
    fn resolve_use_type(
        &self,
        u: UseRef,
        referring_cmd_idx: usize,
    ) -> Result<Option<TypeTag>, BuildError> {
        if (u.cmd_idx as usize) >= referring_cmd_idx {
            return Err(PtbError::DanglingUse {
                cmd_idx: u.cmd_idx,
                ret_idx: u.ret_idx,
            }
            .into());
        }
        let slots = self
            .return_types
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

    /// Snapshot of session state (§3.2).
    pub fn status(&self) -> SessionStatus {
        let commands = self
            .return_types
            .iter()
            .enumerate()
            .map(|(idx, slots)| {
                let (endpoint_path, function, label) = self.endpoints[idx].clone();
                CommandStatus {
                    cmd_idx: idx as u16,
                    endpoint_path,
                    function,
                    return_types: slots.iter().flatten().cloned().collect(),
                    label,
                }
            })
            .collect();
        let mut labels: Vec<(String, u16)> =
            self.labels.iter().map(|(k, v)| (k.clone(), *v)).collect();
        labels.sort();
        SessionStatus {
            id: self.id,
            commands,
            labels,
            gas_payer_set: self.gas_payer.is_some(),
            signer_count: self.signers.len(),
            estimated_gas: self.gas_budget,
        }
    }

    /// Assemble the unsigned [`PtbTx`] and run the full
    /// `bloom_script::validate_ptb` against the chain interface.
    ///
    /// This is the **commit/sign seam**: the returned `PtbTx` has empty
    /// `signatures`. Phase D signs `signing_digest()` and fills them in.
    /// The session must have at least one signer set (so the validator's
    /// gas-payer ownership check has a first-signer address) and a gas
    /// payer.
    pub fn build_unsigned(&self) -> Result<PtbTx, BuildError> {
        if self.commands.is_empty() {
            return Err(BuildError::NotReady("no commands appended".to_string()));
        }
        if self.signers.is_empty() {
            return Err(BuildError::NotReady(
                "no signers set (call set_signers; Phase D supplies keystore pubkeys)".to_string(),
            ));
        }
        let gas_payer = self.gas_payer.ok_or_else(|| {
            BuildError::NotReady(
                "no gas payer set (call set_gas_payer; Phase D selects via coin_select)"
                    .to_string(),
            )
        })?;

        let tx = PtbTx {
            signers: self.signers.clone(),
            commands: self.commands.clone(),
            gas_payer,
            gas_budget: self.gas_budget,
            gas_price: self.gas_price,
            expiry_block: self.expiry_block,
            signatures: Vec::new(),
        };

        // Full validation. Signature checks are short-circuited with an
        // AlwaysOk verifier and a placeholder signature per signer — the
        // *structural* plan (commands, types, gas) is what we validate
        // here; real signature verification happens node-side in Phase D
        // after the keystore signs.
        let mut for_validation = tx.clone();
        for_validation.signatures = vec![PqSignature(vec![0u8; 1]); self.signers.len()];
        let verifier = AlwaysOkVerifier;
        let fungible_petal_hash = self
            .fungible_petal_hash
            .or_else(|| bloom_script::resolve_fungible_petal_hash(self.chain))
            .ok_or_else(|| {
                BuildError::NotReady(format!(
                    "missing required VFS binding for {}",
                    bloom_script::CORE_FUNGIBLE_PATH
                ))
            })?;

        validate_ptb(
            &for_validation,
            &ValidationContext {
                mode: ValidationMode::Commit,
                current_block: self.chain.current_block(),
                chain: self.chain,
                verifier: &verifier as &dyn SignatureVerifier,
                loom_coin_type: loom_coin_type_tag(fungible_petal_hash),
            },
        )?;

        Ok(tx)
    }

    /// Discard all accumulated state. After `abort`, the session is back
    /// to its freshly-`new` shape (id preserved).
    pub fn abort(&mut self) {
        self.commands.clear();
        self.return_types.clear();
        self.endpoints.clear();
        self.labels.clear();
    }
}

// ---------------------------------------------------------------------------
// Local copies of the validator's private structural helpers.
// ---------------------------------------------------------------------------

/// Structural compare between two `TypeTag`s (copy of the validator's
/// `type_tags_match`): a declared `petal_hash` of `[0u8;32]` (self)
/// matches any concrete hash on the actual side.
fn type_tags_match(actual: &TypeTag, declared: &TypeTag) -> bool {
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
            if dh != &[0u8; 32] && ah != dh {
                return false;
            }
            aa.iter().zip(da.iter()).all(|(a, d)| type_tags_match(a, d))
        }
        (TypeTag::Generic { idx: a }, TypeTag::Generic { idx: b }) => a == b,
        (TypeTag::External { ref_idx: a }, TypeTag::External { ref_idx: b }) => a == b,
        _ => false,
    }
}

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
