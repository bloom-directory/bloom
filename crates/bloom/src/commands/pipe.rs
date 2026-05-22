//! `bloom pipe '<expr>'` — the CLI front door (spec §3.5).
//!
//! Parses a pipe expression (linear `A | B | C` plus named
//! `--a <(<sub-expr>)>` DAG inputs), lowers it via
//! [`bloom_ptb_builder::lower_pipe_expr`], drives a
//! [`bloom_ptb_builder::PtbSession`], commits, and streams the receipt
//! to stdout. **Behaviour is identical to the NFS `tx`-session path**
//! (the Phase D gate): both front doors append the same lowered command
//! lines to the same `PtbSession` and assemble the same `PtbTx`.
//!
//! ## Node boundary (and why the lowering/session path is node-free)
//!
//! The CLI rebuilds an in-process daemon per invocation and has no
//! standing chain connection in unit tests. We therefore split the
//! command into:
//!
//! - [`lower_and_build`] — the pure, node-free core: pipe expr +
//!   chain interface → validated [`PtbTx`]. This is the same code path
//!   the tx-session handler runs, and it is fully unit-tested below
//!   against an in-memory chain mock (no node required).
//! - [`receipt_ndjson`] — the canonical NDJSON receipt projection,
//!   byte-identical to the tx handler's `commit` output.
//! - [`run_pipe`] — the dispatcher: lowers + builds against the live
//!   chain, then (in a deployment that can reach a node) signs the
//!   digest and submits. Submission is gated on a reachable node; the
//!   structural plan is what this function renders.

use anyhow::{Context, Result};
use serde_json::Value;

use bloom_objects::{ObjectId, TypeTag};
use bloom_ptb_builder::{PtbSession, SessionStatus, lower_pipe_expr};
use bloom_script::{ChainStateIface, PtbTx};

/// The validated plan a pipe expression lowers to: the unsigned
/// [`PtbTx`] (the commit/sign seam) plus the [`SessionStatus`] snapshot
/// (resolved endpoints + return typing) the receipt is rendered from.
#[derive(Debug)]
pub struct LoweredPlan {
    /// The assembled, fully-validated unsigned transaction. `signatures`
    /// is empty — the caller signs `signing_digest()` and submits.
    pub tx: PtbTx,
    /// Per-command resolution/typing snapshot, identical to what the
    /// tx-session `status` file projects.
    pub status: SessionStatus,
}

/// Lower a pipe expression and build the validated [`LoweredPlan`]
/// against `chain`. This is the **shared, node-free core** — identical
/// to the tx-session handler's append + build path: it drives the same
/// [`PtbSession`], so a plan lowered here commits byte-identically to
/// one staged over NFS.
///
/// `signers` and `gas_payer` are the header-injection seam (the CLI
/// derives them from the keystore + `coin_select`; tests pass them
/// explicitly). The returned tx has empty `signatures` — the caller
/// signs `signing_digest()` and submits.
pub fn lower_and_build(
    chain: &dyn ChainStateIface,
    expr: &str,
    signers: Vec<[u8; 32]>,
    gas_payer: ObjectId,
) -> Result<LoweredPlan> {
    let lines = lower_pipe_expr(expr).context("lower pipe expression")?;
    let mut session = PtbSession::new(chain);
    for line in &lines {
        session
            .append_command(line)
            .with_context(|| format!("append command {line:?}"))?;
    }
    session.set_signers(signers);
    session.set_gas_payer(gas_payer);
    let tx = session.build_unsigned().context("build unsigned PTB")?;
    let status = session.status();
    Ok(LoweredPlan { tx, status })
}

/// Render the canonical NDJSON receipt for a [`LoweredPlan`] — the same
/// projection the tx-session `commit` file emits (modulo the NFS path's
/// `session` id), so the CLI and NFS front doors stream byte-identical
/// per-command receipt lines for the same plan.
///
/// One JSON object per line: a `ptb` header (hash, signer count, gas
/// header, command count) followed by one `command` line per command,
/// carrying its resolved endpoint and declared return-type labels.
pub fn receipt_ndjson(plan: &LoweredPlan) -> String {
    let mut out = header_json(&plan.tx).to_string();
    out.push('\n');
    for line in command_lines(&plan.status) {
        out.push_str(&line.to_string());
        out.push('\n');
    }
    out
}

/// The `ptb` header line shared with the tx-session commit projection.
fn header_json(tx: &PtbTx) -> Value {
    let ptb_hash = tx.signing_digest();
    serde_json::json!({
        "kind": "ptb",
        "ptb_hash": format!("0x{}", hex::encode(ptb_hash)),
        "signers": tx.signers.len(),
        "gas_payer": format!("0x{}", hex::encode(tx.gas_payer.0)),
        "gas_budget": tx.gas_budget,
        "gas_price": tx.gas_price.to_string(),
        "gas_reservation": tx.required_gas_reservation().to_string(),
        "commands": tx.commands.len(),
    })
}

/// The per-`command` receipt lines, projected from the session status so
/// the resolved endpoint + return typing match the NFS `commit` output.
fn command_lines(status: &SessionStatus) -> Vec<Value> {
    status
        .commands
        .iter()
        .map(|cs| {
            serde_json::json!({
                "kind": "command",
                "cmd_idx": cs.cmd_idx,
                "endpoint": cs.endpoint_path,
                "returns": cs.return_types.iter().map(type_tag_label).collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// Human/debug label for a [`TypeTag`] (non-authoritative projection,
/// matching the tx-session handler's `type_tag_label`).
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

// ---------------------------------------------------------------------------
// CLI dispatcher
// ---------------------------------------------------------------------------

/// `bloom pipe '<expr>' [--signer <hex>]... --gas-payer <hex>` entry point
/// dispatched from `main`.
///
/// It validates the CLI-surface arguments (so a malformed signer or
/// gas-payer fails fast, before any chain access), then resolves the
/// [`ChainStateIface`] the lowering core needs. The v1 in-process CLI has
/// no colocated chain `State` to hand it (see [`run_pipe`] for the full
/// boundary rationale), so this returns a documented error rather than a
/// partial receipt. A node-colocated deployment supplies its
/// `PtbChainAdapter` here and delegates to [`run_pipe`].
pub fn run(expr: &str, signers: &[String], gas_payer: &str) -> Result<()> {
    // Parse the CLI surface up front so bad input fails closed regardless
    // of chain availability.
    let _signers = parse_signers(signers)?;
    let _gas_payer = parse_object_id(gas_payer).context("parse --gas-payer")?;

    // Resolve the chain interface. The per-invocation CLI daemon does not
    // colocate a sovereign-chain `State` (that lives in the validator
    // process; the node RPC surface exposes only narrow account/block/key
    // reads, not the object + manifest graph the resolver walks). When a
    // deployment can supply one, it constructs a `PtbChainAdapter` and
    // hands it to `run_pipe`.
    let chain: Option<&dyn ChainStateIface> = None;
    match chain {
        Some(chain) => run_pipe(chain, expr, signers, gas_payer),
        None => anyhow::bail!(
            "bloom pipe: no chain interface in this process — pipe lowering runs \
             against a colocated node `State` (the validator process) or the NFS \
             `tx`-session front door, not the per-invocation CLI daemon"
        ),
    }
}

/// `bloom pipe '<expr>' [--signer <hex>]... --gas-payer <hex>` — lower a
/// pipe expression, build the validated PTB, and stream the canonical
/// receipt to stdout.
///
/// ## Node boundary
///
/// Lowering + validation runs against a [`ChainStateIface`]. The v1 CLI
/// rebuilds an in-process daemon per invocation and does **not**
/// colocate a chain `State` (that lives in the `bloom chain
/// run-validator` process; the node RPC surface exposes only narrow
/// account/block/key reads, not the object + manifest graph the resolver
/// needs). Submitting therefore requires a chain interface the caller
/// supplies — in a node-colocated deployment this is the validator's
/// `PtbChainAdapter`, signed with the operator key and posted via
/// `TxKind::SubmitPtb`. This dispatcher renders the structural plan that
/// gets signed and submitted there; the lowering/build/receipt path it
/// shares with the NFS `tx`-session front door is the fully-tested core
/// ([`lower_and_build`] / [`receipt_ndjson`], exercised below without a
/// node).
///
/// `signers` are 32-byte hex pubkeys (signature order); `gas_payer` is a
/// 32-byte hex object id.
pub fn run_pipe(
    chain: &dyn ChainStateIface,
    expr: &str,
    signers: &[String],
    gas_payer: &str,
) -> Result<()> {
    let signers = parse_signers(signers)?;
    let gas_payer = parse_object_id(gas_payer).context("parse --gas-payer")?;
    let plan = lower_and_build(chain, expr, signers, gas_payer)?;
    let receipt = receipt_ndjson(&plan);
    use std::io::Write as _;
    std::io::stdout()
        .write_all(receipt.as_bytes())
        .context("write receipt")?;
    Ok(())
}

/// Parse the repeated `--signer <hex>` pubkeys into the signer vector.
fn parse_signers(signers: &[String]) -> Result<Vec<[u8; 32]>> {
    signers
        .iter()
        .map(|s| parse_object_id(s).with_context(|| format!("parse --signer {s:?}")))
        .map(|r| r.map(|id| id.0))
        .collect()
}

/// Parse a 32-byte hex value (with or without a `0x` prefix) into an
/// [`ObjectId`]. Used for both signer pubkeys and the gas-payer id.
fn parse_object_id(s: &str) -> Result<ObjectId> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x")).context("decode hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes (64 hex chars)"))?;
    Ok(ObjectId(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use bloom_chain_types::Hash32;
    use bloom_objects::{AccessMode, Object, Owner};
    use bloom_script::{
        Arg, ArgDeclStub, Command, FunctionDeclStub, PetalManifestStub, loom_coin_type_tag,
    };

    // -- In-process chain mock (mirrors bloom-ptb-builder's tests.rs) ------

    #[derive(Default)]
    struct MockChain {
        objects: Mutex<HashMap<[u8; 32], Object>>,
        manifests: Mutex<HashMap<[u8; 32], PetalManifestStub>>,
        paths: Mutex<HashMap<String, Hash32>>,
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
            self.objects.lock().unwrap().insert(obj.id.0, obj);
        }
        fn put_petal(&self, hash: Hash32, manifest: PetalManifestStub) {
            self.manifests.lock().unwrap().insert(hash.0, manifest);
        }
        fn put_path(&self, path: &str, hash: Hash32) {
            self.paths.lock().unwrap().insert(path.to_string(), hash);
        }
    }

    impl ChainStateIface for MockChain {
        fn load_object(&self, id: &ObjectId) -> Option<Object> {
            self.objects.lock().unwrap().get(&id.0).cloned()
        }
        fn load_petal(&self, hash: &Hash32) -> Option<Vec<u8>> {
            self.manifests.lock().unwrap().get(&hash.0).map(|_| vec![0])
        }
        fn load_manifest(&self, hash: &Hash32) -> Option<PetalManifestStub> {
            self.manifests.lock().unwrap().get(&hash.0).cloned()
        }
        fn resolve_path(&self, path: &str) -> Option<Hash32> {
            self.paths.lock().unwrap().get(path).copied()
        }
        fn current_block(&self) -> u64 {
            self.block
        }
    }

    const POOL_HASH: Hash32 = Hash32([0xAB; 32]);
    const POOL_PATH: &str = "/bloom/dex/pool";

    fn concrete(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: vec![],
        }
    }

    fn coin(inner: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "Coin".to_string(),
            type_args: vec![concrete(inner)],
        }
    }

    fn func(name: &str, args: Vec<ArgDeclStub>, returns: Vec<TypeTag>) -> FunctionDeclStub {
        FunctionDeclStub {
            name: name.to_string(),
            type_params: vec![],
            args,
            returns,
            attached_invariants: vec![],
        }
    }

    /// A chain with a pool petal + a pre-funded `Coin<LOOM>` gas payer.
    fn chain_with(funcs: Vec<FunctionDeclStub>, signer: [u8; 32]) -> (MockChain, ObjectId) {
        let chain = MockChain::new();
        let manifest = PetalManifestStub {
            module_path: POOL_PATH.to_string(),
            functions: funcs,
            object_types: vec![],
            external_type_refs: vec![],
        };
        chain.put_petal(POOL_HASH, manifest);
        chain.put_path(POOL_PATH, POOL_HASH);

        let gas_id = ObjectId([0xFE; 32]);
        let mut payload = vec![0u8; 32];
        payload.extend_from_slice(&1_000_000u128.to_be_bytes());
        chain.put_object(Object {
            id: gas_id,
            type_tag: loom_coin_type_tag(Hash32([0u8; 32])),
            owner: Owner::Address(signer),
            version: 0,
            payload,
        });
        (chain, gas_id)
    }

    /// A linear `A | B | C` pipe lowers to the expected use-edge chain
    /// and builds a 3-command PtbTx.
    #[test]
    fn linear_pipe_lowers_to_use_edge_chain() {
        let signer = [0x11; 32];
        let (chain, gas) = chain_with(
            vec![
                func("spend", vec![], vec![coin("LOOM")]),
                func(
                    "swap",
                    vec![ArgDeclStub::Object {
                        ty: coin("LOOM"),
                        mode: AccessMode::Consume,
                    }],
                    vec![coin("LOOM")],
                ),
                func(
                    "receive",
                    vec![ArgDeclStub::Object {
                        ty: coin("LOOM"),
                        mode: AccessMode::Consume,
                    }],
                    vec![],
                ),
            ],
            signer,
        );
        let plan = lower_and_build(
            &chain,
            "/bloom/dex/pool/spend | /bloom/dex/pool/swap | /bloom/dex/pool/receive",
            vec![signer],
            gas,
        )
        .unwrap();
        let tx = &plan.tx;
        assert_eq!(tx.commands.len(), 3);
        // swap consumes spend's output (cmd 0), receive consumes swap's
        // output (cmd 1) — the linear use-edge chain.
        match &tx.commands[1] {
            Command::Move(m) => assert_eq!(
                m.args,
                vec![Arg::Use {
                    cmd_idx: 0,
                    ret_idx: 0
                }]
            ),
            _ => panic!(),
        }
        match &tx.commands[2] {
            Command::Move(m) => assert_eq!(
                m.args,
                vec![Arg::Use {
                    cmd_idx: 1,
                    ret_idx: 0
                }]
            ),
            _ => panic!(),
        }
        // The receipt is well-formed NDJSON: header + one line per command.
        let receipt = receipt_ndjson(&plan);
        let lines: Vec<&str> = receipt.lines().collect();
        assert_eq!(lines.len(), 4);
        let header: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(header["commands"], 3);
        assert_eq!(header["signers"], 1);
    }

    /// A named-input `--a <(…)> --b <(…)>` DAG lowers to the
    /// sub-expressions first, then the consuming command with its two
    /// `Use` edges — the add-liquidity case (litmus 5.3).
    #[test]
    fn named_dag_pipe_lowers_to_two_use_edges() {
        let signer = [0x22; 32];
        let (chain, gas) = chain_with(
            vec![
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
            ],
            signer,
        );
        let plan = lower_and_build(
            &chain,
            "/bloom/dex/pool/add_liquidity min-lp=10 --a <(/bloom/dex/pool/spend_eth)> --b <(/bloom/dex/pool/spend_usdc)>",
            vec![signer],
            gas,
        )
        .unwrap();
        let tx = &plan.tx;
        assert_eq!(tx.commands.len(), 3);
        match &tx.commands[2] {
            Command::Move(m) => {
                assert_eq!(m.function, "add_liquidity");
                assert_eq!(
                    m.args,
                    vec![
                        Arg::Const(10u64.to_be_bytes().to_vec()),
                        Arg::Use {
                            cmd_idx: 0,
                            ret_idx: 0
                        },
                        Arg::Use {
                            cmd_idx: 1,
                            ret_idx: 0
                        },
                    ]
                );
            }
            _ => panic!(),
        }
    }

    /// A dangling forward `@ref` fails the build closed (same error the
    /// tx-session handler surfaces).
    #[test]
    fn dangling_ref_fails_closed() {
        let signer = [0x33; 32];
        let (chain, gas) = chain_with(
            vec![func(
                "consumer",
                vec![ArgDeclStub::Const(concrete("u64"))],
                vec![],
            )],
            signer,
        );
        let err = lower_and_build(&chain, "/bloom/dex/pool/consumer @9.0", vec![signer], gas)
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("dangling") || msg.contains("@9.0"), "{msg}");
    }

    /// The CLI lower+build path produces the *same* PtbTx the tx-session
    /// path would: feeding the lowered lines into a bare PtbSession and
    /// building yields an identical command list + digest.
    #[test]
    fn cli_and_session_paths_commit_identically() {
        let signer = [0x44; 32];
        let (chain, gas) = chain_with(
            vec![
                func("spend", vec![], vec![coin("LOOM")]),
                func(
                    "receive",
                    vec![ArgDeclStub::Object {
                        ty: coin("LOOM"),
                        mode: AccessMode::Consume,
                    }],
                    vec![],
                ),
            ],
            signer,
        );
        let expr = "/bloom/dex/pool/spend | /bloom/dex/pool/receive";

        // CLI path.
        let cli = lower_and_build(&chain, expr, vec![signer], gas).unwrap();

        // tx-session path: same lowered lines, same PtbSession seam.
        let lines = lower_pipe_expr(expr).unwrap();
        let mut session = PtbSession::new(&chain);
        for line in &lines {
            session.append_command(line).unwrap();
        }
        session.set_signers(vec![signer]);
        session.set_gas_payer(gas);
        let session = LoweredPlan {
            tx: session.build_unsigned().unwrap(),
            status: session.status(),
        };
        // (`build_unsigned` and `status` both take `&self`; the struct
        // field assignment evaluates left-to-right.)

        assert_eq!(cli.tx.commands, session.tx.commands);
        assert_eq!(cli.tx.signing_digest(), session.tx.signing_digest());
        assert_eq!(receipt_ndjson(&cli), receipt_ndjson(&session));
    }
}
