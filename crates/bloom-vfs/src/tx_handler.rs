//! `tx/` — the tx-session VFS front door (spec §3.3).
//!
//! Pure NFS read/write staging over a [`bloom_ptb_builder::PtbSession`].
//! This is the **canonical substrate**: the `bloom pipe` CLI and this
//! handler both drive the same `PtbSession` code path, so a plan staged
//! over NFS commits *identically* to one lowered from a pipe expression
//! (Phase D gate).
//!
//! Path layout (relative to the `tx` mount point):
//!
//! ```text
//! new                 # cat → allocate a PtbSession, returns "<id>\n"
//! <id>/
//!   cmd               # write a command line → append_command;
//!                     #   cat → lists the appended command lines
//!   status            # cat → JSON: resolved endpoints, arg/use typing, est. gas
//!   commit            # cat → finalize + (sign) + submit; NDJSON receipt.
//!                     #   Errors leave the session intact.
//!   abort             # write/cat → discard the session
//!   signer            # write a 32-byte hex pubkey → PtbSession::set_signers
//!                     #   (the §3.2 / §3.4 header injection seam)
//!   gas-payer         # write an object id (hex) → PtbSession::set_gas_payer
//! ```
//!
//! ## Session storage and the `PtbSession` lifetime
//!
//! [`bloom_ptb_builder::PtbSession`] borrows `&'a dyn ChainStateIface`,
//! so it cannot be stored directly in a `'static` registry without a
//! self-referential borrow against the handler-owned chain. Instead the
//! registry stores each session's **inputs** — the accumulated command
//! lines plus the header settings (signers, gas payer, gas, expiry) —
//! and every VFS op reconstructs a fresh `PtbSession::new(&*chain)` and
//! replays the stored lines. This keeps `PtbSession` the single source
//! of truth (same `append_command` / `build_unsigned` path the CLI
//! uses) while sidestepping the lifetime. Replaying is cheap and the
//! validation outcome is identical to incremental appends, so a bad
//! `cmd` write is rejected without mutating the stored lines — the prior
//! commands survive (spec §3.3 / §6 "leaves the session intact").
//!
//! ## Commit and the node boundary
//!
//! This crate has no node or keystore, so live submission is injected via
//! [`PtbSubmitter`]. `commit` always assembles and validates the `PtbTx`;
//! with a submitter it then signs/submits and appends the on-chain receipt
//! NDJSON, while tests can still run the structural path without a node.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use bloom_objects::{ObjectId, TypeTag};
use bloom_ptb_builder::session::SessionId;
use bloom_ptb_builder::{BuildError, PtbSession, SessionStatus};
use bloom_script::{ChainStateIface, PtbTx};

use crate::handler::{Entry, Handler, HandlerError};
use crate::paginate;
use crate::path::VfsPath;

/// Per-session state held in the registry. Re-applied to a fresh
/// [`PtbSession`] on every VFS op (see the module docs for why we store
/// the *inputs* rather than the borrowing session struct).
#[derive(Clone, Debug, Default)]
struct SessionState {
    /// Accumulated command lines, in append order. The single source of
    /// truth a `PtbSession` is rebuilt from.
    lines: Vec<String>,
    /// Signer pubkeys (`set_signers`), written via `<id>/signer`.
    signers: Vec<[u8; 32]>,
    /// Gas-payer object id (`set_gas_payer`), written via `<id>/gas-payer`.
    gas_payer: Option<ObjectId>,
}

/// The `tx` VFS handler. Owns the chain interface and the session
/// registry.
#[derive(Clone)]
pub struct TxHandler {
    chain: Arc<dyn ChainStateIface + Send + Sync>,
    submitter: Option<Arc<dyn PtbSubmitter>>,
    sessions: Arc<Mutex<HashMap<SessionId, SessionState>>>,
}

/// Optional live submission backend for `tx/<id>/commit`.
///
/// `bloom-vfs` owns the staging semantics, but the daemon owns keys and node
/// RPC. This trait keeps the VFS handler generic while allowing production
/// mounts to sign, submit, wait for the on-chain receipt, and append it to the
/// same NDJSON stream.
#[async_trait]
pub trait PtbSubmitter: Send + Sync {
    /// Select a gas-payer object when the session did not explicitly set one.
    async fn select_gas_payer(&self, signers: &[[u8; 32]]) -> Result<ObjectId, HandlerError>;

    /// Sign and submit a fully validated PTB, returning extra NDJSON records
    /// to append after the structural PTB/command receipt lines.
    async fn submit_ptb(
        &self,
        session_id: SessionId,
        tx: PtbTx,
        status: SessionStatus,
    ) -> Result<Vec<serde_json::Value>, HandlerError>;
}

impl TxHandler {
    /// Build a handler over a chain interface. The chain is consulted by
    /// the resolver/validator on every append and commit.
    pub fn new(chain: Arc<dyn ChainStateIface + Send + Sync>) -> Self {
        Self {
            chain,
            submitter: None,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Attach a live signer/submitter backend. Without one, `commit` preserves
    /// the historical structural behavior used by unit tests.
    pub fn with_submitter(mut self, submitter: Arc<dyn PtbSubmitter>) -> Self {
        self.submitter = Some(submitter);
        self
    }

    /// Allocate a new session and return its id. Backs `cat new`.
    fn allocate(&self) -> SessionId {
        // Allocating a real `PtbSession` mints a fresh, process-unique
        // `SessionId` from the same monotonic counter the CLI uses.
        let id = PtbSession::new(&*self.chain).id();
        self.sessions.lock().insert(id, SessionState::default());
        id
    }

    /// Parse a `<id>` path segment into a [`SessionId`].
    fn parse_id(seg: &str) -> Result<SessionId, HandlerError> {
        seg.parse::<u64>()
            .map(SessionId)
            .map_err(|_| HandlerError::not_found(format!("tx session {seg:?}")))
    }

    /// Look up an existing session's state, or 404.
    fn state(&self, id: SessionId) -> Result<SessionState, HandlerError> {
        self.sessions
            .lock()
            .get(&id)
            .cloned()
            .ok_or_else(|| HandlerError::not_found(format!("tx session {}", id.0)))
    }

    /// Rebuild a [`PtbSession`] from stored state by replaying the lines
    /// and re-applying the header settings. The returned session is
    /// equivalent (same validated commands, same header) to one driven
    /// incrementally — `build_unsigned` / `status` see the same plan.
    ///
    /// Replaying a stored line cannot fail: every line in `state.lines`
    /// was validated by `append_command` before it was stored, and the
    /// chain is the same one it validated against.
    fn rebuild<'a>(&'a self, state: &SessionState) -> PtbSession<'a> {
        let mut s = PtbSession::new(&*self.chain);
        for line in &state.lines {
            s.append_command(line)
                .expect("stored command line re-validates against the same chain");
        }
        if !state.signers.is_empty() {
            s.set_signers(state.signers.clone());
        }
        if let Some(gp) = state.gas_payer {
            s.set_gas_payer(gp);
        }
        s
    }

    async fn state_for_commit(&self, id: SessionId) -> Result<SessionState, HandlerError> {
        let mut state = self.state(id)?;
        if state.gas_payer.is_none()
            && let Some(submitter) = &self.submitter
        {
            let gas_payer = submitter.select_gas_payer(&state.signers).await?;
            state.gas_payer = Some(gas_payer);
        }
        Ok(state)
    }

    /// Append `line` to session `id`'s stored state, validating it
    /// against a freshly-replayed [`PtbSession`] first. On a validation
    /// failure the stored state is **unchanged** (the prior commands
    /// survive). Backs `write <id>/cmd`.
    fn append(&self, id: SessionId, line: &str) -> Result<(), HandlerError> {
        let mut guard = self.sessions.lock();
        let state = guard
            .get(&id)
            .ok_or_else(|| HandlerError::not_found(format!("tx session {}", id.0)))?;

        // Validate against a session rebuilt from the *current* lines.
        let mut session = PtbSession::new(&*self.chain);
        for prior in &state.lines {
            session
                .append_command(prior)
                .expect("stored command line re-validates");
        }
        session.append_command(line).map_err(build_err_to_handler)?;

        // Validation passed — now (and only now) mutate the stored state.
        guard
            .get_mut(&id)
            .expect("session present under the same lock")
            .lines
            .push(line.trim().to_string());
        Ok(())
    }

    /// Discard session `id`. Backs `write/cat <id>/abort`.
    fn abort(&self, id: SessionId) -> Result<(), HandlerError> {
        self.sessions
            .lock()
            .remove(&id)
            .map(|_| ())
            .ok_or_else(|| HandlerError::not_found(format!("tx session {}", id.0)))
    }

    /// Set the signer pubkeys for session `id` from a body of one
    /// 32-byte hex pubkey per line. Backs `write <id>/signer`.
    fn set_signer(&self, id: SessionId, body: &str) -> Result<(), HandlerError> {
        let mut signers = Vec::new();
        for tok in body.split_whitespace() {
            let bytes = hex::decode(tok.trim_start_matches("0x"))
                .map_err(|e| HandlerError::invalid(format!("signer pubkey hex: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| HandlerError::invalid("signer pubkey must be 32 bytes"))?;
            signers.push(arr);
        }
        if signers.is_empty() {
            return Err(HandlerError::invalid("no signer pubkey provided"));
        }
        let mut guard = self.sessions.lock();
        let state = guard
            .get_mut(&id)
            .ok_or_else(|| HandlerError::not_found(format!("tx session {}", id.0)))?;
        state.signers = signers;
        Ok(())
    }

    /// Set the gas-payer object id for session `id` from a 32-byte hex
    /// object id. Backs `write <id>/gas-payer`.
    fn set_gas_payer(&self, id: SessionId, body: &str) -> Result<(), HandlerError> {
        let tok = body.trim();
        let bytes = hex::decode(tok.trim_start_matches("0x"))
            .map_err(|e| HandlerError::invalid(format!("gas-payer id hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| HandlerError::invalid("gas-payer id must be 32 bytes"))?;
        let mut guard = self.sessions.lock();
        let state = guard
            .get_mut(&id)
            .ok_or_else(|| HandlerError::not_found(format!("tx session {}", id.0)))?;
        state.gas_payer = Some(ObjectId(arr));
        Ok(())
    }

    /// Render session `id`'s status as JSON bytes. Backs `cat <id>/status`.
    fn status_json(&self, id: SessionId) -> Result<Vec<u8>, HandlerError> {
        let state = self.state(id)?;
        let session = self.rebuild(&state);
        let status = session.status();
        let v = status_to_json(&status);
        let mut bytes = serde_json::to_vec_pretty(&v).map_err(json_err)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Build the unsigned [`bloom_script::PtbTx`] for session `id` — the
    /// seam an NFS deployment hands to the signer/submitter, mirroring
    /// `commit_ndjson`'s build step (which renders its receipt). Exposed
    /// so callers (and the Phase F litmus) can execute the staged plan
    /// through the chain VM, proving the VFS front door commits an
    /// *identical* `PtbTx` to the CLI pipe path.
    pub fn build_tx(&self, id: SessionId) -> Result<bloom_script::PtbTx, HandlerError> {
        let state = self.state(id)?;
        self.rebuild(&state)
            .build_unsigned()
            .map_err(build_err_to_handler)
    }

    /// Finalise session `id` and render the canonical receipt as NDJSON.
    /// Backs `cat <id>/commit`. A build error (missing signer / gas
    /// payer, or a validation failure) leaves the session intact. Once
    /// the commit receipt renders successfully, the session is consumed.
    async fn commit_ndjson(&self, id: SessionId) -> Result<Vec<u8>, HandlerError> {
        let state = self.state_for_commit(id).await?;
        let (tx, status) = {
            let session = self.rebuild(&state);
            let tx = session.build_unsigned().map_err(build_err_to_handler)?;
            let status = session.status();
            (tx, status)
        };

        // The receipt is canonical NDJSON: one object per line. The PTB
        // hash is what a signer covers (and what the node indexes); a
        // live deployment signs this digest and submits, then appends the
        // on-chain result line. Here we render the assembled, validated
        // plan — identical for the CLI and NFS front doors.
        let ptb_hash = tx.signing_digest();
        let header = serde_json::json!({
            "kind": "ptb",
            "session": id.0,
            "ptb_hash": format!("0x{}", hex::encode(ptb_hash)),
            "signers": tx.signers.len(),
            "gas_payer": format!("0x{}", hex::encode(tx.gas_payer.0)),
            "gas_budget": tx.gas_budget,
            "gas_price": tx.gas_price.to_string(),
            "gas_reservation": tx.checked_gas_reservation()
                .map(|reservation| reservation.to_string())
                .unwrap_or_else(|| "overflow".to_string()),
            "commands": tx.commands.len(),
        });
        let mut out = serde_json::to_vec(&header).map_err(json_err)?;
        out.push(b'\n');
        for cs in &status.commands {
            let line = serde_json::json!({
                "kind": "command",
                "cmd_idx": cs.cmd_idx,
                "endpoint": cs.endpoint_path,
                "returns": cs.return_types.iter().map(type_tag_label).collect::<Vec<_>>(),
            });
            out.extend(serde_json::to_vec(&line).map_err(json_err)?);
            out.push(b'\n');
        }
        if let Some(submitter) = &self.submitter {
            for line in submitter.submit_ptb(id, tx, status).await? {
                out.extend(serde_json::to_vec(&line).map_err(json_err)?);
                out.push(b'\n');
            }
        }
        self.sessions.lock().remove(&id);
        Ok(out)
    }
}

/// Map a [`BuildError`] onto the right [`HandlerError`] flavour so the
/// NFS layer surfaces a useful message. Resolution / validation /
/// parse failures are *invalid input* (the write is rejected); a
/// not-ready commit is also invalid (caller must set signer/gas first).
fn build_err_to_handler(e: BuildError) -> HandlerError {
    HandlerError::invalid(e.to_string())
}

/// Map a JSON serialisation failure onto a backend error.
fn json_err(e: serde_json::Error) -> HandlerError {
    HandlerError::backend(e.to_string())
}

/// Render a [`SessionStatus`] as a JSON value (the type is not
/// `Serialize`, so we project it explicitly).
fn status_to_json(status: &SessionStatus) -> serde_json::Value {
    serde_json::json!({
        "id": status.id.0,
        "commands": status.commands.iter().map(|c| {
            serde_json::json!({
                "cmd_idx": c.cmd_idx,
                "endpoint": c.endpoint_path,
                "function": c.function,
                "returns": c.return_types.iter().map(type_tag_label).collect::<Vec<_>>(),
                "label": c.label,
            })
        }).collect::<Vec<_>>(),
        "labels": status.labels.iter().map(|(name, idx)| {
            serde_json::json!({ "name": name, "cmd_idx": idx })
        }).collect::<Vec<_>>(),
        "gas_payer_set": status.gas_payer_set,
        "signer_count": status.signer_count,
        "estimated_gas": status.estimated_gas,
    })
}

/// Human/debug label for a [`TypeTag`] (non-authoritative projection,
/// matching the builder's `type_tag_label`).
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
// Handler impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Handler for TxHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => Ok(Entry::dir("")),
            1 => match segs[0].as_str() {
                "new" => Ok(Entry::file("new")),
                id => {
                    let id = Self::parse_id(id)?;
                    let _ = self.state(id)?;
                    Ok(Entry::dir(&id.0.to_string()))
                }
            },
            2 => {
                let id = Self::parse_id(&segs[0])?;
                let _ = self.state(id)?;
                match segs[1].as_str() {
                    "cmd" => Ok(Entry::writable_file("cmd")),
                    "status" => Ok(Entry::file("status")),
                    "commit" => Ok(Entry::file("commit")),
                    "abort" => Ok(Entry::writable_file("abort")),
                    "signer" => Ok(Entry::writable_file("signer")),
                    "gas-payer" => Ok(Entry::writable_file("gas-payer")),
                    _ => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            1 if segs[0] == "new" => {
                // `cat new` is the allocation verb (spec §3.3).
                let id = self.allocate();
                Ok(format!("{}\n", id.0).into_bytes())
            }
            2 => {
                let id = Self::parse_id(&segs[0])?;
                match segs[1].as_str() {
                    "cmd" => {
                        let state = self.state(id)?;
                        let mut body = state.lines.join("\n");
                        if !body.is_empty() {
                            body.push('\n');
                        }
                        Ok(body.into_bytes())
                    }
                    "status" => self.status_json(id),
                    "commit" => self.commit_ndjson(id).await,
                    "abort" => {
                        // `cat abort` also discards (spec allows write/cat).
                        self.abort(id)?;
                        Ok(b"aborted\n".to_vec())
                    }
                    "signer" => {
                        let state = self.state(id)?;
                        let body = state
                            .signers
                            .iter()
                            .map(|s| format!("0x{}", hex::encode(s)))
                            .collect::<Vec<_>>()
                            .join("\n");
                        Ok(if body.is_empty() {
                            Vec::new()
                        } else {
                            format!("{body}\n").into_bytes()
                        })
                    }
                    "gas-payer" => {
                        let state = self.state(id)?;
                        Ok(match state.gas_payer {
                            Some(gp) => format!("0x{}\n", hex::encode(gp.0)).into_bytes(),
                            None => Vec::new(),
                        })
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        let body =
            std::str::from_utf8(data).map_err(|_| HandlerError::invalid("non-utf8 input"))?;
        match segs {
            [id, file] => {
                let id = Self::parse_id(id)?;
                match file.as_str() {
                    "cmd" => {
                        // One command line per write. Reject an empty
                        // write loudly so a stray `touch` doesn't no-op.
                        let line = body.trim_end_matches(['\n', '\r']);
                        self.append(id, line)
                    }
                    "abort" => self.abort(id),
                    "signer" => self.set_signer(id, body),
                    "gas-payer" => self.set_gas_payer(id, body),
                    _ => Err(HandlerError::PermissionDenied),
                }
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => {
                // Root: `new` plus one dir per live session. Bounded via
                // the pagination primitive so a long-lived daemon with
                // thousands of staged sessions never floods `READDIR`.
                let mut ids: Vec<u64> = self.sessions.lock().keys().map(|k| k.0).collect();
                ids.sort_unstable();
                let mut entries = vec![Entry::file("new")];
                entries.extend(ids.iter().map(|id| Entry::dir(&id.to_string())));
                match paginate::project(entries) {
                    paginate::Projection::Direct(es) => Ok(es),
                    paginate::Projection::Paged { .. } => Ok(vec![Entry::dir("page")]),
                }
            }
            1 => match segs[0].as_str() {
                "new" => Err(HandlerError::NotADir(path.to_string_path())),
                "page" => {
                    // The root collection's page index (only reached when
                    // the session set overflows a page).
                    let total = self.sessions.lock().len() + 1; // + `new`
                    Ok(paginate::page_indices(total))
                }
                id => {
                    let id = Self::parse_id(id)?;
                    let _ = self.state(id)?;
                    Ok(vec![
                        Entry::writable_file("cmd"),
                        Entry::file("status"),
                        Entry::file("commit"),
                        Entry::writable_file("abort"),
                        Entry::writable_file("signer"),
                        Entry::writable_file("gas-payer"),
                    ])
                }
            },
            2 if segs[0] == "page" => {
                // `ls page/<NNNNNN>` — the slice of the root collection
                // for that page index.
                let index = paginate::parse_page_name(&segs[1])
                    .ok_or_else(|| HandlerError::not_found(path.to_string_path()))?;
                let mut ids: Vec<u64> = self.sessions.lock().keys().map(|k| k.0).collect();
                ids.sort_unstable();
                let mut entries = vec![Entry::file("new")];
                entries.extend(ids.iter().map(|id| Entry::dir(&id.to_string())));
                Ok(paginate::page_slice(&entries, index).to_vec())
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }

    /// `cat <id>/commit` and `cat <id>/abort` mutate state (submit /
    /// discard), so they are side-effecting reads worth auditing.
    fn is_read_side_effecting(&self, path: &VfsPath) -> bool {
        matches!(path.segments(), [_, file] if file == "commit" || file == "abort")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bloom_chain_types::Hash32;
    use bloom_objects::{Object, Owner};
    use bloom_script::{
        ArgDeclStub, CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH, FunctionDeclStub,
        PetalManifestStub, loom_coin_type_tag,
    };

    // -- In-process chain mock (mirrors bloom-ptb-builder's tests.rs, but
    // uses `Mutex` so it is `Send + Sync` for the handler registry; the
    // crate forbids `unsafe_code`, so we cannot hand-wave a `RefCell`). --

    #[derive(Default)]
    struct MockChain {
        objects: StdMutex<Map<[u8; 32], Object>>,
        manifests: StdMutex<Map<[u8; 32], PetalManifestStub>>,
        paths: StdMutex<Map<String, Hash32>>,
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
    const AUTO_GAS_ID: ObjectId = ObjectId([0xA5; 32]);

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
            attached_invariants: vec![],
        }
    }

    /// A chain carrying a pool petal with the given functions plus a
    /// pre-funded `Coin<LOOM>` gas payer owned by `signer`.
    fn handler_with(funcs: Vec<FunctionDeclStub>, signer: [u8; 32]) -> (TxHandler, ObjectId) {
        let chain = MockChain::new();
        let manifest = PetalManifestStub {
            module_path: POOL_PATH.to_string(),
            functions: funcs,
            object_types: vec![],
            external_type_refs: vec![],
        };
        chain.put_petal(POOL_HASH, manifest);
        chain.put_path(POOL_PATH, POOL_HASH);
        chain.put_path(CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH);

        let gas_id = ObjectId([0xFE; 32]);
        let mut payload = vec![0u8; 32];
        payload.extend_from_slice(&1_000_000u128.to_be_bytes());
        chain.put_object(Object {
            id: gas_id,
            type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
            owner: Owner::Address(signer),
            version: 0,
            payload,
        });
        (TxHandler::new(Arc::new(chain)), gas_id)
    }

    #[derive(Default)]
    struct MockSubmitter {
        selects: AtomicUsize,
        submits: AtomicUsize,
        fail_submit: bool,
    }

    #[async_trait]
    impl PtbSubmitter for MockSubmitter {
        async fn select_gas_payer(&self, _signers: &[[u8; 32]]) -> Result<ObjectId, HandlerError> {
            self.selects.fetch_add(1, Ordering::SeqCst);
            Ok(AUTO_GAS_ID)
        }

        async fn submit_ptb(
            &self,
            _session_id: SessionId,
            _tx: PtbTx,
            _status: SessionStatus,
        ) -> Result<Vec<serde_json::Value>, HandlerError> {
            self.submits.fetch_add(1, Ordering::SeqCst);
            if self.fail_submit {
                return Err(HandlerError::backend("submit failed"));
            }
            Ok(vec![serde_json::json!({
                "kind": "receipt",
                "success": true,
            })])
        }
    }

    fn handler_with_submitter(
        funcs: Vec<FunctionDeclStub>,
        signer: [u8; 32],
        submitter: Arc<MockSubmitter>,
    ) -> TxHandler {
        let chain = MockChain::new();
        let manifest = PetalManifestStub {
            module_path: POOL_PATH.to_string(),
            functions: funcs,
            object_types: vec![],
            external_type_refs: vec![],
        };
        chain.put_petal(POOL_HASH, manifest);
        chain.put_path(POOL_PATH, POOL_HASH);
        chain.put_path(CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH);
        let mut payload = vec![0u8; 32];
        payload.extend_from_slice(&1_000_000u128.to_be_bytes());
        chain.put_object(Object {
            id: AUTO_GAS_ID,
            type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
            owner: Owner::Address(signer),
            version: 0,
            payload,
        });
        TxHandler::new(Arc::new(chain)).with_submitter(submitter)
    }

    fn vpath(p: &str) -> VfsPath {
        VfsPath::parse(p).unwrap()
    }

    /// `cat new` allocates a session and returns its id.
    async fn new_session(h: &TxHandler) -> u64 {
        let bytes = h.read(&vpath("new")).await.unwrap();
        let s = String::from_utf8(bytes).unwrap();
        s.trim().parse::<u64>().unwrap()
    }

    // -- Tests -------------------------------------------------------------

    #[tokio::test]
    async fn new_allocates_session_id() {
        let (h, _) = handler_with(
            vec![func("swap", vec![ArgDeclStub::Signer], vec![])],
            [1; 32],
        );
        let id1 = new_session(&h).await;
        let id2 = new_session(&h).await;
        assert_ne!(id1, id2, "each `cat new` mints a distinct id");
        // The session dir is now listable.
        let entries = h.list(&vpath(&id1.to_string())).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"cmd"));
        assert!(names.contains(&"status"));
        assert!(names.contains(&"commit"));
        assert!(names.contains(&"abort"));
    }

    #[tokio::test]
    async fn full_flow_new_cmd_status_commit() {
        let signer = [0x11; 32];
        let (h, gas_id) = handler_with(
            vec![
                func("producer", vec![], vec![concrete("u64")]),
                func(
                    "consumer",
                    vec![ArgDeclStub::Const(concrete("u64"))],
                    vec![],
                ),
            ],
            signer,
        );
        let id = new_session(&h).await;

        // Append two good commands + bind a label.
        h.write(
            &vpath(&format!("{id}/cmd")),
            b"/bloom/dex/pool/producer as p",
        )
        .await
        .unwrap();
        h.write(&vpath(&format!("{id}/cmd")), b"/bloom/dex/pool/consumer @p")
            .await
            .unwrap();

        // `cat cmd` lists the appended lines.
        let listing =
            String::from_utf8(h.read(&vpath(&format!("{id}/cmd"))).await.unwrap()).unwrap();
        assert!(listing.contains("/bloom/dex/pool/producer as p"));
        assert!(listing.contains("/bloom/dex/pool/consumer @p"));

        // `cat status` is JSON with both commands resolved.
        let status = h.read(&vpath(&format!("{id}/status"))).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&status).unwrap();
        assert_eq!(v["commands"].as_array().unwrap().len(), 2);
        assert_eq!(v["commands"][0]["endpoint"], "/bloom/dex/pool/producer");
        assert_eq!(v["commands"][0]["returns"][0], "u64");

        // Set signer + gas payer (the §3.4 header injection seam), then commit.
        h.write(
            &vpath(&format!("{id}/signer")),
            format!("0x{}", hex::encode(signer)).as_bytes(),
        )
        .await
        .unwrap();
        h.write(
            &vpath(&format!("{id}/gas-payer")),
            format!("0x{}", hex::encode(gas_id.0)).as_bytes(),
        )
        .await
        .unwrap();

        // `cat commit` returns NDJSON: a header line + one per command.
        let receipt = h.read(&vpath(&format!("{id}/commit"))).await.unwrap();
        let text = String::from_utf8(receipt).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "header + 2 command lines: {text}");
        let header: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(header["kind"], "ptb");
        assert_eq!(header["commands"], 2);
        assert!(header["ptb_hash"].as_str().unwrap().starts_with("0x"));
        // A successful commit consumes the session; failed commits are
        // covered separately and leave their session intact.
        let err = h.read(&vpath(&format!("{id}/cmd"))).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn submitter_commit_auto_selects_gas_and_appends_receipt() {
        let signer = [0x44; 32];
        let submitter = Arc::new(MockSubmitter::default());
        let h = handler_with_submitter(
            vec![func("producer", vec![], vec![concrete("u64")])],
            signer,
            submitter.clone(),
        );
        let id = new_session(&h).await;
        h.write(&vpath(&format!("{id}/cmd")), b"/bloom/dex/pool/producer")
            .await
            .unwrap();
        h.write(
            &vpath(&format!("{id}/signer")),
            format!("0x{}", hex::encode(signer)).as_bytes(),
        )
        .await
        .unwrap();

        let receipt = h.read(&vpath(&format!("{id}/commit"))).await.unwrap();
        let text = String::from_utf8(receipt).unwrap();
        assert!(text.contains(r#""kind":"receipt""#), "{text}");
        assert_eq!(submitter.selects.load(Ordering::SeqCst), 1);
        assert_eq!(submitter.submits.load(Ordering::SeqCst), 1);
        let err = h.read(&vpath(&format!("{id}/cmd"))).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn submitter_failure_leaves_session_intact() {
        let signer = [0x45; 32];
        let submitter = Arc::new(MockSubmitter {
            fail_submit: true,
            ..Default::default()
        });
        let h = handler_with_submitter(
            vec![func("producer", vec![], vec![concrete("u64")])],
            signer,
            submitter,
        );
        let id = new_session(&h).await;
        h.write(&vpath(&format!("{id}/cmd")), b"/bloom/dex/pool/producer")
            .await
            .unwrap();
        h.write(
            &vpath(&format!("{id}/signer")),
            format!("0x{}", hex::encode(signer)).as_bytes(),
        )
        .await
        .unwrap();

        let err = h.read(&vpath(&format!("{id}/commit"))).await.unwrap_err();
        assert!(matches!(err, HandlerError::Backend(_)), "got {err:?}");
        let listing =
            String::from_utf8(h.read(&vpath(&format!("{id}/cmd"))).await.unwrap()).unwrap();
        assert!(listing.contains("/bloom/dex/pool/producer"));
    }

    #[tokio::test]
    async fn bad_cmd_leaves_session_intact() {
        let (h, _) = handler_with(
            vec![
                func("producer", vec![], vec![concrete("u64")]),
                func(
                    "consumer",
                    vec![ArgDeclStub::Const(concrete("u64"))],
                    vec![],
                ),
            ],
            [0x22; 32],
        );
        let id = new_session(&h).await;
        // One good command.
        h.write(&vpath(&format!("{id}/cmd")), b"/bloom/dex/pool/producer")
            .await
            .unwrap();
        // A bad one: dangling forward use-ref. Must be rejected.
        let err = h
            .write(
                &vpath(&format!("{id}/cmd")),
                b"/bloom/dex/pool/consumer @9.0",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::Invalid(_)), "got {err:?}");
        // An unknown-path command also fails closed.
        let err2 = h
            .write(&vpath(&format!("{id}/cmd")), b"/bloom/nope/whatever")
            .await
            .unwrap_err();
        assert!(matches!(err2, HandlerError::Invalid(_)), "got {err2:?}");
        // The prior good command survives both bad writes.
        let listing =
            String::from_utf8(h.read(&vpath(&format!("{id}/cmd"))).await.unwrap()).unwrap();
        assert_eq!(listing.trim(), "/bloom/dex/pool/producer");
        // status reflects exactly one command.
        let v: serde_json::Value =
            serde_json::from_slice(&h.read(&vpath(&format!("{id}/status"))).await.unwrap())
                .unwrap();
        assert_eq!(v["commands"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn abort_discards_session() {
        let (h, _) = handler_with(
            vec![func("swap", vec![ArgDeclStub::Signer], vec![])],
            [3; 32],
        );
        let id = new_session(&h).await;
        h.write(
            &vpath(&format!("{id}/cmd")),
            b"/bloom/dex/pool/swap signer:0",
        )
        .await
        .unwrap();
        // Abort via write.
        h.write(&vpath(&format!("{id}/abort")), b"yes")
            .await
            .unwrap();
        // The session is gone: cmd read 404s.
        let err = h.read(&vpath(&format!("{id}/cmd"))).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn commit_without_signer_leaves_session_intact() {
        let (h, _gas) = handler_with(
            vec![func("swap", vec![ArgDeclStub::Signer], vec![])],
            [4; 32],
        );
        let id = new_session(&h).await;
        h.write(
            &vpath(&format!("{id}/cmd")),
            b"/bloom/dex/pool/swap signer:0",
        )
        .await
        .unwrap();
        // Commit before setting signer/gas → NotReady, surfaced as Invalid.
        let err = h.read(&vpath(&format!("{id}/commit"))).await.unwrap_err();
        assert!(matches!(err, HandlerError::Invalid(_)), "got {err:?}");
        // Session still has its command.
        let listing =
            String::from_utf8(h.read(&vpath(&format!("{id}/cmd"))).await.unwrap()).unwrap();
        assert!(listing.contains("swap"));
    }

    #[tokio::test]
    async fn root_list_includes_new_and_sessions() {
        let (h, _) = handler_with(
            vec![func("swap", vec![ArgDeclStub::Signer], vec![])],
            [5; 32],
        );
        let id = new_session(&h).await;
        let entries = h.list(&VfsPath::root()).await.unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&"new".to_string()));
        assert!(names.contains(&id.to_string()));
        // The root listing is bounded.
        assert!(entries.len() <= paginate::PAGE_SIZE);
    }

    #[tokio::test]
    async fn unknown_session_404s() {
        let (h, _) = handler_with(
            vec![func("swap", vec![ArgDeclStub::Signer], vec![])],
            [6; 32],
        );
        let err = h.read(&vpath("999999/cmd")).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)));
    }
}
