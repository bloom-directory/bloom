//! Error types for the front-door builder.
//!
//! Two layers:
//!
//! - [`ResolveError`] — endpoint-path / manifest resolution failures
//!   (unknown path, unknown function). Fails closed.
//! - [`BuildError`] — everything the [`crate::PtbSession`] can reject:
//!   grammar/parse errors, resolution failures (wrapped), and the
//!   incremental validation failures that mirror
//!   `bloom_script::validator` (`PtbError`).
//!
//! A failed [`crate::PtbSession::append_command`] leaves the session
//! unchanged — the error is returned and no command is appended.

use bloom_chain_types::Hash32;
use bloom_script::PtbError;
use thiserror::Error;

/// Endpoint-path → `(petal_hash, fn)` resolution failures. Fails closed:
/// an unknown path or unknown function is always an error, never a
/// silently-accepted no-op.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResolveError {
    /// The endpoint path did not name a petal path + function (it had no
    /// `/`-separated function suffix, or was empty).
    #[error("malformed endpoint path {path:?}: expected `<petal-path>/<function>`")]
    MalformedPath {
        /// The offending path.
        path: String,
    },
    /// `ChainStateIface::resolve_path` returned `None` for the petal
    /// portion of the endpoint path.
    #[error("no petal bound at path {petal_path:?}")]
    UnknownPath {
        /// The petal path (the endpoint path minus its function suffix).
        petal_path: String,
    },
    /// The petal resolved, but its manifest could not be loaded
    /// (`load_manifest` returned `None`).
    #[error("manifest not found for petal {hash} bound at {petal_path:?}")]
    ManifestNotFound {
        /// The petal path that resolved.
        petal_path: String,
        /// The hash it resolved to.
        hash: Hash32,
    },
    /// The petal resolved and its manifest loaded, but it declares no
    /// function with the requested name.
    #[error("unknown function {function:?} in petal at {petal_path:?} (hash {hash})")]
    UnknownFunction {
        /// The petal path.
        petal_path: String,
        /// The function name that was not found.
        function: String,
        /// The petal hash searched.
        hash: Hash32,
    },
}

/// Everything [`crate::PtbSession::append_command`] (and the pipe / cmd
/// grammar lowering) can fail with.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BuildError {
    /// The command line could not be parsed (empty line, malformed
    /// argument token, bad literal, unknown label, …).
    #[error("parse error: {0}")]
    Parse(String),
    /// Endpoint resolution failed (unknown path / function).
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// Incremental validation against the manifest function signature
    /// failed. Mirrors `bloom_script::validator` exactly (arity / type /
    /// Use-ref typing). The wrapped [`PtbError`] carries the precise
    /// reason.
    #[error("validation error: {0}")]
    Validation(#[from] PtbError),
    /// `commit` / `build_unsigned` was called but a required field was
    /// not set on the session (gas payer or signers).
    #[error("session not ready to build: {0}")]
    NotReady(String),
    /// A `@<label>` reference named a label that was never bound by an
    /// `as <label>` clause.
    #[error("unknown label {0:?} in use-reference")]
    UnknownLabel(String),
    /// A `@<cmd>.<ret>` reference points at a command index that does
    /// not exist yet (forward / out-of-range).
    #[error("dangling use-reference @{cmd_idx}.{ret_idx}: only {appended} command(s) appended")]
    DanglingUse {
        /// Referenced command index.
        cmd_idx: u16,
        /// Referenced return slot.
        ret_idx: u16,
        /// How many commands have been appended so far.
        appended: usize,
    },
}
