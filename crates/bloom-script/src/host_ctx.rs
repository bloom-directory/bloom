//! Per-PTB host context shared between the chain VM's spec §16.2
//! host imports and the [`PtbExecutor`](crate::executor::PtbExecutor).
//!
//! Lifetime: one `PtbHostCtx` per PTB submission. The chain-node layer
//! constructs it inside an `Arc<Mutex<...>>` before calling
//! `PtbExecutor::execute`, then drains the accumulated mutations after
//! the executor returns to fold them into the chain's `WriteSet`.
//!
//! Why a single shared context (rather than per-call scratch)?
//! Section §16.2 of the design spec specifies that host imports like
//! `object.borrow` / `object.read` / `object.mutate` operate on a
//! per-PTB borrow table — handles minted in command `i` may be used by
//! command `j > i` provided the underlying object's `Use(...)` lineage
//! permits. The `BorrowTable` lives here so all of:
//!
//!   - the executor's command dispatch + linearity check, and
//!   - the chain VM's host-import bodies (across Move calls), and
//!   - the executor's post-call diff-extraction
//!
//! see the same row state.
//!
//! The chain VM accesses this through `Arc<Mutex<PtbHostCtx>>` stored
//! on `ChainStoreData::ptb_ctx` for `TxKind::SubmitPtb` calls.

use std::collections::BTreeSet;

use bloom_chain_types::Hash32;
use bloom_objects::{Object, ObjectId, Owner};

use crate::borrow_table::BorrowTable;
use crate::executor::LogEntry;

/// Handle table entry connecting a wasm-side `handle: i32` to a
/// borrow-table row by `ObjectId`. Handles are minted on
/// `object.borrow` / `object.create` and consulted on every subsequent
/// `object.*` import.
///
/// Indices are 1-based on the wire so `0` is reserved as "not a
/// handle" if needed in the future; we expose this transparently
/// through [`PtbHostCtx::handle_for`] / [`PtbHostCtx::id_for_handle`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleEntry {
    /// Object the handle refers to.
    pub object_id: ObjectId,
    /// Whether the handle was minted by `object.borrow` (true) or
    /// `object.create` (false). Influences §16.2 enforcement (`create`
    /// must originate from the type-defining petal).
    pub created: bool,
}

/// Per-PTB shared context.
///
/// All fields are public so the executor and host-import bodies (which
/// live in different crates) can read and mutate without forwarding
/// methods on every byte.
#[derive(Default, Debug)]
pub struct PtbHostCtx {
    /// Authoritative borrow table for the PTB. Mutated by both the
    /// executor (load_persistent / insert_transient / drop_row /
    /// mark_consumed / diff_check / linearity_check) and the chain
    /// VM's `object.*` host imports (mark_dirty / drop_row /
    /// insert_transient).
    pub borrow_table: BorrowTable,

    /// PTB signer pubkeys (32-byte identifiers). Read by `signer.index`
    /// and `signer.address`. Populated by the chain-node layer from
    /// `PtbTx::signers` before the first command runs.
    pub signers: Vec<[u8; 32]>,

    /// Per-command return slot bytes: `command_outputs[cmd][ret]`.
    /// Read by `ptb.command_output`. The executor appends a new
    /// per-command vector at the end of each command so host imports
    /// see only the *completed* commands' outputs.
    pub command_outputs: Vec<Vec<Vec<u8>>>,

    /// The 0-based index of the currently-executing command. Read by
    /// `signer.index` so a Move call inside command `i` learns its
    /// own command position. Initialised to 0 by the executor before
    /// the first command and bumped after each command.
    pub current_command_idx: u16,

    /// Signing digest of the PTB currently executing. Host-side object
    /// creation mixes this into transient ids so identical creates in
    /// different PTBs cannot collide.
    pub ptb_digest: [u8; 32],

    /// Content hash of the petal whose function is currently being
    /// executed. Read by `object.create` to enforce the
    /// type-defining-petal rule and by `log.emit` to attribute log
    /// entries. Updated by the runner before each Move call.
    pub current_petal_hash: Hash32,

    /// Logs emitted by `log.emit` during the PTB. Drained by the
    /// chain-node layer into the receipt's `Vec<Log>`.
    pub logs: Vec<LogEntry>,

    /// Objects deleted via the `object.delete` host import, paired
    /// with the row's *prior* owner so the chain-node layer can
    /// rebuild the prior owner's ownership-index row at commit time
    /// (spec §16.3). The executor reconciles these with its own
    /// `planned_deletes` at commit time.
    pub object_deletes: Vec<(ObjectId, Owner)>,

    /// Ownership re-keys emitted by `object.transfer` / `object.share` /
    /// `object.freeze`. Each entry is `(id, old_owner, new_owner)` —
    /// the chain-node's `rebuild_ownership_rows` needs both keys to
    /// keep the OwnershipIndex symmetric (the old owner's row must
    /// drop the id, the new owner's row must gain it; spec §16.3).
    pub ownership_changes: Vec<(ObjectId, Owner, Owner)>,

    /// Newly-created objects from `object.create` that haven't been
    /// folded into the executor's borrow table yet. The runner pushes
    /// them here so the executor can promote them to transient borrow
    /// rows at the end of the Move call.
    pub created_objects: Vec<Object>,

    /// Wasm-handle table. Index = handle - 1 (handles are 1-based);
    /// 0 is reserved for "not allocated".
    pub handles: Vec<HandleEntry>,

    /// Object ids whose handles have been linearly consumed or
    /// re-homed. Existing and future handles to these ids are rejected
    /// for the remainder of the PTB.
    retired_handle_ids: BTreeSet<[u8; 32]>,
}

impl PtbHostCtx {
    /// Construct an empty context. The chain-node layer populates
    /// `signers` and `current_petal_hash` before the first command
    /// runs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh `i32` handle pointing at `entry`. Returns the
    /// 1-based handle id (always positive).
    pub fn alloc_handle(&mut self, entry: HandleEntry) -> i32 {
        self.handles.push(entry);
        // 1-based so the wasm side can use 0 as a sentinel.
        self.handles.len() as i32
    }

    /// Look up the [`ObjectId`] a handle refers to. Returns `None` for
    /// 0, negative handles, or out-of-range positives.
    pub fn id_for_handle(&self, handle: i32) -> Option<ObjectId> {
        let idx: usize = (handle.checked_sub(1)?).try_into().ok()?;
        let id = self.handles.get(idx).map(|h| h.object_id)?;
        if self.is_handle_retired(&id) {
            None
        } else {
            Some(id)
        }
    }

    /// Look up the full [`HandleEntry`] for a handle.
    pub fn entry_for_handle(&self, handle: i32) -> Option<&HandleEntry> {
        let idx: usize = (handle.checked_sub(1)?).try_into().ok()?;
        let entry = self.handles.get(idx)?;
        if self.is_handle_retired(&entry.object_id) {
            None
        } else {
            Some(entry)
        }
    }

    /// Find the first existing handle pointing at `id`, if any. Used
    /// by `object.borrow` to coalesce repeat borrows of the same
    /// object during a single PTB.
    pub fn handle_for(&self, id: &ObjectId) -> Option<i32> {
        if self.is_handle_retired(id) {
            return None;
        }
        self.handles
            .iter()
            .position(|h| h.object_id == *id)
            .map(|i| (i + 1) as i32)
    }

    /// Retire every handle to `id` after a linear terminal operation
    /// such as transfer, share, freeze, delete, or built-in consume.
    pub fn retire_handles_for(&mut self, id: &ObjectId) {
        self.retired_handle_ids.insert(id.0);
    }

    /// Returns true when handles to `id` are no longer usable.
    pub fn is_handle_retired(&self, id: &ObjectId) -> bool {
        self.retired_handle_ids.contains(&id.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_handle_returns_one_based() {
        let mut ctx = PtbHostCtx::new();
        let h1 = ctx.alloc_handle(HandleEntry {
            object_id: ObjectId([1; 32]),
            created: false,
        });
        let h2 = ctx.alloc_handle(HandleEntry {
            object_id: ObjectId([2; 32]),
            created: true,
        });
        assert_eq!(h1, 1);
        assert_eq!(h2, 2);
    }

    #[test]
    fn id_for_handle_round_trips() {
        let mut ctx = PtbHostCtx::new();
        let id = ObjectId([7; 32]);
        let h = ctx.alloc_handle(HandleEntry {
            object_id: id,
            created: false,
        });
        assert_eq!(ctx.id_for_handle(h), Some(id));
        assert_eq!(ctx.id_for_handle(0), None);
        assert_eq!(ctx.id_for_handle(-1), None);
        assert_eq!(ctx.id_for_handle(999), None);
    }

    #[test]
    fn handle_for_coalesces_repeat_borrows() {
        let mut ctx = PtbHostCtx::new();
        let id = ObjectId([3; 32]);
        let h = ctx.alloc_handle(HandleEntry {
            object_id: id,
            created: false,
        });
        assert_eq!(ctx.handle_for(&id), Some(h));
        assert!(ctx.handle_for(&ObjectId([9; 32])).is_none());
    }

    #[test]
    fn consumed_handles_are_not_resolved_or_coalesced() {
        let mut ctx = PtbHostCtx::new();
        let id = ObjectId([4; 32]);
        let h = ctx.alloc_handle(HandleEntry {
            object_id: id,
            created: false,
        });

        ctx.retire_handles_for(&id);

        assert_eq!(ctx.id_for_handle(h), None);
        assert_eq!(ctx.entry_for_handle(h), None);
        assert_eq!(ctx.handle_for(&id), None);
    }
}
