//! Per-PTB borrow table — the executor's authoritative record of every
//! object currently in scope (spec §4.4).
//!
//! Two row states:
//!
//! - **Persistent** (`origin_command_idx == None`) — the object lives
//!   in the chain's `Object` trie and was loaded into the table when
//!   the PTB borrowed it.
//! - **Transient** (`origin_command_idx == Some(i)`) — the object was
//!   produced by the `i`-th command and has never been persisted.
//!   Linearity rule: must be consumed, transferred, shared, frozen,
//!   or deleted by tx-end, else `PtbError::LinearityViolation`.
//!
//! End-of-command:
//! - `diff_check` ensures no `ReadOnly` row was mutated.
//! - Mutable rows whose payload changed get an auto-bumped `version`.
//!
//! End-of-tx:
//! - `linearity_check` returns the list of orphan transient ids (empty
//!   = success).

use std::collections::BTreeMap;

use bloom_objects::{AccessMode, Object, ObjectId, Owner, TypeTag};

use crate::error::PtbError;

/// A single row in the borrow table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BorrowRow {
    /// Object identifier.
    pub object_id: ObjectId,
    /// Recursive type identity.
    pub type_tag: TypeTag,
    /// Ownership category.
    pub owner: Owner,
    /// Version as observed when the row was loaded; bumped by
    /// [`BorrowTable::diff_check`] when the payload mutates.
    pub version: u64,
    /// Current payload bytes (may be updated by [`BorrowTable::mark_dirty`]).
    pub payload_bytes: Vec<u8>,
    /// Mode under which the row was borrowed / created.
    pub access_mode: AccessMode,
    /// `Some(cmd_idx)` for transient rows (produced by command N),
    /// `None` for persistent rows loaded from the trie.
    pub origin_command_idx: Option<u16>,
    /// Set whenever the executor calls [`BorrowTable::mark_dirty`].
    pub dirty: bool,
    /// Snapshot of `payload_bytes` taken at row insertion / last
    /// `diff_check`. Used to detect "Mutable but didn't call
    /// object.mutate" (auto-bumps the version) and "ReadOnly but
    /// payload differs" (rejected as `IllegalMutation`).
    pub baseline_payload: Vec<u8>,
}

/// Snapshot retained after a row is dropped during the current command.
///
/// Dropped rows are no longer candidates for commit writes or linearity, but
/// object-type invariants still need their pre-delete type and payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DroppedBorrowRow {
    /// Object identifier.
    pub object_id: ObjectId,
    /// Recursive type identity.
    pub type_tag: TypeTag,
    /// Command index that produced a transient row, if any.
    pub origin_command_idx: Option<u16>,
    /// Payload snapshot from before the command's mutation/delete.
    pub baseline_payload: Vec<u8>,
}

impl BorrowRow {
    /// Construct a persistent row from an [`Object`] loaded out of
    /// the chain trie.
    pub fn from_persistent(obj: &Object, mode: AccessMode) -> Self {
        Self {
            object_id: obj.id,
            type_tag: obj.type_tag.clone(),
            owner: obj.owner.clone(),
            version: obj.version,
            payload_bytes: obj.payload.clone(),
            access_mode: mode,
            origin_command_idx: None,
            dirty: false,
            baseline_payload: obj.payload.clone(),
        }
    }

    /// Re-render this row as a chain [`Object`] (used by the
    /// executor's commit-phase write list).
    pub fn to_object(&self) -> Object {
        Object {
            id: self.object_id,
            type_tag: self.type_tag.clone(),
            owner: self.owner.clone(),
            version: self.version,
            payload: self.payload_bytes.clone(),
        }
    }
}

/// Row's persistence kind — informational accessor for callers that
/// want to skip transient rows in iteration.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RowState {
    /// Row was produced by an earlier command and has not been
    /// transferred / shared / frozen / deleted yet.
    Transient,
    /// Row was loaded from the chain trie.
    Persistent,
}

impl BorrowRow {
    /// Returns whether this row is currently transient or persistent.
    pub fn state(&self) -> RowState {
        if self.origin_command_idx.is_some() {
            RowState::Transient
        } else {
            RowState::Persistent
        }
    }
}

/// Per-PTB borrow table.
#[derive(Default, Clone, Debug)]
pub struct BorrowTable {
    /// Map keyed by `ObjectId` (we use `BTreeMap` to guarantee
    /// deterministic iteration order for the orphan list).
    rows: BTreeMap<[u8; 32], BorrowRow>,
    /// Ids that have been explicitly dropped (transferred to a new
    /// owner / shared / frozen / deleted). Tracked so subsequent
    /// `linearity_check` doesn't flag them as orphans even after the
    /// row is removed from `rows`.
    consumed_transient: BTreeMap<[u8; 32], ()>,
    /// Rows dropped since the last successful `diff_check`. These tombstones
    /// are for per-command invariant firing only and are cleared once that
    /// command's invariant/diff pass completes.
    dropped_rows: BTreeMap<[u8; 32], DroppedBorrowRow>,
}

impl BorrowTable {
    /// Construct an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of rows currently in the table.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table contains any rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Insert (or replace) a persistent row loaded from the chain
    /// trie.
    pub fn load_persistent(&mut self, obj: &Object, mode: AccessMode) {
        let row = BorrowRow::from_persistent(obj, mode);
        self.rows.insert(obj.id.0, row);
    }

    /// Insert a transient row produced by command `cmd_idx`.
    pub fn insert_transient(&mut self, mut row: BorrowRow) {
        // Force the origin to be Some(...) — callers should set it,
        // but defend against forgetting.
        if row.origin_command_idx.is_none() {
            // Default to command 0 if unset; in practice the executor
            // always supplies the producing command index.
            row.origin_command_idx = Some(0);
        }
        // Treat the inserted payload as the baseline (transient rows
        // have no prior state to diff against).
        row.baseline_payload.clone_from(&row.payload_bytes);
        self.rows.insert(row.object_id.0, row);
    }

    /// Borrow a row by id.
    pub fn get(&self, id: &ObjectId) -> Option<&BorrowRow> {
        self.rows.get(&id.0)
    }

    /// Mutably borrow a row by id.
    pub fn get_mut(&mut self, id: &ObjectId) -> Option<&mut BorrowRow> {
        self.rows.get_mut(&id.0)
    }

    /// Mark a row dirty and update its payload bytes (used by the
    /// `object.mutate` host import).
    pub fn mark_dirty(&mut self, id: &ObjectId, new_payload: Vec<u8>) -> Result<(), PtbError> {
        match self.rows.get_mut(&id.0) {
            None => Err(PtbError::ObjectNotFound { id: *id }),
            Some(row) => {
                row.payload_bytes = new_payload;
                row.dirty = true;
                Ok(())
            }
        }
    }

    /// Drop a row entirely (used by `object.delete` and by the
    /// transfer/share/freeze commands once the executor finishes
    /// re-homing the object on commit).
    pub fn drop_row(&mut self, id: &ObjectId) {
        if let Some(row) = self.rows.remove(&id.0) {
            if row.origin_command_idx.is_some() {
                self.consumed_transient.insert(id.0, ());
            }
            self.dropped_rows.insert(
                id.0,
                DroppedBorrowRow {
                    object_id: row.object_id,
                    type_tag: row.type_tag,
                    origin_command_idx: row.origin_command_idx,
                    baseline_payload: row.baseline_payload,
                },
            );
        }
    }

    /// Mark a transient row as consumed / re-homed *without* removing
    /// it from the table (used by `TransferObjects` so the executor
    /// can still emit an `ownership_changes` entry from the row
    /// before commit).
    pub fn mark_consumed(&mut self, id: &ObjectId) {
        self.consumed_transient.insert(id.0, ());
    }

    /// All ids currently transient (whether dirty or not), in
    /// deterministic order.
    pub fn transient_ids(&self) -> Vec<ObjectId> {
        self.rows
            .values()
            .filter(|r| r.origin_command_idx.is_some())
            .map(|r| r.object_id)
            .collect()
    }

    /// All ids currently persistent, in deterministic order.
    pub fn persistent_ids(&self) -> Vec<ObjectId> {
        self.rows
            .values()
            .filter(|r| r.origin_command_idx.is_none())
            .map(|r| r.object_id)
            .collect()
    }

    /// Run the per-command diff-check (spec §4.4):
    ///
    /// 1. ReadOnly rows whose payload differs from baseline →
    ///    `IllegalMutation`.
    /// 2. Mutable / Consume rows whose payload differs from baseline
    ///    but whose dirty flag is unset → auto-bump version and dirty
    ///    flag (the bloom-resource runtime is supposed to call
    ///    `object.mutate`; this defends against guests that mutate
    ///    via in-place serialization without calling the host).
    /// 3. Any row whose `dirty == true` gets `version += 1`, then the
    ///    baseline snapshot is updated and `dirty` reset.
    pub fn diff_check(&mut self, cmd_idx: u16) -> Result<(), PtbError> {
        for row in self.rows.values_mut() {
            let mutated = row.payload_bytes != row.baseline_payload;
            match row.access_mode {
                AccessMode::ReadOnly => {
                    if mutated || row.dirty {
                        return Err(PtbError::IllegalMutation {
                            id: row.object_id,
                            cmd_idx,
                        });
                    }
                }
                AccessMode::Mutable | AccessMode::Consume => {
                    if mutated && !row.dirty {
                        row.dirty = true; // auto-promote
                    }
                    if row.dirty {
                        row.version =
                            row.version
                                .checked_add(1)
                                .ok_or(PtbError::ObjectVersionOverflow {
                                    id: row.object_id,
                                    version: row.version,
                                })?;
                        row.baseline_payload.clone_from(&row.payload_bytes);
                        row.dirty = false;
                    }
                }
            }
        }
        self.dropped_rows.clear();
        Ok(())
    }

    /// Tx-end linearity check (spec §4.4):
    /// returns the orphan transient object ids (empty if none).
    pub fn linearity_check(&self) -> Vec<ObjectId> {
        self.transient_ids()
            .into_iter()
            .filter(|id| !self.consumed_transient.contains_key(&id.0))
            .collect()
    }

    /// Iterate every row in the table (for the executor's commit phase).
    pub fn iter(&self) -> impl Iterator<Item = (&ObjectId, &BorrowRow)> {
        self.rows.values().map(|row| (&row.object_id, row))
    }

    /// Iterate rows dropped during the current command.
    pub fn dropped_rows(&self) -> impl Iterator<Item = (&ObjectId, &DroppedBorrowRow)> {
        self.dropped_rows.values().map(|row| (&row.object_id, row))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_objects::{Owner, TypeTag};

    fn sample_obj(id_byte: u8, payload: Vec<u8>, version: u64) -> Object {
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: TypeTag::Concrete {
                petal_hash: [0; 32],
                type_name: "Coin".to_string(),
                type_args: vec![],
            },
            owner: Owner::Address([1; 32]),
            version,
            payload,
        }
    }

    fn transient_row(id_byte: u8, cmd: u16, mode: AccessMode) -> BorrowRow {
        BorrowRow {
            object_id: ObjectId([id_byte; 32]),
            type_tag: TypeTag::Generic { idx: 0 },
            owner: Owner::Address([2; 32]),
            version: 0,
            payload_bytes: vec![],
            access_mode: mode,
            origin_command_idx: Some(cmd),
            dirty: false,
            baseline_payload: vec![],
        }
    }

    #[test]
    fn new_table_is_empty() {
        let t = BorrowTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn load_persistent_inserts_row() {
        let mut t = BorrowTable::new();
        let obj = sample_obj(1, vec![1, 2, 3], 5);
        t.load_persistent(&obj, AccessMode::ReadOnly);
        assert_eq!(t.len(), 1);
        let row = t.get(&obj.id).unwrap();
        assert_eq!(row.version, 5);
        assert_eq!(row.access_mode, AccessMode::ReadOnly);
        assert_eq!(row.state(), RowState::Persistent);
    }

    #[test]
    fn insert_transient_inserts_row() {
        let mut t = BorrowTable::new();
        let row = transient_row(7, 0, AccessMode::Mutable);
        let id = row.object_id;
        t.insert_transient(row);
        let got = t.get(&id).unwrap();
        assert_eq!(got.state(), RowState::Transient);
        assert_eq!(got.origin_command_idx, Some(0));
    }

    #[test]
    fn drop_row_removes_and_marks_consumed_for_transient() {
        let mut t = BorrowTable::new();
        t.insert_transient(transient_row(7, 0, AccessMode::Mutable));
        let id = ObjectId([7; 32]);
        t.drop_row(&id);
        assert!(t.get(&id).is_none());
        // Transient row dropped = consumed (no orphan).
        assert!(t.linearity_check().is_empty());
        assert_eq!(t.dropped_rows().count(), 1);
        t.diff_check(0).unwrap();
        assert_eq!(t.dropped_rows().count(), 0);
    }

    #[test]
    fn mark_dirty_on_readonly_fails_diff_check() {
        let mut t = BorrowTable::new();
        let obj = sample_obj(1, vec![1, 2, 3], 1);
        t.load_persistent(&obj, AccessMode::ReadOnly);
        t.mark_dirty(&obj.id, vec![9, 9, 9]).unwrap();
        let err = t.diff_check(0).unwrap_err();
        match err {
            PtbError::IllegalMutation { id, cmd_idx } => {
                assert_eq!(id, obj.id);
                assert_eq!(cmd_idx, 0);
            }
            _ => panic!("expected IllegalMutation"),
        }
    }

    #[test]
    fn diff_check_bumps_version_on_mutable_row() {
        let mut t = BorrowTable::new();
        let obj = sample_obj(1, vec![1, 2, 3], 1);
        t.load_persistent(&obj, AccessMode::Mutable);
        t.mark_dirty(&obj.id, vec![5, 6, 7]).unwrap();
        t.diff_check(0).unwrap();
        let row = t.get(&obj.id).unwrap();
        assert_eq!(row.version, 2);
        assert!(!row.dirty);
        assert_eq!(row.baseline_payload, vec![5, 6, 7]);
    }

    #[test]
    fn diff_check_auto_promotes_silent_mutation_on_mutable() {
        let mut t = BorrowTable::new();
        let obj = sample_obj(1, vec![1, 2, 3], 1);
        t.load_persistent(&obj, AccessMode::Mutable);
        // Guest mutated payload without calling mark_dirty.
        let row = t.get_mut(&obj.id).unwrap();
        row.payload_bytes = vec![9, 9];
        t.diff_check(0).unwrap();
        let row = t.get(&obj.id).unwrap();
        assert_eq!(row.version, 2, "auto-promoted mutation must bump version");
    }

    #[test]
    fn diff_check_reports_version_overflow() {
        let mut t = BorrowTable::new();
        let obj = sample_obj(1, vec![1, 2, 3], u64::MAX);
        t.load_persistent(&obj, AccessMode::Mutable);
        t.mark_dirty(&obj.id, vec![5, 6, 7]).unwrap();
        let err = t.diff_check(0).unwrap_err();
        assert_eq!(
            err,
            PtbError::ObjectVersionOverflow {
                id: obj.id,
                version: u64::MAX,
            }
        );
    }

    #[test]
    fn diff_check_leaves_unchanged_rows_alone() {
        let mut t = BorrowTable::new();
        let obj = sample_obj(1, vec![1, 2, 3], 5);
        t.load_persistent(&obj, AccessMode::Mutable);
        t.diff_check(0).unwrap();
        assert_eq!(t.get(&obj.id).unwrap().version, 5);
    }

    #[test]
    fn linearity_check_flags_orphans() {
        let mut t = BorrowTable::new();
        t.insert_transient(transient_row(1, 0, AccessMode::Mutable));
        t.insert_transient(transient_row(2, 0, AccessMode::Mutable));
        let orphans = t.linearity_check();
        assert_eq!(orphans.len(), 2);
        assert!(orphans.contains(&ObjectId([1; 32])));
        assert!(orphans.contains(&ObjectId([2; 32])));
    }

    #[test]
    fn linearity_check_ignores_consumed_transient() {
        let mut t = BorrowTable::new();
        t.insert_transient(transient_row(1, 0, AccessMode::Mutable));
        t.mark_consumed(&ObjectId([1; 32]));
        assert!(t.linearity_check().is_empty());
    }

    #[test]
    fn transient_ids_and_persistent_ids_distinct() {
        let mut t = BorrowTable::new();
        t.insert_transient(transient_row(1, 0, AccessMode::Mutable));
        let obj = sample_obj(2, vec![], 0);
        t.load_persistent(&obj, AccessMode::ReadOnly);
        let trans = t.transient_ids();
        let pers = t.persistent_ids();
        assert_eq!(trans, vec![ObjectId([1; 32])]);
        assert_eq!(pers, vec![ObjectId([2; 32])]);
    }

    #[test]
    fn mark_dirty_unknown_object_errors() {
        let mut t = BorrowTable::new();
        let err = t.mark_dirty(&ObjectId([9; 32]), vec![1]).unwrap_err();
        assert!(matches!(err, PtbError::ObjectNotFound { .. }));
    }

    #[test]
    fn to_object_roundtrips_basic_fields() {
        let obj = sample_obj(5, vec![1, 2, 3], 7);
        let row = BorrowRow::from_persistent(&obj, AccessMode::Mutable);
        let back = row.to_object();
        assert_eq!(back, obj);
    }
}
