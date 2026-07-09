use embednfs_proto::{LockDenied4, NfsLockType4, NfsStat4, StateOwner4, Stateid4};

use crate::internal::ServerObject;

use super::StateManager;
use super::model::{LockFileState, LockRange};

impl StateManager {
    fn lock_end(offset: u64, length: u64) -> u128 {
        if length == u64::MAX {
            u128::MAX
        } else {
            offset as u128 + length as u128
        }
    }

    fn locks_overlap(a_offset: u64, a_length: u64, b_offset: u64, b_length: u64) -> bool {
        let a_end = Self::lock_end(a_offset, a_length);
        let b_end = Self::lock_end(b_offset, b_length);
        (a_offset as u128) < b_end && (b_offset as u128) < a_end
    }

    fn range_from_bounds(locktype: NfsLockType4, start: u64, end: u128) -> Option<LockRange> {
        if start as u128 >= end {
            return None;
        }

        Some(LockRange {
            locktype,
            offset: start,
            length: if end == u128::MAX {
                u64::MAX
            } else {
                (end - start as u128) as u64
            },
        })
    }

    pub(crate) fn validate_lock_bounds(&self, offset: u64, length: u64) -> Result<(), NfsStat4> {
        if length == 0 {
            return Err(NfsStat4::Inval);
        }
        if length != u64::MAX && offset.checked_add(length).is_none() {
            return Err(NfsStat4::Inval);
        }
        Ok(())
    }

    #[expect(
        clippy::expect_used,
        reason = "overlapping ranges always produce a non-empty merged interval"
    )]
    fn normalize_lock_ranges(ranges: &mut Vec<LockRange>) {
        ranges.sort_by_key(|range| range.offset);
        let mut normalized: Vec<LockRange> = Vec::with_capacity(ranges.len());
        for range in ranges.drain(..) {
            if let Some(last) = normalized.last_mut() {
                let last_end = Self::lock_end(last.offset, last.length);
                if last.locktype == range.locktype && last_end >= range.offset as u128 {
                    let merged_end = last_end.max(Self::lock_end(range.offset, range.length));
                    *last = Self::range_from_bounds(last.locktype, last.offset, merged_end)
                        .expect("merged lock range must remain non-empty");
                    continue;
                }
            }
            normalized.push(range);
        }
        *ranges = normalized;
    }

    fn replace_lock_range(ranges: &[LockRange], replacement: LockRange) -> Vec<LockRange> {
        let replacement_end = Self::lock_end(replacement.offset, replacement.length);
        let mut next_ranges = Vec::with_capacity(ranges.len() + 1);

        for range in ranges {
            if !Self::locks_overlap(
                range.offset,
                range.length,
                replacement.offset,
                replacement.length,
            ) {
                next_ranges.push(LockRange {
                    locktype: range.locktype,
                    offset: range.offset,
                    length: range.length,
                });
                continue;
            }

            let range_end = Self::lock_end(range.offset, range.length);
            if let Some(left) =
                Self::range_from_bounds(range.locktype, range.offset, replacement.offset as u128)
            {
                next_ranges.push(left);
            }
            if replacement_end != u128::MAX
                && let Some(right) =
                    Self::range_from_bounds(range.locktype, replacement_end as u64, range_end)
            {
                next_ranges.push(right);
            }
        }

        next_ranges.push(replacement);
        Self::normalize_lock_ranges(&mut next_ranges);
        next_ranges
    }

    fn is_write_lock(locktype: NfsLockType4) -> bool {
        matches!(locktype, NfsLockType4::WriteLt | NfsLockType4::WritewLt)
    }

    fn same_lock_owner(a: &StateOwner4, b: &StateOwner4) -> bool {
        a.clientid == b.clientid && a.owner == b.owner
    }

    pub(crate) async fn has_conflicting_io_lock(
        &self,
        object: &ServerObject,
        owner: Option<&StateOwner4>,
        is_write: bool,
        offset: u64,
        length: u64,
        ignore_stateid: Option<[u8; 12]>,
    ) -> bool {
        self.reap_expired_clients().await;
        if length == 0 {
            return false;
        }

        let inner = self.inner.read().await;
        inner.lock_files.iter().any(|(other, state)| {
            if !state.active
                || state.object != *object
                || Some(*other) == ignore_stateid
                || owner.is_some_and(|owner| Self::same_lock_owner(&state.owner, owner))
            {
                return false;
            }

            state.ranges.iter().any(|range| {
                Self::locks_overlap(range.offset, range.length, offset, length)
                    && (is_write || Self::is_write_lock(range.locktype))
            })
        })
    }

    pub(crate) async fn find_lock_conflict(
        &self,
        object: &ServerObject,
        owner: &StateOwner4,
        locktype: NfsLockType4,
        offset: u64,
        length: u64,
        ignore_stateid: Option<&Stateid4>,
    ) -> Option<LockDenied4> {
        self.reap_expired_clients().await;
        let inner = self.inner.read().await;
        for (other, state) in &inner.lock_files {
            if Some(*other) == ignore_stateid.map(|sid| sid.other) {
                continue;
            }
            if !state.active {
                continue;
            }
            if state.object != *object {
                continue;
            }
            if Self::same_lock_owner(&state.owner, owner) {
                continue;
            }
            for range in &state.ranges {
                if !Self::locks_overlap(range.offset, range.length, offset, length) {
                    continue;
                }
                if !Self::is_write_lock(range.locktype) && !Self::is_write_lock(locktype) {
                    continue;
                }
                return Some(LockDenied4 {
                    offset: range.offset,
                    length: range.length,
                    locktype: range.locktype,
                    owner: state.owner.clone(),
                });
            }
        }
        None
    }

    /// Create a new lock state (LOCK with new lock owner).
    pub(crate) async fn create_lock_state(
        &self,
        open_stateid: &Stateid4,
        owner: &StateOwner4,
        object: ServerObject,
        locktype: NfsLockType4,
        offset: u64,
        length: u64,
    ) -> Result<Stateid4, NfsStat4> {
        self.reap_expired_clients().await;
        self.validate_lock_bounds(offset, length)?;
        let mut inner = self.inner.write().await;
        let open = inner
            .open_files
            .get(&open_stateid.other)
            .ok_or(NfsStat4::Openmode)?;
        if !open.active || open.object != object {
            return Err(NfsStat4::Openmode);
        }

        let seq = self
            .next_stateid
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut other = [0u8; 12];
        other[..4].copy_from_slice(&seq.to_be_bytes());
        other[4..12].copy_from_slice(&owner.clientid.to_be_bytes());

        let _ = inner.lock_files.insert(
            other,
            LockFileState {
                object,
                owner: owner.clone(),
                open_state_other: open_stateid.other,
                ranges: vec![LockRange {
                    locktype,
                    offset,
                    length,
                }],
                active: true,
                stateid_seq: 1,
            },
        );

        Ok(Stateid4 { seqid: 1, other })
    }

    /// Update an existing lock state (LOCK with existing lock owner).
    pub(crate) async fn update_lock_state(
        &self,
        lock_stateid: &Stateid4,
        locktype: NfsLockType4,
        offset: u64,
        length: u64,
    ) -> Result<Stateid4, NfsStat4> {
        self.reap_expired_clients().await;
        self.validate_lock_bounds(offset, length)?;
        let mut inner = self.inner.write().await;
        let state = inner
            .lock_files
            .get_mut(&lock_stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        Self::validate_stateid_seq(state.stateid_seq, lock_stateid.seqid)?;
        let replacement = LockRange {
            locktype,
            offset,
            length,
        };
        state.ranges = Self::replace_lock_range(&state.ranges, replacement);
        state.active = true;
        state.stateid_seq += 1;
        Ok(Stateid4 {
            seqid: state.stateid_seq,
            other: lock_stateid.other,
        })
    }

    /// Unlock (LOCKU).
    pub(crate) async fn unlock_state(
        &self,
        lock_stateid: &Stateid4,
        offset: u64,
        length: u64,
    ) -> Result<Stateid4, NfsStat4> {
        self.reap_expired_clients().await;
        self.validate_lock_bounds(offset, length)?;
        let mut inner = self.inner.write().await;
        let state = inner
            .lock_files
            .get_mut(&lock_stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        Self::validate_stateid_seq(state.stateid_seq, lock_stateid.seqid)?;

        if !state
            .ranges
            .iter()
            .any(|range| Self::locks_overlap(range.offset, range.length, offset, length))
        {
            state.stateid_seq += 1;
            return Ok(Stateid4 {
                seqid: state.stateid_seq,
                other: lock_stateid.other,
            });
        }

        let unlock_end = Self::lock_end(offset, length);
        let mut next_ranges = Vec::with_capacity(state.ranges.len() + 1);
        for range in &state.ranges {
            if !Self::locks_overlap(range.offset, range.length, offset, length) {
                next_ranges.push(LockRange {
                    locktype: range.locktype,
                    offset: range.offset,
                    length: range.length,
                });
                continue;
            }

            let range_end = Self::lock_end(range.offset, range.length);
            if let Some(left) =
                Self::range_from_bounds(range.locktype, range.offset, offset as u128)
            {
                next_ranges.push(left);
            }
            if unlock_end != u128::MAX
                && let Some(right) =
                    Self::range_from_bounds(range.locktype, unlock_end as u64, range_end)
            {
                next_ranges.push(right);
            }
        }
        state.ranges = next_ranges;
        state.active = !state.ranges.is_empty();
        state.stateid_seq += 1;
        Ok(Stateid4 {
            seqid: state.stateid_seq,
            other: lock_stateid.other,
        })
    }
}
