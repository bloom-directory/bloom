use std::sync::atomic::Ordering;

use crate::fs::{
    Attrs, AuthContext, FsError, FsResult, ObjectType, RequestContext, SetAttrs, SetTime, Timestamp,
};

use super::MemFs;
use super::state::{Inode, InodeData, MemFsInner};

impl MemFs {
    pub(super) fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn next_change(&self) -> u64 {
        self.next_change.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn checked_file_len(&self, len: u64) -> FsResult<usize> {
        if len > super::MAX_FILE_BYTES {
            return Err(FsError::FileTooLarge);
        }
        usize::try_from(len).map_err(|_| FsError::FileTooLarge)
    }

    pub(super) fn checked_write_range(&self, offset: u64, len: usize) -> FsResult<(usize, usize)> {
        let data_len = u64::try_from(len).map_err(|_| FsError::FileTooLarge)?;
        let end = offset.checked_add(data_len).ok_or(FsError::FileTooLarge)?;
        Ok((self.checked_file_len(offset)?, self.checked_file_len(end)?))
    }

    pub(super) fn touch_change(&self, attrs: &mut Attrs) {
        let now = Timestamp::now();
        attrs.change = self.next_change();
        attrs.ctime = now;
    }

    pub(super) fn touch_data_change(&self, attrs: &mut Attrs) {
        let now = Timestamp::now();
        attrs.change = self.next_change();
        attrs.mtime = now;
        attrs.ctime = now;
    }

    pub(super) fn apply_set_time(field: &mut Timestamp, value: SetTime) {
        *field = match value {
            SetTime::ServerNow => Timestamp::now(),
            SetTime::Client(ts) => ts,
        };
    }

    pub(super) fn apply_create_owner(attrs: &mut Attrs, ctx: &RequestContext) {
        if let AuthContext::Sys { uid, gid, .. } = &ctx.auth {
            attrs.uid = *uid;
            attrs.gid = *gid;
        }
    }

    pub(super) fn apply_setattrs(&self, inode: &mut Inode, attrs: &SetAttrs) -> FsResult<()> {
        let mut changed = false;
        let mut data_changed = false;
        let mut explicit_mtime = false;

        if let Some(size) = attrs.size {
            match &mut inode.data {
                InodeData::File(data) => {
                    data.resize(self.checked_file_len(size)?, 0);
                    inode.attrs.size = size;
                    inode.attrs.space_used = size;
                    changed = true;
                    data_changed = true;
                }
                _ => return Err(FsError::InvalidInput),
            }
        }
        if let Some(mode) = attrs.mode {
            inode.attrs.mode = mode & 0o7777;
            changed = true;
        }
        if let Some(uid) = attrs.uid {
            inode.attrs.uid = uid;
            changed = true;
        }
        if let Some(gid) = attrs.gid {
            inode.attrs.gid = gid;
            changed = true;
        }
        if let Some(archive) = attrs.archive {
            inode.attrs.archive = archive;
            changed = true;
        }
        if let Some(hidden) = attrs.hidden {
            inode.attrs.hidden = hidden;
            changed = true;
        }
        if let Some(system) = attrs.system {
            inode.attrs.system = system;
            changed = true;
        }
        if let Some(atime) = attrs.atime {
            Self::apply_set_time(&mut inode.attrs.atime, atime);
            changed = true;
        }
        if let Some(mtime) = attrs.mtime {
            Self::apply_set_time(&mut inode.attrs.mtime, mtime);
            changed = true;
            explicit_mtime = true;
        }
        if let Some(birthtime) = attrs.birthtime {
            Self::apply_set_time(&mut inode.attrs.birthtime, birthtime);
            changed = true;
        }

        if changed {
            let now = Timestamp::now();
            inode.attrs.change = self.next_change();
            inode.attrs.ctime = now;
            if data_changed && !explicit_mtime {
                inode.attrs.mtime = now;
            }
        }

        Ok(())
    }

    pub(super) fn recompute_link_counts(inner: &mut MemFsInner) {
        for inode in inner.inodes.values_mut() {
            inode.attrs.link_count = match inode.attrs.object_type {
                ObjectType::Directory => 2,
                _ => 0,
            };
        }

        let directory_ids: Vec<u64> = inner
            .inodes
            .iter()
            .filter_map(|(id, inode)| match inode.data {
                InodeData::Directory(_) => Some(*id),
                _ => None,
            })
            .collect();

        for dir_id in directory_ids {
            let Some(entries) = inner
                .inodes
                .get(&dir_id)
                .and_then(|inode| match &inode.data {
                    InodeData::Directory(entries) => Some(entries.clone()),
                    _ => None,
                })
            else {
                continue;
            };
            for child_id in entries.values() {
                if let Some(child) = inner.inodes.get_mut(child_id) {
                    match child.attrs.object_type {
                        ObjectType::Directory => {
                            if let Some(parent) = inner.inodes.get_mut(&dir_id) {
                                parent.attrs.link_count += 1;
                            }
                        }
                        _ => child.attrs.link_count += 1,
                    }
                }
            }
        }
    }

    pub(super) fn remove_if_unlinked(inner: &mut MemFsInner, inode_id: u64) {
        let should_remove = match inner.inodes.get(&inode_id) {
            Some(inode) => match inode.attrs.object_type {
                ObjectType::Directory => true,
                _ => !inner
                    .inodes
                    .values()
                    .any(|candidate| match &candidate.data {
                        InodeData::Directory(entries) => entries.values().any(|id| *id == inode_id),
                        _ => false,
                    }),
            },
            None => false,
        };

        if should_remove {
            let _ = inner.inodes.remove(&inode_id);
        }
    }

    pub(super) fn directory_descends_from(
        inner: &MemFsInner,
        descendant_id: u64,
        ancestor_id: u64,
    ) -> bool {
        let mut current = Some(descendant_id);
        let mut remaining = inner.inodes.len();

        while let Some(id) = current {
            if id == ancestor_id {
                return true;
            }
            if remaining == 0 {
                break;
            }
            remaining -= 1;
            current = inner
                .inodes
                .get(&id)
                .and_then(|inode| {
                    (inode.attrs.object_type == ObjectType::Directory).then_some(inode.parent)
                })
                .flatten();
        }

        false
    }

    pub(super) fn update_has_named_attrs(inode: &mut Inode) {
        inode.attrs.has_named_attrs = !inode.xattrs.is_empty();
    }
}
