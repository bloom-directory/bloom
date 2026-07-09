use std::collections::HashMap;

use async_trait::async_trait;
use bytes::Bytes;

use crate::fs::{
    AccessMask, Attrs, CommitSupport, CreateKind, CreateRequest, CreateResult, DirEntry, DirPage,
    FileSystem, FsCapabilities, FsError, FsLimits, FsResult, FsStats, HardLinks, ObjectType,
    ReadResult, RequestContext, SetAttrs, Symlinks, Timestamp, WriteResult, WriteStability, Xattrs,
};

use super::MemFs;
use super::state::{Inode, InodeData};

#[async_trait]
impl FileSystem for MemFs {
    type Handle = u64;

    fn root(&self) -> Self::Handle {
        1
    }

    fn capabilities(&self) -> FsCapabilities {
        FsCapabilities {
            symlinks: true,
            hard_links: true,
            xattrs: true,
            explicit_sync: true,
            case_sensitive: true,
            case_preserving: true,
        }
    }

    fn limits(&self) -> FsLimits {
        FsLimits {
            max_file_size: super::MAX_FILE_BYTES,
            ..FsLimits::default()
        }
    }

    async fn statfs(&self, _ctx: &RequestContext) -> FsResult<FsStats> {
        let inner = self.inner.read().await;
        let used_bytes = inner.inodes.values().fold(0_u64, |total, inode| {
            total.saturating_add(inode.attrs.space_used)
        });
        let total_files = 1 << 20;
        let used_files = inner.inodes.len() as u64;

        Ok(FsStats {
            total_bytes: 1 << 30,
            free_bytes: (1_u64 << 30).saturating_sub(used_bytes),
            avail_bytes: (1_u64 << 30).saturating_sub(used_bytes),
            total_files,
            free_files: total_files.saturating_sub(used_files),
            avail_files: total_files.saturating_sub(used_files),
        })
    }

    async fn getattr(&self, _ctx: &RequestContext, handle: &Self::Handle) -> FsResult<Attrs> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        Ok(inode.attrs.clone())
    }

    async fn access(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        requested: AccessMask,
    ) -> FsResult<AccessMask> {
        let inner = self.inner.read().await;
        let _inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        Ok(requested)
    }

    async fn lookup(
        &self,
        _ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<Self::Handle> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(parent).ok_or(FsError::Stale)?;
        match &inode.data {
            InodeData::Directory(entries) => entries.get(name).copied().ok_or(FsError::NotFound),
            _ => Err(FsError::NotDirectory),
        }
    }

    async fn parent(
        &self,
        _ctx: &RequestContext,
        dir: &Self::Handle,
    ) -> FsResult<Option<Self::Handle>> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(dir).ok_or(FsError::Stale)?;
        if inode.attrs.object_type != ObjectType::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(inode.parent)
    }

    async fn readdir(
        &self,
        _ctx: &RequestContext,
        dir: &Self::Handle,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> FsResult<DirPage<Self::Handle>> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(dir).ok_or(FsError::Stale)?;
        let entries = match &inode.data {
            InodeData::Directory(entries) => entries,
            _ => return Err(FsError::NotDirectory),
        };

        let mut names: Vec<_> = entries.iter().collect();
        names.sort_by(|a, b| a.0.cmp(b.0));

        let start = if cookie == 0 {
            0
        } else {
            cookie.saturating_sub(2) as usize
        };
        let limit = if max_entries == 0 {
            usize::MAX
        } else {
            max_entries as usize
        };

        let mut page = Vec::with_capacity(limit.min(names.len().saturating_sub(start)));
        for (idx, (name, child)) in names.into_iter().skip(start).take(limit).enumerate() {
            let child_inode = inner.inodes.get(child).ok_or(FsError::Stale)?;
            page.push(DirEntry {
                name: name.clone(),
                handle: *child,
                cookie: (start + idx + 3) as u64,
                attrs: with_attrs.then(|| child_inode.attrs.clone()),
            });
        }

        Ok(DirPage {
            eof: start + page.len() >= entries.len(),
            entries: page,
        })
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "the read range is validated locally before slicing the file buffer"
    )]
    async fn read(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        count: u32,
    ) -> FsResult<ReadResult> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        match &inode.data {
            InodeData::File(data) => {
                let offset = usize::try_from(offset).map_err(|_| FsError::FileTooLarge)?;
                if offset >= data.len() {
                    return Ok(ReadResult {
                        data: Bytes::new(),
                        eof: true,
                    });
                }
                let end = offset.saturating_add(count as usize).min(data.len());
                let chunk = &data[offset..end];
                Ok(ReadResult {
                    data: Bytes::copy_from_slice(chunk),
                    eof: end == data.len(),
                })
            }
            _ => Err(FsError::InvalidInput),
        }
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "the file is resized locally to cover the validated write range"
    )]
    async fn write(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        data: Bytes,
        _requested: WriteStability,
    ) -> FsResult<WriteResult> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(handle).ok_or(FsError::Stale)?;
        match &mut inode.data {
            InodeData::File(file) => {
                let (offset, end) = self.checked_write_range(offset, data.len())?;
                if end > file.len() {
                    file.resize(end, 0);
                }
                file[offset..end].copy_from_slice(&data);
                inode.attrs.size = file.len() as u64;
                inode.attrs.space_used = inode.attrs.size;
                self.touch_data_change(&mut inode.attrs);
                Ok(WriteResult {
                    written: data.len() as u32,
                    stability: WriteStability::FileSync,
                })
            }
            _ => Err(FsError::InvalidInput),
        }
    }

    async fn create(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
        req: CreateRequest,
    ) -> FsResult<CreateResult<Self::Handle>> {
        let new_id = self.next_id();
        let mut inner = self.inner.write().await;

        {
            let parent_inode = inner.inodes.get(parent).ok_or(FsError::Stale)?;
            if parent_inode.attrs.object_type != ObjectType::Directory {
                return Err(FsError::NotDirectory);
            }
            if let InodeData::Directory(entries) = &parent_inode.data
                && entries.contains_key(name)
            {
                return Err(FsError::AlreadyExists);
            }
        }

        let mut inode = Inode {
            attrs: Attrs::new(
                match req.kind {
                    CreateKind::File => ObjectType::File,
                    CreateKind::Directory => ObjectType::Directory,
                },
                new_id,
            ),
            parent: Some(*parent),
            data: match req.kind {
                CreateKind::File => InodeData::File(Vec::new()),
                CreateKind::Directory => InodeData::Directory(HashMap::new()),
            },
            xattrs: HashMap::new(),
        };
        Self::apply_create_owner(&mut inode.attrs, ctx);
        self.apply_setattrs(&mut inode, &req.attrs)?;

        {
            let parent_inode = inner.inodes.get_mut(parent).ok_or(FsError::Stale)?;
            let InodeData::Directory(entries) = &mut parent_inode.data else {
                return Err(FsError::NotDirectory);
            };
            let _ = entries.insert(name.to_string(), new_id);
            self.touch_change(&mut parent_inode.attrs);
            parent_inode.attrs.mtime = Timestamp::now();
        }
        let _ = inner.inodes.insert(new_id, inode);
        Self::recompute_link_counts(&mut inner);

        let attrs = inner
            .inodes
            .get(&new_id)
            .ok_or(FsError::ServerFault)?
            .attrs
            .clone();
        Ok(CreateResult {
            handle: new_id,
            attrs,
        })
    }

    async fn remove(
        &self,
        _ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<()> {
        let mut inner = self.inner.write().await;
        let child_id = {
            let parent_inode = inner.inodes.get(parent).ok_or(FsError::Stale)?;
            match &parent_inode.data {
                InodeData::Directory(entries) => *entries.get(name).ok_or(FsError::NotFound)?,
                _ => return Err(FsError::NotDirectory),
            }
        };

        if let Some(child) = inner.inodes.get(&child_id)
            && let InodeData::Directory(entries) = &child.data
            && !entries.is_empty()
        {
            return Err(FsError::NotEmpty);
        }

        if let Some(parent_inode) = inner.inodes.get_mut(parent) {
            if let InodeData::Directory(entries) = &mut parent_inode.data {
                let _ = entries.remove(name);
            }
            self.touch_change(&mut parent_inode.attrs);
            parent_inode.attrs.mtime = Timestamp::now();
        }

        Self::remove_if_unlinked(&mut inner, child_id);
        Self::recompute_link_counts(&mut inner);
        Ok(())
    }

    async fn rename(
        &self,
        _ctx: &RequestContext,
        from_dir: &Self::Handle,
        from_name: &str,
        to_dir: &Self::Handle,
        to_name: &str,
    ) -> FsResult<()> {
        let mut inner = self.inner.write().await;

        let child_id = {
            let from_inode = inner.inodes.get(from_dir).ok_or(FsError::Stale)?;
            match &from_inode.data {
                InodeData::Directory(entries) => {
                    *entries.get(from_name).ok_or(FsError::NotFound)?
                }
                _ => return Err(FsError::NotDirectory),
            }
        };
        let child_type = inner
            .inodes
            .get(&child_id)
            .ok_or(FsError::Stale)?
            .attrs
            .object_type;

        if child_type == ObjectType::Directory
            && Self::directory_descends_from(&inner, *to_dir, child_id)
        {
            return Err(FsError::InvalidInput);
        }

        let replaced = {
            let target_inode = inner.inodes.get(to_dir).ok_or(FsError::Stale)?;
            match &target_inode.data {
                InodeData::Directory(entries) => entries.get(to_name).copied(),
                _ => return Err(FsError::NotDirectory),
            }
        };

        if replaced == Some(child_id) {
            return Ok(());
        }

        if let Some(replaced_id) = replaced {
            let replaced_inode = inner.inodes.get(&replaced_id).ok_or(FsError::Stale)?;
            match (
                child_type,
                replaced_inode.attrs.object_type,
                &replaced_inode.data,
            ) {
                (ObjectType::Directory, ObjectType::Directory, InodeData::Directory(entries))
                    if !entries.is_empty() =>
                {
                    return Err(FsError::NotEmpty);
                }
                (ObjectType::Directory, ObjectType::Directory, _) => {}
                (ObjectType::Directory, _, _) => return Err(FsError::NotDirectory),
                (_, ObjectType::Directory, _) => return Err(FsError::IsDirectory),
                _ => {}
            }
        }

        if from_dir == to_dir {
            if let Some(dir_inode) = inner.inodes.get_mut(from_dir) {
                if let InodeData::Directory(entries) = &mut dir_inode.data {
                    let removed = entries.remove(from_name);
                    debug_assert_eq!(removed, Some(child_id));
                    let previous = entries.insert(to_name.to_string(), child_id);
                    debug_assert_eq!(previous, replaced);
                }
                self.touch_change(&mut dir_inode.attrs);
                dir_inode.attrs.mtime = Timestamp::now();
            }
        } else {
            if let Some(from_inode) = inner.inodes.get_mut(from_dir) {
                if let InodeData::Directory(entries) = &mut from_inode.data {
                    let removed = entries.remove(from_name);
                    debug_assert_eq!(removed, Some(child_id));
                }
                self.touch_change(&mut from_inode.attrs);
                from_inode.attrs.mtime = Timestamp::now();
            }
            if let Some(to_inode) = inner.inodes.get_mut(to_dir) {
                if let InodeData::Directory(entries) = &mut to_inode.data {
                    let previous = entries.insert(to_name.to_string(), child_id);
                    debug_assert_eq!(previous, replaced);
                }
                self.touch_change(&mut to_inode.attrs);
                to_inode.attrs.mtime = Timestamp::now();
            }
        }
        if let Some(child_inode) = inner.inodes.get_mut(&child_id)
            && child_inode.attrs.object_type == ObjectType::Directory
            && from_dir != to_dir
        {
            child_inode.parent = Some(*to_dir);
        }
        if let Some(replaced_id) = replaced {
            Self::remove_if_unlinked(&mut inner, replaced_id);
        }

        Self::recompute_link_counts(&mut inner);
        Ok(())
    }

    async fn setattr(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        attrs: &SetAttrs,
    ) -> FsResult<Attrs> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(handle).ok_or(FsError::Stale)?;
        self.apply_setattrs(inode, attrs)?;
        Ok(inode.attrs.clone())
    }

    fn xattrs(&self) -> Option<&dyn Xattrs<Self::Handle>> {
        Some(self)
    }

    fn symlinks(&self) -> Option<&dyn Symlinks<Self::Handle>> {
        Some(self)
    }

    fn hard_links(&self) -> Option<&dyn HardLinks<Self::Handle>> {
        Some(self)
    }

    fn commit_support(&self) -> Option<&dyn CommitSupport<Self::Handle>> {
        Some(self)
    }
}
