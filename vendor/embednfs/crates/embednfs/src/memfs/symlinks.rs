use async_trait::async_trait;
use std::collections::HashMap;

use crate::fs::*;

use super::{Inode, InodeData, MemFs};

#[async_trait]
impl Symlinks<u64> for MemFs {
    async fn create_symlink(
        &self,
        ctx: &RequestContext,
        parent: &u64,
        name: &str,
        target: &str,
        attrs: &SetAttrs,
    ) -> FsResult<CreateResult<u64>> {
        let new_id = self.next_id();
        let mut inner = self.inner.write().await;

        {
            let parent_inode = inner.inodes.get(parent).ok_or(FsError::Stale)?;
            match &parent_inode.data {
                InodeData::Directory(entries) => {
                    if entries.contains_key(name) {
                        return Err(FsError::AlreadyExists);
                    }
                }
                _ => return Err(FsError::NotDirectory),
            }
        }

        let mut inode = Inode {
            attrs: Attrs::new(ObjectType::Symlink, new_id),
            parent: Some(*parent),
            data: InodeData::Symlink(target.to_string()),
            xattrs: HashMap::new(),
        };
        Self::apply_create_owner(&mut inode.attrs, ctx);
        inode.attrs.size = target.len() as u64;
        inode.attrs.space_used = inode.attrs.size;
        self.apply_setattrs(&mut inode, attrs)?;
        inode.attrs.size = target.len() as u64;
        inode.attrs.space_used = inode.attrs.size;

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

        Ok(CreateResult {
            handle: new_id,
            attrs: inner
                .inodes
                .get(&new_id)
                .ok_or(FsError::ServerFault)?
                .attrs
                .clone(),
        })
    }

    async fn readlink(&self, _ctx: &RequestContext, handle: &u64) -> FsResult<String> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        match &inode.data {
            InodeData::Symlink(target) => Ok(target.clone()),
            _ => Err(FsError::InvalidInput),
        }
    }
}
