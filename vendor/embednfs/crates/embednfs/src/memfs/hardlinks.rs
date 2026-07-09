use async_trait::async_trait;

use crate::fs::*;

use super::{InodeData, MemFs};

#[async_trait]
impl HardLinks<u64> for MemFs {
    async fn link(
        &self,
        _ctx: &RequestContext,
        source: &u64,
        parent: &u64,
        name: &str,
    ) -> FsResult<()> {
        let mut inner = self.inner.write().await;
        let source_inode = inner.inodes.get(source).ok_or(FsError::Stale)?;
        if source_inode.attrs.object_type == ObjectType::Directory {
            return Err(FsError::IsDirectory);
        }

        let parent_inode = inner.inodes.get_mut(parent).ok_or(FsError::Stale)?;
        match &mut parent_inode.data {
            InodeData::Directory(entries) => {
                if entries.contains_key(name) {
                    return Err(FsError::AlreadyExists);
                }
                let _ = entries.insert(name.to_string(), *source);
            }
            _ => return Err(FsError::NotDirectory),
        }
        self.touch_change(&mut parent_inode.attrs);
        parent_inode.attrs.mtime = Timestamp::now();
        Self::recompute_link_counts(&mut inner);
        Ok(())
    }
}
