use async_trait::async_trait;
use bytes::Bytes;

use crate::fs::*;

use super::MemFs;

#[async_trait]
impl Xattrs<u64> for MemFs {
    async fn list_xattrs(&self, _ctx: &RequestContext, handle: &u64) -> FsResult<Vec<String>> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        let mut names: Vec<String> = inode.xattrs.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    async fn get_xattr(&self, _ctx: &RequestContext, handle: &u64, name: &str) -> FsResult<Bytes> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        inode.xattrs.get(name).cloned().ok_or(FsError::NotFound)
    }

    async fn set_xattr(
        &self,
        _ctx: &RequestContext,
        handle: &u64,
        name: &str,
        value: Bytes,
        mode: XattrSetMode,
    ) -> FsResult<()> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(handle).ok_or(FsError::Stale)?;
        let exists = inode.xattrs.contains_key(name);
        match mode {
            XattrSetMode::CreateOrReplace => {}
            XattrSetMode::CreateOnly if exists => return Err(FsError::AlreadyExists),
            XattrSetMode::ReplaceOnly if !exists => return Err(FsError::NotFound),
            XattrSetMode::CreateOnly | XattrSetMode::ReplaceOnly => {}
        }
        let _ = inode.xattrs.insert(name.to_string(), value);
        Self::update_has_named_attrs(inode);
        self.touch_data_change(&mut inode.attrs);
        Ok(())
    }

    async fn remove_xattr(&self, _ctx: &RequestContext, handle: &u64, name: &str) -> FsResult<()> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(handle).ok_or(FsError::Stale)?;
        if inode.xattrs.remove(name).is_none() {
            return Err(FsError::NotFound);
        }
        Self::update_has_named_attrs(inode);
        self.touch_change(&mut inode.attrs);
        Ok(())
    }
}
