use async_trait::async_trait;

use crate::fs::*;

use super::MemFs;

#[async_trait]
impl CommitSupport<u64> for MemFs {
    async fn commit(
        &self,
        _ctx: &RequestContext,
        handle: &u64,
        _offset: u64,
        _count: u32,
    ) -> FsResult<()> {
        let inner = self.inner.read().await;
        if inner.inodes.contains_key(handle) {
            Ok(())
        } else {
            Err(FsError::Stale)
        }
    }
}
