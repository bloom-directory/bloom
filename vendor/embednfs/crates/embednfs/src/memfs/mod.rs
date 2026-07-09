//! In-memory reference backend for the filesystem API.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use tokio::sync::RwLock;

use crate::fs::{Attrs, ObjectType};

mod commit;
mod core;
mod hardlinks;
mod helpers;
mod state;
mod symlinks;
#[cfg(test)]
mod tests;
mod xattrs;

use state::{Inode, InodeData, MemFsInner};

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// In-memory filesystem implementation used by tests and examples.
pub struct MemFs {
    inner: RwLock<MemFsInner>,
    next_id: AtomicU64,
    next_change: AtomicU64,
}

impl MemFs {
    /// Creates a new empty in-memory filesystem.
    pub fn new() -> Self {
        let mut inodes = HashMap::new();
        let mut root_attrs = Attrs::new(ObjectType::Directory, 1);
        root_attrs.mode = 0o777;
        let _ = inodes.insert(
            1,
            Inode {
                attrs: root_attrs,
                parent: None,
                data: InodeData::Directory(HashMap::new()),
                xattrs: HashMap::new(),
            },
        );

        Self {
            inner: RwLock::new(MemFsInner { inodes }),
            next_id: AtomicU64::new(2),
            next_change: AtomicU64::new(2),
        }
    }
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}
