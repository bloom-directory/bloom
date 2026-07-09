use std::collections::HashMap;

use bytes::Bytes;

use crate::fs::Attrs;

pub(super) struct MemFsInner {
    pub inodes: HashMap<u64, Inode>,
}

pub(super) struct Inode {
    pub attrs: Attrs,
    pub parent: Option<u64>,
    pub data: InodeData,
    pub xattrs: HashMap<String, Bytes>,
}

pub(super) enum InodeData {
    File(Vec<u8>),
    Directory(HashMap<String, u64>),
    Symlink(String),
}
