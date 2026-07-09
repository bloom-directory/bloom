use crate::fs::Attrs;

/// Internal identifier used to map opaque backend handles to server state.
pub(crate) type ObjectId = u64;

/// Internal object identity used by the server for filehandles and state.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum ServerObject {
    Fs(ObjectId),
    NamedAttrDir(ObjectId),
    NamedAttrFile { parent: ObjectId, name: String },
}

/// Internal file kinds used for NFS attribute encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerFileType {
    Regular,
    Directory,
    Symlink,
    NamedAttrDir,
    NamedAttr,
}

/// Internal attribute record used by the protocol layer.
#[derive(Debug, Clone)]
pub(crate) struct ServerFileAttr {
    pub fileid: u64,
    pub file_type: ServerFileType,
    pub size: u64,
    pub used: u64,
    pub mode: u32,
    pub nlink: u32,
    pub owner: String,
    pub owner_group: String,
    pub atime_sec: i64,
    pub atime_nsec: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
    pub crtime_sec: i64,
    pub crtime_nsec: u32,
    pub change_id: u64,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub archive: bool,
    pub hidden: bool,
    pub system: bool,
    pub has_named_attrs: bool,
}

impl ServerFileType {
    pub(crate) fn from_attrs(attrs: &Attrs) -> Self {
        match attrs.object_type {
            crate::fs::ObjectType::File => Self::Regular,
            crate::fs::ObjectType::Directory => Self::Directory,
            crate::fs::ObjectType::Symlink => Self::Symlink,
        }
    }
}
