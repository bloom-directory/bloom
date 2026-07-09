//! Embeddable NFSv4.1 server library.
//!
//! Provides a complete NFSv4.1 server implementation. Users implement the
//! [`FileSystem`] trait; the library handles the wire protocol, session
//! management, and serves it over TCP.

pub(crate) mod attrs;
pub(crate) mod fs;
pub(crate) mod internal;
pub(crate) mod memfs;
pub(crate) mod server;
pub(crate) mod session;

pub use fs::{
    AccessMask, Attrs, AuthContext, CloseSupport, CommitSupport, CreateKind, CreateRequest,
    CreateResult, DirEntry, DirPage, FileSystem, FsCapabilities, FsError, FsLimits, FsResult,
    FsStats, HardLinks, ObjectType, ReadResult, RequestContext, SetAttrs, SetTime, Symlinks,
    Timestamp, WriteResult, WriteStability, XattrSetMode, Xattrs,
};
pub use memfs::MemFs;
pub use server::{IdMapper, NfsServer, NfsServerBuilder, NumericIdMapper};
