//! Public filesystem API for the embeddable NFSv4.1 server.

use async_trait::async_trait;
use bytes::Bytes;
use std::fmt;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign};

/// Result type used by filesystem backends.
pub type FsResult<T> = Result<T, FsError>;

/// Backend error values surfaced through the NFS server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FsError {
    /// Operation completed successfully.
    #[error("success")]
    Ok,
    /// Caller lacks permission for the operation.
    #[error("permission denied")]
    PermissionDenied,
    /// Object does not exist.
    #[error("not found")]
    NotFound,
    /// A lower-level I/O failure occurred.
    #[error("i/o error")]
    Io,
    /// Access was denied for the requested principal or mode bits.
    #[error("access denied")]
    AccessDenied,
    /// An entry with the requested name already exists.
    #[error("already exists")]
    AlreadyExists,
    /// Cross-filesystem rename/link is not supported.
    #[error("cross-device link")]
    CrossDevice,
    /// A directory was required but another object type was supplied.
    #[error("not a directory")]
    NotDirectory,
    /// A non-directory was required but a directory was supplied.
    #[error("is a directory")]
    IsDirectory,
    /// The input was invalid for the target backend.
    #[error("invalid input")]
    InvalidInput,
    /// The resulting file would be too large.
    #[error("file too large")]
    FileTooLarge,
    /// The backend ran out of space.
    #[error("no space left")]
    NoSpace,
    /// The backend is read-only.
    #[error("read-only filesystem")]
    ReadOnly,
    /// The provided name is too long.
    #[error("name too long")]
    NameTooLong,
    /// The target directory is not empty.
    #[error("directory not empty")]
    NotEmpty,
    /// The handle or object is stale.
    #[error("stale handle")]
    Stale,
    /// The backend does not support the requested operation.
    #[error("operation not supported")]
    Unsupported,
    /// The file handle was malformed or invalid.
    #[error("bad handle")]
    BadHandle,
    /// The backend encountered an unrecoverable server-side fault.
    #[error("server fault")]
    ServerFault,
}

impl FsError {
    pub(crate) fn to_nfsstat4(self) -> embednfs_proto::NfsStat4 {
        use embednfs_proto::NfsStat4;

        match self {
            FsError::Ok => NfsStat4::Ok,
            FsError::PermissionDenied => NfsStat4::Perm,
            FsError::NotFound => NfsStat4::Noent,
            FsError::Io => NfsStat4::Io,
            FsError::AccessDenied => NfsStat4::Access,
            FsError::AlreadyExists => NfsStat4::Exist,
            FsError::CrossDevice => NfsStat4::Xdev,
            FsError::NotDirectory => NfsStat4::Notdir,
            FsError::IsDirectory => NfsStat4::Isdir,
            FsError::InvalidInput => NfsStat4::Inval,
            FsError::FileTooLarge => NfsStat4::Fbig,
            FsError::NoSpace => NfsStat4::Nospc,
            FsError::ReadOnly => NfsStat4::Rofs,
            FsError::NameTooLong => NfsStat4::Nametoolong,
            FsError::NotEmpty => NfsStat4::Notempty,
            FsError::Stale => NfsStat4::Stale,
            FsError::Unsupported => NfsStat4::Notsupp,
            FsError::BadHandle => NfsStat4::Badhandle,
            FsError::ServerFault => NfsStat4::Serverfault,
        }
    }
}

/// Exported object kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    /// Regular file data object.
    File,
    /// Directory object.
    Directory,
    /// Symbolic link object.
    Symlink,
}

/// High-level server capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsCapabilities {
    /// Whether symbolic links are supported.
    pub symlinks: bool,
    /// Whether hard links are supported.
    pub hard_links: bool,
    /// Whether named attributes / xattrs are supported.
    pub xattrs: bool,
    /// Whether explicit sync/commit is supported.
    pub explicit_sync: bool,
    /// Whether lookups treat names case-sensitively.
    pub case_sensitive: bool,
    /// Whether name case is preserved.
    pub case_preserving: bool,
}

impl Default for FsCapabilities {
    fn default() -> Self {
        Self {
            symlinks: false,
            hard_links: false,
            xattrs: false,
            explicit_sync: false,
            case_sensitive: true,
            case_preserving: true,
        }
    }
}

/// Exported filesystem limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsLimits {
    /// Maximum object name length in bytes.
    pub max_name_bytes: u32,
    /// Maximum read size the backend wants to advertise.
    pub max_read: u32,
    /// Maximum write size the backend wants to advertise.
    pub max_write: u32,
    /// Maximum regular file size in bytes.
    pub max_file_size: u64,
}

impl Default for FsLimits {
    fn default() -> Self {
        Self {
            max_name_bytes: 255,
            max_read: 1_048_576,
            max_write: 1_048_576,
            max_file_size: 1 << 40,
        }
    }
}

/// Exported filesystem space and inode statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsStats {
    /// Total bytes in the filesystem.
    pub total_bytes: u64,
    /// Free bytes in the filesystem.
    pub free_bytes: u64,
    /// Bytes available to the caller.
    pub avail_bytes: u64,
    /// Total file/object slots.
    pub total_files: u64,
    /// Free file/object slots.
    pub free_files: u64,
    /// File/object slots available to the caller.
    pub avail_files: u64,
}

impl Default for FsStats {
    fn default() -> Self {
        Self {
            total_bytes: 1 << 40,
            free_bytes: 1 << 39,
            avail_bytes: 1 << 39,
            total_files: 1 << 30,
            free_files: 1 << 29,
            avail_files: 1 << 29,
        }
    }
}

/// Timestamp carried through exported attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    /// Seconds since the Unix epoch.
    pub seconds: i64,
    /// Nanoseconds within the second.
    pub nanos: u32,
}

impl Timestamp {
    /// Returns the current wall-clock time.
    pub fn now() -> Self {
        let dur = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            seconds: dur.as_secs() as i64,
            nanos: dur.subsec_nanos(),
        }
    }
}

/// Requested time update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTime {
    /// Use the server's current time.
    ServerNow,
    /// Use a client-specified time.
    Client(Timestamp),
}

/// Exported object attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attrs {
    /// Object type.
    pub object_type: ObjectType,
    /// Stable exported file identifier.
    pub fileid: u64,
    /// Change identifier for cookie verifiers and client cache invalidation.
    pub change: u64,
    /// Logical object size in bytes.
    pub size: u64,
    /// Space consumed by the object in bytes.
    pub space_used: u64,
    /// Link count.
    pub link_count: u32,
    /// POSIX-like permission bits.
    pub mode: u32,
    /// Numeric owner id.
    pub uid: u32,
    /// Numeric group id.
    pub gid: u32,
    /// Access time.
    pub atime: Timestamp,
    /// Modification time.
    pub mtime: Timestamp,
    /// Metadata change time.
    pub ctime: Timestamp,
    /// Birth / creation time.
    pub birthtime: Timestamp,
    /// Archive flag.
    pub archive: bool,
    /// Hidden flag.
    pub hidden: bool,
    /// System flag.
    pub system: bool,
    /// Whether the object has named attributes.
    pub has_named_attrs: bool,
}

impl Attrs {
    /// Returns a new attribute set with consistent zeroed timestamps.
    pub fn new(object_type: ObjectType, fileid: u64) -> Self {
        let now = Timestamp::now();
        Self {
            object_type,
            fileid,
            change: fileid.max(1),
            size: 0,
            space_used: 0,
            link_count: match object_type {
                ObjectType::Directory => 2,
                _ => 1,
            },
            mode: match object_type {
                ObjectType::Directory => 0o755,
                ObjectType::File => 0o644,
                ObjectType::Symlink => 0o777,
            },
            uid: 0,
            gid: 0,
            atime: now,
            mtime: now,
            ctime: now,
            birthtime: now,
            archive: false,
            hidden: false,
            system: false,
            has_named_attrs: false,
        }
    }
}

/// Partial attribute update request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetAttrs {
    /// Resize the object to the requested logical size.
    pub size: Option<u64>,
    /// Update the archive flag.
    pub archive: Option<bool>,
    /// Update the hidden flag.
    pub hidden: Option<bool>,
    /// Update permission bits.
    pub mode: Option<u32>,
    /// Update owner id.
    pub uid: Option<u32>,
    /// Update group id.
    pub gid: Option<u32>,
    /// Update the system flag.
    pub system: Option<bool>,
    /// Update access time.
    pub atime: Option<SetTime>,
    /// Update modification time.
    pub mtime: Option<SetTime>,
    /// Update birth time.
    pub birthtime: Option<SetTime>,
}

impl SetAttrs {
    /// Returns true if the request does not change any metadata.
    pub fn is_empty(&self) -> bool {
        self.size.is_none()
            && self.archive.is_none()
            && self.hidden.is_none()
            && self.mode.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && self.system.is_none()
            && self.atime.is_none()
            && self.mtime.is_none()
            && self.birthtime.is_none()
    }
}

/// Requested access bits for `ACCESS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AccessMask(pub u32);

impl AccessMask {
    /// No access requested.
    pub const NONE: Self = Self(0);
    /// Read file data.
    pub const READ: Self = Self(1 << 0);
    /// Lookup within a directory.
    pub const LOOKUP: Self = Self(1 << 1);
    /// Modify existing bytes or metadata.
    pub const MODIFY: Self = Self(1 << 2);
    /// Extend file length.
    pub const EXTEND: Self = Self(1 << 3);
    /// Delete object.
    pub const DELETE: Self = Self(1 << 4);
    /// Execute/search permission.
    pub const EXECUTE: Self = Self(1 << 5);

    /// Returns the raw bit representation.
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Returns true when all bits in `other` are present.
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns true when any bit in `other` is present.
    pub fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

impl BitAnd for AccessMask {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for AccessMask {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitOr for AccessMask {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for AccessMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Display for AccessMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// Request context for a single NFS operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// Authenticated caller context.
    pub auth: AuthContext,
}

impl RequestContext {
    /// Returns an anonymous request context.
    pub fn anonymous() -> Self {
        Self {
            auth: AuthContext::None,
        }
    }
}

/// Caller authentication details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthContext {
    /// No caller identity was supplied.
    None,
    /// AUTH_SYS credentials.
    Sys {
        /// Numeric uid.
        uid: u32,
        /// Primary gid.
        gid: u32,
        /// Supplemental gids.
        supplemental_gids: Vec<u32>,
    },
    /// Any other auth flavor.
    Unknown {
        /// RPC auth flavor value.
        flavor: u32,
    },
}

/// Create kind for the core `create` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateKind {
    /// Create a regular file.
    File,
    /// Create a directory.
    Directory,
}

/// Create request for the core `create` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    /// Requested object kind.
    pub kind: CreateKind,
    /// Initial attributes to apply during creation.
    pub attrs: SetAttrs,
}

/// Create result for the core `create` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateResult<H> {
    /// Handle for the created object.
    pub handle: H,
    /// Final attributes for the created object.
    pub attrs: Attrs,
}

/// Read result for regular files and named attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    /// Returned data slice.
    pub data: Bytes,
    /// Whether the end of the object was reached.
    pub eof: bool,
}

/// Write stability level reported by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStability {
    /// Data may require a later commit.
    Unstable,
    /// Data is durable but metadata may not be.
    DataSync,
    /// Data and metadata are durable.
    FileSync,
}

/// Write result for the core `write` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteResult {
    /// Number of bytes written.
    pub written: u32,
    /// Durability guarantee for the completed write.
    pub stability: WriteStability,
}

/// Paged directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry<H> {
    /// Entry name.
    pub name: String,
    /// Handle for the child object.
    pub handle: H,
    /// Cookie to resume after this entry.
    pub cookie: u64,
    /// Optional inline attributes when requested.
    pub attrs: Option<Attrs>,
}

/// Paged directory listing result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirPage<H> {
    /// Entries included in this page.
    pub entries: Vec<DirEntry<H>>,
    /// Whether the end of the directory was reached.
    pub eof: bool,
}

/// Controls how a named attribute should be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrSetMode {
    /// Create the attribute if absent, otherwise replace it.
    CreateOrReplace,
    /// Only create a new attribute.
    CreateOnly,
    /// Only replace an existing attribute.
    ReplaceOnly,
}

/// Optional named-attribute support.
#[async_trait]
pub trait Xattrs<H>: Send + Sync {
    /// List all named attributes attached to an object.
    async fn list_xattrs(&self, ctx: &RequestContext, handle: &H) -> FsResult<Vec<String>>;

    /// Fetch a full named-attribute value.
    async fn get_xattr(&self, ctx: &RequestContext, handle: &H, name: &str) -> FsResult<Bytes>;

    /// Set or replace a named attribute value.
    async fn set_xattr(
        &self,
        ctx: &RequestContext,
        handle: &H,
        name: &str,
        value: Bytes,
        mode: XattrSetMode,
    ) -> FsResult<()>;

    /// Remove a named attribute.
    async fn remove_xattr(&self, ctx: &RequestContext, handle: &H, name: &str) -> FsResult<()>;
}

/// Optional symbolic-link support.
#[async_trait]
pub trait Symlinks<H>: Send + Sync {
    /// Create a symbolic link and return the created handle and attrs.
    async fn create_symlink(
        &self,
        ctx: &RequestContext,
        parent: &H,
        name: &str,
        target: &str,
        attrs: &SetAttrs,
    ) -> FsResult<CreateResult<H>>;

    /// Read a symlink target.
    async fn readlink(&self, ctx: &RequestContext, handle: &H) -> FsResult<String>;
}

/// Optional hard-link support.
#[async_trait]
pub trait HardLinks<H>: Send + Sync {
    /// Create a hard link to an existing file.
    async fn link(&self, ctx: &RequestContext, source: &H, parent: &H, name: &str) -> FsResult<()>;
}

/// Optional explicit commit support.
#[async_trait]
pub trait CommitSupport<H>: Send + Sync {
    /// Flush buffered writes for a byte range.
    async fn commit(
        &self,
        ctx: &RequestContext,
        handle: &H,
        offset: u64,
        count: u32,
    ) -> FsResult<()>;
}

/// Optional close support for filesystems that buffer write data until
/// the client closes the open state.
#[async_trait]
pub trait CloseSupport<H>: Send + Sync {
    /// Flush buffered writes for an open file before the NFS CLOSE completes.
    async fn close(&self, ctx: &RequestContext, handle: &H) -> FsResult<()>;
}

/// Core filesystem trait implemented by embedders.
#[async_trait]
pub trait FileSystem: Send + Sync + 'static {
    /// Opaque stable handle type for backend objects.
    type Handle: Clone + Eq + std::hash::Hash + Send + Sync + 'static;

    /// Returns the root handle for the exported filesystem.
    fn root(&self) -> Self::Handle;

    /// Returns static capability flags.
    fn capabilities(&self) -> FsCapabilities {
        FsCapabilities::default()
    }

    /// Returns static filesystem limits.
    fn limits(&self) -> FsLimits {
        FsLimits::default()
    }

    /// Returns filesystem-wide space and object statistics.
    async fn statfs(&self, ctx: &RequestContext) -> FsResult<FsStats>;

    /// Returns complete exported attributes for an object.
    async fn getattr(&self, ctx: &RequestContext, handle: &Self::Handle) -> FsResult<Attrs>;

    /// Returns the subset of requested access bits granted for the caller.
    async fn access(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        requested: AccessMask,
    ) -> FsResult<AccessMask>;

    /// Looks up a named child in a directory.
    async fn lookup(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<Self::Handle>;

    /// Returns the parent of a directory, or `None` for the root directory.
    async fn parent(
        &self,
        ctx: &RequestContext,
        dir: &Self::Handle,
    ) -> FsResult<Option<Self::Handle>>;

    /// Returns a page of directory entries starting after `cookie`.
    async fn readdir(
        &self,
        ctx: &RequestContext,
        dir: &Self::Handle,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> FsResult<DirPage<Self::Handle>>;

    /// Reads a byte range from an object.
    async fn read(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        count: u32,
    ) -> FsResult<ReadResult>;

    /// Writes a byte range to an object.
    async fn write(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        data: Bytes,
        requested: WriteStability,
    ) -> FsResult<WriteResult>;

    /// Creates a regular file or directory.
    async fn create(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
        req: CreateRequest,
    ) -> FsResult<CreateResult<Self::Handle>>;

    /// Removes a file or empty directory by name.
    async fn remove(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str)
    -> FsResult<()>;

    /// Renames or moves an entry.
    async fn rename(
        &self,
        ctx: &RequestContext,
        from_dir: &Self::Handle,
        from_name: &str,
        to_dir: &Self::Handle,
        to_name: &str,
    ) -> FsResult<()>;

    /// Applies attribute updates and returns the resulting attrs.
    async fn setattr(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        attrs: &SetAttrs,
    ) -> FsResult<Attrs>;

    /// Returns optional named-attribute support.
    fn xattrs(&self) -> Option<&dyn Xattrs<Self::Handle>> {
        None
    }

    /// Returns optional symlink support.
    fn symlinks(&self) -> Option<&dyn Symlinks<Self::Handle>> {
        None
    }

    /// Returns optional hard-link support.
    fn hard_links(&self) -> Option<&dyn HardLinks<Self::Handle>> {
        None
    }

    /// Returns optional explicit commit support.
    fn commit_support(&self) -> Option<&dyn CommitSupport<Self::Handle>> {
        None
    }

    /// Returns optional explicit close support.
    fn close_support(&self) -> Option<&dyn CloseSupport<Self::Handle>> {
        None
    }
}
