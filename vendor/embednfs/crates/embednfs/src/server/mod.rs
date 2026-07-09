use bytes::{Bytes, BytesMut};
/// NFSv4.1 server - COMPOUND procedure handling.
///
/// This is the core of the NFS server. It receives COMPOUND requests,
/// dispatches each operation, and builds the COMPOUND response.
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info};

use embednfs_proto::xdr::*;
use embednfs_proto::*;

use crate::fs::*;
use crate::internal::ObjectId;
use crate::session::StateManager;

const RPC_LAST_FRAGMENT: u32 = 0x8000_0000;
const RPC_FRAG_LEN_MASK: u32 = 0x7fff_ffff;
const MAX_FRAGMENT_SIZE: usize = 2 * 1024 * 1024;
const CONN_BUF_SIZE: usize = 65_536;

type NfsResult<T> = FsResult<T>;

mod compound;
mod file_attrs;
mod objects;
mod ops;
mod transport;

/// Maps numeric ids to NFS owner/group strings.
pub trait IdMapper: Send + Sync + 'static {
    /// Maps a numeric uid to an NFS owner string.
    fn owner(&self, uid: u32) -> String;

    /// Maps a numeric gid to an NFS owner-group string.
    fn group(&self, gid: u32) -> String;
}

/// Default id mapper that renders numeric ids directly.
pub struct NumericIdMapper;

impl IdMapper for NumericIdMapper {
    fn owner(&self, uid: u32) -> String {
        uid.to_string()
    }

    fn group(&self, gid: u32) -> String {
        gid.to_string()
    }
}

/// Builder for [`NfsServer`].
pub struct NfsServerBuilder<F: FileSystem> {
    fs: F,
    id_mapper: Arc<dyn IdMapper>,
}

impl<F: FileSystem> NfsServerBuilder<F> {
    /// Replaces the uid/gid string mapper used for `owner` attributes.
    pub fn id_mapper<M: IdMapper>(mut self, mapper: M) -> Self {
        self.id_mapper = Arc::new(mapper);
        self
    }

    /// Builds the server instance.
    pub fn build(self) -> NfsServer<F> {
        NfsServer {
            fs: Arc::new(self.fs),
            state: Arc::new(StateManager::new()),
            handle_to_object: Arc::new(RwLock::new(HashMap::new())),
            object_to_handle: Arc::new(RwLock::new(HashMap::new())),
            next_object_id: AtomicU64::new(1),
            id_mapper: self.id_mapper,
        }
    }
}

/// The NFS server.
pub struct NfsServer<F: FileSystem> {
    fs: Arc<F>,
    state: Arc<StateManager>,
    handle_to_object: Arc<RwLock<HashMap<F::Handle, ObjectId>>>,
    object_to_handle: Arc<RwLock<HashMap<ObjectId, F::Handle>>>,
    next_object_id: AtomicU64,
    id_mapper: Arc<dyn IdMapper>,
}

impl<F: FileSystem> NfsServer<F> {
    /// Creates a builder for a new server.
    pub fn builder(fs: F) -> NfsServerBuilder<F> {
        NfsServerBuilder {
            fs,
            id_mapper: Arc::new(NumericIdMapper),
        }
    }

    /// Create a new NFS server with the given filesystem.
    pub fn new(fs: F) -> Self {
        Self::builder(fs).build()
    }

    /// Start listening on the given address.
    pub async fn listen(self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.serve(listener).await
    }

    /// Serve on an already-bound TCP listener. Returns the local address.
    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        let local_addr = listener.local_addr()?;
        info!("NFSv4.1 server listening on {local_addr}");

        let server = Arc::new(self);

        loop {
            let (stream, peer) = listener.accept().await?;
            stream.set_nodelay(true)?;
            debug!("New connection from {peer}");
            let server = server.clone();
            std::mem::drop(tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream).await {
                    debug!("Connection error from {peer}: {e}");
                }
            }));
        }
    }

    fn symlinks(&self) -> Option<&dyn Symlinks<F::Handle>> {
        self.fs.symlinks()
    }

    fn hard_links(&self) -> Option<&dyn HardLinks<F::Handle>> {
        self.fs.hard_links()
    }

    fn named_attrs(&self) -> Option<&dyn Xattrs<F::Handle>> {
        self.fs.xattrs()
    }

    fn syncer(&self) -> Option<&dyn CommitSupport<F::Handle>> {
        self.fs.commit_support()
    }

    fn closer(&self) -> Option<&dyn CloseSupport<F::Handle>> {
        self.fs.close_support()
    }

    fn fh_has_valid_format(fh: &NfsFh4) -> bool {
        fh.0.len() == std::mem::size_of::<u64>()
    }

    fn parse_auth_sys(body: &Bytes) -> Option<AuthSysParams> {
        let mut body = body.clone();
        let params = AuthSysParams::decode(&mut body).ok()?;
        if body.is_empty() { Some(params) } else { None }
    }

    fn validate_rpc_auth(call: &RpcCallHeader) -> Result<(), AuthStat> {
        if call.cred.flavor == AuthFlavor::Sys as u32
            && Self::parse_auth_sys(&call.cred.body).is_none()
        {
            return Err(AuthStat::BadCred);
        }

        if call.verf.flavor == AuthFlavor::Sys as u32
            && Self::parse_auth_sys(&call.verf.body).is_none()
        {
            return Err(AuthStat::BadVerf);
        }

        Ok(())
    }

    fn request_context(cred: &OpaqueAuth) -> RequestContext {
        let auth = match cred.flavor {
            x if x == AuthFlavor::None as u32 => AuthContext::None,
            x if x == AuthFlavor::Sys as u32 => match Self::parse_auth_sys(&cred.body) {
                Some(params) => AuthContext::Sys {
                    uid: params.uid,
                    gid: params.gid,
                    supplemental_gids: params.gids,
                },
                None => AuthContext::Unknown {
                    flavor: cred.flavor,
                },
            },
            flavor => AuthContext::Unknown { flavor },
        };

        RequestContext { auth }
    }

    fn capabilities(&self) -> FsCapabilities {
        self.fs.capabilities()
    }

    fn limits(&self) -> FsLimits {
        self.fs.limits()
    }

    async fn statfs(&self, ctx: &RequestContext) -> NfsResult<FsStats> {
        self.fs.statfs(ctx).await
    }

    async fn getattr(&self, ctx: &RequestContext, id: ObjectId) -> NfsResult<Attrs> {
        let handle = self.resolve_backend_handle(id).await?;
        self.fs.getattr(ctx, &handle).await
    }

    async fn kind_of(&self, ctx: &RequestContext, id: ObjectId) -> NfsResult<ObjectType> {
        self.getattr(ctx, id).await.map(|attrs| attrs.object_type)
    }

    async fn access_for(
        &self,
        ctx: &RequestContext,
        id: ObjectId,
        requested: AccessMask,
    ) -> NfsResult<AccessMask> {
        let handle = self.resolve_backend_handle(id).await?;
        self.fs.access(ctx, &handle, requested).await
    }

    async fn lookup(
        &self,
        ctx: &RequestContext,
        dir_id: ObjectId,
        name: &str,
    ) -> NfsResult<ObjectId> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        let child = self.fs.lookup(ctx, &handle, name).await?;
        Ok(self.register_handle(&child).await)
    }

    async fn lookup_parent(&self, ctx: &RequestContext, dir_id: ObjectId) -> NfsResult<ObjectId> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        let parent = self.fs.parent(ctx, &handle).await?;
        match parent {
            Some(handle) => Ok(self.register_handle(&handle).await),
            None => Err(FsError::NotFound),
        }
    }

    async fn read(
        &self,
        ctx: &RequestContext,
        id: ObjectId,
        offset: u64,
        count: u32,
    ) -> NfsResult<(Bytes, bool)> {
        let handle = self.resolve_backend_handle(id).await?;
        self.fs
            .read(ctx, &handle, offset, count)
            .await
            .map(|res| (res.data, res.eof))
    }

    async fn write(
        &self,
        ctx: &RequestContext,
        id: ObjectId,
        offset: u64,
        data: Bytes,
        requested: WriteStability,
    ) -> NfsResult<WriteResult> {
        let handle = self.resolve_backend_handle(id).await?;
        self.fs.write(ctx, &handle, offset, data, requested).await
    }

    async fn create_file(
        &self,
        ctx: &RequestContext,
        dir_id: ObjectId,
        name: &str,
        attrs: SetAttrs,
    ) -> NfsResult<CreateResult<ObjectId>> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        let created = self
            .fs
            .create(
                ctx,
                &handle,
                name,
                CreateRequest {
                    kind: CreateKind::File,
                    attrs,
                },
            )
            .await?;
        Ok(CreateResult {
            handle: self.register_handle(&created.handle).await,
            attrs: created.attrs,
        })
    }

    async fn create_dir(
        &self,
        ctx: &RequestContext,
        dir_id: ObjectId,
        name: &str,
        attrs: SetAttrs,
    ) -> NfsResult<CreateResult<ObjectId>> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        let created = self
            .fs
            .create(
                ctx,
                &handle,
                name,
                CreateRequest {
                    kind: CreateKind::Directory,
                    attrs,
                },
            )
            .await?;
        Ok(CreateResult {
            handle: self.register_handle(&created.handle).await,
            attrs: created.attrs,
        })
    }

    async fn remove(&self, ctx: &RequestContext, dir_id: ObjectId, name: &str) -> NfsResult<()> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        self.fs.remove(ctx, &handle, name).await
    }

    async fn rename(
        &self,
        ctx: &RequestContext,
        from_dir: ObjectId,
        from_name: &str,
        to_dir: ObjectId,
        to_name: &str,
    ) -> NfsResult<()> {
        let from_handle = self.resolve_backend_handle(from_dir).await?;
        let to_handle = self.resolve_backend_handle(to_dir).await?;
        self.fs
            .rename(ctx, &from_handle, from_name, &to_handle, to_name)
            .await
    }

    async fn readdir(
        &self,
        ctx: &RequestContext,
        dir_id: ObjectId,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> NfsResult<DirPage<ObjectId>> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        let page = self
            .fs
            .readdir(ctx, &handle, cookie, max_entries, with_attrs)
            .await?;
        let mut entries = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            let object_id = self.register_handle(&entry.handle).await;
            entries.push(DirEntry {
                name: entry.name,
                handle: object_id,
                cookie: entry.cookie,
                attrs: entry.attrs,
            });
        }
        Ok(DirPage {
            entries,
            eof: page.eof,
        })
    }

    async fn setattr_real(
        &self,
        ctx: &RequestContext,
        id: ObjectId,
        attrs: &SetAttrs,
    ) -> NfsResult<Attrs> {
        let handle = self.resolve_backend_handle(id).await?;
        self.fs.setattr(ctx, &handle, attrs).await
    }

    fn nfs_access_mask(bits: u32) -> AccessMask {
        let mut out = AccessMask::NONE;
        if bits & ACCESS4_READ != 0 {
            out |= AccessMask::READ;
        }
        if bits & ACCESS4_LOOKUP != 0 {
            out |= AccessMask::LOOKUP;
        }
        if bits & ACCESS4_MODIFY != 0 {
            out |= AccessMask::MODIFY;
        }
        if bits & ACCESS4_EXTEND != 0 {
            out |= AccessMask::EXTEND;
        }
        if bits & ACCESS4_DELETE != 0 {
            out |= AccessMask::DELETE;
        }
        if bits & ACCESS4_EXECUTE != 0 {
            out |= AccessMask::EXECUTE;
        }
        out
    }

    fn access_bits(mask: AccessMask) -> u32 {
        let mut out = 0;
        if mask.intersects(AccessMask::READ) {
            out |= ACCESS4_READ;
        }
        if mask.intersects(AccessMask::LOOKUP) {
            out |= ACCESS4_LOOKUP;
        }
        if mask.intersects(AccessMask::MODIFY) {
            out |= ACCESS4_MODIFY;
        }
        if mask.intersects(AccessMask::EXTEND) {
            out |= ACCESS4_EXTEND;
        }
        if mask.intersects(AccessMask::DELETE) {
            out |= ACCESS4_DELETE;
        }
        if mask.intersects(AccessMask::EXECUTE) {
            out |= ACCESS4_EXECUTE;
        }
        out
    }

    fn committed_how(stability: WriteStability) -> u32 {
        match stability {
            WriteStability::Unstable => UNSTABLE4,
            WriteStability::DataSync => DATA_SYNC4,
            WriteStability::FileSync => FILE_SYNC4,
        }
    }

    fn validate_component_name(&self, name: &str) -> Result<(), NfsStat4> {
        if name.is_empty() {
            return Err(NfsStat4::Inval);
        }
        if name == "." || name == ".." {
            return Err(NfsStat4::Badname);
        }
        if name.contains('/') {
            return Err(NfsStat4::Badchar);
        }
        if name.len() > self.limits().max_name_bytes as usize {
            return Err(NfsStat4::Nametoolong);
        }
        Ok(())
    }

    // ===== Individual operation handlers =====
}

fn xdr_opaque_len(len: usize) -> usize {
    4 + len + xdr_pad(len)
}

fn hex_bytes(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn replay_fingerprint(cred: &OpaqueAuth, payload: &Bytes) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(8 + cred.body.len() + payload.len());
    cred.flavor.encode(&mut out);
    encode_opaque(&mut out, &cred.body);
    out.extend_from_slice(payload);
    out.to_vec()
}

fn xdr_bitmap4_len(bitmap: &Bitmap4) -> usize {
    4 + (bitmap.0.len() * 4)
}

fn xdr_fattr4_len(fattr: &Fattr4) -> usize {
    xdr_bitmap4_len(&fattr.attrmask) + xdr_opaque_len(fattr.attr_vals.len())
}

fn readdir_dir_info_len(entry: &Entry4) -> usize {
    8 + xdr_opaque_len(entry.name.len())
}

fn readdir_entry_len(entry: &Entry4) -> usize {
    8 + xdr_opaque_len(entry.name.len()) + xdr_fattr4_len(&entry.attrs)
}

fn readdir_entry_list_item_len(entry: &Entry4) -> usize {
    4 + readdir_entry_len(entry)
}

fn readdir_resok_len(entries: &[Entry4], _eof: bool) -> usize {
    8 + entries
        .iter()
        .map(readdir_entry_list_item_len)
        .sum::<usize>()
        + 4
        + 4
}

#[cfg(test)]
mod tests;
