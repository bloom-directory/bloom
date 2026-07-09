use bytes::Bytes;
use embednfs_proto::{Bitmap4, ChangeInfo4, Createhow4, Fattr4, NfsFh4};

use crate::attrs;
use crate::fs::{Attrs, FileSystem, FsError, RequestContext, XattrSetMode};
use crate::internal::{ObjectId, ServerFileAttr, ServerFileType, ServerObject};

use super::{NfsResult, NfsServer};

impl<F: FileSystem> NfsServer<F> {
    pub(super) async fn encode_fattr(
        &self,
        request_ctx: &RequestContext,
        attr: &ServerFileAttr,
        request: &Bitmap4,
        fh: &NfsFh4,
    ) -> NfsResult<Fattr4> {
        let stats = self.statfs(request_ctx).await?;
        let limits = self.limits();
        let capabilities = self.capabilities();
        let ctx = attrs::AttrEncodingContext {
            limits: &limits,
            stats: &stats,
            capabilities: &capabilities,
        };
        Ok(attrs::encode_fattr4(attr, request, fh, &ctx))
    }

    fn attr_from_meta(
        meta: crate::session::SynthMeta,
        file_type: ServerFileType,
        size: u64,
        has_named_attrs: bool,
    ) -> ServerFileAttr {
        ServerFileAttr {
            fileid: meta.fileid,
            file_type,
            size,
            used: size,
            mode: meta.mode,
            nlink: meta.nlink,
            owner: meta.owner,
            owner_group: meta.owner_group,
            atime_sec: meta.atime_sec,
            atime_nsec: meta.atime_nsec,
            mtime_sec: meta.mtime_sec,
            mtime_nsec: meta.mtime_nsec,
            ctime_sec: meta.ctime_sec,
            ctime_nsec: meta.ctime_nsec,
            crtime_sec: meta.crtime_sec,
            crtime_nsec: meta.crtime_nsec,
            change_id: meta.change_id,
            rdev_major: 0,
            rdev_minor: 0,
            archive: meta.archive,
            hidden: meta.hidden,
            system: meta.system,
            has_named_attrs,
        }
    }

    pub(super) fn attr_from_backend(&self, attrs: Attrs) -> ServerFileAttr {
        ServerFileAttr {
            fileid: attrs.fileid,
            file_type: ServerFileType::from_attrs(&attrs),
            size: attrs.size,
            used: attrs.space_used,
            mode: attrs.mode,
            nlink: attrs.link_count,
            owner: self.id_mapper.owner(attrs.uid),
            owner_group: self.id_mapper.group(attrs.gid),
            atime_sec: attrs.atime.seconds,
            atime_nsec: attrs.atime.nanos,
            mtime_sec: attrs.mtime.seconds,
            mtime_nsec: attrs.mtime.nanos,
            ctime_sec: attrs.ctime.seconds,
            ctime_nsec: attrs.ctime.nanos,
            crtime_sec: attrs.birthtime.seconds,
            crtime_nsec: attrs.birthtime.nanos,
            change_id: attrs.change,
            rdev_major: 0,
            rdev_minor: 0,
            archive: attrs.archive,
            hidden: attrs.hidden,
            system: attrs.system,
            has_named_attrs: attrs.has_named_attrs,
        }
    }

    pub(super) async fn build_attr(
        &self,
        ctx: &RequestContext,
        object: &ServerObject,
    ) -> NfsResult<ServerFileAttr> {
        match object {
            ServerObject::Fs(id) => {
                let attrs = self.getattr(ctx, *id).await?;
                Ok(self.attr_from_backend(attrs))
            }
            ServerObject::NamedAttrDir(parent) => {
                if self.named_attrs().is_none() {
                    return Err(FsError::Unsupported);
                }
                let count = match self.state.named_attr_count(object).await {
                    Some(count) => count,
                    None => {
                        let count = self.xattr_count(ctx, *parent).await?;
                        self.state
                            .set_named_attr_count(object, ServerFileType::NamedAttrDir, count)
                            .await;
                        count
                    }
                };
                let meta = self
                    .state
                    .ensure_meta(object, ServerFileType::NamedAttrDir)
                    .await;
                Ok(Self::attr_from_meta(
                    meta,
                    ServerFileType::NamedAttrDir,
                    count,
                    false,
                ))
            }
            ServerObject::NamedAttrFile { parent, name } => {
                let parent_handle = self.resolve_backend_handle(*parent).await?;
                let named = self.named_attrs().ok_or(FsError::Unsupported)?;
                let value = named.get_xattr(ctx, &parent_handle, name).await?;
                let meta = self
                    .state
                    .ensure_meta(object, ServerFileType::NamedAttr)
                    .await;
                Ok(Self::attr_from_meta(
                    meta,
                    ServerFileType::NamedAttr,
                    value.len() as u64,
                    false,
                ))
            }
        }
    }

    pub(super) async fn xattr_count(
        &self,
        ctx: &RequestContext,
        parent: ObjectId,
    ) -> NfsResult<u64> {
        let parent_handle = self.resolve_backend_handle(parent).await?;
        let named = self.named_attrs().ok_or(FsError::Unsupported)?;
        Ok(named.list_xattrs(ctx, &parent_handle).await?.len() as u64)
    }

    pub(super) fn create_mode_requires_nonexistence(how: &Createhow4) -> bool {
        matches!(
            how,
            Createhow4::Guarded(_) | Createhow4::Exclusive(_) | Createhow4::Exclusive4_1 { .. }
        )
    }

    pub(super) fn open_set_mode(how: &Createhow4) -> XattrSetMode {
        match how {
            Createhow4::Unchecked(_) => XattrSetMode::CreateOrReplace,
            Createhow4::Guarded(_) | Createhow4::Exclusive(_) | Createhow4::Exclusive4_1 { .. } => {
                XattrSetMode::CreateOnly
            }
        }
    }

    pub(super) async fn xattr_read_slice(
        &self,
        ctx: &RequestContext,
        parent: ObjectId,
        name: &str,
        offset: u64,
        count: u32,
    ) -> NfsResult<(Bytes, bool)> {
        let parent_handle = self.resolve_backend_handle(parent).await?;
        let named = self.named_attrs().ok_or(FsError::Unsupported)?;
        let value = named.get_xattr(ctx, &parent_handle, name).await?;
        let offset = usize::try_from(offset).map_err(|_| FsError::FileTooLarge)?;
        if offset >= value.len() {
            return Ok((Bytes::new(), true));
        }
        let end = offset.saturating_add(count as usize).min(value.len());
        Ok((value.slice(offset..end), end == value.len()))
    }

    pub(super) async fn xattr_resize(
        &self,
        ctx: &RequestContext,
        parent: ObjectId,
        name: &str,
        size: u64,
    ) -> NfsResult<()> {
        let parent_handle = self.resolve_backend_handle(parent).await?;
        let named = self.named_attrs().ok_or(FsError::Unsupported)?;
        let mut value = named.get_xattr(ctx, &parent_handle, name).await?.to_vec();
        let size = usize::try_from(size).map_err(|_| FsError::FileTooLarge)?;
        value.resize(size, 0);
        named
            .set_xattr(
                ctx,
                &parent_handle,
                name,
                Bytes::from(value),
                XattrSetMode::CreateOrReplace,
            )
            .await
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "the xattr buffer is resized locally to cover the validated write range"
    )]
    pub(super) async fn xattr_write(
        &self,
        ctx: &RequestContext,
        parent: ObjectId,
        name: &str,
        offset: u64,
        data: &[u8],
    ) -> NfsResult<u32> {
        let parent_handle = self.resolve_backend_handle(parent).await?;
        let named = self.named_attrs().ok_or(FsError::Unsupported)?;
        let mut value = named.get_xattr(ctx, &parent_handle, name).await?.to_vec();
        let offset = usize::try_from(offset).map_err(|_| FsError::FileTooLarge)?;
        let end = offset
            .checked_add(data.len())
            .ok_or(FsError::FileTooLarge)?;
        if end > value.len() {
            value.resize(end, 0);
        }
        value[offset..end].copy_from_slice(data);
        named
            .set_xattr(
                ctx,
                &parent_handle,
                name,
                Bytes::from(value),
                XattrSetMode::CreateOrReplace,
            )
            .await?;
        Ok(data.len() as u32)
    }

    pub(super) async fn refresh_xattr_summary(
        &self,
        ctx: &RequestContext,
        parent: ObjectId,
    ) -> NfsResult<u64> {
        let count = self.xattr_count(ctx, parent).await?;
        self.state
            .set_named_attr_count(
                &ServerObject::NamedAttrDir(parent),
                ServerFileType::NamedAttrDir,
                count,
            )
            .await;
        Ok(count)
    }

    pub(super) fn synthetic_change_info(before: u64) -> ChangeInfo4 {
        ChangeInfo4 {
            atomic: false,
            before,
            after: before.wrapping_add(1),
        }
    }

    pub(super) async fn mutation_change_info(
        &self,
        ctx: &RequestContext,
        object: &ServerObject,
        before: u64,
    ) -> ChangeInfo4 {
        match self.build_attr(ctx, object).await {
            Ok(attr) => ChangeInfo4 {
                atomic: true,
                before,
                after: attr.change_id,
            },
            Err(_) => Self::synthetic_change_info(before),
        }
    }
}
