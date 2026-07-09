use tracing::{trace, warn};

use embednfs_proto::*;

use crate::attrs;
use crate::fs::{FileSystem, FsError, ObjectType, RequestContext};
use crate::internal::{ServerFileType, ServerObject};

use super::super::{
    NfsServer, readdir_dir_info_len, readdir_entry_list_item_len, readdir_resok_len,
};

impl<F: FileSystem> NfsServer<F> {
    pub(crate) async fn op_create(
        &self,
        request_ctx: &RequestContext,
        args: &CreateArgs4,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, dir_object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Create(status, None, Bitmap4::new()),
        };

        let dir_id = match dir_object {
            ServerObject::Fs(id) => id,
            _ => return NfsResop4::Create(NfsStat4::Notsupp, None, Bitmap4::new()),
        };

        match self.kind_of(request_ctx, dir_id).await {
            Ok(ObjectType::Directory) => {}
            Ok(_) => return NfsResop4::Create(NfsStat4::Notdir, None, Bitmap4::new()),
            Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
        }
        let dir_attr_before = match self.build_attr(request_ctx, &dir_object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
        };

        let set_attrs = match attrs::decode_setattr(&args.createattrs) {
            Ok(attrs) => attrs,
            Err(status) => return NfsResop4::Create(status, None, Bitmap4::new()),
        };
        if let Err(status) = self.validate_component_name(&args.objname) {
            return NfsResop4::Create(status, None, Bitmap4::new());
        }

        let (new_object, _new_type) = match &args.objtype {
            Createtype4::Reg => {
                return NfsResop4::Create(NfsStat4::Badtype, None, Bitmap4::new());
            }
            Createtype4::Dir => match self
                .create_dir(request_ctx, dir_id, &args.objname, set_attrs.clone())
                .await
            {
                Ok(created) => (ServerObject::Fs(created.handle), ServerFileType::Directory),
                Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
            },
            Createtype4::Link(target) => {
                let symlinks = match self.symlinks() {
                    Some(s) => s,
                    None => return NfsResop4::Create(NfsStat4::Notsupp, None, Bitmap4::new()),
                };
                let parent_handle = match self.resolve_backend_handle(dir_id).await {
                    Ok(handle) => handle,
                    Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
                };
                match symlinks
                    .create_symlink(
                        request_ctx,
                        &parent_handle,
                        &args.objname,
                        target,
                        &set_attrs,
                    )
                    .await
                {
                    Ok(created) => {
                        let object_id = self.register_handle(&created.handle).await;
                        (ServerObject::Fs(object_id), ServerFileType::Symlink)
                    }
                    Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
                }
            }
            Createtype4::Unsupported(_) => {
                return NfsResop4::Create(NfsStat4::Badtype, None, Bitmap4::new());
            }
            _ => return NfsResop4::Create(NfsStat4::Notsupp, None, Bitmap4::new()),
        };

        let new_fh = self.state.object_to_fh(&new_object);
        *current_fh = Some(new_fh);

        let cinfo = self
            .mutation_change_info(request_ctx, &dir_object, dir_attr_before.change_id)
            .await;
        NfsResop4::Create(NfsStat4::Ok, Some(cinfo), Bitmap4::new())
    }

    pub(crate) async fn op_link(
        &self,
        request_ctx: &RequestContext,
        args: &LinkArgs4,
        current_fh: &Option<NfsFh4>,
        saved_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, source) = match self.resolve_object(saved_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Link(status, None),
        };
        let (_, target_dir) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Link(status, None),
        };

        let (source_id, dir_id) = match (source, target_dir.clone()) {
            (ServerObject::Fs(source_id), ServerObject::Fs(dir_id)) => (source_id, dir_id),
            _ => return NfsResop4::Link(NfsStat4::Notsupp, None),
        };

        match self.kind_of(request_ctx, dir_id).await {
            Ok(ObjectType::Directory) => {}
            Ok(_) => return NfsResop4::Link(NfsStat4::Notdir, None),
            Err(e) => return NfsResop4::Link(e.to_nfsstat4(), None),
        }
        let dir_attr_before = match self.build_attr(request_ctx, &target_dir).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Link(e.to_nfsstat4(), None),
        };
        if let Err(status) = self.validate_component_name(&args.newname) {
            return NfsResop4::Link(status, None);
        }

        let links = match self.hard_links() {
            Some(links) => links,
            None => return NfsResop4::Link(NfsStat4::Notsupp, None),
        };
        let source_handle = match self.resolve_backend_handle(source_id).await {
            Ok(handle) => handle,
            Err(e) => return NfsResop4::Link(e.to_nfsstat4(), None),
        };
        let dir_handle = match self.resolve_backend_handle(dir_id).await {
            Ok(handle) => handle,
            Err(e) => return NfsResop4::Link(e.to_nfsstat4(), None),
        };
        match links
            .link(request_ctx, &source_handle, &dir_handle, &args.newname)
            .await
        {
            Ok(()) => {
                let cinfo = self
                    .mutation_change_info(request_ctx, &target_dir, dir_attr_before.change_id)
                    .await;
                NfsResop4::Link(NfsStat4::Ok, Some(cinfo))
            }
            Err(e) => NfsResop4::Link(e.to_nfsstat4(), None),
        }
    }

    pub(crate) async fn op_lookup(
        &self,
        request_ctx: &RequestContext,
        args: &LookupArgs4,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Lookup(status),
        };

        let child = match object {
            ServerObject::Fs(dir_id) => match self.kind_of(request_ctx, dir_id).await {
                Ok(ObjectType::Directory) => {
                    if let Err(status) = self.validate_component_name(&args.objname) {
                        return NfsResop4::Lookup(status);
                    }
                    match self.lookup(request_ctx, dir_id, &args.objname).await {
                        Ok(id) => Ok(ServerObject::Fs(id)),
                        Err(e) => Err(e),
                    }
                }
                Ok(_) => Err(FsError::NotDirectory),
                Err(e) => Err(e),
            },
            ServerObject::NamedAttrDir(parent) => {
                let named = match self.named_attrs() {
                    Some(named) => named,
                    None => return NfsResop4::Lookup(NfsStat4::Notsupp),
                };
                let parent_handle = match self.resolve_backend_handle(parent).await {
                    Ok(handle) => handle,
                    Err(e) => return NfsResop4::Lookup(e.to_nfsstat4()),
                };
                match named
                    .get_xattr(request_ctx, &parent_handle, &args.objname)
                    .await
                {
                    Ok(_) => Ok(ServerObject::NamedAttrFile {
                        parent,
                        name: args.objname.clone(),
                    }),
                    Err(e) => Err(e),
                }
            }
            ServerObject::NamedAttrFile { .. } => Err(FsError::NotDirectory),
        };

        match child {
            Ok(child) => {
                *current_fh = Some(self.state.object_to_fh(&child));
                NfsResop4::Lookup(NfsStat4::Ok)
            }
            Err(e) => NfsResop4::Lookup(e.to_nfsstat4()),
        }
    }

    pub(crate) async fn op_lookupp(
        &self,
        request_ctx: &RequestContext,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Lookupp(status),
        };

        let root_object = self.root_object().await;
        let parent = match object {
            ServerObject::Fs(id) if root_object == ServerObject::Fs(id) => Err(FsError::NotFound),
            ServerObject::Fs(id) => match self.lookup_parent(request_ctx, id).await {
                Ok(parent_id) => Ok(ServerObject::Fs(parent_id)),
                Err(e) => Err(e),
            },
            ServerObject::NamedAttrDir(parent) => Ok(ServerObject::Fs(parent)),
            ServerObject::NamedAttrFile { parent, .. } => Ok(ServerObject::NamedAttrDir(parent)),
        };

        match parent {
            Ok(parent) => {
                *current_fh = Some(self.state.object_to_fh(&parent));
                NfsResop4::Lookupp(NfsStat4::Ok)
            }
            Err(e) => NfsResop4::Lookupp(e.to_nfsstat4()),
        }
    }

    pub(crate) async fn op_secinfo_no_name(
        &self,
        request_ctx: &RequestContext,
        style: u32,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::SecInfoNoName(status, vec![]),
        };

        let style_status = match style {
            0 => Ok(()),
            1 => {
                let root_object = self.root_object().await;
                match object {
                    ServerObject::Fs(id) if root_object == ServerObject::Fs(id) => {
                        Err(NfsStat4::Noent)
                    }
                    ServerObject::Fs(id) => self
                        .lookup_parent(request_ctx, id)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_nfsstat4()),
                    ServerObject::NamedAttrDir(_) | ServerObject::NamedAttrFile { .. } => Ok(()),
                }
            }
            _ => Err(NfsStat4::Inval),
        };

        match style_status {
            Ok(()) => {
                *current_fh = None;
                NfsResop4::SecInfoNoName(
                    NfsStat4::Ok,
                    vec![SecinfoEntry4 { flavor: 1 }, SecinfoEntry4 { flavor: 0 }],
                )
            }
            Err(status) => NfsResop4::SecInfoNoName(status, vec![]),
        }
    }

    pub(crate) async fn op_readdir(
        &self,
        request_ctx: &RequestContext,
        args: &ReaddirArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Readdir(status, None),
        };

        let dir_attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
        };
        if !matches!(
            dir_attr.file_type,
            ServerFileType::Directory | ServerFileType::NamedAttrDir
        ) {
            return NfsResop4::Readdir(NfsStat4::Notdir, None);
        }
        if matches!(args.cookie, 1 | 2) {
            return NfsResop4::Readdir(NfsStat4::BadCookie, None);
        }
        if args.maxcount == 0 {
            return NfsResop4::Readdir(NfsStat4::Toosmall, None);
        }
        if args.attr_request.is_set(FATTR4_TIME_ACCESS_SET)
            || args.attr_request.is_set(FATTR4_TIME_MODIFY_SET)
        {
            return NfsResop4::Readdir(NfsStat4::Inval, None);
        }
        let cookieverf = dir_attr.change_id.to_be_bytes();

        if args.cookie != 0 && args.cookieverf != cookieverf {
            return NfsResop4::Readdir(NfsStat4::NotSame, None);
        }

        let with_attrs = args.attr_request.0.iter().any(|word| *word != 0);
        let backend_max_entries = (args.maxcount / 128).max(1);
        let (entries, backend_eof) = match object.clone() {
            ServerObject::Fs(dir_id) => match self
                .readdir(
                    request_ctx,
                    dir_id,
                    args.cookie,
                    backend_max_entries,
                    with_attrs,
                )
                .await
            {
                Ok(page) => (
                    page.entries
                        .into_iter()
                        .map(|entry| {
                            (
                                entry.name,
                                ServerObject::Fs(entry.handle),
                                entry.cookie,
                                entry.attrs,
                            )
                        })
                        .collect::<Vec<_>>(),
                    page.eof,
                ),
                Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
            },
            ServerObject::NamedAttrDir(parent) => {
                let named = match self.named_attrs() {
                    Some(named) => named,
                    None => return NfsResop4::Readdir(NfsStat4::Notsupp, None),
                };
                let parent_handle = match self.resolve_backend_handle(parent).await {
                    Ok(handle) => handle,
                    Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
                };
                let names = match named.list_xattrs(request_ctx, &parent_handle).await {
                    Ok(names) => names,
                    Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
                };
                let start = if args.cookie == 0 {
                    0
                } else {
                    args.cookie.saturating_sub(2) as usize
                };
                (
                    names
                        .into_iter()
                        .skip(start)
                        .map(|name| {
                            let object = ServerObject::NamedAttrFile {
                                parent,
                                name: name.clone(),
                            };
                            let cookie = start as u64 + 3;
                            (name, object, cookie, None)
                        })
                        .enumerate()
                        .map(|(idx, (name, object, base_cookie, attrs))| {
                            (name, object, base_cookie + idx as u64, attrs)
                        })
                        .collect::<Vec<_>>(),
                    true,
                )
            }
            ServerObject::NamedAttrFile { .. } => {
                return NfsResop4::Readdir(NfsStat4::Notdir, None);
            }
        };

        let maxcount_limit = args.maxcount as usize;
        let dircount_limit = if args.dircount == 0 {
            usize::MAX
        } else {
            args.dircount as usize
        };

        let base_resok_len = readdir_resok_len(&[], false);
        if base_resok_len > maxcount_limit {
            return NfsResop4::Readdir(NfsStat4::Toosmall, None);
        }

        let stats = match self.statfs(request_ctx).await {
            Ok(stats) => stats,
            Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
        };
        let limits = self.limits();
        let caps = self.capabilities();
        let encode_ctx = attrs::AttrEncodingContext {
            limits: &limits,
            stats: &stats,
            capabilities: &caps,
        };

        let mut result_entries = Vec::with_capacity(entries.len().min(64));
        let mut dir_bytes = 0usize;
        let mut total_resok_bytes = base_resok_len;

        for (name, object, cookie, inline_attrs) in &entries {
            let entry_attr = match inline_attrs.clone() {
                Some(attrs) => self.attr_from_backend(attrs),
                None => match self.build_attr(request_ctx, object).await {
                    Ok(attr) => attr,
                    Err(e) => {
                        trace!("readdir: skipping entry {name:?}: {e:?}");
                        continue;
                    }
                },
            };
            let entry_fh = self.state.object_to_fh(object);
            let result_entry = Entry4 {
                cookie: *cookie,
                name: name.clone(),
                attrs: attrs::encode_fattr4(
                    &entry_attr,
                    &args.attr_request,
                    &entry_fh,
                    &encode_ctx,
                ),
            };
            let dir_entry_size = readdir_dir_info_len(&result_entry);
            let entry_total = readdir_entry_list_item_len(&result_entry);

            let exceeds_dircount = dir_bytes + dir_entry_size > dircount_limit;
            let exceeds_maxcount = total_resok_bytes + entry_total > maxcount_limit;
            if !result_entries.is_empty() && (exceeds_dircount || exceeds_maxcount) {
                break;
            }

            if result_entries.is_empty() && exceeds_maxcount {
                return NfsResop4::Readdir(NfsStat4::Toosmall, None);
            }

            dir_bytes += dir_entry_size;
            total_resok_bytes += entry_total;
            result_entries.push(result_entry);
        }

        let eof = backend_eof && result_entries.len() == entries.len();
        NfsResop4::Readdir(
            NfsStat4::Ok,
            Some(ReaddirRes4 {
                cookieverf,
                entries: result_entries,
                eof,
            }),
        )
    }

    pub(crate) async fn op_remove(
        &self,
        request_ctx: &RequestContext,
        args: &RemoveArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, dir_object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Remove(status, None),
        };

        let dir_attr_before = match self.build_attr(request_ctx, &dir_object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Remove(e.to_nfsstat4(), None),
        };
        if let Err(status) = self.validate_component_name(&args.target) {
            return NfsResop4::Remove(status, None);
        }

        let status = match dir_object.clone() {
            ServerObject::Fs(dir_id) => {
                match self.remove(request_ctx, dir_id, &args.target).await {
                    Ok(()) => NfsStat4::Ok,
                    Err(e) => e.to_nfsstat4(),
                }
            }
            ServerObject::NamedAttrDir(parent) => {
                let named = match self.named_attrs() {
                    Some(named) => named,
                    None => return NfsResop4::Remove(NfsStat4::Notsupp, None),
                };
                let parent_handle = match self.resolve_backend_handle(parent).await {
                    Ok(handle) => handle,
                    Err(e) => return NfsResop4::Remove(e.to_nfsstat4(), None),
                };
                match named
                    .remove_xattr(request_ctx, &parent_handle, &args.target)
                    .await
                {
                    Ok(()) => {
                        if let Err(e) = self.refresh_xattr_summary(request_ctx, parent).await {
                            warn!("xattr summary refresh failed: {e:?}");
                        }
                        self.state
                            .touch_metadata(&dir_object, ServerFileType::NamedAttrDir)
                            .await;
                        self.parent_change_after_xattr_mutation(request_ctx, parent)
                            .await;
                        NfsStat4::Ok
                    }
                    Err(e) => e.to_nfsstat4(),
                }
            }
            ServerObject::NamedAttrFile { .. } => NfsStat4::Notdir,
        };

        if status == NfsStat4::Ok {
            let cinfo = self
                .mutation_change_info(request_ctx, &dir_object, dir_attr_before.change_id)
                .await;
            NfsResop4::Remove(NfsStat4::Ok, Some(cinfo))
        } else {
            NfsResop4::Remove(status, None)
        }
    }

    pub(crate) async fn op_rename(
        &self,
        request_ctx: &RequestContext,
        args: &RenameArgs4,
        current_fh: &Option<NfsFh4>,
        saved_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, src_object) = match self.resolve_object(saved_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Rename(status, None, None),
        };
        let (_, tgt_object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Rename(status, None, None),
        };

        let (src_dir_id, tgt_dir_id) = match (src_object.clone(), tgt_object.clone()) {
            (ServerObject::Fs(src_dir_id), ServerObject::Fs(tgt_dir_id)) => {
                (src_dir_id, tgt_dir_id)
            }
            _ => return NfsResop4::Rename(NfsStat4::Notsupp, None, None),
        };

        let src_before = match self.build_attr(request_ctx, &src_object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Rename(e.to_nfsstat4(), None, None),
        };
        let tgt_before = match self.build_attr(request_ctx, &tgt_object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Rename(e.to_nfsstat4(), None, None),
        };

        match self
            .rename(
                request_ctx,
                src_dir_id,
                &args.oldname,
                tgt_dir_id,
                &args.newname,
            )
            .await
        {
            Ok(()) => {
                let src_cinfo = self
                    .mutation_change_info(request_ctx, &src_object, src_before.change_id)
                    .await;
                let tgt_cinfo = self
                    .mutation_change_info(request_ctx, &tgt_object, tgt_before.change_id)
                    .await;
                NfsResop4::Rename(NfsStat4::Ok, Some(src_cinfo), Some(tgt_cinfo))
            }
            Err(e) => NfsResop4::Rename(e.to_nfsstat4(), None, None),
        }
    }

    pub(crate) async fn op_openattr(
        &self,
        _request_ctx: &RequestContext,
        _args: &OpenAttrArgs4,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        if self.named_attrs().is_none() {
            return NfsResop4::OpenAttr(NfsStat4::Notsupp);
        }
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::OpenAttr(status),
        };
        let attrdir = match object {
            ServerObject::Fs(id) => ServerObject::NamedAttrDir(id),
            _ => return NfsResop4::OpenAttr(NfsStat4::Inval),
        };
        let _ = self
            .state
            .ensure_meta(&attrdir, ServerFileType::NamedAttrDir)
            .await;
        *current_fh = Some(self.state.object_to_fh(&attrdir));
        NfsResop4::OpenAttr(NfsStat4::Ok)
    }
}
