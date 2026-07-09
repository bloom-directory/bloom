use bytes::Bytes;
use tracing::warn;

use embednfs_proto::*;

use crate::attrs;
use crate::fs::{FileSystem, FsError, ObjectType, RequestContext, WriteResult, WriteStability};
use crate::internal::{ServerFileType, ServerObject};
use crate::session::{CurrentStateidMode, ResolvedStateid};

use super::super::NfsServer;

#[derive(Clone, Copy)]
pub(super) struct IoStateContext {
    pub current_stateid: Option<Stateid4>,
    pub sequence_clientid: Option<Clientid4>,
    pub is_write: bool,
    pub offset: u64,
    pub length: u64,
}

impl<F: FileSystem> NfsServer<F> {
    async fn resolve_io_stateid(
        &self,
        object: &ServerObject,
        stateid: &Stateid4,
        current_stateid: Option<Stateid4>,
        sequence_clientid: Option<Clientid4>,
    ) -> Result<ResolvedStateid, NfsStat4> {
        let clientid = sequence_clientid.ok_or(NfsStat4::BadStateid)?;
        let resolved = self
            .state
            .resolve_stateid(
                clientid,
                stateid,
                current_stateid,
                CurrentStateidMode::ZeroSeqid,
            )
            .await?;
        match &resolved {
            ResolvedStateid::Open(open) if open.object != *object => Err(NfsStat4::BadStateid),
            ResolvedStateid::Lock(lock) if lock.object != *object => Err(NfsStat4::BadStateid),
            _ => Ok(resolved),
        }
    }

    pub(super) async fn validate_io_stateid(
        &self,
        object: &ServerObject,
        stateid: &Stateid4,
        io: IoStateContext,
    ) -> Result<(), NfsStat4> {
        let resolved = self
            .resolve_io_stateid(object, stateid, io.current_stateid, io.sequence_clientid)
            .await?;
        let access = if io.is_write {
            OPEN4_SHARE_ACCESS_WRITE
        } else {
            OPEN4_SHARE_ACCESS_READ
        };

        let (ignore_open, lock_owner, ignore_lock) = match &resolved {
            ResolvedStateid::Anonymous | ResolvedStateid::Bypass => (None, None, None),
            ResolvedStateid::Open(open) => {
                let share_access = self.state.share_access_mode(open.share_access);
                if io.is_write && (share_access & OPEN4_SHARE_ACCESS_WRITE) == 0 {
                    return Err(NfsStat4::Openmode);
                }
                (Some(open.other), None, None)
            }
            ResolvedStateid::Lock(lock) => {
                let share_access = self.state.share_access_mode(lock.open_state.share_access);
                if io.is_write && (share_access & OPEN4_SHARE_ACCESS_WRITE) == 0 {
                    return Err(NfsStat4::Openmode);
                }
                (
                    Some(lock.open_state.other),
                    Some(&lock.owner),
                    Some(lock.other),
                )
            }
        };

        if self
            .state
            .has_conflicting_share_deny(object, access, ignore_open)
            .await
        {
            return Err(NfsStat4::Locked);
        }
        if self
            .state
            .has_conflicting_io_lock(
                object,
                lock_owner,
                io.is_write,
                io.offset,
                io.length,
                ignore_lock,
            )
            .await
        {
            return Err(NfsStat4::Locked);
        }

        Ok(())
    }

    fn requested_write_stability(stable: u32) -> Result<WriteStability, NfsStat4> {
        match stable {
            UNSTABLE4 => Ok(WriteStability::Unstable),
            DATA_SYNC4 => Ok(WriteStability::DataSync),
            FILE_SYNC4 => Ok(WriteStability::FileSync),
            _ => Err(NfsStat4::Inval),
        }
    }

    fn stability_at_least(actual: WriteStability, requested: WriteStability) -> bool {
        let rank = |stability| match stability {
            WriteStability::Unstable => 0,
            WriteStability::DataSync => 1,
            WriteStability::FileSync => 2,
        };
        rank(actual) >= rank(requested)
    }

    pub(crate) async fn op_close(
        &self,
        request_ctx: &RequestContext,
        args: &CloseArgs4,
        current_fh: &Option<NfsFh4>,
        current_stateid: Option<Stateid4>,
        sequence_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Close(status, Stateid4::default()),
        };

        let stateid = match self.state.normalize_stateid(
            &args.open_stateid,
            current_stateid,
            CurrentStateidMode::PreserveSeqid,
        ) {
            Ok(crate::session::NormalizedStateid::Concrete(stateid)) => stateid,
            Ok(
                crate::session::NormalizedStateid::Anonymous
                | crate::session::NormalizedStateid::Bypass,
            ) => {
                return NfsResop4::Close(NfsStat4::BadStateid, Stateid4::default());
            }
            Err(status) => return NfsResop4::Close(status, Stateid4::default()),
        };

        let clientid = match sequence_clientid {
            Some(clientid) => clientid,
            None => return NfsResop4::Close(NfsStat4::BadStateid, Stateid4::default()),
        };
        match self
            .state
            .resolve_stateid(clientid, &stateid, None, CurrentStateidMode::PreserveSeqid)
            .await
        {
            Ok(ResolvedStateid::Open(open)) if open.object == object => {}
            Ok(_) => return NfsResop4::Close(NfsStat4::BadStateid, Stateid4::default()),
            Err(status) => return NfsResop4::Close(status, Stateid4::default()),
        }

        let close_error = if let ServerObject::Fs(id) = object
            && let Some(closer) = self.closer()
        {
            let handle = match self.resolve_backend_handle(id).await {
                Ok(handle) => handle,
                Err(e) => {
                    return NfsResop4::Close(e.to_nfsstat4(), Stateid4::default());
                }
            };
            closer
                .close(request_ctx, &handle)
                .await
                .err()
                .map(|e| e.to_nfsstat4())
        } else {
            None
        };

        match self.state.close_state(&stateid).await {
            Ok(stateid) => match close_error {
                Some(status) => NfsResop4::Close(status, Stateid4::default()),
                None => NfsResop4::Close(NfsStat4::Ok, stateid),
            },
            Err(status) => NfsResop4::Close(status, Stateid4::default()),
        }
    }

    pub(crate) async fn op_commit(
        &self,
        request_ctx: &RequestContext,
        args: &CommitArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Commit(status, [0u8; 8]),
        };

        let status = match object {
            ServerObject::Fs(id) => {
                // RFC 8881's COMMIT error table allows NFS4ERR_ISDIR for directories.
                match self.getattr(request_ctx, id).await {
                    Ok(attrs) if attrs.object_type == ObjectType::Directory => {
                        return NfsResop4::Commit(NfsStat4::Isdir, [0u8; 8]);
                    }
                    Err(e) => return NfsResop4::Commit(e.to_nfsstat4(), [0u8; 8]),
                    _ => {}
                }
                if let Some(syncer) = self.syncer() {
                    let handle = match self.resolve_backend_handle(id).await {
                        Ok(handle) => handle,
                        Err(e) => return NfsResop4::Commit(e.to_nfsstat4(), [0u8; 8]),
                    };
                    syncer
                        .commit(request_ctx, &handle, args.offset, args.count)
                        .await
                        .map_err(|e| e.to_nfsstat4())
                } else {
                    Ok(())
                }
            }
            ServerObject::NamedAttrFile { .. } => Ok(()),
            ServerObject::NamedAttrDir(_) => Err(NfsStat4::Isdir),
        };

        match status {
            Ok(()) => NfsResop4::Commit(NfsStat4::Ok, self.state.write_verifier),
            Err(status) => NfsResop4::Commit(status, [0u8; 8]),
        }
    }

    pub(crate) async fn op_open(
        &self,
        request_ctx: &RequestContext,
        args: &OpenArgs4,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, container) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Open(status, None),
        };
        let before_attr = self.build_attr(request_ctx, &container).await;

        let mut created = false;
        let mut created_before_change = None;
        let object = match (&container, &args.claim) {
            (ServerObject::Fs(dir_id), OpenClaim4::Null(name)) => {
                if let Err(status) = self.validate_component_name(name) {
                    return NfsResop4::Open(status, None);
                }
                match self.kind_of(request_ctx, *dir_id).await {
                    Ok(ObjectType::Directory) => {}
                    Ok(_) => return NfsResop4::Open(NfsStat4::Notdir, None),
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                }

                match self.lookup(request_ctx, *dir_id, name).await {
                    Ok(id) => {
                        if let Openflag4::Create(how) = &args.openhow
                            && Self::create_mode_requires_nonexistence(how)
                        {
                            return NfsResop4::Open(NfsStat4::Exist, None);
                        }
                        ServerObject::Fs(id)
                    }
                    Err(FsError::NotFound) => match &args.openhow {
                        Openflag4::Create(how) => {
                            let before_change = match &before_attr {
                                Ok(attr) => attr.change_id,
                                Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                            };
                            let set_attrs = match how {
                                Createhow4::Unchecked(fa) | Createhow4::Guarded(fa) => {
                                    match attrs::decode_setattr(fa) {
                                        Ok(attrs) => attrs,
                                        Err(status) => return NfsResop4::Open(status, None),
                                    }
                                }
                                Createhow4::Exclusive4_1 { attrs: fa, .. } => {
                                    match attrs::decode_setattr(fa) {
                                        Ok(attrs) => attrs,
                                        Err(status) => return NfsResop4::Open(status, None),
                                    }
                                }
                                Createhow4::Exclusive(_) => Default::default(),
                            };
                            match self
                                .create_file(request_ctx, *dir_id, name, set_attrs)
                                .await
                            {
                                Ok(created_file) => {
                                    created = true;
                                    created_before_change = Some(before_change);
                                    ServerObject::Fs(created_file.handle)
                                }
                                Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                            }
                        }
                        Openflag4::NoCreate => return NfsResop4::Open(NfsStat4::Noent, None),
                    },
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                }
            }
            (ServerObject::NamedAttrDir(parent), OpenClaim4::Null(name)) => {
                let named = match self.named_attrs() {
                    Some(named) => named,
                    None => return NfsResop4::Open(NfsStat4::Notsupp, None),
                };
                let parent_handle = match self.resolve_backend_handle(*parent).await {
                    Ok(handle) => handle,
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                };
                match named.get_xattr(request_ctx, &parent_handle, name).await {
                    Ok(_) => {
                        if let Openflag4::Create(how) = &args.openhow
                            && Self::create_mode_requires_nonexistence(how)
                        {
                            return NfsResop4::Open(NfsStat4::Exist, None);
                        }
                        ServerObject::NamedAttrFile {
                            parent: *parent,
                            name: name.clone(),
                        }
                    }
                    Err(FsError::NotFound) => match &args.openhow {
                        Openflag4::Create(how) => {
                            let before_change = match &before_attr {
                                Ok(attr) => attr.change_id,
                                Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                            };
                            created = true;
                            created_before_change = Some(before_change);
                            let object = ServerObject::NamedAttrFile {
                                parent: *parent,
                                name: name.clone(),
                            };
                            let set_attrs = match how {
                                Createhow4::Unchecked(fa) | Createhow4::Guarded(fa) => {
                                    match attrs::decode_setattr(fa) {
                                        Ok(attrs) => attrs,
                                        Err(status) => return NfsResop4::Open(status, None),
                                    }
                                }
                                Createhow4::Exclusive4_1 { attrs: fa, .. } => {
                                    match attrs::decode_setattr(fa) {
                                        Ok(attrs) => attrs,
                                        Err(status) => return NfsResop4::Open(status, None),
                                    }
                                }
                                Createhow4::Exclusive(_) => Default::default(),
                            };
                            let mut initial = vec![];
                            if let Some(size) = set_attrs.size {
                                initial.resize(size as usize, 0);
                            }
                            if let Err(e) = named
                                .set_xattr(
                                    request_ctx,
                                    &parent_handle,
                                    name,
                                    Bytes::from(initial),
                                    Self::open_set_mode(how),
                                )
                                .await
                            {
                                return NfsResop4::Open(e.to_nfsstat4(), None);
                            }
                            if let Err(e) = self.refresh_xattr_summary(request_ctx, *parent).await {
                                warn!("xattr summary refresh failed: {e:?}");
                            }
                            self.state
                                .apply_setattr(&object, ServerFileType::NamedAttr, &set_attrs)
                                .await;
                            self.state
                                .touch_metadata(&container, ServerFileType::NamedAttrDir)
                                .await;
                            self.parent_change_after_xattr_mutation(request_ctx, *parent)
                                .await;
                            object
                        }
                        Openflag4::NoCreate => return NfsResop4::Open(NfsStat4::Noent, None),
                    },
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                }
            }
            (_, OpenClaim4::Fh)
            | (_, OpenClaim4::Previous(_))
            | (_, OpenClaim4::DelegCurFh(_))
            | (_, OpenClaim4::DelegPrevFh) => container.clone(),
            _ => return NfsResop4::Open(NfsStat4::Notsupp, None),
        };

        let opened_attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
        };
        if matches!(
            opened_attr.file_type,
            ServerFileType::Directory | ServerFileType::NamedAttrDir
        ) {
            return NfsResop4::Open(NfsStat4::Isdir, None);
        }

        if !created && let Err(e) = &before_attr {
            return NfsResop4::Open(e.to_nfsstat4(), None);
        }

        let stateid = match self
            .state
            .create_open_state(
                object.clone(),
                args.owner.clientid,
                args.share_access,
                args.share_deny,
            )
            .await
        {
            Ok(stateid) => stateid,
            Err(status) => return NfsResop4::Open(status, None),
        };

        *current_fh = Some(self.state.object_to_fh(&object));

        let cinfo = if created {
            let before_change = match created_before_change {
                Some(before_change) => before_change,
                None => return NfsResop4::Open(NfsStat4::Serverfault, None),
            };
            self.mutation_change_info(request_ctx, &container, before_change)
                .await
        } else {
            let change = match &before_attr {
                Ok(attr) => attr.change_id,
                Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
            };
            ChangeInfo4 {
                atomic: true,
                before: change,
                after: change,
            }
        };

        NfsResop4::Open(
            NfsStat4::Ok,
            Some(OpenRes4 {
                stateid,
                cinfo,
                rflags: OPEN4_RESULT_LOCKTYPE_POSIX,
                attrset: Bitmap4::new(),
                delegation: OpenDelegation4::None,
            }),
        )
    }

    pub(crate) async fn op_read(
        &self,
        request_ctx: &RequestContext,
        args: &ReadArgs4,
        current_fh: &Option<NfsFh4>,
        current_stateid: Option<Stateid4>,
        sequence_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Read(status, None),
        };

        if let Err(status) = self
            .validate_io_stateid(
                &object,
                &args.stateid,
                IoStateContext {
                    current_stateid,
                    sequence_clientid,
                    is_write: false,
                    offset: args.offset,
                    length: args.count as u64,
                },
            )
            .await
        {
            return NfsResop4::Read(status, None);
        }

        let result = match object {
            ServerObject::Fs(id) => {
                // RFC 8881 §18.22.3: READ on a directory must return NFS4ERR_ISDIR.
                match self.getattr(request_ctx, id).await {
                    Ok(attrs) if attrs.object_type == ObjectType::Directory => {
                        return NfsResop4::Read(NfsStat4::Isdir, None);
                    }
                    Err(e) => return NfsResop4::Read(e.to_nfsstat4(), None),
                    _ => {}
                }
                self.read(request_ctx, id, args.offset, args.count).await
            }
            ServerObject::NamedAttrFile { parent, name } => {
                self.xattr_read_slice(request_ctx, parent, &name, args.offset, args.count)
                    .await
            }
            ServerObject::NamedAttrDir(_) => Err(FsError::IsDirectory),
        };

        match result {
            Ok((data, eof)) => NfsResop4::Read(NfsStat4::Ok, Some(ReadRes4 { eof, data })),
            Err(e) => NfsResop4::Read(e.to_nfsstat4(), None),
        }
    }

    pub(crate) async fn op_readlink(
        &self,
        request_ctx: &RequestContext,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Readlink(status, None),
        };

        let result = match object {
            ServerObject::Fs(id) => match self.symlinks() {
                Some(symlinks) => {
                    let handle = match self.resolve_backend_handle(id).await {
                        Ok(handle) => handle,
                        Err(e) => return NfsResop4::Readlink(e.to_nfsstat4(), None),
                    };
                    symlinks.readlink(request_ctx, &handle).await
                }
                None => Err(FsError::Unsupported),
            },
            _ => Err(FsError::InvalidInput),
        };

        match result {
            Ok(target) => NfsResop4::Readlink(NfsStat4::Ok, Some(target)),
            Err(e) => NfsResop4::Readlink(e.to_nfsstat4(), None),
        }
    }

    pub(crate) async fn op_write(
        &self,
        request_ctx: &RequestContext,
        args: &WriteArgs4,
        current_fh: &Option<NfsFh4>,
        current_stateid: Option<Stateid4>,
        sequence_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Write(status, None),
        };

        if let Err(status) = self
            .validate_io_stateid(
                &object,
                &args.stateid,
                IoStateContext {
                    current_stateid,
                    sequence_clientid,
                    is_write: true,
                    offset: args.offset,
                    length: args.data.len() as u64,
                },
            )
            .await
        {
            return NfsResop4::Write(status, None);
        }

        let requested_stability = match Self::requested_write_stability(args.stable) {
            Ok(stability) => stability,
            Err(status) => return NfsResop4::Write(status, None),
        };

        let file_type = match &object {
            ServerObject::Fs(id) => match self.getattr(request_ctx, *id).await {
                Ok(attrs) => {
                    let file_type = ServerFileType::from_attrs(&attrs);
                    if file_type == ServerFileType::Directory {
                        return NfsResop4::Write(NfsStat4::Isdir, None);
                    }
                    file_type
                }
                Err(e) => return NfsResop4::Write(e.to_nfsstat4(), None),
            },
            ServerObject::NamedAttrFile { .. } => ServerFileType::NamedAttr,
            ServerObject::NamedAttrDir(_) => return NfsResop4::Write(NfsStat4::Isdir, None),
        };

        let result = match object.clone() {
            ServerObject::Fs(id) => {
                self.write(
                    request_ctx,
                    id,
                    args.offset,
                    args.data.clone(),
                    requested_stability,
                )
                .await
            }
            ServerObject::NamedAttrFile { parent, name } => self
                .xattr_write(request_ctx, parent, &name, args.offset, &args.data)
                .await
                .map(|written| WriteResult {
                    written,
                    stability: WriteStability::FileSync,
                }),
            ServerObject::NamedAttrDir(_) => Err(FsError::IsDirectory),
        };

        match result {
            Ok(result) => {
                if !Self::stability_at_least(result.stability, requested_stability) {
                    return NfsResop4::Write(NfsStat4::Serverfault, None);
                }
                if !matches!(object, ServerObject::Fs(_)) {
                    self.state.touch_data(&object, file_type).await;
                }
                NfsResop4::Write(
                    NfsStat4::Ok,
                    Some(WriteRes4 {
                        count: result.written,
                        committed: Self::committed_how(result.stability),
                        writeverf: self.state.write_verifier,
                    }),
                )
            }
            Err(e) => NfsResop4::Write(e.to_nfsstat4(), None),
        }
    }

    pub(crate) async fn op_open_downgrade(
        &self,
        args: &OpenDowngradeArgs4,
        current_stateid: Option<Stateid4>,
        sequence_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let clientid = match sequence_clientid {
            Some(clientid) => clientid,
            None => return NfsResop4::OpenDowngrade(NfsStat4::BadStateid, None),
        };
        let stateid = match self.state.normalize_stateid(
            &args.open_stateid,
            current_stateid,
            CurrentStateidMode::PreserveSeqid,
        ) {
            Ok(crate::session::NormalizedStateid::Concrete(stateid)) => stateid,
            Ok(
                crate::session::NormalizedStateid::Anonymous
                | crate::session::NormalizedStateid::Bypass,
            ) => {
                return NfsResop4::OpenDowngrade(NfsStat4::BadStateid, None);
            }
            Err(status) => return NfsResop4::OpenDowngrade(status, None),
        };

        match self
            .state
            .resolve_stateid(clientid, &stateid, None, CurrentStateidMode::PreserveSeqid)
            .await
        {
            Ok(ResolvedStateid::Open(_)) => {}
            Ok(_) => return NfsResop4::OpenDowngrade(NfsStat4::BadStateid, None),
            Err(status) => return NfsResop4::OpenDowngrade(status, None),
        }

        match self
            .state
            .open_downgrade(&stateid, args.share_access, args.share_deny)
            .await
        {
            Ok(stateid) => NfsResop4::OpenDowngrade(NfsStat4::Ok, Some(stateid)),
            Err(status) => NfsResop4::OpenDowngrade(status, None),
        }
    }
}
