use embednfs_proto::*;

use crate::fs::{FileSystem, RequestContext};
use crate::internal::ServerFileType;
use crate::session::{CurrentStateidMode, NormalizedStateid, ResolvedStateid};

use super::super::NfsServer;

impl<F: FileSystem> NfsServer<F> {
    pub(crate) async fn op_lock(
        &self,
        request_ctx: &RequestContext,
        args: &LockArgs4,
        current_fh: &Option<NfsFh4>,
        current_stateid: Option<Stateid4>,
        sequence_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Lock(status, None, None),
        };

        let object_attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Lock(e.to_nfsstat4(), None, None),
        };
        if matches!(
            object_attr.file_type,
            ServerFileType::Directory | ServerFileType::NamedAttrDir
        ) {
            return NfsResop4::Lock(NfsStat4::Isdir, None, None);
        }
        if let Err(status) = self.state.validate_lock_bounds(args.offset, args.length) {
            return NfsResop4::Lock(status, None, None);
        }

        let clientid = match sequence_clientid {
            Some(clientid) => clientid,
            None => return NfsResop4::Lock(NfsStat4::BadStateid, None, None),
        };

        match &args.locker {
            Locker4::NewLockOwner(new_owner) => {
                let open_stateid = match self.state.normalize_stateid(
                    &new_owner.open_stateid,
                    current_stateid,
                    CurrentStateidMode::ZeroSeqid,
                ) {
                    Ok(NormalizedStateid::Concrete(stateid)) => stateid,
                    Ok(NormalizedStateid::Anonymous | NormalizedStateid::Bypass) => {
                        return NfsResop4::Lock(NfsStat4::BadStateid, None, None);
                    }
                    Err(status) => return NfsResop4::Lock(status, None, None),
                };
                match self
                    .state
                    .resolve_stateid(clientid, &open_stateid, None, CurrentStateidMode::ZeroSeqid)
                    .await
                {
                    Ok(ResolvedStateid::Open(open)) if open.object == object => {}
                    Ok(_) => return NfsResop4::Lock(NfsStat4::Openmode, None, None),
                    Err(status) => return NfsResop4::Lock(status, None, None),
                }
                if let Some(denied) = self
                    .state
                    .find_lock_conflict(
                        &object,
                        &new_owner.lock_owner,
                        args.locktype,
                        args.offset,
                        args.length,
                        None,
                    )
                    .await
                {
                    return NfsResop4::Lock(NfsStat4::Denied, None, Some(denied));
                }
                match self
                    .state
                    .create_lock_state(
                        &open_stateid,
                        &new_owner.lock_owner,
                        object,
                        args.locktype,
                        args.offset,
                        args.length,
                    )
                    .await
                {
                    Ok(stateid) => NfsResop4::Lock(NfsStat4::Ok, Some(stateid), None),
                    Err(status) => NfsResop4::Lock(status, None, None),
                }
            }
            Locker4::ExistingLockOwner(existing) => {
                let lock_stateid = match self.state.normalize_stateid(
                    &existing.lock_stateid,
                    current_stateid,
                    CurrentStateidMode::ZeroSeqid,
                ) {
                    Ok(NormalizedStateid::Concrete(stateid)) => stateid,
                    Ok(NormalizedStateid::Anonymous | NormalizedStateid::Bypass) => {
                        return NfsResop4::Lock(NfsStat4::BadStateid, None, None);
                    }
                    Err(status) => return NfsResop4::Lock(status, None, None),
                };
                let (_lock_object, owner) = match self
                    .state
                    .resolve_stateid(clientid, &lock_stateid, None, CurrentStateidMode::ZeroSeqid)
                    .await
                {
                    Ok(ResolvedStateid::Lock(lock)) if lock.object == object => {
                        (lock.object, lock.owner)
                    }
                    Ok(_) => return NfsResop4::Lock(NfsStat4::BadStateid, None, None),
                    Err(status) => return NfsResop4::Lock(status, None, None),
                };
                if let Some(denied) = self
                    .state
                    .find_lock_conflict(
                        &object,
                        &owner,
                        args.locktype,
                        args.offset,
                        args.length,
                        Some(&lock_stateid),
                    )
                    .await
                {
                    return NfsResop4::Lock(NfsStat4::Denied, None, Some(denied));
                }
                match self
                    .state
                    .update_lock_state(&lock_stateid, args.locktype, args.offset, args.length)
                    .await
                {
                    Ok(stateid) => NfsResop4::Lock(NfsStat4::Ok, Some(stateid), None),
                    Err(status) => NfsResop4::Lock(status, None, None),
                }
            }
        }
    }

    pub(crate) async fn op_lockt(
        &self,
        request_ctx: &RequestContext,
        args: &LocktArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Lockt(status, None),
        };
        let object_attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Lockt(e.to_nfsstat4(), None),
        };
        if matches!(
            object_attr.file_type,
            ServerFileType::Directory | ServerFileType::NamedAttrDir
        ) {
            return NfsResop4::Lockt(NfsStat4::Isdir, None);
        }
        if let Err(status) = self.state.validate_lock_bounds(args.offset, args.length) {
            return NfsResop4::Lockt(status, None);
        }
        match self
            .state
            .find_lock_conflict(
                &object,
                &args.owner,
                args.locktype,
                args.offset,
                args.length,
                None,
            )
            .await
        {
            Some(denied) => NfsResop4::Lockt(NfsStat4::Denied, Some(denied)),
            None => NfsResop4::Lockt(NfsStat4::Ok, None),
        }
    }

    pub(crate) async fn op_locku(
        &self,
        args: &LockuArgs4,
        current_fh: &Option<NfsFh4>,
        current_stateid: Option<Stateid4>,
        sequence_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Locku(status, None),
        };
        let clientid = match sequence_clientid {
            Some(clientid) => clientid,
            None => return NfsResop4::Locku(NfsStat4::BadStateid, None),
        };
        let stateid = match self.state.normalize_stateid(
            &args.lock_stateid,
            current_stateid,
            CurrentStateidMode::ZeroSeqid,
        ) {
            Ok(NormalizedStateid::Concrete(stateid)) => stateid,
            Ok(NormalizedStateid::Anonymous | NormalizedStateid::Bypass) => {
                return NfsResop4::Locku(NfsStat4::BadStateid, None);
            }
            Err(status) => return NfsResop4::Locku(status, None),
        };
        match self
            .state
            .resolve_stateid(clientid, &stateid, None, CurrentStateidMode::ZeroSeqid)
            .await
        {
            Ok(ResolvedStateid::Lock(lock)) if lock.object == object => {}
            Ok(_) => return NfsResop4::Locku(NfsStat4::BadStateid, None),
            Err(status) => return NfsResop4::Locku(status, None),
        }
        match self
            .state
            .unlock_state(&stateid, args.offset, args.length)
            .await
        {
            Ok(stateid) => NfsResop4::Locku(NfsStat4::Ok, Some(stateid)),
            Err(status) => NfsResop4::Locku(status, None),
        }
    }
}
