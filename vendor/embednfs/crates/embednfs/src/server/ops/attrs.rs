use embednfs_proto::*;

use crate::attrs;
use crate::fs::{FileSystem, RequestContext};
use crate::internal::{ServerFileType, ServerObject};

use super::super::NfsServer;
use super::file::IoStateContext;

impl<F: FileSystem> NfsServer<F> {
    pub(crate) async fn op_access(
        &self,
        request_ctx: &RequestContext,
        args: &AccessArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Access(status, 0, 0),
        };

        match self.build_attr(request_ctx, &object).await {
            Ok(attr) => {
                let mut server_supported = ACCESS4_READ
                    | ACCESS4_LOOKUP
                    | ACCESS4_MODIFY
                    | ACCESS4_EXTEND
                    | ACCESS4_DELETE
                    | ACCESS4_EXECUTE;
                if matches!(
                    attr.file_type,
                    ServerFileType::Directory | ServerFileType::NamedAttrDir
                ) {
                    server_supported &= !ACCESS4_EXECUTE;
                }
                let requested = Self::nfs_access_mask(args.access & server_supported);
                let granted = match object {
                    ServerObject::Fs(id) => match self.access_for(request_ctx, id, requested).await
                    {
                        Ok(mask) => mask,
                        Err(e) => return NfsResop4::Access(e.to_nfsstat4(), 0, 0),
                    },
                    _ => requested,
                };
                let supported = args.access & server_supported;
                NfsResop4::Access(
                    NfsStat4::Ok,
                    supported,
                    Self::access_bits(granted) & supported,
                )
            }
            Err(e) => NfsResop4::Access(e.to_nfsstat4(), 0, 0),
        }
    }

    pub(crate) async fn op_getattr(
        &self,
        request_ctx: &RequestContext,
        args: &GetattrArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (fh, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Getattr(status, None),
        };

        match self.build_attr(request_ctx, &object).await {
            Ok(attr) => match self
                .encode_fattr(request_ctx, &attr, &args.attr_request, &fh)
                .await
            {
                Ok(fattr) => NfsResop4::Getattr(NfsStat4::Ok, Some(fattr)),
                Err(e) => NfsResop4::Getattr(e.to_nfsstat4(), None),
            },
            Err(e) => NfsResop4::Getattr(e.to_nfsstat4(), None),
        }
    }

    pub(crate) fn op_getfh(&self, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        match current_fh {
            Some(fh) => NfsResop4::Getfh(NfsStat4::Ok, Some(fh.clone())),
            None => NfsResop4::Getfh(NfsStat4::Nofilehandle, None),
        }
    }

    pub(crate) async fn op_setattr(
        &self,
        request_ctx: &RequestContext,
        args: &SetattrArgs4,
        current_fh: &Option<NfsFh4>,
        current_stateid: Option<Stateid4>,
        sequence_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Setattr(status, Bitmap4::new()),
        };

        let set_attrs = match attrs::decode_setattr(&args.obj_attributes) {
            Ok(attrs) => attrs,
            Err(status) => return NfsResop4::Setattr(status, Bitmap4::new()),
        };

        if let Some(new_size) = set_attrs.size {
            let current_attr = match self.build_attr(request_ctx, &object).await {
                Ok(attr) => attr,
                Err(e) => return NfsResop4::Setattr(e.to_nfsstat4(), Bitmap4::new()),
            };
            let offset = current_attr.size.min(new_size);
            let length = current_attr.size.max(new_size) - offset;
            if let Err(status) = self
                .validate_io_stateid(
                    &object,
                    &args.stateid,
                    IoStateContext {
                        current_stateid,
                        sequence_clientid,
                        is_write: true,
                        offset,
                        length,
                    },
                )
                .await
            {
                return NfsResop4::Setattr(status, Bitmap4::new());
            }
        }

        let status = match object.clone() {
            ServerObject::Fs(id) => match self.setattr_real(request_ctx, id, &set_attrs).await {
                Ok(_) => NfsStat4::Ok,
                Err(e) => e.to_nfsstat4(),
            },
            ServerObject::NamedAttrFile { parent, name } => {
                if let Some(size) = set_attrs.size
                    && let Err(e) = self.xattr_resize(request_ctx, parent, &name, size).await
                {
                    return NfsResop4::Setattr(e.to_nfsstat4(), Bitmap4::new());
                }
                self.state
                    .apply_setattr(&object, ServerFileType::NamedAttr, &set_attrs)
                    .await;
                if set_attrs.size.is_some() {
                    self.state
                        .touch_data(&object, ServerFileType::NamedAttr)
                        .await;
                }
                NfsStat4::Ok
            }
            ServerObject::NamedAttrDir(_) => {
                if set_attrs.size.is_some() {
                    NfsStat4::Isdir
                } else {
                    self.state
                        .apply_setattr(&object, ServerFileType::NamedAttrDir, &set_attrs)
                        .await;
                    NfsStat4::Ok
                }
            }
        };

        if status == NfsStat4::Ok {
            NfsResop4::Setattr(NfsStat4::Ok, args.obj_attributes.attrmask.clone())
        } else {
            NfsResop4::Setattr(status, Bitmap4::new())
        }
    }

    pub(crate) async fn op_verify(
        &self,
        request_ctx: &RequestContext,
        client_fattr: &Fattr4,
        current_fh: &Option<NfsFh4>,
        negate: bool,
    ) -> NfsResop4 {
        let make_res = |s: NfsStat4| {
            if negate {
                NfsResop4::Nverify(s)
            } else {
                NfsResop4::Verify(s)
            }
        };

        let (fh, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return make_res(status),
        };

        let attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return make_res(e.to_nfsstat4()),
        };
        if client_fattr.attrmask.is_set(FATTR4_RDATTR_ERROR)
            || client_fattr.attrmask.is_set(FATTR4_TIME_ACCESS_SET)
            || client_fattr.attrmask.is_set(FATTR4_TIME_MODIFY_SET)
        {
            return make_res(NfsStat4::Inval);
        }
        let supported = attrs::supported_attrs_bitmap(&self.capabilities());
        for (word_idx, word) in client_fattr.attrmask.0.iter().enumerate() {
            let supported_word = supported.0.get(word_idx).copied().unwrap_or(0);
            if word & !supported_word != 0 {
                return make_res(NfsStat4::AttrNotsupp);
            }
        }

        let server_fattr = match self
            .encode_fattr(request_ctx, &attr, &client_fattr.attrmask, &fh)
            .await
        {
            Ok(fattr) => fattr,
            Err(e) => return make_res(e.to_nfsstat4()),
        };

        let attrs_match = server_fattr.attrmask == client_fattr.attrmask
            && server_fattr.attr_vals == client_fattr.attr_vals;

        if negate {
            if attrs_match {
                make_res(NfsStat4::Same)
            } else {
                make_res(NfsStat4::Ok)
            }
        } else if attrs_match {
            make_res(NfsStat4::Ok)
        } else {
            make_res(NfsStat4::NotSame)
        }
    }
}
