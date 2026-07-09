use bytes::{Bytes, BytesMut};

use crate::xdr::*;

use super::*;

fn encode_open_none_delegation(why: &OpenNoneDelegation4, dst: &mut BytesMut) {
    match why {
        OpenNoneDelegation4::Contention {
            server_will_push_deleg,
        } => {
            (WhyNoDelegation4::Contention as u32).encode(dst);
            server_will_push_deleg.encode(dst);
        }
        OpenNoneDelegation4::Resource {
            server_will_signal_avail,
        } => {
            (WhyNoDelegation4::ResourceNotAvail as u32).encode(dst);
            server_will_signal_avail.encode(dst);
        }
        OpenNoneDelegation4::Other(why) => {
            (*why as u32).encode(dst);
        }
    }
}

fn encode_open_delegation(delegation: &OpenDelegation4, dst: &mut BytesMut) {
    match delegation {
        OpenDelegation4::None => {
            (OpenDelegationType4::None as u32).encode(dst);
        }
        OpenDelegation4::NoneExt(why) => {
            (OpenDelegationType4::NoneExt as u32).encode(dst);
            encode_open_none_delegation(why, dst);
        }
        OpenDelegation4::Read(read) => {
            (OpenDelegationType4::Read as u32).encode(dst);
            read.stateid.encode(dst);
            read.recall.encode(dst);
            read.permissions.encode(dst);
        }
        OpenDelegation4::Write(write) => {
            (OpenDelegationType4::Write as u32).encode(dst);
            write.stateid.encode(dst);
            write.recall.encode(dst);
            write.space_limit.encode(dst);
            write.permissions.encode(dst);
        }
    }
}

impl XdrEncode for NfsResop4 {
    fn encode(&self, dst: &mut BytesMut) {
        match self {
            NfsResop4::Access(status, supported, access) => {
                OP_ACCESS.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    supported.encode(dst);
                    access.encode(dst);
                }
            }
            NfsResop4::Close(status, stateid) => {
                OP_CLOSE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    stateid.encode(dst);
                }
            }
            NfsResop4::Commit(status, verf) => {
                OP_COMMIT.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    dst.extend_from_slice(verf);
                }
            }
            NfsResop4::Create(status, cinfo, attrset) => {
                OP_CREATE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(ci) = cinfo {
                        ci.encode(dst);
                    }
                    attrset.encode(dst);
                }
            }
            NfsResop4::Getattr(status, attrs) => {
                OP_GETATTR.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(a) = attrs
                {
                    a.encode(dst);
                }
            }
            NfsResop4::Getfh(status, fh) => {
                OP_GETFH.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(f) = fh
                {
                    f.encode(dst);
                }
            }
            NfsResop4::Link(status, cinfo) => {
                OP_LINK.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(ci) = cinfo
                {
                    ci.encode(dst);
                }
            }
            NfsResop4::Lookup(status) => {
                OP_LOOKUP.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Lookupp(status) => {
                OP_LOOKUPP.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Open(status, res) => {
                OP_OPEN.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(r) = res
                {
                    r.stateid.encode(dst);
                    r.cinfo.encode(dst);
                    r.rflags.encode(dst);
                    r.attrset.encode(dst);
                    encode_open_delegation(&r.delegation, dst);
                }
            }
            NfsResop4::Putfh(status) => {
                OP_PUTFH.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Putpubfh(status) => {
                OP_PUTPUBFH.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Putrootfh(status) => {
                OP_PUTROOTFH.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Read(status, res) => {
                OP_READ.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(r) = res
                {
                    r.eof.encode(dst);
                    encode_opaque(dst, &r.data);
                }
            }
            NfsResop4::Readdir(status, res) => {
                OP_READDIR.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(r) = res
                {
                    dst.extend_from_slice(&r.cookieverf);
                    for entry in &r.entries {
                        true.encode(dst);
                        entry.cookie.encode(dst);
                        entry.name.encode(dst);
                        entry.attrs.encode(dst);
                    }
                    false.encode(dst);
                    r.eof.encode(dst);
                }
            }
            NfsResop4::Readlink(status, target) => {
                OP_READLINK.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(t) = target
                {
                    t.encode(dst);
                }
            }
            NfsResop4::Remove(status, cinfo) => {
                OP_REMOVE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(ci) = cinfo
                {
                    ci.encode(dst);
                }
            }
            NfsResop4::Rename(status, src_cinfo, tgt_cinfo) => {
                OP_RENAME.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(ci) = src_cinfo {
                        ci.encode(dst);
                    }
                    if let Some(ci) = tgt_cinfo {
                        ci.encode(dst);
                    }
                }
            }
            NfsResop4::Restorefh(status) => {
                OP_RESTOREFH.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Savefh(status) => {
                OP_SAVEFH.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Secinfo(status, entries) => {
                OP_SECINFO.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    (entries.len() as u32).encode(dst);
                    for e in entries {
                        e.encode(dst);
                    }
                }
            }
            NfsResop4::Setattr(status, attrsset) => {
                OP_SETATTR.encode(dst);
                status.encode(dst);
                attrsset.encode(dst);
            }
            NfsResop4::Write(status, res) => {
                OP_WRITE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(r) = res
                {
                    r.count.encode(dst);
                    r.committed.encode(dst);
                    dst.extend_from_slice(&r.writeverf);
                }
            }
            NfsResop4::ExchangeId(status, res) => {
                OP_EXCHANGE_ID.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(r) = res
                {
                    r.clientid.encode(dst);
                    r.sequenceid.encode(dst);
                    r.flags.encode(dst);
                    r.state_protect.encode(dst);
                    r.server_owner.encode(dst);
                    encode_opaque(dst, &r.server_scope);
                    (r.server_impl_id.len() as u32).encode(dst);
                    for id in &r.server_impl_id {
                        id.encode(dst);
                    }
                }
            }
            NfsResop4::CreateSession(status, res) => {
                OP_CREATE_SESSION.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(r) = res
                {
                    dst.extend_from_slice(&r.sessionid);
                    r.sequenceid.encode(dst);
                    r.flags.encode(dst);
                    r.fore_chan_attrs.encode(dst);
                    r.back_chan_attrs.encode(dst);
                }
            }
            NfsResop4::DestroySession(status) => {
                OP_DESTROY_SESSION.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Sequence(status, res) => {
                OP_SEQUENCE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(r) = res
                {
                    dst.extend_from_slice(&r.sessionid);
                    r.sequenceid.encode(dst);
                    r.slotid.encode(dst);
                    r.highest_slotid.encode(dst);
                    r.target_highest_slotid.encode(dst);
                    r.status_flags.encode(dst);
                }
            }
            NfsResop4::ReclaimComplete(status) => {
                OP_RECLAIM_COMPLETE.encode(dst);
                status.encode(dst);
            }
            NfsResop4::DestroyClientid(status) => {
                OP_DESTROY_CLIENTID.encode(dst);
                status.encode(dst);
            }
            NfsResop4::BindConnToSession(status, res) => {
                OP_BIND_CONN_TO_SESSION.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(r) = res
                {
                    dst.extend_from_slice(&r.sessionid);
                    r.dir.encode(dst);
                    r.use_conn_in_rdma_mode.encode(dst);
                }
            }
            NfsResop4::SecInfoNoName(status, entries) => {
                OP_SECINFO_NO_NAME.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    (entries.len() as u32).encode(dst);
                    for e in entries {
                        e.encode(dst);
                    }
                }
            }
            NfsResop4::FreeStateid(status) => {
                OP_FREE_STATEID.encode(dst);
                status.encode(dst);
            }
            NfsResop4::TestStateid(status, results) => {
                OP_TEST_STATEID.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    (results.len() as u32).encode(dst);
                    for r in results {
                        r.encode(dst);
                    }
                }
            }
            NfsResop4::DelegReturn(status) => {
                OP_DELEGRETURN.encode(dst);
                status.encode(dst);
            }
            NfsResop4::MustNotImplement(op, status) => {
                op.opcode().encode(dst);
                status.encode(dst);
            }
            NfsResop4::Lock(status, stateid, denied) => {
                OP_LOCK.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(s) = stateid
                {
                    s.encode(dst);
                } else if *status == NfsStat4::Denied
                    && let Some(d) = denied
                {
                    d.offset.encode(dst);
                    d.length.encode(dst);
                    d.locktype.encode(dst);
                    d.owner.clientid.encode(dst);
                    encode_opaque(dst, &d.owner.owner);
                }
            }
            NfsResop4::Lockt(status, denied) => {
                OP_LOCKT.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Denied
                    && let Some(d) = denied
                {
                    d.offset.encode(dst);
                    d.length.encode(dst);
                    d.locktype.encode(dst);
                    d.owner.clientid.encode(dst);
                    encode_opaque(dst, &d.owner.owner);
                }
            }
            NfsResop4::Locku(status, stateid) => {
                OP_LOCKU.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(s) = stateid
                {
                    s.encode(dst);
                }
            }
            NfsResop4::OpenAttr(status) => {
                OP_OPENATTR.encode(dst);
                status.encode(dst);
            }
            NfsResop4::DelegPurge(status) => {
                OP_DELEGPURGE.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Verify(status) => {
                OP_VERIFY.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Nverify(status) => {
                OP_NVERIFY.encode(dst);
                status.encode(dst);
            }
            NfsResop4::OpenDowngrade(status, stateid) => {
                OP_OPEN_DOWNGRADE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(s) = stateid
                {
                    s.encode(dst);
                }
            }
            NfsResop4::LayoutGet(status, res) => {
                OP_LAYOUTGET.encode(dst);
                status.encode(dst);
                match (*status, res) {
                    (NfsStat4::Ok, Some(LayoutGetRes4::Ok(ok))) => {
                        ok.return_on_close.encode(dst);
                        ok.stateid.encode(dst);
                        ok.layout.encode(dst);
                    }
                    (
                        NfsStat4::LayoutTrylater,
                        Some(LayoutGetRes4::LayoutTryLater {
                            will_signal_layout_avail,
                        }),
                    ) => {
                        will_signal_layout_avail.encode(dst);
                    }
                    _ => {}
                }
            }
            NfsResop4::LayoutReturn(status, res) => {
                OP_LAYOUTRETURN.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(res) = res
                {
                    match res {
                        LayoutReturnStateid4::None => false.encode(dst),
                        LayoutReturnStateid4::Some(stateid) => {
                            true.encode(dst);
                            stateid.encode(dst);
                        }
                    }
                }
            }
            NfsResop4::LayoutCommit(status, res) => {
                OP_LAYOUTCOMMIT.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(res) = res
                {
                    res.newsize.encode(dst);
                }
            }
            NfsResop4::GetDirDelegation(status, res) => {
                OP_GET_DIR_DELEGATION.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(res) = res
                {
                    match res {
                        GetDirDelegationRes4::Ok(ok) => {
                            0u32.encode(dst);
                            dst.extend_from_slice(&ok.cookieverf);
                            ok.stateid.encode(dst);
                            ok.notification.encode(dst);
                            ok.child_attributes.encode(dst);
                            ok.dir_attributes.encode(dst);
                        }
                        GetDirDelegationRes4::Unavail {
                            will_signal_deleg_avail,
                        } => {
                            1u32.encode(dst);
                            will_signal_deleg_avail.encode(dst);
                        }
                    }
                }
            }
            NfsResop4::WantDelegation(status, res) => {
                OP_WANT_DELEGATION.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(res) = res
                {
                    encode_open_delegation(res, dst);
                }
            }
            NfsResop4::BackchannelCtl(status) => {
                OP_BACKCHANNEL_CTL.encode(dst);
                status.encode(dst);
            }
            NfsResop4::GetDeviceInfo(status, res) => {
                OP_GETDEVICEINFO.encode(dst);
                status.encode(dst);
                match (*status, res) {
                    (
                        NfsStat4::Ok,
                        Some(GetDeviceInfoRes4::Ok {
                            device_addr,
                            notification,
                        }),
                    ) => {
                        device_addr.encode(dst);
                        notification.encode(dst);
                    }
                    (NfsStat4::Toosmall, Some(GetDeviceInfoRes4::TooSmall { mincount })) => {
                        mincount.encode(dst);
                    }
                    _ => {}
                }
            }
            NfsResop4::GetDeviceList(status, res) => {
                OP_GETDEVICELIST.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(res) = res
                {
                    res.cookie.encode(dst);
                    dst.extend_from_slice(&res.cookieverf);
                    (res.deviceid_list.len() as u32).encode(dst);
                    for deviceid in &res.deviceid_list {
                        dst.extend_from_slice(deviceid);
                    }
                    res.eof.encode(dst);
                }
            }
            NfsResop4::SetSsv(status, res) => {
                OP_SET_SSV.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok
                    && let Some(res) = res
                {
                    res.digest.encode(dst);
                }
            }
            NfsResop4::Illegal(status) => {
                OP_ILLEGAL.encode(dst);
                status.encode(dst);
            }
        }
    }
}

impl Compound4Args {
    pub fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let tag = String::decode(src)?;
        let minorversion = u32::decode(src)?;
        let count = u32::decode(src)? as usize;
        let mut argarray = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            argarray.push(decode_nfs_argop4(src)?);
        }
        Ok(Compound4Args {
            tag,
            minorversion,
            argarray,
        })
    }
}

fn decode_nfs_argop4(src: &mut Bytes) -> XdrResult<NfsArgop4> {
    let opnum = u32::decode(src)?;
    match opnum {
        OP_ACCESS => Ok(NfsArgop4::Access(AccessArgs4 {
            access: u32::decode(src)?,
        })),
        OP_CLOSE => Ok(NfsArgop4::Close(CloseArgs4 {
            seqid: u32::decode(src)?,
            open_stateid: Stateid4::decode(src)?,
        })),
        OP_COMMIT => Ok(NfsArgop4::Commit(CommitArgs4 {
            offset: u64::decode(src)?,
            count: u32::decode(src)?,
        })),
        OP_CREATE => {
            let type_val = u32::decode(src)?;
            let objtype = match type_val {
                1 => Createtype4::Reg,
                5 => Createtype4::Link(String::decode(src)?),
                3 => Createtype4::Blk(Specdata4 {
                    specdata1: u32::decode(src)?,
                    specdata2: u32::decode(src)?,
                }),
                4 => Createtype4::Chr(Specdata4 {
                    specdata1: u32::decode(src)?,
                    specdata2: u32::decode(src)?,
                }),
                6 => Createtype4::Sock,
                7 => Createtype4::Fifo,
                2 => Createtype4::Dir,
                _ => Createtype4::Unsupported(type_val),
            };
            Ok(NfsArgop4::Create(CreateArgs4 {
                objtype,
                objname: String::decode(src)?,
                createattrs: Fattr4::decode(src)?,
            }))
        }
        OP_GETATTR => Ok(NfsArgop4::Getattr(GetattrArgs4 {
            attr_request: Bitmap4::decode(src)?,
        })),
        OP_GETFH => Ok(NfsArgop4::Getfh),
        OP_LINK => Ok(NfsArgop4::Link(LinkArgs4 {
            newname: String::decode(src)?,
        })),
        OP_LOOKUP => Ok(NfsArgop4::Lookup(LookupArgs4 {
            objname: String::decode(src)?,
        })),
        OP_LOOKUPP => Ok(NfsArgop4::Lookupp),
        OP_OPEN => {
            let seqid = u32::decode(src)?;
            let share_access = u32::decode(src)?;
            let share_deny = u32::decode(src)?;
            let owner = StateOwner4::decode(src)?;
            let opentype = u32::decode(src)?;
            let openhow = if opentype == 1 {
                let createmode = u32::decode(src)?;
                let how = match createmode {
                    0 => Createhow4::Unchecked(Fattr4::decode(src)?),
                    1 => Createhow4::Guarded(Fattr4::decode(src)?),
                    2 => {
                        let vdata = decode_fixed_opaque(src, 8)?;
                        let mut v = [0u8; 8];
                        v.copy_from_slice(&vdata);
                        Createhow4::Exclusive(v)
                    }
                    3 => {
                        let vdata = decode_fixed_opaque(src, 8)?;
                        let mut v = [0u8; 8];
                        v.copy_from_slice(&vdata);
                        Createhow4::Exclusive4_1 {
                            verifier: v,
                            attrs: Fattr4::decode(src)?,
                        }
                    }
                    _ => return Err(XdrError::InvalidEnum(createmode)),
                };
                Openflag4::Create(how)
            } else {
                Openflag4::NoCreate
            };
            let claim_type = u32::decode(src)?;
            let claim = match claim_type {
                0 => OpenClaim4::Null(String::decode(src)?),
                1 => OpenClaim4::Previous(u32::decode(src)?),
                2 => OpenClaim4::DelegateCur {
                    delegate_stateid: Stateid4::decode(src)?,
                    file: String::decode(src)?,
                },
                3 => OpenClaim4::DelegatePrev(String::decode(src)?),
                4 => OpenClaim4::Fh,
                5 => OpenClaim4::DelegCurFh(Stateid4::decode(src)?),
                6 => OpenClaim4::DelegPrevFh,
                _ => return Err(XdrError::InvalidEnum(claim_type)),
            };
            Ok(NfsArgop4::Open(OpenArgs4 {
                seqid,
                share_access,
                share_deny,
                owner,
                openhow,
                claim,
            }))
        }
        OP_OPEN_CONFIRM => {
            let _open_stateid = Stateid4::decode(src)?;
            let _seqid = u32::decode(src)?;
            Ok(NfsArgop4::MustNotImplement(
                MustNotImplementOp4::OpenConfirm,
            ))
        }
        OP_OPEN_DOWNGRADE => Ok(NfsArgop4::OpenDowngrade(OpenDowngradeArgs4 {
            open_stateid: Stateid4::decode(src)?,
            seqid: u32::decode(src)?,
            share_access: u32::decode(src)?,
            share_deny: u32::decode(src)?,
        })),
        OP_PUTFH => Ok(NfsArgop4::Putfh(PutfhArgs4 {
            object: NfsFh4::decode(src)?,
        })),
        OP_PUTPUBFH => Ok(NfsArgop4::Putpubfh),
        OP_PUTROOTFH => Ok(NfsArgop4::Putrootfh),
        OP_READ => Ok(NfsArgop4::Read(ReadArgs4 {
            stateid: Stateid4::decode(src)?,
            offset: u64::decode(src)?,
            count: u32::decode(src)?,
        })),
        OP_READDIR => {
            let cookie = u64::decode(src)?;
            let cvdata = decode_fixed_opaque(src, 8)?;
            let mut cookieverf = [0u8; 8];
            cookieverf.copy_from_slice(&cvdata);
            Ok(NfsArgop4::Readdir(ReaddirArgs4 {
                cookie,
                cookieverf,
                dircount: u32::decode(src)?,
                maxcount: u32::decode(src)?,
                attr_request: Bitmap4::decode(src)?,
            }))
        }
        OP_READLINK => Ok(NfsArgop4::Readlink),
        OP_REMOVE => Ok(NfsArgop4::Remove(RemoveArgs4 {
            target: String::decode(src)?,
        })),
        OP_RENAME => Ok(NfsArgop4::Rename(RenameArgs4 {
            oldname: String::decode(src)?,
            newname: String::decode(src)?,
        })),
        OP_RESTOREFH => Ok(NfsArgop4::Restorefh),
        OP_SAVEFH => Ok(NfsArgop4::Savefh),
        OP_SECINFO => Ok(NfsArgop4::Secinfo(SecinfoArgs4 {
            name: String::decode(src)?,
        })),
        OP_SETATTR => Ok(NfsArgop4::Setattr(SetattrArgs4 {
            stateid: Stateid4::decode(src)?,
            obj_attributes: Fattr4::decode(src)?,
        })),
        OP_WRITE => Ok(NfsArgop4::Write(WriteArgs4 {
            stateid: Stateid4::decode(src)?,
            offset: u64::decode(src)?,
            stable: u32::decode(src)?,
            data: decode_opaque(src)?,
        })),
        OP_EXCHANGE_ID => {
            let clientowner = ClientOwner4::decode(src)?;
            let flags = u32::decode(src)?;
            let sp_type = u32::decode(src)?;
            let state_protect = match sp_type {
                0 => StateProtect4A::None,
                1 => StateProtect4A::MachCred {
                    ops: StateProtectOps4 {
                        enforce: Bitmap4::decode(src)?,
                        allow: Bitmap4::decode(src)?,
                    },
                },
                2 => StateProtect4A::Ssv {
                    parms: SsvSpParms4 {
                        ops: StateProtectOps4 {
                            enforce: Bitmap4::decode(src)?,
                            allow: Bitmap4::decode(src)?,
                        },
                        hash_algs: decode_list(src)?,
                        encr_algs: decode_list(src)?,
                        window: u32::decode(src)?,
                        num_gss_handles: u32::decode(src)?,
                    },
                },
                _ => return Err(XdrError::InvalidEnum(sp_type)),
            };
            Ok(NfsArgop4::ExchangeId(ExchangeIdArgs4 {
                clientowner,
                flags,
                state_protect,
                client_impl_id: decode_list(src)?,
            }))
        }
        OP_CREATE_SESSION => Ok(NfsArgop4::CreateSession(CreateSessionArgs4 {
            clientid: u64::decode(src)?,
            sequence: u32::decode(src)?,
            flags: u32::decode(src)?,
            fore_chan_attrs: ChannelAttrs4::decode(src)?,
            back_chan_attrs: ChannelAttrs4::decode(src)?,
            cb_program: u32::decode(src)?,
            sec_parms: decode_list(src)?,
        })),
        OP_DESTROY_SESSION => {
            let sid = decode_fixed_opaque(src, 16)?;
            let mut sessionid = [0u8; 16];
            sessionid.copy_from_slice(&sid);
            Ok(NfsArgop4::DestroySession(DestroySessionArgs4 { sessionid }))
        }
        OP_SEQUENCE => {
            let sid = decode_fixed_opaque(src, 16)?;
            let mut sessionid = [0u8; 16];
            sessionid.copy_from_slice(&sid);
            Ok(NfsArgop4::Sequence(SequenceArgs4 {
                sessionid,
                sequenceid: u32::decode(src)?,
                slotid: u32::decode(src)?,
                highest_slotid: u32::decode(src)?,
                cachethis: bool::decode(src)?,
            }))
        }
        OP_RECLAIM_COMPLETE => Ok(NfsArgop4::ReclaimComplete(ReclaimCompleteArgs4 {
            one_fs: bool::decode(src)?,
        })),
        OP_DESTROY_CLIENTID => Ok(NfsArgop4::DestroyClientid(DestroyClientidArgs4 {
            clientid: u64::decode(src)?,
        })),
        OP_BIND_CONN_TO_SESSION => {
            let sid = decode_fixed_opaque(src, 16)?;
            let mut sessionid = [0u8; 16];
            sessionid.copy_from_slice(&sid);
            Ok(NfsArgop4::BindConnToSession(BindConnToSessionArgs4 {
                sessionid,
                dir: u32::decode(src)?,
                use_conn_in_rdma_mode: bool::decode(src)?,
            }))
        }
        OP_SECINFO_NO_NAME => Ok(NfsArgop4::SecInfoNoName(u32::decode(src)?)),
        OP_FREE_STATEID => Ok(NfsArgop4::FreeStateid(FreeStateidArgs4 {
            stateid: Stateid4::decode(src)?,
        })),
        OP_TEST_STATEID => Ok(NfsArgop4::TestStateid(TestStateidArgs4 {
            stateids: decode_list(src)?,
        })),
        OP_DELEGRETURN => Ok(NfsArgop4::DelegReturn(DelegReturnArgs4 {
            stateid: Stateid4::decode(src)?,
        })),
        OP_SETCLIENTID => {
            let vdata = decode_fixed_opaque(src, 8)?;
            let mut verifier = [0u8; 8];
            verifier.copy_from_slice(&vdata);
            let ownerid = decode_opaque_max(src, 1024)?;
            let _client = ClientOwner4 { verifier, ownerid };
            let _cb_program = u32::decode(src)?;
            let _cb_netid = String::decode(src)?;
            let _cb_addr = String::decode(src)?;
            let _callback_ident = u32::decode(src)?;
            Ok(NfsArgop4::MustNotImplement(
                MustNotImplementOp4::SetClientId,
            ))
        }
        OP_SETCLIENTID_CONFIRM => {
            let _clientid = u64::decode(src)?;
            let _verifier = decode_fixed_opaque(src, 8)?;
            Ok(NfsArgop4::MustNotImplement(
                MustNotImplementOp4::SetClientIdConfirm,
            ))
        }
        OP_RENEW => {
            let _clientid = u64::decode(src)?;
            Ok(NfsArgop4::MustNotImplement(MustNotImplementOp4::Renew))
        }
        OP_RELEASE_LOCKOWNER => {
            let _clientid = u64::decode(src)?;
            let _owner = decode_opaque_max(src, 1024)?;
            Ok(NfsArgop4::MustNotImplement(
                MustNotImplementOp4::ReleaseLockowner,
            ))
        }
        OP_LOCK => {
            let locktype = NfsLockType4::decode(src)?;
            let reclaim = bool::decode(src)?;
            let offset = u64::decode(src)?;
            let length = u64::decode(src)?;
            let new_lock_owner = bool::decode(src)?;
            let locker = if new_lock_owner {
                Locker4::NewLockOwner(OpenToLockOwner4 {
                    open_seqid: u32::decode(src)?,
                    open_stateid: Stateid4::decode(src)?,
                    lock_seqid: u32::decode(src)?,
                    lock_owner: StateOwner4 {
                        clientid: u64::decode(src)?,
                        owner: decode_opaque_max(src, 1024)?,
                    },
                })
            } else {
                Locker4::ExistingLockOwner(ExistLockOwner4 {
                    lock_stateid: Stateid4::decode(src)?,
                    lock_seqid: u32::decode(src)?,
                })
            };
            Ok(NfsArgop4::Lock(LockArgs4 {
                locktype,
                reclaim,
                offset,
                length,
                locker,
            }))
        }
        OP_LOCKT => Ok(NfsArgop4::Lockt(LocktArgs4 {
            locktype: NfsLockType4::decode(src)?,
            offset: u64::decode(src)?,
            length: u64::decode(src)?,
            owner: StateOwner4 {
                clientid: u64::decode(src)?,
                owner: decode_opaque_max(src, 1024)?,
            },
        })),
        OP_LOCKU => Ok(NfsArgop4::Locku(LockuArgs4 {
            locktype: NfsLockType4::decode(src)?,
            seqid: u32::decode(src)?,
            lock_stateid: Stateid4::decode(src)?,
            offset: u64::decode(src)?,
            length: u64::decode(src)?,
        })),
        OP_OPENATTR => Ok(NfsArgop4::OpenAttr(OpenAttrArgs4 {
            createdir: bool::decode(src)?,
        })),
        OP_DELEGPURGE => {
            let _clientid = u64::decode(src)?;
            Ok(NfsArgop4::DelegPurge)
        }
        OP_VERIFY => Ok(NfsArgop4::Verify(Fattr4::decode(src)?)),
        OP_NVERIFY => Ok(NfsArgop4::Nverify(Fattr4::decode(src)?)),
        OP_BACKCHANNEL_CTL => {
            let _cb_program = u32::decode(src)?;
            let _sec_parms: Vec<CallbackSecParms4> = decode_list(src)?;
            Ok(NfsArgop4::BackchannelCtl)
        }
        OP_GET_DIR_DELEGATION => {
            let _signal = bool::decode(src)?;
            let _notif_types = Bitmap4::decode(src)?;
            let _child_attr_delay = u64::decode(src)?;
            let _ = u32::decode(src)?;
            let _dir_attr_delay = u64::decode(src)?;
            let _ = u32::decode(src)?;
            let _child_attrs = Bitmap4::decode(src)?;
            let _dir_attrs = Bitmap4::decode(src)?;
            Ok(NfsArgop4::GetDirDelegation)
        }
        OP_GETDEVICEINFO => {
            let _deviceid = decode_fixed_opaque(src, 16)?;
            let _layout_type = u32::decode(src)?;
            let _maxcount = u32::decode(src)?;
            let _notif_types = Bitmap4::decode(src)?;
            Ok(NfsArgop4::GetDeviceInfo)
        }
        OP_GETDEVICELIST => {
            let _layout_type = u32::decode(src)?;
            let _maxdevices = u32::decode(src)?;
            let _cookie = u64::decode(src)?;
            let _vdata = decode_fixed_opaque(src, 8)?;
            Ok(NfsArgop4::GetDeviceList)
        }
        OP_LAYOUTCOMMIT => {
            let _offset = u64::decode(src)?;
            let _length = u64::decode(src)?;
            let _reclaim = bool::decode(src)?;
            let _stateid = Stateid4::decode(src)?;
            let _new_offset = bool::decode(src)?;
            if _new_offset {
                let _last_byte = u64::decode(src)?;
            }
            let _time_modify = bool::decode(src)?;
            if _time_modify {
                let _t = NfsTime4::decode(src)?;
            }
            let _layout_type = u32::decode(src)?;
            let _layoutupdate = decode_opaque(src)?;
            Ok(NfsArgop4::LayoutCommit)
        }
        OP_LAYOUTGET => {
            let _signal = bool::decode(src)?;
            let _layout_type = u32::decode(src)?;
            let _iomode = u32::decode(src)?;
            let _offset = u64::decode(src)?;
            let _length = u64::decode(src)?;
            let _minlength = u64::decode(src)?;
            let _stateid = Stateid4::decode(src)?;
            let _maxcount = u32::decode(src)?;
            Ok(NfsArgop4::LayoutGet)
        }
        OP_LAYOUTRETURN => {
            let _reclaim = bool::decode(src)?;
            let _layout_type = u32::decode(src)?;
            let _iomode = u32::decode(src)?;
            let _return_type = u32::decode(src)?;
            match _return_type {
                1 => {
                    let _offset = u64::decode(src)?;
                    let _length = u64::decode(src)?;
                    let _stateid = Stateid4::decode(src)?;
                    let _body = decode_opaque(src)?;
                }
                2 | 3 => {}
                _ => {}
            }
            Ok(NfsArgop4::LayoutReturn)
        }
        OP_SET_SSV => {
            let _ssv = decode_opaque(src)?;
            let _digest = decode_opaque(src)?;
            Ok(NfsArgop4::SetSsv)
        }
        OP_WANT_DELEGATION => {
            let _want = u32::decode(src)?;
            let claim_type = u32::decode(src)?;
            match claim_type {
                0 => {}
                3 => {
                    let _file = String::decode(src)?;
                }
                _ => {}
            }
            Ok(NfsArgop4::WantDelegation)
        }
        _ => Ok(NfsArgop4::Illegal),
    }
}
