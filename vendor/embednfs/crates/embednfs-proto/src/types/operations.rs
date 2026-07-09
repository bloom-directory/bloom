use bytes::BytesMut;

use crate::xdr::{XdrDecode, XdrEncode, XdrResult};

use super::basic::*;
use super::constants::*;
use super::session::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OpenClaimType4 {
    Null = 0,
    Previous = 1,
    DelegateCur = 2,
    DelegatePrev = 3,
    Fh = 4,
    DelegCurFh = 5,
    DelegPrevFh = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Createmode4 {
    Unchecked4 = 0,
    Guarded4 = 1,
    Exclusive4 = 2,
    Exclusive4_1 = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OpenDelegationType4 {
    None = 0,
    Read = 1,
    Write = 2,
    NoneExt = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WhyNoDelegation4 {
    NotWanted = 0,
    Contention = 1,
    ResourceNotAvail = 2,
    NotSuppFtype = 3,
    WriteDelegNotSuppFtype = 4,
    NotSuppUpgrade = 5,
    NotSuppDowngrade = 6,
    Cancelled = 7,
    IsDir = 8,
}

/// NFSv4.0 operations that RFC 8881 marks as mandatory not-to-implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MustNotImplementOp4 {
    OpenConfirm,
    Renew,
    SetClientId,
    SetClientIdConfirm,
    ReleaseLockowner,
}

impl MustNotImplementOp4 {
    pub fn opcode(self) -> u32 {
        match self {
            MustNotImplementOp4::OpenConfirm => OP_OPEN_CONFIRM,
            MustNotImplementOp4::Renew => OP_RENEW,
            MustNotImplementOp4::SetClientId => OP_SETCLIENTID,
            MustNotImplementOp4::SetClientIdConfirm => OP_SETCLIENTID_CONFIRM,
            MustNotImplementOp4::ReleaseLockowner => OP_RELEASE_LOCKOWNER,
        }
    }
}

#[derive(Debug)]
pub struct AccessArgs4 {
    pub access: u32,
}

#[derive(Debug)]
pub struct CloseArgs4 {
    pub seqid: Seqid4,
    pub open_stateid: Stateid4,
}

#[derive(Debug)]
pub struct CommitArgs4 {
    pub offset: Offset4,
    pub count: Count4,
}

#[derive(Debug)]
pub struct CreateArgs4 {
    pub objtype: Createtype4,
    pub objname: String,
    pub createattrs: Fattr4,
}

#[derive(Debug)]
pub enum Createtype4 {
    Reg,
    Link(String),
    Blk(Specdata4),
    Chr(Specdata4),
    Sock,
    Fifo,
    Dir,
    Unsupported(u32),
}

#[derive(Debug)]
pub struct GetattrArgs4 {
    pub attr_request: Bitmap4,
}

#[derive(Debug)]
pub struct LinkArgs4 {
    pub newname: String,
}

#[derive(Debug)]
pub struct LookupArgs4 {
    pub objname: String,
}

#[derive(Debug, Clone)]
pub struct StateOwner4 {
    pub clientid: Clientid4,
    pub owner: bytes::Bytes,
}

impl XdrDecode for StateOwner4 {
    fn decode(src: &mut bytes::Bytes) -> XdrResult<Self> {
        Ok(StateOwner4 {
            clientid: u64::decode(src)?,
            owner: crate::xdr::decode_opaque_max(src, 1024)?,
        })
    }
}

#[derive(Debug)]
pub enum Openflag4 {
    NoCreate,
    Create(Createhow4),
}

#[derive(Debug)]
pub enum Createhow4 {
    Unchecked(Fattr4),
    Guarded(Fattr4),
    Exclusive(Verifier4),
    Exclusive4_1 { verifier: Verifier4, attrs: Fattr4 },
}

#[derive(Debug)]
pub enum OpenClaim4 {
    Null(String),
    Previous(u32),
    DelegateCur {
        delegate_stateid: Stateid4,
        file: String,
    },
    DelegatePrev(String),
    Fh,
    DelegCurFh(Stateid4),
    DelegPrevFh,
}

#[derive(Debug)]
pub struct OpenArgs4 {
    pub seqid: Seqid4,
    pub share_access: u32,
    pub share_deny: u32,
    pub owner: StateOwner4,
    pub openhow: Openflag4,
    pub claim: OpenClaim4,
}

#[derive(Debug)]
pub struct PutfhArgs4 {
    pub object: NfsFh4,
}

#[derive(Debug)]
pub struct ReadArgs4 {
    pub stateid: Stateid4,
    pub offset: Offset4,
    pub count: Count4,
}

#[derive(Debug)]
pub struct ReaddirArgs4 {
    pub cookie: u64,
    pub cookieverf: Verifier4,
    pub dircount: Count4,
    pub maxcount: Count4,
    pub attr_request: Bitmap4,
}

#[derive(Debug)]
pub struct RemoveArgs4 {
    pub target: String,
}

#[derive(Debug)]
pub struct RenameArgs4 {
    pub oldname: String,
    pub newname: String,
}

#[derive(Debug)]
pub struct SecinfoArgs4 {
    pub name: String,
}

#[derive(Debug)]
pub struct OpenDowngradeArgs4 {
    pub open_stateid: Stateid4,
    pub seqid: Seqid4,
    pub share_access: u32,
    pub share_deny: u32,
}

#[derive(Debug)]
pub struct SetattrArgs4 {
    pub stateid: Stateid4,
    pub obj_attributes: Fattr4,
}

#[derive(Debug)]
pub struct WriteArgs4 {
    pub stateid: Stateid4,
    pub offset: Offset4,
    pub stable: u32,
    pub data: bytes::Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsLockType4 {
    ReadLt = 1,
    WriteLt = 2,
    ReadwLt = 3,
    WritewLt = 4,
}

impl XdrDecode for NfsLockType4 {
    fn decode(src: &mut bytes::Bytes) -> XdrResult<Self> {
        match u32::decode(src)? {
            1 => Ok(NfsLockType4::ReadLt),
            2 => Ok(NfsLockType4::WriteLt),
            3 => Ok(NfsLockType4::ReadwLt),
            4 => Ok(NfsLockType4::WritewLt),
            v => Err(crate::xdr::XdrError::InvalidEnum(v)),
        }
    }
}

impl XdrEncode for NfsLockType4 {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

#[derive(Debug)]
pub struct OpenToLockOwner4 {
    pub open_seqid: Seqid4,
    pub open_stateid: Stateid4,
    pub lock_seqid: Seqid4,
    pub lock_owner: StateOwner4,
}

#[derive(Debug)]
pub struct ExistLockOwner4 {
    pub lock_stateid: Stateid4,
    pub lock_seqid: Seqid4,
}

#[derive(Debug)]
pub enum Locker4 {
    NewLockOwner(OpenToLockOwner4),
    ExistingLockOwner(ExistLockOwner4),
}

#[derive(Debug)]
pub struct LockArgs4 {
    pub locktype: NfsLockType4,
    pub reclaim: bool,
    pub offset: Offset4,
    pub length: Length4,
    pub locker: Locker4,
}

#[derive(Debug)]
pub struct LocktArgs4 {
    pub locktype: NfsLockType4,
    pub offset: Offset4,
    pub length: Length4,
    pub owner: StateOwner4,
}

#[derive(Debug)]
pub struct LockuArgs4 {
    pub locktype: NfsLockType4,
    pub seqid: Seqid4,
    pub lock_stateid: Stateid4,
    pub offset: Offset4,
    pub length: Length4,
}

#[derive(Debug)]
pub struct LockDenied4 {
    pub offset: Offset4,
    pub length: Length4,
    pub locktype: NfsLockType4,
    pub owner: StateOwner4,
}

#[derive(Debug)]
pub struct OpenAttrArgs4 {
    pub createdir: bool,
}

#[derive(Debug)]
pub struct NfsAce4 {
    pub ace_type: u32,
    pub ace_flags: u32,
    pub access_mask: u32,
    pub who: String,
}

impl XdrEncode for NfsAce4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.ace_type.encode(dst);
        self.ace_flags.encode(dst);
        self.access_mask.encode(dst);
        self.who.encode(dst);
    }
}

#[derive(Debug)]
pub struct NfsModifiedLimit4 {
    pub num_blocks: u32,
    pub bytes_per_block: u32,
}

#[derive(Debug)]
pub enum NfsSpaceLimit4 {
    Size(u64),
    Blocks(NfsModifiedLimit4),
}

impl XdrEncode for NfsSpaceLimit4 {
    fn encode(&self, dst: &mut BytesMut) {
        match self {
            NfsSpaceLimit4::Size(filesize) => {
                1u32.encode(dst);
                filesize.encode(dst);
            }
            NfsSpaceLimit4::Blocks(limit) => {
                2u32.encode(dst);
                limit.num_blocks.encode(dst);
                limit.bytes_per_block.encode(dst);
            }
        }
    }
}

#[derive(Debug)]
pub struct OpenReadDelegation4 {
    pub stateid: Stateid4,
    pub recall: bool,
    pub permissions: NfsAce4,
}

#[derive(Debug)]
pub struct OpenWriteDelegation4 {
    pub stateid: Stateid4,
    pub recall: bool,
    pub space_limit: NfsSpaceLimit4,
    pub permissions: NfsAce4,
}

#[derive(Debug)]
pub enum OpenNoneDelegation4 {
    Contention { server_will_push_deleg: bool },
    Resource { server_will_signal_avail: bool },
    Other(WhyNoDelegation4),
}

#[derive(Debug)]
pub struct DeviceAddr4 {
    pub layout_type: u32,
    pub addr_body: bytes::Bytes,
}

impl XdrEncode for DeviceAddr4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.layout_type.encode(dst);
        self.addr_body.encode(dst);
    }
}

#[derive(Debug)]
pub struct LayoutContent4 {
    pub layout_type: u32,
    pub body: bytes::Bytes,
}

impl XdrEncode for LayoutContent4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.layout_type.encode(dst);
        self.body.encode(dst);
    }
}

#[derive(Debug)]
pub struct Layout4 {
    pub offset: Offset4,
    pub length: Length4,
    pub iomode: u32,
    pub content: LayoutContent4,
}

impl XdrEncode for Layout4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.offset.encode(dst);
        self.length.encode(dst);
        self.iomode.encode(dst);
        self.content.encode(dst);
    }
}

#[derive(Debug)]
pub enum Newsize4 {
    Unchanged,
    Size(Length4),
}

impl XdrEncode for Newsize4 {
    fn encode(&self, dst: &mut BytesMut) {
        match self {
            Newsize4::Unchanged => false.encode(dst),
            Newsize4::Size(size) => {
                true.encode(dst);
                size.encode(dst);
            }
        }
    }
}

#[derive(Debug)]
pub struct GetDirDelegationResOk4 {
    pub cookieverf: Verifier4,
    pub stateid: Stateid4,
    pub notification: Bitmap4,
    pub child_attributes: Bitmap4,
    pub dir_attributes: Bitmap4,
}

#[derive(Debug)]
pub enum GetDirDelegationRes4 {
    Ok(GetDirDelegationResOk4),
    Unavail { will_signal_deleg_avail: bool },
}

#[derive(Debug)]
pub enum GetDeviceInfoRes4 {
    Ok {
        device_addr: DeviceAddr4,
        notification: Bitmap4,
    },
    TooSmall {
        mincount: Count4,
    },
}

#[derive(Debug)]
pub struct GetDeviceListResOk4 {
    pub cookie: u64,
    pub cookieverf: Verifier4,
    pub deviceid_list: Vec<Deviceid4>,
    pub eof: bool,
}

#[derive(Debug)]
pub struct LayoutCommitResOk4 {
    pub newsize: Newsize4,
}

#[derive(Debug)]
pub struct LayoutGetResOk4 {
    pub return_on_close: bool,
    pub stateid: Stateid4,
    pub layout: Vec<Layout4>,
}

#[derive(Debug)]
pub enum LayoutGetRes4 {
    Ok(LayoutGetResOk4),
    LayoutTryLater { will_signal_layout_avail: bool },
}

#[derive(Debug)]
pub enum LayoutReturnStateid4 {
    None,
    Some(Stateid4),
}

#[derive(Debug)]
pub struct SetSsvResOk4 {
    pub digest: bytes::Bytes,
}

/// NfsArgop4 - a single operation in a COMPOUND request.
#[derive(Debug)]
pub enum NfsArgop4 {
    Access(AccessArgs4),
    Close(CloseArgs4),
    Commit(CommitArgs4),
    Create(CreateArgs4),
    Getattr(GetattrArgs4),
    Getfh,
    Link(LinkArgs4),
    Lookup(LookupArgs4),
    Lookupp,
    Open(OpenArgs4),
    Putfh(PutfhArgs4),
    Putpubfh,
    Putrootfh,
    Read(ReadArgs4),
    Readdir(ReaddirArgs4),
    Readlink,
    Remove(RemoveArgs4),
    Rename(RenameArgs4),
    Restorefh,
    Savefh,
    Secinfo(SecinfoArgs4),
    Setattr(SetattrArgs4),
    Write(WriteArgs4),
    ExchangeId(ExchangeIdArgs4),
    CreateSession(CreateSessionArgs4),
    DestroySession(DestroySessionArgs4),
    Sequence(SequenceArgs4),
    ReclaimComplete(ReclaimCompleteArgs4),
    DestroyClientid(DestroyClientidArgs4),
    BindConnToSession(BindConnToSessionArgs4),
    SecInfoNoName(u32),
    FreeStateid(FreeStateidArgs4),
    TestStateid(TestStateidArgs4),
    DelegReturn(DelegReturnArgs4),
    MustNotImplement(MustNotImplementOp4),
    Lock(LockArgs4),
    Lockt(LocktArgs4),
    Locku(LockuArgs4),
    OpenAttr(OpenAttrArgs4),
    DelegPurge,
    Verify(Fattr4),
    Nverify(Fattr4),
    OpenDowngrade(OpenDowngradeArgs4),
    LayoutGet,
    LayoutReturn,
    LayoutCommit,
    GetDirDelegation,
    WantDelegation,
    BackchannelCtl,
    GetDeviceInfo,
    GetDeviceList,
    SetSsv,
    Illegal,
}

/// A COMPOUND request (NFSv4.1 procedure 1).
#[derive(Debug)]
pub struct Compound4Args {
    pub tag: String,
    pub minorversion: u32,
    pub argarray: Vec<NfsArgop4>,
}

/// A COMPOUND response.
#[derive(Debug)]
pub struct Compound4Res {
    pub status: NfsStat4,
    pub tag: String,
    pub resarray: Vec<NfsResop4>,
}

impl XdrEncode for Compound4Res {
    fn encode(&self, dst: &mut BytesMut) {
        self.status.encode(dst);
        self.tag.encode(dst);
        (self.resarray.len() as u32).encode(dst);
        for res in &self.resarray {
            res.encode(dst);
        }
    }
}

#[derive(Debug)]
pub enum OpenDelegation4 {
    None,
    NoneExt(OpenNoneDelegation4),
    Read(OpenReadDelegation4),
    Write(OpenWriteDelegation4),
}

#[derive(Debug)]
pub struct OpenRes4 {
    pub stateid: Stateid4,
    pub cinfo: ChangeInfo4,
    pub rflags: u32,
    pub attrset: Bitmap4,
    pub delegation: OpenDelegation4,
}

#[derive(Debug)]
pub struct ReadRes4 {
    pub eof: bool,
    pub data: bytes::Bytes,
}

#[derive(Debug)]
pub struct WriteRes4 {
    pub count: Count4,
    pub committed: u32,
    pub writeverf: Verifier4,
}

#[derive(Debug)]
pub struct ReaddirRes4 {
    pub cookieverf: Verifier4,
    pub entries: Vec<Entry4>,
    pub eof: bool,
}

#[derive(Debug)]
pub struct Entry4 {
    pub cookie: u64,
    pub name: String,
    pub attrs: Fattr4,
}

/// A single operation result.
#[derive(Debug)]
pub enum NfsResop4 {
    Access(NfsStat4, u32, u32),
    Close(NfsStat4, Stateid4),
    Commit(NfsStat4, Verifier4),
    Create(NfsStat4, Option<ChangeInfo4>, Bitmap4),
    Getattr(NfsStat4, Option<Fattr4>),
    Getfh(NfsStat4, Option<NfsFh4>),
    Link(NfsStat4, Option<ChangeInfo4>),
    Lookup(NfsStat4),
    Lookupp(NfsStat4),
    Open(NfsStat4, Option<OpenRes4>),
    Putfh(NfsStat4),
    Putpubfh(NfsStat4),
    Putrootfh(NfsStat4),
    Read(NfsStat4, Option<ReadRes4>),
    Readdir(NfsStat4, Option<ReaddirRes4>),
    Readlink(NfsStat4, Option<String>),
    Remove(NfsStat4, Option<ChangeInfo4>),
    Rename(NfsStat4, Option<ChangeInfo4>, Option<ChangeInfo4>),
    Restorefh(NfsStat4),
    Savefh(NfsStat4),
    Secinfo(NfsStat4, Vec<SecinfoEntry4>),
    Setattr(NfsStat4, Bitmap4),
    Write(NfsStat4, Option<WriteRes4>),
    ExchangeId(NfsStat4, Option<ExchangeIdRes4>),
    CreateSession(NfsStat4, Option<CreateSessionRes4>),
    DestroySession(NfsStat4),
    Sequence(NfsStat4, Option<SequenceRes4>),
    ReclaimComplete(NfsStat4),
    DestroyClientid(NfsStat4),
    BindConnToSession(NfsStat4, Option<BindConnToSessionRes4>),
    SecInfoNoName(NfsStat4, Vec<SecinfoEntry4>),
    FreeStateid(NfsStat4),
    TestStateid(NfsStat4, Vec<NfsStat4>),
    DelegReturn(NfsStat4),
    MustNotImplement(MustNotImplementOp4, NfsStat4),
    Lock(NfsStat4, Option<Stateid4>, Option<LockDenied4>),
    Lockt(NfsStat4, Option<LockDenied4>),
    Locku(NfsStat4, Option<Stateid4>),
    OpenAttr(NfsStat4),
    DelegPurge(NfsStat4),
    Verify(NfsStat4),
    Nverify(NfsStat4),
    OpenDowngrade(NfsStat4, Option<Stateid4>),
    LayoutGet(NfsStat4, Option<LayoutGetRes4>),
    LayoutReturn(NfsStat4, Option<LayoutReturnStateid4>),
    LayoutCommit(NfsStat4, Option<LayoutCommitResOk4>),
    GetDirDelegation(NfsStat4, Option<GetDirDelegationRes4>),
    WantDelegation(NfsStat4, Option<OpenDelegation4>),
    BackchannelCtl(NfsStat4),
    GetDeviceInfo(NfsStat4, Option<GetDeviceInfoRes4>),
    GetDeviceList(NfsStat4, Option<GetDeviceListResOk4>),
    SetSsv(NfsStat4, Option<SetSsvResOk4>),
    Illegal(NfsStat4),
}
