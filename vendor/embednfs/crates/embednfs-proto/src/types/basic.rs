use bytes::{Buf, Bytes, BytesMut};

use crate::xdr::*;

pub type Offset4 = u64;
pub type Count4 = u32;
pub type Length4 = u64;
pub type Changeid4 = u64;
pub type Clientid4 = u64;
pub type Seqid4 = u32;
pub type Sequenceid4 = u32;
pub type Slotid4 = u32;
pub type Sessionid4 = [u8; 16];
pub type Deviceid4 = [u8; 16];
pub type Verifier4 = [u8; 8];

/// NFS file handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NfsFh4(pub Bytes);

impl XdrEncode for NfsFh4 {
    fn encode(&self, dst: &mut BytesMut) {
        encode_opaque(dst, &self.0);
    }
}

impl XdrDecode for NfsFh4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let data = decode_opaque_max(src, 128)?;
        Ok(NfsFh4(data))
    }
}

/// NFS status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsStat4 {
    Ok = 0,
    Perm = 1,
    Noent = 2,
    Io = 5,
    Nxio = 6,
    Access = 13,
    Exist = 17,
    Xdev = 18,
    Notdir = 20,
    Isdir = 21,
    Inval = 22,
    Fbig = 27,
    Nospc = 28,
    Rofs = 30,
    Mlink = 31,
    Nametoolong = 63,
    Notempty = 66,
    Dquot = 69,
    Stale = 70,
    Badhandle = 10001,
    BadCookie = 10003,
    Notsupp = 10004,
    Toosmall = 10005,
    Serverfault = 10006,
    Badtype = 10007,
    Delay = 10008,
    Same = 10009,
    Denied = 10010,
    Expired = 10011,
    Locked = 10012,
    Grace = 10013,
    Fhexpired = 10014,
    ShareDenied = 10015,
    WrongSec = 10016,
    ClidInuse = 10017,
    Moved = 10019,
    Nofilehandle = 10020,
    MinorVersMismatch = 10021,
    StaleClientid = 10022,
    StaleStateid = 10023,
    OldStateid = 10024,
    BadStateid = 10025,
    BadSeqid = 10026,
    NotSame = 10027,
    LockRange = 10028,
    Symlink = 10029,
    Restorefh = 10030,
    LeaseMoved = 10031,
    AttrNotsupp = 10032,
    NoGrace = 10033,
    ReclaimBad = 10034,
    ReclaimConflict = 10035,
    BadXdr = 10036,
    LocksHeld = 10037,
    Openmode = 10038,
    BadOwner = 10039,
    Badchar = 10040,
    Badname = 10041,
    BadRange = 10042,
    LockNotsupp = 10043,
    OpIllegal = 10044,
    Deadlock = 10045,
    FileOpen = 10046,
    AdminRevoked = 10047,
    CbPathDown = 10048,
    BadIomode = 10049,
    BadLayout = 10050,
    BadSessionDigest = 10051,
    BadSession = 10052,
    BadSlot = 10053,
    CompleteAlready = 10054,
    ConnNotBoundToSession = 10055,
    DelegAlreadyWanted = 10056,
    BackChanBusy = 10057,
    LayoutTrylater = 10058,
    LayoutUnavailable = 10059,
    NomatchingLayout = 10060,
    RecallConflict = 10061,
    UnknownLayouttype = 10062,
    SeqMisordered = 10063,
    SequencePos = 10064,
    ReqTooBig = 10065,
    RepTooBig = 10066,
    RepTooBigToCache = 10067,
    RetryUncachedRep = 10068,
    UnsafeCompound = 10069,
    TooManyOps = 10070,
    OpNotInSession = 10071,
    HashAlgUnsupp = 10072,
    ClientidBusy = 10074,
    PnfsIoHole = 10075,
    SeqFalseRetry = 10076,
    BadHighSlot = 10077,
    DeadSession = 10078,
    EncrAlgUnsupp = 10079,
    PnfsNoLayout = 10080,
    NotOnlyOp = 10081,
    WrongCred = 10082,
    WrongType = 10083,
    DirDelegUnavail = 10084,
    RejectDeleg = 10085,
    ReturnConflict = 10086,
    DelegRevoked = 10087,
}

impl NfsStat4 {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => NfsStat4::Ok,
            1 => NfsStat4::Perm,
            2 => NfsStat4::Noent,
            5 => NfsStat4::Io,
            6 => NfsStat4::Nxio,
            13 => NfsStat4::Access,
            17 => NfsStat4::Exist,
            18 => NfsStat4::Xdev,
            20 => NfsStat4::Notdir,
            21 => NfsStat4::Isdir,
            22 => NfsStat4::Inval,
            27 => NfsStat4::Fbig,
            28 => NfsStat4::Nospc,
            30 => NfsStat4::Rofs,
            31 => NfsStat4::Mlink,
            63 => NfsStat4::Nametoolong,
            66 => NfsStat4::Notempty,
            69 => NfsStat4::Dquot,
            70 => NfsStat4::Stale,
            10001 => NfsStat4::Badhandle,
            10003 => NfsStat4::BadCookie,
            10004 => NfsStat4::Notsupp,
            10005 => NfsStat4::Toosmall,
            10006 => NfsStat4::Serverfault,
            10007 => NfsStat4::Badtype,
            10008 => NfsStat4::Delay,
            10009 => NfsStat4::Same,
            10010 => NfsStat4::Denied,
            10011 => NfsStat4::Expired,
            10012 => NfsStat4::Locked,
            10013 => NfsStat4::Grace,
            10014 => NfsStat4::Fhexpired,
            10015 => NfsStat4::ShareDenied,
            10016 => NfsStat4::WrongSec,
            10017 => NfsStat4::ClidInuse,
            10019 => NfsStat4::Moved,
            10020 => NfsStat4::Nofilehandle,
            10021 => NfsStat4::MinorVersMismatch,
            10022 => NfsStat4::StaleClientid,
            10023 => NfsStat4::StaleStateid,
            10024 => NfsStat4::OldStateid,
            10025 => NfsStat4::BadStateid,
            10026 => NfsStat4::BadSeqid,
            10027 => NfsStat4::NotSame,
            10028 => NfsStat4::LockRange,
            10029 => NfsStat4::Symlink,
            10030 => NfsStat4::Restorefh,
            10031 => NfsStat4::LeaseMoved,
            10032 => NfsStat4::AttrNotsupp,
            10033 => NfsStat4::NoGrace,
            10034 => NfsStat4::ReclaimBad,
            10035 => NfsStat4::ReclaimConflict,
            10036 => NfsStat4::BadXdr,
            10037 => NfsStat4::LocksHeld,
            10038 => NfsStat4::Openmode,
            10039 => NfsStat4::BadOwner,
            10040 => NfsStat4::Badchar,
            10041 => NfsStat4::Badname,
            10042 => NfsStat4::BadRange,
            10043 => NfsStat4::LockNotsupp,
            10044 => NfsStat4::OpIllegal,
            10045 => NfsStat4::Deadlock,
            10046 => NfsStat4::FileOpen,
            10047 => NfsStat4::AdminRevoked,
            10048 => NfsStat4::CbPathDown,
            10049 => NfsStat4::BadIomode,
            10050 => NfsStat4::BadLayout,
            10051 => NfsStat4::BadSessionDigest,
            10052 => NfsStat4::BadSession,
            10053 => NfsStat4::BadSlot,
            10054 => NfsStat4::CompleteAlready,
            10055 => NfsStat4::ConnNotBoundToSession,
            10056 => NfsStat4::DelegAlreadyWanted,
            10057 => NfsStat4::BackChanBusy,
            10058 => NfsStat4::LayoutTrylater,
            10059 => NfsStat4::LayoutUnavailable,
            10060 => NfsStat4::NomatchingLayout,
            10061 => NfsStat4::RecallConflict,
            10062 => NfsStat4::UnknownLayouttype,
            10063 => NfsStat4::SeqMisordered,
            10064 => NfsStat4::SequencePos,
            10065 => NfsStat4::ReqTooBig,
            10066 => NfsStat4::RepTooBig,
            10067 => NfsStat4::RepTooBigToCache,
            10068 => NfsStat4::RetryUncachedRep,
            10069 => NfsStat4::UnsafeCompound,
            10070 => NfsStat4::TooManyOps,
            10071 => NfsStat4::OpNotInSession,
            10072 => NfsStat4::HashAlgUnsupp,
            10074 => NfsStat4::ClientidBusy,
            10075 => NfsStat4::PnfsIoHole,
            10076 => NfsStat4::SeqFalseRetry,
            10077 => NfsStat4::BadHighSlot,
            10078 => NfsStat4::DeadSession,
            10079 => NfsStat4::EncrAlgUnsupp,
            10080 => NfsStat4::PnfsNoLayout,
            10081 => NfsStat4::NotOnlyOp,
            10082 => NfsStat4::WrongCred,
            10083 => NfsStat4::WrongType,
            10084 => NfsStat4::DirDelegUnavail,
            10085 => NfsStat4::RejectDeleg,
            10086 => NfsStat4::ReturnConflict,
            10087 => NfsStat4::DelegRevoked,
            _ => return None,
        })
    }
}

impl XdrEncode for NfsStat4 {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

impl XdrDecode for NfsStat4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let value = u32::decode(src)?;
        NfsStat4::from_u32(value).ok_or(XdrError::InvalidEnum(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsFtype4 {
    Reg = 1,
    Dir = 2,
    Blk = 3,
    Chr = 4,
    Lnk = 5,
    Sock = 6,
    Fifo = 7,
    AttrDir = 8,
    NamedAttr = 9,
}

impl XdrEncode for NfsFtype4 {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

impl XdrDecode for NfsFtype4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        match u32::decode(src)? {
            1 => Ok(NfsFtype4::Reg),
            2 => Ok(NfsFtype4::Dir),
            3 => Ok(NfsFtype4::Blk),
            4 => Ok(NfsFtype4::Chr),
            5 => Ok(NfsFtype4::Lnk),
            6 => Ok(NfsFtype4::Sock),
            7 => Ok(NfsFtype4::Fifo),
            8 => Ok(NfsFtype4::AttrDir),
            9 => Ok(NfsFtype4::NamedAttr),
            v => Err(XdrError::InvalidEnum(v)),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NfsTime4 {
    pub seconds: i64,
    pub nseconds: u32,
}

impl XdrEncode for NfsTime4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.seconds.encode(dst);
        self.nseconds.encode(dst);
    }
}

impl XdrDecode for NfsTime4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        Ok(NfsTime4 {
            seconds: i64::decode(src)?,
            nseconds: u32::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Stateid4 {
    pub seqid: u32,
    pub other: [u8; 12],
}

impl Stateid4 {
    pub const ANONYMOUS: Stateid4 = Stateid4 {
        seqid: 0,
        other: [0; 12],
    };
    pub const CURRENT: Stateid4 = Stateid4 {
        seqid: 1,
        other: [0; 12],
    };
    pub const BYPASS: Stateid4 = Stateid4 {
        seqid: 0xffffffff,
        other: [0xff; 12],
    };
}

impl XdrEncode for Stateid4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.seqid.encode(dst);
        dst.extend_from_slice(&self.other);
    }
}

impl XdrDecode for Stateid4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let seqid = u32::decode(src)?;
        let other_data = decode_fixed_opaque(src, 12)?;
        let mut other = [0u8; 12];
        other.copy_from_slice(&other_data);
        Ok(Stateid4 { seqid, other })
    }
}

/// Bitmap4 - variable length bitmap for file attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bitmap4(pub Vec<u32>);

impl Bitmap4 {
    pub fn new() -> Self {
        Bitmap4(vec![])
    }

    pub fn is_set(&self, bit: u32) -> bool {
        let word = (bit / 32) as usize;
        let mask = 1u32 << (bit % 32);
        self.0.get(word).is_some_and(|w| w & mask != 0)
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "the loop below grows the bitmap through the requested word"
    )]
    pub fn set(&mut self, bit: u32) {
        let word = (bit / 32) as usize;
        let mask = 1u32 << (bit % 32);
        while self.0.len() <= word {
            self.0.push(0);
        }
        self.0[word] |= mask;
    }
}

impl XdrEncode for Bitmap4 {
    fn encode(&self, dst: &mut BytesMut) {
        let trimmed_len = self
            .0
            .iter()
            .rposition(|word| *word != 0)
            .map_or(0, |idx| idx + 1);
        (trimmed_len as u32).encode(dst);
        for w in self.0.iter().take(trimmed_len) {
            w.encode(dst);
        }
    }
}

impl XdrDecode for Bitmap4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let count = u32::decode(src)? as usize;
        let bytes_needed = count
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or(XdrError::Overflow)?;
        if src.remaining() < bytes_needed {
            return Err(XdrError::Underflow);
        }
        let mut words = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            words.push(u32::decode(src)?);
        }
        Ok(Bitmap4(words))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Fsid4 {
    pub major: u64,
    pub minor: u64,
}

impl XdrEncode for Fsid4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.major.encode(dst);
        self.minor.encode(dst);
    }
}

impl XdrDecode for Fsid4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        Ok(Fsid4 {
            major: u64::decode(src)?,
            minor: u64::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Specdata4 {
    pub specdata1: u32,
    pub specdata2: u32,
}

impl XdrEncode for Specdata4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.specdata1.encode(dst);
        self.specdata2.encode(dst);
    }
}

/// Fattr4 - file attributes with bitmap + opaque value.
#[derive(Debug, Clone)]
pub struct Fattr4 {
    pub attrmask: Bitmap4,
    pub attr_vals: Bytes,
}

impl XdrEncode for Fattr4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.attrmask.encode(dst);
        encode_opaque(dst, &self.attr_vals);
    }
}

impl XdrDecode for Fattr4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        Ok(Fattr4 {
            attrmask: Bitmap4::decode(src)?,
            attr_vals: decode_opaque(src)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ChangeInfo4 {
    pub atomic: bool,
    pub before: Changeid4,
    pub after: Changeid4,
}

impl XdrEncode for ChangeInfo4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.atomic.encode(dst);
        self.before.encode(dst);
        self.after.encode(dst);
    }
}
