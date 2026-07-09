use crate::xdr::*;
/// Sun RPC (ONC RPC) message types per RFC 5531.
use bytes::{Bytes, BytesMut};

pub const RPC_VERSION: u32 = 2;
pub const NFS_PROGRAM: u32 = 100003;
pub const NFS_V4: u32 = 4;
pub const NFS_CB_PROGRAM: u32 = 0x40000000;

/// RPC message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Call = 0,
    Reply = 1,
}

impl XdrEncode for MsgType {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

impl XdrDecode for MsgType {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        match u32::decode(src)? {
            0 => Ok(MsgType::Call),
            1 => Ok(MsgType::Reply),
            v => Err(XdrError::InvalidEnum(v)),
        }
    }
}

/// RPC reply status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyStat {
    Accepted = 0,
    Denied = 1,
}

impl XdrEncode for ReplyStat {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

/// Accept status in an accepted reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptStat {
    Success = 0,
    ProgUnavail = 1,
    ProgMismatch = 2,
    ProcUnavail = 3,
    GarbageArgs = 4,
    SystemErr = 5,
}

impl XdrEncode for AcceptStat {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

/// Authentication failure status for rejected replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStat {
    Ok = 0,
    BadCred = 1,
    RejectedCred = 2,
    BadVerf = 3,
    RejectedVerf = 4,
    TooWeak = 5,
    InvalidResp = 6,
    Failed = 7,
    KerbGeneric = 8,
    TimeExpire = 9,
    TktFile = 10,
    Decode = 11,
    NetAddr = 12,
    RpcsecGssCredProblem = 13,
    RpcsecGssCtxProblem = 14,
}

impl XdrEncode for AuthStat {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

/// Auth flavor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFlavor {
    None = 0,
    Sys = 1,
    Short = 2,
    Dh = 3,
    RpcSecGss = 6,
}

impl XdrDecode for AuthFlavor {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        match u32::decode(src)? {
            0 => Ok(AuthFlavor::None),
            1 => Ok(AuthFlavor::Sys),
            2 => Ok(AuthFlavor::Short),
            3 => Ok(AuthFlavor::Dh),
            6 => Ok(AuthFlavor::RpcSecGss),
            v => Err(XdrError::InvalidEnum(v)),
        }
    }
}

impl XdrEncode for AuthFlavor {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

/// Opaque auth (credential or verifier).
#[derive(Debug, Clone)]
pub struct OpaqueAuth {
    pub flavor: u32,
    pub body: Bytes,
}

impl XdrEncode for OpaqueAuth {
    fn encode(&self, dst: &mut BytesMut) {
        self.flavor.encode(dst);
        encode_opaque(dst, &self.body);
    }
}

impl XdrDecode for OpaqueAuth {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let flavor = u32::decode(src)?;
        let body = decode_opaque_max(src, 400)?;
        Ok(OpaqueAuth { flavor, body })
    }
}

impl OpaqueAuth {
    pub fn null() -> Self {
        OpaqueAuth {
            flavor: 0,
            body: Bytes::new(),
        }
    }
}

/// AUTH_SYS credentials.
#[derive(Debug, Clone)]
pub struct AuthSysParams {
    pub stamp: u32,
    pub machinename: String,
    pub uid: u32,
    pub gid: u32,
    pub gids: Vec<u32>,
}

impl XdrDecode for AuthSysParams {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let stamp = u32::decode(src)?;
        let machinename = decode_string_max(src, 255)?;
        let uid = u32::decode(src)?;
        let gid = u32::decode(src)?;
        let gids = decode_list_max(src, 16)?;
        Ok(AuthSysParams {
            stamp,
            machinename,
            uid,
            gid,
            gids,
        })
    }
}

/// RPC call header.
#[derive(Debug, Clone)]
pub struct RpcCallHeader {
    pub xid: u32,
    pub rpcvers: u32,
    pub prog: u32,
    pub vers: u32,
    pub proc_num: u32,
    pub cred: OpaqueAuth,
    pub verf: OpaqueAuth,
}

impl XdrDecode for RpcCallHeader {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let xid = u32::decode(src)?;
        let msg_type = u32::decode(src)?;
        if msg_type != 0 {
            return Err(XdrError::InvalidEnum(msg_type));
        }
        let rpcvers = u32::decode(src)?;
        let prog = u32::decode(src)?;
        let vers = u32::decode(src)?;
        let proc_num = u32::decode(src)?;
        let cred = OpaqueAuth::decode(src)?;
        let verf = OpaqueAuth::decode(src)?;
        Ok(RpcCallHeader {
            xid,
            rpcvers,
            prog,
            vers,
            proc_num,
            cred,
            verf,
        })
    }
}

/// Encode a successful RPC reply header.
pub fn encode_rpc_reply_accepted(dst: &mut BytesMut, xid: u32) {
    xid.encode(dst);
    MsgType::Reply.encode(dst);
    ReplyStat::Accepted.encode(dst);
    // Verifier: AUTH_NONE
    OpaqueAuth::null().encode(dst);
    AcceptStat::Success.encode(dst);
}

/// Encode an RPC reply with PROG_MISMATCH.
pub fn encode_rpc_reply_prog_mismatch(dst: &mut BytesMut, xid: u32, low: u32, high: u32) {
    xid.encode(dst);
    MsgType::Reply.encode(dst);
    ReplyStat::Accepted.encode(dst);
    OpaqueAuth::null().encode(dst);
    AcceptStat::ProgMismatch.encode(dst);
    low.encode(dst);
    high.encode(dst);
}

/// Encode an RPC reply with PROC_UNAVAIL.
pub fn encode_rpc_reply_proc_unavail(dst: &mut BytesMut, xid: u32) {
    xid.encode(dst);
    MsgType::Reply.encode(dst);
    ReplyStat::Accepted.encode(dst);
    OpaqueAuth::null().encode(dst);
    AcceptStat::ProcUnavail.encode(dst);
}

/// Encode an RPC reply rejected due to authentication failure.
pub fn encode_rpc_reply_auth_error(dst: &mut BytesMut, xid: u32, auth: AuthStat) {
    xid.encode(dst);
    MsgType::Reply.encode(dst);
    ReplyStat::Denied.encode(dst);
    1u32.encode(dst);
    auth.encode(dst);
}
