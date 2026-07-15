//! Binary blob helpers shared by mediated host adapters.
//!
//! The Wasm boundary only sees `(ptr, len)` byte blobs. This module is the
//! shared definition for how those blobs are encoded.

use crate::host::HostError;

const MAX_STRING_LEN: usize = 64 * 1024;
const MAX_HEADERS: usize = 256;
const MAX_LIST_ENTRIES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub wallet: String,
    pub hash32: [u8; 32],
    pub purpose: String,
    pub context: Option<PetalRouteContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignBatchRequest {
    pub requests: Vec<SignRequest>,
}

/// Result of a structured component signing request.
///
/// Unlike the legacy `sign_hash` error-only protocol, this makes a pending
/// Sealed Approval ceremony machine-readable so a component can persist it
/// and retry the exact prepared request after approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequired {
    pub action_id: String,
    pub ceremony_url: String,
    pub expires_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignOutcome {
    Signature(Vec<u8>),
    ApprovalRequired(ApprovalRequired),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignBatchOutcome {
    Signatures(Vec<Vec<u8>>),
    ApprovalRequired(ApprovalRequired),
}

/// A generic EVM transaction prepared by a Petal route. Route provenance is
/// injected by the runner and never supplied by the component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmTransactionRequest {
    pub wallet: String,
    pub chain: String,
    pub to: String,
    pub value_wei: String,
    pub data_hex: String,
    pub nonce: Option<u64>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub context: Option<PetalRouteContext>,
}

/// Generic staged-EVM transaction state returned through
/// `bloom:tx/outbox@0.1.0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmOutboxOutcome {
    pub outbox_id: String,
    pub plan_md: String,
    pub approval_required: Option<ApprovalRequired>,
}

/// Read-only projection of a generic EVM outbox entry. `receipt_json` is the
/// persisted generic mined receipt, not a venue-specific receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmOutboxInspection {
    pub outbox_id: String,
    pub state: String,
    pub tx_hash: Option<String>,
    pub receipt_json: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetalRouteContext {
    pub petal_root: String,
    pub package_hash: String,
    pub route_id: String,
    pub op: String,
    pub path: String,
    pub params: Vec<(String, String)>,
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRequest {
    pub chain: String,
    pub method: String,
    pub params_json: String,
    /// Trusted route provenance injected by the runner, never the component.
    pub context: Option<PetalRouteContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainResponse {
    pub result_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchOp {
    Lookup,
    List,
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchRequest {
    pub op: DispatchOp,
    pub path: String,
    pub body: Vec<u8>,
    pub ctx: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchEntryKind {
    Dir,
    File,
    WritableFile,
    ExecutableFile,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchEntry {
    pub name: String,
    pub kind: DispatchEntryKind,
    pub size: u64,
    pub mode: u32,
    pub ttl_hint_ms: Option<u64>,
    pub link_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchResponse {
    Lookup(DispatchEntry),
    List(Vec<DispatchEntry>),
    Read(Vec<u8>),
    Write,
    Error { code: i32, message: String },
}

pub fn encode_http_request(req: &HttpRequest) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, &req.method);
    put_string(&mut out, &req.url);
    put_headers(&mut out, &req.headers);
    put_bytes(&mut out, &req.body);
    out
}

pub fn encode_dispatch_request(req: &DispatchRequest) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(match req.op {
        DispatchOp::Lookup => 0,
        DispatchOp::List => 1,
        DispatchOp::Read => 2,
        DispatchOp::Write => 3,
    });
    put_string(&mut out, &req.path);
    put_bytes(&mut out, &req.body);
    put_headers(&mut out, &req.ctx);
    out
}

pub fn decode_dispatch_request(bytes: &[u8]) -> Result<DispatchRequest, HostError> {
    let mut r = Reader::new(bytes);
    let op = match r.u8()? {
        0 => DispatchOp::Lookup,
        1 => DispatchOp::List,
        2 => DispatchOp::Read,
        3 => DispatchOp::Write,
        _ => return Err(HostError::Invalid("unknown dispatch op".into())),
    };
    let path = r.string()?;
    let body = r.bytes()?.to_vec();
    let ctx = r.headers()?;
    r.finish()?;
    Ok(DispatchRequest {
        op,
        path,
        body,
        ctx,
    })
}

pub fn encode_dispatch_response(resp: &DispatchResponse) -> Vec<u8> {
    let mut out = Vec::new();
    match resp {
        DispatchResponse::Lookup(entry) => {
            out.push(0);
            put_entry(&mut out, entry);
        }
        DispatchResponse::List(entries) => {
            out.push(1);
            put_u32(&mut out, entries.len() as u32);
            for entry in entries {
                put_entry(&mut out, entry);
            }
        }
        DispatchResponse::Read(bytes) => {
            out.push(2);
            put_bytes(&mut out, bytes);
        }
        DispatchResponse::Write => out.push(3),
        DispatchResponse::Error { code, message } => {
            out.push(4);
            put_i32(&mut out, *code);
            put_string(&mut out, message);
        }
    }
    out
}

pub fn decode_dispatch_response(bytes: &[u8]) -> Result<DispatchResponse, HostError> {
    let mut r = Reader::new(bytes);
    let response = match r.u8()? {
        0 => DispatchResponse::Lookup(r.entry()?),
        1 => {
            let count = r.u32()? as usize;
            if count > MAX_LIST_ENTRIES {
                return Err(HostError::Invalid("too many dispatch entries".into()));
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                entries.push(r.entry()?);
            }
            DispatchResponse::List(entries)
        }
        2 => DispatchResponse::Read(r.bytes()?.to_vec()),
        3 => DispatchResponse::Write,
        4 => DispatchResponse::Error {
            code: r.i32()?,
            message: r.string()?,
        },
        _ => return Err(HostError::Invalid("unknown dispatch response tag".into())),
    };
    r.finish()?;
    Ok(response)
}

pub fn decode_http_request(bytes: &[u8]) -> Result<HttpRequest, HostError> {
    let mut r = Reader::new(bytes);
    let method = r.string()?;
    let url = r.string()?;
    let headers = r.headers()?;
    let body = r.bytes()?.to_vec();
    r.finish()?;
    Ok(HttpRequest {
        method,
        url,
        headers,
        body,
    })
}

pub fn encode_http_response(resp: &HttpResponse) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, resp.status as u32);
    put_headers(&mut out, &resp.headers);
    put_bytes(&mut out, &resp.body);
    out
}

pub fn decode_http_response(bytes: &[u8]) -> Result<HttpResponse, HostError> {
    let mut r = Reader::new(bytes);
    let status = r.u32()?;
    if status > u16::MAX as u32 {
        return Err(HostError::Invalid("http status out of range".into()));
    }
    let headers = r.headers()?;
    let body = r.bytes()?.to_vec();
    r.finish()?;
    Ok(HttpResponse {
        status: status as u16,
        headers,
        body,
    })
}

pub fn encode_sign_request(req: &SignRequest) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, &req.wallet);
    put_bytes(&mut out, &req.hash32);
    put_string(&mut out, &req.purpose);
    out
}

pub fn decode_sign_request(bytes: &[u8]) -> Result<SignRequest, HostError> {
    let mut r = Reader::new(bytes);
    let wallet = r.string()?;
    let hash = r.bytes()?;
    if hash.len() != 32 {
        return Err(HostError::Invalid(
            "sign_hash requires a 32-byte hash".into(),
        ));
    }
    let mut hash32 = [0u8; 32];
    hash32.copy_from_slice(hash);
    let purpose = r.string()?;
    r.finish()?;
    Ok(SignRequest {
        wallet,
        hash32,
        purpose,
        context: None,
    })
}

pub fn encode_string_list(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, items.len() as u32);
    for item in items {
        put_string(&mut out, item);
    }
    out
}

pub fn decode_string_list(bytes: &[u8]) -> Result<Vec<String>, HostError> {
    let mut r = Reader::new(bytes);
    let count = r.u32()? as usize;
    if count > MAX_HEADERS {
        return Err(HostError::Invalid("too many strings".into()));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.string()?);
    }
    r.finish()?;
    Ok(out)
}

fn put_headers(out: &mut Vec<u8>, headers: &[(String, String)]) {
    put_u32(out, headers.len() as u32);
    for (name, value) in headers {
        put_string(out, name);
        put_string(out, value);
    }
}

fn put_entry(out: &mut Vec<u8>, entry: &DispatchEntry) {
    put_string(out, &entry.name);
    out.push(match entry.kind {
        DispatchEntryKind::Dir => 0,
        DispatchEntryKind::File => 1,
        DispatchEntryKind::WritableFile => 2,
        DispatchEntryKind::ExecutableFile => 3,
        DispatchEntryKind::Symlink => 4,
    });
    put_u64(out, entry.size);
    put_u32(out, entry.mode);
    put_opt_u64(out, entry.ttl_hint_ms);
    put_opt_string(out, entry.link_target.as_deref());
}

fn put_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            put_u64(out, value);
        }
        None => out.push(0),
    }
}

fn put_opt_string(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            put_string(out, value);
        }
        None => out.push(0),
    }
}

fn put_string(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_i32(out: &mut Vec<u8>, n: i32) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> Result<(), HostError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(HostError::Invalid("trailing ABI bytes".into()))
        }
    }

    fn u8(&mut self) -> Result<u8, HostError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, HostError> {
        let raw = self.take(4)?;
        Ok(u32::from_le_bytes(raw.try_into().expect("len checked")))
    }

    fn i32(&mut self) -> Result<i32, HostError> {
        let raw = self.take(4)?;
        Ok(i32::from_le_bytes(raw.try_into().expect("len checked")))
    }

    fn u64(&mut self) -> Result<u64, HostError> {
        let raw = self.take(8)?;
        Ok(u64::from_le_bytes(raw.try_into().expect("len checked")))
    }

    fn bytes(&mut self) -> Result<&'a [u8], HostError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn string(&mut self) -> Result<String, HostError> {
        let bytes = self.bytes()?;
        if bytes.len() > MAX_STRING_LEN {
            return Err(HostError::Invalid("string too large".into()));
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| HostError::Invalid("string not utf-8".into()))
    }

    fn headers(&mut self) -> Result<Vec<(String, String)>, HostError> {
        let count = self.u32()? as usize;
        if count > MAX_HEADERS {
            return Err(HostError::Invalid("too many headers".into()));
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push((self.string()?, self.string()?));
        }
        Ok(out)
    }

    fn entry(&mut self) -> Result<DispatchEntry, HostError> {
        let name = self.string()?;
        let kind = match self.u8()? {
            0 => DispatchEntryKind::Dir,
            1 => DispatchEntryKind::File,
            2 => DispatchEntryKind::WritableFile,
            3 => DispatchEntryKind::ExecutableFile,
            4 => DispatchEntryKind::Symlink,
            _ => return Err(HostError::Invalid("unknown dispatch entry kind".into())),
        };
        let size = self.u64()?;
        let mode = self.u32()?;
        let ttl_hint_ms = self.opt_u64()?;
        let link_target = self.opt_string()?;
        Ok(DispatchEntry {
            name,
            kind,
            size,
            mode,
            ttl_hint_ms,
            link_target,
        })
    }

    fn opt_u64(&mut self) -> Result<Option<u64>, HostError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(HostError::Invalid("invalid option tag".into())),
        }
    }

    fn opt_string(&mut self) -> Result<Option<String>, HostError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.string()?)),
            _ => Err(HostError::Invalid("invalid option tag".into())),
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], HostError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| HostError::Invalid("ABI length overflow".into()))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| HostError::Invalid("truncated ABI bytes".into()))?;
        self.offset = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_roundtrip() {
        let req = HttpRequest {
            method: "POST".into(),
            url: "https://api.example.com/order".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"ok":true}"#.to_vec(),
        };
        assert_eq!(
            decode_http_request(&encode_http_request(&req)).unwrap(),
            req
        );
    }

    #[test]
    fn sign_request_requires_hash32() {
        let mut bad = Vec::new();
        put_string(&mut bad, "wallet");
        put_bytes(&mut bad, b"short");
        put_string(&mut bad, "purpose");
        assert!(matches!(
            decode_sign_request(&bad),
            Err(HostError::Invalid(_))
        ));
    }

    #[test]
    fn dispatch_roundtrip() {
        let req = DispatchRequest {
            op: DispatchOp::Write,
            path: "orders/new".into(),
            body: b"body".to_vec(),
            ctx: vec![("wallet".into(), "alice".into())],
        };
        assert_eq!(
            decode_dispatch_request(&encode_dispatch_request(&req)).unwrap(),
            req
        );

        let resp = DispatchResponse::List(vec![DispatchEntry {
            name: "status.json".into(),
            kind: DispatchEntryKind::File,
            size: 12,
            mode: 0o444,
            ttl_hint_ms: Some(5000),
            link_target: None,
        }]);
        assert_eq!(
            decode_dispatch_response(&encode_dispatch_response(&resp)).unwrap(),
            resp
        );
    }
}
