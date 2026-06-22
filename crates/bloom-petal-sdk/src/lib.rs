//! Guest-side SDK for Bloom local handler petals.
//!
//! This crate is intentionally independent of `bloom-petals`, which is the
//! host/runtime crate. Local petals can depend on this SDK to encode the
//! `bloom.v1` ABI, call host imports, and export a `petal_dispatch` entrypoint.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

const MAX_STRING_LEN: usize = 64 * 1024;
const MAX_HEADERS: usize = 256;
const MAX_LIST_ENTRIES: usize = 8192;
const OVERFLOW_BIAS: i32 = 0x10000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkError {
    UnexpectedEof,
    TrailingBytes,
    InvalidUtf8,
    StringTooLong,
    CountTooLarge,
    UnknownTag,
    NegativePtrLen,
    ResponseTooLarge,
    HostUnavailable,
    Host(HostStatus),
}

impl SdkError {
    pub fn message(&self) -> String {
        match self {
            SdkError::UnexpectedEof => "unexpected end of ABI bytes".into(),
            SdkError::TrailingBytes => "trailing ABI bytes".into(),
            SdkError::InvalidUtf8 => "ABI string is not utf-8".into(),
            SdkError::StringTooLong => "ABI string is too long".into(),
            SdkError::CountTooLarge => "ABI list count is too large".into(),
            SdkError::UnknownTag => "unknown ABI tag".into(),
            SdkError::NegativePtrLen => "negative pointer or length".into(),
            SdkError::ResponseTooLarge => "host response buffer is too large".into(),
            SdkError::HostUnavailable => "bloom.v1 host imports are unavailable".into(),
            SdkError::Host(status) => format!("host error: {status:?}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SdkError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    NotFound,
    Denied,
    Invalid,
    Backend,
    BufferTooSmall { needed: usize },
    Unknown(i32),
}

impl HostStatus {
    pub fn from_code(code: i32) -> Self {
        if code <= -OVERFLOW_BIAS {
            let needed = (-(code as i64) - OVERFLOW_BIAS as i64) as usize;
            return HostStatus::BufferTooSmall { needed };
        }
        match code {
            -1 => HostStatus::NotFound,
            -2 => HostStatus::Denied,
            -3 => HostStatus::Invalid,
            -4 => HostStatus::Backend,
            other => HostStatus::Unknown(other),
        }
    }
}

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

pub fn decode_http_response(bytes: &[u8]) -> Result<HttpResponse, SdkError> {
    let mut r = Reader::new(bytes);
    let status = r.u32()?;
    if status > u16::MAX as u32 {
        return Err(SdkError::UnknownTag);
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

pub fn encode_string_list(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, items.len() as u32);
    for item in items {
        put_string(&mut out, item);
    }
    out
}

pub fn decode_string_list(bytes: &[u8]) -> Result<Vec<String>, SdkError> {
    let mut r = Reader::new(bytes);
    let count = r.u32()? as usize;
    if count > MAX_HEADERS {
        return Err(SdkError::CountTooLarge);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.string()?);
    }
    r.finish()?;
    Ok(out)
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

pub fn decode_dispatch_request(bytes: &[u8]) -> Result<DispatchRequest, SdkError> {
    let mut r = Reader::new(bytes);
    let op = match r.u8()? {
        0 => DispatchOp::Lookup,
        1 => DispatchOp::List,
        2 => DispatchOp::Read,
        3 => DispatchOp::Write,
        _ => return Err(SdkError::UnknownTag),
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

pub fn decode_dispatch_response(bytes: &[u8]) -> Result<DispatchResponse, SdkError> {
    let mut r = Reader::new(bytes);
    let response = match r.u8()? {
        0 => DispatchResponse::Lookup(r.entry()?),
        1 => {
            let count = r.u32()? as usize;
            if count > MAX_LIST_ENTRIES {
                return Err(SdkError::CountTooLarge);
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
        _ => return Err(SdkError::UnknownTag),
    };
    r.finish()?;
    Ok(response)
}

pub fn http_fetch(req: &HttpRequest, max_response_bytes: usize) -> Result<HttpResponse, SdkError> {
    let input = encode_http_request(req);
    #[cfg(not(target_arch = "wasm32"))]
    let raw = call_blob4_unavailable(&input, max_response_bytes)?;
    #[cfg(target_arch = "wasm32")]
    let raw = call_blob4_raw(&input, max_response_bytes, raw::http_fetch)?;
    decode_http_response(&raw)
}

pub fn sign_hash(req: &SignRequest) -> Result<Vec<u8>, SdkError> {
    let input = encode_sign_request(req);
    #[cfg(not(target_arch = "wasm32"))]
    {
        call_blob4_unavailable(&input, 65)
    }
    #[cfg(target_arch = "wasm32")]
    {
        call_blob4_raw(&input, 65, raw::sign_hash)
    }
}

pub fn vfs_read(path: &str, max_response_bytes: usize) -> Result<Vec<u8>, SdkError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        call_blob4_unavailable(path.as_bytes(), max_response_bytes)
    }
    #[cfg(target_arch = "wasm32")]
    {
        call_blob4_raw(path.as_bytes(), max_response_bytes, raw::vfs_read)
    }
}

pub fn vfs_list(path: &str, max_response_bytes: usize) -> Result<Vec<String>, SdkError> {
    #[cfg(not(target_arch = "wasm32"))]
    let raw = call_blob4_unavailable(path.as_bytes(), max_response_bytes)?;
    #[cfg(target_arch = "wasm32")]
    let raw = call_blob4_raw(path.as_bytes(), max_response_bytes, raw::vfs_list)?;
    decode_string_list(&raw)
}

pub fn vfs_write(path: &str, bytes: &[u8]) -> Result<(), SdkError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (path, bytes);
        Err(SdkError::HostUnavailable)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let status = unsafe {
            raw::vfs_write(
                path.as_ptr() as i32,
                checked_i32(path.len())?,
                bytes.as_ptr() as i32,
                checked_i32(bytes.len())?,
            )
        };
        host_unit(status)
    }
}

pub fn store_get(key: &str, max_response_bytes: usize) -> Result<Vec<u8>, SdkError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        call_blob4_unavailable(key.as_bytes(), max_response_bytes)
    }
    #[cfg(target_arch = "wasm32")]
    {
        call_blob4_raw(key.as_bytes(), max_response_bytes, raw::store_get)
    }
}

pub fn store_put(key: &str, value: &[u8], secret: bool) -> Result<(), SdkError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (key, value, secret);
        Err(SdkError::HostUnavailable)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let status = unsafe {
            raw::store_put(
                key.as_ptr() as i32,
                checked_i32(key.len())?,
                value.as_ptr() as i32,
                checked_i32(value.len())?,
                i32::from(secret),
            )
        };
        host_unit(status)
    }
}

pub fn store_put_new(key: &str, value: &[u8], secret: bool) -> Result<(), SdkError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (key, value, secret);
        Err(SdkError::HostUnavailable)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let status = unsafe {
            raw::store_put_new(
                key.as_ptr() as i32,
                checked_i32(key.len())?,
                value.as_ptr() as i32,
                checked_i32(value.len())?,
                i32::from(secret),
            )
        };
        host_unit(status)
    }
}

pub fn store_list(prefix: &str, max_response_bytes: usize) -> Result<Vec<String>, SdkError> {
    #[cfg(not(target_arch = "wasm32"))]
    let raw = call_blob4_unavailable(prefix.as_bytes(), max_response_bytes)?;
    #[cfg(target_arch = "wasm32")]
    let raw = call_blob4_raw(prefix.as_bytes(), max_response_bytes, raw::store_list)?;
    decode_string_list(&raw)
}

pub fn store_del(key: &str) -> Result<(), SdkError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = key;
        Err(SdkError::HostUnavailable)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let status = unsafe { raw::store_del(key.as_ptr() as i32, checked_i32(key.len())?) };
        host_unit(status)
    }
}

pub fn store_del_if_value(key: &str, expected: &[u8]) -> Result<(), SdkError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (key, expected);
        Err(SdkError::HostUnavailable)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let status = unsafe {
            raw::store_del_if_value(
                key.as_ptr() as i32,
                checked_i32(key.len())?,
                expected.as_ptr() as i32,
                checked_i32(expected.len())?,
            )
        };
        host_unit(status)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn petal_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

pub fn dispatch_export<F>(ptr: i32, len: i32, handler: F) -> i64
where
    F: FnOnce(DispatchRequest) -> DispatchResponse,
{
    let response = match read_guest_bytes(ptr, len) {
        Ok(bytes) => match decode_dispatch_request(&bytes) {
            Ok(req) => handler(req),
            Err(e) => DispatchResponse::Error {
                code: -3,
                message: e.message(),
            },
        },
        Err(e) => DispatchResponse::Error {
            code: -3,
            message: e.message(),
        },
    };
    pack_dispatch_response(response)
}

#[macro_export]
macro_rules! export_dispatch {
    ($handler:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn petal_dispatch(ptr: i32, len: i32) -> i64 {
            $crate::dispatch_export(ptr, len, $handler)
        }
    };
}

#[cfg(not(target_arch = "wasm32"))]
fn call_blob4_unavailable(input: &[u8], max_response_bytes: usize) -> Result<Vec<u8>, SdkError> {
    checked_i32(input.len())?;
    checked_i32(max_response_bytes)?;
    Err(SdkError::HostUnavailable)
}

#[cfg(target_arch = "wasm32")]
fn call_blob4_raw(
    input: &[u8],
    max_response_bytes: usize,
    raw_fn: unsafe extern "C" fn(i32, i32, i32, i32) -> i32,
) -> Result<Vec<u8>, SdkError> {
    checked_i32(input.len())?;
    checked_i32(max_response_bytes)?;
    let mut dst = Vec::<u8>::with_capacity(max_response_bytes);
    let status = unsafe {
        raw_fn(
            input.as_ptr() as i32,
            input.len() as i32,
            dst.as_mut_ptr() as i32,
            max_response_bytes as i32,
        )
    };
    let len = host_len(status, max_response_bytes)?;
    unsafe {
        dst.set_len(len);
    }
    Ok(dst)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn host_len(status: i32, max_response_bytes: usize) -> Result<usize, SdkError> {
    if status >= 0 {
        let len = status as usize;
        if len > max_response_bytes {
            Err(SdkError::ResponseTooLarge)
        } else {
            Ok(len)
        }
    } else {
        Err(SdkError::Host(HostStatus::from_code(status)))
    }
}

#[cfg(target_arch = "wasm32")]
fn host_unit(status: i32) -> Result<(), SdkError> {
    if status == 0 {
        Ok(())
    } else if status < 0 {
        Err(SdkError::Host(HostStatus::from_code(status)))
    } else {
        Err(SdkError::Host(HostStatus::Unknown(status)))
    }
}

fn checked_i32(len: usize) -> Result<i32, SdkError> {
    if len > i32::MAX as usize {
        Err(SdkError::ResponseTooLarge)
    } else {
        Ok(len as i32)
    }
}

fn read_guest_bytes(ptr: i32, len: i32) -> Result<Vec<u8>, SdkError> {
    if ptr < 0 || len < 0 {
        return Err(SdkError::NegativePtrLen);
    }
    let ptr = ptr as usize as *const u8;
    let len = len as usize;
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec())
}

fn pack_dispatch_response(response: DispatchResponse) -> i64 {
    match leak_packed(encode_dispatch_response(&response)) {
        Ok(packed) => packed,
        Err(e) => {
            let fallback = DispatchResponse::Error {
                code: -4,
                message: e.message(),
            };
            leak_packed(encode_dispatch_response(&fallback)).unwrap_or(0)
        }
    }
}

fn leak_packed(mut bytes: Vec<u8>) -> Result<i64, SdkError> {
    let packed = pack_ptr_len(bytes.as_mut_ptr() as usize, bytes.len())?;
    core::mem::forget(bytes);
    Ok(packed)
}

fn pack_ptr_len(ptr: usize, len: usize) -> Result<i64, SdkError> {
    checked_i32(ptr)?;
    checked_i32(len)?;
    Ok(((ptr as u64) << 32 | len as u64) as i64)
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

    fn finish(&self) -> Result<(), SdkError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SdkError::TrailingBytes)
        }
    }

    fn u8(&mut self) -> Result<u8, SdkError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, SdkError> {
        let raw = self.take(4)?;
        Ok(u32::from_le_bytes(raw.try_into().expect("len checked")))
    }

    fn i32(&mut self) -> Result<i32, SdkError> {
        let raw = self.take(4)?;
        Ok(i32::from_le_bytes(raw.try_into().expect("len checked")))
    }

    fn u64(&mut self) -> Result<u64, SdkError> {
        let raw = self.take(8)?;
        Ok(u64::from_le_bytes(raw.try_into().expect("len checked")))
    }

    fn string(&mut self) -> Result<String, SdkError> {
        let bytes = self.bytes()?;
        if bytes.len() > MAX_STRING_LEN {
            return Err(SdkError::StringTooLong);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| SdkError::InvalidUtf8)
    }

    fn bytes(&mut self) -> Result<&'a [u8], SdkError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn headers(&mut self) -> Result<Vec<(String, String)>, SdkError> {
        let count = self.u32()? as usize;
        if count > MAX_HEADERS {
            return Err(SdkError::CountTooLarge);
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push((self.string()?, self.string()?));
        }
        Ok(out)
    }

    fn entry(&mut self) -> Result<DispatchEntry, SdkError> {
        let name = self.string()?;
        let kind = match self.u8()? {
            0 => DispatchEntryKind::Dir,
            1 => DispatchEntryKind::File,
            2 => DispatchEntryKind::WritableFile,
            3 => DispatchEntryKind::ExecutableFile,
            4 => DispatchEntryKind::Symlink,
            _ => return Err(SdkError::UnknownTag),
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

    fn opt_u64(&mut self) -> Result<Option<u64>, SdkError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(SdkError::UnknownTag),
        }
    }

    fn opt_string(&mut self) -> Result<Option<String>, SdkError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.string()?)),
            _ => Err(SdkError::UnknownTag),
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SdkError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SdkError::UnexpectedEof)?;
        let out = self
            .bytes
            .get(self.offset..end)
            .ok_or(SdkError::UnexpectedEof)?;
        self.offset = end;
        Ok(out)
    }
}

#[cfg(target_arch = "wasm32")]
mod raw {
    #[link(wasm_import_module = "bloom.v1")]
    unsafe extern "C" {
        pub fn http_fetch(req_ptr: i32, req_len: i32, dst_ptr: i32, dst_max: i32) -> i32;
        pub fn sign_hash(req_ptr: i32, req_len: i32, dst_ptr: i32, dst_max: i32) -> i32;
        pub fn vfs_read(path_ptr: i32, path_len: i32, dst_ptr: i32, dst_max: i32) -> i32;
        pub fn vfs_list(path_ptr: i32, path_len: i32, dst_ptr: i32, dst_max: i32) -> i32;
        pub fn vfs_write(path_ptr: i32, path_len: i32, bytes_ptr: i32, bytes_len: i32) -> i32;
        pub fn store_get(key_ptr: i32, key_len: i32, dst_ptr: i32, dst_max: i32) -> i32;
        pub fn store_put(
            key_ptr: i32,
            key_len: i32,
            value_ptr: i32,
            value_len: i32,
            secret_flag: i32,
        ) -> i32;
        pub fn store_put_new(
            key_ptr: i32,
            key_len: i32,
            value_ptr: i32,
            value_len: i32,
            secret_flag: i32,
        ) -> i32;
        pub fn store_list(prefix_ptr: i32, prefix_len: i32, dst_ptr: i32, dst_max: i32) -> i32;
        pub fn store_del(key_ptr: i32, key_len: i32) -> i32;
        pub fn store_del_if_value(
            key_ptr: i32,
            key_len: i32,
            expected_ptr: i32,
            expected_len: i32,
        ) -> i32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn dispatch_request_roundtrip() {
        let req = DispatchRequest {
            op: DispatchOp::Write,
            path: "markets/123".into(),
            body: b"body".to_vec(),
            ctx: vec![("k".into(), "v".into())],
        };
        assert_eq!(
            decode_dispatch_request(&encode_dispatch_request(&req)).unwrap(),
            req
        );
    }

    #[test]
    fn dispatch_response_roundtrip() {
        let resp = DispatchResponse::List(vec![DispatchEntry {
            name: "status.json".into(),
            kind: DispatchEntryKind::File,
            size: 7,
            mode: 0o444,
            ttl_hint_ms: Some(1000),
            link_target: None,
        }]);
        assert_eq!(
            decode_dispatch_response(&encode_dispatch_response(&resp)).unwrap(),
            resp
        );
    }

    #[test]
    fn http_response_roundtrip() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: b"{}".to_vec(),
        };
        let mut bytes = Vec::new();
        put_u32(&mut bytes, resp.status as u32);
        put_headers(&mut bytes, &resp.headers);
        put_bytes(&mut bytes, &resp.body);
        assert_eq!(decode_http_response(&bytes).unwrap(), resp);
    }

    #[test]
    fn string_list_roundtrip() {
        let list = vec!["a".to_string(), "b/c".to_string()];
        assert_eq!(
            decode_string_list(&encode_string_list(&list)).unwrap(),
            list
        );
    }

    #[test]
    fn host_overflow_sentinel_decodes_needed_length() {
        assert_eq!(
            HostStatus::from_code(-(OVERFLOW_BIAS + 42)),
            HostStatus::BufferTooSmall { needed: 42 }
        );
    }

    #[test]
    fn host_len_rejects_lengths_beyond_destination_capacity() {
        assert_eq!(host_len(3, 4).unwrap(), 3);
        assert!(matches!(host_len(5, 4), Err(SdkError::ResponseTooLarge)));
    }

    #[test]
    fn pack_ptr_len_rejects_signed_i32_overflow() {
        assert!(matches!(
            pack_ptr_len(i32::MAX as usize + 1, 1),
            Err(SdkError::ResponseTooLarge)
        ));
        assert!(matches!(
            pack_ptr_len(1, i32::MAX as usize + 1),
            Err(SdkError::ResponseTooLarge)
        ));
        assert_eq!(
            pack_ptr_len(0x1234, 0x56).unwrap(),
            (0x1234_u64 << 32 | 0x56) as i64
        );
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn dispatch_export_encodes_handler_response() {
        let req = DispatchRequest {
            op: DispatchOp::Read,
            path: "x".into(),
            body: Vec::new(),
            ctx: Vec::new(),
        };
        let req_bytes = encode_dispatch_request(&req);
        let packed = dispatch_export(req_bytes.as_ptr() as i32, req_bytes.len() as i32, |req| {
            assert_eq!(req.path, "x");
            DispatchResponse::Read(b"ok".to_vec())
        }) as u64;
        let ptr = (packed >> 32) as usize as *const u8;
        let len = (packed & 0xffff_ffff) as usize;
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
        assert_eq!(
            decode_dispatch_response(bytes).unwrap(),
            DispatchResponse::Read(b"ok".to_vec())
        );
    }

    #[test]
    fn non_wasm_host_calls_are_unavailable() {
        assert!(matches!(
            vfs_read("status/version", 16),
            Err(SdkError::HostUnavailable)
        ));
        assert!(matches!(
            vfs_list("wallets", 1024),
            Err(SdkError::HostUnavailable)
        ));
        assert!(matches!(
            store_put_new("x", b"y", false),
            Err(SdkError::HostUnavailable)
        ));
        assert!(matches!(store_del("x"), Err(SdkError::HostUnavailable)));
        assert!(matches!(
            store_del_if_value("x", b"y"),
            Err(SdkError::HostUnavailable)
        ));
    }
}
