//! Binary blob ABI used by `bloom.v1` host imports.
//!
//! The Wasm boundary only sees `(ptr, len)` byte blobs. This module is the
//! shared definition for how those blobs are encoded.

use crate::host::HostError;

const MAX_STRING_LEN: usize = 64 * 1024;
const MAX_HEADERS: usize = 256;

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

pub fn encode_http_request(req: &HttpRequest) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, &req.method);
    put_string(&mut out, &req.url);
    put_headers(&mut out, &req.headers);
    put_bytes(&mut out, &req.body);
    out
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

    fn u32(&mut self) -> Result<u32, HostError> {
        let raw = self.take(4)?;
        Ok(u32::from_le_bytes(raw.try_into().expect("len checked")))
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
}
