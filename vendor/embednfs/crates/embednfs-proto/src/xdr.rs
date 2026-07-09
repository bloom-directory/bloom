/// XDR (External Data Representation) encoding and decoding.
///
/// Implements RFC 4506 XDR encoding, used as the wire format for NFS.
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;

#[derive(Debug)]
pub enum XdrError {
    Underflow,
    Overflow,
    InvalidEnum(u32),
    InvalidBool(u32),
    InvalidUtf8,
    StringTooLong(usize),
    OpaqueTooLong(usize),
    Io(io::Error),
}

impl std::fmt::Display for XdrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XdrError::Underflow => write!(f, "XDR underflow: not enough data"),
            XdrError::Overflow => write!(f, "XDR overflow: buffer too small"),
            XdrError::InvalidEnum(v) => write!(f, "XDR invalid enum value: {v}"),
            XdrError::InvalidBool(v) => write!(f, "XDR invalid bool value: {v}"),
            XdrError::InvalidUtf8 => write!(f, "XDR invalid UTF-8"),
            XdrError::StringTooLong(n) => write!(f, "XDR string too long: {n}"),
            XdrError::OpaqueTooLong(n) => write!(f, "XDR opaque too long: {n}"),
            XdrError::Io(e) => write!(f, "XDR I/O error: {e}"),
        }
    }
}

impl std::error::Error for XdrError {}

pub type XdrResult<T> = Result<T, XdrError>;

/// Trait for types that can be encoded to XDR.
pub trait XdrEncode {
    fn encode(&self, dst: &mut BytesMut);

    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(256);
        self.encode(&mut buf);
        buf.freeze()
    }
}

/// Trait for types that can be decoded from XDR.
pub trait XdrDecode: Sized {
    fn decode(src: &mut Bytes) -> XdrResult<Self>;
}

/// XDR padding: round up to multiple of 4.
#[inline]
pub fn xdr_pad(len: usize) -> usize {
    (4 - (len & 3)) & 3
}

// Primitive implementations

impl XdrEncode for u32 {
    fn encode(&self, dst: &mut BytesMut) {
        dst.put_u32(*self);
    }
}

impl XdrDecode for u32 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        if src.remaining() < 4 {
            return Err(XdrError::Underflow);
        }
        Ok(src.get_u32())
    }
}

impl XdrEncode for i32 {
    fn encode(&self, dst: &mut BytesMut) {
        dst.put_i32(*self);
    }
}

impl XdrDecode for i32 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        if src.remaining() < 4 {
            return Err(XdrError::Underflow);
        }
        Ok(src.get_i32())
    }
}

impl XdrEncode for u64 {
    fn encode(&self, dst: &mut BytesMut) {
        dst.put_u64(*self);
    }
}

impl XdrDecode for u64 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        if src.remaining() < 8 {
            return Err(XdrError::Underflow);
        }
        Ok(src.get_u64())
    }
}

impl XdrEncode for i64 {
    fn encode(&self, dst: &mut BytesMut) {
        dst.put_i64(*self);
    }
}

impl XdrDecode for i64 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        if src.remaining() < 8 {
            return Err(XdrError::Underflow);
        }
        Ok(src.get_i64())
    }
}

impl XdrEncode for bool {
    fn encode(&self, dst: &mut BytesMut) {
        dst.put_u32(if *self { 1 } else { 0 });
    }
}

impl XdrDecode for bool {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let v = u32::decode(src)?;
        match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(XdrError::InvalidBool(v)),
        }
    }
}

/// Encode a variable-length opaque (byte array) with length prefix.
pub fn encode_opaque(dst: &mut BytesMut, data: &[u8]) {
    let len = data.len() as u32;
    dst.put_u32(len);
    dst.put_slice(data);
    let pad = xdr_pad(data.len());
    for _ in 0..pad {
        dst.put_u8(0);
    }
}

/// Decode a variable-length opaque.
pub fn decode_opaque(src: &mut Bytes) -> XdrResult<Bytes> {
    let len = u32::decode(src)? as usize;
    let padded = len + xdr_pad(len);
    if src.remaining() < padded {
        return Err(XdrError::Underflow);
    }
    let data = src.split_to(len);
    let pad = xdr_pad(len);
    if pad > 0 {
        src.advance(pad);
    }
    Ok(data)
}

/// Decode a variable-length opaque with maximum length.
pub fn decode_opaque_max(src: &mut Bytes, max: usize) -> XdrResult<Bytes> {
    let data = decode_opaque(src)?;
    if data.len() > max {
        return Err(XdrError::OpaqueTooLong(data.len()));
    }
    Ok(data)
}

/// Decode a variable-length UTF-8 string with a maximum length.
pub fn decode_string_max(src: &mut Bytes, max: usize) -> XdrResult<String> {
    let data = decode_opaque_max(src, max)?;
    String::from_utf8(data.to_vec()).map_err(|_| XdrError::InvalidUtf8)
}

/// Encode a fixed-length opaque.
pub fn encode_fixed_opaque(dst: &mut BytesMut, data: &[u8]) {
    dst.put_slice(data);
    let pad = xdr_pad(data.len());
    for _ in 0..pad {
        dst.put_u8(0);
    }
}

/// Decode a fixed-length opaque.
pub fn decode_fixed_opaque(src: &mut Bytes, len: usize) -> XdrResult<Bytes> {
    let padded = len + xdr_pad(len);
    if src.remaining() < padded {
        return Err(XdrError::Underflow);
    }
    let data = src.split_to(len);
    let pad = xdr_pad(len);
    if pad > 0 {
        src.advance(pad);
    }
    Ok(data)
}

impl XdrEncode for Bytes {
    fn encode(&self, dst: &mut BytesMut) {
        encode_opaque(dst, self);
    }
}

impl XdrDecode for Bytes {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        decode_opaque(src)
    }
}

impl XdrEncode for Vec<u8> {
    fn encode(&self, dst: &mut BytesMut) {
        encode_opaque(dst, self);
    }
}

impl XdrDecode for Vec<u8> {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        decode_opaque(src).map(|data| data.to_vec())
    }
}

impl XdrEncode for String {
    fn encode(&self, dst: &mut BytesMut) {
        encode_opaque(dst, self.as_bytes());
    }
}

impl XdrDecode for String {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let data = decode_opaque(src)?;
        String::from_utf8(data.to_vec()).map_err(|_| XdrError::InvalidUtf8)
    }
}

impl<T: XdrEncode> XdrEncode for Vec<T> {
    fn encode(&self, dst: &mut BytesMut) {
        (self.len() as u32).encode(dst);
        for item in self {
            item.encode(dst);
        }
    }
}

impl<T: XdrEncode> XdrEncode for Option<T> {
    fn encode(&self, dst: &mut BytesMut) {
        match self {
            Some(v) => {
                1u32.encode(dst);
                v.encode(dst);
            }
            None => {
                0u32.encode(dst);
            }
        }
    }
}

impl<T: XdrDecode> XdrDecode for Option<T> {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let present = u32::decode(src)?;
        match present {
            0 => Ok(None),
            1 => Ok(Some(T::decode(src)?)),
            _ => Err(XdrError::InvalidBool(present)),
        }
    }
}

/// Decode a list of XDR items (length-prefixed array).
pub fn decode_list<T: XdrDecode>(src: &mut Bytes) -> XdrResult<Vec<T>> {
    let count = u32::decode(src)? as usize;
    let mut result = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        result.push(T::decode(src)?);
    }
    Ok(result)
}

/// Decode a list of XDR items with an upper bound on the element count.
pub fn decode_list_max<T: XdrDecode>(src: &mut Bytes, max: usize) -> XdrResult<Vec<T>> {
    let count = u32::decode(src)? as usize;
    if count > max {
        return Err(XdrError::OpaqueTooLong(count));
    }

    let mut result = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        result.push(T::decode(src)?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u32_roundtrip() {
        let mut buf = BytesMut::new();
        42u32.encode(&mut buf);
        let mut bytes = buf.freeze();
        assert_eq!(u32::decode(&mut bytes).unwrap(), 42);
    }

    #[test]
    fn test_opaque_roundtrip() {
        let mut buf = BytesMut::new();
        let data = vec![1, 2, 3, 4, 5];
        encode_opaque(&mut buf, &data);
        assert_eq!(buf.len(), 4 + 5 + 3); // length + data + padding
        let mut bytes = buf.freeze();
        let decoded = decode_opaque(&mut bytes).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_string_roundtrip() {
        let mut buf = BytesMut::new();
        let s = String::from("hello");
        s.encode(&mut buf);
        let mut bytes = buf.freeze();
        let decoded = String::decode(&mut bytes).unwrap();
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn test_string_decode_rejects_invalid_utf8() {
        let mut buf = BytesMut::new();
        encode_opaque(&mut buf, &[0xff, 0xfe]);
        let mut bytes = buf.freeze();
        let err = String::decode(&mut bytes).unwrap_err();
        assert!(matches!(err, XdrError::InvalidUtf8));
    }
}
