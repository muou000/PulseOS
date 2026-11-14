//! Shared serialization codec helpers for length-prefixed values and strings.

use alloc::string::String;
use alloc::vec::Vec;
use crate::framing::CaptureError;

/// Encode a UTF-8 string with a 4-byte little-endian length prefix.
pub fn encode_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Decode a UTF-8 string with a 4-byte little-endian length prefix from a byte slice.
pub fn decode_string(slice: &[u8], offset: &mut usize) -> Result<String, CaptureError> {
    if offset.checked_add(4).is_none_or(|end| end > slice.len()) {
        return Err(CaptureError::TruncatedMetadata);
    }
    let len = u32::from_le_bytes(slice[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;

    let end = offset.checked_add(len).ok_or(CaptureError::TruncatedMetadata)?;
    if end > slice.len() { return Err(CaptureError::TruncatedMetadata); }
    let s = String::from_utf8(slice[*offset..end].to_vec())
        .map_err(|_| CaptureError::TruncatedMetadata)?;
    *offset = end;
    Ok(s)
}
