//! Base64url without padding (RFC 4648 §5), strict: no padding, no other characters, zero trailing bits.
use crate::{Error, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.len();
        let v = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..=n {
            out.push(ALPHABET[((v >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn value(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    } as u32)
}

pub fn decode(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(Error::Malformed("base64url length"));
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut v = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            v |= value(c).ok_or(Error::Malformed("base64url character"))? << (18 - 6 * i);
        }
        let produced = chunk.len() - 1;
        let unused = 24 - 8 * produced as u32;
        if v & ((1 << unused) - 1) != 0 && chunk.len() < 4 {
            return Err(Error::Malformed("base64url trailing bits"));
        }
        for i in 0..produced {
            out.push((v >> (16 - 8 * i)) as u8);
        }
    }
    Ok(out)
}

/// Decodes exactly `N` bytes.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    decode(text)?.try_into().map_err(|_| Error::Malformed("base64url length"))
}
