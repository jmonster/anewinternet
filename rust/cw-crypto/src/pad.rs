//! Padding buckets: 256, 512, 1024, then ×5/4 rounded up to 64 bytes. Sizes include the 16-byte tag.
use crate::{Error, Result};

pub const TAG: usize = 16;

/// The smallest bucket that holds `n` bytes.
pub const fn bucket(n: usize) -> usize {
    let mut b = 256usize;
    while b < n {
        b = if b < 1024 { b * 2 } else { (b * 5).div_ceil(4).div_ceil(64) * 64 };
    }
    b
}

/// `plaintext || 0x80 || 0x00…`, sized so that adding the tag reaches a bucket.
pub fn pad(plaintext: &[u8]) -> Vec<u8> {
    let total = bucket(plaintext.len() + 1 + TAG) - TAG;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(total, 0);
    out
}

pub fn unpad(mut padded: Vec<u8>) -> Result<Vec<u8>> {
    if bucket(padded.len() + TAG) != padded.len() + TAG {
        return Err(Error::Decrypt);
    }
    let end = padded.iter().rposition(|&b| b != 0).ok_or(Error::Decrypt)?;
    if padded[end] != 0x80 {
        return Err(Error::Decrypt);
    }
    padded.truncate(end);
    Ok(padded)
}
