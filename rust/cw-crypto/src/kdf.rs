//! Labels, HKDF and HMAC as the format defines them.
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub const PREFIX: &[u8] = b"commonwire 1 ";

/// The bytes of label `L`: `"commonwire 1 " || L`.
pub fn label(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX.len() + name.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(name.as_bytes());
    out
}

/// `label(name)` followed by each part.
pub fn labeled(name: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = label(name);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

pub fn expand<const N: usize>(key: &[u8], name: &str) -> [u8; N] {
    let hk = Hkdf::<Sha256>::from_prk(key).expect("keys are at least 32 bytes");
    let mut out = [0u8; N];
    hk.expand(&label(name), &mut out).expect("short output");
    out
}

/// `Expand(key, label(name) || parts…, N)`.
pub fn expand_labeled<const N: usize>(key: &[u8], name: &str, parts: &[&[u8]]) -> [u8; N] {
    let hk = Hkdf::<Sha256>::from_prk(key).expect("keys are at least 32 bytes");
    let mut out = [0u8; N];
    hk.expand(&labeled(name, parts), &mut out).expect("short output");
    out
}

pub fn derive<const N: usize>(ikm: &[u8], name: &str) -> [u8; N] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; N];
    hk.expand(&label(name), &mut out).expect("short output");
    out
}

pub fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
