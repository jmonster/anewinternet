//! Objects: padded AES-256-GCM under a key used for nothing else, named by the digest of the ciphertext.
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::wire::ObjectRef;
use crate::{aead, b64, kdf, Error, Result};

pub const LIMIT: usize = 16 * 1024 * 1024;
const NONCE: [u8; 12] = [0; 12];

/// `sha256-<base64url digest>`.
pub fn name(digest: &[u8; 32]) -> String {
    format!("sha256-{}", b64::encode(digest))
}

pub fn parse_name(text: &str) -> Result<[u8; 32]> {
    let rest = text.strip_prefix("sha256-").ok_or(Error::Malformed("object name"))?;
    if rest.len() != 43 {
        return Err(Error::Malformed("object name"));
    }
    b64::decode_array(rest)
}

/// Encrypts `plaintext` as a new object under a fresh key.
pub fn encrypt(plaintext: &[u8], rng: &mut (impl RngCore + CryptoRng)) -> Result<(Vec<u8>, ObjectRef)> {
    encrypt_with_key(plaintext, aead::random(rng))
}

/// Encrypts under a given key. The caller guarantees the key is used for no other object.
pub fn encrypt_with_key(plaintext: &[u8], key: [u8; 32]) -> Result<(Vec<u8>, ObjectRef)> {
    if plaintext.len() > LIMIT {
        return Err(Error::TooLarge("object"));
    }
    let ciphertext = aead::seal(&key, &NONCE, &kdf::label("object"), plaintext);
    let digest = kdf::sha256(&ciphertext);
    Ok((ciphertext, ObjectRef { digest, key, size: plaintext.len() as u32 }))
}

/// A manifest part: its key is `Expand(owner key, "manifest part" || SHA-256(plaintext), 32)`, so every own device makes
/// the same object for the same part and an unchanged part keeps its object.
pub fn encrypt_part(plaintext: &[u8], owner_key: &[u8; 32]) -> Result<(Vec<u8>, ObjectRef)> {
    encrypt_with_key(plaintext, kdf::expand_labeled(owner_key, "manifest part", &[&kdf::sha256(plaintext)]))
}

/// Checks the digest, then decrypts and checks the size.
pub fn decrypt(ciphertext: &[u8], reference: &ObjectRef) -> Result<Vec<u8>> {
    if ciphertext.len() > crate::pad::bucket(LIMIT + 1 + crate::pad::TAG) {
        return Err(Error::TooLarge("object"));
    }
    if kdf::sha256(ciphertext) != reference.digest {
        return Err(Error::Digest);
    }
    let plaintext = aead::open(&reference.key, &NONCE, &kdf::label("object"), ciphertext)?;
    if plaintext.len() != reference.size as usize {
        return Err(Error::Malformed("object size"));
    }
    Ok(plaintext)
}

/// The JSON form `{"h": name, "k": key, "n": size}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRef {
    pub h: String,
    pub k: String,
    pub n: u32,
}

impl From<&ObjectRef> for JsonRef {
    fn from(r: &ObjectRef) -> Self {
        JsonRef { h: name(&r.digest), k: b64::encode(&r.key), n: r.size }
    }
}

impl TryFrom<&JsonRef> for ObjectRef {
    type Error = Error;
    fn try_from(r: &JsonRef) -> Result<Self> {
        Ok(ObjectRef { digest: parse_name(&r.h)?, key: b64::decode_array(&r.k)?, size: r.n })
    }
}
