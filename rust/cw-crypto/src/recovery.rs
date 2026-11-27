//! The profile seed, its written form, the recovery key pair and the passkey backup.
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::wire::{self, vl, SealedBox};
use crate::{aead, card, hpke, kdf, Error, Result};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
fn checksum(seed: &[u8; 32]) -> [u8; 4] {
    let input = Zeroizing::new(kdf::labeled("recovery check", &[seed]));
    kdf::sha256(&input)[..4].try_into().unwrap()
}

/// `CW1-XXXX-…`: base32 of the seed and its checksum.
pub fn written(seed: &[u8; 32]) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 36]);
    bytes[..32].copy_from_slice(seed);
    bytes[32..].copy_from_slice(&checksum(seed));
    let mut chars = Zeroizing::new(String::with_capacity(58));
    let (mut value, mut bits) = (0u32, 0u32);
    for &b in bytes.iter() {
        value = (value << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            chars.push(ALPHABET[((value >> bits) & 31) as usize] as char);
        }
        value &= (1 << bits) - 1;
    }
    chars.push(ALPHABET[((value << (5 - bits)) & 31) as usize] as char);
    let mut out = Zeroizing::new(String::from("CW1"));
    for (i, c) in chars.chars().enumerate() {
        if i % 4 == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// Reads a written key, case-insensitively, ignoring whitespace and dashes.
pub fn read_written(text: &str) -> Result<Zeroizing<[u8; 32]>> {
    let normalized: Zeroizing<String> = Zeroizing::new(
        text.chars().filter(|c| !c.is_whitespace() && *c != '-').map(|c| c.to_ascii_uppercase()).collect(),
    );
    let body = normalized.strip_prefix("CW1").ok_or(Error::Malformed("recovery key"))?;
    if body.len() != 58 {
        return Err(Error::Malformed("recovery key"));
    }
    let mut bytes = Zeroizing::new([0u8; 36]);
    let (mut value, mut bits, mut offset) = (0u32, 0u32, 0usize);
    for c in body.bytes() {
        let v = ALPHABET.iter().position(|&a| a == c).ok_or(Error::Malformed("recovery key"))? as u32;
        value = (value << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes[offset] = (value >> bits) as u8;
            offset += 1;
        }
        value &= (1 << bits) - 1;
    }
    if value != 0 {
        return Err(Error::Malformed("recovery key"));
    }
    let seed: [u8; 32] = bytes[..32].try_into().unwrap();
    let seed = Zeroizing::new(seed);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&checksum(&seed)[..], &bytes[32..])) {
        return Err(Error::Digest);
    }
    Ok(seed)
}

/// The recovery key pair derived from the profile seed.
pub fn recovery_keys(seed: &[u8; 32]) -> hpke::KeyPair {
    hpke::KeyPair::from_private(kdf::derive(seed, "recovery"))
}

/// The WebAuthn PRF input.
pub fn prf_input() -> Vec<u8> {
    kdf::label("passkey prf")
}

pub fn seal_passkey_backup(
    prf: &[u8],
    profile: &[u8; 32],
    seed: &[u8; 32],
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(prf, "passkey backup"));
    let nonce = aead::random(rng);
    let sealed = aead::seal(&key, &nonce, &kdf::labeled("passkey backup", &[profile]), seed);
    wire::encode(&SealedBox { nonce, sealed: vl(sealed) })
}

pub fn open_passkey_backup(prf: &[u8], profile: &[u8; 32], bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let b: SealedBox = wire::decode(bytes, 1024, "passkey backup")?;
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(prf, "passkey backup"));
    let plain =
        Zeroizing::new(aead::open(&key, &b.nonce, &kdf::labeled("passkey backup", &[profile]), b.sealed.as_slice())?);
    let seed: [u8; 32] = plain.as_slice().try_into().map_err(|_| Error::Malformed("passkey backup"))?;
    Ok(Zeroizing::new(seed))
}

/// The passkey user handle: the tenant ID, then a scheme byte (0 for `https`, 1 for `http`) and the tenant URL's
/// host when they fit in 64 bytes. The URL's path is always `/t/<tenant ID>`, so the host locates the backup.
pub fn user_handle(tenant_url: &str) -> Result<Vec<u8>> {
    let tenant = card::tenant_url(tenant_url)?;
    let (scheme, rest) = match tenant_url.strip_prefix("https://") {
        Some(rest) => (0u8, rest),
        None => (1u8, tenant_url.strip_prefix("http://").ok_or(Error::Malformed("tenant url"))?),
    };
    let host = rest.split_once('/').ok_or(Error::Malformed("tenant url"))?.0;
    let mut out = tenant.to_vec();
    if 17 + host.len() <= 64 {
        out.push(scheme);
        out.extend_from_slice(host.as_bytes());
    }
    Ok(out)
}

/// Returns the tenant ID and, when the handle names its host, the tenant URL.
pub fn read_user_handle(handle: &[u8]) -> Result<([u8; 16], Option<String>)> {
    if handle.len() < 16 || handle.len() == 17 || handle.len() > 64 {
        return Err(Error::Malformed("user handle"));
    }
    let tenant: [u8; 16] = handle[..16].try_into().unwrap();
    if handle.len() == 16 {
        return Ok((tenant, None));
    }
    let scheme = match handle[16] {
        0 => "https",
        1 => "http",
        _ => return Err(Error::Malformed("user handle")),
    };
    let host = std::str::from_utf8(&handle[17..]).map_err(|_| Error::Malformed("user handle"))?;
    let url = format!("{scheme}://{host}/t/{}", crate::b64::encode(&tenant));
    if card::tenant_url(&url)? != tenant {
        return Err(Error::Malformed("user handle"));
    }
    Ok((tenant, Some(url)))
}
