//! Device links.
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::wire::{self, vl, LinkReplyBody, LinkRequest, SealedBox};
use crate::sign::{Public, MLDSA_PUBLIC};
use crate::{aead, b64, card, kdf, Error, Result};

const LIMIT: usize = 64 * 1024;

fn link_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(kdf::derive(secret, "link"))
}

pub fn lookup(secret: &[u8; 32]) -> [u8; 16] {
    kdf::derive(secret, "link lookup")
}

/// A link request for the new device whose public key is `public`.
pub fn request(secret: &[u8; 32], public: &Public, name: &str) -> Vec<u8> {
    let (device, signing_key) = split(public);
    let proof = kdf::hmac(&*link_key(secret), &kdf::labeled("link request", &[&device, &signing_key]));
    wire::encode(&LinkRequest { device, signing_key, name: vl(name.as_bytes()), proof })
}

fn split(public: &Public) -> ([u8; 32], [u8; MLDSA_PUBLIC]) {
    (public[..32].try_into().unwrap(), public[32..].try_into().unwrap())
}

/// Checks a link request's proof. Returns the new device, the ML-DSA-44 half of its public key and its name.
pub fn check_request(secret: &[u8; 32], bytes: &[u8]) -> Result<([u8; 32], [u8; MLDSA_PUBLIC], String)> {
    let r: LinkRequest = wire::decode(bytes, LIMIT, "link request")?;
    let expected = kdf::hmac(&*link_key(secret), &kdf::labeled("link request", &[&r.device, &r.signing_key]));
    if !bool::from(expected.ct_eq(&r.proof)) {
        return Err(Error::BadSignature);
    }
    let name = String::from_utf8(r.name.as_slice().to_vec()).map_err(|_| Error::Malformed("device name"))?;
    if name.chars().count() > 64 {
        return Err(Error::TooLarge("device name"));
    }
    Ok((r.device, r.signing_key, name))
}

/// The six-digit code both devices show.
pub fn code(secret: &[u8; 32], existing: &[u8; 32], new: &[u8; 32]) -> String {
    let mac = kdf::hmac(&*link_key(secret), &kdf::labeled("link code", &[existing, new]));
    format!("{:06}", u32::from_be_bytes(mac[..4].try_into().unwrap()) % 1_000_000)
}

pub fn seal_reply(secret: &[u8; 32], reply: &LinkReplyBody, rng: &mut (impl RngCore + CryptoRng)) -> Vec<u8> {
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(secret, "link reply"));
    let nonce = aead::random(rng);
    let sealed = aead::seal(&key, &nonce, &kdf::label("link reply"), &wire::encode(reply));
    wire::encode(&SealedBox { nonce, sealed: vl(sealed) })
}

pub fn open_reply(secret: &[u8; 32], bytes: &[u8]) -> Result<LinkReplyBody> {
    let b: SealedBox = wire::decode(bytes, LIMIT, "link reply")?;
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(secret, "link reply"));
    let plain = aead::open(&key, &b.nonce, &kdf::label("link reply"), b.sealed.as_slice())?;
    wire::decode(&plain, LIMIT, "link reply")
}

/// What a device link is for. A compared link travels between devices, so both show a code; a scanned link is
/// read off the screen of the device showing it, so it shows none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Compare,
    Scan,
}

impl Kind {
    fn suffix(self) -> &'static str {
        match self {
            Kind::Compare => "",
            Kind::Scan => ".scan",
        }
    }
}

/// `https://anewinter.net/link#<l>.<tenant URL>.<write token>.<existing device>[.scan]`.
pub fn url(secret: &[u8; 32], tenant_url: &str, write_token: &str, existing: &[u8; 32], kind: Kind) -> String {
    format!(
        "{}/link#{}.{}.{}.{}{}",
        crate::invite::ORIGIN,
        b64::encode(secret),
        b64::encode(tenant_url.as_bytes()),
        write_token,
        b64::encode(existing),
        kind.suffix()
    )
}

/// A parsed device link: the secret, the tenant URL, the write token, the device showing the link and its kind.
pub struct Fragment {
    pub secret: [u8; 32],
    pub tenant_url: String,
    pub write_token: String,
    pub existing: [u8; 32],
    pub kind: Kind,
}

/// Parses a link fragment (without `#`).
pub fn parse_fragment(fragment: &str) -> Result<Fragment> {
    let mut parts = fragment.split('.');
    let (Some(s), Some(url), Some(token), Some(existing), kind, None) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Malformed("device link"));
    };
    let kind = match kind {
        None => Kind::Compare,
        Some("scan") => Kind::Scan,
        Some(_) => return Err(Error::Malformed("device link")),
    };
    let tenant_url = String::from_utf8(b64::decode(url)?).map_err(|_| Error::Malformed("device link"))?;
    card::tenant_url(&tenant_url)?;
    b64::decode(token)?;
    Ok(Fragment {
        secret: b64::decode_array(s)?,
        tenant_url,
        write_token: token.to_string(),
        existing: b64::decode_array(existing)?,
        kind,
    })
}
