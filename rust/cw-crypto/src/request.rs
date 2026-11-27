//! Owner and admin request signatures, and the WebSocket subprotocol form.
use rand::{CryptoRng, RngCore};

use crate::sign::{verify_raw, Key, Public};
use crate::wire::{self, vl, SocketAuth};
use crate::{aead, b64, kdf, Error, Result};

pub const WINDOW_MS: u64 = 60_000;
pub const NONCE_MEMORY_MS: u64 = 120_000;

/// The headers of a signed request, as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAuth {
    /// `CW-Device` (or `CW-Admin`).
    pub key: String,
    /// `CW-Time`.
    pub time: String,
    /// `CW-Nonce`.
    pub nonce: String,
    /// `CW-Signature`.
    pub signature: String,
}

fn string(method: &str, authority: &str, path: &str, time: u64, nonce: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut out = kdf::label("request");
    out.push(0);
    let lines = [
        method.to_ascii_uppercase(),
        authority.to_string(),
        path.to_string(),
        time.to_string(),
        b64::encode(nonce),
        b64::encode(&kdf::sha256(body)),
    ];
    out.extend_from_slice(lines.join("\n").as_bytes());
    out
}

pub fn sign(
    key: &Key,
    method: &str,
    authority: &str,
    path: &str,
    body: &[u8],
    now: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> RequestAuth {
    let nonce: [u8; 16] = aead::random(rng);
    let signature = key.sign_raw(&string(method, authority, path, now, &nonce, body));
    RequestAuth {
        key: b64::encode(&key.id()),
        time: now.to_string(),
        nonce: b64::encode(&nonce),
        signature: b64::encode(&signature),
    }
}

/// A request whose signature verified and whose time is inside the window. Checking that the nonce is new is the
/// host's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub key: [u8; 32],
    pub time: u64,
    pub nonce: [u8; 16],
}

fn parse_time(text: &str) -> Result<u64> {
    if text.is_empty()
        || text.len() > 16
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(Error::Malformed("request time"));
    }
    text.parse().map_err(|_| Error::Malformed("request time"))
}

/// Verifies a signed request. `public` returns the public key of a signer the host allows, by the ID the request
/// names.
pub fn verify(
    auth: &RequestAuth,
    method: &str,
    authority: &str,
    path: &str,
    body: &[u8],
    now: u64,
    public: impl FnOnce(&[u8; 32]) -> Option<Public>,
) -> Result<Signer> {
    let key = b64::decode_array::<32>(&auth.key)?;
    let time = parse_time(&auth.time)?;
    let nonce = b64::decode_array::<16>(&auth.nonce)?;
    if auth.signature.len() > 2 * crate::sign::SIGNATURE {
        return Err(Error::BadSignature);
    }
    let signature = b64::decode(&auth.signature)?;
    let public = public(&key).ok_or(Error::WrongSigner)?;
    verify_raw(&public, &string(method, authority, path, time, &nonce, body), &signature)?;
    if time.abs_diff(now) > WINDOW_MS {
        return Err(Error::Expired);
    }
    Ok(Signer { key, time, nonce })
}

/// The `cw1.<auth>` subprotocol for `GET /t/<tenant>/push`.
pub fn socket_protocol(
    key: &Key,
    token: &str,
    authority: &str,
    tenant: &str,
    now: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> String {
    let nonce: [u8; 16] = aead::random(rng);
    let path = format!("/t/{tenant}/push");
    let signature = key.sign_raw(&string("GET", authority, &path, now, &nonce, b""));
    let auth = SocketAuth { token: vl(token.as_bytes()), device: key.id(), time: now, nonce, signature: vl(signature) };
    format!("cw1.{}", b64::encode(&wire::encode(&auth)))
}

/// The longest `cw1.<auth>` subprotocol a host reads.
pub const SOCKET_AUTH_LIMIT: usize = 4096;

/// Verifies a `cw1.<auth>` subprotocol. `public` returns the public key of a device the host allows. Returns the
/// token text and the signer.
pub fn verify_socket(
    protocol: &str,
    authority: &str,
    tenant: &str,
    now: u64,
    public: impl FnOnce(&[u8; 32]) -> Option<Public>,
) -> Result<(String, Signer)> {
    let text = protocol.strip_prefix("cw1.").ok_or(Error::Malformed("socket auth"))?;
    if text.len() > SOCKET_AUTH_LIMIT {
        return Err(Error::Malformed("socket auth"));
    }
    let auth: SocketAuth = wire::decode(&b64::decode(text)?, SOCKET_AUTH_LIMIT, "socket auth")?;
    let path = format!("/t/{tenant}/push");
    let key = public(&auth.device).ok_or(Error::WrongSigner)?;
    verify_raw(&key, &string("GET", authority, &path, auth.time, &auth.nonce, b""), auth.signature.as_slice())?;
    if auth.time.abs_diff(now) > WINDOW_MS {
        return Err(Error::Expired);
    }
    let token = String::from_utf8(auth.token.as_slice().to_vec()).map_err(|_| Error::Malformed("socket auth"))?;
    Ok((token, Signer { key: auth.device, time: auth.time, nonce: auth.nonce }))
}
