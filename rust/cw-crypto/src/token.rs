//! Values a host issues and checks under its host secret with no storage: tokens, tenant IDs, hosting
//! offers, and the one-time claim secret.
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::wire::{self, Token};
use crate::{b64, kdf, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenKind {
    Read = 1,
    Write = 2,
    Owner = 3,
    Admin = 4,
    Contact = 5,
    /// Posts inbox items through one open slot: `epoch` is the slot number, `serial` 0.
    Slot = 6,
    /// A group's readers and posters, on the tenant's group counter.
    GroupRead = 7,
    GroupWrite = 8,
}

impl TokenKind {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(TokenKind::Read),
            2 => Ok(TokenKind::Write),
            3 => Ok(TokenKind::Owner),
            4 => Ok(TokenKind::Admin),
            5 => Ok(TokenKind::Contact),
            6 => Ok(TokenKind::Slot),
            7 => Ok(TokenKind::GroupRead),
            8 => Ok(TokenKind::GroupWrite),
            _ => Err(Error::Malformed("token kind")),
        }
    }
}

fn mac(secret: &[u8; 32], tenant: &[u8; 16], epoch: u64, kind: u8, serial: u32) -> [u8; 16] {
    let full =
        kdf::hmac(secret, &kdf::labeled("token", &[tenant, &epoch.to_be_bytes(), &[kind], &serial.to_be_bytes()]));
    full[..16].try_into().unwrap()
}

/// Issues a token, as the base64url text sent in `Authorization: CW <token>`.
pub fn issue(secret: &[u8; 32], tenant: &[u8; 16], epoch: u64, kind: TokenKind, serial: u32) -> String {
    let t =
        Token { tenant: *tenant, epoch, kind: kind as u8, serial, mac: mac(secret, tenant, epoch, kind as u8, serial) };
    b64::encode(&wire::encode(&t))
}

/// A token whose MAC verified. The epoch check against the tenant's current epoch is the caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checked {
    pub tenant: [u8; 16],
    pub epoch: u64,
    pub kind: TokenKind,
    pub serial: u32,
}

/// Checks a token's MAC in constant time, using no storage.
pub fn check(secret: &[u8; 32], text: &str) -> Result<Checked> {
    if text.len() > 64 {
        return Err(Error::Malformed("token"));
    }
    let t: Token = wire::decode(&b64::decode(text)?, 64, "token")?;
    let expected = mac(secret, &t.tenant, t.epoch, t.kind, t.serial);
    if !bool::from(expected.ct_eq(&t.mac)) {
        return Err(Error::BadSignature);
    }
    Ok(Checked { tenant: t.tenant, epoch: t.epoch, kind: TokenKind::from_u8(t.kind)?, serial: t.serial })
}

/// The tenant field of admin tokens.
pub const ADMIN_TENANT: [u8; 16] = [0; 16];

fn short_mac<const N: usize>(secret: &[u8; 32], label: &str, data: &[u8]) -> [u8; N] {
    kdf::hmac(secret, &kdf::labeled(label, &[data]))[..N].try_into().unwrap()
}

/// A new tenant ID: 8 random bytes and the first 8 bytes of their MAC.
pub fn new_tenant(secret: &[u8; 32], rng: &mut (impl RngCore + CryptoRng)) -> [u8; 16] {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id[..8]);
    let mac: [u8; 8] = short_mac(secret, "tenant", &id[..8]);
    id[8..].copy_from_slice(&mac);
    id
}

/// Whether this host issued a tenant ID.
pub fn check_tenant(secret: &[u8; 32], id: &[u8; 16]) -> bool {
    let mac: [u8; 8] = short_mac(secret, "tenant", &id[..8]);
    id != &ADMIN_TENANT && bool::from(mac.ct_eq(&id[8..]))
}

/// A hosting offer's secret: the 16-byte offer ID and the first 16 bytes of its MAC.
pub fn offer_secret(secret: &[u8; 32], id: &[u8; 16]) -> [u8; 32] {
    let mac: [u8; 16] = short_mac(secret, "offer", id);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(id);
    out[16..].copy_from_slice(&mac);
    out
}

/// Returns the offer ID of a secret this host issued.
pub fn check_offer(secret: &[u8; 32], offer: &[u8; 32]) -> Result<[u8; 16]> {
    let id: [u8; 16] = offer[..16].try_into().unwrap();
    let mac: [u8; 16] = short_mac(secret, "offer", &id);
    if bool::from(mac.ct_eq(&offer[16..])) {
        Ok(id)
    } else {
        Err(Error::BadSignature)
    }
}

/// The claim digest a host keeps: `SHA-256(label("claim") || claim secret)`.
pub fn claim_digest(claim: &[u8; 32]) -> [u8; 32] {
    kdf::sha256(&kdf::labeled("claim", &[claim]))
}

/// Checks a presented claim secret against the kept digest in constant time.
pub fn check_claim(digest: &[u8; 32], claim: &[u8; 32]) -> bool {
    bool::from(claim_digest(claim).ct_eq(digest))
}
