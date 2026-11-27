//! Invitations: public part under the link secret, keys under the link secret and the host's release secret.
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::wire::{self, vl, Invitation, InviteKeys, InvitePublic};
use crate::{aead, b64, card, kdf, Error, Result};

pub const LIMIT: usize = 64 * 1024;
pub const MAX_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;
pub const ORIGIN: &str = "https://anewinter.net";

pub fn lookup(secret: &[u8; 32]) -> [u8; 16] {
    kdf::derive(secret, "invite lookup")
}

fn keys_key(secret: &[u8; 32], release: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(secret);
    ikm[32..].copy_from_slice(release);
    Zeroizing::new(kdf::derive(&*ikm, "invite keys"))
}

/// Builds an invitation. Returns its lookup and bytes.
pub fn create(
    secret: &[u8; 32],
    release: &[u8; 32],
    expires_at: u64,
    now: u64,
    public: &InvitePublic,
    keys: &InviteKeys,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<([u8; 16], Vec<u8>)> {
    if expires_at <= now || expires_at - now > MAX_LIFETIME_MS {
        return Err(Error::Expired);
    }
    let nonce1 = aead::random(rng);
    let nonce2 = aead::random(rng);
    let k1: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(secret, "invite"));
    let public = aead::seal(&k1, &nonce1, &kdf::label("invite"), &wire::encode(public));
    let keys = aead::seal(&keys_key(secret, release), &nonce2, &kdf::label("invite keys"), &wire::encode(keys));
    let bytes = wire::encode(&Invitation { expires_at, nonce1, public: vl(public), nonce2, keys: vl(keys) });
    if bytes.len() > LIMIT {
        return Err(Error::TooLarge("invitation"));
    }
    Ok((lookup(secret), bytes))
}

fn decode(bytes: &[u8], now: u64) -> Result<Invitation> {
    let inv: Invitation = wire::decode(bytes, LIMIT, "invitation")?;
    if inv.expires_at <= now {
        return Err(Error::Expired);
    }
    Ok(inv)
}

pub fn open_public(bytes: &[u8], secret: &[u8; 32], now: u64) -> Result<(u64, InvitePublic)> {
    let inv = decode(bytes, now)?;
    let k1: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(secret, "invite"));
    let plain = aead::open(&k1, &inv.nonce1, &kdf::label("invite"), inv.public.as_slice())?;
    Ok((inv.expires_at, wire::decode(&plain, LIMIT, "invitation")?))
}

pub fn open_keys(bytes: &[u8], secret: &[u8; 32], release: &[u8; 32], now: u64) -> Result<InviteKeys> {
    let inv = decode(bytes, now)?;
    let plain = aead::open(&keys_key(secret, release), &inv.nonce2, &kdf::label("invite keys"), inv.keys.as_slice())?;
    let keys: InviteKeys = wire::decode(&plain, LIMIT, "invitation")?;
    if keys.generation == 0 || crate::head::keyring_generation(keys.keyring.as_slice())? != u64::from(keys.generation) {
        return Err(Error::Malformed("invitation"));
    }
    Ok(keys)
}

/// `https://anewinter.net/invite#<s>.<tenant URL>`.
/// Proves an acceptance comes from whoever holds the link secret: `HMAC(Derive(s, "acceptance"), label || card)`.
pub fn acceptance_proof(secret: &[u8; 32], card: &[u8]) -> [u8; 32] {
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(secret, "acceptance"));
    kdf::hmac(&*key, &kdf::labeled("acceptance", &[card]))
}

pub fn check_acceptance(secret: &[u8; 32], card: &[u8], proof: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(acceptance_proof(secret, card).ct_eq(proof))
}

pub fn link(secret: &[u8; 32], tenant_url: &str) -> String {
    format!("{ORIGIN}/invite/#{}.{}", b64::encode(secret), b64::encode(tenant_url.as_bytes()))
}

/// Parses an invitation link's fragment (without `#`). Returns the secret and the inviter's tenant URL.
pub fn parse_fragment(fragment: &str) -> Result<([u8; 32], String)> {
    let (s, url) = fragment.split_once('.').ok_or(Error::Malformed("invitation link"))?;
    let url = String::from_utf8(b64::decode(url)?).map_err(|_| Error::Malformed("invitation link"))?;
    card::tenant_url(&url)?;
    Ok((b64::decode_array(s)?, url))
}
