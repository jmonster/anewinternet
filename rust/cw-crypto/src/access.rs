//! Access boxes: what a group link's access secret opens on the group's tenant (docs/format.md, "Groups").
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::wire::{self, vl, AccessBody, AccessBox, HostingOffer};
use crate::{aead, card, kdf, Error, Result};

/// The largest access box a host stores.
pub const LIMIT: usize = 4 * 1024;
/// Key generations one box carries.
pub const MAX_KEYS: usize = 4;
/// A group name, in characters.
pub const NAME_CHARS: usize = 80;
const TOKEN_LIMIT: usize = 64;
/// A group write token appends to a wall only while the wall's next sequence is below this.
pub const WALL_ENTRIES: u64 = 1_800;
/// The largest object, in ciphertext bytes, a group write token puts.
pub const OBJECT_LIMIT: usize = 512 * 1024;

/// An opened access box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    pub group: [u8; 16],
    /// The generation of `keys[0]`; each later key is one generation older.
    pub generation: u32,
    pub keys: Vec<[u8; 32]>,
    pub read_token: String,
    pub write_token: String,
    pub name: String,
    pub tenant: String,
    pub offer: Option<HostingOffer>,
}

/// The ID a host stores the box under: `Derive(a, "access lookup", 16)`.
pub fn lookup(secret: &[u8; 32]) -> [u8; 16] {
    kdf::derive(secret, "access lookup")
}

/// The thread key of wall `wall` under a group key: `Expand(G, "wall" || uint32 wall, 32)`.
pub fn wall_key(group_key: &[u8; 32], wall: u32) -> [u8; 32] {
    kdf::expand_labeled(group_key, "wall", &[&wall.to_be_bytes()])
}

fn aad(lookup: &[u8; 16]) -> Vec<u8> {
    kdf::labeled("access", &[lookup])
}

fn token(text: &str) -> Result<()> {
    if text.is_empty() || text.len() > TOKEN_LIMIT {
        return Err(Error::Malformed("access token"));
    }
    Ok(())
}

fn check(a: &Access) -> Result<()> {
    if a.keys.is_empty() || a.keys.len() > MAX_KEYS || (a.generation as usize) < a.keys.len() {
        return Err(Error::Malformed("access keys"));
    }
    token(&a.read_token)?;
    token(&a.write_token)?;
    let chars = a.name.chars().count();
    if chars == 0 || chars > NAME_CHARS {
        return Err(Error::Malformed("access name"));
    }
    card::tenant_url(&a.tenant)?;
    if let Some(o) = &a.offer {
        let host = core::str::from_utf8(o.tenant_host.as_slice()).map_err(|_| Error::Malformed("access offer"))?;
        if host.is_empty() || host.len() > 256 {
            return Err(Error::Malformed("access offer"));
        }
    }
    Ok(())
}

pub fn seal(secret: &[u8; 32], a: &Access, rng: &mut (impl RngCore + CryptoRng)) -> Result<Vec<u8>> {
    check(a)?;
    let body = AccessBody {
        group: a.group,
        generation: a.generation,
        keys: vl(a.keys.concat()),
        read_token: vl(a.read_token.as_bytes()),
        write_token: vl(a.write_token.as_bytes()),
        name: vl(a.name.as_bytes()),
        tenant: vl(a.tenant.as_bytes()),
        offer: vl(a.offer.as_ref().map(wire::encode).unwrap_or_default()),
    };
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(secret, "access"));
    let nonce = aead::random(rng);
    let sealed = aead::seal(&key, &nonce, &aad(&lookup(secret)), &wire::encode(&body));
    let bytes = wire::encode(&AccessBox { nonce, sealed: vl(sealed) });
    if bytes.len() > LIMIT {
        return Err(Error::TooLarge("access box"));
    }
    Ok(bytes)
}

fn text(v: &tls_codec::VLBytes, what: &'static str) -> Result<String> {
    String::from_utf8(v.as_slice().to_vec()).map_err(|_| Error::Malformed(what))
}

pub fn open(secret: &[u8; 32], bytes: &[u8]) -> Result<Access> {
    let b: AccessBox = wire::decode(bytes, LIMIT, "access box")?;
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(secret, "access"));
    let plain = aead::open(&key, &b.nonce, &aad(&lookup(secret)), b.sealed.as_slice())?;
    let body: AccessBody = wire::decode(&plain, LIMIT, "access box")?;
    let keys = body.keys.as_slice();
    if keys.len() % 32 != 0 {
        return Err(Error::Malformed("access keys"));
    }
    let offer = match body.offer.as_slice() {
        [] => None,
        o => Some(wire::decode::<HostingOffer>(o, 1024, "access offer")?),
    };
    let a = Access {
        group: body.group,
        generation: body.generation,
        keys: keys.chunks(32).map(|k| k.try_into().unwrap()).collect(),
        read_token: text(&body.read_token, "access token")?,
        write_token: text(&body.write_token, "access token")?,
        name: text(&body.name, "access name")?,
        tenant: text(&body.tenant, "access tenant")?,
        offer,
    };
    check(&a)?;
    Ok(a)
}
