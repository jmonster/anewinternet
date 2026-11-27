//! The head and the keyring box, both under a key of one generation: a profile's audience key or a group's key.
use rand::{CryptoRng, RngCore};

use crate::card::Card;
use crate::sign::{self, Key, Kind};
use crate::wire::{self, vl, HeadAad, HeadBody, HeadSecret, Keyring, KeyringBox, KeyringHost, ObjectRef};
use crate::{aead, kdf, Error, Result};

pub const LIMIT: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub signer: [u8; 32],
    pub profile: [u8; 32],
    pub group: Vec<u8>,
    pub generation: u64,
    pub revision: u64,
    pub published_at: u64,
    pub manifest: ObjectRef,
}

fn aad(profile: &[u8; 32], group: &[u8], generation: u64, revision: u64) -> Vec<u8> {
    let mut out = kdf::label("head");
    out.extend(wire::encode(&HeadAad { profile: *profile, group: vl(group), generation, revision }));
    out
}

#[allow(clippy::too_many_arguments)]
pub fn seal(
    device: &Key,
    profile: &[u8; 32],
    group: &[u8],
    generation: u64,
    revision: u64,
    published_at: u64,
    key: &[u8; 32],
    manifest: &ObjectRef,
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    let key: [u8; 32] = kdf::expand(key, "head");
    let nonce = aead::random(rng);
    let sealed = aead::seal(
        &key,
        &nonce,
        &aad(profile, group, generation, revision),
        &wire::encode(&HeadSecret { manifest: *manifest }),
    );
    let body =
        HeadBody { profile: *profile, group: vl(group), generation, revision, published_at, nonce, sealed: vl(sealed) };
    device.sign(Kind::Head, wire::encode(&body))
}

/// Verifies and decrypts a head. `key` returns the key of a group (empty for a profile) and generation, when known.
/// `known` is the highest revision already verified for this profile; lower revisions are refused.
pub fn open(
    bytes: &[u8],
    card: &Card,
    known: Option<u64>,
    key: impl FnOnce(&[u8], u64) -> Option<[u8; 32]>,
) -> Result<Head> {
    let verified = sign::open(bytes, Kind::Head, LIMIT, |s| card.device_key(s))?;
    let body: HeadBody = wire::decode(&verified.body, LIMIT, "head")?;
    if body.profile != card.profile {
        return Err(Error::Malformed("head profile"));
    }
    if known.is_some_and(|k| body.revision < k) {
        return Err(Error::Rollback);
    }
    let group = body.group.as_slice();
    let sealing = key(group, body.generation).ok_or(Error::WrongGeneration)?;
    let key: [u8; 32] = kdf::expand(&sealing, "head");
    let plain = aead::open(
        &key,
        &body.nonce,
        &aad(&body.profile, group, body.generation, body.revision),
        body.sealed.as_slice(),
    )?;
    let secret: HeadSecret = wire::decode(&plain, LIMIT, "head secret")?;
    Ok(Head {
        signer: verified.signer,
        profile: body.profile,
        group: group.to_vec(),
        generation: body.generation,
        revision: body.revision,
        published_at: body.published_at,
        manifest: secret.manifest,
    })
}

fn keyring_aad(profile: &[u8; 32], generation: u64) -> Vec<u8> {
    kdf::labeled("keyring", &[profile, &generation.to_be_bytes()])
}

fn token_text(v: &tls_codec::VLBytes, what: &'static str) -> Result<String> {
    match String::from_utf8(v.as_slice().to_vec()) {
        Ok(t) if !t.is_empty() => Ok(t),
        _ => Err(Error::Malformed(what)),
    }
}

/// A host's tokens in the keyring: read and write for one audience generation, and the contact token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringTokens {
    pub read: String,
    pub write: String,
    pub contact: String,
}

impl KeyringTokens {
    pub fn encode(list: &[KeyringTokens]) -> Vec<KeyringHost> {
        list.iter()
            .map(|t| KeyringHost {
                read_token: vl(t.read.as_bytes()),
                write_token: vl(t.write.as_bytes()),
                contact_token: vl(t.contact.as_bytes()),
            })
            .collect()
    }

    /// One entry per card host: 1–4, each token non-empty UTF-8.
    pub fn decode(list: &[KeyringHost]) -> Result<Vec<KeyringTokens>> {
        if list.is_empty() || list.len() > crate::card::MAX_HOSTS {
            return Err(Error::Malformed("keyring"));
        }
        list.iter()
            .map(|h| {
                Ok(KeyringTokens {
                    read: token_text(&h.read_token, "keyring")?,
                    write: token_text(&h.write_token, "keyring")?,
                    contact: token_text(&h.contact_token, "keyring")?,
                })
            })
            .collect()
    }
}

pub fn seal_keyring(
    profile: &[u8; 32],
    generation: u64,
    audience_key: &[u8; 32],
    tokens: &[KeyringTokens],
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    let key: [u8; 32] = kdf::expand(audience_key, "keyring");
    let nonce = aead::random(rng);
    let ring = Keyring { hosts: KeyringTokens::encode(tokens) };
    let sealed = aead::seal(&key, &nonce, &keyring_aad(profile, generation), &wire::encode(&ring));
    wire::encode(&KeyringBox { generation, nonce, sealed: vl(sealed) })
}

/// The generation a keyring box is of.
pub fn keyring_generation(bytes: &[u8]) -> Result<u64> {
    Ok(wire::decode::<KeyringBox>(bytes, LIMIT, "keyring")?.generation)
}

/// Returns the tokens of each card host, in card order.
pub fn open_keyring(bytes: &[u8], profile: &[u8; 32], generation: u64, audience_key: &[u8; 32]) -> Result<Vec<KeyringTokens>> {
    let b: KeyringBox = wire::decode(bytes, LIMIT, "keyring")?;
    if b.generation != generation {
        return Err(Error::WrongGeneration);
    }
    let key: [u8; 32] = kdf::expand(audience_key, "keyring");
    let plain = aead::open(&key, &b.nonce, &keyring_aad(profile, generation), b.sealed.as_slice())?;
    let ring: Keyring = wire::decode(&plain, LIMIT, "keyring")?;
    KeyringTokens::decode(&ring.hosts)
}
