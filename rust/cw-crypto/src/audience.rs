//! The audience key's boxes: one per friend, on the profile's hosts, sealed to the friend's inbox key under the
//! friendship secret (docs/format.md, "Audience boxes"); and device seal keys with their records.
use zeroize::Zeroizing;

use crate::card::Card;
use crate::sign::{self, Key, Kind};
use crate::wire::{self, vl, AudienceBoxBody, HpkeBox, SealKeyBody};
use crate::{hpke, kdf, pad, xwing, Error, Result};

/// The largest audience box, as the host keeps it.
pub const LIMIT: usize = crate::access::LIMIT;

/// Where `owner` stores the box of the friend it shares `friendship` with.
pub fn lookup(friendship: &[u8; 32], owner: &[u8; 32]) -> [u8; 16] {
    kdf::expand_labeled(friendship, "audience box lookup", &[owner])
}

fn info(owner: &[u8; 32], friend: &[u8; 32], lookup: &[u8; 16]) -> Vec<u8> {
    kdf::labeled("audience box", &[owner, friend, lookup])
}

fn psk_id() -> Vec<u8> {
    kdf::label("audience box")
}

/// `owner`'s box for `friend`, sealed to `friend_inbox`, the inbox key in the friend's current card. Returns the
/// lookup and the box.
pub fn seal(
    friendship: &[u8; 32],
    owner: &[u8; 32],
    friend: &[u8; 32],
    friend_inbox: &[u8; xwing::PUBLIC],
    generation: u32,
    key: &[u8; 32],
) -> Result<([u8; 16], Vec<u8>)> {
    if generation == 0 {
        return Err(Error::Malformed("audience generation"));
    }
    let lookup = lookup(friendship, owner);
    let body = wire::encode(&AudienceBoxBody { generation, key: *key });
    let id = psk_id();
    let (enc, ciphertext) = hpke::seal(
        friend_inbox,
        &info(owner, friend, &lookup),
        b"",
        &pad::pad(&body),
        Some(hpke::Psk { key: friendship, id: &id }),
    )?;
    Ok((lookup, wire::encode(&HpkeBox { enc: vl(enc), ciphertext: vl(ciphertext) })))
}

/// Opens `owner`'s box for `friend` with one of the friend's inbox private keys. Returns the generation and the
/// audience key.
pub fn open(
    friendship: &[u8; 32],
    owner: &[u8; 32],
    friend: &[u8; 32],
    inbox_private: &[u8; xwing::PRIVATE],
    bytes: &[u8],
) -> Result<(u32, Zeroizing<[u8; 32]>)> {
    let b: HpkeBox = wire::decode(bytes, LIMIT, "audience box")?;
    let id = psk_id();
    let padded = Zeroizing::new(hpke::open(
        inbox_private,
        b.enc.as_slice(),
        b.ciphertext.as_slice(),
        &info(owner, friend, &lookup(friendship, owner)),
        b"",
        Some(hpke::Psk { key: friendship, id: &id }),
    )?);
    let plain = Zeroizing::new(pad::unpad(padded.to_vec())?);
    let body: AudienceBoxBody = wire::decode(&plain, LIMIT, "audience box")?;
    if body.generation == 0 {
        return Err(Error::Malformed("audience generation"));
    }
    Ok((body.generation, Zeroizing::new(body.key)))
}

/// A device's seal key pair, from its device seed: the X-Wing private key `Derive(seed, "device seal", 32)`.
pub fn device_seal_keys(device_seed: &[u8; 32]) -> hpke::KeyPair {
    hpke::KeyPair::from_private(kdf::derive(device_seed, "device seal"))
}

/// The device's own record of its seal key, for `profile`.
pub fn seal_key_record(device: &Key, profile: &[u8; 32]) -> Vec<u8> {
    let seal = device_seal_keys(&device.seed());
    device.sign(Kind::SealKey, wire::encode(&SealKeyBody { profile: *profile, seal_key: seal.public }))
}

/// Verifies a seal key record against `card`: signed by the device it names, which the card lists, for the card's
/// profile. Returns the device and its seal key.
pub fn open_seal_key_record(bytes: &[u8], card: &Card) -> Result<([u8; 32], [u8; xwing::PUBLIC])> {
    let v = sign::open(bytes, Kind::SealKey, 2048, |s| card.device_key(s))?;
    let body: SealKeyBody = wire::decode(&v.body, 2048, "seal key")?;
    if body.profile != card.profile {
        return Err(Error::WrongSigner);
    }
    xwing::check_public(&body.seal_key)?;
    Ok((v.signer, body.seal_key))
}
