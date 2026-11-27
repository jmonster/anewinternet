//! Device inbox keys: X-Wing keys only one device holds, renewed every few days and deleted once the first host has
//! the next one and the inbox was read, so inbox items have forward secrecy (docs/format.md, "Device inbox keys").
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::card::Card;
use crate::sign::{self, Key, Kind};
use crate::wire::{self, DeviceKeyBody};
use crate::{aead, xwing, Error, Result};

const LIMIT: usize = 2048;

/// A verified device key record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKey {
    pub device: [u8; 32],
    pub created_at: u64,
    pub key: [u8; xwing::PUBLIC],
}

/// A new device key for `profile`: the signed record and the private key, which only this device keeps.
pub fn create(
    device: &Key,
    profile: &[u8; 32],
    now: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<u8>, Zeroizing<[u8; xwing::PRIVATE]>) {
    let private = Zeroizing::new(aead::random::<{ xwing::PRIVATE }>(rng));
    let body = DeviceKeyBody { profile: *profile, created_at: now, key: xwing::public(&private) };
    (device.sign(Kind::DeviceKey, wire::encode(&body)), private)
}

/// Verifies a record against `card`: signed by a device the card lists, for its profile.
pub fn open(bytes: &[u8], card: &Card) -> Result<DeviceKey> {
    let v = sign::open(bytes, Kind::DeviceKey, LIMIT, |s| card.device_key(s))?;
    let body: DeviceKeyBody = wire::decode(&v.body, LIMIT, "device key")?;
    if body.profile != card.profile {
        return Err(Error::WrongSigner);
    }
    xwing::check_public(&body.key)?;
    Ok(DeviceKey { device: v.signer, created_at: body.created_at, key: body.key })
}

/// The newest key of each device in `card` among `records`, at most one per device.
pub fn usable(records: &[Vec<u8>], card: &Card) -> Vec<DeviceKey> {
    let mut out: Vec<DeviceKey> = Vec::new();
    for key in records.iter().filter_map(|r| open(r, card).ok()) {
        match out.iter_mut().find(|k| k.device == key.device) {
            Some(k) if k.created_at < key.created_at => *k = key,
            Some(_) => {}
            None => out.push(key),
        }
    }
    out
}
