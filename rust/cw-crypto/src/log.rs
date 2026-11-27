//! The owner key, the own log and snapshots.
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::card::Card;
use crate::sign::{self, Key, Kind};
use crate::wire::{self, vl, DeviceSeal, HpkeBox, LogEntryBody, ObjectRef, OwnerKeyBody};
use crate::{aead, audience, hpke, kdf, xwing, Error, Result};

pub const ENTRY_LIMIT: usize = 256 * 1024;
const BOX_LIMIT: usize = ENTRY_LIMIT + 1024;
/// The largest owner key record body: a seal for each of 32 devices and the recovery key.
pub const KEY_LIMIT: usize = 48 * 1024;

fn recovery_info(profile: &[u8; 32], generation: u32) -> Vec<u8> {
    kdf::labeled("owner key", &[profile, &generation.to_be_bytes()])
}

fn device_info(profile: &[u8; 32], generation: u32, device: &[u8; 32]) -> Vec<u8> {
    kdf::labeled("owner key", &[profile, &generation.to_be_bytes(), device])
}

fn hpke_box(public: &[u8; xwing::PUBLIC], info: &[u8], owner_key: &[u8; 32]) -> Result<HpkeBox> {
    let (enc, ciphertext) = hpke::seal(public, info, b"", owner_key, None)?;
    Ok(HpkeBox { enc: vl(enc), ciphertext: vl(ciphertext) })
}

fn open_box(b: &HpkeBox, private: &[u8; xwing::PRIVATE], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let plain = Zeroizing::new(hpke::open(private, b.enc.as_slice(), b.ciphertext.as_slice(), info, b"", None)?);
    Ok(Zeroizing::new(plain.as_slice().try_into().map_err(|_| Error::Malformed("owner key"))?))
}

/// Publishes generation `generation` of the owner key, sealed to the recovery key and to the seal key of every device
/// in `card` that has a valid seal key record among `records`. A device without one gets no seal.
pub fn seal_owner_key(device: &Key, card: &Card, records: &[Vec<u8>], generation: u32, owner_key: &[u8; 32]) -> Result<Vec<u8>> {
    let recovery = wire::encode(&hpke_box(&card.recovery_key, &recovery_info(&card.profile, generation), owner_key)?);
    let seal_keys: Vec<([u8; 32], [u8; xwing::PUBLIC])> =
        records.iter().filter_map(|r| audience::open_seal_key_record(r, card).ok()).collect();
    let devices = card
        .devices
        .iter()
        .filter_map(|d| seal_keys.iter().find(|(id, _)| id == &d.device))
        .map(|(id, key)| {
            Ok(DeviceSeal { device: *id, sealed: hpke_box(key, &device_info(&card.profile, generation, id), owner_key)? })
        })
        .collect::<Result<Vec<_>>>()?;
    let body = wire::encode(&OwnerKeyBody { generation, recovery: vl(recovery), devices });
    if body.len() > KEY_LIMIT {
        return Err(Error::TooLarge("owner key"));
    }
    Ok(device.sign(Kind::OwnerKey, body))
}

/// A verified owner-key record, not yet opened.
pub struct OwnerKeyRecord(OwnerKeyBody);

impl OwnerKeyRecord {
    /// Verifies a record. `key` returns the public key of a device a reader allows to have signed it.
    pub fn open(bytes: &[u8], key: impl FnOnce(&[u8; 32]) -> Option<sign::Public>) -> Result<Self> {
        let v = sign::open(bytes, Kind::OwnerKey, KEY_LIMIT, key)?;
        Ok(OwnerKeyRecord(wire::decode(&v.body, KEY_LIMIT, "owner key")?))
    }

    pub fn generation(&self) -> u32 {
        self.0.generation
    }

    /// Opens the seal to a device, with that device's seal private key.
    pub fn open_sealed(&self, profile: &[u8; 32], device: &[u8; 32], seal_private: &[u8; xwing::PRIVATE]) -> Result<Zeroizing<[u8; 32]>> {
        let seal = self.0.devices.iter().find(|d| &d.device == device).ok_or(Error::WrongSigner)?;
        open_box(&seal.sealed, seal_private, &device_info(profile, self.0.generation, device))
    }

    /// Opens it with the recovery private key.
    pub fn recover(&self, profile: &[u8; 32], recovery_private: &[u8; xwing::PRIVATE]) -> Result<Zeroizing<[u8; 32]>> {
        let b: HpkeBox = wire::decode(self.0.recovery.as_slice(), KEY_LIMIT, "owner key recovery")?;
        open_box(&b, recovery_private, &recovery_info(profile, self.0.generation))
    }
}

fn entry_aad(label: &str, profile: &[u8; 32], seq: u64, generation: u32) -> Vec<u8> {
    kdf::labeled(label, &[profile, &seq.to_be_bytes(), &generation.to_be_bytes()])
}

/// The digest an entry's successor names in `previous`.
pub fn digest(entry: &[u8]) -> [u8; 32] {
    kdf::sha256(entry)
}

#[allow(clippy::too_many_arguments)]
fn seal_chained(
    kind: Kind,
    device: &Key,
    profile: &[u8; 32],
    seq: u64,
    previous: &[u8; 32],
    generation: u32,
    owner_key: &[u8; 32],
    plaintext: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    if plaintext.len() > ENTRY_LIMIT {
        return Err(Error::TooLarge(kind.label()));
    }
    let nonce = aead::random(rng);
    let sealed = aead::seal(owner_key, &nonce, &entry_aad(kind.label(), profile, seq, generation), plaintext);
    let body = LogEntryBody { seq, previous: *previous, generation, nonce, sealed: vl(sealed) };
    Ok(device.sign(kind, wire::encode(&body)))
}

/// What a reader expects at this position of the chain.
pub struct Position<'a> {
    pub seq: u64,
    pub previous: &'a [u8; 32],
}

/// An opened entry or snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub signer: [u8; 32],
    pub seq: u64,
    pub generation: u32,
    pub plaintext: Vec<u8>,
}

fn open_chained(
    kind: Kind,
    bytes: &[u8],
    card: &Card,
    at: Option<Position<'_>>,
    owner_key: impl FnOnce(u32) -> Option<Zeroizing<[u8; 32]>>,
) -> Result<(Opened, [u8; 32])> {
    let v = sign::open(bytes, kind, BOX_LIMIT, |s| card.device_key(s))?;
    let body: LogEntryBody = wire::decode(&v.body, BOX_LIMIT, kind.label())?;
    if let Some(at) = at {
        if body.seq < at.seq {
            return Err(Error::Replay);
        }
        if body.seq != at.seq || &body.previous != at.previous {
            return Err(Error::Rollback);
        }
    }
    let key = owner_key(body.generation).ok_or(Error::WrongGeneration)?;
    let plaintext = aead::open(
        &key,
        &body.nonce,
        &entry_aad(kind.label(), &card.profile, body.seq, body.generation),
        body.sealed.as_slice(),
    )?;
    Ok((Opened { signer: v.signer, seq: body.seq, generation: body.generation, plaintext }, body.previous))
}

#[allow(clippy::too_many_arguments)]
pub fn seal_entry(
    device: &Key,
    profile: &[u8; 32],
    seq: u64,
    previous: &[u8; 32],
    generation: u32,
    owner_key: &[u8; 32],
    operation: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    seal_chained(Kind::LogEntry, device, profile, seq, previous, generation, owner_key, operation, rng)
}

/// Opens the entry at `at`: it must name exactly that sequence number and predecessor.
pub fn open_entry(
    bytes: &[u8],
    card: &Card,
    at: Position<'_>,
    owner_key: impl FnOnce(u32) -> Option<Zeroizing<[u8; 32]>>,
) -> Result<Opened> {
    Ok(open_chained(Kind::LogEntry, bytes, card, Some(at), owner_key)?.0)
}

/// A snapshot of own state through entry `seq`, whose bytes hash to `entry_digest`.
#[allow(clippy::too_many_arguments)]
pub fn seal_snapshot(
    device: &Key,
    profile: &[u8; 32],
    seq: u64,
    entry_digest: &[u8; 32],
    generation: u32,
    owner_key: &[u8; 32],
    state: &ObjectRef,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    seal_chained(Kind::Snapshot, device, profile, seq, entry_digest, generation, owner_key, &wire::encode(state), rng)
}

/// Returns the snapshot's sequence number, the digest of the entry it covers, and its state object.
pub fn open_snapshot(
    bytes: &[u8],
    card: &Card,
    owner_key: impl FnOnce(u32) -> Option<Zeroizing<[u8; 32]>>,
) -> Result<(u64, [u8; 32], ObjectRef)> {
    let (opened, previous) = open_chained(Kind::Snapshot, bytes, card, None, owner_key)?;
    Ok((opened.seq, previous, wire::decode(&opened.plaintext, 128, "snapshot")?))
}
