//! A locked browser's storage (docs/format.md, "Locked browsers"): the local key, sealed under a passkey's PRF output
//! and under the profile seed, and the records, files and names it encrypts.
use aes::cipher::{KeyIvInit, StreamCipher};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::wire::{self, vl, LocalLock, LocalPlace, SealedBox};
use crate::{aead, b64, kdf, Error, Result};

type Ctr = ctr::Ctr128BE<aes::Aes256>;

/// The largest sealed record or file: an object's 16 MiB plaintext after padding, with room to spare.
const SEALED_LIMIT: usize = 32 << 20;
const TAG: usize = 16;

/// A fresh local key.
pub fn new_key(rng: &mut (impl RngCore + CryptoRng)) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(aead::random(rng))
}

fn seal_box(key: &[u8; 32], aad: &[u8], plaintext: &[u8], rng: &mut (impl RngCore + CryptoRng)) -> SealedBox {
    let nonce = aead::random(rng);
    SealedBox { nonce, sealed: vl(aead::seal(key, &nonce, aad, plaintext)) }
}

fn lock_aad(profile: &[u8; 32]) -> Vec<u8> {
    kdf::labeled("local lock", &[profile])
}

/// Seals the local key under the passkey's PRF output and under `S`.
pub fn lock(
    local: &[u8; 32],
    prf: &[u8],
    seed: &[u8; 32],
    profile: &[u8; 32],
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    let aad = lock_aad(profile);
    let by_passkey: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(prf, "local lock"));
    let by_seed: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(seed, "local lock"));
    wire::encode(&LocalLock {
        passkey: seal_box(&by_passkey, &aad, local, rng),
        recovery: seal_box(&by_seed, &aad, local, rng),
    })
}

/// The same lock with its passkey part sealed under another passkey's PRF output; the `S` part stays.
pub fn relock_passkey(
    bytes: &[u8],
    local: &[u8; 32],
    prf: &[u8],
    profile: &[u8; 32],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    let mut lock: LocalLock = wire::decode(bytes, 1024, "local lock")?;
    let by_passkey: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(prf, "local lock"));
    lock.passkey = seal_box(&by_passkey, &lock_aad(profile), local, rng);
    Ok(wire::encode(&lock))
}

fn open_part(part: &SealedBox, key: &[u8; 32], profile: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let plain = Zeroizing::new(aead::open(key, &part.nonce, &lock_aad(profile), part.sealed.as_slice())?);
    let local: [u8; 32] = plain.as_slice().try_into().map_err(|_| Error::Malformed("local lock"))?;
    Ok(Zeroizing::new(local))
}

/// Opens the local key with the passkey's PRF output.
pub fn open_with_passkey(bytes: &[u8], prf: &[u8], profile: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let lock: LocalLock = wire::decode(bytes, 1024, "local lock")?;
    open_part(&lock.passkey, &Zeroizing::new(kdf::derive(prf, "local lock")), profile)
}

/// Opens the local key with `S`, from the written recovery key.
pub fn open_with_seed(bytes: &[u8], seed: &[u8; 32], profile: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let lock: LocalLock = wire::decode(bytes, 1024, "local lock")?;
    open_part(&lock.recovery, &Zeroizing::new(kdf::derive(seed, "local lock")), profile)
}

fn record_aad(store: &str, key: &str) -> Vec<u8> {
    let place = wire::encode(&LocalPlace { store: vl(store.as_bytes()), key: vl(key.as_bytes()) });
    kdf::labeled("local record", &[&place])
}

fn file_aad(path: &str) -> Vec<u8> {
    kdf::labeled("local file", &[path.as_bytes()])
}

fn seal_with(local: &[u8; 32], aad: &[u8], plaintext: &[u8], rng: &mut (impl RngCore + CryptoRng)) -> Vec<u8> {
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::expand(local, "local value"));
    wire::encode(&seal_box(&key, aad, plaintext, rng))
}

fn open_with(local: &[u8; 32], aad: &[u8], bytes: &[u8], what: &'static str) -> Result<Vec<u8>> {
    let b: SealedBox = wire::decode(bytes, SEALED_LIMIT, what)?;
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::expand(local, "local value"));
    aead::open(&key, &b.nonce, aad, b.sealed.as_slice())
}

/// Seals the value of a record that the browser keeps under `key` in `store`.
pub fn seal_record(
    local: &[u8; 32],
    store: &str,
    key: &str,
    value: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    seal_with(local, &record_aad(store, key), value, rng)
}

pub fn open_record(local: &[u8; 32], store: &str, key: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    open_with(local, &record_aad(store, key), bytes, "local record")
}

/// Seals the bytes of a file that the browser keeps at `path`.
pub fn seal_file(local: &[u8; 32], path: &str, bytes: &[u8], rng: &mut (impl RngCore + CryptoRng)) -> Vec<u8> {
    seal_with(local, &file_aad(path), bytes, rng)
}

pub fn open_file(local: &[u8; 32], path: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    open_with(local, &file_aad(path), bytes, "local file")
}

fn name_tag(local: &[u8; 32], segment: &[u8]) -> [u8; TAG] {
    let mac: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::expand(local, "local name mac"));
    kdf::hmac(&*mac, &kdf::labeled("local name", &[segment]))[..TAG].try_into().unwrap()
}

fn name_stream(local: &[u8; 32], tag: &[u8; TAG], bytes: &mut [u8]) {
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::expand(local, "local name"));
    Ctr::new(key.as_ref().into(), tag.into()).apply_keystream(bytes);
}

/// One segment of a record key or file path, encrypted so that the same segment always gives the same name.
pub fn seal_name(local: &[u8; 32], segment: &str) -> String {
    let tag = name_tag(local, segment.as_bytes());
    let mut out = tag.to_vec();
    let start = out.len();
    out.extend_from_slice(segment.as_bytes());
    name_stream(local, &tag, &mut out[start..]);
    b64::encode(&out)
}

pub fn open_name(local: &[u8; 32], name: &str) -> Result<String> {
    let bytes = b64::decode(name)?;
    if bytes.len() < TAG {
        return Err(Error::Malformed("local name"));
    }
    let tag: [u8; TAG] = bytes[..TAG].try_into().unwrap();
    let mut segment = bytes[TAG..].to_vec();
    name_stream(local, &tag, &mut segment);
    if !bool::from(name_tag(local, &segment).ct_eq(&tag)) {
        return Err(Error::Decrypt);
    }
    String::from_utf8(segment).map_err(|_| Error::Malformed("local name"))
}
