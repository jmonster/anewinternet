//! HPKE (RFC 9180), single shot, in base or PSK mode, with the X-Wing KEM, HKDF-SHA256 and AES-256-GCM.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{aead, xwing, Error, Result};

/// `"HPKE" || I2OSP(kem, 2) || I2OSP(kdf, 2) || I2OSP(aead, 2)`: X-Wing `0x647a`, HKDF-SHA256, AES-256-GCM.
const SUITE: &[u8] = b"HPKE\x64\x7a\x00\x01\x00\x02";

/// An X-Wing key pair: a private key and the public key it gives.
pub struct KeyPair {
    pub private: Zeroizing<[u8; xwing::PRIVATE]>,
    pub public: [u8; xwing::PUBLIC],
}

impl KeyPair {
    pub fn from_private(private: [u8; xwing::PRIVATE]) -> Self {
        let public = xwing::public(&private);
        KeyPair { private: Zeroizing::new(private), public }
    }
}

pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> KeyPair {
    KeyPair::from_private(aead::random(rng))
}

/// The pre-shared key of PSK mode and its ID.
#[derive(Clone, Copy)]
pub struct Psk<'a> {
    pub key: &'a [u8],
    pub id: &'a [u8],
}

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let input = Zeroizing::new([b"HPKE-v1".as_slice(), suite, label, ikm].concat());
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &input);
    Zeroizing::new(prk.into())
}

fn labeled_expand<const N: usize>(suite: &[u8], prk: &[u8; 32], label: &[u8], info: &[u8]) -> Zeroizing<[u8; N]> {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("32-byte PRK");
    let mut out = Zeroizing::new([0u8; N]);
    hk.expand_multi_info(&[&(N as u16).to_be_bytes(), b"HPKE-v1", suite, label, info], &mut *out).expect("short output");
    out
}

/// The key schedule (RFC 9180 §5.1) of `suite`, for a key of `NK` bytes: the AEAD key and the nonce of the first
/// (and only) message.
pub fn schedule<const NK: usize>(
    suite: &[u8],
    shared: &[u8; 32],
    info: &[u8],
    psk: Option<Psk<'_>>,
) -> Result<(Zeroizing<[u8; NK]>, [u8; 12])> {
    let (mode, key, id) = match psk {
        Some(p) if !p.key.is_empty() && !p.id.is_empty() => (1u8, p.key, p.id),
        Some(_) => return Err(Error::Malformed("hpke psk")),
        None => (0u8, &[][..], &[][..]),
    };
    let psk_id_hash = labeled_extract(suite, b"", b"psk_id_hash", id);
    let info_hash = labeled_extract(suite, b"", b"info_hash", info);
    let context = [[mode].as_slice(), &*psk_id_hash, &*info_hash].concat();
    let secret = labeled_extract(suite, shared, b"secret", key);
    let aead_key = labeled_expand::<NK>(suite, &secret, b"key", &context);
    let nonce = labeled_expand::<12>(suite, &secret, b"base_nonce", &context);
    Ok((aead_key, *nonce))
}

fn cipher(shared: &[u8; 32], info: &[u8], psk: Option<Psk<'_>>) -> Result<(Aes256Gcm, [u8; 12])> {
    let (key, nonce) = schedule::<32>(SUITE, shared, info, psk)?;
    Ok((Aes256Gcm::new_from_slice(&*key).expect("32-byte key"), nonce))
}

/// Seals with the encapsulation randomness `eseed`.
pub fn seal_with(
    eseed: &[u8; 64],
    public: &[u8; xwing::PUBLIC],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    psk: Option<Psk<'_>>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (enc, shared) = xwing::encapsulate(public, eseed)?;
    let (cipher, nonce) = cipher(&shared, info, psk)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::TooLarge("hpke plaintext"))?;
    Ok((enc.to_vec(), ciphertext))
}

/// Seals `plaintext` to `public`. Returns `(enc, ciphertext)`.
pub fn seal(public: &[u8; xwing::PUBLIC], info: &[u8], aad: &[u8], plaintext: &[u8], psk: Option<Psk<'_>>) -> Result<(Vec<u8>, Vec<u8>)> {
    let eseed = Zeroizing::new(aead::random::<64>(&mut rand::rngs::OsRng));
    seal_with(&eseed, public, info, aad, plaintext, psk)
}

pub fn open(
    private: &[u8; xwing::PRIVATE],
    enc: &[u8],
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: Option<Psk<'_>>,
) -> Result<Vec<u8>> {
    let shared = xwing::decapsulate(private, enc)?;
    let (cipher, nonce) = cipher(&shared, info, psk)?;
    cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad }).map_err(|_| Error::Decrypt)
}
