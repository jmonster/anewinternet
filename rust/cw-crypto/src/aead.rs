//! AES-256-GCM over padded plaintext.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{CryptoRng, RngCore};

use crate::{pad, Error, Result};

pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let padded = pad::pad(plaintext);
    cipher.encrypt(Nonce::from_slice(nonce), Payload { msg: &padded, aad }).expect("in-memory encryption")
}

pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let padded =
        cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad }).map_err(|_| Error::Decrypt)?;
    pad::unpad(padded)
}

pub fn random<const N: usize>(rng: &mut (impl RngCore + CryptoRng)) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}
