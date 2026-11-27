//! Signing keys, Ed25519 and ML-DSA-44 together (docs/format.md, "Signing keys"), and the `Signed` envelope.
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use libcrux_ml_dsa::ml_dsa_44::{self, MLDSA44Signature, MLDSA44SigningKey, MLDSA44VerificationKey};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::{Zeroize, Zeroizing};

use crate::wire::{self, vl, Signed};
use crate::{kdf, Error, Result};

/// The ML-DSA-44 half of a public key.
pub const MLDSA_PUBLIC: usize = 1312;
const MLDSA_SIGNATURE: usize = 2420;
/// A public key: the Ed25519 key, then the ML-DSA-44 key.
pub const PUBLIC: usize = 32 + MLDSA_PUBLIC;
/// A signature: the Ed25519 signature, then the ML-DSA-44 signature.
pub const SIGNATURE: usize = 64 + MLDSA_SIGNATURE;

pub type Public = [u8; PUBLIC];

/// `Signed.kind` values and their labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Kind {
    Card = 1,
    Head = 2,
    LogEntry = 3,
    ThreadEntry = 4,
    InboxItem = 5,
    Snapshot = 6,
    TransferGrant = 7,
    OwnerKey = 8,
    SealKey = 9,
    DeviceKey = 10,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Card => "card",
            Kind::Head => "head",
            Kind::LogEntry => "log entry",
            Kind::ThreadEntry => "thread entry",
            Kind::InboxItem => "inbox item",
            Kind::Snapshot => "snapshot",
            Kind::TransferGrant => "transfer grant",
            Kind::OwnerKey => "owner key",
            Kind::SealKey => "seal key",
            Kind::DeviceKey => "device key",
        }
    }
}

/// A signing key: a profile key, a device key or a host admin key.
pub struct Key {
    ed25519: SigningKey,
    mldsa: MLDSA44SigningKey,
    mldsa_public: [u8; MLDSA_PUBLIC],
    /// Signing randomness for the vectors, which must come out the same on every target. Keys otherwise draw it
    /// from the operating system for every signature.
    vectors_rng: Option<std::sync::Mutex<ChaCha20Rng>>,
}

impl Drop for Key {
    fn drop(&mut self) {
        self.mldsa.as_mut_slice().zeroize();
    }
}

impl Key {
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let seed = Zeroizing::new(crate::aead::random::<32>(rng));
        Key::from_seed(&seed)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let xi: Zeroizing<[u8; 32]> = Zeroizing::new(kdf::derive(seed, "ml-dsa"));
        let pair = ml_dsa_44::generate_key_pair(*xi);
        Key {
            ed25519: SigningKey::from_bytes(seed),
            mldsa: pair.signing_key,
            mldsa_public: *pair.verification_key.as_ref(),
            vectors_rng: None,
        }
    }

    /// A key whose signatures are reproducible, for the vectors only.
    pub fn for_vectors(seed: &[u8; 32]) -> Self {
        let mut key = Key::from_seed(seed);
        key.vectors_rng = Some(std::sync::Mutex::new(ChaCha20Rng::from_seed(*seed)));
        key
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.ed25519.to_bytes())
    }

    /// The Ed25519 half of the public key: a device ID, or the `CW-Admin` of an admin key.
    pub fn id(&self) -> [u8; 32] {
        self.ed25519.verifying_key().to_bytes()
    }

    pub fn public(&self) -> Public {
        let mut out = [0u8; PUBLIC];
        out[..32].copy_from_slice(&self.id());
        out[32..].copy_from_slice(&self.mldsa_public);
        out
    }

    /// The ML-DSA-44 half of the public key, which a card lists beside a device ID.
    pub fn mldsa_public(&self) -> [u8; MLDSA_PUBLIC] {
        self.mldsa_public
    }

    /// The profile ID of a profile key.
    pub fn profile_id(&self) -> [u8; 32] {
        profile_id(&self.public())
    }

    fn randomness(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        match &self.vectors_rng {
            Some(rng) => rng.lock().expect("one signer at a time").fill_bytes(&mut *out),
            None => rand::rngs::OsRng.fill_bytes(&mut *out),
        }
        out
    }

    pub fn sign_raw(&self, message: &[u8]) -> Vec<u8> {
        let mldsa = ml_dsa_44::sign(&self.mldsa, message, b"", *self.randomness()).expect("an empty context fits");
        let mut out = Vec::with_capacity(SIGNATURE);
        out.extend_from_slice(&self.ed25519.sign(message).to_bytes());
        out.extend_from_slice(mldsa.as_slice());
        out
    }

    /// Signs `body` as a `Signed` of `kind`, naming `signer`: the device ID, or the profile ID for a card.
    fn sign_as(&self, signer: [u8; 32], kind: Kind, body: Vec<u8>) -> Vec<u8> {
        let signature = self.sign_raw(&message(kind, &body));
        wire::encode(&Signed { kind: kind as u16, body: vl(body), signer, signature: vl(signature) })
    }

    /// Signs as a device (or admin key), naming its ID.
    pub fn sign(&self, kind: Kind, body: Vec<u8>) -> Vec<u8> {
        self.sign_as(self.id(), kind, body)
    }

    /// Signs as a profile key, naming its profile ID.
    pub fn sign_as_profile(&self, kind: Kind, body: Vec<u8>) -> Vec<u8> {
        self.sign_as(self.profile_id(), kind, body)
    }
}

/// The device ID of a seed, its Ed25519 public key, without making the ML-DSA-44 half.
pub fn id_of(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// `SHA-256(label("profile") || public key)`.
pub fn profile_id(public: &Public) -> [u8; 32] {
    kdf::sha256(&kdf::labeled("profile", &[public]))
}

/// A device's public key, from its ID and the ML-DSA-44 key the card lists.
pub fn device_public(id: &[u8; 32], mldsa: &[u8; MLDSA_PUBLIC]) -> Public {
    let mut out = [0u8; PUBLIC];
    out[..32].copy_from_slice(id);
    out[32..].copy_from_slice(mldsa);
    out
}

fn message(kind: Kind, body: &[u8]) -> Vec<u8> {
    let mut out = kdf::label(kind.label());
    out.push(0);
    out.extend_from_slice(body);
    out
}

/// Verifies a signature by `public` over `message`: Ed25519 strictly, refusing weak keys and non-canonical
/// signatures, and ML-DSA-44. Both must verify.
pub fn verify_raw(public: &Public, message: &[u8], signature: &[u8]) -> Result<()> {
    if signature.len() != SIGNATURE {
        return Err(Error::BadSignature);
    }
    let ed: [u8; 32] = public[..32].try_into().unwrap();
    let key = VerifyingKey::from_bytes(&ed).map_err(|_| Error::BadSignature)?;
    if key.is_weak() {
        return Err(Error::BadSignature);
    }
    let ed_signature: [u8; 64] = signature[..64].try_into().unwrap();
    key.verify_strict(message, &Signature::from_bytes(&ed_signature)).map_err(|_| Error::BadSignature)?;
    let mldsa_public: [u8; MLDSA_PUBLIC] = public[32..].try_into().unwrap();
    let mldsa_signature: [u8; MLDSA_SIGNATURE] = signature[64..].try_into().unwrap();
    ml_dsa_44::verify(
        &MLDSA44VerificationKey::new(mldsa_public),
        message,
        b"",
        &MLDSA44Signature::new(mldsa_signature),
    )
    .map_err(|_| Error::BadSignature)
}

/// A verified `Signed`: who signed it and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub signer: [u8; 32],
    pub body: Vec<u8>,
}

/// A decoded `Signed` whose signature isn't checked yet, for structures whose signer's key is inside the body.
pub struct Unverified {
    kind: Kind,
    pub signer: [u8; 32],
    pub body: Vec<u8>,
    signature: Vec<u8>,
}

impl Unverified {
    pub fn decode(bytes: &[u8], kind: Kind, limit: usize) -> Result<Self> {
        let signed: Signed = wire::decode(bytes, limit + SIGNATURE + 64, kind.label())?;
        if signed.kind != kind as u16 {
            return Err(Error::Malformed("signed kind"));
        }
        if signed.body.as_slice().len() > limit {
            return Err(Error::TooLarge(kind.label()));
        }
        Ok(Unverified {
            kind,
            signer: signed.signer,
            body: signed.body.as_slice().to_vec(),
            signature: signed.signature.as_slice().to_vec(),
        })
    }

    /// Verifies with `public`, the signer's key.
    pub fn verify(self, public: &Public) -> Result<Verified> {
        verify_raw(public, &message(self.kind, &self.body), &self.signature)?;
        Ok(Verified { signer: self.signer, body: self.body })
    }
}

/// Decodes and verifies a `Signed` of `kind`. `key` returns the public key of a signer allowed to sign it.
pub fn open(bytes: &[u8], kind: Kind, limit: usize, key: impl FnOnce(&[u8; 32]) -> Option<Public>) -> Result<Verified> {
    let unverified = Unverified::decode(bytes, kind, limit)?;
    let public = key(&unverified.signer).ok_or(Error::WrongSigner)?;
    unverified.verify(&public)
}
