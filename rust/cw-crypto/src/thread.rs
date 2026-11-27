//! Thread entries: signed by the author's device, then encrypted under the post's thread key.
use rand::{CryptoRng, RngCore};

use crate::card::Card;
use crate::sign::{self, Key, Kind};
use crate::wire::{self, vl, SealedBox, ThreadEntryBody};
use crate::{aead, kdf, Error, Result};

pub const ENTRY_LIMIT: usize = 16 * 1024;
pub const MAX_ENTRIES: usize = 2_000;
/// The largest signed entry: the entry JSON, a carried card and the envelope around them.
const SIGNED_LIMIT: usize = ENTRY_LIMIT + crate::card::SIGNED_LIMIT + crate::sign::SIGNATURE + 256;
/// The largest `ThreadBox`, as the host keeps it.
pub const BOX_LIMIT: usize = crate::pad::bucket(SIGNED_LIMIT + 1 + crate::pad::TAG) + 32;

/// The thread ID hosts see: `Expand(T, "thread id", 16)`.
pub fn id(thread_key: &[u8; 32]) -> [u8; 16] {
    kdf::expand(thread_key, "thread id")
}

/// Seals an entry by `device` of the author whose card is `author_card`. `carry` is the signed card the entry
/// carries, or empty: the author's own until the thread holds it, or another profile's that the entry relays.
pub fn seal(
    device: &Key,
    author_card: &[u8],
    carry: &[u8],
    thread_key: &[u8; 32],
    created_at: u64,
    entry: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    if entry.len() > ENTRY_LIMIT {
        return Err(Error::TooLarge("thread entry"));
    }
    let author = Card::open(author_card, None)?;
    if !author.has_device(&device.id()) {
        return Err(Error::WrongSigner);
    }
    if !carry.is_empty() {
        Card::open(carry, None)?;
    }
    let thread = id(thread_key);
    let signed = device.sign(
        Kind::ThreadEntry,
        wire::encode(&ThreadEntryBody {
            author: author.profile,
            thread,
            created_at,
            card: vl(carry),
            entry: vl(entry),
        }),
    );
    let nonce = aead::random(rng);
    let sealed = aead::seal(thread_key, &nonce, &kdf::labeled("thread entry", &[&thread]), &signed);
    Ok(wire::encode(&SealedBox { nonce, sealed: vl(sealed) }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub author: [u8; 32],
    pub signer: [u8; 32],
    pub created_at: u64,
    pub entry: Vec<u8>,
    /// The signed card the entry carries, or empty: the author's own, or another profile's it relays.
    pub card: Vec<u8>,
}

/// Decrypts and verifies an entry. `card` returns the newest card of an author the reader holds: its own copy, or
/// one an earlier entry of the thread carried. The newer of that and the entry's own card names the devices that may
/// sign, so a device removed since can't sign as the author; an entry whose author no card is known for is refused.
pub fn open(bytes: &[u8], thread_key: &[u8; 32], card: impl FnOnce(&[u8; 32]) -> Option<Card>) -> Result<Entry> {
    let b: SealedBox = wire::decode(bytes, BOX_LIMIT, "thread entry")?;
    let thread = id(thread_key);
    let signed = aead::open(thread_key, &b.nonce, &kdf::labeled("thread entry", &[&thread]), b.sealed.as_slice())?;
    // The author is inside the signed body: decode it, find the author's card, then verify.
    let unverified = sign::Unverified::decode(&signed, Kind::ThreadEntry, SIGNED_LIMIT)?;
    let body: ThreadEntryBody = wire::decode(&unverified.body, SIGNED_LIMIT, "thread entry")?;
    if body.thread != thread {
        return Err(Error::Malformed("thread id"));
    }
    if body.entry.as_slice().len() > ENTRY_LIMIT {
        return Err(Error::TooLarge("thread entry"));
    }
    // A relayed card belongs to another profile and says nothing about this entry's author.
    let carried = match body.card.as_slice() {
        [] => None,
        bytes => Some(Card::open(bytes, None)?).filter(|c| c.profile == body.author),
    };
    let known = card(&body.author).filter(|c| c.profile == body.author);
    let author_card = match (carried, known) {
        (Some(c), Some(k)) => if k.version > c.version { k } else { c },
        (Some(c), None) => c,
        (None, Some(k)) => k,
        (None, None) => return Err(Error::WrongSigner),
    };
    let key = author_card.device_key(&unverified.signer).ok_or(Error::WrongSigner)?;
    let v = unverified.verify(&key)?;
    Ok(Entry {
        author: body.author,
        signer: v.signer,
        created_at: body.created_at,
        entry: body.entry.as_slice().to_vec(),
        card: body.card.as_slice().to_vec(),
    })
}
