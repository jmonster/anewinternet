//! Inbox items: signed by the sender's device, padded and encrypted under an item key, which is wrapped for each of
//! the recipient's device inbox keys (docs/format.md, "Inbox items").
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::card::Card;
use crate::devicekey::{self, DeviceKey};
use crate::sign::{self, Key, Kind};
use crate::wire::{self, vl, Acceptance, DeviceWrap, HpkeBox, InboxBox, InboxItemBody, LinkRequest, Question};
use crate::{aead, hpke, kdf, pad, xwing, Error, Result};

pub const ITEM_LIMIT: usize = 64 * 1024;
pub const MAX_ITEMS: usize = 2_000;
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
pub const MAX_SKEW_MS: u64 = 10 * 60 * 1000;
/// The most device key records an item carries.
pub const MAX_KEYS: usize = 8;
const MAX_WRAPS: usize = crate::card::MAX_DEVICES;
const KEYS_LIMIT: usize = MAX_KEYS * 4096;
const SIGNED_LIMIT: usize = ITEM_LIMIT + KEYS_LIMIT + 1024;
/// The largest `InboxBox`, as the host takes it.
pub const BOX_LIMIT: usize = pad::bucket(SIGNED_LIMIT + sign::SIGNATURE + 1 + pad::TAG) + MAX_WRAPS * 1280 + 64;

pub mod kind {
    pub const NOTICE: u16 = 1;
    pub const MESSAGE: u16 = 2;
    pub const RECEIPT: u16 = 3;
    pub const ACCEPTANCE: u16 = 4;
    pub const PRIVATE_COMMENT: u16 = 5;
    pub const LINK_REQUEST: u16 = 6;
    pub const CARD_CHANGED: u16 = 7;
    pub const CONVERSATION: u16 = 8;
    pub const QUESTION: u16 = 9;
    pub const BUNDLE: u16 = 10;
    pub const LAST: u16 = 10;
}

fn aad(recipient: &[u8; 32]) -> Vec<u8> {
    kdf::labeled("inbox", &[recipient])
}

fn wrap_info(recipient: &[u8; 32], device: &[u8; 32], created_at: u64) -> Vec<u8> {
    kdf::labeled("inbox", &[recipient, device, &created_at.to_be_bytes()])
}

/// Seals an item to the newest key of each device of `recipient_card` among `records`, carrying `keys`, the sender's
/// own device key records. Refuses with `NoDeviceKey` when none of them is the recipient's.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    device: &Key,
    sender: &[u8; 32],
    recipient_card: &Card,
    records: &[Vec<u8>],
    keys: &[Vec<u8>],
    id: [u8; 16],
    created_at: u64,
    kind: u16,
    payload: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    if !(1..=kind::LAST).contains(&kind) {
        return Err(Error::Malformed("inbox kind"));
    }
    if payload.len() > ITEM_LIMIT {
        return Err(Error::TooLarge("inbox item"));
    }
    if keys.len() > MAX_KEYS {
        return Err(Error::TooLarge("inbox keys"));
    }
    let to = devicekey::usable(records, recipient_card);
    if to.is_empty() {
        return Err(Error::NoDeviceKey);
    }
    let recipient = recipient_card.profile;
    let body = InboxItemBody {
        sender: *sender,
        recipient,
        id,
        created_at,
        kind,
        payload: vl(payload),
        keys: keys.iter().map(|k| vl(k.as_slice())).collect(),
    };
    let signed = device.sign(Kind::InboxItem, wire::encode(&body));
    let k = Zeroizing::new(aead::random::<32>(rng));
    let ciphertext = aead::seal(&k, &[0; 12], &aad(&recipient), &signed);
    let wraps = to
        .iter()
        .map(|d: &DeviceKey| {
            let (enc, sealed) = hpke::seal(&d.key, &wrap_info(&recipient, &d.device, d.created_at), b"", &*k, None)?;
            Ok(DeviceWrap { device: d.device, created_at: d.created_at, wrap: HpkeBox { enc: vl(enc), ciphertext: vl(sealed) } })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(wire::encode(&InboxBox { ciphertext: vl(ciphertext), wraps }))
}

pub fn new_id(rng: &mut (impl RngCore + CryptoRng)) -> [u8; 16] {
    crate::aead::random(rng)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub sender: [u8; 32],
    pub signer: [u8; 32],
    pub id: [u8; 16],
    pub created_at: u64,
    pub kind: u16,
    pub payload: Vec<u8>,
    /// The sender's device key records the item carried that verify against the sender's card.
    pub keys: Vec<Vec<u8>>,
}

/// Opens an item sealed to this person, with the key of this device (`device`) that `private` returns for a record's
/// `created_at`. `card` returns a known sender's card; `seen` reports processed IDs.
pub fn open(
    bytes: &[u8],
    recipient: &[u8; 32],
    device: &[u8; 32],
    private: impl Fn(u64) -> Option<Zeroizing<[u8; xwing::PRIVATE]>>,
    now: u64,
    card: impl FnOnce(&[u8; 32]) -> Option<Card>,
    seen: impl FnOnce(&[u8; 16]) -> bool,
) -> Result<Item> {
    let b: InboxBox = wire::decode(bytes, BOX_LIMIT, "inbox item")?;
    if b.wraps.is_empty() || b.wraps.len() > MAX_WRAPS {
        return Err(Error::Malformed("inbox wraps"));
    }
    let (w, key) = b
        .wraps
        .iter()
        .filter(|w| &w.device == device)
        .find_map(|w| private(w.created_at).map(|k| (w, k)))
        .ok_or(Error::Decrypt)?;
    let k = Zeroizing::new(hpke::open(
        &key,
        w.wrap.enc.as_slice(),
        w.wrap.ciphertext.as_slice(),
        &wrap_info(recipient, device, w.created_at),
        b"",
        None,
    )?);
    let k: Zeroizing<[u8; 32]> = Zeroizing::new(k.as_slice().try_into().map_err(|_| Error::Decrypt)?);
    let signed = aead::open(&k, &[0; 12], &aad(recipient), b.ciphertext.as_slice())?;
    // The signer's key depends on the body: decode first, then verify with the key the body's rules name.
    let unverified = sign::Unverified::decode(&signed, Kind::InboxItem, SIGNED_LIMIT)?;
    let body: InboxItemBody = wire::decode(&unverified.body, SIGNED_LIMIT, "inbox item")?;
    if body.payload.as_slice().len() > ITEM_LIMIT || body.keys.len() > MAX_KEYS {
        return Err(Error::TooLarge("inbox item"));
    }
    if &body.recipient != recipient {
        return Err(Error::Malformed("inbox recipient"));
    }
    if !(1..=kind::LAST).contains(&body.kind) {
        return Err(Error::Malformed("inbox kind"));
    }
    if body.created_at.saturating_add(MAX_AGE_MS) < now || body.created_at > now.saturating_add(MAX_SKEW_MS) {
        return Err(Error::Expired);
    }
    let payload = body.payload.as_slice();
    let signer = unverified.signer;
    let mut sender_card: Option<Card> = None;
    let key = match body.kind {
        // Items from people the recipient may hold no card for carry the sender's card, which the signer must be in.
        kind::ACCEPTANCE | kind::CARD_CHANGED | kind::QUESTION => {
            let card_bytes = match body.kind {
                kind::ACCEPTANCE => wire::decode::<Acceptance>(payload, ITEM_LIMIT, "acceptance")?.card.as_slice().to_vec(),
                kind::QUESTION => wire::decode::<Question>(payload, ITEM_LIMIT, "question")?.card.as_slice().to_vec(),
                _ => payload.to_vec(),
            };
            let c = Card::open(&card_bytes, Some(&body.sender))?;
            let k = c.device_key(&signer);
            sender_card = Some(c);
            k
        }
        // A device asking to be linked isn't in the card yet: its request carries its key.
        kind::LINK_REQUEST => {
            let request: LinkRequest = wire::decode(payload, ITEM_LIMIT, "link request")?;
            (body.sender == *recipient && request.device == signer)
                .then(|| sign::device_public(&request.device, &request.signing_key))
        }
        _ => {
            let c = card(&body.sender).filter(|c| c.profile == body.sender);
            let k = c.as_ref().and_then(|c| c.device_key(&signer));
            sender_card = c;
            k
        }
    };
    let key = key.ok_or(Error::WrongSigner)?;
    let v = unverified.verify(&key)?;
    if seen(&body.id) {
        return Err(Error::Replay);
    }
    // A link request comes from this person's own new device; its keys are checked once its card lists it.
    let keys = match &sender_card {
        Some(c) => body.keys.iter().map(|k| k.as_slice().to_vec()).filter(|k| devicekey::open(k, c).is_ok()).collect(),
        None => Vec::new(),
    };
    Ok(Item {
        sender: body.sender,
        signer: v.signer,
        id: body.id,
        created_at: body.created_at,
        kind: body.kind,
        payload: payload.to_vec(),
        keys,
    })
}
