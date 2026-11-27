//! The profile-signed card.
use crate::sign::{self, Key, Kind, Public, Unverified};
use crate::wire::{self, vl, CardBody, DeviceEntry};
use crate::{xwing, Error, Result};

pub const LIMIT: usize = 48 * 1024;
/// The largest signed card: its body and the envelope around it.
pub const SIGNED_LIMIT: usize = LIMIT + sign::SIGNATURE + 64;
pub const MAX_DEVICES: usize = 32;
pub const MAX_HOSTS: usize = 4;
pub const MAX_URL: usize = 256;
/// How many verified cards `Card::open` keeps.
const VERIFIED_KEPT: usize = 32;

thread_local! {
    static VERIFIED: core::cell::RefCell<Vec<(Vec<u8>, Card)>> = const { core::cell::RefCell::new(Vec::new()) };
}

/// A card's contents, as a device builds or reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// The profile ID, from `profile_key`.
    pub profile: [u8; 32],
    pub profile_key: Public,
    pub version: u64,
    pub issued_at: u64,
    pub devices: Vec<DeviceEntry>,
    pub inbox_key: [u8; xwing::PUBLIC],
    pub recovery_key: [u8; xwing::PUBLIC],
    pub hosts: Vec<String>,
}

impl Card {
    pub fn has_device(&self, device: &[u8; 32]) -> bool {
        self.devices.iter().any(|d| &d.device == device)
    }

    /// The public key of a device the card lists.
    pub fn device_key(&self, device: &[u8; 32]) -> Option<Public> {
        self.devices.iter().find(|d| &d.device == device).map(|d| sign::device_public(&d.device, &d.signing_key))
    }

    fn check(&self) -> Result<()> {
        if self.devices.is_empty() || self.devices.len() > MAX_DEVICES {
            return Err(Error::Malformed("card devices"));
        }
        for (i, d) in self.devices.iter().enumerate() {
            if self.devices[..i].iter().any(|e| e.device == d.device) {
                return Err(Error::Malformed("card devices"));
            }
        }
        if self.hosts.is_empty() || self.hosts.len() > MAX_HOSTS {
            return Err(Error::Malformed("card hosts"));
        }
        for (i, h) in self.hosts.iter().enumerate() {
            tenant_url(h)?;
            if self.hosts[..i].contains(h) {
                return Err(Error::Malformed("card hosts"));
            }
        }
        xwing::check_public(&self.inbox_key)?;
        xwing::check_public(&self.recovery_key)?;
        Ok(())
    }

    /// Signs the card with the profile key, which must be the card's profile key.
    pub fn sign(&self, profile: &Key) -> Result<Vec<u8>> {
        if profile.public() != self.profile_key || sign::profile_id(&self.profile_key) != self.profile {
            return Err(Error::WrongSigner);
        }
        self.check()?;
        let body = CardBody {
            profile_key: self.profile_key,
            version: self.version,
            issued_at: self.issued_at,
            devices: self.devices.clone(),
            inbox_key: self.inbox_key,
            recovery_key: self.recovery_key,
            hosts: self.hosts.iter().map(|h| vl(h.as_bytes())).collect(),
        };
        let bytes = wire::encode(&body);
        if bytes.len() > LIMIT {
            return Err(Error::TooLarge("card"));
        }
        Ok(profile.sign_as_profile(Kind::Card, bytes))
    }

    /// Verifies a card. `profile` is the profile it must belong to, when the caller knows it. A device opens the same
    /// few cards over and over, so the last ones verified are kept and matched by their exact bytes.
    pub fn open(bytes: &[u8], profile: Option<&[u8; 32]>) -> Result<Card> {
        let card = VERIFIED.with(|v| v.borrow().iter().find(|(b, _)| b.as_slice() == bytes).map(|(_, c)| c.clone()));
        let card = match card {
            Some(c) => c,
            None => {
                let c = Card::verify(bytes)?;
                VERIFIED.with(|v| {
                    let mut v = v.borrow_mut();
                    if v.len() == VERIFIED_KEPT {
                        v.remove(0);
                    }
                    v.push((bytes.to_vec(), c.clone()));
                });
                c
            }
        };
        if profile.is_some_and(|p| p != &card.profile) {
            return Err(Error::WrongSigner);
        }
        Ok(card)
    }

    fn verify(bytes: &[u8]) -> Result<Card> {
        let unverified = Unverified::decode(bytes, Kind::Card, LIMIT)?;
        let body: CardBody = wire::decode(&unverified.body, LIMIT, "card")?;
        let id = sign::profile_id(&body.profile_key);
        if unverified.signer != id {
            return Err(Error::WrongSigner);
        }
        unverified.verify(&body.profile_key)?;
        let hosts = body
            .hosts
            .iter()
            .map(|h| String::from_utf8(h.as_slice().to_vec()).map_err(|_| Error::Malformed("card hosts")))
            .collect::<Result<Vec<_>>>()?;
        let card = Card {
            profile: id,
            profile_key: body.profile_key,
            version: body.version,
            issued_at: body.issued_at,
            devices: body.devices,
            inbox_key: body.inbox_key,
            recovery_key: body.recovery_key,
            hosts,
        };
        card.check()?;
        Ok(card)
    }

    /// Accepts `next` over `known`: a strictly higher version, or the identical card.
    pub fn supersedes(known: &[u8], next: &[u8]) -> Result<bool> {
        let a = Card::open(known, None)?;
        let b = Card::open(next, Some(&a.profile))?;
        if b.version > a.version {
            Ok(true)
        } else if b.version == a.version && known == next {
            Ok(false)
        } else {
            Err(Error::Rollback)
        }
    }
}

/// Whether a host (with optional port) is a loopback name: `localhost`, `*.localhost`, `127.0.0.1` or `[::1]`.
pub fn is_loopback(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => {
            return rest.split_once(']').is_some_and(|(a, p)| a == "::1" && (p.is_empty() || p.starts_with(':')))
        }
        None => host.split_once(':').map_or(host, |(n, _)| n),
    };
    name == "localhost" || name.ends_with(".localhost") || name == "127.0.0.1"
}

/// Checks a tenant URL: `https://<host>/t/<22-character tenant ID>`, or `http://` for a loopback host, at most
/// 256 bytes. Returns the tenant ID.
pub fn tenant_url(url: &str) -> Result<[u8; 16]> {
    if url.len() > MAX_URL {
        return Err(Error::TooLarge("tenant url"));
    }
    let (rest, plain) = match url.strip_prefix("https://") {
        Some(rest) => (rest, false),
        None => (url.strip_prefix("http://").ok_or(Error::Malformed("tenant url"))?, true),
    };
    let (host, path) = rest.split_once('/').ok_or(Error::Malformed("tenant url"))?;
    if plain && !is_loopback(host) {
        return Err(Error::Malformed("tenant url"));
    }
    let valid_host = !host.is_empty()
        && host.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || b == b'.'
                || b == b'-'
                || b == b':'
                || b == b'['
                || b == b']'
        });
    let id = path.strip_prefix("t/").ok_or(Error::Malformed("tenant url"))?;
    if !valid_host || id.len() != 22 {
        return Err(Error::Malformed("tenant url"));
    }
    crate::b64::decode_array(id)
}
