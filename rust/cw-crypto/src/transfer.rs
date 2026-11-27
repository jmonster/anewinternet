//! Transfer grants from a tenant's device to a new host.
use crate::card::Card;
use crate::sign::{self, Key, Kind};
use crate::wire::{self, vl, TransferGrantBody};
use crate::{Error, Result};

pub const MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

pub fn grant(device: &Key, tenant: &[u8; 16], new_host: &str, expires_at: u64) -> Vec<u8> {
    device.sign(
        Kind::TransferGrant,
        wire::encode(&TransferGrantBody { tenant: *tenant, new_host: vl(new_host.as_bytes()), expires_at }),
    )
}

/// Verifies a grant for `tenant` and returns the new host it names. The old host accepts it from anyone.
pub fn open(bytes: &[u8], card: &Card, tenant: &[u8; 16], now: u64) -> Result<String> {
    let v = sign::open(bytes, Kind::TransferGrant, 1024, |s| card.device_key(s))?;
    let body: TransferGrantBody = wire::decode(&v.body, 1024, "transfer grant")?;
    if &body.tenant != tenant {
        return Err(Error::WrongSigner);
    }
    if body.expires_at <= now || body.expires_at - now > MAX_LIFETIME_MS {
        return Err(Error::Expired);
    }
    String::from_utf8(body.new_host.as_slice().to_vec()).map_err(|_| Error::Malformed("transfer grant"))
}

/// Verifies a grant for `tenant` presented by `new_host`.
pub fn check(bytes: &[u8], card: &Card, tenant: &[u8; 16], new_host: &str, now: u64) -> Result<()> {
    if open(bytes, card, tenant, now)? != new_host {
        return Err(Error::WrongSigner);
    }
    Ok(())
}
