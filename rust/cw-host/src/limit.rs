//! Fixed one-minute windows, kept in memory, for per-IP and per-token limits.
use std::collections::HashMap;

#[derive(Default)]
pub struct Windows {
    map: HashMap<Vec<u8>, (u64, u32)>,
}

const MAX_KEYS: usize = 20_000;

impl Windows {
    /// Counts one hit for `key`. Returns the seconds to wait when the limit is reached.
    pub fn hit(&mut self, key: &[u8], now: u64, limit: u32) -> Result<(), u64> {
        let minute = now / 60_000;
        if self.map.len() >= MAX_KEYS {
            self.map.retain(|_, (m, _)| *m == minute);
        }
        let slot = self.map.entry(key.to_vec()).or_insert((minute, 0));
        if slot.0 != minute {
            *slot = (minute, 0);
        }
        if slot.1 >= limit {
            return Err(60 - (now / 1000) % 60);
        }
        slot.1 += 1;
        Ok(())
    }
}

/// Open, signed, grant and offer requests per IP per minute.
pub const PER_IP: u32 = 120;
/// Requests with a group read token per IP per minute.
pub const GROUP_READ_PER_IP: u32 = 600;
/// Requests with a group write token per IP per minute.
pub const GROUP_WRITE_PER_IP: u32 = 30;
/// Requests with a slot token per IP per minute.
pub const SLOT_PER_IP: u32 = 30;
/// Writes per token per minute.
pub const PER_TOKEN: u32 = 60;
/// Writes per group write token per minute.
pub const GROUP_WRITE_PER_TOKEN: u32 = 600;

/// The key of an address's window for one per-IP limit: IPv4 addresses whole, IPv6 addresses by their first 64
/// bits, since one subscriber holds a whole /64.
pub fn ip_key(limit: u8, ip: std::net::IpAddr) -> Vec<u8> {
    let mut key = vec![limit];
    match ip {
        std::net::IpAddr::V4(a) => key.extend_from_slice(&a.octets()),
        std::net::IpAddr::V6(a) => key.extend_from_slice(&a.octets()[..8]),
    }
    key
}
