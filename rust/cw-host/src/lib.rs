//! The commonwire host API (docs/hosts.md): one implementation, run by `commonwire` natively and by the
//! Cloudflare Worker as WASM. The runtime supplies storage, the clock, randomness, open sockets and fetches.
pub mod auth;
pub mod config;
pub mod gate;
pub mod host;
pub mod http;
pub mod limit;
pub mod push;
pub mod route;
pub mod schema;
pub mod sql;
pub mod tenant;
#[cfg(target_arch = "wasm32")]
mod wasm;

pub use config::Config;
pub use http::{Request, Response};
pub use sql::{Store, Value};

pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// A guest's quota and how long it may write before its notice begins (docs/hosts.md, "Guests and budgets").
pub const GUEST_QUOTA: u64 = 10 * 1024 * 1024;
pub const GUEST_MS: u64 = 30 * DAY_MS;
/// How long a guest's notice lasts, read-only, before it is removed.
pub const GUEST_NOTICE_MS: u64 = 30 * DAY_MS;
/// Guest offers and guests one member holds at once.
pub const SPONSOR_LIMIT: i64 = 25;
/// The settings a host starts with.
pub const GUEST_LIMIT: u64 = 100;
pub const MEMBER_BUDGET: u64 = 20_000;
pub const GUEST_BUDGET: u64 = 5_000;
