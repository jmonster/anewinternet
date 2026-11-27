//! Every commonwire format and cryptographic rule, as `docs/format.md` defines them.
//! Browsers and the Worker use it as WASM; `commonwire` uses it natively.

pub mod access;
pub mod aead;
pub mod audience;
pub mod b64;
pub mod card;
pub mod devicekey;
mod error;
pub mod head;
pub mod hpke;
pub mod inbox;
pub mod invite;
pub mod kdf;
pub mod link;
pub mod local;
pub mod log;
pub mod object;
pub mod pad;
pub mod recovery;
pub mod request;
pub mod sign;
pub mod thread;
pub mod token;
pub mod transfer;
pub mod vectors;
#[cfg(target_arch = "wasm32")]
mod wasm;
pub mod wire;
pub mod xwing;

pub use error::{Error, Result};
