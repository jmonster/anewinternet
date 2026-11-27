//! Signed requests: signature, clock window and nonce memory, which needs storage.
use cw_crypto::request::{self, RequestAuth, Signer, NONCE_MEMORY_MS};
use cw_crypto::sign::Public;

use crate::http::{Request, Response};
use crate::sql::Store;

/// Verifies the owner (`CW-Device`) or admin (`CW-Admin`) signature of a request against the time it arrived.
/// `public` returns the public key of a signer the host allows, by the ID the request names; any other is
/// forbidden. An `expired` answer carries the host's time in `CW-Time`, so a device whose clock is off signs again
/// with it.
pub fn signature(req: &Request, key_header: &str, public: impl FnOnce(&[u8; 32]) -> Option<Public>) -> Result<Signer, Response> {
    let get = |n: &str| req.header(n).map(str::to_string);
    let auth = (|| {
        Some(RequestAuth {
            key: get(key_header)?,
            time: get("cw-time")?,
            nonce: get("cw-nonce")?,
            signature: get("cw-signature")?,
        })
    })()
    .ok_or_else(|| Response::error(401, "unauthorized"))?;
    request::verify(&auth, &req.method, &req.authority, &req.target, &req.body, req.received, public).map_err(|e| match e {
        cw_crypto::Error::Expired => Response::error(401, "expired").with("cw-time", req.received),
        cw_crypto::Error::WrongSigner => Response::error(403, "forbidden"),
        _ => Response::error(401, "unauthorized"),
    })
}

/// Records a signer's nonce, refusing one seen in the last 120 seconds.
pub fn nonce(store: &mut impl Store, signer: &Signer, now: u64) -> Result<(), Response> {
    let failed = |_| Response::error(500, "storage");
    store
        .exec(
            "DELETE FROM nonces WHERE device = ?1 AND at < ?2",
            &[(&signer.key).into(), now.saturating_sub(NONCE_MEMORY_MS).into()],
        )
        .map_err(failed)?;
    let seen = store
        .exec("SELECT 1 FROM nonces WHERE device = ?1 AND nonce = ?2", &[(&signer.key).into(), (&signer.nonce).into()])
        .map_err(failed)?;
    if !seen.is_empty() {
        return Err(Response::error(401, "replay"));
    }
    store
        .exec(
            "INSERT INTO nonces (device, nonce, at) VALUES (?1, ?2, ?3)",
            &[(&signer.key).into(), (&signer.nonce).into(), now.into()],
        )
        .map_err(failed)?;
    Ok(())
}
