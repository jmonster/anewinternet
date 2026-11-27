//! Web Push with no content (RFC 8030), authorized with VAPID (RFC 8292).
use cw_crypto::b64;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use serde_json::json;

use crate::Config;

const LIFETIME_S: u64 = 12 * 60 * 60;

/// The push service origin of an endpoint, the JWT audience. `http` is allowed only for loopback hosts, for
/// development.
fn audience(endpoint: &str) -> Option<String> {
    let (scheme, rest) = match endpoint.strip_prefix("https://") {
        Some(rest) => ("https", rest),
        None => ("http", endpoint.strip_prefix("http://")?),
    };
    let host = rest.split('/').next()?;
    let allowed = !host.is_empty() && (scheme == "https" || cw_crypto::card::is_loopback(host));
    allowed.then(|| format!("{scheme}://{host}"))
}

/// Whether an endpoint is acceptable: an `https` URL (or loopback `http`) of at most 1 KiB.
pub fn valid_endpoint(endpoint: &str) -> bool {
    endpoint.len() <= 1024 && audience(endpoint).is_some() && endpoint.bytes().all(|b| b.is_ascii_graphic())
}

/// The `Authorization` header for a push to `endpoint`, reusing a JWT until an hour before it expires.
pub fn authorization(config: &Config, endpoint: &str, now: u64) -> Option<String> {
    let aud = audience(endpoint)?;
    let now_s = now / 1000;
    let mut cache = config.jwts.lock().ok()?;
    let fresh = cache.get(&aud).filter(|(_, exp)| *exp > now_s + 3600).map(|(jwt, _)| jwt.clone());
    let jwt = match fresh {
        Some(jwt) => jwt,
        None => {
            let exp = now_s + LIFETIME_S;
            let header = b64::encode(br#"{"typ":"JWT","alg":"ES256"}"#);
            let claims = b64::encode(json!({ "aud": aud, "exp": exp, "sub": config.origin }).to_string().as_bytes());
            let input = format!("{header}.{claims}");
            let signature: Signature = config.vapid.sign(input.as_bytes());
            let jwt = format!("{input}.{}", b64::encode(&signature.to_bytes()));
            cache.insert(aud, (jwt.clone(), exp));
            jwt
        }
    };
    Some(format!("vapid t={jwt}, k={}", b64::encode(&config.vapid_public)))
}
