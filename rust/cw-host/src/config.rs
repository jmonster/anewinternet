//! A host's secrets and public origin.
use std::collections::HashMap;
use std::sync::Mutex;

use p256::ecdsa::SigningKey;

pub struct Config {
    /// Tokens, tenant IDs and offers are MACs under it.
    pub secret: [u8; 32],
    /// `SHA-256(label("claim") || claim secret)`.
    pub claim: [u8; 32],
    pub vapid: SigningKey,
    /// Uncompressed P-256 point.
    pub vapid_public: [u8; 65],
    /// The origin clients use, `https://host[:port]`, or `http://` for loopback.
    pub origin: String,
    pub(crate) jwts: Mutex<HashMap<String, (String, u64)>>,
}

impl Config {
    pub fn new(secret: [u8; 32], claim: [u8; 32], vapid_secret: [u8; 32], origin: &str) -> Option<Config> {
        let vapid = SigningKey::from_bytes(&vapid_secret.into()).ok()?;
        let point = vapid.verifying_key().to_encoded_point(false);
        let vapid_public: [u8; 65] = point.as_bytes().try_into().ok()?;
        let origin = origin.trim_end_matches('/').to_string();
        let host = origin.strip_prefix("https://").or_else(|| origin.strip_prefix("http://"))?;
        if host.is_empty() || host.contains('/') {
            return None;
        }
        Some(Config { secret, claim, vapid, vapid_public, origin, jwts: Mutex::new(HashMap::new()) })
    }

    pub fn tenant_url(&self, tenant: &[u8; 16]) -> String {
        format!("{}/t/{}", self.origin, cw_crypto::b64::encode(tenant))
    }
}

/// Generates a VAPID private key.
pub fn vapid_secret(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> [u8; 32] {
    SigningKey::random(rng).to_bytes().into()
}
