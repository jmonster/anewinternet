//! The native commonwire host: cw-host over rusqlite, hyper, rustls and ACME.
pub mod client;
pub mod db;
pub mod io;
pub mod runtime;
pub mod server;
pub mod service;

use std::path::Path;

use cw_crypto::b64;

/// Reads `host.json` in `data`: the host's origin and secrets.
pub fn load_config(data: &Path) -> Result<cw_host::Config, String> {
    let text = std::fs::read_to_string(data.join("host.json"))
        .map_err(|e| format!("no host in {} ({e}); run `commonwire host init` first", data.display()))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("host.json: {e}"))?;
    let field = |k: &str| -> Result<[u8; 32], String> {
        v[k].as_str().and_then(|s| b64::decode_array(s).ok()).ok_or_else(|| format!("host.json: {k}"))
    };
    let origin = v["origin"].as_str().ok_or("host.json: origin")?;
    cw_host::Config::new(field("secret")?, field("claim")?, field("vapid")?, origin).ok_or_else(|| "host.json: invalid".into())
}
