//! Requests and responses as the handlers see them.
use serde_json::json;

#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    /// The host as sent in `:authority` or `Host`.
    pub authority: String,
    /// The path and query exactly as sent.
    pub target: String,
    /// Header names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// When the headers arrived, in ms. A signature's clock window ends here, so a slow upload doesn't age it.
    pub received: u64,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    pub fn path(&self) -> &str {
        self.target.split_once('?').map_or(self.target.as_str(), |(p, _)| p)
    }
    pub fn query(&self, key: &str) -> Option<&str> {
        let (_, q) = self.target.split_once('?')?;
        q.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v))
    }
    pub fn query_u64(&self, key: &str) -> Option<u64> {
        let v = self.query(key)?;
        if v.is_empty() || v.len() > 19 || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        v.parse().ok()
    }
    pub fn header_u64(&self, name: &str) -> Option<u64> {
        let v = self.header(name)?.trim().trim_matches('"');
        if v.is_empty() || v.len() > 19 || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        v.parse().ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Response { status, headers: Vec::new(), body }
    }
    pub fn ok(body: Vec<u8>) -> Self {
        Response::new(200, body).with("content-type", "application/octet-stream")
    }
    pub fn empty(status: u16) -> Self {
        Response::new(status, Vec::new())
    }
    pub fn json(status: u16, value: serde_json::Value) -> Self {
        Response::new(status, value.to_string().into_bytes()).with("content-type", "application/json")
    }
    pub fn error(status: u16, code: &str) -> Self {
        Response::json(status, json!({ "error": code }))
    }
    pub fn with(mut self, name: &str, value: impl ToString) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    /// A changing resource: an `ETag`, revalidated by the browser's own cache.
    pub fn tagged(self, tag: u64, req: &Request) -> Self {
        let etag = format!("\"{tag}\"");
        if req.header("if-none-match").is_some_and(|v| v.split(',').any(|t| t.trim() == etag)) {
            return Response::empty(304).with("etag", etag).with("cache-control", "no-cache");
        }
        self.with("etag", etag).with("cache-control", "no-cache")
    }
    pub fn immutable(self) -> Self {
        self.with("cache-control", "private, max-age=31536000, immutable")
    }
    /// Adds the CORS headers every host response carries.
    pub fn cors(mut self) -> Self {
        if self.header("access-control-allow-origin").is_none() {
            self.headers.push(("access-control-allow-origin".into(), "*".into()));
            self.headers.push(("access-control-expose-headers".into(), EXPOSED.into()));
        }
        self
    }
}

pub const EXPOSED: &str = "etag, cw-current, cw-epoch, cw-seq, cw-time, cw-index, retry-after";
const ALLOWED: &str = "authorization, content-type, if-match, if-none-match, cw-device, cw-admin, cw-time, cw-nonce, cw-signature, cw-grant, cw-claim, cw-offer";

/// The answer to every CORS preflight.
pub fn preflight() -> Response {
    Response::empty(204)
        .with("access-control-allow-origin", "*")
        .with("access-control-allow-methods", "GET, HEAD, POST, PUT, DELETE")
        .with("access-control-allow-headers", ALLOWED)
        .with("access-control-max-age", "86400")
}
