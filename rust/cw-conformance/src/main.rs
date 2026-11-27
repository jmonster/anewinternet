//! The host conformance suite (docs/hosts.md).
//!
//! `cw-conformance check --base <origin> --claim <secret>` runs every route, request class and refusal against a
//! running host and prints a JSON report of outcomes, which must be identical on every runtime. Encrypted
//! payloads carry the text `MARKER`, so a scan of the host's storage afterwards proves no plaintext was stored.
//!
//! `cw-conformance seed --base <origin> --claim <secret> --tenants N` creates N tenants with published heads and
//! prints their URLs and read tokens. `cw-conformance load --base <origin> --seeded <file> --readers R
//! --interval-ms I` measures head reads from R concurrent readers spread across the seeded tenants, each on its
//! own connection reading every I ms (0 reads back to back, which measures saturation throughput rather than
//! latency). `cw-conformance idle --base <origin> --claim <secret> --seconds S` opens a push socket and pings it
//! for S seconds.
//!
//! `cw-conformance restarts --base <origin> --claim <secret> --tenants N --seconds S` writes and reads as N owners
//! and their friends would for S seconds while the host is restarted: each operation is retried until the host
//! answers it, and afterwards every acknowledged write must be readable.
//!
//! `cw-conformance wakes --base <origin> --claim <secret> --seconds S` runs, for S seconds, three tenants whose
//! objects a host on Cloudflare bills separately: ten friends reading one person's head 12 s apart, the same
//! ten reading another's 4 s apart, and an owner's push socket pinged as the app pings it. It prints each
//! tenant's requests and the time window, to compare with the account's Durable Object analytics.
//!
//! `cw-conformance upgrade-make --base <origin> --claim <secret>` makes a tenant with requests every host version
//! answers and prints its keys; after the host is replaced by a newer build over the same data,
//! `cw-conformance upgrade-check --base <origin> --saved <file>` runs a request of every newer kind against it.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use commonwire::client::{fetch, Fetched};
use cw_crypto::card::Card;
use cw_crypto::sign::Key;
use cw_crypto::wire::{self, DeviceEntry, Entries, InviteKeys, InvitePublic, InviteUpload, LinkReplyBody, OwnerKey};
use cw_crypto::{audience, b64, devicekey, head, hpke, inbox, invite, kdf, link, log, object, recovery, request, thread, transfer};
use futures::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("cw-conformance: {message}");
    std::process::exit(1)
}

type Headers = Vec<(&'static str, String)>;

struct Person {
    profile: Key,
    devices: Vec<Key>,
    inbox: hpke::KeyPair,
    seed: [u8; 32],
    version: u64,
    card: Vec<u8>,
    tenant: [u8; 16],
    url: String,
    owner: Vec<String>,
    read: String,
    write: String,
    contact: String,
    contact_next: String,
}

const PLACEHOLDER: &str = "https://placeholder.example/t/AAAAAAAAAAAAAAAAAAAAAA";

impl Person {
    fn new(devices: usize) -> Person {
        let seed = random::<32>();
        let profile = Key::from_seed(&seed);
        let devices: Vec<Key> = (0..devices).map(|_| Key::generate(&mut OsRng)).collect();
        let inbox = hpke::generate(&mut OsRng);
        let mut p = Person {
            profile,
            devices,
            inbox,
            seed,
            version: 0,
            card: Vec::new(),
            tenant: [0; 16],
            url: String::new(),
            owner: Vec::new(),
            read: String::new(),
            write: String::new(),
            contact: String::new(),
        contact_next: String::new(),
        };
        p.card = p.sign_card(1, &[PLACEHOLDER.to_string()]);
        p
    }

    fn sign_card(&mut self, version: u64, hosts: &[String]) -> Vec<u8> {
        self.version = version;
        let card = Card {
            profile: self.profile.profile_id(),
            profile_key: self.profile.public(),
            version,
            issued_at: now(),
            devices: self
                .devices
                .iter()
                .map(|d| DeviceEntry { device: d.id(), signing_key: d.mldsa_public(), added_at: 1 })
                .collect(),
            inbox_key: self.inbox.public,
            recovery_key: recovery::recovery_keys(&self.seed).public,
            hosts: hosts.to_vec(),
        };
        card.sign(&self.profile).unwrap()
    }

    /// A fresh inbox key record of this person's first device.
    fn device_key(&self) -> Vec<u8> {
        self.device_keys()[0].clone()
    }

    /// One inbox key record per device, the same each time: what this person's hosts hold once put there.
    fn device_keys(&self) -> Vec<Vec<u8>> {
        let profile = self.profile.profile_id();
        self.devices
            .iter()
            .enumerate()
            .map(|(i, d)| devicekey::create(d, &profile, 1 + i as u64, &mut <rand::rngs::StdRng as rand::SeedableRng>::from_seed(*d.seed())).0)
            .collect()
    }

    /// An item from `from` to this person, sealed to every one of their devices' inbox keys.
    fn sealed_item(&self, from: &Person, text: &[u8]) -> Vec<u8> {
        inbox::seal(&from.devices[0], &from.profile.profile_id(), &self.card(), &self.device_keys(), &[], inbox::new_id(&mut OsRng), now(), inbox::kind::MESSAGE, text, &mut OsRng)
            .unwrap()
    }

    /// Each device's own seal key record, as the own log keeps them.
    fn seal_records(&self) -> Vec<Vec<u8>> {
        self.devices.iter().map(|d| audience::seal_key_record(d, &self.profile.profile_id())).collect()
    }

    fn card(&self) -> Card {
        Card::open(&self.card, None).unwrap()
    }

    fn tid(&self) -> String {
        b64::encode(&self.tenant)
    }

    fn tokens(&self) -> Vec<head::KeyringTokens> {
        vec![head::KeyringTokens { read: self.read.clone(), write: self.write.clone(), contact: self.contact.clone() }]
    }
}

struct Suite {
    base: String,
    authority: String,
    claim: [u8; 32],
    out: BTreeMap<String, String>,
    admin: Key,
    admin_token: String,
    /// Wait out rate limits instead of reporting them; the conformance check reports them.
    patient: bool,
}

fn outcome(f: &Fetched) -> String {
    let code = serde_json::from_slice::<Value>(&f.body).ok().and_then(|v| v["error"].as_str().map(str::to_string));
    match code {
        Some(c) => format!("{} {c}", f.status),
        None => f.status.to_string(),
    }
}

/// An inbox list as `(seq, kind, body)`, each entry an `InboxEntry`.
fn inbox_entries(f: &Fetched) -> Vec<(u64, u8, Vec<u8>)> {
    entries(f)
        .into_iter()
        .filter_map(|(seq, bytes)| {
            let e = wire::decode::<wire::InboxEntry>(&bytes, usize::MAX, "inbox entry").ok()?;
            Some((seq, e.kind, e.body.as_slice().to_vec()))
        })
        .collect()
}

fn json_body(f: &Fetched) -> Value {
    serde_json::from_slice(&f.body).unwrap_or(Value::Null)
}

fn entries(f: &Fetched) -> Vec<(u64, Vec<u8>)> {
    wire::decode::<Entries>(&f.body, usize::MAX, "entries")
        .map(|e| e.entries.into_iter().map(|e| (e.position, e.bytes.as_slice().to_vec())).collect())
        .unwrap_or_default()
}

impl Suite {
    fn record(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        eprintln!("  {name}: {value}");
        self.out.insert(name.to_string(), value);
    }

    async fn call(&self, method: &str, path: &str, headers: Headers, body: Vec<u8>) -> Fetched {
        loop {
            let f = fetch(method, &format!("{}{path}", self.base), &headers, body.clone())
                .await
                .unwrap_or_else(|e| fail(format!("{method} {path}: {e}")));
            if !(self.patient && f.status == 429) {
                return f;
            }
            let wait = f.header("retry-after").and_then(|w| w.parse().ok()).unwrap_or(1);
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }
    }

    fn sign(&self, key: &Key, header: &'static str, method: &str, path: &str, body: &[u8], at: u64) -> Headers {
        let a = request::sign(key, method, &self.authority, path, body, at, &mut OsRng);
        vec![(header, a.key), ("cw-time", a.time), ("cw-nonce", a.nonce), ("cw-signature", a.signature)]
    }

    async fn signed(&self, key: &Key, method: &str, path: &str, body: Vec<u8>) -> Fetched {
        let h = self.sign(key, "cw-device", method, path, &body, now());
        self.call(method, path, h, body).await
    }

    async fn admin(&self, key: &Key, method: &str, path: &str, body: Vec<u8>) -> (Fetched, Headers) {
        let mut h = self.sign(key, "cw-admin", method, path, &body, now());
        h.push(("authorization", format!("CW {}", self.admin_token)));
        (self.call(method, path, h.clone(), body).await, h)
    }

    async fn owner(
        &self,
        p: &Person,
        d: usize,
        method: &str,
        rel: &str,
        body: Vec<u8>,
        if_match: Option<u64>,
    ) -> Fetched {
        let path = format!("/t/{}{rel}", p.tid());
        let mut h = self.sign(&p.devices[d], "cw-device", method, &path, &body, now());
        h.push(("authorization", format!("CW {}", p.owner[d])));
        if let Some(m) = if_match {
            h.push(("if-match", m.to_string()));
        }
        self.call(method, &path, h, body).await
    }

    /// `POST /batch` of `(method, path, If-Match, body)` requests.
    async fn batch(&self, p: &Person, d: usize, requests: Vec<(&str, String, Option<u64>, Vec<u8>)>) -> Fetched {
        let batch = wire::Batch {
            requests: requests
                .into_iter()
                .map(|(method, path, if_match, body)| wire::BatchRequest {
                    method: wire::vl(method.as_bytes()),
                    path: wire::vl(path.into_bytes()),
                    if_match,
                    body: wire::vl(body),
                })
                .collect(),
        };
        self.owner(p, d, "POST", "/batch", wire::encode(&batch), None).await
    }

    async fn read(&self, p: &Person, rel: &str, token: &str, extra: Headers) -> Fetched {
        let sep = if rel.contains('?') { '&' } else { '?' };
        self.call("GET", &format!("/t/{}{rel}{sep}t={token}", p.tid()), extra, vec![]).await
    }

    async fn tokens(&self, p: &mut Person) -> Fetched {
        let mut last = None;
        p.owner.clear();
        for d in 0..p.devices.len() {
            let f = self.signed(&p.devices[d], "POST", &format!("/t/{}/tokens", p.tid()), vec![]).await;
            let v = json_body(&f);
            p.owner.push(v["owner"].as_str().unwrap_or_default().to_string());
            p.read = v["read"].as_str().unwrap_or_default().to_string();
            p.write = v["write"].as_str().unwrap_or_default().to_string();
            p.contact = v["contact"].as_str().unwrap_or_default().to_string();
            p.contact_next = v["contact_next"].as_str().unwrap_or_default().to_string();
            last = Some(f);
        }
        last.unwrap()
    }

    async fn put_card(&self, p: &mut Person, hosts: &[String]) -> Fetched {
        p.card = p.sign_card(p.version + 1, hosts);
        let card = p.card.clone();
        self.signed(&p.devices[0], "PUT", &format!("/t/{}/card", p.tid()), card).await
    }

    async fn inbox_item(&self, from: &Person, to: &Person, text: &[u8]) -> Vec<u8> {
        to.sealed_item(from, text)
    }
}

/// A local push service that records each push's `Authorization` header.
async fn push_service() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { continue };
            let log = log.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let log = log.clone();
                    async move {
                        let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
                        log.lock().unwrap().push(auth.to_string());
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder().status(201).body(commonwire::io::Full::new(vec![])).unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(commonwire::io::Io(tcp), svc).await;
            });
        }
    });
    (addr, seen)
}

/// Checks a VAPID authorization: ES256 by the host's push key, for this audience, from this origin.
fn vapid_valid(auth: &str, key: &[u8], audience: &str, origin: &str) -> bool {
    use p256::ecdsa::signature::Verifier;
    let Some(rest) = auth.strip_prefix("vapid t=") else { return false };
    let Some((jwt, k)) = rest.split_once(", k=") else { return false };
    if b64::decode(k).ok().as_deref() != Some(key) {
        return false;
    }
    let parts: Vec<&str> = jwt.split('.').collect();
    let (Some(claims), Some(sig)) =
        (parts.get(1).and_then(|c| b64::decode(c).ok()), parts.get(2).and_then(|s| b64::decode(s).ok()))
    else {
        return false;
    };
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(key) else { return false };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(&sig) else { return false };
    let claims: Value = serde_json::from_slice(&claims).unwrap_or(Value::Null);
    vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).is_ok()
        && claims["aud"] == audience
        && claims["sub"] == origin
        && claims["exp"].as_u64().is_some_and(|e| e > now() / 1000)
}

async fn socket(
    suite: &Suite,
    p: &Person,
    d: usize,
) -> Result<Ws, u16> {
    let protocol = request::socket_protocol(&p.devices[d], &p.owner[d], &suite.authority, &p.tid(), now(), &mut OsRng);
    let req = http::Request::builder()
        .uri(format!("{}/t/{}/push", suite.base.replacen("http", "ws", 1), p.tid()))
        .header("host", &suite.authority)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", tokio_tungstenite::tungstenite::handshake::client::generate_key())
        .header("sec-websocket-protocol", format!("cw1, {protocol}"))
        .body(())
        .unwrap();
    let (conn, _, _) = commonwire::client::connect(&suite.base).await.map_err(|_| 0u16)?;
    match tokio_tungstenite::client_async(req, conn).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
        Err(_) => Err(1),
    }
}

type Ws = tokio_tungstenite::WebSocketStream<Box<dyn commonwire::client::Conn>>;

async fn next_text(ws: &mut Ws) -> Option<String> {
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => Some(t.as_str().to_string()),
        _ => None,
    }
}

async fn wait_pushes(seen: &Arc<Mutex<Vec<String>>>, n: usize) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && seen.lock().unwrap().len() < n {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    seen.lock().unwrap().len()
}

async fn check(base: &str, claim: [u8; 32]) -> BTreeMap<String, String> {
    let authority = base.split_once("://").map(|(_, a)| a.to_string()).unwrap_or_default();
    let mut s = Suite {
        base: base.to_string(),
        authority,
        claim,
        out: BTreeMap::new(),
        admin: Key::generate(&mut OsRng),
        admin_token: String::new(),
        patient: false,
    };

    // The gate.
    let f = s.call("GET", "/nope", vec![], vec![]).await;
    s.record("gate.unknown-path", outcome(&f));
    let f = s.call("OPTIONS", "/t/AAAAAAAAAAAAAAAAAAAAAA/head", vec![], vec![]).await;
    let conditional = f.header("access-control-allow-headers").is_some_and(|h| h.split(", ").any(|n| n == "if-none-match"));
    s.record("gate.preflight", format!("{} {} conditional={conditional}", f.status, f.header("access-control-allow-origin").unwrap_or("-")));
    let f = s.call("GET", &format!("/t/{}/card", b64::encode(&random::<16>())), vec![], vec![]).await;
    s.record("gate.forged-tenant", outcome(&f));
    let f = s.call("GET", "/admin/tenants", vec![], vec![]).await;
    s.record("gate.admin-without-token", outcome(&f));

    // Claim.
    let f = s.call("POST", "/claim", vec![("cw-claim", b64::encode(&random::<32>()))], s.admin.public().to_vec()).await;
    s.record("host.claim-wrong-secret", outcome(&f));
    let offer_before = s.call("POST", "/tenants", vec![("cw-offer", b64::encode(&random::<32>()))], vec![]).await;
    s.record("host.offer-forged", outcome(&offer_before));
    let f = s.call("POST", "/claim", vec![("cw-claim", b64::encode(&s.claim))], s.admin.public().to_vec()).await;
    s.record("host.claim", outcome(&f));
    s.admin_token = json_body(&f)["admin_token"].as_str().unwrap_or_default().to_string();
    let f = s.call("POST", "/claim", vec![("cw-claim", b64::encode(&s.claim))], s.admin.public().to_vec()).await;
    s.record("host.claim-again", outcome(&f));
    let f = s.call("GET", "/push/key", vec![], vec![]).await;
    let push_key = f.body.clone();
    s.record("host.push-key", format!("{} {} {}", f.status, f.body.len(), f.body.first().copied().unwrap_or(0)));

    // Tenants by the admin and by a hosting offer.
    let mut ada = Person::new(2);
    let body = json!({ "card": b64::encode(&ada.card), "quota": 8 * 1024 * 1024 }).to_string().into_bytes();
    let admin = Key::from_seed(&s.admin.seed());
    let (f, replay) = s.admin(&admin, "POST", "/admin/tenants", body.clone()).await;
    s.record(
        "host.create-tenant",
        format!("{} {}", outcome(&f), json_body(&f)["url"].as_str().is_some_and(|u| u.starts_with(base))),
    );
    ada.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
    ada.url = format!("{base}/t/{}", ada.tid());
    let f = s.call("POST", "/admin/tenants", replay, body.clone()).await;
    s.record("host.admin-replay", outcome(&f));
    let (f, _) = s.admin(&Key::generate(&mut OsRng), "POST", "/admin/tenants", body).await;
    s.record("host.admin-wrong-key", outcome(&f));
    let offer = json!({ "quota": 64 * 1024, "expires_at": now() + 86_400_000 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "POST", "/admin/offers", offer).await;
    s.record("host.create-offer", outcome(&f));
    let secret = json_body(&f)["secret"].as_str().unwrap_or_default().to_string();
    let offer_id = json_body(&f)["offer"].clone();
    let mut bo = Person::new(1);
    let f = s.call("POST", "/tenants", vec![("cw-offer", secret.clone())], bo.card.clone()).await;
    s.record("host.offer-tenant", outcome(&f));
    bo.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
    bo.url = format!("{base}/t/{}", bo.tid());
    let f = s.call("POST", "/tenants", vec![("cw-offer", secret)], bo.card.clone()).await;
    s.record("host.offer-reused", outcome(&f));
    places(&mut s, &admin).await;

    // Cards.
    let hosts = vec![ada.url.clone()];
    let f = s.put_card(&mut ada, &hosts).await;
    s.record("card.put", outcome(&f));
    let bo_hosts = vec![bo.url.clone()];
    s.put_card(&mut bo, &bo_hosts).await;
    let old = ada.sign_card(1, &hosts);
    ada.version = 2;
    let f = s.signed(&ada.devices[0], "PUT", &format!("/t/{}/card", ada.tid()), old).await;
    s.record("card.rollback", outcome(&f));
    let f = s.call("GET", &format!("/t/{}/card", ada.tid()), vec![], vec![]).await;
    s.record("card.get", format!("{} {} {}", f.status, f.header("etag").unwrap_or("-"), f.body == ada.card));
    let f = s.signed(&Key::generate(&mut OsRng), "PUT", &format!("/t/{}/card", ada.tid()), ada.card.clone()).await;
    s.record("card.stranger", outcome(&f));

    // Tokens.
    let f = s.tokens(&mut ada).await;
    let v = json_body(&f);
    s.record(
        "tokens.issue",
        format!("{} audience={} next-differs={}", f.status, v["audience"], v["read_next"] != v["read"] && v["read_next"].is_string()),
    );
    s.tokens(&mut bo).await;
    let f = s.call("POST", &format!("/t/{}/tokens", ada.tid()), vec![], vec![]).await;
    s.record("tokens.unsigned", outcome(&f));
    let f = s.signed(&Key::generate(&mut OsRng), "POST", &format!("/t/{}/tokens", ada.tid()), vec![]).await;
    s.record("tokens.stranger", outcome(&f));
    let path = format!("/t/{}/tokens", ada.tid());
    let h = s.sign(&ada.devices[0], "cw-device", "POST", &path, &[], now() - 120_000);
    let f = s.call("POST", &path, h, vec![]).await;
    // The answer names the host's time, so a device whose clock is off signs again with it.
    let host_time = f.header("cw-time").and_then(|t| t.parse::<u64>().ok()).is_some_and(|t| t.abs_diff(now()) < 10_000);
    s.record("tokens.stale-time", format!("{} host-time={host_time}", outcome(&f)));
    let h = s.sign(&ada.devices[0], "cw-device", "POST", &path, &[], now());
    s.call("POST", &path, h.clone(), vec![]).await;
    let f = s.call("POST", &path, h, vec![]).await;
    s.record("tokens.replay", outcome(&f));
    let f = s.read(&bo, "/head", &ada.read, vec![]).await;
    s.record("tokens.other-tenant", outcome(&f));
    let f = s
        .call("PUT", &format!("/t/{}/head", ada.tid()), vec![("authorization", format!("CW {}", ada.read))], vec![])
        .await;
    s.record("tokens.read-for-owner", outcome(&f));

    // The audience counter: read and write tokens of the current counter and the next one work; the owner advances
    // it, which retires every token before it.
    let profile = ada.profile.profile_id();
    let audience_key = random::<32>();
    let generation = 1u64;
    let next_read = json_body(&s.tokens(&mut ada).await)["read_next"].as_str().unwrap_or_default().to_string();
    let f = s.read(&ada, "/head", &next_read, vec![]).await;
    s.record("audience.next-token", outcome(&f));
    let old_read = ada.read.clone();
    let f = s.owner(&ada, 0, "POST", "/tokens/audience?to=1", vec![], None).await;
    let v = json_body(&f);
    s.record("audience.advance", format!("{} audience={} read-is-old-next={}", f.status, v["audience"], v["read"].as_str() == Some(next_read.as_str())));
    let f = s.read(&ada, "/head", &old_read, vec![]).await;
    s.record("audience.read-token-retired", outcome(&f));
    let f = s.owner(&ada, 0, "POST", "/tokens/audience?to=1", vec![], None).await;
    s.record("audience.advance-again", format!("{} audience={}", f.status, json_body(&f)["audience"]));
    let f = s.owner(&ada, 0, "POST", "/tokens/audience?to=3", vec![], None).await;
    s.record("audience.advance-beyond-next", outcome(&f));
    let f = s.owner(&ada, 0, "POST", "/tokens/audience", vec![], None).await;
    s.record("audience.advance-without-to", outcome(&f));
    let f = s.call("POST", &format!("/t/{}/tokens/audience?to=2&t={}", ada.tid(), next_read), vec![], vec![]).await;
    s.record("audience.advance-with-read-token", outcome(&f));
    s.tokens(&mut ada).await;
    // Owner tokens carry no counter, so the advance left them working.
    let f = s.owner(&ada, 0, "GET", "/status", vec![], None).await;
    s.record("audience.owner-token-kept", outcome(&f));

    // Audience boxes: one per friend at a lookup the friendship secret gives, sealed to the friend's inbox key.
    let friendship = random::<32>();
    let (lookup, audience_box) =
        audience::seal(&friendship, &profile, &bo.profile.profile_id(), &bo.inbox.public, generation as u32, &audience_key).unwrap();
    let box_path = format!("/access/{}", b64::encode(&lookup));
    let f = s.owner(&ada, 0, "PUT", &box_path, audience_box.clone(), None).await;
    s.record("audience-box.put", outcome(&f));
    let f = s.call("GET", &format!("/t/{}{box_path}", ada.tid()), vec![], vec![]).await;
    let opened = audience::open(&friendship, &profile, &bo.profile.profile_id(), &bo.inbox.private, &f.body);
    s.record(
        "audience-box.get-open",
        format!("{} opens={}", f.status, opened.is_ok_and(|(g, k)| u64::from(g) == generation && *k == audience_key)),
    );
    let f = s.call("PUT", &format!("/t/{}{box_path}?t={}", ada.tid(), ada.write), vec![], audience_box.clone()).await;
    s.record("audience-box.put-with-write-token", outcome(&f));
    let f = s.owner(&ada, 0, "DELETE", &box_path, vec![], None).await;
    s.record("audience-box.delete", outcome(&f));
    let f = s.call("GET", &format!("/t/{}{box_path}", ada.tid()), vec![], vec![]).await;
    s.record("audience-box.after-delete", outcome(&f));

    // Keyring.
    let keyring = head::seal_keyring(&profile, generation, &audience_key, &ada.tokens(), &mut OsRng);
    let f = s.owner(&ada, 0, "PUT", "/keyring", keyring, None).await;
    s.record("keyring.put", outcome(&f));
    let f = s.call("GET", &format!("/t/{}/keyring", ada.tid()), vec![], vec![]).await;
    s.record("keyring.get", format!("{} {}", f.status, f.header("etag").unwrap_or("-")));
    let f = s.owner(&ada, 0, "PUT", "/keyring", b"not a keyring".to_vec(), None).await;
    s.record("keyring.malformed", outcome(&f));
    // A keyring re-sealed for the same generation, with new tokens, is new to a browser cache holding the old one.
    let first_tag = s.call("GET", &format!("/t/{}/keyring", ada.tid()), vec![], vec![]).await.header("etag").unwrap_or("-").to_string();
    let resealed = head::seal_keyring(&profile, generation, &audience_key, &ada.tokens(), &mut OsRng);
    let f = s.owner(&ada, 0, "PUT", "/keyring", resealed.clone(), None).await;
    s.record("keyring.reseal", outcome(&f));
    let f = s.call("GET", &format!("/t/{}/keyring", ada.tid()), vec![("if-none-match", first_tag.clone())], vec![]).await;
    s.record("keyring.reseal-revalidated", format!("{} changed={} same-body={}", f.status, f.header("etag") != Some(first_tag.as_str()), f.body == resealed));

    // Objects.
    let (photo, photo_ref) = object::encrypt(b"MARKER photo pixels", &mut OsRng).unwrap();
    let photo_name = object::name(&photo_ref.digest);
    let f = s.owner(&ada, 0, "PUT", &format!("/objects/{photo_name}"), photo.clone(), None).await;
    s.record("objects.put", outcome(&f));
    let f = s.owner(&ada, 0, "PUT", &format!("/objects/{photo_name}"), photo.clone(), None).await;
    s.record("objects.put-again", outcome(&f));
    let f = s.read(&ada, &format!("/objects/{photo_name}"), &ada.read, vec![]).await;
    s.record("objects.get", format!("{} {} {}", f.status, f.body == photo, f.header("cache-control").unwrap_or("-")));
    let f = s.call("GET", &format!("/t/{}/objects/{photo_name}", ada.tid()), vec![], vec![]).await;
    s.record("objects.get-without-token", outcome(&f));
    let f = s.read(&ada, &format!("/objects/{photo_name}"), &ada.contact, vec![]).await;
    s.record("objects.get-contact-token", format!("{} {}", f.status, f.body == photo));
    let f = s.owner(&ada, 0, "PUT", &format!("/objects/{}", object::name(&[7; 32])), photo.clone(), None).await;
    s.record("objects.wrong-digest", outcome(&f));
    // The owner's object list: names, sizes and times; deleting frees the object.
    let names = |f: &Fetched| -> Vec<String> {
        json_body(f)["objects"].as_array().map_or(Vec::new(), |a| a.iter().filter_map(|o| o["name"].as_str().map(String::from)).collect())
    };
    let f = s.owner(&ada, 0, "GET", "/objects", vec![], None).await;
    let photo_size = json_body(&f)["objects"]
        .as_array()
        .and_then(|a| a.iter().find(|o| o["name"] == photo_name.as_str()).map(|o| o["size"].as_u64()))
        .flatten();
    s.record(
        "objects.list",
        format!(
            "{} photo={} sized={} next={}",
            f.status,
            names(&f).contains(&photo_name),
            photo_size == Some(photo.len() as u64),
            json_body(&f)["next"]
        ),
    );
    let f = s.call("GET", &format!("/t/{}/objects", ada.tid()), vec![], vec![]).await;
    s.record("objects.list-without-owner", outcome(&f));
    let (spare, spare_ref) = object::encrypt(b"MARKER spare", &mut OsRng).unwrap();
    let spare_name = object::name(&spare_ref.digest);
    s.owner(&ada, 0, "PUT", &format!("/objects/{spare_name}"), spare, None).await;
    let f = s.owner(&ada, 0, "DELETE", &format!("/objects/{spare_name}"), vec![], None).await;
    s.record("objects.delete", outcome(&f));
    let f = s.owner(&ada, 0, "GET", "/objects", vec![], None).await;
    s.record("objects.list-after-delete", format!("{} spare={}", f.status, names(&f).contains(&spare_name)));

    // Head.
    let (manifest, manifest_ref) = object::encrypt(br#"{"about":"MARKER profile"}"#, &mut OsRng).unwrap();
    s.owner(&ada, 0, "PUT", &format!("/objects/{}", object::name(&manifest_ref.digest)), manifest, None).await;
    let head1 = head::seal(&ada.devices[0], &profile, &[], generation, 1, now(), &audience_key, &manifest_ref, &mut OsRng);
    let f = s.owner(&ada, 0, "PUT", "/head", head1.clone(), Some(0)).await;
    s.record("head.put", outcome(&f));
    let f = s.owner(&ada, 0, "PUT", "/head", head1.clone(), Some(0)).await;
    s.record("head.stale", format!("{} current={}", outcome(&f), f.header("cw-current").unwrap_or("-")));
    let f = s.read(&ada, "/head", &ada.read, vec![]).await;
    s.record("head.get", format!("{} {} {}", f.status, f.body == head1, f.header("etag").unwrap_or("-")));
    let f = s.read(&ada, "/head", &ada.read, vec![("if-none-match", "\"1\"".into())]).await;
    s.record("head.not-modified", outcome(&f));
    let forged =
        head::seal(&Key::generate(&mut OsRng), &profile, &[], generation, 2, now(), &audience_key, &manifest_ref, &mut OsRng);
    let f = s.owner(&ada, 0, "PUT", "/head", forged, Some(1)).await;
    s.record("head.stranger-signed", outcome(&f));

    // Own log, snapshot, owner keys, passkey.
    let owner_key = random::<32>();
    let e0 =
        log::seal_entry(&ada.devices[0], &profile, 0, &[0; 32], 0, &owner_key, br#"{"op":"MARKER log"}"#, &mut OsRng)
            .unwrap();
    let f = s.owner(&ada, 0, "POST", "/log", e0.clone(), Some(0)).await;
    s.record("log.append-0", format!("{} seq={}", outcome(&f), f.header("cw-seq").unwrap_or("-")));
    let e1 = log::seal_entry(
        &ada.devices[1],
        &profile,
        1,
        &log::digest(&e0),
        0,
        &owner_key,
        br#"{"op":"MARKER 2"}"#,
        &mut OsRng,
    )
    .unwrap();
    let f = s.owner(&ada, 1, "POST", "/log", e1.clone(), Some(1)).await;
    s.record("log.append-1", outcome(&f));
    let e5 =
        log::seal_entry(&ada.devices[0], &profile, 5, &log::digest(&e1), 0, &owner_key, b"{}", &mut OsRng).unwrap();
    let f = s.owner(&ada, 0, "POST", "/log", e5, Some(5)).await;
    s.record("log.wrong-seq", format!("{} current={}", outcome(&f), f.header("cw-current").unwrap_or("-")));
    let e2 = log::seal_entry(&ada.devices[0], &profile, 2, &[0; 32], 0, &owner_key, b"{}", &mut OsRng).unwrap();
    let f = s.owner(&ada, 0, "POST", "/log", e2, Some(2)).await;
    s.record("log.wrong-previous", outcome(&f));
    let f = s.owner(&ada, 0, "GET", "/log?from=0", vec![], None).await;
    s.record(
        "log.list",
        format!("{} count={} current={}", f.status, entries(&f).len(), f.header("cw-current").unwrap_or("-")),
    );
    let (state_obj, state_ref) = object::encrypt(br#"{"state":"MARKER"}"#, &mut OsRng).unwrap();
    s.owner(&ada, 0, "PUT", &format!("/objects/{}", object::name(&state_ref.digest)), state_obj, None).await;
    let snap =
        log::seal_snapshot(&ada.devices[0], &profile, 1, &log::digest(&e1), 0, &owner_key, &state_ref, &mut OsRng)
            .unwrap();
    let f = s.owner(&ada, 0, "PUT", "/snapshot", snap.clone(), None).await;
    s.record("snapshot.put", outcome(&f));
    let f = s.owner(&ada, 0, "PUT", "/snapshot", snap.clone(), None).await;
    s.record("snapshot.not-newer", outcome(&f));
    let f = s.owner(&ada, 0, "GET", "/snapshot", vec![], None).await;
    s.record("snapshot.get", format!("{} {}", f.status, f.body == snap));
    // Storing the snapshot removed the entries it covers.
    let f = s.owner(&ada, 0, "GET", "/log?from=0", vec![], None).await;
    s.record("log.pruned", format!("count={} first={}", entries(&f).len(), entries(&f).first().map_or(99, |e| e.0)));
    let ok0 = log::seal_owner_key(&ada.devices[0], &ada.card(), &ada.seal_records(), 0, &owner_key).unwrap();
    let f = s.owner(&ada, 0, "PUT", "/ownerkeys", ok0.clone(), None).await;
    s.record("ownerkeys.put", outcome(&f));
    let ok1 = log::seal_owner_key(&ada.devices[1], &ada.card(), &ada.seal_records(), 1, &random::<32>()).unwrap();
    let f = s.owner(&ada, 1, "PUT", "/ownerkeys", ok1, None).await;
    s.record("ownerkeys.next-generation", outcome(&f));
    let again = log::seal_owner_key(&ada.devices[0], &ada.card(), &ada.seal_records(), 0, &owner_key).unwrap();
    let f = s.owner(&ada, 0, "PUT", "/ownerkeys", again.clone(), None).await;
    s.record("ownerkeys.replace", outcome(&f));
    let stranger_key = log::seal_owner_key(&Key::generate(&mut OsRng), &ada.card(), &ada.seal_records(), 2, &owner_key).unwrap();
    let f = s.owner(&ada, 0, "PUT", "/ownerkeys", stranger_key, None).await;
    s.record("ownerkeys.stranger-signed", outcome(&f));
    let f = s.owner(&ada, 0, "GET", "/ownerkeys", vec![], None).await;
    let listed = entries(&f);
    let seal_b = audience::device_seal_keys(&ada.devices[1].seed());
    let opened = listed.first().and_then(|(_, b)| log::OwnerKeyRecord::open(b, |d| ada.card().device_key(d)).ok()).and_then(|r| {
        r.open_sealed(&profile, &ada.devices[1].id(), &seal_b.private).ok()
    });
    s.record(
        "ownerkeys.list",
        format!("{} count={} replaced={} device-opens={}", f.status, listed.len(), listed.first().is_some_and(|(_, b)| *b == again), opened.is_some_and(|k| *k == owner_key)),
    );
    // After the rollover to generation 1, an entry of generation 0 is refused, and generation 0's record can go.
    let stale = log::seal_entry(&ada.devices[0], &profile, 2, &log::digest(&e1), 0, &owner_key, b"{}", &mut OsRng).unwrap();
    let f = s.owner(&ada, 0, "POST", "/log", stale, Some(2)).await;
    s.record("log.older-generation", outcome(&f));
    let f = s.owner(&ada, 0, "DELETE", "/ownerkeys/1", vec![], None).await;
    s.record("ownerkeys.delete-newest", outcome(&f));
    let f = s.owner(&ada, 0, "DELETE", "/ownerkeys/0", vec![], None).await;
    s.record("ownerkeys.delete-older", outcome(&f));
    let f = s.owner(&ada, 0, "GET", "/ownerkeys", vec![], None).await;
    s.record("ownerkeys.after-delete", format!("{} generations={:?}", f.status, entries(&f).iter().map(|e| e.0).collect::<Vec<_>>()));

    // Device inbox keys: each device's newest record, open to read.
    // An item before any record is stored needs no particular wraps.
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], s.inbox_item(&bo, &ada, b"before keys").await).await;
    s.record("inbox.before-device-keys", outcome(&f));
    let first = ada.device_key();
    let f = s.owner(&ada, 0, "PUT", "/devicekeys", first.clone(), None).await;
    s.record("devicekeys.put", outcome(&f));
    // An item that leaves out a device whose record is stored is refused with the current records.
    let only_second = inbox::seal(&bo.devices[0], &bo.profile.profile_id(), &ada.card(), &ada.device_keys()[1..], &[], inbox::new_id(&mut OsRng), now(), inbox::kind::MESSAGE, b"stale", &mut OsRng).unwrap();
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], only_second).await;
    let refused: Value = serde_json::from_slice(&f.body).unwrap_or(Value::Null);
    s.record("inbox.missing-device-key", format!("{} {} keys={}", f.status, refused["error"], refused["keys"].as_array().map_or(0, |k| k.len())));
    let newer = ada.device_keys()[1].clone();
    let f = s.owner(&ada, 0, "PUT", "/devicekeys", newer.clone(), None).await;
    s.record("devicekeys.put-other-device", outcome(&f));
    // An item sealed to an older key of a device is refused once a newer record is stored.
    let older = devicekey::create(&ada.devices[0], &profile, 0, &mut OsRng).0;
    let stale = inbox::seal(&bo.devices[0], &bo.profile.profile_id(), &ada.card(), &[older, newer.clone()], &[], inbox::new_id(&mut OsRng), now(), inbox::kind::MESSAGE, b"stale", &mut OsRng).unwrap();
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], stale).await;
    s.record("inbox.older-device-key", outcome(&f));
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], s.inbox_item(&bo, &ada, b"current keys").await).await;
    s.record("inbox.current-device-keys", outcome(&f));
    let f = s.owner(&ada, 0, "PUT", "/devicekeys", devicekey::create(&Key::generate(&mut OsRng), &profile, now(), &mut OsRng).0, None).await;
    s.record("devicekeys.stranger", outcome(&f));
    let f = s.call("GET", &format!("/t/{}/devicekeys", ada.tid()), vec![], vec![]).await;
    let listed = entries(&f);
    s.record("devicekeys.get", format!("{} count={} both={}", f.status, listed.len(), listed.iter().any(|(_, b)| *b == first) && listed.iter().any(|(_, b)| *b == newer)));

    let backup = recovery::seal_passkey_backup(&random::<32>(), &profile, &ada.seed, &mut OsRng);
    let f = s.owner(&ada, 0, "PUT", "/recovery/passkey", backup.clone(), None).await;
    s.record("passkey.put", outcome(&f));
    let f = s.call("GET", &format!("/t/{}/recovery/passkey", ada.tid()), vec![], vec![]).await;
    s.record("passkey.get-open", format!("{} {}", f.status, f.body == backup));

    // Batches: several requests in one transaction, all or none.
    let (manifest2, manifest2_ref) = object::encrypt(br#"{"about":"MARKER batch"}"#, &mut OsRng).unwrap();
    let manifest2_name = object::name(&manifest2_ref.digest);
    let head2 = head::seal(&ada.devices[0], &profile, &[], generation, 2, now(), &audience_key, &manifest2_ref, &mut OsRng);
    let e2 = log::seal_entry(&ada.devices[0], &profile, 2, &log::digest(&e1), 1, &owner_key, b"{}", &mut OsRng).unwrap();
    let f = s
        .batch(&ada, 0, vec![
            ("PUT", format!("/objects/{manifest2_name}"), None, manifest2.clone()),
            ("PUT", "/head".into(), Some(1), head2.clone()),
            ("POST", "/log".into(), Some(2), e2.clone()),
            ("POST", "/tokens".into(), None, vec![]),
        ])
        .await;
    let answers = wire::decode::<wire::BatchAnswers>(&f.body, usize::MAX, "answers").map(|a| a.answers).unwrap_or_default();
    let tokens_issued = answers.get(3).is_some_and(|a| {
        serde_json::from_slice::<Value>(a.body.as_slice()).is_ok_and(|v| v["owner"].as_str() == Some(ada.owner[0].as_str()))
    });
    s.record(
        "batch.applies",
        format!(
            "{} statuses={:?} log-seq={} tokens={tokens_issued}",
            f.status,
            answers.iter().map(|a| a.status).collect::<Vec<_>>(),
            answers.get(2).map_or(99, |a| a.value)
        ),
    );
    let f = s.read(&ada, "/head", &ada.read, vec![]).await;
    s.record("batch.head-stored", format!("{} {}", f.status, f.body == head2));
    let (lost, lost_ref) = object::encrypt(b"MARKER lost", &mut OsRng).unwrap();
    let lost_name = object::name(&lost_ref.digest);
    let f = s
        .batch(&ada, 0, vec![
            ("PUT", format!("/objects/{lost_name}"), None, lost),
            ("POST", "/log".into(), Some(2), e2.clone()),
        ])
        .await;
    s.record(
        "batch.precondition",
        format!("{} index={} current={}", outcome(&f), f.header("cw-index").unwrap_or("-"), f.header("cw-current").unwrap_or("-")),
    );
    let f = s.read(&ada, &format!("/objects/{lost_name}"), &ada.read, vec![]).await;
    s.record("batch.rolled-back", outcome(&f));
    let f = s.batch(&ada, 0, vec![("GET", "/status".into(), None, vec![]), ("POST", "/import".into(), None, b"{}".to_vec())]).await;
    s.record("batch.refused-request", format!("{} index={}", outcome(&f), f.header("cw-index").unwrap_or("-")));
    let f = s.batch(&ada, 0, vec![]).await;
    s.record("batch.empty", outcome(&f));
    // A rotation in one batch: the keyring for the next counter's tokens, then the advance, which retires the tokens
    // the batch's later requests don't use.
    let ring = head::seal_keyring(&profile, generation + 1, &audience_key, &ada.tokens(), &mut OsRng);
    let before_read = ada.read.clone();
    let f = s
        .batch(&ada, 0, vec![
            ("PUT", "/keyring".into(), None, ring),
            ("POST", "/tokens/audience?to=2".into(), None, vec![]),
            ("GET", "/status".into(), None, vec![]),
        ])
        .await;
    let answers = wire::decode::<wire::BatchAnswers>(&f.body, usize::MAX, "answers").map(|a| a.answers).unwrap_or_default();
    s.record("batch.rotation", format!("{} statuses={:?}", f.status, answers.iter().map(|a| a.status).collect::<Vec<_>>()));
    let f = s.read(&ada, "/head", &before_read, vec![]).await;
    s.record("batch.rotation-retired", outcome(&f));
    s.tokens(&mut ada).await;
    let unsigned = wire::encode(&wire::Batch {
        requests: vec![wire::BatchRequest { method: wire::vl(&b"GET"[..]), path: wire::vl(&b"/status"[..]), if_match: None, body: wire::vl(Vec::new()) }],
    });
    let f = s
        .call("POST", &format!("/t/{}/batch", ada.tid()), vec![("authorization", format!("CW {}", ada.owner[0]))], unsigned)
        .await;
    s.record("batch.unsigned", outcome(&f));

    // Inbox.
    let item = s.inbox_item(&bo, &ada, b"MARKER message").await;
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], item.clone()).await;
    s.record("inbox.post", format!("{} seq={}", outcome(&f), f.header("cw-seq").unwrap_or("-")));
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.read), vec![], item.clone()).await;
    s.record("inbox.read-token", outcome(&f));
    let contacted = s.inbox_item(&bo, &ada, b"MARKER contact").await;
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.contact), vec![], contacted).await;
    s.record("inbox.contact-token", format!("{} seq={}", outcome(&f), f.header("cw-seq").unwrap_or("-")));
    // A contact token reads objects and posts inbox items, and nothing else.
    let f = s.read(&ada, "/head", &ada.contact, vec![]).await;
    s.record("contact.head", outcome(&f));
    let f = s.read(&ada, &format!("/threads/{}", b64::encode(&[9; 16])), &ada.contact, vec![]).await;
    s.record("contact.thread-read", outcome(&f));
    let f = s
        .call("POST", &format!("/t/{}/threads/{}?t={}", ada.tid(), b64::encode(&[9; 16]), ada.contact), vec![], b"x".to_vec())
        .await;
    s.record("contact.thread-write", outcome(&f));
    let f = s.call("POST", &format!("/t/{}/tokens/contact?to=1&t={}", ada.tid(), ada.contact), vec![], vec![]).await;
    s.record("contact.rotate-with-contact-token", outcome(&f));
    // The next contact token works before the rotation; rotating retires the current one and makes the next current.
    let old_contact = ada.contact.clone();
    let next_contact = ada.contact_next.clone();
    let early = s.inbox_item(&bo, &ada, b"MARKER contact next").await;
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), next_contact), vec![], early).await;
    s.record("contact.next-before-rotate", format!("{} distinct={}", outcome(&f), !next_contact.is_empty() && next_contact != old_contact));
    let f = s.owner(&ada, 0, "POST", "/tokens/contact", vec![], None).await;
    s.record("contact.rotate-without-target", outcome(&f));
    let f = s.owner(&ada, 0, "POST", "/tokens/contact?to=2", vec![], None).await;
    s.record("contact.rotate-past-next", outcome(&f));
    let f = s.owner(&ada, 0, "POST", "/tokens/contact?to=1", vec![], None).await;
    let rotated = json_body(&f)["contact"].as_str().unwrap_or_default().to_string();
    s.record("contact.rotate", format!("{} new={} was-next={}", f.status, !rotated.is_empty() && rotated != old_contact, rotated == next_contact));
    // A second device retiring the same generation changes nothing.
    let f = s.owner(&ada, 0, "POST", "/tokens/contact?to=1", vec![], None).await;
    s.record("contact.rotate-again", format!("{} same={}", f.status, json_body(&f)["contact"].as_str() == Some(rotated.as_str())));
    let again = s.inbox_item(&bo, &ada, b"MARKER contact again").await;
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), old_contact), vec![], again.clone()).await;
    s.record("contact.old-token", outcome(&f));
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), rotated), vec![], again).await;
    s.record("contact.new-token", outcome(&f));
    let f = s.tokens(&mut ada).await;
    s.record("contact.tokens-after-rotate", format!("{} same={}", f.status, ada.contact == rotated));
    let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], b"junk".to_vec()).await;
    s.record("inbox.malformed", outcome(&f));
    let f = s.owner(&ada, 0, "GET", "/inbox?from=0", vec![], None).await;
    s.record(
        "inbox.list",
        format!(
            "{} count={} same={}",
            f.status,
            entries(&f).len(),
            inbox_entries(&f).first().map(|e| (e.1, &e.2)) == Some((wire::INBOX_ITEM, &item))
        ),
    );
    let f = s.owner(&ada, 0, "DELETE", "/inbox?through=2", vec![], None).await;
    s.record("inbox.collect", outcome(&f));
    let f = s.owner(&ada, 0, "GET", "/inbox?from=0", vec![], None).await;
    s.record(
        "inbox.after-collect",
        format!("count={} current={}", entries(&f).len(), f.header("cw-current").unwrap_or("-")),
    );

    // Threads.
    let thread_key = random::<32>();
    let thread_id = b64::encode(&thread::id(&thread_key));
    let entry = thread::seal(&bo.devices[0], &bo.card, &bo.card, &thread_key, now(), br#"{"text":"MARKER comment"}"#, &mut OsRng)
        .unwrap();
    let f =
        s.call("POST", &format!("/t/{}/threads/{thread_id}?t={}", ada.tid(), ada.write), vec![], entry.clone()).await;
    s.record("threads.post", format!("{} seq={}", outcome(&f), f.header("cw-seq").unwrap_or("-")));
    let f = s.read(&ada, &format!("/threads/{thread_id}?from=0"), &ada.read, vec![]).await;
    s.record("threads.get", format!("{} count={} {}", f.status, entries(&f).len(), f.header("etag").unwrap_or("-")));
    // A friend's entry is noted in the owner's inbox with its bytes; the owner's own entry is not.
    let f = s.owner(&ada, 0, "GET", "/inbox?from=0", vec![], None).await;
    let note = inbox_entries(&f).into_iter().rev().find(|e| e.1 == wire::INBOX_THREAD).and_then(|e| {
        wire::decode::<wire::ThreadNote>(&e.2, usize::MAX, "note").ok()
    });
    s.record(
        "threads.noted",
        format!(
            "{} thread={} seq={} same={}",
            f.status,
            note.as_ref().is_some_and(|n| b64::encode(&n.thread) == thread_id),
            note.as_ref().map_or(99, |n| n.seq),
            note.as_ref().is_some_and(|n| n.entry.as_slice() == entry.as_slice())
        ),
    );
    let before = inbox_entries(&f).len();
    let own_entry = thread::seal(&ada.devices[0], &ada.card, &ada.card, &thread_key, now(), br#"{"text":"MARKER own"}"#, &mut OsRng).unwrap();
    s.owner(&ada, 0, "POST", &format!("/threads/{thread_id}"), own_entry, None).await;
    let f = s.owner(&ada, 0, "GET", "/inbox?from=0", vec![], None).await;
    s.record("threads.own-not-noted", format!("{} added={}", f.status, inbox_entries(&f).len() - before));
    let f =
        s.read(&ada, &format!("/threads/{thread_id}?from=0"), &ada.read, vec![("if-none-match", "\"1\"".into())]).await;
    s.record("threads.not-modified", outcome(&f));
    let f = s.owner(&ada, 0, "DELETE", &format!("/threads/{thread_id}/0"), vec![], None).await;
    s.record("threads.delete-entry", outcome(&f));
    let f = s.read(&ada, &format!("/threads/{thread_id}?from=0"), &ada.read, vec![]).await;
    s.record("threads.after-delete", format!("count={} {}", entries(&f).len(), f.header("etag").unwrap_or("-")));

    // Invitations.
    let (link_secret, release) = (random::<32>(), random::<32>());
    let public = InvitePublic { card: wire::vl(ada.card.clone()), name: wire::vl(b"MARKER Ada".to_vec()) };
    let keys = InviteKeys {
        generation: generation as u32,
        audience_key,
        keyring: wire::vl(head::seal_keyring(&profile, generation, &audience_key, &ada.tokens(), &mut OsRng)),
        offer: wire::vl(Vec::new()),
        head: wire::vl(Vec::new()),
        objects: Vec::new(),
        keys: Vec::new(),
    };
    let (lookup_id, invitation) =
        invite::create(&link_secret, &release, now() + 86_400_000, now(), &public, &keys, &mut OsRng).unwrap();
    let upload = wire::encode(&InviteUpload { invitation: wire::vl(invitation.clone()), release });
    let inv_path = format!("/invites/{}", b64::encode(&lookup_id));
    let f = s.owner(&ada, 0, "PUT", &inv_path, upload, None).await;
    s.record("invites.put", outcome(&f));
    let f = s.call("GET", &format!("/t/{}{inv_path}", ada.tid()), vec![], vec![]).await;
    s.record("invites.get", format!("{} {}", f.status, f.body == invitation));
    let (redeem, redeemer) = (format!("/t/{}{inv_path}/redeem", ada.tid()), random::<32>().to_vec());
    let f = s.call("POST", &redeem, vec![], vec![]).await;
    s.record("invites.redeem-unclaimed", outcome(&f));
    let f = s.call("POST", &redeem, vec![], redeemer.clone()).await;
    s.record("invites.redeem", format!("{} {} {}", f.status, f.body.get(..32) == Some(&release[..]), f.body.get(32..) == Some(&invitation[..])));
    let f = s.call("POST", &redeem, vec![], redeemer.clone()).await;
    s.record("invites.redeem-same-claim", format!("{} {}", f.status, f.body.get(..32) == Some(&release[..])));
    let f = s.call("POST", &redeem, vec![], random::<32>().to_vec()).await;
    s.record("invites.redeem-other-claim", outcome(&f));
    let reupload = wire::encode(&InviteUpload { invitation: wire::vl(invitation.clone()), release: random::<32>() });
    let f = s.owner(&ada, 0, "PUT", &inv_path, reupload, None).await;
    s.record("invites.replace-redeemed", outcome(&f));
    let f = s.call("POST", &redeem, vec![], random::<32>().to_vec()).await;
    s.record("invites.redeem-after-replace", outcome(&f));
    let f = s.call("POST", &redeem, vec![], redeemer).await;
    s.record("invites.claim-after-replace", format!("{} {}", f.status, f.body.get(..32) == Some(&release[..])));
    let f = s.owner(&ada, 0, "DELETE", &inv_path, vec![], None).await;
    s.record("invites.delete", outcome(&f));
    let f = s.call("GET", &format!("/t/{}{inv_path}", ada.tid()), vec![], vec![]).await;
    s.record("invites.after-delete", outcome(&f));

    // Device link replies.
    let l = random::<32>();
    let reply = link::seal_reply(
        &l,
        &LinkReplyBody { card: wire::vl(ada.card.clone()), owner_keys: vec![OwnerKey { generation: 0, key: [4; 32] }] },
        &mut OsRng,
    );
    let link_path = format!("/links/{}", b64::encode(&link::lookup(&l)));
    let f = s.owner(&ada, 0, "PUT", &link_path, reply.clone(), None).await;
    s.record("links.put", outcome(&f));
    let f = s.call("GET", &format!("/t/{}{link_path}", ada.tid()), vec![], vec![]).await;
    s.record("links.get", format!("{} {}", f.status, f.body == reply));
    let f = s.call("GET", &format!("/t/{}{link_path}", ada.tid()), vec![], vec![]).await;
    s.record("links.get-again", outcome(&f));

    // Push: Web Push to a device with no socket, at most one per 10 s; socket events otherwise.
    let (push_addr, seen) = push_service().await;
    let endpoint = format!("http://{push_addr}/p/{}", b64::encode(&ada.devices[0].id()));
    let f = s
        .owner(&ada, 0, "PUT", "/push/subscription", json!({ "endpoint": endpoint }).to_string().into_bytes(), None)
        .await;
    s.record("push.subscribe", outcome(&f));
    let f = s
        .owner(
            &ada,
            0,
            "PUT",
            "/push/subscription",
            json!({ "endpoint": "http://example.com/p" }).to_string().into_bytes(),
            None,
        )
        .await;
    s.record("push.subscribe-invalid", outcome(&f));
    let item = s.inbox_item(&bo, &ada, b"MARKER ping").await;
    s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], item).await;
    let count = wait_pushes(&seen, 1).await;
    let auth = seen.lock().unwrap().first().cloned().unwrap_or_default();
    s.record(
        "push.web-push",
        format!("count={count} valid={}", vapid_valid(&auth, &push_key, &format!("http://{push_addr}"), base)),
    );
    let item = s.inbox_item(&bo, &ada, b"MARKER pong").await;
    s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], item).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    s.record("push.within-10s", format!("count={}", seen.lock().unwrap().len()));
    match socket(&s, &ada, 0).await {
        Ok(mut ws) => {
            let state = next_text(&mut ws).await.and_then(|t| serde_json::from_str::<Value>(&t).ok()).unwrap_or_default();
            // The opening device's own socket counts as seen today, as a UTC midnight.
            let today = now() / 86_400_000 * 86_400_000;
            s.record(
                "socket.seen",
                format!(
                    "devices={} self-today={}",
                    state["seen"].as_object().map_or(0, |d| d.len()),
                    state["seen"][b64::encode(&ada.devices[0].id())].as_u64() == Some(today)
                ),
            );
            s.record(
                "socket.state",
                format!(
                    "{} inbox={} log={} card={} status={} fields={}",
                    state["t"], state["inbox"], state["log"], state["card"], state["status"]["state"],
                    state.as_object().map_or(0, |o| o.len())
                ),
            );
            ws.send(Message::text("ping")).await.ok();
            let pong = next_text(&mut ws).await;
            s.record("socket.ping", pong.unwrap_or_else(|| "none".into()));
            tokio::time::sleep(Duration::from_millis(9_000)).await;
            let item = s.inbox_item(&bo, &ada, b"MARKER live").await;
            s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], item).await;
            let event = next_text(&mut ws).await.and_then(|t| serde_json::from_str::<Value>(&t).ok());
            s.record("socket.event", event.map_or("none".into(), |e| e["t"].to_string()));
            tokio::time::sleep(Duration::from_millis(1500)).await;
            s.record("push.socket-open", format!("count={}", seen.lock().unwrap().len()));
            ws.send(Message::text("hello")).await.ok();
            let closed = matches!(
                tokio::time::timeout(Duration::from_secs(5), ws.next()).await,
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_)))
            );
            s.record("socket.other-frame-closes", closed.to_string());
        }
        Err(status) => s.record("socket.ping", format!("refused {status}")),
    }
    let mut stranger = Person::new(1);
    stranger.tenant = ada.tenant;
    stranger.owner = vec![ada.owner[0].clone()];
    s.record("socket.stranger", format!("{:?}", socket(&s, &stranger, 0).await.err()));
    // A socket that stops pinging, as a suspended phone's does, is checked once its silence runs out, below.
    let (silent_addr, silent_seen) = push_service().await;
    let endpoint = format!("http://{silent_addr}/p/{}", b64::encode(&ada.devices[1].id()));
    s.owner(&ada, 1, "PUT", "/push/subscription", json!({ "endpoint": endpoint }).to_string().into_bytes(), None).await;
    let silent_since = Instant::now();
    let mut silent = socket(&s, &ada, 1).await.ok();
    if let Some(ws) = silent.as_mut() {
        next_text(ws).await;
    }

    // Status and quota.
    let f = s.owner(&ada, 0, "GET", "/status", vec![], None).await;
    let v = json_body(&f);
    s.record("status.get", format!("{} {} used>0={}", f.status, v["state"], v["used"].as_u64().unwrap_or(0) > 0));
    let (big, big_ref) = object::encrypt(&vec![0x41; 100 * 1024], &mut OsRng).unwrap();
    let f = s.owner(&bo, 0, "PUT", &format!("/objects/{}", object::name(&big_ref.digest)), big, None).await;
    s.record("quota.exceeded", outcome(&f));

    groups(&mut s, &admin).await;

    // Transfer to a new tenant on this host, with a grant from Ada's device.
    let body = json!({ "card": b64::encode(&ada.card), "quota": 8 * 1024 * 1024 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "POST", "/admin/tenants", body).await;
    let mut moved = Person {
        profile: Key::from_seed(&ada.seed),
        devices: ada.devices.iter().map(|d| Key::from_seed(&d.seed())).collect(),
        inbox: hpke::KeyPair::from_private(*ada.inbox.private),
        seed: ada.seed,
        version: ada.version,
        card: ada.card.clone(),
        tenant: b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default(),
        url: String::new(),
        owner: Vec::new(),
        read: String::new(),
        write: String::new(),
        contact: String::new(),
        contact_next: String::new(),
    };
    moved.url = format!("{base}/t/{}", moved.tid());
    s.tokens(&mut moved).await;
    let f = s.call("GET", &format!("/t/{}/export", ada.tid()), vec![], vec![]).await;
    s.record("transfer.export-without-grant", outcome(&f));
    let wrong = transfer::grant(
        &ada.devices[0],
        &ada.tenant,
        "https://elsewhere.example/t/AAAAAAAAAAAAAAAAAAAAAA",
        now() + 3_600_000,
    );
    let req = json!({ "from": ada.url, "grant": b64::encode(&wrong) }).to_string().into_bytes();
    let f = s.owner(&moved, 0, "POST", "/import", req, None).await;
    s.record("transfer.grant-for-other-host", outcome(&f));
    let grant = transfer::grant(&ada.devices[0], &ada.tenant, &moved.url, now() + 3_600_000);
    let req = json!({ "from": ada.url, "grant": b64::encode(&grant) }).to_string().into_bytes();
    let f = s.owner(&moved, 0, "POST", "/import", req, None).await;
    s.record("transfer.import", format!("{} objects={}", outcome(&f), json_body(&f)["objects"]));
    s.tokens(&mut moved).await;
    let a = s.owner(&ada, 0, "GET", "/snapshot", vec![], None).await;
    let b = s.owner(&moved, 0, "GET", "/snapshot", vec![], None).await;
    let ha = s.read(&ada, "/head", &ada.read, vec![]).await;
    let hb = s.read(&moved, "/head", &moved.read, vec![]).await;
    let la = s.owner(&ada, 0, "GET", "/log?from=0", vec![], None).await;
    let lb = s.owner(&moved, 0, "GET", "/log?from=0", vec![], None).await;
    let pa = s.read(&ada, &format!("/objects/{photo_name}"), &ada.read, vec![]).await;
    let pb = s.read(&moved, &format!("/objects/{photo_name}"), &moved.read, vec![]).await;
    s.record(
        "transfer.same-data",
        format!(
            "snapshot={} head={} log={} object={}",
            a.body == b.body && a.status == 200,
            ha.body == hb.body && hb.status == 200,
            entries(&la) == entries(&lb),
            pa.body == pb.body && pb.status == 200
        ),
    );

    // Rebuilding from a device: an empty tenant takes an export the device built, with the log continuing after the
    // entry the snapshot names; a tenant that holds data refuses one.
    let body = json!({ "card": b64::encode(&ada.card), "quota": 8 * 1024 * 1024 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "POST", "/admin/tenants", body).await;
    let mut rebuilt = Person {
        profile: Key::from_seed(&ada.seed),
        devices: ada.devices.iter().map(|d| Key::from_seed(&d.seed())).collect(),
        inbox: hpke::KeyPair::from_private(*ada.inbox.private),
        seed: ada.seed,
        version: ada.version,
        card: ada.card.clone(),
        tenant: b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default(),
        url: String::new(),
        owner: Vec::new(),
        read: String::new(),
        write: String::new(),
        contact: String::new(),
        contact_next: String::new(),
    };
    rebuilt.url = format!("{base}/t/{}", rebuilt.tid());
    s.tokens(&mut rebuilt).await;
    let restore = wire::encode(&wire::Export {
        card: wire::vl(ada.card.clone()),
        head: wire::vl(Vec::new()),
        log: Entries::default(),
        snapshot: wire::vl(snap.clone()),
        owner_keys: Entries::default(),
        passkey: wire::vl(Vec::new()),
        keyring: wire::vl(Vec::new()),
        inbox: Entries::default(),
        threads: Entries::default(),
        invites: Entries::default(),
        objects: Entries::default(),
        group_counter: 0,
        device_keys: wire::Entries::default(),
    });
    let f = s.owner(&rebuilt, 0, "POST", "/restore", restore.clone(), None).await;
    s.record("restore.empty-tenant", outcome(&f));
    s.tokens(&mut rebuilt).await;
    let f = s.owner(&rebuilt, 0, "GET", "/snapshot", vec![], None).await;
    s.record("restore.snapshot", format!("{} {}", f.status, f.body == snap));
    let e2 = log::seal_entry(
        &ada.devices[0],
        &profile,
        2,
        &log::digest(&e1),
        0,
        &owner_key,
        b"after the rebuild",
        &mut OsRng,
    )
    .unwrap();
    let f = s.owner(&rebuilt, 0, "POST", "/log", e2, Some(2)).await;
    s.record("restore.log-continues", outcome(&f));
    let f = s.owner(&rebuilt, 0, "POST", "/restore", restore.clone(), None).await;
    s.record("restore.not-empty", outcome(&f));
    let f = s.owner(&moved, 0, "POST", "/restore", restore, None).await;
    s.record("restore.after-import", outcome(&f));

    tokio::time::sleep((silent_since + Duration::from_secs(76)).saturating_duration_since(Instant::now())).await;
    let item = s.inbox_item(&bo, &ada, b"MARKER silent").await;
    s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], item).await;
    let pushed = wait_pushes(&silent_seen, 1).await;
    let mut closed = false;
    if let Some(ws) = silent.as_mut() {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match tokio::time::timeout(deadline - Instant::now(), ws.next()).await {
                Ok(Some(Ok(Message::Text(_)))) => continue,
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => closed = true,
                _ => {}
            }
            break;
        }
    }
    s.record("push.silent-socket", format!("count={pushed} closed={closed}"));

    // Administration: usage, quota, notice and removal.
    let (f, _) = s.admin(&admin, "GET", "/admin/tenants", vec![]).await;
    let list = json_body(&f);
    let listed = |p: &Person| list.as_array().and_then(|a| a.iter().find(|t| t["tenant"] == p.tid()).cloned()).unwrap_or_default();
    // A tenant names the admin offer it was made with; one the admin made directly names none.
    s.record(
        "admin.list",
        format!(
            "{} tenants={} offer-named={} direct-unnamed={}",
            f.status,
            list.as_array().map_or(0, |a| a.len()),
            listed(&bo)["offer"] == offer_id,
            listed(&ada)["offer"].is_null()
        ),
    );
    let (f, _) = s
        .admin(
            &admin,
            "PUT",
            &format!("/admin/tenants/{}/quota", bo.tid()),
            json!({ "quota": 1024 * 1024 }).to_string().into_bytes(),
        )
        .await;
    s.record("admin.quota", outcome(&f));
    let (f, _) = s
        .admin(
            &admin,
            "POST",
            &format!("/admin/tenants/{}/notice", bo.tid()),
            json!({ "days": 1 }).to_string().into_bytes(),
        )
        .await;
    s.record("admin.notice", outcome(&f));
    let (small, small_ref) = object::encrypt(b"MARKER small", &mut OsRng).unwrap();
    let f = s.owner(&bo, 0, "PUT", &format!("/objects/{}", object::name(&small_ref.digest)), small, None).await;
    s.record("notice.write-refused", outcome(&f));
    let f = s.owner(&bo, 0, "GET", "/status", vec![], None).await;
    s.record("notice.status", format!("{} {}", f.status, json_body(&f)["state"]));
    let f = s.call("GET", &format!("/t/{}/card", bo.tid()), vec![], vec![]).await;
    s.record("notice.card", outcome(&f));
    let (f, _) = s.admin(&admin, "DELETE", &format!("/admin/tenants/{}", moved.tid()), vec![]).await;
    s.record("admin.remove", outcome(&f));
    let f = s.read(&moved, "/head", &moved.read, vec![]).await;
    s.record("removed.head", outcome(&f));
    let f = s.call("GET", &format!("/t/{}/card", moved.tid()), vec![], vec![]).await;
    s.record("removed.forwarding-card", format!("{} {}", f.status, f.body == moved.card));
    let forward = vec![bo.url.clone(), moved.url.clone()];
    let f = s.put_card(&mut moved, &forward).await;
    s.record("removed.card-update", outcome(&f));

    // A person who moved away removes their old tenant; its card stays as the forwarding card.
    let mut cy = Person::new(1);
    let body = json!({ "card": b64::encode(&cy.card), "quota": 1 << 20 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "POST", "/admin/tenants", body).await;
    cy.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
    cy.url = format!("{base}/t/{}", cy.tid());
    let hosts = vec![cy.url.clone()];
    s.put_card(&mut cy, &hosts).await;
    s.tokens(&mut cy).await;
    let f = s.call("DELETE", &format!("/t/{}?t={}", cy.tid(), cy.write), vec![], vec![]).await;
    s.record("tenant.remove-without-owner", outcome(&f));
    let forward = vec![bo.url.clone()];
    s.put_card(&mut cy, &forward).await;
    let f = s.owner(&cy, 0, "DELETE", "", vec![], None).await;
    s.record("tenant.remove-by-owner", outcome(&f));
    let f = s.read(&cy, "/head", &cy.read, vec![]).await;
    s.record("tenant.removed-head", outcome(&f));
    let f = s.call("GET", &format!("/t/{}/card", cy.tid()), vec![], vec![]).await;
    s.record("tenant.removed-card", format!("{} {}", f.status, f.body == cy.card));

    // Guests and budgets.
    let (f, _) = s.admin(&admin, "GET", "/admin/settings", vec![]).await;
    s.record("guests.settings-default", format!("{} {}", f.status, json_body(&f)));
    let expires = || json!({ "expires_at": now() + 86_400_000 }).to_string().into_bytes();
    let f = s.owner(&ada, 0, "POST", "/guests", expires(), None).await;
    s.record("guests.offer-while-off", outcome(&f));
    let settings = |guests: bool, member: u64| {
        json!({ "guests": guests, "guest_limit": 2, "member_budget": member, "guest_budget": 1000 }).to_string().into_bytes()
    };
    let bad = json!({ "guests": true, "guest_limit": 2, "member_budget": 10, "guest_budget": 1000 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "PUT", "/admin/settings", bad).await;
    s.record("guests.settings-invalid", outcome(&f));
    let (f, _) = s.admin(&admin, "PUT", "/admin/settings", settings(true, 1000)).await;
    s.record("guests.settings-put", format!("{} {}", f.status, json_body(&f)));
    let f = s.owner(&ada, 0, "GET", "/status", vec![], None).await;
    s.record("guests.member-status", format!("{} guests={}", f.status, json_body(&f)["guests"]));
    let far = json!({ "expires_at": now() + 31 * 86_400_000 }).to_string().into_bytes();
    let f = s.owner(&ada, 0, "POST", "/guests", far, None).await;
    s.record("guests.offer-too-long", outcome(&f));
    let f = s.owner(&ada, 0, "POST", "/guests", expires(), None).await;
    s.record("guests.offer", outcome(&f));
    let guest_secret = json_body(&f)["secret"].as_str().unwrap_or_default().to_string();
    let mut dee = Person::new(1);
    let f = s.call("POST", "/tenants", vec![("cw-offer", guest_secret.clone())], dee.card.clone()).await;
    s.record("guests.join", outcome(&f));
    dee.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
    dee.url = format!("{base}/t/{}", dee.tid());
    let f = s.call("POST", "/tenants", vec![("cw-offer", guest_secret)], dee.card.clone()).await;
    s.record("guests.offer-reused", outcome(&f));
    s.tokens(&mut dee).await;
    let f = s.owner(&dee, 0, "GET", "/status", vec![], None).await;
    let v = json_body(&f);
    let thirty_days = v["notice_until"].as_u64().is_some_and(|u| u > now() + 29 * 86_400_000 && u <= now() + 30 * 86_400_000);
    s.record("guests.status", format!("{} {} quota={} guests={} thirty-days={thirty_days}", f.status, v["state"], v["quota"], v["guests"]));
    let f = s.owner(&dee, 0, "POST", "/guests", expires(), None).await;
    s.record("guests.guest-cannot-invite", outcome(&f));
    let f = s.owner(&ada, 0, "POST", "/guests", expires(), None).await;
    s.record("guests.second-offer", outcome(&f));
    let second = json_body(&f)["offer"].as_str().unwrap_or_default().to_string();
    let f = s.owner(&ada, 0, "POST", "/guests", expires(), None).await;
    s.record("guests.host-full", outcome(&f));
    let f = s.owner(&ada, 0, "DELETE", &format!("/guests/{second}"), vec![], None).await;
    s.record("guests.withdraw", outcome(&f));
    let f = s.owner(&ada, 0, "DELETE", &format!("/guests/{second}"), vec![], None).await;
    s.record("guests.withdraw-again", outcome(&f));
    let (f, _) = s.admin(&admin, "GET", "/admin/tenants", vec![]).await;
    let listed = json_body(&f).as_array().and_then(|a| a.iter().find(|t| t["tenant"] == dee.tid()).cloned()).unwrap_or_default();
    s.record(
        "guests.listed",
        format!("{} {} sponsor-is-ada={} budget={}", f.status, listed["state"], listed["sponsor"] == ada.tid(), listed["budget"]),
    );
    let approve = json!({ "quota": 1 << 20 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "POST", &format!("/admin/tenants/{}/approve", ada.tid()), approve.clone()).await;
    s.record("guests.approve-member", outcome(&f));
    let (f, _) = s.admin(&admin, "POST", &format!("/admin/tenants/{}/approve", dee.tid()), approve.clone()).await;
    s.record("guests.approve", outcome(&f));
    let f = s.owner(&dee, 0, "GET", "/status", vec![], None).await;
    let v = json_body(&f);
    s.record("guests.approved-status", format!("{} {} quota={} guests={}", f.status, v["state"], v["quota"], v["guests"]));
    let (f, _) = s.admin(&admin, "POST", &format!("/admin/tenants/{}/approve", dee.tid()), approve).await;
    s.record("guests.approve-again", outcome(&f));
    // A tenant made while the member budget is 1,000 answers 429 from its 1,001st request today.
    let mut eve = Person::new(1);
    let body = json!({ "card": b64::encode(&eve.card), "quota": 1 << 20 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "POST", "/admin/tenants", body).await;
    eve.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
    eve.url = format!("{base}/t/{}", eve.tid());
    s.tokens(&mut eve).await;
    let mut answered = 0;
    let mut busy = None;
    for _ in 0..1_100 {
        let f = s.read(&eve, "/head", &eve.read, vec![]).await;
        if f.status == 429 {
            busy = Some(f);
            break;
        }
        answered += 1;
    }
    let wait = busy.as_ref().and_then(|f| f.header("retry-after")?.parse::<u64>().ok());
    s.record(
        "budget.exhausted",
        format!("answered={answered} {} until-midnight={}", busy.as_ref().map_or("-".into(), outcome), wait.is_some_and(|w| w > 0 && w <= 86_400)),
    );
    let (f, _) = s.admin(&admin, "PUT", "/admin/settings", settings(false, 20_000)).await;
    s.record("guests.settings-restore", outcome(&f));
    let f = s.read(&eve, "/head", &eve.read, vec![]).await;
    s.record("budget.raised", outcome(&f));

    group_budget(&mut s, &admin).await;
    // Group and slot tokens have per-IP windows of their own, apart from the one the limits below use up.
    group_limits(&mut s, &admin).await;

    // Limits last, since they use up this minute's allowance.
    let mut statuses = std::collections::BTreeSet::new();
    for _ in 0..61 {
        let item = s.inbox_item(&bo, &ada, b"MARKER flood").await;
        let f = s.call("POST", &format!("/t/{}/inbox?t={}", ada.tid(), ada.write), vec![], item).await;
        statuses.insert(outcome(&f));
    }
    s.record("limits.per-token", format!("{statuses:?}"));
    let mut statuses = std::collections::BTreeSet::new();
    for _ in 0..121 {
        let f = s.call("GET", &format!("/t/{}/card", ada.tid()), vec![], vec![]).await;
        statuses.insert(f.status);
    }
    s.record("limits.per-ip", format!("{statuses:?}"));

    // Destroying the host comes after everything else: the admin's signed request deletes every tenant and the
    // host's own state, and from then on nothing answers, a second claim with the setup link included. Open requests
    // wait out the minute the limits above used up.
    let token = vec![("authorization", format!("CW {}", s.admin_token))];
    let f = s.call("DELETE", "/admin/host", token, vec![]).await;
    s.record("destroy.unsigned", outcome(&f));
    let (f, _) = s.admin(&admin, "DELETE", "/admin/host", vec![]).await;
    s.record("destroy.admin", outcome(&f));
    let f = s.read(&ada, "/head", &ada.read, vec![]).await;
    s.record("destroy.tenant-head", outcome(&f));
    let f = s.owner(&bo, 0, "GET", "/status", vec![], None).await;
    s.record("destroy.tenant-status", outcome(&f));
    let (f, _) = s.admin(&admin, "GET", "/admin/tenants", vec![]).await;
    s.record("destroy.admin-after", outcome(&f));
    let f = s.call("POST", "/claim", vec![("cw-claim", b64::encode(&s.claim))], Key::generate(&mut OsRng).public().to_vec()).await;
    s.record("destroy.claim", outcome(&f));
    s.out
}

/// One reader: a kept-alive HTTP/1.1 connection reading the head until the deadline.
async fn reader(authority: String, path: String, deadline: Instant, interval: Duration) -> (Vec<u64>, u64) {
    let mut times = Vec::new();
    let mut errors = 0u64;
    'connect: while Instant::now() < deadline {
        let Ok(tcp) = tokio::net::TcpStream::connect(&authority).await else {
            errors += 1;
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        tcp.set_nodelay(true).ok();
        let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(commonwire::io::Io(tcp)).await else {
            errors += 1;
            continue;
        };
        tokio::spawn(conn);
        while Instant::now() < deadline {
            if !interval.is_zero() {
                tokio::time::sleep(interval).await;
            }
            let req = http::Request::builder()
                .uri(path.as_str())
                .header("host", authority.as_str())
                .body(commonwire::io::Full::new(Vec::new()))
                .unwrap();
            let t = Instant::now();
            if sender.ready().await.is_err() {
                errors += 1;
                continue 'connect;
            }
            match sender.send_request(req).await {
                Ok(r) if r.status() == 200 => {
                    if commonwire::io::collect(r.into_body(), 1 << 20).await.is_err() {
                        errors += 1;
                        continue 'connect;
                    }
                    times.push(t.elapsed().as_micros() as u64);
                }
                _ => {
                    errors += 1;
                    continue 'connect;
                }
            }
        }
    }
    (times, errors)
}

async fn load(base: &str, seeded: &[(String, String)], readers: usize, seconds: u64, interval_ms: u64) -> Value {
    let authority = base.split_once("://").map(|(_, a)| a.to_string()).unwrap_or_default();
    let paths: Vec<String> = seeded
        .iter()
        .map(|(url, token)| format!("{}/head?t={token}", url.strip_prefix(base).unwrap_or(url)))
        .collect();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let tasks: Vec<_> = (0..readers)
        .map(|i| {
            let (authority, path) = (authority.clone(), paths[i % paths.len()].clone());
            let interval = Duration::from_millis(interval_ms);
            tokio::spawn(async move {
                // Spread the readers' first reads across one interval.
                tokio::time::sleep(interval.mul_f64(i as f64 / readers as f64)).await;
                reader(authority, path, deadline, interval).await
            })
        })
        .collect();
    let mut all = Vec::new();
    let mut errors = 0;
    for t in tasks {
        let (times, e) = t.await.unwrap();
        all.extend(times);
        errors += e;
    }
    all.sort_unstable();
    let pct =
        |p: f64| all.get(((all.len() as f64 * p) as usize).min(all.len().saturating_sub(1))).copied().unwrap_or(0);
    json!({ "readers": readers, "tenants": paths.len(), "interval_ms": interval_ms, "requests": all.len(), "errors": errors, "p50_us": pct(0.5), "p99_us": pct(0.99) })
}

/// Claims the host and returns a patient suite holding its admin key.
async fn claimed(base: &str, claim: [u8; 32]) -> (Suite, Key) {
    let authority = base.split_once("://").map(|(_, a)| a.to_string()).unwrap_or_default();
    let mut s = Suite {
        base: base.into(),
        authority,
        claim,
        out: BTreeMap::new(),
        admin: Key::generate(&mut OsRng),
        admin_token: String::new(),
        patient: true,
    };
    let f = s.call("POST", "/claim", vec![("cw-claim", b64::encode(&claim))], s.admin.public().to_vec()).await;
    s.admin_token = json_body(&f)["admin_token"].as_str().unwrap_or_default().to_string();
    let admin = Key::from_seed(&s.admin.seed());
    (s, admin)
}

impl Suite {
    /// A new tenant with one object and a published head, as friends would read it.
    async fn published(&mut self, admin: &Key) -> Person {
        let base = self.base.clone();
        let mut p = Person::new(1);
        let body = json!({ "card": b64::encode(&p.card), "quota": 64 * 1024 * 1024 }).to_string().into_bytes();
        let (f, _) = self.admin(admin, "POST", "/admin/tenants", body).await;
        p.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
        p.url = format!("{base}/t/{}", p.tid());
        self.tokens(&mut p).await;
        let (m, m_ref) = object::encrypt(b"{}", &mut OsRng).unwrap();
        self.owner(&p, 0, "PUT", &format!("/objects/{}", object::name(&m_ref.digest)), m, None).await;
        let h =
            head::seal(&p.devices[0], &p.profile.profile_id(), &[], 1, 1, now(), &kdf::sha256(b"k"), &m_ref, &mut OsRng);
        self.owner(&p, 0, "PUT", "/head", h, Some(0)).await;
        p
    }
}

/// Creates tenants with published heads for `load`, printing their URLs and read tokens.
async fn seed(base: &str, claim: [u8; 32], tenants: usize) -> Value {
    let (mut s, admin) = claimed(base, claim).await;
    let mut seeded = Vec::new();
    for _ in 0..tenants {
        let p = s.published(&admin).await;
        seeded.push(json!({ "url": p.url, "read": p.read }));
    }
    json!({ "tenants": seeded })
}

/// Opens a push socket for a fresh tenant and pings it every second for `seconds`.
async fn idle(base: &str, claim: [u8; 32], seconds: u64) -> Value {
    let (s, admin) = claimed(base, claim).await;
    let mut p = Person::new(1);
    let body = json!({ "card": b64::encode(&p.card), "quota": 1024 * 1024 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "POST", "/admin/tenants", body).await;
    p.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
    s.tokens(&mut p).await;
    let Ok(mut ws) = socket(&s, &p, 0).await else { fail("socket refused") };
    // The opening state frame.
    next_text(&mut ws).await;
    let mut pongs = 0;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        ws.send(Message::text("ping")).await.ok();
        if next_text(&mut ws).await.as_deref() == Some("pong") {
            pongs += 1;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let f = s.call("GET", &format!("/t/{}/card", p.tid()), vec![], vec![]).await;
    json!({ "pongs": pongs, "after": f.status })
}

mod restarts;
mod upgrade;
mod wakes;

/// A tenant made by the admin for this person, with its card naming it and owner tokens.
async fn admin_tenant(s: &Suite, admin: &Key, p: &mut Person, quota: u64) {
    let body = json!({ "card": b64::encode(&p.card), "quota": quota }).to_string().into_bytes();
    let (f, _) = s.admin(admin, "POST", "/admin/tenants", body).await;
    p.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
    p.url = format!("{}/t/{}", s.base, p.tid());
    let hosts = vec![p.url.clone()];
    s.put_card(p, &hosts).await;
    s.tokens(p).await;
}

/// Waits for the next minute when this one has under 10 s left, so a run of requests stays in one window.
async fn fresh_minute() {
    let left = 60_000 - now() % 60_000;
    if left < 10_000 {
        tokio::time::sleep(Duration::from_millis(left + 50)).await;
    }
}

struct GroupTokens {
    read: String,
    write: String,
    read_next: String,
    write_next: String,
}

fn group_tokens(f: &Fetched) -> GroupTokens {
    let v = json_body(f);
    let t = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    GroupTokens { read: t("read"), write: t("write"), read_next: t("read_next"), write_next: t("write_next") }
}

fn inbox_box(size: usize) -> Vec<u8> {
    wire::encode(&wire::HpkeBox { enc: wire::vl(vec![1; 32]), ciphertext: wire::vl(vec![0x4d; size]) })
}

impl Suite {
    async fn with_token(&self, p: &Person, method: &str, rel: &str, token: &str, body: Vec<u8>) -> Fetched {
        self.call(method, &format!("/t/{}{rel}", p.tid()), vec![("authorization", format!("CW {token}"))], body).await
    }
}

/// Group tokens, access boxes, opened threads and slots (docs/hosts.md, "Groups").
async fn groups(s: &mut Suite, admin: &Key) {
    let mut gus = Person::new(1);
    admin_tenant(s, admin, &mut gus, 8 * 1024 * 1024).await;
    let f = s.owner(&gus, 0, "POST", "/tokens/group", vec![], None).await;
    s.record("group.tokens", format!("{} counter={}", outcome(&f), json_body(&f)["counter"]));
    let g = group_tokens(&f);
    let f = s.with_token(&gus, "POST", "/tokens/group", &g.write, vec![]).await;
    s.record("group.tokens-without-owner", outcome(&f));

    // Opened threads: a group write token appends only to a thread the owner opened.
    let wall = b64::encode(&random::<16>());
    // Thread entries the host checks only for shape.
    let entry = |_what: &str| wire::encode(&wire::SealedBox { nonce: random::<12>(), sealed: wire::vl(random::<48>().to_vec()) });
    let f = s.with_token(&gus, "POST", &format!("/threads/{wall}"), &g.write, entry("unopened")).await;
    s.record("group.post-unopened", outcome(&f));
    let f = s.with_token(&gus, "PUT", &format!("/threads/{wall}"), &g.write, vec![]).await;
    s.record("group.open-without-owner", outcome(&f));
    let f = s.owner(&gus, 0, "PUT", &format!("/threads/{wall}"), vec![], None).await;
    s.record("group.open", outcome(&f));
    let f = s.with_token(&gus, "POST", &format!("/threads/{wall}"), &g.write, entry("first")).await;
    s.record("group.post", format!("{} seq={}", outcome(&f), f.header("cw-seq").unwrap_or("-")));
    let f = s.owner(&gus, 0, "PUT", &format!("/threads/{wall}"), vec![], None).await;
    s.record("group.open-again", outcome(&f));
    let f = s.with_token(&gus, "POST", &format!("/threads/{wall}"), &g.write, entry("second")).await;
    s.record("group.post-after-reopen", format!("{} seq={}", outcome(&f), f.header("cw-seq").unwrap_or("-")));
    let empty_wall = b64::encode(&random::<16>());
    s.owner(&gus, 0, "PUT", &format!("/threads/{empty_wall}"), vec![], None).await;

    // Each token kind works on its paths only.
    let (photo, photo_ref) = object::encrypt(b"MARKER group photo", &mut OsRng).unwrap();
    let photo_path = format!("/objects/{}", object::name(&photo_ref.digest));
    let (big, big_ref) = object::encrypt(&vec![0x42; 520 * 1024], &mut OsRng).unwrap();
    let big_path = format!("/objects/{}", object::name(&big_ref.digest));
    let mut w = Vec::new();
    w.push(format!("put-object={}", outcome(&s.with_token(&gus, "PUT", &photo_path, &g.write, photo.clone()).await)));
    w.push(format!("put-object-over-512k={}", outcome(&s.with_token(&gus, "PUT", &big_path, &g.write, big).await)));
    w.push(format!("head={}", outcome(&s.read(&gus, "/head", &g.write, vec![]).await)));
    w.push(format!("thread={}", outcome(&s.read(&gus, &format!("/threads/{wall}"), &g.write, vec![]).await)));
    w.push(format!("object={}", outcome(&s.read(&gus, &photo_path, &g.write, vec![]).await)));
    w.push(format!("inbox={}", outcome(&s.with_token(&gus, "POST", "/inbox", &g.write, inbox_box(64)).await)));
    w.push(format!("delete-thread={}", outcome(&s.with_token(&gus, "DELETE", &format!("/threads/{wall}"), &g.write, vec![]).await)));
    s.record("group.write-token", w.join(" "));
    let mut r = Vec::new();
    r.push(format!("head={}", outcome(&s.read(&gus, "/head", &g.read, vec![]).await)));
    let f = s.read(&gus, &format!("/threads/{wall}?from=0"), &g.read, vec![]).await;
    r.push(format!("thread={}:{}", outcome(&f), entries(&f).len()));
    let f = s.read(&gus, &photo_path, &g.read, vec![]).await;
    r.push(format!("object={}:{}", outcome(&f), f.body == photo));
    r.push(format!("post={}", outcome(&s.call("POST", &format!("/t/{}/threads/{wall}?t={}", gus.tid(), g.read), vec![], entry("read token")).await)));
    r.push(format!("put-object={}", outcome(&s.with_token(&gus, "PUT", &photo_path, &g.read, photo.clone()).await)));
    r.push(format!("inbox={}", outcome(&s.with_token(&gus, "POST", "/inbox", &g.read, inbox_box(64)).await)));
    r.push(format!("status={}", outcome(&s.with_token(&gus, "GET", "/status", &g.read, vec![]).await)));
    s.record("group.read-token", r.join(" "));
    let f = s.with_token(&gus, "POST", &format!("/threads/{wall}"), &gus.write, entry("audience write")).await;
    s.record("group.audience-write-token-on-wall", outcome(&f));
    let f = s.with_token(&gus, "PUT", &photo_path, &gus.write, photo.clone()).await;
    s.record("group.audience-write-token-put-object", outcome(&f));

    // Group tokens for the counter and the next one work; advancing retires the earlier ones.
    let f = s.read(&gus, &format!("/threads/{wall}?from=0"), &g.read_next, vec![]).await;
    s.record("group.next-before-advance", outcome(&f));
    let f = s.owner(&gus, 0, "POST", "/tokens/group?to=2", vec![], None).await;
    s.record("group.advance-past-next", outcome(&f));
    let f = s.owner(&gus, 0, "POST", "/tokens/group?to=1", vec![], None).await;
    s.record("group.advance", format!("{} counter={}", outcome(&f), json_body(&f)["counter"]));
    let g1 = group_tokens(&f);
    let f = s.owner(&gus, 0, "POST", "/tokens/group?to=1", vec![], None).await;
    s.record("group.advance-again", format!("{} counter={}", outcome(&f), json_body(&f)["counter"]));
    let f = s.read(&gus, &format!("/threads/{wall}?from=0"), &g.read, vec![]).await;
    s.record("group.old-read-token", outcome(&f));
    let f = s.with_token(&gus, "POST", &format!("/threads/{wall}"), &g.write, entry("old write")).await;
    s.record("group.old-write-token", outcome(&f));
    let f = s.with_token(&gus, "POST", &format!("/threads/{wall}"), &g.write_next, entry("next write")).await;
    s.record("group.former-next-write-token", format!("{} seq={}", outcome(&f), f.header("cw-seq").unwrap_or("-")));
    let f = s.read(&gus, &format!("/threads/{wall}?from=0"), &g1.read, vec![]).await;
    s.record("group.new-read-token", format!("{} count={}", outcome(&f), entries(&f).len()));

    // Access boxes.
    let a = random::<32>();
    let lookup = b64::encode(&cw_crypto::access::lookup(&a));
    let access = cw_crypto::access::Access {
        group: random::<16>(),
        generation: 1,
        keys: vec![random::<32>()],
        read_token: g1.read.clone(),
        write_token: g1.write.clone(),
        name: "MARKER group".into(),
        tenant: gus.url.clone(),
        offer: None,
    };
    let sealed = cw_crypto::access::seal(&a, &access, &mut OsRng).unwrap();
    let f = s.call("PUT", &format!("/t/{}/access/{lookup}", gus.tid()), vec![], sealed.clone()).await;
    s.record("access.put-without-owner", outcome(&f));
    let f = s.owner(&gus, 0, "PUT", &format!("/access/{lookup}"), sealed.clone(), None).await;
    s.record("access.put", outcome(&f));
    let f = s.call("GET", &format!("/t/{}/access/{lookup}", gus.tid()), vec![], vec![]).await;
    let opened = cw_crypto::access::open(&a, &f.body).map(|o| o == access).unwrap_or(false);
    s.record("access.get", format!("{} opens={opened}", outcome(&f)));
    let f = s.call("GET", &format!("/t/{}/access/{}", gus.tid(), b64::encode(&random::<16>())), vec![], vec![]).await;
    s.record("access.unknown", outcome(&f));
    let f = s.owner(&gus, 0, "PUT", &format!("/access/{lookup}"), b"MARKER not a box".to_vec(), None).await;
    s.record("access.malformed", outcome(&f));
    let huge = wire::encode(&wire::SealedBox { nonce: [0; 12], sealed: wire::vl(vec![0x4d; 5000]) });
    let f = s.owner(&gus, 0, "PUT", &format!("/access/{lookup}"), huge, None).await;
    s.record("access.too-large", outcome(&f));
    let second = b64::encode(&random::<16>());
    s.owner(&gus, 0, "PUT", &format!("/access/{second}"), sealed.clone(), None).await;
    let f = s.owner(&gus, 0, "DELETE", &format!("/access/{second}"), vec![], None).await;
    s.record("access.delete", outcome(&f));
    let f = s.call("GET", &format!("/t/{}/access/{second}", gus.tid()), vec![], vec![]).await;
    s.record("access.after-delete", outcome(&f));

    // Slots: at most 20 waiting from one slot; closing one retires its token; numbers are never reused.
    fresh_minute().await;
    let f = s.owner(&gus, 0, "POST", "/slots", vec![], None).await;
    let slot = json_body(&f);
    s.record("slots.open", format!("{} slot={}", outcome(&f), slot["slot"]));
    let slot_token = slot["token"].as_str().unwrap_or_default().to_string();
    let mut statuses = Vec::new();
    let mut last_seq = 0u64;
    for _ in 0..21 {
        let f = s.with_token(&gus, "POST", "/inbox", &slot_token, inbox_box(1024)).await;
        last_seq = f.header("cw-seq").and_then(|v| v.parse().ok()).unwrap_or(last_seq);
        statuses.push(outcome(&f));
    }
    let accepted = statuses.iter().filter(|o| o.as_str() == "201").count();
    s.record("slots.unread-cap", format!("accepted={accepted} then={}", statuses.last().cloned().unwrap_or_default()));
    let f = s.owner(&gus, 0, "GET", "/slots", vec![], None).await;
    s.record("slots.list", format!("{} {}", outcome(&f), json_body(&f)["slots"].as_array().map_or(String::new(), |a| a.iter().map(|x| format!("{}:{}", x["slot"], x["unread"])).collect::<Vec<_>>().join(","))));
    let mut w = Vec::new();
    w.push(format!("head={}", outcome(&s.read(&gus, "/head", &slot_token, vec![]).await)));
    w.push(format!("object={}", outcome(&s.read(&gus, &photo_path, &slot_token, vec![]).await)));
    w.push(format!("thread-post={}", outcome(&s.call("POST", &format!("/t/{}/threads/{wall}?t={slot_token}", gus.tid()), vec![], entry("slot")).await)));
    w.push(format!("inbox-read={}", outcome(&s.with_token(&gus, "GET", "/inbox", &slot_token, vec![]).await)));
    s.record("slots.token-paths", w.join(" "));
    let f = s.owner(&gus, 0, "DELETE", &format!("/inbox?through={}", last_seq.saturating_sub(10)), vec![], None).await;
    let after = s.owner(&gus, 0, "GET", "/slots", vec![], None).await;
    s.record("slots.read-frees", format!("{} unread={}", outcome(&f), json_body(&after)["slots"][0]["unread"]));
    let f = s.with_token(&gus, "POST", "/inbox", &slot_token, inbox_box(1024)).await;
    s.record("slots.after-read", outcome(&f));
    let number = slot["slot"].as_u64().unwrap_or_default();
    let f = s.owner(&gus, 0, "DELETE", &format!("/slots/{number}"), vec![], None).await;
    s.record("slots.close", outcome(&f));
    let f = s.owner(&gus, 0, "DELETE", &format!("/slots/{number}"), vec![], None).await;
    s.record("slots.close-again", outcome(&f));
    let f = s.with_token(&gus, "POST", "/inbox", &slot_token, inbox_box(1024)).await;
    s.record("slots.closed", outcome(&f));
    let f = s.owner(&gus, 0, "POST", "/slots", vec![], None).await;
    s.record("slots.not-reused", format!("{} slot={}", outcome(&f), json_body(&f)["slot"]));

    // A transfer carries the group counter and threads with entries, and leaves access boxes and slots behind.
    let mut moved = Person {
        profile: Key::from_seed(&gus.seed),
        devices: gus.devices.iter().map(|d| Key::from_seed(&d.seed())).collect(),
        inbox: hpke::KeyPair::from_private(*gus.inbox.private),
        seed: gus.seed,
        version: gus.version,
        card: gus.card.clone(),
        tenant: [0; 16],
        url: String::new(),
        owner: Vec::new(),
        read: String::new(),
        write: String::new(),
        contact: String::new(),
        contact_next: String::new(),
    };
    let body = json!({ "card": b64::encode(&moved.card), "quota": 8 * 1024 * 1024 }).to_string().into_bytes();
    let (f, _) = s.admin(admin, "POST", "/admin/tenants", body).await;
    moved.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
    moved.url = format!("{}/t/{}", s.base, moved.tid());
    s.tokens(&mut moved).await;
    let grant = transfer::grant(&gus.devices[0], &gus.tenant, &moved.url, now() + 3_600_000);
    let req = json!({ "from": gus.url, "grant": b64::encode(&grant) }).to_string().into_bytes();
    let f = s.owner(&moved, 0, "POST", "/import", req, None).await;
    s.record("group.import", outcome(&f));
    let f = s.owner(&moved, 0, "POST", "/tokens/group", vec![], None).await;
    s.record("group.import-counter", format!("{} counter={}", outcome(&f), json_body(&f)["counter"]));
    let m = group_tokens(&f);
    let f = s.read(&moved, &format!("/threads/{wall}?from=0"), &m.read, vec![]).await;
    let w = s.with_token(&moved, "POST", &format!("/threads/{wall}"), &m.write, entry("after import")).await;
    let e = s.with_token(&moved, "POST", &format!("/threads/{empty_wall}"), &m.write, entry("empty wall")).await;
    s.record(
        "group.import-walls",
        format!("{} count={} post={} seq={} empty-wall={}", outcome(&f), entries(&f).len(), outcome(&w), w.header("cw-seq").unwrap_or("-"), outcome(&e)),
    );
    let f = s.call("GET", &format!("/t/{}/access/{lookup}", moved.tid()), vec![], vec![]).await;
    let slots = s.owner(&moved, 0, "GET", "/slots", vec![], None).await;
    s.record("group.import-omits", format!("access={} slots={}", outcome(&f), json_body(&slots)["slots"]));

    // Under notice a box can be replaced and the counter advanced, and nothing else is written.
    let (f, _) = s
        .admin(admin, "POST", &format!("/admin/tenants/{}/notice", gus.tid()), json!({ "days": 1 }).to_string().into_bytes())
        .await;
    s.record("group.notice", outcome(&f));
    let mut n = Vec::new();
    n.push(format!("replace={}", outcome(&s.owner(&gus, 0, "PUT", &format!("/access/{lookup}"), sealed.clone(), None).await)));
    n.push(format!("new={}", outcome(&s.owner(&gus, 0, "PUT", &format!("/access/{}", b64::encode(&random::<16>())), sealed.clone(), None).await)));
    let f = s.owner(&gus, 0, "POST", "/tokens/group?to=2", vec![], None).await;
    n.push(format!("advance={}:{}", outcome(&f), json_body(&f)["counter"]));
    n.push(format!("open={}", outcome(&s.owner(&gus, 0, "PUT", &format!("/threads/{}", b64::encode(&random::<16>())), vec![], None).await)));
    n.push(format!("slot={}", outcome(&s.owner(&gus, 0, "POST", "/slots", vec![], None).await)));
    n.push(format!("delete={}", outcome(&s.owner(&gus, 0, "DELETE", &format!("/access/{lookup}"), vec![], None).await)));
    s.record("group.under-notice", n.join(" "));
}

/// Offers with places: each `POST /tenants` takes one.
async fn places(s: &mut Suite, admin: &Key) {
    let offer = |places: Value| json!({ "quota": 64 * 1024, "expires_at": now() + 86_400_000, "places": places }).to_string().into_bytes();
    let (zero, _) = s.admin(admin, "POST", "/admin/offers", offer(json!(0))).await;
    let (many, _) = s.admin(admin, "POST", "/admin/offers", offer(json!(1001))).await;
    s.record("places.invalid", format!("zero={} too-many={}", outcome(&zero), outcome(&many)));
    let (f, _) = s.admin(admin, "POST", "/admin/offers", offer(json!(3))).await;
    let secret = json_body(&f)["secret"].as_str().unwrap_or_default().to_string();
    let id = json_body(&f)["offer"].as_str().unwrap_or_default().to_string();
    let mut taken = Vec::new();
    let mut tenants = std::collections::BTreeSet::new();
    for _ in 0..4 {
        let p = Person::new(1);
        let f = s.call("POST", "/tenants", vec![("cw-offer", secret.clone())], p.card.clone()).await;
        if let Some(t) = json_body(&f)["tenant"].as_str() {
            tenants.insert(t.to_string());
        }
        taken.push(outcome(&f));
    }
    s.record("places.three", format!("{} tenants={}", taken.join(","), tenants.len()));
    let (f, _) = s.admin(admin, "DELETE", &format!("/admin/offers/{id}"), vec![]).await;
    s.record("places.withdraw-used", outcome(&f));
    let (f, _) = s.admin(admin, "POST", "/admin/offers", offer(json!(2))).await;
    let secret = json_body(&f)["secret"].as_str().unwrap_or_default().to_string();
    let id = json_body(&f)["offer"].as_str().unwrap_or_default().to_string();
    let p = Person::new(1);
    let first = s.call("POST", "/tenants", vec![("cw-offer", secret.clone())], p.card.clone()).await;
    let made = json_body(&first)["tenant"].as_str().unwrap_or_default().to_string();
    let (f, _) = s.admin(admin, "DELETE", &format!("/admin/offers/{id}"), vec![]).await;
    let after = s.call("POST", "/tenants", vec![("cw-offer", secret)], Person::new(1).card).await;
    let card = s.call("GET", &format!("/t/{made}/card"), vec![], vec![]).await;
    s.record("places.withdraw-rest", format!("first={} withdraw={} after={} made-stays={}", outcome(&first), outcome(&f), outcome(&after), card.status));
}

/// A per-tenant budget, and the half of it kept for requests with a current token.
async fn group_budget(s: &mut Suite, admin: &Key) {
    let mut hal = Person::new(1);
    admin_tenant(s, admin, &mut hal, 1 << 20).await;
    let path = format!("/admin/tenants/{}/budget", hal.tid());
    let (f, _) = s.admin(admin, "PUT", &path, json!({ "budget": 10 }).to_string().into_bytes()).await;
    s.record("budget.override-invalid", outcome(&f));
    let (f, _) = s.admin(admin, "PUT", &format!("/admin/tenants/{}/budget", b64::encode(&random::<16>())), json!({ "budget": 1000 }).to_string().into_bytes()).await;
    s.record("budget.override-unknown", outcome(&f));
    let (f, _) = s.admin(admin, "PUT", &path, json!({ "budget": 1000 }).to_string().into_bytes()).await;
    s.record("budget.override", outcome(&f));
    let settings = json!({ "guests": false, "guest_limit": 2, "member_budget": 30_000, "guest_budget": 1000 }).to_string().into_bytes();
    s.admin(admin, "PUT", "/admin/settings", settings).await;
    let (f, _) = s.admin(admin, "GET", "/admin/tenants", vec![]).await;
    let tid = hal.tid();
    let listed = |f: &Fetched| json_body(f).as_array().and_then(|a| a.iter().find(|t| t["tenant"] == tid).cloned()).unwrap_or_default();
    let l = listed(&f);
    s.record("budget.override-kept", format!("budget={} override={}", l["budget"], l["budget_override"]));
    // A retired read token passes the gate but isn't current: such requests stop at half the budget.
    let retired = hal.read.clone();
    s.owner(&hal, 0, "POST", "/tokens/audience?to=1", vec![], None).await;
    s.tokens(&mut hal).await;
    let mut answered = 0;
    let mut busy = None;
    for _ in 0..600 {
        let f = s.read(&hal, "/head", &retired, vec![]).await;
        if f.status == 429 {
            busy = Some(f);
            break;
        }
        answered += 1;
    }
    let wait = busy.as_ref().and_then(|f| f.header("retry-after")?.parse::<u64>().ok());
    s.record(
        "budget.half-without-token",
        format!("answered={answered} {} until-midnight={}", busy.as_ref().map_or("-".into(), outcome), wait.is_some_and(|w| w > 0 && w <= 86_400)),
    );
    let f = s.read(&hal, "/head", &hal.read, vec![]).await;
    let card = s.call("GET", &format!("/t/{}/card", hal.tid()), vec![], vec![]).await;
    s.record("budget.current-token-goes-on", format!("current={} open={}", outcome(&f), outcome(&card)));
    let (f, _) = s.admin(admin, "PUT", &path, json!({ "budget": null }).to_string().into_bytes()).await;
    let (l, _) = s.admin(admin, "GET", "/admin/tenants", vec![]).await;
    let l = listed(&l);
    s.record("budget.override-cleared", format!("{} budget={} override={}", outcome(&f), l["budget"], l["budget_override"]));
    let restore = json!({ "guests": false, "guest_limit": 2, "member_budget": 20_000, "guest_budget": 1000 }).to_string().into_bytes();
    s.admin(admin, "PUT", "/admin/settings", restore).await;
}

/// Per-IP limits for group and slot tokens. Each fills its own window for this minute.
async fn group_limits(s: &mut Suite, admin: &Key) {
    let mut ivy = Person::new(1);
    admin_tenant(s, admin, &mut ivy, 8 * 1024 * 1024).await;
    let g = group_tokens(&s.owner(&ivy, 0, "POST", "/tokens/group", vec![], None).await);
    let wall = b64::encode(&random::<16>());
    s.owner(&ivy, 0, "PUT", &format!("/threads/{wall}"), vec![], None).await;
    let first = json_body(&s.owner(&ivy, 0, "POST", "/slots", vec![], None).await)["token"].as_str().unwrap_or_default().to_string();
    let second = json_body(&s.owner(&ivy, 0, "POST", "/slots", vec![], None).await)["token"].as_str().unwrap_or_default().to_string();
    fresh_minute().await;
    let mut statuses = std::collections::BTreeSet::new();
    let mut ok = 0;
    for _ in 0..601 {
        let f = s.read(&ivy, &format!("/threads/{wall}"), &g.read, vec![]).await;
        ok += (f.status == 200) as u32;
        statuses.insert(outcome(&f));
    }
    s.record("limits.group-read-per-ip", format!("{statuses:?} answered={ok}"));
    let mut statuses = std::collections::BTreeSet::new();
    let mut ok = 0;
    for i in 0..31 {
        let _ = i;
        let body = wire::encode(&wire::SealedBox { nonce: random::<12>(), sealed: wire::vl(random::<48>().to_vec()) });
        let f = s.with_token(&ivy, "POST", &format!("/threads/{wall}"), &g.write, body).await;
        ok += (f.status == 201) as u32;
        statuses.insert(outcome(&f));
    }
    s.record("limits.group-write-per-ip", format!("{statuses:?} answered={ok}"));
    let mut statuses = std::collections::BTreeSet::new();
    let mut ok = 0;
    for i in 0..31 {
        let token = if i % 2 == 0 { &first } else { &second };
        let f = s.with_token(&ivy, "POST", "/inbox", token, inbox_box(256)).await;
        ok += (f.status == 201) as u32;
        statuses.insert(outcome(&f));
    }
    s.record("limits.slot-per-ip", format!("{statuses:?} answered={ok}"));
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut value = |name: &str| -> Option<String> {
        let i = args.iter().position(|a| a == name)?;
        args.remove(i);
        (i < args.len()).then(|| args.remove(i))
    };
    let base = value("--base").unwrap_or_else(|| fail("--base <origin>"));
    let claim = value("--claim").map(|c| b64::decode_array::<32>(&c).unwrap_or_else(|_| fail("--claim")));
    let readers = value("--readers").map_or(1000, |r| r.parse().unwrap_or_else(|_| fail("--readers")));
    let seconds = value("--seconds").map_or(10, |r| r.parse().unwrap_or_else(|_| fail("--seconds")));
    let interval = value("--interval-ms").map_or(100, |r| r.parse().unwrap_or_else(|_| fail("--interval-ms")));
    let tenants = value("--tenants").map_or(1, |r| r.parse().unwrap_or_else(|_| fail("--tenants")));
    let seeded = value("--seeded").map(|path| {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| fail(format!("{path}: {e}")));
        let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| fail(format!("{path}: {e}")));
        let list: Vec<(String, String)> = v["tenants"]
            .as_array()
            .map(|a| a.iter().map(|t| (t["url"].as_str().unwrap_or_default().into(), t["read"].as_str().unwrap_or_default().into())).collect())
            .unwrap_or_default();
        if list.is_empty() {
            fail(format!("{path}: no tenants"));
        }
        list
    });
    let saved = value("--saved");
    let command = args.first().cloned().unwrap_or_default();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let report = rt.block_on(async {
        match command.as_str() {
            "check" => {
                let out = check(&base, claim.unwrap_or_else(|| fail("--claim"))).await;
                let digest = b64::encode(&kdf::sha256(serde_json::to_string(&out).unwrap().as_bytes()));
                json!({ "checks": out.len(), "digest": digest, "outcomes": out })
            }
            "seed" => seed(&base, claim.unwrap_or_else(|| fail("--claim")), tenants).await,
            "load" => load(&base, &seeded.unwrap_or_else(|| fail("--seeded <file>")), readers, seconds, interval).await,
            "idle" => idle(&base, claim.unwrap_or_else(|| fail("--claim")), seconds).await,
            "restarts" => restarts::run(&base, claim.unwrap_or_else(|| fail("--claim")), tenants, seconds).await,
            "wakes" => wakes::run(&base, claim.unwrap_or_else(|| fail("--claim")), seconds).await,
            "upgrade-make" => upgrade::make(&base, claim.unwrap_or_else(|| fail("--claim"))).await,
            "upgrade-check" => {
                let path = saved.unwrap_or_else(|| fail("--saved <file>"));
                let text = std::fs::read_to_string(&path).unwrap_or_else(|e| fail(format!("{path}: {e}")));
                upgrade::check(&base, &serde_json::from_str(&text).unwrap_or_else(|e| fail(format!("{path}: {e}")))).await
            }
            _ => fail("usage: cw-conformance check|seed|load|idle|restarts|wakes|upgrade-make|upgrade-check --base <origin> ..."),
        }
    });
    println!("{report}");
}
