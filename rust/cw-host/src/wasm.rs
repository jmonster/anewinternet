//! The Worker's entry points: the gate, and the Host and Tenant Durable Objects' handlers over Durable
//! Object SQL. JavaScript passes requests in and performs the returned effects.
use js_sys::{Array, Object, Reflect, Uint8Array};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

use crate::gate::{gate, Gated};
use crate::host::{self, Internal};
use crate::limit::{ip_key, Windows};
use crate::route::Route;
use crate::sql::{Row, Store, StoreError, StoreResult, Value};
use crate::tenant::{self, Effect, Memory};
use crate::{Config, Request, Response};

#[wasm_bindgen]
extern "C" {
    /// `{ exec(sql, params) -> rows }` over `ctx.storage.sql`.
    pub type SqlBridge;
    #[wasm_bindgen(method, catch)]
    fn exec(this: &SqlBridge, sql: &str, params: Array) -> Result<Array, JsValue>;
}

struct JsStore<'a>(&'a SqlBridge);

impl Store for JsStore<'_> {
    fn exec(&mut self, sql: &str, params: &[Value]) -> StoreResult<Vec<Row>> {
        let args = Array::new();
        for p in params {
            args.push(&match p {
                Value::Null => JsValue::NULL,
                Value::Int(v) => JsValue::from_f64(*v as f64),
                Value::Text(t) => JsValue::from_str(t),
                Value::Blob(b) => Uint8Array::from(b.as_slice()).buffer().into(),
            });
        }
        let rows = self.0.exec(sql, args).map_err(|e| StoreError(format!("{e:?}")))?;
        let mut out = Vec::with_capacity(rows.length() as usize);
        for row in rows.iter() {
            let row = Array::from(&row);
            out.push(
                row.iter()
                    .map(|v| {
                        if v.is_null() || v.is_undefined() {
                            Value::Null
                        } else if let Some(n) = v.as_f64() {
                            Value::Int(n as i64)
                        } else if let Some(s) = v.as_string() {
                            Value::Text(s)
                        } else {
                            Value::Blob(Uint8Array::new(&v).to_vec())
                        }
                    })
                    .collect(),
            );
        }
        Ok(out)
    }
}

fn config(secret: &str, claim: &str, vapid: &str, origin: &str) -> Result<Config, JsValue> {
    let key = |v: &str| cw_crypto::b64::decode_array::<32>(v).map_err(|_| JsValue::from_str("host secrets"));
    Config::new(key(secret)?, key(claim)?, key(vapid)?, origin).ok_or_else(|| JsValue::from_str("host origin"))
}

fn request(method: String, authority: String, target: String, headers: Array, body: Vec<u8>, received: f64) -> Request {
    let headers = headers
        .iter()
        .filter_map(|pair| {
            let pair = Array::from(&pair);
            Some((pair.get(0).as_string()?.to_ascii_lowercase(), pair.get(1).as_string()?))
        })
        .collect();
    Request { method, authority, target, headers, body, received: received as u64 }
}

fn set(o: &Object, k: &str, v: impl Into<JsValue>) {
    let _ = Reflect::set(o, &JsValue::from_str(k), &v.into());
}

fn response_object(r: &Response, commit: bool) -> Object {
    let r = r.clone().cors();
    let o = Object::new();
    set(&o, "kind", "respond");
    set(&o, "commit", commit);
    set(&o, "status", r.status);
    let headers = Array::new();
    for (k, v) in &r.headers {
        headers.push(&Array::of2(&JsValue::from_str(k), &JsValue::from_str(v)));
    }
    set(&o, "headers", headers);
    set(&o, "body", Uint8Array::from(r.body.as_slice()));
    o
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes: Vec<u8> =
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect::<Option<_>>()?;
    bytes.try_into().ok()
}

fn effects_array(effects: Vec<Effect>) -> Array {
    let out = Array::new();
    for e in effects {
        let o = Object::new();
        match e {
            Effect::Event(text) => {
                set(&o, "t", "event");
                set(&o, "text", text);
            }
            Effect::WebPush { device, endpoint, authorization } => {
                set(&o, "t", "push");
                set(&o, "device", cw_crypto::b64::encode(&device));
                set(&o, "endpoint", endpoint);
                set(&o, "authorization", authorization);
            }
            Effect::Alarm(at) => {
                set(&o, "t", "alarm");
                set(&o, "at", at as f64);
            }
            Effect::CloseSockets => set(&o, "t", "close"),
        }
        out.push(&o);
    }
    out
}

/// The Worker's in-memory checks, run before any Durable Object is called.
#[wasm_bindgen]
pub struct Gate {
    config: Config,
    ip: Windows,
}

#[wasm_bindgen]
impl Gate {
    #[wasm_bindgen(constructor)]
    pub fn new(secret: &str, claim: &str, vapid: &str, origin: &str) -> Result<Gate, JsValue> {
        Ok(Gate { config: config(secret, claim, vapid, origin)?, ip: Windows::default() })
    }

    /// Returns `{ ok: true, target: "host" | <tenant hex> }`, or a response to send.
    pub fn check(&mut self, method: String, target: String, headers: Array, ip: &str, now: f64) -> Object {
        let req = request(method, String::new(), target, headers, Vec::new(), now);
        let gated = match gate(&self.config, &req) {
            Ok(g) => g,
            Err(r) => return response_object(&r, false),
        };
        if let Some((window, limit)) = gated.ip_limit() {
            let key = match ip.parse::<std::net::IpAddr>() {
                Ok(addr) => ip_key(window, addr),
                Err(_) => [&[window][..], ip.as_bytes()].concat(),
            };
            if let Err(wait) = self.ip.hit(&key, now as u64, limit) {
                return response_object(&Response::error(429, "rate").with("retry-after", wait), false);
            }
        }
        let o = Object::new();
        set(&o, "ok", true);
        set(
            &o,
            "target",
            match gated.route {
                Route::Host(_) => "host".to_string(),
                Route::Tenant(t, _) => hex(&t),
            },
        );
        o
    }
}

/// The Host Durable Object's handler.
#[wasm_bindgen]
pub struct HostHandle {
    config: Config,
}

#[wasm_bindgen]
impl HostHandle {
    #[wasm_bindgen(constructor)]
    pub fn new(secret: &str, claim: &str, vapid: &str, origin: &str) -> Result<HostHandle, JsValue> {
        Ok(HostHandle { config: config(secret, claim, vapid, origin)? })
    }

    pub fn ensure(&self, sql: &SqlBridge) -> Result<(), JsValue> {
        host::ensure(&mut JsStore(sql)).map_err(|e| JsValue::from_str(&e.0))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle(
        &self,
        sql: &SqlBridge,
        method: String,
        authority: String,
        target: String,
        headers: Array,
        body: Vec<u8>,
        received: f64,
        now: f64,
    ) -> Object {
        let req = request(method, authority, target, headers, body, received);
        let gated: Gated = match gate(&self.config, &req) {
            Ok(g) => g,
            Err(r) => return response_object(&r, false),
        };
        let mut store = JsStore(sql);
        let mut rng = OsRng;
        let mut ctx = host::Ctx { store: &mut store, config: &self.config, now: now as u64, rng: &mut rng };
        let (outcome, commit) = host::handle(&mut ctx, &gated, &req);
        match outcome {
            host::Outcome::Respond(r) => response_object(&r, commit),
            host::Outcome::Tenant(t, op) => {
                let o = Object::new();
                set(&o, "kind", "tenant");
                set(&o, "commit", commit);
                set(&o, "tenant", hex(&t));
                set(&o, "op", op.to_json().to_string());
                o
            }
            host::Outcome::Each(ops, finish) => {
                let o = Object::new();
                set(&o, "kind", "each");
                set(&o, "commit", commit);
                let list = Array::new();
                for (id, op) in ops {
                    list.push(&Array::of2(&JsValue::from_str(&hex(&id)), &JsValue::from_str(&op.to_json().to_string())));
                }
                set(&o, "ops", list);
                set(&o, "finish", match finish {
                    host::Finish::List => "list",
                    host::Finish::Settings => "settings",
                    host::Finish::Destroy => "destroy",
                });
                o
            }
        }
    }

    /// `results` is a JSON array of `[tenant hex, status, body text]`, one for each operation of an `each`.
    pub fn finish(&self, sql: &SqlBridge, finish: &str, results: &str) -> Object {
        let finish = match finish {
            "list" => host::Finish::List,
            "destroy" => host::Finish::Destroy,
            _ => host::Finish::Settings,
        };
        let parsed: Vec<(String, u16, String)> = serde_json::from_str(results).unwrap_or_default();
        let results = parsed
            .into_iter()
            .filter_map(|(t, status, body)| {
                let mut r = Response::empty(status);
                r.body = body.into_bytes();
                Some((unhex::<16>(&t)?, r))
            })
            .collect();
        let (r, commit, _) = host::finish(&mut JsStore(sql), &finish, results);
        response_object(&r, commit)
    }

    /// Runs an operation a tenant started.
    pub fn internal(&self, sql: &SqlBridge, op: &str, now: f64) -> Object {
        let Some(op) = serde_json::from_str(op).ok().as_ref().and_then(host::HostInternal::from_json) else {
            return response_object(&Response::error(400, "malformed"), false);
        };
        let mut store = JsStore(sql);
        let mut rng = OsRng;
        let mut ctx = host::Ctx { store: &mut store, config: &self.config, now: now as u64, rng: &mut rng };
        let (r, commit) = host::internal(&mut ctx, &op);
        response_object(&r, commit)
    }
}

/// A Tenant Durable Object's handler and memory.
#[wasm_bindgen]
pub struct TenantHandle {
    config: Config,
    tenant: [u8; 16],
    memory: Memory,
}

fn connected(list: Array) -> Vec<[u8; 32]> {
    list.iter().filter_map(|v| unhex::<32>(&v.as_string()?)).collect()
}

#[wasm_bindgen]
impl TenantHandle {
    #[wasm_bindgen(constructor)]
    pub fn new(secret: &str, claim: &str, vapid: &str, origin: &str, tenant: &str) -> Result<TenantHandle, JsValue> {
        Ok(TenantHandle {
            config: config(secret, claim, vapid, origin)?,
            tenant: unhex(tenant).ok_or_else(|| JsValue::from_str("tenant"))?,
            memory: Memory::default(),
        })
    }

    pub fn forget(&mut self) {
        self.memory.forget();
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle(
        &mut self,
        sql: &SqlBridge,
        method: String,
        authority: String,
        target: String,
        headers: Array,
        body: Vec<u8>,
        sockets: Array,
        received: f64,
        now: f64,
    ) -> Object {
        let req = request(method, authority, target, headers, body, received);
        let gated = match gate(&self.config, &req) {
            Ok(g) => g,
            Err(r) => return response_object(&r, false),
        };
        let connected = connected(sockets);
        let mut store = JsStore(sql);
        let mut rng = OsRng;
        let mut ctx = tenant::Ctx {
            store: &mut store,
            config: &self.config,
            now: now as u64,
            rng: &mut rng,
            memory: &mut self.memory,
            tenant: self.tenant,
            connected: &connected,
            effects: Vec::new(),
        };
        let (outcome, commit) = tenant::handle(&mut ctx, &gated, &req);
        let effects = effects_array(std::mem::take(&mut ctx.effects));
        let o = match outcome {
            tenant::Outcome::Respond(r) => response_object(&r, commit),
            tenant::Outcome::Accept { device, state } => {
                let o = Object::new();
                set(&o, "kind", "accept");
                set(&o, "commit", commit);
                set(&o, "device", hex(&device));
                set(&o, "state", state);
                o
            }
            tenant::Outcome::Import { from, grant } => {
                let o = Object::new();
                set(&o, "kind", "import");
                set(&o, "commit", commit);
                set(&o, "from", from);
                set(&o, "grant", grant);
                o
            }
            tenant::Outcome::Host(op) => {
                let o = Object::new();
                set(&o, "kind", "host");
                set(&o, "commit", commit);
                set(&o, "op", op.to_json().to_string());
                o
            }
        };
        set(&o, "effects", effects);
        o
    }

    pub fn internal(&mut self, sql: &SqlBridge, op: &str, sockets: Array, now: f64) -> Object {
        let Some(op) = serde_json::from_str(op).ok().as_ref().and_then(Internal::from_json) else {
            return response_object(&Response::error(400, "malformed"), false);
        };
        let connected = connected(sockets);
        let mut store = JsStore(sql);
        let mut rng = OsRng;
        let mut ctx = tenant::Ctx {
            store: &mut store,
            config: &self.config,
            now: now as u64,
            rng: &mut rng,
            memory: &mut self.memory,
            tenant: self.tenant,
            connected: &connected,
            effects: Vec::new(),
        };
        let (r, commit) = tenant::internal(&mut ctx, &op);
        let o = response_object(&r, commit);
        set(&o, "effects", effects_array(std::mem::take(&mut ctx.effects)));
        o
    }

    /// Returns `{ commit, missing: [name] }` or a response.
    pub fn import_export(&mut self, sql: &SqlBridge, bytes: Vec<u8>, now: f64) -> Object {
        let mut store = JsStore(sql);
        let mut rng = OsRng;
        let mut ctx = tenant::Ctx {
            store: &mut store,
            config: &self.config,
            now: now as u64,
            rng: &mut rng,
            memory: &mut self.memory,
            tenant: self.tenant,
            connected: &[],
            effects: Vec::new(),
        };
        match tenant::import_export(&mut ctx, &bytes) {
            (Ok(missing), commit) => {
                let o = Object::new();
                set(&o, "kind", "missing");
                set(&o, "commit", commit);
                let list = Array::new();
                for name in missing {
                    list.push(&JsValue::from_str(&name));
                }
                set(&o, "missing", list);
                o
            }
            (Err(r), commit) => response_object(&r, commit),
        }
    }

    pub fn import_object(&mut self, sql: &SqlBridge, name: &str, bytes: Vec<u8>, now: f64) -> Object {
        let mut store = JsStore(sql);
        let mut rng = OsRng;
        let mut ctx = tenant::Ctx {
            store: &mut store,
            config: &self.config,
            now: now as u64,
            rng: &mut rng,
            memory: &mut self.memory,
            tenant: self.tenant,
            connected: &[],
            effects: Vec::new(),
        };
        match tenant::import_object(&mut ctx, name, &bytes) {
            (Ok(()), commit) => {
                let o = Object::new();
                set(&o, "kind", "stored");
                set(&o, "commit", commit);
                o
            }
            (Err(r), commit) => response_object(&r, commit),
        }
    }

    pub fn import_done(&self, objects: u32, bytes: f64) -> Object {
        response_object(&tenant::import_done(objects as usize, bytes as u64), true)
    }
}
