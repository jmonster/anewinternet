//! Runs cw-host natively: gates each request, opens the tenant's or host's database, applies effects
//! (socket events, Web Push, alarms), and pulls transfers.
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cw_host::gate::{gate, Gated};
use cw_host::host::{self, Internal};
use cw_host::limit::{ip_key, Windows};
use cw_host::route::{Route, TenantRoute};
use cw_host::tenant::{self, Effect, Memory};
use cw_host::{Config, Request, Response};
use rand::rngs::OsRng;
use rusqlite::Connection;
use tokio::sync::mpsc;

use crate::client;
use crate::db::{self, Db};

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

pub enum Frame {
    Text(String),
    Close,
}

struct Socket {
    id: u64,
    device: [u8; 32],
    tx: mpsc::UnboundedSender<Frame>,
}

struct Slot {
    conn: Connection,
    memory: Memory,
    used: Instant,
}

pub enum Reply {
    Response(Response),
    /// Accept the push socket for this tenant's device.
    Upgrade {
        tenant: [u8; 16],
        device: [u8; 32],
        /// The socket's first frame.
        state: String,
    },
}

pub struct Runtime {
    pub config: Config,
    data: PathBuf,
    host: Mutex<Connection>,
    tenants: Mutex<HashMap<[u8; 16], Arc<Mutex<Slot>>>>,
    ip: Mutex<Windows>,
    sockets: Mutex<HashMap<[u8; 16], Vec<Socket>>>,
    alarms: Mutex<HashMap<[u8; 16], u64>>,
    next_socket: AtomicU64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn storage(e: impl std::fmt::Display) -> Response {
    Response::error(500, &format!("storage: {e}"))
}

impl Runtime {
    pub fn open(data: &Path, config: Config) -> Result<Arc<Runtime>, String> {
        std::fs::create_dir_all(data.join("tenants")).map_err(|e| e.to_string())?;
        let conn = db::open(&data.join("host.db"), true).map_err(|e| e.to_string())?;
        host::ensure(&mut Db { conn: &conn, objects: None }).map_err(|e| e.to_string())?;
        Ok(Arc::new(Runtime {
            config,
            data: data.to_path_buf(),
            host: Mutex::new(conn),
            tenants: Mutex::new(HashMap::new()),
            ip: Mutex::new(Windows::default()),
            sockets: Mutex::new(HashMap::new()),
            alarms: Mutex::new(HashMap::new()),
            next_socket: AtomicU64::new(1),
        }))
    }

    fn tenant_db(&self, tenant: &[u8; 16]) -> PathBuf {
        self.data.join("tenants").join(format!("{}.db", hex(tenant)))
    }

    fn tenant_objects(&self, tenant: &[u8; 16]) -> PathBuf {
        self.data.join("tenants").join(hex(tenant))
    }

    fn slot(&self, tenant: &[u8; 16], create: bool) -> Result<Option<Arc<Mutex<Slot>>>, Response> {
        let mut tenants = self.tenants.lock().unwrap();
        if let Some(slot) = tenants.get(tenant) {
            return Ok(Some(slot.clone()));
        }
        let path = self.tenant_db(tenant);
        if !create && !path.exists() {
            return Ok(None);
        }
        let conn = db::open(&path, create).map_err(storage)?;
        let slot = Arc::new(Mutex::new(Slot { conn, memory: Memory::default(), used: Instant::now() }));
        tenants.insert(*tenant, slot.clone());
        Ok(Some(slot))
    }

    fn connected(&self, tenant: &[u8; 16]) -> Vec<[u8; 32]> {
        self.sockets.lock().unwrap().get(tenant).map_or_else(Vec::new, |s| s.iter().map(|s| s.device).collect())
    }

    /// Runs `f` on a tenant's store inside one transaction. `None` when the tenant has no database.
    fn with_tenant<T>(
        &self,
        tenant: [u8; 16],
        create: bool,
        f: impl FnOnce(&mut tenant::Ctx<Db, OsRng>) -> (T, bool),
    ) -> Result<Option<(T, Vec<Effect>)>, Response> {
        let Some(slot) = self.slot(&tenant, create)? else { return Ok(None) };
        let connected = self.connected(&tenant);
        let mut guard = slot.lock().unwrap();
        let slot = &mut *guard;
        slot.used = Instant::now();
        let mut rng = OsRng;
        let mut store = Db { conn: &slot.conn, objects: Some(self.tenant_objects(&tenant)) };
        let mut ctx = tenant::Ctx {
            store: &mut store,
            config: &self.config,
            now: now_ms(),
            rng: &mut rng,
            memory: &mut slot.memory,
            tenant,
            connected: &connected,
            effects: Vec::new(),
        };
        let value = db::transaction(&slot.conn, || f(&mut ctx)).map_err(|e| {
            ctx.memory.forget();
            storage(e)
        })?;
        let effects = std::mem::take(&mut ctx.effects);
        Ok(Some((value, effects)))
    }

    async fn blocking<T: Send + 'static>(self: &Arc<Self>, f: impl FnOnce(&Runtime) -> T + Send + 'static) -> T {
        let rt = self.clone();
        tokio::task::spawn_blocking(move || f(&rt)).await.expect("blocking task")
    }

    pub async fn handle(self: &Arc<Self>, req: Request, ip: IpAddr) -> Reply {
        let gated = match gate(&self.config, &req) {
            Ok(g) => g,
            Err(r) => return Reply::Response(r),
        };
        if let Some((window, limit)) = gated.ip_limit() {
            if let Err(wait) = self.ip.lock().unwrap().hit(&ip_key(window, ip), now_ms(), limit) {
                return Reply::Response(Response::error(429, "rate").with("retry-after", wait));
            }
        }
        match gated.route.clone() {
            Route::Host(_) => Reply::Response(self.host_request(gated, req).await),
            Route::Tenant(t, _) => self.tenant_request(t, gated, req).await,
        }
    }

    async fn host_request(self: &Arc<Self>, gated: Gated, req: Request) -> Response {
        let outcome = self
            .blocking(move |rt| {
                let conn = rt.host.lock().unwrap();
                let mut store = Db { conn: &conn, objects: None };
                let mut rng = OsRng;
                let mut ctx = host::Ctx { store: &mut store, config: &rt.config, now: now_ms(), rng: &mut rng };
                db::transaction(&conn, || host::handle(&mut ctx, &gated, &req)).map_err(storage)
            })
            .await;
        match outcome {
            Err(r) | Ok(host::Outcome::Respond(r)) => r,
            Ok(host::Outcome::Tenant(t, op)) => self.internal(t, op).await,
            Ok(host::Outcome::Each(ops, finish)) => {
                let destroy = finish == host::Finish::Destroy;
                let mut results = Vec::new();
                for (id, op) in ops {
                    results.push((id, self.internal(id, op).await));
                }
                let (response, gone) = self
                    .blocking(move |rt| {
                        let conn = rt.host.lock().unwrap();
                        let mut store = Db { conn: &conn, objects: None };
                        let mut gone = Vec::new();
                        let response = db::transaction(&conn, || {
                            let (r, commit, g) = host::finish(&mut store, &finish, results);
                            gone = g;
                            (r, commit)
                        });
                        (response.unwrap_or_else(storage), gone)
                    })
                    .await;
                for id in gone {
                    self.forget(&id);
                }
                // A destroyed host's deleted rows leave no trace in its database file.
                if destroy && response.status == 204 {
                    let _ = self.blocking(|rt| rt.host.lock().unwrap().execute_batch("VACUUM")).await;
                }
                response
            }
        }
    }

    /// Runs an operation a tenant started on the host's store.
    async fn host_internal(self: &Arc<Self>, op: host::HostInternal) -> Response {
        self.blocking(move |rt| {
            let conn = rt.host.lock().unwrap();
            let mut store = Db { conn: &conn, objects: None };
            let mut rng = OsRng;
            let mut ctx = host::Ctx { store: &mut store, config: &rt.config, now: now_ms(), rng: &mut rng };
            db::transaction(&conn, || host::internal(&mut ctx, &op)).unwrap_or_else(storage)
        })
        .await
    }

    /// Drops a tenant whose forwarding period ended: its database and objects.
    fn forget(&self, tenant: &[u8; 16]) {
        self.tenants.lock().unwrap().remove(tenant);
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.tenant_db(tenant).into_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_dir_all(self.tenant_objects(tenant));
    }

    /// Runs an internal operation on a tenant and applies its effects.
    pub async fn internal(self: &Arc<Self>, tenant: [u8; 16], op: Internal) -> Response {
        let create = matches!(op, Internal::Init { .. });
        let result = self.blocking(move |rt| rt.with_tenant(tenant, create, |ctx| tenant::internal(ctx, &op))).await;
        match result {
            Err(r) => r,
            Ok(None) => Response::error(404, "not-found"),
            Ok(Some((response, effects))) => {
                self.apply(tenant, effects);
                response
            }
        }
    }

    async fn tenant_request(self: &Arc<Self>, t: [u8; 16], gated: Gated, req: Request) -> Reply {
        // Requests that touch object files go to the blocking pool; the rest take microseconds and run here.
        let files = matches!(
            gated.route,
            Route::Tenant(
                _,
                TenantRoute::PutObject(_)
                    | TenantRoute::GetObject(_)
                    | TenantRoute::DeleteObject(_)
                    | TenantRoute::Export
            )
        ) || req.body.len() > 64 * 1024;
        let result = if files {
            self.blocking(move |rt| rt.with_tenant(t, false, |ctx| tenant::handle(ctx, &gated, &req))).await
        } else {
            self.with_tenant(t, false, |ctx| tenant::handle(ctx, &gated, &req))
        };
        let (outcome, effects) = match result {
            Err(r) => return Reply::Response(r),
            Ok(None) => return Reply::Response(Response::error(404, "not-found")),
            Ok(Some(v)) => v,
        };
        self.apply(t, effects);
        match outcome {
            tenant::Outcome::Respond(r) => Reply::Response(r),
            tenant::Outcome::Accept { device, state } => Reply::Upgrade { tenant: t, device, state },
            tenant::Outcome::Import { from, grant } => Reply::Response(self.import(t, from, grant).await),
            tenant::Outcome::Host(op) => Reply::Response(self.host_internal(op).await),
        }
    }

    async fn import(self: &Arc<Self>, t: [u8; 16], from: String, grant: String) -> Response {
        let failed = |what: &str| Response::error(502, &format!("transfer: {what}"));
        let export = match client::fetch("GET", &format!("{from}/export"), &[("cw-grant", grant.clone())], vec![]).await
        {
            Ok(f) if f.status == 200 => f.body,
            Ok(f) => return failed(&format!("export answered {}", f.status)),
            Err(e) => return failed(&e),
        };
        let result = self.blocking(move |rt| rt.with_tenant(t, false, |ctx| tenant::import_export(ctx, &export))).await;
        let missing = match result {
            Err(r) => return r,
            Ok(None) => return Response::error(404, "not-found"),
            Ok(Some((Err(r), _))) => return r,
            Ok(Some((Ok(missing), effects))) => {
                self.apply(t, effects);
                missing
            }
        };
        let (mut count, mut bytes) = (0usize, 0u64);
        for name in missing {
            let url = format!("{from}/objects/{name}");
            let body = match client::fetch("GET", &url, &[("cw-grant", grant.clone())], vec![]).await {
                Ok(f) if f.status == 200 => f.body,
                Ok(f) => return failed(&format!("{name} answered {}", f.status)),
                Err(e) => return failed(&e),
            };
            let size = body.len() as u64;
            let result = self
                .blocking(move |rt| rt.with_tenant(t, false, |ctx| tenant::import_object(ctx, &name, &body)))
                .await;
            match result {
                Err(r) | Ok(Some((Err(r), _))) => return r,
                Ok(None) => return Response::error(404, "not-found"),
                Ok(Some((Ok(()), _))) => {}
            }
            count += 1;
            bytes += size;
        }
        tenant::import_done(count, bytes)
    }

    fn apply(self: &Arc<Self>, tenant: [u8; 16], effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Event(text) => {
                    if let Some(list) = self.sockets.lock().unwrap().get(&tenant) {
                        for s in list {
                            let _ = s.tx.send(Frame::Text(text.clone()));
                        }
                    }
                }
                Effect::CloseSockets => {
                    if let Some(list) = self.sockets.lock().unwrap().remove(&tenant) {
                        for s in list {
                            let _ = s.tx.send(Frame::Close);
                        }
                    }
                }
                Effect::WebPush { device, endpoint, authorization } => {
                    let rt = self.clone();
                    tokio::spawn(async move {
                        let headers =
                            [("authorization", authorization), ("ttl", "86400".into()), ("urgency", "high".into())];
                        if let Ok(f) = client::fetch("POST", &endpoint, &headers, vec![]).await {
                            if f.status == 404 || f.status == 410 {
                                rt.internal(tenant, Internal::DropSubscription(device)).await;
                            }
                        }
                    });
                }
                Effect::Alarm(at) => {
                    if self.alarms.lock().unwrap().insert(tenant, at) == Some(at) {
                        continue;
                    }
                    let rt = self.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(at.saturating_sub(now_ms()))).await;
                        let current = rt.alarms.lock().unwrap().get(&tenant).copied();
                        if current == Some(at) {
                            rt.alarms.lock().unwrap().remove(&tenant);
                            rt.internal(tenant, Internal::Alarm).await;
                        }
                    });
                }
            }
        }
    }

    /// Registers an accepted push socket; returns its ID and the frames to send.
    pub fn attach(&self, tenant: [u8; 16], device: [u8; 32]) -> (u64, mpsc::UnboundedReceiver<Frame>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.next_socket.fetch_add(1, Ordering::Relaxed);
        self.sockets.lock().unwrap().entry(tenant).or_default().push(Socket { id, device, tx });
        (id, rx)
    }

    pub fn detach(&self, tenant: [u8; 16], id: u64) {
        let mut sockets = self.sockets.lock().unwrap();
        if let Some(list) = sockets.get_mut(&tenant) {
            list.retain(|s| s.id != id);
            if list.is_empty() {
                sockets.remove(&tenant);
            }
        }
    }

    /// Runs each tenant's deadlines once at start, which also re-arms pending notice alarms.
    pub async fn start(self: &Arc<Self>) {
        let ids: Vec<[u8; 16]> = std::fs::read_dir(self.data.join("tenants"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let hex = name.strip_suffix(".db")?;
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
                    .collect::<Option<_>>()?;
                bytes.try_into().ok()
            })
            .collect();
        for id in ids {
            self.internal(id, Internal::Alarm).await;
            self.tenants.lock().unwrap().remove(&id);
        }
        let rt = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                rt.close_idle();
            }
        });
    }

    /// Asks every push socket to close, when the host stops; devices reconnect to the next process.
    pub fn close_sockets(&self) {
        for socket in self.sockets.lock().unwrap().values().flatten() {
            let _ = socket.tx.send(Frame::Close);
        }
    }

    /// Closes tenant databases unused for five minutes.
    fn close_idle(&self) {
        let sockets = self.sockets.lock().unwrap();
        self.tenants.lock().unwrap().retain(|id, slot| {
            sockets.contains_key(id) || slot.try_lock().map_or(true, |s| s.used.elapsed() < Duration::from_secs(300))
        });
    }

    /// Whether this route is the socket upgrade (for the server to keep hyper's upgrade handle).
    pub fn is_socket(req: &Request) -> bool {
        matches!(cw_host::route::route("GET", req.path()), Some(Route::Tenant(_, TenantRoute::Socket)))
    }
}
