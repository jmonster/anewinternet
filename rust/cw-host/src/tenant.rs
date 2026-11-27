//! Tenant requests (docs/hosts.md, "Tenant paths"). Each call runs inside one transaction of the tenant's
//! store; `Memory` caches the tenant row between calls and is dropped whenever a call rolls back.
use cw_crypto::card::Card;
use cw_crypto::request::Signer;
use cw_crypto::sign::{self, Kind};
use cw_crypto::token::{self, Checked, TokenKind};
use cw_crypto::wire::{self, Entries, Export, InviteExport, InviteUpload, ThreadExport};
use cw_crypto::{b64, kdf, object, pad};
use rand::{CryptoRng, RngCore};
use serde_json::{json, Value as Json};
use subtle::ConstantTimeEq;

use crate::gate::Gated;
use crate::host::{HostInternal, Internal, Limits};
use crate::http::{Request, Response};
use crate::limit::{Windows, GROUP_WRITE_PER_TOKEN, PER_TOKEN};
use crate::route::{Route, TenantRoute as T};
use crate::sql::{Store, StoreError, Value};
use crate::{auth, push, Config, DAY_MS, GUEST_MS, GUEST_NOTICE_MS, MEMBER_BUDGET};

type R<T> = Result<T, Response>;

const ACTIVE: i64 = 1;
const NOTICE: i64 = 2;
const REMOVED: i64 = 3;
/// Writes allowed, on the guest quota until `notice_until`, when notice begins.
const GUEST: i64 = 4;

const FORWARD_MS: u64 = 7 * DAY_MS;
const LINK_MS: u64 = 10 * 60 * 1000;
const INVITE_MS: u64 = 30 * DAY_MS;
/// An invitation's release secret, and the redeemer's claim that follows it once redeemed.
const RELEASE: usize = 32;
const CLAIMED: usize = 2 * RELEASE;
const PUSH_GAP_MS: u64 = 10_000;
const LIST_ENTRIES: i64 = 1_000;
const LIST_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACCESS: i64 = 10_000;
const MAX_SLOTS: usize = 64;
const SLOT_UNREAD: u64 = 20;
const SLOT_ITEMS: u64 = 200;
const SLOT_BYTES: u64 = 4 * 1024 * 1024;
/// What an inbox entry adds to the item it carries: its kind and the item's length.
const INBOX_FRAMING: u64 = 5;

/// The tenant's state as its owner sees it in `GET /status`.
fn status_json(s: &State) -> Json {
    json!({
        "state": s.state_name(),
        "notice_until": s.notice_until,
        "quota": s.quota,
        "used": s.used,
        "inbox": s.inbox_count,
        "inbox_bytes": s.inbox_bytes,
        "guests": s.limits.guests && s.state == ACTIVE,
    })
}

/// A push socket's first frame: where the inbox, log and card stand, the status, and the day each device last opened
/// a socket, so an opening device fetches only what moved while it was away.
fn socket_state<S: Store, Rn: RngCore + CryptoRng>(ctx: &mut Ctx<S, Rn>) -> R<String> {
    let mut seen = serde_json::Map::new();
    for row in ctx.exec("SELECT device, day FROM seen", &[])? {
        seen.insert(b64::encode(&row[0].blob()), (row[1].u64() * DAY_MS).into());
    }
    let s = ctx.st();
    Ok(json!({
        "t": "state",
        "inbox": s.inbox_seq,
        "log": s.log_next,
        "card": s.card.version,
        "status": status_json(s),
        "seen": seen,
    })
    .to_string())
}

/// The read and write tokens of the audience counter and the next one, and the counter.
fn audience_json<S: Store, Rn: RngCore + CryptoRng>(ctx: &Ctx<S, Rn>) -> serde_json::Map<String, Json> {
    let s = ctx.st();
    let secret = &ctx.config.secret;
    let issue = |counter: u64, kind: TokenKind| Json::String(token::issue(secret, &s.tenant, counter, kind, 0));
    let mut out = serde_json::Map::new();
    out.insert("read".into(), issue(s.audience_counter, TokenKind::Read));
    out.insert("write".into(), issue(s.audience_counter, TokenKind::Write));
    out.insert("read_next".into(), issue(s.audience_counter + 1, TokenKind::Read));
    out.insert("write_next".into(), issue(s.audience_counter + 1, TokenKind::Write));
    out.insert("audience".into(), s.audience_counter.into());
    out
}

/// `POST /tokens` for a device: its owner token, the audience tokens and the contact tokens, and the counters.
/// Owner tokens carry no counter; the request signature limits them to devices in the card.
fn tokens_json<S: Store, Rn: RngCore + CryptoRng>(ctx: &Ctx<S, Rn>, device: &[u8; 32]) -> Json {
    let s = ctx.st();
    let secret = &ctx.config.secret;
    let serial = u32::from_be_bytes(kdf::sha256(device)[..4].try_into().unwrap());
    let mut out = audience_json(ctx);
    out.insert("owner".into(), token::issue(secret, &s.tenant, 0, TokenKind::Owner, serial).into());
    out.insert("contact".into(), token::issue(secret, &s.tenant, s.contact_counter, TokenKind::Contact, 0).into());
    out.insert(
        "contact_next".into(),
        token::issue(secret, &s.tenant, s.contact_counter + 1, TokenKind::Contact, 0).into(),
    );
    out.insert("contact_counter".into(), s.contact_counter.into());
    Json::Object(out)
}

fn sealed_limit(plain: usize) -> usize {
    pad::bucket(plain + 1 + pad::TAG)
}

/// Something the runtime does after the transaction commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// A text frame for every open socket of the tenant.
    Event(String),
    /// A Web Push with no content.
    WebPush { device: [u8; 32], endpoint: String, authorization: String },
    /// Run `Internal::Alarm` at this time.
    Alarm(u64),
    /// Close every open socket of the tenant.
    CloseSockets,
}

/// Seconds from `now` to the next midnight UTC, when daily budgets reset.
fn until_midnight(now: u64) -> u64 {
    ((now / DAY_MS + 1) * DAY_MS - now).div_ceil(1000)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Respond(Response),
    /// Upgrade to the push socket for this device, answering with subprotocol `cw1`; `state` is its first frame.
    Accept {
        device: [u8; 32],
        state: String,
    },
    /// Pull the tenant from the old host: `GET <from>/export` with `CW-Grant`, `import_export`, then each
    /// missing object with `import_object`, then `import_done`.
    Import {
        from: String,
        grant: String,
    },
    /// Run the operation on the host's store, after this transaction commits, and answer with its response.
    Host(HostInternal),
}

#[derive(Debug, Clone)]
struct State {
    tenant: [u8; 16],
    created_at: u64,
    quota: u64,
    used: u64,
    state: i64,
    notice_until: u64,
    removed_at: u64,
    audience_counter: u64,
    requests_day: u64,
    requests: u64,
    last_write: u64,
    card_bytes: Vec<u8>,
    card: Card,
    head_revision: u64,
    snapshot_seq: u64,
    inbox_seq: u64,
    inbox_count: u64,
    inbox_bytes: u64,
    log_next: u64,
    log_tail: [u8; 32],
    last_maintenance: u64,
    /// From the `limits` table, which the host's settings write.
    limits: Limits,
    /// From the `contact` table.
    contact_counter: u64,
    /// From the `keyring_revision` table: the keyring's `ETag`, advanced by every put.
    keyring_revision: u64,
    /// From the `group_tokens` table.
    group_counter: u64,
    /// From the `budget_override` table: the admin's budget for this tenant, which wins over `limits`.
    budget_override: Option<u64>,
    /// From the `slots` table: each open slot, when it opened, and its items still in the inbox.
    slots: Vec<Slot>,
    /// From the `slot_items` table: items in the inbox that came through a slot, and their bytes.
    slot_items: u64,
    slot_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    slot: u64,
    opened_at: u64,
    unread: u64,
}

const COLUMNS: &str = "tenant, created_at, quota, used, state, notice_until, removed_at, audience_counter, \
    requests_day, requests, last_write, card, head_revision, snapshot_seq, inbox_seq, inbox_count, inbox_bytes, \
    log_next, log_tail, last_maintenance";

impl State {
    fn from_row(r: &[Value]) -> Option<State> {
        let card_bytes = r[11].blob();
        Some(State {
            tenant: r[0].array()?,
            created_at: r[1].u64(),
            quota: r[2].u64(),
            used: r[3].u64(),
            state: r[4].int(),
            notice_until: r[5].u64(),
            removed_at: r[6].u64(),
            audience_counter: r[7].u64(),
            requests_day: r[8].u64(),
            requests: r[9].u64(),
            last_write: r[10].u64(),
            card: Card::open(&card_bytes, None).ok()?,
            card_bytes,
            head_revision: r[12].u64(),
            snapshot_seq: r[13].u64(),
            inbox_seq: r[14].u64(),
            inbox_count: r[15].u64(),
            inbox_bytes: r[16].u64(),
            log_next: r[17].u64(),
            log_tail: r[18].array()?,
            last_maintenance: r[19].u64(),
            limits: Limits { guests: false, budget: MEMBER_BUDGET },
            contact_counter: 0,
            keyring_revision: 0,
            group_counter: 0,
            budget_override: None,
            slots: Vec::new(),
            slot_items: 0,
            slot_bytes: 0,
        })
    }

    fn value(&self, column: &str) -> Value {
        match column {
            "quota" => self.quota.into(),
            "used" => self.used.into(),
            "state" => self.state.into(),
            "notice_until" => self.notice_until.into(),
            "removed_at" => self.removed_at.into(),
            "audience_counter" => self.audience_counter.into(),
            "requests_day" => self.requests_day.into(),
            "requests" => self.requests.into(),
            "last_write" => self.last_write.into(),
            "card" => self.card_bytes.clone().into(),
            "head_revision" => self.head_revision.into(),
            "snapshot_seq" => self.snapshot_seq.into(),
            "inbox_seq" => self.inbox_seq.into(),
            "inbox_count" => self.inbox_count.into(),
            "inbox_bytes" => self.inbox_bytes.into(),
            "log_next" => self.log_next.into(),
            "log_tail" => (&self.log_tail).into(),
            "last_maintenance" => self.last_maintenance.into(),
            other => unreachable!("tenant column {other}"),
        }
    }

    /// Today's request budget: the admin's for this tenant, or the host setting's.
    fn budget(&self) -> u64 {
        self.budget_override.unwrap_or(self.limits.budget)
    }

    fn state_name(&self) -> &'static str {
        match self.state {
            NOTICE => "notice",
            REMOVED => "removed",
            GUEST => "guest",
            _ => "active",
        }
    }
}

/// What a tenant keeps in memory between requests: the tenant row, per-token write windows, and today's
/// request count.
#[derive(Default)]
pub struct Memory {
    schema: bool,
    state: Option<State>,
    tokens: Windows,
    /// The signed head, the most-read item, kept with the tenant row.
    head: Option<Option<Vec<u8>>>,
    /// The UTC day and its request count. A refused request rolls its transaction back but still counts, so this
    /// outlives `forget`; the tenant row gets it every 100 requests.
    requests: Option<(u64, u64)>,
    /// The UTC day and its count of requests without a current token, which may use half the budget. Kept in
    /// memory only, and like `requests` it outlives `forget`.
    open_requests: Option<(u64, u64)>,
    /// The `POST /batch` running in this transaction.
    batch: Option<BatchRun>,
}

/// A batch's signer, which every request in it runs as, and the tenant row columns its requests changed, written
/// once when it ends.
struct BatchRun {
    signer: [u8; 32],
    columns: Vec<&'static str>,
}

impl Memory {
    /// Drops the cached tenant row, after a rollback the runtime saw.
    pub fn forget(&mut self) {
        self.state = None;
        self.head = None;
        self.batch = None;
    }
}

pub struct Ctx<'a, S: Store, Rn: RngCore + CryptoRng> {
    pub store: &'a mut S,
    pub config: &'a Config,
    pub now: u64,
    pub rng: &'a mut Rn,
    pub memory: &'a mut Memory,
    pub tenant: [u8; 16],
    /// Devices with an open push socket.
    pub connected: &'a [[u8; 32]],
    pub effects: Vec<Effect>,
}

fn st(e: StoreError) -> Response {
    Response::error(500, &format!("storage: {e}"))
}

fn malformed() -> Response {
    Response::error(400, "malformed")
}

fn entries_response(entries: Entries, current: u64) -> Response {
    Response::ok(wire::encode(&entries)).with("cw-current", current)
}

impl<S: Store, Rn: RngCore + CryptoRng> Ctx<'_, S, Rn> {
    fn exec(&mut self, sql: &str, params: &[Value]) -> R<Vec<Vec<Value>>> {
        self.store.exec(sql, params).map_err(st)
    }

    fn next_keyring_revision(&mut self) -> R<()> {
        let revision = self.st().keyring_revision + 1;
        self.exec(
            "INSERT INTO keyring_revision (id, revision) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET revision = excluded.revision",
            &[revision.into()],
        )?;
        self.stm().keyring_revision = revision;
        Ok(())
    }

    /// The tenant row, loaded once per memory lifetime. `None` when the tenant has no data (never created,
    /// or its forwarding period ended).
    fn load(&mut self) -> R<Option<&mut State>> {
        if !self.memory.schema {
            crate::schema::create(self.store, crate::schema::TENANT).map_err(st)?;
            self.memory.schema = true;
        }
        if self.memory.state.is_none() {
            let rows = self.store.exec(&format!("SELECT {COLUMNS} FROM tenant WHERE id = 1"), &[]).map_err(st)?;
            match rows.first() {
                Some(row) => {
                    let mut state = State::from_row(row).ok_or_else(|| Response::error(500, "storage: tenant row"))?;
                    if state.tenant != self.tenant {
                        return Err(Response::error(500, "storage: tenant mismatch"));
                    }
                    let limits = self.store.exec("SELECT guests, budget FROM limits WHERE id = 1", &[]).map_err(st)?;
                    if let Some(l) = limits.first() {
                        state.limits = Limits { guests: l[0].int() != 0, budget: l[1].u64() };
                    }
                    let contact = self.store.exec("SELECT counter FROM contact WHERE id = 1", &[]).map_err(st)?;
                    if let Some(c) = contact.first() {
                        state.contact_counter = c[0].u64();
                    }
                    let keyring = self.store.exec("SELECT revision FROM keyring_revision WHERE id = 1", &[]).map_err(st)?;
                    if let Some(k) = keyring.first() {
                        state.keyring_revision = k[0].u64();
                    }
                    let group = self.store.exec("SELECT counter FROM group_tokens WHERE id = 1", &[]).map_err(st)?;
                    if let Some(g) = group.first() {
                        state.group_counter = g[0].u64();
                    }
                    let budget = self.store.exec("SELECT budget FROM budget_override WHERE id = 1", &[]).map_err(st)?;
                    state.budget_override = budget.first().map(|b| b[0].u64());
                    let slots =
                        self.store.exec("SELECT slot, opened_at, unread FROM slots ORDER BY slot", &[]).map_err(st)?;
                    state.slots =
                        slots.iter().map(|r| Slot { slot: r[0].u64(), opened_at: r[1].u64(), unread: r[2].u64() }).collect();
                    let items = self
                        .store
                        .exec("SELECT COUNT(*), COALESCE(SUM(size), 0) FROM slot_items", &[])
                        .map_err(st)?;
                    if let Some(i) = items.first() {
                        state.slot_items = i[0].u64();
                        state.slot_bytes = i[1].u64();
                    }
                    self.memory.state = Some(state);
                }
                None => return Ok(None),
            }
        }
        Ok(self.memory.state.as_mut())
    }

    fn state(&mut self) -> R<&mut State> {
        self.load()?.ok_or_else(|| Response::error(404, "not-found"))
    }

    fn st(&self) -> &State {
        self.memory.state.as_ref().expect("loaded")
    }

    fn stm(&mut self) -> &mut State {
        self.memory.state.as_mut().expect("loaded")
    }

    /// Writes these tenant row columns from memory.
    /// Inside a batch, the columns wait for its end, so the tenant row is written once.
    fn persist(&mut self, columns: &[&'static str]) -> R<()> {
        if let Some(batch) = self.memory.batch.as_mut() {
            for c in columns {
                if !batch.columns.contains(c) {
                    batch.columns.push(c);
                }
            }
            return Ok(());
        }
        let state = self.st();
        let sets: Vec<String> = columns.iter().enumerate().map(|(i, c)| format!("{c} = ?{}", i + 1)).collect();
        // The head is kept in memory with the row, and written with the row's other columns.
        let head = self.memory.head.clone().flatten();
        let values: Vec<Value> = columns.iter().map(|c| if *c == "head" { head.clone().into() } else { state.value(c) }).collect();
        self.exec(&format!("UPDATE tenant SET {} WHERE id = 1", sets.join(", ")), &values).map(|_| ())
    }

    fn set_limits(&mut self, limits: Limits) -> R<()> {
        self.stm().limits = limits;
        self.exec(
            "INSERT INTO limits (id, guests, budget) VALUES (1, ?1, ?2) \
             ON CONFLICT (id) DO UPDATE SET guests = excluded.guests, budget = excluded.budget",
            &[(limits.guests as i64).into(), limits.budget.into()],
        )
        .map(|_| ())
    }

    /// Adds `delta` bytes of storage, refusing it past the quota.
    fn charge(&mut self, delta: i64) -> R<()> {
        let s = self.stm();
        if delta > 0 && s.used + delta as u64 > s.quota {
            return Err(Response::error(507, "quota"));
        }
        s.used = (s.used as i64 + delta).max(0) as u64;
        Ok(())
    }

    fn writable(&mut self) -> R<()> {
        match self.st().state {
            ACTIVE | GUEST => Ok(()),
            NOTICE => Err(Response::error(403, "read-only")),
            _ => Err(Response::error(410, "gone")),
        }
    }

    fn wrote(&mut self, mut columns: Vec<&'static str>) -> R<()> {
        self.stm().last_write = self.now;
        columns.extend(["used", "last_write"]);
        self.persist(&columns)
    }

    fn event(&mut self, value: Json) {
        self.effects.push(Effect::Event(value.to_string()));
    }

    /// An inbox item or thread entry arrived: tell open sockets, and Web Push the card's other devices.
    fn notify(&mut self, value: Json) -> R<()> {
        self.event(value);
        let rows = self.exec("SELECT device, endpoint, last_push FROM subscriptions", &[])?;
        for row in rows {
            let Some(device) = row[0].array::<32>() else { continue };
            let endpoint = row[1].text();
            if !self.st().card.has_device(&device)
                || self.connected.contains(&device)
                || self.now < row[2].u64() + PUSH_GAP_MS
            {
                continue;
            }
            let Some(authorization) = push::authorization(self.config, &endpoint, self.now) else { continue };
            self.exec(
                "UPDATE subscriptions SET last_push = ?1 WHERE device = ?2",
                &[self.now.into(), (&device).into()],
            )?;
            self.effects.push(Effect::WebPush { device, endpoint, authorization });
        }
        Ok(())
    }

    // Credentials.

    fn token_current(&mut self, token: &Checked) -> R<()> {
        let s = self.st();
        let current = match token.kind {
            TokenKind::Read | TokenKind::Write => s.audience_counter,
            TokenKind::Owner => {
                return if token.epoch == 0 { Ok(()) } else { Err(Response::error(401, "expired-token")) };
            }
            TokenKind::Contact => s.contact_counter,
            TokenKind::GroupRead | TokenKind::GroupWrite => s.group_counter,
            TokenKind::Slot => {
                return if token.serial == 0 && s.slots.iter().any(|x| x.slot == token.epoch) {
                    Ok(())
                } else {
                    Err(Response::error(401, "expired-token"))
                };
            }
            TokenKind::Admin => return Err(Response::error(401, "unauthorized")),
        };
        // The next tokens of every counter work before their rotation, so the owner hands them out before retiring
        // the current ones.
        if token.epoch != current && token.epoch != current + 1 {
            return Err(Response::error(401, "expired-token"));
        }
        Ok(())
    }

    /// Each device's newest inbox key record, for devices the card lists: `(device, created_at, record)`.
    fn device_keys(&mut self) -> R<Vec<([u8; 32], u64, Vec<u8>)>> {
        let rows = self.exec("SELECT device, created_at, bytes FROM device_keys ORDER BY created_at", &[])?;
        let card = &self.st().card;
        Ok(rows
            .into_iter()
            .filter_map(|r| Some((r[0].array::<32>()?, r[1].u64(), r[2].blob())))
            .filter(|(d, _, _)| card.has_device(d))
            .collect())
    }

    /// The newest owner key generation stored.
    fn newest_owner_key(&mut self) -> R<Option<u64>> {
        Ok(self.exec("SELECT MAX(generation) FROM owner_keys", &[])?.first().and_then(|r| match r[0] { crate::sql::Value::Int(n) => Some(n as u64), _ => None }))
    }

    /// Refuses a log entry or snapshot of a generation below the newest owner key, so every entry after a rollover is
    /// of the new generation (docs/format.md, Owner key and own log).
    fn newest_generation(&mut self, generation: u32) -> R<()> {
        match self.newest_owner_key()? {
            Some(newest) if u64::from(generation) < newest => Err(Response::error(409, "generation")),
            _ => Ok(()),
        }
    }

    /// A signed request from a device in the card, or in `carried`, the card a `PUT /card` brings.
    fn signed(&mut self, req: &Request, carried: Option<&Card>) -> R<Signer> {
        if let Some(batch) = &self.memory.batch {
            return Ok(Signer { key: batch.signer, time: self.now, nonce: [0; 16] });
        }
        let card = &self.st().card;
        let signer = auth::signature(req, "cw-device", |id| card.device_key(id).or_else(|| carried?.device_key(id)))?;
        auth::nonce(self.store, &signer, self.now)?;
        Ok(signer)
    }

    fn owner(&mut self, req: &Request, token: &Option<Checked>) -> R<[u8; 32]> {
        // A batch checked its owner token and signature once; its requests may move the counter the token names.
        if let Some(batch) = &self.memory.batch {
            return Ok(batch.signer);
        }
        let token = token
            .as_ref()
            .filter(|t| t.kind == TokenKind::Owner)
            .ok_or_else(|| Response::error(401, "unauthorized"))?;
        self.token_current(token)?;
        Ok(self.signed(req, None)?.key)
    }

    fn reader(&mut self, token: &Option<Checked>) -> R<()> {
        if self.memory.batch.is_some() {
            return Ok(());
        }
        let token = token.ok_or_else(|| Response::error(401, "unauthorized"))?;
        self.token_current(&token)
    }

    fn writer(&mut self, token: &Option<Checked>) -> R<()> {
        if self.memory.batch.is_some() {
            return Ok(());
        }
        let token = token.ok_or_else(|| Response::error(401, "unauthorized"))?;
        self.token_current(&token)?;
        let key =
            [&token.tenant[..], &token.epoch.to_be_bytes(), &[token.kind as u8], &token.serial.to_be_bytes()].concat();
        let limit = if token.kind == TokenKind::GroupWrite { GROUP_WRITE_PER_TOKEN } else { PER_TOKEN };
        self.memory
            .tokens
            .hit(&key, self.now, limit)
            .map_err(|wait| Response::error(429, "rate").with("retry-after", wait))
    }

    // Deadlines, enforced on access.

    /// Today's request count: the one in memory, or the tenant row's when memory has none for today.
    fn requests_today(&self) -> u64 {
        let today = self.now / DAY_MS;
        let s = self.st();
        match self.memory.requests {
            Some((day, n)) if day == today => n.max(if s.requests_day == today { s.requests } else { 0 }),
            _ if s.requests_day == today => s.requests,
            _ => 0,
        }
    }

    /// Counts the request toward today's budget, whether or not it then succeeds. Past the budget it is refused
    /// until midnight UTC and not counted. A request without a current token is also refused, and not counted,
    /// once such requests used half of today's budget.
    fn count_request(&mut self, current: bool) -> R<Option<Response>> {
        let today = self.now / DAY_MS;
        let count = self.requests_today();
        let budget = self.st().budget();
        let now = self.now;
        let busy = move || Ok(Some(Response::error(429, "rate").with("retry-after", until_midnight(now))));
        if count >= budget {
            return busy();
        }
        if !current {
            let open = match self.memory.open_requests {
                Some((day, n)) if day == today => n,
                _ => 0,
            };
            if open >= budget / 2 {
                return busy();
            }
            self.memory.open_requests = Some((today, open + 1));
        }
        self.memory.requests = Some((today, count + 1));
        let s = self.stm();
        let rollover = s.requests_day != today;
        if rollover || (count + 1).is_multiple_of(100) || count + 1 == budget {
            s.requests_day = today;
            s.requests = count + 1;
            self.persist(&["requests_day", "requests"])?;
        }
        Ok(None)
    }

    fn maintain(&mut self) -> R<()> {
        let now = self.now;
        let s = self.st().clone();
        if s.state == GUEST && now >= s.notice_until {
            let until = s.notice_until + GUEST_NOTICE_MS;
            let t = self.stm();
            t.state = NOTICE;
            t.notice_until = until;
            self.persist(&["state", "notice_until"])?;
            self.event(json!({ "t": "status" }));
            self.effects.push(Effect::Alarm(until));
            return Ok(());
        }
        if s.state == NOTICE && now >= s.notice_until {
            return self.remove();
        }
        if s.state == REMOVED {
            if now >= s.removed_at + FORWARD_MS {
                self.exec("DELETE FROM tenant WHERE id = 1", &[])?;
                self.exec("DELETE FROM limits WHERE id = 1", &[])?;
                self.memory.forget();
            }
            return Ok(());
        }
        if now < s.last_maintenance + DAY_MS {
            return Ok(());
        }
        let freed: i64 = self
            .exec("SELECT COALESCE(SUM(length(bytes)), 0) FROM invites WHERE expires_at <= ?1", &[now.into()])?
            .first()
            .map_or(0, |r| r[0].int())
            + self
                .exec("SELECT COALESCE(SUM(length(bytes)), 0) FROM links WHERE expires_at <= ?1", &[now.into()])?
                .first()
                .map_or(0, |r| r[0].int());
        self.exec("DELETE FROM invites WHERE expires_at <= ?1", &[now.into()])?;
        self.exec("DELETE FROM links WHERE expires_at <= ?1", &[now.into()])?;
        self.exec(
            "DELETE FROM nonces WHERE at < ?1",
            &[now.saturating_sub(cw_crypto::request::NONCE_MEMORY_MS).into()],
        )?;
        self.charge(-freed)?;
        self.stm().last_maintenance = now;
        self.persist(&["used", "last_maintenance"])
    }

    /// Deletes everything but the card, which is served as the forwarding card for 7 days.
    fn remove(&mut self) -> R<()> {
        for table in crate::schema::TENANT_DATA {
            self.exec(&format!("DELETE FROM {table}"), &[])?;
        }
        self.store.blob_clear().map_err(st)?;
        self.exec("UPDATE tenant SET head = NULL, snapshot = NULL, passkey = NULL, keyring = NULL WHERE id = 1", &[])?;
        self.memory.head = None;
        let now = self.now;
        let s = self.stm();
        s.state = REMOVED;
        s.removed_at = now;
        s.used = s.card_bytes.len() as u64;
        s.inbox_count = 0;
        s.inbox_bytes = 0;
        s.group_counter = 0;
        s.budget_override = None;
        s.slots.clear();
        s.slot_items = 0;
        s.slot_bytes = 0;
        self.persist(&["state", "removed_at", "used", "inbox_count", "inbox_bytes"])?;
        self.event(json!({ "t": "status" }));
        self.effects.push(Effect::CloseSockets);
        Ok(())
    }
}

/// Handles a tenant request. The bool says whether to commit.
pub fn handle<S: Store, Rn: RngCore + CryptoRng>(
    ctx: &mut Ctx<S, Rn>,
    gated: &Gated,
    req: &Request,
) -> (Outcome, bool) {
    let result = (|| {
        let Route::Tenant(tenant, route) = &gated.route else { return Err(Response::error(404, "not-found")) };
        if *tenant != ctx.tenant {
            return Err(Response::error(404, "not-found"));
        }
        if ctx.load()?.is_none() {
            return Err(Response::error(404, "not-found"));
        }
        ctx.maintain()?;
        if ctx.memory.state.is_none() {
            return Err(Response::error(404, "not-found"));
        }
        // A request has a current token when its token's counter is the tenant's current one (or the next, for
        // contact and group tokens), or its slot is open.
        let current = gated.token.as_ref().is_some_and(|t| ctx.token_current(t).is_ok());
        if let Some(busy) = ctx.count_request(current)? {
            return Ok(Outcome::Respond(busy));
        }
        if ctx.st().state == REMOVED && !matches!(route, T::GetCard | T::PutCard) {
            return Err(Response::error(410, "gone"));
        }
        run(ctx, route, &gated.token, req)
    })();
    match result {
        Ok(outcome) => (outcome, true),
        Err(response) => {
            ctx.memory.forget();
            ctx.effects.clear();
            (Outcome::Respond(response), false)
        }
    }
}

fn respond(r: Response) -> R<Outcome> {
    Ok(Outcome::Respond(r))
}

fn run<S: Store, Rn: RngCore + CryptoRng>(
    ctx: &mut Ctx<S, Rn>,
    route: &T,
    token: &Option<Checked>,
    req: &Request,
) -> R<Outcome> {
    let now = ctx.now;
    match route {
        T::GetCard => {
            let s = ctx.st();
            respond(Response::ok(s.card_bytes.clone()).tagged(s.card.version, req))
        }
        T::PutCard => {
            let next = req.body.clone();
            if next.len() > cw_crypto::card::SIGNED_LIMIT {
                return Err(Response::error(413, "too-large"));
            }
            let card = Card::open(&next, None).map_err(|_| malformed())?;
            ctx.signed(req, Some(&card))?;
            let newer = Card::supersedes(&ctx.st().card_bytes, &next).map_err(|_| Response::error(409, "conflict"))?;
            if newer {
                let delta = next.len() as i64 - ctx.st().card_bytes.len() as i64;
                ctx.stm().used = (ctx.st().used as i64 + delta).max(0) as u64;
                let version = card.version;
                for row in ctx.exec("SELECT device FROM seen", &[])? {
                    if !row[0].array::<32>().is_some_and(|d| card.has_device(&d)) {
                        ctx.exec("DELETE FROM seen WHERE device = ?1", &[row[0].clone()])?;
                    }
                }
                // A removed device's inbox key goes with it.
                for row in ctx.exec("SELECT device, length(bytes) FROM device_keys", &[])? {
                    if !row[0].array::<32>().is_some_and(|d| card.has_device(&d)) {
                        ctx.exec("DELETE FROM device_keys WHERE device = ?1", &[row[0].clone()])?;
                        ctx.charge(-row[1].int())?;
                    }
                }
                let s = ctx.stm();
                s.card = card;
                s.card_bytes = next;
                ctx.wrote(vec!["card"])?;
                ctx.event(json!({ "t": "card", "version": version }));
            }
            respond(Response::empty(204))
        }
        T::Tokens => {
            let signer = ctx.signed(req, None)?;
            respond(Response::json(200, tokens_json(ctx, &signer.key)))
        }
        T::RotateContact => {
            ctx.owner(req, token)?;
            // `to` names the counter to reach, so devices that retire the same generation at once advance it once.
            let to = req.query_u64("to").ok_or_else(malformed)?;
            let current = ctx.st().contact_counter;
            if to > current + 1 {
                return Err(malformed());
            }
            if to == current + 1 {
                ctx.exec(
                    "INSERT INTO contact (id, counter) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET counter = excluded.counter",
                    &[to.into()],
                )?;
                ctx.stm().contact_counter = to;
            }
            let counter = ctx.st().contact_counter;
            let s = ctx.st();
            respond(Response::json(
                200,
                json!({ "contact": token::issue(&ctx.config.secret, &s.tenant, counter, TokenKind::Contact, 0) }),
            ))
        }
        T::Remove => {
            ctx.owner(req, token)?;
            ctx.remove()?;
            ctx.event(json!({ "t": "status" }));
            respond(Response::empty(204))
        }
        T::Status => {
            ctx.owner(req, token)?;
            respond(Response::json(200, status_json(ctx.st())))
        }
        T::PutKeyring => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            wire::decode::<wire::KeyringBox>(&req.body, 4096, "keyring").map_err(|_| malformed())?;
            let old = ctx.exec("SELECT length(keyring) FROM tenant WHERE id = 1", &[])?[0][0].int();
            ctx.charge(req.body.len() as i64 - old)?;
            ctx.exec("UPDATE tenant SET keyring = ?1 WHERE id = 1", &[req.body.clone().into()])?;
            // Every put changes the ETag: a keyring re-sealed for the same generation carries new tokens.
            ctx.next_keyring_revision()?;
            respond(Response::empty(204))
        }
        T::AudienceTokens => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            // `to` names the counter to reach, so devices finishing the same rotation advance it once.
            let to = req.query_u64("to").ok_or_else(malformed)?;
            let current = ctx.st().audience_counter;
            if to > current + 1 {
                return Err(malformed());
            }
            if to == current + 1 {
                ctx.stm().audience_counter = to;
                ctx.wrote(vec!["audience_counter"])?;
            }
            respond(Response::json(200, Json::Object(audience_json(ctx))))
        }
        T::GetKeyring => {
            let rows = ctx.exec("SELECT keyring FROM tenant WHERE id = 1", &[])?;
            let bytes = rows[0][0].opt_blob().ok_or_else(|| Response::error(404, "not-found"))?;
            respond(Response::ok(bytes).tagged(ctx.st().keyring_revision, req))
        }
        T::GetHead => {
            ctx.reader(token)?;
            if ctx.memory.head.is_none() {
                let rows = ctx.exec("SELECT head FROM tenant WHERE id = 1", &[])?;
                ctx.memory.head = Some(rows[0][0].opt_blob());
            }
            let bytes = ctx.memory.head.clone().flatten().ok_or_else(|| Response::error(404, "not-found"))?;
            respond(Response::ok(bytes).tagged(ctx.st().head_revision, req))
        }
        T::PutHead => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            let card = ctx.st().card.clone();
            let head = sign::open(&req.body, Kind::Head, 4096, |s| card.device_key(s)).map_err(|_| malformed())?;
            let body: wire::HeadBody = wire::decode(&head.body, 4096, "head").map_err(|_| malformed())?;
            let current = ctx.st().head_revision;
            if req.header_u64("if-match") != Some(current) || body.revision <= current || body.profile != card.profile {
                return Err(Response::error(412, "precondition").with("cw-current", current));
            }
            let old = match &ctx.memory.head {
                Some(head) => head.as_ref().map_or(0, |h| h.len() as i64),
                None => ctx.exec("SELECT length(head) FROM tenant WHERE id = 1", &[])?[0][0].int(),
            };
            ctx.charge(req.body.len() as i64 - old)?;
            ctx.memory.head = Some(Some(req.body.clone()));
            ctx.stm().head_revision = body.revision;
            ctx.wrote(vec!["head", "head_revision"])?;
            ctx.event(json!({ "t": "head", "revision": body.revision }));
            respond(Response::empty(204).with("etag", format!("\"{}\"", body.revision)))
        }
        T::PutObject(name) => {
            // A group's posters put photos with the group write token, at most 512 KiB each.
            let group = token.is_some_and(|t| t.kind == TokenKind::GroupWrite);
            if group {
                ctx.writer(token)?;
            } else {
                ctx.owner(req, token)?;
            }
            ctx.writable()?;
            let digest = object::parse_name(name).map_err(|_| malformed())?;
            let limit = if group { cw_crypto::access::OBJECT_LIMIT } else { sealed_limit(object::LIMIT) };
            if req.body.len() > limit {
                return Err(Response::error(413, "too-large"));
            }
            if kdf::sha256(&req.body) != digest {
                return Err(malformed());
            }
            let exists = ctx.exec("SELECT 1 FROM objects WHERE name = ?1", &[name.as_str().into()])?;
            if exists.is_empty() {
                ctx.charge(req.body.len() as i64)?;
                ctx.exec(
                    "INSERT INTO objects (name, size, created_at) VALUES (?1, ?2, ?3)",
                    &[name.as_str().into(), req.body.len().into(), now.into()],
                )?;
                ctx.store.blob_put(name, &req.body).map_err(st)?;
                ctx.wrote(vec![])?;
            }
            respond(Response::empty(if exists.is_empty() { 201 } else { 200 }))
        }
        T::GetObject(name) => {
            match req.header("cw-grant") {
                Some(grant) => grant_check(ctx, grant).map(|_| ())?,
                None => ctx.reader(token)?,
            }
            if ctx.exec("SELECT 1 FROM objects WHERE name = ?1", &[name.as_str().into()])?.is_empty() {
                return Err(Response::error(404, "not-found"));
            }
            let bytes = ctx.store.blob_get(name).map_err(st)?.ok_or_else(|| Response::error(500, "storage: object"))?;
            respond(Response::ok(bytes).immutable())
        }
        T::ListObjects => {
            ctx.owner(req, token)?;
            let after = req.query("after").unwrap_or("");
            let rows = ctx.exec(
                "SELECT name, size, created_at FROM objects WHERE name > ?1 ORDER BY name LIMIT ?2",
                &[after.into(), (LIST_ENTRIES + 1).into()],
            )?;
            let more = rows.len() as i64 > LIST_ENTRIES;
            let objects: Vec<Json> = rows
                .iter()
                .take(LIST_ENTRIES as usize)
                .map(|r| json!({ "name": r[0].text(), "size": r[1].int(), "created_at": r[2].u64() }))
                .collect();
            let next = if more { objects.last().map_or(Json::Null, |o| o["name"].clone()) } else { Json::Null };
            respond(Response::json(200, json!({ "objects": objects, "next": next })))
        }
        T::DeleteObject(name) => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            let rows = ctx.exec("DELETE FROM objects WHERE name = ?1 RETURNING size", &[name.as_str().into()])?;
            if let Some(row) = rows.first() {
                ctx.store.blob_delete(name).map_err(st)?;
                ctx.charge(-row[0].int())?;
                ctx.wrote(vec![])?;
            }
            respond(Response::empty(204))
        }
        T::PostLog => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            let card = ctx.st().card.clone();
            let limit = sealed_limit(cw_crypto::log::ENTRY_LIMIT) + 128;
            let entry =
                sign::open(&req.body, Kind::LogEntry, limit, |s| card.device_key(s)).map_err(|_| malformed())?;
            let body: wire::LogEntryBody = wire::decode(&entry.body, limit, "log entry").map_err(|_| malformed())?;
            let (next, tail) = (ctx.st().log_next, ctx.st().log_tail);
            if req.header_u64("if-match") != Some(next) || body.seq != next || body.previous != tail {
                return Err(Response::error(412, "precondition").with("cw-current", next));
            }
            ctx.newest_generation(body.generation)?;
            ctx.charge(req.body.len() as i64)?;
            ctx.exec("INSERT INTO log (seq, bytes) VALUES (?1, ?2)", &[next.into(), req.body.clone().into()])?;
            let s = ctx.stm();
            s.log_next = next + 1;
            s.log_tail = cw_crypto::log::digest(&req.body);
            ctx.wrote(vec!["log_next", "log_tail"])?;
            ctx.event(json!({ "t": "log", "seq": next }));
            respond(Response::empty(201).with("cw-seq", next))
        }
        T::GetLog => {
            ctx.owner(req, token)?;
            let from = req.query_u64("from").unwrap_or(0);
            let rows = ctx.exec(
                "SELECT seq, bytes FROM log WHERE seq >= ?1 ORDER BY seq LIMIT ?2",
                &[from.into(), LIST_ENTRIES.into()],
            )?;
            respond(entries_response(list(rows), ctx.st().log_next))
        }
        T::PutSnapshot => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            let card = ctx.st().card.clone();
            let snap = sign::open(&req.body, Kind::Snapshot, 4096, |s| card.device_key(s)).map_err(|_| malformed())?;
            let body: wire::SnapshotBody = wire::decode(&snap.body, 4096, "snapshot").map_err(|_| malformed())?;
            let (current, next) = (ctx.st().snapshot_seq, ctx.st().log_next);
            ctx.newest_generation(body.generation)?;
            let has = !ctx.exec("SELECT 1 FROM tenant WHERE id = 1 AND snapshot IS NOT NULL", &[])?.is_empty();
            if (has && body.seq <= current) || body.seq >= next {
                return Err(Response::error(412, "precondition").with("cw-current", current));
            }
            let old = ctx.exec("SELECT length(snapshot) FROM tenant WHERE id = 1", &[])?[0][0].int();
            ctx.charge(req.body.len() as i64 - old)?;
            ctx.exec("UPDATE tenant SET snapshot = ?1 WHERE id = 1", &[req.body.clone().into()])?;
            // The snapshot holds every record through its entry, so the entries it covers go. A device behind it
            // loads the snapshot instead.
            let freed = ctx.exec("DELETE FROM log WHERE seq <= ?1 RETURNING length(bytes)", &[body.seq.into()])?;
            ctx.charge(-freed.iter().map(|r| r[0].int()).sum::<i64>())?;
            ctx.stm().snapshot_seq = body.seq;
            ctx.wrote(vec!["snapshot_seq"])?;
            respond(Response::empty(204))
        }
        T::GetSnapshot => {
            ctx.owner(req, token)?;
            let rows = ctx.exec("SELECT snapshot FROM tenant WHERE id = 1", &[])?;
            let bytes = rows[0][0].opt_blob().ok_or_else(|| Response::error(404, "not-found"))?;
            respond(Response::ok(bytes).tagged(ctx.st().snapshot_seq, req))
        }
        T::PutOwnerKey => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            let card = ctx.st().card.clone();
            let limit = cw_crypto::log::KEY_LIMIT;
            let key = sign::open(&req.body, Kind::OwnerKey, limit, |s| card.device_key(s)).map_err(|e| match e {
                cw_crypto::Error::TooLarge(_) => Response::error(413, "too-large"),
                _ => malformed(),
            })?;
            let body: wire::OwnerKeyBody = wire::decode(&key.body, limit, "owner key").map_err(|_| malformed())?;
            // A generation is made once: two devices that roll over at once make the same generation with different
            // keys, and the second learns of the first here instead of writing entries nobody else can open.
            let rows = ctx.exec("SELECT bytes FROM owner_keys WHERE generation = ?1", &[body.generation.into()])?;
            if let Some(stored) = rows.first() {
                if stored[0].blob() != req.body {
                    return Err(Response::error(409, "conflict"));
                }
                return respond(Response::empty(204));
            }
            ctx.charge(req.body.len() as i64)?;
            ctx.exec("INSERT INTO owner_keys (generation, bytes) VALUES (?1, ?2)", &[body.generation.into(), req.body.clone().into()])?;
            ctx.wrote(vec![])?;
            respond(Response::empty(204))
        }
        T::GetOwnerKeys => {
            ctx.owner(req, token)?;
            let rows = ctx.exec("SELECT generation, bytes FROM owner_keys ORDER BY generation", &[])?;
            respond(entries_response(list(rows), 0))
        }
        T::DeleteOwnerKey(generation) => {
            ctx.owner(req, token)?;
            // The newest generation stays: the log and snapshot are sealed under it.
            if *generation >= ctx.newest_owner_key()?.unwrap_or(0) {
                return Err(Response::error(409, "conflict"));
            }
            let freed = ctx.exec("DELETE FROM owner_keys WHERE generation = ?1 RETURNING length(bytes)", &[(*generation).into()])?;
            ctx.charge(-freed.iter().map(|r| r[0].int()).sum::<i64>())?;
            ctx.wrote(vec![])?;
            respond(Response::empty(204))
        }
        T::PutDeviceKey => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            let card = ctx.st().card.clone();
            let key = cw_crypto::devicekey::open(&req.body, &card).map_err(|_| malformed())?;
            let old = ctx.exec("SELECT created_at, length(bytes) FROM device_keys WHERE device = ?1", &[(&key.device).into()])?;
            if old.first().is_some_and(|r| r[0].u64() >= key.created_at) {
                return respond(Response::empty(204));
            }
            ctx.charge(req.body.len() as i64 - old.first().map_or(0, |r| r[1].int()))?;
            ctx.exec(
                "INSERT INTO device_keys (device, created_at, bytes) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (device) DO UPDATE SET created_at = excluded.created_at, bytes = excluded.bytes",
                &[(&key.device).into(), key.created_at.into(), req.body.clone().into()],
            )?;
            ctx.wrote(vec![])?;
            respond(Response::empty(204))
        }
        T::GetDeviceKeys => {
            let rows = ctx.device_keys()?.into_iter().map(|(_, created_at, bytes)| vec![created_at.into(), bytes.into()]).collect();
            respond(entries_response(list(rows), 0))
        }
        T::PutPasskey => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            if req.body.len() > 1024 {
                return Err(Response::error(413, "too-large"));
            }
            wire::decode::<wire::SealedBox>(&req.body, 1024, "passkey backup").map_err(|_| malformed())?;
            let old = ctx.exec("SELECT length(passkey) FROM tenant WHERE id = 1", &[])?[0][0].int();
            ctx.charge(req.body.len() as i64 - old)?;
            ctx.exec("UPDATE tenant SET passkey = ?1 WHERE id = 1", &[req.body.clone().into()])?;
            ctx.wrote(vec![])?;
            respond(Response::empty(204))
        }
        T::GetPasskey => {
            let rows = ctx.exec("SELECT passkey FROM tenant WHERE id = 1", &[])?;
            let bytes = rows[0][0].opt_blob().ok_or_else(|| Response::error(404, "not-found"))?;
            respond(Response::ok(bytes))
        }
        T::PostInbox => {
            ctx.writer(token)?;
            ctx.writable()?;
            let item = wire::decode::<wire::InboxBox>(&req.body, cw_crypto::inbox::BOX_LIMIT, "inbox item").map_err(|e| match e {
                cw_crypto::Error::TooLarge(_) => Response::error(413, "too-large"),
                _ => malformed(),
            })?;
            // Every device with a record here must be wrapped for, with its newest key: an item sealed to an older key, or
            // leaving a device out, would be one some device can't open. The refusal carries the current records.
            let keys = ctx.device_keys()?;
            let current = keys.iter().all(|(device, created_at, _)| item.wraps.iter().any(|w| &w.device == device && w.created_at == *created_at));
            if !current {
                let records: Vec<String> = keys.iter().map(|(_, _, bytes)| b64::encode(bytes)).collect();
                return Err(Response::json(409, json!({ "error": "device-keys", "keys": records })));
            }
            let len = req.body.len() as u64;
            let s = ctx.st();
            if s.inbox_count + 1 > cw_crypto::inbox::MAX_ITEMS as u64
                || s.inbox_bytes + len + INBOX_FRAMING > cw_crypto::inbox::MAX_BYTES as u64
            {
                return Err(Response::error(507, "inbox-full"));
            }
            // An item through a slot: at most 20 waiting from that slot, and 200 items or 4 MiB from every slot.
            let slot = token.filter(|t| t.kind == TokenKind::Slot).map(|t| t.epoch);
            if let Some(slot) = slot {
                let unread = s.slots.iter().find(|x| x.slot == slot).map_or(0, |x| x.unread);
                if unread >= SLOT_UNREAD || s.slot_items + 1 > SLOT_ITEMS || s.slot_bytes + len > SLOT_BYTES {
                    return Err(Response::error(507, "slot-full"));
                }
            }
            let stored = wire::encode(&wire::InboxEntry { kind: wire::INBOX_ITEM, body: wire::vl(req.body.clone()) });
            ctx.charge(stored.len() as i64)?;
            let seq = ctx.st().inbox_seq;
            ctx.exec("INSERT INTO inbox (seq, bytes) VALUES (?1, ?2)", &[seq.into(), stored.clone().into()])?;
            if let Some(slot) = slot {
                ctx.exec(
                    "INSERT INTO slot_items (seq, slot, size) VALUES (?1, ?2, ?3)",
                    &[seq.into(), slot.into(), len.into()],
                )?;
                ctx.exec("UPDATE slots SET unread = unread + 1 WHERE slot = ?1", &[slot.into()])?;
                let s = ctx.stm();
                s.slot_items += 1;
                s.slot_bytes += len;
                if let Some(x) = s.slots.iter_mut().find(|x| x.slot == slot) {
                    x.unread += 1;
                }
            }
            let s = ctx.stm();
            s.inbox_seq = seq + 1;
            s.inbox_count += 1;
            s.inbox_bytes += stored.len() as u64;
            ctx.wrote(vec!["inbox_seq", "inbox_count", "inbox_bytes"])?;
            ctx.notify(json!({ "t": "inbox", "seq": seq }))?;
            respond(Response::empty(201).with("cw-seq", seq))
        }
        T::GetInbox => {
            ctx.owner(req, token)?;
            let from = req.query_u64("from").unwrap_or(0);
            let rows = ctx.exec(
                "SELECT seq, bytes FROM inbox WHERE seq >= ?1 ORDER BY seq LIMIT ?2",
                &[from.into(), LIST_ENTRIES.into()],
            )?;
            respond(entries_response(list(rows), ctx.st().inbox_seq))
        }
        T::DeleteInbox => {
            ctx.owner(req, token)?;
            let through = req.query_u64("through").ok_or_else(malformed)?;
            let rows = ctx.exec("DELETE FROM inbox WHERE seq <= ?1 RETURNING length(bytes)", &[through.into()])?;
            let bytes: i64 = rows.iter().map(|r| r[0].int()).sum();
            let items = ctx.exec("DELETE FROM slot_items WHERE seq <= ?1 RETURNING slot, size", &[through.into()])?;
            for item in &items {
                let slot = item[0].u64();
                ctx.exec("UPDATE slots SET unread = MAX(unread - 1, 0) WHERE slot = ?1", &[slot.into()])?;
                let s = ctx.stm();
                s.slot_items = s.slot_items.saturating_sub(1);
                s.slot_bytes = s.slot_bytes.saturating_sub(item[1].u64());
                if let Some(x) = s.slots.iter_mut().find(|x| x.slot == slot) {
                    x.unread = x.unread.saturating_sub(1);
                }
            }
            let s = ctx.stm();
            s.inbox_count = s.inbox_count.saturating_sub(rows.len() as u64);
            s.inbox_bytes = s.inbox_bytes.saturating_sub(bytes as u64);
            ctx.charge(-bytes)?;
            ctx.persist(&["inbox_count", "inbox_bytes", "used"])?;
            respond(Response::empty(204))
        }
        T::PostThread(thread) => {
            ctx.writer(token)?;
            ctx.writable()?;
            wire::decode::<wire::SealedBox>(&req.body, cw_crypto::thread::BOX_LIMIT, "thread entry").map_err(|e| match e {
                cw_crypto::Error::TooLarge(_) => Response::error(413, "too-large"),
                _ => malformed(),
            })?;
            let rows = ctx.exec("SELECT next, count FROM thread_heads WHERE thread = ?1", &[thread.into()])?;
            // A group write token appends only to a thread the owner opened, while its next sequence is below 1,800.
            if token.is_some_and(|t| t.kind == TokenKind::GroupWrite) {
                match rows.first() {
                    None => return Err(Response::error(404, "not-found")),
                    Some(r) if r[0].u64() >= cw_crypto::access::WALL_ENTRIES => {
                        return Err(Response::error(507, "thread-full"))
                    }
                    Some(_) => {}
                }
            }
            let (seq, count) = rows.first().map_or((0, 0), |r| (r[0].u64(), r[1].u64()));
            if count >= cw_crypto::thread::MAX_ENTRIES as u64 {
                return Err(Response::error(507, "thread-full"));
            }
            // A friend's entry, written with a write token, is noted in the owner's inbox with its bytes, so the owner's
            // devices learn of it, and read it, with their inbox. Without room there, the entry is stored unnoted.
            let note = token.is_some_and(|t| t.kind == TokenKind::Write)
                .then(|| wire::encode(&wire::InboxEntry {
                    kind: wire::INBOX_THREAD,
                    body: wire::vl(wire::encode(&wire::ThreadNote { thread: *thread, seq, entry: wire::vl(req.body.clone()) })),
                }))
                .filter(|n| {
                    let s = ctx.st();
                    s.inbox_count < cw_crypto::inbox::MAX_ITEMS as u64
                        && s.inbox_bytes + n.len() as u64 <= cw_crypto::inbox::MAX_BYTES as u64
                        && s.used + req.body.len() as u64 + n.len() as u64 <= s.quota
                });
            ctx.charge(req.body.len() as i64)?;
            ctx.exec(
                "INSERT INTO threads (thread, seq, bytes) VALUES (?1, ?2, ?3)",
                &[thread.into(), seq.into(), req.body.clone().into()],
            )?;
            ctx.exec(
                "INSERT INTO thread_heads (thread, next, count) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (thread) DO UPDATE SET next = excluded.next, count = excluded.count",
                &[thread.into(), (seq + 1).into(), (count + 1).into()],
            )?;
            if let Some(note) = note {
                ctx.charge(note.len() as i64)?;
                let at = ctx.st().inbox_seq;
                ctx.exec("INSERT INTO inbox (seq, bytes) VALUES (?1, ?2)", &[at.into(), note.clone().into()])?;
                let s = ctx.stm();
                s.inbox_seq = at + 1;
                s.inbox_count += 1;
                s.inbox_bytes += note.len() as u64;
                ctx.wrote(vec!["inbox_seq", "inbox_count", "inbox_bytes"])?;
                ctx.notify(json!({ "t": "inbox", "seq": at }))?;
            } else {
                ctx.wrote(vec![])?;
                ctx.notify(json!({ "t": "thread", "id": b64::encode(thread), "seq": seq }))?;
            }
            respond(Response::empty(201).with("cw-seq", seq))
        }
        T::GetThread(thread) => {
            ctx.reader(token)?;
            let from = req.query_u64("from").unwrap_or(0);
            let head = ctx.exec("SELECT next FROM thread_heads WHERE thread = ?1", &[thread.into()])?;
            let next = head.first().map_or(0, |r| r[0].u64());
            let rows = ctx.exec(
                "SELECT seq, bytes FROM threads WHERE thread = ?1 AND seq >= ?2 ORDER BY seq LIMIT ?3",
                &[thread.into(), from.into(), LIST_ENTRIES.into()],
            )?;
            respond(entries_response(list(rows), next).tagged(next, req))
        }
        T::DeleteThreadEntry(thread, seq) => {
            ctx.owner(req, token)?;
            let rows = ctx.exec(
                "DELETE FROM threads WHERE thread = ?1 AND seq = ?2 RETURNING length(bytes)",
                &[thread.into(), (*seq).into()],
            )?;
            if let Some(row) = rows.first() {
                ctx.exec("UPDATE thread_heads SET count = count - 1 WHERE thread = ?1", &[thread.into()])?;
                ctx.charge(-row[0].int())?;
                ctx.persist(&["used"])?;
            }
            respond(Response::empty(204))
        }
        T::DeleteThread(thread) => {
            ctx.owner(req, token)?;
            let rows = ctx.exec("DELETE FROM threads WHERE thread = ?1 RETURNING length(bytes)", &[thread.into()])?;
            ctx.exec("DELETE FROM thread_heads WHERE thread = ?1", &[thread.into()])?;
            ctx.charge(-rows.iter().map(|r| r[0].int()).sum::<i64>())?;
            ctx.persist(&["used"])?;
            respond(Response::empty(204))
        }
        T::OpenThread(thread) => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            ctx.exec("INSERT OR IGNORE INTO thread_heads (thread, next, count) VALUES (?1, 0, 0)", &[thread.into()])?;
            respond(Response::empty(204))
        }
        T::GroupTokens => {
            ctx.owner(req, token)?;
            // `to` names the counter to reach, so devices finishing the same rotation advance it once. Allowed under
            // notice, so a group can leave a host that gave notice.
            if let Some(to) = req.query_u64("to") {
                let current = ctx.st().group_counter;
                if to > current + 1 {
                    return Err(malformed());
                }
                if to == current + 1 {
                    ctx.exec(
                        "INSERT INTO group_tokens (id, counter) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET counter = excluded.counter",
                        &[to.into()],
                    )?;
                    ctx.stm().group_counter = to;
                }
            } else if req.query("to").is_some() {
                return Err(malformed());
            }
            let s = ctx.st();
            let (secret, counter) = (&ctx.config.secret, s.group_counter);
            respond(Response::json(
                200,
                json!({
                    "read": token::issue(secret, &s.tenant, counter, TokenKind::GroupRead, 0),
                    "write": token::issue(secret, &s.tenant, counter, TokenKind::GroupWrite, 0),
                    "read_next": token::issue(secret, &s.tenant, counter + 1, TokenKind::GroupRead, 0),
                    "write_next": token::issue(secret, &s.tenant, counter + 1, TokenKind::GroupWrite, 0),
                    "counter": counter,
                }),
            ))
        }
        T::PutAccess(lookup) => {
            ctx.owner(req, token)?;
            // A group's access box, or an audience box.
            let limit = cw_crypto::access::LIMIT;
            wire::decode::<wire::AccessBox>(&req.body, limit, "access box")
                .map(|_| ())
                .or_else(|_| wire::decode::<wire::HpkeBox>(&req.body, limit, "audience box").map(|_| ()))
                .map_err(|e| match e {
                    cw_crypto::Error::TooLarge(_) => Response::error(413, "too-large"),
                    _ => malformed(),
                })?;
            let old = ctx.exec("SELECT length(bytes) FROM access WHERE lookup = ?1", &[lookup.into()])?;
            match old.first() {
                // Under notice a box can still be replaced, so a group can move away.
                Some(_) if ctx.st().state == NOTICE => {}
                _ => ctx.writable()?,
            }
            if old.is_empty()
                && ctx.exec("SELECT COUNT(*) FROM access", &[])?.first().map_or(0, |r| r[0].int()) >= MAX_ACCESS
            {
                return Err(Response::error(507, "access-limit"));
            }
            ctx.charge(req.body.len() as i64 - old.first().map_or(0, |r| r[0].int()))?;
            ctx.exec(
                "INSERT INTO access (lookup, bytes) VALUES (?1, ?2) ON CONFLICT (lookup) DO UPDATE SET bytes = excluded.bytes",
                &[lookup.into(), req.body.clone().into()],
            )?;
            ctx.wrote(vec![])?;
            respond(Response::empty(204))
        }
        T::GetAccess(lookup) => {
            let rows = ctx.exec("SELECT bytes FROM access WHERE lookup = ?1", &[lookup.into()])?;
            let row = rows.first().ok_or_else(|| Response::error(404, "not-found"))?;
            respond(Response::ok(row[0].blob()))
        }
        T::DeleteAccess(lookup) => {
            ctx.owner(req, token)?;
            let rows = ctx.exec("DELETE FROM access WHERE lookup = ?1 RETURNING length(bytes)", &[lookup.into()])?;
            ctx.charge(-rows.iter().map(|r| r[0].int()).sum::<i64>())?;
            ctx.persist(&["used"])?;
            respond(Response::empty(204))
        }
        T::OpenSlot => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            if ctx.st().slots.len() >= MAX_SLOTS {
                return Err(Response::error(507, "slot-limit"));
            }
            let rows = ctx.exec("SELECT next FROM slot_next WHERE id = 1", &[])?;
            let slot = rows.first().map_or(1, |r| r[0].u64());
            ctx.exec(
                "INSERT INTO slot_next (id, next) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET next = excluded.next",
                &[(slot + 1).into()],
            )?;
            ctx.exec("INSERT INTO slots (slot, opened_at, unread) VALUES (?1, ?2, 0)", &[slot.into(), now.into()])?;
            ctx.stm().slots.push(Slot { slot, opened_at: now, unread: 0 });
            let s = ctx.st();
            let token = token::issue(&ctx.config.secret, &s.tenant, slot, TokenKind::Slot, 0);
            respond(Response::json(200, json!({ "slot": slot, "token": token })))
        }
        T::ListSlots => {
            ctx.owner(req, token)?;
            let slots: Vec<Json> = ctx
                .st()
                .slots
                .iter()
                .map(|x| json!({ "slot": x.slot, "opened_at": x.opened_at, "unread": x.unread }))
                .collect();
            respond(Response::json(200, json!({ "slots": slots })))
        }
        T::CloseSlot(slot) => {
            ctx.owner(req, token)?;
            ctx.exec("DELETE FROM slots WHERE slot = ?1", &[(*slot).into()])?;
            ctx.stm().slots.retain(|x| x.slot != *slot);
            respond(Response::empty(204))
        }
        T::PutInvite(lookup) => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            let upload: InviteUpload =
                wire::decode(&req.body, cw_crypto::invite::LIMIT + 64, "invitation").map_err(|_| malformed())?;
            let invitation: wire::Invitation =
                wire::decode(upload.invitation.as_slice(), cw_crypto::invite::LIMIT, "invitation")
                    .map_err(|_| malformed())?;
            if invitation.expires_at <= now || invitation.expires_at > now + INVITE_MS {
                return Err(malformed());
            }
            // Replacing an invitation keeps its redemption, so a re-upload can't re-arm a used link.
            let old =
                ctx.exec("DELETE FROM invites WHERE lookup = ?1 RETURNING length(bytes), release", &[lookup.into()])?;
            ctx.charge(upload.invitation.as_slice().len() as i64 - old.first().map_or(0, |r| r[0].int()))?;
            let release: Value = match old.first() {
                Some(r) if r[1].opt_blob().is_none_or(|b| b.len() != RELEASE) => r[1].clone(),
                _ => (&upload.release).into(),
            };
            ctx.exec(
                "INSERT INTO invites (lookup, expires_at, release, bytes) VALUES (?1, ?2, ?3, ?4)",
                &[lookup.into(), invitation.expires_at.into(), release, upload.invitation.as_slice().into()],
            )?;
            ctx.wrote(vec![])?;
            respond(Response::empty(204))
        }
        T::GetInvite(lookup) | T::RedeemInvite(lookup) => {
            let rows =
                ctx.exec("SELECT expires_at, release, bytes FROM invites WHERE lookup = ?1", &[lookup.into()])?;
            let row = rows.first().filter(|r| r[0].u64() > now).ok_or_else(|| Response::error(404, "not-found"))?;
            if let T::GetInvite(_) = route {
                return respond(Response::ok(row[2].blob()));
            }
            // The release goes to the first claim, and again to that claim alone, so a redeemer whose answer was
            // lost can ask again. The invitation as it is now follows it, since its owner may have replaced it.
            let claim: [u8; RELEASE] = req.body.as_slice().try_into().map_err(|_| malformed())?;
            let stored = row[1].opt_blob().unwrap_or_default();
            let invitation = row[2].blob();
            match stored.len() {
                RELEASE => {
                    let claimed = [&stored[..], &claim[..]].concat();
                    ctx.exec("UPDATE invites SET release = ?2 WHERE lookup = ?1", &[lookup.into(), claimed.into()])?;
                    respond(Response::ok([&stored[..], &invitation[..]].concat()))
                }
                CLAIMED if bool::from(stored[RELEASE..].ct_eq(&claim)) => {
                    respond(Response::ok([&stored[..RELEASE], &invitation[..]].concat()))
                }
                _ => Err(Response::error(410, "gone")),
            }
        }
        T::DeleteInvite(lookup) => {
            ctx.owner(req, token)?;
            let rows = ctx.exec("DELETE FROM invites WHERE lookup = ?1 RETURNING length(bytes)", &[lookup.into()])?;
            ctx.charge(-rows.iter().map(|r| r[0].int()).sum::<i64>())?;
            ctx.persist(&["used"])?;
            respond(Response::empty(204))
        }
        T::PutLink(lookup) => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            wire::decode::<wire::SealedBox>(&req.body, 64 * 1024, "link reply").map_err(|_| malformed())?;
            let old = ctx.exec("DELETE FROM links WHERE lookup = ?1 RETURNING length(bytes)", &[lookup.into()])?;
            ctx.charge(req.body.len() as i64 - old.first().map_or(0, |r| r[0].int()))?;
            ctx.exec(
                "INSERT INTO links (lookup, expires_at, bytes) VALUES (?1, ?2, ?3)",
                &[lookup.into(), (now + LINK_MS).into(), req.body.clone().into()],
            )?;
            ctx.wrote(vec![])?;
            respond(Response::empty(204))
        }
        T::GetLink(lookup) => {
            let rows = ctx.exec("DELETE FROM links WHERE lookup = ?1 RETURNING expires_at, bytes", &[lookup.into()])?;
            let row = rows.first().ok_or_else(|| Response::error(404, "not-found"))?;
            ctx.charge(-(row[1].blob().len() as i64))?;
            ctx.persist(&["used"])?;
            if row[0].u64() <= now {
                return respond(Response::error(404, "not-found"));
            }
            respond(Response::ok(row[1].blob()))
        }
        T::PostGuest => {
            ctx.owner(req, token)?;
            if !(ctx.st().limits.guests && ctx.st().state == ACTIVE) {
                return Err(Response::error(403, "forbidden"));
            }
            let body: Json = serde_json::from_slice(&req.body).map_err(|_| malformed())?;
            let expires_at =
                body["expires_at"].as_u64().filter(|e| *e > now && *e <= now + INVITE_MS).ok_or_else(malformed)?;
            Ok(Outcome::Host(HostInternal::GuestOffer { sponsor: ctx.tenant, expires_at }))
        }
        T::DeleteGuest(offer) => {
            ctx.owner(req, token)?;
            Ok(Outcome::Host(HostInternal::WithdrawGuestOffer { sponsor: ctx.tenant, offer: *offer }))
        }
        T::PutSubscription => {
            let device = ctx.owner(req, token)?;
            let body: Json = serde_json::from_slice(&req.body).map_err(|_| malformed())?;
            let endpoint = body["endpoint"].as_str().filter(|e| push::valid_endpoint(e)).ok_or_else(malformed)?;
            ctx.exec(
                "INSERT INTO subscriptions (device, endpoint, last_push) VALUES (?1, ?2, 0) \
                 ON CONFLICT (device) DO UPDATE SET endpoint = excluded.endpoint, last_push = 0",
                &[(&device).into(), endpoint.into()],
            )?;
            respond(Response::empty(204))
        }
        T::DeleteSubscription => {
            let device = ctx.owner(req, token)?;
            ctx.exec("DELETE FROM subscriptions WHERE device = ?1", &[(&device).into()])?;
            respond(Response::empty(204))
        }
        T::Socket => {
            let token = token.as_ref().ok_or_else(|| Response::error(401, "unauthorized"))?;
            ctx.token_current(token)?;
            let protocol = crate::gate::socket_protocol(req).ok_or_else(|| Response::error(401, "unauthorized"))?;
            let tenant = b64::encode(&ctx.tenant);
            let card = &ctx.st().card;
            let (_, signer) =
                cw_crypto::request::verify_socket(&protocol, &req.authority, &tenant, now, |id| card.device_key(id))
                    .map_err(|e| match e {
                        cw_crypto::Error::WrongSigner => Response::error(403, "forbidden"),
                        _ => Response::error(401, "unauthorized"),
                    })?;
            auth::nonce(ctx.store, &signer, now)?;
            // At most one write per device per day.
            ctx.exec(
                "INSERT INTO seen (device, day) VALUES (?1, ?2) ON CONFLICT (device) DO UPDATE SET day = excluded.day WHERE day < excluded.day",
                &[(&signer.key).into(), (now / DAY_MS).into()],
            )?;
            Ok(Outcome::Accept { device: signer.key, state: socket_state(ctx)? })
        }
        T::Export => {
            let grant = req.header("cw-grant").ok_or_else(|| Response::error(401, "unauthorized"))?.to_string();
            grant_check(ctx, &grant)?;
            respond(Response::ok(export(ctx)?))
        }
        T::Import => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            let body: Json = serde_json::from_slice(&req.body).map_err(|_| malformed())?;
            let from = body["from"].as_str().ok_or_else(malformed)?.to_string();
            let grant = body["grant"].as_str().ok_or_else(malformed)?.to_string();
            let old_tenant = cw_crypto::card::tenant_url(&from).map_err(|_| malformed())?;
            let bytes = b64::decode(&grant).map_err(|_| malformed())?;
            let own_url = ctx.config.tenant_url(&ctx.tenant);
            cw_crypto::transfer::check(&bytes, &ctx.st().card, &old_tenant, &own_url, now)
                .map_err(|_| Response::error(403, "forbidden"))?;
            Ok(Outcome::Import { from, grant })
        }
        T::Restore => {
            ctx.owner(req, token)?;
            ctx.writable()?;
            // Only an empty tenant takes a profile rebuilt from a device.
            let has_head = !ctx.exec("SELECT 1 FROM tenant WHERE id = 1 AND head IS NOT NULL", &[])?.is_empty();
            let s = ctx.st();
            if s.log_next > 0 || has_head {
                return Err(Response::error(409, "conflict"));
            }
            let export: Export = wire::decode(&req.body, 512 * 1024 * 1024, "export").map_err(|_| malformed())?;
            apply_export(ctx, &export)?;
            respond(Response::empty(204))
        }
        T::Batch => {
            let signer = ctx.owner(req, token)?;
            let batch: wire::Batch = wire::decode(&req.body, BATCH_BYTES, "batch").map_err(|e| match e {
                cw_crypto::Error::TooLarge(_) => Response::error(413, "too-large"),
                _ => malformed(),
            })?;
            if batch.requests.is_empty() || batch.requests.len() > BATCH_REQUESTS {
                return Err(malformed());
            }
            ctx.memory.batch = Some(BatchRun { signer, columns: Vec::new() });
            let mut answers = wire::BatchAnswers::default();
            for (index, request) in batch.requests.iter().enumerate() {
                let answer = batched(ctx, token, req, request).map_err(|r| r.with("cw-index", index))?;
                answers.answers.push(answer);
            }
            let columns = ctx.memory.batch.take().map(|b| b.columns).unwrap_or_default();
            if !columns.is_empty() {
                ctx.persist(&columns)?;
            }
            respond(Response::ok(wire::encode(&answers)))
        }
    }
}

/// The most a batch carries: as many bytes as `commonwire` takes in one request body, and 100 requests.
const BATCH_BYTES: usize = 24 * 1024 * 1024;
const BATCH_REQUESTS: usize = 100;

/// Runs one request of a batch as the batch's signer, with the batch's owner token.
fn batched<S: Store, Rn: RngCore + CryptoRng>(
    ctx: &mut Ctx<S, Rn>,
    token: &Option<Checked>,
    outer: &Request,
    request: &wire::BatchRequest,
) -> R<wire::BatchAnswer> {
    let method = std::str::from_utf8(request.method.as_slice()).map_err(|_| malformed())?;
    let path = std::str::from_utf8(request.path.as_slice()).map_err(|_| malformed())?;
    if !path.starts_with('/') {
        return Err(malformed());
    }
    let mut sub = Request {
        method: method.to_string(),
        authority: outer.authority.clone(),
        target: format!("/t/{}{path}", b64::encode(&ctx.tenant)),
        headers: Vec::new(),
        body: request.body.as_slice().to_vec(),
        received: outer.received,
    };
    if let Some(m) = request.if_match {
        sub.headers.push(("if-match".into(), m.to_string()));
    }
    let route = match crate::route::route(method, sub.path()) {
        Some(Route::Tenant(t, r)) if t == ctx.tenant => r,
        _ => return Err(Response::error(404, "not-found")),
    };
    if !batchable(&route) {
        return Err(malformed());
    }
    let Outcome::Respond(answer) = run(ctx, &route, token, &sub)? else { return Err(malformed()) };
    let value = ["cw-epoch", "cw-seq", "cw-current"]
        .iter()
        .find_map(|h| answer.header(h).and_then(|v| v.parse::<u64>().ok()))
        .unwrap_or(0);
    Ok(wire::BatchAnswer { status: answer.status, value, body: wire::vl(answer.body) })
}

/// What a batch may carry: every owner request but removing the tenant, transfers, guest offers and the push socket,
/// and the card, tokens, head, object and thread requests a device makes of its own tenant.
fn batchable(route: &T) -> bool {
    use crate::route::{class, Class};
    match route {
        T::Batch | T::Remove | T::Import | T::Restore | T::PostGuest | T::DeleteGuest(_) => false,
        T::PutCard | T::Tokens | T::GetHead | T::GetObject(_) | T::GetThread(_) | T::PostThread(_) => true,
        r => class(&Route::Tenant([0; 16], r.clone())) == Class::Owner,
    }
}

fn grant_check<S: Store, Rn: RngCore + CryptoRng>(ctx: &mut Ctx<S, Rn>, grant: &str) -> R<String> {
    let bytes = b64::decode(grant).map_err(|_| Response::error(401, "unauthorized"))?;
    cw_crypto::transfer::open(&bytes, &ctx.st().card, &ctx.tenant, ctx.now)
        .map_err(|_| Response::error(401, "unauthorized"))
}

fn list(rows: Vec<Vec<Value>>) -> Entries {
    let mut out = Entries::default();
    let mut bytes = 0usize;
    for r in rows {
        let b = r[1].blob();
        bytes += b.len();
        if bytes > LIST_BYTES && !out.entries.is_empty() {
            break;
        }
        out.push(r[0].u64(), b);
    }
    out
}

fn all(rows: Vec<Vec<Value>>) -> Entries {
    let mut out = Entries::default();
    for r in rows {
        out.push(r[0].u64(), r[1].blob());
    }
    out
}

fn export<S: Store, Rn: RngCore + CryptoRng>(ctx: &mut Ctx<S, Rn>) -> R<Vec<u8>> {
    let single = ctx.exec("SELECT head, snapshot, passkey, keyring FROM tenant WHERE id = 1", &[])?;
    let s = &single[0];
    let mut threads = Entries::default();
    for r in ctx.exec("SELECT thread, seq, bytes FROM threads ORDER BY thread, seq", &[])? {
        let thread = r[0].array::<16>().ok_or_else(|| Response::error(500, "storage: thread"))?;
        threads.push(r[1].u64(), wire::encode(&ThreadExport { thread, entry: wire::vl(r[2].blob()) }));
    }
    let mut invites = Entries::default();
    for r in ctx.exec("SELECT lookup, expires_at, release, bytes FROM invites", &[])? {
        let lookup = r[0].array::<16>().ok_or_else(|| Response::error(500, "storage: invite"))?;
        invites.push(
            r[1].u64(),
            wire::encode(&InviteExport {
                lookup,
                invitation: wire::vl(r[3].blob()),
                release: wire::vl(r[2].opt_blob().unwrap_or_default()),
            }),
        );
    }
    let mut objects = Entries::default();
    for r in ctx.exec("SELECT name, size FROM objects ORDER BY name", &[])? {
        objects.push(r[1].u64(), r[0].blob());
    }
    let export = Export {
        card: wire::vl(ctx.st().card_bytes.clone()),
        head: wire::vl(s[0].opt_blob().unwrap_or_default()),
        log: all(ctx.exec("SELECT seq, bytes FROM log ORDER BY seq", &[])?),
        snapshot: wire::vl(s[1].opt_blob().unwrap_or_default()),
        owner_keys: all(ctx.exec("SELECT generation, bytes FROM owner_keys ORDER BY generation", &[])?),
        passkey: wire::vl(s[2].opt_blob().unwrap_or_default()),
        keyring: wire::vl(s[3].opt_blob().unwrap_or_default()),
        inbox: all(ctx.exec("SELECT seq, bytes FROM inbox ORDER BY seq", &[])?),
        threads,
        invites,
        objects,
        group_counter: ctx.st().group_counter,
        device_keys: all(ctx.exec("SELECT created_at, bytes FROM device_keys ORDER BY created_at", &[])?),
    };
    Ok(wire::encode(&export))
}

/// Applies an export from the old host. Returns the names of the objects to fetch.
pub fn import_export<S: Store, Rn: RngCore + CryptoRng>(
    ctx: &mut Ctx<S, Rn>,
    bytes: &[u8],
) -> (Result<Vec<String>, Response>, bool) {
    let result = (|| {
        ctx.state()?;
        let export: Export = wire::decode(bytes, 512 * 1024 * 1024, "export").map_err(|_| malformed())?;
        apply_export(ctx, &export)
    })();
    match result {
        Ok(missing) => (Ok(missing), true),
        Err(response) => {
            ctx.memory.forget();
            (Err(response), false)
        }
    }
}

/// Stores an export: from the old host on `POST /import`, or built by a device on `POST /restore`. Returns the
/// objects it names that this host doesn't hold.
fn apply_export<S: Store, Rn: RngCore + CryptoRng>(ctx: &mut Ctx<S, Rn>, export: &Export) -> R<Vec<String>> {
    {
        let card = export.card.as_slice();
        let theirs = Card::open(card, None).map_err(|_| malformed())?;
        if theirs.profile != ctx.st().card.profile {
            return Err(Response::error(403, "forbidden"));
        }
        let mut size = 0i64;
        if Card::supersedes(&ctx.st().card_bytes, card).unwrap_or(false) {
            size += card.len() as i64 - ctx.st().card_bytes.len() as i64;
            let s = ctx.stm();
            s.card = theirs;
            s.card_bytes = card.to_vec();
        }
        let opt = |b: &[u8]| if b.is_empty() { Value::Null } else { Value::Blob(b.to_vec()) };
        if !export.head.as_slice().is_empty() {
            // Devices verify what they read; the host only checks the structures it keeps positions from.
            let head = sign::Unverified::decode(export.head.as_slice(), Kind::Head, 4096).map_err(|_| malformed())?;
            let body: wire::HeadBody = wire::decode(&head.body, 4096, "head").map_err(|_| malformed())?;
            ctx.stm().head_revision = body.revision;
        }
        if !export.snapshot.as_slice().is_empty() {
            let snap =
                sign::Unverified::decode(export.snapshot.as_slice(), Kind::Snapshot, 4096).map_err(|_| malformed())?;
            let body: wire::SnapshotBody = wire::decode(&snap.body, 4096, "snapshot").map_err(|_| malformed())?;
            let s = ctx.stm();
            s.snapshot_seq = body.seq;
            // Without log entries, the log continues after the entry the snapshot names.
            if export.log.entries.is_empty() {
                s.log_next = body.seq + 1;
                s.log_tail = body.previous;
            }
        }
        if !export.keyring.as_slice().is_empty() {
            wire::decode::<wire::KeyringBox>(export.keyring.as_slice(), 4096, "keyring").map_err(|_| malformed())?;
            ctx.next_keyring_revision()?;
        }
        ctx.memory.head = None;
        ctx.exec(
            "UPDATE tenant SET head = ?1, snapshot = ?2, passkey = ?3, keyring = ?4 WHERE id = 1",
            &[
                opt(export.head.as_slice()),
                opt(export.snapshot.as_slice()),
                opt(export.passkey.as_slice()),
                opt(export.keyring.as_slice()),
            ],
        )?;
        size += (export.head.as_slice().len()
            + export.snapshot.as_slice().len()
            + export.passkey.as_slice().len()
            + export.keyring.as_slice().len()) as i64;
        let mut tail = [0u8; 32];
        let mut next = 0;
        for e in &export.log.entries {
            ctx.exec(
                "INSERT OR REPLACE INTO log (seq, bytes) VALUES (?1, ?2)",
                &[e.position.into(), e.bytes.as_slice().into()],
            )?;
            size += e.bytes.as_slice().len() as i64;
            next = e.position + 1;
            tail = cw_crypto::log::digest(e.bytes.as_slice());
        }
        if next > 0 {
            let s = ctx.stm();
            s.log_next = next;
            s.log_tail = tail;
        }
        for e in &export.owner_keys.entries {
            let limit = cw_crypto::log::KEY_LIMIT;
            let key = sign::Unverified::decode(e.bytes.as_slice(), Kind::OwnerKey, limit).map_err(|_| malformed())?;
            let body: wire::OwnerKeyBody = wire::decode(&key.body, limit, "owner key").map_err(|_| malformed())?;
            ctx.exec(
                "INSERT OR REPLACE INTO owner_keys (generation, bytes) VALUES (?1, ?2)",
                &[body.generation.into(), e.bytes.as_slice().into()],
            )?;
            size += e.bytes.as_slice().len() as i64;
        }
        // Devices' inbox keys come along, so senders who read them from this host find them at once.
        for e in &export.device_keys.entries {
            let Ok(key) = cw_crypto::devicekey::open(e.bytes.as_slice(), &ctx.st().card.clone()) else { continue };
            ctx.exec(
                "INSERT INTO device_keys (device, created_at, bytes) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (device) DO UPDATE SET created_at = excluded.created_at, bytes = excluded.bytes \
                 WHERE excluded.created_at > device_keys.created_at",
                &[(&key.device).into(), key.created_at.into(), e.bytes.as_slice().into()],
            )?;
            size += e.bytes.as_slice().len() as i64;
        }
        let (mut count, mut inbox_bytes, mut inbox_next) = (0u64, 0u64, 0u64);
        for e in &export.inbox.entries {
            ctx.exec(
                "INSERT OR REPLACE INTO inbox (seq, bytes) VALUES (?1, ?2)",
                &[e.position.into(), e.bytes.as_slice().into()],
            )?;
            count += 1;
            inbox_bytes += e.bytes.as_slice().len() as u64;
            inbox_next = e.position + 1;
        }
        size += inbox_bytes as i64;
        let s = ctx.stm();
        s.inbox_count = count;
        s.inbox_bytes = inbox_bytes;
        s.inbox_seq = s.inbox_seq.max(inbox_next);
        let mut heads: std::collections::HashMap<[u8; 16], (u64, u64)> = Default::default();
        for e in &export.threads.entries {
            let t: ThreadExport =
                wire::decode(e.bytes.as_slice(), 64 * 1024, "thread entry").map_err(|_| malformed())?;
            ctx.exec(
                "INSERT OR REPLACE INTO threads (thread, seq, bytes) VALUES (?1, ?2, ?3)",
                &[(&t.thread).into(), e.position.into(), t.entry.as_slice().into()],
            )?;
            size += t.entry.as_slice().len() as i64;
            let h = heads.entry(t.thread).or_default();
            *h = (h.0.max(e.position + 1), h.1 + 1);
        }
        if export.group_counter > ctx.st().group_counter {
            ctx.exec(
                "INSERT INTO group_tokens (id, counter) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET counter = excluded.counter",
                &[export.group_counter.into()],
            )?;
            ctx.stm().group_counter = export.group_counter;
        }
        for (thread, (next, count)) in heads {
            ctx.exec(
                "INSERT OR REPLACE INTO thread_heads (thread, next, count) VALUES (?1, ?2, ?3)",
                &[(&thread).into(), next.into(), count.into()],
            )?;
        }
        for e in &export.invites.entries {
            let i: InviteExport =
                wire::decode(e.bytes.as_slice(), 128 * 1024, "invitation").map_err(|_| malformed())?;
            let release = match i.release.as_slice().len() {
                0 => Value::Null,
                RELEASE | CLAIMED => i.release.as_slice().into(),
                _ => return Err(malformed()),
            };
            ctx.exec(
                "INSERT OR REPLACE INTO invites (lookup, expires_at, release, bytes) VALUES (?1, ?2, ?3, ?4)",
                &[(&i.lookup).into(), e.position.into(), release, i.invitation.as_slice().into()],
            )?;
            size += i.invitation.as_slice().len() as i64;
        }
        ctx.charge(size)?;
        ctx.wrote(vec![
            "card",
            "head_revision",
            "snapshot_seq",
            "log_next",
            "log_tail",
            "inbox_seq",
            "inbox_count",
            "inbox_bytes",
        ])?;
        let mut missing = Vec::new();
        for e in &export.objects.entries {
            let name = std::str::from_utf8(e.bytes.as_slice()).map_err(|_| malformed())?;
            object::parse_name(name).map_err(|_| malformed())?;
            if ctx.exec("SELECT 1 FROM objects WHERE name = ?1", &[name.into()])?.is_empty() {
                missing.push(name.to_string());
            }
        }
        Ok(missing)
    }
}

/// Stores one object pulled from the old host.
pub fn import_object<S: Store, Rn: RngCore + CryptoRng>(
    ctx: &mut Ctx<S, Rn>,
    name: &str,
    bytes: &[u8],
) -> (Result<(), Response>, bool) {
    let result = (|| {
        ctx.state()?;
        let digest = object::parse_name(name).map_err(|_| malformed())?;
        if kdf::sha256(bytes) != digest {
            return Err(malformed());
        }
        if !ctx.exec("SELECT 1 FROM objects WHERE name = ?1", &[name.into()])?.is_empty() {
            return Ok(());
        }
        ctx.charge(bytes.len() as i64)?;
        ctx.exec(
            "INSERT INTO objects (name, size, created_at) VALUES (?1, ?2, ?3)",
            &[name.into(), bytes.len().into(), ctx.now.into()],
        )?;
        ctx.store.blob_put(name, bytes).map_err(st)?;
        ctx.wrote(vec![])
    })();
    let ok = result.is_ok();
    if !ok {
        ctx.memory.forget();
    }
    (result, ok)
}

/// Runs an operation the host or runtime starts. The bool says whether to commit.
pub fn internal<S: Store, Rn: RngCore + CryptoRng>(ctx: &mut Ctx<S, Rn>, op: &Internal) -> (Response, bool) {
    let result = (|| match op {
        Internal::Init { card, quota, guest, limits } => {
            if ctx.load()?.is_some() {
                return Err(Response::error(409, "conflict"));
            }
            Card::open(card, None).map_err(|_| malformed())?;
            let until = if *guest { ctx.now + GUEST_MS } else { 0 };
            let values: Vec<Value> = vec![
                (&ctx.tenant).into(),
                ctx.now.into(),
                (*quota).into(),
                card.len().into(),
                (if *guest { GUEST } else { ACTIVE }).into(),
                until.into(),
                card.clone().into(),
                (&[0u8; 32]).into(),
            ];
            ctx.exec(
                "INSERT INTO tenant (id, tenant, created_at, quota, used, state, notice_until, removed_at, \
                 audience_counter, requests_day, requests, last_write, card, head_revision, snapshot_seq, \
                 inbox_seq, inbox_count, inbox_bytes, log_next, log_tail, last_maintenance) \
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 0, 0, 0, ?7, 0, 0, 0, 0, 0, 0, ?8, 0)",
                &values,
            )?;
            ctx.state()?;
            ctx.set_limits(*limits)?;
            if *guest {
                ctx.effects.push(Effect::Alarm(until));
            }
            let url = ctx.config.tenant_url(&ctx.tenant);
            // The tokens of the card's first device, so the device that made the tenant writes to it at once.
            let tokens = ctx.st().card.devices.first().map(|d| tokens_json(ctx, &d.device));
            Ok(Response::json(200, json!({ "tenant": b64::encode(&ctx.tenant), "url": url, "tokens": tokens })))
        }
        Internal::Usage => {
            let Some(s) = ctx.load()?.cloned() else {
                return Ok(Response::json(200, json!({ "tenant": b64::encode(&ctx.tenant), "state": "gone" })));
            };
            let requests = ctx.requests_today();
            Ok(Response::json(
                200,
                json!({
                    "tenant": b64::encode(&s.tenant),
                    "created_at": s.created_at,
                    "quota": s.quota,
                    "used": s.used,
                    "requests_today": requests,
                    "budget": s.budget(),
                    "budget_override": s.budget_override,
                    "last_write": s.last_write,
                    "state": if s.state == REMOVED && ctx.now >= s.removed_at + FORWARD_MS { "gone" } else { s.state_name() },
                    "notice_until": s.notice_until,
                }),
            ))
        }
        Internal::Quota(quota) => {
            ctx.state()?;
            ctx.stm().quota = *quota;
            ctx.persist(&["quota"])?;
            Ok(Response::empty(204))
        }
        Internal::Notice(until) => {
            ctx.state()?;
            if !matches!(ctx.st().state, ACTIVE | GUEST) {
                return Err(Response::error(409, "conflict"));
            }
            let s = ctx.stm();
            s.state = NOTICE;
            s.notice_until = *until;
            ctx.persist(&["state", "notice_until"])?;
            ctx.event(json!({ "t": "status" }));
            ctx.effects.push(Effect::Alarm(*until));
            Ok(Response::empty(204))
        }
        Internal::Remove => {
            ctx.state()?;
            if ctx.st().state != REMOVED {
                ctx.remove()?;
            }
            Ok(Response::empty(204))
        }
        Internal::Destroy => {
            ctx.state()?;
            if ctx.st().state != REMOVED {
                ctx.remove()?;
            }
            Ok(Response::empty(204))
        }
        Internal::DropSubscription(device) => {
            ctx.state()?;
            ctx.exec("DELETE FROM subscriptions WHERE device = ?1", &[device.into()])?;
            Ok(Response::empty(204))
        }
        Internal::Limits(limits) => {
            ctx.state()?;
            ctx.set_limits(*limits)?;
            ctx.event(json!({ "t": "status" }));
            Ok(Response::empty(204))
        }
        Internal::Budget(budget) => {
            ctx.state()?;
            if ctx.st().state == REMOVED {
                return Err(Response::error(410, "gone"));
            }
            match budget {
                Some(b) => ctx.exec(
                    "INSERT INTO budget_override (id, budget) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET budget = excluded.budget",
                    &[(*b).into()],
                )?,
                None => ctx.exec("DELETE FROM budget_override WHERE id = 1", &[])?,
            };
            ctx.stm().budget_override = *budget;
            Ok(Response::empty(204))
        }
        Internal::Approve { quota, limits } => {
            ctx.state()?;
            if ctx.st().state == REMOVED {
                return Err(Response::error(410, "gone"));
            }
            let s = ctx.stm();
            s.state = ACTIVE;
            s.notice_until = 0;
            s.quota = *quota;
            ctx.persist(&["state", "notice_until", "quota"])?;
            ctx.set_limits(*limits)?;
            ctx.event(json!({ "t": "status" }));
            Ok(Response::empty(204))
        }
        Internal::Alarm => {
            if ctx.load()?.is_some() {
                ctx.maintain()?;
                if let Some(s) = ctx.memory.state.as_ref().filter(|s| matches!(s.state, NOTICE | GUEST)) {
                    let until = s.notice_until;
                    ctx.effects.push(Effect::Alarm(until));
                }
            }
            Ok(Response::empty(204))
        }
    })();
    match result {
        Ok(r) => (r, true),
        Err(r) => {
            ctx.memory.forget();
            ctx.effects.clear();
            (r, false)
        }
    }
}

/// The JSON answer to `POST /import` once every object is in.
pub fn import_done(objects: usize, bytes: u64) -> Response {
    Response::json(200, json!({ "objects": objects, "bytes": bytes }))
}
