//! Host-level requests: claim, hosting offers and administration. Work on a tenant's data is handed to that
//! tenant's store as an internal operation, which the runtime runs and answers with.
use cw_crypto::b64;
use cw_crypto::card::Card;
use cw_crypto::token::{self, TokenKind};
use rand::{CryptoRng, RngCore};
use serde_json::{json, Value as Json};

use crate::gate::Gated;
use crate::http::{Request, Response};
use crate::route::{HostRoute, Route};
use crate::sql::Store;
use crate::{auth, Config, DAY_MS, GUEST_BUDGET, GUEST_LIMIT, GUEST_MS, GUEST_NOTICE_MS, MEMBER_BUDGET, SPONSOR_LIMIT};

/// An offer's places: the row in `offer_places`, or 1 without one.
const PLACES: &str = "COALESCE((SELECT places FROM offer_places WHERE offer_places.id = offers.id), 1)";
/// The most tenants one offer makes.
const MAX_PLACES: u64 = 1_000;

/// What the host's settings give a tenant: whether members may make guest offers, and the daily budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub guests: bool,
    pub budget: u64,
}

/// An operation on a tenant's store that only the host or the runtime starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Internal {
    /// Creates the tenant; a guest gets the guest quota and its 30 days.
    Init { card: Vec<u8>, quota: u64, guest: bool, limits: Limits },
    Usage,
    Quota(u64),
    Notice(u64),
    Remove,
    DropSubscription([u8; 32]),
    Alarm,
    Limits(Limits),
    /// A guest becomes a member.
    Approve { quota: u64, limits: Limits },
    /// The admin's daily budget for this tenant, or none to follow the host setting.
    Budget(Option<u64>),
    /// The host is being destroyed: the tenant deletes everything it holds, and the runtime then deletes its storage.
    Destroy,
}

fn limits_json(l: &Limits) -> Json {
    json!({ "guests": l.guests, "budget": l.budget })
}

fn limits_of(v: &Json) -> Option<Limits> {
    Some(Limits { guests: v["guests"].as_bool()?, budget: v["budget"].as_u64()? })
}

impl Internal {
    /// The form an internal operation travels in between the Worker's Durable Objects.
    pub fn to_json(&self) -> Json {
        match self {
            Internal::Init { card, quota, guest, limits } => json!({
                "op": "init", "card": b64::encode(card), "quota": quota, "guest": guest, "limits": limits_json(limits),
            }),
            Internal::Usage => json!({ "op": "usage" }),
            Internal::Quota(q) => json!({ "op": "quota", "quota": q }),
            Internal::Notice(until) => json!({ "op": "notice", "until": until }),
            Internal::Remove => json!({ "op": "remove" }),
            Internal::DropSubscription(d) => json!({ "op": "drop-subscription", "device": b64::encode(d) }),
            Internal::Alarm => json!({ "op": "alarm" }),
            Internal::Limits(l) => json!({ "op": "limits", "limits": limits_json(l) }),
            Internal::Approve { quota, limits } => json!({ "op": "approve", "quota": quota, "limits": limits_json(limits) }),
            Internal::Budget(b) => json!({ "op": "budget", "budget": b }),
            Internal::Destroy => json!({ "op": "destroy" }),
        }
    }

    pub fn from_json(v: &Json) -> Option<Internal> {
        Some(match v["op"].as_str()? {
            "init" => Internal::Init {
                card: b64::decode(v["card"].as_str()?).ok()?,
                quota: v["quota"].as_u64()?,
                guest: v["guest"].as_bool()?,
                limits: limits_of(&v["limits"])?,
            },
            "usage" => Internal::Usage,
            "quota" => Internal::Quota(v["quota"].as_u64()?),
            "notice" => Internal::Notice(v["until"].as_u64()?),
            "remove" => Internal::Remove,
            "drop-subscription" => Internal::DropSubscription(b64::decode_array(v["device"].as_str()?).ok()?),
            "alarm" => Internal::Alarm,
            "limits" => Internal::Limits(limits_of(&v["limits"])?),
            "approve" => Internal::Approve { quota: v["quota"].as_u64()?, limits: limits_of(&v["limits"])? },
            "destroy" => Internal::Destroy,
            "budget" => Internal::Budget(match &v["budget"] {
                Json::Null => None,
                b => Some(b.as_u64()?),
            }),
            _ => return None,
        })
    }
}

/// An operation on the host's store that a tenant starts, after checking its owner's request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostInternal {
    GuestOffer { sponsor: [u8; 16], expires_at: u64 },
    WithdrawGuestOffer { sponsor: [u8; 16], offer: [u8; 16] },
}

impl HostInternal {
    pub fn to_json(&self) -> Json {
        match self {
            HostInternal::GuestOffer { sponsor, expires_at } => {
                json!({ "op": "guest-offer", "sponsor": b64::encode(sponsor), "expires_at": expires_at })
            }
            HostInternal::WithdrawGuestOffer { sponsor, offer } => {
                json!({ "op": "withdraw-guest-offer", "sponsor": b64::encode(sponsor), "offer": b64::encode(offer) })
            }
        }
    }

    pub fn from_json(v: &Json) -> Option<HostInternal> {
        let sponsor = b64::decode_array(v["sponsor"].as_str()?).ok()?;
        Some(match v["op"].as_str()? {
            "guest-offer" => HostInternal::GuestOffer { sponsor, expires_at: v["expires_at"].as_u64()? },
            "withdraw-guest-offer" => {
                HostInternal::WithdrawGuestOffer { sponsor, offer: b64::decode_array(v["offer"].as_str()?).ok()? }
            }
            _ => return None,
        })
    }
}

/// How the host answers once every tenant ran its operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finish {
    /// `GET /admin/tenants`, from each tenant's `Usage`.
    List,
    /// `PUT /admin/settings`, with the settings stored.
    Settings,
    /// `DELETE /admin/host`, once every tenant deleted what it held.
    Destroy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Respond(Response),
    /// Run the operation on the tenant's store and answer with its response.
    Tenant([u8; 16], Internal),
    /// Run each operation on its tenant's store, then call `finish` with the responses.
    Each(Vec<([u8; 16], Internal)>, Finish),
}

/// The admin's settings (docs/hosts.md, "Guests and budgets").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub guests: bool,
    pub guest_limit: u64,
    pub member_budget: u64,
    pub guest_budget: u64,
}

impl Settings {
    fn load(store: &mut impl Store) -> Result<Settings, Response> {
        let rows = store
            .exec("SELECT guests, guest_limit, member_budget, guest_budget FROM settings WHERE id = 1", &[])
            .map_err(storage)?;
        Ok(rows.first().map_or(
            Settings {
                guests: false,
                guest_limit: GUEST_LIMIT,
                member_budget: MEMBER_BUDGET,
                guest_budget: GUEST_BUDGET,
            },
            |r| Settings { guests: r[0].int() != 0, guest_limit: r[1].u64(), member_budget: r[2].u64(), guest_budget: r[3].u64() },
        ))
    }

    fn json(&self) -> Json {
        json!({
            "guests": self.guests,
            "guest_limit": self.guest_limit,
            "member_budget": self.member_budget,
            "guest_budget": self.guest_budget,
        })
    }

    fn member(&self) -> Limits {
        Limits { guests: self.guests, budget: self.member_budget }
    }

    fn guest(&self) -> Limits {
        Limits { guests: self.guests, budget: self.guest_budget }
    }
}

fn is_guest(store: &mut impl Store, tenant: &[u8; 16]) -> Result<bool, Response> {
    Ok(!store.exec("SELECT 1 FROM guests WHERE tenant = ?1", &[tenant.into()]).map_err(storage)?.is_empty())
}

fn count(store: &mut impl Store, sql: &str, params: &[crate::sql::Value]) -> Result<i64, Response> {
    Ok(store.exec(sql, params).map_err(storage)?.first().map_or(0, |r| r[0].int()))
}

/// Unused guest offers and guests that count toward the host's guest limit.
fn guests_held(store: &mut impl Store, now: u64) -> Result<i64, Response> {
    Ok(count(store, "SELECT COUNT(*) FROM guest_offers WHERE expires_at > ?1", &[now.into()])?
        + count(
            store,
            "SELECT COUNT(*) FROM guests WHERE joined_at > ?1",
            &[now.saturating_sub(GUEST_MS + GUEST_NOTICE_MS).into()],
        )?)
}

pub struct Ctx<'a, S: Store, R: RngCore + CryptoRng> {
    pub store: &'a mut S,
    pub config: &'a Config,
    pub now: u64,
    pub rng: &'a mut R,
}

/// Creates the host store's tables.
pub fn ensure(store: &mut impl Store) -> crate::sql::StoreResult<()> {
    crate::schema::create(store, crate::schema::HOST)
}

fn storage(e: crate::sql::StoreError) -> Response {
    Response::error(500, &format!("storage: {e}"))
}

fn destroyed(store: &mut impl Store) -> Result<bool, Response> {
    Ok(!store.exec("SELECT 1 FROM destroyed WHERE id = 1", &[]).map_err(storage)?.is_empty())
}

/// The admin public key stored at claim.
fn admin_key(store: &mut impl Store) -> Result<Option<cw_crypto::sign::Public>, Response> {
    let rows = store.exec("SELECT admin FROM host WHERE id = 1", &[]).map_err(storage)?;
    Ok(rows.first().and_then(|r| r[0].array::<{ cw_crypto::sign::PUBLIC }>()))
}

fn json_body(req: &Request) -> Result<Json, Response> {
    if req.body.len() > 64 * 1024 {
        return Err(Response::error(413, "too-large"));
    }
    serde_json::from_slice(&req.body).map_err(|_| Response::error(400, "malformed"))
}

fn card_of(text: Option<&str>) -> Result<Vec<u8>, Response> {
    let bytes = text.and_then(|t| b64::decode(t).ok()).ok_or_else(|| Response::error(400, "malformed"))?;
    Card::open(&bytes, None).map_err(|_| Response::error(400, "malformed"))?;
    Ok(bytes)
}

fn registered(store: &mut impl Store, tenant: &[u8; 16]) -> Result<bool, Response> {
    Ok(!store.exec("SELECT 1 FROM tenants WHERE id = ?1", &[tenant.into()]).map_err(storage)?.is_empty())
}

fn new_tenant<S: Store, R: RngCore + CryptoRng>(ctx: &mut Ctx<S, R>) -> Result<[u8; 16], Response> {
    let tenant = token::new_tenant(&ctx.config.secret, ctx.rng);
    ctx.store
        .exec("INSERT INTO tenants (id, created_at) VALUES (?1, ?2)", &[(&tenant).into(), ctx.now.into()])
        .map_err(storage)?;
    Ok(tenant)
}

/// Handles a host request. The bool says whether to commit the store's transaction.
pub fn handle<S: Store, R: RngCore + CryptoRng>(ctx: &mut Ctx<S, R>, gated: &Gated, req: &Request) -> (Outcome, bool) {
    match run(ctx, gated, req) {
        Ok(outcome) => (outcome, true),
        Err(response) => (Outcome::Respond(response), false),
    }
}

fn run<S: Store, R: RngCore + CryptoRng>(
    ctx: &mut Ctx<S, R>,
    gated: &Gated,
    req: &Request,
) -> Result<Outcome, Response> {
    let Route::Host(route) = &gated.route else { return Err(Response::error(404, "not-found")) };
    let respond = |r| Ok(Outcome::Respond(r));
    if destroyed(ctx.store)? {
        return Err(Response::error(410, "destroyed"));
    }
    match route {
        HostRoute::PushKey => return respond(Response::ok(ctx.config.vapid_public.to_vec())),
        HostRoute::Claim => {
            if admin_key(ctx.store)?.is_some() {
                return Err(Response::error(409, "conflict"));
            }
            let key: cw_crypto::sign::Public =
                req.body.as_slice().try_into().map_err(|_| Response::error(400, "malformed"))?;
            ctx.store
                .exec("INSERT INTO host (id, admin, claimed_at) VALUES (1, ?1, ?2)", &[(&key).into(), ctx.now.into()])
                .map_err(storage)?;
            let admin = token::issue(&ctx.config.secret, &token::ADMIN_TENANT, 1, TokenKind::Admin, 0);
            return respond(Response::json(200, json!({ "admin_token": admin })));
        }
        _ => {}
    }
    let Some(admin) = admin_key(ctx.store)? else { return Err(Response::error(403, "unclaimed")) };
    if let HostRoute::OfferTenant = route {
        return offer_tenant(ctx, req);
    }
    let signer = auth::signature(req, "cw-admin", |id| (id[..] == admin[..32]).then_some(admin))?;
    auth::nonce(ctx.store, &signer, ctx.now)?;
    match route {
        HostRoute::CreateTenant => {
            let body = json_body(req)?;
            let card = card_of(body["card"].as_str())?;
            let quota = body["quota"].as_u64().ok_or_else(|| Response::error(400, "malformed"))?;
            let limits = Settings::load(ctx.store)?.member();
            let tenant = new_tenant(ctx)?;
            Ok(Outcome::Tenant(tenant, Internal::Init { card, quota, guest: false, limits }))
        }
        HostRoute::ListTenants => {
            let rows = ctx.store.exec("SELECT id FROM tenants ORDER BY created_at", &[]).map_err(storage)?;
            let ops = rows.iter().filter_map(|r| r[0].array::<16>()).map(|t| (t, Internal::Usage)).collect();
            Ok(Outcome::Each(ops, Finish::List))
        }
        HostRoute::Destroy => {
            let rows = ctx.store.exec("SELECT id FROM tenants", &[]).map_err(storage)?;
            let ops = rows.iter().filter_map(|r| r[0].array::<16>()).map(|t| (t, Internal::Destroy)).collect();
            Ok(Outcome::Each(ops, Finish::Destroy))
        }
        HostRoute::Quota(t)
        | HostRoute::Notice(t)
        | HostRoute::Remove(t)
        | HostRoute::Approve(t)
        | HostRoute::Budget(t) => {
            if !registered(ctx.store, t)? {
                return Err(Response::error(404, "not-found"));
            }
            let op = match route {
                HostRoute::Quota(_) => {
                    Internal::Quota(json_body(req)?["quota"].as_u64().ok_or_else(|| Response::error(400, "malformed"))?)
                }
                HostRoute::Budget(_) => {
                    let body = json_body(req)?;
                    Internal::Budget(match &body["budget"] {
                        Json::Null => None,
                        b => Some(
                            b.as_u64()
                                .filter(|b| (1_000..=10_000_000).contains(b))
                                .ok_or_else(|| Response::error(400, "malformed"))?,
                        ),
                    })
                }
                HostRoute::Notice(_) => {
                    let days = json_body(req)?["days"].as_u64().filter(|d| (1..=90).contains(d));
                    Internal::Notice(ctx.now + days.ok_or_else(|| Response::error(400, "malformed"))? * DAY_MS)
                }
                HostRoute::Approve(_) => {
                    let quota = json_body(req)?["quota"].as_u64().filter(|q| *q > 0);
                    let quota = quota.ok_or_else(|| Response::error(400, "malformed"))?;
                    let approved = ctx
                        .store
                        .exec("DELETE FROM guests WHERE tenant = ?1 RETURNING 1", &[t.into()])
                        .map_err(storage)?;
                    if approved.is_empty() {
                        return Err(Response::error(404, "not-found"));
                    }
                    Internal::Approve { quota, limits: Settings::load(ctx.store)?.member() }
                }
                _ => {
                    ctx.store.exec("DELETE FROM guests WHERE tenant = ?1", &[t.into()]).map_err(storage)?;
                    Internal::Remove
                }
            };
            Ok(Outcome::Tenant(*t, op))
        }
        HostRoute::CreateOffer => {
            let body = json_body(req)?;
            let quota = body["quota"].as_u64().filter(|q| *q > 0);
            let expires_at = body["expires_at"].as_u64().filter(|e| *e > ctx.now && *e <= ctx.now + 90 * DAY_MS);
            let places = match &body["places"] {
                Json::Null => Some(1),
                p => p.as_u64().filter(|p| (1..=MAX_PLACES).contains(p)),
            };
            let (Some(quota), Some(expires_at), Some(places)) = (quota, expires_at, places) else {
                return Err(Response::error(400, "malformed"));
            };
            ctx.store
                .exec(
                    &format!("DELETE FROM offers WHERE used >= {PLACES} OR expires_at <= ?1 RETURNING id"),
                    &[ctx.now.into()],
                )
                .map_err(storage)?
                .iter()
                .try_for_each(|r| {
                    ctx.store.exec("DELETE FROM offer_places WHERE id = ?1", &[r[0].clone()]).map(|_| ())
                })
                .map_err(storage)?;
            let mut id = [0u8; 16];
            ctx.rng.fill_bytes(&mut id);
            ctx.store
                .exec(
                    "INSERT INTO offers (id, quota, expires_at, used) VALUES (?1, ?2, ?3, 0)",
                    &[(&id).into(), quota.into(), expires_at.into()],
                )
                .map_err(storage)?;
            if places > 1 {
                ctx.store
                    .exec("INSERT INTO offer_places (id, places) VALUES (?1, ?2)", &[(&id).into(), places.into()])
                    .map_err(storage)?;
            }
            Ok(Outcome::Respond(offer_response(&ctx.config.secret, &id)))
        }
        HostRoute::WithdrawOffer(id) => {
            // Withdrawing removes the places left; the tenants made in places taken stay.
            let rows = ctx
                .store
                .exec(&format!("DELETE FROM offers WHERE id = ?1 AND used < {PLACES} RETURNING id"), &[id.into()])
                .map_err(storage)?;
            if rows.is_empty() {
                return Err(Response::error(404, "not-found"));
            }
            ctx.store.exec("DELETE FROM offer_places WHERE id = ?1", &[id.into()]).map_err(storage)?;
            Ok(Outcome::Respond(Response::empty(204)))
        }
        HostRoute::GetSettings => Ok(Outcome::Respond(Response::json(200, Settings::load(ctx.store)?.json()))),
        HostRoute::PutSettings => {
            let body = json_body(req)?;
            let budget = |key: &str| body[key].as_u64().filter(|b| (1_000..=10_000_000).contains(b));
            let settings = match (
                body["guests"].as_bool(),
                body["guest_limit"].as_u64().filter(|l| *l <= 10_000),
                budget("member_budget"),
                budget("guest_budget"),
            ) {
                (Some(guests), Some(guest_limit), Some(member_budget), Some(guest_budget)) => {
                    Settings { guests, guest_limit, member_budget, guest_budget }
                }
                _ => return Err(Response::error(400, "malformed")),
            };
            ctx.store
                .exec(
                    "INSERT INTO settings (id, guests, guest_limit, member_budget, guest_budget) VALUES (1, ?1, ?2, ?3, ?4) \
                     ON CONFLICT (id) DO UPDATE SET guests = excluded.guests, guest_limit = excluded.guest_limit, \
                     member_budget = excluded.member_budget, guest_budget = excluded.guest_budget",
                    &[
                        (settings.guests as i64).into(),
                        settings.guest_limit.into(),
                        settings.member_budget.into(),
                        settings.guest_budget.into(),
                    ],
                )
                .map_err(storage)?;
            let rows = ctx
                .store
                .exec("SELECT tenants.id, guests.tenant IS NOT NULL FROM tenants LEFT JOIN guests ON guests.tenant = tenants.id", &[])
                .map_err(storage)?;
            let ops = rows
                .iter()
                .filter_map(|r| {
                    let limits = if r[1].int() != 0 { settings.guest() } else { settings.member() };
                    Some((r[0].array::<16>()?, Internal::Limits(limits)))
                })
                .collect();
            Ok(Outcome::Each(ops, Finish::Settings))
        }
        HostRoute::Claim | HostRoute::PushKey | HostRoute::OfferTenant => unreachable!(),
    }
}

fn offer_response(secret: &[u8; 32], id: &[u8; 16]) -> Response {
    let offer = token::offer_secret(secret, id);
    Response::json(200, json!({ "offer": b64::encode(id), "secret": b64::encode(&offer) }))
}

/// `POST /tenants` with a hosting offer from the admin, or a guest offer from a member.
fn offer_tenant<S: Store, R: RngCore + CryptoRng>(ctx: &mut Ctx<S, R>, req: &Request) -> Result<Outcome, Response> {
    let offer = req.header("cw-offer").and_then(|v| b64::decode_array::<32>(v).ok());
    let id = offer
        .and_then(|o| token::check_offer(&ctx.config.secret, &o).ok())
        .ok_or_else(|| Response::error(401, "unauthorized"))?;
    if req.body.len() > cw_crypto::card::SIGNED_LIMIT || Card::open(&req.body, None).is_err() {
        return Err(Response::error(400, "malformed"));
    }
    let settings = Settings::load(ctx.store)?;
    let rows = ctx
        .store
        .exec(&format!("SELECT quota, expires_at, used >= {PLACES} FROM offers WHERE id = ?1"), &[(&id).into()])
        .map_err(storage)?;
    if let Some(row) = rows.first() {
        if row[2].int() != 0 || row[1].u64() <= ctx.now {
            return Err(Response::error(410, "gone"));
        }
        ctx.store.exec("UPDATE offers SET used = used + 1 WHERE id = ?1", &[(&id).into()]).map_err(storage)?;
        let tenant = new_tenant(ctx)?;
        ctx.store
            .exec("INSERT INTO offered (tenant, offer) VALUES (?1, ?2)", &[(&tenant).into(), (&id).into()])
            .map_err(storage)?;
        let init = Internal::Init { card: req.body.clone(), quota: row[0].u64(), guest: false, limits: settings.member() };
        return Ok(Outcome::Tenant(tenant, init));
    }
    let rows = ctx
        .store
        .exec("DELETE FROM guest_offers WHERE id = ?1 AND expires_at > ?2 RETURNING sponsor", &[(&id).into(), ctx.now.into()])
        .map_err(storage)?;
    let sponsor = rows.first().and_then(|r| r[0].array::<16>()).ok_or_else(|| Response::error(410, "gone"))?;
    if !settings.guests {
        return Err(Response::error(410, "gone"));
    }
    // The offer just used counted toward the limit while it waited, and the guest takes its place.
    if guests_held(ctx.store, ctx.now)? >= settings.guest_limit as i64 {
        return Err(Response::error(507, "guest-limit"));
    }
    let tenant = new_tenant(ctx)?;
    ctx.store
        .exec(
            "INSERT INTO guests (tenant, sponsor, joined_at) VALUES (?1, ?2, ?3)",
            &[(&tenant).into(), (&sponsor).into(), ctx.now.into()],
        )
        .map_err(storage)?;
    let init = Internal::Init { card: req.body.clone(), quota: crate::GUEST_QUOTA, guest: true, limits: settings.guest() };
    Ok(Outcome::Tenant(tenant, init))
}

/// Runs an operation a tenant started. The bool says whether to commit.
pub fn internal<S: Store, R: RngCore + CryptoRng>(ctx: &mut Ctx<S, R>, op: &HostInternal) -> (Response, bool) {
    let result = (|| match op {
        HostInternal::GuestOffer { sponsor, expires_at } => {
            let settings = Settings::load(ctx.store)?;
            if !settings.guests || !registered(ctx.store, sponsor)? || is_guest(ctx.store, sponsor)? {
                return Err(Response::error(403, "forbidden"));
            }
            ctx.store.exec("DELETE FROM guest_offers WHERE expires_at <= ?1", &[ctx.now.into()]).map_err(storage)?;
            let held = count(ctx.store, "SELECT COUNT(*) FROM guest_offers WHERE sponsor = ?1", &[sponsor.into()])?
                + count(
                    ctx.store,
                    "SELECT COUNT(*) FROM guests WHERE sponsor = ?1 AND joined_at > ?2",
                    &[sponsor.into(), ctx.now.saturating_sub(GUEST_MS).into()],
                )?;
            if held >= SPONSOR_LIMIT || guests_held(ctx.store, ctx.now)? >= settings.guest_limit as i64 {
                return Err(Response::error(507, "guest-limit"));
            }
            let mut id = [0u8; 16];
            ctx.rng.fill_bytes(&mut id);
            ctx.store
                .exec(
                    "INSERT INTO guest_offers (id, sponsor, expires_at) VALUES (?1, ?2, ?3)",
                    &[(&id).into(), sponsor.into(), (*expires_at).into()],
                )
                .map_err(storage)?;
            Ok(offer_response(&ctx.config.secret, &id))
        }
        HostInternal::WithdrawGuestOffer { sponsor, offer } => {
            let rows = ctx
                .store
                .exec("DELETE FROM guest_offers WHERE id = ?1 AND sponsor = ?2 RETURNING id", &[offer.into(), sponsor.into()])
                .map_err(storage)?;
            if rows.is_empty() {
                return Err(Response::error(404, "not-found"));
            }
            Ok(Response::empty(204))
        }
    })();
    match result {
        Ok(r) => (r, true),
        Err(r) => (r, false),
    }
}

/// Answers once every tenant ran its operation. Returns the tenants whose forwarding period ended, which the
/// host forgets here and the runtime drops.
pub fn finish(store: &mut impl Store, finish: &Finish, results: Vec<([u8; 16], Response)>) -> (Response, bool, Vec<[u8; 16]>) {
    let result = (|| {
        let mut gone = Vec::new();
        match finish {
            Finish::Settings => Ok((Response::json(200, Settings::load(store)?.json()), gone)),
            // Every tenant's storage goes, whether or not its own deletion answered, and the host keeps only the mark.
            Finish::Destroy => {
                for table in crate::schema::HOST_DATA {
                    store.exec(&format!("DELETE FROM {table}"), &[]).map_err(storage)?;
                }
                store.exec("INSERT OR IGNORE INTO destroyed (id) VALUES (1)", &[]).map_err(storage)?;
                gone.extend(results.into_iter().map(|(tenant, _)| tenant));
                Ok((Response::empty(204), gone))
            }
            Finish::List => {
                let mut list = Vec::new();
                for (tenant, response) in results {
                    let mut usage: Json = if response.status == 200 {
                        serde_json::from_slice(&response.body).unwrap_or_default()
                    } else {
                        json!({ "state": "gone" })
                    };
                    match usage["state"].as_str() {
                        Some("gone") | None => {
                            store.exec("DELETE FROM tenants WHERE id = ?1", &[(&tenant).into()]).map_err(storage)?;
                            store.exec("DELETE FROM guests WHERE tenant = ?1", &[(&tenant).into()]).map_err(storage)?;
                            store.exec("DELETE FROM offered WHERE tenant = ?1", &[(&tenant).into()]).map_err(storage)?;
                            gone.push(tenant);
                            continue;
                        }
                        // A guest who moved away removed their tenant; it no longer holds a guest place.
                        Some("removed") => {
                            store.exec("DELETE FROM guests WHERE tenant = ?1", &[(&tenant).into()]).map_err(storage)?;
                        }
                        _ => {}
                    }
                    let sponsor = store
                        .exec("SELECT sponsor FROM guests WHERE tenant = ?1", &[(&tenant).into()])
                        .map_err(storage)?
                        .first()
                        .and_then(|r| r[0].array::<16>());
                    usage["sponsor"] = sponsor.map_or(Json::Null, |s| b64::encode(&s).into());
                    let offer = store
                        .exec("SELECT offer FROM offered WHERE tenant = ?1", &[(&tenant).into()])
                        .map_err(storage)?
                        .first()
                        .and_then(|r| r[0].array::<16>());
                    usage["offer"] = offer.map_or(Json::Null, |o| b64::encode(&o).into());
                    list.push(usage);
                }
                Ok((Response::json(200, Json::Array(list)), gone))
            }
        }
    })();
    match result {
        Ok((r, gone)) => (r, true, gone),
        Err(r) => (r, false, Vec::new()),
    }
}
