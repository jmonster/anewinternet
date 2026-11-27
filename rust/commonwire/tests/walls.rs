//! Group walls and slots on the host's clock. A wall takes group posts until its next sequence is 1,800, and a
//! tenant takes 200 items or 4 MiB through its slots; a running host can't show either within the conformance
//! suite's minute, so these step the clock past the per-token windows instead.
use commonwire::db::{self, Db};
use cw_crypto::card::Card;
use cw_crypto::token::{self, TokenKind};
use cw_crypto::wire::{self, DeviceEntry};
use cw_crypto::{b64, hpke, recovery, request, sign::Key};
use cw_host::gate::gate;
use cw_host::host::{Internal, Limits};
use cw_host::tenant::{self, Memory, Outcome};
use cw_host::{http::Request, http::Response, Config, MEMBER_BUDGET};
use rand::rngs::OsRng;
use serde_json::Value;

const T0: u64 = 1_800_000_000_000;
const AUTHORITY: &str = "127.0.0.1:1";

struct Tenant {
    conn: rusqlite::Connection,
    memory: Memory,
    config: Config,
    tenant: [u8; 16],
    device: Key,
}

impl Tenant {
    fn new(quota: u64) -> Tenant {
        let config =
            Config::new([7; 32], [8; 32], cw_host::config::vapid_secret(&mut OsRng), &format!("http://{AUTHORITY}")).unwrap();
        let tenant = token::new_tenant(&config.secret, &mut OsRng);
        let device = Key::generate(&mut OsRng);
        let mut t = Tenant { conn: rusqlite::Connection::open_in_memory().unwrap(), memory: Memory::default(), config, tenant, device };
        let seed = [3u8; 32];
        let profile = Key::from_seed(&seed);
        let card = Card {
            profile: profile.profile_id(),
            profile_key: profile.public(),
            version: 1,
            issued_at: T0,
            devices: vec![DeviceEntry { device: t.device.id(), signing_key: t.device.mldsa_public(), added_at: 1 }],
            inbox_key: hpke::generate(&mut OsRng).public,
            recovery_key: recovery::recovery_keys(&seed).public,
            hosts: vec![t.config.tenant_url(&t.tenant)],
        }
        .sign(&profile)
        .unwrap();
        let init = Internal::Init { card, quota, guest: false, limits: Limits { guests: false, budget: MEMBER_BUDGET } };
        assert_eq!(t.internal(T0, init).status, 200);
        t
    }

    fn ctx_run<T>(&mut self, now: u64, f: impl FnOnce(&mut tenant::Ctx<Db, OsRng>) -> (T, bool)) -> T {
        let objects = std::env::var_os("PB_TMP_ROOT").map_or_else(std::env::temp_dir, Into::into).join("commonwire-walls-none");
        let mut store = Db { conn: &self.conn, objects: Some(objects) };
        let mut rng = OsRng;
        let mut ctx = tenant::Ctx {
            store: &mut store,
            config: &self.config,
            now,
            rng: &mut rng,
            memory: &mut self.memory,
            tenant: self.tenant,
            connected: &[],
            effects: Vec::new(),
        };
        db::transaction(&self.conn, || f(&mut ctx)).unwrap()
    }

    fn internal(&mut self, now: u64, op: Internal) -> Response {
        self.ctx_run(now, |ctx| tenant::internal(ctx, &op))
    }

    fn token(&self, kind: TokenKind, counter: u64) -> String {
        token::issue(&self.config.secret, &self.tenant, counter, kind, 0)
    }

    /// A request with `token`, signed by the owner's device when `signed`.
    fn request(&mut self, now: u64, method: &str, rel: &str, token: &str, signed: bool, body: Vec<u8>) -> Response {
        let target = format!("/t/{}{rel}", b64::encode(&self.tenant));
        let mut headers = vec![("authorization".to_string(), format!("CW {token}"))];
        if signed {
            let a = request::sign(&self.device, method, AUTHORITY, &target, &body, now, &mut OsRng);
            headers.extend([
                ("cw-device".into(), a.key),
                ("cw-time".into(), a.time),
                ("cw-nonce".into(), a.nonce),
                ("cw-signature".into(), a.signature),
            ]);
        }
        let req = Request { method: method.into(), authority: AUTHORITY.into(), target, headers, body, received: now };
        let gated = match gate(&self.config, &req) {
            Ok(g) => g,
            Err(r) => return r,
        };
        match self.ctx_run(now, |ctx| tenant::handle(ctx, &gated, &req)) {
            Outcome::Respond(r) => r,
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    fn owner(&mut self, now: u64, method: &str, rel: &str, body: Vec<u8>) -> Response {
        let owner = self.token(TokenKind::Owner, 0);
        self.request(now, method, rel, &owner, true, body)
    }
}

fn header(r: &Response, name: &str) -> Option<String> {
    r.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
}

fn error(r: &Response) -> String {
    let code = serde_json::from_slice::<Value>(&r.body).ok().and_then(|v| v["error"].as_str().map(str::to_string));
    format!("{} {}", r.status, code.unwrap_or_default())
}

fn entry() -> Vec<u8> {
    wire::encode(&wire::SealedBox { nonce: [0; 12], sealed: wire::vl(vec![0x5a; 64]) })
}

fn item(size: usize) -> Vec<u8> {
    let wrap = wire::HpkeBox { enc: wire::vl(vec![1; 1120]), ciphertext: wire::vl(vec![2; 48]) };
    wire::encode(&wire::InboxBox {
        ciphertext: wire::vl(vec![0x5a; size]),
        wraps: vec![wire::DeviceWrap { device: [3; 32], created_at: 1, wrap }],
    })
}

#[test]
fn a_group_write_token_appends_until_sequence_1799_and_an_owner_token_after() {
    let mut t = Tenant::new(64 * 1024 * 1024);
    let wall = format!("/threads/{}", b64::encode(&[0x77; 16]));
    let write = t.token(TokenKind::GroupWrite, 0);
    assert_eq!(t.owner(T0, "PUT", &wall, vec![]).status, 204);
    // 200 ms apart: 300 posts a minute, under the token's 600.
    let mut now = T0;
    for seq in 0..1_800u64 {
        now += 200;
        let r = t.request(now, "POST", &wall, &write, false, entry());
        assert_eq!(r.status, 201, "post {seq}: {}", error(&r));
        assert_eq!(header(&r, "cw-seq"), Some(seq.to_string()));
    }
    now += 200;
    assert_eq!(error(&t.request(now, "POST", &wall, &write, false, entry())), "507 thread-full");
    now += 200;
    let owner = t.owner(now, "POST", &wall, entry());
    assert_eq!((owner.status, header(&owner, "cw-seq")), (201, Some("1800".into())));
    now += 200;
    assert_eq!(error(&t.request(now, "POST", &wall, &write, false, entry())), "507 thread-full");
}

#[test]
fn slots_take_at_most_200_items_and_4_mib_in_all() {
    // By count: ten slots of 20 items fill the tenant's 200, and an eleventh slot can't add one.
    let mut t = Tenant::new(64 * 1024 * 1024);
    let mut now = T0;
    let mut tokens = Vec::new();
    for _ in 0..11 {
        now += 1;
        let r = t.owner(now, "POST", "/slots", vec![]);
        assert_eq!(r.status, 200, "{}", error(&r));
        tokens.push(serde_json::from_slice::<Value>(&r.body).unwrap()["token"].as_str().unwrap().to_string());
    }
    for token in &tokens[..10] {
        for i in 0..20 {
            now += 1_000;
            let r = t.request(now, "POST", "/inbox", token, false, item(64));
            assert_eq!(r.status, 201, "item {i}: {}", error(&r));
        }
    }
    now += 1_000;
    assert_eq!(error(&t.request(now, "POST", "/inbox", &tokens[10], false, item(64))), "507 slot-full");
    // Reading items frees their places.
    now += 1_000;
    assert_eq!(t.owner(now, "DELETE", "/inbox?through=0", vec![]).status, 204);
    now += 1_000;
    assert_eq!(t.request(now, "POST", "/inbox", &tokens[10], false, item(64)).status, 201);

    // By bytes: items of 64 KB fill 4 MiB at the 65th.
    let mut t = Tenant::new(64 * 1024 * 1024);
    let size = 64_000;
    let mut tokens = Vec::new();
    for _ in 0..4 {
        now += 1;
        let r = t.owner(now, "POST", "/slots", vec![]);
        tokens.push(serde_json::from_slice::<Value>(&r.body).unwrap()["token"].as_str().unwrap().to_string());
    }
    let fits = (4 * 1024 * 1024) / item(size).len();
    for i in 0..fits {
        now += 1_000;
        let r = t.request(now, "POST", "/inbox", &tokens[i / 20], false, item(size));
        assert_eq!(r.status, 201, "item {i}: {}", error(&r));
    }
    now += 1_000;
    assert_eq!(error(&t.request(now, "POST", "/inbox", &tokens[fits / 20], false, item(size))), "507 slot-full");
    // A friend's item, with a write token, still arrives.
    now += 1_000;
    let write = t.token(TokenKind::Write, 0);
    assert_eq!(t.request(now, "POST", "/inbox", &write, false, item(size)).status, 201);
}
