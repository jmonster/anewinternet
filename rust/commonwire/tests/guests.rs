//! A guest's lifecycle on the host's clock: 30 days of writes, 30 days of notice, then removal; and approval.
//! The conformance suite covers what a running host shows within a minute; this covers what takes days.
use commonwire::db::{self, Db};
use cw_crypto::card::Card;
use cw_crypto::wire::DeviceEntry;
use cw_crypto::{hpke, recovery, sign::Key};
use cw_host::host::{Internal, Limits};
use cw_host::tenant::{self, Memory};
use cw_host::{http::Response, Config, GUEST_BUDGET, GUEST_MS, GUEST_NOTICE_MS, GUEST_QUOTA, MEMBER_BUDGET};
use rand::rngs::OsRng;
use serde_json::Value;

const T0: u64 = 1_800_000_000_000;

struct Tenant {
    conn: rusqlite::Connection,
    memory: Memory,
    config: Config,
}

impl Tenant {
    fn new() -> Tenant {
        let config = Config::new([7; 32], [8; 32], cw_host::config::vapid_secret(&mut OsRng), "http://127.0.0.1:1").unwrap();
        Tenant { conn: rusqlite::Connection::open_in_memory().unwrap(), memory: Memory::default(), config }
    }

    fn run(&mut self, now: u64, op: Internal) -> Response {
        // Removal clears the object directory, which these tenants never create.
        let objects = std::env::var_os("PB_TMP_ROOT").map_or_else(std::env::temp_dir, Into::into).join("commonwire-guests-none");
        let mut store = Db { conn: &self.conn, objects: Some(objects) };
        let mut ctx = tenant::Ctx {
            store: &mut store,
            config: &self.config,
            now,
            rng: &mut OsRng,
            memory: &mut self.memory,
            tenant: [1; 16],
            connected: &[],
            effects: Vec::new(),
        };
        db::transaction(&self.conn, || tenant::internal(&mut ctx, &op)).unwrap()
    }

    fn usage(&mut self, now: u64) -> Value {
        serde_json::from_slice(&self.run(now, Internal::Usage).body).unwrap()
    }
}

fn card() -> Vec<u8> {
    let seed = [3u8; 32];
    let profile = Key::from_seed(&seed);
    Card {
        profile: profile.profile_id(),
            profile_key: profile.public(),
        version: 1,
        issued_at: T0,
        devices: vec![{ let d = Key::generate(&mut OsRng); DeviceEntry { device: d.id(), signing_key: d.mldsa_public(), added_at: 1 } }],
        inbox_key: hpke::generate(&mut OsRng).public,
        recovery_key: recovery::recovery_keys(&seed).public,
        hosts: vec!["http://127.0.0.1:1/t/AQEBAQEBAQEBAQEBAQEBAQ".into()],
    }
    .sign(&profile)
    .unwrap()
}

fn guest() -> Internal {
    Internal::Init { card: card(), quota: GUEST_QUOTA, guest: true, limits: Limits { guests: true, budget: GUEST_BUDGET } }
}

#[test]
fn a_guest_writes_for_30_days_then_has_30_days_of_notice_then_is_removed() {
    let mut t = Tenant::new();
    assert_eq!(t.run(T0, guest()).status, 200);
    let u = t.usage(T0);
    assert_eq!((u["state"].as_str(), u["quota"].as_u64(), u["budget"].as_u64()), (Some("guest"), Some(GUEST_QUOTA), Some(GUEST_BUDGET)));
    assert_eq!(u["notice_until"].as_u64(), Some(T0 + GUEST_MS));

    assert_eq!(t.run(T0 + GUEST_MS - 1, Internal::Alarm).status, 204);
    assert_eq!(t.usage(T0 + GUEST_MS - 1)["state"], "guest");

    assert_eq!(t.run(T0 + GUEST_MS, Internal::Alarm).status, 204);
    let u = t.usage(T0 + GUEST_MS);
    assert_eq!(u["state"], "notice");
    assert_eq!(u["notice_until"].as_u64(), Some(T0 + GUEST_MS + GUEST_NOTICE_MS));

    assert_eq!(t.run(T0 + GUEST_MS + GUEST_NOTICE_MS, Internal::Alarm).status, 204);
    assert_eq!(t.usage(T0 + GUEST_MS + GUEST_NOTICE_MS)["state"], "removed");
}

#[test]
fn an_approved_guest_is_a_member_even_after_its_notice_began() {
    let mut t = Tenant::new();
    t.run(T0, guest());
    t.run(T0 + GUEST_MS, Internal::Alarm);
    assert_eq!(t.usage(T0 + GUEST_MS)["state"], "notice");
    let member = Limits { guests: true, budget: MEMBER_BUDGET };
    assert_eq!(t.run(T0 + GUEST_MS + 1, Internal::Approve { quota: 1 << 30, limits: member }).status, 204);
    // The alarm set for the notice's end finds a member and leaves it.
    t.run(T0 + GUEST_MS + GUEST_NOTICE_MS, Internal::Alarm);
    let u = t.usage(T0 + GUEST_MS + GUEST_NOTICE_MS);
    assert_eq!((u["state"].as_str(), u["quota"].as_u64(), u["budget"].as_u64()), (Some("active"), Some(1 << 30), Some(MEMBER_BUDGET)));
}
