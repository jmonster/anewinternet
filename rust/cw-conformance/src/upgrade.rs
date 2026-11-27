//! `cw-conformance upgrade-make` makes a tenant with only the requests every host version answers, and saves its
//! keys; `cw-conformance upgrade-check` runs a request of every newer kind against that tenant after the host was
//! replaced by a newer build over the same data. Together they show a new host opens the tenants an earlier one made.
use cw_crypto::sign::Key;
use cw_crypto::wire::{self, ObjectRef};
use cw_crypto::{b64, head, hpke, object, transfer};
use rand::rngs::OsRng;
use serde_json::{json, Value};

use crate::{claimed, json_body, outcome, random, Person, Suite};

pub async fn make(base: &str, claim: [u8; 32]) -> Value {
    let (s, admin) = claimed(base, claim).await;
    let mut p = Person::new(1);
    crate::admin_tenant(&s, &admin, &mut p, 8 * 1024 * 1024).await;
    let manifest = ObjectRef { digest: random(), key: random(), size: 1 };
    let audience_key = random::<32>();
    let signed = head::seal(&p.devices[0], &p.profile.profile_id(), &[], 1, 1, crate::now(), &audience_key, &manifest, &mut OsRng);
    let f = s.owner(&p, 0, "PUT", "/head", signed, Some(0)).await;
    let (photo, photo_ref) = object::encrypt(b"MARKER before the upgrade", &mut OsRng).unwrap();
    let g = s.owner(&p, 0, "PUT", &format!("/objects/{}", object::name(&photo_ref.digest)), photo, None).await;
    json!({
        "head": outcome(&f),
        "object": outcome(&g),
        "admin_seed": b64::encode(&admin.seed()[..]),
        "admin_token": s.admin_token,
        "profile_seed": b64::encode(&p.seed),
        "device_seed": b64::encode(&p.devices[0].seed()[..]),
        "inbox": b64::encode(&p.inbox.private[..]),
        "version": p.version,
        "tenant": p.tid(),
    })
}

pub async fn check(base: &str, saved: &Value) -> Value {
    let field = |k: &str| saved[k].as_str().unwrap_or_default().to_string();
    let seed = |k: &str| b64::decode_array::<32>(&field(k)).unwrap_or_default();
    let authority = base.split_once("://").map(|(_, a)| a.to_string()).unwrap_or_default();
    let mut s = Suite {
        base: base.into(),
        authority,
        claim: [0; 32],
        out: Default::default(),
        admin: Key::from_seed(&seed("admin_seed")),
        admin_token: field("admin_token"),
        patient: false,
    };
    let admin = Key::from_seed(&seed("admin_seed"));
    let profile = Key::from_seed(&seed("profile_seed"));
    let mut p = Person::new(1);
    p.profile = profile;
    p.seed = seed("profile_seed");
    p.devices = vec![Key::from_seed(&seed("device_seed"))];
    p.inbox = hpke::KeyPair::from_private(seed("inbox"));
    p.tenant = b64::decode_array(&field("tenant")).unwrap_or_default();
    p.url = format!("{base}/t/{}", p.tid());
    p.version = saved["version"].as_u64().unwrap_or(1);
    p.card = p.sign_card(p.version, &[p.url.clone()]);
    s.tokens(&mut p).await;

    let f = s.read(&p, "/head", &p.read, vec![]).await;
    s.record("upgrade.old-head", outcome(&f));
    // Two keyring puts advance the ETag, and the contact counter rotates.
    let mut tags = Vec::new();
    for _ in 0..2 {
        let keyring = head::seal_keyring(&p.profile.profile_id(), 1, &random::<32>(), &p.tokens(), &mut OsRng);
        s.owner(&p, 0, "PUT", "/keyring", keyring, None).await;
        let f = s.call("GET", &format!("/t/{}/keyring", p.tid()), vec![], vec![]).await;
        tags.push(f.header("etag").unwrap_or("-").to_string());
    }
    s.record("upgrade.keyring-etags", tags.join(","));
    s.record("upgrade.contact-rotate", outcome(&s.owner(&p, 0, "POST", "/tokens/contact?to=1", vec![], None).await));
    let f = s.owner(&p, 0, "POST", "/tokens/group", vec![], None).await;
    s.record("upgrade.group-tokens", format!("{} counter={}", outcome(&f), json_body(&f)["counter"]));
    let write = json_body(&f)["write"].as_str().unwrap_or_default().to_string();
    let read = json_body(&f)["read"].as_str().unwrap_or_default().to_string();
    let wall = b64::encode(&random::<16>());
    s.record("upgrade.open-thread", outcome(&s.owner(&p, 0, "PUT", &format!("/threads/{wall}"), vec![], None).await));
    let entry = wire::encode(&wire::SealedBox { nonce: random(), sealed: wire::vl(random::<48>().to_vec()) });
    s.record("upgrade.group-post", outcome(&s.with_token(&p, "POST", &format!("/threads/{wall}"), &write, entry).await));
    let (photo, photo_ref) = object::encrypt(b"MARKER after the upgrade", &mut OsRng).unwrap();
    let path = format!("/objects/{}", object::name(&photo_ref.digest));
    s.record("upgrade.group-object", outcome(&s.with_token(&p, "PUT", &path, &write, photo).await));
    s.record("upgrade.group-read", outcome(&s.read(&p, &format!("/threads/{wall}"), &read, vec![]).await));
    let f = s.owner(&p, 0, "POST", "/tokens/group?to=1", vec![], None).await;
    s.record("upgrade.group-advance", format!("{} counter={}", outcome(&f), json_body(&f)["counter"]));
    let lookup = b64::encode(&random::<16>());
    let sealed = wire::encode(&wire::SealedBox { nonce: random(), sealed: wire::vl(random::<64>().to_vec()) });
    s.record("upgrade.access-put", outcome(&s.owner(&p, 0, "PUT", &format!("/access/{lookup}"), sealed, None).await));
    s.record("upgrade.access-get", outcome(&s.call("GET", &format!("/t/{}/access/{lookup}", p.tid()), vec![], vec![]).await));
    s.record("upgrade.access-delete", outcome(&s.owner(&p, 0, "DELETE", &format!("/access/{lookup}"), vec![], None).await));
    let f = s.owner(&p, 0, "POST", "/slots", vec![], None).await;
    let slot = json_body(&f);
    s.record("upgrade.slot-open", format!("{} slot={}", outcome(&f), slot["slot"]));
    let token = slot["token"].as_str().unwrap_or_default().to_string();
    let item = wire::encode(&wire::HpkeBox { enc: wire::vl(vec![1; 32]), ciphertext: wire::vl(vec![0x5a; 256]) });
    s.record("upgrade.slot-post", outcome(&s.with_token(&p, "POST", "/inbox", &token, item).await));
    let f = s.owner(&p, 0, "GET", "/slots", vec![], None).await;
    s.record("upgrade.slot-list", format!("{} {}", outcome(&f), json_body(&f)["slots"][0]["unread"]));
    s.record("upgrade.slot-close", outcome(&s.owner(&p, 0, "DELETE", &format!("/slots/{}", slot["slot"]), vec![], None).await));
    let budget = json!({ "budget": 50_000 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "PUT", &format!("/admin/tenants/{}/budget", p.tid()), budget).await;
    s.record("upgrade.budget", outcome(&f));
    let (f, _) = s.admin(&admin, "GET", "/admin/tenants", vec![]).await;
    let listed = json_body(&f).as_array().and_then(|a| a.iter().find(|t| t["tenant"] == p.tid()).cloned()).unwrap_or_default();
    s.record("upgrade.budget-listed", format!("budget={}", listed["budget"]));
    let offer = json!({ "quota": 64 * 1024, "expires_at": crate::now() + 86_400_000, "places": 2 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "POST", "/admin/offers", offer).await;
    let secret = json_body(&f)["secret"].as_str().unwrap_or_default().to_string();
    let mut taken = Vec::new();
    for _ in 0..3 {
        let f = s.call("POST", "/tenants", vec![("cw-offer", secret.clone())], Person::new(1).card).await;
        taken.push(outcome(&f));
    }
    s.record("upgrade.places", taken.join(","));
    let body = json!({ "card": b64::encode(&p.card), "quota": 8 * 1024 * 1024 }).to_string().into_bytes();
    let (f, _) = s.admin(&admin, "POST", "/admin/tenants", body).await;
    let mut moved = Person::new(1);
    moved.profile = Key::from_seed(&p.seed);
    moved.seed = p.seed;
    moved.devices = vec![Key::from_seed(&p.devices[0].seed())];
    moved.card = p.card.clone();
    moved.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
    moved.url = format!("{base}/t/{}", moved.tid());
    s.tokens(&mut moved).await;
    let grant = transfer::grant(&p.devices[0], &p.tenant, &moved.url, crate::now() + 3_600_000);
    let req = json!({ "from": p.url, "grant": b64::encode(&grant) }).to_string().into_bytes();
    s.record("upgrade.export", outcome(&s.owner(&moved, 0, "POST", "/import", req, None).await));
    let f = s.owner(&moved, 0, "POST", "/tokens/group", vec![], None).await;
    s.record("upgrade.export-counter", format!("counter={}", json_body(&f)["counter"]));
    json!({ "outcomes": s.out })
}
