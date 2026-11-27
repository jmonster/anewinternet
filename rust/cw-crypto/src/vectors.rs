//! The format's vectors. Every target runs `check` on `vectors/format.json` and `vectors/standards.json` (RFC 9180's
//! key schedule and X-Wing's) and must produce the same outcomes and digest. Deterministic cases are computed from
//! fixed seeds, signatures with reproducible signing randomness; cases that need fresh randomness (HPKE seals) use
//! inputs recorded in the vectors file.
use std::collections::BTreeMap;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::card::Card;
use crate::sign::{Key, Kind};
use crate::token::TokenKind;
use crate::wire::{self, vl, DeviceEntry, InviteKeys, InvitePublic, LinkReplyBody, ObjectRef, OwnerKey};
use crate::{
    access, audience, b64, devicekey, head, hpke, inbox, invite, kdf, link, local, log, object, pad, recovery, request, thread, token,
    transfer, xwing, Error, Result,
};

const NOW: u64 = 1_800_000_000_000;
const TENANT: [u8; 16] = [0x11; 16];
const TENANT_URL: &str = "https://h7k2.example.net/t/EREREREREREREREREREREQ";
const FRIEND_URL: &str = "https://q9x4.example.org/t/IiIiIiIiIiIiIiIiIiIiIg";
const GROUP: [u8; 16] = [0x09; 16];
const FRIENDSHIP: [u8; 32] = [0x2f; 32];
/// When the vectors' device keys were made.
const KEYS_AT: u64 = NOW - 3_600_000;

/// A device's inbox key, made the same way on every target: its record and private key.
fn inbox_key(device: &Key, profile: &[u8; 32], seed: u8) -> (Vec<u8>, Zeroizing<[u8; 32]>) {
    devicekey::create(device, profile, KEYS_AT, &mut ChaCha20Rng::from_seed([seed; 32]))
}

struct Fixture {
    profile: Key,
    device_a: Key,
    device_b: Key,
    friend: Key,
    friend_device: Key,
    stranger: Key,
    inbox: hpke::KeyPair,
    friend_inbox: hpke::KeyPair,
    recovery: hpke::KeyPair,
    owner_card: Vec<u8>,
    friend_card: Vec<u8>,
}

fn key(byte: u8) -> Key {
    Key::for_vectors(&[byte; 32])
}

fn device_entry(byte: u8, added_at: u64) -> Result<DeviceEntry> {
    let k = key(byte);
    Ok(DeviceEntry { device: k.id(), signing_key: k.mldsa_public(), added_at })
}

fn fixture() -> Result<Fixture> {
    let profile = key(1);
    let (device_a, device_b, friend, friend_device, stranger) = (key(2), key(3), key(4), key(5), key(6));
    let inbox = hpke::KeyPair::from_private([0xa1; 32]);
    let friend_inbox = hpke::KeyPair::from_private([0xa2; 32]);
    let recovery = recovery::recovery_keys(&profile.seed());
    let owner_card = Card {
        profile: profile.profile_id(),
        profile_key: profile.public(),
        version: 3,
        issued_at: NOW,
        devices: vec![device_entry(2, NOW - 1000)?, device_entry(3, NOW - 500)?],
        inbox_key: inbox.public,
        recovery_key: recovery.public,
        hosts: vec![TENANT_URL.into()],
    }
    .sign(&profile)?;
    let friend_recovery = recovery::recovery_keys(&friend.seed());
    let friend_card = Card {
        profile: friend.profile_id(),
        profile_key: friend.public(),
        version: 1,
        issued_at: NOW,
        devices: vec![device_entry(5, NOW - 2000)?],
        inbox_key: friend_inbox.public,
        recovery_key: friend_recovery.public,
        hosts: vec![FRIEND_URL.into()],
    }
    .sign(&friend)?;
    Ok(Fixture {
        profile,
        device_a,
        device_b,
        friend,
        friend_device,
        stranger,
        inbox,
        friend_inbox,
        recovery,
        owner_card,
        friend_card,
    })
}

fn outcome(result: Result<Vec<u8>>) -> String {
    match result {
        Ok(bytes) => format!("ok:{}", b64::encode(&bytes)),
        Err(e) => format!("err:{}", e.code()),
    }
}

fn get(recorded: &Map<String, Value>, name: &str) -> Result<Vec<u8>> {
    b64::decode(recorded.get(name).and_then(Value::as_str).ok_or(Error::Malformed("vector input"))?)
}

fn flip(mut bytes: Vec<u8>, at: usize) -> Vec<u8> {
    let i = at.min(bytes.len() - 1);
    bytes[i] ^= 1;
    bytes
}

/// Recorded inputs that need fresh randomness. Only the generator calls this.
pub fn record() -> Result<Value> {
    let f = fixture()?;
    let owner = Card::open(&f.owner_card, None)?;
    let payload = br#"{"text":"hello"}"#;
    let friend = Card::open(&f.friend_card, None)?;
    let (friend_key, _) = inbox_key(&f.friend_device, &friend.profile, 0xd5);
    let (own_key, _) = inbox_key(&f.device_a, &owner.profile, 0xd2);
    let inbox_box = inbox::seal(
        &f.device_a,
        &owner.profile,
        &friend,
        &[friend_key],
        &[own_key],
        [0x42; 16],
        NOW - 60_000,
        inbox::kind::MESSAGE,
        payload,
        &mut rand::rngs::OsRng,
    )?;
    let records = [audience::seal_key_record(&f.device_a, &owner.profile), audience::seal_key_record(&f.device_b, &owner.profile)];
    let owner_key = log::seal_owner_key(&f.device_a, &owner, &records, 2, &[0x32; 32])?;
    let (_, audience_box) =
        audience::seal(&FRIENDSHIP, &owner.profile, &f.friend.profile_id(), &f.friend_inbox.public, 3, &[0x21; 32])?;
    Ok(json!({
        "inbox_box": b64::encode(&inbox_box),
        "owner_key": b64::encode(&owner_key),
        "audience_box": b64::encode(&audience_box),
    }))
}

pub fn outcomes(recorded: &Map<String, Value>, standards: &Value) -> Result<BTreeMap<String, String>> {
    let f = fixture()?;
    let mut out = BTreeMap::new();
    let mut put = |name: &str, result: Result<Vec<u8>>| {
        out.insert(name.to_string(), outcome(result));
    };
    let rng = || ChaCha20Rng::from_seed([7; 32]);
    let owner = Card::open(&f.owner_card, None)?;
    let friend = Card::open(&f.friend_card, None)?;
    let profile = f.profile.profile_id();
    let device_key = |k: &Key| {
        let public = k.public();
        let id = k.id();
        move |s: &[u8; 32]| (s == &id).then_some(public)
    };

    // Encodings and primitives.
    put("b64.encode", Ok(b64::encode(&[0xfb, 0xff, 0x00, 0x10]).into_bytes()));
    put("b64.padding", b64::decode("-_8AEA=="));
    put("b64.character", b64::decode("-_8A+A"));
    put("b64.trailing", b64::decode("-_9"));
    put(
        "pad.buckets",
        Ok([1usize, 256, 257, 1024, 1025, 1281, 2049, 100_000]
            .iter()
            .flat_map(|&n| (pad::bucket(n) as u32).to_be_bytes())
            .collect()),
    );
    put("pad.refused", pad::unpad(vec![0x41; 240]));
    put("kdf.derive", Ok(kdf::derive::<32>(b"ikm", "vector").to_vec()));
    put("kdf.expand", Ok(kdf::expand::<16>(&[3; 32], "vector").to_vec()));

    // Signatures and cards.
    let signed = f.device_a.sign(Kind::Head, b"body".to_vec());
    put("sign.bytes", Ok(signed.clone()));
    let a_key = device_key(&f.device_a);
    put("sign.open", crate::sign::open(&signed, Kind::Head, 64, a_key).map(|v| v.body));
    put("sign.wrong-kind", crate::sign::open(&signed, Kind::Card, 64, a_key).map(|v| v.body));
    put(
        "sign.bad-ed25519",
        crate::sign::open(&flip(signed.clone(), signed.len() - crate::sign::SIGNATURE), Kind::Head, 64, a_key).map(|v| v.body),
    );
    put(
        "sign.bad-ml-dsa",
        crate::sign::open(&flip(signed.clone(), signed.len() - 1), Kind::Head, 64, a_key).map(|v| v.body),
    );
    put("sign.wrong-signer", crate::sign::open(&signed, Kind::Head, 64, device_key(&f.device_b)).map(|v| v.body));
    // A signer's ID with another device's ML-DSA-44 key: both halves must belong to the signer.
    let mixed = crate::sign::device_public(&f.device_a.id(), &f.device_b.mldsa_public());
    put("sign.mixed-key", crate::sign::open(&signed, Kind::Head, 64, |_| Some(mixed)).map(|v| v.body));
    put(
        "sign.trailing",
        crate::sign::open(&[signed.clone(), vec![0]].concat(), Kind::Head, 64, a_key).map(|v| v.body),
    );
    put("sign.profile-id", Ok(profile.to_vec()));
    put("card.bytes", Ok(f.owner_card.clone()));
    put("card.wrong-profile", Card::open(&f.owner_card, Some(&f.friend.profile_id())).map(|_| vec![]));
    let older = Card { version: 2, ..owner.clone() }.sign(&f.profile)?;
    put("card.rollback", Card::supersedes(&f.owner_card, &older).map(|b| vec![b as u8]));
    let same_version = Card { issued_at: NOW + 1, ..owner.clone() }.sign(&f.profile)?;
    put("card.equivocation", Card::supersedes(&f.owner_card, &same_version).map(|b| vec![b as u8]));
    put("card.newer", Card::supersedes(&older, &f.owner_card).map(|b| vec![b as u8]));
    let duplicate = Card { devices: vec![owner.devices[0].clone(), owner.devices[0].clone()], ..owner.clone() };
    put("card.duplicate-device", duplicate.sign(&f.profile));
    put(
        "card.by-device",
        Card::open(
            &f.device_a.sign(
                Kind::Card,
                wire::encode(&wire::CardBody {
                    profile_key: f.profile.public(),
                    version: 9,
                    issued_at: NOW,
                    devices: owner.devices.clone(),
                    inbox_key: owner.inbox_key,
                    recovery_key: owner.recovery_key,
                    hosts: vec![vl(TENANT_URL.as_bytes())],
                }),
            ),
            None,
        )
        .map(|_| vec![]),
    );

    // Tokens and requests.
    let secret = [0x5a; 32];
    let read = token::issue(&secret, &TENANT, 4, TokenKind::Read, 1);
    put("token.bytes", Ok(read.clone().into_bytes()));
    put(
        "token.check",
        token::check(&secret, &read).map(|c| [c.epoch.to_be_bytes().to_vec(), vec![c.kind as u8]].concat()),
    );
    put("token.wrong-secret", token::check(&[0x5b; 32], &read).map(|_| vec![]));
    let mut forged = b64::decode(&read)?;
    forged[16] ^= 1;
    put("token.altered-epoch", token::check(&secret, &b64::encode(&forged)).map(|_| vec![]));
    let admin = token::issue(&secret, &token::ADMIN_TENANT, 1, TokenKind::Admin, 0);
    put("token.admin", token::check(&secret, &admin).map(|c| vec![c.kind as u8]));
    let contact = token::issue(&secret, &TENANT, 2, TokenKind::Contact, 0);
    put(
        "token.contact",
        token::check(&secret, &contact).map(|c| [c.epoch.to_be_bytes().to_vec(), vec![c.kind as u8]].concat()),
    );
    for (name, kind, epoch) in
        [("token.slot", TokenKind::Slot, 41), ("token.group-read", TokenKind::GroupRead, 3), ("token.group-write", TokenKind::GroupWrite, 3)]
    {
        let t = token::issue(&secret, &TENANT, epoch, kind, 0);
        put(name, token::check(&secret, &t).map(|c| [b64::decode(&t).unwrap_or_default(), vec![c.kind as u8]].concat()));
    }
    let tenant = token::new_tenant(&secret, &mut rng());
    put("token.tenant", Ok(tenant.to_vec()));
    put("token.tenant-check", Ok(vec![token::check_tenant(&secret, &tenant) as u8]));
    let mut other = tenant;
    other[0] ^= 1;
    put("token.tenant-forged", Ok(vec![token::check_tenant(&secret, &other) as u8]));
    let offer = token::offer_secret(&secret, &[0x0f; 16]);
    put("token.offer", token::check_offer(&secret, &offer).map(|id| [offer.to_vec(), id.to_vec()].concat()));
    let mut forged_offer = offer;
    forged_offer[31] ^= 1;
    put("token.offer-forged", token::check_offer(&secret, &forged_offer).map(|id| id.to_vec()));
    let claim = token::claim_digest(&[0x0c; 32]);
    put("token.claim", Ok([claim.to_vec(), vec![token::check_claim(&claim, &[0x0c; 32]) as u8]].concat()));
    put(
        "card.tenant-urls",
        Ok([
            "https://h.example.net/t/EREREREREREREREREREREQ",
            "http://127.0.0.1:4190/t/EREREREREREREREREREREQ",
            "http://h1.localhost:4190/t/EREREREREREREREREREREQ",
            "http://[::1]:4190/t/EREREREREREREREREREREQ",
            "http://h.example.net/t/EREREREREREREREREREREQ",
            "http://localhost.example.net/t/EREREREREREREREREREREQ",
            "https://H.example.net/t/EREREREREREREREREREREQ",
        ]
        .iter()
        .map(|u| crate::card::tenant_url(u).is_ok() as u8)
        .collect()),
    );
    put("token.claim-wrong", Ok(vec![token::check_claim(&claim, &[0x0d; 32]) as u8]));
    let auth = request::sign(&f.device_a, "put", "h7k2.example.net", "/t/x/head", b"{}", NOW, &mut rng());
    put("request.signature", Ok(auth.signature.clone().into_bytes()));
    let verify = |path: &str, body: &[u8], now: u64, key: &Key| {
        request::verify(&auth, "PUT", "h7k2.example.net", path, body, now, device_key(key))
    };
    put("request.verify", verify("/t/x/head", b"{}", NOW + 59_000, &f.device_a).map(|s| s.key.to_vec()));
    put("request.expired", verify("/t/x/head", b"{}", NOW + 61_000, &f.device_a).map(|_| vec![]));
    put("request.altered-path", verify("/t/y/head", b"{}", NOW, &f.device_a).map(|_| vec![]));
    put("request.altered-body", verify("/t/x/head", b"{ }", NOW, &f.device_a).map(|_| vec![]));
    put("request.unknown-device", verify("/t/x/head", b"{}", NOW, &f.device_b).map(|_| vec![]));
    let protocol = request::socket_protocol(&f.device_a, &read, "h7k2.example.net", "x", NOW, &mut rng());
    put("socket.length", Ok((protocol.len() as u32).to_be_bytes().to_vec()));
    put(
        "socket.verify",
        request::verify_socket(&protocol, "h7k2.example.net", "x", NOW, device_key(&f.device_a)).map(|(t, _)| t.into_bytes()),
    );
    put(
        "socket.other-tenant",
        request::verify_socket(&protocol, "h7k2.example.net", "y", NOW, device_key(&f.device_a)).map(|_| vec![]),
    );

    // Objects, head and keyring.
    let (ciphertext, reference) = object::encrypt(b"photo bytes", &mut rng())?;
    put("object.ciphertext", Ok(ciphertext.clone()));
    put("object.name", Ok(object::name(&reference.digest).into_bytes()));
    put("object.decrypt", object::decrypt(&ciphertext, &reference));
    put("object.digest", object::decrypt(&flip(ciphertext.clone(), 3), &reference));
    put("object.wrong-key", object::decrypt(&ciphertext, &ObjectRef { key: [0; 32], ..reference }));
    put("object.wrong-size", object::decrypt(&ciphertext, &ObjectRef { size: 3, ..reference }));
    let (part, part_ref) = object::encrypt_part(br#"{"about":{"name":"Ada"}}"#, &[0x31; 32])?;
    put("object.manifest-part", Ok(part.clone()));
    put("object.manifest-part-key", Ok(part_ref.key.to_vec()));
    put("object.manifest-part-decrypt", object::decrypt(&part, &part_ref));
    let audience_key = [0x21; 32];
    let head_bytes = head::seal(&f.device_a, &profile, &[], 4, 17, NOW, &audience_key, &reference, &mut rng());
    put("head.bytes", Ok(head_bytes.clone()));
    let keys_for = |g: &[u8], n: u64| (g.is_empty() && n == 4).then_some(audience_key);
    put("head.open", head::open(&head_bytes, &owner, Some(17), keys_for).map(|h| wire::encode(&h.manifest)));
    put("head.rollback", head::open(&head_bytes, &owner, Some(18), keys_for).map(|_| vec![]));
    put("head.wrong-generation", head::open(&head_bytes, &owner, None, |_, _| None).map(|_| vec![]));
    put("head.wrong-signer", head::open(&head_bytes, &friend, None, keys_for).map(|_| vec![]));
    let stranger_head = head::seal(&f.stranger, &profile, &[], 4, 18, NOW, &audience_key, &reference, &mut rng());
    put("head.stranger", head::open(&stranger_head, &owner, None, keys_for).map(|_| vec![]));
    let group_head = head::seal(&f.device_a, &profile, &GROUP, 2, 19, NOW, &audience_key, &reference, &mut rng());
    put(
        "head.group",
        head::open(&group_head, &owner, None, |g, n| (g == GROUP && n == 2).then_some(audience_key)).map(|h| h.group),
    );
    put("head.group-as-profile", head::open(&group_head, &owner, None, keys_for).map(|_| vec![]));
    let entry = |r: &str, w: &str, c: &str| head::KeyringTokens { read: r.into(), write: w.into(), contact: c.into() };
    let ring = head::seal_keyring(&profile, 4, &audience_key, &[entry("r", "w", "c"), entry("r2", "w2", "c2")], &mut rng());
    put("keyring.bytes", Ok(ring.clone()));
    put(
        "keyring.open",
        head::open_keyring(&ring, &profile, 4, &audience_key).map(|t| {
            t.iter().map(|t| format!("{}|{}|{}", t.read, t.write, t.contact)).collect::<Vec<_>>().join(",").into_bytes()
        }),
    );
    put("keyring.wrong-generation", head::open_keyring(&ring, &profile, 5, &audience_key).map(|_| vec![]));
    put("keyring.generation", head::keyring_generation(&ring).map(|g| g.to_be_bytes().to_vec()));
    put("keyring.other-profile", head::open_keyring(&ring, &f.friend.profile_id(), 4, &audience_key).map(|_| vec![]));

    // Audience boxes, device seal keys and their records.
    let friend_id = f.friend.profile_id();
    let sealed_box = get(recorded, "audience_box")?;
    put("audience.lookup", Ok(audience::lookup(&FRIENDSHIP, &profile).to_vec()));
    put("audience.direction", Ok(vec![(audience::lookup(&FRIENDSHIP, &friend_id) != audience::lookup(&FRIENDSHIP, &profile)) as u8]));
    let open_box = |friendship: &[u8; 32], owner: &[u8; 32], friend: &[u8; 32], private: &[u8; 32], bytes: &[u8]| {
        audience::open(friendship, owner, friend, private, bytes).map(|(g, k)| [g.to_be_bytes().to_vec(), k.to_vec()].concat())
    };
    put("audience.open", open_box(&FRIENDSHIP, &profile, &friend_id, &f.friend_inbox.private, &sealed_box));
    put("audience.other-friendship", open_box(&[0x30; 32], &profile, &friend_id, &f.friend_inbox.private, &sealed_box));
    put("audience.other-inbox", open_box(&FRIENDSHIP, &profile, &friend_id, &f.inbox.private, &sealed_box));
    put("audience.reversed", open_box(&FRIENDSHIP, &friend_id, &profile, &f.friend_inbox.private, &sealed_box));
    put("audience.tampered", open_box(&FRIENDSHIP, &profile, &friend_id, &f.friend_inbox.private, &flip(sealed_box.clone(), 1200)));
    put(
        "audience.generation-zero",
        audience::seal(&FRIENDSHIP, &profile, &friend_id, &f.friend_inbox.public, 0, &audience_key).map(|(l, _)| l.to_vec()),
    );
    put("device.seal-key", Ok(audience::device_seal_keys(&[2; 32]).public.to_vec()));
    let record_a = audience::seal_key_record(&f.device_a, &profile);
    let record_b = audience::seal_key_record(&f.device_b, &profile);
    put("seal-key.bytes", Ok(record_a.clone()));
    put("seal-key.open", audience::open_seal_key_record(&record_a, &owner).map(|(d, k)| [d.to_vec(), k.to_vec()].concat()));
    put(
        "seal-key.other-profile",
        audience::open_seal_key_record(&audience::seal_key_record(&f.device_a, &friend_id), &owner).map(|_| vec![]),
    );
    put(
        "seal-key.not-in-card",
        audience::open_seal_key_record(&audience::seal_key_record(&f.stranger, &profile), &owner).map(|_| vec![]),
    );

    // Owner key, log and snapshots.
    let o_key = || [0x32u8; 32];
    let record = get(recorded, "owner_key")?;
    let owner_key = log::OwnerKeyRecord::open(&record, |s| owner.device_key(s))?;
    put("owner-key.generation", Ok(owner_key.generation().to_be_bytes().to_vec()));
    let seal_b = audience::device_seal_keys(&[3; 32]);
    put("owner-key.device", owner_key.open_sealed(&profile, &f.device_b.id(), &seal_b.private).map(|k| k.to_vec()));
    put(
        "owner-key.other-device-key",
        owner_key.open_sealed(&profile, &f.device_a.id(), &seal_b.private).map(|k| k.to_vec()),
    );
    put("owner-key.not-sealed-to", owner_key.open_sealed(&profile, &f.stranger.id(), &seal_b.private).map(|k| k.to_vec()));
    put("owner-key.recover", owner_key.recover(&profile, &f.recovery.private).map(|k| k.to_vec()));
    put(
        "owner-key.wrong-signer",
        log::OwnerKeyRecord::open(&record, device_key(&f.device_b)).map(|r| r.generation().to_be_bytes().to_vec()),
    );
    // A device in the card without a seal key record gets no seal.
    let partial = log::seal_owner_key(&f.device_a, &owner, &[record_a.clone()], 2, &o_key())?;
    let partial = log::OwnerKeyRecord::open(&partial, |s| owner.device_key(s))?;
    put("owner-key.without-record", partial.open_sealed(&profile, &f.device_b.id(), &seal_b.private).map(|k| k.to_vec()));
    // Records in any order seal each owner key to the device that signed its record.
    let forged = log::seal_owner_key(&f.device_a, &owner, &[record_b.clone(), record_a.clone()], 2, &o_key())?;
    let forged = log::OwnerKeyRecord::open(&forged, |s| owner.device_key(s))?;
    put("owner-key.both-records", forged.open_sealed(&profile, &f.device_b.id(), &seal_b.private).map(|k| k.to_vec()));
    let o = [0x32; 32];
    let keys = |g: u32| (g == 2).then(|| Zeroizing::new(o));
    let mut r = rng();
    let e0 = log::seal_entry(&f.device_a, &profile, 0, &[0; 32], 2, &o, br#"{"op":0}"#, &mut r)?;
    let e1 = log::seal_entry(&f.device_b, &profile, 1, &log::digest(&e0), 2, &o, br#"{"op":1}"#, &mut r)?;
    let e2 = log::seal_entry(&f.device_a, &profile, 2, &log::digest(&e1), 2, &o, br#"{"op":2}"#, &mut r)?;
    put("log.entries", Ok([e0.clone(), e1.clone(), e2.clone()].concat()));
    put(
        "log.open",
        log::open_entry(&e1, &owner, log::Position { seq: 1, previous: &log::digest(&e0) }, keys).map(|e| e.plaintext),
    );
    put(
        "log.replay",
        log::open_entry(&e0, &owner, log::Position { seq: 1, previous: &log::digest(&e0) }, keys).map(|e| e.plaintext),
    );
    put(
        "log.rollback",
        log::open_entry(&e2, &owner, log::Position { seq: 2, previous: &log::digest(&e0) }, keys).map(|e| e.plaintext),
    );
    put(
        "log.wrong-generation",
        log::open_entry(&e1, &owner, log::Position { seq: 1, previous: &log::digest(&e0) }, |_| None)
            .map(|e| e.plaintext),
    );
    put(
        "log.wrong-signer",
        log::open_entry(&e1, &friend, log::Position { seq: 1, previous: &log::digest(&e0) }, keys).map(|e| e.plaintext),
    );
    let snap = log::seal_snapshot(&f.device_a, &profile, 2, &log::digest(&e2), 2, &o, &reference, &mut rng())?;
    put(
        "snapshot.open",
        log::open_snapshot(&snap, &owner, keys)
            .map(|(s, d, r)| [s.to_be_bytes().to_vec(), d.to_vec(), wire::encode(&r)].concat()),
    );

    // Threads.
    let thread_key = [0x44; 32];
    let entry =
        thread::seal(&f.friend_device, &f.friend_card, &f.friend_card, &thread_key, NOW, br#"{"id":"c1","text":"nice"}"#, &mut rng())?;
    let bare =
        thread::seal(&f.friend_device, &f.friend_card, b"", &thread_key, NOW, br#"{"id":"c2","text":"again"}"#, &mut rng())?;
    put("thread.bare-bytes", Ok(bare.clone()));
    // The thread's owner relays the friend's card in an entry of its own; the card counts for the friend, not the owner.
    let relay = thread::seal(&f.device_a, &f.owner_card, &f.friend_card, &thread_key, NOW, br#"{"type":"card"}"#, &mut rng())?;
    let owner_only = |p: &[u8; 32]| (p == &owner.profile).then(|| owner.clone());
    put(
        "thread.relay",
        thread::open(&relay, &thread_key, owner_only).map(|e| [e.entry, Card::open(&e.card, None).map(|c| c.profile.to_vec()).unwrap_or_default()].concat()),
    );
    put("thread.relay-unknown-owner", thread::open(&relay, &thread_key, |_| None).map(|e| e.entry));
    put("thread.relay-malformed-card", thread::seal(&f.device_a, &f.owner_card, b"not a card", &thread_key, NOW, b"{}", &mut rng()));
    put("thread.id", Ok(thread::id(&thread_key).to_vec()));
    put("thread.bytes", Ok(entry.clone()));
    let cards = |p: &[u8; 32]| [&owner, &friend].into_iter().find(|c| &c.profile == p).cloned();
    put("thread.open", thread::open(&entry, &thread_key, cards).map(|e| e.entry));
    put("thread.unknown-author", thread::open(&entry, &thread_key, |_| None).map(|e| e.entry));
    put("thread.bare", thread::open(&bare, &thread_key, cards).map(|e| e.entry));
    put("thread.bare-unknown-author", thread::open(&bare, &thread_key, |_| None).map(|e| e.entry));
    put("thread.wrong-key", thread::open(&entry, &[0x45; 32], cards).map(|e| e.entry));
    put("thread.seal-not-in-card", thread::seal(&f.stranger, &f.friend_card, &f.friend_card, &thread_key, NOW, b"{}", &mut rng()));
    // An entry signed by a device the carried card doesn't list.
    let body = wire::ThreadEntryBody {
        author: f.friend.profile_id(),
        thread: thread::id(&thread_key),
        created_at: NOW,
        card: wire::vl(f.friend_card.clone()),
        entry: wire::vl(b"{}".to_vec()),
    };
    let signed = f.stranger.sign(crate::sign::Kind::ThreadEntry, wire::encode(&body));
    let nonce = [0x46; 12];
    let impostor = wire::encode(&wire::SealedBox {
        nonce,
        sealed: wire::vl(crate::aead::seal(
            &thread_key,
            &nonce,
            &kdf::labeled("thread entry", &[&thread::id(&thread_key)]),
            &signed,
        )),
    });
    put("thread.impostor", thread::open(&impostor, &thread_key, cards).map(|e| e.entry));
    // A newer card the reader holds, without the signing device, overrides the older card the entry carries.
    let newer = Card {
        version: 2,
        devices: vec![device_entry(6, NOW)?],
        ..friend.clone()
    }
    .sign(&f.friend)?;
    let newer = Card::open(&newer, None)?;
    put("thread.removed-device", thread::open(&entry, &thread_key, |_| Some(newer.clone())).map(|e| e.entry));
    put("thread.bare-removed-device", thread::open(&bare, &thread_key, |_| Some(newer.clone())).map(|e| e.entry));

    // Device inbox keys.
    let (friend_key, friend_private) = inbox_key(&f.friend_device, &friend_id, 0xd5);
    let (own_key, _) = inbox_key(&f.device_a, &profile, 0xd2);
    put("devicekey.bytes", Ok(friend_key.clone()));
    put("devicekey.open", devicekey::open(&friend_key, &friend).map(|k| [k.device.to_vec(), k.created_at.to_be_bytes().to_vec(), k.key.to_vec()].concat()));
    put("devicekey.other-card", devicekey::open(&friend_key, &owner).map(|_| vec![]));
    put("devicekey.not-in-card", devicekey::open(&inbox_key(&f.stranger, &friend_id, 0xd6).0, &friend).map(|_| vec![]));
    let malformed_key = f.friend_device.sign(
        Kind::DeviceKey,
        wire::encode(&wire::DeviceKeyBody { profile: friend_id, created_at: KEYS_AT, key: [0xff; 1216] }),
    );
    put("devicekey.bad-key", devicekey::open(&malformed_key, &friend).map(|_| vec![]));
    let (newer, _) = devicekey::create(&f.friend_device, &friend_id, KEYS_AT + 1, &mut ChaCha20Rng::from_seed([0xd7; 32]));
    put(
        "devicekey.newest-per-device",
        Ok(devicekey::usable(&[friend_key.clone(), newer, own_key.clone()], &friend).iter().map(|k| k.created_at.to_be_bytes()).collect::<Vec<_>>().concat()),
    );

    // Inbox.
    let boxed = get(recorded, "inbox_box")?;
    let friend_device = f.friend_device.id();
    let private = |at: u64| (at == KEYS_AT).then(|| friend_private.clone());
    put(
        "inbox.open",
        inbox::open(&boxed, &friend_id, &friend_device, private, NOW, cards, |_| false)
            .map(|i| [i.id.to_vec(), i.payload, i.keys.concat()].concat()),
    );
    put("inbox.replay", inbox::open(&boxed, &friend_id, &friend_device, private, NOW, cards, |_| true).map(|_| vec![]));
    put(
        "inbox.expired",
        inbox::open(&boxed, &friend_id, &friend_device, private, NOW + inbox::MAX_AGE_MS, cards, |_| false).map(|_| vec![]),
    );
    put("inbox.unknown-sender", inbox::open(&boxed, &friend_id, &friend_device, private, NOW, |_| None, |_| false).map(|_| vec![]));
    // The key deleted, or another device: nothing opens.
    put("inbox.key-deleted", inbox::open(&boxed, &friend_id, &friend_device, |_| None, NOW, cards, |_| false).map(|_| vec![]));
    put("inbox.other-device", inbox::open(&boxed, &friend_id, &f.device_a.id(), private, NOW, cards, |_| false).map(|_| vec![]));
    put("inbox.wrong-recipient", inbox::open(&boxed, &profile, &friend_device, private, NOW, cards, |_| false).map(|_| vec![]));
    let seal_to = |records: &[Vec<u8>]| {
        inbox::seal(&f.device_a, &profile, &friend, records, &[], [0x44; 16], NOW, inbox::kind::MESSAGE, b"{}", &mut rng())
    };
    put("inbox.no-device-key", seal_to(&[]));
    put("inbox.only-other-profile-keys", seal_to(&[own_key.clone()]));

    // A question carries the sender's card, so someone who holds no card for the sender opens it.
    let question = |device: &Key, card: &[u8]| -> Result<Vec<u8>> {
        let payload = wire::encode(&wire::Question { card: vl(card.to_vec()), body: vl(br#"{"text":"Still for sale?"}"#.to_vec()) });
        let sealed = inbox::seal(device, &profile, &friend, &[friend_key.clone()], &[], [0x43; 16], NOW - 1000, inbox::kind::QUESTION, &payload, &mut rng())?;
        inbox::open(&sealed, &friend_id, &friend_device, private, NOW, |_| None, |_| false).map(|i| [vec![i.kind as u8], i.payload].concat())
    };
    put("inbox.question", question(&f.device_a, &f.owner_card));
    put("inbox.question-other-card", question(&f.device_a, &f.friend_card));
    put("inbox.question-signer-not-in-card", question(&f.stranger, &f.owner_card));

    // Invitations and device links.
    let s = [0x61; 32];
    let h = [0x62; 32];
    let public = InvitePublic { card: vl(f.owner_card.clone()), name: vl("Ada".as_bytes()) };
    let keys_in = InviteKeys {
        generation: 4,
        audience_key,
        keyring: vl(ring.clone()),
        offer: vl(vec![]),
        head: vl(vec![]),
        objects: vec![],
        keys: vec![vl(own_key.clone())],
    };
    let (lookup, invitation) = invite::create(&s, &h, NOW + 86_400_000, NOW, &public, &keys_in, &mut rng())?;
    put("invite.lookup", Ok(lookup.to_vec()));
    put("invite.bytes", Ok(invitation.clone()));
    put("invite.public", invite::open_public(&invitation, &s, NOW).map(|(_, p)| p.name.as_slice().to_vec()));
    put("invite.keys", invite::open_keys(&invitation, &s, &h, NOW).map(|k| k.audience_key.to_vec()));
    put("invite.without-release", invite::open_keys(&invitation, &s, &[0; 32], NOW).map(|k| k.audience_key.to_vec()));
    let carrying = InviteKeys {
        head: vl(b"head".to_vec()),
        objects: vec![vl(b"root".to_vec()), vl(b"page".to_vec())],
        ..keys_in.clone()
    };
    let (_, carried) = invite::create(&s, &h, NOW + 86_400_000, NOW, &public, &carrying, &mut rng())?;
    put("invite.carries", invite::open_keys(&carried, &s, &h, NOW).map(|k| wire::encode(&(k.keyring, k.head, k.objects))));
    let mismatched = InviteKeys { generation: 5, ..keys_in.clone() };
    let (_, mismatched) = invite::create(&s, &h, NOW + 86_400_000, NOW, &public, &mismatched, &mut rng())?;
    put("invite.keyring-generation", invite::open_keys(&mismatched, &s, &h, NOW).map(|k| k.audience_key.to_vec()));
    put("invite.expired", invite::open_public(&invitation, &s, NOW + 86_400_000).map(|_| vec![]));
    put(
        "invite.too-long",
        invite::create(&s, &h, NOW + invite::MAX_LIFETIME_MS + 1, NOW, &public, &keys_in, &mut rng()).map(|(_, b)| b),
    );
    let url = invite::link(&s, TENANT_URL);
    let proof = invite::acceptance_proof(&s, &f.friend_card);
    put("invite.acceptance-proof", Ok(proof.to_vec()));
    put("invite.acceptance-checks", Ok(vec![invite::check_acceptance(&s, &f.friend_card, &proof) as u8]));
    put(
        "invite.acceptance-wrong-secret",
        Ok(vec![invite::check_acceptance(&[0x01; 32], &f.friend_card, &proof) as u8]),
    );
    put("invite.link", Ok(url.clone().into_bytes()));
    put(
        "invite.parse",
        invite::parse_fragment(url.split_once('#').unwrap().1).map(|(s, u)| [s.to_vec(), u.into_bytes()].concat()),
    );
    let l = [0x71; 32];
    let req = link::request(&l, &f.device_b.public(), "Laptop");
    put("link.request", Ok(req.clone()));
    put("link.check", link::check_request(&l, &req).map(|(d, k, n)| [d.to_vec(), k.to_vec(), n.into_bytes()].concat()));
    let mut swapped: wire::LinkRequest = wire::decode(&req, 4096, "link request")?;
    swapped.signing_key = f.device_a.mldsa_public();
    put("link.other-signing-key", link::check_request(&l, &wire::encode(&swapped)).map(|_| vec![]));
    put("link.wrong-secret", link::check_request(&[0x72; 32], &req).map(|_| vec![]));
    put("link.code", Ok(link::code(&l, &f.device_a.id(), &f.device_b.id()).into_bytes()));
    let reply = LinkReplyBody {
        card: vl(f.owner_card.clone()),
        owner_keys: vec![OwnerKey { generation: 1, key: [0x31; 32] }, OwnerKey { generation: 2, key: [0x32; 32] }],
    };
    let sealed_reply = link::seal_reply(&l, &reply, &mut rng());
    put("link.reply", link::open_reply(&l, &sealed_reply).map(|r| wire::encode(&r.owner_keys)));
    put("link.reply-wrong-secret", link::open_reply(&[0x72; 32], &sealed_reply).map(|_| vec![]));
    let link_url = link::url(&l, TENANT_URL, &read, &f.device_a.id(), link::Kind::Compare);
    put(
        "link.parse",
        link::parse_fragment(link_url.split_once('#').unwrap().1).map(|p| {
            [p.secret.to_vec(), p.tenant_url.into_bytes(), p.write_token.into_bytes(), p.existing.to_vec()].concat()
        }),
    );
    let scan = link::url(&l, TENANT_URL, &read, &f.device_a.id(), link::Kind::Scan);
    put(
        "link.parse-scan",
        link::parse_fragment(scan.split_once('#').unwrap().1)
            .map(|p| [p.kind == link::Kind::Scan].map(u8::from).to_vec()),
    );
    put(
        "link.parse-unknown-kind",
        link::parse_fragment(&format!("{}.later", link_url.split_once('#').unwrap().1)).map(|_| vec![]),
    );

    // Recovery.
    let written = recovery::written(&f.profile.seed());
    put("recovery.written", Ok(written.as_bytes().to_vec()));
    put("recovery.read", recovery::read_written(&written.to_lowercase().replace('-', " ")).map(|s| s.to_vec()));
    let mut wrong = written.to_string();
    let last = wrong.pop().unwrap();
    wrong.push(if last == 'A' { 'B' } else { 'A' });
    put("recovery.checksum", recovery::read_written(&wrong).map(|s| s.to_vec()));
    put("recovery.public", Ok(f.recovery.public.to_vec()));
    let prf = [0x81; 32];
    let backup = recovery::seal_passkey_backup(&prf, &profile, &f.profile.seed(), &mut rng());
    put("passkey.bytes", Ok(backup.clone()));
    put("passkey.open", recovery::open_passkey_backup(&prf, &profile, &backup).map(|s| s.to_vec()));
    put("passkey.wrong-prf", recovery::open_passkey_backup(&[0x82; 32], &profile, &backup).map(|s| s.to_vec()));
    put("passkey.handle", recovery::user_handle(TENANT_URL));
    put(
        "passkey.read-handle",
        recovery::read_user_handle(&recovery::user_handle(TENANT_URL)?)
            .map(|(t, u)| [t.to_vec(), u.unwrap_or_default().into_bytes()].concat()),
    );
    let long_host = format!("https://{}.example.net/t/EREREREREREREREREREREQ", "h".repeat(40));
    put("passkey.handle-long-host", recovery::user_handle(&long_host));
    put(
        "passkey.read-handle-scheme",
        recovery::read_user_handle(&[[0x11; 16].as_slice(), &[2], b"h7k2.example.net"].concat()).map(|_| vec![]),
    );

    // Locked browsers.
    let local_key = local::new_key(&mut rng());
    let lock = local::lock(&local_key, &prf, &f.profile.seed(), &profile, &mut rng());
    put("local.lock", Ok(lock.clone()));
    put("local.open-passkey", local::open_with_passkey(&lock, &prf, &profile).map(|k| k.to_vec()));
    put("local.open-seed", local::open_with_seed(&lock, &f.profile.seed(), &profile).map(|k| k.to_vec()));
    put("local.wrong-prf", local::open_with_passkey(&lock, &[0x82; 32], &profile).map(|k| k.to_vec()));
    put("local.other-profile", local::open_with_seed(&lock, &f.profile.seed(), &f.friend.profile_id()).map(|k| k.to_vec()));
    let relocked = local::relock_passkey(&lock, &local_key, &[0x83; 32], &profile, &mut rng())?;
    put("local.relock-passkey", local::open_with_passkey(&relocked, &[0x83; 32], &profile).map(|k| k.to_vec()));
    put("local.relock-seed", local::open_with_seed(&relocked, &f.profile.seed(), &profile).map(|k| k.to_vec()));
    let record = local::seal_record(&local_key, "rows", "friend:x", b"{}", &mut rng());
    put("local.record", Ok(record.clone()));
    put("local.record-open", local::open_record(&local_key, "rows", "friend:x", &record));
    put("local.record-moved", local::open_record(&local_key, "rows", "friend:y", &record));
    put("local.record-store", local::open_record(&local_key, "vault", "friend:x", &record));
    let file = local::seal_file(&local_key, "own/p/h", b"jpeg", &mut rng());
    put("local.file", Ok(file.clone()));
    put("local.file-open", local::open_file(&local_key, "own/p/h", &file));
    put("local.file-moved", local::open_file(&local_key, "own/p/g", &file));
    let name = local::seal_name(&local_key, "friend");
    put("local.name", Ok(name.clone().into_bytes()));
    put("local.name-open", local::open_name(&local_key, &name).map(String::into_bytes));
    put("local.name-empty", local::open_name(&local_key, &local::seal_name(&local_key, "")).map(String::into_bytes));
    let mut forged = b64::decode(&name)?;
    forged[16] ^= 1;
    put("local.name-forged", local::open_name(&local_key, &b64::encode(&forged)).map(String::into_bytes));

    // Transfer.
    let grant = transfer::grant(&f.device_a, &TENANT, "https://new.example.com", NOW + 3_600_000);
    put("transfer.check", transfer::check(&grant, &owner, &TENANT, "https://new.example.com", NOW).map(|_| vec![1]));
    put(
        "transfer.other-host",
        transfer::check(&grant, &owner, &TENANT, "https://evil.example.com", NOW).map(|_| vec![]),
    );
    put(
        "transfer.expired",
        transfer::check(&grant, &owner, &TENANT, "https://new.example.com", NOW + 3_600_000).map(|_| vec![]),
    );

    // Access boxes.
    let a = [0x61; 32];
    let access = access::Access {
        group: GROUP,
        generation: 3,
        keys: vec![[0x63; 32], [0x62; 32]],
        read_token: token::issue(&secret, &TENANT, 3, TokenKind::GroupRead, 0),
        write_token: token::issue(&secret, &TENANT, 3, TokenKind::GroupWrite, 0),
        name: "Elm Street market".into(),
        tenant: TENANT_URL.into(),
        offer: Some(wire::HostingOffer { tenant_host: vl("https://h7k2.example.net"), secret: [0x0f; 32], quota: 100 << 20 }),
    };
    put("access.lookup", Ok(access::lookup(&a).to_vec()));
    put("access.wall-key", Ok([access::wall_key(&[0x63; 32], 1), access::wall_key(&[0x63; 32], 7)].concat()));
    let access_box = access::seal(&a, &access, &mut rng())?;
    put("access.bytes", Ok(access_box.clone()));
    let opened = |r: Result<access::Access>| {
        r.map(|o| {
            [
                o.group.to_vec(),
                o.generation.to_be_bytes().to_vec(),
                o.keys.concat(),
                o.read_token.into_bytes(),
                o.write_token.into_bytes(),
                o.name.into_bytes(),
                o.tenant.into_bytes(),
                o.offer.map(|x| wire::encode(&x)).unwrap_or_default(),
            ]
            .concat()
        })
    };
    put("access.open", opened(access::open(&a, &access_box)));
    put("access.wrong-secret", opened(access::open(&[0x60; 32], &access_box)));
    put("access.tampered", opened(access::open(&a, &flip(access_box.clone(), 20))));
    put(
        "access.too-many-keys",
        access::seal(&a, &access::Access { keys: vec![[1; 32]; 5], generation: 5, ..access.clone() }, &mut rng()),
    );
    put(
        "access.generation-below-keys",
        access::seal(&a, &access::Access { generation: 1, ..access.clone() }, &mut rng()),
    );
    put("access.bad-tenant", access::seal(&a, &access::Access { tenant: "https://example.net/x".into(), ..access.clone() }, &mut rng()));
    put(
        "access.without-offer",
        opened(access::seal(&a, &access::Access { offer: None, ..access.clone() }, &mut rng()).and_then(|b| access::open(&a, &b))),
    );

    // RFC 9180, Appendix A.1.1 and A.1.2: the key schedule from the shared secret on, in base and PSK mode.
    let hex = |v: &Value, name: &str| -> Result<Vec<u8>> {
        let text = v.get(name).and_then(Value::as_str).ok_or(Error::Malformed("standards vector"))?;
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| Error::Malformed("hex")))
            .collect()
    };
    let list = |path: &str| -> Result<Vec<Value>> {
        standards.pointer(path).and_then(Value::as_array).cloned().ok_or(Error::Malformed("standards vector"))
    };
    for (i, case) in list("/rfc9180/cases")?.iter().enumerate() {
        let shared: [u8; 32] = hex(case, "shared_secret")?.try_into().map_err(|_| Error::Malformed("standards vector"))?;
        let (psk, psk_id) = (hex(case, "psk")?, hex(case, "psk_id")?);
        let psk = (!psk.is_empty()).then_some(hpke::Psk { key: &psk, id: &psk_id });
        let (key, nonce) = hpke::schedule::<16>(b"HPKE\x00\x20\x00\x01\x00\x01", &shared, &hex(case, "info")?, psk)?;
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let ct = aes_gcm::Aes128Gcm::new_from_slice(&*key)
            .expect("16-byte key")
            .encrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: &hex(case, "pt")?, aad: &hex(case, "aad")? })
            .map_err(|_| Error::Decrypt)?;
        put(
            &format!("rfc9180.{i}"),
            Ok(vec![(key.to_vec() == hex(case, "key")?) as u8, (nonce.to_vec() == hex(case, "base_nonce")?) as u8, (ct == hex(case, "ct")?) as u8]),
        );
    }
    // X-Wing, draft-connolly-cfrg-xwing-kem-06, Appendix C.
    for (i, case) in list("/xwing/cases")?.iter().enumerate() {
        let seed: [u8; 32] = hex(case, "seed")?.try_into().map_err(|_| Error::Malformed("standards vector"))?;
        let eseed: [u8; 64] = hex(case, "eseed")?.try_into().map_err(|_| Error::Malformed("standards vector"))?;
        let public = xwing::public(&seed);
        let (enc, shared) = xwing::encapsulate(&public, &eseed)?;
        let opened = xwing::decapsulate(&seed, &hex(case, "ct")?)?;
        put(
            &format!("xwing.{i}"),
            Ok(vec![
                (public.to_vec() == hex(case, "pk")?) as u8,
                (enc.to_vec() == hex(case, "ct")?) as u8,
                (shared.to_vec() == hex(case, "ss")?) as u8,
                (opened.to_vec() == hex(case, "ss")?) as u8,
            ]),
        );
    }
    put("xwing.short-enc", xwing::decapsulate(&[1; 32], &[0; 100]).map(|s| s.to_vec()));
    Ok(out)
}

/// Builds `vectors/format.json`: fresh recorded inputs and the outcomes they produce.
pub fn generate(standards: &Value) -> Result<Value> {
    let recorded = record()?;
    let expected = outcomes(recorded.as_object().unwrap(), standards)?;
    Ok(json!({ "recorded": recorded, "expected": expected }))
}

/// Runs every case and compares it with the vectors file. Returns the report every target must match.
pub fn check(format_json: &str, standards_json: &str) -> Value {
    let run = || -> Result<(BTreeMap<String, String>, BTreeMap<String, String>)> {
        let file: Value = serde_json::from_str(format_json).map_err(|_| Error::Malformed("vectors"))?;
        let rfc: Value = serde_json::from_str(standards_json).map_err(|_| Error::Malformed("vectors"))?;
        let recorded = file.get("recorded").and_then(Value::as_object).ok_or(Error::Malformed("vectors"))?;
        let expected: BTreeMap<String, String> =
            serde_json::from_value(file.get("expected").cloned().ok_or(Error::Malformed("vectors"))?)
                .map_err(|_| Error::Malformed("vectors"))?;
        Ok((outcomes(recorded, &rfc)?, expected))
    };
    match run() {
        Err(e) => json!({ "cases": 0, "failures": [format!("setup: {e}")], "digest": "" }),
        Ok((actual, expected)) => {
            let mut failures: Vec<String> = Vec::new();
            for (name, want) in &expected {
                match actual.get(name) {
                    Some(got) if got == want => {}
                    Some(got) => failures.push(format!("{name}: expected {want:.40} got {got:.40}")),
                    None => failures.push(format!("{name}: missing")),
                }
            }
            for name in actual.keys().filter(|n| !expected.contains_key(*n)) {
                failures.push(format!("{name}: not in vectors"));
            }
            let canonical = serde_json::to_vec(&actual).expect("in-memory encoding");
            json!({ "cases": actual.len(), "failures": failures, "digest": b64::encode(&kdf::sha256(&canonical)) })
        }
    }
}
