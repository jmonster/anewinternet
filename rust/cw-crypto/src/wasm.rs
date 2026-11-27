//! JavaScript bindings for browsers and the Worker.
//!
//! Bytes cross as `Uint8Array`. Structured results are JSON strings whose byte fields are base64url. Times and
//! counters are numbers. A card lookup is a JavaScript function from a profile ID to that profile's signed card
//! (or `undefined`), so every signer check stays here.
use rand::rngs::OsRng;
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::card::Card;
use crate::object::JsonRef;
use crate::sign::{self, Key};
use crate::wire::{self, vl, DeviceEntry, HostingOffer, InviteKeys, InvitePublic, LinkReplyBody, ObjectRef, OwnerKey};
use crate::{
    access, audience, b64, card, head, hpke, inbox, invite, link, local, log, object, recovery, request, thread, transfer,
    Error,
};

type R<T> = core::result::Result<T, JsError>;

fn fail(e: Error) -> JsError {
    JsError::new(&format!("{}: {e}", e.code()))
}

fn arr<const N: usize>(bytes: &[u8], what: &'static str) -> R<[u8; N]> {
    bytes.try_into().map_err(|_| fail(Error::Malformed(what)))
}

thread_local! {
    /// The signing keys of the last few seeds: a device signs with its own seed again and again, and making the
    /// ML-DSA-44 key costs more than a signature.
    static KEYS: core::cell::RefCell<Vec<([u8; 32], std::rc::Rc<Key>)>> = const { core::cell::RefCell::new(Vec::new()) };
}

/// A profile key, never kept: the profile seed lives only for the one change it was opened for.
fn profile_key(seed: &[u8]) -> R<Key> {
    Ok(Key::from_seed(&Zeroizing::new(arr::<32>(seed, "seed")?)))
}

/// A device or admin key, kept among the last few.
fn key(seed: &[u8]) -> R<std::rc::Rc<Key>> {
    let seed = Zeroizing::new(arr::<32>(seed, "seed")?);
    if let Some(k) = KEYS.with(|k| k.borrow().iter().find(|(s, _)| s == &*seed).map(|(_, k)| k.clone())) {
        return Ok(k);
    }
    let k = std::rc::Rc::new(Key::from_seed(&seed));
    KEYS.with(|keys| {
        let mut keys = keys.borrow_mut();
        if keys.len() == 4 {
            keys.remove(0);
        }
        keys.push((*seed, k.clone()));
    });
    Ok(k)
}

fn time(n: f64) -> u64 {
    if n.is_finite() && n >= 0.0 {
        n as u64
    } else {
        0
    }
}

fn parse(text: &str) -> R<Value> {
    serde_json::from_str(text).map_err(|_| fail(Error::Malformed("json")))
}

fn field<'a>(v: &'a Value, name: &'static str) -> R<&'a str> {
    v[name].as_str().ok_or(fail(Error::Malformed(name)))
}

fn bytes_field(v: &Value, name: &'static str) -> R<Vec<u8>> {
    b64::decode(field(v, name)?).map_err(fail)
}

fn array_field<const N: usize>(v: &Value, name: &'static str) -> R<[u8; N]> {
    b64::decode_array(field(v, name)?).map_err(fail)
}

fn number(v: &Value, name: &'static str) -> R<u64> {
    v[name].as_u64().ok_or(fail(Error::Malformed(name)))
}

fn reference_json(r: &ObjectRef) -> Value {
    serde_json::to_value(JsonRef::from(r)).expect("object reference")
}

fn reference(text: &str) -> R<ObjectRef> {
    let r: JsonRef = serde_json::from_str(text).map_err(|_| fail(Error::Malformed("object reference")))?;
    ObjectRef::try_from(&r).map_err(fail)
}

fn list(v: &Value, name: &'static str) -> R<Vec<Vec<u8>>> {
    v[name]
        .as_array()
        .ok_or(fail(Error::Malformed(name)))?
        .iter()
        .map(|x| b64::decode(x.as_str().unwrap_or("!")).map_err(fail))
        .collect()
}

/// A list of base64url byte strings, or none when the field is absent.
fn optional_list(v: &Value, name: &'static str) -> R<Vec<tls_codec::VLBytes>> {
    if v[name].is_null() {
        return Ok(Vec::new());
    }
    Ok(list(v, name)?.into_iter().map(vl).collect())
}

fn encoded_list(items: &[Vec<u8>]) -> Value {
    Value::Array(items.iter().map(|b| Value::String(b64::encode(b))).collect())
}

/// A result with bytes and a JSON description.
#[wasm_bindgen]
pub struct Out {
    bytes: Vec<u8>,
    json: String,
}

#[wasm_bindgen]
impl Out {
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn json(&self) -> String {
        self.json.clone()
    }
}

fn out(bytes: Vec<u8>, json: Value) -> Out {
    Out { bytes, json: json.to_string() }
}

/// Looks up and verifies a profile's card through the caller's function.
fn card_lookup(f: &js_sys::Function) -> impl Fn(&[u8; 32]) -> Option<Card> + '_ {
    move |profile: &[u8; 32]| {
        let arg = js_sys::Uint8Array::from(&profile[..]);
        let value = f.call1(&JsValue::NULL, &arg).ok()?;
        if value.is_undefined() || value.is_null() {
            return None;
        }
        let bytes = js_sys::Uint8Array::new(&value).to_vec();
        Card::open(&bytes, Some(profile)).ok()
    }
}

/// Runs the format vectors and the standards' (RFC 9180, X-Wing); returns the report as JSON.
#[wasm_bindgen]
pub fn selftest(format_json: &str, standards_json: &str) -> String {
    crate::vectors::check(format_json, standards_json).to_string()
}

// Keys

/// The device ID of a device seed: the Ed25519 half of its public key.
#[wasm_bindgen]
pub fn device_id(seed: &[u8]) -> R<Vec<u8>> {
    Ok(sign::id_of(&arr(seed, "seed")?).to_vec())
}

/// The ML-DSA-44 half of a device's public key, which the card lists beside its ID.
#[wasm_bindgen]
pub fn signing_key(seed: &[u8]) -> R<Vec<u8>> {
    Ok(key(seed)?.mldsa_public().to_vec())
}

/// The profile ID of a profile seed.
#[wasm_bindgen]
pub fn profile_id(seed: &[u8]) -> R<Vec<u8>> {
    Ok(profile_key(seed)?.profile_id().to_vec())
}

/// The recovery key pair derived from a profile seed: JSON `{public, private}`.
/// The digest a new host keeps of its claim secret (docs/format.md).
#[wasm_bindgen]
pub fn claim_digest(claim: &[u8]) -> R<Vec<u8>> {
    Ok(crate::token::claim_digest(&arr::<32>(claim, "claim")?).to_vec())
}

#[wasm_bindgen]
pub fn recovery_keys(seed: &[u8]) -> R<String> {
    let pair = recovery::recovery_keys(&arr::<32>(seed, "seed")?);
    Ok(json!({ "public": b64::encode(&pair.public), "private": b64::encode(&*pair.private) }).to_string())
}

#[wasm_bindgen]
pub fn recovery_written(seed: &[u8]) -> R<String> {
    Ok(recovery::written(&arr::<32>(seed, "seed")?).to_string())
}

#[wasm_bindgen]
pub fn recovery_read(text: &str) -> R<Vec<u8>> {
    Ok(recovery::read_written(text).map_err(fail)?.to_vec())
}

/// The device's own seal key record for `profile`, which it keeps in the own log.
#[wasm_bindgen]
pub fn seal_key_record(seed: &[u8], profile: &[u8]) -> R<Vec<u8>> {
    Ok(audience::seal_key_record(&*key(seed)?, &arr(profile, "profile")?))
}

/// The device a seal key record belongs to, once it verifies against the card.
#[wasm_bindgen]
pub fn seal_key_device(record: &[u8], card_bytes: &[u8]) -> R<Vec<u8>> {
    let c = Card::open(card_bytes, None).map_err(fail)?;
    Ok(audience::open_seal_key_record(record, &c).map_err(fail)?.0.to_vec())
}

/// A new inbox key pair: JSON `{public, private}`.
#[wasm_bindgen]
pub fn inbox_keys() -> R<String> {
    let pair = hpke::generate(&mut OsRng);
    Ok(json!({ "public": b64::encode(&pair.public), "private": b64::encode(&*pair.private) }).to_string())
}

// Cards

fn card_json(c: &Card) -> Value {
    json!({
        "profile": b64::encode(&c.profile),
        "version": c.version,
        "issued_at": c.issued_at,
        "profile_key": b64::encode(&c.profile_key),
        "devices": c.devices.iter().map(|d| json!({ "device": b64::encode(&d.device), "signing_key": b64::encode(&d.signing_key), "added_at": d.added_at })).collect::<Vec<_>>(),
        "inbox_key": b64::encode(&c.inbox_key),
        "recovery_key": b64::encode(&c.recovery_key),
        "hosts": c.hosts,
    })
}

/// Signs a card with the profile seed. `card` is the JSON form `card_open` returns, without `profile` and
/// `profile_key`.
#[wasm_bindgen]
pub fn card_sign(profile_seed: &[u8], card: &str) -> R<Vec<u8>> {
    let profile = profile_key(profile_seed)?;
    let v = parse(card)?;
    let devices = v["devices"]
        .as_array()
        .ok_or(fail(Error::Malformed("devices")))?
        .iter()
        .map(|d| {
            Ok(DeviceEntry {
                device: array_field(d, "device")?,
                signing_key: array_field(d, "signing_key")?,
                added_at: number(d, "added_at")?,
            })
        })
        .collect::<R<Vec<_>>>()?;
    let hosts = v["hosts"]
        .as_array()
        .ok_or(fail(Error::Malformed("hosts")))?
        .iter()
        .map(|h| h.as_str().map(str::to_string).ok_or(fail(Error::Malformed("hosts"))))
        .collect::<R<Vec<_>>>()?;
    let c = Card {
        profile: profile.profile_id(),
        profile_key: profile.public(),
        version: number(&v, "version")?,
        issued_at: number(&v, "issued_at")?,
        devices,
        inbox_key: array_field(&v, "inbox_key")?,
        recovery_key: array_field(&v, "recovery_key")?,
        hosts,
    };
    c.sign(&profile).map_err(fail)
}

/// Verifies a card, optionally for a known profile, and returns its JSON form.
#[wasm_bindgen]
pub fn card_open(bytes: &[u8], profile: Option<Vec<u8>>) -> R<String> {
    let profile = profile.map(|p| arr::<32>(&p, "profile")).transpose()?;
    Ok(card_json(&Card::open(bytes, profile.as_ref()).map_err(fail)?).to_string())
}

/// Whether `next` replaces `known`; refuses a lower version or a different card at the same version.
#[wasm_bindgen]
pub fn card_supersedes(known: &[u8], next: &[u8]) -> R<bool> {
    Card::supersedes(known, next).map_err(fail)
}

/// The tenant ID of a tenant URL.
#[wasm_bindgen]
pub fn tenant_of(url: &str) -> R<Vec<u8>> {
    Ok(card::tenant_url(url).map_err(fail)?.to_vec())
}

// Requests

/// Headers for an owner request: JSON `{"cw-device", "cw-time", "cw-nonce", "cw-signature"}`.
#[wasm_bindgen]
pub fn sign_request(seed: &[u8], method: &str, authority: &str, path: &str, body: &[u8], now: f64) -> R<String> {
    let a = request::sign(&*key(seed)?, method, authority, path, body, time(now), &mut OsRng);
    Ok(json!({ "cw-device": a.key, "cw-time": a.time, "cw-nonce": a.nonce, "cw-signature": a.signature }).to_string())
}

/// The same signature for administration, keyed by the admin key.
#[wasm_bindgen]
pub fn sign_admin(seed: &[u8], method: &str, authority: &str, path: &str, body: &[u8], now: f64) -> R<String> {
    let a = request::sign(&*key(seed)?, method, authority, path, body, time(now), &mut OsRng);
    Ok(json!({ "cw-admin": a.key, "cw-time": a.time, "cw-nonce": a.nonce, "cw-signature": a.signature }).to_string())
}

#[wasm_bindgen]
pub fn socket_protocol(seed: &[u8], token: &str, authority: &str, tenant: &str, now: f64) -> R<String> {
    Ok(request::socket_protocol(&*key(seed)?, token, authority, tenant, time(now), &mut OsRng))
}

// Objects

/// Encrypts a new object: the ciphertext, with its reference as JSON.
#[wasm_bindgen]
pub fn object_encrypt(plaintext: &[u8]) -> R<Out> {
    let (ciphertext, r) = object::encrypt(plaintext, &mut OsRng).map_err(fail)?;
    Ok(out(ciphertext, reference_json(&r)))
}

/// Encrypts under a given key, which reproduces an object's exact ciphertext from its plaintext.
#[wasm_bindgen]
pub fn object_encrypt_with_key(plaintext: &[u8], key: &[u8]) -> R<Out> {
    let (ciphertext, r) = object::encrypt_with_key(plaintext, arr(key, "object key")?).map_err(fail)?;
    Ok(out(ciphertext, reference_json(&r)))
}

/// A manifest part under the current owner key: the ciphertext and its reference.
#[wasm_bindgen]
pub fn manifest_part(plaintext: &[u8], owner_key: &[u8]) -> R<Out> {
    let (ciphertext, r) = object::encrypt_part(plaintext, &arr(owner_key, "owner key")?).map_err(fail)?;
    Ok(out(ciphertext, reference_json(&r)))
}

#[wasm_bindgen]
pub fn object_decrypt(ciphertext: &[u8], reference_text: &str) -> R<Vec<u8>> {
    object::decrypt(ciphertext, &reference(reference_text)?).map_err(fail)
}

/// A random 32-byte key for a thread, a link or an invitation.
#[wasm_bindgen]
pub fn random_key() -> Vec<u8> {
    crate::aead::random::<32>(&mut OsRng).to_vec()
}

// Heads and keyrings

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn head_seal(
    seed: &[u8],
    profile: &[u8],
    group: &[u8],
    generation: f64,
    revision: f64,
    published_at: f64,
    key_bytes: &[u8],
    manifest: &str,
) -> R<Vec<u8>> {
    Ok(head::seal(
        &*key(seed)?,
        &arr(profile, "profile")?,
        group,
        time(generation),
        time(revision),
        time(published_at),
        &arr(key_bytes, "head key")?,
        &reference(manifest)?,
        &mut OsRng,
    ))
}

/// The unverified group, generation and revision of a head, to choose its key.
#[wasm_bindgen]
pub fn head_peek(bytes: &[u8]) -> R<String> {
    let s: wire::Signed = wire::decode(bytes, head::LIMIT + sign::SIGNATURE + 64, "head").map_err(fail)?;
    let b: wire::HeadBody = wire::decode(s.body.as_slice(), head::LIMIT, "head").map_err(fail)?;
    Ok(json!({ "group": b64::encode(b.group.as_slice()), "generation": b.generation, "revision": b.revision }).to_string())
}

/// Verifies and opens a head against the profile's card with the key of its generation, refusing a revision below
/// `known`.
#[wasm_bindgen]
pub fn head_open(bytes: &[u8], card_bytes: &[u8], known: f64, key_bytes: &[u8]) -> R<String> {
    let c = Card::open(card_bytes, None).map_err(fail)?;
    let sealing: [u8; 32] = arr(key_bytes, "head key")?;
    let known = (known > 0.0).then_some(time(known));
    let h = head::open(bytes, &c, known, |_, _| Some(sealing)).map_err(fail)?;
    Ok(json!({
        "signer": b64::encode(&h.signer),
        "group": b64::encode(&h.group),
        "generation": h.generation,
        "revision": h.revision,
        "published_at": h.published_at,
        "manifest": reference_json(&h.manifest),
    })
    .to_string())
}

#[wasm_bindgen]
pub fn keyring_seal(profile: &[u8], generation: f64, audience_key: &[u8], tokens: &str) -> R<Vec<u8>> {
    Ok(head::seal_keyring(
        &arr(profile, "profile")?,
        time(generation),
        &arr(audience_key, "audience key")?,
        &keyring_tokens_from(&parse(tokens)?)?,
        &mut OsRng,
    ))
}

/// Keyring tokens as JSON `[{read, write, contact}]`, one per card host in card order.
fn keyring_tokens_from(v: &Value) -> R<Vec<head::KeyringTokens>> {
    let list = v.as_array().ok_or(fail(Error::Malformed("tokens")))?;
    let tokens = list
        .iter()
        .map(|t| {
            Ok(head::KeyringTokens {
                read: field(t, "read")?.to_string(),
                write: field(t, "write")?.to_string(),
                contact: field(t, "contact")?.to_string(),
            })
        })
        .collect::<R<Vec<_>>>()?;
    head::KeyringTokens::decode(&head::KeyringTokens::encode(&tokens)).map_err(fail)
}

#[wasm_bindgen]
pub fn keyring_generation(bytes: &[u8]) -> R<f64> {
    Ok(head::keyring_generation(bytes).map_err(fail)? as f64)
}

/// JSON `[{read, write, contact}]`, one per card host in card order.
#[wasm_bindgen]
pub fn keyring_open(bytes: &[u8], profile: &[u8], generation: f64, audience_key: &[u8]) -> R<String> {
    let tokens =
        head::open_keyring(bytes, &arr(profile, "profile")?, time(generation), &arr(audience_key, "audience key")?)
            .map_err(fail)?;
    Ok(Value::Array(tokens.iter().map(|t| json!({ "read": t.read, "write": t.write, "contact": t.contact })).collect())
        .to_string())
}

// Audience boxes

/// The owner's box for a friend, sealed to the inbox key of the friend's card under their friendship secret: the box,
/// with JSON `{lookup}`.
#[wasm_bindgen]
pub fn audience_seal(friendship: &[u8], owner: &[u8], friend: &[u8], friend_inbox: &[u8], generation: u32, audience_key: &[u8]) -> R<Out> {
    let (lookup, sealed) = audience::seal(
        &Zeroizing::new(arr(friendship, "friendship")?),
        &arr(owner, "profile")?,
        &arr(friend, "profile")?,
        &arr(friend_inbox, "inbox key")?,
        generation,
        &arr(audience_key, "audience key")?,
    )
    .map_err(fail)?;
    Ok(out(sealed, json!({ "lookup": b64::encode(&lookup) })))
}

/// Where `owner` stores the box of the friend it shares `friendship` with.
#[wasm_bindgen]
pub fn audience_lookup(friendship: &[u8], owner: &[u8]) -> R<String> {
    Ok(b64::encode(&audience::lookup(&arr(friendship, "friendship")?, &arr(owner, "profile")?)))
}

/// Opens the owner's box for a friend with one of the friend's inbox private keys: the audience key, with JSON
/// `{generation}`.
#[wasm_bindgen]
pub fn audience_open(friendship: &[u8], owner: &[u8], friend: &[u8], inbox_private: &[u8], bytes: &[u8]) -> R<Out> {
    let (generation, key) = audience::open(
        &Zeroizing::new(arr(friendship, "friendship")?),
        &arr(owner, "profile")?,
        &arr(friend, "profile")?,
        &Zeroizing::new(arr(inbox_private, "inbox key")?),
        bytes,
    )
    .map_err(fail)?;
    Ok(out(key.to_vec(), json!({ "generation": generation })))
}

// Owner keys, the own log and snapshots

/// Publishes an owner key generation sealed to the card's recovery key and to the seal key of each of its devices
/// that has a record among `records`, a JSON list of base64url seal key records.
#[wasm_bindgen]
pub fn owner_key_seal(seed: &[u8], card_bytes: &[u8], records: &str, generation: u32, owner_key: &[u8]) -> R<Vec<u8>> {
    let c = Card::open(card_bytes, None).map_err(fail)?;
    let records = parse(records)?
        .as_array()
        .ok_or(fail(Error::Malformed("seal key records")))?
        .iter()
        .map(|r| b64::decode(r.as_str().unwrap_or("!")).map_err(fail))
        .collect::<R<Vec<_>>>()?;
    log::seal_owner_key(&*key(seed)?, &c, &records, generation, &arr(owner_key, "owner key")?).map_err(fail)
}

/// Device public keys of earlier cards, each its 32-byte ID and its ML-DSA-44 key, concatenated.
fn earlier_keys(bytes: &[u8]) -> R<Vec<DeviceEntry>> {
    if bytes.len() % sign::PUBLIC != 0 {
        return Err(fail(Error::Malformed("devices")));
    }
    Ok(bytes
        .chunks(sign::PUBLIC)
        .map(|k| DeviceEntry { device: k[..32].try_into().unwrap(), signing_key: k[32..].try_into().unwrap(), added_at: 0 })
        .collect())
}

/// Opens an owner key record signed by a device of the card or of an earlier card, with this device's seed (its
/// seal key) or with the recovery private key: the owner key, with JSON `{generation}`.
#[wasm_bindgen]
pub fn owner_key_open(
    bytes: &[u8],
    card_bytes: &[u8],
    earlier_devices: &[u8],
    device_seed: Option<Vec<u8>>,
    recovery_private: Option<Vec<u8>>,
) -> R<Out> {
    let c = Card::open(card_bytes, None).map_err(fail)?;
    let earlier = earlier_keys(earlier_devices)?;
    let record = log::OwnerKeyRecord::open(bytes, |s| {
        c.device_key(s).or_else(|| earlier.iter().find(|d| &d.device == s).map(|d| sign::device_public(&d.device, &d.signing_key)))
    })
    .map_err(fail)?;
    let k = match (device_seed, recovery_private) {
        (Some(seed), _) => {
            let seed = Zeroizing::new(arr::<32>(&seed, "seed")?);
            let seal = audience::device_seal_keys(&seed);
            record.open_sealed(&c.profile, &Key::from_seed(&seed).id(), &seal.private)
        }
        (None, Some(private)) => record.recover(&c.profile, &Zeroizing::new(arr(&private, "recovery key")?)),
        _ => return Err(fail(Error::Malformed("owner key"))),
    }
    .map_err(fail)?;
    Ok(out(k.to_vec(), json!({ "generation": record.generation() })))
}

/// The devices allowed to sign log entries: the current card's, plus those of earlier verified cards for
/// entries of earlier owner-key generations.
fn log_signers(card_bytes: &[u8], earlier: &[u8], generation: u32, current: u32) -> R<Card> {
    let mut c = Card::open(card_bytes, None).map_err(fail)?;
    if generation < current {
        for entry in earlier_keys(earlier)? {
            if !c.has_device(&entry.device) {
                c.devices.push(entry);
            }
        }
    }
    Ok(c)
}

fn owner_keys(keys: &str) -> R<Vec<(u32, Zeroizing<[u8; 32]>)>> {
    let v = parse(keys)?;
    let map = v.as_object().ok_or(fail(Error::Malformed("owner keys")))?;
    map.iter()
        .map(|(g, k)| {
            let g: u32 = g.parse().map_err(|_| fail(Error::Malformed("owner keys")))?;
            let k = b64::decode_array::<32>(k.as_str().unwrap_or("!")).map_err(fail)?;
            Ok((g, Zeroizing::new(k)))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn log_seal(
    seed: &[u8],
    profile: &[u8],
    seq: f64,
    previous: &[u8],
    generation: u32,
    owner_key: &[u8],
    operation: &[u8],
) -> R<Vec<u8>> {
    log::seal_entry(
        &*key(seed)?,
        &arr(profile, "profile")?,
        time(seq),
        &arr(previous, "previous")?,
        generation,
        &arr(owner_key, "owner key")?,
        operation,
        &mut OsRng,
    )
    .map_err(fail)
}

/// Opens the log entry expected at `seq` after `previous`: the operation, with JSON
/// `{signer, seq, generation, digest}`. `keys` maps generations to owner keys.
#[wasm_bindgen]
pub fn log_open(
    bytes: &[u8],
    card_bytes: &[u8],
    earlier_devices: &[u8],
    seq: f64,
    previous: &[u8],
    keys: &str,
) -> R<Out> {
    let keys = owner_keys(keys)?;
    let current = keys.iter().map(|(g, _)| *g).max().unwrap_or(0);
    let s: wire::Signed = wire::decode(bytes, log::ENTRY_LIMIT + 2048 + sign::SIGNATURE, "log entry").map_err(fail)?;
    let b: wire::LogEntryBody = wire::decode(s.body.as_slice(), log::ENTRY_LIMIT + 2048, "log entry").map_err(fail)?;
    let signers = log_signers(card_bytes, earlier_devices, b.generation, current)?;
    let previous: [u8; 32] = arr(previous, "previous")?;
    let opened = log::open_entry(bytes, &signers, log::Position { seq: time(seq), previous: &previous }, |g| {
        keys.iter().find(|(k, _)| *k == g).map(|(_, v)| v.clone())
    })
    .map_err(fail)?;
    Ok(out(
        opened.plaintext,
        json!({
            "signer": b64::encode(&opened.signer),
            "seq": opened.seq,
            "generation": opened.generation,
            "digest": b64::encode(&log::digest(bytes)),
        }),
    ))
}

#[wasm_bindgen]
pub fn log_digest(bytes: &[u8]) -> Vec<u8> {
    log::digest(bytes).to_vec()
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn snapshot_seal(
    seed: &[u8],
    profile: &[u8],
    seq: f64,
    entry_digest: &[u8],
    generation: u32,
    owner_key: &[u8],
    state: &str,
) -> R<Vec<u8>> {
    log::seal_snapshot(
        &*key(seed)?,
        &arr(profile, "profile")?,
        time(seq),
        &arr(entry_digest, "digest")?,
        generation,
        &arr(owner_key, "owner key")?,
        &reference(state)?,
        &mut OsRng,
    )
    .map_err(fail)
}

/// JSON `{seq, digest, state}`.
#[wasm_bindgen]
pub fn snapshot_open(bytes: &[u8], card_bytes: &[u8], earlier_devices: &[u8], keys: &str) -> R<String> {
    let keys = owner_keys(keys)?;
    let current = keys.iter().map(|(g, _)| *g).max().unwrap_or(0);
    let s: wire::Signed = wire::decode(bytes, 4096 + sign::SIGNATURE, "snapshot").map_err(fail)?;
    let b: wire::LogEntryBody = wire::decode(s.body.as_slice(), 4096, "snapshot").map_err(fail)?;
    let signers = log_signers(card_bytes, earlier_devices, b.generation, current)?;
    let (seq, digest, state) =
        log::open_snapshot(bytes, &signers, |g| keys.iter().find(|(k, _)| *k == g).map(|(_, v)| v.clone()))
            .map_err(fail)?;
    Ok(json!({ "seq": seq, "digest": b64::encode(&digest), "state": reference_json(&state) }).to_string())
}

// Threads

#[wasm_bindgen]
pub fn thread_id(thread_key: &[u8]) -> R<Vec<u8>> {
    Ok(thread::id(&arr(thread_key, "thread key")?).to_vec())
}

/// Seals a thread entry by the author whose signed card is `author_card`; `carry` is the signed card it carries, or
/// empty: the author's own, or another profile's it relays.
#[wasm_bindgen]
pub fn thread_seal(seed: &[u8], author_card: &[u8], carry: &[u8], thread_key: &[u8], created_at: f64, entry: &[u8]) -> R<Vec<u8>> {
    thread::seal(&*key(seed)?, author_card, carry, &arr(thread_key, "thread key")?, time(created_at), entry, &mut OsRng)
        .map_err(fail)
}

/// The entry, with JSON `{author, signer, created_at, card}`; `card` is the signed card the entry carries, or
/// empty. `card_of` returns the newest card of an author the reader holds.
#[wasm_bindgen]
pub fn thread_open(bytes: &[u8], thread_key: &[u8], card_of: &js_sys::Function) -> R<Out> {
    let e = thread::open(bytes, &arr(thread_key, "thread key")?, card_lookup(card_of)).map_err(fail)?;
    Ok(out(
        e.entry,
        json!({
            "author": b64::encode(&e.author),
            "signer": b64::encode(&e.signer),
            "created_at": e.created_at,
            "card": b64::encode(&e.card),
        }),
    ))
}

// Inbox items

// Device inbox keys

/// A new inbox key for this device: the signed record, with JSON `{private, created_at}`. Only this device keeps the
/// private key.
#[wasm_bindgen]
pub fn device_key_new(seed: &[u8], profile: &[u8], now: f64) -> R<Out> {
    let now = time(now);
    let (record, private) = crate::devicekey::create(&*key(seed)?, &arr(profile, "profile")?, now, &mut OsRng);
    Ok(out(record, json!({ "private": b64::encode(&*private), "created_at": now })))
}

/// A device key record checked against the card it must belong to: JSON `{device, created_at}`.
#[wasm_bindgen]
pub fn device_key_open(record: &[u8], card_bytes: &[u8]) -> R<String> {
    let c = Card::open(card_bytes, None).map_err(fail)?;
    let k = crate::devicekey::open(record, &c).map_err(fail)?;
    Ok(json!({ "device": b64::encode(&k.device), "created_at": k.created_at }).to_string())
}

/// Seals an item to the newest key of each device of `recipient_card` among `records`, a JSON list of base64url
/// records, carrying `keys`, this profile's records, likewise.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn inbox_seal(
    seed: &[u8],
    sender: &[u8],
    recipient_card: &[u8],
    records: &str,
    keys: &str,
    id: &[u8],
    created_at: f64,
    kind: u16,
    payload: &[u8],
) -> R<Vec<u8>> {
    let c = Card::open(recipient_card, None).map_err(fail)?;
    let decode = |text: &str| -> R<Vec<Vec<u8>>> {
        parse(text)?
            .as_array()
            .ok_or(fail(Error::Malformed("records")))?
            .iter()
            .map(|r| b64::decode(r.as_str().unwrap_or("!")).map_err(fail))
            .collect()
    };
    inbox::seal(
        &*key(seed)?,
        &arr(sender, "sender")?,
        &c,
        &decode(records)?,
        &decode(keys)?,
        arr(id, "id")?,
        time(created_at),
        kind,
        payload,
        &mut OsRng,
    )
    .map_err(fail)
}

/// Opens an item with this device's keys, `keys` a JSON object from a record's `created_at` to its base64url private
/// key: the payload, with JSON `{sender, signer, id, created_at, kind, keys}`. `seen` is called with an item ID and
/// returns whether it was already processed.
#[wasm_bindgen]
pub fn inbox_open(
    bytes: &[u8],
    recipient: &[u8],
    seed: &[u8],
    keys: &str,
    now: f64,
    card_of: &js_sys::Function,
    seen: &js_sys::Function,
) -> R<Out> {
    let held = parse(keys)?;
    let held = held.as_object().ok_or(fail(Error::Malformed("device keys")))?;
    let private = |at: u64| {
        held.get(&at.to_string()).and_then(Value::as_str).and_then(|k| b64::decode_array::<32>(k).ok()).map(Zeroizing::new)
    };
    let seen_check = |id: &[u8; 16]| {
        seen.call1(&JsValue::NULL, &js_sys::Uint8Array::from(&id[..])).map(|v| v.is_truthy()).unwrap_or(true)
    };
    let device = sign::id_of(&arr(seed, "seed")?);
    let item = inbox::open(bytes, &arr(recipient, "recipient")?, &device, private, time(now), card_lookup(card_of), seen_check)
        .map_err(fail)?;
    Ok(out(
        item.payload,
        json!({
            "sender": b64::encode(&item.sender),
            "signer": b64::encode(&item.signer),
            "id": b64::encode(&item.id),
            "created_at": item.created_at,
            "kind": item.kind,
            "keys": item.keys.iter().map(|k| b64::encode(k)).collect::<Vec<_>>(),
        }),
    ))
}

/// An acceptance of the invitation whose link secret is `secret`, from JSON `{card, name, friendship, box, keyring,
/// head?, objects?}`, the bytes base64url and `objects` a list of them.
#[wasm_bindgen]
pub fn acceptance_encode(secret: &[u8], value: &str) -> R<Vec<u8>> {
    let v = parse(value)?;
    let secret: [u8; 32] = arr(secret, "secret")?;
    let card = bytes_field(&v, "card")?;
    let bytes = wire::encode(&wire::Acceptance {
        invite: invite::lookup(&secret),
        proof: invite::acceptance_proof(&secret, &card),
        card: vl(card),
        name: vl(field(&v, "name")?.as_bytes()),
        friendship: array_field(&v, "friendship")?,
        audience_box: vl(bytes_field(&v, "box")?),
        keyring: vl(bytes_field(&v, "keyring")?),
        head: vl(if v["head"].is_string() { bytes_field(&v, "head")? } else { Vec::new() }),
        objects: optional_list(&v, "objects")?,
    });
    if bytes.len() > inbox::ITEM_LIMIT {
        return Err(fail(Error::TooLarge("acceptance")));
    }
    Ok(bytes)
}

/// JSON `{invite, proof, card, name, friendship, box, keyring, head, objects}`, `head` null when the acceptance
/// carries none.
#[wasm_bindgen]
pub fn acceptance_decode(bytes: &[u8]) -> R<String> {
    let a: wire::Acceptance = wire::decode(bytes, inbox::ITEM_LIMIT, "acceptance").map_err(fail)?;
    let name = String::from_utf8(a.name.as_slice().to_vec()).map_err(|_| fail(Error::Malformed("name")))?;
    Ok(json!({
        "invite": b64::encode(&a.invite),
        "proof": b64::encode(&a.proof),
        "card": b64::encode(a.card.as_slice()),
        "name": name,
        "friendship": b64::encode(&a.friendship),
        "box": b64::encode(a.audience_box.as_slice()),
        "keyring": b64::encode(a.keyring.as_slice()),
        "head": if a.head.as_slice().is_empty() { Value::Null } else { b64::encode(a.head.as_slice()).into() },
        "objects": a.objects.iter().map(|o| b64::encode(o.as_slice())).collect::<Vec<_>>(),
    })
    .to_string())
}

/// Whether an acceptance proves the link secret of the invitation it names.
#[wasm_bindgen]
pub fn acceptance_check(secret: &[u8], payload: &[u8]) -> R<bool> {
    let a: wire::Acceptance = wire::decode(payload, inbox::ITEM_LIMIT, "acceptance").map_err(fail)?;
    let secret: [u8; 32] = arr(secret, "secret")?;
    Ok(a.invite == invite::lookup(&secret) && invite::check_acceptance(&secret, a.card.as_slice(), &a.proof))
}

/// The name an object's ciphertext is stored under.
#[wasm_bindgen]
pub fn object_name(ciphertext: &[u8]) -> String {
    object::name(&crate::kdf::sha256(ciphertext))
}

// Lists

/// `Entries` → JSON list of `{position, bytes}`.
#[wasm_bindgen]
pub fn entries_decode(bytes: &[u8]) -> R<String> {
    let e: wire::Entries = wire::decode(bytes, 64 * 1024 * 1024, "entries").map_err(fail)?;
    Ok(Value::Array(
        e.entries.iter().map(|x| json!({ "position": x.position, "bytes": b64::encode(x.bytes.as_slice()) })).collect(),
    )
    .to_string())
}

#[wasm_bindgen]
pub fn entries_encode(value: &str) -> R<Vec<u8>> {
    let v = parse(value)?;
    let mut e = wire::Entries::default();
    for x in v.as_array().ok_or(fail(Error::Malformed("entries")))? {
        e.push(number(x, "position")?, bytes_field(x, "bytes")?);
    }
    Ok(wire::encode(&e))
}

/// An inbox entry (docs/hosts.md): `{kind}` with the posted item as bytes, or `{kind, thread, seq}` for a thread note with
/// the entry as bytes.
#[wasm_bindgen]
pub fn inbox_entry(bytes: &[u8]) -> R<Out> {
    let e: wire::InboxEntry = wire::decode(bytes, 64 * 1024 * 1024, "inbox entry").map_err(fail)?;
    match e.kind {
        wire::INBOX_THREAD => {
            let n: wire::ThreadNote = wire::decode(e.body.as_slice(), 64 * 1024 * 1024, "thread note").map_err(fail)?;
            Ok(out(n.entry.as_slice().to_vec(), json!({ "kind": e.kind, "thread": b64::encode(&n.thread), "seq": n.seq })))
        }
        _ => Ok(out(e.body.as_slice().to_vec(), json!({ "kind": e.kind }))),
    }
}

/// The body of `POST /batch`. `requests` is JSON `[{method, path, if_match, length}]`, `if_match` a number or null,
/// and `bodies` every request's body in order, each `length` bytes.
#[wasm_bindgen]
pub fn batch_encode(requests: &str, bodies: &[u8]) -> R<Vec<u8>> {
    let v = parse(requests)?;
    let mut batch = wire::Batch::default();
    let mut at = 0usize;
    for r in v.as_array().ok_or(fail(Error::Malformed("batch")))? {
        let length = number(r, "length")? as usize;
        let body = bodies.get(at..at + length).ok_or(fail(Error::Malformed("batch body")))?;
        at += length;
        batch.requests.push(wire::BatchRequest {
            method: wire::vl(field(r, "method")?.as_bytes()),
            path: wire::vl(field(r, "path")?.as_bytes()),
            if_match: r["if_match"].as_u64(),
            body: wire::vl(body),
        });
    }
    if at != bodies.len() {
        return Err(fail(Error::Malformed("batch body")));
    }
    Ok(wire::encode(&batch))
}

/// A `POST /batch` answer: JSON `[{status, value, length}]` and every answer's body in order.
#[wasm_bindgen]
pub fn batch_decode(bytes: &[u8]) -> R<Out> {
    let answers: wire::BatchAnswers = wire::decode(bytes, 64 * 1024 * 1024, "batch answers").map_err(fail)?;
    let mut bodies = Vec::new();
    let list: Vec<Value> = answers
        .answers
        .iter()
        .map(|a| {
            bodies.extend_from_slice(a.body.as_slice());
            json!({ "status": a.status, "value": a.value, "length": a.body.as_slice().len() })
        })
        .collect();
    Ok(out(bodies, Value::Array(list)))
}

/// The body of `POST /restore`: the `Export` a device builds from what it holds. `value` is JSON `{card, snapshot,
/// threads: [{thread, seq, entry}]}`.
#[wasm_bindgen]
pub fn restore_encode(value: &str) -> R<Vec<u8>> {
    let v = parse(value)?;
    let mut threads = wire::Entries::default();
    for t in v["threads"].as_array().ok_or(fail(Error::Malformed("threads")))? {
        let entry = wire::ThreadExport { thread: array_field(t, "thread")?, entry: vl(bytes_field(t, "entry")?) };
        threads.push(number(t, "seq")?, wire::encode(&entry));
    }
    Ok(wire::encode(&wire::Export {
        card: vl(bytes_field(&v, "card")?),
        head: vl(Vec::new()),
        log: wire::Entries::default(),
        snapshot: vl(bytes_field(&v, "snapshot")?),
        owner_keys: wire::Entries::default(),
        passkey: vl(Vec::new()),
        keyring: vl(Vec::new()),
        inbox: wire::Entries::default(),
        threads,
        invites: wire::Entries::default(),
        objects: wire::Entries::default(),
        group_counter: 0,
        device_keys: {
            let mut keys = wire::Entries::default();
            for k in v["device_keys"].as_array().into_iter().flatten() {
                keys.push(0, b64::decode(k.as_str().unwrap_or("!")).map_err(fail)?);
            }
            keys
        },
    }))
}

// Invitations

/// Creates an invitation. `value` is JSON `{card, name, generation, audience_key, keyring, offer?, head?, objects?}`
/// with `offer` `{tenant_host, secret, quota}`, the bytes base64url and `objects` a list of them. Returns the upload
/// body for `PUT /invites/<lookup>`, with JSON `{lookup}`.
#[wasm_bindgen]
pub fn invite_create(secret: &[u8], release: &[u8], expires_at: f64, now: f64, value: &str) -> R<Out> {
    let v = parse(value)?;
    let offer = if v["offer"].is_object() {
        let o = &v["offer"];
        wire::encode(&HostingOffer {
            tenant_host: vl(field(o, "tenant_host")?.as_bytes()),
            secret: array_field(o, "secret")?,
            quota: number(o, "quota")?,
        })
    } else {
        Vec::new()
    };
    let public = InvitePublic { card: vl(bytes_field(&v, "card")?), name: vl(field(&v, "name")?.as_bytes()) };
    let keys = InviteKeys {
        generation: u32::try_from(number(&v, "generation")?).map_err(|_| fail(Error::Malformed("generation")))?,
        audience_key: array_field(&v, "audience_key")?,
        keyring: vl(bytes_field(&v, "keyring")?),
        offer: vl(offer),
        head: vl(if v["head"].is_string() { bytes_field(&v, "head")? } else { Vec::new() }),
        objects: optional_list(&v, "objects")?,
        keys: optional_list(&v, "keys")?,
    };
    let secret: [u8; 32] = arr(secret, "secret")?;
    let release: [u8; 32] = arr(release, "release")?;
    let (lookup, invitation) =
        invite::create(&secret, &release, time(expires_at), time(now), &public, &keys, &mut OsRng).map_err(fail)?;
    let upload = wire::encode(&wire::InviteUpload { invitation: vl(invitation), release });
    Ok(out(upload, json!({ "lookup": b64::encode(&lookup) })))
}

#[wasm_bindgen]
pub fn invite_lookup(secret: &[u8]) -> R<Vec<u8>> {
    Ok(invite::lookup(&arr(secret, "secret")?).to_vec())
}

/// JSON `{expires_at, card, name}`.
#[wasm_bindgen]
pub fn invite_open_public(bytes: &[u8], secret: &[u8], now: f64) -> R<String> {
    let (expires_at, p) = invite::open_public(bytes, &arr(secret, "secret")?, time(now)).map_err(fail)?;
    let name = String::from_utf8(p.name.as_slice().to_vec()).map_err(|_| fail(Error::Malformed("name")))?;
    Ok(json!({ "expires_at": expires_at, "card": b64::encode(p.card.as_slice()), "name": name }).to_string())
}

/// JSON `{generation, audience_key, keyring, offer, head, objects}`, `offer` null or `{tenant_host, secret, quota}`,
/// `head` null or base64url bytes and `objects` a list of them.
#[wasm_bindgen]
pub fn invite_open_keys(bytes: &[u8], secret: &[u8], release: &[u8], now: f64) -> R<String> {
    let k = invite::open_keys(bytes, &arr(secret, "secret")?, &arr(release, "release")?, time(now)).map_err(fail)?;
    let text = |v: &tls_codec::VLBytes| {
        String::from_utf8(v.as_slice().to_vec()).map_err(|_| fail(Error::Malformed("invitation")))
    };
    let offer = if k.offer.as_slice().is_empty() {
        Value::Null
    } else {
        let o: HostingOffer = wire::decode(k.offer.as_slice(), 1024, "offer").map_err(fail)?;
        json!({ "tenant_host": text(&o.tenant_host)?, "secret": b64::encode(&o.secret), "quota": o.quota })
    };
    Ok(json!({
        "generation": k.generation,
        "audience_key": b64::encode(&k.audience_key),
        "keyring": b64::encode(k.keyring.as_slice()),
        "offer": offer,
        "head": if k.head.as_slice().is_empty() { Value::Null } else { b64::encode(k.head.as_slice()).into() },
        "objects": k.objects.iter().map(|o| b64::encode(o.as_slice())).collect::<Vec<_>>(),
        "keys": k.keys.iter().map(|o| b64::encode(o.as_slice())).collect::<Vec<_>>(),
    })
    .to_string())
}

/// The payload of an inbox item of kind 9: the sender's signed card and the question's JSON body.
#[wasm_bindgen]
pub fn question_encode(card: &[u8], body: &[u8]) -> Vec<u8> {
    wire::encode(&wire::Question { card: vl(card), body: vl(body) })
}

/// JSON `{card, body}`, both base64url.
#[wasm_bindgen]
pub fn question_decode(payload: &[u8]) -> R<String> {
    let q: wire::Question = wire::decode(payload, inbox::ITEM_LIMIT, "question").map_err(fail)?;
    Ok(json!({ "card": b64::encode(q.card.as_slice()), "body": b64::encode(q.body.as_slice()) }).to_string())
}

// Groups

/// The ID a host keeps an access box under.
#[wasm_bindgen]
pub fn access_lookup(secret: &[u8]) -> R<Vec<u8>> {
    Ok(access::lookup(&arr(secret, "secret")?).to_vec())
}

/// Seals an access box. `value` is JSON `{group, generation, keys: [..], read, write, name, tenant, offer?}` with
/// `offer` `{tenant_host, secret, quota}`; keys newest first.
#[wasm_bindgen]
pub fn access_seal(secret: &[u8], value: &str) -> R<Vec<u8>> {
    let v = parse(value)?;
    let offer = if v["offer"].is_object() {
        let o = &v["offer"];
        Some(HostingOffer {
            tenant_host: vl(field(o, "tenant_host")?.as_bytes()),
            secret: array_field(o, "secret")?,
            quota: number(o, "quota")?,
        })
    } else {
        None
    };
    let keys = list(&v, "keys")?
        .iter()
        .map(|k| arr::<32>(k, "access keys"))
        .collect::<R<Vec<[u8; 32]>>>()?;
    let generation = u32::try_from(number(&v, "generation")?).map_err(|_| fail(Error::Malformed("generation")))?;
    let a = access::Access {
        group: array_field(&v, "group")?,
        generation,
        keys,
        read_token: field(&v, "read")?.to_string(),
        write_token: field(&v, "write")?.to_string(),
        name: field(&v, "name")?.to_string(),
        tenant: field(&v, "tenant")?.to_string(),
        offer,
    };
    access::seal(&arr(secret, "secret")?, &a, &mut OsRng).map_err(fail)
}

/// Opens an access box: JSON `{group, generation, keys, read, write, name, tenant, offer}`, `offer` null or
/// `{tenant_host, secret, quota}`.
#[wasm_bindgen]
pub fn access_open(secret: &[u8], bytes: &[u8]) -> R<String> {
    let a = access::open(&arr(secret, "secret")?, bytes).map_err(fail)?;
    let offer = match &a.offer {
        None => Value::Null,
        Some(o) => json!({
            "tenant_host": String::from_utf8_lossy(o.tenant_host.as_slice()),
            "secret": b64::encode(&o.secret),
            "quota": o.quota,
        }),
    };
    let keys: Vec<Vec<u8>> = a.keys.iter().map(|k| k.to_vec()).collect();
    Ok(json!({
        "group": b64::encode(&a.group),
        "generation": a.generation,
        "keys": encoded_list(&keys),
        "read": a.read_token,
        "write": a.write_token,
        "name": a.name,
        "tenant": a.tenant,
        "offer": offer,
    })
    .to_string())
}

/// The thread key of a group's wall under one key generation.
#[wasm_bindgen]
pub fn wall_key(group_key: &[u8], wall: u32) -> R<Vec<u8>> {
    Ok(access::wall_key(&arr(group_key, "group key")?, wall).to_vec())
}

/// The unverified kind and counter of a host token: JSON `{kind, counter}`. Only the host that issued it can check it.
#[wasm_bindgen]
pub fn token_peek(text: &str) -> R<String> {
    if text.len() > 64 {
        return Err(fail(Error::Malformed("token")));
    }
    let t: wire::Token = wire::decode(&b64::decode(text).map_err(fail)?, 64, "token").map_err(fail)?;
    Ok(json!({ "kind": t.kind, "counter": t.epoch }).to_string())
}

// Device links

#[wasm_bindgen]
pub fn link_lookup(secret: &[u8]) -> R<Vec<u8>> {
    Ok(link::lookup(&arr(secret, "secret")?).to_vec())
}

/// A `LinkRequest` for the new device whose seed is `seed`: its public key and name.
#[wasm_bindgen]
pub fn link_request(secret: &[u8], seed: &[u8], name: &str) -> R<Vec<u8>> {
    Ok(link::request(&arr(secret, "secret")?, &key(seed)?.public(), name))
}

/// JSON `{device, signing_key, name}` once the proof checks.
#[wasm_bindgen]
pub fn link_check(secret: &[u8], bytes: &[u8]) -> R<String> {
    let (device, signing_key, name) = link::check_request(&arr(secret, "secret")?, bytes).map_err(fail)?;
    Ok(json!({ "device": b64::encode(&device), "signing_key": b64::encode(&signing_key), "name": name }).to_string())
}

#[wasm_bindgen]
pub fn link_code(secret: &[u8], existing: &[u8], new: &[u8]) -> R<String> {
    Ok(link::code(&arr(secret, "secret")?, &arr(existing, "device")?, &arr(new, "device")?))
}

/// Seals a `LinkReply` from JSON `{card, owner_keys: {"<generation>": key}}`.
#[wasm_bindgen]
pub fn link_reply_seal(secret: &[u8], value: &str) -> R<Vec<u8>> {
    let v = parse(value)?;
    let mut owner_keys = owner_keys(&v["owner_keys"].to_string())?;
    owner_keys.sort_by_key(|(g, _)| *g);
    let reply = LinkReplyBody {
        card: vl(bytes_field(&v, "card")?),
        owner_keys: owner_keys.iter().map(|(generation, key)| OwnerKey { generation: *generation, key: **key }).collect(),
    };
    Ok(link::seal_reply(&arr(secret, "secret")?, &reply, &mut OsRng))
}

/// JSON `{card, owner_keys: {"<generation>": key}}`.
#[wasm_bindgen]
pub fn link_reply_open(secret: &[u8], bytes: &[u8]) -> R<String> {
    let r = link::open_reply(&arr(secret, "secret")?, bytes).map_err(fail)?;
    let keys: serde_json::Map<String, Value> =
        r.owner_keys.iter().map(|k| (k.generation.to_string(), Value::String(b64::encode(&k.key)))).collect();
    Ok(json!({ "card": b64::encode(r.card.as_slice()), "owner_keys": keys }).to_string())
}

// Recovery

#[wasm_bindgen]
pub fn passkey_prf_input() -> Vec<u8> {
    recovery::prf_input()
}

#[wasm_bindgen]
pub fn passkey_seal(prf: &[u8], profile: &[u8], seed: &[u8]) -> R<Vec<u8>> {
    Ok(recovery::seal_passkey_backup(prf, &arr(profile, "profile")?, &arr(seed, "seed")?, &mut OsRng))
}

#[wasm_bindgen]
pub fn passkey_open(prf: &[u8], profile: &[u8], bytes: &[u8]) -> R<Vec<u8>> {
    Ok(recovery::open_passkey_backup(prf, &arr(profile, "profile")?, bytes).map_err(fail)?.to_vec())
}

#[wasm_bindgen]
pub fn passkey_user_handle(tenant_url: &str) -> R<Vec<u8>> {
    recovery::user_handle(tenant_url).map_err(fail)
}

/// JSON `{tenant, url}`, `url` null when the handle holds only the tenant ID.
#[wasm_bindgen]
pub fn passkey_read_user_handle(handle: &[u8]) -> R<String> {
    let (tenant, url) = recovery::read_user_handle(handle).map_err(fail)?;
    Ok(json!({ "tenant": b64::encode(&tenant), "url": url }).to_string())
}

// Locked browsers

#[wasm_bindgen]
pub fn local_key() -> Vec<u8> {
    local::new_key(&mut OsRng).to_vec()
}

#[wasm_bindgen]
pub fn local_lock(key: &[u8], prf: &[u8], seed: &[u8], profile: &[u8]) -> R<Vec<u8>> {
    let seed = Zeroizing::new(arr::<32>(seed, "seed")?);
    Ok(local::lock(&arr(key, "local key")?, prf, &seed, &arr(profile, "profile")?, &mut OsRng))
}

#[wasm_bindgen]
pub fn local_relock_passkey(lock: &[u8], key: &[u8], prf: &[u8], profile: &[u8]) -> R<Vec<u8>> {
    local::relock_passkey(lock, &arr(key, "local key")?, prf, &arr(profile, "profile")?, &mut OsRng).map_err(fail)
}

#[wasm_bindgen]
pub fn local_open_with_passkey(lock: &[u8], prf: &[u8], profile: &[u8]) -> R<Vec<u8>> {
    Ok(local::open_with_passkey(lock, prf, &arr(profile, "profile")?).map_err(fail)?.to_vec())
}

#[wasm_bindgen]
pub fn local_open_with_seed(lock: &[u8], seed: &[u8], profile: &[u8]) -> R<Vec<u8>> {
    let seed = Zeroizing::new(arr::<32>(seed, "seed")?);
    Ok(local::open_with_seed(lock, &seed, &arr(profile, "profile")?).map_err(fail)?.to_vec())
}

#[wasm_bindgen]
pub fn local_seal_record(key: &[u8], store: &str, name: &str, value: &[u8]) -> R<Vec<u8>> {
    Ok(local::seal_record(&arr(key, "local key")?, store, name, value, &mut OsRng))
}

#[wasm_bindgen]
pub fn local_open_record(key: &[u8], store: &str, name: &str, bytes: &[u8]) -> R<Vec<u8>> {
    local::open_record(&arr(key, "local key")?, store, name, bytes).map_err(fail)
}

#[wasm_bindgen]
pub fn local_seal_file(key: &[u8], path: &str, bytes: &[u8]) -> R<Vec<u8>> {
    Ok(local::seal_file(&arr(key, "local key")?, path, bytes, &mut OsRng))
}

#[wasm_bindgen]
pub fn local_open_file(key: &[u8], path: &str, bytes: &[u8]) -> R<Vec<u8>> {
    local::open_file(&arr(key, "local key")?, path, bytes).map_err(fail)
}

#[wasm_bindgen]
pub fn local_seal_name(key: &[u8], segment: &str) -> R<String> {
    Ok(local::seal_name(&arr(key, "local key")?, segment))
}

#[wasm_bindgen]
pub fn local_open_name(key: &[u8], name: &str) -> R<String> {
    local::open_name(&arr(key, "local key")?, name).map_err(fail)
}

// Transfer

#[wasm_bindgen]
pub fn transfer_grant(seed: &[u8], tenant: &[u8], new_host: &str, expires_at: f64) -> R<Vec<u8>> {
    Ok(transfer::grant(&*key(seed)?, &arr(tenant, "tenant")?, new_host, time(expires_at)))
}
