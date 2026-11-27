# commonwire formats

This document is normative for every key, group rule, encrypted structure, signature, token, invitation, recovery format and limit that devices and hosts exchange. `rust/cw-crypto` is its only implementation; browsers, the Cloudflare Worker and `commonwire` all call it. The vectors in `rust/cw-crypto/vectors/` are part of this specification.

## Conventions

- **Binary structures** use the TLS presentation language (RFC 8446 §3) with variable-length vectors: `opaque x<V>` is a QUIC variable-length integer (RFC 9000 §16) length followed by the bytes, and `T x<V>` is the same length, in bytes, followed by the encoded `T`s. Integers are big-endian. A structure that has bytes left over after decoding is refused.
- **Text encodings.** Bytes inside JSON, headers and URLs are base64url without padding (RFC 4648 §5). A decoder refuses padding, non-alphabet characters and non-zero trailing bits.
- **Times** are `uint64` milliseconds since the Unix epoch.
- **JSON** inside encrypted payloads is I-JSON (RFC 7493), UTF-8, with no duplicate keys.
- **Labels.** Every key derivation, signature and AEAD in this document is domain-separated by a label. A label `L` is used as the ASCII bytes `"commonwire 1 " || L`.
- **Concatenation.** `||` joins fields in the encodings of their structures: integers big-endian at their declared width, fixed arrays as they are, and `opaque x<V>` fields with their length prefix.
- **HPKE results** are encoded as `struct { opaque enc<V>; opaque ciphertext<V>; } HpkeBox`.

## Primitives

| Purpose | Primitive |
|---|---|
| Signatures | Ed25519 (RFC 8032, pure, strict verification) and ML-DSA-44 (FIPS 204, pure, empty context, hedged signing) together, as signing keys below |
| Hash | SHA-256 |
| Key derivation | HKDF-SHA256 (RFC 5869). `Expand(K, L, n)` is HKDF-Expand with `info` = the label bytes of `L`. `Derive(IKM, L, n)` is HKDF-Extract with an empty salt, then `Expand`. |
| MAC | HMAC-SHA256 |
| Content AEAD | AES-256-GCM with a 96-bit nonce and 128-bit tag |
| KEM | X-Wing (draft-connolly-cfrg-xwing-kem-06), which combines X25519 and ML-KEM-768 (FIPS 203): a 32-byte private key, a 1,216-byte public key, a 1,120-byte encapsulation and a 32-byte shared secret |
| Public-key sealing | HPKE (RFC 9180), single shot, in base mode or PSK mode, with the X-Wing KEM `0x647a`, HKDF-SHA256 `0x0001` and AES-256-GCM `0x0002`. The KEM's shared secret enters the key schedule (RFC 9180 §5.1) as `shared_secret`, and `enc` is its encapsulation. |

Every key exchange is X-Wing and every signature carries ML-DSA-44, so what hosts store stays sealed against an attacker with a quantum computer, and signatures stay unforgeable by one.

### Signing keys

A signing key is made from a 32-byte seed. Its Ed25519 private key is the seed, and its ML-DSA-44 key pair is `ML-DSA.KeyGen_internal(Derive(seed, "ml-dsa", 32))`. Its public key is the 32-byte Ed25519 public key followed by the 1,312-byte ML-DSA-44 public key, 1,344 bytes. A signature is the 64-byte Ed25519 signature followed by the 2,420-byte ML-DSA-44 signature over the same message, 2,484 bytes; a verifier refuses it unless both verify.

## Identifiers

| Name | Form |
|---|---|
| Profile ID | `SHA-256(label("profile") \|\| profile public key)`, which commits to both halves of the profile key, so the ID stays 32 bytes in links, codes and conversation IDs |
| Device ID | The 32-byte Ed25519 half of a device's public key. The card binds it to the device's ML-DSA-44 key. |
| Tenant ID | 16 bytes chosen by the host when the tenant is created: 8 random bytes `r`, then the first 8 bytes of `HMAC(host secret, label("tenant") \|\| r)`, so a host refuses paths for tenants it never created without touching storage |
| Tenant URL | `https://<host>/t/<tenant ID>`, the base of every tenant path below, with the host in lowercase. `http://` is allowed only for loopback hosts (`localhost`, `*.localhost`, `127.0.0.1`, `[::1]`), for development. Cards list tenant URLs. |
| Object name | `sha256-` followed by the base64url SHA-256 of the object's ciphertext (43 characters) |
| Group ID | 16 random bytes chosen by the device that creates the group |

## Keys

### Profile seed and recovery key

The profile seed `S` is 32 random bytes, the seed of the profile key, a signing key. It lives in the passkey backup and in the written recovery key. No device stores it: a device opens it from one of them for one change (a card it signs, a passkey backup it seals, a join) and wipes it afterwards. The device that creates the profile holds `S` only until the person confirms they saved the written recovery key.

The recovery key is the X-Wing key pair whose private key is `Derive(S, "recovery", 32)`. Devices hold only the recovery public key.

The written recovery key is `CW1-` followed by the RFC 4648 base32 encoding (alphabet `A–Z2–7`, no padding) of `S || C`, in groups of four characters joined by `-`. `C` is the first 4 bytes of `SHA-256(label("recovery check") || S)`. Input is accepted case-insensitively with whitespace and dashes ignored. A key whose checksum doesn't match is refused before anything else happens.

### Device keys

Each device generates a 32-byte device seed that never leaves it. It is the seed of the device's signing key, which signs every structure below that a device signs; the card lists its public key.

The device's seal key is the X-Wing key pair whose private key is `Derive(device seed, "device seal", 32)`. Owner keys are sealed to it. The device publishes it in its own seal key record, a `Signed` of type 9 that the device signs itself:

```
struct { opaque profile[32]; opaque seal_key[1216]; } SealKeyBody;
```

The record is kept in the own log as the product's `seal-key` row of that device. A device seals owner keys only to a seal key whose record its own device signed, for the card's profile, so no other device, while it was in the card or after, can put its own key in another device's place. A device writes its record as soon as the card lists it, before anything else it writes.

### Inbox key

The person's inbox key pair is an X-Wing key pair, generated by the device that creates the profile or removes a device. Friends seal audience boxes to it (Audience boxes); inbox items go to device inbox keys instead. The public key is in the card. The private key travels between own devices only inside the own log. It is replaced whenever an own device is removed; devices keep earlier private keys to open boxes sealed before the change.

### Device inbox keys

Inbox items are sealed to keys that only one device holds and that it deletes, so an item recorded from a host can't be opened with any key stolen later.

- Each device makes an X-Wing key pair from fresh randomness, keeps the private key only in its own storage, never in the own log, and publishes the public key in a device key record, a `Signed` of type 10 that the device signs:

```
struct { opaque profile[32]; uint64 created_at; opaque key[1216]; } DeviceKeyBody;
```

- A device's current key is its newest record, however old: a device that is away still holds that key, so items wait for it on its host like any others. A device makes a new key when it is first listed in the card, and again whenever its newest is more than 3 days old when it opens or sweeps. It puts the record on every host in the card (`PUT /devicekeys`) and keeps it in the own log as the product's `device-key` row of that device.
- The first host refuses an inbox item unless it wraps the key of every device that has a record there, each naming that device's newest (`POST /inbox`, 409 `device-keys`), and answers with the current records. So once a newer record is stored, no item sealed to an older key arrives, and no item leaves out a device that published one.
- A device deletes a private key once it has put a newer record on the first host and then read the inbox: every item that key opens arrived before.
- A sender seals to the newest record of each device in the recipient's current card that it holds, verified against that card. It holds records from items the recipient sent (`keys` below), from conversation contact entries and from the host's refusals, and reads them from the recipient's first host (`GET /devicekeys`) only when it holds none. When the recipient has no record at all, the item waits with the sender and is tried again daily and whenever something arrives from them.

### Host admin key and host secret

A person who runs a host generates a host admin key, a signing key whose seed is kept in own state. Setup makes a 32-byte host secret and a 32-byte claim secret: `commonwire host init` makes both on the host's machine; for a host on Cloudflare, the app's setup step makes the host secret and the browser makes the claim secret. The host secret is kept only on the host (a Worker secret on Cloudflare); tokens, tenant IDs and hosting offers are MACs under it. The host keeps only the claim digest `SHA-256(label("claim") || claim secret)`, and the claim secret travels only in the setup link's fragment.

A setup link is `<app>/host#claim=<base64url claim secret>.<base64url host origin>`. A space link, which offers space on a host to someone who already has a profile or is about to make one, is `<app>/host#space=<base64url offer secret>.<base64url host origin>`, with the offer secret below. Both secrets travel only in the fragment.

## Signed structures

```
struct {
  uint16 type;
  opaque body<V>;
  opaque signer[32];
  opaque signature<V>;
} Signed;
```

`signature` is the signer's signature (Signing keys) over `label(type) || 0x00 || body`. `signer` is a profile ID or a device ID; the verifier is always told which key or key set may sign, takes the signer's public key from the card (the card's own profile key for a card, the device's entry for everything else) and refuses any other signer.

| `type` | Label | Signed by | Body |
|---|---|---|---|
| 1 | `card` | profile key | `CardBody` |
| 2 | `head` | an own device | `HeadBody` |
| 3 | `log entry` | an own device | `LogEntryBody` |
| 4 | `thread entry` | the author's device | `ThreadEntryBody` |
| 5 | `inbox item` | the sender's device | `InboxItemBody` |
| 6 | `snapshot` | an own device | `SnapshotBody` |
| 7 | `transfer grant` | an own device | `TransferGrantBody` |
| 8 | `owner key` | an own device | `OwnerKeyBody` |
| 9 | `seal key` | the device whose seal key it is | `SealKeyBody` |
| 10 | `device key` | the device whose key it is | `DeviceKeyBody` |

### Card

```
struct {
  opaque profile_key[1344];  /* the profile's public key */
  uint64 version;
  uint64 issued_at;
  opaque devices<V>;         /* DeviceEntry list */
  opaque inbox_key[1216];    /* X-Wing public */
  opaque recovery_key[1216]; /* X-Wing public */
  opaque hosts<V>;           /* list of opaque url<V>, tenant URLs, first orders writes */
} CardBody;
struct { opaque device[32]; opaque signing_key[1312]; uint64 added_at; } DeviceEntry;
```

- The card's profile is the profile ID of `profile_key`, and it must be the signer. A device's public key is its ID followed by its `signing_key`, the ML-DSA-44 half.
- `version` strictly increases. A device keeps the highest version it has verified for each profile and refuses lower ones; an equal version with different bytes is refused.
- 1–32 devices, unique; 1–4 hosts, unique, each a tenant URL of at most 256 bytes whose host is lowercase.
- The card holds no names. A host that stopped hosting the person serves the last card it holds, whose first host is the new one, for 7 days.

### Request signatures

Owner requests carry these headers:

| Header | Value |
|---|---|
| `CW-Device` | device ID |
| `CW-Time` | decimal milliseconds |
| `CW-Nonce` | 16 random bytes |
| `CW-Signature` | the device's signature over the request string |

The request string is the label `request`, then `0x00`, then these lines joined by `\n`: the method in upper case, the host as sent in `:authority`, the path and query exactly as sent, `CW-Time`, `CW-Nonce`, and the base64url SHA-256 of the body (of the empty string when there is none). A host refuses a request whose device isn't in the tenant's current card, whose time is more than 60 s from its clock, or whose nonce it has seen from that device in the last 120 s. `PUT /card` is the one exception: its signer may instead be a device in the card it carries, which is how a device joining with `S` adds itself.

Administration uses the same scheme with `CW-Admin` carrying the Ed25519 half of the host admin public key in place of `CW-Device`; the host verifies with the whole admin public key it stored at claim.

A browser can't set headers on a WebSocket, so `GET /push` carries them in its subprotocols: `cw1` and `cw1.` followed by the base64url of

```
struct { opaque token<V>; opaque device[32]; uint64 time; opaque nonce[16]; opaque signature<V>; } SocketAuth;
```

signed as above with method `GET`, the path `/t/<tenant>/push`, and the SHA-256 of the empty string. The host answers with subprotocol `cw1`.

## Tokens

```
struct {
  opaque tenant[16];
  uint64 epoch;
  uint8 kind;      /* 1 read, 2 write, 3 owner, 4 admin, 5 contact, 6 slot, 7 group read, 8 group write */
  uint32 serial;
  opaque mac[16];
} Token;
```

`mac` is the first 16 bytes of `HMAC(host secret, label("token") || tenant || epoch || kind || serial)`. A token is sent as `Authorization: CW <base64url Token>`, or on `GET` and `POST` requests as the query parameter `t=<base64url Token>`, which keeps friends' reads and appends free of CORS preflights.

- A tenant has three token counters: audience, contact and group. Read and write tokens carry the audience counter, which the host advances only when the owner asks (Audience rotation). The host also accepts read and write tokens carrying the next counter, so the owner seals them into the new keyring before advancing. Owner tokens carry no counter: their `epoch` is 0, and the request signature limits them to devices in the card. `serial` is chosen by the host; owner tokens use the first four bytes of `SHA-256(device ID)`.
- A contact token reads objects and posts inbox items, and nothing else. It carries the contact counter, which the host advances only when the owner asks, so contact tokens outlast audience generations. The host also accepts a contact token carrying the next counter, so the owner can hand out the next generation before retiring the current one (Conversations: contact rotation).
- Group read and group write tokens carry the tenant's group counter, which the host advances only when the owner asks; the host also accepts the next counter, so the owner hands out the next generation before retiring the current one (Groups: rotation). A group read token reads the head, threads and objects; a group write token appends to threads the owner opened and puts objects. `serial` is 0.
- A slot token posts inbox items and nothing else. Its `epoch` is the slot number and `serial` is 0; it works while the owner keeps that slot open, and slot numbers are never reused.
- Admin tokens have an all-zero `tenant`, `epoch` 1 and `serial` 0, and are issued once, at claim.
- A host checks the MAC in constant time before it touches storage, then refuses a token whose counter is neither the tenant's current one for that kind nor the next, an owner token whose `epoch` isn't 0, or a slot token whose slot isn't open. It stores no token values.
- Tokens only ration host resources. Confidentiality never depends on them.

## Encrypted payloads

### Padding

Every AEAD plaintext in this document is padded before encryption: append `0x80`, then zero bytes until the plaintext plus the 16-byte tag reaches the smallest bucket at least that large. Buckets are 256, 512 and 1024 bytes, then each next bucket is the previous one times 5/4, rounded up to a multiple of 64 (1280, 1600, 2048, 2560, …). Decryption refuses a plaintext whose padding is anything else.

### Objects

Photos, the manifest, message photos and snapshots are objects.

- Each object has its own random 32-byte key `k`. Its ciphertext is `AES-256-GCM(k, nonce = 12 zero bytes, aad = label("object"), padded plaintext)`. A key is never used for a second object.
- The object is stored and fetched under its object name. A reader checks the digest before it decrypts.
- Plaintext is at most 16 MiB.

An object reference, in binary or JSON:

```
struct { opaque digest[32]; opaque key[32]; uint32 size; } ObjectRef;
{"h": "sha256-…", "k": "<base64url key>", "n": <plaintext size>}
```

### Audience key

Everything a friend reads of a profile is under its audience key `A_n`, 32 random bytes of generation `n`, from 1. Every own device holds it, from the own log, and every friend holds it, from the invitation or their audience box. The head key is `Expand(A_n, "head", 32)` and the keyring key `Expand(A_n, "keyring", 32)`. An own device makes the next generation whenever someone loses access: an unfriending, an own device's removal, or a friend's card whose inbox key changed, since that friend removed a device that held this key (Audience rotation).

### Head

```
struct {
  opaque profile[32];
  opaque group<V>;     /* empty for a profile's head; the group ID for a group's head */
  uint64 generation;   /* of the key the head is sealed under */
  uint64 revision;
  uint64 published_at;
  opaque nonce[12];
  opaque sealed<V>;    /* AES-256-GCM(head key, nonce, aad = label("head") || HeadAad, padded HeadSecret) */
} HeadBody;
struct { opaque profile[32]; opaque group<V>; uint64 generation; uint64 revision; } HeadAad;
struct { ObjectRef manifest; } HeadSecret;
```

- Signed by a device in the profile's card.
- `revision` strictly increases across every head of a profile, through key generations. A reader keeps the highest revision it has verified and refuses anything lower, so a host can withhold an update but can't roll one back unnoticed.
- The head names the manifest's root part.

### Manifest

The manifest is the product's publication (`about`, `theme`, `sections`, `albums`, `posts`), where every photo, avatar and cover is an `ObjectRef` in JSON form and each post carries `thread`, its 32-byte thread key. The product's contract defines the content fields and their validation. It is stored as parts, each an object whose plaintext is JSON, so a publication writes only the parts that changed:

- The **root** part is `{"about", "theme", "sections", "albums": [{"id", "title", "items"}], "volumes": [ObjectRef, …]}`. Each album's `items` is an `ObjectRef` to the part holding that album's items as a JSON array.
- A **page** holds posts as a JSON array, newest first. A post's week is `floor(created_at / 604,800,000)`; the posts of a week, oldest first, fill pages of 32, and pages are ordered newest week first and, within a week, newest page first.
- A **volume** is a JSON array of page `ObjectRef`s, newest first. Counted from the oldest page, every 64 pages make a volume, and the root lists volumes newest first. A new post changes its page, the newest volume and the root, whatever the profile's size.
- A part's key is `Expand(owner key, "manifest part", 32)` with `SHA-256(plaintext)` appended to the label, under the current owner key generation, so every own device makes the same object for the same part, an unchanged part keeps its object across publications and audience generations, and readers fetch only parts they don't hold. A new owner key generation gives every part a new object.
- A notice of a new publication may carry, beside the head, the ciphertext of the root and of parts the publication added (`docs/hosts.md` stores them as objects either way). A reader checks each digest against the reference that names it, as for any object.

### Keyring

The keyring holds the tokens that friends need for the current audience generation:

```
struct { uint64 generation; opaque nonce[12]; opaque sealed<V>; } KeyringBox;
struct { opaque read_token<V>; opaque write_token<V>; opaque contact_token<V>; } KeyringHost;
struct { KeyringHost hosts<V>; } Keyring;
```

`hosts` holds one entry for each host in the card, in card order, 1–4 entries of non-empty UTF-8 tokens. Each host issues its own tokens, so a reader uses the entry of the host it reads from. Friends post inbox items with the first host's contact token.

`sealed` is `AES-256-GCM(keyring key, nonce, aad = label("keyring") || profile || uint64 generation, padded Keyring)`.

### Audience boxes

A friend reads the current audience key from their audience box on the profile's hosts.

- The friendship secret `f` of a profile `P` and its friend `F` is 32 random bytes that the person accepting the invitation chooses and sends in the acceptance (Invitations). Both keep it in their own logs with the friend's records.
- `P` stores `F`'s box at `access/<lookup>` on every host in `P`'s card, where the lookup is `Expand(f, "audience box lookup", 16)` with `P` appended to the label. The box is an `HpkeBox`: HPKE in PSK mode to the inbox key in `F`'s current card, with `psk = f`, `psk_id = label("audience box")`, `info = label("audience box") || P || F || lookup`, empty `aad` and the padded

```
struct { uint32 generation; opaque key[32]; } AudienceBoxBody;
```

- Only `F`'s inbox private key opens the box, and only someone holding `f` can make one that opens. An inbox key changes when a device is removed, and every change starts an audience rotation on both sides (Audience rotation), so a removed device can't open a box written after its removal.
- A friend reads its box when a head names a generation newer than the key it holds, or when a read with its tokens is refused. A device keeps its earlier inbox private keys and tries them newest first.
- A box that is missing at its lookup means the friendship ended, once the reader has read that profile's box before or accepted its invitation more than 30 days ago, the most an invitation lives. Until then the profile may not have handled the reader's acceptance yet. A notice `{}` from the profile says the friendship ended in any case.

### Audience rotation

An own device moves the audience key to its next generation in this order, each step repeatable:

1. It keeps the new key, the audience counter to reach on each host (the host's current counter plus one) and the boxes to delete on the device, so a closed tab finishes the rotation when it opens again.
2. On the first host, in one batch: the own-log entry that records the new key, the deletion of the boxes of whoever lost access, every remaining friend's box under the new key, the keyring of the new generation with the read and write tokens of the counter to reach, the head under the new key, and the advance of the audience counter, which retires every read and write token before it. Other own devices see the new key only together with all of it. Then the same on every replica, without the log entry. A batch over the host's limits is split, the advance last.
3. It sends each remaining friend the publication's notice, which carries that friend's box and the keyring, so friends read nothing else for the new generation.

Every rotation removes someone, a friend or a device that held the key, so it also replaces the contact tokens (Conversations: contact rotation): the keyring carries the next ones, and when no co-member outside the keyring needs them first, the batch advances the contact counter too.

### Owner key and own log

The own log is encrypted under the owner key `O_g`, 32 random bytes of generation `g`, from 0. An own device makes the next generation whenever an own device is removed, and publishes each generation as:

```
struct { opaque device[32]; HpkeBox sealed; } DeviceSeal;
struct {
  uint32 generation;
  opaque recovery<V>;    /* HpkeBox: O_g sealed to the recovery public key, info = label("owner key") || profile || generation, empty aad, unpadded */
  DeviceSeal devices<V>; /* O_g sealed to the seal key of each device in the card, info = label("owner key") || profile || generation || device, empty aad, unpadded */
} OwnerKeyBody;
```

Both are HPKE in base mode. The seal key of each device comes from its seal key record (Device keys); a device in the card without a valid record gets no seal and joins again with `S` if it returns.

A device that meets a log entry or snapshot of a generation it doesn't hold reads the owner keys and opens its own seal. A recovering device opens `recovery` with the recovery private key, and a newly linked device gets every generation in the link reply.

- **Rollover.** An own device also makes the next generation when the current one is more than 7 days old, in its daily sweep, and seals a snapshot under it. A host keeps the first record of each generation, so when two devices make the same one, the second reads the first's and makes the one after. A host refuses a log entry or snapshot of a generation below the newest owner key it holds, so every entry after that snapshot is of the new generation.
- **Erasure.** Once the host's snapshot is of the newest generation, nothing anyone reads needs the older ones: a device deletes every older owner key it holds, and the device that rolled over deletes the older records from every host (`DELETE /ownerkeys/<generation>`). Rows deleted before the snapshot then can't be read from any copy of the log, whoever later learns `S` or a device's keys.

```
struct {
  uint64 seq;
  opaque previous[32]; /* SHA-256 of the previous entry's Signed bytes; zeros for seq 0 */
  uint32 generation;
  opaque nonce[12];
  opaque sealed<V>;    /* AES-256-GCM(O_g, nonce, aad = label("log entry") || profile || seq || generation, padded operation JSON) */
} LogEntryBody;
```

- The host stores an entry only at the `seq` it names, the next one, and refuses others with 412. Readers check `previous`, so a host can't drop, reorder or replay entries without detection.
- The operation JSON is a list of one or more of the product's operation records, the writes a device sends together, in the order it made them; each record's operation ID makes retries idempotent. Each row keeps the write with the highest `(at, id)`; a device gives a write an `at` later than every row it changes as that device holds them, so a write always supersedes what its author saw.

### Snapshots

```
struct { uint64 seq; opaque previous[32]; uint32 generation; opaque nonce[12]; opaque sealed<V>; } SnapshotBody;
```

`sealed` is `AES-256-GCM(O_g, nonce, aad = label("snapshot") || profile || seq || generation, padded ObjectRef)`. The referenced object holds the person's complete own state as of log entry `seq`, whose bytes hash to `previous`. The host removes the entries through `seq` when it stores the snapshot; a device whose position is behind it loads the snapshot instead. Recovery reads the latest snapshot and every entry after it.

### Threads

Each post has a random 32-byte thread key `T`, kept in the manifest. Its thread is stored at `threads/<thread ID>`, where the thread ID is `Expand(T, "thread id", 16)`, so hosts never see post identifiers. An entry is

```
struct { opaque nonce[12]; opaque sealed<V>; } ThreadBox;
```

with `sealed = AES-256-GCM(T, nonce, aad = label("thread entry") || thread ID, padded Signed)` where the `Signed` has type 4 and body

```
struct { opaque author[32]; opaque thread[16]; uint64 created_at; opaque card<V>; opaque entry<V>; } ThreadEntryBody;
```

- The signature is inside the encryption, so a host can't tell which friend wrote an entry.
- `card` is a signed card or empty, so readers who aren't the author's friends can still check entries. An author carries their card in an entry unless the thread, as they last read it, holds an entry carrying that same card. A carried card must verify; it is usually the author's own, and a card of another profile is relayed. A card proves itself, so a reader takes a relayed card as if that profile had carried it.
- Before the thread's owner deletes entries, their device relays the newest card of every author who keeps entries in the thread but would keep none carrying a card of theirs: one entry of its own per card, whose `entry` is `{"type": "card"}`.
- The signer must be a device in the newest card of the author the reader holds: the entry's own card, one carried by any other entry of the thread, or the reader's own copy. A reader that meets an entry before the card it needs, as when a relay follows it, checks it again once it holds the card. A higher version than the carried card wins, so a device removed since can't write as the author. A reader that holds no card for the author skips the entry.
- `thread` must match the thread being read. `entry` is the product's comment or like JSON, at most 16 KiB, identified by its own ID; a reader keeps the version with the highest `changed_at` for each ID.
- Private comments go to the owner's inbox instead.

### Inbox items

An `InboxBox`: the padded `Signed` of type 5 under a random 32-byte item key `k`, and `k` wrapped for each recipient device key the sender chose (Device inbox keys):

```
struct {
  opaque ciphertext<V>;  /* AES-256-GCM(k, nonce = 12 zero bytes, aad = label("inbox") || recipient profile ID, padded Signed) */
  DeviceWrap wraps<V>;   /* 1–32, one per device */
} InboxBox;
struct {
  opaque device[32];
  uint64 created_at;     /* of the device key record, which names the key */
  HpkeBox wrap;          /* k, HPKE base mode to that key, info = label("inbox") || recipient profile ID || device || created_at, empty aad */
} DeviceWrap;
struct {
  opaque sender[32];
  opaque recipient[32];
  opaque id[16];
  uint64 created_at;
  uint16 kind;
  opaque payload<V>;
  opaque keys<V><V>;     /* the sender's device key records, or none */
} InboxItemBody;
```

- A device opens the wrap of its own device and key. `keys` holds up to 8 of the sender's device key records, newest per device, whenever they changed since the sender's devices last carried them to this recipient, so a recipient who answers seldom needs to read them from a host. The recipient keeps them for the sender after checking each against the sender's card.
- A device that keeps an item for later, such as a message ahead of the conversation it belongs to, keeps it opened, so deleting the key loses nothing.

- The signer must be a device in the sender's card, with these exceptions. For kinds 4, 7 and 9 the signer must be in the card the payload carries, which must be the sender's. For kind 6 the sender must be the recipient's own profile and the signer the device the link request names, verified with the signing key the request carries.
- `recipient` must be the reader's own profile. A device refuses an item more than 30 days old or more than 10 minutes in the future, and an `id` it has already processed.

| `kind` | Payload |
|---|---|
| 1 notice | JSON `{"revision": n, "head"?, "objects"?, "box"?, "keyring"?}`: a new publication, with the signed head in base64url; in `objects`, the ciphertext of manifest parts it added, base64url by object name, at most 40 KiB of ciphertext in all; and, for the publication of an audience rotation, the recipient's audience box and the keyring in base64url. Or `{}`, a friendship that ended. Or `{"deleted": true}`, the sender deleted their profile: the recipient's devices end the friendship and delete what they kept of the sender (card, keys, posts, cached files, the sender's entries in the recipient's own threads, deliveries waiting for them) and keep conversations |
| 2 message | JSON `{"id", "conv", "text", "created_at", "name", "photos"}`, each photo a thumb and display `{"hash", "ref"}` with the `ObjectRef` of a copy on the sender's host; or `{"id", "conv", "deleted": true}`, its author deleting it for everyone |
| 3 receipt | JSON `{"conv", "ids"}`: messages of a two-person conversation that arrived |
| 4 acceptance | `Acceptance` |
| 5 private comment | comment JSON |
| 6 link request | `LinkRequest` |
| 7 card changed | the sender's `Signed` card |
| 8 conversation | JSON `{"conv", "owner"?, "name"?, "topic"?, "members"?, "contacts"?}`: conversation rows and contact entries (Conversations) |
| 9 question | `Question`: a private question about a group post, or a report to a group's owner (Groups: questions) |
| 10 bundle | JSON list of `{"kind", "payload"}`, each a kind 2, 3 or 8 item's kind and JSON payload: a sender's items to one member, in the order they were written, at most 48 KiB of payload JSON. Each is handled as its own item; parts of any other kind are ignored. |

```
struct {
  opaque invite[16]; opaque proof[32]; opaque card<V>; opaque name<V>;
  opaque friendship[32];  /* the friendship secret the sender chose */
  opaque box<V>;          /* the sender's audience box for the recipient */
  opaque keyring<V>;      /* the sender's KeyringBox */
  opaque head<V>;         /* the sender's signed head, or empty */
  opaque objects<V><V>;   /* manifest parts that head names, each an object's ciphertext */
} Acceptance;
struct { opaque card<V>; opaque body<V>; } Question;
```

An acceptance carries what its reader would otherwise read from the sender's hosts: the sender's audience box for the recipient, which the sender also stores, the keyring, and the head and as many manifest parts as fit in the item with the rest, the root first; the head is left out when it doesn't fit. The reader checks each as if it had fetched it: the box with its inbox key and the acceptance's friendship secret, the keyring under the box's key, the head against the sender's card and the parts against the references that name them.

### Conversations

A conversation is a set of members, 2–32 profiles, who send each message and each membership change to every other member's inbox. What a sender has waiting for one member goes in one item, a bundle when there is more than one, so a new conversation and its first message reach each member together and in order. Members needn't be friends.

- **Identity.** A conversation ID is its creator's profile ID followed by 16 random bytes, 65 base64url characters. Any number of conversations may have the same members.
- **Rows.** Each member keeps the conversation in their own log: `conv-owner` `{"id", "owners", "stamp"}`, `conv-name` `{"id", "name", "by", "n", "stamp"}`, `conv-topic` `{"id", "group", "post", "title", "by", "n", "stamp"}` for a conversation started from a group post, and one `member` row per profile who was ever in it, `{"id": conv ‖ profile, "conv", "profile", "state", "by", "n", "stamp"}`, `state` being `in`, `left` or `removed`. `stamp` is `{"at", "id"}`, `at` greater than the stamp of the row it replaces and `id` random. Rows of one key merge by the higher stamp, ordering `at` then `id`, so every device converges whatever order items arrive in.
- **Ownership.** `owners` is the chain of owners, starting with the creator; the last is the current owner. `n` on a row is the index in `owners` of the owner who wrote it. An owner who leaves appends the member who came in earliest to the chain and marks themself `left` in one change.
- **Who writes what.** Only the owner at index `n` writes `in` and `removed` member rows, the name and the topic; any member writes their own `left` row. A member accepts the owner's rows from the current owner, a row of an earlier owner when the current owner passes it on, a `left` row from the member leaving or from the owner, and the owner chain from the current owner only when it extends the chain it holds. A row naming an ownership index the member hasn't heard of yet is kept and tried again once the chain reaches it. A conversation new to a device is taken whole from its current owner, and only when it lists the device's profile as `in`. Messages are accepted only from members who are `in`.
- **Fan-out.** The owner sends a new member every row, and every other member the changed rows. An owner device records on each row who it was sent to; another own device that sees a member the row missed sends it to them. The owner passes every `left` row it receives to the other members.
- **Contact entries.** `contacts` holds `{"profile", "hosts", "tokens", "version", "name"}`: a member's card hosts with each host's contact token, and the card version they come from. The owner sends everyone's entry to a new member, and the new member's to everyone. A member sends their own entry to every co-member when an item lists it with an older card version or other tokens, such as the reply slot a question gave, and whenever their card changes (a move, a host added or removed, a device linked or removed). A member keeps the entry with the higher card version; for one version, an entry whose first token is a contact token replaces one whose first token is a slot token, and then the higher token counter wins. It posts to non-friends with the entry it keeps. A device holding no card for a contact reads it from the contact's hosts. Contact entries go at most eight to an item. A message waiting for someone who has since left or been removed is dropped, and an item refused for an expired token to someone who isn't a friend and shares no conversation any more is final; to anyone else it waits for their next entry.
- **Receipts.** Only in a two-person conversation does the recipient answer a message with a receipt.
- **Deleting messages.** A deleted message keeps its row with empty `text` and `photos` and `deleted` `{"at", "for"}`, `for` being `me` or `everyone`, so an item handled again can't bring it back; a message row deleted for everyone outranks one deleted for me, which outranks the live message, whatever order own devices write them in. Its author deletes a message for everyone by sending its deletion to every other member: a send of the message still waiting carries the deletion instead. A member accepts a deletion only from the message's author, keeps a "Message deleted" row even for a message it hasn't received, and removes its photo copies. A message whose photo is already gone from its author's host waits in the held queue for the deletion. Rows deleted for me alone are removed 31 days after their deletion, past the inbox item lifetime.
- **Contact rotation.** A person replaces their contact tokens with every audience rotation, and when someone who isn't their friend stops sharing any conversation with them. They hand out the next contact tokens first: in the keyring, and in a contact entry to every co-member. Once every co-member's item is posted, or a day after it began, they advance the counter on every host to the next, which retires every token a removed person holds; with no co-member to tell, an audience rotation's batch advances it. Two people rotating at once can still post to each other until both have handed out the next tokens, so neither waits for a token the other can't deliver. A rotation needed while one is in progress follows it.

## Invitations

The inviter picks a 32-byte link secret `s` and a 32-byte release secret `h`, and gives the host `h` with the invitation. The link is `https://anewinter.net/invite/#<base64url s>`, followed by `.` and the base64url inviter tenant URL; the secret never appears in a path, query or log.

```
struct {
  uint64 expires_at;
  opaque nonce1[12];
  opaque public<V>;    /* AES-256-GCM(Derive(s, "invite", 32), nonce1, aad = label("invite"), padded InvitePublic) */
  opaque nonce2[12];
  opaque keys<V>;      /* AES-256-GCM(Derive(s || h, "invite keys", 32), nonce2, aad = label("invite keys"), padded InviteKeys) */
} Invitation;
struct { opaque card<V>; opaque name<V>; } InvitePublic;
struct {
  uint32 generation; opaque audience_key[32]; opaque keyring<V>; opaque offer<V>;
  opaque head<V>; opaque objects<V><V>;
  opaque keys<V><V>;   /* the inviter's device key records, up to 8 */
} InviteKeys;
```

- The host stores it at `invites/<lookup>`, where the lookup is `Derive(s, "invite lookup", 16)`, and deletes it at `expires_at` (at most 30 days away).
- `POST invites/<lookup>/redeem` carries a random 32-byte claim that the redeemer keeps before asking. It returns `h` to the first claim and again only to that claim; any other claim gets 410. A leaked, unredeemed link reveals only the inviter's card and name.
- `offer` is empty or a hosting offer: `struct { opaque tenant_host<V>; opaque secret[32]; uint64 quota; }`. The secret is a 16-byte offer ID followed by the first 16 bytes of `HMAC(host secret, label("offer") || offer ID)`. The host keeps the offer ID with its quota and expiry and accepts it once; `quota` is for display, and the host's record is authoritative. A guest offer, which a member asks their host for, has the same form; the host also keeps which member asked.
- `audience_key` is the inviter's audience key of `generation`, and `keyring` the inviter's `KeyringBox` for it, so the friend holds every host's tokens from the start. `keys` are the inviter's device key records, so the acceptance needs no read of them.
- `head` is the inviter's signed head for `generation`, or empty when it doesn't fit, and `objects` holds manifest parts it names, the root first, as many as fit in the invitation with the rest. The reader checks them as if it had fetched them, and reads only the missing parts from the host. Every publication, and every audience rotation, re-uploads each waiting invitation in its batch, so a redemption gets the current key, keyring and head.
- Acceptance is an inbox item of kind 4 to the inviter, posted to the inviter's first host with that host's contact token. `invite` is the invitation's lookup and `proof` is `HMAC(Derive(s, "acceptance", 32), label("acceptance") || card)`. Anyone holding a contact token can post, so the inviter accepts only an acceptance whose proof matches a waiting invitation's secret.
- The person accepting chooses the friendship secret, stores their audience box for the inviter on their own hosts with the records of the new friendship, then posts the acceptance. The acceptance is sealed to the inviter's inbox key, so the friendship secret reaches only the inviter. The inviter, handling a valid acceptance, stores the new friend's audience box with the friend's records and deletes the invitation, in one batch, and sends nothing back: adding a friend leaves the audience key as it is.

## Device links

The device showing the link picks a 32-byte secret `l`. The link is `https://anewinter.net/link#<base64url l>.<base64url tenant URL>.<base64url write token>.<base64url device ID of the device showing it>`, followed by `.scan` for a link shown as a QR code. A link without a suffix travels between devices, so both devices compare the code before the device showing the link approves. A scan link admits one request, which that device approves without a code.

```
struct { opaque device[32]; opaque signing_key[1312]; opaque name<V>; opaque proof[32]; } LinkRequest;
```

`device` and `signing_key` are the new device's public key, which the approved card lists. `proof` is `HMAC(Derive(l, "link", 32), label("link request") || device || signing_key)`, and the device name is at most 64 characters. Both devices show the six-digit code `uint32(first 4 bytes of HMAC(Derive(l, "link", 32), label("link code") || existing device ID || new device ID)) mod 1,000,000`. After approval, the existing device writes the reply to `links/<Derive(l, "link lookup", 16)>`:

```
struct { opaque nonce[12]; opaque sealed<V>; } LinkReply;  /* AES-256-GCM(Derive(l, "link reply", 32), nonce, aad = label("link reply"), padded LinkReplyBody) */
struct { uint32 generation; opaque key[32]; } OwnerKey;
struct { opaque card<V>; OwnerKey owner_keys<V>; } LinkReplyBody;   /* every owner key generation the device holds */
```

The new device reads it with conditional `GET`s every 2 s while the link screen is open, for at most 10 minutes. The host deletes it after the first successful read or after 10 minutes.

Approval signs a card that adds the new device, so the device showing the link opens `S` before it shows the link and keeps it in memory only until the request is approved or declined, the link is closed or it expires. Before it puts the reply it seals a snapshot under the current owner key generation. The new device asks the host for its own owner token (`POST /tokens`) once the card lists it, then reads the snapshot and the log, which hold the audience key, every friend's key and tokens, and the inbox keys, and writes its seal key record.

A move link, `https://anewinter.net/link#<base64url tenant URL>.<base64url device ID>.move`, moves a profile from a browser to another one on the same device, such as Safari to the Home Screen app. It holds no secret. The browser that opens it joins with `S` (Recovery) and removes the device the link names, which must be in the card.

## Groups

A group lives in its own tenant, which holds its owner's card. Whoever holds a link to the group reads its access box, which holds the group keys and the group's tokens.

### Group keys, head and walls

- The group key `G` of generation `n` (from 1) is 32 random bytes.
- The group's head is a `Head` sealed under `G`: `group` is the 16-byte group ID, `generation` the key generation, and the head key `Expand(G, "head", 32)`. A device in the owner's card signs it, and `profile` is the owner's. A reader keeps the highest revision it verified for each group, apart from the revision it keeps for the owner's profile, and refuses a lower one.
- Wall `w` of generation `g` is a thread whose thread key is `Expand(G_g, "wall" || uint32 w, 32)`; its thread ID is `Expand(T, "thread id", 16)` as for every thread, and its entries are `ThreadBox`es. Wall numbers rise by one and are never reused.

### Group manifest and wall entries

The head names an object holding the manifest JSON:

```
{"kind": "group"|"market", "closed": bool, "group": {"name", "about", "rules"},
 "walls": [{"n", "gen"}, ...], "posting": n, "hidden": [profile, ...], "categories"?: [name, ...], "report"?: {"host", "token"}}
```

- `name` is 1–80 characters, `about` at most 2,000 and `rules` at most 4,000.
- `walls` lists every wall open on the host, oldest first, with the key generation each uses: at most 13. `posting` is the wall members were posting to when it was published.
- `hidden` lists at most 1,000 profiles whose entries readers drop. `categories`, in a market, is at most 24 names of at most 40 characters.

A wall entry is a thread entry whose `entry` is JSON of at most 12 KiB:

```
{"type": "post", "id", "name", "text", "photos": [{"thumb": ObjectRef, "display": ObjectRef}], "target": null | "<post id>",
 "created_at", "edited_at", "deleted"?: true}
{"type": "like", "id", "name", "target": "<post id>", "liked", "changed_at"}
{"type": "remove", "target": "<post id>", "author": "<profile>", "at"}
```

- IDs are 16 random bytes in base64url. Text is at most 4,000 characters, a name at most 80, and a post has at most four photos; a deleted version has empty text and no photos. A reader skips an entry that fails any field rule, or whose times are more than 10 minutes ahead of its clock.
- A post is its author and `id`, and so is a like; an entry by another author never replaces one. A reader keeps the version with the highest `edited_at` (`changed_at` for likes), and once it has seen a deleted version it keeps that. It honours a `remove` only from the group's owner, and then drops every version of that post. The host's order never decides.
- The posting wall is the first wall, from `posting` on, whose next sequence is below 1,800. A full wall never changes for members again, so a reader reads it to its end once. A poster whose posting wall is under an older key generation than its newest reads the head again first.

### Access boxes

```
struct { opaque nonce[12]; opaque sealed<V>; } AccessBox;
/* sealed = AES-256-GCM(Derive(a, "access", 32), nonce, aad = label("access") || lookup, padded AccessBody) */
struct {
  opaque group[16];
  uint32 generation;       /* of the first key */
  opaque keys<V>;          /* 32-byte group keys, newest generation first, 1–4 */
  opaque read_token<V>;    /* group read token */
  opaque write_token<V>;   /* group write token */
  opaque name<V>;          /* the group's name, 1–80 characters */
  opaque tenant<V>;        /* the tenant URL the group lives at */
  opaque offer<V>;         /* empty, or a hosting offer as in an invitation */
} AccessBody;
```

- `a` is an access secret of 32 random bytes. The box is stored at `access/<lookup>` on the group's tenant, where the lookup is `Derive(a, "access lookup", 16)`. A box is at most 4 KiB.
- `generation` is at least the number of keys, so every key has a generation of 1 or more. Each token is non-empty UTF-8 of at most 64 bytes.

### Listings and questions

- A post in a marketplace may carry `"listing": {"kind": "offer"|"wanted", "title", "price", "currency", "category", "area", "state": "open"|"held"|"sold", "expires_at"}`: a title of 1–80 characters, a price in whole units from 0 to 1,000,000, a currency of three capital letters, a category from the manifest's `categories` (empty when it has none), an area of at most 60 characters, and `expires_at` at most 31 days after `edited_at`. A reply carries no listing. Readers don't show a listing past `expires_at`.
- A post may carry `"ask": {"host", "token"}`: the author's first tenant URL and a slot token there. A person keeps at most 64 slots open.
- A question is an inbox item of kind 11 posted with the post's slot token. `card` is the sender's signed card and `body` is JSON `{"kind": "question"|"report", "group", "post", "author", "title", "text", "name", "contact"}`: `text` of 1–500 characters and `contact` the sender's contact entry whose only host and token are a reply slot on their first host. The recipient keeps a question only when it names a post of theirs that carries `ask`, and a report only when it names a group they own; at most 20 unanswered questions for one post and 200 in all.
- The author answers with a conversation whose `conv-topic` names the group and post, sent to the reply slot. The author lists the asker's entry with the reply slot, so the asker then sends their contact entry, and closes the reply slot. An unanswered question's reply slot closes after 14 days.
- A report goes to the slot the manifest names in `report`, on the owner's first host. When 20 wait there, the owner's device replaces the slot with the next publication, at most once a day.

### Group rotation

Revoking closed links, changing an open group's link and replacing every link are one procedure, in this order, each step repeatable: delete the revoked boxes; open walls under the new key, whose first becomes the posting wall; write every remaining box with the new key first and the tokens for the next group counter; publish the manifest and head under the new generation; advance the group counter. Advancing before the boxes are written would leave every member without working tokens.

### Group links

The link is `<app>/group#<base64url a>.<base64url tenant URL>.<base64url owner profile ID>`, where `<app>` is the origin of the app that made it. The secret never appears in a path, query or log. A device that opens it reads the box, then the tenant's card, which must be the link's profile; then the head, which must be signed by a device in that card and open under a key from the box.


## Recovery

- **Passkey backup.** Offered only after a second WebAuthn assertion returned the same PRF output as the first. Every host in the card stores it. The backup is `struct { opaque nonce[12]; opaque sealed<V>; }` with `sealed = AES-256-GCM(Derive(PRF output, "passkey backup", 32), nonce, aad = label("passkey backup") || profile ID, padded S)`, stored at `recovery/passkey`. The PRF input is `label("passkey prf")`. The passkey's user handle is `tenant ID || uint8 scheme || UTF-8 host` when that fits in 64 bytes, otherwise the tenant ID alone; the scheme is 0 for `https` and 1 for `http`, and the tenant URL is `<scheme>://<host>/t/<tenant ID>`. The handle only locates the backup, and a typed profile address may name any host, since only the PRF output opens it.
- **Written recovery key** as above.
- **Joining with `S`.** From the passkey backup or the written recovery key: derive the profile and recovery keys; sign a card that adds the new device's public key, and put it with the new device as the request's signer; open every owner key generation's `recovery` seal; read the latest snapshot and the log after it, which hold the audience key, every friend's key and tokens, and the inbox keys; take the inbox private key that matches the card; write the device's seal key record. Every other device and every friend stays, and nothing waits for another device or a friend. The device keeps the join's progress but not `S`, so after a closed tab the next time the person opens `S` the join continues with the device key it started with.
- **Card changes.** Any device in the card links or removes devices and adds, moves or removes hosts by signing the next card with `S` opened for that change. The host takes only a strictly higher version, so when two devices sign the same version the second gets 409, reads the stored card and signs the change again on top of it.
- **Removing a device** signs a card without it and with a new inbox key, publishes a new owner key generation sealed to the remaining devices' seal keys and the recovery key, writes a snapshot under it, so a device that later joins with `S` reads records signed only by devices in the card, and rotates the audience key (Audience rotation). Each friend rotates their own audience key when they read the card, since the removed device held their keys too.

## Locked browsers

A locked browser keeps its copy of the profile sealed under a 32-byte random local key `K`. Only that browser reads any of it; nothing here is sent to a host.

- **Lock.** `struct { SealedBox passkey; SealedBox recovery; } LocalLock`, with `SealedBox` = `struct { opaque nonce[12]; opaque sealed<V>; }`. `passkey.sealed = AES-256-GCM(Derive(PRF output, "local lock", 32), nonce, aad = label("local lock") || profile ID, padded K)`, and `recovery.sealed` is the same under `Derive(S, "local lock", 32)`. The PRF output comes from the passkey backup's PRF input, and a browser locks only with a passkey whose output opens the passkey backup. Replacing the passkey on the browser reseals `passkey` under the new output and keeps `recovery`.
- **Records.** The record under key `k` in store `s` is a `SealedBox` with `sealed = AES-256-GCM(Expand(K, "local value", 32), nonce, aad = label("local record") || struct { opaque store<V>; opaque key<V>; }, padded value)`, where `store` and `key` are the UTF-8 `s` and `k` and the value is in the app's own encoding (`src/core/local-seal.ts`).
- **Files.** The file at path `p` is a `SealedBox` under the same key with `aad = label("local file") || UTF-8 p`.
- **Names.** Each `:`-separated segment of a record key, and each segment of a file path except the profile ID, is stored as `base64url(t || c)`: `t` is the first 16 bytes of `HMAC(Expand(K, "local name mac", 32), label("local name") || segment)` and `c` is the segment under AES-256-CTR with key `Expand(K, "local name", 32)` and initial counter block `t`. Opening a name decrypts it, recomputes `t` and refuses a mismatch. A segment always gives the same name, so a key is found by its name and a prefix of whole segments lists as one range. The file at `<kind>/<profile ID>/<rest>` is stored at `locked/<profile ID>/` followed by the names of `kind` and of each segment of `rest`.

## Transfer

```
struct { opaque tenant[16]; opaque new_host<V>; uint64 expires_at; } TransferGrantBody;
```

Signed by a device in the tenant's card, at most 24 hours ahead. The new host presents it to the old one and pulls every stored item.

## Limits

| Item | Limit |
|---|---|
| Object plaintext | 16 MiB |
| Manifest part plaintext | 4 MiB |
| Card body | 48 KiB |
| Head body | 4 KiB |
| Owner key record body | 48 KiB |
| Log entry plaintext | 256 KiB |
| Thread entry plaintext | 16 KiB of entry JSON, beside the carried card; 2,000 entries per thread |
| Inbox item plaintext | 64 KiB of payload beside the carried device key records; 2,000 items or 16 MiB per inbox |
| Device inbox keys | a new one at least every 3 days; up to 32 wraps per item |
| Invitation | 64 KiB; 30 days |
| Clock window / nonce memory | 60 s / 120 s |
| Writes per token | 60 per minute; 600 for a group write token |
| Access box | 4 KiB; 10,000 per tenant |
| Group write token | appends while a thread's next sequence is below 1,800; objects of at most 512 KiB of ciphertext |
| Slots | 64 open per tenant; 20 unread items per slot; 200 items or 4 MiB through slots per inbox |
| Questions | 500 characters; 20 unanswered kept per post, 200 in all |
| Listings | title 80 characters, area 60, price 0–1,000,000 whole units, at most 31 days open; 24 categories of 40 characters |
