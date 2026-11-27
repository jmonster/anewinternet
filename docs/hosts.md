# commonwire hosts

This document is normative for the HTTP API that every host serves, whether it is `commonwire` on a person's machine or the Cloudflare Worker. `rust/cw-host` is its only implementation, and the conformance suite in `rust/cw-conformance` checks it against both runtimes. Every structure named here is defined in `docs/format.md`.

## Runtimes

- **`commonwire`** serves HTTPS on port 443 with certificates from ACME (TLS-ALPN-01), HTTP/2 and HTTP/1.1. It keeps one SQLite database per tenant and one for the host in its data directory, and stores objects as files. Asked to stop, it stops accepting, closes push sockets and lets requests in flight finish for at most 5 seconds. `commonwire service install` runs it at boot under an account of its own, restarted a second after it exits: a LaunchDaemon as `_commonwire` on macOS, a systemd unit with a dynamic user and its data in `/var/lib` on Linux, and a Windows service as LocalService. Installing again replaces the program and restarts it; `commonwire service uninstall` removes the service and the program and keeps the data.
- **Cloudflare** runs a Worker in front of two Durable Object classes, both SQLite-backed: one `Host` object for host-level state and one `Tenant` object per tenant. Objects are stored as 1 MiB rows. No other Cloudflare product holds data.
- Both run the same `cw-host` request handlers and SQL statements. The runtime supplies storage, the clock, randomness, open push sockets, and outbound fetches.

## Request classes

Every request is classified by method and path before anything is stored or read. The gate runs in memory: in the Worker before any Durable Object is called, and in `commonwire` before any database access.

| Class | Credential | Gate check | Further checks |
|---|---|---|---|
| Open | none | tenant ID MAC; per-IP rate limit | — |
| Signed | owner request signature | tenant ID MAC; per-IP rate limit | signer in the tenant's card; nonce |
| Read | read or owner token | tenant ID MAC; token MAC; token tenant | token counter current or next |
| Write | write or owner token | as Read | token counter current or next; 60 writes per token per minute |
| Owner | owner token and owner request signature | as Read, owner kind, epoch 0 | signer in card; nonce |
| Grant | `CW-Grant` transfer grant | tenant ID MAC; per-IP rate limit | grant signed by a device in the card, unexpired, for this tenant |
| Admin | admin token and admin request signature | admin token MAC | signer is the claimed admin key; nonce |
| Claim | `CW-Claim` claim secret | claim digest | host not yet claimed |
| Offer | `CW-Offer` hosting offer secret | offer MAC; per-IP rate limit | offer unused and unexpired |

A contact token also passes the Read check for `GET /objects/<name>` and the Write check for `POST /inbox`, and no other path. Its counter must be the tenant's contact counter or the next one.

Group and slot tokens (`docs/format.md`, Groups) pass these checks and no others:

- a group read token, the Read check for `GET /head`, `GET /threads/<thread>` and `GET /objects/<name>`;
- a group write token, the Write check for `POST /threads/<thread>`, only to a thread the owner opened whose next sequence is below 1,800, and `PUT /objects/<name>` of at most 512 KiB, with 600 writes per token per minute;
- a slot token, the Write check for `POST /inbox`.

Group tokens carry the tenant's group counter or the next one; a slot token works while its slot is open. Read, write and owner tokens keep every power they have, and a write token still makes a thread by posting to it.

Requests that fail the gate get 401 (or 404 for a tenant ID whose MAC fails) and touch no storage. Per-IP limits run in the gate, in memory, with each IPv6 address counted by its first 64 bits: 120 requests per minute for Open, Signed, Grant and Offer requests together; 600 for requests with a group read token; 30 for requests with a group write token; and 30 for requests with a slot token.

Owner request signatures use `CW-Device`, `CW-Time`, `CW-Nonce` and `CW-Signature` as in `docs/format.md`; admin requests put the Ed25519 half of the admin public key in `CW-Admin`, and the host verifies with the whole key it stored at claim. A host remembers each nonce for 120 seconds.

## Responses

- Errors are `application/json` bodies `{"error": "<code>"}`:

  | Status | Codes |
  |---|---|
  | 400 | `malformed` |
  | 401 | `unauthorized`; `expired-token` for a token from an earlier counter or a closed slot; `expired`, with `CW-Time` naming the host's time in ms, for a signature timestamp more than the clock window from when the request's headers arrived; `replay` |
  | 403 | `forbidden`, `read-only`, `unclaimed` |
  | 404 | `not-found` |
  | 409 | `conflict` |
  | 410 | `gone` |
  | 412 | `precondition`, with `CW-Current` naming the current revision or sequence |
  | 413 | `too-large` |
  | 429 | `rate`, with `Retry-After` in seconds |
  | 500 | `storage`, when the host's storage fails |
  | 507 | `quota`, `inbox-full`, `thread-full`, `guest-limit`, `access-limit`, `slot-limit`, `slot-full` |

- Every response allows any origin (`Access-Control-Allow-Origin: *`), exposes `ETag`, `CW-Current`, `CW-Epoch`, `CW-Seq`, `CW-Index` and `Retry-After`, and answers preflights for the request headers above, `If-Match` and `If-None-Match`, with `Access-Control-Max-Age: 86400`. Hosts use no cookies.
- Changing resources carry an `ETag` and `Cache-Control: no-cache`, so browsers revalidate them with `If-None-Match` from their own cache and get 304 when nothing changed. Objects carry `Cache-Control: private, max-age=31536000, immutable`.
- **Lists** are encoded as `struct { Entry entries<V>; } Entries` with `struct { uint64 position; opaque bytes<V>; } Entry`. A list response holds at most 1,000 entries or 4 MiB, and carries `CW-Current` with the newest position the host holds.

## Host paths

| Method and path | Class | Body → response |
|---|---|---|
| `POST /claim` | Claim | 1,344-byte admin public key → JSON `{"admin_token"}`. 409 once claimed. Until then every other path answers 403 `unclaimed`. |
| `GET /push/key` | Open | → the VAPID public key, 65 bytes uncompressed P-256 |
| `POST /tenants` | Offer | `Signed` card → JSON `{"tenant", "url", "tokens"}`, with the offer's quota; `tokens` is the `POST /tokens` answer for the card's first device. Each takes one of the offer's places; 410 when none is left or the offer expired. A guest offer makes a guest; 507 `guest-limit` when the host is full of guests. |
| `POST /admin/tenants` | Admin | JSON `{"card": "<base64url Signed card>", "quota": bytes}` → JSON `{"tenant", "url", "tokens"}`, as `POST /tenants` answers |
| `GET /admin/tenants` | Admin | → JSON list of `{"tenant", "created_at", "quota", "used", "requests_today", "budget", "budget_override", "last_write", "state", "notice_until", "sponsor", "offer"}`; `budget` is today's budget and `budget_override` the one set for this tenant, otherwise null; `sponsor` is the tenant that invited a guest, otherwise null; `offer` is the admin offer the tenant was made with, otherwise null |
| `PUT /admin/tenants/<tenant>/quota` | Admin | JSON `{"quota"}` |
| `PUT /admin/tenants/<tenant>/budget` | Admin | JSON `{"budget"}`, 1,000–10,000,000, or null → this tenant's daily budget, which replaces the host setting for it and which `PUT /admin/settings` leaves; null returns it to the host setting |
| `POST /admin/tenants/<tenant>/approve` | Admin | JSON `{"quota"}` → a guest becomes a member with that quota and the member budget. 404 unless the tenant joined as a guest and was not approved or removed. |
| `POST /admin/tenants/<tenant>/notice` | Admin | JSON `{"days"}`, 1–90 → the tenant becomes read-only until then, then is removed |
| `DELETE /admin/tenants/<tenant>` | Admin | removes the tenant now |
| `DELETE /admin/host` | Admin | destroys the host → 204: every tenant deletes everything it holds and the runtime deletes its storage (its database and objects natively, `deleteAll()` on its Durable Object), then the host empties its own tables, keeping only a mark, and `commonwire` vacuums its database. From then on every host request answers 410 `destroyed`, a claim with the old setup link included, and tenant requests 404. |
| `POST /admin/offers` | Admin | JSON `{"quota", "expires_at", "places"}` → JSON `{"offer", "secret"}`. `expires_at` at most 90 days away; `places`, 1–1,000 (1 when left out), is how many tenants the offer makes, each with `quota`. |
| `DELETE /admin/offers/<offer>` | Admin | withdraws the offer's places left; tenants made with it stay. 404 when none is left. |
| `GET /admin/settings` | Admin | → JSON `{"guests", "guest_limit", "member_budget", "guest_budget"}` |
| `PUT /admin/settings` | Admin | the same JSON → the settings, applied to every tenant. `guests` is a boolean, `guest_limit` 0–10,000, budgets 1,000–10,000,000. |

A tenant's state is `active`, `guest`, `notice` or `removed`. Removing deletes everything except the card, which the host keeps serving for 7 days as the forwarding card; every other tenant path then answers 410.

### Guests and budgets

- **Guests.** When the admin turns `guests` on (it starts off), a member can ask for a guest offer (`POST /guests`) to put in an invitation. The tenant it makes is a guest: 10 MiB (10,485,760 bytes) for 30 days, with writes allowed. Then it is under notice for 30 days, read-only, and then removed, unless the admin approves it first. Guests can't make guest offers.
- **Limits.** A member holds at most 25 guest offers and guests at once: unused, unexpired offers plus guests in their first 30 days. A host holds at most `guest_limit` guests (100 to start), counting unused guest offers and guests until 60 days after they joined, unless approved or removed. Past either limit, the request answers 507 `guest-limit`.
- **Budgets.** Every request to a tenant counts toward its daily budget, which resets at midnight UTC: `member_budget` (20,000 to start) for members and `guest_budget` (5,000) for guests, unless the admin set a budget for that tenant (`PUT /admin/tenants/<tenant>/budget`), which wins. Past it, requests answer 429 `rate` with `Retry-After` until midnight. Budgets keep one tenant from using a host's whole day; requests over budget still reach the host, and the app waits for `Retry-After`.
- **Requests without a current token.** A request has a current token when its token's MAC verified and its counter is the tenant's current one for that kind (or the next, for contact and group tokens), or its slot is open. Requests without one, including every Open and Signed request, may use half of the day's budget: past that half they answer 429 `rate` until midnight, and those refused don't count. The ones answered count toward the whole budget. Retired tokens and open paths can't use up the half that owners, friends and members with current tokens use.

## Tenant paths

Under the tenant URL `/t/<tenant>`.

| Method and path | Class | Body → response |
|---|---|---|
| `DELETE /` | Owner | removes the tenant now, as `DELETE /admin/tenants/<tenant>` does. A person who moved to another host removes the old tenant after the card there names the new host first. |
| `GET /card` | Open | → `Signed` card. `ETag` is the version. |
| `PUT /card` | Signed | `Signed` card, verified against the stored card's profile, version strictly higher. The signer of the request may be a device in the stored card or in the card it carries, which is how a device joining with the profile key adds itself. |
| `POST /tokens` | Signed | → JSON `{"owner", "read", "write", "read_next", "write_next", "audience", "contact", "contact_next", "contact_counter"}`: the device's owner token, the read and write tokens for the audience counter and the next one, the audience counter, the contact tokens for the contact counter and the next one, and the contact counter |
| `POST /tokens/audience?to=<n>` | Owner | advances the audience counter to `n`, which retires every read and write token before it, and answers `{"read", "write", "read_next", "write_next", "audience"}` for the new counter. `n` at or below the counter changes nothing; `n` beyond the next is 400. |
| `POST /tokens/group` | Owner | → JSON `{"read", "write", "read_next", "write_next", "counter"}`: group read and write tokens for the group counter and the next one, and the counter |
| `POST /tokens/group?to=<n>` | Owner | advances the group counter to `n`, which retires every group token before it, and answers as above. `n` at or below the counter changes nothing; `n` beyond the next is 400. Allowed under notice. |
| `POST /tokens/contact?to=<n>` | Owner | → JSON `{"contact"}`: advances the contact counter to `n`, which retires the contact tokens before it, and returns the current one. `n` at or below the counter changes nothing; `n` beyond the next is 400. |
| `GET /status` | Owner | → JSON `{"state", "notice_until", "quota", "used", "inbox", "inbox_bytes", "guests"}`. For a guest, `notice_until` is when its 30 days end. `guests` says whether this tenant can make guest offers. |
| `PUT /keyring` | Owner | `KeyringBox`, replacing the stored one |
| `GET /keyring` | Open | → the newest `KeyringBox`. `ETag` changes with every put. |
| `GET /head` | Read | → `Signed` head. `ETag` is the revision. |
| `PUT /head` | Owner | `Signed` head by a device in the card, `If-Match: <revision>` (0 for the first). 412 unless that is the stored revision and the new one is higher. |
| `GET /objects` | Owner | → `{"objects": [{"name", "size", "created_at"}], "next"}`, in name order, at most 1,000; `?after=<name>` with `next` reads on. |
| `PUT /objects/<name>` | Owner | ciphertext whose SHA-256 is the name. Idempotent. |
| `GET /objects/<name>` | Read or Grant | → ciphertext |
| `DELETE /objects/<name>` | Owner | |
| `POST /log` | Owner | `Signed` log entry, `If-Match: <seq>` → 201. 412 unless `seq` is the next one and `previous` is the digest of the entry before; 409 `generation` for a generation below the newest owner key stored. |
| `GET /log?from=<seq>` | Owner | → `Entries` |
| `PUT /snapshot` | Owner | `Signed` snapshot whose seq is higher than the stored one and at most the newest entry, of no generation below the newest owner key stored (409 `generation`). Storing it removes the log entries through its seq. |
| `GET /snapshot` | Owner | → `Signed` snapshot |
| `PUT /ownerkeys` | Owner | `Signed` owner key, at most 48 KiB. Kept per generation; the same record again is 204, another record of a stored generation 409. |
| `GET /ownerkeys` | Owner | → `Entries` by generation |
| `DELETE /ownerkeys/<generation>` | Owner | removes the record of a generation below the newest → 204 (409 for the newest) |
| `PUT /devicekeys` | Owner | a `Signed` device key record of a device in the card, for its profile; replaces an older record of that device, so any own device can put every own device's |
| `GET /devicekeys` | Open | → `Entries` of the newest record of each device in the card, position its `created_at` |
| `PUT /recovery/passkey` | Owner | the passkey backup |
| `GET /recovery/passkey` | Open | → the passkey backup |
| `POST /inbox` | Write | an `InboxBox` whose wraps name, for every device with a record here, that device's newest; otherwise 409 JSON `{"error": "device-keys", "keys": [<base64url record>, …]}` with the current records → 201 with `CW-Seq`. 507 `inbox-full` past 2,000 items or 16 MiB. With a slot token, 507 `slot-full` past 20 items from that slot, or 200 items or 4 MiB from every slot, still in the inbox. |
| `GET /inbox?from=<seq>` | Owner | → `Entries`, each an `InboxEntry` |
| `DELETE /inbox?through=<seq>` | Owner | removes items up to that seq |
| `POST /threads/<thread>` | Write | a `ThreadBox` → 201 with `CW-Seq`. 507 `thread-full` past 2,000 entries. With a write token, the host also notes the entry in the tenant's inbox, as below. |
| `GET /threads/<thread>?from=<seq>` | Read | → `Entries`. `ETag` is the newest seq. |
| `DELETE /threads/<thread>/<seq>` | Owner | removes one entry |
| `DELETE /threads/<thread>` | Owner | removes the thread |
| `PUT /threads/<thread>` | Owner | opens an empty thread, which group write tokens may then append to. Idempotent. |
| `PUT /access/<lookup>` | Owner | A group's `AccessBox` or an audience box's `HpkeBox`, at most 4 KiB, replacing any box at that lookup. 507 `access-limit` past 10,000 boxes. |
| `GET /access/<lookup>` | Open | → `AccessBox` |
| `DELETE /access/<lookup>` | Owner | |
| `POST /slots` | Owner | → JSON `{"slot", "token"}`: opens a slot and returns its token. Slot numbers rise and are never reused. 507 `slot-limit` with 64 open. |
| `GET /slots` | Owner | → JSON `{"slots": [{"slot", "opened_at", "unread"}]}`; `unread` counts the slot's items still in the inbox |
| `DELETE /slots/<slot>` | Owner | closes the slot, which retires its token. Idempotent. |
| `PUT /invites/<lookup>` | Owner | `struct { opaque invitation<V>; opaque release[32]; }`. Kept until the invitation's `expires_at`, at most 30 days. Replacing an invitation keeps its redemption: once redeemed, it stays redeemed to the same claim. |
| `GET /invites/<lookup>` | Open | → `Invitation` |
| `POST /invites/<lookup>/redeem` | Open | `opaque claim[32]`, random, chosen and kept by the redeemer before the request → the 32-byte release secret followed by the `Invitation` as stored now. The first claim redeems the invitation; the same claim gets the same secret again, so a redemption whose answer was lost can be repeated; any other claim gets 410 |
| `DELETE /invites/<lookup>` | Owner | |
| `PUT /links/<lookup>` | Owner | `LinkReply`. Kept 10 minutes. |
| `GET /links/<lookup>` | Open | → `LinkReply`, then removed. The lookup is known only to the two devices and the host, and the reply is encrypted. |
| `POST /guests` | Owner | JSON `{"expires_at"}`, at most 30 days away → JSON `{"offer", "secret"}`: a guest offer, accepted once by `POST /tenants`. 403 `forbidden` unless the host allows guests and this tenant is a member; 507 `guest-limit` past a limit. |
| `DELETE /guests/<offer>` | Owner | withdraws an unused guest offer of this tenant |
| `PUT /push/subscription` | Owner | JSON `{"endpoint"}`, an `https` URL (or `http` to a loopback host, for development) of at most 1 KiB, for the signing device |
| `DELETE /push/subscription` | Owner | |
| `GET /push` | Owner, as `SocketAuth` | WebSocket upgrade with subprotocol `cw1` |
| `GET /export` | Grant | → `Export` |
| `POST /restore` | Owner | `Export` built by an own device → 204. 409 unless the tenant has no log and no head. |
| `POST /import` | Owner | JSON `{"from": "<old tenant URL>", "grant": "<base64url Signed grant>"}` → JSON `{"objects", "bytes"}` once the copy is complete |
| `POST /batch` | Owner | `Batch` → `BatchAnswers`, as below |

While the tenant is under notice, requests that add data answer 403 `read-only`, except `PUT /card`, push subscriptions, `PUT /access/<lookup>` that replaces a box, and the group counter's advance, so a group can leave a host that gave notice. Reads, deletions, invite redemptions and `GET /export` still work. Storage beyond the tenant's quota answers 507 `quota`. Every stored byte counts toward the quota except push subscriptions.

### Inbox entries

```
struct { uint8 kind; opaque body<V>; } InboxEntry;   /* 1: an item, the HpkeBox posted; 2: a ThreadNote */
struct { opaque thread[16]; uint64 seq; opaque entry<V>; } ThreadNote;
```

- The inbox holds `InboxEntry`s in sequence order. `POST /inbox` stores its body as an item. An entry a friend writes to `POST /threads/<thread>` with a write token is also stored as a note with the entry's bytes, so the owner's devices learn of it and read it with the inbox, and the friend sends nothing else. A note counts toward the inbox limits and the quota like an item; when either is reached, the entry is stored without a note.
- Entries written with other tokens are not noted. Those, and entries stored without a note, raise the `thread` socket event; a noted entry raises `inbox`.

### Batches

```
struct {
  opaque method<V>;
  opaque path<V>;        /* a tenant path with its query, from "/" */
  optional<uint64> if_match;
  opaque body<V>;
} BatchRequest;
struct { BatchRequest requests<V>; } Batch;

struct {
  uint16 status;
  uint64 value;          /* the answer's CW-Epoch, CW-Seq or CW-Current, 0 for none */
  opaque body<V>;
} BatchAnswer;
struct { BatchAnswer answers<V>; } BatchAnswers;
```

- A batch is 1 to 100 requests and at most 24 MiB, as one request to the tenant. Its owner token and signature are checked once, its nonce is remembered once, and it counts once toward the daily budget. Each request then runs, in order, as an owner request by the batch's signer, so a request that moves a counter leaves the requests after it allowed.
- A batch may carry every Owner path except `DELETE /`, `POST /import`, `POST /restore`, `POST /guests`, `DELETE /guests/<offer>` and `GET /push`, and `PUT /card`, `POST /tokens`, `GET /head`, `GET /objects/<name>`, `GET /threads/<thread>` and `POST /threads/<thread>`.
- The requests apply together or not at all, in one transaction. The first one refused answers for the whole batch: its status and body, and its headers, with `CW-Index` naming its position from 0. Nothing of the batch is stored. A request a batch can't carry answers 400 `malformed`; an unknown path, 404.
- Otherwise the batch answers 200 with `BatchAnswers`, one per request in order. The tenant row is written once for the whole batch, and socket events and Web Push follow each request as they would alone.

### Push

- **Opening state.** A socket's first frame is `{"t":"state","inbox":n,"log":n,"card":version,"status":{…},"seen":{"<device>":ms,…}}`: the next inbox and log sequence numbers, the card version, the `GET /status` body, and for each device in the card that has opened a socket, the UTC midnight of the last day it did. The host keeps one day per device, written at most once a day, and drops a device's day when a card leaves it out. A device that opens the app fetches only what moved since it last read, so a profile with nothing new costs one request.
- **Socket events.** The host sends text frames of JSON to the tenant's open sockets: `{"t":"inbox","seq":n}`, `{"t":"thread","id":"<thread>","seq":n}`, `{"t":"log","seq":n}`, `{"t":"head","revision":n}`, `{"t":"card","version":n}` and `{"t":"status"}`.
- **Keepalive.** A client sends only the text `ping`, and the host answers `pong` without waking anything; any other frame from a client closes the socket. A socket that sends no `ping` for 75 seconds is closed and stops counting as open, so a suspended device gets Web Push.
- **Web Push.** When an inbox item or thread entry arrives, each device in the card that has a subscription and no open socket gets a Web Push with no content (RFC 8030), authorized with VAPID (RFC 8292), at most one every 10 seconds per device. A subscription whose push service answers 404 or 410 is removed. The VAPID JWT's `sub` is the host's own `https` origin.

### Transfer

```
struct {
  opaque card<V>;
  opaque head<V>;
  Entries log;
  opaque snapshot<V>;
  Entries owner_keys;
  opaque passkey<V>;
  opaque keyring<V>;
  Entries inbox;
  Entries threads;       /* position: seq; bytes: struct { opaque thread[16]; opaque entry<V>; } */
  Entries invites;       /* position: expires_at; bytes: struct { opaque lookup[16]; opaque invitation<V>; opaque release<V>; }; release: the release secret, then the claim once redeemed */
  Entries objects;       /* position: size; bytes: object name */
  uint64 group_counter;
  Entries device_keys;   /* position: created_at; bytes: a device key record */
} Export;
```

The new host verifies the grant names its own tenant URL, fetches `Export` and then every object it doesn't hold, checking each digest, and refuses an export whose card is for a different profile than the new tenant's. Sequence numbers and the group counter carry over. Access boxes, audience boxes and slots stay behind: group access boxes hold tokens that are MACs under the old host's secret and audience boxes go with the keyring of the new host's tokens, so the owner writes every box and the keyring again on the new host and opens slots again. Threads without entries stay behind too, and the owner opens them again.

`POST /restore` stores an `Export` an own device built when none of the profile's hosts answers, by the same rules: card, snapshot and the thread entries of own posts it read, with every other field empty. An export with a snapshot and no log entries continues the log after the entry the snapshot names. The device then puts objects, the owner keys, every audience box, the keyring and the head with the usual requests.

### Replicas

A card lists one to four hosts. The first orders every write; the others are replicas that keep the profile readable while the first is down.

- A device makes a replica by creating a tenant on the other host and importing from the first host with a grant, then deletes the imported invitations and inbox items there, since invitations are redeemed and inboxes read only at the first host. It then signs a card that adds the replica after the first host.
- Own devices send every card, head, object, owner key, audience box, keyring and audience counter write to each host in the card, the keyring sealing each host's own tokens. A replica that missed writes while it was down catches up at the next write there: the device puts the card, the owner keys, every audience box, the keyring and the head again, and the head replaces whatever revision it holds.
- Friends post inbox items and thread entries, and redeem invitations, only at the first host. While it is down, those writes wait and are retried.
- Readers read the card, head, objects, audience boxes and keyring from the hosts in card order, with each host's tokens, and move to the next host when one doesn't answer.
- Moving to another host is the same import, from the first host in card order that answers, followed by a card that names the new host first and leaves the old one out. The device puts that card on the old host too, so it serves it as the forwarding card, and then removes the old tenant with `DELETE /`.
- When no host in the card holds the profile, because none answers or each deleted the tenant and answers 410, an own device rebuilds the profile on the new host with `POST /restore`. The old tenant is removed, leaving its forwarding card, when its host answers again; one the host deleted already is done.

## Deadlines

Nothing runs on a timer while a tenant is idle. Invitation and link expiry, nonce memory and the end of a notice period are enforced when the tenant is next accessed. A tenant under notice also has one alarm at its end. Request counts are kept in memory and written at most every 100 requests and at each day's end; the count of requests without a current token is kept in memory only.

## Request floors

Every person's data is on their own host, end to end encrypted, and hosts never talk to each other. So a change reaches another person only through their own read, and every write is a request to the host that stores it. Within that, each operation costs the requests below, from everyone involved; `tests/e2e/budgets.spec.ts` and the conversation budget in `tests/e2e/conversations.spec.ts` hold each one.

| Operation | Requests | What they are |
|---|---|---|
| Opening the app with nothing new | 1 | The push socket, whose first frame says where the inbox, log and card stand. |
| Making a profile on a host the person runs | 4 | Claiming the host; making the tenant, which answers the device's tokens; one batch with everything the profile starts with (card, owner key, keyring, first log entry, manifest and head); the socket. Saving the recovery key is one more batch, since the person does it after. |
| A post, to F friends | 1 + 2F | The author's batch: the log entry, the photo copies, the manifest parts that changed and the head. A notice to each friend, carrying the head and those parts, and each friend's read of their inbox. A friend then reads each photo copy it shows. |
| A like or a comment on a friend's post | 2 | The thread write, which the post owner's host notes in the owner's inbox with the entry, and the owner's inbox read. The writer's outbox item, delivered before it reached the log, is never logged. |
| A message to a conversation of N | 3N − 2 | One inbox item to each other member, each member's read of it, and one log entry each. |
| An invitation, joining on the space it offers, and the friendship | 14 | The inviter: the space offer, a batch with the invitation, the inbox read, the batch with the friend's record, their audience box and the invitation's deletion, and opening the friend's profile. The friend: reading and redeeming the invitation, the tenant and its batch, the acceptance, the batch with the inviter's record and box, log entries and opening the inviter's profile. The invitation carries the inviter's audience key, keyring, head and manifest, and the acceptance the friend's box, keyring, head and manifest; nothing else goes back. |
| Unfriending, with F friends staying | 4 + 3F | The batch with the new key's log entry, the deletion of the former friend's box, the F boxes, the keyring, the head and the counters' advance (one batch per 100 requests); a notice to each staying friend, carrying their box and the keyring, their inbox read and the log entry of the new key; the notice that ends the friendship, the former friend's inbox read and their own rotation, which takes the person out of their audience. |

A post's bytes don't grow with the profile: its batch carries its week's page, the newest volume of 64 pages and the root (`docs/format.md`, Manifest). An audience rotation is one batch per 100 requests on each host: the advance of the audience counter goes last, after the keyring that already holds the next counter's tokens.

## Checks

`scripts/sl test hosts` runs the conformance suite on both runtimes and the budgets: the binary at most 15 MiB, idle RSS with 10 tenants at most 15 MiB, and 1,000 readers spread over 100 tenants, each reading a head every 100 ms on its own connection, within 120 MiB RSS and a p99 of 10 ms on loopback. It then has 40 owners and their friends write logs, objects and inbox items, with readers and push sockets, for 35 seconds while the host is stopped or killed six times: every acknowledged write must be readable afterwards, and the host must serve again within 10 seconds of each restart. `cw-conformance wakes` runs against a host on Cloudflare: one tenant read every 12 s, longer than an idle Durable Object stays active; one read every 4 s; and one holding a push socket pinged every 25 s as the app pings it. `scripts/do-usage.py <report>` then reads each tenant object's requests, active time (what duration is billed on), CPU time and SQLite rows from the account's analytics. `scripts/sl release` builds `commonwire` for macOS (arm64, x86_64), Linux (x86_64, aarch64, static musl) and Windows (x86_64).
