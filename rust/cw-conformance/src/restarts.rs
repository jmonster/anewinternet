//! Writes through restarts: each owner appends to their log and stores objects, a friend posts to their inbox,
//! readers read their head, and the owner's device holds a push socket, while the harness stops and kills the host.
//! Every operation is retried until the host answers it, so restarts cost time but nothing else; afterwards every
//! acknowledged write must be readable.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// How long operations still retry after the time is up before they count as unfinished.
const GRACE: Duration = Duration::from_secs(60);
const RETRY: Duration = Duration::from_millis(50);

#[derive(Default)]
struct Counts {
    reads: AtomicU64,
    retries: AtomicU64,
    rate_limited: AtomicU64,
    longest_outage_ms: AtomicU64,
    reconnects: AtomicU64,
    events: AtomicU64,
}

/// What one tenant's worker had acknowledged, to check afterwards.
#[derive(Default)]
struct Acked {
    log: Vec<Vec<u8>>,
    inbox: Vec<Vec<u8>>,
    objects: Vec<(String, Vec<u8>)>,
    unfinished: u64,
    errors: Vec<String>,
}

struct Owner {
    person: Person,
    owner_key: [u8; 32],
}

struct Writes {
    base: String,
    authority: String,
    counts: Counts,
    /// When retrying stops.
    give_up: Instant,
}

impl Writes {
    /// Sends the request `make` builds (afresh each attempt, so signatures stay unique) until the host answers
    /// with anything but a rate limit or a server error. `None` when retrying gave up first.
    async fn send(&self, mut make: impl FnMut() -> (&'static str, String, Headers, Vec<u8>)) -> Option<Fetched> {
        let mut outage: Option<Instant> = None;
        loop {
            let (method, path, headers, body) = make();
            match fetch(method, &format!("{}{path}", self.base), &headers, body).await {
                Ok(f) if f.status == 429 => {
                    self.counts.rate_limited.fetch_add(1, Relaxed);
                    let wait = f.header("retry-after").and_then(|w| w.parse().ok()).unwrap_or(1);
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                    continue;
                }
                Ok(f) if f.status < 500 => {
                    if let Some(since) = outage {
                        self.counts.longest_outage_ms.fetch_max(since.elapsed().as_millis() as u64, Relaxed);
                    }
                    return Some(f);
                }
                _ => {
                    outage.get_or_insert_with(Instant::now);
                    self.counts.retries.fetch_add(1, Relaxed);
                }
            }
            if Instant::now() > self.give_up {
                return None;
            }
            tokio::time::sleep(RETRY).await;
        }
    }

    fn owner_request(
        &self,
        o: &Owner,
        method: &'static str,
        rel: &str,
        body: &[u8],
        if_match: Option<u64>,
    ) -> (&'static str, String, Headers, Vec<u8>) {
        let p = &o.person;
        let path = format!("/t/{}{rel}", p.tid());
        let a = request::sign(&p.devices[0], method, &self.authority, &path, body, now(), &mut OsRng);
        let mut h: Headers =
            vec![("cw-device", a.key), ("cw-time", a.time), ("cw-nonce", a.nonce), ("cw-signature", a.signature)];
        h.push(("authorization", format!("CW {}", p.owner[0])));
        if let Some(m) = if_match {
            h.push(("if-match", m.to_string()));
        }
        (method, path, h, body.to_vec())
    }

    /// Reads a list route (`/log` or `/inbox`) from the start, page by page.
    async fn list(&self, o: &Owner, route: &str) -> Option<Vec<(u64, Vec<u8>)>> {
        let mut all: Vec<(u64, Vec<u8>)> = Vec::new();
        loop {
            let from = all.last().map_or(0, |(p, _)| p + 1);
            let f = self.send(|| self.owner_request(o, "GET", &format!("{route}?from={from}"), &[], None)).await?;
            let page = entries(&f);
            if f.status != 200 || page.is_empty() {
                return Some(all);
            }
            all.extend(page);
        }
    }

    /// One owner's writes and reads until `until`.
    async fn work(&self, o: &Owner, friend: &Person, until: Instant, offset: Duration) -> Acked {
        let mut acked = Acked::default();
        let p = &o.person;
        let mut previous = [0u8; 32];
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + offset, Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut round = 0u64;
        while Instant::now() < until {
            tick.tick().await;
            // The owner's log, in order: a repeat of an append whose answer was lost finds its entry in place.
            let seq = acked.log.len() as u64;
            let payload = format!("{{\"entry\":{seq}}}");
            let entry = log::seal_entry(&p.devices[0], &p.profile.profile_id(), seq, &previous, 0, &o.owner_key, payload.as_bytes(), &mut OsRng)
                .unwrap();
            match self.send(|| self.owner_request(o, "POST", "/log", &entry, Some(seq))).await {
                None => {
                    acked.unfinished += 1;
                    break;
                }
                Some(f) if f.status / 100 == 2 => {}
                Some(f) if f.status == 412 => {
                    let found = self
                        .send(|| self.owner_request(o, "GET", &format!("/log?from={seq}"), &[], None))
                        .await
                        .map(|f| entries(&f).first().is_some_and(|(pos, bytes)| *pos == seq && *bytes == entry));
                    if found != Some(true) {
                        acked.errors.push(format!("log {seq}: refused and not in place"));
                        break;
                    }
                }
                Some(f) => {
                    acked.errors.push(format!("log {seq}: {}", outcome(&f)));
                    break;
                }
            }
            previous = log::digest(&entry);
            acked.log.push(entry);
            // An object.
            let mut plain = vec![0u8; 256 + (OsRng.next_u32() % 1792) as usize];
            OsRng.fill_bytes(&mut plain);
            let (sealed, sealed_ref) = object::encrypt(&plain, &mut OsRng).unwrap();
            let name = object::name(&sealed_ref.digest);
            match self.send(|| self.owner_request(o, "PUT", &format!("/objects/{name}"), &sealed, None)).await {
                None => acked.unfinished += 1,
                Some(f) if f.status / 100 == 2 => acked.objects.push((name, sealed)),
                Some(f) => acked.errors.push(format!("object: {}", outcome(&f))),
            }
            // A friend's message every other second, inside the per-token write limit.
            if round % 2 == 0 {
                let item = p.sealed_item(friend, b"restarts");
                let path = format!("/t/{}/inbox?t={}", p.tid(), p.write);
                match self.send(|| ("POST", path.clone(), vec![], item.clone())).await {
                    None => acked.unfinished += 1,
                    Some(f) if f.status / 100 == 2 => acked.inbox.push(item),
                    Some(f) => acked.errors.push(format!("inbox: {}", outcome(&f))),
                }
            }
            // Two readers.
            for _ in 0..2 {
                let path = format!("/t/{}/head?t={}", p.tid(), p.read);
                match self.send(|| ("GET", path.clone(), vec![], vec![])).await {
                    Some(f) if f.status == 200 => {
                        self.counts.reads.fetch_add(1, Relaxed);
                    }
                    Some(f) => acked.errors.push(format!("head: {}", outcome(&f))),
                    None => acked.unfinished += 1,
                }
            }
            round += 1;
        }
        acked
    }

    /// The owner's device keeps a push socket open, reconnecting whenever the host closes it.
    async fn hold_socket(&self, suite: &Suite, o: &Owner, until: Instant) {
        while Instant::now() < until {
            if let Ok(mut ws) = socket(suite, &o.person, 0).await {
                loop {
                    let left = until.saturating_duration_since(Instant::now());
                    match tokio::time::timeout(left, ws.next()).await {
                        Ok(Some(Ok(Message::Text(_)))) => {
                            self.counts.events.fetch_add(1, Relaxed);
                        }
                        Ok(Some(Ok(_))) => {}
                        Ok(_) => break,
                        Err(_) => return,
                    }
                }
            }
            self.counts.reconnects.fetch_add(1, Relaxed);
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Checks one owner's acknowledged writes against what the host serves. Returns (missing, inbox duplicates).
    async fn verify(&self, o: &Owner, acked: &Acked, errors: &mut Vec<String>) -> (u64, u64) {
        let p = &o.person;
        let mut missing = 0u64;
        match self.list(o, "/log").await {
            Some(log) => {
                for (i, entry) in acked.log.iter().enumerate() {
                    if log.get(i).is_none_or(|(pos, bytes)| *pos != i as u64 || bytes != entry) {
                        missing += 1;
                    }
                }
                if log.len() > acked.log.len() {
                    errors.push(format!("{}: {} log entries beyond those acknowledged", p.tid(), log.len() - acked.log.len()));
                }
            }
            None => missing += acked.log.len() as u64,
        }
        let mut duplicates = 0u64;
        match self.list(o, "/inbox").await {
            Some(items) => {
                let mut seen: std::collections::HashMap<&[u8], u64> = std::collections::HashMap::new();
                let bodies: Vec<Vec<u8>> = items
                    .iter()
                    .filter_map(|(_, bytes)| wire::decode::<wire::InboxEntry>(bytes, usize::MAX, "inbox entry").ok())
                    .map(|e| e.body.as_slice().to_vec())
                    .collect();
                for body in &bodies {
                    *seen.entry(body.as_slice()).or_default() += 1;
                }
                for item in &acked.inbox {
                    match seen.get(item.as_slice()) {
                        None => missing += 1,
                        Some(n) => duplicates += n - 1,
                    }
                }
            }
            None => missing += acked.inbox.len() as u64,
        }
        for (name, sealed) in &acked.objects {
            let path = format!("/t/{}/objects/{name}?t={}", p.tid(), p.read);
            match self.send(|| ("GET", path.clone(), vec![], vec![])).await {
                Some(f) if f.status == 200 && f.body == *sealed => {}
                _ => missing += 1,
            }
        }
        (missing, duplicates)
    }
}

pub async fn run(base: &str, claim: [u8; 32], tenants: usize, seconds: u64) -> Value {
    let authority = base.split_once("://").map(|(_, a)| a.to_string()).unwrap_or_default();
    let mut s = Suite {
        base: base.into(),
        authority: authority.clone(),
        claim,
        out: BTreeMap::new(),
        admin: Key::generate(&mut OsRng),
        admin_token: String::new(),
        patient: true,
    };
    let f = s.call("POST", "/claim", vec![("cw-claim", b64::encode(&claim))], s.admin.public().to_vec()).await;
    s.admin_token = json_body(&f)["admin_token"].as_str().unwrap_or_default().to_string();
    let admin = Key::from_seed(&s.admin.seed());
    let mut owners = Vec::new();
    for _ in 0..tenants {
        let mut p = Person::new(1);
        let body = json!({ "card": b64::encode(&p.card), "quota": 1024 * 1024 * 1024 }).to_string().into_bytes();
        let (f, _) = s.admin(&admin, "POST", "/admin/tenants", body).await;
        p.tenant = b64::decode_array(json_body(&f)["tenant"].as_str().unwrap_or_default()).unwrap_or_default();
        p.url = format!("{base}/t/{}", p.tid());
        s.tokens(&mut p).await;
        let (m, m_ref) = object::encrypt(b"{}", &mut OsRng).unwrap();
        s.owner(&p, 0, "PUT", &format!("/objects/{}", object::name(&m_ref.digest)), m, None).await;
        let h = head::seal(&p.devices[0], &p.profile.profile_id(), &[], 1, 1, now(), &kdf::sha256(b"k"), &m_ref, &mut OsRng);
        s.owner(&p, 0, "PUT", "/head", h, Some(0)).await;
        owners.push(Owner { person: p, owner_key: random::<32>() });
    }
    let friend = Arc::new(Person::new(1));
    let until = Instant::now() + Duration::from_secs(seconds);
    let writes = Arc::new(Writes { base: base.into(), authority, counts: Counts::default(), give_up: until + GRACE });
    let suite = Arc::new(s);
    let owners: Vec<Arc<Owner>> = owners.into_iter().map(Arc::new).collect();
    let mut workers = Vec::new();
    let mut sockets = Vec::new();
    for (i, o) in owners.iter().enumerate() {
        let (w, o2, friend) = (writes.clone(), o.clone(), friend.clone());
        // Spread the owners' rounds across one second.
        let offset = Duration::from_secs(1).mul_f64(i as f64 / owners.len() as f64);
        workers.push(tokio::spawn(async move { w.work(&o2, &friend, until, offset).await }));
        let (w, o2, suite) = (writes.clone(), o.clone(), suite.clone());
        sockets.push(tokio::spawn(async move { w.hold_socket(&suite, &o2, until).await }));
    }
    let mut acked = Vec::new();
    for w in workers {
        acked.push(w.await.unwrap());
    }
    for t in sockets {
        t.await.unwrap();
    }
    let mut errors: Vec<String> = acked.iter().flat_map(|a| a.errors.iter().cloned()).collect();
    let (mut missing, mut duplicates) = (0, 0);
    for (o, a) in owners.iter().zip(&acked) {
        let (m, d) = writes.verify(o, a, &mut errors).await;
        missing += m;
        duplicates += d;
    }
    let sum = |f: fn(&Acked) -> u64| acked.iter().map(f).sum::<u64>();
    let (log, inbox, objects) =
        (sum(|a| a.log.len() as u64), sum(|a| a.inbox.len() as u64), sum(|a| a.objects.len() as u64));
    let unfinished = sum(|a| a.unfinished);
    let c = &writes.counts;
    errors.truncate(20);
    json!({
        "seconds": seconds,
        "tenants": tenants,
        "acknowledged": { "log": log, "inbox": inbox, "objects": objects, "reads": c.reads.load(Relaxed) },
        "unfinished": unfinished,
        "missing": missing,
        "lost": missing + unfinished,
        "inbox_duplicates": duplicates,
        "retries": c.retries.load(Relaxed),
        "rate_limited": c.rate_limited.load(Relaxed),
        "longest_outage_ms": c.longest_outage_ms.load(Relaxed),
        "socket_reconnects": c.reconnects.load(Relaxed),
        "socket_events": c.events.load(Relaxed),
        "errors": errors,
    })
}
