//! What tenants cost on Cloudflare, where each tenant is a Durable Object billed for the time it is active. Ten
//! friends read one person's head 12 s apart, longer than the 10 s an idle object stays active; the same ten read
//! another person's head 4 s apart, so that object never goes idle; a third person's device holds a push socket
//! and pings it every 25 s, as the app does. The report gives each tenant's requests and the time window.
use super::*;

const PING: Duration = Duration::from_secs(25);

/// Reads `p`'s head once every `gap` until `deadline`, as friends taking turns would.
async fn friends(p: &Person, gap: Duration, deadline: Instant) -> (u64, u64) {
    let url = format!("{}/head?t={}", p.url, p.read);
    let (mut reads, mut errors) = (0, 0);
    let mut next = Instant::now();
    while next < deadline {
        tokio::time::sleep_until(next.into()).await;
        match fetch("GET", &url, &[], Vec::new()).await {
            Ok(f) if f.status == 200 => reads += 1,
            _ => errors += 1,
        }
        next += gap;
    }
    (reads, errors)
}

pub async fn run(base: &str, claim: [u8; 32], seconds: u64) -> Value {
    let (mut s, admin) = claimed(base, claim).await;
    let sporadic = s.published(&admin).await;
    let busy = s.published(&admin).await;
    let listening = s.published(&admin).await;
    let Ok(mut ws) = socket(&s, &listening, 0).await else { fail("socket refused") };
    // The opening state frame.
    next_text(&mut ws).await;
    let started = now();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let socket = async {
        let (mut pings, mut pongs) = (0u64, 0u64);
        while Instant::now() + PING < deadline {
            tokio::time::sleep(PING).await;
            ws.send(Message::text("ping")).await.ok();
            pings += 1;
            if next_text(&mut ws).await.as_deref() == Some("pong") {
                pongs += 1;
            }
        }
        (pings, pongs)
    };
    let ((sporadic_reads, sporadic_errors), (busy_reads, busy_errors), (pings, pongs)) = tokio::join!(
        friends(&sporadic, Duration::from_secs(12), deadline),
        friends(&busy, Duration::from_secs(4), deadline),
        socket,
    );
    let ended = now();
    json!({
        "started_ms": started,
        "ended_ms": ended,
        "sporadic": { "tenant": sporadic.tid(), "gap_s": 12, "reads": sporadic_reads, "errors": sporadic_errors },
        "busy": { "tenant": busy.tid(), "gap_s": 4, "reads": busy_reads, "errors": busy_errors },
        "socket": { "tenant": listening.tid(), "ping_s": PING.as_secs(), "pings": pings, "pongs": pongs },
    })
}
