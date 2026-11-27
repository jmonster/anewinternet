//! HTTPS on port 443 with ACME (TLS-ALPN-01), HTTP/2 and HTTP/1.1; plain HTTP only on loopback, for
//! development and tests. A stop request ends accepting, closes push sockets and lets requests in flight
//! finish, for at most five seconds.
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use hyper::body::Incoming;
use hyper::service::service_fn;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_util::task::TaskTracker;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::io::{collect, Exec, Full, Io, Timer, Upgraded};
use crate::runtime::{Frame, Reply, Runtime};

/// How long a push socket may go without a `ping` (the app sends one every 25 s, hidden tabs about once a minute).
const SOCKET_SILENCE: Duration = Duration::from_secs(75);

/// The largest request body: an object of 16 MiB plaintext after padding, with room to spare.
const BODY_LIMIT: usize = 24 * 1024 * 1024;
/// How long a stop waits for requests in flight.
const DRAIN: Duration = Duration::from_secs(5);

fn reply(response: cw_host::Response) -> hyper::Response<Full> {
    let response = response.cors();
    let mut builder = hyper::Response::builder().status(response.status);
    for (k, v) in &response.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    builder.body(Full::new(response.body)).expect("response")
}

async fn service(
    rt: Arc<Runtime>,
    mut req: hyper::Request<Incoming>,
    peer: IpAddr,
) -> Result<hyper::Response<Full>, Infallible> {
    let upgrade = hyper::upgrade::on(&mut req);
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| req.headers().get("host").and_then(|v| v.to_str().ok()).map(str::to_string))
        .unwrap_or_default();
    let target = req.uri().path_and_query().map_or("/", |p| p.as_str()).to_string();
    let method = req.method().as_str().to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_ascii_lowercase(), v.to_str().ok()?.to_string())))
        .collect();
    let key = req.headers().get("sec-websocket-key").and_then(|v| v.to_str().ok()).map(str::to_string);
    let received = crate::runtime::now_ms();
    let body = match collect(req.into_body(), BODY_LIMIT).await {
        Ok(b) => b,
        Err(()) => return Ok(reply(cw_host::Response::error(413, "too-large"))),
    };
    let request = cw_host::Request { method, authority, target, headers, body, received };
    let wants_socket = Runtime::is_socket(&request);
    match rt.handle(request, peer).await {
        Reply::Response(r) => Ok(reply(r)),
        Reply::Upgrade { tenant, device, state } => {
            let Some(key) = key.filter(|_| wants_socket) else {
                return Ok(reply(cw_host::Response::error(400, "malformed")));
            };
            tokio::spawn(async move {
                if let Ok(upgraded) = upgrade.await {
                    let ws = WebSocketStream::from_raw_socket(Upgraded(upgraded), Role::Server, None).await;
                    socket(rt, tenant, device, state, ws).await;
                }
            });
            let response = hyper::Response::builder()
                .status(101)
                .header("upgrade", "websocket")
                .header("connection", "Upgrade")
                .header("sec-websocket-accept", derive_accept_key(key.as_bytes()))
                .header("sec-websocket-protocol", "cw1")
                .body(Full::new(Vec::new()))
                .expect("upgrade response");
            Ok(response)
        }
    }
}

/// A push socket: events go down; the client may send only `ping`, answered with `pong`. A socket silent for
/// `SOCKET_SILENCE` belongs to a suspended or vanished device, so it closes and the device gets Web Push again.
async fn socket(rt: Arc<Runtime>, tenant: [u8; 16], device: [u8; 32], state: String, ws: WebSocketStream<Upgraded>) {
    let (id, mut frames) = rt.attach(tenant, device);
    let (mut tx, mut rx) = ws.split();
    if tx.send(Message::text(state)).await.is_err() {
        rt.detach(tenant, id);
        return;
    }
    let silence = tokio::time::sleep(SOCKET_SILENCE);
    tokio::pin!(silence);
    loop {
        tokio::select! {
            _ = &mut silence => break,
            incoming = rx.next() => match incoming {
                Some(Ok(Message::Text(t))) if t.as_str() == "ping" => {
                    silence.as_mut().reset(tokio::time::Instant::now() + SOCKET_SILENCE);
                    if tx.send(Message::text("pong")).await.is_err() { break }
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                _ => break,
            },
            frame = frames.recv() => match frame {
                Some(Frame::Text(t)) => {
                    if tx.send(Message::text(t)).await.is_err() { break }
                }
                Some(Frame::Close) | None => break,
            },
        }
    }
    let _ = tx.send(Message::Close(None)).await;
    rt.detach(tenant, id);
}

/// Resolves once the host is stopping.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    while !*stop.borrow_and_update() {
        if stop.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

/// Serves one connection until it ends or the host stops, when it finishes the requests in flight.
async fn connection<T>(rt: Arc<Runtime>, io: T, peer: IpAddr, h2: bool, mut stop: watch::Receiver<bool>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| service(rt.clone(), req, peer));
    if h2 {
        let conn = hyper::server::conn::http2::Builder::new(Exec).timer(Timer).serve_connection(Io(io), svc);
        tokio::pin!(conn);
        tokio::select! {
            _ = conn.as_mut() => {}
            () = stopped(&mut stop) => {
                conn.as_mut().graceful_shutdown();
                let _ = conn.await;
            }
        }
    } else {
        let conn = hyper::server::conn::http1::Builder::new()
            .timer(Timer)
            .header_read_timeout(Duration::from_secs(30))
            .serve_connection(Io(io), svc)
            .with_upgrades();
        tokio::pin!(conn);
        tokio::select! {
            _ = conn.as_mut() => {}
            () = stopped(&mut stop) => {
                conn.as_mut().graceful_shutdown();
                let _ = conn.await;
            }
        }
    }
}

/// Opens the host in `data` and serves it until `stop` resolves: plain HTTP on `plain`, or on the origin's own
/// address for a loopback origin, otherwise HTTPS on port 443 with ACME.
pub async fn run(
    data: &Path,
    config: cw_host::Config,
    staging: bool,
    plain: Option<SocketAddr>,
    stop: impl Future<Output = ()>,
) -> Result<(), String> {
    raise_open_files();
    let loopback = config.origin.strip_prefix("http://").and_then(|a| a.parse::<SocketAddr>().ok());
    let domain = config.origin.strip_prefix("https://").map(str::to_string);
    let rt = Runtime::open(data, config)?;
    rt.start().await;
    let (stopping, stopped) = watch::channel(false);
    let connections = TaskTracker::new();
    let serving = async {
        match (plain.or(loopback), domain) {
            (Some(addr), _) => serve_plain(rt.clone(), addr, &connections, stopped).await,
            (None, Some(domain)) => serve_tls(rt.clone(), &domain, data, staging, 443, &connections, stopped).await,
            (None, None) => Err("this host's origin is neither HTTPS nor a loopback address".into()),
        }
    };
    tokio::select! {
        served = serving => served?,
        () = stop => {}
    }
    stopping.send_replace(true);
    rt.close_sockets();
    connections.close();
    let _ = tokio::time::timeout(DRAIN, connections.wait()).await;
    Ok(())
}

/// Raises the soft limit on open files to the hard limit: each reader holds a connection, and each open tenant a
/// database, while service managers start processes with low soft limits.
fn raise_open_files() {
    #[cfg(unix)]
    unsafe {
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return;
        }
        // macOS refuses a soft limit above OPEN_MAX even when the hard limit is unlimited.
        let ceiling: libc::rlim_t = if cfg!(target_os = "macos") { 10240 } else { 65536 };
        let wanted = limit.rlim_max.min(ceiling);
        if wanted > limit.rlim_cur {
            limit.rlim_cur = wanted;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

/// Plain HTTP on a loopback address.
async fn serve_plain(
    rt: Arc<Runtime>,
    addr: SocketAddr,
    connections: &TaskTracker,
    stopped: watch::Receiver<bool>,
) -> Result<(), String> {
    if !addr.ip().is_loopback() {
        return Err("plain HTTP listens only on loopback addresses".into());
    }
    let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
    eprintln!("commonwire serving {} on http://{addr}", rt.config.origin);
    loop {
        let Ok((tcp, peer)) = listener.accept().await else { continue };
        tcp.set_nodelay(true).ok();
        connections.spawn(connection(rt.clone(), tcp, peer.ip(), false, stopped.clone()));
    }
}

/// HTTPS on `port` for `domain`, with certificates from Let's Encrypt.
async fn serve_tls(
    rt: Arc<Runtime>,
    domain: &str,
    data: &Path,
    staging: bool,
    port: u16,
    connections: &TaskTracker,
    stopped: watch::Receiver<bool>,
) -> Result<(), String> {
    let v6 = TcpListener::bind(("::", port)).await;
    let v4 = TcpListener::bind(("0.0.0.0", port)).await;
    if v6.is_err() && v4.is_err() {
        return Err(format!("can't listen on port {port}"));
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<TcpStream>>(256);
    for listener in [v6.ok(), v4.ok()].into_iter().flatten() {
        let tx = tx.clone();
        tokio::spawn(async move {
            loop {
                let accepted = listener.accept().await.map(|(tcp, _)| {
                    tcp.set_nodelay(true).ok();
                    tcp
                });
                if tx.send(accepted).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    let tcp = futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|t| (t, rx)) });
    let mut tls = AcmeConfig::new([domain])
        .cache(DirCache::new(data.join("acme")))
        .directory_lets_encrypt(!staging)
        .tokio_incoming(Box::pin(tcp), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    eprintln!("commonwire serving {} on port {port}", rt.config.origin);
    while let Some(stream) = tls.next().await {
        let Ok(stream) = stream else { continue };
        let (peer, h2) = {
            let (tcp, session) = stream.get_ref().get_ref();
            let peer = tcp.get_ref().peer_addr().map(|a| a.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
            (peer, session.alpn_protocol() == Some(b"h2"))
        };
        connections.spawn(connection(rt.clone(), stream, peer, h2, stopped.clone()));
    }
    Err("listener closed".into())
}
