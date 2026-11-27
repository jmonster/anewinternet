//! Outbound HTTP/1.1 for Web Push, transfer pulls and the Cloudflare API: HTTPS through rustls, and plain
//! HTTP only to loopback hosts.
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_rustls::TlsConnector;
use http::{Method, Request};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::io::{collect, Full, Io};

pub struct Fetched {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Fetched {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// The largest response body read: an export or a whole object.
const LIMIT: usize = 1024 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(60);

fn tls() -> TlsConnector {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    });
    TlsConnector::from(config.clone())
}

pub async fn fetch(method: &str, url: &str, headers: &[(&str, String)], body: Vec<u8>) -> Result<Fetched, String> {
    tokio::time::timeout(TIMEOUT, fetch_inner(method, url, headers, body)).await.map_err(|_| "timed out".to_string())?
}

/// A byte stream to a host.
pub trait Conn: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> Conn for T {}

/// Connects to the host of an `https://` URL, or of an `http://` URL on a loopback host, and returns the stream
/// with the URL's authority and path.
pub async fn connect(url: &str) -> Result<(Box<dyn Conn>, &str, &str), String> {
    let (secure, rest) = match url.strip_prefix("https://") {
        Some(r) => (true, r),
        None => (false, url.strip_prefix("http://").ok_or("unsupported URL")?),
    };
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
    let default = if secure { 443 } else { 80 };
    let parse = |p: &str| p.parse::<u16>().map_err(|_| "bad port".to_string());
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (h, after) = rest.split_once(']').ok_or("bad host")?;
            (h, after.strip_prefix(':').map(parse).transpose()?.unwrap_or(default))
        }
        None => match authority.split_once(':') {
            Some((h, p)) => (h, parse(p)?),
            None => (authority, default),
        },
    };
    if !secure && !cw_crypto::card::is_loopback(authority) {
        return Err("plain HTTP is allowed only to loopback hosts".into());
    }
    let tcp = TcpStream::connect((host, port)).await.map_err(|e| e.to_string())?;
    tcp.set_nodelay(true).ok();
    if !secure {
        return Ok((Box::new(tcp), authority, path));
    }
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let stream = tls().connect(name, tcp.compat()).await.map_err(|e| e.to_string())?;
    Ok((Box::new(stream.compat()), authority, path))
}

async fn fetch_inner(method: &str, url: &str, headers: &[(&str, String)], body: Vec<u8>) -> Result<Fetched, String> {
    let (conn, authority, path) = connect(url).await?;
    let mut builder = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?)
        .uri(path)
        .header("host", authority)
        .header("content-length", body.len().to_string());
    for (k, v) in headers {
        builder = builder.header(*k, v.as_str());
    }
    let request = builder.body(Full::new(body)).map_err(|e| e.to_string())?;
    send(Io(conn), request).await
}

async fn send<T>(io: Io<T>, request: Request<Full>) -> Result<Fetched, String>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let response = sender.send_request(request).await.map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    let body = collect(response.into_body(), LIMIT).await.map_err(|_| "response body".to_string())?;
    Ok(Fetched { status, headers, body })
}
