//! `commonwire`: runs a commonwire host on this machine. Hosts on Cloudflare are set up from the app.
use commonwire::{server, service};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use cw_crypto::b64;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::json;

const USAGE: &str = "usage:
  commonwire host init --domain <name> [--data <dir>]
  commonwire host init --origin http://<loopback>:<port> [--data <dir>]
  commonwire serve [--data <dir>] [--staging] [--http <loopback address:port>]
  commonwire service install [--data <dir>]
  commonwire service uninstall";

/// The app that opens setup links.
const APP: &str = "https://anewinter.net";

fn default_data() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/commonwire")
    } else if cfg!(windows) {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into())).join("commonwire")
    } else {
        PathBuf::from("/var/lib/commonwire")
    }
}

struct Args(Vec<String>);

impl Args {
    fn flag(&mut self, name: &str) -> bool {
        let found = self.0.iter().position(|a| a == name);
        found.map(|i| self.0.remove(i)).is_some()
    }
    fn value(&mut self, name: &str) -> Option<String> {
        let i = self.0.iter().position(|a| a == name)?;
        self.0.remove(i);
        (i < self.0.len()).then(|| self.0.remove(i))
    }
    fn data(&mut self) -> PathBuf {
        self.value("--data")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("COMMONWIRE_DATA").map(PathBuf::from))
            .unwrap_or_else(default_data)
    }
}

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("commonwire: {message}");
    std::process::exit(1)
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        f.write_all(text.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        std::fs::write(path, text)
    }
}

fn init(mut args: Args) {
    let data = args.data();
    let origin = match (args.value("--domain"), args.value("--origin")) {
        (Some(domain), None) => {
            let domain = domain.to_ascii_lowercase();
            if domain.is_empty() || !domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
                fail("--domain must be a DNS name");
            }
            format!("https://{domain}")
        }
        (None, Some(origin)) => {
            let host =
                origin.strip_prefix("http://").unwrap_or_else(|| fail("--origin is for loopback development hosts"));
            if !cw_crypto::card::is_loopback(host) {
                fail("--origin must be a loopback http origin; use --domain for a real host");
            }
            origin
        }
        _ => fail(USAGE),
    };
    std::fs::create_dir_all(&data).unwrap_or_else(|e| fail(format!("{}: {e}", data.display())));
    let mut secret = [0u8; 32];
    let mut claim = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    OsRng.fill_bytes(&mut claim);
    let vapid = cw_host::config::vapid_secret(&mut OsRng);
    let config = json!({
        "origin": origin,
        "secret": b64::encode(&secret),
        "claim": b64::encode(&cw_crypto::token::claim_digest(&claim)),
        "vapid": b64::encode(&vapid),
    });
    write_private(&data.join("host.json"), &format!("{config:#}\n"))
        .unwrap_or_else(|e| fail(format!("{}: {e}", data.join("host.json").display())));
    println!("Host created in {}.", data.display());
    println!("Open this link on the device that will run this host, then keep it private:");
    println!("{APP}/host#claim={}.{}", b64::encode(&claim), b64::encode(origin.as_bytes()));
}

/// Resolves when the process is asked to stop: SIGTERM or SIGINT, or Ctrl+C on Windows.
async fn stop_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn serve(mut args: Args) {
    let data = args.data();
    let staging = args.flag("--staging");
    let plain =
        args.value("--http").map(|a| a.parse::<SocketAddr>().unwrap_or_else(|_| fail("--http needs address:port")));
    let config = commonwire::load_config(&data).unwrap_or_else(|e| fail(e));
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap_or_else(|e| fail(e));
    if let Err(e) = runtime.block_on(server::run(&data, config, staging, plain, stop_requested())) {
        fail(e);
    }
}

fn service_install(mut args: Args) {
    let data = args.data();
    if !args.0.is_empty() {
        fail(USAGE);
    }
    // Absolute without resolving links: systemd replaces /var/lib/<name> with a link into /var/lib/private.
    let data = std::path::absolute(&data).unwrap_or_else(|e| fail(format!("{}: {e}", data.display())));
    let config = commonwire::load_config(&data).unwrap_or_else(|e| fail(e));
    service::install(&data).unwrap_or_else(|e| fail(e));
    match service::wait_serving(&config.origin, service::READY) {
        Some(took) => println!("Installed. Serving {} ({} ms after starting).", config.origin, took.as_millis()),
        None => fail(format!("installed, but the host isn't serving {} yet", config.origin)),
    }
}

fn service_uninstall(args: Args) {
    if !args.0.is_empty() {
        fail(USAGE);
    }
    service::uninstall().unwrap_or_else(|e| fail(e));
    println!("Uninstalled. The host's data stays where it was.");
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let command: Vec<String> = args.iter().take(2).cloned().collect();
    match command.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["host", "init", ..] => init(Args(args.split_off(2))),
        ["serve", ..] => serve(Args(args.split_off(1))),
        ["service", "install", ..] => service_install(Args(args.split_off(2))),
        ["service", "uninstall", ..] => service_uninstall(Args(args.split_off(2))),
        #[cfg(windows)]
        ["service", "run", ..] => {
            let data = Args(args.split_off(2)).data();
            service::run_service(data).unwrap_or_else(|e| fail(e));
        }
        ["version", ..] | ["--version", ..] => println!("commonwire {}", env!("CARGO_PKG_VERSION")),
        _ => fail(USAGE),
    }
}
