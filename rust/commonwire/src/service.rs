//! `commonwire service install` and `uninstall`: the host as a LaunchDaemon on macOS, a systemd unit on Linux and
//! a Windows service. Each starts at boot, runs under an account of its own and is restarted a second after it
//! exits. Installing again replaces the program and restarts it, which is also how a host is upgraded.
use std::net::{Ipv6Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

pub use platform::{install, uninstall};
#[cfg(windows)]
pub use platform::run_service;

/// How long installing waits for the host to accept connections.
pub const READY: Duration = Duration::from_secs(10);

/// Waits until the host for `origin` accepts a connection on this machine, returning how long that took.
pub fn wait_serving(origin: &str, within: Duration) -> Option<Duration> {
    let addrs: Vec<SocketAddr> = match origin.strip_prefix("http://").and_then(|a| a.parse().ok()) {
        Some(addr) => vec![addr],
        None => vec![SocketAddr::from(([127, 0, 0, 1], 443)), SocketAddr::from((Ipv6Addr::LOCALHOST, 443))],
    };
    let start = Instant::now();
    while start.elapsed() < within {
        if addrs.iter().any(|a| TcpStream::connect_timeout(a, Duration::from_millis(200)).is_ok()) {
            return Some(start.elapsed());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program).args(args).output().map_err(|e| format!("{program}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("{program} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Copies this program to `dest`, replacing an earlier copy; nothing to do when it already runs from there.
fn place_binary(dest: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().and_then(|e| e.canonicalize()).map_err(|e| e.to_string())?;
    if dest.canonicalize().is_ok_and(|d| d == exe) {
        return Ok(());
    }
    let dir = dest.parent().ok_or("binary path")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let partial = dir.join(".commonwire.partial");
    std::fs::copy(&exe, &partial).map_err(|e| format!("{}: {e}", partial.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&partial, dest).map_err(|e| format!("{}: {e}", dest.display()))
}

#[cfg(unix)]
fn require_root() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err("installing a service needs administrator rights; run this with sudo".into())
    }
}

#[cfg(unix)]
fn write_file(path: &str, text: &str, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let partial = format!("{path}.partial");
    std::fs::write(&partial, text).map_err(|e| format!("{partial}: {e}"))?;
    std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    std::fs::rename(&partial, path).map_err(|e| format!("{path}: {e}"))
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    const LABEL: &str = "net.anewinter.commonwire";
    const PLIST: &str = "/Library/LaunchDaemons/net.anewinter.commonwire.plist";
    const BINARY: &str = "/usr/local/bin/commonwire";
    const LOG: &str = "/Library/Logs/commonwire.log";
    const ACCOUNT: &str = "_commonwire";

    fn escape(text: &str) -> String {
        text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    fn plist(data: &Path) -> String {
        let data = escape(&data.display().to_string());
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{BINARY}</string>
		<string>serve</string>
		<string>--data</string>
		<string>{data}</string>
	</array>
	<key>UserName</key>
	<string>{ACCOUNT}</string>
	<key>GroupName</key>
	<string>{ACCOUNT}</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>1</integer>
	<key>StandardOutPath</key>
	<string>{LOG}</string>
	<key>StandardErrorPath</key>
	<string>{LOG}</string>
</dict>
</plist>
"#
        )
    }

    /// The numbers in use for `kind` (`/Users` with `UniqueID`, `/Groups` with `PrimaryGroupID`).
    fn ids(kind: &str, attribute: &str) -> Result<Vec<u32>, String> {
        let listed = run("dscl", &[".", "-list", kind, attribute])?;
        Ok(listed.lines().filter_map(|l| l.split_whitespace().last()?.parse().ok()).collect())
    }

    /// Creates the hidden `_commonwire` user and group the daemon runs as, unless they exist.
    fn ensure_account() -> Result<(), String> {
        let user = format!("/Users/{ACCOUNT}");
        let group = format!("/Groups/{ACCOUNT}");
        if run("dscl", &[".", "-read", &user]).is_ok() {
            return Ok(());
        }
        let taken: Vec<u32> = ids("/Users", "UniqueID")?.into_iter().chain(ids("/Groups", "PrimaryGroupID")?).collect();
        let id = (300..400).find(|id| !taken.contains(id)).ok_or("no free system account number between 300 and 400")?;
        let id = id.to_string();
        if run("dscl", &[".", "-read", &group]).is_err() {
            run("dscl", &[".", "-create", &group])?;
            run("dscl", &[".", "-create", &group, "PrimaryGroupID", &id])?;
            run("dscl", &[".", "-create", &group, "RealName", "commonwire"])?;
            run("dscl", &[".", "-create", &group, "Password", "*"])?;
        }
        let gid = run("dscl", &[".", "-read", &group, "PrimaryGroupID"])?;
        let gid = gid.split_whitespace().last().ok_or("group number")?.to_string();
        run("dscl", &[".", "-create", &user])?;
        for (key, value) in [
            ("UniqueID", id.as_str()),
            ("PrimaryGroupID", gid.as_str()),
            ("UserShell", "/usr/bin/false"),
            ("NFSHomeDirectory", "/var/empty"),
            ("RealName", "commonwire"),
            ("Password", "*"),
            ("IsHidden", "1"),
        ] {
            run("dscl", &[".", "-create", &user, key, value])?;
        }
        Ok(())
    }

    pub fn install(data: &Path) -> Result<(), String> {
        require_root()?;
        let _ = run("launchctl", &["bootout", &format!("system/{LABEL}")]);
        place_binary(Path::new(BINARY))?;
        ensure_account()?;
        let owner = format!("{ACCOUNT}:{ACCOUNT}");
        run("chown", &["-R", &owner, &data.display().to_string()])?;
        std::fs::OpenOptions::new().create(true).append(true).open(LOG).map_err(|e| format!("{LOG}: {e}"))?;
        run("chown", &[&owner, LOG])?;
        write_file(PLIST, &plist(data), 0o644)?;
        run("launchctl", &["enable", &format!("system/{LABEL}")])?;
        // Bootout finishes asynchronously, so bootstrap can briefly report the old job as still loaded.
        let start = Instant::now();
        loop {
            match run("launchctl", &["bootstrap", "system", PLIST]) {
                Ok(_) => return Ok(()),
                Err(e) if start.elapsed() > Duration::from_secs(5) => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn the_property_list_is_valid_and_escapes_the_data_path() {
        let text = plist(Path::new("/Library/Application Support/A & <B>"));
        let mut lint = Command::new("plutil")
            .args(["-convert", "json", "-o", "-", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        lint.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        let out = lint.wait_with_output().unwrap();
        assert!(out.status.success());
        let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(parsed["ProgramArguments"][3], "/Library/Application Support/A & <B>");
        assert_eq!(parsed["UserName"], ACCOUNT);
        assert_eq!(parsed["KeepAlive"], true);
    }

    pub fn uninstall() -> Result<(), String> {
        require_root()?;
        let _ = run("launchctl", &["bootout", &format!("system/{LABEL}")]);
        for path in [PLIST, BINARY] {
            match std::fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{path}: {e}")),
                _ => {}
            }
        }
        let _ = run("dscl", &[".", "-delete", &format!("/Users/{ACCOUNT}")]);
        let _ = run("dscl", &[".", "-delete", &format!("/Groups/{ACCOUNT}")]);
        Ok(())
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use super::*;

    const UNIT: &str = "/etc/systemd/system/commonwire.service";
    const BINARY: &str = "/usr/local/bin/commonwire";

    /// systemd keeps a service's state in `/var/lib/<name>` and gives it to the service's own account.
    fn state_directory(data: &Path) -> Result<String, String> {
        let name = data.strip_prefix("/var/lib").ok().and_then(|n| n.to_str()).unwrap_or_default();
        let valid = !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && !name.starts_with('.');
        if valid {
            Ok(name.to_string())
        } else {
            Err("the service keeps its data in a directory of /var/lib, such as /var/lib/commonwire".into())
        }
    }

    fn unit(data: &Path, state: &str) -> String {
        format!(
            "[Unit]
Description=commonwire host
Wants=network-online.target
After=network-online.target

[Service]
ExecStart={BINARY} serve --data {data}
Restart=always
RestartSec=1
TimeoutStopSec=10
DynamicUser=yes
StateDirectory={state}
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65536
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
",
            data = data.display()
        )
    }

    pub fn install(data: &Path) -> Result<(), String> {
        require_root()?;
        if !Path::new("/run/systemd/system").is_dir() {
            return Err("this system doesn't run systemd".into());
        }
        let state = state_directory(data)?;
        let _ = run("systemctl", &["stop", "commonwire.service"]);
        place_binary(Path::new(BINARY))?;
        write_file(UNIT, &unit(data, &state), 0o644)?;
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "commonwire.service"])?;
        run("systemctl", &["start", "commonwire.service"])?;
        Ok(())
    }

    pub fn uninstall() -> Result<(), String> {
        require_root()?;
        let _ = run("systemctl", &["disable", "--now", "commonwire.service"]);
        for path in [UNIT, BINARY] {
            match std::fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{path}: {e}")),
                _ => {}
            }
        }
        run("systemctl", &["daemon-reload"])?;
        Ok(())
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use windows_service::service::{
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    const NAME: &str = "commonwire";
    /// LocalService, by its SID, so granting it the data directory works in every language.
    const LOCAL_SERVICE_SID: &str = "*S-1-5-19";

    fn binary() -> PathBuf {
        PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into()))
            .join("commonwire")
            .join("commonwire.exe")
    }

    fn manager(access: ServiceManagerAccess) -> Result<ServiceManager, String> {
        ServiceManager::local_computer(None::<&str>, access)
            .map_err(|e| format!("can't open the service manager ({e}); run this from an administrator prompt"))
    }

    const ACCESS: ServiceAccess = ServiceAccess::QUERY_STATUS
        .union(ServiceAccess::START)
        .union(ServiceAccess::STOP)
        .union(ServiceAccess::CHANGE_CONFIG)
        .union(ServiceAccess::DELETE);

    fn stop(service: &Service) -> Result<(), String> {
        let stopped = |s: &Service| s.query_status().is_ok_and(|st| st.current_state == ServiceState::Stopped);
        if stopped(service) {
            return Ok(());
        }
        let _ = service.stop();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(15) {
            if stopped(service) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err("the running host didn't stop".into())
    }

    pub fn install(data: &Path) -> Result<(), String> {
        let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
        let existing = manager.open_service(NAME, ACCESS).ok();
        if let Some(service) = &existing {
            stop(service)?;
        }
        let binary = binary();
        place_binary(&binary)?;
        let data_text = data.display().to_string();
        run("icacls", &[&data_text, "/grant", &format!("{LOCAL_SERVICE_SID}:(OI)(CI)M"), "/T", "/Q"])?;
        let info = ServiceInfo {
            name: OsString::from(NAME),
            display_name: OsString::from("commonwire host"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: binary,
            launch_arguments: ["service", "run", "--data", data_text.as_str()].iter().map(OsString::from).collect(),
            dependencies: vec![],
            account_name: Some(OsString::from(r"NT AUTHORITY\LocalService")),
            account_password: None,
        };
        let service = match existing {
            Some(service) => {
                service.change_config(&info).map_err(|e| e.to_string())?;
                service
            }
            None => manager.create_service(&info, ACCESS).map_err(|e| e.to_string())?,
        };
        service.set_description("Runs the commonwire host on this computer.").map_err(|e| e.to_string())?;
        let restart = ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(1) };
        service
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![restart.clone(), restart.clone(), restart]),
            })
            .map_err(|e| e.to_string())?;
        service.set_failure_actions_on_non_crash_failures(true).map_err(|e| e.to_string())?;
        service.start::<&str>(&[]).map_err(|e| e.to_string())
    }

    pub fn uninstall() -> Result<(), String> {
        let manager = manager(ServiceManagerAccess::CONNECT)?;
        if let Ok(service) = manager.open_service(NAME, ACCESS) {
            stop(&service)?;
            service.delete().map_err(|e| e.to_string())?;
        }
        let binary = binary();
        let running_it = std::env::current_exe().ok().and_then(|e| e.canonicalize().ok()) == binary.canonicalize().ok();
        if !running_it {
            if let Some(dir) = binary.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        } else {
            println!("Delete {} to remove the program.", binary.parent().map_or(binary.clone(), Path::to_path_buf).display());
        }
        Ok(())
    }

    static DATA: OnceLock<PathBuf> = OnceLock::new();

    /// Runs as the service the manager started: serves until told to stop.
    pub fn run_service(data: PathBuf) -> Result<(), String> {
        let _ = DATA.set(data);
        service_dispatcher::start(NAME, ffi_service_main).map_err(|e| e.to_string())
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        let data = DATA.get().cloned().unwrap_or_default();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let tx = Mutex::new(Some(tx));
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(tx) = tx.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(status) = service_control_handler::register(NAME, handler) else { return };
        let report = |state, accepted, exit_code| {
            let _ = status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: accepted,
                exit_code,
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
        };
        report(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, ServiceExitCode::Win32(0));
        let served = crate::load_config(&data).and_then(|config| {
            let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
            runtime.block_on(crate::server::run(&data, config, false, None, async {
                let _ = rx.await;
            }))
        });
        let exit = match served {
            Ok(()) => ServiceExitCode::Win32(0),
            Err(e) => {
                use std::io::Write;
                if let Ok(mut log) = std::fs::OpenOptions::new().create(true).append(true).open(data.join("commonwire.log")) {
                    let _ = writeln!(log, "commonwire: {e}");
                }
                ServiceExitCode::ServiceSpecific(1)
            }
        };
        report(ServiceState::Stopped, ServiceControlAccept::empty(), exit);
    }
}
