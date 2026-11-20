//! alwaysconnect-gate: the egress gate program (DESIGN.md §66.5).
//!
//! openconnect starts it in `--script-tun` mode: every tunnel IP packet
//! arrives on the datagram socket `$VPNFD`, and the usual vpnc-script
//! variables describe the tunnel. The gate creates the tunnel interface
//! itself, moves packets between the interface and `$VPNFD`, and lets
//! [`egress_gate::Gate`] decide each outbound packet. Egress checks are
//! delegated to a controller over a UNIX stream socket (`$AC_GATE_CONTROL`),
//! one JSON object per line:
//!
//! - controller -> gate, first line: `{"probe_alpn":"...","groups":[{"id":1,"names":["a.example","*.a.example"],"cidrs":["203.0.113.0/24"]}]}`
//! - gate -> controller: `{"check":{"group":1,"host":"a.example"}}`
//! - controller -> gate: `{"verdict":{"group":1,"ok":true}}`, `{"invalidate":true}`
//!
//! Without a controller every check times out and protected connections
//! are refused: the gate fails closed.
//!
//! `$AC_GATE_TUN` picks the interface: `utun` (macOS, the product path) or
//! `linux:<name>[:netns=<ns>]` (the CI harness, which keeps the client side
//! in its own network namespace).

use alwaysconnect_core::egress_gate::{Classifier, Gate, GateConfig, GroupId, Out, Step};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

#[derive(Deserialize)]
struct GroupCfg {
    id: GroupId,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    cidrs: Vec<String>,
}

#[derive(Deserialize)]
struct ControllerCfg {
    probe_alpn: String,
    groups: Vec<GroupCfg>,
}

#[derive(Deserialize)]
struct Verdict {
    group: GroupId,
    ok: bool,
}

#[derive(Deserialize)]
struct ControlMsg {
    verdict: Option<Verdict>,
    invalidate: Option<bool>,
}

/// Exact names, `*.suffix` wildcards (subdomains only) and CIDRs. The
/// product will feed the split-rule engine's resolved lists here.
struct Groups {
    groups: Vec<(GroupId, Vec<String>, Vec<(IpAddr, u8)>)>,
}

impl Classifier for Groups {
    fn group_for_name(&self, name: &str) -> Option<GroupId> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.groups.iter().find(|(_, names, _)| names.iter().any(|p| match p.strip_prefix("*.") {
            Some(suffix) => name.len() > suffix.len() && name.ends_with(suffix) && name.as_bytes()[name.len() - suffix.len() - 1] == b'.',
            None => *p == name,
        })).map(|(id, _, _)| *id)
    }
    fn group_for_ip(&self, ip: IpAddr) -> Option<GroupId> {
        self.groups.iter().find(|(_, _, nets)| nets.iter().any(|(net, len)| in_net(ip, *net, *len))).map(|(id, _, _)| *id)
    }
}

fn in_net(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => len <= 32 && (len == 0 || (u32::from(a) ^ u32::from(n)) >> (32 - len as u32) == 0),
        (IpAddr::V6(a), IpAddr::V6(n)) => len <= 128 && (len == 0 || (u128::from(a) ^ u128::from(n)) >> (128 - len as u32) == 0),
        _ => false,
    }
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, len) = s.split_once('/').unwrap_or((s, ""));
    let ip: IpAddr = ip.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = if len.is_empty() { max } else { len.trim().parse().ok()? };
    (len <= max).then_some((ip, len))
}

fn log(msg: &str) {
    eprintln!("alwaysconnect-gate: {msg}");
}

// ------------------------------------------------------------------ tunnel

trait Tun {
    fn fd(&self) -> RawFd;
    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn write(&self, pkt: &[u8]) -> std::io::Result<()>;
}

fn sys(r: isize) -> std::io::Result<usize> {
    if r < 0 { Err(std::io::Error::last_os_error()) } else { Ok(r as usize) }
}

#[cfg(target_os = "linux")]
mod linux_tun {
    use super::*;
    pub struct LinuxTun(pub OwnedFd);
    impl Tun for LinuxTun {
        fn fd(&self) -> RawFd { self.0.as_raw_fd() }
        fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            sys(unsafe { libc::read(self.fd(), buf.as_mut_ptr().cast(), buf.len()) })
        }
        fn write(&self, pkt: &[u8]) -> std::io::Result<()> {
            sys(unsafe { libc::write(self.fd(), pkt.as_ptr().cast(), pkt.len()) }).map(|_| ())
        }
    }
    /// Create `name` (IFF_TUN|IFF_NO_PI), optionally move it into a network
    /// namespace, and give it the tunnel address and a default route there.
    pub fn open(name: &str, netns: Option<&str>, addr: &str, mtu: &str) -> std::io::Result<LinuxTun> {
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut ifr = [0u8; 40];
        ifr[..name.len().min(15)].copy_from_slice(&name.as_bytes()[..name.len().min(15)]);
        let flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF as _, ifr.as_mut_ptr()) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ip = |args: &[&str]| -> std::io::Result<()> {
            let st = std::process::Command::new("ip").args(args).status()?;
            if st.success() { Ok(()) } else { Err(std::io::Error::other(format!("ip {args:?} failed"))) }
        };
        let mut pre: Vec<&str> = Vec::new();
        if let Some(ns) = netns {
            ip(&["link", "set", name, "netns", ns])?;
            pre = vec!["-n", ns];
        }
        let cidr = format!("{addr}/32");
        let run = |rest: &[&str]| -> std::io::Result<()> { ip(&[pre.as_slice(), rest].concat()) };
        run(&["addr", "add", &cidr, "dev", name])?;
        run(&["link", "set", name, "mtu", mtu, "up"])?;
        run(&["route", "replace", "default", "dev", name])?;
        Ok(LinuxTun(fd))
    }
}

#[cfg(target_os = "macos")]
mod utun {
    use super::*;
    /// A utun with the 4-byte protocol family prefix macOS uses.
    pub struct Utun { pub fd: OwnedFd, pub name: String }
    impl Tun for Utun {
        fn fd(&self) -> RawFd { self.fd.as_raw_fd() }
        fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut tmp = vec![0u8; buf.len() + 4];
            let n = sys(unsafe { libc::read(self.fd(), tmp.as_mut_ptr().cast(), tmp.len()) })?;
            if n < 4 { return Ok(0); }
            buf[..n - 4].copy_from_slice(&tmp[4..n]);
            Ok(n - 4)
        }
        fn write(&self, pkt: &[u8]) -> std::io::Result<()> {
            let af: u32 = if pkt.first().map(|b| b >> 4) == Some(6) { libc::AF_INET6 as u32 } else { libc::AF_INET as u32 };
            let mut v = Vec::with_capacity(pkt.len() + 4);
            v.extend_from_slice(&af.to_be_bytes());
            v.extend_from_slice(pkt);
            sys(unsafe { libc::write(self.fd(), v.as_ptr().cast(), v.len()) }).map(|_| ())
        }
    }
    pub fn open() -> std::io::Result<Utun> {
        unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if fd < 0 { return Err(std::io::Error::last_os_error()); }
            let fd = OwnedFd::from_raw_fd(fd);
            let mut info: libc::ctl_info = std::mem::zeroed();
            for (i, b) in b"com.apple.net.utun_control".iter().enumerate() { info.ctl_name[i] = *b as libc::c_char; }
            if libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) < 0 { return Err(std::io::Error::last_os_error()); }
            let mut addr: libc::sockaddr_ctl = std::mem::zeroed();
            addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
            addr.sc_family = libc::AF_SYSTEM as u8;
            addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
            addr.sc_id = info.ctl_id;
            addr.sc_unit = 0;
            if libc::connect(fd.as_raw_fd(), (&addr as *const libc::sockaddr_ctl).cast(), addr.sc_len as libc::socklen_t) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut name = [0u8; 32];
            let mut len = name.len() as libc::socklen_t;
            if libc::getsockopt(fd.as_raw_fd(), libc::SYSPROTO_CONTROL, libc::UTUN_OPT_IFNAME, name.as_mut_ptr().cast(), &mut len) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let name = String::from_utf8_lossy(&name[..len.saturating_sub(1) as usize]).into_owned();
            Ok(Utun { fd, name })
        }
    }
}

/// Run the existing vpnc-script for the interface the gate created, so
/// addresses, routes, DNS and drop protection stay exactly as today.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn vpnc_script(reason: &str, tundev: &str) -> bool {
    let Ok(script) = std::env::var("AC_GATE_VPNC_SCRIPT") else { return true };
    std::process::Command::new("/bin/sh")
        .args(["-c", &script])
        .env("reason", reason)
        .env("TUNDEV", tundev)
        .env_remove("VPNFD")
        .status()
        .is_ok_and(|s| s.success())
}

fn open_tun() -> std::io::Result<(Box<dyn Tun>, String)> {
    let spec = std::env::var("AC_GATE_TUN").unwrap_or_else(|_| "utun".into());
    let addr = std::env::var("INTERNAL_IP4_ADDRESS").map_err(|_| std::io::Error::other("INTERNAL_IP4_ADDRESS missing"))?;
    let mtu = std::env::var("INTERNAL_IP4_MTU").unwrap_or_else(|_| "1300".into());
    if let Some(rest) = spec.strip_prefix("linux:") {
        #[cfg(target_os = "linux")]
        {
            let mut parts = rest.split(':');
            let name = parts.next().unwrap_or("acgate0").to_string();
            let netns = parts.find_map(|p| p.strip_prefix("netns=")).map(str::to_string);
            let t = linux_tun::open(&name, netns.as_deref(), &addr, &mtu)?;
            return Ok((Box::new(t), name));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (rest, addr, mtu);
            return Err(std::io::Error::other("linux tun requested on another platform"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (addr, mtu);
        let t = utun::open()?;
        let name = t.name.clone();
        if !vpnc_script("connect", &name) {
            return Err(std::io::Error::other("vpnc-script connect failed"));
        }
        Ok((Box::new(t), name))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (addr, mtu);
        Err(std::io::Error::other(format!("unsupported AC_GATE_TUN {spec}")))
    }
}

// ---------------------------------------------------------------- control

struct Control {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

fn connect_control() -> Option<(Control, ControllerCfg)> {
    let path = std::env::var("AC_GATE_CONTROL").ok()?;
    let stream = UnixStream::connect(&path).map_err(|e| log(&format!("control {path}: {e}"))).ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut first = String::new();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    reader.read_line(&mut first).ok()?;
    let cfg: ControllerCfg = serde_json::from_str(&first).map_err(|e| log(&format!("bad config: {e}"))).ok()?;
    stream.set_read_timeout(None).ok()?;
    stream.set_nonblocking(true).ok()?;
    Some((Control { stream, reader }, cfg))
}

fn main() {
    unsafe {
        libc::signal(libc::SIGHUP, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let Some(vpnfd) = std::env::var("VPNFD").ok().and_then(|v| v.parse::<RawFd>().ok()) else {
        log("VPNFD missing: run me as openconnect --script-tun");
        std::process::exit(2);
    };
    let vpn = unsafe { OwnedFd::from_raw_fd(vpnfd) };
    let (tun, ifname) = match open_tun() {
        Ok(t) => t,
        Err(e) => {
            log(&format!("cannot create the tunnel interface: {e}"));
            std::process::exit(1);
        }
    };
    let (mut control, cfg) = match connect_control() {
        Some((c, cfg)) => (Some(c), cfg),
        None => {
            log("no controller: protected connections will be refused (fail closed)");
            (None, ControllerCfg { probe_alpn: String::new(), groups: Vec::new() })
        }
    };
    let groups = Groups {
        groups: cfg.groups.iter().map(|g| (g.id, g.names.iter().map(|n| n.trim_end_matches('.').to_ascii_lowercase()).collect(), g.cidrs.iter().filter_map(|c| parse_cidr(c)).collect())).collect(),
    };
    let gcfg = GateConfig { probe_alpn: cfg.probe_alpn.into_bytes(), ..GateConfig::default() };
    let mut gate = Gate::new(gcfg, Box::new(groups));
    log(&format!("up on {ifname}"));
    let _ = std::io::stdout().flush();

    let mut buf = vec![0u8; 65536];
    let mut last_tick = Instant::now();
    let mut ctl_line = String::new();
    while !STOP.load(Ordering::SeqCst) {
        let mut fds = vec![
            libc::pollfd { fd: tun.fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: vpn.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        if let Some(c) = &control {
            fds.push(libc::pollfd { fd: c.stream.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 250) };
        if r < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break;
        }
        let now = Instant::now();
        if fds[0].revents & libc::POLLIN != 0 {
            // Drain a burst from the Mac side.
            for _ in 0..64 {
                match tun.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if gate.outbound(&buf[..n], now) == Step::Forward {
                            let _ = send(&vpn, &buf[..n]);
                        }
                        apply(&mut gate, &vpn, tun.as_ref(), &mut control);
                    }
                }
                if !readable(tun.fd()) {
                    break;
                }
            }
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            match sys(unsafe { libc::recv(vpn.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) }) {
                Ok(0) => {
                    log("tunnel closed");
                    break;
                }
                Ok(n) => {
                    gate.inbound(&buf[..n], now);
                    let _ = tun.write(&buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log(&format!("tunnel socket: {e}"));
                    break;
                }
            }
        }
        if fds.len() > 2 && fds[2].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut lost = false;
            if let Some(c) = &mut control {
                loop {
                    ctl_line.clear();
                    match c.reader.read_line(&mut ctl_line) {
                        Ok(0) => {
                            lost = true;
                            break;
                        }
                        Ok(_) => match serde_json::from_str::<ControlMsg>(&ctl_line) {
                            Ok(m) => {
                                if let Some(v) = m.verdict {
                                    log(&format!("verdict group={} ok={}", v.group, v.ok));
                                    gate.verdict(v.group, v.ok, Instant::now());
                                }
                                if m.invalidate == Some(true) {
                                    gate.invalidate();
                                }
                            }
                            Err(e) => log(&format!("bad control line: {e}")),
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            lost = true;
                            break;
                        }
                    }
                }
            }
            if lost {
                log("controller gone: protected connections will be refused (fail closed)");
                control = None;
            }
            apply(&mut gate, &vpn, tun.as_ref(), &mut control);
        }
        if now.duration_since(last_tick) >= Duration::from_millis(250) {
            gate.tick(now);
            apply(&mut gate, &vpn, tun.as_ref(), &mut control);
            last_tick = now;
        }
    }
    #[cfg(target_os = "macos")]
    let _ = vpnc_script("disconnect", &ifname);
    log("stopped");
}

fn readable(fd: RawFd) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut p, 1, 0) > 0 && p.revents & libc::POLLIN != 0 }
}

fn send(vpn: &OwnedFd, pkt: &[u8]) -> std::io::Result<usize> {
    sys(unsafe { libc::send(vpn.as_raw_fd(), pkt.as_ptr().cast(), pkt.len(), 0) })
}

fn apply(gate: &mut Gate, vpn: &OwnedFd, tun: &dyn Tun, control: &mut Option<Control>) {
    for o in gate.drain() {
        match o {
            Out::ToTunnel(p) => {
                let _ = send(vpn, &p);
            }
            Out::ToHost(p) => {
                let _ = tun.write(&p);
            }
            Out::Check { group, host } => {
                log(&format!("check group={group} host={}", host.as_deref().unwrap_or("-")));
                if let Some(c) = control {
                    let line = serde_json::json!({ "check": { "group": group, "host": host } }).to_string() + "\n";
                    let _ = c.stream.write_all(line.as_bytes());
                }
            }
        }
    }
}
