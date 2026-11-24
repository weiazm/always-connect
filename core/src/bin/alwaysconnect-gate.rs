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
//! - controller -> gate, first line: `{"probe_alpn":"...","groups":[{"id":1,"sites":["a.example"]}]}`
//!   (a site covers its subdomains); the same shape again replaces it
//! - gate -> controller: `{"check":{"group":1,"host":"www.a.example","ip":"192.0.2.1","port":443,"requestId":1}}`
//! - gate -> controller statistics: `{"denied":[{"group":1,"count":2,"hosts":[{"host":"a.example","count":2}],"hostsTruncated":false,"lastHost":"a.example"}]}`
//!   Cumulative for this peer and sent only after a real denial.
//! - controller -> gate: `{"verdict":{"group":1,"requestId":1,"result":"allow","evidenceAtMs":1234}}`
//!   (`result` is `allow`, `block` or `unverified`), or `{"invalidate":true}`
//!
//! Without a controller every check times out and protected connections
//! are refused: the gate fails closed.
//!
//! `$AC_GATE_TUN` picks the interface: `utun` (macOS, the product path) or
//! `linux:<name>[:netns=<ns>]` (the CI harness, which keeps the client side
//! in its own network namespace).

use alwaysconnect_core::egress_gate::{DeniedGroup, Gate, GateConfig, GroupId, Out, ProtectedSites, RequestId, SiteGroup, Step, Verdict};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

#[derive(Deserialize)]
struct ControllerCfg {
    probe_alpn: String,
    groups: Vec<SiteGroup>,
}

#[derive(Deserialize)]
struct ControlVerdict {
    group: GroupId,
    #[serde(rename = "requestId")]
    request_id: RequestId,
    result: String,
    #[serde(rename = "evidenceAtMs")]
    evidence_at_ms: Option<u64>,
}

impl ControlVerdict {
    fn verdict(&self) -> Verdict {
        match (self.result.as_str(), self.evidence_at_ms) {
            ("allow", Some(evidence_at_ms)) => Verdict::Allow { evidence_at_ms },
            ("unverified", _) => Verdict::Unverified,
            _ => Verdict::Block,
        }
    }
}

#[derive(Deserialize)]
struct ControlMsg {
    verdict: Option<ControlVerdict>,
    invalidate: Option<bool>,
    /// A new configuration while running (same shape as the first line).
    probe_alpn: Option<String>,
    groups: Option<Vec<SiteGroup>>,
}

fn log(msg: &str) {
    eprintln!("alwaysconnect-gate: {msg}");
}

// ------------------------------------------------------------------ tunnel

trait Tun {
    fn fd(&self) -> RawFd;
    fn read<'a>(&self, buf: &'a mut [u8]) -> std::io::Result<&'a [u8]>;
    fn write(&self, pkt: &[u8]) -> std::io::Result<()>;
}

fn sys(r: isize) -> std::io::Result<usize> {
    if r < 0 { Err(std::io::Error::last_os_error()) } else { Ok(r as usize) }
}

fn cloexec(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux_tun {
    use super::*;
    pub struct LinuxTun(pub OwnedFd);
    impl Tun for LinuxTun {
        fn fd(&self) -> RawFd { self.0.as_raw_fd() }
        fn read<'a>(&self, buf: &'a mut [u8]) -> std::io::Result<&'a [u8]> {
            let len = sys(unsafe { libc::read(self.fd(), buf.as_mut_ptr().cast(), buf.len()) })?;
            Ok(&buf[..len])
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
        fn read<'a>(&self, buf: &'a mut [u8]) -> std::io::Result<&'a [u8]> {
            let len = sys(unsafe { libc::read(self.fd(), buf.as_mut_ptr().cast(), buf.len()) })?;
            Ok(buf.get(4..len).unwrap_or_default())
        }
        fn write(&self, pkt: &[u8]) -> std::io::Result<()> {
            let af: u32 = if pkt.first().map(|b| b >> 4) == Some(6) { libc::AF_INET6 as u32 } else { libc::AF_INET as u32 };
            let family = af.to_be_bytes();
            let slices = [
                libc::iovec { iov_base: family.as_ptr().cast_mut().cast(), iov_len: family.len() },
                libc::iovec { iov_base: pkt.as_ptr().cast_mut().cast(), iov_len: pkt.len() },
            ];
            sys(unsafe { libc::writev(self.fd(), slices.as_ptr(), 2) }).map(|_| ())
        }
    }
    pub fn open() -> std::io::Result<Utun> {
        unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if fd < 0 { return Err(std::io::Error::last_os_error()); }
            let fd = OwnedFd::from_raw_fd(fd);
            cloexec(fd.as_raw_fd())?;
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
#[cfg(target_os = "macos")]
fn vpnc_script(reason: &str, tundev: &str) -> bool {
    // The engine passes the installed vpnc-script as our first argument, so
    // openconnect's command line still names it (process sweeps and the
    // recovery script find it, DESIGN §66.5).
    let Some(path) = std::env::args().nth(1) else { return false; };
    std::process::Command::new(path).env("reason", reason)
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
            let _ = vpnc_script("disconnect", &name);
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
    partial_optional: bool,
}

impl Control {
    fn separated_frame(&self, mut frame: String) -> String {
        if self.partial_optional {
            frame.insert(0, '\n');
        }
        frame
    }

    fn write_required(&mut self, frame: String) -> std::io::Result<()> {
        let frame = self.separated_frame(frame);
        self.stream.write_all(frame.as_bytes())?;
        self.partial_optional = false;
        Ok(())
    }

    fn report_denied(&mut self, denied: &DeniedGroup) {
        let line = serde_json::json!({ "denied": [denied] }).to_string() + "\n";
        self.write_optional(line);
    }

    fn write_optional(&mut self, line: String) {
        let frame = self.separated_frame(line);
        if let Ok(written) = self.stream.write(frame.as_bytes()) {
            if written > 0 {
                // Incomplete optional frames are discarded by the line
                // reader. Terminate the fragment before any subsequent frame.
                self.partial_optional = frame.as_bytes()[written - 1] != b'\n';
            }
        }
    }
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
    Some((Control { stream, reader, partial_optional: false }, cfg))
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
    if let Err(error) = cloexec(vpn.as_raw_fd()) {
        log(&format!("invalid tunnel descriptor: {error}"));
        std::process::exit(1);
    }
    let Some((controller, cfg)) = connect_control() else {
        log("no initial configuration; refusing to start the tunnel");
        std::process::exit(1);
    };
    let (tun, ifname) = match open_tun() {
        Ok(t) => t,
        Err(e) => {
            log(&format!("cannot create the tunnel interface: {e}"));
            std::process::exit(1);
        }
    };
    let mut control = Some(controller);
    let gcfg = GateConfig { probe_alpn: cfg.probe_alpn.into_bytes(), ..GateConfig::default() };
    let mut gate = Gate::new(gcfg, ProtectedSites::new(&cfg.groups));
    log(&format!("up on {ifname}"));
    if let Some(c) = &mut control {
        let _ = c.stream.write_all((serde_json::json!({ "up": { "ifname": ifname } }).to_string() + "\n").as_bytes());
    }
    let _ = std::io::stdout().flush();

    let mut buf = vec![0u8; 65_540];
    let mut last_tick = Instant::now();
    let mut ctl_line = Vec::new();
    while !STOP.load(Ordering::SeqCst) {
        let mut fds = vec![
            libc::pollfd { fd: tun.fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: vpn.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        if let Some(c) = &control {
            fds.push(libc::pollfd { fd: c.stream.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        let buffered = control.as_ref().is_some_and(|c| !c.reader.buffer().is_empty());
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, if buffered { 0 } else { 250 }) };
        if r < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break;
        }
        if buffered || (fds.len() > 2 && fds[2].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0) {
            let mut lost = false;
            while let Some(c) = &mut control {
                match c.reader.read_until(b'\n', &mut ctl_line) {
                    Ok(0) => {
                        lost = true;
                        break;
                    }
                    Ok(_) => match serde_json::from_slice::<ControlMsg>(&std::mem::take(&mut ctl_line)) {
                        Ok(m) => {
                            if let (Some(alpn), Some(groups)) = (m.probe_alpn, m.groups) {
                                log("new configuration");
                                gate.reconfigure(alpn.into_bytes(), ProtectedSites::new(&groups));
                            }
                            if m.invalidate == Some(true) {
                                gate.invalidate();
                            }
                            if let Some(v) = m.verdict {
                                log(&format!("verdict group={} request={} result={}", v.group, v.request_id, v.result));
                                gate.verdict(v.group, v.request_id, v.verdict(), Instant::now());
                            }
                        }
                        Err(e) => log(&format!("bad control line: {e}")),
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        lost = ctl_line.len() > 524_288;
                        break;
                    }
                    Err(_) => {
                        lost = true;
                        break;
                    }
                }
            }
            if lost {
                log("controller gone: protected connections will be refused (fail closed)");
                gate.invalidate();
                control = None;
            }
            // Apply only after buffered invalidations have had a chance to
            // retire permits from earlier frames.
            apply(&mut gate, &vpn, tun.as_ref(), &mut control);
        }
        let now = Instant::now();
        if fds[0].revents & libc::POLLIN != 0 {
            // Drain a burst from the Mac side.
            for _ in 0..64 {
                match tun.read(&mut buf) {
                    Ok(pkt) if !pkt.is_empty() => {
                        if gate.outbound(pkt, now) == Step::Forward {
                            let _ = send(&vpn, pkt);
                        }
                        apply(&mut gate, &vpn, tun.as_ref(), &mut control);
                    }
                    _ => break,
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
                    let _ = tun.write(&buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log(&format!("tunnel socket: {e}"));
                    break;
                }
            }
        }
        if now.duration_since(last_tick) >= Duration::from_millis(250) {
            gate.tick(now);
            apply(&mut gate, &vpn, tun.as_ref(), &mut control);
            if let Some(control) = &mut control {
                if let Some(denied) = gate.take_denied_group() {
                    control.report_denied(denied);
                }
            }
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

fn send_checked(vpn: &OwnedFd, packets: &[Vec<u8>]) -> bool {
    let mut packets = packets.iter();
    let send = |pkt: &[u8]| {
        sys(unsafe { libc::send(vpn.as_raw_fd(), pkt.as_ptr().cast(), pkt.len(), libc::MSG_DONTWAIT) })
            .is_ok_and(|written| written == pkt.len())
    };
    if !packets.next().is_some_and(|first| send(first)) {
        return false;
    }
    for pkt in packets {
        let _ = send(pkt);
    }
    true
}

fn check_line(group: GroupId, host: &str, destination: SocketAddr, request_id: RequestId) -> String {
    serde_json::json!({
        "check": {
            "group": group,
            "host": host,
            "ip": destination.ip(),
            "port": destination.port(),
            "requestId": request_id,
        },
    }).to_string() + "\n"
}

fn apply(gate: &mut Gate, vpn: &OwnedFd, tun: &dyn Tun, control: &mut Option<Control>) {
    let had_controller = control.is_some();
    let mut actions = gate.drain().into_iter();
    while let Some(o) = actions.next().or_else(|| {
        actions = gate.drain().into_iter();
        actions.next()
    }) {
        match o {
            Out::ToTunnel(p) => {
                let _ = send(vpn, &p);
            }
            Out::ToHost(p) => {
                let _ = tun.write(&p);
            }
            Out::SendChecked(id) => {
                gate.send_checked(id, Instant::now(), |packets| control.is_some() && send_checked(vpn, packets));
            }
            Out::Check { group, host, destination, request_id } => {
                if let Some(c) = control {
                    log(&format!("check group={group} request={request_id}"));
                    if let Err(error) = c.write_required(check_line(group, &host, destination, request_id)) {
                        log(&format!("controller write failed: {error}"));
                        *control = None;
                    }
                }
            }
        }
    }
    if had_controller && control.is_none() {
        gate.invalidate();
        for action in gate.drain() {
            if let Out::ToHost(packet) = action {
                let _ = tun.write(&packet);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::net::UnixDatagram;

    #[derive(Default)]
    struct TestTun(RefCell<Vec<Vec<u8>>>);

    impl Tun for TestTun {
        fn fd(&self) -> RawFd { unreachable!() }
        fn read<'a>(&self, _: &'a mut [u8]) -> std::io::Result<&'a [u8]> { unreachable!() }
        fn write(&self, packet: &[u8]) -> std::io::Result<()> {
            self.0.borrow_mut().push(packet.to_vec());
            Ok(())
        }
    }

    fn tcp(dst: u8, flags: u8, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
        packet[9] = 6;
        packet[12..20].copy_from_slice(&[192, 0, 2, 10, 198, 51, 100, dst]);
        packet[20..24].copy_from_slice(&[0x9c, 0x40, 0x01, 0xbb]);
        packet[24..28].copy_from_slice(&seq.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet.extend_from_slice(payload);
        packet
    }

    /// A connection to `dst` whose first data is a plain HTTP request for `host`.
    fn hold_request(gate: &mut Gate, dst: u8, host: &str, now: Instant) {
        assert_eq!(gate.outbound(&tcp(dst, 0x02, 1000, &[]), now), Step::Forward);
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        assert_eq!(gate.outbound(&tcp(dst, 0x18, 1001, request.as_bytes()), now), Step::Consumed);
    }

    fn gate() -> Gate {
        Gate::new(GateConfig::default(), ProtectedSites::new(&[SiteGroup { id: 7, sites: vec!["a.example".into()] }]))
    }

    #[test]
    fn check_carries_the_numeric_destination_and_request_id() {
        let destination = "[2001:db8::1]:8443".parse().unwrap();
        let id = RequestId::new(u64::MAX).unwrap();
        let line = check_line(7, "www.a.example", destination, id);
        assert!(line.ends_with('\n'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap(),
            serde_json::json!({
                "check": {"group": 7, "host": "www.a.example", "ip": "2001:db8::1", "port": 8443, "requestId": u64::MAX},
            })
        );
    }

    #[test]
    fn verdicts_require_a_request_id_and_fail_closed() {
        let parse = |line: &str| serde_json::from_str::<ControlMsg>(line).map(|m| m.verdict.unwrap().verdict());
        assert_eq!(parse(r#"{"verdict":{"group":7,"requestId":42,"result":"allow","evidenceAtMs":81234}}"#).unwrap(),
                   Verdict::Allow { evidence_at_ms: 81234 });
        assert_eq!(parse(r#"{"verdict":{"group":7,"requestId":42,"result":"unverified"}}"#).unwrap(), Verdict::Unverified);
        assert_eq!(parse(r#"{"verdict":{"group":7,"requestId":42,"result":"allow"}}"#).unwrap(), Verdict::Block,
                   "an allow without its evidence time");
        assert_eq!(parse(r#"{"verdict":{"group":7,"requestId":42,"result":"later"}}"#).unwrap(), Verdict::Block);
        for invalid in [
            r#"{"verdict":{"group":7,"requestId":0,"result":"allow"}}"#,
            r#"{"verdict":{"group":7,"result":"allow"}}"#,
        ] {
            assert!(serde_json::from_str::<ControlMsg>(invalid).is_err());
        }
    }

    #[test]
    fn configuration_frames_name_sites_per_rule() {
        let cfg: ControllerCfg = serde_json::from_str(r#"{"probe_alpn":"m","groups":[{"id":1,"sites":["a.example"]}]}"#).unwrap();
        let sites = ProtectedSites::new(&cfg.groups);
        assert_eq!(sites.group_for("www.a.example"), Some(1));
        assert_eq!(sites.group_for("b.example"), None);
        let update = serde_json::from_str::<ControlMsg>(r#"{"probe_alpn":"m","groups":[]}"#).unwrap();
        assert!(update.groups.unwrap().is_empty());
    }

    #[test]
    fn a_partial_denial_frame_is_separated_before_later_policy_frames() {
        let (stream, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut control = Control { reader: BufReader::new(stream.try_clone().unwrap()), stream, partial_optional: true };
        control.stream.write_all(b"{\"denied\":[").unwrap();
        control.report_denied(&DeniedGroup { group: 7, count: 2, ..Default::default() });
        assert!(!control.partial_optional);
        let check = check_line(7, "a.example", "192.0.2.1:443".parse().unwrap(), RequestId::new(42).unwrap());
        control.write_required(check).unwrap();

        let mut lines = BufReader::new(peer).lines();
        let partial = lines.next().unwrap().unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&partial).is_err());
        let denied: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
        assert_eq!(denied, serde_json::json!({
            "denied":[{"group":7,"count":2,"hosts":[],"hostsTruncated":false,"lastHost":null}],
        }));
        let required: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
        assert_eq!(required["check"]["requestId"], 42);
    }

    #[test]
    fn a_failed_check_write_refuses_the_other_waiting_connections() {
        let (stream, peer) = UnixStream::pair().unwrap();
        let mut control = Some(Control { reader: BufReader::new(stream.try_clone().unwrap()), stream, partial_optional: false });
        let (vpn, remote) = UnixDatagram::pair().unwrap();
        remote.set_nonblocking(true).unwrap();
        let vpn = vpn.into();
        let tun = TestTun::default();
        let mut gate = gate();
        let now = Instant::now();
        hold_request(&mut gate, 1, "a.example", now);
        apply(&mut gate, &vpn, &tun, &mut control);
        drop(peer);

        hold_request(&mut gate, 2, "www.a.example", now);
        apply(&mut gate, &vpn, &tun, &mut control);
        assert!(control.is_none());
        assert_eq!(tun.0.borrow().len(), 2, "both connections were reset");
        gate.verdict(7, RequestId::new(2).unwrap(), Verdict::Unverified, now);
        apply(&mut gate, &vpn, &tun, &mut control);
        assert_eq!(remote.recv(&mut [0; 128]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }
}
