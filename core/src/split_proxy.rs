//! Sites that go through a user-configured SOCKS5 or HTTP CONNECT proxy
//! (DESIGN.md §六十九). Same rule syntax and parser as the split list
//! (`SplitRules`); only the destination differs.
//!
//! - The App sends the proxies inside the split list: "proxy:<n> socks5|http
//!   <host> <port>" declares proxy n, "via:<n>:<rule>" sends the rule's names
//!   to it. An older service ignores both kinds (they contain ':'), so those
//!   names stay in the VPN there; never direct.
//! - The DNS forwarder answers a proxied name with an address of its own
//!   from 198.19.128.0/17 and never asks any DNS server about it: the proxy
//!   resolves the name. AAAA, HTTPS and every other type get an empty answer.
//! - The range is routed to the loopback interface and pf redirects its TCP
//!   to this listener; everything else to the range (UDP, so QUIC) is refused
//!   at once. The listener asks pf for the original address, maps it back to
//!   the name and opens the tunnel through the proxy with the NAME, so the
//!   name's DNS happens at the proxy.
//! - Fail closed: no mapping, a rule that changed, a missing proxy, a proxy
//!   that does not answer or refuses — the app's connection is reset. Nothing
//!   that matched a proxy rule is ever sent direct or into the VPN instead.
//! - The connection to the proxy itself follows the ordinary split: a proxy
//!   in the local network or the direct list goes out locally, any other
//!   proxy through the VPN. A proxy address that is itself a proxied name
//!   is refused (it would loop).

use crate::dns_forwarder::SplitRules;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The answers' range: the upper half of 198.19/16 in the benchmarking
/// block, never routed publicly. Proxy tools' own TUN modes commonly take
/// 198.18.0.0/15 or 198.18.0.0/16; this narrower route wins over the first
/// and does not overlap the second.
pub const FAKE_NETWORK: &str = "198.19.128.0/17";
const FAKE_BASE: u32 = 0xC613_8000;
const FAKE_SIZE: u32 = 1 << 15;
/// Applications re-ask within a minute; the mapping itself lives longer.
pub const ANSWER_TTL: u32 = 60;
/// Names kept at most; the least recently used go first.
const MAX_NAMES: usize = 8192;
const MAX_PROXIES: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Simultaneous proxied connections; more are reset.
const MAX_CONNECTIONS: usize = 256;
const STACK: usize = 128 * 1024;
/// A failure is shown on the panel this long and logged once per this.
const NOTICE_FOR: Duration = Duration::from_secs(60);

pub fn is_fake(ip: Ipv4Addr) -> bool {
    u32::from(ip) & !(FAKE_SIZE - 1) == FAKE_BASE
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind { Socks5, Http }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server { pub kind: Kind, pub host: String, pub port: u16 }

impl Server {
    fn parse(text: &str) -> Option<Server> {
        let mut fields = text.split_whitespace();
        let kind = match fields.next()? { "socks5" => Kind::Socks5, "http" => Kind::Http, _ => return None };
        let host = fields.next()?.trim_matches(|c| c == '[' || c == ']').to_owned();
        let port: u16 = fields.next()?.parse().ok().filter(|p| *p > 0)?;
        let valid = !host.is_empty() && host.len() <= 253
            && host.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b':'));
        (valid && fields.next().is_none()).then_some(Server { kind, host, port })
    }

    pub fn label(&self) -> String {
        let kind = match self.kind { Kind::Socks5 => "SOCKS5", Kind::Http => "HTTP" };
        format!("{kind} {}:{}", self.host, self.port)
    }
}

fn clean(name: &str) -> String {
    name.trim_matches('.').to_ascii_lowercase()
}

/// The proxies and their rules, in the App's order: the first proxy whose
/// rules match a name takes it.
#[derive(Default, Debug)]
pub struct Table {
    /// None: declared badly or not at all. Its names are refused.
    servers: Vec<Option<Server>>,
    groups: Vec<(usize, SplitRules)>,
}

impl Table {
    pub fn parse<S: AsRef<str>>(list: &[S]) -> Table {
        let mut servers: BTreeMap<usize, Option<Server>> = BTreeMap::new();
        let mut rules: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        for raw in list {
            let line = raw.as_ref().trim();
            if let Some(rest) = line.strip_prefix("proxy:") {
                let (index, server) = rest.split_once(' ').unwrap_or((rest, ""));
                if let Some(n) = index.parse::<usize>().ok().filter(|n| *n < MAX_PROXIES) {
                    servers.insert(n, Server::parse(server));
                }
            } else if let Some(rest) = line.strip_prefix("via:") {
                if let Some((index, rule)) = rest.split_once(':') {
                    if let Some(n) = index.parse::<usize>().ok().filter(|n| *n < MAX_PROXIES) {
                        // Names only: an address range needs the real
                        // answer first, which would ask a DNS server.
                        if !rule.starts_with("ipcidr:") { rules.entry(n).or_default().push(rule.to_owned()); }
                    }
                }
            }
        }
        let size = servers.keys().chain(rules.keys()).max().map_or(0, |n| n + 1);
        let mut table = Table { servers: vec![None; size], groups: Vec::new() };
        for (n, server) in servers { table.servers[n] = server; }
        table.groups = rules.into_iter().map(|(n, list)| (n, SplitRules::new(&list))).collect();
        table
    }

    pub fn is_empty(&self) -> bool { self.groups.is_empty() }

    /// Which proxy takes `name` (already trimmed and lowercased).
    fn route(&self, name: &str) -> Option<usize> {
        self.groups.iter().find(|(_, rules)| rules.matches_name(name)).map(|(n, _)| *n)
    }

    fn server(&self, n: usize) -> Option<&Server> {
        self.servers.get(n).and_then(Option::as_ref)
    }
}

struct Entry { name: String, used: Instant }

#[derive(Default)]
struct Pool {
    by_name: HashMap<String, u32>,
    by_offset: HashMap<u32, Entry>,
    next: u32,
}

impl Pool {
    fn assign(&mut self, name: &str, now: Instant) -> Ipv4Addr {
        if let Some(&offset) = self.by_name.get(name) {
            if let Some(entry) = self.by_offset.get_mut(&offset) { entry.used = now; }
            return Ipv4Addr::from(FAKE_BASE + offset);
        }
        if self.by_offset.len() >= MAX_NAMES {
            // Down to 7/8 in one pass, oldest first.
            let mut by_age: Vec<_> = self.by_offset.iter().map(|(o, e)| (e.used, *o)).collect();
            by_age.sort_unstable();
            for (_, offset) in by_age.into_iter().take(MAX_NAMES / 8) {
                if let Some(entry) = self.by_offset.remove(&offset) { self.by_name.remove(&entry.name); }
            }
        }
        // Walk the whole range before reusing an address, so a forgotten
        // name's address is not handed to another name soon after.
        let offset = loop {
            self.next = self.next % (FAKE_SIZE - 2) + 1;
            if !self.by_offset.contains_key(&self.next) { break self.next; }
        };
        self.by_name.insert(name.to_owned(), offset);
        self.by_offset.insert(offset, Entry { name: name.to_owned(), used: now });
        Ipv4Addr::from(FAKE_BASE + offset)
    }

    fn name(&mut self, ip: Ipv4Addr, now: Instant) -> Option<String> {
        if !is_fake(ip) { return None; }
        let entry = self.by_offset.get_mut(&(u32::from(ip) - FAKE_BASE))?;
        entry.used = now;
        Some(entry.name.clone())
    }
}

/// Shared by the DNS forwarder (answers) and the listener (connections).
#[derive(Default)]
pub struct Routing {
    table: RwLock<Arc<Table>>,
    pool: Mutex<Pool>,
    notice: Mutex<Option<(Instant, String)>>,
    logged: Mutex<HashMap<String, Instant>>,
    connections: AtomicU64,
}

impl Routing {
    pub fn new(table: Table) -> Arc<Routing> {
        let routing = Routing::default();
        *routing.table.write().unwrap() = Arc::new(table);
        Arc::new(routing)
    }

    pub fn set_table(&self, table: Table) {
        *self.table.write().unwrap() = Arc::new(table);
    }

    pub fn is_empty(&self) -> bool { self.table.read().unwrap().is_empty() }

    /// The address to answer `name` with, or None when no proxy rule
    /// matches it (then the ordinary split decides).
    pub fn answer(&self, name: &str) -> Option<Ipv4Addr> {
        let name = clean(name);
        if name.is_empty() { return None; }
        self.table.read().unwrap().route(&name)?;
        Some(self.pool.lock().unwrap().assign(&name, Instant::now()))
    }

    /// The name behind one of our addresses (the connections panel).
    pub fn name_for(&self, ip: Ipv4Addr) -> Option<String> {
        self.pool.lock().unwrap().name(ip, Instant::now())
    }

    /// The name and proxy for a connection to `ip`, decided by the rules
    /// now: a rule changed since the answer goes to its new proxy, or is
    /// refused when no proxy takes it any more.
    fn target(&self, ip: Ipv4Addr) -> Result<(String, Server), (String, &'static str)> {
        let name = self.pool.lock().unwrap().name(ip, Instant::now())
            .ok_or_else(|| (ip.to_string(), "这个地址的记录已过期，请重新打开网页"))?;
        let table = self.table.read().unwrap().clone();
        let Some(n) = table.route(&name) else { return Err((name, "代理规则已改，这条连接不再走代理，请重新打开网页")) };
        match table.server(n) {
            Some(server) => Ok((name, server.clone())),
            None => Err((name, "规则指向的代理不存在或地址无效")),
        }
    }

    fn failed(&self, name: &str, reason: &str) {
        let now = Instant::now();
        let text = format!("经代理打开 {name} 失败：{reason}");
        *self.notice.lock().unwrap() = Some((now, text.clone()));
        let mut logged = self.logged.lock().unwrap();
        if logged.len() > 256 { logged.retain(|_, at| now.duration_since(*at) < NOTICE_FOR); }
        let key = format!("{name}\u{0}{reason}");
        if logged.get(&key).is_none_or(|at| now.duration_since(*at) >= NOTICE_FOR) {
            logged.insert(key, now);
            crate::network_guard::log(&format!("split proxy: {text}"));
        }
    }

    /// The latest failure within the last minute, for the panel.
    pub fn recent_notice(&self) -> Option<String> {
        let mut notice = self.notice.lock().unwrap();
        match &*notice {
            Some((at, text)) if at.elapsed() < NOTICE_FOR => Some(text.clone()),
            _ => { *notice = None; None }
        }
    }

    /// Connections opened through a proxy so far.
    pub fn connections(&self) -> u64 { self.connections.load(Ordering::Relaxed) }
}

// MARK: - Proxy handshakes

fn read_exact(stream: &mut TcpStream, bytes: &mut [u8]) -> Result<(), String> {
    stream.read_exact(bytes).map_err(|e| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => "代理没有回应（超时）".to_owned(),
        io::ErrorKind::UnexpectedEof => "代理关闭了连接".to_owned(),
        _ => format!("与代理通信出错（{e}）"),
    })
}

fn write_all(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    stream.write_all(bytes).map_err(|e| format!("与代理通信出错（{e}）"))
}

/// SOCKS5 CONNECT by name (RFC 1928), without authentication.
pub fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), String> {
    if host.is_empty() || host.len() > 255 { return Err("域名太长".into()); }
    write_all(stream, &[5, 1, 0])?;
    let mut choice = [0u8; 2];
    read_exact(stream, &mut choice)?;
    if choice[0] != 5 { return Err("对方不是 SOCKS5 代理".into()); }
    if choice[1] != 0 { return Err("代理要求用户名密码（暂不支持）".into()); }
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    write_all(stream, &request)?;
    let mut head = [0u8; 4];
    read_exact(stream, &mut head)?;
    if head[0] != 5 { return Err("对方不是 SOCKS5 代理".into()); }
    if head[1] != 0 {
        return Err(match head[1] {
            2 => "代理的规则不允许这个连接",
            3 => "代理那边网络不可达",
            4 => "代理那边找不到这个网站",
            5 => "网站拒绝了代理的连接",
            6 => "代理那边连接超时",
            7 | 8 => "代理不支持这种请求",
            _ => "代理报告连接失败",
        }.into());
    }
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => { let mut n = [0u8; 1]; read_exact(stream, &mut n)?; n[0] as usize + 2 }
        _ => return Err("代理的答复格式不对".into()),
    };
    let mut skip = vec![0u8; rest];
    read_exact(stream, &mut skip)
}

/// HTTP CONNECT. Returns bytes the proxy sent after its header (already
/// the site's data).
pub fn http_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<Vec<u8>, String> {
    let authority = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    write_all(stream, format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n").as_bytes())?;
    let mut buffer = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    let end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") { break at + 4; }
        if buffer.len() > 16 * 1024 { return Err("代理的答复头太长".into()); }
        let n = stream.read(&mut chunk).map_err(|e| match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => "代理没有回应（超时）".to_owned(),
            _ => format!("与代理通信出错（{e}）"),
        })?;
        if n == 0 { return Err("代理关闭了连接".into()); }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buffer[..end]);
    let status = head.lines().next().unwrap_or("");
    let mut parts = status.split_whitespace();
    let code = match (parts.next(), parts.next().and_then(|c| c.parse::<u16>().ok())) {
        (Some(v), Some(code)) if v.starts_with("HTTP/") => code,
        _ => return Err("对方不是 HTTP 代理".into()),
    };
    match code {
        200..=299 => Ok(buffer[end..].to_vec()),
        407 => Err("代理要求用户名密码（暂不支持）".into()),
        403 => Err("代理拒绝了这个连接（403）".into()),
        _ => Err(format!("代理拒绝了这个连接（{code}）")),
    }
}

/// Connect to the proxy itself, through the ordinary system path.
fn connect_proxy(server: &Server) -> Result<TcpStream, String> {
    let addresses: Vec<SocketAddr> = (server.host.as_str(), server.port).to_socket_addrs()
        .map_err(|_| format!("解析不了代理地址 {}", server.host))?.collect();
    if addresses.iter().any(|a| matches!(a, SocketAddr::V4(v4) if is_fake(*v4.ip()))) {
        return Err("代理地址本身命中了代理规则，请把它从规则里去掉".into());
    }
    let mut last = format!("连不上代理 {}", server.label());
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => last = format!("连接代理 {} 超时", server.label()),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => last = format!("代理 {} 拒绝连接（没有在运行？）", server.label()),
            Err(_) => {}
        }
    }
    Err(last)
}

/// Open `name:port` through `server`. Bytes already read past the
/// proxy's answer come back with the stream.
pub fn open_through(server: &Server, name: &str, port: u16) -> Result<(TcpStream, Vec<u8>), String> {
    let mut stream = connect_proxy(server)?;
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let early = match server.kind {
        Kind::Socks5 => socks5_connect(&mut stream, name, port).map(|_| Vec::new()),
        Kind::Http => http_connect(&mut stream, name, port),
    }?;
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
    let _ = stream.set_nodelay(true);
    Ok((stream, early))
}

// MARK: - The listener

/// The address an accepted connection was originally made to.
pub type OriginalDestination = Arc<dyn Fn(&TcpStream) -> Option<SocketAddrV4> + Send + Sync>;

/// pf's record of a redirected connection (DIOCNATLOOK on /dev/pf; root).
#[cfg(target_os = "macos")]
pub fn pf_original_destination() -> io::Result<OriginalDestination> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    #[repr(C, align(4))]
    struct NatLook {
        saddr: [u8; 16], daddr: [u8; 16], rsaddr: [u8; 16], rdaddr: [u8; 16],
        sxport: [u8; 4], dxport: [u8; 4], rsxport: [u8; 4], rdxport: [u8; 4],
        af: u8, proto: u8, proto_variant: u8, direction: u8,
    }
    const _: () = assert!(std::mem::size_of::<NatLook>() == 84);
    // _IOWR('D', 23, struct pfioc_natlook)
    const DIOCNATLOOK: libc::c_ulong = 0xC000_0000 | (84 << 16) | ((b'D' as libc::c_ulong) << 8) | 23;
    const PF_OUT: u8 = 2;
    let raw = unsafe { libc::open(c"/dev/pf".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if raw < 0 { return Err(io::Error::last_os_error()); }
    let pf = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
    Ok(Arc::new(move |stream: &TcpStream| {
        let (SocketAddr::V4(peer), SocketAddr::V4(local)) = (stream.peer_addr().ok()?, stream.local_addr().ok()?) else { return None };
        let mut look = NatLook {
            saddr: [0; 16], daddr: [0; 16], rsaddr: [0; 16], rdaddr: [0; 16],
            sxport: [0; 4], dxport: [0; 4], rsxport: [0; 4], rdxport: [0; 4],
            af: libc::AF_INET as u8, proto: libc::IPPROTO_TCP as u8, proto_variant: 0, direction: PF_OUT,
        };
        look.saddr[..4].copy_from_slice(&peer.ip().octets());
        look.daddr[..4].copy_from_slice(&local.ip().octets());
        look.sxport[..2].copy_from_slice(&peer.port().to_be_bytes());
        look.dxport[..2].copy_from_slice(&local.port().to_be_bytes());
        if unsafe { libc::ioctl(pf.as_raw_fd(), DIOCNATLOOK, &mut look as *mut NatLook) } != 0 { return None; }
        let ip = Ipv4Addr::new(look.rdaddr[0], look.rdaddr[1], look.rdaddr[2], look.rdaddr[3]);
        Some(SocketAddrV4::new(ip, u16::from_be_bytes([look.rdxport[0], look.rdxport[1]])))
    }))
}

#[cfg(not(target_os = "macos"))]
pub fn pf_original_destination() -> io::Result<OriginalDestination> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "pf is macOS only"))
}

#[derive(Default)]
struct Open {
    next: u64,
    streams: HashMap<u64, (TcpStream, Option<TcpStream>)>,
}

pub struct Listener {
    port: u16,
    stop: Arc<AtomicBool>,
    open: Arc<Mutex<Open>>,
    thread: Option<JoinHandle<()>>,
}

fn reset(stream: &TcpStream) {
    // Linger 0: close sends RST, so the app fails at once.
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
    let _ = stream.shutdown(Shutdown::Both);
}

impl Listener {
    pub fn start(routing: Arc<Routing>, original: OriginalDestination) -> io::Result<Listener> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let open = Arc::new(Mutex::new(Open::default()));
        let active = Arc::new(AtomicUsize::new(0));
        let thread = std::thread::Builder::new().name("ac-proxy".into()).stack_size(STACK).spawn({
            let (stop, open) = (stop.clone(), open.clone());
            move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::Acquire) { break; }
                    let Ok(stream) = stream else { continue };
                    if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                        active.fetch_sub(1, Ordering::AcqRel);
                        routing.failed("网站", "同时经代理的连接太多");
                        reset(&stream);
                        continue;
                    }
                    let (routing, original, open, active) = (routing.clone(), original.clone(), open.clone(), active.clone());
                    let started = std::thread::Builder::new().name("ac-proxy-conn".into()).stack_size(STACK)
                        .spawn(move || {
                            serve(stream, &routing, &original, &open);
                            active.fetch_sub(1, Ordering::AcqRel);
                        });
                    if started.is_err() { /* the stream was moved and dropped: closed */ }
                }
            }
        })?;
        Ok(Listener { port, stop, open, thread: Some(thread) })
    }

    pub fn port(&self) -> u16 { self.port }

    /// Ends the listener and every connection it carries.
    pub fn stop(&mut self) {
        if self.stop.swap(true, Ordering::AcqRel) { return; }
        let _ = TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)), Duration::from_secs(1));
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        for (_, (client, upstream)) in self.open.lock().unwrap().streams.drain() {
            let _ = client.shutdown(Shutdown::Both);
            if let Some(upstream) = upstream { let _ = upstream.shutdown(Shutdown::Both); }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) { self.stop(); }
}

fn serve(client: TcpStream, routing: &Routing, original: &OriginalDestination, open: &Mutex<Open>) {
    let Some(destination) = original(&client) else {
        // Not a redirected connection (someone connected to the port).
        reset(&client);
        return;
    };
    let (name, server) = match routing.target(*destination.ip()) {
        Ok(target) => target,
        Err((name, reason)) => { routing.failed(&name, reason); reset(&client); return; }
    };
    let id = {
        let mut open = open.lock().unwrap();
        open.next += 1;
        let id = open.next;
        if let Ok(copy) = client.try_clone() { open.streams.insert(id, (copy, None)); }
        id
    };
    let forget = || { open.lock().unwrap().streams.remove(&id); };
    let (upstream, early) = match open_through(&server, &name, destination.port()) {
        Ok(opened) => opened,
        Err(reason) => { routing.failed(&name, &reason); reset(&client); forget(); return; }
    };
    routing.connections.fetch_add(1, Ordering::Relaxed);
    if let (Some(entry), Ok(copy)) = (open.lock().unwrap().streams.get_mut(&id), upstream.try_clone()) { entry.1 = Some(copy); }
    let _ = client.set_nodelay(true);
    let mut to_app = &client;
    if !early.is_empty() && to_app.write_all(&early).is_err() { reset(&client); forget(); return; }
    splice(&client, &upstream);
    forget();
}

/// Both directions until both ends are done; one end finishing closes
/// the other's sending side.
fn splice(client: &TcpStream, upstream: &TcpStream) {
    let (Ok(client_read), Ok(upstream_write)) = (client.try_clone(), upstream.try_clone()) else { return };
    let up = std::thread::Builder::new().name("ac-proxy-up".into()).stack_size(STACK).spawn(move || {
        let (mut from, mut to) = (&client_read, &upstream_write);
        let _ = io::copy(&mut from, &mut to);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let (mut from, mut to) = (upstream, client);
    let _ = io::copy(&mut from, &mut to);
    let _ = client.shutdown(Shutdown::Write);
    match up {
        Ok(thread) => { let _ = thread.join(); }
        Err(_) => { let _ = upstream.shutdown(Shutdown::Both); }
    }
}

#[cfg(test)]
mod tests;
