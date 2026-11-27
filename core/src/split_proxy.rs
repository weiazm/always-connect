//! Sites that go through a user-configured SOCKS5 or HTTP CONNECT proxy
//! (DESIGN.md §六十九). Same rule syntax and parser as the split list
//! (`SplitRules`); only the destination differs.
//!
//! - The App sends the proxies inside the split list: "proxy:<n> socks5|http
//!   <host> <port> [<user> <password>]" (percent-encoded) declares proxy n,
//!   "via:<n>:<rule>" sends a rule to it (names, site lists, and geoip as
//!   "ipcidr:" ranges matched against the DNS answer), "vianet:<n>:<cidr>"
//!   a network the user wrote (also routed, for connections by address).
//!   An older service ignores all three (they contain ':'), so those sites
//!   stay in the VPN there; never direct.
//! - Order: exit protection > proxy name rules > the direct list's names >
//!   proxy address rules > the direct list's addresses > the VPN.
//! - A name matched by a name rule is answered with an address of our own
//!   from 198.19.128.0/17 and never asked of any DNS server: the proxy
//!   resolves it. A name matched by its answer's address (geoip, networks)
//!   was resolved through the VPN's DNS like any VPN name, then answered
//!   with our address. The proxy is always given the NAME.
//! - Our range and the networks are routed to loopback; pf redirects their
//!   TCP (and, with a SOCKS5 proxy, UDP) to this service, which asks pf for
//!   the original address. TCP goes through CONNECT; UDP through SOCKS5 UDP
//!   ASSOCIATE (HTTP proxies cannot carry UDP: those datagrams are dropped
//!   and the app falls back to TCP).
//! - Fail closed: no mapping, a rule that changed, a missing proxy, a proxy
//!   that does not answer or refuses — the app's connection is reset.
//!   Nothing that matched a proxy rule is ever sent direct or into the VPN.
//! - The connection to the proxy itself follows the ordinary split. A proxy
//!   address that is itself proxied is refused (it would loop).

use crate::dns_forwarder::{cidr_range, SplitRules};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub mod hysteria;
pub(crate) mod owner;
mod probe;
mod protocol;
pub mod redirect;
mod relay;
pub use hysteria::HysteriaSpec;
pub use probe::{probe, site_from_rules, Level, Probe};
pub use redirect::RedirectSession;
pub use protocol::{http_connect, open_through, socks5_connect, udp_associate, udp_unwrap, udp_wrap};
pub use relay::{pf_original_destination, Listener, OriginalDestination, Proto};

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
/// A failure is shown on the panel this long and logged once per this.
const NOTICE_FOR: Duration = Duration::from_secs(60);
/// How long a proxy's last success or failure is reported (§69.8).
const HEALTH_FOR: Duration = Duration::from_secs(600);

pub fn is_fake(ip: Ipv4Addr) -> bool {
    u32::from(ip) & !(FAKE_SIZE - 1) == FAKE_BASE
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind { Socks5, Http }

/// Where a connection goes: the site's name (the proxy resolves it), or
/// an address in a network the user wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target { Name(String), Ip(Ipv4Addr) }

impl Target {
    pub fn label(&self) -> String {
        match self { Target::Name(n) => n.clone(), Target::Ip(ip) => ip.to_string() }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Server {
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    /// Username and password (SOCKS5 RFC 1929, HTTP Basic).
    pub auth: Option<(String, String)>,
}

/// Never print the password (logs, panics).
impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.label(), if self.auth.is_some() { " (with password)" } else { "" })
    }
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl Server {
    /// "socks5|http <host> <port> [<user> <password>]", percent-encoded
    /// as in the split list (the App's checks use the same line).
    pub fn parse(text: &str) -> Option<Server> {
        let fields: Vec<&str> = text.split_whitespace().collect();
        let kind = match *fields.first()? { "socks5" => Kind::Socks5, "http" => Kind::Http, _ => return None };
        let host = fields.get(1)?.trim_matches(|c| c == '[' || c == ']').to_owned();
        let port: u16 = fields.get(2)?.parse().ok().filter(|p| *p > 0)?;
        let valid = !host.is_empty() && host.len() <= 253
            && host.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b':'));
        let auth = match fields.len() {
            3 => None,
            5 => {
                let (user, password) = (percent_decode(fields[3])?, percent_decode(fields[4])?);
                let fits = |s: &str| !s.is_empty() && s.len() <= 255;
                if !fits(&user) || !fits(&password) { return None; }
                Some((user, password))
            }
            _ => return None,
        };
        valid.then_some(Server { kind, host, port, auth })
    }

    pub fn label(&self) -> String {
        let kind = match self.kind { Kind::Socks5 => "SOCKS5", Kind::Http => "HTTP" };
        if self.host.contains(':') { format!("{kind} [{}]:{}", self.host, self.port) } else { format!("{kind} {}:{}", self.host, self.port) }
    }
}

fn clean(name: &str) -> String {
    name.trim_matches('.').to_ascii_lowercase()
}

fn proxy_index(text: &str) -> Option<usize> {
    text.parse::<usize>().ok().filter(|n| *n < MAX_PROXIES)
}

fn parse_health_key(text: &str) -> Option<u128> {
    if text.len() != 36 { return None; }
    u128::from_str_radix(&text.replace('-', ""), 16).ok()
}

/// The proxies and their rules, in the App's order: the first proxy whose
/// rules match takes the site.
#[derive(Default, Debug)]
pub struct Table {
    /// None: declared badly, not at all, or managed externally (Hysteria2).
    /// Its sites are refused unless a managed local backend is registered.
    servers: Vec<Option<Server>>,
    /// Managed Hysteria2 proxies, keyed by the App's proxy index (§七十).
    hysteria: BTreeMap<usize, HysteriaSpec>,
    health_keys: BTreeMap<usize, u128>,
    groups: Vec<(usize, SplitRules)>,
    /// Networks the user wrote, routed here for connections by address.
    networks: Vec<(usize, String, (u32, u32))>,
}

impl Table {
    pub fn parse<S: AsRef<str>>(list: &[S]) -> Table {
        let mut servers: BTreeMap<usize, Option<Server>> = BTreeMap::new();
        let mut hysteria: BTreeMap<usize, HysteriaSpec> = BTreeMap::new();
        let mut rules: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        let mut networks = Vec::new();
        let mut health_keys = BTreeMap::new();
        for raw in list {
            let line = raw.as_ref().trim();
            if let Some(rest) = line.strip_prefix("proxy:") {
                let (index, server) = rest.split_once(' ').unwrap_or((rest, ""));
                if let Some(n) = proxy_index(index) {
                    if let Some(hy) = HysteriaSpec::parse_rule_line(server) {
                        servers.insert(n, None);
                        hysteria.insert(n, hy);
                    } else {
                        hysteria.remove(&n);
                        servers.insert(n, Server::parse(server));
                    }
                }
            } else if let Some(rest) = line.strip_prefix("proxyhealth:") {
                if let Some((index, key)) = rest.split_once(' ') {
                    if let (Some(n), Some(key)) = (proxy_index(index), parse_health_key(key)) {
                        health_keys.insert(n, key);
                    }
                }
            } else if let Some(rest) = line.strip_prefix("vianet:") {
                if let Some((n, cidr)) = rest.split_once(':').and_then(|(i, c)| Some((proxy_index(i)?, c))) {
                    if crate::direct_routes::is_network(cidr) && cidr_range(cidr).is_some() {
                        networks.push((n, cidr.to_owned()));
                        rules.entry(n).or_default().push(format!("ipcidr:{cidr}"));
                    }
                }
            } else if let Some(rest) = line.strip_prefix("via:") {
                if let Some((n, rule)) = rest.split_once(':').and_then(|(i, r)| Some((proxy_index(i)?, r))) {
                    rules.entry(n).or_default().push(rule.to_owned());
                }
            }
        }
        let size = servers.keys().chain(rules.keys()).max().map_or(0, |n| n + 1);
        let groups: Vec<_> = rules.into_iter().map(|(n, list)| (n, SplitRules::new(&list))).collect();
        let mut routed = Vec::new();
        for (index, matcher) in &groups {
            let written = networks.iter().filter(|(n, _)| n == index).map(|(_, cidr)| cidr.as_str());
            routed.extend(matcher.effective_networks(written).into_iter()
                .filter_map(|cidr| {
                    let range = cidr_range(&cidr)?;
                    Some((*index, cidr, range))
                }));
        }
        let mut table = Table { servers: vec![None; size], hysteria, health_keys, groups, networks: routed };
        for (n, server) in servers { table.servers[n] = server; }
        table
    }

    pub fn hysteria_specs(&self) -> BTreeMap<usize, HysteriaSpec> {
        self.hysteria.clone()
    }

    pub fn is_empty(&self) -> bool { self.groups.is_empty() }

    /// Which proxy takes `name` by its name rules (trimmed, lowercased).
    fn named_route(&self, name: &str, addresses: &[Ipv4Addr]) -> Option<(usize, bool)> {
        self.groups.iter().find(|(_, rules)| rules.matches_name(name)
            && !addresses.iter().any(|ip| rules.excludes_ip(*ip)))
            .map(|(n, rules)| (*n, rules.has_ip_exceptions()))
    }

    #[cfg(test)]
    fn route_name(&self, name: &str) -> Option<usize> {
        self.named_route(name, &[]).map(|(n, _)| n)
    }

    /// Which proxy takes a name whose answer holds these addresses.
    fn route_addresses(&self, name: &str, addresses: &[Ipv4Addr]) -> Option<usize> {
        self.groups.iter().find(|(_, rules)| rules.has_ranges() && !rules.excludes_name(name)
            && !addresses.iter().any(|ip| rules.excludes_ip(*ip))
            && addresses.iter().any(|ip| rules.contains(*ip))).map(|(n, _)| *n)
    }

    fn route_target(&self, name: &str, addresses: &[Ipv4Addr], include_address_rules: bool) -> Option<usize> {
        self.named_route(name, addresses)
            .filter(|(_, needs_addresses)| !needs_addresses || !addresses.is_empty())
            .map(|(n, _)| n)
            .or_else(|| include_address_rules.then(|| self.route_addresses(name, addresses)).flatten())
    }

    /// Which proxy takes a connection made straight to `ip` (only the
    /// networks the user wrote are routed here).
    fn route_ip(&self, ip: Ipv4Addr) -> Option<usize> {
        let v = u32::from(ip);
        self.networks.iter().find(|(_, _, (lo, hi))| *lo <= v && v <= *hi).map(|(n, _, _)| *n)
    }

    pub(crate) fn server(&self, n: usize) -> Option<&Server> {
        self.servers.get(n).and_then(Option::as_ref)
    }

    /// The networks to route to this service, in order, without repeats.
    pub fn networks(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for (_, cidr, _) in &self.networks { if !out.contains(cidr) { out.push(cidr.clone()); } }
        out
    }

    /// The proxies' own servers written as IPv4 addresses (SOCKS5, HTTP,
    /// Hysteria2): never routed back here, even inside a written network.
    pub fn server_addresses(&self) -> Vec<Ipv4Addr> {
        let mut out: Vec<Ipv4Addr> = self.servers.iter().flatten().map(|s| s.host.as_str())
            .chain(self.hysteria.values().map(|h| h.host.as_str()))
            .filter_map(|host| host.parse().ok())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Ports of proxies running on this Mac: their own connections come
    /// back here and must not be sent to them again.
    fn local_ports(&self) -> Vec<u16> {
        let mut out: Vec<u16> = self.servers.iter().flatten()
            .filter(|s| s.host == "localhost" || s.host == "::1" || s.host.starts_with("127."))
            .map(|s| s.port).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// UDP is redirected only when some proxy can carry it (SOCKS5 or Hysteria2).
    pub fn carries_udp(&self) -> bool {
        self.servers.iter().flatten().any(|s| s.kind == Kind::Socks5) || !self.hysteria.is_empty()
    }
}

struct Entry { name: String, addresses: Vec<Ipv4Addr>, used: Instant }

#[derive(Default)]
struct Pool {
    by_name: HashMap<String, u32>,
    by_offset: HashMap<u32, Entry>,
    next: u32,
}

impl Pool {
    /// `addresses`: the real answer when the name was matched by address
    /// (empty for a name rule).
    fn assign(&mut self, name: &str, addresses: &[Ipv4Addr], now: Instant) -> Ipv4Addr {
        if let Some(&offset) = self.by_name.get(name) {
            if let Some(entry) = self.by_offset.get_mut(&offset) {
                entry.used = now;
                if !addresses.is_empty() { entry.addresses = addresses.to_vec(); }
            }
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
        self.by_offset.insert(offset, Entry { name: name.to_owned(), addresses: addresses.to_vec(), used: now });
        Ipv4Addr::from(FAKE_BASE + offset)
    }

    fn entry(&mut self, ip: Ipv4Addr, now: Instant) -> Option<(String, Vec<Ipv4Addr>)> {
        if !is_fake(ip) { return None; }
        let entry = self.by_offset.get_mut(&(u32::from(ip) - FAKE_BASE))?;
        entry.used = now;
        Some((entry.name.clone(), entry.addresses.clone()))
    }

    fn knows(&self, name: &str) -> bool { self.by_name.contains_key(name) }
}

/// The real addresses of a name by the ordinary split (proxy rules
/// skipped), for a local proxy's own connections.
pub type Resolver = Arc<dyn Fn(&str) -> Vec<Ipv4Addr> + Send + Sync>;

/// How long the processes behind local proxies' ports are remembered.
const LOCAL_PIDS_FOR: Duration = Duration::from_secs(30);

#[derive(Clone)]
enum ManagedProxy {
    Ready { server: Server, server_ip: Ipv4Addr, ports: String },
    Unavailable(String),
}

/// Where the relay sends one redirected connection (§69, §71).
#[derive(Clone, Debug)]
pub(crate) enum RouteVia {
    Proxy { server: Server, index: usize, health_key: Option<(u128, u64)> },
    /// Proxy-only mode: a protected site not matched by any proxy (§71 D2).
    Local,
}

pub(crate) struct ResolvedTarget {
    pub target: Target,
    pub via: RouteVia,
    /// Real IPv4 addresses known from DNS (address rules or local protected).
    pub resolved_ips: Vec<Ipv4Addr>,
}

/// Shared by the DNS forwarder (answers) and the listener (connections).
#[derive(Default)]
pub struct Routing {
    table: RwLock<Arc<Table>>,
    /// Runtime backends for managed Hysteria2 proxies (local SOCKS5 + remote IP).
    managed: Mutex<HashMap<usize, ManagedProxy>>,
    resolver: RwLock<Option<Resolver>>,
    /// Exit protection gate attached to this relay (§71).
    egress: RwLock<Option<crate::egress_control::RelayGate>>,
    /// True in proxy-only mode when non-proxied protected sites also pass
    /// through this relay (LocalPolicy::Probe / Block, §71 D2).
    local_egress: std::sync::atomic::AtomicBool,
    /// Processes listening on local proxies' ports, and when looked up.
    local_pids: Mutex<Option<(Instant, Vec<u16>, Vec<i32>)>>,
    /// Harnesses whose stand-in proxies share the test's own process.
    same_process_proxies: std::sync::atomic::AtomicBool,
    pool: Mutex<Pool>,
    notice: Mutex<Option<(Instant, String)>>,
    logged: Mutex<HashMap<String, Instant>>,
    connections: AtomicU64,
    /// Per proxy (the App's index): the last connection that opened
    /// through it, and the last that did not, with why.
    health: Mutex<HashMap<usize, Health>>,
    health_generation: AtomicU64,
    /// The proxy servers' addresses this relay connected to, per proxy,
    /// and when: the connections page marks those connections (§69.12).
    upstreams: Mutex<HashMap<std::net::SocketAddr, (usize, Instant)>>,
    /// Bytes forwarded through proxies so far, by the road the proxy is
    /// reached on (§69.17): [to the apps, to the proxies] for each.
    traffic: [[AtomicU64; 2]; 3],
}

/// The road to a proxy server: the panel takes proxied bytes out of the
/// speed of that road, so nothing counts twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Leg { Direct = 0, Vpn = 1, Local = 2 }

impl Leg {
    pub(crate) fn of(peer: std::net::IpAddr) -> Leg {
        if peer.is_loopback() { return Leg::Local; }
        match crate::connections::route_interface(&peer.to_string()) {
            Some(name) if name == "lo0" => Leg::Local,
            Some(name) if name.starts_with("utun") || name.starts_with("ipsec") || name.starts_with("ppp") => Leg::Vpn,
            _ => Leg::Direct,
        }
    }
}

#[derive(Default, Clone)]
struct Health { key: Option<u128>, ok: Option<HealthTime>, failed: Option<(HealthTime, String)> }

#[derive(Clone, Copy)]
struct HealthTime { when: Instant, tick: f64 }

pub(crate) type Refusal = (String, String);

impl Routing {
    pub fn new(table: Table) -> Arc<Routing> {
        let routing = Routing::default();
        *routing.table.write().unwrap() = Arc::new(table);
        Arc::new(routing)
    }

    pub fn set_table(&self, table: Table) {
        let active: std::collections::HashSet<usize> = table.hysteria.keys().copied().collect();
        self.managed.lock().unwrap().retain(|k, _| active.contains(k));
        *self.table.write().unwrap() = Arc::new(table);
        if let Some(gate) = self.egress.read().unwrap().as_ref() {
            gate.invalidate_all();
        }
    }

    /// Registers a running managed Hysteria2 backend for proxy `n`.
    pub fn set_managed_ready(&self, n: usize, server: Server, server_ip: Ipv4Addr, ports: String) {
        self.managed.lock().unwrap().insert(n, ManagedProxy::Ready { server, server_ip, ports });
        if let Some(gate) = self.egress.read().unwrap().as_ref() {
            gate.invalidate_path(crate::egress_control::EgressPath::Proxy(n));
        }
    }

    /// Marks managed Hysteria2 proxy `n` unavailable with a plain-Chinese reason (fail closed).
    pub fn set_managed_unavailable(&self, n: usize, reason: String) {
        self.managed.lock().unwrap().insert(n, ManagedProxy::Unavailable(reason));
        if let Some(gate) = self.egress.read().unwrap().as_ref() {
            gate.invalidate_path(crate::egress_control::EgressPath::Proxy(n));
        }
    }

    /// Attach or detach the exit-protection gate for this relay (§71).
    pub fn set_egress(self: &Arc<Self>, gate: Option<crate::egress_control::RelayGate>, local_egress: bool) {
        if let Some(prev) = self.egress.read().unwrap().as_ref() {
            prev.set_relay_opener(None);
        }
        self.local_egress.store(local_egress, Ordering::Release);
        if let Some(ref g) = gate {
            let weak = Arc::downgrade(self);
            let opener: crate::egress_control::RelayOpener = Arc::new(move |path, host, peer_ip| {
                let Some(routing) = weak.upgrade() else {
                    return Err("代理转发已停止".into());
                };
                routing.open_for_probe(path, host, peer_ip)
            });
            g.set_relay_opener(Some(opener));
        }
        *self.egress.write().unwrap() = gate;
    }

    pub fn local_egress_active(&self) -> bool {
        self.local_egress.load(Ordering::Acquire)
    }

    /// Opens an outbound TCP stream to `host:443` along `path` for one exit check (§71).
    fn open_for_probe(
        &self,
        path: &crate::egress_control::EgressPath,
        host: &str,
        peer_ip: Option<std::net::IpAddr>,
    ) -> Result<(std::net::TcpStream, Vec<u8>, Option<std::net::IpAddr>), String> {
        use crate::egress_control::EgressPath;
        match path {
            EgressPath::Proxy(n) => {
                let server = self.resolve_server(*n)?;
                let target = if !host.is_empty() {
                    Target::Name(host.to_owned())
                } else if let Some(std::net::IpAddr::V4(ip)) = peer_ip {
                    Target::Ip(ip)
                } else {
                    return Err("看不到网站名".into());
                };
                let (stream, early) = open_through(&server, &target, 443)?;
                Ok((stream, early, peer_ip))
            }
            EgressPath::Local => {
                let ip = match peer_ip {
                    Some(std::net::IpAddr::V4(ip)) => ip,
                    _ => self.passthrough(&Target::Name(host.to_owned()))
                        .ok_or_else(|| "本地网络解析不到这个网站的地址".to_owned())?,
                };
                let stream = std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from((ip, 443)),
                    Duration::from_secs(4),
                ).map_err(|e| format!("经本地网络连接失败（{e}）"))?;
                protocol::no_sigpipe(&stream);
                Ok((stream, Vec::new(), Some(std::net::IpAddr::V4(ip))))
            }
            EgressPath::Cisco => Err("非代理通道".into()),
        }
    }

    fn resolve_server(&self, n: usize) -> Result<Server, String> {
        if let Some(entry) = self.managed.lock().unwrap().get(&n).cloned() {
            return match entry {
                ManagedProxy::Ready { server, .. } => Ok(server),
                ManagedProxy::Unavailable(reason) => Err(reason),
            };
        }
        self.table().server(n).cloned()
            .ok_or_else(|| "规则指向的代理不存在或地址无效".to_owned())
    }

    /// Assigns a local fake address for a protected name routed locally in
    /// proxy-only mode (§71 D2).
    pub fn answer_local_protected(&self, name: &str, addresses: &[Ipv4Addr]) -> Option<Ipv4Addr> {
        if !self.local_egress_active() { return None; }
        let name = clean(name);
        if name.is_empty() { return None; }
        Some(self.pool.lock().unwrap().assign(&name, addresses, Instant::now()))
    }

    pub(crate) fn is_egress_protected(&self, target: &Target, resolved_ips: &[Ipv4Addr]) -> bool {
        let Some(gate) = self.egress.read().unwrap().clone() else { return false };
        let host = match target { Target::Name(n) => n.as_str(), Target::Ip(_) => "" };
        let ips: Vec<std::net::IpAddr> = match target {
            Target::Ip(ip) => vec![std::net::IpAddr::V4(*ip)],
            Target::Name(_) => resolved_ips.iter().copied().map(std::net::IpAddr::V4).collect(),
        };
        gate.protects_target(host, &ips).is_some()
    }

    /// Checks exit protection for `resolved` before forwarding any bytes (§71).
    /// Returns `Ok(Some(local_ip))` for an allowed `RouteVia::Local` connection,
    /// `Ok(None)` for an allowed `RouteVia::Proxy` connection, or `Err(reason)`
    /// when refused (`None` when exit protection already recorded the block).
    pub(crate) fn check_egress(&self, resolved: &ResolvedTarget) -> Result<Option<Ipv4Addr>, Option<String>> {
        use crate::egress_control::{EgressPath, LocalPolicy, RelayVerdict};
        let gate = self.egress.read().unwrap().clone();
        let host = match &resolved.target { Target::Name(n) => n.as_str(), Target::Ip(_) => "" };
        let ips: Vec<std::net::IpAddr> = match &resolved.target {
            Target::Ip(ip) => vec![std::net::IpAddr::V4(*ip)],
            Target::Name(_) => resolved.resolved_ips.iter().copied().map(std::net::IpAddr::V4).collect(),
        };
        match &resolved.via {
            RouteVia::Proxy { index, .. } => {
                if let Some(gate) = gate {
                    let peer_ip = match &resolved.target {
                        Target::Name(_) => None,
                        Target::Ip(ip) => Some(std::net::IpAddr::V4(*ip)),
                    };
                    if let Some(verdict) = gate.check_connection(host, &ips, EgressPath::Proxy(*index), peer_ip) {
                        if verdict == RelayVerdict::Block {
                            return Err(None);
                        }
                    }
                }
                Ok(None)
            }
            RouteVia::Local => {
                let Some(gate) = gate else {
                    return Err(Some("出口保护已关闭，请重新打开网页".into()));
                };
                if gate.local_policy() == LocalPolicy::Block {
                    let _ = gate.check_connection(host, &ips, EgressPath::Local, None);
                    return Err(None);
                }
                let local_ip = resolved.resolved_ips.first().copied()
                    .or_else(|| self.passthrough(&resolved.target))
                    .ok_or_else(|| Some("本地网络解析不到这个网站的地址".into()))?;
                let check_ips = if ips.is_empty() { vec![std::net::IpAddr::V4(local_ip)] } else { ips };
                match gate.check_connection(host, &check_ips, EgressPath::Local, Some(std::net::IpAddr::V4(local_ip))) {
                    Some(RelayVerdict::Block) => Err(None),
                    Some(RelayVerdict::Allow | RelayVerdict::Unverified) | None => Ok(Some(local_ip)),
                }
            }
        }
    }

    /// The road for counting proxied bytes (§69.17, §七十): for a managed
    /// Hysteria2 proxy (whose local SOCKS5 sits on 127.0.0.1), attribute traffic
    /// to the road to the actual Hysteria2 server IP instead of `Leg::Local`.
    pub(crate) fn leg_for(&self, n: usize, peer: std::net::IpAddr) -> Leg {
        if let Some(ManagedProxy::Ready { server_ip, .. }) = self.managed.lock().unwrap().get(&n) {
            return Leg::of(std::net::IpAddr::V4(*server_ip));
        }
        Leg::of(peer)
    }

    pub fn table(&self) -> Arc<Table> { self.table.read().unwrap().clone() }

    pub fn set_resolver(&self, resolver: Option<Resolver>) { *self.resolver.write().unwrap() = resolver; }

    /// Harnesses only: stand-in proxies in the same process as the apps
    /// being tested would look like a local proxy's own connections.
    pub fn treat_same_process_as_apps(&self) { self.same_process_proxies.store(true, Ordering::Relaxed); }

    /// Whether the app socket on `port` belongs to a proxy running on this
    /// Mac (its own outbound connection, after resolving the proxied name
    /// through the same resolver). Looked up only when such a proxy exists.
    pub(crate) fn from_local_proxy(&self, proto: Proto, port: u16) -> bool {
        if self.same_process_proxies.load(Ordering::Relaxed) { return false; }
        let ports = self.table().local_ports();
        if ports.is_empty() { return false; }
        let lookup = |ports: &[u16]| -> Vec<i32> { ports.iter().flat_map(|p| owner::listeners(*p)).collect() };
        let alive = |pid: &i32| unsafe { libc::kill(*pid, 0) } == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        let mut cached = self.local_pids.lock().unwrap();
        // Looked up again when the ports changed, every LOCAL_PIDS_FOR, when
        // a proxy process ended (restarted) or, if none was found, after 5 s:
        // never a scan of every process per connection.
        let stale = match cached.as_ref() {
            None => true,
            Some((at, known, pids)) => *known != ports || at.elapsed() >= LOCAL_PIDS_FOR || !pids.iter().all(alive)
                || (pids.is_empty() && at.elapsed() >= Duration::from_secs(5)),
        };
        if stale { *cached = Some((Instant::now(), ports.clone(), lookup(&ports))); }
        let pids = cached.as_ref().map(|c| c.2.clone()).unwrap_or_default();
        drop(cached);
        pids.iter().any(|pid| owner::owns(*pid, proto, port))
    }

    /// Where a local proxy's own connection to `target` really goes: the
    /// name's address by the ordinary split. A written network is never
    /// passed through (its route leads back here); None refuses.
    pub(crate) fn passthrough(&self, target: &Target) -> Option<Ipv4Addr> {
        let Target::Name(name) = target else { return None };
        let resolver = self.resolver.read().unwrap().clone()?;
        let table = self.table();
        resolver(name).into_iter().find(|ip| !is_fake(*ip) && table.route_ip(*ip).is_none())
    }

    pub fn is_empty(&self) -> bool { self.table.read().unwrap().is_empty() }

    /// Before any DNS server is asked: our address for a name a proxy's
    /// name rules take, or None (then the ordinary split decides).
    pub fn answer(&self, name: &str) -> Option<Ipv4Addr> {
        let name = clean(name);
        if name.is_empty() { return None; }
        let (_, requires_dns) = self.table.read().unwrap().named_route(&name, &[])?;
        if requires_dns { return None; }
        Some(self.pool.lock().unwrap().assign(&name, &[], Instant::now()))
    }

    /// After the VPN's DNS answered: our address when a proxy's address
    /// rules (geoip, networks) take one of `addresses`.
    pub fn answer_by_address(&self, name: &str, addresses: &[Ipv4Addr]) -> Option<Ipv4Addr> {
        self.answer_resolved(name, addresses, true)
    }

    pub(crate) fn name_needs_addresses(&self, name: &str) -> bool {
        self.table.read().unwrap().named_route(name, &[]).is_some_and(|(_, needs)| needs)
    }

    pub(crate) fn answer_resolved(&self, name: &str, addresses: &[Ipv4Addr], include_address_rules: bool) -> Option<Ipv4Addr> {
        let name = clean(name);
        if name.is_empty() || addresses.is_empty() { return None; }
        self.table.read().unwrap().route_target(&name, addresses, include_address_rules)?;
        Some(self.pool.lock().unwrap().assign(&name, addresses, Instant::now()))
    }

    /// The name already goes through a proxy: its other record types
    /// (HTTPS address hints above all) must not point around it.
    pub fn knows(&self, name: &str) -> bool { self.pool.lock().unwrap().knows(&clean(name)) }

    /// Which proxy a connection to `ip` goes through now, for the
    /// connections page (§69.12): the same rules as `target`, without
    /// refreshing the answer's lifetime.
    pub fn proxy_for(&self, ip: Ipv4Addr) -> Option<usize> {
        let table = self.table();
        if is_fake(ip) {
            let (name, addresses) = {
                let pool = self.pool.lock().unwrap();
                let entry = pool.by_offset.get(&(u32::from(ip) - FAKE_BASE))?;
                (entry.name.clone(), entry.addresses.clone())
            };
            return table.route_target(&name, &addresses, true);
        }
        table.route_ip(ip)
    }

    /// This relay reached proxy `n` at `peer`. A few entries, each kept
    /// for the health window.
    pub(crate) fn connected_to(&self, n: usize, peer: std::net::SocketAddr) {
        let mut upstreams = self.upstreams.lock().unwrap();
        upstreams.retain(|_, (_, at)| at.elapsed() < HEALTH_FOR);
        if upstreams.len() < 64 || upstreams.contains_key(&peer) { upstreams.insert(peer, (n, Instant::now())); }
    }

    /// The proxy whose server sits at `ip:port`, when this relay talks to it
    /// (including a managed Hysteria2 child's UDP socket to its remote server).
    pub fn upstream_proxy(&self, ip: Ipv4Addr, port: u16) -> Option<usize> {
        {
            let managed = self.managed.lock().unwrap();
            for (&n, entry) in managed.iter() {
                if let ManagedProxy::Ready { server_ip, ports, .. } = entry {
                    if *server_ip == ip && hysteria::port_in_spec(ports, port) {
                        return Some(n);
                    }
                }
            }
        }
        let upstreams = self.upstreams.lock().unwrap();
        upstreams.get(&std::net::SocketAddr::from((ip, port))).filter(|(_, at)| at.elapsed() < HEALTH_FOR).map(|(n, _)| *n)
    }

    /// The name behind one of our addresses (the connections panel).
    pub fn name_for(&self, ip: Ipv4Addr) -> Option<String> {
        self.pool.lock().unwrap().entry(ip, Instant::now()).map(|(name, _)| name)
    }

    /// The target and route (proxy or local-protected) for a connection to `ip`,
    /// decided by the rules now: a rule changed since the answer goes to its new
    /// proxy, or is refused when no rule takes it any more.
    pub(crate) fn target(&self, ip: Ipv4Addr) -> Result<ResolvedTarget, Refusal> {
        let table = self.table();
        if is_fake(ip) {
            let (name, addresses) = self.pool.lock().unwrap().entry(ip, Instant::now())
                .ok_or_else(|| (ip.to_string(), "这个地址的记录已过期，请重新打开网页".to_owned()))?;
            if let Some(n) = table.route_target(&name, &addresses, true) {
                let server = self.resolve_server(n).map_err(|reason| (name.clone(), reason))?;
                return Ok(ResolvedTarget {
                    target: Target::Name(name),
                    via: RouteVia::Proxy { server, index: n, health_key: self.health_tag(&table, n) },
                    resolved_ips: addresses,
                });
            }
            if self.local_egress_active() {
                let target = Target::Name(name.clone());
                if self.is_egress_protected(&target, &addresses) {
                    return Ok(ResolvedTarget {
                        target,
                        via: RouteVia::Local,
                        resolved_ips: addresses,
                    });
                }
            }
            return Err((name, "代理规则已改，这条连接不再走代理，请重新打开网页".to_owned()));
        }
        let n = table.route_ip(ip).ok_or_else(|| (ip.to_string(), "这个地址已不在代理规则里".to_owned()))?;
        let server = self.resolve_server(n).map_err(|reason| (ip.to_string(), reason))?;
        Ok(ResolvedTarget {
            target: Target::Ip(ip),
            via: RouteVia::Proxy { server, index: n, health_key: self.health_tag(&table, n) },
            resolved_ips: vec![ip],
        })
    }

    pub(crate) fn failed(&self, site: &str, reason: &str) {
        let now = Instant::now();
        let text = format!("经代理打开 {site} 失败：{reason}");
        *self.notice.lock().unwrap() = Some((now, text.clone()));
        let mut logged = self.logged.lock().unwrap();
        if logged.len() > 256 { logged.retain(|_, at| now.duration_since(*at) < NOTICE_FOR); }
        let key = format!("{site}\u{0}{reason}");
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

    /// A connection through proxy `n` opened (None) or failed (Some(why)).
    pub(crate) fn record(&self, n: usize, failure: Option<&str>) {
        self.record_for(n, self.health_tag(&self.table(), n), failure);
    }

    pub fn reset_health(&self) {
        let mut health = self.health.lock().unwrap();
        self.health_generation.fetch_add(1, Ordering::AcqRel);
        health.clear();
    }

    fn health_tag(&self, table: &Table, n: usize) -> Option<(u128, u64)> {
        table.health_keys.get(&n).map(|key| (*key, self.health_generation.load(Ordering::Acquire)))
    }

    fn record_for(&self, n: usize, tag: Option<(u128, u64)>, failure: Option<&str>) {
        let table = self.table.read().unwrap();
        let mut health = self.health.lock().unwrap();
        if self.health_tag(&table, n) != tag { return; }
        let key = tag.map(|(key, _)| key);
        let now = HealthTime { when: Instant::now(), tick: crate::proxy_health::ac_proxy_health_now() };
        let entry = health.entry(n).or_default();
        if entry.key != key { *entry = Health { key, ..Health::default() }; }
        match failure {
            None => entry.ok = Some(now),
            Some(reason) => entry.failed = Some((now, reason.to_owned())),
        }
    }

    /// Each proxy's recent results, for the panel: seconds since the last
    /// success and the last failure (within the last ten minutes).
    pub fn health_json(&self) -> serde_json::Value {
        let table = self.table.read().unwrap();
        let mut health = self.health.lock().unwrap();
        health.retain(|n, h| {
            if h.key != table.health_keys.get(n).copied() { return false; }
            if h.ok.is_some_and(|at| at.when.elapsed() >= HEALTH_FOR) { h.ok = None; }
            if h.failed.as_ref().is_some_and(|(at, _)| at.when.elapsed() >= HEALTH_FOR) { h.failed = None; }
            h.ok.is_some() || h.failed.is_some()
        });
        let mut rows: Vec<_> = health.iter().map(|(n, h)| serde_json::json!({
            "proxy": n,
            "key": h.key.map(|key| format!("{key:032x}")),
            "okAt": h.ok.map(|at| at.tick),
            "failedAt": h.failed.as_ref().map(|(at, _)| at.tick),
            "okAgo": h.ok.map(|at| at.when.elapsed().as_secs()),
            "failedAgo": h.failed.as_ref().map(|(at, _)| at.when.elapsed().as_secs()),
            "reason": h.failed.as_ref().map(|(_, why)| why.clone()),
        })).collect();
        rows.sort_by_key(|row| row["proxy"].as_u64());
        serde_json::Value::Array(rows)
    }

    /// Connections and UDP flows opened through a proxy so far.
    pub fn connections(&self) -> u64 { self.connections.load(Ordering::Relaxed) }

    /// `n` bytes forwarded on `leg`, toward the app or toward the proxy.
    pub(crate) fn count(&self, leg: Leg, to_app: bool, n: usize) {
        self.traffic[leg as usize][usize::from(!to_app)].fetch_add(n as u64, Ordering::Relaxed);
    }

    /// The running totals for the panel's 代理 speed: per road, [in, out].
    pub fn traffic_json(&self) -> serde_json::Value {
        let leg = |l: Leg| {
            let c = &self.traffic[l as usize];
            serde_json::json!([c[0].load(Ordering::Relaxed), c[1].load(Ordering::Relaxed)])
        };
        serde_json::json!({ "direct": leg(Leg::Direct), "vpn": leg(Leg::Vpn), "local": leg(Leg::Local) })
    }

    pub(crate) fn opened(&self) { self.connections.fetch_add(1, Ordering::Relaxed); }
}

#[cfg(test)]
mod tests;
