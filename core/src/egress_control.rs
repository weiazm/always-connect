//! Exit protection controller (DESIGN.md §66.3–66.7, §66.25): the
//! background service's side of the gate. It owns the user's rules (sites
//! to protect and the countries they may leave from), answers the gate's
//! checks by probing the connection's own destination through the tunnel,
//! and keeps the status and the last block records for the App.
//!
//! The HTTPS request itself is made by a thin platform hook (Network.framework
//! on macOS: TLS, the ALPN marker, the tunnel interface); everything else —
//! building the request, parsing the answer, the decision, the records — is
//! here and tested on Linux.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::egress_gate::{evidence_clock_ms, ProtectedSites, SiteGroup};

mod activity;
use activity::{Denied, SiteStatus};
pub use activity::PathStatus;
mod bridge;
pub use bridge::RelayOpener;
mod refresh;
mod steer;
pub use refresh::{DEFAULT_HALF_LIFE_MIN, DEFAULT_PREFETCH, MAX_HALF_LIFE_MIN, MAX_PREFETCH};
use refresh::{Bell, Cache};
use steer::Ledger;

const MAX_GROUPS: usize = 16;
const MAX_SITES: usize = 256;
const MAX_MATCHES: usize = 20_000;
/// Checks running at once; more are refused until one finishes.
const MAX_CHECKS: usize = 32;
/// Wrong-exit servers remembered per rule (status, approval, recheck).
const MAX_FAILED_TARGETS: usize = 8;
const PROBE_TIMEOUT_MS: u64 = 2_400;
const RELAY_WAIT_TIMEOUT: Duration = Duration::from_millis(bridge::PROXY_PROBE_TIMEOUT_MS + 1_500);
pub const MAX_RECORDS: usize = 10;

/// Which road a connection or check took (DESIGN.md §71).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EgressPath {
    #[default]
    Cisco,
    Proxy(usize),
    Local,
}

impl EgressPath {
    pub fn wire(&self) -> String {
        match self {
            EgressPath::Cisco => "cisco".into(),
            EgressPath::Proxy(n) => format!("proxy:{n}"),
            EgressPath::Local => "local".into(),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        if s == "cisco" {
            Some(EgressPath::Cisco)
        } else if s == "local" {
            Some(EgressPath::Local)
        } else if let Some(rest) = s.strip_prefix("proxy:") {
            rest.parse::<usize>().ok().map(EgressPath::Proxy)
        } else {
            None
        }
    }

    pub fn is_cisco(&self) -> bool {
        matches!(self, EgressPath::Cisco)
    }
}

/// What to do with a protected site when Cisco is off and no proxy matches
/// (DESIGN.md §71 D2).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LocalPolicy {
    /// Forward directly via local network after checking its exit country.
    #[default]
    Probe,
    /// Refuse immediately when neither Cisco nor a proxy carries the site.
    Block,
    /// Do not intercept non-proxied protected sites when Cisco is off.
    Bypass,
}

/// Decision returned to the in-process proxy/local relay before forwarding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayVerdict {
    Allow,
    Block,
    Unverified,
}

// ------------------------------------------------------------------ config

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct EgressConfig {
    pub enabled: bool,
    pub groups: Vec<Group>,
    /// How many of the busiest servers are re-probed in the background
    /// (§66.31); None = the default, 0 = off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefetch: Option<u32>,
    /// Steer protected names to a verified entry (§66.28); None = on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steer: Option<bool>,
    /// Minutes after which a server's busyness halves (§66.31); None = the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub half_life: Option<u32>,
    /// Policy for protected sites when Cisco is off and no proxy matches (§71 D2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_policy: Option<LocalPolicy>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Unverified {
    Allow,
    #[default]
    WhenWrong,
    Block,
}

/// A rule: the sites and IPv4 ranges it protects, and the countries
/// their connections may leave from (ISO 3166 alpha-2).
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: u32,
    pub name: String,
    pub enabled: bool,
    pub sites: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceptions: Option<Arc<Vec<String>>>,
    pub expect: Vec<String>,
    pub unverified: Unverified,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<Arc<Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_matches: Option<Arc<Vec<String>>>,
}

impl<'de> Deserialize<'de> for Group {
    /// Rules saved before §66.25 listed website members ("example.com",
    /// "*.example.com", "geosite:…"); they become the sites they named.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Member {
            pattern: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Fields {
            id: u32,
            name: String,
            enabled: bool,
            sites: Vec<String>,
            exceptions: Option<Arc<Vec<String>>>,
            expect: Vec<String>,
            members: Vec<Member>,
            unverified: Unverified,
            matches: Option<Arc<Vec<String>>>,
            #[serde(rename = "exceptionMatches")]
            exception_matches: Option<Arc<Vec<String>>>,
        }
        let f = Fields::deserialize(deserializer)?;
        let mut sites = f.sites;
        if sites.is_empty() {
            for member in f.members {
                let site = member.pattern.trim().to_ascii_lowercase().replace("*.", "");
                let site = site.trim_matches('.');
                if !site.is_empty() && !site.contains(':') && site.contains('.') && !sites.iter().any(|s| s == site) {
                    sites.push(site.to_owned());
                }
            }
        }
        Ok(Group {
            id: f.id, name: f.name, enabled: f.enabled, sites, expect: f.expect,
            unverified: f.unverified, matches: f.matches, exceptions: f.exceptions,
            exception_matches: f.exception_matches,
        })
    }
}

impl Group {
    pub fn allows(&self, country: &str) -> bool {
        self.expect.iter().any(|c| c.eq_ignore_ascii_case(country))
    }

    fn site_group(&self) -> SiteGroup {
        fn literal_entries(sites: &[String]) -> impl Iterator<Item = String> + '_ {
            sites.iter().filter_map(|site| {
                if site.starts_with("geosite:") || site.starts_with("geoip:") {
                    None
                } else if crate::dns_forwarder::cidr_range(site).is_some() {
                    Some(format!("ipcidr:{site}"))
                } else {
                    Some(site.trim().to_owned())
                }
            })
        }
        let mut sites = self.matches.as_deref().cloned()
            .unwrap_or_else(|| literal_entries(&self.sites).collect());
        if !sites.is_empty() {
            if let Some(matches) = &self.exception_matches {
                sites.extend(matches.iter().map(|rule| format!("except:{rule}")));
            } else if let Some(exceptions) = &self.exceptions {
                sites.extend(literal_entries(exceptions).map(|rule| format!("except:{rule}")));
            }
        }
        SiteGroup { id: self.id, sites }
    }
}

impl EgressConfig {
    pub fn prefetch_limit(&self) -> usize {
        self.prefetch.unwrap_or(DEFAULT_PREFETCH).min(MAX_PREFETCH) as usize
    }

    pub fn half_life(&self) -> Duration {
        Duration::from_secs(60 * u64::from(self.half_life.unwrap_or(DEFAULT_HALF_LIFE_MIN).clamp(1, MAX_HALF_LIFE_MIN)))
    }

    pub fn steering(&self) -> bool {
        self.steer.unwrap_or(true)
    }

    pub fn local_policy(&self) -> LocalPolicy {
        self.local_policy.unwrap_or_default()
    }

    pub fn active(&self) -> bool {
        self.enabled && self.groups.iter().any(|g| g.enabled && !g.sites.is_empty())
    }

    /// At most 16 rules with unique ids; sites are host names; countries
    /// are two capital letters; an enabled rule with sites has a country.
    pub fn valid(&self) -> bool {
        let ids: std::collections::HashSet<_> = self.groups.iter().map(|g| g.id).collect();
        ids.len() == self.groups.len() && self.groups.len() <= MAX_GROUPS
            && self.prefetch.is_none_or(|n| n <= MAX_PREFETCH)
            && self.half_life.is_none_or(|m| (1..=MAX_HALF_LIFE_MIN).contains(&m))
            && self.groups.iter().all(|g| {
                g.sites.len() <= MAX_SITES
                    && g.sites.iter().all(|site| valid_rule(site, false))
                    && g.exceptions.as_ref().is_none_or(|entries| entries.len() <= MAX_SITES
                        && entries.iter().all(|entry| valid_rule(entry, false)))
                    // Empty matches are valid: a rule made only of site lists
                    // the App has not downloaded yet protects nothing until
                    // they arrive, and must not stop the VPN from connecting
                    // (§66.30; on the real Mac it held the network, so the
                    // lists could not download either).
                    && g.matches.as_ref().is_none_or(|entries| entries.len() <= MAX_MATCHES
                        && entries.iter().all(|entry| valid_rule(entry, true)))
                    && g.exception_matches.as_ref().is_none_or(|entries| entries.len() <= MAX_MATCHES
                        && entries.iter().all(|entry| valid_rule(entry, true)))
                    && g.expect.iter().all(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
                    && (!g.enabled || g.sites.is_empty() || !g.expect.is_empty())
            })
    }

    /// The sites of each enabled rule, for the gate and the DNS forwarder.
    pub fn site_groups(&self) -> Vec<SiteGroup> {
        if !self.enabled {
            return Vec::new();
        }
        self.groups.iter().filter(|g| g.enabled && !g.sites.is_empty())
            .map(Group::site_group).collect()
    }

    pub fn protected_sites(&self) -> ProtectedSites {
        ProtectedSites::new(&self.site_groups())
    }

    pub fn group(&self, id: u32) -> Option<&Group> {
        self.groups.iter().find(|g| g.id == id)
    }

    fn enabled_group(&self, id: u32) -> Option<&Group> {
        self.group(id).filter(|g| g.enabled && self.active())
    }
}

pub fn valid_rule(raw: &str, expanded: bool) -> bool {
    let rule = raw.trim();
    if rule.is_empty() || raw.len() > 300 || rule.chars().any(char::is_control) {
        return false;
    }
    match rule.split_once(':') {
        Some(("full" | "domain", value)) => valid_host(value),
        Some(("keyword", value)) => !value.is_empty(),
        Some(("regexp", value)) => !value.is_empty() && regex_lite::Regex::new(value).is_ok(),
        Some(("ipcidr", value)) if expanded => crate::dns_forwarder::cidr_range(value).is_some(),
        Some(("geoip", "cn")) if !expanded => true,
        Some(("geosite", value)) if !expanded => {
            let identifier = |s: &str| !s.is_empty()
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
            value.split_once('@').map_or_else(|| identifier(value), |(n, a)| {
                identifier(n) && identifier(a.strip_prefix('!').unwrap_or(a))
            })
        }
        Some(_) => false,
        None => (rule.contains('.') && valid_host(rule))
            || (!expanded && crate::dns_forwarder::cidr_range(rule).is_some()),
    }
}

// ------------------------------------------------------------------ probes

/// One HTTPS exchange for the platform hook to carry out through the tunnel.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRequest {
    pub host: String,
    /// The checked connection's destination; TLS and HTTP keep the site name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_ip: Option<IpAddr>,
    pub port: u16,
    /// The full HTTP/1.1 request bytes (UTF-8 text).
    pub request: String,
    /// ALPN list: `http/1.1` plus the gate's marker.
    pub alpn: Vec<String>,
    /// Tunnel interface to bind to.
    pub interface: String,
    pub timeout_ms: u64,
}

/// Raw response bytes, or None (connect/TLS/timeout failure). The second
/// argument receives the address actually connected to.
pub type ProbeHook = Arc<dyn Fn(&ProbeRequest, &mut Option<IpAddr>) -> Option<Vec<u8>> + Send + Sync>;

/// What one probe saw for one site at one server.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Observation {
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_address: Option<IpAddr>,
    pub country: Option<String>,
    pub ip: Option<String>,
    pub error: Option<String>,
    /// Set on a wrong-country observation the user may approve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    /// Which road produced this observation ("cisco", "proxy:<n>", "local"; §71).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip)]
    pub evidence_at_ms: Option<u64>,
}

pub fn valid_host(host: &str) -> bool {
    host.len() <= 253 && host.trim_end_matches('.').split('.').all(|label|
        !label.is_empty() && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

/// The site's own trace page (§66.4): `GET https://{host}/cdn-cgi/trace`.
pub fn trace_request(host: &str) -> String {
    format!("GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn parse_response(raw: &[u8]) -> Option<Response> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let mut body = raw[end + 4..].to_vec();
    if !body.is_empty() && headers.iter().any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked")) {
        body = dechunk(&body)?;
    }
    Some(Response { status, headers, body })
}

fn dechunk(b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut p = 0;
    loop {
        let line_end = p + b.get(p..)?.windows(2).position(|w| w == b"\r\n")?;
        let size = usize::from_str_radix(std::str::from_utf8(&b[p..line_end]).ok()?.split(';').next()?.trim(), 16).ok()?;
        p = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(p..p + size)?);
        p += size + 2;
    }
}

/// Country (`loc=`) and exit address (`ip=`) from a trace answer.
pub fn read_trace(resp: &Response) -> Result<(String, Option<String>), String> {
    if resp.status >= 400 {
        return Err(format!("网站回答 {}", resp.status));
    }
    let text = String::from_utf8_lossy(&resp.body);
    let value = |key: &str| text.lines().find_map(|l| l.split_once('=').filter(|(k, _)| k.trim() == key).map(|(_, v)| v.trim().to_owned()));
    let code = value("loc").ok_or("回答里没有国家信息")?.to_ascii_uppercase();
    if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(format!("不认识的国家代码 {code}"));
    }
    Ok((code, value("ip").filter(|s| s.parse::<IpAddr>().is_ok())))
}

/// Probe `host` at the checked server `ip` through the tunnel.
fn probe(hook: &ProbeHook, host: &str, ip: IpAddr, marker: &str, interface: &str) -> Observation {
    let mut obs = Observation { host: host.into(), peer_address: Some(ip), path: Some(EgressPath::Cisco.wire()), ..Default::default() };
    if host.is_empty() {
        obs.error = Some("看不到网站名".into());
        return obs;
    }
    let mut alpn = vec!["http/1.1".to_string()];
    if !marker.is_empty() {
        alpn.push(marker.into());
    }
    let req = ProbeRequest {
        host: host.into(), connect_ip: Some(ip), port: 443, request: trace_request(host), alpn,
        interface: interface.into(), timeout_ms: PROBE_TIMEOUT_MS,
    };
    let mut peer = None;
    let raw = hook(&req, &mut peer);
    // The exit is what the answer says at the moment it arrived (§66.31:
    // stamping the start made a reused result look up to a probe's
    // duration older, and the gate dropped connections on the real Mac).
    let answered_at = evidence_clock_ms();
    if peer.is_some_and(|peer| peer != ip) {
        obs.error = Some("探测对端与指定地址不符".into());
        return obs;
    }
    match raw.as_deref().and_then(parse_response) {
        None => obs.error = Some("连不上或没有回答".into()),
        Some(resp) => match read_trace(&resp) {
            Ok((country, exit)) => {
                obs.evidence_at_ms = answered_at;
                obs.country = Some(country);
                obs.ip = exit;
            }
            Err(e) => obs.error = Some(e),
        },
    }
    obs
}

// ------------------------------------------------------------ status/records

#[derive(Serialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupStatus {
    pub id: u32,
    pub name: String,
    /// "ok", "blocked" (some servers exit from a wrong country), "unknown".
    pub state: String,
    pub last_check: f64,
    /// The wrong-exit servers while blocked, else the latest observation.
    pub observed: Vec<Observation>,
    pub blocked_count: u64,
    /// Connections let through because their exit could not be read
    /// (best effort, §66.25).
    pub unverified_count: u64,
    pub last_blocked_host: Option<String>,
    pub last_blocked_country: Option<String>,
    pub sites: Vec<SiteStatus>,
    /// Names recently answered with another entry of their CDN whose
    /// exit was verified (§66.28).
    pub steered: Vec<String>,
    /// The road most recently checked for this rule ("cisco", "proxy:<n>", "local"; §71).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Per-road status & last observed exit (§71).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<PathStatus>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BlockRecord {
    pub started: f64,
    pub ended: Option<f64>,
    pub group: u32,
    pub name: String,
    pub host: Option<String>,
    pub observed: Vec<Observation>,
    pub expected: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub running: bool,
    pub checking: Vec<u32>,
    pub groups: Vec<GroupStatus>,
    pub records: VecDeque<BlockRecord>,
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

impl Status {
    fn group(&mut self, group: &Group) -> &mut GroupStatus {
        let index = match self.groups.iter().position(|g| g.id == group.id) {
            Some(index) => index,
            None => {
                self.groups.push(GroupStatus { id: group.id, state: "unknown".into(), ..Default::default() });
                self.groups.len() - 1
            }
        };
        let st = &mut self.groups[index];
        st.name.clone_from(&group.name);
        st
    }

    /// A rule's state after a check: blocked while any server is known to
    /// exit wrong. A block opens a record once and keeps it listing the
    /// current wrong-exit servers (what an approval refers to); recovery
    /// closes it.
    fn apply(&mut self, group: &Group, latest: &Observation, failing: Vec<Observation>, at: f64) {
        let st = self.group(group);
        st.last_check = at;
        st.observe_site(group, latest, at);
        let was_blocked = st.state == "blocked";
        let blocked = !failing.is_empty();
        st.state = if blocked { "blocked" } else { "ok" }.into();
        st.observed = if blocked { failing.clone() } else { vec![latest.clone()] };
        if !blocked {
            for r in self.records.iter_mut().filter(|r| r.group == group.id && r.ended.is_none()) {
                r.ended = Some(at);
            }
        } else if let Some(open) = self.records.iter_mut().find(|r| r.group == group.id && r.ended.is_none()).filter(|_| was_blocked) {
            open.observed = failing;
            if let Some(p) = open.observed.first().and_then(|o| o.path.clone()) {
                open.path = Some(p);
            }
        } else {
            let host = failing.first().filter(|o| !o.host.is_empty()).map(|o| o.host.clone());
            let path = failing.first().and_then(|o| o.path.clone());
            self.records.push_front(BlockRecord {
                started: at, ended: None, group: group.id, name: group.name.clone(), host,
                observed: failing, expected: group.expect.clone(), path,
            });
            self.records.truncate(MAX_RECORDS);
        }
    }
}

// --------------------------------------------------------------- controller

struct Shared {
    state: Mutex<ControlState>,
    marker: String,
    hook: ProbeHook,
    stop: AtomicBool,
    /// Wakes the refresher (§66.31).
    bell: Bell,
}

#[derive(Clone, PartialEq, Eq)]
struct Target {
    host: String,
    ip: IpAddr,
    path: EgressPath,
}

struct Failed {
    target: Target,
    observation: Observation,
}

struct ActiveCheck {
    group: u32,
    epoch: u64,
}

type RelaySlot = Arc<(Mutex<Option<&'static str>>, std::sync::Condvar)>;

struct ControlState {
    config: EgressConfig,
    sites: ProtectedSites,
    status: Status,
    interface: String,
    peer: Option<UnixStream>,
    peer_id: u64,
    epoch: u64,
    /// Keyed by (gate peer, request id); explicit rechecks use peer 0,
    /// relay checks use peer u64::MAX.
    checks: HashMap<(u64, u64), ActiveCheck>,
    failures: HashMap<u32, Vec<Failed>>,
    peer_counts: HashMap<u32, Denied>,
    /// Exits seen per (name, address), for steering DNS answers (§66.28).
    ledger: Ledger,
    /// Recent results and the busiest servers (§66.31).
    cache: Cache,
    on_peer_loss: Option<Box<dyn Fn() + Send>>,
    /// In-process proxy/local relay opener (§71).
    relay_opener: Option<RelayOpener>,
    /// Singleflight map for concurrent relay connections waiting on one probe.
    relay_running: HashMap<refresh::Key, RelaySlot>,
    next_relay_check: u64,
}

fn approval_id() -> Option<String> {
    let mut bytes = [0u8; 16];
    (unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } == 0)
        .then(|| format!("{:032x}", u128::from_be_bytes(bytes)))
}

impl ControlState {
    fn send(&mut self, line: &str) {
        if let Some(peer) = &mut self.peer {
            if peer.write_all(format!("{line}\n").as_bytes()).is_err() {
                self.peer_lost();
            }
        }
    }

    fn gate_config(&self, marker: &str) -> String {
        serde_json::json!({ "probe_alpn": marker, "groups": self.config.site_groups() }).to_string()
    }

    /// Note one probe result for a connection. Returns the gate's verdict.
    fn record(&mut self, group: &Group, target: Target, obs: Observation) -> &'static str {
        self.record_probe(group, target, obs, true)
    }

    /// Note one probe result; `connection` is false for a background
    /// refresh, which does not count as another unreadable connection.
    fn record_probe(&mut self, group: &Group, target: Target, mut obs: Observation, connection: bool) -> &'static str {
        if obs.path.is_none() {
            obs.path = Some(target.path.wire());
        }
        if target.path.is_cisco() {
            if let Some(country) = obs.country.as_deref() {
                self.ledger.note(&target.host, target.ip, country, std::time::Instant::now());
            }
        }
        let failed = self.failures.entry(group.id).or_default();
        let previous = failed.iter().position(|f| f.target == target).map(|i| failed.remove(i));
        let mut remember = false;
        let verdict = match obs.country.as_deref() {
            Some(country) if group.allows(country) => "allow",
            Some(_) => {
                obs.approval_id = previous.as_ref()
                    .filter(|p| p.observation.country == obs.country && p.observation.ip == obs.ip)
                    .and_then(|p| p.observation.approval_id.clone())
                    .or_else(approval_id);
                remember = true;
                "block"
            }
            None if group.unverified == Unverified::Block => {
                remember = true;
                "block"
            }
            None => {
                // A failed probe does not establish that a wrong exit recovered.
                if let Some(previous) = previous.as_ref().filter(|p| p.observation.country.is_some()) {
                    failed.push(Failed { target: previous.target.clone(), observation: previous.observation.clone() });
                }
                if group.unverified == Unverified::WhenWrong && failed.iter().any(|f| f.observation.country.is_some()) {
                    return "block";
                }
                if connection { self.note_unverified(group); }
                return "unverified";
            }
        };
        if remember {
            if failed.len() >= MAX_FAILED_TARGETS {
                failed.remove(0);
            }
            failed.push(Failed { target, observation: obs.clone() });
        }
        let failing = failed.iter().map(|f| f.observation.clone()).collect();
        self.status.apply(group, &obs, failing, now());
        verdict
    }

    /// Settle each rule's state with its remaining failures (after an edit
    /// or an approval removed some).
    fn settle(&mut self) {
        let at = now();
        for st in &mut self.status.groups {
            let failing = self.failures.get(&st.id).map_or(0, Vec::len);
            if st.state == "blocked" && failing == 0 {
                st.state = "ok".into();
                st.observed.clear();
                for r in self.status.records.iter_mut().filter(|r| r.group == st.id && r.ended.is_none()) {
                    r.ended = Some(at);
                }
            } else if failing > 0 {
                st.observed = self.failures[&st.id].iter().map(|f| f.observation.clone()).collect();
                for r in self.status.records.iter_mut().filter(|r| r.group == st.id && r.ended.is_none()) {
                    r.observed.clone_from(&st.observed);
                    if let Some(group) = self.config.group(st.id) {
                        r.expected.clone_from(&group.expect);
                    }
                }
            }
        }
    }

    fn wake_relay_waiters(&mut self, filter: Option<EgressPath>, verdict: &'static str) {
        let keys: Vec<_> = self.relay_running.keys()
            .filter(|k| filter.is_none_or(|p| k.1 == p))
            .cloned().collect();
        for key in keys {
            if let Some(slot) = self.relay_running.remove(&key) {
                let mut guard = slot.0.lock().expect("relay slot");
                if guard.is_none() {
                    *guard = Some(verdict);
                    slot.1.notify_all();
                }
            }
        }
    }

    fn replace_config(&mut self, cfg: EgressConfig, marker: &str) {
        self.epoch = self.epoch.wrapping_add(1);
        self.ledger.clear();
        self.cache.forget();
        self.wake_relay_waiters(None, "block");
        let sites = cfg.protected_sites();
        self.failures.retain(|id, failed| {
            let Some(group) = cfg.enabled_group(*id) else { return false };
            failed.retain(|f| sites.group_for_target(&f.target.host, f.target.ip) == Some(*id)
                && f.observation.country.as_deref().map_or(group.unverified == Unverified::Block,
                    |country| !group.allows(country)));
            !failed.is_empty()
        });
        self.cache.half_life = cfg.half_life();
        self.config = cfg;
        self.sites = sites;
        self.settle();
        self.status.groups.retain(|st| self.config.enabled_group(st.id).is_some());
        let frame = self.gate_config(marker);
        self.send(&frame);
        self.send("{\"invalidate\":true}");
    }

    fn retire_checks(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.ledger.clear();
        self.cache.forget();
        self.wake_relay_waiters(None, "block");
    }

    fn invalidate_path(&mut self, path: EgressPath) {
        self.cache.forget_path(path);
        self.wake_relay_waiters(Some(path), "block");
    }

    fn disconnect(&mut self) {
        if let Some(peer) = self.peer.take() {
            let _ = peer.shutdown(std::net::Shutdown::Both);
        }
        self.peer_counts.clear();
        self.interface.clear();
        self.peer_id = self.peer_id.wrapping_add(1);
        self.retire_checks();
    }

    fn peer_lost(&mut self) {
        self.disconnect();
        if let Some(notify) = &self.on_peer_loss {
            notify();
        }
    }
}

/// Listens on a root-private UNIX socket for the gate (one at a time), and
/// optionally serves the in-process proxy/local relay (§71).
pub struct Controller {
    shared: Arc<Shared>,
    path: Option<PathBuf>,
    wake_stop: Option<OwnedFd>,
}

/// Cloneable handle passed to `split_proxy::Routing` so the in-process relay
/// can check protected connections before forwarding any bytes (§71).
#[derive(Clone)]
pub struct RelayGate {
    shared: Arc<Shared>,
}

fn verdict_from_str(s: &str) -> RelayVerdict {
    match s {
        "allow" => RelayVerdict::Allow,
        "unverified" => RelayVerdict::Unverified,
        _ => RelayVerdict::Block,
    }
}

impl RelayGate {
    /// Whether `host` or any of `ips` belongs to an enabled protection group.
    pub fn protects_target(&self, host: &str, ips: &[IpAddr]) -> Option<u32> {
        let state = self.shared.state.lock().ok()?;
        if !state.config.active() { return None; }
        state.sites.group_for_addresses(host, ips.iter().copied())
    }

    pub fn is_active(&self) -> bool {
        self.shared.state.lock().ok().is_some_and(|s| s.config.active())
    }

    pub fn local_policy(&self) -> LocalPolicy {
        self.shared.state.lock().ok().map(|s| s.config.local_policy()).unwrap_or_default()
    }

    pub fn set_relay_opener(&self, opener: Option<RelayOpener>) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.relay_opener = opener;
            self.shared.bell.0.notify_one();
        }
    }

    pub fn invalidate_path(&self, path: EgressPath) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.invalidate_path(path);
        }
    }

    pub fn invalidate_all(&self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.retire_checks();
        }
    }

    /// Gate a TCP connection before any bytes are forwarded (§71).
    /// Returns `None` when the target is not protected by any enabled rule.
    pub fn check_connection(
        &self,
        host: &str,
        ips: &[IpAddr],
        path: EgressPath,
        resolved_local_ip: Option<IpAddr>,
    ) -> Option<RelayVerdict> {
        let clean_host = host.trim_end_matches('.').to_ascii_lowercase();
        let wait_slot: Option<RelaySlot>;
        let probe_ctx: Option<(u32, Group, refresh::Key, u64, (u64, u64), RelayOpener, RelaySlot)>;
        let group_id: u32;
        {
            let mut state = self.shared.state.lock().ok()?;
            if !state.config.active() { return None; }
            let id = state.sites.group_for_addresses(&clean_host, ips.iter().copied())?;
            let Some(rule) = state.config.enabled_group(id).cloned() else { return None };
            group_id = id;

            // D2-B: block non-proxied protected sites when Cisco is off.
            if path == EgressPath::Local && state.config.local_policy() == LocalPolicy::Block {
                let obs = Observation {
                    host: clean_host.clone(),
                    peer_address: resolved_local_ip,
                    error: Some("Cisco 未连接且未命中代理".into()),
                    path: Some(path.wire()),
                    ..Default::default()
                };
                let failing = vec![obs.clone()];
                state.status.apply(&rule, &obs, failing, now());
                state.note_relay_denied(&rule, &clean_host, &path);
                return Some(RelayVerdict::Block);
            }

            if clean_host.is_empty() {
                let ip = resolved_local_ip.or_else(|| ips.first().copied())
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                let target = Target { host: String::new(), ip, path };
                let obs = Observation {
                    host: String::new(),
                    peer_address: (ip != IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)).then_some(ip),
                    error: Some("看不到网站名".into()),
                    path: Some(path.wire()),
                    ..Default::default()
                };
                let answer = state.record(&rule, target, obs);
                if answer == "block" {
                    state.note_relay_denied(&rule, "", &path);
                }
                return Some(verdict_from_str(answer));
            }

            if !valid_host(&clean_host) {
                state.note_relay_denied(&rule, &clean_host, &path);
                return Some(RelayVerdict::Block);
            }

            let key_ip = resolved_local_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let key: refresh::Key = (id, path, clean_host.clone(), key_ip);
            let now_inst = Instant::now();
            state.cache.bump(&key, now_inst);
            self.shared.bell.0.notify_one();

            if let Some(fresh) = state.cache.reusable(&key, state.epoch, now_inst) {
                let answer = fresh.answer;
                if answer == "block" {
                    state.note_relay_denied(&rule, &clean_host, &path);
                }
                return Some(verdict_from_str(answer));
            }

            if let Some(slot) = state.relay_running.get(&key) {
                wait_slot = Some(slot.clone());
                probe_ctx = None;
            } else {
                let Some(opener) = state.relay_opener.clone() else {
                    state.note_relay_denied(&rule, &clean_host, &path);
                    return Some(RelayVerdict::Block);
                };
                if state.checks.len() >= MAX_CHECKS {
                    state.note_relay_denied(&rule, &clean_host, &path);
                    return Some(RelayVerdict::Block);
                }
                let epoch = state.epoch;
                state.next_relay_check = state.next_relay_check.wrapping_add(1).max(1);
                let check_key = (u64::MAX, state.next_relay_check);
                state.checks.insert(check_key, ActiveCheck { group: id, epoch });
                let slot: RelaySlot = Arc::new((Mutex::new(None), std::sync::Condvar::new()));
                state.relay_running.insert(key.clone(), slot.clone());
                wait_slot = None;
                probe_ctx = Some((id, rule, key, epoch, check_key, opener, slot));
            }
        }

        if let Some(slot) = wait_slot {
            let (lock, cv) = &*slot;
            let mut guard = lock.lock().expect("relay slot");
            let deadline = Instant::now() + RELAY_WAIT_TIMEOUT;
            while guard.is_none() {
                let Some(rem) = deadline.checked_duration_since(Instant::now()) else { break };
                let (g, timed) = cv.wait_timeout(guard, rem).expect("relay slot");
                guard = g;
                if timed.timed_out() { break; }
            }
            let answer = *guard;
            drop(guard);
            let mut state = self.shared.state.lock().expect("controller");
            let Some(rule) = state.config.enabled_group(group_id).cloned() else {
                return Some(RelayVerdict::Block);
            };
            let final_ans = match answer {
                Some(ans) => ans,
                None => match rule.unverified {
                    Unverified::Block => "block",
                    Unverified::WhenWrong if state.failures.get(&group_id).is_some_and(|f| f.iter().any(|x| x.observation.country.is_some())) => "block",
                    Unverified::WhenWrong | Unverified::Allow => {
                        state.note_unverified(&rule);
                        "unverified"
                    }
                },
            };
            if final_ans == "block" {
                state.note_relay_denied(&rule, &clean_host, &path);
            }
            return Some(verdict_from_str(final_ans));
        }

        let (id, _rule, key, epoch, check_key, opener, slot) = probe_ctx.expect("probe_ctx");
        let obs = bridge::probe_via_relay(&self.shared.hook, &opener, &path, &clean_host, resolved_local_ip);
        let answer = {
            let mut state = self.shared.state.lock().expect("controller");
            state.checks.remove(&check_key);
            state.relay_running.remove(&key);
            if state.epoch != epoch || self.shared.stop.load(Ordering::SeqCst) {
                "block"
            } else if let Some(rule) = state.config.enabled_group(id).cloned() {
                let target = Target { host: clean_host.clone(), ip: key.3, path };
                let ans = state.record(&rule, target, obs.clone());
                state.cache.note(key, ans, &obs, epoch, Instant::now());
                if ans == "block" {
                    state.note_relay_denied(&rule, &clean_host, &path);
                }
                ans
            } else {
                "block"
            }
        };
        {
            let mut guard = slot.0.lock().expect("relay slot");
            *guard = Some(answer);
            slot.1.notify_all();
        }
        Some(verdict_from_str(answer))
    }
}

impl Controller {
    pub fn start(path: &Path, cfg: EgressConfig, hook: ProbeHook) -> std::io::Result<Controller> {
        let _ = std::fs::remove_file(path);
        let half_life = cfg.half_life();
        let (wake, wake_stop) = crate::child_io::pipe()?;
        let listener = crate::child_io::creation(|| UnixListener::bind(path))?;
        let shared = Arc::new(Shared {
            state: Mutex::new(ControlState {
                sites: cfg.protected_sites(), config: cfg, status: Status::default(), interface: String::new(), peer: None, peer_id: 0,
                epoch: 0, checks: HashMap::new(), failures: HashMap::new(), peer_counts: HashMap::new(),
                ledger: Ledger::default(), cache: Cache::with_half_life(half_life), on_peer_loss: None,
                relay_opener: None, relay_running: HashMap::new(), next_relay_check: 0,
            }),
            marker: format!("ac-probe-{:016x}", random_u64()), hook, stop: AtomicBool::new(false),
            bell: Bell::default(),
        });
        let controller = Controller { shared, path: Some(path.to_path_buf()), wake_stop: Some(wake_stop) };
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let shared = controller.shared.clone();
        listener.set_nonblocking(true)?;
        std::thread::Builder::new().name("egress-control".into()).spawn(move || accept_loop(listener, wake, shared))?;
        let shared = controller.shared.clone();
        std::thread::Builder::new().name("egress-refresher".into()).spawn(move || refresh::refresh_loop(shared))?;
        Ok(controller)
    }

    /// Starts an in-process controller with no UNIX gate socket (for proxy-only
    /// mode when Cisco is off, §71).
    pub fn in_process(cfg: EgressConfig, hook: ProbeHook) -> std::io::Result<Controller> {
        let half_life = cfg.half_life();
        let shared = Arc::new(Shared {
            state: Mutex::new(ControlState {
                sites: cfg.protected_sites(), config: cfg, status: Status::default(), interface: String::new(), peer: None, peer_id: 0,
                epoch: 0, checks: HashMap::new(), failures: HashMap::new(), peer_counts: HashMap::new(),
                ledger: Ledger::default(), cache: Cache::with_half_life(half_life), on_peer_loss: None,
                relay_opener: None, relay_running: HashMap::new(), next_relay_check: 0,
            }),
            marker: format!("ac-probe-{:016x}", random_u64()), hook, stop: AtomicBool::new(false),
            bell: Bell::default(),
        });
        let controller = Controller { shared, path: None, wake_stop: None };
        let shared = controller.shared.clone();
        std::thread::Builder::new().name("egress-refresher".into()).spawn(move || refresh::refresh_loop(shared))?;
        Ok(controller)
    }

    pub fn relay_gate(&self) -> RelayGate {
        RelayGate { shared: self.shared.clone() }
    }

    pub fn set_relay_opener(&self, opener: Option<RelayOpener>) {
        self.relay_gate().set_relay_opener(opener);
    }

    pub fn invalidate_path(&self, path: EgressPath) {
        self.relay_gate().invalidate_path(path);
    }

    pub fn marker(&self) -> String {
        self.shared.marker.clone()
    }

    /// Retire the previous script's reader before starting another VPN process.
    pub(crate) fn watch_next_launch(&self, notify: Box<dyn Fn() + Send>) {
        let mut state = self.shared.state.lock().expect("controller");
        state.disconnect();
        state.on_peer_loss = Some(notify);
    }

    pub(crate) fn has_peer(&self) -> bool {
        self.shared.state.lock().expect("controller").peer.is_some()
    }

    pub fn status_json(&self) -> String {
        let state = self.shared.state.lock().expect("controller");
        let mut status = state.status.clone();
        status.running = state.peer.is_some() || state.relay_opener.is_some();
        status.checking = state.checks.values().filter(|c| c.epoch == state.epoch).map(|c| c.group).collect();
        status.checking.sort_unstable();
        status.checking.dedup();
        serde_json::to_string(&status).unwrap_or_else(|_| "{}".into())
    }

    /// Send the new rules. A probe started before this configuration can
    /// no longer release packets.
    pub fn update(&self, cfg: EgressConfig) {
        let mut state = self.shared.state.lock().expect("controller");
        state.replace_config(cfg, &self.shared.marker);
        self.shared.bell.0.notify_one();
    }

    /// Probe a rule's wrong-exit servers again ("重新检查").
    pub fn recheck_job(&self, id: u32) -> Option<impl FnOnce() -> bool + Send + 'static> {
        let mut state = self.shared.state.lock().ok()?;
        state.config.enabled_group(id)?;
        let cisco_ready = !state.interface.is_empty() && state.peer.is_some();
        let relay_opener = state.relay_opener.clone();
        let targets: Vec<Target> = state.failures.get(&id)?.iter()
            .filter(|f| if f.target.path.is_cisco() { cisco_ready } else { relay_opener.is_some() })
            .map(|f| f.target.clone())
            .collect();
        let key = (0, u64::from(id)); // gate peer ids start at one
        if targets.is_empty() || state.checks.contains_key(&key) || state.checks.len() >= MAX_CHECKS { return None; }
        let epoch = state.epoch;
        let interface = state.interface.clone();
        state.checks.insert(key, ActiveCheck { group: id, epoch });
        let shared = self.shared.clone();
        Some(move || run_check(&shared, id, targets, &interface, relay_opener, key))
    }

    /// Add `country` to a rule after the user approved one of its current
    /// wrong-exit observations. Returns the new configuration.
    pub fn allow_country(&self, expected: &EgressConfig, group_id: u32, started: f64, country: &str,
                         evidence: &Observation) -> Option<EgressConfig> {
        let proxy_path = evidence.path.as_deref().is_some_and(|p| p.starts_with("proxy:"));
        if !started.is_finite() || (evidence.peer_address.is_none() && !proxy_path) || evidence.error.is_some()
            || evidence.approval_id.is_none() || evidence.country.as_deref() != Some(country)
            || country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) { return None; }
        let mut state = self.shared.state.lock().ok()?;
        state.status.records.iter().find(|r| r.group == group_id && r.started == started && r.ended.is_none())?;
        fn norm_path(p: &Option<String>) -> &str { p.as_deref().unwrap_or("cisco") }
        let current = state.failures.get(&group_id)?.iter().any(|f| {
            let o = &f.observation;
            o.host.eq_ignore_ascii_case(&evidence.host) && o.peer_address == evidence.peer_address
                && o.country == evidence.country && o.ip == evidence.ip && o.approval_id == evidence.approval_id
                && norm_path(&o.path) == norm_path(&evidence.path)
        });
        let active = (state.peer.is_some() && !state.interface.is_empty()) || state.relay_opener.is_some();
        if &state.config != expected || !active || !current {
            return None;
        }
        let mut config = state.config.clone();
        let group = config.groups.iter_mut().find(|g| g.enabled && g.id == group_id)?;
        if group.allows(country) {
            return None;
        }
        group.expect.push(country.to_owned());
        state.replace_config(config.clone(), &self.shared.marker);
        Some(config)
    }

    /// Forget every verdict (network change, wake: §66.6).
    pub fn invalidate(&self) {
        let mut state = self.shared.state.lock().expect("controller");
        state.retire_checks();
        state.send("{\"invalidate\":true}");
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        let mut state = self.shared.state.lock().expect("controller");
        state.relay_opener = None;
        state.disconnect();
        drop(state);
        self.shared.bell.0.notify_all();
        self.wake_stop.take();
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    u64::from_ne_bytes(b) ^ now().to_bits()
}

fn accept_loop(listener: UnixListener, wake: OwnedFd, shared: Arc<Shared>) {
    while !shared.stop.load(Ordering::SeqCst) {
        let mut fds = [
            libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: wake.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted { continue; }
            break;
        }
        if fds[1].revents != 0 || fds[0].revents & libc::POLLIN == 0 { break; }
        let stream = match crate::child_io::creation(|| listener.accept()) {
            Ok((stream, _)) => stream,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) => continue,
            Err(_) => break,
        };
        if stream.set_nonblocking(false).is_err() { continue; }
        let Ok(writer) = stream.try_clone() else { continue };
        if writer.set_write_timeout(Some(Duration::from_millis(100))).is_err() { continue; }
        #[cfg(target_os = "macos")]
        {
            let on: libc::c_int = 1;
            if unsafe { libc::setsockopt(writer.as_raw_fd(), libc::SOL_SOCKET, libc::SO_NOSIGPIPE,
                (&on as *const libc::c_int).cast(), std::mem::size_of_val(&on) as libc::socklen_t) } != 0 {
                continue;
            }
        }
        let mut state = shared.state.lock().expect("controller");
        if shared.stop.load(Ordering::SeqCst) { break; }
        state.disconnect();
        state.peer = Some(writer);
        let peer_id = state.peer_id;
        let line = state.gate_config(&shared.marker);
        state.send(&line);
        let shared = shared.clone();
        if std::thread::Builder::new().name("egress-gate".into())
            .spawn(move || read_loop(stream, shared, peer_id)).is_err()
        {
            state.peer_lost();
        }
    }
}

#[derive(Deserialize)]
struct GateMsg {
    check: Option<CheckMsg>,
    denied: Option<Vec<Denied>>,
    up: Option<UpMsg>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckMsg {
    group: u32,
    host: String,
    ip: IpAddr,
    request_id: std::num::NonZeroU64,
}

#[derive(Deserialize)]
struct UpMsg {
    ifname: String,
}

fn verdict(group: u32, request_id: u64, result: &str, at: Option<u64>) -> String {
    let mut value = serde_json::json!({"group": group, "requestId": request_id, "result": result});
    if result == "allow" {
        value["evidenceAtMs"] = serde_json::json!(at.unwrap_or(0));
    }
    serde_json::json!({ "verdict": value }).to_string()
}

fn read_loop(stream: UnixStream, shared: Arc<Shared>, peer_id: u64) {
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<GateMsg>(&line) else { continue };
        let mut state = shared.state.lock().expect("controller");
        if state.peer_id != peer_id { return; }
        if let Some(up) = msg.up {
            if state.interface != up.ifname {
                if !state.interface.is_empty() {
                    state.retire_checks();
                    state.send("{\"invalidate\":true}");
                }
                state.interface = up.ifname;
            }
        }
        if let Some(reports) = msg.denied {
            state.denied_counts(reports);
        }
        let Some(check) = msg.check else { continue };
        let id = check.request_id.get();
        let key = (peer_id, id);
        if state.checks.contains_key(&key) { continue; }
        let host = check.host.trim_end_matches('.').to_ascii_lowercase();
        let usable = (host.is_empty() || valid_host(&host))
            && state.sites.group_for_target(&host, check.ip) == Some(check.group)
            && !state.interface.is_empty() && state.checks.len() < MAX_CHECKS;
        if !usable {
            state.send(&verdict(check.group, id, "block", None));
            continue;
        }
        if host.is_empty() {
            if let Some(rule) = state.config.enabled_group(check.group).cloned() {
                let target = Target { host, ip: check.ip, path: EgressPath::Cisco };
                let obs = probe(&shared.hook, "", target.ip, &shared.marker, &state.interface);
                let answer = state.record(&rule, target, obs);
                state.send(&verdict(check.group, id, answer, None));
            }
            continue;
        }
        // §66.31: a young result answers at once; a probe of the same
        // server already running is waited for instead of repeated.
        let server = (check.group, EgressPath::Cisco, host.clone(), check.ip);
        let now = Instant::now();
        state.cache.bump(&server, now);
        shared.bell.0.notify_one();
        if let Some(fresh) = state.cache.reusable(&server, state.epoch, now) {
            let line = verdict(check.group, id, fresh.answer, fresh.evidence_at);
            state.send(&line);
            continue;
        }
        if let Some(waiting) = state.cache.running.get_mut(&server) {
            waiting.push((peer_id, id));
            continue;
        }
        state.cache.running.insert(server, Vec::new());
        let epoch = state.epoch;
        let interface = state.interface.clone();
        state.checks.insert(key, ActiveCheck { group: check.group, epoch });
        let worker = shared.clone();
        let target = Target { host, ip: check.ip, path: EgressPath::Cisco };
        if std::thread::Builder::new().name("egress-check".into())
            .spawn(move || run_check(&worker, check.group, vec![target], &interface, None, key)).is_err()
        {
            state.checks.remove(&key);
            state.send(&verdict(check.group, id, "block", None));
        }
    }
    let mut state = shared.state.lock().expect("controller");
    if state.peer_id == peer_id { state.peer_lost(); }
}

fn run_check(shared: &Arc<Shared>, group: u32, targets: Vec<Target>, interface: &str,
             opener: Option<RelayOpener>, key: (u64, u64)) -> bool {
    let results: Vec<(Target, Observation)> = std::thread::scope(|scope| {
        let workers: Vec<_> = targets.iter().map(|target| {
            let opener = opener.clone();
            let worker = std::thread::Builder::new().spawn_scoped(scope, move || {
                if target.path.is_cisco() {
                    probe(&shared.hook, &target.host, target.ip, &shared.marker, interface)
                } else if let Some(opener) = opener.as_ref() {
                    let peer_ip = (target.ip != IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)).then_some(target.ip);
                    bridge::probe_via_relay(&shared.hook, opener, &target.path, &target.host, peer_ip)
                } else {
                    Observation {
                        host: target.host.clone(),
                        peer_address: (target.ip != IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)).then_some(target.ip),
                        error: Some("代理通道不可用".into()),
                        path: Some(target.path.wire()),
                        ..Default::default()
                    }
                }
            });
            (target, worker)
        }).collect();
        workers.into_iter().map(|(target, worker)| {
            let obs = worker.ok().and_then(|w| w.join().ok()).unwrap_or_else(|| Observation {
                host: target.host.clone(),
                peer_address: (target.ip != IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)).then_some(target.ip),
                error: Some("出口检查未完成".into()),
                path: Some(target.path.wire()),
                ..Default::default()
            });
            (target.clone(), obs)
        }).collect()
    });
    let mut state = shared.state.lock().expect("controller");
    let Some(active) = state.checks.remove(&key) else { return false };
    if active.epoch != state.epoch || (key.0 != 0 && state.peer_id != key.0) { return false; }
    let Some(rule) = state.config.enabled_group(group).cloned() else { return false };
    let mut answer = "block";
    let mut at = None;
    let mut searches = Vec::new();
    let mut joined = Vec::new();
    for (target, obs) in results {
        at = obs.evidence_at_ms;
        let wrong_cloudflare = target.path.is_cisco() && obs.country.is_some()
            && matches!(target.ip, IpAddr::V4(ip) if steer::cloudflare(ip));
        let host = target.host.clone();
        let server = (group, target.path, target.host.clone(), target.ip);
        answer = state.record(&rule, target, obs.clone());
        let epoch = state.epoch;
        state.cache.note(server.clone(), answer, &obs, epoch, Instant::now());
        joined.extend(state.cache.running.remove(&server).unwrap_or_default().into_iter().map(|w| (w, answer, at)));
        // A wrong exit at a Cloudflare entry: look for a verified one now,
        // so the next DNS answer can point there (§66.28).
        if answer == "block" && wrong_cloudflare && state.config.steering() {
            searches.extend(state.search_job(shared, &rule, &host));
        }
    }
    if key.0 != 0 {
        state.send(&verdict(group, key.1, answer, at));
    }
    for ((peer, id), answer, at) in joined {
        if peer == state.peer_id { state.send(&verdict(group, id, answer, at)); }
    }
    drop(state);
    for job in searches {
        let _ = std::thread::Builder::new().name("egress-steer".into()).spawn(job);
    }
    true
}

#[cfg(test)]
mod tests;
