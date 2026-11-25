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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::egress_gate::{evidence_clock_ms, ProtectedSites, SiteGroup};

mod activity;
use activity::{Denied, SiteStatus};
mod steer;
use steer::Ledger;

const MAX_GROUPS: usize = 16;
const MAX_SITES: usize = 256;
const MAX_MATCHES: usize = 20_000;
/// Checks running at once; more are refused until one finishes.
const MAX_CHECKS: usize = 32;
/// Wrong-exit servers remembered per rule (status, approval, recheck).
const MAX_FAILED_TARGETS: usize = 8;
const PROBE_TIMEOUT_MS: u64 = 2_400;
pub const MAX_RECORDS: usize = 10;

// ------------------------------------------------------------------ config

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct EgressConfig {
    pub enabled: bool,
    pub groups: Vec<Group>,
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
    pub expect: Vec<String>,
    pub unverified: Unverified,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<Arc<Vec<String>>>,
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
            expect: Vec<String>,
            members: Vec<Member>,
            unverified: Unverified,
            matches: Option<Arc<Vec<String>>>,
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
            unverified: f.unverified, matches: f.matches,
        })
    }
}

impl Group {
    pub fn allows(&self, country: &str) -> bool {
        self.expect.iter().any(|c| c.eq_ignore_ascii_case(country))
    }

    fn site_group(&self) -> SiteGroup {
        let sites = self.matches.as_deref().cloned().unwrap_or_else(|| {
            self.sites.iter().filter_map(|site| {
                if site.starts_with("geosite:") || site.starts_with("geoip:") {
                    None
                } else if crate::dns_forwarder::cidr_range(site).is_some() {
                    Some(format!("ipcidr:{site}"))
                } else {
                    Some(site.trim().to_owned())
                }
            }).collect()
        });
        SiteGroup { id: self.id, sites }
    }
}

impl EgressConfig {
    pub fn active(&self) -> bool {
        self.enabled && self.groups.iter().any(|g| g.enabled && !g.sites.is_empty())
    }

    /// At most 16 rules with unique ids; sites are host names; countries
    /// are two capital letters; an enabled rule with sites has a country.
    pub fn valid(&self) -> bool {
        let ids: std::collections::HashSet<_> = self.groups.iter().map(|g| g.id).collect();
        ids.len() == self.groups.len() && self.groups.len() <= MAX_GROUPS
            && self.groups.iter().all(|g| {
                g.sites.len() <= MAX_SITES
                    && g.sites.iter().all(|site| valid_rule(site, false))
                    // Empty matches are valid: a rule made only of site lists
                    // the App has not downloaded yet protects nothing until
                    // they arrive, and must not stop the VPN from connecting
                    // (§66.30; on the real Mac it held the network, so the
                    // lists could not download either).
                    && g.matches.as_ref().is_none_or(|entries| entries.len() <= MAX_MATCHES
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
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-!".contains(&b));
            value.split_once('@').map_or_else(|| identifier(value), |(n, a)| identifier(n) && identifier(a))
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
    let mut obs = Observation { host: host.into(), peer_address: Some(ip), ..Default::default() };
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
    let started_at = evidence_clock_ms();
    let raw = hook(&req, &mut peer);
    if peer.is_some_and(|peer| peer != ip) {
        obs.error = Some("探测对端与指定地址不符".into());
        return obs;
    }
    match raw.as_deref().and_then(parse_response) {
        None => obs.error = Some("连不上或没有回答".into()),
        Some(resp) => match read_trace(&resp) {
            Ok((country, exit)) => {
                obs.evidence_at_ms = started_at;
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
        } else {
            let host = failing.first().filter(|o| !o.host.is_empty()).map(|o| o.host.clone());
            self.records.push_front(BlockRecord {
                started: at, ended: None, group: group.id, name: group.name.clone(), host,
                observed: failing, expected: group.expect.clone(),
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
}

#[derive(Clone, PartialEq)]
struct Target {
    host: String,
    ip: IpAddr,
}

struct Failed {
    target: Target,
    observation: Observation,
}

struct ActiveCheck {
    group: u32,
    epoch: u64,
}

struct ControlState {
    config: EgressConfig,
    sites: ProtectedSites,
    status: Status,
    interface: String,
    peer: Option<UnixStream>,
    peer_id: u64,
    epoch: u64,
    /// Keyed by (gate peer, request id); explicit rechecks use peer 0.
    checks: HashMap<(u64, u64), ActiveCheck>,
    failures: HashMap<u32, Vec<Failed>>,
    peer_counts: HashMap<u32, Denied>,
    /// Exits seen per (name, address), for steering DNS answers (§66.28).
    ledger: Ledger,
    on_peer_loss: Option<Box<dyn Fn() + Send>>,
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

    /// Note one probe result. Returns the gate's verdict for it.
    fn record(&mut self, group: &Group, target: Target, mut obs: Observation) -> &'static str {
        if let Some(country) = obs.country.as_deref() {
            self.ledger.note(&target.host, target.ip, country, std::time::Instant::now());
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
                self.note_unverified(group);
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

    fn replace_config(&mut self, cfg: EgressConfig, marker: &str) {
        self.epoch = self.epoch.wrapping_add(1);
        self.ledger.clear();
        let sites = cfg.protected_sites();
        self.failures.retain(|id, failed| {
            let Some(group) = cfg.enabled_group(*id) else { return false };
            failed.retain(|f| sites.group_for_target(&f.target.host, f.target.ip) == Some(*id)
                && f.observation.country.as_deref().map_or(group.unverified == Unverified::Block,
                    |country| !group.allows(country)));
            !failed.is_empty()
        });
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

/// Listens on a root-private UNIX socket for the gate (one at a time).
pub struct Controller {
    shared: Arc<Shared>,
    path: PathBuf,
    wake_stop: Option<OwnedFd>,
}

impl Controller {
    pub fn start(path: &Path, cfg: EgressConfig, hook: ProbeHook) -> std::io::Result<Controller> {
        let _ = std::fs::remove_file(path);
        let (wake, wake_stop) = crate::child_io::pipe()?;
        let listener = crate::child_io::creation(|| UnixListener::bind(path))?;
        let shared = Arc::new(Shared {
            state: Mutex::new(ControlState {
                sites: cfg.protected_sites(), config: cfg, status: Status::default(), interface: String::new(), peer: None, peer_id: 0,
                epoch: 0, checks: HashMap::new(), failures: HashMap::new(), peer_counts: HashMap::new(),
                ledger: Ledger::default(), on_peer_loss: None,
            }),
            marker: format!("ac-probe-{:016x}", random_u64()), hook, stop: AtomicBool::new(false),
        });
        let controller = Controller { shared, path: path.to_path_buf(), wake_stop: Some(wake_stop) };
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let shared = controller.shared.clone();
        listener.set_nonblocking(true)?;
        std::thread::Builder::new().name("egress-control".into()).spawn(move || accept_loop(listener, wake, shared))?;
        Ok(controller)
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
        status.running = state.peer.is_some();
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
    }

    /// Probe a rule's wrong-exit servers again ("重新检查").
    pub fn recheck_job(&self, id: u32) -> Option<impl FnOnce() -> bool + Send + 'static> {
        let mut state = self.shared.state.lock().ok()?;
        state.config.enabled_group(id)?;
        let targets: Vec<Target> = state.failures.get(&id)?.iter().map(|f| f.target.clone()).collect();
        let key = (0, u64::from(id)); // gate peer ids start at one
        if targets.is_empty() || state.interface.is_empty() || state.peer.is_none()
            || state.checks.contains_key(&key) || state.checks.len() >= MAX_CHECKS { return None; }
        let epoch = state.epoch;
        let interface = state.interface.clone();
        state.checks.insert(key, ActiveCheck { group: id, epoch });
        let shared = self.shared.clone();
        Some(move || run_check(&shared, id, targets, &interface, key))
    }

    /// Add `country` to a rule after the user approved one of its current
    /// wrong-exit observations. Returns the new configuration.
    pub fn allow_country(&self, expected: &EgressConfig, group_id: u32, started: f64, country: &str,
                         evidence: &Observation) -> Option<EgressConfig> {
        if !started.is_finite() || evidence.peer_address.is_none() || evidence.error.is_some()
            || evidence.approval_id.is_none() || evidence.country.as_deref() != Some(country)
            || country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) { return None; }
        let mut state = self.shared.state.lock().ok()?;
        state.status.records.iter().find(|r| r.group == group_id && r.started == started && r.ended.is_none())?;
        let current = state.failures.get(&group_id)?.iter().any(|f| {
            let o = &f.observation;
            o.host.eq_ignore_ascii_case(&evidence.host) && o.peer_address == evidence.peer_address
                && o.country == evidence.country && o.ip == evidence.ip && o.approval_id == evidence.approval_id
        });
        if &state.config != expected || state.peer.is_none() || state.interface.is_empty() || !current {
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
        self.shared.state.lock().expect("controller").disconnect();
        self.wake_stop.take();
        let _ = std::fs::remove_file(&self.path);
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
                let target = Target { host, ip: check.ip };
                let obs = probe(&shared.hook, "", target.ip, &shared.marker, &state.interface);
                let answer = state.record(&rule, target, obs);
                state.send(&verdict(check.group, id, answer, None));
            }
            continue;
        }
        let epoch = state.epoch;
        let interface = state.interface.clone();
        state.checks.insert(key, ActiveCheck { group: check.group, epoch });
        let worker = shared.clone();
        let target = Target { host, ip: check.ip };
        if std::thread::Builder::new().name("egress-check".into())
            .spawn(move || run_check(&worker, check.group, vec![target], &interface, key)).is_err()
        {
            state.checks.remove(&key);
            state.send(&verdict(check.group, id, "block", None));
        }
    }
    let mut state = shared.state.lock().expect("controller");
    if state.peer_id == peer_id { state.peer_lost(); }
}

fn run_check(shared: &Arc<Shared>, group: u32, targets: Vec<Target>, interface: &str, key: (u64, u64)) -> bool {
    let results: Vec<(Target, Observation)> = std::thread::scope(|scope| {
        let workers: Vec<_> = targets.iter().map(|target| {
            let worker = std::thread::Builder::new().spawn_scoped(scope, ||
                probe(&shared.hook, &target.host, target.ip, &shared.marker, interface));
            (target, worker)
        }).collect();
        workers.into_iter().map(|(target, worker)| {
            let obs = worker.ok().and_then(|w| w.join().ok()).unwrap_or_else(|| Observation {
                host: target.host.clone(), peer_address: Some(target.ip),
                error: Some("出口检查未完成".into()), ..Default::default()
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
    for (target, obs) in results {
        at = obs.evidence_at_ms;
        let wrong_cloudflare = obs.country.is_some() && matches!(target.ip, IpAddr::V4(ip) if steer::cloudflare(ip));
        let host = target.host.clone();
        answer = state.record(&rule, target, obs);
        // A wrong exit at a Cloudflare entry: look for a verified one now,
        // so the next DNS answer can point there (§66.28).
        if answer == "block" && wrong_cloudflare {
            searches.extend(state.search_job(shared, &rule, &host));
        }
    }
    if key.0 != 0 {
        state.send(&verdict(group, key.1, answer, at));
    }
    drop(state);
    for job in searches {
        let _ = std::thread::Builder::new().name("egress-steer".into()).spawn(job);
    }
    true
}

#[cfg(test)]
mod tests;
