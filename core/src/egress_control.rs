//! Egress protection controller (DESIGN.md §66.3–66.7): the background
//! service's side of the gate. It owns the user's groups and probe methods,
//! answers the gate's checks by probing through the tunnel, and keeps the
//! status and the last block records for the App.
//!
//! The HTTPS request itself is made by a thin platform hook (Network.framework
//! on macOS: TLS, the ALPN marker, the tunnel interface); everything else —
//! building the request, parsing the answer, extracting the country, the
//! group decision, the records — is here and tested on Linux.

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

mod airports;
mod activity;
use activity::{Denied, SiteStatus};
mod recheck;
pub(crate) mod setup_probe;
use recheck::{Failures, Target};

// ------------------------------------------------------------------ config

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct EgressConfig {
    pub enabled: bool,
    pub groups: Vec<Group>,
    /// User-defined methods; the presets ([`preset_methods`]) are always
    /// available under their own ids.
    pub methods: Vec<ProbeMethod>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Group {
    pub id: u32,
    pub name: String,
    pub enabled: bool,
    pub members: Vec<Member>,
    /// Address ranges that belong to this group (hard-coded addresses).
    pub cidrs: Vec<String>,
    /// Expected countries (ISO 3166 alpha-2). Empty: not locked yet, every
    /// check fails closed.
    pub expect: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Member {
    /// `a.example` or `*.a.example`.
    pub pattern: String,
    /// Probe method id; None = "follow the group" (§66.3).
    pub method: Option<String>,
    /// Concrete name to probe for a wildcard member when no connection named
    /// one (set up time, or a check triggered by an address).
    pub probe_host: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeMethod {
    pub id: String,
    pub name: String,
    /// `https://{host}/...`; `{host}` is the member's site.
    pub url: String,
    #[serde(default)]
    pub head: bool,
    pub extract: Extract,
}

impl ProbeMethod {
    pub fn is_direct(&self) -> bool {
        let Some(url) = self.url.strip_prefix("https://") else { return false };
        let authority = url.split('/').next().unwrap_or_default();
        authority == "{host}" || authority.strip_prefix("{host}:")
            .is_some_and(|port| port.parse::<std::num::NonZeroU16>().is_ok())
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Extract {
    pub kind: ExtractKind,
    /// kv: the key (`loc`); json: a dot path (`country`); header: header
    /// names, comma separated, tried in order.
    pub key: String,
    /// Optional regular expression; capture group 1 is the code.
    #[serde(default)]
    pub regex: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExtractKind {
    Kv,
    Json,
    Header,
}

#[derive(Deserialize)]
pub struct GateGroup {
    id: u32,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    cidrs: Vec<String>,
}

struct ProtectedGroup {
    id: u32,
    exact: std::collections::HashSet<String>,
    wildcards: Vec<String>,
    lists: crate::dns_forwarder::SplitRules,
    cidrs: Vec<(IpAddr, u8)>,
}

pub struct ProtectedRoutes(Vec<ProtectedGroup>);

impl ProtectedRoutes {
    pub fn new(groups: &[GateGroup]) -> Self {
        Self(groups.iter().map(|group| {
            let mut exact = std::collections::HashSet::new();
            let mut wildcards = Vec::new();
            let mut lists = Vec::new();
            for name in &group.names {
                if name.starts_with("*.") {
                    wildcards.push(name.to_string());
                } else if name.contains(':') {
                    lists.push(name.to_string());
                } else {
                    exact.insert(name.trim_end_matches('.').to_ascii_lowercase());
                }
            }
            ProtectedGroup { id: group.id, exact, wildcards,
                lists: crate::dns_forwarder::SplitRules::new(&lists),
                cidrs: group.cidrs.iter().filter_map(|cidr| parse_cidr(cidr)).collect() }
        }).collect())
    }

    pub fn overlaps(&self, range: &str) -> bool {
        let Some((addr, len)) = parse_cidr(range) else { return false };
        self.0.iter().any(|group| group.cidrs.iter().any(|&(other, bits)|
            in_net(addr, other, len.min(bits))))
    }
}

impl crate::egress_gate::Classifier for ProtectedRoutes {
    fn group_for_name(&self, name: &str) -> Option<u32> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.0.iter().find(|group| group.exact.contains(&name)
            || group.wildcards.iter().any(|pattern| pattern_matches(pattern, &name))
            || group.lists.matches(&name).is_some()).map(|group| group.id)
    }

    fn group_for_ip(&self, ip: IpAddr) -> Option<u32> {
        self.0.iter().find(|group| group.cidrs.iter().any(|&(net, len)| in_net(ip, net, len)))
            .map(|group| group.id)
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

pub const PRESET_TRACE: &str = "trace";
pub const PRESET_CDN: &str = "cdn-node";
const MAX_METHODS: usize = 8;
const MAX_GROUPS: usize = 16;
const MAX_PROBES_PER_GROUP: usize = 8;

/// Built-in methods (§66.4). Generic, no company or service names.
pub fn preset_methods() -> Vec<ProbeMethod> {
    vec![
        ProbeMethod {
            id: PRESET_TRACE.into(),
            name: "网站自己的检测地址".into(),
            url: "https://{host}/cdn-cgi/trace".into(),
            head: false,
            extract: Extract { kind: ExtractKind::Kv, key: "loc".into(), regex: None },
        },
        ProbeMethod {
            id: PRESET_CDN.into(),
            name: "CDN 节点（近似）".into(),
            url: "https://{host}/".into(),
            head: true,
            extract: Extract { kind: ExtractKind::Header, key: "cf-ray,x-amz-cf-pop,x-served-by".into(), regex: None },
        },
    ]
}

impl EgressConfig {
    pub fn active(&self) -> bool {
        self.enabled && self.groups.iter().any(|g| g.enabled)
    }

    pub fn protected_routes(&self) -> ProtectedRoutes {
        ProtectedRoutes::new(&self.groups.iter().filter(|g| g.enabled).map(|g| GateGroup {
            id: g.id,
            names: g.members.iter().map(|m| m.pattern.trim().to_string()).collect(),
            cidrs: g.cidrs.clone(),
        }).collect::<Vec<_>>())
    }

    pub fn valid(&self) -> bool {
        let group_ids: std::collections::HashSet<_> = self.groups.iter().map(|g| g.id).collect();
        let method_ids: std::collections::HashSet<_> = self.methods.iter().map(|m| &m.id).collect();
        group_ids.len() == self.groups.len() && method_ids.len() == self.methods.len()
            && self.methods.len() <= MAX_METHODS && self.groups.len() <= MAX_GROUPS
            && self.groups.iter().all(|g| {
                let checkable = g.members.iter().filter(|m| m.method.is_some()).count();
                g.members.len() <= 2_048 && g.cidrs.len() <= 256
                    && g.cidrs.iter().all(|range| parse_cidr(range).is_some())
                    && g.expect.iter().all(|country| country.len() == 2 && country.bytes().all(|b| b.is_ascii_uppercase()))
                    && checkable <= MAX_PROBES_PER_GROUP
                    && (!g.enabled || (!g.expect.is_empty() && checkable > 0 && probe_targets(self, g, None).len() == checkable))
            })
            && self.methods.iter().all(|m| !m.extract.key.is_empty()
                && m.extract.regex.as_ref().is_none_or(|pattern| regex_lite::Regex::new(pattern).is_ok())
                && build_request(m, "site.example").is_ok())
    }

    pub fn method(&self, id: &str) -> Option<ProbeMethod> {
        self.methods.iter().find(|m| m.id == id).cloned().or_else(|| preset_methods().into_iter().find(|m| m.id == id))
    }

    /// The gate's view: names and ranges per enabled group.
    pub fn gate_groups(&self) -> Vec<serde_json::Value> {
        self.groups
            .iter()
            .filter(|g| g.enabled)
            .map(|g| serde_json::json!({ "id": g.id, "names": g.members.iter().map(|m| m.pattern.trim().to_ascii_lowercase()).collect::<Vec<_>>(), "cidrs": g.cidrs }))
            .collect()
    }

    fn has_direct_method(&self, group: &Group) -> bool {
        group.members.iter().filter_map(|m| self.method(m.method.as_deref()?)).any(|m| m.is_direct())
    }

    pub fn group(&self, id: u32) -> Option<&Group> {
        self.groups.iter().find(|g| g.id == id)
    }
}

pub fn pattern_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => name.len() > suffix.len() && name.ends_with(&suffix) && name.as_bytes()[name.len() - suffix.len() - 1] == b'.',
        None => pattern == name,
    }
}

// ------------------------------------------------------------------ probes

/// One HTTPS exchange for the platform hook to carry out through the tunnel.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRequest {
    pub host: String,
    /// Numeric destination of a triggering same-site flow. TLS and HTTP keep the original site name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_ip: Option<IpAddr>,
    pub port: u16,
    /// The full HTTP/1.1 request bytes (UTF-8 text).
    pub request: String,
    /// ALPN list: `http/1.1` plus the gate's marker.
    pub alpn: Vec<String>,
    /// Tunnel interface to bind to (empty: let routing decide).
    pub interface: String,
    pub timeout_ms: u64,
}

/// Raw response bytes, or None (connect/TLS/timeout failure).
pub type ProbeHook = Arc<dyn Fn(&ProbeRequest, &mut Option<IpAddr>) -> Option<Vec<u8>> + Send + Sync>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_address: Option<IpAddr>,
    pub host: String,
    pub method: String,
    pub country: Option<String>,
    pub ip: Option<String>,
    pub error: Option<String>,
}

pub fn build_request(method: &ProbeMethod, host: &str) -> Result<(String, u16, String), String> {
    if !valid_host(host) { return Err("需要具体的网站名".into()); }
    let url = method.url.replace("{host}", host);
    let rest = url.strip_prefix("https://").ok_or("只接受 https 地址")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, suffix) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']').ok_or("地址里缺网站名")?;
        if host.parse::<std::net::Ipv6Addr>().is_err() { return Err("地址里缺网站名".into()); }
        (host, suffix)
    } else {
        let (host, suffix) = authority.find(':').map_or((authority, ""), |i| authority.split_at(i));
        if !valid_host(host) { return Err("地址里缺网站名".into()); }
        (host, suffix)
    };
    let port = if suffix.is_empty() { 443 } else {
        suffix.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).filter(|p| *p != 0).ok_or("端口不对")?
    };
    if !path.bytes().all(|c| c.is_ascii_graphic() && c != b'#') {
        return Err("请求路径格式不对".into());
    }
    let verb = if method.head { "HEAD" } else { "GET" };
    let req = format!("{verb} {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    Ok((host.into(), port, req))
}

pub fn valid_host(host: &str) -> bool {
    host.len() <= 253 && host.trim_end_matches('.').split('.').all(|label|
        !label.is_empty() && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
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

/// Country (and address when the answer has one) from a response.
pub fn extract(method: &ProbeMethod, resp: &Response) -> Result<(String, Option<String>), String> {
    if resp.status >= 400 && method.extract.kind != ExtractKind::Header {
        return Err(format!("网站回答 {}", resp.status));
    }
    let x = &method.extract;
    let (raw, ip) = match x.kind {
        ExtractKind::Kv => {
            let text = String::from_utf8_lossy(&resp.body);
            let kv: HashMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim(), v.trim())).collect();
            (kv.get(x.key.as_str()).map(|s| s.to_string()), kv.get("ip").map(|s| s.to_string()))
        }
        ExtractKind::Json => {
            let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|_| "回答不是 JSON")?;
            let mut cur = &v;
            for part in x.key.split('.') {
                cur = cur.get(part).unwrap_or(&serde_json::Value::Null);
            }
            let ip = v.get("ip").and_then(|i| i.as_str()).map(str::to_string);
            (cur.as_str().map(str::to_string), ip)
        }
        ExtractKind::Header => {
            let mut found = None;
            for name in x.key.split(',').map(|n| n.trim().to_ascii_lowercase()) {
                if let Some((_, v)) = resp.headers.iter().find(|(k, _)| *k == name) {
                    found = if x.regex.is_some() { Some(v.clone()) } else { pop_code(&name, v) };
                    if found.is_some() {
                        break;
                    }
                }
            }
            (found, None)
        }
    };
    let mut code = raw.ok_or("回答里没有国家信息")?;
    if let Some(re) = &x.regex {
        let re = regex_lite::Regex::new(re).map_err(|_| "正则写错了")?;
        code = re.captures(&code).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()).ok_or("正则没匹配上")?;
    }
    let code = code.trim().to_ascii_uppercase();
    let country = match code.len() {
        2 if code.chars().all(|c| c.is_ascii_alphabetic()) => code,
        3 => airports::country(&code).map(str::to_string).ok_or_else(|| format!("不认识的节点代码 {code}"))?,
        _ => return Err(format!("不认识的国家代码 {code}")),
    };
    let ip = ip.filter(|s| s.parse::<IpAddr>().is_ok());
    Ok((country, ip))
}

/// The CDN node's airport code in the usual headers (§66.4).
fn pop_code(name: &str, v: &str) -> Option<String> {
    let code = match name {
        "cf-ray" => v.rsplit('-').next()?.to_string(),
        "x-amz-cf-pop" => v.get(..3)?.to_string(),
        "x-served-by" => v.rsplit(',').next()?.trim().rsplit('-').next()?.to_string(),
        _ => v.to_string(),
    };
    (code.len() == 3 && code.chars().all(|c| c.is_ascii_alphabetic())).then(|| code.to_ascii_uppercase())
}

fn probe_once(hook: &ProbeHook, method: &ProbeMethod, host: &str, alpn: &str, interface: &str,
              connect_ip: Option<IpAddr>, evidence: &str, timeout_ms: u64) -> (Observation, bool) {
    let mut obs = Observation { host: host.into(), method: method.id.clone(), evidence: Some(evidence.into()),
        peer_address: connect_ip, ..Default::default() };
    let (h, port, request) = match build_request(method, host) {
        Ok(x) => x,
        Err(e) => {
            obs.error = Some(e);
            return (obs, false);
        }
    };
    let mut list = vec!["http/1.1".to_string()];
    if !alpn.is_empty() {
        list.push(alpn.into());
    }
    let req = ProbeRequest { host: h, connect_ip, port, request, alpn: list, interface: interface.into(), timeout_ms };
    let mut peer = None;
    let raw = hook(&req, &mut peer);
    if connect_ip.is_some() && peer.is_some() && peer != connect_ip {
        obs.error = Some("探测对端与指定地址不符".into());
        return (obs, false);
    }
    obs.peer_address = connect_ip.or(peer);
    let response = raw.as_deref().and_then(parse_response);
    let received = response.is_some();
    match response {
        None => obs.error = Some("连不上或没有回答".into()),
        Some(resp) => match extract(method, &resp) {
            Ok((c, ip)) => {
                obs.country = Some(c);
                obs.ip = ip;
            }
            Err(e) => obs.error = Some(e),
        },
    }
    (obs, received)
}

// --------------------------------------------------------------- decisions

/// Which (host, method) pairs a check for `group` triggered by `host` probes
/// (§66.6): every checkable member, using the actual name for matching wildcards.
pub fn probe_targets(cfg: &EgressConfig, group: &Group, host: Option<&str>) -> Vec<(String, ProbeMethod)> {
    let concrete = |m: &Member| -> Option<String> {
        if !m.pattern.starts_with("*.") {
            valid_host(m.pattern.trim()).then(|| m.pattern.trim().to_ascii_lowercase())
        } else {
            m.probe_host.clone().filter(|h| valid_host(h) && pattern_matches(&m.pattern, h))
        }
    };
    group
        .members
        .iter()
        .filter_map(|m| {
            let target = host.filter(|h| pattern_matches(&m.pattern, h))
                .map(str::to_ascii_lowercase).or_else(|| concrete(m))?;
            Some((target, cfg.method(m.method.as_deref()?)?))
        })
        .collect()
}

pub fn probe_methods(cfg: &EgressConfig, host: &str, hook: &ProbeHook, marker: &str, iface: &str) -> Vec<Observation> {
    if !valid_host(host) || iface.is_empty() { return Vec::new(); }
    std::thread::scope(|scope| {
        let mut methods = preset_methods();
        for preset in &mut methods {
            if let Some(custom) = cfg.methods.iter().find(|method| method.id == preset.id) {
                *preset = custom.clone();
            }
        }
        methods.extend(cfg.methods.iter().filter(|method| method.id != PRESET_TRACE && method.id != PRESET_CDN).cloned());
        methods.into_iter().filter_map(|method| std::thread::Builder::new().spawn_scoped(scope, move || probe_once(hook, &method, host, marker, iface, None,
                if method.is_direct() { "member" } else { "third-party" }, 2400).0).ok())
            .collect::<Vec<_>>().into_iter().filter_map(|worker| worker.join().ok()).collect()
    })
}

pub fn decide(group: &Group, obs: &[Observation]) -> bool {
    !obs.is_empty()
        && !group.expect.is_empty()
        && obs.iter().all(|o| o.country.as_deref().is_some_and(|c| group.expect.iter().any(|e| e.eq_ignore_ascii_case(c))))
}

// ------------------------------------------------------------ status/records

#[derive(Serialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupStatus {
    pub level: String,
    pub blocked_count: u64,
    pub last_blocked_host: Option<String>,
    pub last_blocked_country: Option<String>,
    pub sites: Vec<SiteStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub id: u32,
    pub name: String,
    /// "ok", "blocked", "unknown".
    pub state: String,
    pub last_check: f64,
    pub observed: Vec<Observation>,
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

pub const MAX_RECORDS: usize = 10;

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub running: bool,
    pub checking: Vec<u32>,
    pub interface: String,
    pub groups: Vec<GroupStatus>,
    pub records: VecDeque<BlockRecord>,
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

impl Status {
    /// Record a check's outcome; a block opens a record once, a pass closes it.
    pub fn apply(&mut self, group: &Group, host: Option<&str>, obs: Vec<Observation>, ok: bool, at: f64) {
        let st = match self.groups.iter_mut().find(|g| g.id == group.id) {
            Some(s) => s,
            None => {
                self.groups.push(GroupStatus { id: group.id, name: group.name.clone(), ..Default::default() });
                self.groups.last_mut().expect("pushed")
            }
        };
        st.name = group.name.clone();
        st.last_check = at;
        st.observed = obs.clone();
        let was_blocked = st.state == "blocked";
        st.state = if ok { "ok" } else { "blocked" }.into();
        if ok {
            for r in self.records.iter_mut().filter(|r| r.group == group.id && r.ended.is_none()) {
                r.ended = Some(at);
            }
        } else if !was_blocked {
            self.records.push_front(BlockRecord { started: at, ended: None, group: group.id, name: group.name.clone(), host: host.map(str::to_string), observed: obs, expected: group.expect.clone() });
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

struct ControlState {
    config: EgressConfig,
    status: Status,
    peer: Option<UnixStream>,
    peer_id: u64,
    epoch: u64,
    // Retired workers count towards the bound until they exit.
    checks: HashMap<(u64, u64), ActiveCheck>,
    failures: HashMap<u32, Failures>,
    peer_counts: HashMap<u32, Denied>,
    on_peer_loss: Option<Box<dyn Fn() + Send>>,
}

struct ActiveCheck {
    group: u32,
    epoch: u64,
    generation: u64,
    trigger: Option<String>,
    targets: Vec<Target>,
}

impl ControlState {
    fn send(&mut self, line: &str) {
        if let Some(peer) = &mut self.peer {
            if peer.write_all(format!("{line}\n").as_bytes()).is_err() {
                self.peer_lost();
            }
        }
    }

    fn record(&mut self, group: &Group, host: Option<&str>, generation: u64,
              results: Vec<(Target, Observation)>) -> bool {
        let failures = self.failures.entry(group.id).or_default();
        let was_overflowed = failures.overflowed();
        let ok = failures.evaluate(group, generation, &results);
        let unresolved = failures.observed_failures();
        let blocked = !unresolved.is_empty() || !ok;
        let reason = if failures.overflowed() { Some("failed-target-overflow") }
            else if !self.config.has_direct_method(group) { Some("no-direct-method") } else { None };
        let mut observations: Vec<_> = results.into_iter().map(|(_, obs)| obs).collect();
        if let Some(problem) = failures.diagnostic() { observations.push(problem); }
        if !was_overflowed && failures.overflowed() {
            if let Some(record) = self.status.records.iter_mut().find(|r| r.group == group.id && r.ended.is_none()) {
                if let Some(problem) = failures.diagnostic() { record.observed.push(problem); }
            }
            self.send(&serde_json::json!({"blockGroup":group.id}).to_string());
        }
        self.status.apply(group, host, observations, !blocked, now());
        if let Some(st) = self.status.groups.iter_mut().find(|s| s.id == group.id) {
            st.reason = reason.map(str::to_owned);
            let last = st.last_check;
            let latest = std::mem::take(&mut st.observed);
            st.observe_sites(group, &latest, last);
            st.observe_sites(group, &unresolved, last);
            st.observed = if unresolved.is_empty() { latest } else { unresolved };
            st.level = st.level().into();
        }
        ok
    }

    fn replace_config(&mut self, cfg: EgressConfig, marker: &str) {
        let line = config_line(&cfg, marker);
        self.epoch = self.epoch.wrapping_add(1);
        self.status.groups.retain(|group| cfg.active() && cfg.group(group.id).is_some_and(|g| g.enabled));
        let previous = std::mem::replace(&mut self.config, cfg);
        let ControlState { failures, config, .. } = self;
        failures.retain(|id, failed| {
            let Some(group) = config.group(*id).filter(|g| config.active() && g.enabled) else { return false };
            failed.reset_if_edited(&previous, config, group);
            failed.update(config, group);
            failed.invalidate_dns();
            true
        });
        self.send(&line);
        self.send("{\"invalidate\":true}");
    }

    fn retire_checks(&mut self) {
        let checks: Vec<_> = self.checks.values().filter(|c| c.epoch == self.epoch).map(|c|
            (c.group, c.trigger.clone(), c.generation, recheck::unconfirmed(&c.targets, "出口检查被中断"))).collect();
        for (id, host, generation, observed) in checks {
            if let Some(group) = self.config.group(id).cloned() {
                self.record(&group, host.as_deref(), generation, observed);
            }
        }
        self.epoch = self.epoch.wrapping_add(1);
        for failed in self.failures.values_mut() { failed.invalidate_dns(); }
    }

    fn disconnect(&mut self) {
        if let Some(peer) = self.peer.take() {
            let _ = peer.shutdown(std::net::Shutdown::Both);
        }
        self.peer_counts.clear();
        self.status.interface.clear();
        self.peer_id = self.peer_id.wrapping_add(1);
        self.retire_checks();
    }

    fn peer_lost(&mut self) {
        self.disconnect();
        if let Some(notify) = &self.on_peer_loss { notify(); }
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
                config: cfg, status: Status::default(), peer: None, peer_id: 0,
                epoch: 0, checks: HashMap::new(), failures: HashMap::new(), peer_counts: HashMap::new(), on_peer_loss: None,
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

    pub(crate) fn setup_probe_context(&self) -> Option<(String, u64)> {
        let state = self.shared.state.lock().expect("controller");
        state.peer.as_ref()?;
        Some((self.marker(), state.epoch))
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

    pub(crate) fn wrong_dns_addresses(&self, group: u32, name: &str, candidates: &[std::net::Ipv4Addr],
                                      interface: &str) -> Vec<std::net::Ipv4Addr> {
        let Ok(state) = self.shared.state.try_lock() else { return Vec::new() };
        if state.peer.is_none() || state.status.interface != interface || !state.config.active() { return Vec::new(); }
        let Some(g) = state.config.group(group).filter(|g| g.enabled) else { return Vec::new() };
        state.failures.get(&group).map_or_else(Vec::new, |f| f.wrong_ipv4(g, name, candidates))
    }

    pub fn status_json(&self) -> String {
        let state = self.shared.state.lock().expect("controller");
        let mut status = state.status.clone();
        status.running = state.peer.is_some();
        for group in state.config.groups.iter().filter(|g| g.enabled && state.config.active() && !state.config.has_direct_method(g)) {
            if let Some(st) = status.groups.iter_mut().find(|s| s.id == group.id) {
                st.state = "blocked".into();
                st.reason = Some("no-direct-method".into());
            } else {
                status.groups.push(GroupStatus { id: group.id, name: group.name.clone(), state: "blocked".into(),
                    reason: Some("no-direct-method".into()), ..Default::default() });
            }
        }
        status.checking = state.checks.values().filter(|c| c.epoch == state.epoch).map(|c| c.group).collect();
        for st in &mut status.groups { st.level = st.level().into(); }
        status.checking.sort_unstable();
        status.checking.dedup();
        serde_json::to_string(&status).unwrap_or_else(|_| "{}".into())
    }

    /// Send the new rules. A probe started before this configuration can no longer release packets.
    pub fn update(&self, cfg: EgressConfig) {
        let mut state = self.shared.state.lock().expect("controller");
        state.replace_config(cfg, &self.shared.marker);
    }

    pub fn recheck_job(&self, id: u32) -> Option<impl FnOnce() -> bool + Send + 'static> {
        let mut state = self.shared.state.lock().ok()?;
        let group = state.config.group(id).filter(|g| g.enabled && state.config.active())?.clone();
        let failed = state.failures.get(&id)?;
        let targets = failed.pending_targets();
        let generation = failed.generation;
        let key = (0, u64::from(id)); // gate peer ids start at one
        if failed.overflowed() || targets.is_empty() || state.status.interface.is_empty() || state.peer.is_none()
            || state.checks.contains_key(&key) || state.checks.len() >= MAX_GROUPS
            || targets.len() + state.checks.values().map(|c| c.targets.len()).sum::<usize>() > MAX_GROUPS * MAX_PROBES_PER_GROUP { return None; }
        let epoch = state.epoch;
        let iface = state.status.interface.clone();
        state.checks.insert(key, ActiveCheck { group: id, epoch, generation, trigger: None, targets: targets.clone() });
        let shared = self.shared.clone();
        Some(move || run_check(&shared, group, None, targets, iface, key))
    }

    pub fn allow_country(&self, expected: &EgressConfig, group_id: u32, started: f64, country: &str,
                         evidence: &Observation) -> Option<EgressConfig> {
        if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) || !started.is_finite()
            || evidence.evidence.as_deref() != Some("direct") || evidence.peer_address.is_none()
            || evidence.error.is_some() || evidence.country.as_deref() != Some(country) { return None; }
        let matches = |o: &Observation| o.evidence == evidence.evidence && o.peer_address == evidence.peer_address
            && o.method == evidence.method && o.host.eq_ignore_ascii_case(&evidence.host)
            && o.country == evidence.country && o.error.is_none();
        let mut state = self.shared.state.lock().ok()?;
        let record = state.status.records.iter().find(|r| r.group == group_id && r.started == started && r.ended.is_none())?;
        let failed = state.failures.get(&group_id)?;
        if &state.config != expected || state.peer.is_none() || state.status.interface.is_empty() || failed.overflowed()
            || !record.observed.iter().any(&matches) || !failed.observed_failures().iter().any(matches) { return None; }
        let mut config = state.config.clone();
        let group = config.groups.iter_mut().find(|g| g.enabled && g.id == group_id)?;
        if !group.expect.iter().any(|v| v.eq_ignore_ascii_case(country)) { group.expect.push(country.to_owned()); }
        state.replace_config(config.clone(), &self.shared.marker);
        Some(config)
    }

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

fn config_line(cfg: &EgressConfig, marker: &str) -> String {
    serde_json::json!({ "probe_alpn": marker, "groups": cfg.gate_groups() }).to_string()
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
        let line = config_line(&state.config, &shared.marker);
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
    #[serde(rename = "timedOut")]
    timed_out: Option<CheckMsg>,
    denied: Option<Vec<Denied>>,
    up: Option<UpMsg>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckMsg {
    group: u32,
    host: Option<String>,
    ip: IpAddr,
    port: std::num::NonZeroU16,
    request_id: std::num::NonZeroU64,
}
#[derive(Deserialize)]
struct UpMsg {
    ifname: String,
}

fn verdict(group: u32, request_id: u64, ok: bool, direct: bool) -> String {
    serde_json::json!({ "verdict": { "group": group, "requestId": request_id, "ok": ok, "direct": ok && direct } }).to_string()
}

fn read_loop(stream: UnixStream, shared: Arc<Shared>, peer_id: u64) {
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<GateMsg>(&line) else { continue };
        let mut state = shared.state.lock().expect("controller");
        if state.peer_id != peer_id { return; }
        if let Some(up) = msg.up {
            state.status.interface = up.ifname;
        }
        if let Some(reports) = msg.denied { state.denied_counts(reports); }
        let timed_out = msg.timed_out.is_some();
        if let Some(check) = msg.timed_out.or(msg.check) {
            let id = check.request_id.get();
            let key = (peer_id, id);
            if !timed_out && state.checks.contains_key(&key) { continue; }
            let Some(group) = state.config.group(check.group).filter(|g| g.enabled && state.config.active()).cloned() else {
                state.send(&verdict(check.group, id, false, false));
                continue;
            };
            let generation = state.failures.get(&group.id).map_or(0, |f| f.generation);
            if !state.config.has_direct_method(&group) || state.failures.get(&group.id).is_some_and(Failures::overflowed) {
                state.send(&serde_json::json!({"blockGroup":group.id}).to_string());
                if !timed_out { state.send(&verdict(group.id, id, false, false)); }
                continue;
            }
            let targets = state.failures.get(&group.id).unwrap_or(&Failures::default()).plan(&state.config, &group, &check);
            let workers: usize = state.checks.values().map(|c| c.targets.len()).sum();
            if timed_out || state.status.interface.is_empty() || state.checks.len() >= MAX_GROUPS
                || workers + targets.len() > MAX_GROUPS * MAX_PROBES_PER_GROUP
            {
                let reason = if timed_out { "出口检查超时" } else { "出口检查暂不可用" };
                state.record(&group, check.host.as_deref(), generation, recheck::unconfirmed(&targets, reason));
                if !timed_out { state.send(&verdict(group.id, id, false, false)); }
                continue;
            }
            let epoch = state.epoch;
            let iface = state.status.interface.clone();
            let group_id = group.id;
            state.checks.insert(key, ActiveCheck { group: group_id, epoch, generation,
                trigger: check.host.clone(), targets: targets.clone() });
            let worker = shared.clone();
            if std::thread::Builder::new().name("egress-check".into()).spawn(move ||
                run_check(&worker, group, check.host, targets, iface, key)).is_err()
            {
                let pending = state.checks.remove(&key).expect("inserted");
                let group = state.config.group(group_id).expect("existing group").clone();
                state.record(&group, pending.trigger.as_deref(), generation,
                             recheck::unconfirmed(&pending.targets, "无法启动出口检查"));
                state.send(&verdict(group_id, id, false, false));
            }
        }
    }
    let mut state = shared.state.lock().expect("controller");
    if state.peer_id == peer_id { state.peer_lost(); }
}

fn run_check(shared: &Shared, group: Group, host: Option<String>, targets: Vec<Target>,
             iface: String, key: (u64, u64)) -> bool {
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = targets.iter().map(|target| {
            let worker = std::thread::Builder::new().spawn_scoped(scope, || target.observe(&shared.hook, &shared.marker, &iface));
            (target, worker)
        }).collect();
        workers.into_iter().map(|(target, worker)| {
            let obs = worker.ok().and_then(|w| w.join().ok()).unwrap_or_else(||
                Observation { host: target.host.clone(), method: target.method.id.clone(),
                    error: Some("出口检查未完成".into()), ..Default::default() });
            (target.clone(), obs)
        }).collect()
    });
    let mut state = shared.state.lock().expect("controller");
    let Some(active) = state.checks.remove(&key) else { return false };
    if active.epoch != state.epoch || (key.0 != 0 && state.peer_id != key.0) { return false; }
    let direct = !targets.is_empty() && targets.iter().all(Target::direct_flow);
    let ok = state.record(&group, host.as_deref(), active.generation, results);
    if key.0 != 0 { state.send(&verdict(group.id, key.1, ok, direct)); }
    true
}

#[cfg(test)]
mod tests;
