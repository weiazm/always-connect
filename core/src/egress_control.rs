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
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod airports;

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

pub const PRESET_TRACE: &str = "trace";
pub const PRESET_CDN: &str = "cdn-node";

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
pub type ProbeHook = Arc<dyn Fn(&ProbeRequest) -> Option<Vec<u8>> + Send + Sync>;

#[derive(Serialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub host: String,
    pub method: String,
    pub country: Option<String>,
    pub ip: Option<String>,
    pub error: Option<String>,
}

pub fn build_request(method: &ProbeMethod, host: &str) -> Result<(String, u16, String), String> {
    let url = method.url.replace("{host}", host);
    let rest = url.strip_prefix("https://").ok_or("只接受 https 地址")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (h, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h.to_string(), p.parse::<u16>().map_err(|_| "端口不对")?),
        _ => (authority.to_string(), 443),
    };
    if h.is_empty() || h.contains(['{', '}', ' ']) {
        return Err("地址里缺网站名".into());
    }
    let verb = if method.head { "HEAD" } else { "GET" };
    let req = format!("{verb} {path} HTTP/1.1\r\nHost: {h}\r\nUser-Agent: AlwaysConnect-egress-check\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    Ok((h, port, req))
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
    if headers.iter().any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked")) {
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

pub fn probe_once(hook: &ProbeHook, method: &ProbeMethod, host: &str, alpn: &str, interface: &str) -> Observation {
    let mut obs = Observation { host: host.into(), method: method.id.clone(), ..Default::default() };
    let (h, port, request) = match build_request(method, host) {
        Ok(x) => x,
        Err(e) => {
            obs.error = Some(e);
            return obs;
        }
    };
    let mut list = vec!["http/1.1".to_string()];
    if !alpn.is_empty() {
        list.push(alpn.into());
    }
    let req = ProbeRequest { host: h, port, request, alpn: list, interface: interface.into(), timeout_ms: 3000 };
    match hook(&req).as_deref().and_then(parse_response) {
        None => obs.error = Some("连不上或没有回答".into()),
        Some(resp) => match extract(method, &resp) {
            Ok((c, ip)) => {
                obs.country = Some(c);
                obs.ip = ip;
            }
            Err(e) => obs.error = Some(e),
        },
    }
    obs
}

// --------------------------------------------------------------- decisions

/// Which (host, method) pairs a check for `group` triggered by `host` probes
/// (§66.6): the trigger itself when it has a method, otherwise every other
/// checkable member.
pub fn probe_targets(cfg: &EgressConfig, group: &Group, host: Option<&str>) -> Vec<(String, ProbeMethod)> {
    let concrete = |m: &Member| -> Option<String> {
        if !m.pattern.starts_with("*.") {
            Some(m.pattern.trim().to_ascii_lowercase())
        } else {
            m.probe_host.clone().filter(|h| pattern_matches(&m.pattern, h))
        }
    };
    if let Some(h) = host {
        if let Some(m) = group.members.iter().find(|m| pattern_matches(&m.pattern, h)) {
            if let Some(method) = m.method.as_deref().and_then(|id| cfg.method(id)) {
                return vec![(h.to_ascii_lowercase(), method)];
            }
        }
    }
    group
        .members
        .iter()
        .filter_map(|m| Some((concrete(m)?, cfg.method(m.method.as_deref()?)?)))
        .collect()
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
    cfg: Mutex<EgressConfig>,
    status: Mutex<Status>,
    gate: Mutex<Option<UnixStream>>,
    marker: String,
    hook: ProbeHook,
    stop: AtomicBool,
}

/// Listens on a root-private UNIX socket for the gate (one at a time).
pub struct Controller {
    shared: Arc<Shared>,
    path: PathBuf,
}

impl Controller {
    pub fn start(path: &Path, cfg: EgressConfig, hook: ProbeHook) -> std::io::Result<Controller> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let marker = format!("ac-probe-{:016x}", random_u64());
        let shared = Arc::new(Shared { cfg: Mutex::new(cfg), status: Mutex::new(Status::default()), gate: Mutex::new(None), marker, hook, stop: AtomicBool::new(false) });
        let s = shared.clone();
        listener.set_nonblocking(true)?;
        std::thread::Builder::new().name("egress-control".into()).spawn(move || accept_loop(listener, s))?;
        Ok(Controller { shared, path: path.to_path_buf() })
    }

    pub fn marker(&self) -> String {
        self.shared.marker.clone()
    }

    pub fn status_json(&self) -> String {
        let mut st = self.shared.status.lock().expect("status").clone();
        st.running = self.shared.gate.lock().expect("gate").is_some();
        serde_json::to_string(&st).unwrap_or_else(|_| "{}".into())
    }

    /// New groups/methods while running (expected countries after "trust",
    /// members added): the gate gets the new names, verdicts are dropped.
    pub fn update(&self, cfg: EgressConfig) {
        let line = config_line(&cfg, &self.shared.marker);
        *self.shared.cfg.lock().expect("cfg") = cfg;
        send_line(&self.shared, &line);
        send_line(&self.shared, "{\"invalidate\":true}");
    }

    /// Network change, wake, reconnect (§66.6).
    pub fn invalidate(&self) {
        send_line(&self.shared, "{\"invalidate\":true}");
    }

    /// Set-up time probing (§66.4): every method for one site.
    pub fn probe_all(&self, host: &str) -> Vec<Observation> {
        let (cfg, iface) = (self.shared.cfg.lock().expect("cfg").clone(), self.shared.status.lock().expect("status").interface.clone());
        let mut methods = preset_methods();
        methods.extend(cfg.methods.iter().cloned());
        let handles: Vec<_> = methods
            .into_iter()
            .map(|m| {
                let (hook, marker, host, iface) = (self.shared.hook.clone(), self.shared.marker.clone(), host.to_string(), iface.clone());
                std::thread::spawn(move || probe_once(&hook, &m, &host, &marker, &iface))
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(g) = self.shared.gate.lock().expect("gate").take() {
            let _ = g.shutdown(std::net::Shutdown::Both);
        }
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

fn send_line(shared: &Shared, line: &str) {
    if let Some(g) = shared.gate.lock().expect("gate").as_mut() {
        let _ = g.write_all(format!("{line}\n").as_bytes());
    }
}

fn accept_loop(listener: UnixListener, shared: Arc<Shared>) {
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let line = config_line(&shared.cfg.lock().expect("cfg"), &shared.marker);
                let mut w = match stream.try_clone() {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                if w.write_all(format!("{line}\n").as_bytes()).is_err() {
                    continue;
                }
                *shared.gate.lock().expect("gate") = Some(w);
                let s = shared.clone();
                let _ = std::thread::Builder::new().name("egress-gate".into()).spawn(move || read_loop(stream, s));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

#[derive(Deserialize)]
struct GateMsg {
    check: Option<CheckMsg>,
    up: Option<UpMsg>,
}
#[derive(Deserialize)]
struct CheckMsg {
    group: u32,
    host: Option<String>,
}
#[derive(Deserialize)]
struct UpMsg {
    ifname: String,
}

fn read_loop(stream: UnixStream, shared: Arc<Shared>) {
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<GateMsg>(&line) else { continue };
        if let Some(up) = msg.up {
            shared.status.lock().expect("status").interface = up.ifname;
        }
        if let Some(c) = msg.check {
            let s = shared.clone();
            let _ = std::thread::Builder::new().name("egress-check".into()).spawn(move || run_check(&s, c.group, c.host));
        }
    }
    *shared.gate.lock().expect("gate") = None;
}

fn run_check(shared: &Shared, group_id: u32, host: Option<String>) {
    let cfg = shared.cfg.lock().expect("cfg").clone();
    let iface = shared.status.lock().expect("status").interface.clone();
    let (ok, group, obs) = match cfg.group(group_id).filter(|g| g.enabled) {
        None => (false, None, Vec::new()),
        Some(g) => {
            let targets = probe_targets(&cfg, g, host.as_deref());
            let handles: Vec<_> = targets
                .into_iter()
                .map(|(h, m)| {
                    let (hook, marker, iface) = (shared.hook.clone(), shared.marker.clone(), iface.clone());
                    std::thread::spawn(move || probe_once(&hook, &m, &h, &marker, &iface))
                })
                .collect();
            let obs: Vec<Observation> = handles.into_iter().filter_map(|h| h.join().ok()).collect();
            (decide(g, &obs), Some(g.clone()), obs)
        }
    };
    if let Some(g) = group {
        shared.status.lock().expect("status").apply(&g, host.as_deref(), obs, ok, now());
    }
    send_line(shared, &serde_json::json!({ "verdict": { "group": group_id, "ok": ok } }).to_string());
}

#[cfg(test)]
mod tests;
