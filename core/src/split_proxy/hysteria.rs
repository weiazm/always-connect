//! Managed Hysteria2 proxy support (DESIGN.md §七十, docs/hysteria2-plan.md).
//!
//! Hysteria2 is the third proxy type in 分流代理. Rather than reimplementing
//! QUIC + Brutal + Salamander/Gecko in-process, the background service runs
//! the bundled, signature-verified official Hysteria2 client as an unprivileged
//! child (`nobody` when root) exposing a loopback-only SOCKS5 endpoint with
//! random per-run credentials. All rule matching, DNS synthetic addressing,
//! pf redirection, TCP/UDP forwarding, and fail-closed guarantees are reused
//! directly from `split_proxy`.
//!
//! All resident logic — URI parsing, rule-line encoding/decoding, client JSON
//! generation, log error classification, secret redaction, process supervision
//! (backoff, generation tracking, handover across Cisco/proxy-only switches),
//! and on-demand probing — lives here in Rust.

use super::probe::{probe as probe_socks, Level, Probe};
use super::{Kind, Routing, Server};
use crate::network_guard;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Root-owned install path of the bundled official Hysteria2 client.
pub const BUNDLED_BIN: &str = "/Library/PrivilegedHelperTools/AlwaysConnect-hysteria/bin/hysteria";
/// Root-owned (0711) parent directory for per-process `nobody`-owned config dirs.
pub const RUNTIME_DIR: &str = "/Library/Application Support/AlwaysConnect-hysteria";

const DEFAULT_PORT: &str = "443";
const DEFAULT_HOP_SECS: u32 = 30;
const MIN_HOP_SECS: u32 = 5;
const MAX_HOP_SECS: u32 = 3600;
const MAX_MBPS: u32 = 100_000;
const BACKOFF_SECS: &[u64] = &[1, 2, 5, 10, 20, 30];
const HANDOVER_GRACE: Duration = Duration::from_secs(15);
const PROBE_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Parsed Hysteria2 server specification (rules & runtime).
#[derive(Clone, PartialEq, Eq)]
pub struct HysteriaSpec {
    pub host: String,
    pub ports: String,
    pub auth: String,
    pub sni: Option<String>,
    pub pin_sha256: Option<String>,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    pub ech: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub hop_secs: Option<u32>,
}

/// Never print passwords in logs or panics.
impl fmt::Debug for HysteriaSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hysteria2 {}:{} (auth=***{})",
            self.host,
            self.ports,
            if self.obfs.is_some() { ", obfs=***" } else { "" }
        )
    }
}

/// Parsed URI result for the App's editor (`ac_hysteria_parse_uri`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedUri {
    pub host: String,
    pub ports: String,
    pub first_port: u16,
    pub has_port_hopping: bool,
    pub auth: Option<String>,
    pub sni: Option<String>,
    pub pin_sha256: Option<String>,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    pub ech: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub hop_secs: Option<u32>,
    pub name: Option<String>,
    pub summary: String,
}

// MARK: - Validation & URI parsing

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

pub fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Validates a Hysteria2 port specification (`443`, `443,5000-6000`, `20000-50000`).
/// Returns `(first_port, has_port_hopping)`.
pub fn parse_ports(spec: &str) -> Result<(u16, bool), String> {
    if spec.is_empty() || spec.len() > 128 {
        return Err("端口格式不对，例如 443 或 20000-50000".into());
    }
    let mut first: Option<u16> = None;
    let mut hopping = false;
    let mut segments = 0usize;
    for part in spec.split(',') {
        segments += 1;
        if part.is_empty() || segments > 32 {
            return Err("端口格式不对，例如 443 或 443,5000-6000".into());
        }
        if let Some((a, b)) = part.split_once('-') {
            if b.contains('-') {
                return Err("端口范围格式不对，应为 起始-结束".into());
            }
            let start: u16 = a.parse().ok().filter(|&p| p > 0)
                .ok_or_else(|| "端口是 1–65535 之间的数字".to_string())?;
            let end: u16 = b.parse().ok().filter(|&p| p > 0)
                .ok_or_else(|| "端口是 1–65535 之间的数字".to_string())?;
            if start > end {
                return Err(format!("端口范围 {start}-{end} 的起始端口大于结束端口"));
            }
            if first.is_none() {
                first = Some(start);
            }
            if start != end {
                hopping = true;
            }
        } else {
            let p: u16 = part.parse().ok().filter(|&p| p > 0)
                .ok_or_else(|| "端口是 1–65535 之间的数字".to_string())?;
            if first.is_none() {
                first = Some(p);
            }
        }
    }
    if segments > 1 {
        hopping = true;
    }
    Ok((first.unwrap_or(443), hopping))
}

/// Checks whether a numeric port matches a Hysteria2 ports spec (for connections page).
pub fn port_in_spec(spec: &str, port: u16) -> bool {
    for part in spec.split(',') {
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (a.parse::<u16>(), b.parse::<u16>()) {
                if s <= port && port <= e {
                    return true;
                }
            }
        } else if part.parse::<u16>().ok() == Some(port) {
            return true;
        }
    }
    false
}

/// Normalizes a SHA-256 certificate pin (`AA:BB:...`, `sha256/...`, or plain hex)
/// into 64 lowercase hex characters.
pub fn normalize_pin_sha256(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let stripped = trimmed
        .strip_prefix("sha256/")
        .or_else(|| trimmed.strip_prefix("SHA256/"))
        .unwrap_or(trimmed);
    let hex: String = stripped
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | ' '))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("pinSHA256 格式不对，应为 64 位十六进制指纹".into());
    }
    Ok(hex)
}

fn format_summary(
    host: &str,
    ports: &str,
    has_port_hopping: bool,
    sni: Option<&str>,
    pin_sha256: Option<&str>,
    obfs: Option<&str>,
    ech: Option<&str>,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
    hop_secs: Option<u32>,
) -> String {
    let mut parts = Vec::new();
    parts.push("Hysteria2".to_string());
    if has_port_hopping {
        parts.push(format!("{host}:{ports}"));
        let hop_text = match hop_secs {
            Some(s) => format!("端口跳跃（每 {s} 秒）"),
            None => "端口跳跃".to_string(),
        };
        parts.push(hop_text);
    } else {
        parts.push(format!("{host}:{ports}"));
    }
    if let Some(sni) = sni {
        if !sni.eq_ignore_ascii_case(host) {
            parts.push(format!("SNI {sni}"));
        }
    }
    if pin_sha256.is_some() {
        parts.push("证书指纹已固定".to_string());
    }
    if let Some(obfs) = obfs {
        parts.push(format!("{obfs} 混淆"));
    }
    if ech.is_some() {
        parts.push("ECH".to_string());
    }
    match (up_mbps, down_mbps) {
        (Some(u), Some(d)) => parts.push(format!("上 {u} / 下 {d} Mbps")),
        (Some(u), None) => parts.push(format!("上 {u} Mbps")),
        (None, Some(d)) => parts.push(format!("下 {d} Mbps")),
        (None, None) => {}
    }
    parts.join(" · ")
}

/// Parses a `hysteria2://` or `hy2://` share link (DESIGN §七十 / URI-Scheme).
/// `auth` and `obfs_password` may be omitted here so the editor can keep
/// already-saved keychain secrets when editing other fields; callers creating
/// a new proxy require them.
pub fn parse_uri(input: &str) -> Result<ParsedUri, String> {
    let trimmed = input.trim();
    let Some((scheme_raw, after_scheme)) = trimmed.split_once("://") else {
        return Err("不是有效的 Hysteria2 链接，应以 hysteria2:// 或 hy2:// 开头".into());
    };
    let scheme = scheme_raw.to_ascii_lowercase();
    if scheme.starts_with("hysteria2+realm") || scheme.starts_with("hy2+realm") {
        return Err(format!("不支持：{scheme}://（中继模式）"));
    }
    if scheme != "hysteria2" && scheme != "hy2" {
        return Err("不是有效的 Hysteria2 链接，应以 hysteria2:// 或 hy2:// 开头".into());
    }

    // Fragment (#name)
    let (before_hash, name) = match after_scheme.split_once('#') {
        Some((rest, frag)) => {
            let decoded = percent_decode(frag).ok_or_else(|| "链接名称的百分号编码无效".to_string())?;
            let clean = decoded.trim();
            (rest, (!clean.is_empty()).then(|| clean.to_owned()))
        }
        None => (after_scheme, None),
    };

    // Query (?k=v&...)
    let (before_query, query_raw) = match before_hash.split_once('?') {
        Some((rest, q)) => (rest, Some(q)),
        None => (before_hash, None),
    };

    // Authority and optional path (only empty or "/" allowed)
    let authority = match before_query.split_once('/') {
        Some((auth_part, path_part)) => {
            if !path_part.is_empty() {
                return Err(format!("不支持：链接路径 /{path_part}"));
            }
            auth_part
        }
        None => before_query,
    };

    // Userinfo (auth@) — rsplit_once because passwords rarely contain unencoded @,
    // and host never contains @.
    let (auth, host_port) = match authority.rsplit_once('@') {
        Some((user_raw, hp)) => {
            if user_raw.is_empty() {
                return Err("@ 前面的密码是空的".into());
            }
            let decoded = percent_decode(user_raw).ok_or_else(|| "密码的百分号编码无效".to_string())?;
            if decoded.is_empty() || decoded.len() > 1024 || decoded.contains('\0') {
                return Err("密码无效".into());
            }
            (Some(decoded), hp)
        }
        None => (None, authority),
    };

    // Host and optional ports
    if host_port.starts_with('[') {
        return Err("暂不支持 IPv6 服务器地址，请用域名或 IPv4".into());
    }
    let (host, ports_raw) = match host_port.split_once(':') {
        Some((h, p)) => {
            if p.contains(':') {
                return Err("暂不支持 IPv6 服务器地址，请用域名或 IPv4".into());
            }
            (h, if p.is_empty() { DEFAULT_PORT } else { p })
        }
        None => (host_port, DEFAULT_PORT),
    };
    if !is_valid_host(host) {
        return Err("服务器地址只能是域名或 IPv4，例如 proxy.example.com 或 203.0.113.10".into());
    }
    let (first_port, has_port_hopping) = parse_ports(ports_raw)?;

    // Query parameters
    let mut sni: Option<String> = None;
    let mut pin_sha256: Option<String> = None;
    let mut obfs: Option<String> = None;
    let mut obfs_password: Option<String> = None;
    let mut ech: Option<String> = None;
    let mut up_mbps: Option<u32> = None;
    let mut down_mbps: Option<u32> = None;
    let mut hop_secs: Option<u32> = None;

    if let Some(q) = query_raw {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (raw_k, raw_v) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(raw_k).ok_or_else(|| "链接参数的百分号编码无效".to_string())?;
            let val = percent_decode(raw_v).ok_or_else(|| format!("参数 {key} 的百分号编码无效"))?;
            match key.to_ascii_lowercase().as_str() {
                "sni" => {
                    if !val.is_empty() {
                        if !is_valid_host(&val) || val.parse::<Ipv4Addr>().is_ok() {
                            return Err("sni 必须是有效的域名".into());
                        }
                        sni = Some(val);
                    }
                }
                "pinsha256" => {
                    if !val.is_empty() {
                        pin_sha256 = Some(normalize_pin_sha256(&val)?);
                    }
                }
                "insecure" => {
                    match val.to_ascii_lowercase().as_str() {
                        "1" | "true" | "yes" => {
                            return Err("不支持跳过证书校验（insecure=1），自签证书请改用 pinSHA256 指纹".into());
                        }
                        "" | "0" | "false" | "no" => {}
                        _ => return Err(format!("insecure 参数值无效：{val}")),
                    }
                }
                "obfs" => {
                    if !val.is_empty() {
                        let lower = val.to_ascii_lowercase();
                        if lower != "salamander" && lower != "gecko" {
                            return Err(format!("不支持：obfs={val}（仅支持 salamander 和 gecko）"));
                        }
                        obfs = Some(lower);
                    }
                }
                "obfs-password" => {
                    if !val.is_empty() {
                        if val.len() > 1024 || val.contains('\0') {
                            return Err("obfs-password 无效".into());
                        }
                        obfs_password = Some(val);
                    }
                }
                "ech" => {
                    if !val.is_empty() {
                        if val.len() > 4096 || !val.bytes().all(|b| b.is_ascii_graphic()) {
                            return Err("ech 参数格式不对".into());
                        }
                        ech = Some(val);
                    }
                }
                "upmbps" => {
                    if !val.is_empty() {
                        let n: u32 = val.parse().ok().filter(|&n| (1..=MAX_MBPS).contains(&n))
                            .ok_or_else(|| format!("upmbps 应为 1–{MAX_MBPS} 之间的整数"))?;
                        up_mbps = Some(n);
                    }
                }
                "downmbps" => {
                    if !val.is_empty() {
                        let n: u32 = val.parse().ok().filter(|&n| (1..=MAX_MBPS).contains(&n))
                            .ok_or_else(|| format!("downmbps 应为 1–{MAX_MBPS} 之间的整数"))?;
                        down_mbps = Some(n);
                    }
                }
                "hop" => {
                    if !val.is_empty() {
                        let n: u32 = val.parse().ok()
                            .ok_or_else(|| "hop 应为整数（秒）".to_string())?;
                        if n < MIN_HOP_SECS {
                            return Err(format!("端口跳跃间隔（hop）至少 {MIN_HOP_SECS} 秒"));
                        }
                        if n > MAX_HOP_SECS {
                            return Err(format!("端口跳跃间隔（hop）最多 {MAX_HOP_SECS} 秒"));
                        }
                        hop_secs = Some(n);
                    }
                }
                "ca" | "cafile" => return Err("不支持：自定义 CA 文件（请改用 pinSHA256 指纹）".into()),
                "client-cert" | "client-key" | "mtls" => return Err("不支持：客户端证书（mTLS）".into()),
                "fastopen" | "init-stream-receive-window" | "max-stream-receive-window"
                | "init-conn-receive-window" | "max-conn-receive-window" | "max-idle-timeout"
                | "keepalive-period" | "mport" => {
                    return Err(format!("不支持：{key}"));
                }
                _ => {
                    return Err(format!("不支持：{key}"));
                }
            }
        }
    }

    if obfs.is_none() && obfs_password.is_some() {
        return Err("写了 obfs-password 但没指定 obfs 混淆类型".into());
    }
    if host.parse::<Ipv4Addr>().is_ok() && sni.is_none() && pin_sha256.is_none() {
        return Err("服务器写成 IP 且没填 sni 时，必须带 pinSHA256 证书指纹".into());
    }

    let summary = format_summary(
        host,
        ports_raw,
        has_port_hopping,
        sni.as_deref(),
        pin_sha256.as_deref(),
        obfs.as_deref(),
        ech.as_deref(),
        up_mbps,
        down_mbps,
        hop_secs,
    );

    Ok(ParsedUri {
        host: host.to_owned(),
        ports: ports_raw.to_owned(),
        first_port,
        has_port_hopping,
        auth,
        sni,
        pin_sha256,
        obfs,
        obfs_password,
        ech,
        up_mbps,
        down_mbps,
        hop_secs,
        name,
        summary,
    })
}

impl HysteriaSpec {
    /// Parses `"hysteria2 <host> <ports> <key=value ...>"` (percent-encoded values)
    /// as sent in the split rule text.
    pub fn parse_rule_line(text: &str) -> Option<Self> {
        let mut parts = text.split_whitespace();
        if parts.next()? != "hysteria2" {
            return None;
        }
        let host = percent_decode(parts.next()?)?;
        if !is_valid_host(&host) {
            return None;
        }
        let ports = percent_decode(parts.next()?)?;
        let _ = parse_ports(&ports).ok()?;

        let mut auth: Option<String> = None;
        let mut sni: Option<String> = None;
        let mut pin_sha256: Option<String> = None;
        let mut obfs: Option<String> = None;
        let mut obfs_password: Option<String> = None;
        let mut ech: Option<String> = None;
        let mut up_mbps: Option<u32> = None;
        let mut down_mbps: Option<u32> = None;
        let mut hop_secs: Option<u32> = None;

        for kv in parts {
            let (k, raw_v) = kv.split_once('=')?;
            let v = percent_decode(raw_v)?;
            match k {
                "auth" => {
                    if v.is_empty() || v.contains('\0') {
                        return None;
                    }
                    auth = Some(v);
                }
                "sni" => {
                    if !is_valid_host(&v) || v.parse::<Ipv4Addr>().is_ok() {
                        return None;
                    }
                    sni = Some(v);
                }
                "pin" | "pinSHA256" => {
                    pin_sha256 = Some(normalize_pin_sha256(&v).ok()?);
                }
                "obfs" => {
                    let lower = v.to_ascii_lowercase();
                    if lower != "salamander" && lower != "gecko" {
                        return None;
                    }
                    obfs = Some(lower);
                }
                "obfs_password" | "obfs-password" => {
                    if v.is_empty() || v.contains('\0') {
                        return None;
                    }
                    obfs_password = Some(v);
                }
                "ech" => {
                    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_graphic()) {
                        return None;
                    }
                    ech = Some(v);
                }
                "upmbps" => {
                    up_mbps = Some(v.parse::<u32>().ok().filter(|&n| (1..=MAX_MBPS).contains(&n))?);
                }
                "downmbps" => {
                    down_mbps = Some(v.parse::<u32>().ok().filter(|&n| (1..=MAX_MBPS).contains(&n))?);
                }
                "hop" => {
                    hop_secs = Some(v.parse::<u32>().ok().filter(|&n| (MIN_HOP_SECS..=MAX_HOP_SECS).contains(&n))?);
                }
                _ => return None,
            }
        }

        let auth = auth?;
        if obfs.is_some() != obfs_password.is_some() {
            return None;
        }
        if host.parse::<Ipv4Addr>().is_ok() && sni.is_none() && pin_sha256.is_none() {
            return None;
        }
        Some(HysteriaSpec {
            host,
            ports,
            auth,
            sni,
            pin_sha256,
            obfs,
            obfs_password,
            ech,
            up_mbps,
            down_mbps,
            hop_secs,
        })
    }

    pub fn to_rule_line(&self) -> String {
        let mut fields = vec![
            "hysteria2".to_string(),
            percent_encode(&self.host),
            percent_encode(&self.ports),
            format!("auth={}", percent_encode(&self.auth)),
        ];
        if let Some(sni) = &self.sni {
            fields.push(format!("sni={}", percent_encode(sni)));
        }
        if let Some(pin) = &self.pin_sha256 {
            fields.push(format!("pin={pin}"));
        }
        if let Some(obfs) = &self.obfs {
            fields.push(format!("obfs={obfs}"));
        }
        if let Some(pw) = &self.obfs_password {
            fields.push(format!("obfs_password={}", percent_encode(pw)));
        }
        if let Some(ech) = &self.ech {
            fields.push(format!("ech={}", percent_encode(ech)));
        }
        if let Some(u) = self.up_mbps {
            fields.push(format!("upmbps={u}"));
        }
        if let Some(d) = self.down_mbps {
            fields.push(format!("downmbps={d}"));
        }
        if let Some(h) = self.hop_secs {
            fields.push(format!("hop={h}"));
        }
        fields.join(" ")
    }

    pub fn has_port_hopping(&self) -> bool {
        parse_ports(&self.ports).is_ok_and(|(_, hop)| hop)
    }

    /// Generates the official Hysteria2 client JSON config.
    /// Uses the already-resolved IPv4 in `server` and keeps the original hostname
    /// (or explicit `sni`) in `tls.sni`, so the client never queries DNS itself.
    pub fn client_config_json(
        &self,
        resolved_ip: Ipv4Addr,
        socks_port: u16,
        socks_user: &str,
        socks_pass: &str,
    ) -> String {
        let mut tls = serde_json::Map::new();
        // In Go's crypto/tls (used by official Hysteria2), VerifyPeerCertificate
        // runs after standard chain verification unless InsecureSkipVerify is
        // true. User links with insecure=1 are always refused; when pinSHA256
        // is set, enabling tls.insecure lets self-signed certs reach Hysteria2's
        // VerifyPeerCertificate, which strictly enforces exact SHA-256 pin match.
        // Without pinSHA256, tls.insecure is always false (strict CA + SNI).
        tls.insert("insecure".into(), serde_json::Value::Bool(self.pin_sha256.is_some()));
        let effective_sni = self
            .sni
            .as_deref()
            .or_else(|| (self.host.parse::<Ipv4Addr>().is_err()).then_some(self.host.as_str()));
        if let Some(sni) = effective_sni {
            tls.insert("sni".into(), serde_json::Value::String(sni.to_owned()));
        }
        if let Some(pin) = &self.pin_sha256 {
            tls.insert("pinSHA256".into(), serde_json::Value::String(pin.clone()));
        }
        if let Some(ech) = &self.ech {
            tls.insert("ech".into(), serde_json::Value::String(ech.clone()));
        }

        let mut root = serde_json::Map::new();
        root.insert("server".into(), serde_json::Value::String(format!("{resolved_ip}:{}", self.ports)));
        root.insert("auth".into(), serde_json::Value::String(self.auth.clone()));
        root.insert("tls".into(), serde_json::Value::Object(tls));
        root.insert("lazy".into(), serde_json::Value::Bool(false));
        root.insert(
            "socks5".into(),
            serde_json::json!({
                "listen": format!("127.0.0.1:{socks_port}"),
                "username": socks_user,
                "password": socks_pass,
                "disableUDP": false,
            }),
        );

        if let (Some(obfs), Some(pw)) = (&self.obfs, &self.obfs_password) {
            if obfs == "salamander" {
                root.insert(
                    "obfs".into(),
                    serde_json::json!({
                        "type": "salamander",
                        "salamander": { "password": pw },
                    }),
                );
            } else if obfs == "gecko" {
                root.insert(
                    "obfs".into(),
                    serde_json::json!({
                        "type": "gecko",
                        "gecko": { "password": pw },
                    }),
                );
            }
        }

        if self.has_port_hopping() {
            let secs = self.hop_secs.unwrap_or(DEFAULT_HOP_SECS);
            root.insert(
                "transport".into(),
                serde_json::json!({
                    "type": "udp",
                    "udp": { "hopInterval": format!("{secs}s") },
                }),
            );
        }

        if self.up_mbps.is_some() || self.down_mbps.is_some() {
            let mut bw = serde_json::Map::new();
            if let Some(u) = self.up_mbps {
                bw.insert("up".into(), serde_json::Value::String(format!("{u} mbps")));
            }
            if let Some(d) = self.down_mbps {
                bw.insert("down".into(), serde_json::Value::String(format!("{d} mbps")));
            }
            root.insert("bandwidth".into(), serde_json::Value::Object(bw));
        }

        serde_json::Value::Object(root).to_string()
    }
}

// MARK: - Log parsing, error classification & redaction

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogEvent {
    Ready,
    Failure(&'static str),
    Ignore,
}

/// Maps a Hysteria2 client error string to a plain-Chinese user reason (§3.2, §5.4).
pub fn classify_error(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("failed to sufficiently increase receive buffer size") {
        return None;
    }
    if lower.contains("authentication error") || lower.contains("auth error") {
        return Some("密码不对");
    }
    if lower.contains("no certificate matches the pinned hash")
        || lower.contains("x509:")
        || lower.contains("bad certificate")
        || lower.contains("unknown authority")
        || lower.contains("certificate is valid for")
        || lower.contains("certificate has expired")
        || lower.contains("tls: failed to verify")
        || lower.contains("crypto_error")
        || (lower.contains("tls") && lower.contains("certificate"))
    {
        return Some("证书对不上");
    }
    if lower.contains("no recent network activity")
        || lower.contains("handshake timeout")
        || lower.contains("i/o timeout")
        || lower.contains("context deadline exceeded")
        || lower.contains("operation not permitted")
        || lower.contains("permission denied")
        || lower.contains("network is unreachable")
        || lower.contains("host is unreachable")
        || lower.contains("no route to host")
    {
        return Some("UDP 出不去");
    }
    if lower.contains("connection refused")
        || lower.contains("protocol error")
        || lower.contains("failed to initialize client")
        || lower.contains("connect error")
        || lower.contains("server closed")
        || lower.contains("eof")
    {
        return Some("服务器没回应");
    }
    None
}

/// Parses one stderr line from `hysteria client --log-format json`.
pub fn parse_log_line(line: &str) -> LogEvent {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return LogEvent::Ignore;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let msg = v.get("msg").and_then(|m| m.as_str()).unwrap_or("");
        let err = v.get("error").and_then(|e| e.as_str()).unwrap_or("");
        if msg == "SOCKS5 server listening" {
            return LogEvent::Ready;
        }
        // Only classify connection/init/auth errors, not benign info/debug lines.
        if !err.is_empty() || msg.contains("failed") || msg.contains("error") {
            let combined = format!("{msg} {err}");
            if let Some(reason) = classify_error(&combined) {
                return LogEvent::Failure(reason);
            }
        }
        return LogEvent::Ignore;
    }
    if trimmed.contains("SOCKS5 server listening") {
        return LogEvent::Ready;
    }
    if let Some(reason) = classify_error(trimmed) {
        return LogEvent::Failure(reason);
    }
    LogEvent::Ignore
}

/// Removes secrets and any `hysteria2://` / `hy2://` URIs before writing a line to logs.
pub fn redact_log_line(line: &str, secrets: &[&str]) -> String {
    let mut out = redact_uris(line);
    for secret in secrets {
        if !secret.is_empty() {
            out = out.replace(secret, "<已隐去>");
        }
    }
    out
}

/// Redacts any `hysteria2://...` or `hy2://...` URI token in arbitrary text.
pub fn redact_uris(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let lower = rest.to_ascii_lowercase();
        let next = ["hysteria2://", "hy2://", "hysteria2+realm://", "hy2+realm://"]
            .iter()
            .filter_map(|p| lower.find(p))
            .min();
        let Some(pos) = next else {
            result.push_str(rest);
            break;
        };
        result.push_str(&rest[..pos]);
        result.push_str("<已隐去>");
        let after = &rest[pos..];
        let end = after
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | ']' | '>' | ','))
            .unwrap_or(after.len());
        rest = &after[end..];
    }
    result
}

// MARK: - Pure supervisor state machine (unit-tested without processes)

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotAction {
    Start { index: usize, generation: u64 },
    Stop { index: usize, generation: u64 },
}

#[derive(Clone, Debug)]
struct SlotRecord {
    spec: HysteriaSpec,
    resolved_ip: Option<Ipv4Addr>,
    generation: u64,
    backoff_step: usize,
    next_retry_at: Option<Instant>,
    running: bool,
    last_error: Option<String>,
}

/// Pure supervisor planner: decides which Hysteria2 slots to start, keep,
/// restart, backoff-retry, or stop during handover/teardown.
#[derive(Default)]
pub struct SupervisorPlan {
    slots: BTreeMap<usize, SlotRecord>,
    next_gen: u64,
    handover_until: Option<Instant>,
}

impl SupervisorPlan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconciles desired specs (and their resolved IPs) against active slots.
    /// Unchanged slots stay alive without restart (including across handover).
    pub fn sync(
        &mut self,
        desired: &BTreeMap<usize, (HysteriaSpec, Option<Ipv4Addr>)>,
    ) -> Vec<SlotAction> {
        self.handover_until = None;
        let mut actions = Vec::new();
        let existing_keys: Vec<usize> = self.slots.keys().copied().collect();
        for idx in existing_keys {
            match desired.get(&idx) {
                Some((spec, ip)) => {
                    let slot = &self.slots[&idx];
                    if slot.spec == *spec && slot.resolved_ip == *ip {
                        continue; // Keep running across rule updates or handover!
                    }
                    let old_gen = slot.generation;
                    actions.push(SlotAction::Stop { index: idx, generation: old_gen });
                    self.slots.remove(&idx);
                }
                None => {
                    if let Some(old) = self.slots.remove(&idx) {
                        actions.push(SlotAction::Stop { index: idx, generation: old.generation });
                    }
                }
            }
        }
        for (&idx, (spec, ip)) in desired {
            if !self.slots.contains_key(&idx) {
                self.next_gen += 1;
                let gen = self.next_gen;
                self.slots.insert(
                    idx,
                    SlotRecord {
                        spec: spec.clone(),
                        resolved_ip: *ip,
                        generation: gen,
                        backoff_step: 0,
                        next_retry_at: None,
                        running: true,
                        last_error: None,
                    },
                );
                actions.push(SlotAction::Start { index: idx, generation: gen });
            }
        }
        actions
    }

    pub fn on_ready(&mut self, index: usize, generation: u64) {
        if let Some(slot) = self.slots.get_mut(&index) {
            if slot.generation == generation {
                slot.backoff_step = 0;
                slot.last_error = None;
                slot.next_retry_at = None;
            }
        }
    }

    /// Returns the backoff delay before restarting an unexpectedly exited child.
    pub fn on_exit(
        &mut self,
        index: usize,
        generation: u64,
        reason: Option<String>,
        now: Instant,
    ) -> Option<Duration> {
        let slot = self.slots.get_mut(&index)?;
        if slot.generation != generation {
            return None;
        }
        slot.running = false;
        if let Some(r) = reason {
            slot.last_error = Some(r);
        }
        let secs = BACKOFF_SECS[slot.backoff_step.min(BACKOFF_SECS.len() - 1)];
        slot.backoff_step = (slot.backoff_step + 1).min(BACKOFF_SECS.len() - 1);
        let delay = Duration::from_secs(secs);
        slot.next_retry_at = Some(now + delay);
        Some(delay)
    }

    /// Returns slots whose backoff timer has elapsed.
    pub fn due_retries(&mut self, now: Instant) -> Vec<SlotAction> {
        let mut actions = Vec::new();
        for (&idx, slot) in self.slots.iter_mut() {
            if !slot.running && slot.next_retry_at.is_some_and(|t| now >= t) {
                self.next_gen += 1;
                slot.generation = self.next_gen;
                slot.running = true;
                slot.next_retry_at = None;
                actions.push(SlotAction::Start { index: idx, generation: slot.generation });
            }
        }
        actions
    }

    /// Marks handover: existing slots stay alive until `now + grace`.
    pub fn begin_handover(&mut self, now: Instant, grace: Duration) {
        if !self.slots.is_empty() {
            self.handover_until = Some(now + grace);
        }
    }

    /// If handover expired without a new owner calling `sync`, stops all slots.
    pub fn expire_handover(&mut self, now: Instant) -> Vec<SlotAction> {
        if self.handover_until.is_some_and(|t| now >= t) {
            return self.stop_all();
        }
        Vec::new()
    }

    pub fn stop_all(&mut self) -> Vec<SlotAction> {
        self.handover_until = None;
        let mut actions = Vec::new();
        for (idx, slot) in std::mem::take(&mut self.slots) {
            actions.push(SlotAction::Stop { index: idx, generation: slot.generation });
        }
        actions
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

// MARK: - Random bytes, binary checks & private config files

fn random_hex(bytes: usize) -> std::io::Result<String> {
    let mut f = std::fs::File::open("/dev/urandom")?;
    let mut buf = vec![0u8; bytes];
    f.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn free_loopback_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

/// Checks the bundled client's code signature against this service's own
/// certificate (the platform shell does it: Security.framework).
pub type Verifier = extern "C" fn(*const std::os::raw::c_char) -> bool;

/// What a verified file looked like: a replaced or rewritten file is checked again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileIdentity {
    fn of(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        FileIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

#[derive(Clone, Debug)]
struct BinaryConfig {
    path: PathBuf,
    verifier: Option<Verifier>,
    /// The file as it was when its signature last checked out.
    verified: Option<FileIdentity>,
    test_mode: bool,
}

static BINARY_CONFIG: OnceLock<Mutex<BinaryConfig>> = OnceLock::new();

fn binary_config() -> &'static Mutex<BinaryConfig> {
    BINARY_CONFIG.get_or_init(|| {
        Mutex::new(BinaryConfig { path: PathBuf::from(BUNDLED_BIN), verifier: None, verified: None, test_mode: false })
    })
}

/// Set by the service at start: where the client is and how to check its
/// signature. The check itself waits until a client is about to run, so a
/// service start without Hysteria2 proxies never reads the 20-odd MB file.
/// `test_mode` (non-root harnesses and examples): any existing file runs.
pub fn configure_binary(path: PathBuf, verifier: Option<Verifier>, test_mode: bool) {
    let mut cfg = binary_config().lock().unwrap();
    *cfg = BinaryConfig { path, verifier, verified: None, test_mode };
}

/// Every directory from `path`'s parent up to `/`: a real directory, owned
/// by root, writable by nobody else.
fn root_private_ancestors(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    path.ancestors().skip(1).filter(|p| !p.as_os_str().is_empty()).all(|dir| {
        std::fs::symlink_metadata(dir)
            .is_ok_and(|m| m.file_type().is_dir() && m.uid() == 0 && (m.mode() & 0o022) == 0)
    })
}

/// The client to run, as root only a root-private file whose signature
/// carries our certificate (checked once per file version, before its
/// first run; DESIGN §七十, AGENTS 提权与进程边界).
fn resolve_verified_binary() -> Result<PathBuf, &'static str> {
    use std::os::unix::fs::MetadataExt;
    let mut cfg = binary_config().lock().unwrap();
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root && !cfg.test_mode {
        let meta = std::fs::symlink_metadata(&cfg.path)
            .map_err(|_| "未找到 Hysteria2 组件，请重新安装或更新后台服务")?;
        if !meta.file_type().is_file() || meta.uid() != 0 || (meta.mode() & 0o022) != 0 {
            return Err("Hysteria2 组件权限异常，已拒绝启动");
        }
        if !root_private_ancestors(&cfg.path) {
            return Err("Hysteria2 组件目录权限异常，已拒绝启动");
        }
        let identity = FileIdentity::of(&meta);
        if cfg.verified != Some(identity) {
            cfg.verified = None;
            let Some(verifier) = cfg.verifier else {
                return Err("未找到已验证签名的 Hysteria2 组件，请重新安装或更新后台服务");
            };
            let Ok(c_path) = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(cfg.path.as_os_str())) else {
                return Err("Hysteria2 组件路径无效");
            };
            if !verifier(c_path.as_ptr()) {
                return Err("Hysteria2 组件签名不对，已拒绝启动，请重新安装或更新后台服务");
            }
            // Unchanged while it was being checked: this is the file that runs.
            let after = std::fs::symlink_metadata(&cfg.path).map(|m| FileIdentity::of(&m));
            if after.ok() != Some(identity) {
                return Err("Hysteria2 组件在检查时被改动，已拒绝启动");
            }
            cfg.verified = Some(identity);
        }
        return Ok(cfg.path.clone());
    }
    if cfg.path.is_file() {
        return Ok(cfg.path.clone());
    }
    if let Ok(env_path) = std::env::var("ALWAYSCONNECT_TEST_HYSTERIA") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    Err("未找到 Hysteria2 组件")
}

struct PrivateConfigDir {
    dir: PathBuf,
    config_file: PathBuf,
}

impl PrivateConfigDir {
    /// Creates a private config directory with a 128-bit random name and writes
    /// `config.json`. When running as root, the parent dir is `0711 root:wheel`
    /// (unbrowseable by non-root), the child dir is `0700 nobody`, and the file
    /// is `0400 nobody`.
    fn create(contents: &str, as_nobody: Option<(u32, u32)>) -> std::io::Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let parent = if as_nobody.is_some() {
            let p = PathBuf::from(RUNTIME_DIR);
            std::fs::create_dir_all(&p)?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o711))?;
            p
        } else {
            let p = std::env::temp_dir().join(format!("ac-hysteria-{}", std::process::id()));
            std::fs::create_dir_all(&p)?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))?;
            p
        };
        let token = random_hex(16)?;
        let dir = parent.join(format!("run-{token}"));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let config_file = dir.join("config.json");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&config_file)?;
        f.write_all(contents.as_bytes())?;
        drop(f);
        if let Some((uid, gid)) = as_nobody {
            chown_path(&dir, uid, gid)?;
            chown_path(&config_file, uid, gid)?;
        }
        Ok(PrivateConfigDir { dir, config_file })
    }

    fn remove_file_only(&self) {
        let _ = std::fs::remove_file(&self.config_file);
    }
}

impl Drop for PrivateConfigDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.config_file);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad path"))?;
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn nobody_ids() -> Option<(u32, u32)> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let pw = unsafe { libc::getpwnam(c"nobody".as_ptr()) };
    if pw.is_null() {
        return None;
    }
    Some(unsafe { ((*pw).pw_uid, (*pw).pw_gid) })
}

/// Removes any leftover config directories from an earlier crashed Helper.
pub fn clean_runtime_dir() {
    let dir = Path::new(RUNTIME_DIR);
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("run-"))
            {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}

fn spawn_hysteria(bin: &Path, config_path: &Path, as_nobody: Option<(u32, u32)>) -> std::io::Result<Child> {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(bin);
    cmd.args(["client", "-c"])
        .arg(config_path)
        .args(["--log-format", "json", "--log-level", "info", "--disable-update-check"])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some((uid, gid)) = as_nobody {
        cmd.uid(uid).gid(gid);
    }
    crate::reset_child_signals(&mut cmd);
    crate::child_io::spawn(&mut cmd)
}

fn terminate_child(child: &mut Child) {
    let pid = child.id() as i32;
    if pid > 0 {
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// MARK: - Live Managed Client Process & Manager

struct LiveProcess {
    spec: HysteriaSpec,
    resolved_ip: Ipv4Addr,
    local_server: Server,
    generation: u64,
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    last_reason: Arc<Mutex<Option<String>>>,
    ready: Arc<AtomicBool>,
}

impl LiveProcess {
    fn terminate(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(mut child) = self.child.lock().unwrap().take() {
            terminate_child(&mut child);
        }
    }
}

pub type HostResolver = Arc<dyn Fn(&str) -> Vec<Ipv4Addr> + Send + Sync>;

fn resolve_host_ipv4(host: &str, resolver: Option<&HostResolver>) -> Option<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    if let Some(res) = resolver {
        if let Some(ip) = res(host).into_iter().find(|ip| !super::is_fake(*ip)) {
            return Some(ip);
        }
    }
    (host, 443)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(ip) if !super::is_fake(ip) => Some(ip),
            _ => None,
        })
}

/// Process-wide manager of running Hysteria2 client children, shared across
/// `ProxyOnly` and `oc_engine` so handover keeps unchanged tunnels alive.
pub struct HysteriaManager {
    inner: Arc<Mutex<ManagerInner>>,
    next_gen: AtomicU64,
}

#[derive(Default)]
struct ManagerInner {
    routing: Option<Arc<Routing>>,
    resolver: Option<HostResolver>,
    specs: BTreeMap<usize, HysteriaSpec>,
    live: HashMap<usize, LiveProcess>,
    backoff_steps: HashMap<usize, usize>,
    handover_token: u64,
}

static MANAGER: OnceLock<HysteriaManager> = OnceLock::new();

pub fn shared() -> &'static HysteriaManager {
    MANAGER.get_or_init(|| HysteriaManager {
        inner: Arc::new(Mutex::new(ManagerInner::default())),
        next_gen: AtomicU64::new(1),
    })
}

impl HysteriaManager {
    /// Brings running Hysteria2 processes in line with `specs` for `routing`.
    /// Unchanged entries stay running and are immediately re-bound into
    /// `routing`. Never waits for DNS: a server named by a domain is looked
    /// up again on a background thread, and its client is restarted only if
    /// the address changed (a network switch, a dynamic-DNS server).
    pub fn sync(
        &self,
        specs: BTreeMap<usize, HysteriaSpec>,
        routing: Arc<Routing>,
        resolver: Option<HostResolver>,
    ) {
        let mut to_stop = Vec::new();
        let mut to_start = Vec::new();
        let mut recheck = Vec::new();
        {
            let mut st = self.inner.lock().unwrap();
            st.handover_token = st.handover_token.wrapping_add(1);
            st.routing = Some(routing.clone());
            st.resolver = resolver.clone();
            st.specs = specs.clone();

            let existing: Vec<usize> = st.live.keys().copied().collect();
            for idx in existing {
                let keep = specs.get(&idx).is_some_and(|want| st.live[&idx].spec == *want);
                if !keep {
                    if let Some(proc) = st.live.remove(&idx) {
                        to_stop.push(proc);
                    }
                    st.backoff_steps.remove(&idx);
                } else {
                    let proc = &st.live[&idx];
                    if proc.spec.host.parse::<Ipv4Addr>().is_err() {
                        recheck.push((idx, proc.spec.clone(), proc.resolved_ip, proc.generation));
                    }
                    if proc.ready.load(Ordering::Acquire) {
                        routing.set_managed_ready(idx, proc.local_server.clone(), proc.resolved_ip, proc.spec.ports.clone());
                    } else if let Some(reason) = proc.last_reason.lock().unwrap().clone() {
                        routing.set_managed_unavailable(idx, reason);
                    } else {
                        routing.set_managed_unavailable(idx, "正在连接 Hysteria2 代理".into());
                    }
                }
            }

            for (idx, spec) in specs {
                if !st.live.contains_key(&idx) {
                    routing.set_managed_unavailable(idx, "正在连接 Hysteria2 代理".into());
                    let gen = self.next_gen.fetch_add(1, Ordering::Relaxed);
                    to_start.push((idx, spec, gen));
                }
            }
        }

        for proc in to_stop {
            proc.terminate();
        }
        for (idx, spec, gen) in to_start {
            self.launch_slot(idx, spec, gen, routing.clone(), resolver.clone());
        }
        if !recheck.is_empty() {
            let inner = self.inner.clone();
            std::thread::Builder::new()
                .name("ac-hy2-recheck".into())
                .spawn(move || Self::recheck_addresses(inner, recheck, resolver))
                .ok();
        }
    }

    /// Restarts a running client whose server name now resolves to another
    /// address; the same process, untouched in the meantime, only.
    fn recheck_addresses(
        inner: Arc<Mutex<ManagerInner>>,
        running: Vec<(usize, HysteriaSpec, Ipv4Addr, u64)>,
        resolver: Option<HostResolver>,
    ) {
        for (idx, spec, old_ip, gen) in running {
            let Some(ip) = resolve_host_ipv4(&spec.host, resolver.as_ref()) else { continue };
            if ip == old_ip {
                continue;
            }
            let (stale, routing, resolver) = {
                let mut st = inner.lock().unwrap();
                if st.specs.get(&idx) != Some(&spec) || !st.live.get(&idx).is_some_and(|p| p.generation == gen) {
                    continue;
                }
                let Some(routing) = st.routing.clone() else { continue };
                st.backoff_steps.remove(&idx);
                (st.live.remove(&idx), routing, st.resolver.clone())
            };
            network_guard::log(&format!("hysteria2[{idx}]: server address changed, restarting the client"));
            if let Some(stale) = stale {
                stale.terminate();
            }
            routing.set_managed_unavailable(idx, "正在连接 Hysteria2 代理".into());
            let gen = shared().next_gen.fetch_add(1, Ordering::Relaxed);
            shared().launch_slot(idx, spec, gen, routing, resolver);
        }
    }

    /// Keeps running clients alive for `HANDOVER_GRACE` while ownership switches
    /// between `ProxyOnly` and `oc_engine`. If no new owner claims them in time,
    /// stops all of them.
    pub fn begin_handover(&self) {
        let token = {
            let mut st = self.inner.lock().unwrap();
            if st.live.is_empty() && st.specs.is_empty() {
                return;
            }
            st.handover_token = st.handover_token.wrapping_add(1);
            st.handover_token
        };
        let inner = self.inner.clone();
        std::thread::Builder::new()
            .name("ac-hy2-handover".into())
            .spawn(move || {
                std::thread::sleep(HANDOVER_GRACE);
                let to_stop: Vec<LiveProcess> = {
                    let mut st = inner.lock().unwrap();
                    if st.handover_token != token {
                        return;
                    }
                    st.routing = None;
                    st.resolver = None;
                    st.specs.clear();
                    st.backoff_steps.clear();
                    st.live.drain().map(|(_, p)| p).collect()
                };
                for p in to_stop {
                    p.terminate();
                }
            })
            .ok();
    }

    /// Stops all managed Hysteria2 clients immediately.
    pub fn stop_all(&self) {
        let to_stop: Vec<LiveProcess> = {
            let mut st = self.inner.lock().unwrap();
            st.handover_token = st.handover_token.wrapping_add(1);
            st.routing = None;
            st.resolver = None;
            st.specs.clear();
            st.backoff_steps.clear();
            st.live.drain().map(|(_, p)| p).collect()
        };
        for p in to_stop {
            p.terminate();
        }
    }

    /// Returns the active forwarder's plain resolver, if a redirect session is running.
    pub fn active_resolver(&self) -> Option<HostResolver> {
        self.inner.lock().unwrap().resolver.clone()
    }

    /// If an identical Hysteria2 spec is already running and ready, returns its
    /// local SOCKS5 server so health checks can reuse it with zero extra processes.
    pub fn running_socks_for(&self, spec: &HysteriaSpec) -> Option<Server> {
        let st = self.inner.lock().unwrap();
        st.live.values().find_map(|p| {
            (p.spec == *spec && p.ready.load(Ordering::Acquire)).then(|| p.local_server.clone())
        })
    }

    fn launch_slot(
        &self,
        idx: usize,
        spec: HysteriaSpec,
        gen: u64,
        routing: Arc<Routing>,
        resolver: Option<HostResolver>,
    ) {
        let inner = self.inner.clone();
        std::thread::Builder::new()
            .name(format!("ac-hy2-{idx}"))
            .spawn(move || {
                let inner_retry = inner.clone();
                let routing_retry = routing.clone();
                let spec_retry = spec.clone();
                let fail_and_retry = move |reason: String| {
                    routing_retry.set_managed_unavailable(idx, reason.clone());
                    routing_retry.record(idx, Some(&reason));
                    let delay = {
                        let mut st = inner_retry.lock().unwrap();
                        if st.specs.get(&idx) != Some(&spec_retry) {
                            return;
                        }
                        if st.live.get(&idx).is_some_and(|p| p.generation == gen) {
                            st.live.remove(&idx);
                        }
                        let step = st.backoff_steps.entry(idx).or_insert(0);
                        let secs = BACKOFF_SECS[(*step).min(BACKOFF_SECS.len() - 1)];
                        *step = (*step + 1).min(BACKOFF_SECS.len() - 1);
                        Duration::from_secs(secs)
                    };
                    std::thread::sleep(delay);
                    let next = {
                        let st = inner_retry.lock().unwrap();
                        if st.specs.get(&idx) != Some(&spec_retry) || st.live.contains_key(&idx) {
                            return;
                        }
                        (st.routing.clone(), st.resolver.clone())
                    };
                    if let Some(r) = next.0 {
                        let new_gen = shared().next_gen.fetch_add(1, Ordering::Relaxed);
                        shared().launch_slot(idx, spec_retry, new_gen, r, next.1);
                    }
                };

                let bin = match resolve_verified_binary() {
                    Ok(b) => b,
                    Err(msg) => {
                        network_guard::log(&format!("hysteria2[{idx}]: {msg}"));
                        fail_and_retry(msg.to_string());
                        return;
                    }
                };
                let Some(resolved_ip) = resolve_host_ipv4(&spec.host, resolver.as_ref()) else {
                    network_guard::log(&format!("hysteria2[{idx}]: could not resolve server host"));
                    fail_and_retry("服务器地址无法解析".to_string());
                    return;
                };
                let Ok(port) = free_loopback_port() else {
                    fail_and_retry("无法分配本机端口".to_string());
                    return;
                };
                let (Ok(user), Ok(pass)) = (random_hex(12), random_hex(16)) else {
                    fail_and_retry("无法生成临时凭据".to_string());
                    return;
                };
                let cfg_json = spec.client_config_json(resolved_ip, port, &user, &pass);
                let as_nobody = nobody_ids();
                let cfg_dir = match PrivateConfigDir::create(&cfg_json, as_nobody) {
                    Ok(d) => d,
                    Err(e) => {
                        network_guard::log(&format!("hysteria2[{idx}]: config dir failed: {e}"));
                        fail_and_retry("无法准备 Hysteria2 临时配置".to_string());
                        return;
                    }
                };
                let mut child = match spawn_hysteria(&bin, &cfg_dir.config_file, as_nobody) {
                    Ok(c) => c,
                    Err(e) => {
                        network_guard::log(&format!("hysteria2[{idx}]: spawn failed: {e}"));
                        fail_and_retry("Hysteria2 客户端启动失败".to_string());
                        return;
                    }
                };
                let stderr = child.stderr.take();
                let stop = Arc::new(AtomicBool::new(false));
                let ready = Arc::new(AtomicBool::new(false));
                let last_reason: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
                let local_server = Server {
                    kind: Kind::Socks5,
                    host: "127.0.0.1".into(),
                    port,
                    auth: Some((user.clone(), pass.clone())),
                };
                let child_slot = Arc::new(Mutex::new(Some(child)));
                {
                    let mut st = inner.lock().unwrap();
                    // Gone from the wanted list, or another launch for this
                    // slot (a retry racing a sync) got there first: one
                    // client per slot, never an orphan.
                    if st.specs.get(&idx) != Some(&spec) || st.live.contains_key(&idx) {
                        drop(st);
                        if let Some(mut c) = child_slot.lock().unwrap().take() {
                            terminate_child(&mut c);
                        }
                        return;
                    }
                    st.live.insert(
                        idx,
                        LiveProcess {
                            spec: spec.clone(),
                            resolved_ip,
                            local_server: local_server.clone(),
                            generation: gen,
                            stop: stop.clone(),
                            child: child_slot.clone(),
                            last_reason: last_reason.clone(),
                            ready: ready.clone(),
                        },
                    );
                }

                // Read stderr until EOF (child exits).
                let secrets: Vec<String> = [
                    Some(spec.auth.clone()),
                    spec.obfs_password.clone(),
                    Some(user.clone()),
                    Some(pass.clone()),
                ]
                .into_iter()
                .flatten()
                .collect();
                let secret_refs: Vec<&str> = secrets.iter().map(String::as_str).collect();

                if let Some(err_stream) = stderr {
                    let reader = BufReader::new(err_stream);
                    for line in reader.lines().map_while(Result::ok) {
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        match parse_log_line(&line) {
                            LogEvent::Ready => {
                                cfg_dir.remove_file_only();
                                ready.store(true, Ordering::Release);
                                {
                                    let mut st = inner.lock().unwrap();
                                    st.backoff_steps.insert(idx, 0);
                                }
                                let active_routing = inner.lock().unwrap().routing.clone().unwrap_or_else(|| routing.clone());
                                active_routing.set_managed_ready(idx, local_server.clone(), resolved_ip, spec.ports.clone());
                                active_routing.record(idx, None);
                            }
                            LogEvent::Failure(reason) => {
                                *last_reason.lock().unwrap() = Some(reason.to_string());
                                let active_routing = inner.lock().unwrap().routing.clone().unwrap_or_else(|| routing.clone());
                                if !ready.load(Ordering::Acquire) {
                                    active_routing.set_managed_unavailable(idx, reason.to_string());
                                }
                                active_routing.record(idx, Some(reason));
                                let clean = redact_log_line(&line, &secret_refs);
                                network_guard::log(&format!("hysteria2[{idx}]: {reason} ({clean})"));
                            }
                            LogEvent::Ignore => {}
                        }
                    }
                }

                // Reap child
                if let Some(mut c) = child_slot.lock().unwrap().take() {
                    let _ = c.wait();
                }
                drop(cfg_dir);

                if stop.load(Ordering::Acquire) {
                    return;
                }
                let reason = last_reason
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| "服务器没回应".to_string());
                fail_and_retry(reason);
            })
            .ok();
    }
}

// MARK: - On-demand probe (pre-save check & Settings check)

/// Probes a candidate Hysteria2 proxy: reuses an already-running managed client
/// if identical, otherwise starts a temporary unprivileged client, waits for
/// handshake/SOCKS5 readiness, and (when `site` is given) asks it to open `site:443`.
pub fn probe_hysteria(
    spec: &HysteriaSpec,
    site: Option<&str>,
    resolver: Option<&HostResolver>,
) -> Probe {
    let started = Instant::now();
    let done = |level: Level, text: String| Probe {
        level,
        text,
        millis: started.elapsed().as_millis() as u64,
    };

    // Fast path: identical proxy is already running in the manager.
    if let Some(existing) = shared().running_socks_for(spec) {
        return probe_socks(&existing, site);
    }

    let bin = match resolve_verified_binary() {
        Ok(b) => b,
        Err(msg) => return done(Level::Fail, msg.to_string()),
    };
    let active_resolver = resolver.cloned().or_else(|| shared().active_resolver());
    let Some(resolved_ip) = resolve_host_ipv4(&spec.host, active_resolver.as_ref()) else {
        return done(Level::Fail, "服务器地址无法解析".into());
    };
    let Ok(port) = free_loopback_port() else {
        return done(Level::Fail, "无法分配本机端口".into());
    };
    let (Ok(user), Ok(pass)) = (random_hex(12), random_hex(16)) else {
        return done(Level::Fail, "无法生成临时凭据".into());
    };
    let cfg_json = spec.client_config_json(resolved_ip, port, &user, &pass);
    let as_nobody = nobody_ids();
    let cfg_dir = match PrivateConfigDir::create(&cfg_json, as_nobody) {
        Ok(d) => d,
        Err(_) => return done(Level::Fail, "无法准备 Hysteria2 临时配置".into()),
    };
    let mut child = match spawn_hysteria(&bin, &cfg_dir.config_file, as_nobody) {
        Ok(c) => c,
        Err(_) => return done(Level::Fail, "Hysteria2 客户端启动失败".into()),
    };
    struct ChildGuard(Option<Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut c) = self.0.take() {
                terminate_child(&mut c);
            }
        }
    }
    let stderr = child.stderr.take();
    let _guard = ChildGuard(Some(child));

    let (tx, rx) = std::sync::mpsc::channel::<Result<(), &'static str>>();
    if let Some(err_stream) = stderr {
        std::thread::Builder::new()
            .name("ac-hy2-probe".into())
            .spawn(move || {
                let mut last_err: Option<&'static str> = None;
                for line in BufReader::new(err_stream).lines().map_while(Result::ok) {
                    match parse_log_line(&line) {
                        LogEvent::Ready => {
                            let _ = tx.send(Ok(()));
                            return;
                        }
                        LogEvent::Failure(reason) => {
                            last_err = Some(reason);
                        }
                        LogEvent::Ignore => {}
                    }
                }
                let _ = tx.send(Err(last_err.unwrap_or("服务器没回应")));
            })
            .ok();
    }

    match rx.recv_timeout(PROBE_STARTUP_TIMEOUT) {
        Ok(Ok(())) => {
            cfg_dir.remove_file_only();
            let local = Server {
                kind: Kind::Socks5,
                host: "127.0.0.1".into(),
                port,
                auth: Some((user, pass)),
            };
            let result = probe_socks(&local, site);
            // Keep total elapsed millis from start of probe so user sees real latency.
            Probe {
                level: result.level,
                text: result.text,
                millis: started.elapsed().as_millis() as u64,
            }
        }
        Ok(Err(reason)) => done(Level::Fail, reason.to_string()),
        Err(_) => done(Level::Fail, "UDP 出不去".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_parses_all_supported_parameters_and_defaults() {
        let u = parse_uri(
            "hy2://user%3Ap%40ss@203.0.113.10:443,20000-50000/?sni=edge.example.com&pinSHA256=AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99&obfs=salamander&obfs-password=ob%20fs&ech=QUJDRA==&upmbps=50&downmbps=200&hop=15#%E7%A4%BA%E4%BE%8B%E8%8A%82%E7%82%B9",
        )
        .expect("valid uri");
        assert_eq!(u.host, "203.0.113.10");
        assert_eq!(u.ports, "443,20000-50000");
        assert_eq!(u.first_port, 443);
        assert!(u.has_port_hopping);
        assert_eq!(u.auth.as_deref(), Some("user:p@ss"));
        assert_eq!(u.sni.as_deref(), Some("edge.example.com"));
        assert_eq!(
            u.pin_sha256.as_deref(),
            Some("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
        );
        assert_eq!(u.obfs.as_deref(), Some("salamander"));
        assert_eq!(u.obfs_password.as_deref(), Some("ob fs"));
        assert_eq!(u.ech.as_deref(), Some("QUJDRA=="));
        assert_eq!(u.up_mbps, Some(50));
        assert_eq!(u.down_mbps, Some(200));
        assert_eq!(u.hop_secs, Some(15));
        assert_eq!(u.name.as_deref(), Some("示例节点"));
        assert!(u.summary.contains("Hysteria2"));
        assert!(u.summary.contains("端口跳跃（每 15 秒）"));
        assert!(u.summary.contains("证书指纹已固定"));
        assert!(u.summary.contains("salamander 混淆"));
        assert!(u.summary.contains("上 50 / 下 200 Mbps"));

        // Default port 443 & gecko obfs
        let d = parse_uri("hysteria2://pw@proxy.example.com/?obfs=gecko&obfs-password=gp").expect("default port");
        assert_eq!(d.ports, "443");
        assert_eq!(d.first_port, 443);
        assert!(!d.has_port_hopping);
        assert_eq!(d.obfs.as_deref(), Some("gecko"));
    }

    #[test]
    fn uri_refuses_insecure_ipv6_ip_without_sni_or_pin_and_unsupported() {
        assert!(parse_uri("hy2://pw@proxy.example.com:443/?insecure=1")
            .unwrap_err()
            .contains("pinSHA256"));
        assert!(parse_uri("hy2://pw@proxy.example.com:443/?insecure=true")
            .unwrap_err()
            .contains("insecure"));
        assert!(parse_uri("hy2://pw@proxy.example.com:443/?insecure=0").is_ok());

        // IP without sni requires pinSHA256
        assert!(parse_uri("hy2://pw@203.0.113.10:443").unwrap_err().contains("pinSHA256"));
        let pin = "0".repeat(64);
        assert!(parse_uri(&format!("hy2://pw@203.0.113.10:443/?pinSHA256={pin}")).is_ok());
        assert!(parse_uri("hy2://pw@203.0.113.10:443/?sni=edge.example.com").is_ok());

        // IPv6 refused
        assert!(parse_uri("hy2://pw@[2001:db8::1]:443").unwrap_err().contains("IPv6"));
        // Realm refused
        assert!(parse_uri("hysteria2+realm://tok@rendezvous.example.com/room?auth=pw")
            .unwrap_err()
            .contains("不支持"));
        // Unsupported params never silently dropped
        assert!(parse_uri("hy2://pw@proxy.example.com:443/?ca=/tmp/ca.pem")
            .unwrap_err()
            .contains("不支持"));
        assert!(parse_uri("hy2://pw@proxy.example.com:443/?unknown=1")
            .unwrap_err()
            .contains("不支持：unknown"));
        assert!(parse_uri("hy2://pw@proxy.example.com:443/?hop=4")
            .unwrap_err()
            .contains("至少 5 秒"));
        assert!(parse_uri("hy2://pw@proxy.example.com:50000-20000")
            .unwrap_err()
            .contains("大于"));
    }

    #[test]
    fn rule_line_round_trip_and_config_generation_keep_secrets_safe() {
        let pin = "ab".repeat(32);
        let spec = HysteriaSpec {
            host: "proxy.example.com".into(),
            ports: "20000-50000".into(),
            auth: "sec ret%1:2".into(),
            sni: Some("cdn.example.com".into()),
            pin_sha256: Some(pin.clone()),
            obfs: Some("salamander".into()),
            obfs_password: Some("obfs pw".into()),
            ech: Some("QUJD".into()),
            up_mbps: Some(50),
            down_mbps: Some(200),
            hop_secs: Some(20),
        };
        let line = spec.to_rule_line();
        assert_eq!(HysteriaSpec::parse_rule_line(&line), Some(spec.clone()));
        // Debug never exposes passwords
        let dbg = format!("{spec:?}");
        assert!(!dbg.contains("sec ret") && !dbg.contains("obfs pw"));

        // Old Server::parse refuses hysteria2 (fail closed on older service)
        assert!(Server::parse(&line).is_none());

        // Client JSON puts resolved IP in server and keeps sni separate
        let json_str = spec.client_config_json(Ipv4Addr::new(203, 0, 113, 10), 18080, "u1", "p1");
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["server"], "203.0.113.10:20000-50000");
        assert_eq!(v["tls"]["sni"], "cdn.example.com");
        assert_eq!(v["tls"]["insecure"], true, "pinSHA256 enables VerifyPeerCertificate for self-signed certs");
        assert_eq!(v["tls"]["pinSHA256"], pin);
        let mut no_pin = spec.clone();
        no_pin.pin_sha256 = None;
        let v2: serde_json::Value =
            serde_json::from_str(&no_pin.client_config_json(Ipv4Addr::new(203, 0, 113, 10), 18080, "u1", "p1")).unwrap();
        assert_eq!(v2["tls"]["insecure"], false, "without pinSHA256, strict CA verification is always enforced");
        assert_eq!(v["tls"]["ech"], "QUJD");
        assert_eq!(v["obfs"]["type"], "salamander");
        assert_eq!(v["obfs"]["salamander"]["password"], "obfs pw");
        assert_eq!(v["transport"]["udp"]["hopInterval"], "20s");
        assert_eq!(v["bandwidth"]["up"], "50 mbps");
        assert_eq!(v["bandwidth"]["down"], "200 mbps");
        assert_eq!(v["socks5"]["listen"], "127.0.0.1:18080");
        assert_eq!(v["socks5"]["username"], "u1");
        assert_eq!(v["socks5"]["password"], "p1");
        assert_eq!(v["socks5"]["disableUDP"], false);
    }

    #[test]
    fn error_classification_and_redaction() {
        assert_eq!(
            parse_log_line(r#"{"level":"info","msg":"SOCKS5 server listening","addr":"127.0.0.1:1234"}"#),
            LogEvent::Ready
        );
        assert_eq!(
            parse_log_line(r#"{"level":"fatal","msg":"failed to initialize client","error":"authentication error, HTTP status code: 404"}"#),
            LogEvent::Failure("密码不对")
        );
        assert_eq!(
            parse_log_line(r#"{"level":"fatal","msg":"failed to initialize client","error":"connect error: no certificate matches the pinned hash"}"#),
            LogEvent::Failure("证书对不上")
        );
        assert_eq!(
            parse_log_line(r#"{"level":"fatal","msg":"failed to initialize client","error":"connect error: x509: certificate signed by unknown authority"}"#),
            LogEvent::Failure("证书对不上")
        );
        assert_eq!(
            parse_log_line(r#"{"level":"fatal","msg":"failed to initialize client","error":"connect error: timeout: no recent network activity"}"#),
            LogEvent::Failure("UDP 出不去")
        );
        assert_eq!(
            parse_log_line(r#"{"level":"fatal","msg":"failed to initialize client","error":"connect error: write udp: operation not permitted"}"#),
            LogEvent::Failure("UDP 出不去")
        );
        assert_eq!(
            parse_log_line(r#"{"level":"fatal","msg":"failed to initialize client","error":"connect error: read udp: connection refused"}"#),
            LogEvent::Failure("服务器没回应")
        );
        // Benign quic-go buffer warning ignored
        assert_eq!(
            parse_log_line("failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 7168 kiB)"),
            LogEvent::Ignore
        );

        let redacted = redact_log_line(
            "uri=hysteria2://mysecret@203.0.113.10:443/?obfs-password=obfspw auth=mysecret",
            &["mysecret", "obfspw"],
        );
        assert!(!redacted.contains("mysecret") && !redacted.contains("obfspw") && !redacted.contains("203.0.113.10"));
    }

    #[test]
    fn supervisor_plan_start_keep_on_handover_backoff_and_stop() {
        let mut plan = SupervisorPlan::new();
        let spec = HysteriaSpec {
            host: "proxy.example.com".into(),
            ports: "443".into(),
            auth: "pw".into(),
            sni: None,
            pin_sha256: None,
            obfs: None,
            obfs_password: None,
            ech: None,
            up_mbps: None,
            down_mbps: None,
            hop_secs: None,
        };
        let ip = Some(Ipv4Addr::new(203, 0, 113, 10));
        let mut desired = BTreeMap::new();
        desired.insert(0, (spec.clone(), ip));

        // Start
        let a1 = plan.sync(&desired);
        assert_eq!(a1, vec![SlotAction::Start { index: 0, generation: 1 }]);

        // Handover then re-sync with same spec & IP: kept alive, no restart!
        let t0 = Instant::now();
        plan.begin_handover(t0, Duration::from_secs(15));
        assert!(plan.expire_handover(t0 + Duration::from_secs(5)).is_empty());
        assert!(plan.sync(&desired).is_empty(), "unchanged spec kept across handover");

        // Unexpected exit -> backoff 1s, 2s, 5s...
        assert_eq!(plan.on_exit(0, 1, Some("UDP 出不去".into()), t0), Some(Duration::from_secs(1)));
        assert!(plan.due_retries(t0 + Duration::from_millis(500)).is_empty());
        let retry1 = plan.due_retries(t0 + Duration::from_secs(1));
        assert_eq!(retry1, vec![SlotAction::Start { index: 0, generation: 2 }]);
        assert_eq!(plan.on_exit(0, 2, None, t0 + Duration::from_secs(1)), Some(Duration::from_secs(2)));
        let retry2 = plan.due_retries(t0 + Duration::from_secs(3));
        assert_eq!(retry2, vec![SlotAction::Start { index: 0, generation: 3 }]);
        // Ready resets backoff to 1s
        plan.on_ready(0, 3);
        assert_eq!(plan.on_exit(0, 3, None, t0 + Duration::from_secs(10)), Some(Duration::from_secs(1)));

        // Handover expiry stops all
        plan.begin_handover(t0 + Duration::from_secs(10), Duration::from_secs(15));
        let stopped = plan.expire_handover(t0 + Duration::from_secs(26));
        assert_eq!(stopped.len(), 1);
        assert!(plan.is_empty());
    }
}
