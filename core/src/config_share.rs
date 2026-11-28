//! Sharing settings as one commented TOML file (DESIGN §七十五).
//!
//! Export writes the file text itself (fixed order, fixed comments, no
//! configuration value in any comment). Import reads the file, shows what
//! it would add, and computes the new lists: it only adds, never deletes
//! or overwrites what the user already has. Passwords never enter this
//! module unless the user asked for full proxy links on export; on import
//! the proxy links are parsed by the App's own link parser, not here.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub const KIND: &str = "alwaysconnect-share";
pub const FORMAT: i64 = 1;
const MAX_BYTES: usize = 1 << 20;
const MAX_ITEMS: usize = 64;
const MAX_RULES: usize = 10_000;
/// The proxy editor's limit (ProxyRuleInput.siteLimit).
const MAX_PROXY_RULES: usize = 512;
const MAX_STRING: usize = 4096;
const MAX_NOTES: usize = 50;
/// Placeholders a proxy link may carry, with the word shown to the reader.
const PLACEHOLDERS: [(&str, &str); 7] = [
    ("host", "地址"),
    ("username", "用户名"),
    ("password", "密码"),
    ("obfs_password", "混淆密码"),
    ("sni", "域名"),
    ("pin", "证书指纹"),
    ("ech", "ECH"),
];
const GENERAL_KEYS: [&str; 5] =
    ["drop_protection", "auto_lan", "auto_connect_on_launch", "approval_card", "site_lists_auto_update"];

// MARK: - This Mac's settings, as the App hands them over

#[derive(Deserialize, Serialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Site {
    pub name: String,
    pub domains: Vec<String>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct LocalProxy {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub host: String,
    pub port: i64,
    pub username: Option<String>,
    /// Only present when the user asked for full links.
    pub password: Option<String>,
    pub ports: Option<String>,
    pub sni: Option<String>,
    pub pin_sha256: Option<String>,
    pub obfs: Option<String>,
    /// Only present when the user asked for full links.
    pub obfs_password: Option<String>,
    pub ech: Option<String>,
    pub up_mbps: Option<i64>,
    pub down_mbps: Option<i64>,
    pub hop_seconds: Option<i64>,
    pub sites: Vec<String>,
    pub exceptions: Vec<String>,
}

/// An exit protection rule, in the App's own keys (EgressProtection.Group).
#[derive(Deserialize, Serialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct EgressGroup {
    pub id: u32,
    pub name: String,
    pub enabled: bool,
    pub sites: Vec<String>,
    pub exceptions: Vec<String>,
    pub expect: Vec<String>,
    /// "allow", "whenWrong" or "block".
    pub unverified: String,
}

#[derive(Deserialize, Serialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Server {
    /// This Mac's id for the entry; none for an added one.
    pub id: Option<String>,
    pub name: String,
    pub address: String,
    pub cisco_name: Option<String>,
}

impl Server {
    /// What the engine connects to (ServerEntry.target).
    fn target(&self) -> String {
        self.cisco_name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| self.address.clone())
    }
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Cisco {
    pub servers: Vec<Server>,
    /// The selected server's target.
    pub selected: String,
    pub group: String,
}

#[derive(Deserialize, Serialize, Default, Clone, Copy, Debug, PartialEq)]
#[serde(default)]
pub struct General {
    pub drop_protection: bool,
    pub auto_lan: bool,
    pub auto_connect_on_launch: bool,
    pub approval_card: bool,
    pub site_lists_auto_update: bool,
}

impl General {
    fn get(&self, key: &str) -> bool {
        match key {
            "drop_protection" => self.drop_protection,
            "auto_lan" => self.auto_lan,
            "auto_connect_on_launch" => self.auto_connect_on_launch,
            "approval_card" => self.approval_card,
            _ => self.site_lists_auto_update,
        }
    }
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Local {
    pub direct_sites: Vec<Site>,
    pub direct_exceptions: Vec<String>,
    pub proxies: Vec<LocalProxy>,
    pub egress: Vec<EgressGroup>,
    pub cisco: Cisco,
    pub general: General,
}

// MARK: - Export

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct ExportRequest {
    pub local: Local,
    pub direct: bool,
    /// Ids of the proxies to export, any order (the file keeps the App's order).
    pub proxies: Vec<String>,
    /// Ids of the exit protection rules to export.
    pub egress: Vec<u32>,
    pub cisco: bool,
    pub general: bool,
    /// Proxy links with address, account and password.
    pub full_links: bool,
    pub app_version: String,
    /// "YYYY-MM-DD".
    pub date: String,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ExportResult {
    pub text: String,
    /// Proxies whose link still has placeholders for the reader to replace.
    pub to_fill: usize,
    pub contains_secrets: bool,
    /// Proxies renamed because their name gave away a hidden address or account.
    pub renamed: Vec<String>,
}

pub fn export(req: &ExportRequest) -> ExportResult {
    let local = &req.local;
    let proxies: Vec<&LocalProxy> = local.proxies.iter().filter(|p| req.proxies.contains(&p.id)).collect();
    let egress: Vec<&EgressGroup> = local.egress.iter().filter(|g| req.egress.contains(&g.id)).collect();
    let links: Vec<String> = proxies.iter().map(|p| proxy_link(p, req.full_links)).collect();
    let to_fill = links.iter().filter(|l| l.contains('{')).count();
    let contains_secrets = req.full_links
        && proxies.iter().any(|p| p.password.as_deref().is_some_and(|s| !s.is_empty())
            || p.obfs_password.as_deref().is_some_and(|s| !s.is_empty()));

    let mut t = String::new();
    t.push_str("# AlwaysConnect 分享配置。导入：设置 → 通用 → 导入…（先列出会加什么，确认后才写入）。\n");
    if contains_secrets {
        t.push_str("# 本文件含代理的完整链接（地址、账号和密码），只发给信任的人。\n");
    } else if to_fill > 0 {
        t.push_str("# 代理链接里的 {host}、{password} 这类是分享者没导出的部分，导入时粘贴你自己的完整链接即可。\n");
    }
    t.push_str("# 导入只加不删；没填链接的代理先停用，出口保护先暂停。\n\n");

    t.push_str("[file]\n");
    t.push_str(&format!("kind = {}\n", q(KIND)));
    t.push_str(&format!("format = {FORMAT}\n"));
    t.push_str(&format!("app_version = {}\n", q(&req.app_version)));
    t.push_str(&format!("exported = {}\n", q(&req.date)));
    t.push_str(&format!("contains_secrets = {contains_secrets}\n"));

    if req.general {
        let g = local.general;
        t.push_str("\n# 通用开关：导入时默认保持你本机的值，打开才改\n[general]\n");
        for key in GENERAL_KEYS {
            t.push_str(&format!("{key} = {}\n", g.get(key)));
        }
    }

    if req.cisco {
        let c = &local.cisco;
        t.push_str("\n# Cisco 服务器：cisco_entry 是 Cisco Secure Client 里的条目名，本机找不到时用 address\n[cisco]\n");
        if !c.group.is_empty() {
            t.push_str(&format!("group = {}\n", q(&c.group)));
        }
        if let Some(selected) = c.servers.iter().find(|s| s.target() == c.selected) {
            t.push_str(&format!("selected = {}\n", q(&selected.name)));
        }
        for s in &c.servers {
            t.push_str("\n[[cisco.server]]\n");
            t.push_str(&format!("name = {}\n", q(&s.name)));
            if let Some(entry) = s.cisco_name.as_deref().filter(|e| !e.is_empty()) {
                t.push_str(&format!("cisco_entry = {}\n", q(entry)));
            }
            if !s.address.is_empty() {
                t.push_str(&format!("address = {}\n", q(&s.address)));
            }
        }
    }

    if req.direct {
        let (plain, groups): (Vec<&Site>, Vec<&Site>) =
            local.direct_sites.iter().partition(|s| s.domains.len() == 1 && s.domains[0] == s.name);
        let rules: Vec<String> = plain.iter().map(|s| s.name.clone()).collect();
        t.push_str("\n# 分流直连（按网站分流时）：rules 命中的网站不走 Cisco；exceptions 是例外，命中的照常走 Cisco。\n");
        t.push_str("# 三类名单的规则写法都和 App 里的规则框相同。\n[split.direct]\n");
        t.push_str(&format!("rules = {}\n", array(&rules)));
        t.push_str(&format!("exceptions = {}\n", array(&local.direct_exceptions)));
        for g in groups {
            t.push_str("\n[[split.direct.group]]\n");
            t.push_str(&format!("name = {}\n", q(&g.name)));
            t.push_str(&format!("rules = {}\n", array(&g.domains)));
        }
    }

    let mut renamed = Vec::new();
    if !proxies.is_empty() {
        t.push_str("\n# 分流代理：按先后顺序匹配；exceptions 命中的跳过这个代理，继续往后匹配\n");
        for (i, (p, link)) in proxies.iter().zip(&links).enumerate() {
            let mut name = p.name.trim().to_string();
            if name.is_empty() || (!req.full_links && name_reveals(&name, p)) {
                if !name.is_empty() {
                    renamed.push(name.clone());
                }
                name = format!("代理 {}", i + 1);
            }
            if i > 0 {
                t.push('\n');
            }
            t.push_str("[[proxy]]\n");
            t.push_str(&format!("name = {}\n", q(&name)));
            t.push_str(&format!("link = {}\n", q(link)));
            t.push_str(&format!("rules = {}\n", array(&p.sites)));
            t.push_str(&format!("exceptions = {}\n", array(&p.exceptions)));
        }
    }

    if !egress.is_empty() {
        t.push_str("\n# 出口保护：rules 里的网站只允许从 countries 出去；exceptions 命中的不受这条保护\n");
        for (i, g) in egress.iter().enumerate() {
            if i > 0 {
                t.push('\n');
            }
            t.push_str("[[egress.rule]]\n");
            t.push_str(&format!("name = {}\n", q(&g.name)));
            t.push_str(&format!("rules = {}\n", array(&g.sites)));
            t.push_str(&format!("exceptions = {}\n", array(&g.exceptions)));
            t.push_str(&format!("countries = {}\n", array(&g.expect)));
            t.push_str(&format!(
                "when_unverified = {}   # allow 放行 / when_wrong 有异常就拦 / block 一律拦\n",
                q(unverified_to_file(&g.unverified))
            ));
        }
    }

    ExportResult { text: t, to_fill, contains_secrets, renamed }
}

/// A proxy as one standard link; without `full`, the address, account and
/// everything that names the server are `{…}` placeholders.
pub fn proxy_link(p: &LocalProxy, full: bool) -> String {
    let some = |v: &Option<String>| v.as_deref().filter(|s| !s.is_empty()).map(str::to_string);
    if p.kind == "hysteria2" {
        let ports = some(&p.ports).unwrap_or_else(|| if p.port > 0 { p.port.to_string() } else { "443".into() });
        let auth = if full {
            some(&p.password).map(|a| format!("{}@", enc(&a))).unwrap_or_default()
        } else {
            "{password}@".to_string()
        };
        let host = if full { p.host.clone() } else { "{host}".into() };
        let mut params = Vec::new();
        if let Some(sni) = some(&p.sni) {
            params.push(format!("sni={}", if full { enc(&sni) } else { "{sni}".into() }));
        }
        if let Some(pin) = some(&p.pin_sha256) {
            params.push(format!("pinSHA256={}", if full { enc(&pin) } else { "{pin}".into() }));
        }
        if let Some(obfs) = some(&p.obfs) {
            params.push(format!("obfs={}", enc(&obfs)));
            if full {
                if let Some(pw) = some(&p.obfs_password) {
                    params.push(format!("obfs-password={}", enc(&pw)));
                }
            } else {
                params.push("obfs-password={obfs_password}".into());
            }
        }
        if let Some(ech) = some(&p.ech) {
            params.push(format!("ech={}", if full { enc(&ech) } else { "{ech}".into() }));
        }
        if let Some(u) = p.up_mbps {
            params.push(format!("upmbps={u}"));
        }
        if let Some(d) = p.down_mbps {
            params.push(format!("downmbps={d}"));
        }
        if let Some(h) = p.hop_seconds {
            params.push(format!("hop={h}"));
        }
        let query = if params.is_empty() { String::new() } else { format!("/?{}", params.join("&")) };
        return format!("hysteria2://{auth}{host}:{ports}{query}");
    }
    let scheme = if p.kind == "http" { "http" } else { "socks5" };
    let login = match some(&p.username) {
        None => String::new(),
        Some(_) if !full => "{username}:{password}@".into(),
        Some(user) => match some(&p.password) {
            Some(pw) => format!("{}:{}@", enc(&user), enc(&pw)),
            None => format!("{}@", enc(&user)),
        },
    };
    let host = if !full {
        "{host}".to_string()
    } else if p.host.contains(':') {
        format!("[{}]", p.host)
    } else {
        p.host.clone()
    };
    format!("{scheme}://{login}{host}:{}", p.port)
}

/// The name would give away what the placeholders hide.
fn name_reveals(name: &str, p: &LocalProxy) -> bool {
    let lower = name.to_lowercase();
    let hits = |v: &str| v.chars().count() >= 3 && lower.contains(&v.to_lowercase());
    hits(&p.host) || p.username.as_deref().is_some_and(hits)
}

/// RFC 3986 unreserved characters stay; everything else is %XX.
fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A TOML basic string.
fn q(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Short lists on one line, longer ones one item per line.
fn array(items: &[String]) -> String {
    if items.is_empty() {
        return "[]".into();
    }
    let quoted: Vec<String> = items.iter().map(|s| q(s)).collect();
    let inline = format!("[{}]", quoted.join(", "));
    if items.len() <= 3 && inline.chars().count() <= 72 {
        return inline;
    }
    let mut out = String::from("[\n");
    for item in quoted {
        out.push_str("  ");
        out.push_str(&item);
        out.push_str(",\n");
    }
    out.push(']');
    out
}

fn unverified_to_file(raw: &str) -> &'static str {
    match raw {
        "allow" => "allow",
        "block" => "block",
        _ => "when_wrong",
    }
}

fn unverified_from_file(word: &str) -> Option<&'static str> {
    match word {
        "allow" => Some("allow"),
        "when_wrong" | "whenWrong" => Some("whenWrong"),
        "block" => Some("block"),
        _ => None,
    }
}

// MARK: - The file, read

#[derive(Debug, Default, Clone, PartialEq)]
pub struct FileGeneral {
    pub values: Vec<(String, bool)>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct FileServer {
    pub name: String,
    pub cisco_entry: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct FileCisco {
    pub group: Option<String>,
    pub selected: Option<String>,
    pub servers: Vec<FileServer>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct FileDirect {
    pub rules: Vec<String>,
    pub exceptions: Vec<String>,
    pub groups: Vec<(String, Vec<String>)>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct FileProxy {
    pub name: String,
    pub link: String,
    pub kind: String,
    pub rules: Vec<String>,
    pub exceptions: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct FileEgress {
    pub name: String,
    pub rules: Vec<String>,
    pub exceptions: Vec<String>,
    pub countries: Vec<String>,
    /// The App's raw value.
    pub unverified: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ShareFile {
    pub legacy_egress: bool,
    pub app_version: String,
    pub exported: String,
    pub contains_secrets: bool,
    pub general: Option<FileGeneral>,
    pub cisco: Option<FileCisco>,
    pub direct: Option<FileDirect>,
    pub proxies: Vec<FileProxy>,
    pub egress: Vec<FileEgress>,
    /// What was left out and why, for the reader.
    pub skipped: Vec<String>,
}

impl ShareFile {
    fn skip(&mut self, note: String) {
        if self.skipped.len() < MAX_NOTES {
            self.skipped.push(note);
        }
    }
}

pub fn parse(text: &str) -> Result<ShareFile, String> {
    if text.len() > MAX_BYTES {
        return Err("文件太大（超过 1 MB），不像是分享配置。".into());
    }
    if text.trim_start().starts_with('{') {
        return parse_egress_backup(text);
    }
    let table: toml::Table = text
        .parse()
        .map_err(|_| "这个文件读不出来：不是 AlwaysConnect 导出的分享配置，或者被改坏了。".to_string())?;
    let mut f = ShareFile::default();

    let file = table.get("file").and_then(|v| v.as_table()).ok_or("这不是 AlwaysConnect 的分享配置（缺少 [file]）。")?;
    if file.get("kind").and_then(|v| v.as_str()) != Some(KIND) {
        return Err("这不是 AlwaysConnect 的分享配置。".into());
    }
    match file.get("format").and_then(|v| v.as_integer()) {
        Some(n) if n > FORMAT => return Err(format!("这个文件来自更新版本的 AlwaysConnect（格式 {n}），请先更新 App。")),
        Some(n) if n >= 1 => {}
        _ => return Err("这个文件的格式版本不对。".into()),
    }
    f.app_version = short(file.get("app_version").and_then(|v| v.as_str()).unwrap_or(""));
    f.exported = short(file.get("exported").and_then(|v| v.as_str()).unwrap_or(""));
    f.contains_secrets = file.get("contains_secrets").and_then(|v| v.as_bool()).unwrap_or(false);

    for key in table.keys() {
        if !["file", "general", "cisco", "split", "proxy", "egress"].contains(&key.as_str()) {
            f.skip(format!("不认识的部分 [{}]，已跳过", short(key)));
        }
    }

    if let Some(general) = table.get("general") {
        let general = general.as_table().ok_or("[general] 写法不对。")?;
        let mut g = FileGeneral::default();
        for (key, value) in general {
            match (GENERAL_KEYS.contains(&key.as_str()), value.as_bool()) {
                (true, Some(b)) => g.values.push((key.clone(), b)),
                (true, None) => f.skip(format!("通用开关 {} 不是 true / false，已跳过", short(key))),
                (false, _) => f.skip(format!("不认识的通用开关 {}，已跳过", short(key))),
            }
        }
        f.general = Some(g);
    }

    if let Some(cisco) = table.get("cisco") {
        let cisco = cisco.as_table().ok_or("[cisco] 写法不对。")?;
        let mut c = FileCisco {
            group: cisco.get("group").and_then(|v| v.as_str()).map(short).filter(|s| !s.is_empty()),
            selected: cisco.get("selected").and_then(|v| v.as_str()).map(short).filter(|s| !s.is_empty()),
            servers: Vec::new(),
        };
        let servers = tables(cisco.get("server"));
        if servers.len() > MAX_ITEMS {
            return Err(format!("Cisco 服务器太多（{} 台，最多 {MAX_ITEMS} 台）。", servers.len()));
        }
        for s in servers {
            let name = string(s.get("name"));
            let entry = string(s.get("cisco_entry"));
            let address = string(s.get("address"));
            match (name, entry.is_some() || address.is_some()) {
                (Some(name), true) => c.servers.push(FileServer { name, cisco_entry: entry, address }),
                _ => f.skip("一台 Cisco 服务器缺名字或地址，已跳过".into()),
            }
        }
        f.cisco = Some(c);
    }

    if let Some(split) = table.get("split").and_then(|v| v.as_table()) {
        if let Some(direct) = split.get("direct").and_then(|v| v.as_table()) {
            let mut d = FileDirect::default();
            d.rules = rule_list(&mut f, direct.get("rules"), "分流直连", MAX_RULES)?;
            d.exceptions = rule_list(&mut f, direct.get("exceptions"), "分流直连的例外", MAX_RULES)?;
            let groups = tables(direct.get("group"));
            if groups.len() > MAX_ITEMS {
                return Err("分流直连的分组太多。".into());
            }
            for g in groups {
                let Some(name) = string(g.get("name")) else {
                    f.skip("一个分流直连分组没有名字，已跳过".into());
                    continue;
                };
                let rules = rule_list(&mut f, g.get("rules"), &format!("分组「{name}」"), MAX_RULES)?;
                if !rules.is_empty() {
                    d.groups.push((name, rules));
                }
            }
            f.direct = Some(d);
        }
    }

    let proxies = tables(table.get("proxy"));
    if proxies.len() > MAX_ITEMS {
        return Err(format!("代理太多（{} 个，最多 {MAX_ITEMS} 个）。", proxies.len()));
    }
    for p in proxies {
        let name = string(p.get("name")).unwrap_or_default();
        let label = if name.is_empty() { "一个代理".to_string() } else { format!("代理「{name}」") };
        let Some(link) = string(p.get("link")) else {
            f.skip(format!("{label}没有链接，已跳过"));
            continue;
        };
        let kind = match link_kind(&link) {
            Ok(kind) => kind,
            Err(why) => {
                f.skip(format!("{label}：{why}，已跳过"));
                continue;
            }
        };
        let rules = rule_list(&mut f, p.get("rules"), &label, MAX_PROXY_RULES)?;
        let exceptions = rule_list(&mut f, p.get("exceptions"), &format!("{label}的例外"), MAX_PROXY_RULES)?;
        f.proxies.push(FileProxy { name, link, kind: kind.into(), rules, exceptions });
    }

    if let Some(egress) = table.get("egress").and_then(|v| v.as_table()) {
        let rules = tables(egress.get("rule"));
        if rules.len() > MAX_ITEMS {
            return Err(format!("出口保护太多（{} 条，最多 {MAX_ITEMS} 条）。", rules.len()));
        }
        for r in rules {
            let Some(name) = string(r.get("name")) else {
                f.skip("一条出口保护没有名字，已跳过".into());
                continue;
            };
            let label = format!("出口保护「{name}」");
            let sites = rule_list(&mut f, r.get("rules"), &label, MAX_RULES)?;
            let exceptions = rule_list(&mut f, r.get("exceptions"), &format!("{label}的例外"), MAX_RULES)?;
            let countries = countries(r.get("countries"));
            let unverified = r.get("when_unverified").and_then(|v| v.as_str()).unwrap_or("when_wrong");
            match (sites.is_empty(), countries.is_empty(), unverified_from_file(unverified)) {
                (true, _, _) => f.skip(format!("{label}没有有效的网站，已跳过")),
                (_, true, _) => f.skip(format!("{label}没有允许的国家，已跳过")),
                (_, _, None) => f.skip(format!("{label}的 when_unverified 写法不对，已跳过")),
                (false, false, Some(u)) => f.egress.push(FileEgress {
                    name,
                    rules: sites,
                    exceptions,
                    countries,
                    unverified: u.into(),
                }),
            }
        }
    }
    Ok(f)
}

/// The exit protection backup exported before sharing existed (JSON).
fn parse_egress_backup(text: &str) -> Result<ShareFile, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "这个文件读不出来：不是分享配置，也不是出口保护备份。".to_string())?;
    let groups = value.get("groups").and_then(|g| g.as_array()).ok_or("这个文件读不出来：不是分享配置，也不是出口保护备份。")?;
    if groups.len() > MAX_ITEMS {
        return Err(format!("出口保护太多（{} 条，最多 {MAX_ITEMS} 条）。", groups.len()));
    }
    let mut f = ShareFile { legacy_egress: true, ..Default::default() };
    let strings = |v: Option<&serde_json::Value>| -> Vec<String> {
        v.and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str()).map(str::to_string).collect())
            .unwrap_or_default()
    };
    for g in groups {
        let Some(name) = g.get("name").and_then(|n| n.as_str()).map(short).filter(|n| !n.is_empty()) else {
            f.skip("一条出口保护没有名字，已跳过".into());
            continue;
        };
        let label = format!("出口保护「{name}」");
        let mut sites = Vec::new();
        for raw in strings(g.get("sites")).into_iter().take(MAX_RULES) {
            match rule_ok(&raw) {
                Ok(rule) if !sites.contains(&rule) => sites.push(rule),
                Ok(_) => {}
                Err(why) => f.skip(format!("{label}：{} {why}，已跳过", short(&raw))),
            }
        }
        let mut exceptions = Vec::new();
        for raw in strings(g.get("exceptions")).into_iter().take(MAX_RULES) {
            match rule_ok(&raw) {
                Ok(rule) if !exceptions.contains(&rule) => exceptions.push(rule),
                Ok(_) => {}
                Err(why) => f.skip(format!("{label}的例外：{} {why}，已跳过", short(&raw))),
            }
        }
        let countries: Vec<String> = strings(g.get("expect")).iter().filter_map(|c| country(c)).collect();
        let unverified = g.get("unverified").and_then(|u| u.as_str()).and_then(unverified_from_file).unwrap_or("whenWrong");
        if sites.is_empty() || countries.is_empty() {
            f.skip(format!("{label}没有有效的网站或国家，已跳过"));
            continue;
        }
        f.egress.push(FileEgress { name, rules: sites, exceptions, countries, unverified: unverified.into() });
    }
    Ok(f)
}

fn tables(value: Option<&toml::Value>) -> Vec<&toml::Table> {
    value.and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|t| t.as_table()).collect()).unwrap_or_default()
}

fn string(value: Option<&toml::Value>) -> Option<String> {
    value.and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty() && s.len() <= MAX_STRING).map(str::to_string)
}

/// For notes and labels: one line, at most 80 characters.
fn short(s: &str) -> String {
    let line: String = s.chars().filter(|c| !c.is_control()).take(80).collect();
    line.trim().to_string()
}

fn country(raw: &str) -> Option<String> {
    let c = raw.trim();
    (c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic())).then(|| c.to_ascii_uppercase())
}

fn countries(value: Option<&toml::Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in value.and_then(|v| v.as_array()).into_iter().flatten().filter_map(|v| v.as_str()).filter_map(country) {
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// A list of rules: each checked with the rule box's syntax, repeats
/// dropped, bad ones noted. Too many is the whole file's error.
fn rule_list(f: &mut ShareFile, value: Option<&toml::Value>, label: &str, limit: usize) -> Result<Vec<String>, String> {
    let Some(value) = value else { return Ok(Vec::new()) };
    let Some(items) = value.as_array() else {
        f.skip(format!("{label}的规则不是列表，已跳过"));
        return Ok(Vec::new());
    };
    if items.len() > limit {
        return Err(format!("{label}的规则太多（{} 条，最多 {limit} 条）。", items.len()));
    }
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let Some(raw) = item.as_str() else {
            f.skip(format!("{label}里有一项不是文字，已跳过"));
            continue;
        };
        match rule_ok(raw) {
            Ok(rule) if !out.contains(&rule) => out.push(rule),
            Ok(_) => {}
            Err(why) => f.skip(format!("{label}：{} {why}，已跳过", short(raw))),
        }
    }
    Ok(out)
}

/// One rule as the rule box would store it, or why not.
pub fn rule_ok(raw: &str) -> Result<String, &'static str> {
    let rule = raw.trim();
    if rule.contains('{') || rule.contains('}') {
        return Err("里面有没填的占位");
    }
    if !crate::egress_control::valid_rule(rule, false) {
        return Err("写法不对");
    }
    let rule = rule.strip_prefix("domain:").unwrap_or(rule);
    if let Some(list) = rule.strip_prefix("geosite:") {
        if crate::geodata::available() {
            let (name, attribute) = match list.split_once('@') {
                Some((n, a)) => (n, Some(a)),
                None => (list, None),
            };
            if !crate::geodata::has_list(&name.to_ascii_lowercase()) {
                return Err("本机网站清单里没有这个名字");
            }
            if let Some(attribute) = attribute.filter(|a| !a.starts_with('!')) {
                if crate::geodata::rule_count(&name.to_ascii_lowercase(), Some(&attribute.to_ascii_lowercase())) == 0 {
                    return Err("本机网站清单里没有这个属性");
                }
            }
        }
    }
    Ok(if rule.starts_with("regexp:") { rule.to_string() } else { rule.to_ascii_lowercase() })
}

/// The proxy type a link names, or why it cannot be one.
fn link_kind(link: &str) -> Result<&'static str, String> {
    let lower = link.to_ascii_lowercase();
    let kind = if lower.starts_with("socks5://") || lower.starts_with("socks5h://") || lower.starts_with("socks://") {
        "socks5"
    } else if lower.starts_with("http://") {
        "http"
    } else if lower.starts_with("hysteria2://") || lower.starts_with("hy2://") {
        "hysteria2"
    } else {
        return Err("认不出代理类型，支持 socks5://、http://、hysteria2://".into());
    };
    for token in placeholders(link) {
        if !PLACEHOLDERS.iter().any(|(t, _)| *t == token) {
            return Err(format!("链接里有认不出的 {{{token}}}"));
        }
    }
    Ok(kind)
}

fn placeholders(link: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = link;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}') else { break };
        out.push(rest[open + 1..open + close].to_string());
        rest = &rest[open + close + 1..];
    }
    out
}

/// The link with its placeholders in words, as the input box's hint.
fn link_hint(link: &str) -> String {
    let mut hint = link.to_string();
    for (token, word) in PLACEHOLDERS {
        hint = hint.replace(&format!("{{{token}}}"), word);
    }
    hint
}

// MARK: - Import: what would be added

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Item {
    pub text: String,
    /// False: this Mac already has it, it is skipped.
    pub new: bool,
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct DirectPreview {
    pub rules: Vec<Item>,
    pub exceptions: Vec<Item>,
    pub groups: Vec<GroupPreview>,
    pub added_rules: usize,
    pub added_exceptions: usize,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct GroupPreview {
    pub name: String,
    pub rules: Vec<Item>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ProxyPreview {
    pub index: usize,
    pub name: String,
    /// The name it gets here ("名称（导入）" when the name is taken).
    pub import_name: String,
    pub kind: String,
    /// The link as written in the file.
    pub link: String,
    /// The link has no placeholders: offered as the ready link.
    pub complete: bool,
    /// The link with its placeholders in words.
    pub hint: String,
    pub rules: Vec<String>,
    pub exceptions: Vec<String>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct EgressPreview {
    pub name: String,
    pub import_name: String,
    pub rules: Vec<String>,
    pub exceptions: Vec<String>,
    pub countries: Vec<String>,
    pub unverified: String,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ServerPreview {
    pub name: String,
    pub cisco_entry: Option<String>,
    pub address: Option<String>,
    pub new: bool,
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct CiscoPreview {
    pub servers: Vec<ServerPreview>,
    pub added: usize,
    /// Set only when this Mac has no group yet.
    pub group: Option<String>,
    /// Set only when this Mac has no selected server yet.
    pub selected: Option<String>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct GeneralChange {
    pub key: String,
    pub local: bool,
    pub file: bool,
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct Preview {
    pub ok: bool,
    pub error: Option<String>,
    pub legacy_egress: bool,
    pub app_version: String,
    pub exported: String,
    pub contains_secrets: bool,
    pub direct: Option<DirectPreview>,
    pub proxies: Vec<ProxyPreview>,
    pub egress: Vec<EgressPreview>,
    pub cisco: Option<CiscoPreview>,
    pub general: Vec<GeneralChange>,
    pub skipped: Vec<String>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct PreviewRequest {
    pub text: String,
    pub local: Local,
}

pub fn preview(req: &PreviewRequest) -> Preview {
    let file = match parse(&req.text) {
        Ok(file) => file,
        Err(error) => return Preview { error: Some(error), ..Default::default() },
    };
    preview_of(&file, &req.local)
}

fn preview_of(f: &ShareFile, local: &Local) -> Preview {
    let mut p = Preview {
        ok: true,
        legacy_egress: f.legacy_egress,
        app_version: f.app_version.clone(),
        exported: f.exported.clone(),
        contains_secrets: f.contains_secrets,
        skipped: f.skipped.clone(),
        ..Default::default()
    };

    if let Some(d) = &f.direct {
        let have: HashSet<String> =
            local.direct_sites.iter().flat_map(|s| s.domains.iter()).map(|r| key(r)).collect();
        let have_ex: HashSet<String> = local.direct_exceptions.iter().map(|r| key(r)).collect();
        let mut dp = DirectPreview::default();
        for r in &d.rules {
            let new = !have.contains(&key(r));
            dp.added_rules += new as usize;
            dp.rules.push(Item { text: r.clone(), new });
        }
        for r in &d.exceptions {
            let new = !have_ex.contains(&key(r));
            dp.added_exceptions += new as usize;
            dp.exceptions.push(Item { text: r.clone(), new });
        }
        for (name, rules) in &d.groups {
            let items: Vec<Item> = rules.iter().map(|r| Item { text: r.clone(), new: !have.contains(&key(r)) }).collect();
            dp.added_rules += items.iter().filter(|i| i.new).count();
            dp.groups.push(GroupPreview { name: name.clone(), rules: items });
        }
        p.direct = Some(dp);
    }

    let mut proxy_names: Vec<String> = local.proxies.iter().map(|x| x.name.clone()).collect();
    for (index, x) in f.proxies.iter().enumerate() {
        let base = if x.name.is_empty() { format!("代理 {}", index + 1) } else { x.name.clone() };
        let import_name = free_name(&base, &proxy_names);
        proxy_names.push(import_name.clone());
        p.proxies.push(ProxyPreview {
            index,
            name: base,
            import_name,
            kind: x.kind.clone(),
            link: x.link.clone(),
            complete: !x.link.contains('{'),
            hint: link_hint(&x.link),
            rules: x.rules.clone(),
            exceptions: x.exceptions.clone(),
        });
    }

    let mut egress_names: Vec<String> = local.egress.iter().map(|g| g.name.clone()).collect();
    for e in &f.egress {
        let import_name = free_name(&e.name, &egress_names);
        egress_names.push(import_name.clone());
        p.egress.push(EgressPreview {
            name: e.name.clone(),
            import_name,
            rules: e.rules.clone(),
            exceptions: e.exceptions.clone(),
            countries: e.countries.clone(),
            unverified: e.unverified.clone(),
        });
    }

    if let Some(c) = &f.cisco {
        let mut known: HashSet<String> = HashSet::new();
        for s in &local.cisco.servers {
            if let Some(n) = s.cisco_name.as_deref().filter(|n| !n.is_empty()) {
                known.insert(n.to_lowercase());
            }
            if !s.address.is_empty() {
                known.insert(s.address.to_lowercase());
            }
        }
        let mut cp = CiscoPreview::default();
        for s in &c.servers {
            let new = !s.cisco_entry.iter().chain(s.address.iter()).any(|k| known.contains(&k.to_lowercase()));
            if new {
                for k in s.cisco_entry.iter().chain(s.address.iter()) {
                    known.insert(k.to_lowercase());
                }
            }
            cp.added += new as usize;
            cp.servers.push(ServerPreview {
                name: s.name.clone(),
                cisco_entry: s.cisco_entry.clone(),
                address: s.address.clone(),
                new,
            });
        }
        if local.cisco.group.is_empty() {
            cp.group = c.group.clone();
        }
        if local.cisco.selected.is_empty() {
            cp.selected = c.selected.clone().filter(|name| c.servers.iter().any(|s| &s.name == name));
        }
        p.cisco = Some(cp);
    }

    if let Some(g) = &f.general {
        for (key, file) in &g.values {
            let mine = local.general.get(key);
            if mine != *file {
                p.general.push(GeneralChange { key: key.clone(), local: mine, file: *file });
            }
        }
    }
    p
}

/// How two rules are compared: case-insensitive except regexp.
fn key(rule: &str) -> String {
    let r = rule.trim();
    let r = r.strip_prefix("domain:").unwrap_or(r);
    if r.starts_with("regexp:") { r.to_string() } else { r.to_lowercase() }
}

/// `base`, or "base（导入）", "base（导入 2）"… when the name is taken.
fn free_name(base: &str, taken: &[String]) -> String {
    let used = |n: &str| taken.iter().any(|t| t.eq_ignore_ascii_case(n));
    if !used(base) {
        return base.to_string();
    }
    let mut n = 1;
    loop {
        let candidate = if n == 1 { format!("{base}（导入）") } else { format!("{base}（导入 {n}）") };
        if !used(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

// MARK: - Import: the new lists

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct ApplyRequest {
    pub text: String,
    pub local: Local,
    pub direct: bool,
    pub egress: bool,
    pub cisco: bool,
    pub general: bool,
    /// File indexes of the proxies to add.
    pub proxies: Vec<usize>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct NewProxy {
    pub index: usize,
    pub name: String,
    /// The type the file gave it ("socks5", "http" or "hysteria2").
    pub kind: String,
    pub sites: Vec<String>,
    pub exceptions: Vec<String>,
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct Applied {
    pub ok: bool,
    pub error: Option<String>,
    /// The whole new list, when it changes.
    pub direct_sites: Option<Vec<Site>>,
    pub direct_exceptions: Option<Vec<String>>,
    pub proxies: Vec<NewProxy>,
    /// Added rules only, each switched off, numbered after this Mac's.
    pub egress_groups: Vec<EgressGroup>,
    pub cisco_servers: Option<Vec<Server>>,
    pub selected: Option<String>,
    pub group: Option<String>,
    pub general: Vec<GeneralChange>,
    pub added_rules: usize,
    pub added_exceptions: usize,
    pub added_servers: usize,
}

pub fn apply(req: &ApplyRequest) -> Applied {
    let file = match parse(&req.text) {
        Ok(file) => file,
        Err(error) => return Applied { error: Some(error), ..Default::default() },
    };
    let local = &req.local;
    let p = preview_of(&file, local);
    let mut out = Applied { ok: true, ..Default::default() };

    if req.direct {
        if let (Some(d), Some(dp)) = (&file.direct, &p.direct) {
            let mut sites = local.direct_sites.clone();
            let mut seen: HashSet<String> = sites.iter().flat_map(|s| s.domains.iter()).map(|r| key(r)).collect();
            for r in &d.rules {
                if seen.insert(key(r)) {
                    sites.push(Site { name: r.clone(), domains: vec![r.clone()] });
                    out.added_rules += 1;
                }
            }
            for (name, rules) in &d.groups {
                let fresh: Vec<String> = rules.iter().filter(|r| seen.insert(key(r))).cloned().collect();
                if fresh.is_empty() {
                    continue;
                }
                out.added_rules += fresh.len();
                match sites.iter_mut().find(|s| &s.name == name && !(s.domains.len() == 1 && &s.domains[0] == name)) {
                    Some(existing) => existing.domains.extend(fresh),
                    None => sites.push(Site { name: name.clone(), domains: fresh }),
                }
            }
            if out.added_rules > 0 {
                out.direct_sites = Some(sites);
            }
            if dp.added_exceptions > 0 {
                let mut exceptions = local.direct_exceptions.clone();
                let mut seen: HashSet<String> = exceptions.iter().map(|r| key(r)).collect();
                for r in &d.exceptions {
                    if seen.insert(key(r)) {
                        exceptions.push(r.clone());
                        out.added_exceptions += 1;
                    }
                }
                out.direct_exceptions = Some(exceptions);
            }
        }
    }

    for x in p.proxies.iter().filter(|x| req.proxies.contains(&x.index)) {
        out.proxies.push(NewProxy {
            index: x.index,
            name: x.import_name.clone(),
            kind: x.kind.clone(),
            sites: x.rules.clone(),
            exceptions: x.exceptions.clone(),
        });
    }

    if req.egress {
        let mut next = local.egress.iter().map(|g| g.id).max().unwrap_or(0);
        for e in &p.egress {
            next = next.saturating_add(1);
            out.egress_groups.push(EgressGroup {
                id: next,
                name: e.import_name.clone(),
                enabled: false,
                sites: e.rules.clone(),
                exceptions: e.exceptions.clone(),
                expect: e.countries.clone(),
                unverified: e.unverified.clone(),
            });
        }
    }

    if req.cisco {
        if let (Some(c), Some(cp)) = (&file.cisco, &p.cisco) {
            let mut servers = local.cisco.servers.clone();
            for (s, sp) in c.servers.iter().zip(&cp.servers) {
                if sp.new {
                    servers.push(Server {
                        id: None,
                        name: s.name.clone(),
                        address: s.address.clone().unwrap_or_default(),
                        cisco_name: s.cisco_entry.clone(),
                    });
                    out.added_servers += 1;
                }
            }
            if out.added_servers > 0 {
                out.cisco_servers = Some(servers.clone());
            }
            out.group = cp.group.clone();
            out.selected = cp.selected.as_ref().and_then(|name| {
                let s = c.servers.iter().find(|s| &s.name == name)?;
                let wanted: Vec<String> = s.cisco_entry.iter().chain(s.address.iter()).map(|k| k.to_lowercase()).collect();
                servers
                    .iter()
                    .find(|l| {
                        l.cisco_name.as_deref().is_some_and(|n| wanted.contains(&n.to_lowercase()))
                            || (!l.address.is_empty() && wanted.contains(&l.address.to_lowercase()))
                    })
                    .map(Server::target)
            });
        }
    }

    if req.general {
        out.general = p.general;
    }
    out
}

// MARK: - C ABI (JSON in, JSON out; free with ac_string_free)

fn c_str(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(str::to_string)
}

fn out<T: Serialize>(value: &T) -> *mut c_char {
    serde_json::to_string(value)
        .ok()
        .and_then(|s| CString::new(s).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// ExportRequest in, ExportResult out.
#[no_mangle]
pub extern "C" fn ac_share_export(request: *const c_char) -> *mut c_char {
    let Some(req) = c_str(request).and_then(|s| serde_json::from_str::<ExportRequest>(&s).ok()) else {
        return std::ptr::null_mut();
    };
    out(&export(&req))
}

/// PreviewRequest in, Preview out.
#[no_mangle]
pub extern "C" fn ac_share_preview(request: *const c_char) -> *mut c_char {
    let Some(req) = c_str(request).and_then(|s| serde_json::from_str::<PreviewRequest>(&s).ok()) else {
        return std::ptr::null_mut();
    };
    out(&preview(&req))
}

/// ApplyRequest in, Applied out.
#[no_mangle]
pub extern "C" fn ac_share_apply(request: *const c_char) -> *mut c_char {
    let Some(req) = c_str(request).and_then(|s| serde_json::from_str::<ApplyRequest>(&s).ok()) else {
        return std::ptr::null_mut();
    };
    out(&apply(&req))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socks() -> LocalProxy {
        LocalProxy {
            id: "p1".into(),
            name: "示例 SOCKS5".into(),
            kind: "socks5".into(),
            host: "198.51.100.9".into(),
            port: 1080,
            username: Some("alice".into()),
            password: Some("p@ss word".into()),
            sites: vec!["geosite:example-media".into(), "full:api.example.net".into()],
            ..Default::default()
        }
    }

    fn hysteria() -> LocalProxy {
        LocalProxy {
            id: "p2".into(),
            name: "示例 Hysteria2".into(),
            kind: "hysteria2".into(),
            host: "proxy.example.net".into(),
            port: 443,
            password: Some("s3cret/+".into()),
            ports: Some("443,20000-30000".into()),
            sni: Some("proxy.example.net".into()),
            obfs: Some("salamander".into()),
            obfs_password: Some("ob fs".into()),
            up_mbps: Some(50),
            down_mbps: Some(200),
            hop_seconds: Some(30),
            sites: vec!["198.51.100.0/24".into()],
            exceptions: vec!["full:static.example.org".into()],
            ..Default::default()
        }
    }

    fn local() -> Local {
        Local {
            direct_sites: vec![
                Site { name: "example.com".into(), domains: vec!["example.com".into()] },
                Site { name: "203.0.113.0/24".into(), domains: vec!["203.0.113.0/24".into()] },
                Site { name: "示例分组".into(), domains: vec!["a.example.net".into(), "b.example.net".into()] },
            ],
            direct_exceptions: vec!["full:login.example.com".into()],
            proxies: vec![socks(), hysteria()],
            egress: vec![EgressGroup {
                id: 7,
                name: "示例：只从美国出口".into(),
                enabled: true,
                sites: vec!["shop.example.com".into()],
                exceptions: vec!["full:cdn.shop.example.com".into()],
                expect: vec!["US".into()],
                unverified: "whenWrong".into(),
            }],
            cisco: Cisco {
                servers: vec![
                    Server { id: Some("1".into()), name: "VPN-A".into(), address: "vpn-a.example.com".into(), cisco_name: Some("VPN-A".into()) },
                    Server { id: Some("2".into()), name: "VPN-B".into(), address: "vpn-b.example.com".into(), cisco_name: None },
                ],
                selected: "VPN-A".into(),
                group: "Staff".into(),
            },
            general: General {
                drop_protection: true,
                auto_lan: true,
                auto_connect_on_launch: true,
                approval_card: true,
                site_lists_auto_update: true,
            },
        }
    }

    fn everything(full: bool) -> ExportRequest {
        ExportRequest {
            local: local(),
            direct: true,
            proxies: vec!["p1".into(), "p2".into()],
            egress: vec![7],
            cisco: true,
            general: true,
            full_links: full,
            app_version: "0.6.0".into(),
            date: "2026-11-28".into(),
        }
    }

    #[test]
    fn hidden_links_carry_placeholders_and_no_secret() {
        let r = export(&everything(false));
        assert!(r.text.contains("link = \"socks5://{username}:{password}@{host}:1080\""), "{}", r.text);
        assert!(r.text.contains(
            "link = \"hysteria2://{password}@{host}:443,20000-30000/?sni={sni}&obfs=salamander&obfs-password={obfs_password}&upmbps=50&downmbps=200&hop=30\""
        ));
        for secret in ["198.51.100.9", "alice", "p@ss", "s3cret", "ob fs", "ob%20fs", "proxy.example.net\"\n"] {
            assert!(!r.text.contains(secret), "{secret} leaked:\n{}", r.text);
        }
        assert_eq!(r.to_fill, 2);
        assert!(!r.contains_secrets);
        assert!(r.text.contains("contains_secrets = false"));
    }

    #[test]
    fn full_links_parse_back_to_the_same_proxy() {
        let r = export(&everything(true));
        assert!(r.contains_secrets);
        assert!(r.text.starts_with("# AlwaysConnect 分享配置。"));
        assert!(r.text.contains("本文件含代理的完整链接"));
        let f = parse(&r.text).unwrap();
        let hy = &f.proxies[1].link;
        let u = crate::split_proxy::hysteria::parse_uri(hy).unwrap();
        assert_eq!(u.host, "proxy.example.net");
        assert_eq!(u.ports, "443,20000-30000");
        assert_eq!(u.auth.as_deref(), Some("s3cret/+"));
        assert_eq!(u.obfs_password.as_deref(), Some("ob fs"));
        assert_eq!(u.sni.as_deref(), Some("proxy.example.net"));
        assert_eq!((u.up_mbps, u.down_mbps, u.hop_secs), (Some(50), Some(200), Some(30)));
        assert_eq!(f.proxies[0].link, "socks5://alice:p%40ss%20word@198.51.100.9:1080");
    }

    #[test]
    fn export_round_trips_through_parse() {
        let r = export(&everything(false));
        let f = parse(&r.text).unwrap();
        assert!(f.skipped.is_empty(), "{:?}", f.skipped);
        let d = f.direct.unwrap();
        assert_eq!(d.rules, vec!["example.com", "203.0.113.0/24"]);
        assert_eq!(d.exceptions, vec!["full:login.example.com"]);
        assert_eq!(d.groups, vec![("示例分组".to_string(), vec!["a.example.net".to_string(), "b.example.net".to_string()])]);
        assert_eq!(f.proxies.len(), 2);
        assert_eq!(f.proxies[1].exceptions, vec!["full:static.example.org"]);
        assert_eq!(f.proxies[0].exceptions, Vec::<String>::new());
        assert_eq!(f.egress[0].countries, vec!["US"]);
        assert_eq!(f.egress[0].unverified, "whenWrong");
        let c = f.cisco.unwrap();
        assert_eq!(c.group.as_deref(), Some("Staff"));
        assert_eq!(c.selected.as_deref(), Some("VPN-A"));
        assert_eq!(c.servers[0].cisco_entry.as_deref(), Some("VPN-A"));
        assert_eq!(f.general.unwrap().values.len(), 5);
        // Every list keeps its exceptions line, even when empty.
        assert!(r.text.matches("exceptions = ").count() >= 4);
    }

    #[test]
    fn only_selected_parts_are_written() {
        let mut req = everything(false);
        req.direct = false;
        req.cisco = false;
        req.general = false;
        req.proxies.clear();
        let r = export(&req);
        assert!(!r.text.contains("[split.direct]") && !r.text.contains("[cisco]") && !r.text.contains("[general]"));
        assert!(!r.text.contains("[[proxy]]"));
        assert!(r.text.contains("[[egress.rule]]"));
        assert!(!r.text.contains("{host}"));
    }

    #[test]
    fn a_name_that_gives_the_server_away_is_replaced() {
        let mut req = everything(false);
        req.local.proxies[0].name = "家里 198.51.100.9".into();
        let r = export(&req);
        assert_eq!(r.renamed, vec!["家里 198.51.100.9"]);
        assert!(r.text.contains("name = \"代理 1\""));
        assert!(!r.text.contains("198.51.100.9"));
        req.full_links = true;
        assert!(export(&req).renamed.is_empty());
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(q("a\"b\\c\nd\u{1}"), "\"a\\\"b\\\\c\\nd\\u0001\"");
        let mut req = everything(false);
        req.local.proxies[0].name = "引号\"和\\反斜杠".into();
        let f = parse(&export(&req).text).unwrap();
        assert_eq!(f.proxies[0].name, "引号\"和\\反斜杠");
    }

    #[test]
    fn the_sample_file_reads() {
        let text = include_str!("../../docs/examples/share-sample.toml");
        let f = parse(text).unwrap();
        assert!(f.skipped.is_empty(), "{:?}", f.skipped);
        assert_eq!(f.direct.as_ref().unwrap().rules.len(), 5);
        assert_eq!(f.proxies.len(), 2);
        assert_eq!(f.egress.len(), 1);
    }

    #[test]
    fn whole_file_errors() {
        assert!(parse("not = [toml").unwrap_err().contains("读不出来"));
        assert!(parse("[file]\nkind = \"other\"\nformat = 1\n").unwrap_err().contains("不是"));
        assert!(parse("[file]\nkind = \"alwaysconnect-share\"\nformat = 2\n").unwrap_err().contains("更新"));
        assert!(parse(&"#".repeat(MAX_BYTES + 1)).unwrap_err().contains("太大"));
        let mut many = String::from("[file]\nkind = \"alwaysconnect-share\"\nformat = 1\n");
        for i in 0..70 {
            many.push_str(&format!("[[proxy]]\nname = \"p{i}\"\nlink = \"socks5://{{host}}:1080\"\n"));
        }
        assert!(parse(&many).unwrap_err().contains("太多"));
        let deep = format!("[file]\nkind = \"alwaysconnect-share\"\nformat = 1\nx = {}{}\n", "[".repeat(5000), "]".repeat(5000));
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn bad_items_are_skipped_not_fatal() {
        let text = r#"
[file]
kind = "alwaysconnect-share"
format = 1
[future]
x = 1
[general]
auto_lan = "yes"
wifi = true
[split.direct]
rules = ["example.com", "{host}", "DOMAIN-SUFFIX,example.org", 5, "EXAMPLE.com"]
[[proxy]]
name = "a"
link = "vless://{host}"
[[proxy]]
name = "b"
link = "socks5://{abc}:1080"
[[proxy]]
name = "c"
link = "socks5://{host}:1080"
rules = ["full:x.example.com"]
[[egress.rule]]
name = "no country"
rules = ["example.com"]
countries = []
"#;
        let f = parse(text).unwrap();
        assert_eq!(f.direct.unwrap().rules, vec!["example.com"]);
        assert_eq!(f.proxies.len(), 1);
        assert_eq!(f.proxies[0].name, "c");
        assert!(f.egress.is_empty());
        let notes = f.skipped.join("\n");
        for part in ["[future]", "auto_lan", "wifi", "{host}", "DOMAIN-SUFFIX", "不是文字", "认不出代理类型", "{abc}", "国家"] {
            assert!(notes.contains(part), "missing {part} in\n{notes}");
        }
    }

    #[test]
    fn preview_marks_what_is_already_here() {
        let text = include_str!("../../docs/examples/share-sample.toml");
        let p = preview(&PreviewRequest { text: text.into(), local: local() });
        assert!(p.ok);
        let d = p.direct.unwrap();
        // example.com and 203.0.113.0/24 are already on this Mac.
        assert_eq!(d.added_rules, 3 + 0);
        assert_eq!(d.added_exceptions, 0);
        assert!(d.rules.iter().any(|i| i.text == "203.0.113.0/24" && !i.new));
        assert_eq!(p.proxies[0].import_name, "示例 SOCKS5（导入）");
        assert!(!p.proxies[0].complete);
        assert_eq!(p.proxies[0].hint, "socks5://用户名:密码@地址:1080");
        assert_eq!(p.egress[0].import_name, "示例：只从美国出口（导入）");
        let c = p.cisco.unwrap();
        assert_eq!(c.added, 0);
        assert!(c.group.is_none() && c.selected.is_none());
        assert!(p.general.is_empty());
    }

    #[test]
    fn apply_only_adds() {
        let text = include_str!("../../docs/examples/share-sample.toml");
        let mut here = local();
        here.cisco = Cisco::default();
        here.general.auto_lan = false;
        let a = apply(&ApplyRequest {
            text: text.into(),
            local: here.clone(),
            direct: true,
            egress: true,
            cisco: true,
            general: true,
            proxies: vec![1],
        });
        assert!(a.ok);
        let sites = a.direct_sites.unwrap();
        assert_eq!(&sites[..3], &here.direct_sites[..]);
        assert_eq!(a.added_rules, 3);
        assert!(sites.iter().any(|s| s.name == "keyword:examplecdn"));
        assert!(a.direct_exceptions.is_none());
        assert_eq!(a.proxies.len(), 1);
        assert_eq!(a.proxies[0].name, "示例 Hysteria2（导入）");
        assert_eq!(a.egress_groups.len(), 1);
        assert_eq!(a.egress_groups[0].id, 8);
        assert!(!a.egress_groups[0].enabled);
        let servers = a.cisco_servers.unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].cisco_name.as_deref(), Some("VPN-A"));
        assert_eq!(a.selected.as_deref(), Some("VPN-A"));
        assert_eq!(a.group.as_deref(), Some("Staff"));
        assert_eq!(a.general, vec![GeneralChange { key: "auto_lan".into(), local: false, file: true }]);

        let none = apply(&ApplyRequest { text: text.into(), local: here, ..Default::default() });
        assert!(none.direct_sites.is_none() && none.egress_groups.is_empty() && none.cisco_servers.is_none());
        assert!(none.general.is_empty() && none.proxies.is_empty());
    }

    #[test]
    fn importing_twice_adds_nothing_new_to_the_lists() {
        let text = export(&everything(false)).text;
        let a = apply(&ApplyRequest { text, local: local(), direct: true, cisco: true, ..Default::default() });
        assert!(a.direct_sites.is_none() && a.direct_exceptions.is_none() && a.cisco_servers.is_none());
        assert_eq!(a.added_rules + a.added_exceptions + a.added_servers, 0);
    }

    #[test]
    fn old_egress_backup_is_read() {
        let json = r#"{"enabled":true,"groups":[{"id":3,"name":"旧保护","enabled":true,"sites":["example.com","bad rule"],
            "expect":["us"],"unverified":"block"}]}"#;
        let f = parse(json).unwrap();
        assert!(f.legacy_egress);
        assert_eq!(f.egress.len(), 1);
        assert_eq!(f.egress[0].rules, vec!["example.com"]);
        assert_eq!(f.egress[0].countries, vec!["US"]);
        assert_eq!(f.egress[0].unverified, "block");
        assert_eq!(f.skipped.len(), 1);
        assert!(parse("{\"x\":1}").is_err());
    }

    #[test]
    fn free_names_count_up() {
        let taken = vec!["a".to_string(), "a（导入）".to_string()];
        assert_eq!(free_name("b", &taken), "b");
        assert_eq!(free_name("A", &taken), "A（导入 2）");
    }
}
