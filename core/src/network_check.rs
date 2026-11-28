//! Read-only checks of the configuration actually loaded by macOS (§48).
//! Decisions and parsers are Rust; nothing here changes the network. The
//! active leak probes (leak_probe.rs, §63) run alongside as an ordinary user.
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    pub tunnel: Option<String>, pub dns_interface: Option<String>,
    pub physical: String, pub gateway: Option<String>, pub vpn_gateways: Vec<String>,
    pub dns: Vec<String>, pub split: bool, pub protection: bool,
    pub rules: Option<String>, pub proxy_rules: Option<String>, pub direct: Vec<String>, pub routes: Vec<String>,
    pub error: Option<String>, pub epoch: u64,
    /// The physical network's own DNS servers, for the active probe.
    pub local_dns: Vec<String>,
}
#[derive(Serialize)]
pub struct Item { pub item: String, pub passed: bool, pub informational: bool, pub detail: String }
fn item(name: &str, passed: bool, detail: &str) -> Item {
    Item { item: name.into(), passed, informational: false, detail: detail.into() }
}
#[derive(Default, Clone)]
pub struct Output { pub ok: bool, pub text: String }

pub fn interface(output: &str) -> Option<&str> {
    output.lines().find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
}
fn first_dns(output: &str) -> Vec<String> {
    let mut servers = Vec::new();
    let mut begun = false;
    for line in output.lines().map(str::trim) {
        if line.starts_with("resolver #") {
            if begun { break; }
            begun = true;
        } else if begun && line.starts_with("DNS configuration") { break; }
        if begun && line.starts_with("nameserver[") {
            if let Some((_, value)) = line.split_once(':') { servers.push(value.trim().into()); }
        }
    }
    servers
}
fn expand_sets(text: &str) -> Vec<String> {
    let Some(a) = text.find('{') else { return vec![text.into()] };
    let Some(b) = text[a..].find('}').map(|b| b + a) else { return vec![text.into()] };
    text[a + 1..b].split_whitespace().flat_map(|v| expand_sets(&format!("{}{}{}", &text[..a], v.trim_end_matches(','), &text[b + 1..]))).collect()
}
fn address_range(text:&str)->Option<(u128,u128)> {
    let (address,prefix)=text.split_once('/').map(|(a,p)|(a,Some(p))).unwrap_or((text,None));
    let ip=address.parse::<std::net::IpAddr>().ok()?;
    let (value,bits)=match ip {std::net::IpAddr::V4(ip)=>(u32::from(ip) as u128,32),std::net::IpAddr::V6(ip)=>(u128::from(ip),128)};
    let prefix=if let Some(p)=prefix {p.parse::<u32>().ok()?} else {bits};
    if prefix>bits {return None;}
    let host=bits-prefix;let mask=if host==128 {u128::MAX} else {(1u128<<host)-1};
    Some((value&!mask,value|mask))
}
/// The optimizer also removes covered prefixes and may combine adjacent
/// addresses. Compare their exact union, keeping every other rule field.
fn normalized_passes(passes:&mut Vec<String>)->Vec<String> {
    let mut groups=std::collections::BTreeMap::<String,Vec<(u128,u128)>>::new();let mut out=Vec::new();
    for rule in passes.drain(..) {
        let mut words:Vec<_>=rule.split_whitespace().collect();
        let target=words.iter().position(|w|*w=="to").map(|i|i+1);
        if let Some(at)=target.filter(|i|*i<words.len()) {
            if let Some(range)=address_range(words[at]) {
                words[at]="<address-union>";groups.entry(words.join(" ")).or_default().push(range);continue;
            }
        }
        out.push(rule);
    }
    for (key,mut ranges) in groups {
        ranges.sort_unstable();let mut merged:Vec<(u128,u128)>=Vec::new();
        for (lo,hi) in ranges {
            if let Some(last)=merged.last_mut().filter(|last|lo<=last.1.saturating_add(1)) {last.1=last.1.max(hi);}
            else {merged.push((lo,hi));}
        }
        for (lo,hi) in merged {out.push(format!("{key} [{lo}-{hi}]"));}
    }
    out.sort();out.dedup();out
}
/// Accept pfctl's normal formatting, not arbitrary extra rules. The generated
/// quick blocks keep their ordering barriers; pass expansion within a barrier is immaterial.
fn canonical_rules(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("table ")) {
        for line in expand_sets(line) {
            let mut line = format!(" {} ", line.split_whitespace().collect::<Vec<_>>().join(" "));
            line = line.replace(" keep state ", " ").replace(" port = ", " port ").replace(" user = ", " user ");
            line = line.replace(" all ", " from any to any ");
            if line.contains(" to ") && !line.contains(" from ") { line = line.replacen(" to ", " from any to ", 1); }
            let mut words: Vec<_> = line.split_whitespace().map(str::to_owned).collect();
            let family = if words.iter().any(|w| w == "inet6") || words.iter().any(|w| w.split('/').next().is_some_and(|s| s.parse::<std::net::Ipv6Addr>().is_ok())) {
                Some("inet6")
            } else if words.iter().any(|w| w == "inet") || words.iter().any(|w| w.split('/').next().is_some_and(|s| s.parse::<std::net::Ipv4Addr>().is_ok())) { Some("inet") } else { None };
            words.retain(|w| w != "inet" && w != "inet6");
            let explicit_flags = if let Some(at) = words.iter().position(|w| w == "flags") {
                if at + 1 < words.len() { let flag = words[at + 1].clone(); words.drain(at..at + 2); Some(flag) }
                else { Some("invalid".into()) }
            } else { None };
            let tcp = words.first().map(String::as_str) == Some("pass")
                && words.iter().position(|w| w == "proto").map(|p| words.get(p + 1).map(String::as_str) == Some("tcp")).unwrap_or(true);
            if tcp {
                let stateless = words.windows(2).any(|w| w[0] == "no" && w[1] == "state");
                let flags = explicit_flags.unwrap_or_else(|| if stateless { "any".into() } else { "S/SA".into() });
                words.push(format!("tcp-flags={flags}"));
            } else if let Some(flags) = explicit_flags { if flags != "any" { words.push(format!("unexpected-flags={flags}")); } }
            for w in &mut words {
                *w = match w.as_str() { "root" => "0", "bootpc" => "68", "bootps" => "67", "domain" => "53", "mdns" => "5353", "icmp6" => "ipv6-icmp", "dhcpv6-client" => "546", "dhcpv6-server" => "547", _ => w }.to_owned();
                if w.strip_suffix("/32").is_some_and(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok()) { w.truncate(w.len() - 3); }
            }
            out.push(format!("{} {}", family.unwrap_or("both"), words.join(" ")));
        }
    }
    // Quick blocks are ordering barriers. Only passes within the same
    // barrier may be reordered by pfctl's set expansion.
    let mut ordered = Vec::new(); let mut passes = Vec::new();
    for rule in out {
        if rule.contains(" block ") { ordered.extend(normalized_passes(&mut passes)); ordered.push(rule); }
        else { passes.push(rule); }
    }
    ordered.extend(normalized_passes(&mut passes)); ordered
}
fn rules_match(actual: &str, expected: &str) -> bool {
    let lines: Vec<_> = actual.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    lines.last().is_some_and(|l| l.starts_with("block drop out quick") && (l.contains(" all") || l.contains("from any to any")))
        && canonical_rules(actual) == canonical_rules(expected)
}
/// PF may fold literal destinations into automatic tables. Read their actual
/// members in our anchor; the table name alone is never evidence of a match.
fn expand_loaded_tables(text:&str, anchor: &str, get:&mut impl FnMut(&str,&[&str])->Output)->Option<String> {
    let mut names=BTreeSet::new();
    for line in text.lines() {
        let words:Vec<_>=line.split_whitespace().collect();
        let mut count=0;
        for (at,word) in words.iter().enumerate() {
            if !word.starts_with("<__automatic_") {continue;}
            count+=1;
            let name=word.strip_prefix('<')?.strip_suffix('>')?;
            if count>1 || at==0 || words[at-1]!="to" || name.len()>96
                || !name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_') {return None;}
            names.insert(name.to_owned());
        }
    }
    if names.len()>8 {return None;}
    let mut expanded=text.to_owned();let mut budget=8192usize;
    for name in names {
        let loaded=get("/sbin/pfctl",&["-a",anchor,"-t",&name,"-T","show"]);
        if !loaded.ok {return None;}
        let members:Vec<_>=loaded.text.split_whitespace().collect();
        if members.is_empty() || members.len()>4096 {return None;}
        for member in &members {
            let (address,prefix)=member.split_once('/').map(|(a,p)|(a,Some(p))).unwrap_or((member,None));
            let address=address.parse::<std::net::IpAddr>().ok()?;
            if let Some(prefix)=prefix {
                let max=if address.is_ipv4(){32}else{128};
                if prefix.parse::<u32>().ok()?>max {return None;}
            }
        }
        let token=format!("<{name}>");
        budget=budget.checked_sub(expanded.matches(&token).count().checked_mul(members.len())?)?;
        expanded=expanded.replace(&token,&format!("{{ {} }}",members.join(" ")));
    }
    Some(expanded)
}
fn destination(value: &str) -> Option<(u32, u32)> {
    let (ip, bits) = value.split_once('/').map(|(a,b)| (a, b.parse().ok())).unwrap_or((value, None));
    let mut parts: Vec<_> = ip.split('.').collect();
    if parts.len() > 4 { return None; }
    let prefix = bits.unwrap_or((parts.len() * 8) as u32);
    while parts.len() < 4 { parts.push("0"); }
    crate::dns_forwarder::cidr_range(&format!("{}/{prefix}", parts.join(".")))
}
fn routes_match(output: &str, expected: &Expected) -> bool {
    expected.routes.iter().all(|entry| {
        output.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.len() >= 4 && destination(fields[0]) == destination(entry)
                && fields[3] == expected.physical
                && expected.gateway.as_deref() == Some(fields[1])
        })
    })
}

// Only attest to unambiguous local states. Floating, NAT and unfamiliar
// forms stay unconfirmed. No endpoint or state-table text leaves this check.
fn loopback_state(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    if fields.next() != Some("lo0") || !matches!(fields.next(), Some("tcp" | "udp")) {
        return false;
    }
    let local = |field: Option<&str>| field.and_then(|v| v.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|endpoint| endpoint.ip().is_loopback());
    local(fields.next()) && matches!(fields.next(), Some("->" | "<-")) && local(fields.next())
        && fields.next().is_some() && fields.next().is_none()
}

pub(crate) fn confirm_login_rules(pfctl: &str, expected: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut get = |_: &str, args: &[&str]| read_command(pfctl,
        &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(400)));
    let info = get(pfctl, &["-s", "info"]);
    if !info.ok || !info.text.contains("Status: Enabled") { return Err("系统防火墙状态未确认，已停止登录".into()); }
    let anchor = get(pfctl, &["-a", crate::pf::ANCHOR, "-s", "rules"]);
    if !anchor.ok || !expand_loaded_tables(&anchor.text, crate::pf::ANCHOR, &mut get).is_some_and(|actual| rules_match(&actual, expected)) {
        return Err("登录保护规则未确认，已停止登录".into());
    }
    Ok(())
}

/// Confirm the small, unconditional Apple wildcard/direct call chain. Unknown
/// filter rules and populated sibling anchors are conservatively unconfirmed.
fn anchor_calls(text: &str) -> Option<Vec<String>> {
    let lines:Vec<_>=text.lines().map(str::trim).filter(|s|!s.is_empty()&&!s.starts_with('#')&&!s.starts_with("scrub-anchor ")).collect();
    if lines.is_empty() || lines.len()>8 {return None;}
    lines.into_iter().map(|line| {
        let words:Vec<_>=line.split_whitespace().collect();
        if words.len()!=3 || words[0]!="anchor" || words[2]!="all" {return None;}
        Some(words[1].strip_prefix('"')?.strip_suffix('"')?.to_owned())
    }).collect()
}
fn anchor_call(text: &str) -> Option<String> {
    let mut calls=anchor_calls(text)?;
    if calls.len()==1 {calls.pop()} else {None}
}
/// A proxy anchor contains disjoint TCP/UDP redirects, then loopback passes
/// followed by terminal inbound blocks. Compare those groups separately so
/// printer expansion may reorder destinations, but never cross a block.
#[derive(Default, PartialEq)]
struct ProxyRules {
    redirects: Vec<String>,
    passes: Vec<String>,
    blocks: Vec<String>,
}

fn proxy_rules(text: &str) -> Option<ProxyRules> {
    let mut rules = ProxyRules::default();
    for line in text.lines().map(str::trim).filter(|s| !s.is_empty() && !s.starts_with('#')) {
        let section = match line.split_whitespace().next()? {
            "rdr" if rules.passes.is_empty() && rules.blocks.is_empty() => &mut rules.redirects,
            "pass" if rules.blocks.is_empty() => &mut rules.passes,
            "block" => &mut rules.blocks,
            _ => return None,
        };
        section.extend(expand_sets(line));
    }
    rules.redirects = canonical_rules(&rules.redirects.join("\n"));
    rules.passes = canonical_rules(&rules.passes.join("\n"));
    // All expected blocks have the same action after the passes.
    rules.blocks = normalized_passes(&mut canonical_rules(&rules.blocks.join("\n")));
    Some(rules)
}

/// Compare the supervisor's installed intent with independent reads from PF.
/// An empty leftover anchor is valid only when no proxy rules are expected.
pub fn verify_proxy_anchor(expected: Option<&str>, get: &mut impl FnMut(&str,&[&str])->Output) -> Result<(), &'static str> {
    let anchor = crate::pf::PROXY_ANCHOR;
    let mut read = |kind: &str| {
        let out = get("/sbin/pfctl", &["-a", anchor, "-s", kind]);
        if !out.ok { return Err("未能读取分流代理规则"); }
        expand_loaded_tables(&out.text, anchor, get).ok_or("未能核对分流代理规则中的地址表")
    };
    let redirects = read("nat")?;
    let filters = read("rules")?;
    let expected = proxy_rules(expected.unwrap_or("")).ok_or("分流代理的预期规则无法识别")?;
    let actual_nat = proxy_rules(&redirects).ok_or("分流代理的转发规则无法识别")?;
    let actual_filter = proxy_rules(&filters).ok_or("分流代理的过滤规则无法识别")?;
    if !actual_nat.passes.is_empty() || !actual_nat.blocks.is_empty() || !actual_filter.redirects.is_empty()
        || expected.redirects != actual_nat.redirects || expected.passes != actual_filter.passes
        || expected.blocks != actual_filter.blocks { return Err("分流代理实际加载的规则与当前配置不一致"); }
    Ok(())
}

fn anchor_chain(proxy_rules: Option<&str>, get: &mut impl FnMut(&str,&[&str])->Output) -> Result<(), &'static str> {
    let main = get("/sbin/pfctl", &["-s", "rules"]);
    if !main.ok { return Err("未能读取系统主规则"); }
    let calls = anchor_calls(&main.text).ok_or("系统主规则含未确认的过滤或调用")?;
    let mut target = false;
    for name in calls {
        match name.as_str() {
            crate::pf::ANCHOR => {}
            crate::pf::PROXY_ANCHOR => {
                verify_proxy_anchor(proxy_rules, get)?;
                continue;
            }
            "com.apple/*" => apple_children(proxy_rules, get)?,
            "com.apple" => {
                let parent = get("/sbin/pfctl", &["-a", "com.apple", "-s", "rules"]);
                if !parent.ok { return Err("未能读取系统父规则"); }
                match anchor_call(&parent.text).as_deref() {
                    Some("300.AlwaysConnect") | Some(crate::pf::ANCHOR) => {}
                    Some("*") => apple_children(proxy_rules, get)?,
                    _ => return Err("系统父规则未确认调用断线保护"),
                }
            }
            _ => {
                if !valid_sibling(&name) { return Err("系统含无法识别的过滤分支"); }
                empty_anchor(&name, get)?;
                continue;
            }
        }
        if target { return Err("断线保护的调用不唯一"); }
        target = true;
    }
    target.then_some(()).ok_or("未找到断线保护的规则入口")
}

fn valid_sibling(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('-') && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn empty_anchor(name: &str, get: &mut impl FnMut(&str,&[&str])->Output) -> Result<(), &'static str> {
    let other = get("/sbin/pfctl", &["-a", name, "-s", "rules"]);
    if !other.ok { return Err("未能读取其他过滤分支"); }
    if !other.text.trim().is_empty() { return Err("其他过滤分支含未确认的规则"); }
    Ok(())
}

fn apple_children(proxy_rules: Option<&str>, get: &mut impl FnMut(&str,&[&str])->Output) -> Result<(), &'static str> {
    let names = get("/sbin/pfctl", &["-a", "com.apple", "-s", "Anchors"]);
    if !names.ok { return Err("未能读取系统子规则列表"); }
    let mut target = false;
    for name in names.text.lines().map(str::trim).filter(|s| !s.is_empty()) {
        let name = name.trim_matches('"');
        let name = name.strip_prefix("com.apple/").unwrap_or(name);
        if !valid_sibling(name) { return Err("系统含无法识别的过滤分支"); }
        let anchor = format!("com.apple/{name}");
        match anchor.as_str() {
            crate::pf::ANCHOR => target = true,
            crate::pf::PROXY_ANCHOR => verify_proxy_anchor(proxy_rules, get)?,
            _ => empty_anchor(&anchor, get)?,
        }
    }
    target.then_some(()).ok_or("未找到断线保护的系统子规则")
}

/// `exec` is injected in tests. Missing output, permission errors and deadlines
/// are failed observations, never inferred success from the engine's memory.
pub fn run_with(expected: &Expected, mut exec: impl FnMut(&str, &[String]) -> Output) -> Vec<Item> {
    let mut result = Vec::new();
    let mut get = |path: &str, args: &[&str]| exec(path, &args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let Some(tunnel) = &expected.tunnel else {
        result.push(item("当前 VPN 路径", false, "没有已确认的 VPN 隧道"));
        if expected.protection {
            let loaded = get("/sbin/pfctl", &["-a", crate::pf::ANCHOR, "-s", "rules"]);
            let enabled = get("/sbin/pfctl", &["-s", "info"]);
            let matches = loaded.ok && expected.rules.as_ref().is_some_and(|rules| {
                expand_loaded_tables(&loaded.text, crate::pf::ANCHOR, &mut get).is_some_and(|actual|
                    rules_match(&actual, rules))
            });
            let reached = enabled.ok && enabled.text.contains("Status: Enabled") && matches && anchor_chain(expected.proxy_rules.as_deref(), &mut get).is_ok();
            result.push(item("当前拦截规则与调用链", reached,
                "核对防火墙启用状态、拦截规则和上级锚点，规则内的例外仍然适用"));
            let states = get("/sbin/pfctl", &["-s", "states"]);
            let only_loopback = states.ok && states.text.lines().filter(|s| !s.trim().is_empty()).all(loopback_state);
            result.push(item("已有防火墙状态不影响外部拦截", only_loopback,
                if only_loopback { "状态表为空或仅含绑定回环接口的状态" }
                else { "无法排除其他连接沿用旧状态，现有流量的拦截尚未确认" }));
        }
        return result;
    };
    let default = get("/sbin/route", &["-n", "get", "default"]);
    result.push(item("默认路由指向当前隧道", default.ok && interface(&default.text) == Some(tunnel), "读取系统实际默认路由，不比较公网出口 IP"));
    let scoped = get("/sbin/route", &["-n", "get", "-ifscope", tunnel, "default"]);
    result.push(item("绑定 VPN 网卡的 UDP/TCP 路径", scoped.ok && interface(&scoped.text) == Some(tunnel), "核对当前接口限定默认路由；浏览器选用候选仍需实测"));
    let dns = get("/usr/sbin/scutil", &["--dns"]);
    let mut dns_ok = dns.ok && !expected.dns.is_empty() && expected.dns_interface.as_ref() == Some(tunnel);
    if expected.split { dns_ok &= first_dns(&dns.text) == ["127.0.0.1"]; }
    else { let servers = first_dns(&dns.text); dns_ok &= !servers.is_empty() && servers.iter().all(|s| expected.dns.contains(s)); }
    for server in &expected.dns {
        let route = get("/sbin/route", &["-n", "get", "-ifscope", tunnel, server]);
        dns_ok &= route.ok && interface(&route.text) == Some(tunnel);
    }
    result.push(item("公司 DNS 配置与绑定路径", dns_ok, if expected.split { "系统只问本机转发器；核对本次 DNS 绑定与各上游限定路由" } else { "核对网关下发的 DNS 及当前隧道路由" }));
    let mut gateway_ok = !expected.vpn_gateways.is_empty();
    for gateway in &expected.vpn_gateways {
        let route = get("/sbin/route", &["-n", "get", gateway]);
        gateway_ok &= route.ok && interface(&route.text) == Some(expected.physical.as_str());
    }
    result.push(item("网关经当前物理口直连", gateway_ok, "核对实际网关路由"));
    let pf = get("/sbin/pfctl", &["-a", crate::pf::ANCHOR, "-s", "rules"]);
    let info = get("/sbin/pfctl", &["-s", "info"]);
    let enabled=info.ok&&info.text.contains("Status: Enabled");
    let chain = expected.protection.then(|| anchor_chain(expected.proxy_rules.as_deref(), &mut get));
    let reachable = matches!(chain, Some(Ok(())));
    let actual_rules=if pf.ok {expand_loaded_tables(&pf.text,crate::pf::ANCHOR,&mut get)} else {None};
    let configured=actual_rules.as_ref().zip(expected.rules.as_ref()).is_some_and(|(a,e)|rules_match(a,e));
    let effective=enabled&&reachable&&configured;
    if expected.protection {
        let config_detail = if !pf.ok { "未能读取实际防火墙规则" }
            else if actual_rules.is_none() { "实际规则中的地址表未能核对" }
            else if !configured { "实际加载的规则与当前策略不一致" }
            else if expected.error.is_some() { "后台服务报告规则或路由操作未完成" }
            else if !enabled { "规则内容匹配，防火墙启用状态未确认" }
            else if !reachable { "规则内容匹配，但系统调用链未确认" }
            else { "已核对实际加载的规则及系统调用链" };
        result.push(item("实际防火墙配置与当前策略一致", effective && expected.error.is_none(), config_detail));
        result.push(item("pf 已开启", enabled, "读取系统实际过滤状态"));
        result.push(item("断线保护规则调用链已确认", reachable, chain.and_then(Result::err).unwrap_or("已核对系统主规则及其过滤分支")));
        let ipv6_ok=effective && pf.text.lines().last().is_some_and(|l|l.trim().starts_with("block drop out quick"))
            && pf.text.contains("inet proto udp")&&!pf.text.contains(&format!("on {} all",expected.physical));
        result.push(item("物理公网 IPv6 受保护", ipv6_ok, if !effective { "防火墙规则或调用链未确认，暂无法判断物理公网 IPv6 保护" } else { "默认封堵包含 IPv6；DHCP 限 IPv4，链路本地发现保留；显式地址例外另计" }));
        // The pre-existing broad tunnel allowance is visible, never a green
        // assertion that only this VPN can carry protected traffic.
        let other_tunnel = pf.text.lines().flat_map(expand_sets).any(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            words.windows(2).any(|w| w[0] == "on" && w[1].starts_with("utun") && w[1] != tunnel)
        });
        // The DNS barrier precedes the tunnel passes: other tunnels keep their
        // ordinary traffic, not their port-53 DNS (§61.2). Say so.
        let dns_barrier=expected.rules.as_deref().is_some_and(|r|r.contains("block drop out quick proto { udp tcp } to any port 53"));
        let detail=if dns_barrier {"其他隧道的普通流量保留兼容放行，但它们的 DNS（53 端口）被按网站分流的 DNS 保护拦截；本项目不接管其他 VPN，不承诺整机唯一出口"}
            else {"保留其他隧道的兼容放行；本项目不接管其他 VPN，不承诺整机唯一出口"};
        let mut compatibility=item("其他 VPN 隧道兼容", pf.ok && !other_tunnel, detail);
        compatibility.informational=true;result.push(compatibility);
        if expected.split {
            let table = get("/sbin/pfctl", &["-a", crate::pf::ANCHOR, "-t", crate::pf::DIRECT_TABLE, "-T", "show"]);
            let actual: BTreeSet<_> = table.text.split_whitespace().map(str::to_owned).collect();
            result.push(item("实际直连放行名单一致", table.ok && actual == expected.direct.iter().cloned().collect(), "核对内核中的完整 ac_direct 表，不读取缓存作为实际结果"));
        }
    } else {
        let mut off = item("断线保护", false, "使用者已关闭，不能据此确认断线或 IPv6 防漏"); off.informational = true; result.push(off);
    }
    let routes = get("/usr/sbin/netstat", &["-rn", "-f", "inet"]);
    result.push(item("实际直连路由与当前网关一致", routes.ok && routes_match(&routes.text, expected), "核对本会话记账的全部直连主机/网段路由"));
    result
}

/// Bound every subprocess and the entire check, and bound captured output.
/// Only fixed system binaries and read-only arguments are used.
pub fn run(expected: &Expected) -> Vec<Item> {
    let deadline = Instant::now() + Duration::from_secs(2);
    // Active probes run in parallel with the read-only commands (§63).
    let plan = crate::leak_probe::Plan { physical: expected.physical.clone(), local_dns: expected.local_dns.clone(),
        external_v4: Vec::new(), external_v6: None, dns_port: None, tcp_port: None, timeout_ms: 800 };
    let probes = expected.tunnel.is_some().then(|| std::thread::spawn(move || crate::leak_probe::run_child(&plan, Duration::from_millis(1800))));
    let mut items = run_with(expected, |path,args| read_command(path,args,deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(400))));
    if let Some(probes) = probes {
        let report = probes.join().ok().flatten();
        items.extend(crate::leak_probe::items(report.as_ref(), expected.protection));
    }
    items
}

pub(crate) fn read_command(path: &str, args: &[String], limit: Duration) -> Output {
    if limit.is_zero() { return Output::default(); }
    let mut command=Command::new(path);
    let Ok(mut child) = crate::child_io::spawn(command.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())) else { return Output::default() };
    let Some(stdout) = child.stdout.take() else { let _ = child.kill(); let _ = child.wait(); return Output::default() };
    let reader = std::thread::spawn(move || { let mut bytes = Vec::new(); let _ = stdout.take(512 * 1024 + 1).read_to_end(&mut bytes); bytes });
    let stop = Instant::now() + limit;
    let ok = loop {
        if let Ok(Some(status)) = child.try_wait() { break status.success(); }
        if Instant::now() >= stop { let _ = child.kill(); let _ = child.wait(); break false; }
        std::thread::sleep(Duration::from_millis(5));
    };
    let bytes = reader.join().unwrap_or_default();
    Output { ok: ok && bytes.len() <= 512 * 1024, text: String::from_utf8_lossy(&bytes).into_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> Expected {
        let rules = crate::pf::generate(&crate::pf::PfInput { tunnel_if:"utun5".into(), physical_if:"en0".into(), gateway_ips:vec!["203.0.113.1".into()], allow_networks:vec!["192.168.0.0/16".into()], allow_direct_egress:false, allow_dns:false, dns_servers:vec!["192.168.1.1".into()],tunnel_dns_servers:vec!["10.1.1.1".into()],direct_table:true,strict_dns:false,block_direct:false }).unwrap();
        Expected { tunnel:Some("utun5".into()),dns_interface:Some("utun5".into()),physical:"en0".into(),gateway:Some("192.168.1.1".into()),vpn_gateways:vec!["203.0.113.1".into()],dns:vec!["10.1.1.1".into()],split:true,protection:true,rules:Some(rules),proxy_rules:None,direct:vec!["198.51.100.9".into()],routes:vec!["198.51.100.9".into()],error:None,epoch:1,local_dns:vec![] }
    }
    fn fixture(e:&Expected, path:&str,args:&[String]) -> Output {
        let text = if args==["-s","rules"] {"anchor \"com.apple/*\" all".into()}
        else if args==["-a","com.apple","-s","Anchors"] {"300.AlwaysConnect".into()}
        else if args==["-a","com.apple","-s","rules"] {String::new()}
        else if path.ends_with("route") { if args.last().map(String::as_str)==Some("203.0.113.1") { "interface: en0" } else { "interface: utun5" }.into() }
        else if args.last().map(String::as_str)==Some("--dns") { "resolver #1\\n  nameserver[0] : 127.0.0.1\\nresolver #2\\n  nameserver[0] : 192.168.1.1".replace("\\n","\n") }
        else if args.last().map(String::as_str)==Some("rules") { e.rules.clone().unwrap() }
        else if args.last().map(String::as_str)==Some("info") { "Status: Enabled".into() }
        else if args.last().map(String::as_str)==Some("show") { "198.51.100.9".into() }
        else { "Destination Gateway Flags Netif Expire\n198.51.100.9 192.168.1.1 UGHS en0".into() };
        Output{ok:true,text}
    }
    #[test]
    fn pre_tunnel_checks_do_not_certify_unreadable_or_existing_external_states() {
        let mut e = expected();
        e.tunnel = None;
        for (ok, states, clear) in [(true, "", true), (true, "lo0 tcp 127.0.0.1:5000 -> 127.0.0.1:8000 ESTABLISHED:ESTABLISHED", true),
            (true, "lo0 tcp malformed", false),
            (true, "all tcp external", false), (true, "en0 udp active", false), (false, "", false)] {
            let rows = run_with(&e, |p, args| if args == ["-s", "states"] {
                Output { ok, text: states.into() }
            } else { fixture(&e, p, args) });
            assert_eq!(rows.last().unwrap().passed, clear);
        }
        let rows = run_with(&e, |p, args| if args == ["-s", "rules"] {
            Output { ok: true, text: "pass out quick all".into() }
        } else { fixture(&e, p, args) });
        assert!(!rows[1].passed);
    }

    #[test]
    fn missing_parent_disabled_pf_or_earlier_pass_cannot_report_protection() {
        let e=expected();
        for main in ["","pass out quick all\nanchor \"com.apple/*\" all","anchor \"com.apple/*\" all\npass out quick all"] {
            let rows=run_with(&e,|p,a|if a==["-s","rules"] {Output{ok:true,text:main.into()}}else{fixture(&e,p,a)});
            for label in ["实际防火墙配置与当前策略一致","物理公网 IPv6 受保护"] {assert!(!rows.iter().find(|i|i.item==label).unwrap().passed);}
        }
        let rows=run_with(&e,|p,a|if a==["-s","info"] {Output{ok:true,text:"Status: Disabled".into()}}else{fixture(&e,p,a)});
        assert!(!rows.iter().find(|i|i.item=="物理公网 IPv6 受保护").unwrap().passed);
        let rows=run_with(&e,|p,a| {
            if a==["-a","com.apple","-s","Anchors"] {Output{ok:true,text:"100.Other\n300.AlwaysConnect".into()}}
            else if a==["-a","com.apple/100.Other","-s","rules"] {Output{ok:true,text:"pass out quick all".into()}}
            else{fixture(&e,p,a)}
        });
        assert!(!rows.iter().find(|i|i.item=="物理公网 IPv6 受保护").unwrap().passed);
        let direct=run_with(&e,|p,a|if a==["-s","rules"] {Output{ok:true,text:format!("anchor \"{}\" all",crate::pf::ANCHOR)}}else{fixture(&e,p,a)});
        assert!(direct.iter().find(|i|i.item=="物理公网 IPv6 受保护").unwrap().passed);
    }

    #[test]
    fn empty_vendor_anchor_must_not_hide_a_reachable_protection_anchor() {
        let e=expected();
        let main="scrub-anchor \"vendor.vpn\" all fragment reassemble\nanchor \"vendor.vpn\" all\nanchor \"com.apple/*\" all";
        let rows=run_with(&e,|p,a| {
            if a==["-s","rules"] {Output{ok:true,text:main.into()}}
            else if a==["-a","vendor.vpn","-s","rules"] {Output{ok:true,text:String::new()}}
            else {fixture(&e,p,a)}
        });
        assert!(rows.iter().find(|i|i.item=="断线保护规则调用链已确认").unwrap().passed,
            "an inspected empty sibling cannot bypass our outbound protection");
        for (ok,text) in [(false,""),(true,"pass out quick all"),(true,"anchor \"unknown/*\" all")] {
            let rows=run_with(&e,|p,a| {
                if a==["-s","rules"] {Output{ok:true,text:main.into()}}
                else if a==["-a","vendor.vpn","-s","rules"] {Output{ok,text:text.into()}}
                else {fixture(&e,p,a)}
            });
            assert!(!rows.iter().find(|i|i.item=="断线保护规则调用链已确认").unwrap().passed,
                "unknown or populated vendor rules must stay unconfirmed");
        }
    }

    #[test]
    fn active_proxy_anchor_verifies_the_three_linked_firewall_checks() {
        let mut e = expected();
        let intent = crate::pf::proxy_redirect(Some(50123), Some(50124), &["203.0.113.0/24".into()]);
        e.proxy_rules = Some(intent.clone());
        let nat = intent.lines().filter(|l| l.starts_with("rdr ")).collect::<Vec<_>>().join("\n");
        let filter = intent.lines().filter(|l| l.starts_with("pass ") || l.starts_with("block ")).collect::<Vec<_>>().join("\n");
        let filter = filter.replace("port 50123 keep", "port = 50123 flags S/SA keep")
            .replace("port 50124 keep", "port = 50124 keep");
        let run = |e: &Expected, nat: Option<&str>, filter: Option<&str>, anchored: &str| {
            run_with(e, |p, a| {
                if a == ["-a", "com.apple", "-s", "Anchors"] {
                    return Output { ok: true, text: format!("com.apple/300.AlwaysConnect\n{anchored}") };
                }
                if a.first().map(String::as_str) == Some("-a") && a.get(1).is_some_and(|n| n == anchored) {
                    let text = if a.last().is_some_and(|k| k == "nat") { nat } else { filter };
                    return Output { ok: text.is_some(), text: text.unwrap_or_default().into() };
                }
                fixture(e, p, a)
            })
        };
        let anchor = crate::pf::PROXY_ANCHOR;
        let checks = ["实际防火墙配置与当前策略一致", "断线保护规则调用链已确认", "物理公网 IPv6 受保护"];
        let verify = |rows: Vec<Item>, passed| {
            for name in checks {
                assert_eq!(rows.iter().find(|i| i.item == name).unwrap().passed, passed, "{name}");
            }
        };
        verify(run(&e, Some(&nat), Some(&filter), anchor), true);
        for (nat_read, filter_read) in [(None, Some(filter.as_str())), (Some(nat.as_str()), None),
            (Some(""), Some(filter.as_str())), (Some(nat.as_str()), Some(""))] {
            verify(run(&e, nat_read, filter_read, anchor), false);
        }
        verify(run(&e, Some(&nat.replace("50123", "50125")), Some(&filter), anchor), false);
        verify(run(&e, Some(&nat), Some(&filter.replace(" (if-bound)", "")), anchor), false);
        verify(run(&e, Some(&nat), Some(&filter.replace("lo0", "en0")), anchor), false);
        verify(run(&e, Some(&nat), Some(&filter), "com.apple/302.Unexpected"), false);
        e.proxy_rules = None;
        verify(run(&e, Some(&nat), Some(&filter), anchor), false);
        verify(run(&e, Some(""), Some(""), anchor), true);
    }

    #[test]
    fn proxy_tables_must_be_read_from_the_proxy_anchor_and_match_all_destinations() {
        let intent = crate::pf::proxy_redirect(Some(50123), None, &["203.0.113.0/24".into()]);
        let mut nat = Vec::new();
        let mut filters = Vec::new();
        for line in intent.lines().filter(|line| !line.starts_with('#')) {
            let compiled = line.replace("{ 198.19.128.0/17, 203.0.113.0/24 }", "<__automatic_test>");
            if line.starts_with("rdr ") { nat.push(compiled); } else { filters.push(compiled); }
        }
        for (members, accepted) in [(Some("203.0.113.0/24\n198.19.128.0/17"), true),
                                    (Some("198.19.128.0/17"), false), (None, false)] {
            let verified = verify_proxy_anchor(Some(&intent), &mut |_, args| {
                assert_eq!(args[1], crate::pf::PROXY_ANCHOR);
                let value = match &args[2..] {
                    ["-s", "nat"] => Some(nat.join("\n")),
                    ["-s", "rules"] => Some(filters.join("\n")),
                    ["-t", "__automatic_test", "-T", "show"] => members.map(str::to_owned),
                    _ => panic!("unexpected read"),
                };
                Output { ok: value.is_some(), text: value.unwrap_or_default() }
            });
            assert_eq!(verified.is_ok(), accepted);
        }
    }

    #[test]
    fn loaded_config_not_cached_intent_determines_the_verdict() {
        let e=expected(); let good=run_with(&e,|p,a|fixture(&e,p,a));
        assert!(good.iter().filter(|i|!i.informational).all(|i|i.passed));
        assert!(!good.iter().find(|i|i.item=="其他 VPN 隧道兼容").unwrap().passed);
        for corruption in ["route","dns","rules","table","gateway","info","netstat"] {
            let rows=run_with(&e,|p,a|{
                let mut out=fixture(&e,p,a);
                if (corruption=="route"&&p.ends_with("route")) || (corruption=="dns"&&p.ends_with("scutil"))
                    || (corruption=="rules"&&a.last().map(String::as_str)==Some("rules"))
                    || (corruption=="table"&&a.last().map(String::as_str)==Some("show"))
                    || (corruption=="gateway"&&a.last().map(String::as_str)==Some("203.0.113.1"))
                    || (corruption=="info"&&a.last().map(String::as_str)==Some("info"))
                    || (corruption=="netstat"&&p.ends_with("netstat")) {out.text="stale or unavailable".into();}
                out
            });
            assert!(rows.iter().filter(|i|!i.informational).any(|i|!i.passed),"{corruption}");
        }
    }
    #[test]
    fn optimized_address_tables_require_the_actual_members_and_keep_dns_barriers() {
        let mut e=expected();
        let source=e.rules.as_ref().unwrap().replace("pass out quick to 192.168.0.0/16 no state",
            "pass out quick to 192.168.0.0/16 no state\npass out quick to 192.168.1.0/24 no state");
        e.rules=Some(source.clone());
        let optimized=source.replace("pass out quick to 203.0.113.1 no state\n", "")
            .replace("pass out quick to 192.168.1.0/24 no state\n", "")
            .replace("pass out quick to 192.168.0.0/16 no state", "pass out quick to <__automatic_a1b2_0> no state");
        let run=|ok:bool,members:&str|run_with(&e,|p,a| {
            if a==["-a",crate::pf::ANCHOR,"-s","rules"] {Output{ok:true,text:optimized.clone()}}
            else if a==["-a",crate::pf::ANCHOR,"-t","__automatic_a1b2_0","-T","show"] {Output{ok,text:members.into()}}
            else {fixture(&e,p,a)}
        });
        assert!(run(true,"203.0.113.1\n192.168.0.0/16").iter().find(|r|r.item=="实际防火墙配置与当前策略一致").unwrap().passed);
        for (ok,members) in [(false,""),(true,"203.0.113.1"),(true,"203.0.113.1\n192.168.0.0/16\n198.51.100.1"),(true,"0.0.0.0/0"),(true,"<nested>")] {
            assert!(!run(ok,members).iter().find(|r|r.item=="实际防火墙配置与当前策略一致").unwrap().passed);
        }
        let compatibility=run(true,"203.0.113.1\n192.168.0.0/16").into_iter().find(|r|r.item=="其他 VPN 隧道兼容").unwrap();
        assert!(compatibility.informational, "compatibility outside our scope must not require disabling other clients");
        let e=expected();
        let strict=e.rules.as_deref().unwrap().contains("to any port 53");
        let row=run_with(&e,|p,a|fixture(&e,p,a)).into_iter().find(|r|r.item=="其他 VPN 隧道兼容").unwrap();
        assert_eq!(row.detail.contains("DNS（53 端口）被"),strict,"the compatibility note must not hide the DNS barrier");
    }
    #[test]
    fn kernel_parser_output_matches_implicit_flags_and_deduplicated_passes() {
        let source = include_str!("../tests/fixtures/pf-source.conf");
        let actual = include_str!("../tests/fixtures/pf-compiled.conf");
        assert!(rules_match(actual, source));
        let too_strict = actual.replace("on lo0 all no state", "on lo0 all flags S/SA no state");
        assert!(!rules_match(&too_strict, source), "SYN-only pass cannot replace flags-any no-state pass");
        let broader = actual.replace("fe80::/10 flags S/SA keep state", "fe80::/10 flags any keep state");
        assert!(!rules_match(&broader, source), "explicit flags-any differs from the stateful default");
    }

    #[test]
    fn pf_printer_variants_match_but_extra_passes_and_early_blocks_do_not() {
        let e=expected();let rules=e.rules.unwrap();
        let formatted=rules.replace(" no state", " flags any no state").replace(" port 53 no state", " port = domain no state");
        assert_eq!(canonical_rules(&rules),canonical_rules(&formatted));
        let loaded=rules.lines().filter(|l|!l.starts_with('#')&&!l.starts_with("table ")).collect::<Vec<_>>().join("\n");
        assert!(rules_match(&loaded,&rules));
        assert!(!rules_match(&format!("pass out quick all\n{loaded}"),&rules));
        assert!(!rules_match(&format!("block drop out quick all\n{loaded}\npass out quick all"),&rules));
        let deny = "block drop out quick proto { udp tcp } to any port 53";
        let late_deny = loaded.replace(&format!("{deny}\n"), "").replace("block drop out quick all", &format!("{deny}\nblock drop out quick all"));
        assert!(!rules_match(&late_deny, &rules), "moving DNS denial below LAN exceptions must fail");
        assert_eq!(destination("10.20/16"),destination("10.20.0.0/16"));
        assert_eq!(first_dns("resolver #1\n nameserver[0] : 127.0.0.1\nDNS configuration (for scoped queries)\nresolver #1\n nameserver[0] : 192.168.1.1"),vec!["127.0.0.1"]);
    }
}
