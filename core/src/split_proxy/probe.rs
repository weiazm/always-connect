//! A proxy checked on request (§69.8): the App's editor before saving,
//! and its pages while they are open. One connection, closed at once:
//! reach the proxy, complete its handshake (and password), then, when a
//! site is given, ask the proxy to open it. Nothing is sent to the site.

use super::protocol::{connect_proxy, http_connect, socks5_hello, socks5_request, HTTP_NOT_A_PROXY, PROXY_CLOSED};
use super::{Kind, Server, Target};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// The proxy answered; the site (when given) opened through it.
    Ok,
    /// The proxy works, but it could not open the site.
    Warn,
    /// Unreachable, not this kind of proxy, or the password was refused.
    Fail,
}

impl Level {
    pub fn word(self) -> &'static str {
        match self { Level::Ok => "ok", Level::Warn => "warn", Level::Fail => "fail" }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub level: Level,
    pub text: String,
    /// From the first packet to the last answer.
    pub millis: u64,
}

/// The port asked of the proxy for the site: the common one.
const SITE_PORT: u16 = 443;

pub fn probe(server: &Server, site: Option<&str>) -> Probe {
    let started = Instant::now();
    let done = |level: Level, text: String| Probe { level, text, millis: started.elapsed().as_millis() as u64 };
    let site = site.map(str::trim).filter(|s| !s.is_empty());
    let mut stream = match connect_proxy(server) {
        Ok(stream) => stream,
        Err(reason) => return done(Level::Fail, reason),
    };
    match server.kind {
        Kind::Socks5 => {
            if let Err(reason) = socks5_hello(&mut stream, server.auth.as_ref()) { return done(Level::Fail, reason); }
            let Some(site) = site else {
                return done(Level::Ok, if server.auth.is_some() { "代理可用，用户名密码正确".into() } else { "代理可用".into() });
            };
            match socks5_request(&mut stream, 1, &Target::Name(site.to_owned()), SITE_PORT) {
                Ok(_) => done(Level::Ok, format!("经代理打开 {site} 正常")),
                Err(reason) => done(Level::Warn, format!("代理可用，但它打不开 {site}：{reason}")),
            }
        }
        Kind::Http => {
            // An HTTP proxy checks the password only with a request.
            let Some(site) = site else {
                return done(Level::Ok, "代理端口能连上（规则里没有可试的网站名，密码要等用时才核对）".into());
            };
            match http_connect(&mut stream, server.auth.as_ref(), &Target::Name(site.to_owned()), SITE_PORT) {
                Ok(_) => done(Level::Ok, format!("经代理打开 {site} 正常")),
                Err(reason) if reason.contains("用户名") || reason == HTTP_NOT_A_PROXY || reason == PROXY_CLOSED => done(Level::Fail, reason),
                Err(reason) => done(Level::Warn, format!("代理可用，但它打不开 {site}：{reason}")),
            }
        }
    }
}

/// A site to try from a proxy's rules: the first plain or full name.
pub fn site_from_rules<S: AsRef<str>>(rules: &[S]) -> Option<String> {
    rules.iter().find_map(|rule| {
        let rule = rule.as_ref().trim();
        let name = rule.strip_prefix("full:").or_else(|| rule.strip_prefix("domain:")).unwrap_or(rule);
        let plain = !name.is_empty() && name.contains('.') && !name.contains(['/', ':', '*', ' '])
            && name.parse::<std::net::Ipv4Addr>().is_err()
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-');
        plain.then(|| name.trim_matches('.').to_ascii_lowercase())
    })
}
