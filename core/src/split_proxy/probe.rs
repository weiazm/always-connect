//! A proxy checked on request (§69.8): the App's editor before saving,
//! and its pages while they are open. One connection, closed at once:
//! reach the proxy, complete its handshake (and password), then, when a
//! site is given, ask the proxy to open it and wait for the site's first
//! answer to a TLS hello (§70.7): the time is what opening a site through
//! the proxy takes, the same measure for every kind of proxy, and a proxy
//! that says "connected" before the site answered (Hysteria2's fast open)
//! cannot pass a site it cannot reach. The site gets that hello only.

use super::protocol::{connect_proxy, http_connect, socks5_hello, socks5_request, HTTP_NOT_A_PROXY, PROXY_CLOSED};
use super::{Kind, Server, Target};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// How long the site gets to answer the hello through the proxy.
const SITE_ANSWER: Duration = Duration::from_secs(8);

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
            match socks5_request(&mut stream, 1, &Target::Name(site.to_owned()), SITE_PORT)
                .and_then(|_| site_answers(&mut stream, &[], site)) {
                Ok(()) => done(Level::Ok, format!("经代理打开 {site} 正常")),
                Err(reason) => done(Level::Warn, format!("代理可用，但它打不开 {site}：{reason}")),
            }
        }
        Kind::Http => {
            // An HTTP proxy checks the password only with a request.
            let Some(site) = site else {
                return done(Level::Ok, "代理端口能连上（规则里没有可试的网站名，密码要等用时才核对）".into());
            };
            match http_connect(&mut stream, server.auth.as_ref(), &Target::Name(site.to_owned()), SITE_PORT) {
                Ok(early) => match site_answers(&mut stream, &early, site) {
                    Ok(()) => done(Level::Ok, format!("经代理打开 {site} 正常")),
                    Err(reason) => done(Level::Warn, format!("代理可用，但它打不开 {site}：{reason}")),
                },
                Err(reason) if reason.contains("用户名") || reason == HTTP_NOT_A_PROXY || reason == PROXY_CLOSED => done(Level::Fail, reason),
                Err(reason) => done(Level::Warn, format!("代理可用，但它打不开 {site}：{reason}")),
            }
        }
    }
}

/// Sends a TLS hello for `site` through the open tunnel and waits for the
/// first byte of any answer (a server hello, a retry request or an alert:
/// the site answered). `early`: bytes already read past the proxy's reply.
fn site_answers(stream: &mut TcpStream, early: &[u8], site: &str) -> Result<(), String> {
    if !early.is_empty() { return Ok(()); }
    let _ = stream.set_write_timeout(Some(SITE_ANSWER));
    let _ = stream.set_read_timeout(Some(SITE_ANSWER));
    stream.write_all(&client_hello(site)).map_err(|e| format!("网站没有回应（{e}）"))?;
    let mut first = [0u8; 1];
    match stream.read(&mut first) {
        Ok(1) => Ok(()),
        Ok(_) => Err("网站没有回应（连接被关闭）".into()),
        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Err("网站没有回应".into()),
        Err(e) => Err(format!("网站没有回应（{e}）")),
    }
}

/// A plain TLS 1.3 / 1.2 client hello naming `site` (SNI): enough for any
/// HTTPS server to answer. Nothing else of the handshake is ever sent.
pub(crate) fn client_hello(site: &str) -> Vec<u8> {
    fn u16be(out: &mut Vec<u8>, v: usize) { out.extend_from_slice(&(v as u16).to_be_bytes()); }
    let mut random = [0u8; 64];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") { let _ = f.read_exact(&mut random); }
    let host = site.as_bytes();
    let mut ext = Vec::new();
    // server_name
    u16be(&mut ext, 0x0000); u16be(&mut ext, host.len() + 5); u16be(&mut ext, host.len() + 3);
    ext.push(0); u16be(&mut ext, host.len()); ext.extend_from_slice(host);
    // supported_groups: x25519, secp256r1; ec_point_formats: uncompressed
    ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
    ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    // signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256, ecdsa_secp384r1_sha384
    ext.extend_from_slice(&[0x00, 0x0d, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03]);
    // ALPN: h2, http/1.1
    ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, b'h', b'2', 0x08]);
    ext.extend_from_slice(b"http/1.1");
    // supported_versions: TLS 1.3, 1.2
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);
    // key_share: x25519 (any 32 bytes are a public key)
    ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    ext.extend_from_slice(&random[32..64]);
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&random[..32]);
    body.push(32);
    body.extend_from_slice(&random[32..64]);
    let suites: [u16; 7] = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030];
    u16be(&mut body, suites.len() * 2);
    for suite in suites { body.extend_from_slice(&suite.to_be_bytes()); }
    body.extend_from_slice(&[0x01, 0x00]);
    u16be(&mut body, ext.len());
    body.extend_from_slice(&ext);
    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    u16be(&mut record, handshake.len());
    record.extend_from_slice(&handshake);
    record
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
