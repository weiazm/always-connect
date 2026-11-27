//! Proxies with Cisco off (DESIGN.md §69.20; user, 2026-11-26: "是时候考虑支持
//! 关闭公司vpn的能力，只开代理了"). The same parts as the own connection's
//! split (§69): the DNS forwarder answers proxied names with our addresses,
//! the redirect hands their connections to the proxies. What the tunnel did
//! for the split, two things do here:
//! - The system asks our forwarder: one DNS entry of our own in configd,
//!   `State:/Network/Service/AlwaysConnect-Proxy/DNS`, 127.0.0.1 for every
//!   domain (an empty supplemental match domain). No route, no other
//!   service and no setting of the user's is touched; removing the entry
//!   gives the Mac back exactly what it had (CI on a real macOS runner,
//!   2026-11-26). Rewriting the primary service's DNS left the runner
//!   without DNS after the removal, so that way is not used.
//! - Every other name is asked of the local network's own DNS servers,
//!   bound to the physical interface (never back to ourselves).
//! Everything not proxied goes straight out the local network; there is no
//! tunnel to keep traffic in. Fail closed as everywhere in §69: a proxied
//! site whose proxy cannot be reached does not open.

use crate::direct_routes::DirectRoutes;
use crate::dns_forwarder::{Forwarder, SplitRules, Upstreams};
use crate::egress_control::{Controller, EgressConfig, LocalPolicy, Observation, ProbeHook};
use crate::network_guard;
use crate::split_proxy::{redirect, RedirectSession, Table};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

/// Our own configd service: only a DNS dictionary, never IPv4, so it can
/// never become the primary service or carry a route.
pub const DNS_SERVICE: &str = "AlwaysConnect-Proxy";
/// The same ledger as the split session's: only one of the two owns the
/// proxied sites at a time.
const ROUTES: &str = crate::oc_engine::PROXY_ROUTES;
pub const PORT_BUSY: &str = "本机 53 端口被其他程序占用，只开代理暂时不能用";
pub const REDIRECT_FAILED: &str = "代理转发没能接通，走代理的网站暂时打不开（不会改走直连）";
pub const DNS_FAILED: &str = "没能让系统经过本机的 DNS 转发，走代理的网站暂时可能直连；已停止只开代理";

/// Whether the proxy-only session should run now. Only when the user wants
/// proxies and nothing else owns them: the own connection's split runs them
/// itself, and while Cisco's own client is connected its filter decides
/// where traffic goes (§二十一).
pub fn should_run(wanted: bool, engine_active: bool, cisco_active: bool) -> bool {
    wanted && !engine_active && !cisco_active
}

/// The scutil input that puts our DNS entry in place (`on`) or removes it.
pub fn dns_script(on: bool) -> String {
    let key = format!("State:/Network/Service/{DNS_SERVICE}/DNS");
    if on {
        format!("open\nd.init\nd.add ServerAddresses * 127.0.0.1\nd.add SupplementalMatchDomains * \"\"\nset {key}\nclose\n")
    } else {
        format!("open\nremove {key}\nclose\n")
    }
}

/// Applies `dns_script`; true when scutil accepted it.
pub fn set_dns(on: bool) -> bool {
    let child = crate::child_io::spawn(Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()));
    let Ok(mut child) = child else { return false };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(dns_script(on).as_bytes());
    }
    child.wait().is_ok_and(|status| status.success())
}

/// What the session needs from the Mac (the service reads it from configd).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Network {
    /// The physical interface the local DNS servers are reached on.
    pub interface: Option<String>,
    pub dns: Vec<String>,
}

fn upstreams(network: &Network) -> Upstreams {
    // The "tunnel" path of the forwarder is simply the local network here:
    // every name that is not proxied is asked there, bound to its interface.
    Upstreams { tunnel: network.dns.clone(), local: network.dns.clone(),
                physical_if: network.interface.clone(), tunnel_if: network.interface.clone() }
}

pub struct ProxyOnly {
    forwarder: Forwarder,
    session: Option<RedirectSession>,
    routes: DirectRoutes,
    network: Network,
    lines: Vec<String>,
    no_routes: bool,
    error: Option<&'static str>,
    egress_cfg: Option<EgressConfig>,
    egress_probe: Option<ProbeHook>,
    egress: Option<Controller>,
}

impl ProxyOnly {
    /// `listen`: 53 in the service, another port in tests; `no_routes`:
    /// tests, answers only (no routes, pf or DNS entry).
    pub fn start(lines: Vec<String>, network: Network, support: &Path, boot: String, listen: u16,
                 no_routes: bool) -> Result<Self, &'static str> {
        Self::start_with_egress(lines, network, support, boot, listen, no_routes, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_with_egress(
        lines: Vec<String>,
        network: Network,
        support: &Path,
        boot: String,
        listen: u16,
        no_routes: bool,
        egress_cfg: Option<EgressConfig>,
        egress_probe: Option<ProbeHook>,
    ) -> Result<Self, &'static str> {
        let forwarder = Forwarder::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, listen), 53, Duration::from_secs(2),
                                       lines.clone(), upstreams(&network), None);
        forwarder.start().map_err(|_| PORT_BUSY)?;
        let mut me = ProxyOnly {
            forwarder, session: None,
            routes: DirectRoutes::new(support.join(ROUTES), boot, no_routes),
            network, lines: lines.clone(), no_routes, error: None,
            egress_cfg, egress_probe, egress: None,
        };
        me.sync_all();
        if !no_routes && !set_dns(true) {
            me.stop();
            return Err(DNS_FAILED);
        }
        network_guard::log("proxy only: started");
        Ok(me)
    }

    /// New rules from the App (the split list with the proxies in it).
    pub fn update_rules(&mut self, lines: Vec<String>) {
        self.lines = lines;
        self.sync_all();
    }

    /// Update exit-protection configuration in place (§71).
    pub fn update_egress(&mut self, cfg: Option<EgressConfig>) {
        if self.egress_cfg == cfg { return; }
        self.egress_cfg = cfg;
        self.sync_all();
    }

    /// The Mac moved to another network or its DNS servers changed.
    pub fn update_network(&mut self, network: Network) {
        if network == self.network { return; }
        self.forwarder.set_upstreams(upstreams(&network));
        if let Some(ctl) = &self.egress {
            ctl.invalidate();
        }
        self.network = network;
    }

    fn sync_all(&mut self) {
        let active_egress = self.egress_cfg.as_ref().filter(|e| e.active()).cloned();
        let protected = active_egress.as_ref().map(|e| Arc::new(e.protected_sites()));
        let rules = SplitRules::new(&self.lines).with_protection(protected);
        self.forwarder.set_parsed_rules(rules);

        let local_egress = active_egress.as_ref()
            .is_some_and(|e| e.local_policy() != LocalPolicy::Bypass);
        match active_egress {
            Some(cfg) => match &self.egress {
                Some(ctl) => ctl.update(cfg),
                None => {
                    let hook = self.egress_probe.clone()
                        .unwrap_or_else(|| Arc::new(|_: &crate::egress_control::ProbeRequest, _| None));
                    match Controller::in_process(cfg, hook) {
                        Ok(ctl) => self.egress = Some(ctl),
                        Err(e) => network_guard::log(&format!("proxy only: egress controller failed: {e}")),
                    }
                }
            },
            None => { self.egress = None; }
        }

        let table = Table::parse(&self.lines);
        let guard = network_guard::shared();
        let gate = self.egress.as_ref().map(|c| c.relay_gate());
        let ok = redirect::sync_with_egress(
            &mut self.session, table, &self.forwarder, &self.routes, guard.as_deref(), self.no_routes, gate, local_egress);
        self.error = (!ok).then_some(REDIRECT_FAILED);
        if !ok { network_guard::log(REDIRECT_FAILED); }
    }

    /// Exit-protection status JSON in proxy-only mode (§71).
    pub fn egress_status(&self) -> String {
        self.egress.as_ref().map(|c| c.status_json()).unwrap_or_else(|| "{}".into())
    }

    /// Returns a recheck closure so the caller can drop the ProxyOnly lock
    /// before executing network I/O.
    pub fn recheck_egress_job(&self, group: u32) -> Option<Box<dyn FnOnce() -> bool + Send>> {
        self.egress.as_ref()?.recheck_job(group).map(|f| Box::new(f) as Box<dyn FnOnce() -> bool + Send>)
    }

    pub fn allow_egress_country(
        &mut self,
        expected: &EgressConfig,
        group: u32,
        started: f64,
        country: &str,
        evidence: &Observation,
    ) -> Option<Vec<String>> {
        let cfg = self.egress.as_ref()?.allow_country(expected, group, started, country, evidence)?;
        let countries = cfg.group(group)?.expect.clone();
        self.egress_cfg = Some(cfg);
        Some(countries)
    }

    /// The DNS entry first (the Mac asks its own servers again at once),
    /// then the redirect, routes and forwarder.
    pub fn stop(&mut self) {
        self.stop_with_handover(false);
    }

    /// Stops proxy-only; when `handover` is true, keeps managed Hysteria2
    /// clients alive for the incoming own-connection split session.
    pub fn stop_with_handover(&mut self, handover: bool) {
        if !self.no_routes && !set_dns(false) { network_guard::log("proxy only: DNS entry removal not confirmed"); }
        let guard = network_guard::shared();
        redirect::stop_with_handover(&mut self.session, Some(&self.forwarder), &self.routes, guard.as_deref(), self.no_routes, handover);
        self.egress = None;
        self.forwarder.stop();
        network_guard::log("proxy only: stopped");
    }

    /// The panel's part of the split status (§69.8, §69.17), same keys.
    pub fn status_json(&self) -> String {
        let proxy = self.session.as_ref().map(|s| s.routing.clone());
        let notice = self.error.map(str::to_owned).or_else(|| proxy.as_ref().and_then(|p| p.recent_notice()))
            .or_else(|| self.forwarder.inner().recent_dns_notice());
        serde_json::json!({
            "proxyOnly": true,
            "splitRunning": false, "splitHits": Vec::<String>::new(), "splitAddresses": 0,
            "dnsNotice": notice,
            "proxyConnections": proxy.as_ref().map(|p| p.connections()),
            "proxyBytes": proxy.as_ref().map(|p| p.traffic_json()),
            "proxyHealth": proxy.map(|p| p.health_json()),
        }).to_string()
    }

    /// The local address the forwarder gave a proxied name (connections page).
    pub fn name_for(&self, ip: Ipv4Addr) -> Option<String> { self.forwarder.name_for(ip) }

    /// The proxied sites' table (the root check on CI marks its stand-in
    /// proxies, which live in the checking process, as apps).
    pub fn routing(&self) -> Option<std::sync::Arc<crate::split_proxy::Routing>> {
        self.session.as_ref().map(|s| s.routing.clone())
    }
}

/// A service that stopped without stopping the session (crash, power) left
/// the DNS entry behind: the Mac would ask a forwarder that is not there.
/// Called when the service starts and before a connection takes over.
pub fn remove_leftover() {
    if !set_dns(false) { network_guard::log("proxy only: leftover DNS entry not confirmed removed"); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::time::Duration;

    fn query(name: &str) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') { q.push(label.len() as u8); q.extend_from_slice(label.as_bytes()); }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    fn ask(port: u16, name: &str) -> Option<Vec<Ipv4Addr>> {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.send_to(&query(name), ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 512];
        let n = s.recv(&mut buf).ok()?;
        Some(crate::dns_forwarder::ipv4_answers(&buf[..n]))
    }

    /// A local "network DNS" answering 203.0.113.9 for everything.
    fn upstream() -> (u16, std::sync::mpsc::Receiver<String>) {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = s.recv_from(&mut buf) {
                let q = &buf[..n];
                let mut i = 12; let mut labels = Vec::new();
                while q[i] != 0 { let l = q[i] as usize; labels.push(String::from_utf8_lossy(&q[i + 1..i + 1 + l]).to_string()); i += l + 1; }
                let _ = tx.send(labels.join("."));
                let mut out = q[..2].to_vec();
                out.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                out.extend_from_slice(&q[12..i + 5]);
                out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 9]);
                let _ = s.send_to(&out, from);
            }
        });
        (port, rx)
    }

    #[test]
    fn runs_only_when_wanted_and_nothing_else_owns_the_proxies() {
        assert!(should_run(true, false, false));
        assert!(!should_run(false, false, false));
        assert!(!should_run(true, true, false), "the own connection's split runs them");
        assert!(!should_run(true, false, true), "Cisco's client decides while it is connected");
    }

    #[test]
    fn the_dns_entry_is_ours_alone_and_only_dns() {
        let on = dns_script(true);
        assert!(on.contains("State:/Network/Service/AlwaysConnect-Proxy/DNS"));
        assert!(on.contains("ServerAddresses * 127.0.0.1") && on.contains("SupplementalMatchDomains * \"\""));
        assert!(!on.contains("IPv4") && !on.contains("OverridePrimary"), "never a primary service or a route");
        assert_eq!(dns_script(false), "open\nremove State:/Network/Service/AlwaysConnect-Proxy/DNS\nclose\n");
    }

    #[test]
    fn proxied_names_get_our_address_and_the_rest_ask_the_local_network() {
        // §69.20: with Cisco off, names of proxied sites never reach any
        // DNS server; every other name is asked of the local network's.
        let (upstream_port, asked) = upstream();
        let dir = std::env::temp_dir().join(format!("ac-proxy-only-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lines = vec!["proxy:0 socks5 192.0.2.5 1080".to_string(), "via:0:proxied.example".to_string()];
        let listen = 25353;
        let lo = if cfg!(target_os = "macos") { "lo0" } else { "lo" };
        let mut session = ProxyOnly::start(lines, Network { interface: Some(lo.into()), dns: vec![format!("127.0.0.1:{upstream_port}")] },
                                           &dir, "B1".into(), listen, true).expect("started");
        let proxied = ask(listen, "www.proxied.example").expect("answered");
        assert!(proxied.len() == 1 && crate::split_proxy::is_fake(proxied[0]), "our address: {proxied:?}");
        assert!(asked.try_recv().is_err(), "the proxied name was asked of no server");
        assert_eq!(ask(listen, "plain.example").expect("answered"), vec![Ipv4Addr::new(203, 0, 113, 9)]);
        assert_eq!(asked.recv_timeout(Duration::from_secs(2)).unwrap(), "plain.example");
        assert!(session.status_json().contains("\"proxyOnly\":true"));
        // Rules change in place: the site is no longer proxied.
        session.update_rules(vec![]);
        assert_eq!(ask(listen, "www.proxied.example").expect("answered"), vec![Ipv4Addr::new(203, 0, 113, 9)]);
        session.stop();
        assert!(ask(listen, "plain.example").is_none(), "stopped: the port is free again");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
