//! The proxied sites' local plumbing (§69, §69.20): the rule table the DNS
//! forwarder answers from, the receiving listener, the loopback routes and
//! the pf redirect. One owner at a time: the own connection's split session
//! or the proxy-only session (Cisco off); both use these two functions, so
//! the order of steps and the fail-closed rule are the same.

use super::{Listener, Routing, Table};
use crate::direct_routes::{self, DirectRoutes};
use crate::dns_forwarder::Forwarder;
use crate::network_guard::{self, Guard};
use std::collections::HashSet;
use std::sync::Arc;

/// One owner's proxied sites.
pub struct RedirectSession {
    pub routing: Arc<Routing>,
    pub listener: Option<Listener>,
    /// The pf text now loaded in the proxy anchor.
    pub loaded: Option<String>,
}

/// Brings the proxied sites in line with `table`: answers first, then the
/// listener, routes and pf redirect. An empty table stops everything.
/// Returns false when the redirect is not (fully) in place: proxied names
/// still get our addresses, so those sites cannot be reached at all, never
/// reached another way. `no_routes`: tests and the session harness, answers only.
pub fn sync(session: &mut Option<RedirectSession>, table: Table, forwarder: &Forwarder, routes: &DirectRoutes,
            guard: Option<&Guard>, no_routes: bool) -> bool {
    sync_with_egress(session, table, forwarder, routes, guard, no_routes, None, false, Some(("", "")))
}

/// Like `sync`, attaching an optional exit-protection gate (`egress`). When
/// `local_egress` is true (proxy-only mode with active exit protection, §71),
/// the redirect stays alive even if `table` has no proxy rules so non-proxied
/// protected sites still pass through the relay gate.
#[allow(clippy::too_many_arguments)]
pub fn sync_with_egress(
    session: &mut Option<RedirectSession>,
    table: Table,
    forwarder: &Forwarder,
    routes: &DirectRoutes,
    guard: Option<&Guard>,
    no_routes: bool,
    egress: Option<crate::egress_control::RelayGate>,
    local_egress: bool,
    physical_path: Option<(&str, &str)>,
) -> bool {
    if table.is_empty() && !local_egress {
        stop(session, Some(forwarder), routes, guard, no_routes);
        return true;
    }
    // Networks inside the Mac's own LAN stay local, like the direct list's.
    // A proxy's own server inside a written network is cut out of it: its
    // connection would otherwise come back here and go to the proxy again.
    let networks = without_addresses(
        direct_routes::networks_to_route(&table.networks(), &direct_routes::attached_networks()),
        &table.server_addresses());
    let udp = table.carries_udp();
    let hysteria_specs = table.hysteria_specs();
    match session {
        Some(s) => s.routing.set_table(table),
        None => *session = Some(RedirectSession { routing: Routing::new(table), listener: None, loaded: None }),
    }
    let s = session.as_mut().expect("just set");
    s.routing.set_egress(egress, local_egress);
    forwarder.set_proxy(Some(s.routing.clone()));
    // A proxy on this Mac resolves through us too: its own connections get
    // real addresses by the ordinary split.
    let inner = Arc::downgrade(forwarder.inner());
    let resolver: super::Resolver = Arc::new(move |name: &str| {
        inner.upgrade().map(|inner| inner.resolve_plain(name)).unwrap_or_default()
    });
    s.routing.set_resolver(Some(resolver.clone()));
    super::hysteria::shared().sync_on_path(hysteria_specs, s.routing.clone(), Some(resolver), physical_path);
    if no_routes { return true; }
    if s.listener.is_none() {
        match super::pf_original_destination().and_then(|original| Listener::start(s.routing.clone(), original)) {
            Ok(listener) => s.listener = Some(listener),
            Err(e) => network_guard::log(&format!("split proxy: listener did not start: {e}")),
        }
    }
    let wanted: HashSet<String> = std::iter::once(super::FAKE_NETWORK.to_owned()).chain(networks.iter().cloned()).collect();
    let actual: HashSet<String> = routes.managed_addresses().into_iter().collect();
    let gone: Vec<_> = actual.difference(&wanted).cloned().collect();
    let new: Vec<_> = wanted.difference(&actual).cloned().collect();
    let removed = routes.remove(&gone);
    let added = routes.add(&new, "127.0.0.1");
    let routed: HashSet<String> = routes.addresses().into_iter().collect();
    if !removed || !added || routed != wanted { network_guard::log("split proxy: loopback routes not confirmed"); }
    let tcp = s.listener.as_ref().map(|l| l.port());
    let udp_port = s.listener.as_ref().filter(|_| udp).map(|l| l.udp_port());
    let text = crate::pf::proxy_redirect(tcp, udp_port, &networks);
    if s.loaded.as_deref() != Some(text.as_str()) {
        match guard.map(|g| g.proxy_redirect(Some(&text))) {
            Some(Ok(())) => s.loaded = Some(text.clone()),
            Some(Err(e)) => { s.loaded = None; network_guard::log(&format!("split proxy: pf redirect failed: {e}")); }
            None => { s.loaded = None; network_guard::log("split proxy: no network guard for the redirect"); }
        }
    }
    tcp.is_some() && routed == wanted && s.loaded.as_deref() == Some(text.as_str())
}

/// Takes the redirect, routes and listener out (answers stop first).
pub fn stop(session: &mut Option<RedirectSession>, forwarder: Option<&Forwarder>, routes: &DirectRoutes,
            guard: Option<&Guard>, no_routes: bool) {
    stop_with_handover(session, forwarder, routes, guard, no_routes, false);
}

/// Like `stop`, but when `handover` is true keeps managed Hysteria2 children
/// alive across the brief handover between proxy-only and own-connection.
pub fn stop_with_handover(session: &mut Option<RedirectSession>, forwarder: Option<&Forwarder>, routes: &DirectRoutes,
                          guard: Option<&Guard>, no_routes: bool, handover: bool) {
    if handover {
        super::hysteria::shared().begin_handover();
    } else {
        super::hysteria::shared().stop_all();
    }
    let Some(mut s) = session.take() else { return };
    s.routing.set_egress(None, false);
    if let Some(f) = forwarder { f.set_proxy(None); }
    if !no_routes {
        if let Some(Err(e)) = guard.map(|g| g.proxy_redirect(None)) {
            network_guard::log(&format!("split proxy: pf redirect not removed: {e}"));
        }
        if !routes.remove_all() { network_guard::log("split proxy: loopback route removal not confirmed"); }
    }
    if let Some(listener) = s.listener.as_mut() { listener.stop(); }
}

/// `networks` with each of `addresses` cut out: a network holding one is
/// replaced by the at most 32 networks that cover the rest of it.
pub fn without_addresses(networks: Vec<String>, addresses: &[std::net::Ipv4Addr]) -> Vec<String> {
    let mut out = networks;
    for address in addresses {
        let ip = u32::from(*address);
        out = out.into_iter().flat_map(|cidr| {
            let written = if cidr.contains('/') { cidr.clone() } else { format!("{cidr}/32") };
            let Some((lo, hi)) = crate::dns_forwarder::cidr_range(&written) else { return vec![cidr] };
            if ip < lo || ip > hi { return vec![cidr]; }
            let Some(mut len) = written.split_once('/').and_then(|(_, bits)| bits.parse::<u32>().ok()) else { return vec![cidr] };
            let mut base = lo;
            let mut pieces = Vec::new();
            while len < 32 {
                len += 1;
                let half = 1u32 << (32 - len);
                if ip - base >= half {
                    pieces.push(format!("{}/{len}", std::net::Ipv4Addr::from(base)));
                    base += half;
                } else {
                    pieces.push(format!("{}/{len}", std::net::Ipv4Addr::from(base + half)));
                }
            }
            pieces
        }).collect();
    }
    let mut seen = HashSet::new();
    out.retain(|cidr| seen.insert(cidr.clone()));
    out
}

#[cfg(test)]
mod tests {
    use super::without_addresses;
    use std::net::Ipv4Addr;

    fn covers(pieces: &[String], ip: Ipv4Addr) -> bool {
        pieces.iter().any(|c| crate::dns_forwarder::cidr_range(c).is_some_and(|(lo, hi)| (lo..=hi).contains(&u32::from(ip))))
    }

    #[test]
    fn a_proxy_server_inside_a_written_network_is_cut_out() {
        let server = Ipv4Addr::new(203, 0, 113, 77);
        let pieces = without_addresses(vec!["203.0.113.0/24".into(), "198.51.100.0/24".into()], &[server]);
        assert!(!covers(&pieces, server));
        assert!(pieces.contains(&"198.51.100.0/24".to_string()), "{pieces:?}");
        // Every other address of the /24 is still routed, by 8 pieces.
        for last in (0..=255u8).filter(|n| *n != 77) {
            assert!(covers(&pieces, Ipv4Addr::new(203, 0, 113, last)), "{last} {pieces:?}");
        }
        assert_eq!(pieces.len(), 1 + 8);
    }

    #[test]
    fn wide_networks_single_addresses_and_untouched_lists() {
        let server = Ipv4Addr::new(198, 51, 100, 7);
        let wide = without_addresses(vec!["198.0.0.0/8".into()], &[server]);
        assert_eq!(wide.len(), 24);
        assert!(!covers(&wide, server));
        assert!(covers(&wide, Ipv4Addr::new(198, 51, 100, 6)) && covers(&wide, Ipv4Addr::new(198, 255, 0, 1)));
        assert!(without_addresses(vec!["198.51.100.7/32".into()], &[server]).is_empty());
        assert!(without_addresses(vec!["198.51.100.7".into()], &[server]).is_empty());
        let other = vec!["10.9.0.0/16".to_string()];
        assert_eq!(without_addresses(other.clone(), &[server]), other);
        // Two servers in one network.
        let two = without_addresses(vec!["203.0.113.0/24".into()], &[Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 200)]);
        assert!(!covers(&two, Ipv4Addr::new(203, 0, 113, 1)) && !covers(&two, Ipv4Addr::new(203, 0, 113, 200)));
        assert!(covers(&two, Ipv4Addr::new(203, 0, 113, 2)) && covers(&two, Ipv4Addr::new(203, 0, 113, 199)));
    }
}
