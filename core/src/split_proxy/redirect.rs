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
    if table.is_empty() {
        stop(session, Some(forwarder), routes, guard, no_routes);
        return true;
    }
    // Networks inside the Mac's own LAN stay local, like the direct list's.
    let networks = direct_routes::networks_to_route(&table.networks(), &direct_routes::attached_networks());
    let udp = table.carries_udp();
    match session {
        Some(s) => s.routing.set_table(table),
        None => *session = Some(RedirectSession { routing: Routing::new(table), listener: None, loaded: None }),
    }
    let s = session.as_mut().expect("just set");
    forwarder.set_proxy(Some(s.routing.clone()));
    // A proxy on this Mac resolves through us too: its own connections get
    // real addresses by the ordinary split.
    let inner = Arc::downgrade(forwarder.inner());
    s.routing.set_resolver(Some(Arc::new(move |name: &str| {
        inner.upgrade().map(|inner| inner.resolve_plain(name)).unwrap_or_default()
    })));
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
    let Some(mut s) = session.take() else { return };
    if let Some(f) = forwarder { f.set_proxy(None); }
    if !no_routes {
        if let Some(Err(e)) = guard.map(|g| g.proxy_redirect(None)) {
            network_guard::log(&format!("split proxy: pf redirect not removed: {e}"));
        }
        if !routes.remove_all() { network_guard::log("split proxy: loopback route removal not confirmed"); }
    }
    if let Some(listener) = s.listener.as_mut() { listener.stop(); }
}
