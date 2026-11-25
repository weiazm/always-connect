//! Steering a protected name to an entry of the same CDN whose exit was
//! verified for that name (DESIGN §66.28). The company VPN picks the exit
//! by destination address, so a Cloudflare-hosted name reached through a
//! different Cloudflare address leaves from a different place. Traffic
//! stays in the VPN; the gate still checks every connection.

use super::*;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Instant;

/// How long an observed exit counts (§66.28: 10 minutes).
pub(super) const LEDGER_LIFETIME: Duration = Duration::from_secs(600);
const MAX_LEDGER: usize = 4096;
/// Entries tried for one name per search.
const MAX_CANDIDATES: usize = 4;
/// Addresses given in one steered answer.
const MAX_STEERED: usize = 2;

/// Cloudflare's published IPv4 ranges (cloudflare.com/ips-v4). An outdated
/// table only means fewer substitutions: each one is verified first.
const CLOUDFLARE_V4: &[&str] = &[
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
];

pub(crate) fn cloudflare(ip: Ipv4Addr) -> bool {
    let v = u32::from(ip);
    CLOUDFLARE_V4.iter().filter_map(|c| crate::dns_forwarder::cidr_range(c)).any(|(lo, hi)| lo <= v && v <= hi)
}

/// Exits seen per (name, address), from checks and searches.
#[derive(Default)]
pub(super) struct Ledger {
    seen: HashMap<(String, Ipv4Addr), (String, Instant)>,
    pub searching: HashSet<String>,
}

impl Ledger {
    pub fn note(&mut self, host: &str, ip: IpAddr, country: &str, now: Instant) {
        let IpAddr::V4(ip) = ip else { return };
        if host.is_empty() {
            return;
        }
        if self.seen.len() >= MAX_LEDGER {
            self.seen.retain(|_, (_, at)| now.duration_since(*at) < LEDGER_LIFETIME);
            if self.seen.len() >= MAX_LEDGER {
                return;
            }
        }
        self.seen.insert((host.to_owned(), ip), (country.to_owned(), now));
    }

    pub fn clear(&mut self) {
        self.seen.clear();
        self.searching.clear();
    }

    fn country(&self, host: &str, ip: Ipv4Addr, now: Instant) -> Option<&str> {
        self.seen.get(&(host.to_owned(), ip))
            .filter(|(_, at)| now.duration_since(*at) < LEDGER_LIFETIME)
            .map(|(country, _)| country.as_str())
    }

    fn wrong(&self, group: &Group, host: &str, ip: Ipv4Addr, now: Instant) -> bool {
        self.country(host, ip, now).is_some_and(|country| !group.allows(country))
    }

    /// Every address of an answer is known to exit from a wrong country.
    pub fn all_wrong(&self, group: &Group, host: &str, answer: &[Ipv4Addr], now: Instant) -> bool {
        !answer.is_empty() && answer.iter().all(|ip| self.wrong(group, host, *ip, now))
    }

    /// The answer to give for `host`, None to keep the resolver's: known
    /// wrong addresses are dropped; when all are wrong and all are
    /// Cloudflare's, addresses verified for this very name replace them.
    pub fn steer(&self, group: &Group, host: &str, answer: &[Ipv4Addr], now: Instant) -> Option<Vec<Ipv4Addr>> {
        let keep: Vec<_> = answer.iter().copied().filter(|ip| !self.wrong(group, host, *ip, now)).collect();
        if keep.len() == answer.len() {
            return None;
        }
        if !keep.is_empty() {
            return Some(keep);
        }
        if !answer.iter().all(|ip| cloudflare(*ip)) {
            return None;
        }
        let mut verified: Vec<_> = self.seen.iter()
            .filter(|((name, ip), (country, at))| name == host && now.duration_since(*at) < LEDGER_LIFETIME
                && group.allows(country) && cloudflare(*ip))
            .map(|((_, ip), (_, at))| (*at, *ip))
            .collect();
        verified.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let verified: Vec<_> = verified.into_iter().map(|(_, ip)| ip).take(MAX_STEERED).collect();
        (!verified.is_empty()).then_some(verified)
    }

    /// Cloudflare addresses to try for `host`: those any name recently
    /// reached with an exit this rule allows, not yet tried for `host`.
    pub fn candidates(&self, group: &Group, host: &str, now: Instant) -> Vec<Ipv4Addr> {
        let mut found: Vec<(Instant, Ipv4Addr)> = Vec::new();
        for ((name, ip), (country, at)) in &self.seen {
            if name != host && now.duration_since(*at) < LEDGER_LIFETIME && group.allows(country)
                && cloudflare(*ip) && self.country(host, *ip, now).is_none()
                && !found.iter().any(|(_, seen)| seen == ip)
            {
                found.push((*at, *ip));
            }
        }
        found.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        found.into_iter().map(|(_, ip)| ip).take(MAX_CANDIDATES).collect()
    }
}

impl ControlState {
    /// A verified entry was found for `host`: its wrong Cloudflare entries
    /// are bypassed by DNS from now on, so they no longer hold the rule in
    /// the blocked state (or block unreadable exits under "whenWrong").
    /// The gate still checks any connection that reaches them anyway.
    pub(super) fn bypassed(&mut self, group: &Group, host: &str) {
        if let Some(failed) = self.failures.get_mut(&group.id) {
            failed.retain(|f| !(f.target.host == host && matches!(f.target.ip, IpAddr::V4(ip) if cloudflare(ip))));
            if failed.is_empty() {
                self.failures.remove(&group.id);
            }
        }
        self.note_steered(group, host);
        self.settle();
    }

    pub(super) fn note_steered(&mut self, group: &Group, host: &str) {
        let st = self.status.group(group);
        if !st.steered.iter().any(|name| name == host) {
            if st.steered.len() >= 16 {
                st.steered.remove(0);
            }
            st.steered.push(host.to_owned());
        }
    }

    /// Start looking for a verified entry for `host` unless one is being
    /// looked for already. Returns the job to run off the lock.
    pub(super) fn search_job(&mut self, shared: &Arc<Shared>, group: &Group, host: &str)
        -> Option<impl FnOnce() + Send + 'static>
    {
        let now = Instant::now();
        let candidates = self.ledger.candidates(group, host, now);
        if candidates.is_empty() || self.interface.is_empty() || !self.ledger.searching.insert(host.to_owned()) {
            return None;
        }
        let (shared, group, host, interface, epoch) =
            (shared.clone(), group.clone(), host.to_owned(), self.interface.clone(), self.epoch);
        Some(move || {
            for ip in candidates {
                let obs = probe(&shared.hook, &host, IpAddr::V4(ip), &shared.marker, &interface);
                let mut state = shared.state.lock().expect("controller");
                if state.epoch != epoch {
                    return;
                }
                if let Some(country) = obs.country.as_deref() {
                    state.ledger.note(&host, IpAddr::V4(ip), country, Instant::now());
                    if group.allows(country) {
                        state.bypassed(&group, &host);
                        break;
                    }
                }
            }
            shared.state.lock().expect("controller").ledger.searching.remove(&host);
        })
    }
}

impl Controller {
    /// The DNS forwarder's question for a protected name's A answer
    /// (§66.28): the addresses to answer with, None to keep the
    /// resolver's. Never waits: a busy controller keeps the answer.
    pub(crate) fn steer(&self, name: &str, answer: &[Ipv4Addr]) -> Option<Vec<Ipv4Addr>> {
        let Ok(mut state) = self.shared.state.try_lock() else { return None };
        if !state.config.steering() { return None; }
        let id = state.sites.group_for(name)?;
        let group = state.config.enabled_group(id)?.clone();
        let now = Instant::now();
        let steered = state.ledger.steer(&group, name, answer, now);
        if steered.as_ref().is_some_and(|ips| !ips.iter().any(|ip| answer.contains(ip))) {
            state.note_steered(&group, name);
        }
        if steered.is_none() && state.ledger.all_wrong(&group, name, answer, now) && answer.iter().all(|ip| cloudflare(*ip)) {
            if let Some(job) = state.search_job(&self.shared, &group, name) {
                drop(state);
                let _ = std::thread::Builder::new().name("egress-steer".into()).spawn(job);
            }
        }
        steered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> Group {
        Group { id: 1, name: "R".into(), enabled: true, sites: vec!["a.example".into()], expect: vec!["ZZ".into()], ..Group::default() }
    }

    const CF_RIGHT: Ipv4Addr = Ipv4Addr::new(104, 16, 0, 1);
    const CF_WRONG: Ipv4Addr = Ipv4Addr::new(104, 16, 0, 2);
    const CF_WRONG_2: Ipv4Addr = Ipv4Addr::new(172, 64, 0, 2);
    const OTHER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 3);

    #[test]
    fn cloudflare_ranges() {
        assert!(cloudflare(CF_RIGHT) && cloudflare(CF_WRONG_2) && cloudflare(Ipv4Addr::new(162, 159, 1, 1)));
        assert!(!cloudflare(OTHER) && !cloudflare(Ipv4Addr::new(104, 32, 0, 1)));
    }

    #[test]
    fn answers_drop_known_wrong_entries_and_replace_only_with_ones_verified_for_the_name() {
        let g = rule();
        let now = Instant::now();
        let mut ledger = Ledger::default();
        assert_eq!(ledger.steer(&g, "x.a.example", &[CF_WRONG, CF_WRONG_2], now), None, "nothing known: keep");
        ledger.note("x.a.example", IpAddr::V4(CF_WRONG), "YY", now);
        assert_eq!(ledger.steer(&g, "x.a.example", &[CF_WRONG, CF_WRONG_2], now), Some(vec![CF_WRONG_2]), "drop the known wrong one");
        ledger.note("x.a.example", IpAddr::V4(CF_WRONG_2), "YY", now);
        assert!(ledger.all_wrong(&g, "x.a.example", &[CF_WRONG, CF_WRONG_2], now));
        ledger.note("www.a.example", IpAddr::V4(CF_RIGHT), "ZZ", now);
        assert_eq!(ledger.steer(&g, "x.a.example", &[CF_WRONG, CF_WRONG_2], now), None,
                   "another name's good entry is only a candidate until verified for this name");
        assert_eq!(ledger.candidates(&g, "x.a.example", now), vec![CF_RIGHT]);
        ledger.note("x.a.example", IpAddr::V4(CF_RIGHT), "ZZ", now);
        assert_eq!(ledger.steer(&g, "x.a.example", &[CF_WRONG, CF_WRONG_2], now), Some(vec![CF_RIGHT]));
        assert!(ledger.candidates(&g, "x.a.example", now).is_empty(), "tried entries are not tried again");
        let later = now + LEDGER_LIFETIME;
        assert_eq!(ledger.steer(&g, "x.a.example", &[CF_WRONG, CF_WRONG_2], later), None, "observations expire");
        ledger.clear();
        assert_eq!(ledger.steer(&g, "x.a.example", &[CF_WRONG, CF_WRONG_2], now), None);
    }

    #[test]
    fn non_cloudflare_answers_are_only_filtered() {
        let g = rule();
        let now = Instant::now();
        let mut ledger = Ledger::default();
        ledger.note("x.a.example", IpAddr::V4(OTHER), "YY", now);
        ledger.note("x.a.example", IpAddr::V4(CF_RIGHT), "ZZ", now);
        assert_eq!(ledger.steer(&g, "x.a.example", &[OTHER], now), None, "never moved to another provider");
        ledger.note("y.a.example", IpAddr::V4(CF_WRONG), "YY", now);
        assert_eq!(ledger.steer(&g, "y.a.example", &[CF_WRONG, OTHER], now), Some(vec![OTHER]));
    }
}
