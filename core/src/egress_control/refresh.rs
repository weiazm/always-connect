//! Fresh results and refreshing the busiest servers (DESIGN.md §66.31, user
//! 2026-11-25: "复用1秒内的结果…高频访问的头部…异步自动轮询"; "主动刷新最好
//! 有个数量上限…取访问频率topN"; "别搞太复杂").
//!
//! Every probe result is kept per (rule, name, address) with the time the
//! probe started. A gate check for the same server while that result is
//! younger than [`REUSE_UNDER`] is answered at once (the gate itself only
//! releases evidence younger than one second). A check that finds a probe
//! of the same server already running waits for it instead of starting
//! another.
//!
//! Each check also adds one to the server's score, which halves every
//! half-life (set on the 出口保护 page, default [`DEFAULT_HALF_LIFE_MIN`]
//! minutes). A background thread re-probes the top N servers by score
//! (N set on the 出口保护 page, default 5, 0 = off) every
//! [`REFRESH_EVERY`], so a new connection to a busy server finds a fresh
//! result instead of waiting for a probe. A server whose score fell below
//! [`MIN_SCORE`] is not refreshed, and one whose last probe could not read
//! an exit is not either (re-probing it reads nothing new). With nothing to
//! refresh the thread sleeps until the next check.

use super::*;
use std::collections::HashMap;
use std::sync::Condvar;

pub(super) const REUSE_UNDER: Duration = Duration::from_millis(800);
pub(super) const REFRESH_EVERY: Duration = Duration::from_millis(600);
/// Blocked results on proxy/local paths are cached briefly to avoid probe
/// storms on rapid retries while still recovering promptly when upstream changes.
pub(super) const PROXY_BLOCK_REUSE: Duration = Duration::from_secs(10);
/// Minimum interval between background refreshes on a proxy/local path.
const PROXY_REFRESH_MIN: Duration = Duration::from_secs(30);
/// Two minutes: while a site is in use its connections keep it on top;
/// after leaving it, one visit stops being refreshed after about two
/// minutes and a busy session after about ten (user 2026-11-25: defaults
/// "按实际情况优化", the half-life adjustable).
pub const DEFAULT_HALF_LIFE_MIN: u32 = 2;
pub const MAX_HALF_LIFE_MIN: u32 = 30;
pub(super) const MIN_SCORE: f64 = 0.5;
pub const DEFAULT_PREFETCH: u32 = 5;
pub const MAX_PREFETCH: u32 = 20;
const MAX_SCORED: usize = 256;

pub(super) type Key = (u32, EgressPath, String, IpAddr);

pub(super) struct Fresh {
    pub answer: &'static str,
    pub evidence_at: Option<u64>,
    pub at: Instant,
    pub epoch: u64,
    /// The probe read a country (only such servers are refreshed).
    pub read: bool,
}

pub(super) struct Cache {
    pub fresh: HashMap<Key, Fresh>,
    /// Probes running now, with the gate requests waiting for them.
    pub running: HashMap<Key, Vec<(u64, u64)>>,
    scores: HashMap<Key, (f64, Instant)>,
    pub half_life: Duration,
}

impl Default for Cache {
    fn default() -> Self {
        Cache { fresh: HashMap::new(), running: HashMap::new(), scores: HashMap::new(),
                half_life: Duration::from_secs(60 * u64::from(DEFAULT_HALF_LIFE_MIN)) }
    }
}

fn decayed_by(half_life: Duration, score: f64, since: Instant, now: Instant) -> f64 {
    score * 0.5f64.powf(now.duration_since(since).as_secs_f64() / half_life.as_secs_f64().max(1.0))
}

impl Cache {
    pub fn with_half_life(half_life: Duration) -> Self {
        Cache { half_life, ..Cache::default() }
    }

    fn decayed(&self, score: f64, since: Instant, now: Instant) -> f64 {
        decayed_by(self.half_life, score, since, now)
    }

    /// One more connection to this server.
    pub fn bump(&mut self, key: &Key, now: Instant) {
        let half_life = self.half_life;
        let entry = self.scores.entry(key.clone()).or_insert((0.0, now));
        *entry = (decayed_by(half_life, entry.0, entry.1, now) + 1.0, now);
        if self.scores.len() > MAX_SCORED {
            self.scores.retain(|_, (s, at)| decayed_by(half_life, *s, *at, now) >= MIN_SCORE / 4.0);
            while self.scores.len() > MAX_SCORED {
                let lowest = self.scores.iter()
                    .min_by(|a, b| decayed_by(half_life, a.1 .0, a.1 .1, now)
                        .total_cmp(&decayed_by(half_life, b.1 .0, b.1 .1, now)))
                    .map(|(k, _)| k.clone());
                match lowest { Some(k) => { self.scores.remove(&k); } None => break }
            }
        }
    }

    /// A result young enough to answer a new check with. On Cisco (§66.31),
    /// results are aged by the gate's own clock under one second. On proxy and
    /// local paths (§71), allowed results stay fresh for `half_life` (invalidated
    /// immediately on proxy/network/rule changes) and blocked results for
    /// [`PROXY_BLOCK_REUSE`].
    pub fn reusable(&self, key: &Key, epoch: u64, now: Instant) -> Option<&Fresh> {
        self.reusable_at(key, epoch, now, evidence_clock_ms())
    }

    pub fn reusable_at(&self, key: &Key, epoch: u64, now: Instant, clock_ms: Option<u64>) -> Option<&Fresh> {
        self.fresh.get(key).filter(|f| {
            if f.epoch != epoch {
                return false;
            }
            if key.1.is_cisco() {
                match (f.evidence_at, clock_ms) {
                    (Some(at), Some(clock)) => clock.saturating_sub(at) < REUSE_UNDER.as_millis() as u64,
                    _ => now.duration_since(f.at) < REUSE_UNDER,
                }
            } else {
                let limit = if f.answer == "block" { PROXY_BLOCK_REUSE } else { self.half_life };
                now.duration_since(f.at) < limit
            }
        })
    }

    fn refresh_interval(&self, path: EgressPath) -> Duration {
        if path.is_cisco() {
            REFRESH_EVERY
        } else {
            (self.half_life / 2).max(PROXY_REFRESH_MIN)
        }
    }

    /// The servers to re-probe now: the top `limit` by score that are busy
    /// enough, last read a country, and are not being probed.
    pub fn due(&self, limit: usize, epoch: u64, now: Instant) -> Vec<Key> {
        let mut ranked: Vec<(&Key, f64)> = self.scores.iter()
            .map(|(k, (s, at))| (k, self.decayed(*s, *at, now)))
            .filter(|(_, s)| *s >= MIN_SCORE)
            .collect();
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1));
        ranked.into_iter().take(limit)
            .filter(|(k, _)| !self.running.contains_key(*k))
            .filter(|(k, _)| self.fresh.get(*k).is_some_and(|f| f.epoch == epoch && f.read
                && now.duration_since(f.at) >= self.refresh_interval(k.1)))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Anything worth waking up for (busy servers with a readable exit).
    pub fn any_hot(&self, epoch: u64, now: Instant) -> bool {
        self.scores.iter().any(|(k, (s, at))| self.decayed(*s, *at, now) >= MIN_SCORE
            && self.fresh.get(k).is_some_and(|f| f.epoch == epoch && f.read))
    }

    pub fn any_hot_cisco(&self, epoch: u64, now: Instant) -> bool {
        self.scores.iter().any(|(k, (s, at))| k.1.is_cisco() && self.decayed(*s, *at, now) >= MIN_SCORE
            && self.fresh.get(k).is_some_and(|f| f.epoch == epoch && f.read))
    }

    pub fn note(&mut self, key: Key, answer: &'static str, obs: &Observation, epoch: u64, now: Instant) {
        self.fresh.insert(key, Fresh { answer, evidence_at: obs.evidence_at_ms, at: now, epoch, read: obs.country.is_some() });
        if self.fresh.len() > MAX_SCORED {
            let keep = self.half_life;
            self.fresh.retain(|_, f| f.epoch == epoch && now.duration_since(f.at) < keep);
        }
    }

    /// Forget results for one specific path (e.g. a proxy restarted or changed).
    pub fn forget_path(&mut self, path: EgressPath) {
        self.fresh.retain(|k, _| k.1 != path);
        self.running.retain(|k, _| k.1 != path);
    }

    /// Network change, new rules, disconnect: no result carries over.
    pub fn forget(&mut self) {
        self.fresh.clear();
        self.running.clear();
    }
}

/// The refresher's wake-up call (a check arrived, the rules changed, stop).
#[derive(Default)]
pub(super) struct Bell(pub Condvar);

pub(super) fn refresh_loop(shared: Arc<Shared>) {
    let mut state = shared.state.lock().expect("controller");
    while !shared.stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        let limit = state.config.prefetch_limit();
        let cisco_ready = limit > 0 && state.peer.is_some() && !state.interface.is_empty();
        let relay_ready = limit > 0 && state.relay_opener.is_some();
        let ready = cisco_ready || relay_ready;
        let due = if ready { state.cache.due(limit, state.epoch, now) } else { Vec::new() };
        for key in due {
            if key.1.is_cisco() && !cisco_ready { continue; }
            if !key.1.is_cisco() && !relay_ready { continue; }
            if !key.1.is_cisco() && state.relay_running.contains_key(&key) { continue; }
            let Some(rule) = state.config.enabled_group(key.0).cloned() else { continue };
            state.cache.running.insert(key.clone(), Vec::new());
            let (worker, interface, opener, epoch) = (
                shared.clone(),
                state.interface.clone(),
                state.relay_opener.clone(),
                state.epoch,
            );
            let run_key = key.clone();
            let spawned = std::thread::Builder::new().name("egress-refresh".into())
                .spawn(move || run_refresh(&worker, rule, run_key, &interface, opener, epoch));
            if spawned.is_err() {
                state.cache.running.remove(&key);
                break;
            }
        }
        state = if ready && state.cache.any_hot(state.epoch, now) {
            let wait = if cisco_ready && state.cache.any_hot_cisco(state.epoch, now) {
                REFRESH_EVERY / 3
            } else {
                Duration::from_secs(10)
            };
            shared.bell.0.wait_timeout(state, wait).expect("controller").0
        } else {
            shared.bell.0.wait(state).expect("controller")
        };
    }
}

fn run_refresh(shared: &Arc<Shared>, rule: Group, key: Key, interface: &str, opener: Option<RelayOpener>, epoch: u64) {
    let obs = if key.1.is_cisco() {
        probe(&shared.hook, &key.2, key.3, &shared.marker, interface)
    } else if let Some(opener) = opener.as_ref() {
        let peer_ip = (key.3 != IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)).then_some(key.3);
        bridge::probe_via_relay(&shared.hook, opener, &key.1, &key.2, peer_ip)
    } else {
        return;
    };
    let mut state = shared.state.lock().expect("controller");
    let waiting = state.cache.running.remove(&key).unwrap_or_default();
    if state.epoch != epoch || state.config.enabled_group(rule.id).is_none() { return; }
    let wrong_cloudflare = key.1.is_cisco() && obs.country.is_some()
        && matches!(key.3, IpAddr::V4(ip) if steer::cloudflare(ip));
    let target = Target { host: key.2.clone(), ip: key.3, path: key.1 };
    let at = obs.evidence_at_ms;
    // A refresh is not a connection: an unreadable exit is not counted again.
    let answer = state.record_probe(&rule, target, obs.clone(), false);
    state.cache.note(key.clone(), answer, &obs, epoch, Instant::now());
    for (peer, id) in waiting {
        if peer == state.peer_id { state.send(&verdict(rule.id, id, answer, at)); }
    }
    let search = (answer == "block" && wrong_cloudflare && state.config.steering())
        .then(|| state.search_job(shared, &rule, &key.2)).flatten();
    drop(state);
    if let Some(job) = search {
        let _ = std::thread::Builder::new().name("egress-steer".into()).spawn(job);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Key { (1, EgressPath::Cisco, format!("s{n}.example"), IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, n))) }
    fn proxy_key(p: usize, n: u8) -> Key { (1, EgressPath::Proxy(p), format!("s{n}.example"), IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)) }

    fn read(cache: &mut Cache, k: &Key, at: Instant) {
        let obs = Observation { country: Some("ZZ".into()), evidence_at_ms: Some(1), ..Default::default() };
        cache.note(k.clone(), "allow", &obs, 0, at);
    }

    #[test]
    fn the_busiest_servers_are_refreshed_and_quiet_ones_drop_out() {
        let start = Instant::now();
        let mut cache = Cache::default();
        for _ in 0..5 { cache.bump(&key(1), start); }
        for _ in 0..3 { cache.bump(&key(2), start); }
        cache.bump(&key(3), start);
        for n in 1..=3 { read(&mut cache, &key(n), start); }
        let later = start + REFRESH_EVERY;
        assert_eq!(cache.due(2, 0, later), vec![key(1), key(2)], "top N by score");
        assert_eq!(cache.due(5, 0, later).len(), 3);
        assert!(cache.due(5, 0, start).is_empty(), "a result younger than the interval is not re-probed");
        // One connection, then quiet: below the floor after about one half-life.
        let quiet = start + cache.half_life + Duration::from_secs(1);
        let due = cache.due(5, 0, quiet);
        assert!(due.contains(&key(1)) && !due.contains(&key(3)));
        cache.running.insert(key(1), Vec::new());
        assert!(!cache.due(5, 0, quiet).contains(&key(1)), "a server being probed is not probed twice");
    }

    #[test]
    fn a_longer_half_life_keeps_an_occasional_site_refreshed_longer() {
        let start = Instant::now();
        let mut short = Cache::default();
        let mut long = Cache { half_life: Duration::from_secs(600), ..Cache::default() };
        for cache in [&mut short, &mut long] {
            cache.bump(&key(1), start);
            read(cache, &key(1), start);
        }
        let later = start + Duration::from_secs(300);
        assert!(short.due(5, 0, later).is_empty(), "two minutes: gone after five");
        assert_eq!(long.due(5, 0, later), vec![key(1)], "ten minutes: still refreshed after five");
    }

    #[test]
    fn results_are_reused_only_while_young_and_only_in_their_epoch() {
        let start = Instant::now();
        let mut cache = Cache::default();
        read(&mut cache, &key(1), start);
        // Evidence stamped at 1 ms on the gate's clock: aged by that clock.
        assert!(cache.reusable_at(&key(1), 0, start, Some(700)).is_some());
        assert!(cache.reusable_at(&key(1), 0, start, Some(1 + REUSE_UNDER.as_millis() as u64)).is_none(),
                "a result the gate would find too old is not reused");
        assert!(cache.reusable_at(&key(1), 0, start + Duration::from_millis(700), None).is_some());
        assert!(cache.reusable_at(&key(1), 0, start + REUSE_UNDER, None).is_none());
        assert!(cache.reusable_at(&key(1), 1, start, Some(2)).is_none(), "a network change or new rules start over");
        let unreadable = Observation { error: Some("x".into()), ..Default::default() };
        cache.bump(&key(2), start);
        cache.note(key(2), "unverified", &unreadable, 0, start);
        assert!(!cache.due(5, 0, start + REFRESH_EVERY).contains(&key(2)), "an unreadable exit is not polled");
        assert!(!cache.any_hot(0, start + REFRESH_EVERY) || cache.due(5, 0, start + REFRESH_EVERY).is_empty());
    }

    #[test]
    fn proxy_paths_are_isolated_from_each_other_and_reuse_for_half_life() {
        let start = Instant::now();
        let mut cache = Cache::default();
        let p0 = proxy_key(0, 1);
        let p1 = proxy_key(1, 1);
        read(&mut cache, &p0, start);
        assert!(cache.reusable_at(&p0, 0, start + Duration::from_secs(60), None).is_some(),
                "proxy result stays reusable within half_life");
        assert!(cache.reusable_at(&p0, 0, start + cache.half_life, None).is_none(),
                "proxy result expires after half_life");
        assert!(cache.reusable_at(&p1, 0, start, None).is_none(),
                "different proxy path has its own cache entry");
        let blocked = Observation { country: Some("YY".into()), ..Default::default() };
        cache.note(p1.clone(), "block", &blocked, 0, start);
        assert!(cache.reusable_at(&p1, 0, start + Duration::from_secs(5), None).is_some());
        assert!(cache.reusable_at(&p1, 0, start + PROXY_BLOCK_REUSE, None).is_none());
        cache.forget_path(EgressPath::Proxy(0));
        assert!(cache.reusable_at(&p0, 0, start, None).is_none());
        assert!(cache.reusable_at(&p1, 0, start, None).is_some());
    }
}
