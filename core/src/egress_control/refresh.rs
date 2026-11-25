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
//! [`HALF_LIFE`]. A background thread re-probes the top N servers by score
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
pub(super) const HALF_LIFE: Duration = Duration::from_secs(300);
pub(super) const MIN_SCORE: f64 = 0.5;
pub const DEFAULT_PREFETCH: u32 = 5;
pub const MAX_PREFETCH: u32 = 20;
const MAX_SCORED: usize = 256;

pub(super) type Key = (u32, String, IpAddr);

pub(super) struct Fresh {
    pub answer: &'static str,
    pub evidence_at: Option<u64>,
    pub at: Instant,
    pub epoch: u64,
    /// The probe read a country (only such servers are refreshed).
    pub read: bool,
}

#[derive(Default)]
pub(super) struct Cache {
    pub fresh: HashMap<Key, Fresh>,
    /// Probes running now, with the gate requests waiting for them.
    pub running: HashMap<Key, Vec<(u64, u64)>>,
    scores: HashMap<Key, (f64, Instant)>,
}

fn decayed(score: f64, since: Instant, now: Instant) -> f64 {
    score * 0.5f64.powf(now.duration_since(since).as_secs_f64() / HALF_LIFE.as_secs_f64())
}

impl Cache {
    /// One more connection to this server.
    pub fn bump(&mut self, key: &Key, now: Instant) {
        let entry = self.scores.entry(key.clone()).or_insert((0.0, now));
        *entry = (decayed(entry.0, entry.1, now) + 1.0, now);
        if self.scores.len() > MAX_SCORED {
            self.scores.retain(|_, (s, at)| decayed(*s, *at, now) >= MIN_SCORE / 4.0);
            while self.scores.len() > MAX_SCORED {
                let lowest = self.scores.iter()
                    .min_by(|a, b| decayed(a.1 .0, a.1 .1, now).total_cmp(&decayed(b.1 .0, b.1 .1, now)))
                    .map(|(k, _)| k.clone());
                match lowest { Some(k) => { self.scores.remove(&k); } None => break }
            }
        }
    }

    /// A result young enough to answer a new check with. A result with
    /// evidence is aged by the gate's own clock, so what is reused here is
    /// still under the gate's one second on arrival.
    pub fn reusable(&self, key: &Key, epoch: u64, now: Instant) -> Option<&Fresh> {
        self.reusable_at(key, epoch, now, evidence_clock_ms())
    }

    pub fn reusable_at(&self, key: &Key, epoch: u64, now: Instant, clock_ms: Option<u64>) -> Option<&Fresh> {
        self.fresh.get(key).filter(|f| f.epoch == epoch && match (f.evidence_at, clock_ms) {
            (Some(at), Some(clock)) => clock.saturating_sub(at) < REUSE_UNDER.as_millis() as u64,
            _ => now.duration_since(f.at) < REUSE_UNDER,
        })
    }

    /// The servers to re-probe now: the top `limit` by score that are busy
    /// enough, last read a country, and are not being probed.
    pub fn due(&self, limit: usize, epoch: u64, now: Instant) -> Vec<Key> {
        let mut ranked: Vec<(&Key, f64)> = self.scores.iter()
            .map(|(k, (s, at))| (k, decayed(*s, *at, now)))
            .filter(|(_, s)| *s >= MIN_SCORE)
            .collect();
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1));
        ranked.into_iter().take(limit)
            .filter(|(k, _)| !self.running.contains_key(*k))
            .filter(|(k, _)| self.fresh.get(*k).is_some_and(|f| f.epoch == epoch && f.read
                && now.duration_since(f.at) >= REFRESH_EVERY))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Anything worth waking up for (busy servers with a readable exit).
    pub fn any_hot(&self, epoch: u64, now: Instant) -> bool {
        self.scores.iter().any(|(k, (s, at))| decayed(*s, *at, now) >= MIN_SCORE
            && self.fresh.get(k).is_some_and(|f| f.epoch == epoch && f.read))
    }

    pub fn note(&mut self, key: Key, answer: &'static str, obs: &Observation, epoch: u64, now: Instant) {
        self.fresh.insert(key, Fresh { answer, evidence_at: obs.evidence_at_ms, at: now, epoch, read: obs.country.is_some() });
        if self.fresh.len() > MAX_SCORED {
            self.fresh.retain(|_, f| f.epoch == epoch && now.duration_since(f.at) < HALF_LIFE);
        }
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
        let ready = limit > 0 && state.peer.is_some() && !state.interface.is_empty();
        let due = if ready { state.cache.due(limit, state.epoch, now) } else { Vec::new() };
        for key in due {
            let Some(rule) = state.config.enabled_group(key.0).cloned() else { continue };
            state.cache.running.insert(key.clone(), Vec::new());
            let (worker, interface, epoch) = (shared.clone(), state.interface.clone(), state.epoch);
            let spawned = std::thread::Builder::new().name("egress-refresh".into())
                .spawn(move || run_refresh(&worker, rule, key.clone(), &interface, epoch));
            if spawned.is_err() { break; }
        }
        state = if ready && state.cache.any_hot(state.epoch, now) {
            shared.bell.0.wait_timeout(state, REFRESH_EVERY / 3).expect("controller").0
        } else {
            shared.bell.0.wait(state).expect("controller")
        };
    }
}

fn run_refresh(shared: &Arc<Shared>, rule: Group, key: Key, interface: &str, epoch: u64) {
    let obs = probe(&shared.hook, &key.1, key.2, &shared.marker, interface);
    let mut state = shared.state.lock().expect("controller");
    let waiting = state.cache.running.remove(&key).unwrap_or_default();
    if state.epoch != epoch || state.config.enabled_group(rule.id).is_none() { return; }
    let wrong_cloudflare = obs.country.is_some() && matches!(key.2, IpAddr::V4(ip) if steer::cloudflare(ip));
    let target = Target { host: key.1.clone(), ip: key.2 };
    let at = obs.evidence_at_ms;
    // A refresh is not a connection: an unreadable exit is not counted again.
    let answer = state.record_probe(&rule, target, obs.clone(), false);
    state.cache.note(key.clone(), answer, &obs, epoch, Instant::now());
    for (peer, id) in waiting {
        if peer == state.peer_id { state.send(&verdict(rule.id, id, answer, at)); }
    }
    let search = (answer == "block" && wrong_cloudflare && state.config.steering())
        .then(|| state.search_job(shared, &rule, &key.1)).flatten();
    drop(state);
    if let Some(job) = search {
        let _ = std::thread::Builder::new().name("egress-steer".into()).spawn(job);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Key { (1, format!("s{n}.example"), IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, n))) }

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
        let quiet = start + HALF_LIFE + Duration::from_secs(1);
        let due = cache.due(5, 0, quiet);
        assert!(due.contains(&key(1)) && !due.contains(&key(3)));
        cache.running.insert(key(1), Vec::new());
        assert!(!cache.due(5, 0, quiet).contains(&key(1)), "a server being probed is not probed twice");
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
}
