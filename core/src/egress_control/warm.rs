//! A SYN hint can start an ordinary pinned probe before SNI or HTTP Host is known.
//! The controller may use the observation only for a later confirmed check.

use super::recheck::Target;
use super::{
    build_request, pattern_matches, probe_once, valid_host, CheckMsg, EgressConfig, Observation,
    ProbeHook, ProbeMethod,
};
use serde::Deserialize;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_ENTRIES: usize = 8;
const MAX_RUNNING: usize = 2;
const REUSE: Duration = Duration::from_secs(1);
// Leave most of the gate's 3 s budget for the usual 2.4 s probe if this one stalls.
const JOIN_BUDGET: Duration = Duration::from_millis(100);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WarmMsg {
    group: u32,
    host: String,
    ip: IpAddr,
    port: NonZeroU16,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Scope {
    pub peer_id: u64,
    pub epoch: u64,
    pub interface: String,
}

#[derive(Default)]
pub(super) struct WarmProbes(Vec<Arc<Attempt>>);

struct Attempt {
    scope: Scope,
    generation: u64,
    target: WarmMsg,
    method: ProbeMethod,
    started: Instant,
    evidence_at_ms: u64,
    state: Mutex<State>,
    changed: Condvar,
}

enum State {
    Running,
    Retired,
    Finished(Option<Observation>),
}

impl Attempt {
    fn expires(&self) -> Instant {
        self.started + REUSE
    }

    fn finish(&self, observation: Option<Observation>) {
        let mut state = self.state.lock().expect("warm probe");
        let observation = observation
            .filter(|_| matches!(*state, State::Running) && Instant::now() < self.expires());
        *state = State::Finished(observation);
        self.changed.notify_all();
    }

    fn observe(&self, hook: ProbeHook, marker: &str) -> Option<Observation> {
        let timeout: u64 = self
            .expires()
            .checked_duration_since(Instant::now())?
            .as_millis()
            .try_into()
            .ok()?;
        if timeout == 0 || !matches!(*self.state.lock().expect("warm probe"), State::Running) {
            return None;
        }
        let ip = self.target.ip;
        // probe_once also serves callers without numeric peer reporting. Warm
        // requires the platform to report the actual pinned peer explicitly.
        let pinned: ProbeHook = Arc::new(move |request, peer| {
            let answer = hook(request, peer);
            answer.filter(|_| *peer == Some(ip))
        });
        let (observed, _) = probe_once(
            &pinned,
            &self.method,
            &self.target.host,
            marker,
            &self.scope.interface,
            Some(ip),
            "direct",
            timeout,
        );
        (observed.error.is_none() && observed.country.is_some()).then_some(observed)
    }
}

// Keep retired workers counted until the hook exits, including on thread start
// failure or unwinding. The job never locks the controller or records a check.
struct Job(Arc<Attempt>);

impl Job {
    fn run(self, hook: ProbeHook, marker: &str) {
        let observation = self.0.observe(hook, marker);
        self.0.finish(observation);
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().expect("warm probe");
        if matches!(*state, State::Running | State::Retired) {
            *state = State::Finished(None);
            self.0.changed.notify_all();
        }
    }
}

impl WarmProbes {
    /// `msg` comes from the current private gate peer. The gate supplies a
    /// concrete name only when it can associate the destination unambiguously.
    pub(super) fn start(
        &mut self,
        config: &EgressConfig,
        scope: Scope,
        generation: u64,
        mut msg: WarmMsg,
        hook: &ProbeHook,
        marker: &str,
    ) {
        let now = Instant::now();
        let mut running = 0;
        self.0.retain(|attempt| {
            let state = attempt.state.lock().expect("warm probe");
            if matches!(*state, State::Running | State::Retired) {
                running += 1;
                return true;
            }
            now < attempt.expires()
        });
        // Throttle by numeric address, including a probe's own SYN. The reuse
        // identity below is stricter and includes the actual flow port.
        if self.0.len() >= MAX_ENTRIES
            || running >= MAX_RUNNING
            || scope.interface.is_empty()
            || marker.is_empty()
            || self.0.iter().any(|attempt| attempt.target.ip == msg.ip)
        {
            return;
        }
        let Some(host) = canonical_host(&msg.host) else {
            return;
        };
        let Some(group) = config
            .group(msg.group)
            .filter(|g| config.active() && g.enabled)
        else {
            return;
        };
        let mut methods = group
            .members
            .iter()
            .filter(|m| pattern_matches(&m.pattern, &host))
            .filter_map(|m| config.method(m.method.as_deref()?))
            .filter(ProbeMethod::is_direct);
        let Some(method) = methods.next() else { return };
        if methods.any(|other| other != method)
            || !build_request(&method, &host).is_ok_and(|(_, port, _)| port == msg.port.get())
        {
            return;
        }
        let Ok(since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return;
        };
        let Ok(evidence_at_ms) = since_epoch.as_millis().try_into() else {
            return;
        };
        let started = Instant::now();
        msg.host = host;
        let attempt = Arc::new(Attempt {
            scope,
            generation,
            target: msg,
            method,
            started,
            evidence_at_ms,
            state: Mutex::new(State::Running),
            changed: Condvar::new(),
        });
        self.0.push(attempt.clone());
        let job = Job(attempt);
        let hook = hook.clone();
        let marker = marker.to_owned();
        let _ = std::thread::Builder::new()
            .name("egress-warm".into())
            .spawn(move || job.run(hook, &marker));
    }

    pub(super) fn for_check(
        &self,
        scope: &Scope,
        generation: u64,
        check: &CheckMsg,
        host_confirmed: bool,
        targets: &[Target],
    ) -> Option<Candidate> {
        let [target] = targets else { return None };
        if !host_confirmed
            || !target.direct_flow()
            || target.peer != Some((check.ip, check.port.get()))
        {
            return None;
        }
        let host = canonical_host(check.host.as_deref()?)?;
        if canonical_host(&target.host).as_deref() != Some(&host) {
            return None;
        }
        let now = Instant::now();
        let attempt = self.0.iter().find(|attempt| {
            &attempt.scope == scope
                && attempt.generation == generation
                && now < attempt.expires()
                && attempt.target.group == check.group
                && attempt.target.host == host
                && attempt.target.ip == check.ip
                && attempt.target.port == check.port
                && attempt.method == target.method
        })?;
        let state = attempt.state.lock().expect("warm probe");
        if matches!(*state, State::Retired | State::Finished(None)) {
            return None;
        }
        Some(Candidate {
            attempt: attempt.clone(),
            join_until: now + JOIN_BUDGET,
        })
    }

    /// Call on configuration or tunnel invalidation. Late observations are discarded.
    pub(super) fn invalidate(&mut self) {
        self.0.retain(|attempt| {
            let mut state = attempt.state.lock().expect("warm probe");
            if matches!(*state, State::Running | State::Retired) {
                *state = State::Retired;
                attempt.changed.notify_all();
                true
            } else {
                // A real check might still hold a handle to this observation.
                *state = State::Finished(None);
                false
            }
        });
    }
}

pub(super) struct Candidate {
    attempt: Arc<Attempt>,
    join_until: Instant,
}

pub(super) struct Evidence {
    pub observation: Observation,
    /// Age from issuance, when the probe can select its egress, bounded using
    /// the monotonic clock here. Forward this original wall time to the gate.
    pub evidence_at_ms: u64,
}

impl Candidate {
    /// Use outside the controller lock. None means run the ordinary check.
    pub(super) fn wait(&self) -> Option<Evidence> {
        let attempt = &self.attempt;
        let deadline = attempt.expires().min(self.join_until);
        let state = attempt.state.lock().expect("warm probe");
        let remaining = deadline.saturating_duration_since(Instant::now());
        let (state, _) = attempt
            .changed
            .wait_timeout_while(state, remaining, |s| matches!(*s, State::Running))
            .expect("warm probe");
        if Instant::now() >= attempt.expires() {
            return None;
        }
        let State::Finished(Some(observation)) = &*state else {
            return None;
        };
        Some(Evidence {
            observation: observation.clone(),
            evidence_at_ms: attempt.evidence_at_ms,
        })
    }

    /// Recheck under the controller lock before sending this check's verdict or
    /// applying evidence. A warm probe issued before a newer failure cannot clear it.
    pub(super) fn is_current(&self, scope: &Scope, generation: u64) -> bool {
        &self.attempt.scope == scope
            && self.attempt.generation == generation
            && Instant::now() < self.attempt.expires()
            && matches!(
                *self.attempt.state.lock().expect("warm probe"),
                State::Finished(Some(_))
            )
    }
}

fn canonical_host(host: &str) -> Option<String> {
    valid_host(host).then(|| host.trim_end_matches('.').to_ascii_lowercase())
}

#[cfg(test)]
mod tests;
