//! Egress gate (DESIGN.md §66.5): the per-packet decision logic that sits in
//! the own connection's tunnel path when egress protection is on.
//!
//! openconnect runs in `--script-tun` mode and hands every IP packet to the
//! gate program; this module decides, per packet, whether it goes on into the
//! tunnel now, waits, or is dropped. Every new connection's first data packet
//! is held until the gate knows where the connection goes (TLS SNI, HTTP Host,
//! or the destination address). Connections to a protected group wait for an
//! egress check of their destination. A failed check drops the packets
//! waiting for that result and answers the Mac with a TCP RST.
//!
//! The module does no I/O: the caller feeds packets and verdicts and carries
//! out the returned actions. It is pure Rust so it is tested on Linux.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

/// A protected group (DESIGN.md §66.3); the caller's identifier.
pub type GroupId = u32;
pub type RequestId = NonZeroU64;

pub enum Verdict {
    Block,
    AllowDirect,
    AllowDependent,
}

const MAX_PENDING_PER_GROUP: usize = 16;
const MAX_CACHED_PER_GROUP: usize = 64;
const MAX_REPORTED_FLOWS: usize = 4096;
const MAX_REPORTED_GROUPS: usize = 16;
const MAX_REPORTED_HOSTS: usize = 32;
const EVIDENCE_AGE_MS: u64 = 1_000;
const MAX_WARM_IDENTITIES: usize = 256;
const MAX_WARMS_PER_WINDOW: usize = 8;
const WARM_WINDOW: Duration = Duration::from_secs(1);
const WARM_NAME_LIFETIME: Duration = Duration::from_secs(60);

/// Same boot-relative, sleep-inclusive clock in the gate and its controller.
pub fn evidence_clock_ms() -> Option<u64> {
    #[cfg(target_os = "macos")]
    let clock = libc::CLOCK_MONOTONIC;
    #[cfg(target_os = "linux")]
    let clock = libc::CLOCK_BOOTTIME;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let clock = libc::CLOCK_MONOTONIC;
    let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(clock, &mut value) } != 0 {
        return None;
    }
    u64::try_from(value.tv_sec).ok()?.checked_mul(1_000)?
        .checked_add(u64::try_from(value.tv_nsec).ok()? / 1_000_000)
}

/// Which group, if any, a name or address belongs to. Backed by the rule
/// engine in production; the gate only asks.
pub trait Classifier {
    fn group_for_name(&self, name: &str) -> Option<GroupId>;
    fn group_for_ip(&self, ip: IpAddr) -> Option<GroupId>;
}

#[derive(Clone, Debug)]
pub struct GateConfig {
    /// ALPN value the background service's own probes carry (§66.4). Empty
    /// disables the exemption.
    pub probe_alpn: Vec<u8>,
    /// Reuse a recent result only for the same target.
    pub reuse: Duration,
    /// A check not answered within this blocks the waiting connections.
    pub check_timeout: Duration,
    /// How long a connection may trickle an incomplete ClientHello or HTTP
    /// request before the gate decides by destination address alone.
    pub classify_timeout: Duration,
    /// Bytes held per connection before deciding with what is there.
    pub max_held_bytes: usize,
    /// Connection table bound; only passed or blocked entries are evicted.
    pub max_flows: usize,
    /// Learned "protected name -> address" entries (from tunnel DNS answers).
    pub max_learned: usize,
    /// Connections idle this long are forgotten; a later packet of one is
    /// treated as a mid-stream connection and decided by address (§66.5).
    pub idle: Duration,
    /// Drop all UDP 443 (QUIC) into the tunnel (§66.5).
    pub block_quic: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        GateConfig {
            probe_alpn: Vec::new(),
            reuse: Duration::from_secs(1),
            check_timeout: Duration::from_secs(3),
            classify_timeout: Duration::from_secs(3),
            max_held_bytes: 64 * 1024,
            max_flows: 32 * 1024,
            max_learned: 4096,
            idle: Duration::from_secs(15 * 60),
            block_quic: true,
        }
    }
}

/// What to do with the packet just handed to [`Gate::outbound`].
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Send this packet into the tunnel now (the caller still owns it).
    Forward,
    /// The gate kept or dropped it; anything to send is in [`Gate::drain`].
    Consumed,
}

/// Actions produced besides the current packet's [`Step`], in order.
#[derive(Debug, PartialEq, Eq)]
pub enum Out {
    /// A previously held packet, released into the tunnel.
    ToTunnel(Vec<u8>),
    /// Revalidate an approval immediately before writing the first held packet.
    SendChecked(u64),
    /// Advisory only. No permission is granted until a regular check answers.
    Warm { group: GroupId, host: String, destination: SocketAddr },
    /// A packet for the Mac side (a RST for a blocked connection).
    ToHost(Vec<u8>),
    /// Ask the background service to check this exact destination.
    Check {
        group: GroupId,
        host: Option<String>,
        host_confirmed: bool,
        destination: SocketAddr,
        request_id: RequestId,
    },
    /// Record a local deadline failure before sending another check.
    TimedOut {
        group: GroupId,
        host: Option<String>,
        host_confirmed: bool,
        destination: SocketAddr,
        request_id: RequestId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
}

#[derive(Clone, Copy, Debug)]
struct ClientSeg {
    seq: u32,
    ack: u32,
    has_ack: bool,
    syn: bool,
    len: u32,
}

enum State {
    /// Handshake seen, no data yet. `next` is the first data sequence number.
    Fresh { next: u32 },
    /// First data held while the gate learns where the connection goes, or
    /// while its group is being checked.
    Holding(Box<Held>),
    Pass,
    Blocked,
}

struct Held {
    packets: Vec<Vec<u8>>,
    bytes: usize,
    /// In-order client bytes from the first data byte (TCP) or the first
    /// datagram (UDP), for parsing.
    stream: Vec<u8>,
    next: u32,
    since: Instant,
    /// Set once classified as protected: the request holds this flow's key.
    checking: bool,
    /// A TCP flow first seen without its SYN cannot be counted as new.
    client_isn: Option<u32>,
    last: Option<ClientSeg>,
}

struct Flow {
    state: State,
    last_seen: Instant,
}

#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeniedGroup {
    pub group: GroupId,
    pub count: u64,
    pub hosts: Vec<DeniedHost>,
    pub hosts_truncated: bool,
    pub last_host: Option<String>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct DeniedHost {
    pub host: String,
    pub count: u64,
}

#[derive(Default)]
struct BlockedFlows {
    seen: HashSet<u64>,
    groups: HashMap<GroupId, DeniedGroup>,
    dirty: VecDeque<GroupId>,
}

impl BlockedFlows {
    fn record(&mut self, flow: FlowKey, client_isn: Option<u32>, group: GroupId, host: Option<&str>) {
        if self.seen.len() >= MAX_REPORTED_FLOWS || (flow.proto == 6 && client_isn.is_none()) {
            return;
        }
        // Keep a bounded fingerprint even if the packet table evicts the
        // flow. A collision can only lower this best-effort count.
        let flow_id = self.seen.hasher().hash_one((flow, client_isn));
        if !self.seen.insert(flow_id) {
            return;
        }
        if self.groups.len() == MAX_REPORTED_GROUPS && !self.groups.contains_key(&group) {
            return;
        }
        let stats = self.groups.entry(group).or_insert_with(|| DeniedGroup { group, ..Default::default() });
        stats.count += 1;
        let mut reported_host = None;
        // DNS names on the wire use ASCII (including IDNA A-labels). Keep
        // optional reports ASCII too so a short write cannot split UTF-8.
        if let Some(host) = host.filter(|host| host.len() <= 253 && host.is_ascii()) {
            if let Some(entry) = stats.hosts.iter_mut().find(|entry| entry.host == host) {
                entry.count += 1;
                reported_host = Some(host);
            } else if stats.hosts.len() < MAX_REPORTED_HOSTS {
                stats.hosts.push(DeniedHost { host: host.to_owned(), count: 1 });
                reported_host = Some(host);
            } else {
                stats.hosts_truncated = true;
            }
        }
        if stats.last_host.as_deref() != reported_host {
            stats.last_host = reported_host.map(str::to_owned);
        }
        if !self.dirty.contains(&group) {
            self.dirty.push_back(group);
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CheckTarget {
    host: Option<String>,
    host_confirmed: bool,
    destination: SocketAddr,
}

struct PendingCheck {
    id: RequestId,
    target: CheckTarget,
    started: Instant,
    retried: bool,
    waiting: Vec<FlowKey>,
}

#[derive(Clone, Copy)]
struct Evidence {
    at_ms: u64,
    direct: bool,
    request_id: RequestId,
}

impl Evidence {
    fn age(self, clock: fn() -> Option<u64>) -> Option<u64> {
        if self.at_ms == 0 {
            return None;
        }
        clock()?.checked_sub(self.at_ms)
    }
}

#[derive(Clone, Copy)]
struct CachedDecision {
    evidence: Option<Evidence>,
    at: Instant,
}

struct CheckedRelease {
    key: FlowKey,
    group: GroupId,
    target: CheckTarget,
    evidence: Evidence,
    started: Instant,
    retried: bool,
}

struct WarmIdentity {
    name: String,
    valid_until: Instant,
    eligible_until: Option<Instant>,
    shared: bool,
    last_warm: Option<Instant>,
}

#[derive(Default)]
struct GroupCheck {
    recent: HashMap<CheckTarget, CachedDecision>,
    pending: Vec<PendingCheck>,
    failure_cutoff: u64,
}

impl GroupCheck {
    fn expired(&self, now: Instant, timeout: Duration) -> Option<usize> {
        self.pending.iter().enumerate()
            .filter(|(_, check)| now.duration_since(check.started) >= timeout)
            .min_by_key(|(_, check)| (check.started, check.id))
            .map(|(index, _)| index)
    }
}

pub struct Gate {
    cfg: GateConfig,
    classifier: Box<dyn Classifier + Send>,
    flows: HashMap<FlowKey, Flow>,
    groups: HashMap<GroupId, GroupCheck>,
    last_request: u64,
    releases: HashMap<u64, CheckedRelease>,
    last_release: u64,
    learned: HashMap<IpAddr, (GroupId, String, Instant)>,
    warm_names: HashMap<IpAddr, WarmIdentity>,
    next_warm_prune: Option<Instant>,
    warm_sent: VecDeque<Instant>,
    out: Vec<Out>,
    blocked_flows: BlockedFlows,
    clock: fn() -> Option<u64>,
}

impl Gate {
    pub fn new(cfg: GateConfig, classifier: Box<dyn Classifier + Send>) -> Self {
        Gate {
            cfg,
            classifier,
            flows: HashMap::new(),
            groups: HashMap::new(),
            last_request: 0,
            releases: HashMap::new(),
            last_release: 0,
            learned: HashMap::new(),
            warm_names: HashMap::new(),
            next_warm_prune: None,
            warm_sent: VecDeque::new(),
            out: Vec::new(),
            blocked_flows: BlockedFlows::default(),
            clock: evidence_clock_ms,
        }
    }

    /// Actions produced since the last drain, in order.
    pub fn drain(&mut self) -> Vec<Out> {
        std::mem::take(&mut self.out)
    }

    /// A changed group's cumulative counts for this gate's control peer.
    pub fn take_denied_group(&mut self) -> Option<&DeniedGroup> {
        let id = self.blocked_flows.dirty.pop_front()?;
        self.blocked_flows.groups.get(&id)
    }

    /// Forget every verdict (reconnect, network change, wake: §66.6).
    pub fn invalidate(&mut self) {
        let groups = std::mem::take(&mut self.groups);
        let releases = std::mem::take(&mut self.releases);
        self.out.retain(|out| !matches!(out, Out::Check { .. } | Out::SendChecked(_) | Out::Warm { .. }));
        self.warm_names.clear();
        self.next_warm_prune = None;
        self.warm_sent.clear();
        for release in releases.into_values() {
            self.block(release.key, None);
        }
        for key in groups.into_values().flat_map(|group| group.pending).flat_map(|check| check.waiting) {
            self.block(key, None);
        }
    }

    /// New groups or probe marker from the controller (§66.6): established
    /// connections keep their decision; verdicts and learned addresses,
    /// which name the old groups, are dropped.
    pub fn reconfigure(&mut self, probe_alpn: Vec<u8>, classifier: Box<dyn Classifier + Send>) {
        self.cfg.probe_alpn = probe_alpn;
        self.classifier = classifier;
        self.learned.retain(|_, (group, name, _)| {
            let Some(next) = self.classifier.group_for_name(name) else { return false };
            *group = next;
            true
        });
        self.invalidate();
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// A packet from the Mac into the tunnel.
    pub fn outbound(&mut self, pkt: &[u8], now: Instant) -> Step {
        let Some(p) = parse_ip(pkt) else { return Step::Forward };
        match p.l4 {
            L4::Udp { sport, dport } => self.outbound_udp(pkt, &p, sport, dport, now),
            L4::Tcp(t) => self.outbound_tcp(pkt, &p, t, now),
            L4::Other => Step::Forward,
        }
    }

    /// A packet from the tunnel to the Mac. Always delivered by the caller;
    /// the gate only learns protected names' addresses from DNS answers.
    pub fn inbound(&mut self, pkt: &[u8], now: Instant) {
        let Some(p) = parse_ip(pkt) else { return };
        if let L4::Udp { sport: 53, .. } = p.l4 {
            if let Some((name, addrs)) = parse_dns_answer(p.payload) {
                let group = self.classifier.group_for_name(&name);
                for (ip, ttl) in addrs {
                    let lifetime = Duration::from_secs(u64::from(ttl)).min(WARM_NAME_LIFETIME);
                    if !lifetime.is_zero() {
                        self.observe_warm_identity(ip, &name, lifetime, group.is_some(), now);
                    }
                    if let Some(group) = group {
                        self.learn(ip, group, &name, now);
                    }
                }
            }
        }
    }

    /// The background service's answer to an [`Out::Check`].
    pub fn verdict(&mut self, group: GroupId, request_id: RequestId, verdict: Verdict, evidence_at_ms: Option<u64>, now: Instant) {
        self.expire_group(group, now);
        let Some(checks) = self.groups.get_mut(&group) else { return };
        let Some(index) = checks.pending.iter().position(|check| check.id == request_id) else { return };
        match verdict {
            Verdict::Block => self.fail_check(group, index, now),
            Verdict::AllowDependent | Verdict::AllowDirect => {
                let check = checks.pending.swap_remove(index);
                // DNS hints and unnamed traffic cannot assert a flow's host.
                let direct = matches!(verdict, Verdict::AllowDirect) && check.target.host_confirmed;
                if !direct && request_id.get() <= checks.failure_cutoff {
                    self.block_waiting(group, &check);
                    return;
                }
                let proof = evidence_at_ms.map(|at_ms| Evidence { at_ms, direct, request_id });
                match proof.and_then(|proof| proof.age(self.clock).map(|age| (proof, age))) {
                    Some((proof, age)) if age < EVIDENCE_AGE_MS => {
                        if checks.recent.len() < MAX_CACHED_PER_GROUP {
                            let decision = CachedDecision { evidence: Some(proof), at: now };
                            checks.recent.insert(check.target.clone(), decision);
                        }
                        for key in check.waiting {
                            self.queue_release(CheckedRelease {
                                key, group, target: check.target.clone(), evidence: proof,
                                started: check.started, retried: check.retried,
                            });
                        }
                    }
                    Some(_) => self.retry_check(group, check, now),
                    None => self.block_waiting(group, &check),
                }
            }
        }
    }

    /// The controller has suspended this group. Any subsequent new check
    /// goes to the controller for a fresh decision.
    pub fn block_group(&mut self, group: GroupId) {
        let Some(checks) = self.groups.get_mut(&group) else { return };
        checks.recent.retain(|_, decision| decision.evidence.is_none());
        let pending = std::mem::take(&mut checks.pending);
        self.out.retain(|out| !matches!(out, Out::Check { group: id, .. } | Out::Warm { group: id, .. } if *id == group));
        for check in pending {
            self.block_waiting(group, &check);
        }
        self.revoke_group_releases(group, false);
    }

    fn expire_group(&mut self, group: GroupId, now: Instant) {
        while let Some(index) = self.groups.get(&group)
            .and_then(|checks| checks.expired(now, self.cfg.check_timeout))
        {
            let check = &self.groups[&group].pending[index];
            self.out.push(Out::TimedOut {
                group,
                host: check.target.host.clone(),
                host_confirmed: check.target.host_confirmed,
                destination: check.target.destination,
                request_id: check.id,
            });
            self.fail_check(group, index, now);
        }
    }

    fn fail_check(&mut self, group: GroupId, index: usize, now: Instant) {
        let checks = self.groups.get_mut(&group).expect("pending group");
        let failed = checks.pending.swap_remove(index);
        // A dependent result may already be on the wire when a local
        // deadline fires. Independent results still speak for their own key.
        checks.failure_cutoff = self.last_request;
        checks.recent.retain(|_, decision|
            decision.evidence.is_none() && now.duration_since(decision.at) < self.cfg.reuse);
        self.out.retain(|out| !matches!(out, Out::Check { request_id, .. } if *request_id == failed.id));
        self.block_waiting(group, &failed);
        let checks = self.groups.get_mut(&group).expect("pending group");
        if checks.recent.len() < MAX_CACHED_PER_GROUP {
            checks.recent.insert(failed.target, CachedDecision { evidence: None, at: now });
        }
        self.revoke_group_releases(group, true);
    }

    fn block_waiting(&mut self, group: GroupId, check: &PendingCheck) {
        let rule = Some((group, check.target.host.as_deref()));
        for &key in &check.waiting {
            self.block(key, rule);
        }
    }

    fn retry_check(&mut self, group: GroupId, mut check: PendingCheck, now: Instant) {
        if check.retried || now.duration_since(check.started) >= self.cfg.check_timeout {
            self.block_waiting(group, &check);
            return;
        }
        let checks = self.groups.entry(group).or_default();
        if let Some(pending) = checks.pending.iter_mut().find(|pending| pending.target == check.target) {
            if pending.retried && pending.started == check.started {
                pending.waiting.extend(check.waiting);
            } else {
                self.block_waiting(group, &check);
            }
            return;
        }
        let Some(id) = self.last_request.checked_add(1).and_then(RequestId::new)
            .filter(|_| checks.pending.len() < MAX_PENDING_PER_GROUP)
        else {
            self.block_waiting(group, &check);
            return;
        };
        self.last_request = id.get();
        check.id = id;
        check.retried = true;
        self.out.push(Out::Check {
            group, host: check.target.host.clone(), host_confirmed: check.target.host_confirmed,
            destination: check.target.destination, request_id: id,
        });
        checks.pending.push(check);
    }

    fn queue_release(&mut self, release: CheckedRelease) {
        let Some(id) = self.last_release.checked_add(1) else {
            self.block(release.key, Some((release.group, release.target.host.as_deref())));
            return;
        };
        if let Some(Flow { state: State::Holding(held), .. }) = self.flows.get_mut(&release.key) {
            held.checking = true;
            self.last_release = id;
            self.releases.insert(id, release);
            self.out.push(Out::SendChecked(id));
        }
    }

    fn revoke_group_releases(&mut self, group: GroupId, dependent_only: bool) {
        let revoked: Vec<_> = self.releases.iter().filter_map(|(&id, release)|
            (release.group == group && (!dependent_only || !release.evidence.direct)).then_some(id)
        ).collect();
        for id in revoked {
            if let Some(release) = self.take_release(id) {
                self.block(release.key, Some((group, release.target.host.as_deref())));
            }
        }
    }

    fn take_release(&mut self, id: u64) -> Option<CheckedRelease> {
        let release = self.releases.remove(&id);
        if self.releases.is_empty() && self.releases.capacity() > MAX_CACHED_PER_GROUP {
            self.releases.shrink_to_fit();
        }
        release
    }

    /// Commit the release only on its current token and just before the
    /// first packet write. Failure to enqueue a packet leaves the flow blocked.
    pub fn send_checked(&mut self, id: u64, now: Instant, send: impl FnOnce(&[Vec<u8>]) -> bool) {
        let Some(release) = self.take_release(id) else { return };
        let CheckedRelease { key, group, target, evidence, started, retried } = release;
        let Some(Flow { state: State::Holding(held), .. }) = self.flows.get(&key) else { return };
        match evidence.age(self.clock) {
            Some(age) if age < EVIDENCE_AGE_MS => {
                if send(&held.packets) {
                    self.set_state(key, State::Pass);
                    if let Some(name) = target.host.filter(|_| evidence.direct) {
                        self.observe_warm_identity(key.dst, &name, WARM_NAME_LIFETIME, true, now);
                    }
                } else {
                    self.block(key, None);
                }
            }
            Some(_) => self.retry_check(group, PendingCheck {
                id: evidence.request_id, target, started, retried, waiting: vec![key],
            }, now),
            None => self.block(key, Some((group, target.host.as_deref()))),
        }
    }

    /// Timers: checks that took too long, ClientHellos that never finished,
    /// idle connections.
    pub fn tick(&mut self, now: Instant) {
        let timed_out: Vec<_> = self
            .groups
            .iter()
            .filter_map(|(&id, checks)| checks.expired(now, self.cfg.check_timeout).is_some().then_some(id))
            .collect();
        for group in timed_out {
            self.expire_group(group, now);
        }
        self.groups.retain(|_, checks| {
            checks.recent.retain(|_, decision| now.duration_since(decision.at) < self.cfg.reuse);
            !checks.pending.is_empty() || !checks.recent.is_empty()
        });
        let stale: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, f)| matches!(&f.state, State::Holding(h) if !h.checking && now.duration_since(h.since) >= self.cfg.classify_timeout))
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            let _ = self.decide_by_address(k, now, false);
        }
        let idle = self.cfg.idle;
        self.flows.retain(|_, f| matches!(f.state, State::Holding(_)) || now.duration_since(f.last_seen) < idle);
    }

    fn outbound_udp(&mut self, pkt: &[u8], p: &Packet, sport: u16, dport: u16, now: Instant) -> Step {
        if self.cfg.block_quic && dport == 443 {
            return Step::Consumed;
        }
        let key = FlowKey { proto: 17, src: p.src, sport, dst: p.dst, dport };
        if let Some(f) = self.flows.get_mut(&key) {
            f.last_seen = now;
            return match &mut f.state {
                State::Pass => Step::Forward,
                State::Blocked => Step::Consumed,
                State::Holding(h) => {
                    if h.bytes.saturating_add(pkt.len()) > self.cfg.max_held_bytes { return Step::Consumed; }
                    h.packets.push(pkt.to_vec());
                    h.bytes += pkt.len();
                    Step::Consumed
                }
                State::Fresh { .. } => Step::Forward,
            };
        }
        // A new datagram flow: only an address can tell where it goes.
        match self.ip_group(p.dst) {
            None => {
                self.insert(key, State::Pass, now);
                Step::Forward
            }
            Some((group, host)) => {
                if pkt.len() <= self.cfg.max_held_bytes {
                    let held = Held { packets: vec![pkt.to_vec()], bytes: pkt.len(), stream: Vec::new(), next: 0, since: now, checking: false, client_isn: None, last: None };
                    if self.insert(key, State::Holding(Box::new(held)), now) {
                        self.wait_for_check(key, group, host, false, now);
                    }
                }
                Step::Consumed
            }
        }
    }

    fn outbound_tcp(&mut self, pkt: &[u8], p: &Packet, t: Tcp, now: Instant) -> Step {
        let key = FlowKey { proto: 6, src: p.src, sport: t.sport, dst: p.dst, dport: t.dport };
        let seg = ClientSeg { seq: t.seq, ack: t.ack, has_ack: t.flags & ACK != 0, syn: t.flags & SYN != 0, len: p.payload.len() as u32 };
        let syn = t.flags & SYN != 0;
        let data_start = if syn { t.seq.wrapping_add(1) } else { t.seq };
        if !self.flows.contains_key(&key) {
            if syn {
                if !self.insert(key, State::Fresh { next: data_start }, now) {
                    self.reset(key, seg);
                    return Step::Consumed;
                }
                if p.payload.is_empty() {
                    self.warm_known_address(key, now);
                }
            } else if p.payload.is_empty() {
                return Step::Forward;
            } else {
                // Mid-stream (forgotten or older than the gate): no start of
                // stream to parse, so decide by address.
                return match self.ip_group(p.dst) {
                    None => {
                        self.insert(key, State::Pass, now);
                        Step::Forward
                    }
                    Some((group, host)) => {
                        if pkt.len() <= self.cfg.max_held_bytes {
                            let held = Held { packets: vec![pkt.to_vec()], bytes: pkt.len(), stream: Vec::new(), next: t.seq.wrapping_add(seg.len), since: now, checking: false, client_isn: None, last: Some(seg) };
                            if self.insert(key, State::Holding(Box::new(held)), now) {
                                self.wait_for_check(key, group, host, false, now);
                                return Step::Consumed;
                            }
                        }
                        self.reset(key, seg);
                        Step::Consumed
                    }
                };
            }
        }
        let f = self.flows.get_mut(&key).expect("present");
        f.last_seen = now;
        match &mut f.state {
            State::Pass => Step::Forward,
            State::Blocked => {
                if !p.payload.is_empty() || syn {
                    self.reset(key, seg);
                }
                Step::Consumed
            }
            State::Fresh { next } => {
                if p.payload.is_empty() {
                    return Step::Forward;
                }
                if pkt.len() > self.cfg.max_held_bytes {
                    f.state = State::Blocked;
                    self.reset(key, seg);
                    return Step::Consumed;
                }
                let next = *next;
                let mut held = Held { packets: Vec::new(), bytes: 0, stream: Vec::new(), next, since: now, checking: false, client_isn: Some(next.wrapping_sub(1)), last: Some(seg) };
                if data_start == next {
                    held.stream.extend_from_slice(p.payload);
                    held.next = next.wrapping_add(seg.len);
                }
                held.packets.push(pkt.to_vec());
                held.bytes = pkt.len();
                f.state = State::Holding(Box::new(held));
                self.after_hold(key, now, true)
            }
            State::Holding(h) => {
                if h.bytes.saturating_add(pkt.len()) > self.cfg.max_held_bytes {
                    return Step::Consumed;
                }
                if p.payload.is_empty() && !syn {
                    // Pure ACKs keep their place behind the held data.
                    h.packets.push(pkt.to_vec());
                    h.bytes += pkt.len();
                    return Step::Consumed;
                }
                if seq_lt(data_start, h.next) && seq_le(data_start.wrapping_add(seg.len), h.next) {
                    // A retransmission of held data: already held once.
                    return Step::Consumed;
                }
                if data_start == h.next {
                    h.stream.extend_from_slice(p.payload);
                    h.next = h.next.wrapping_add(seg.len);
                }
                h.packets.push(pkt.to_vec());
                h.bytes += pkt.len();
                h.last = Some(seg);
                if h.checking {
                    Step::Consumed
                } else {
                    self.after_hold(key, now, false)
                }
            }
        }
    }

    /// Try to classify a holding connection from what it has sent so far.
    fn after_hold(&mut self, key: FlowKey, now: Instant, first: bool) -> Step {
        let (verdict, full) = {
            let Some(Flow { state: State::Holding(h), .. }) = self.flows.get(&key) else { return Step::Consumed };
            (sniff(&h.stream), h.bytes >= self.cfg.max_held_bytes)
        };
        let target = match verdict {
            Sniff::Incomplete if !full => return Step::Consumed,
            Sniff::Incomplete | Sniff::Unknown => Target::Address,
            Sniff::Tls { sni, alpn, ech } => {
                if !self.cfg.probe_alpn.is_empty() && alpn.contains(&self.cfg.probe_alpn) {
                    Target::Pass
                } else {
                    match sni {
                        Some(name) if !ech => self.classify_named(key.dst, name, now),
                        Some(name) => match self.classifier.group_for_name(&name) {
                            Some(group) => Target::Group(group, name, false),
                            None => Target::Address,
                        },
                        None => Target::Address,
                    }
                }
            }
            Sniff::Http(Some(name)) => self.classify_named(key.dst, name, now),
            Sniff::Http(None) => Target::Address,
        };
        let only_current = first;
        match target {
            Target::Pass => {
                if only_current {
                    self.set_state(key, State::Pass);
                    Step::Forward
                } else {
                    self.release(key);
                    Step::Consumed
                }
            }
            Target::Address => self.decide_by_address(key, now, only_current),
            Target::Group(group, host, confirmed) => {
                self.wait_for_check(key, group, Some(host), confirmed, now);
                Step::Consumed
            }
        }
    }

    fn classify_named(&mut self, ip: IpAddr, name: String, now: Instant) -> Target {
        self.observe_warm_identity(ip, &name, WARM_NAME_LIFETIME, false, now);
        match self.classifier.group_for_name(&name) {
            Some(group) => Target::Group(group, name, true),
            None => Target::Pass,
        }
    }

    fn observe_warm_identity(&mut self, ip: IpAddr, name: &str, lifetime: Duration, eligible: bool, now: Instant) {
        if name.is_empty() || name.len() > 253 || !name.is_ascii() {
            return;
        }
        if self.warm_names.len() >= MAX_WARM_IDENTITIES && !self.warm_names.contains_key(&ip) {
            if self.next_warm_prune.is_none_or(|at| at <= now) {
                self.warm_names.retain(|_, identity| identity.valid_until > now);
                self.next_warm_prune = Some(now + WARM_WINDOW);
            }
            if self.warm_names.len() >= MAX_WARM_IDENTITIES {
                return;
            }
        }
        let until = now + lifetime;
        let identity = self.warm_names.entry(ip).or_insert_with(|| WarmIdentity {
            name: name.to_owned(), valid_until: now, eligible_until: None, shared: false, last_warm: None,
        });
        if identity.valid_until <= now {
            identity.name.clear();
            identity.name.push_str(name);
            identity.shared = false;
            identity.eligible_until = None;
        } else if identity.name != name {
            identity.shared = true;
        }
        identity.valid_until = identity.valid_until.max(until);
        if eligible && !identity.shared {
            identity.eligible_until = Some(identity.eligible_until.unwrap_or(until).max(until));
        }
    }

    fn warm_known_address(&mut self, key: FlowKey, now: Instant) {
        let Some(identity) = self.warm_names.get_mut(&key.dst) else { return };
        if identity.shared || identity.eligible_until.is_none_or(|until| until <= now)
            || identity.last_warm.is_some_and(|last| now.duration_since(last) < WARM_WINDOW)
        {
            return;
        }
        let Some(group) = self.classifier.group_for_name(&identity.name) else { return };
        if self.groups.get(&group).is_some_and(|checks| checks.pending.iter()
            .any(|check| check.target.destination.ip() == key.dst))
        {
            return;
        }
        while self.warm_sent.front().is_some_and(|at| now.duration_since(*at) >= WARM_WINDOW) {
            self.warm_sent.pop_front();
        }
        if self.warm_sent.len() >= MAX_WARMS_PER_WINDOW {
            return;
        }
        self.warm_sent.push_back(now);
        identity.last_warm = Some(now);
        self.out.push(Out::Warm {
            group, host: identity.name.clone(), destination: SocketAddr::new(key.dst, key.dport),
        });
    }

    /// Decide a holding connection by its destination address.
    fn decide_by_address(&mut self, key: FlowKey, now: Instant, only_current: bool) -> Step {
        match self.ip_group(key.dst) {
            None => {
                if only_current {
                    self.set_state(key, State::Pass);
                    Step::Forward
                } else {
                    self.release(key);
                    Step::Consumed
                }
            }
            Some((g, host)) => {
                self.wait_for_check(key, g, host, false, now);
                Step::Consumed
            }
        }
    }

    fn wait_for_check(&mut self, key: FlowKey, group: GroupId, host: Option<String>, host_confirmed: bool, now: Instant) {
        let target = CheckTarget {
            host,
            host_confirmed,
            destination: SocketAddr::new(key.dst, key.dport),
        };
        self.expire_group(group, now);
        let reuse = self.cfg.reuse;
        let checks = self.groups.entry(group).or_default();
        if let Some(&decision) = checks.recent.get(&target) {
            if now.duration_since(decision.at) < reuse {
                match decision.evidence {
                    Some(evidence) if evidence.age(self.clock).is_some_and(|age| age < EVIDENCE_AGE_MS) => {
                        self.queue_release(CheckedRelease {
                            key, group, target, evidence, started: now, retried: false,
                        });
                        return;
                    }
                    None => {
                        self.block(key, Some((group, target.host.as_deref())));
                        return;
                    }
                    Some(_) => {}
                }
            }
        }
        if let Some(check) = checks.pending.iter_mut().find(|check| check.target == target) {
            check.waiting.push(key);
        } else {
            let Some(id) = self.last_request.checked_add(1).and_then(RequestId::new)
                .filter(|_| checks.pending.len() < MAX_PENDING_PER_GROUP)
            else {
                self.block(key, None);
                return;
            };
            self.last_request = id.get();
            self.out.push(Out::Check {
                group,
                host: target.host.clone(),
                host_confirmed: target.host_confirmed,
                destination: target.destination,
                request_id: id,
            });
            checks.pending.push(PendingCheck {
                id,
                target,
                started: now,
                retried: false,
                waiting: vec![key],
            });
        }
        if let Some(Flow { state: State::Holding(held), .. }) = self.flows.get_mut(&key) {
            held.checking = true;
        }
    }

    fn release(&mut self, key: FlowKey) {
        let Some(f) = self.flows.get_mut(&key) else { return };
        if let State::Holding(h) = std::mem::replace(&mut f.state, State::Pass) {
            for pkt in h.packets {
                self.out.push(Out::ToTunnel(pkt));
            }
        }
    }

    fn block(&mut self, key: FlowKey, rule: Option<(GroupId, Option<&str>)>) {
        let Some(f) = self.flows.get_mut(&key) else { return };
        if let State::Holding(h) = std::mem::replace(&mut f.state, State::Blocked) {
            if let Some((group, host)) = rule {
                self.blocked_flows.record(key, h.client_isn, group, host);
            }
            if let (6, Some(last)) = (key.proto, h.last) {
                self.reset(key, last);
            }
        }
    }

    fn reset(&mut self, key: FlowKey, seg: ClientSeg) {
        if let Some(rst) = build_rst(&key, seg) {
            self.out.push(Out::ToHost(rst));
        }
    }

    fn set_state(&mut self, key: FlowKey, s: State) {
        if let Some(f) = self.flows.get_mut(&key) {
            f.state = s;
        }
    }

    fn insert(&mut self, key: FlowKey, state: State, now: Instant) -> bool {
        if self.flows.len() >= self.cfg.max_flows {
            self.evict();
            if self.flows.len() >= self.cfg.max_flows {
                return false;
            }
        }
        self.flows.insert(key, Flow { state, last_seen: now });
        true
    }

    /// Drop the oldest eighth of passed/blocked connections. Holding ones are
    /// never evicted: their packets would be lost or, worse, passed unchecked.
    fn evict(&mut self) {
        let mut idle: Vec<(Instant, FlowKey)> = self
            .flows
            .iter()
            .filter(|(_, f)| matches!(f.state, State::Pass | State::Blocked))
            .map(|(k, f)| (f.last_seen, *k))
            .collect();
        idle.sort_by_key(|(t, _)| *t);
        let n = (self.cfg.max_flows / 8).max(1);
        for (_, k) in idle.into_iter().take(n) {
            self.flows.remove(&k);
        }
    }

    fn ip_group(&self, ip: IpAddr) -> Option<(GroupId, Option<String>)> {
        if let Some((g, name, _)) = self.learned.get(&ip) {
            return Some((*g, Some(name.clone())));
        }
        self.classifier.group_for_ip(ip).map(|g| (g, None))
    }

    fn learn(&mut self, ip: IpAddr, group: GroupId, name: &str, now: Instant) {
        if !self.learned.contains_key(&ip) && self.learned.len() >= self.cfg.max_learned {
            if let Some(oldest) = self.learned.iter().min_by_key(|(_, v)| v.2).map(|(k, _)| *k) {
                self.learned.remove(&oldest);
            }
        }
        self.learned.insert(ip, (group, name.to_string(), now));
    }
}

enum Target {
    Pass,
    Address,
    Group(GroupId, String, bool),
}

// ---------------------------------------------------------------- packets

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

#[derive(Clone, Copy, Debug)]
struct Tcp {
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
}

#[derive(Clone, Copy, Debug)]
enum L4 {
    Tcp(Tcp),
    Udp { sport: u16, dport: u16 },
    Other,
}

struct Packet<'a> {
    src: IpAddr,
    dst: IpAddr,
    l4: L4,
    payload: &'a [u8],
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Parse an IPv4/IPv6 packet as the tunnel carries it (no link header).
/// Fragments and unknown protocols come back as [`L4::Other`]: the gate
/// passes what it cannot attribute to a connection.
fn parse_ip(pkt: &[u8]) -> Option<Packet<'_>> {
    let v = pkt.first()? >> 4;
    let (src, dst, proto, l4_start, end) = match v {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            let total = be16(pkt, 2) as usize;
            if ihl < 20 || total < ihl || total > pkt.len() {
                return None;
            }
            let frag = be16(pkt, 6);
            let src = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
            if frag & 0x3fff != 0 {
                return Some(Packet { src, dst, l4: L4::Other, payload: &[] });
            }
            (src, dst, pkt[9], ihl, total)
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let total = 40 + be16(pkt, 4) as usize;
            if total > pkt.len() {
                return None;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[8..24]);
            let src = IpAddr::V6(Ipv6Addr::from(a));
            a.copy_from_slice(&pkt[24..40]);
            let dst = IpAddr::V6(Ipv6Addr::from(a));
            let (mut next, mut at) = (pkt[6], 40usize);
            loop {
                match next {
                    0 | 43 | 60 => {
                        if at + 8 > total {
                            return None;
                        }
                        next = pkt[at];
                        at += (pkt[at + 1] as usize + 1) * 8;
                    }
                    44 => return Some(Packet { src, dst, l4: L4::Other, payload: &[] }),
                    _ => break,
                }
            }
            (src, dst, next, at, total)
        }
        _ => return None,
    };
    let b = pkt.get(l4_start..end)?;
    match proto {
        6 => {
            if b.len() < 20 {
                return None;
            }
            let off = ((b[12] >> 4) as usize) * 4;
            if off < 20 || off > b.len() {
                return None;
            }
            let t = Tcp { sport: be16(b, 0), dport: be16(b, 2), seq: be32(b, 4), ack: be32(b, 8), flags: b[13] };
            Some(Packet { src, dst, l4: L4::Tcp(t), payload: &b[off..] })
        }
        17 => {
            if b.len() < 8 {
                return None;
            }
            Some(Packet { src, dst, l4: L4::Udp { sport: be16(b, 0), dport: be16(b, 2) }, payload: &b[8..] })
        }
        _ => Some(Packet { src, dst, l4: L4::Other, payload: &[] }),
    }
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        acc += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        acc += (data[i] as u32) << 8;
    }
    acc
}
fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// A RST|ACK from the server's address to the Mac, acceptable to the Mac's
/// stack: its sequence number is what the client last acknowledged.
fn build_rst(k: &FlowKey, seg: ClientSeg) -> Option<Vec<u8>> {
    let (seq, ack) = if seg.has_ack && !seg.syn {
        (seg.ack, seg.seq.wrapping_add(seg.len))
    } else {
        (0, seg.seq.wrapping_add(1).wrapping_add(seg.len))
    };
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&k.dport.to_be_bytes());
    tcp[2..4].copy_from_slice(&k.sport.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = RST | ACK;
    match (k.dst, k.src) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut pseudo = Vec::with_capacity(12);
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&[0, 6, 0, 20]);
            let c = fold(sum16(&tcp, sum16(&pseudo, 0)));
            tcp[16..18].copy_from_slice(&c.to_be_bytes());
            let mut ip = vec![0u8; 20];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&40u16.to_be_bytes());
            ip[6] = 0x40;
            ip[8] = 64;
            ip[9] = 6;
            ip[12..16].copy_from_slice(&s.octets());
            ip[16..20].copy_from_slice(&d.octets());
            let c = fold(sum16(&ip, 0));
            ip[10..12].copy_from_slice(&c.to_be_bytes());
            ip.extend_from_slice(&tcp);
            Some(ip)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut pseudo = Vec::with_capacity(40);
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&[0, 0, 0, 20, 0, 0, 0, 6]);
            let c = fold(sum16(&tcp, sum16(&pseudo, 0)));
            tcp[16..18].copy_from_slice(&c.to_be_bytes());
            let mut ip = vec![0u8; 40];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&20u16.to_be_bytes());
            ip[6] = 6;
            ip[7] = 64;
            ip[8..24].copy_from_slice(&s.octets());
            ip[24..40].copy_from_slice(&d.octets());
            ip.extend_from_slice(&tcp);
            Some(ip)
        }
        _ => None,
    }
}

// ------------------------------------------------------- first-bytes sniff

#[derive(Debug, PartialEq, Eq)]
enum Sniff {
    Incomplete,
    Unknown,
    Tls { sni: Option<String>, alpn: Vec<Vec<u8>>, ech: bool },
    Http(Option<String>),
}

fn sniff(b: &[u8]) -> Sniff {
    if b.is_empty() {
        return Sniff::Incomplete;
    }
    if b[0] == 0x16 {
        return match client_hello(b) {
            Hello::Incomplete => Sniff::Incomplete,
            Hello::Other => Sniff::Unknown,
            Hello::Found { sni, alpn, ech } => Sniff::Tls { sni, alpn, ech },
        };
    }
    match http_host(b) {
        HttpHost::Incomplete => Sniff::Incomplete,
        HttpHost::NotHttp => Sniff::Unknown,
        HttpHost::Host(h) => Sniff::Http(h),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Hello {
    Incomplete,
    Other,
    Found { sni: Option<String>, alpn: Vec<Vec<u8>>, ech: bool },
}

const MAX_HELLO: usize = 16 * 1024;

/// The ClientHello from the first client bytes, joined across TLS records.
fn client_hello(b: &[u8]) -> Hello {
    let mut hs: Vec<u8> = Vec::new();
    let mut at = 0usize;
    loop {
        if b.len() < at + 5 {
            return Hello::Incomplete;
        }
        if b[at] != 0x16 || b[at + 1] != 0x03 {
            return Hello::Other;
        }
        let len = be16(b, at + 3) as usize;
        if len == 0 || len > MAX_HELLO + 256 {
            return Hello::Other;
        }
        if b.len() < at + 5 + len {
            // Parse what is there only to reject early; otherwise wait.
            return Hello::Incomplete;
        }
        hs.extend_from_slice(&b[at + 5..at + 5 + len]);
        at += 5 + len;
        if hs.len() >= 4 {
            if hs[0] != 1 {
                return Hello::Other;
            }
            let need = 4 + ((hs[1] as usize) << 16 | (hs[2] as usize) << 8 | hs[3] as usize);
            if need > MAX_HELLO {
                return Hello::Other;
            }
            if hs.len() >= need {
                return parse_hello_body(&hs[4..need]);
            }
        }
        if at >= MAX_HELLO + 5 {
            return Hello::Other;
        }
    }
}

fn parse_hello_body(h: &[u8]) -> Hello {
    let bad = Hello::Other;
    let mut p = 2 + 32;
    if h.len() < p + 1 {
        return bad;
    }
    p += 1 + h[p] as usize;
    if h.len() < p + 2 {
        return bad;
    }
    p += 2 + be16(h, p) as usize;
    if h.len() < p + 1 {
        return bad;
    }
    p += 1 + h[p] as usize;
    if h.len() < p + 2 {
        return Hello::Found { sni: None, alpn: Vec::new(), ech: false };
    }
    let end = p + 2 + be16(h, p) as usize;
    if end > h.len() {
        return bad;
    }
    p += 2;
    let (mut sni, mut alpn, mut ech) = (None, Vec::new(), false);
    while p + 4 <= end {
        let (ty, len) = (be16(h, p), be16(h, p + 2) as usize);
        p += 4;
        if p + len > end {
            return bad;
        }
        let e = &h[p..p + len];
        match ty {
            0 if e.len() >= 5 && e[2] == 0 => {
                let n = be16(e, 3) as usize;
                if 5 + n <= e.len() {
                    sni = std::str::from_utf8(&e[5..5 + n]).ok().map(norm);
                }
            }
            16 if e.len() >= 2 => {
                let mut q = 2;
                while q < e.len() {
                    let n = e[q] as usize;
                    if q + 1 + n > e.len() {
                        break;
                    }
                    alpn.push(e[q + 1..q + 1 + n].to_vec());
                    q += 1 + n;
                }
            }
            0xfe0d => ech = true,
            _ => {}
        }
        p += len;
    }
    Hello::Found { sni, alpn, ech }
}

#[derive(Debug, PartialEq, Eq)]
enum HttpHost {
    Incomplete,
    NotHttp,
    Host(Option<String>),
}

const METHODS: [&[u8]; 9] = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "];

fn http_host(b: &[u8]) -> HttpHost {
    let is_method = METHODS.iter().any(|m| b.starts_with(m));
    if !is_method {
        let prefix = METHODS.iter().any(|m| m.starts_with(b));
        return if prefix { HttpHost::Incomplete } else { HttpHost::NotHttp };
    }
    let lim = &b[..b.len().min(8192)];
    let Some(end) = find(lim, b"\r\n\r\n") else {
        return if b.len() < 8192 { HttpHost::Incomplete } else { HttpHost::Host(None) };
    };
    for line in lim[..end].split(|c| *c == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() > 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            let v = std::str::from_utf8(&line[5..]).unwrap_or("").trim();
            let host = if let Some(rest) = v.strip_prefix('[') {
                rest.split(']').next().unwrap_or("")
            } else {
                v.rsplit_once(':').filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h).unwrap_or(v)
            };
            return HttpHost::Host(if host.is_empty() { None } else { Some(norm(host)) });
        }
    }
    HttpHost::Host(None)
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn norm(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

// -------------------------------------------------------------- DNS answers

/// The question name and A/AAAA addresses of a DNS response.
fn parse_dns_answer(m: &[u8]) -> Option<(String, Vec<(IpAddr, u32)>)> {
    if m.len() < 12 || m[2] & 0x80 == 0 {
        return None;
    }
    let (qd, an) = (be16(m, 4), be16(m, 6) as usize);
    if qd != 1 {
        return None;
    }
    let (name, mut p) = dns_name(m, 12)?;
    if p + 4 > m.len() {
        return None;
    }
    let question_type = be16(m, p);
    let question_class = be16(m, p + 2);
    p += 4;
    let mut addrs = Vec::new();
    let mut chain_ttl = if m[2] & 0x7a == 0 && m[3] & 0x0f == 0 { u32::MAX } else { 0 };
    for _ in 0..an.min(64) {
        let (owner, q) = dns_name(m, p)?;
        p = q;
        if p + 10 > m.len() {
            return None;
        }
        let (ty, rdlen) = (be16(m, p), be16(m, p + 8) as usize);
        // A foreign-name answer remains a routing hint, but does not
        // qualify for an advisory check before the flow identifies itself.
        let ttl = if question_class == 1 && be16(m, p + 2) == 1 &&
            (ty == question_type || ty == 5) && owner.eq_ignore_ascii_case(&name)
        {
            be32(m, p + 4)
        } else {
            0
        };
        if ty == 5 {
            chain_ttl = chain_ttl.min(ttl);
        }
        p += 10;
        if p + rdlen > m.len() {
            return None;
        }
        match (ty, rdlen) {
            (1, 4) => addrs.push((IpAddr::V4(Ipv4Addr::new(m[p], m[p + 1], m[p + 2], m[p + 3])), ttl)),
            (28, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&m[p..p + 16]);
                addrs.push((IpAddr::V6(Ipv6Addr::from(a)), ttl));
            }
            _ => {}
        }
        p += rdlen;
    }
    for (_, ttl) in &mut addrs {
        *ttl = (*ttl).min(chain_ttl);
    }
    Some((norm(&name), addrs))
}

fn dns_name(m: &[u8], mut p: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *m.get(p)? as usize;
        if len == 0 {
            return Some((out, end.unwrap_or(p + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let ptr = (len & 0x3f) << 8 | *m.get(p + 1)? as usize;
            end.get_or_insert(p + 2);
            if ptr >= p {
                return None;
            }
            p = ptr;
            continue;
        }
        let label = m.get(p + 1..p + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(std::str::from_utf8(label).ok()?);
        p += 1 + len;
    }
    None
}

#[cfg(test)]
mod tests;
