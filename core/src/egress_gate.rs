//! Egress gate (DESIGN.md §66.5, §66.25): the per-packet decision logic that
//! sits in the own connection's tunnel path when exit protection is on.
//!
//! openconnect runs in `--script-tun` mode and hands every IP packet to the
//! gate program; this module decides, per packet, whether it goes on into the
//! tunnel now, waits, or is dropped. A new TCP connection's first data is
//! held until the gate can read the name it shows (TLS SNI or HTTP Host).
//! A name that is one of the protected sites, or below one, waits for an
//! exit check of that connection's own destination; everything else passes
//! at once. A failed check drops the waiting packets and answers the Mac
//! with a TCP RST. A connection that shows no readable name passes (best
//! effort), and so does one whose exit the controller cannot read.
//!
//! The module does no I/O: the caller feeds packets and verdicts and carries
//! out the returned actions. It is pure Rust so it is tested on Linux.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

/// A protection rule (DESIGN.md §66.25); the controller's identifier.
pub type GroupId = u32;
pub type RequestId = NonZeroU64;

/// The controller's answer to an [`Out::Check`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Wrong exit: refuse the waiting connections.
    Block,
    /// The exit is allowed, as observed at this boot-clock time.
    Allow { evidence_at_ms: u64 },
    /// No exit could be read for this destination: let it through (best
    /// effort, §66.25). The controller counts these.
    Unverified,
}

const MAX_PENDING_PER_GROUP: usize = 16;
const MAX_CACHED_PER_GROUP: usize = 64;
const MAX_REPORTED_FLOWS: usize = 4096;
const MAX_REPORTED_GROUPS: usize = 16;
const MAX_REPORTED_HOSTS: usize = 32;
const EVIDENCE_AGE_MS: u64 = 1_000;

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

/// One rule's protected sites, as the controller sends them to the gate.
#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SiteGroup {
    pub id: GroupId,
    pub sites: Vec<String>,
}

/// Ordered split-list matchers shared by the gate, controller, and DNS forwarder.
#[derive(Clone, Debug, Default)]
pub struct ProtectedSites {
    groups: Vec<(GroupId, crate::dns_forwarder::SplitRules)>,
    has_exceptions: bool,
}

impl ProtectedSites {
    pub fn new(groups: &[SiteGroup]) -> Self {
        let groups: Vec<_> = groups.iter()
            .filter(|group| group.sites.iter().any(|site| !site.trim().is_empty()))
            .map(|group| (group.id, crate::dns_forwarder::SplitRules::new(&group.sites)))
            .collect();
        let has_exceptions = groups.iter().any(|(_, rules)| rules.has_exceptions());
        Self { groups, has_exceptions }
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn group_for(&self, name: &str) -> Option<GroupId> {
        let name = norm(name);
        self.groups.iter().find(|(_, rules)| rules.matches_name(&name)).map(|(id, _)| *id)
    }

    pub fn group_for_ip(&self, ip: IpAddr) -> Option<GroupId> {
        let IpAddr::V4(ip) = ip else { return None };
        self.groups.iter().find(|(_, rules)| rules.contains(ip)).map(|(id, _)| *id)
    }

    pub fn group_for_target(&self, host: &str, ip: IpAddr) -> Option<GroupId> {
        self.group_for_addresses(host, std::iter::once(ip))
    }

    pub(crate) fn name_needs_addresses(&self, host: &str) -> bool {
        self.has_exceptions && self.groups.iter().find(|(_, rules)| rules.matches_name(host))
            .is_some_and(|(_, rules)| rules.has_ip_exceptions())
    }

    pub(crate) fn group_for_addresses(&self, host: &str, mut ips: impl Iterator<Item = IpAddr> + Clone) -> Option<GroupId> {
        if !self.has_exceptions {
            return self.group_for(host).or_else(|| ips.find_map(|ip| self.group_for_ip(ip)));
        }
        let host = norm(host);
        let known = ips.clone().next().is_some();
        self.groups.iter().find(|(_, rules)| {
            rules.matches_name(&host) && (!known || ips.clone().any(|ip| match ip {
                IpAddr::V4(ip) => !rules.excludes_ip(ip),
                IpAddr::V6(_) => true,
            }))
        }).map(|(id, _)| *id).or_else(|| ips.find_map(|ip| {
            let IpAddr::V4(ip) = ip else { return None };
            self.groups.iter().find(|(_, rules)| !rules.excludes_name(&host) && rules.contains(ip)).map(|(id, _)| *id)
        }))
    }
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
    /// request before it passes unread (best effort).
    pub classify_timeout: Duration,
    /// Bytes held per connection before deciding with what is there.
    pub max_held_bytes: usize,
    /// Connection table bound; only passed or blocked entries are evicted.
    pub max_flows: usize,
    /// Connections idle this long are forgotten.
    pub idle: Duration,
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
            idle: Duration::from_secs(15 * 60),
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
    /// A packet for the Mac side (a RST for a blocked connection).
    ToHost(Vec<u8>),
    /// Ask the controller to check the exit of this exact destination.
    Check { group: GroupId, host: String, destination: SocketAddr, request_id: RequestId },
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
    /// First data held while the gate reads the name, or while it is checked.
    Holding(Box<Held>),
    Pass,
    Blocked,
}

struct Held {
    packets: Vec<Vec<u8>>,
    bytes: usize,
    /// In-order client bytes from the first data byte, for parsing.
    stream: Vec<u8>,
    next: u32,
    since: Instant,
    /// Set once a check holds this flow's key.
    checking: bool,
    client_isn: u32,
    last: ClientSeg,
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
    fn record(&mut self, flow: FlowKey, client_isn: u32, group: GroupId, host: &str) {
        if self.seen.len() >= MAX_REPORTED_FLOWS {
            return;
        }
        // Keep a bounded fingerprint even if the packet table evicts the
        // flow. A collision can only lower this best-effort count.
        if !self.seen.insert(self.seen.hasher().hash_one((flow, client_isn))) {
            return;
        }
        if self.groups.len() == MAX_REPORTED_GROUPS && !self.groups.contains_key(&group) {
            return;
        }
        let stats = self.groups.entry(group).or_insert_with(|| DeniedGroup { group, ..Default::default() });
        stats.count += 1;
        let mut reported_host = None;
        // DNS names on the wire use ASCII (including IDNA A-labels). Keep
        // reports ASCII too so a short write cannot split UTF-8.
        if host.len() <= 253 && host.is_ascii() {
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
    host: String,
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
enum Cached {
    Allowed(u64),
    Unverified,
    Blocked,
}

struct CheckedRelease {
    key: FlowKey,
    group: GroupId,
    target: CheckTarget,
    evidence_at_ms: u64,
    id: RequestId,
    started: Instant,
    retried: bool,
}

#[derive(Default)]
struct GroupCheck {
    recent: HashMap<CheckTarget, (Cached, Instant)>,
    pending: Vec<PendingCheck>,
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
    sites: ProtectedSites,
    flows: HashMap<FlowKey, Flow>,
    groups: HashMap<GroupId, GroupCheck>,
    last_request: u64,
    releases: HashMap<u64, CheckedRelease>,
    last_release: u64,
    out: Vec<Out>,
    blocked_flows: BlockedFlows,
    clock: fn() -> Option<u64>,
}

impl Gate {
    pub fn new(cfg: GateConfig, sites: ProtectedSites) -> Self {
        Gate {
            cfg,
            sites,
            flows: HashMap::new(),
            groups: HashMap::new(),
            last_request: 0,
            releases: HashMap::new(),
            last_release: 0,
            out: Vec::new(),
            blocked_flows: BlockedFlows::default(),
            clock: evidence_clock_ms,
        }
    }

    /// Actions produced since the last drain, in order.
    pub fn drain(&mut self) -> Vec<Out> {
        std::mem::take(&mut self.out)
    }

    /// A changed rule's cumulative counts for this gate's control peer.
    pub fn take_denied_group(&mut self) -> Option<&DeniedGroup> {
        let id = self.blocked_flows.dirty.pop_front()?;
        self.blocked_flows.groups.get(&id)
    }

    /// Forget every verdict (reconnect, network change, wake, lost
    /// controller: §66.6). Connections waiting for one are refused.
    pub fn invalidate(&mut self) {
        let groups = std::mem::take(&mut self.groups);
        let releases = std::mem::take(&mut self.releases);
        self.out.retain(|out| !matches!(out, Out::Check { .. } | Out::SendChecked(_)));
        for release in releases.into_values() {
            self.block(release.key, None);
        }
        for key in groups.into_values().flat_map(|group| group.pending).flat_map(|check| check.waiting) {
            self.block(key, None);
        }
    }

    /// New sites or probe marker from the controller: established
    /// connections keep their decision; verdicts are dropped.
    pub fn reconfigure(&mut self, probe_alpn: Vec<u8>, sites: ProtectedSites) {
        self.cfg.probe_alpn = probe_alpn;
        self.sites = sites;
        self.invalidate();
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// A packet from the Mac into the tunnel.
    pub fn outbound(&mut self, pkt: &[u8], now: Instant) -> Step {
        let Some(p) = parse_ip(pkt) else { return Step::Forward };
        match p.l4 {
            // QUIC hides which site a datagram is for: while any site is
            // protected, it is dropped so browsers fall back to TCP (§66.5).
            L4::Udp { dport: 443, .. } if !self.sites.is_empty() => Step::Consumed,
            L4::Tcp(t) => self.outbound_tcp(pkt, &p, t, now),
            L4::Udp { .. } | L4::Other => Step::Forward,
        }
    }

    /// The controller's answer to an [`Out::Check`].
    pub fn verdict(&mut self, group: GroupId, request_id: RequestId, verdict: Verdict, now: Instant) {
        self.expire_group(group, now);
        let Some(checks) = self.groups.get_mut(&group) else { return };
        let Some(index) = checks.pending.iter().position(|check| check.id == request_id) else { return };
        let check = checks.pending.swap_remove(index);
        match verdict {
            Verdict::Block => self.fail_check(group, check, now),
            Verdict::Unverified => {
                self.cache(group, &check.target, Cached::Unverified, now);
                for key in check.waiting {
                    self.release(key);
                }
            }
            Verdict::Allow { evidence_at_ms } => match self.evidence_age(evidence_at_ms) {
                Some(age) if age < EVIDENCE_AGE_MS => {
                    self.cache(group, &check.target, Cached::Allowed(evidence_at_ms), now);
                    for &key in &check.waiting {
                        self.queue_release(CheckedRelease {
                            key, group, target: check.target.clone(), evidence_at_ms, id: check.id,
                            started: check.started, retried: check.retried,
                        });
                    }
                }
                Some(_) => self.retry_check(group, check, now),
                None => self.block_waiting(group, &check),
            },
        }
    }

    fn cache(&mut self, group: GroupId, target: &CheckTarget, outcome: Cached, now: Instant) {
        let checks = self.groups.entry(group).or_default();
        if checks.recent.len() < MAX_CACHED_PER_GROUP || checks.recent.contains_key(target) {
            checks.recent.insert(target.clone(), (outcome, now));
        }
    }

    fn evidence_age(&self, at_ms: u64) -> Option<u64> {
        if at_ms == 0 {
            return None;
        }
        (self.clock)()?.checked_sub(at_ms)
    }

    fn expire_group(&mut self, group: GroupId, now: Instant) {
        while let Some(index) = self.groups.get(&group)
            .and_then(|checks| checks.expired(now, self.cfg.check_timeout))
        {
            let check = self.groups.get_mut(&group).expect("pending group").pending.swap_remove(index);
            self.fail_check(group, check, now);
        }
    }

    fn fail_check(&mut self, group: GroupId, failed: PendingCheck, now: Instant) {
        self.block_waiting(group, &failed);
        self.cache(group, &failed.target, Cached::Blocked, now);
    }

    fn block_waiting(&mut self, group: GroupId, check: &PendingCheck) {
        for &key in &check.waiting {
            self.block(key, Some((group, &check.target.host)));
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
            group, host: check.target.host.clone(), destination: check.target.destination, request_id: id,
        });
        checks.pending.push(check);
    }

    fn queue_release(&mut self, release: CheckedRelease) {
        let Some(id) = self.last_release.checked_add(1) else {
            self.block(release.key, Some((release.group, &release.target.host)));
            return;
        };
        if let Some(Flow { state: State::Holding(held), .. }) = self.flows.get_mut(&release.key) {
            held.checking = true;
            self.last_release = id;
            self.releases.insert(id, release);
            self.out.push(Out::SendChecked(id));
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
        let Some(Flow { state: State::Holding(held), .. }) = self.flows.get(&release.key) else { return };
        match self.evidence_age(release.evidence_at_ms) {
            Some(age) if age < EVIDENCE_AGE_MS => {
                if send(&held.packets) {
                    self.set_state(release.key, State::Pass);
                } else {
                    self.block(release.key, None);
                }
            }
            Some(_) => {
                let CheckedRelease { key, group, target, id, started, retried, .. } = release;
                self.retry_check(group, PendingCheck { id, target, started, retried, waiting: vec![key] }, now);
            }
            None => self.block(release.key, Some((release.group, &release.target.host))),
        }
    }

    /// Timers: checks that took too long, ClientHellos that never finished,
    /// idle connections.
    pub fn tick(&mut self, now: Instant) {
        let timed_out: Vec<_> = self.groups.iter()
            .filter_map(|(&id, checks)| checks.expired(now, self.cfg.check_timeout).is_some().then_some(id))
            .collect();
        for group in timed_out {
            self.expire_group(group, now);
        }
        let reuse = self.cfg.reuse;
        self.groups.retain(|_, checks| {
            checks.recent.retain(|_, (_, at)| now.duration_since(*at) < reuse);
            !checks.pending.is_empty() || !checks.recent.is_empty()
        });
        // No readable name in time: fall back to the address rules.
        let stale: Vec<FlowKey> = self.flows.iter()
            .filter(|(_, f)| matches!(&f.state, State::Holding(h) if !h.checking && now.duration_since(h.since) >= self.cfg.classify_timeout))
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            self.classified(key, now, None, false);
        }
        let idle = self.cfg.idle;
        self.flows.retain(|_, f| matches!(f.state, State::Holding(_)) || now.duration_since(f.last_seen) < idle);
    }

    fn outbound_tcp(&mut self, pkt: &[u8], p: &Packet, t: Tcp, now: Instant) -> Step {
        let key = FlowKey { proto: 6, src: p.src, sport: t.sport, dst: p.dst, dport: t.dport };
        let syn = t.flags & SYN != 0;
        let seg = ClientSeg { seq: t.seq, ack: t.ack, has_ack: t.flags & ACK != 0, syn, len: p.payload.len() as u32 };
        let data_start = if syn { t.seq.wrapping_add(1) } else { t.seq };
        if !self.flows.contains_key(&key) {
            // Nothing protected, or a connection older than the gate (no
            // start of stream to read): best effort, it passes.
            if !syn || self.sites.is_empty() {
                return Step::Forward;
            }
            if !self.insert(key, State::Fresh { next: data_start }, now) {
                self.reset(key, seg);
                return Step::Consumed;
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
                let mut held = Held {
                    packets: vec![pkt.to_vec()], bytes: pkt.len(), stream: Vec::new(), next, since: now,
                    checking: false, client_isn: next.wrapping_sub(1), last: seg,
                };
                if data_start == next {
                    held.stream.extend_from_slice(p.payload);
                    held.next = next.wrapping_add(seg.len);
                }
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
                h.last = seg;
                if h.checking {
                    Step::Consumed
                } else {
                    self.after_hold(key, now, false)
                }
            }
        }
    }

    /// Read the name a held connection shows; a protected one waits for a
    /// check, anything else passes.
    fn after_hold(&mut self, key: FlowKey, now: Instant, first: bool) -> Step {
        let (sniffed, full) = {
            let Some(Flow { state: State::Holding(h), .. }) = self.flows.get(&key) else { return Step::Consumed };
            (sniff(&h.stream), h.bytes >= self.cfg.max_held_bytes)
        };
        let name = match sniffed {
            Sniff::Incomplete if !full => return Step::Consumed,
            Sniff::Tls { alpn, .. } if !self.cfg.probe_alpn.is_empty() && alpn.contains(&self.cfg.probe_alpn) => {
                return self.pass_held(key, first);
            }
            Sniff::Tls { sni, .. } => sni,
            Sniff::Http(host) => host,
            Sniff::Incomplete | Sniff::Unknown => None,
        };
        self.classified(key, now, name, first)
    }

    fn classified(&mut self, key: FlowKey, now: Instant, name: Option<String>, first: bool) -> Step {
        let host = name.filter(|host| host.parse::<IpAddr>().is_err()).unwrap_or_default();
        if let Some(group) = self.sites.group_for_target(&host, key.dst) {
            self.wait_for_check(key, group, host, now);
            Step::Consumed
        } else {
            self.pass_held(key, first)
        }
    }

    fn pass_held(&mut self, key: FlowKey, first: bool) -> Step {
        if first {
            self.set_state(key, State::Pass);
            Step::Forward
        } else {
            self.release(key);
            Step::Consumed
        }
    }

    fn wait_for_check(&mut self, key: FlowKey, group: GroupId, host: String, now: Instant) {
        let target = CheckTarget { host, destination: SocketAddr::new(key.dst, key.dport) };
        self.expire_group(group, now);
        let reuse = self.cfg.reuse;
        let checks = self.groups.entry(group).or_default();
        if let Some(&(cached, at)) = checks.recent.get(&target) {
            if now.duration_since(at) < reuse {
                match cached {
                    Cached::Allowed(evidence_at_ms) if self.evidence_age(evidence_at_ms).is_some_and(|age| age < EVIDENCE_AGE_MS) => {
                        let id = RequestId::MIN;
                        self.queue_release(CheckedRelease { key, group, target, evidence_at_ms, id, started: now, retried: false });
                        return;
                    }
                    Cached::Unverified => {
                        self.release(key);
                        return;
                    }
                    Cached::Blocked => {
                        self.block(key, Some((group, &target.host)));
                        return;
                    }
                    Cached::Allowed(_) => {}
                }
            }
        }
        let checks = self.groups.entry(group).or_default();
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
            self.out.push(Out::Check { group, host: target.host.clone(), destination: target.destination, request_id: id });
            checks.pending.push(PendingCheck { id, target, started: now, retried: false, waiting: vec![key] });
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

    /// Refuse a held connection. `rule` counts it as a protection denial;
    /// None is an internal refusal (lost controller, full tables).
    fn block(&mut self, key: FlowKey, rule: Option<(GroupId, &str)>) {
        let Some(f) = self.flows.get_mut(&key) else { return };
        if let State::Holding(h) = std::mem::replace(&mut f.state, State::Blocked) {
            if let Some((group, host)) = rule {
                self.blocked_flows.record(key, h.client_isn, group, host);
            }
            self.reset(key, h.last);
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
        let mut idle: Vec<(Instant, FlowKey)> = self.flows.iter()
            .filter(|(_, f)| matches!(f.state, State::Pass | State::Blocked))
            .map(|(k, f)| (f.last_seen, *k))
            .collect();
        idle.sort_by_key(|(t, _)| *t);
        let n = (self.cfg.max_flows / 8).max(1);
        for (_, k) in idle.into_iter().take(n) {
            self.flows.remove(&k);
        }
    }
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
    Udp { dport: u16 },
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
            Some(Packet { src, dst, l4: L4::Udp { dport: be16(b, 2) }, payload: &b[8..] })
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
    Tls { sni: Option<String>, alpn: Vec<Vec<u8>> },
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
            Hello::Found { sni, alpn } => Sniff::Tls { sni, alpn },
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
    Found { sni: Option<String>, alpn: Vec<Vec<u8>> },
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
        return Hello::Found { sni: None, alpn: Vec::new() };
    }
    let end = p + 2 + be16(h, p) as usize;
    if end > h.len() {
        return bad;
    }
    p += 2;
    let (mut sni, mut alpn) = (None, Vec::new());
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
            _ => {}
        }
        p += len;
    }
    Hello::Found { sni, alpn }
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

#[cfg(test)]
mod tests;
