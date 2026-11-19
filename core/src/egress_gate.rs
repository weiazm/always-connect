//! Egress gate (DESIGN.md §66.5): the per-packet decision logic that sits in
//! the own connection's tunnel path when egress protection is on.
//!
//! openconnect runs in `--script-tun` mode and hands every IP packet to the
//! gate program; this module decides, per packet, whether it goes on into the
//! tunnel now, waits, or is dropped. Every new connection's first data packet
//! is held until the gate knows where the connection goes (TLS SNI, HTTP Host,
//! or the destination address). Connections to a protected group wait for that
//! group's egress check; everything else passes at once and is never looked at
//! again. A failed check drops the held packets and answers the Mac with a TCP
//! RST, so the application fails fast and no data reaches the site.
//!
//! The module does no I/O: the caller feeds packets and verdicts and carries
//! out the returned actions. It is pure Rust so it is tested on Linux.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// A protected group (DESIGN.md §66.3); the caller's identifier.
pub type GroupId = u32;

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
    /// A group verdict younger than this is reused (§66.6).
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
    /// A packet for the Mac side (a RST for a blocked connection).
    ToHost(Vec<u8>),
    /// Ask the background service to check this group's egress now.
    /// `host` is the name the triggering connection asked for, if known.
    Check { group: GroupId, host: Option<String> },
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
    /// Set once classified as protected: waiting for this group's verdict.
    group: Option<GroupId>,
    host: Option<String>,
    last: Option<ClientSeg>,
}

struct Flow {
    state: State,
    last_seen: Instant,
}

#[derive(Default)]
struct GroupCheck {
    verdict: Option<(bool, Instant)>,
    inflight: Option<Instant>,
}

pub struct Gate {
    cfg: GateConfig,
    classifier: Box<dyn Classifier + Send>,
    flows: HashMap<FlowKey, Flow>,
    groups: HashMap<GroupId, GroupCheck>,
    learned: HashMap<IpAddr, (GroupId, String, Instant)>,
    out: Vec<Out>,
}

impl Gate {
    pub fn new(cfg: GateConfig, classifier: Box<dyn Classifier + Send>) -> Self {
        Gate { cfg, classifier, flows: HashMap::new(), groups: HashMap::new(), learned: HashMap::new(), out: Vec::new() }
    }

    /// Actions produced since the last drain, in order.
    pub fn drain(&mut self) -> Vec<Out> {
        std::mem::take(&mut self.out)
    }

    /// Forget every verdict (reconnect, network change, wake: §66.6).
    pub fn invalidate(&mut self) {
        for g in self.groups.values_mut() {
            g.verdict = None;
        }
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
                if let Some(group) = self.classifier.group_for_name(&name) {
                    for ip in addrs {
                        self.learn(ip, group, &name, now);
                    }
                }
            }
        }
    }

    /// The background service's answer to an [`Out::Check`].
    pub fn verdict(&mut self, group: GroupId, ok: bool, now: Instant) {
        let g = self.groups.entry(group).or_default();
        g.verdict = Some((ok, now));
        g.inflight = None;
        let waiting: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, f)| matches!(&f.state, State::Holding(h) if h.group == Some(group)))
            .map(|(k, _)| *k)
            .collect();
        for k in waiting {
            if ok {
                self.release(k);
            } else {
                self.block(k);
            }
        }
    }

    /// Timers: checks that took too long, ClientHellos that never finished,
    /// idle connections.
    pub fn tick(&mut self, now: Instant) {
        let timed_out: Vec<GroupId> = self
            .groups
            .iter()
            .filter(|(_, g)| g.inflight.is_some_and(|t| now.duration_since(t) >= self.cfg.check_timeout))
            .map(|(id, _)| *id)
            .collect();
        for id in timed_out {
            self.verdict(id, false, now);
        }
        let stale: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, f)| matches!(&f.state, State::Holding(h) if h.group.is_none() && now.duration_since(h.since) >= self.cfg.classify_timeout))
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
                let held = Held { packets: vec![pkt.to_vec()], bytes: pkt.len(), stream: Vec::new(), next: 0, since: now, group: None, host: None, last: None };
                self.insert(key, State::Holding(Box::new(held)), now);
                self.wait_for_group(key, group, host, now);
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
            if syn && p.payload.is_empty() {
                self.insert(key, State::Fresh { next: data_start }, now);
                return Step::Forward;
            }
            if p.payload.is_empty() {
                return Step::Forward;
            }
            if syn {
                // TCP Fast Open: the ClientHello rides on the SYN.
                self.insert(key, State::Fresh { next: data_start }, now);
            } else {
                // Mid-stream (forgotten or older than the gate): no start of
                // stream to parse, so decide by address.
                return match self.ip_group(p.dst) {
                    None => {
                        self.insert(key, State::Pass, now);
                        Step::Forward
                    }
                    Some((group, host)) => {
                        let held = Held { packets: vec![pkt.to_vec()], bytes: pkt.len(), stream: Vec::new(), next: t.seq.wrapping_add(seg.len), since: now, group: None, host: None, last: Some(seg) };
                        self.insert(key, State::Holding(Box::new(held)), now);
                        self.wait_for_group(key, group, host, now);
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
                    if let Some(rst) = build_rst(&key, seg) {
                        self.out.push(Out::ToHost(rst));
                    }
                }
                Step::Consumed
            }
            State::Fresh { next } => {
                if p.payload.is_empty() {
                    return Step::Forward;
                }
                let next = *next;
                let mut held = Held { packets: Vec::new(), bytes: 0, stream: Vec::new(), next, since: now, group: None, host: None, last: Some(seg) };
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
                let waiting = h.group.is_some();
                if waiting {
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
                        Some(name) => match self.classifier.group_for_name(&name) {
                            Some(g) => Target::Group(g, Some(name)),
                            None if ech => Target::Address,
                            None => Target::Pass,
                        },
                        None => Target::Address,
                    }
                }
            }
            Sniff::Http(Some(name)) => match self.classifier.group_for_name(&name) {
                Some(g) => Target::Group(g, Some(name)),
                None => Target::Pass,
            },
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
            Target::Group(g, host) => {
                self.wait_for_group(key, g, host, now);
                Step::Consumed
            }
        }
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
                self.wait_for_group(key, g, host, now);
                Step::Consumed
            }
        }
    }

    fn wait_for_group(&mut self, key: FlowKey, group: GroupId, host: Option<String>, now: Instant) {
        if let Some(Flow { state: State::Holding(h), .. }) = self.flows.get_mut(&key) {
            h.group = Some(group);
            h.host = host.clone();
        }
        let reuse = self.cfg.reuse;
        let g = self.groups.entry(group).or_default();
        if let Some((ok, at)) = g.verdict {
            if now.duration_since(at) < reuse {
                if ok {
                    self.release(key);
                } else {
                    self.block(key);
                }
                return;
            }
        }
        if g.inflight.is_none() {
            g.inflight = Some(now);
            self.out.push(Out::Check { group, host });
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

    fn block(&mut self, key: FlowKey) {
        let Some(f) = self.flows.get_mut(&key) else { return };
        if let State::Holding(h) = std::mem::replace(&mut f.state, State::Blocked) {
            if let (6, Some(last)) = (key.proto, h.last) {
                if let Some(rst) = build_rst(&key, last) {
                    self.out.push(Out::ToHost(rst));
                }
            }
        }
    }

    fn set_state(&mut self, key: FlowKey, s: State) {
        if let Some(f) = self.flows.get_mut(&key) {
            f.state = s;
        }
    }

    fn insert(&mut self, key: FlowKey, state: State, now: Instant) {
        if self.flows.len() >= self.cfg.max_flows {
            self.evict();
        }
        self.flows.insert(key, Flow { state, last_seen: now });
    }

    /// Drop the oldest eighth of passed/blocked connections. Holding ones are
    /// never evicted: their packets would be lost or, worse, passed unchecked.
    fn evict(&mut self) {
        let mut idle: Vec<(Instant, FlowKey)> = self
            .flows
            .iter()
            .filter(|(_, f)| !matches!(f.state, State::Holding(_)))
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
    Group(GroupId, Option<String>),
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
fn parse_dns_answer(m: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    if m.len() < 12 || m[2] & 0x80 == 0 {
        return None;
    }
    let (qd, an) = (be16(m, 4), be16(m, 6) as usize);
    if qd != 1 {
        return None;
    }
    let (name, mut p) = dns_name(m, 12)?;
    p += 4;
    let mut addrs = Vec::new();
    for _ in 0..an.min(64) {
        let (_, q) = dns_name(m, p)?;
        p = q;
        if p + 10 > m.len() {
            return None;
        }
        let (ty, rdlen) = (be16(m, p), be16(m, p + 8) as usize);
        p += 10;
        if p + rdlen > m.len() {
            return None;
        }
        match (ty, rdlen) {
            (1, 4) => addrs.push(IpAddr::V4(Ipv4Addr::new(m[p], m[p + 1], m[p + 2], m[p + 3]))),
            (28, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&m[p..p + 16]);
                addrs.push(IpAddr::V6(Ipv6Addr::from(a)));
            }
            _ => {}
        }
        p += rdlen;
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
