use super::*;

mod controller_path;

// Documentation addresses only (RFC 5737 / RFC 3849) and example names.
const MAC: [u8; 4] = [10, 0, 0, 2];
const SITE: [u8; 4] = [198, 51, 100, 10];
const RANGE_IP: [u8; 4] = [203, 0, 113, 7];
const OTHER: [u8; 4] = [192, 0, 2, 50];

struct Rules;
impl Classifier for Rules {
    fn group_for_name(&self, name: &str) -> Option<GroupId> {
        if name == "protected.example" || name.ends_with(".protected.example") {
            Some(1)
        } else if name == "second.example" {
            Some(2)
        } else {
            None
        }
    }
    fn group_for_ip(&self, ip: IpAddr) -> Option<GroupId> {
        match ip {
            IpAddr::V4(v4) if v4.octets()[..3] == [203, 0, 113] => Some(1),
            _ => None,
        }
    }
}

fn gate() -> Gate {
    let cfg = GateConfig { probe_alpn: b"ac-probe-test".to_vec(), ..GateConfig::default() };
    Gate::new(cfg, Box::new(Rules))
}

fn tcp4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 5 << 4;
    t[13] = flags;
    t.extend_from_slice(payload);
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + t.len()) as u16).to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);
    ip.extend_from_slice(&t);
    ip
}

fn tcp6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 5 << 4;
    t[13] = flags;
    t.extend_from_slice(payload);
    let mut ip = vec![0u8; 40];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(t.len() as u16).to_be_bytes());
    ip[6] = 6;
    ip[7] = 64;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    ip.extend_from_slice(&t);
    ip
}

fn udp4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = vec![0u8; 8];
    u[0..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(payload);
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + u.len()) as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);
    ip.extend_from_slice(&u);
    ip
}

/// A TLS 1.3-shaped ClientHello. `pad` adds a padding extension before the
/// SNI so large hellos put the name in a later segment.
fn hello(sni: Option<&str>, alpn: &[&[u8]], ech: bool, pad: usize) -> Vec<u8> {
    let mut ext = Vec::new();
    let mut push = |ty: u16, body: &[u8]| {
        ext.extend_from_slice(&ty.to_be_bytes());
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(body);
    };
    if pad > 0 {
        push(21, &vec![0u8; pad]);
    }
    if ech {
        push(0xfe0d, &[0, 1, 2, 3]);
    }
    if let Some(n) = sni {
        let mut b = Vec::new();
        b.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
        b.push(0);
        b.extend_from_slice(&(n.len() as u16).to_be_bytes());
        b.extend_from_slice(n.as_bytes());
        push(0, &b);
    }
    if !alpn.is_empty() {
        let mut l = Vec::new();
        for a in alpn {
            l.push(a.len() as u8);
            l.extend_from_slice(a);
        }
        let mut b = (l.len() as u16).to_be_bytes().to_vec();
        b.extend_from_slice(&l);
        push(16, &b);
    }
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7u8; 32]);
    body.push(32);
    body.extend_from_slice(&[9u8; 32]);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn dns_answer(name: &str, addrs: &[[u8; 4]]) -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1];
    m.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    for l in name.split('.') {
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    for a in addrs {
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        m.extend_from_slice(a);
    }
    m
}

const PA: u8 = 0x18; // PSH|ACK

/// SYN then the first data packet; returns the step of the data packet.
fn connect_and_send(g: &mut Gate, sport: u16, dst: [u8; 4], payload: &[u8], now: Instant) -> (Step, Vec<u8>) {
    connect_to_port(g, sport, dst, 443, payload, now)
}

fn connect_to_port(g: &mut Gate, sport: u16, dst: [u8; 4], dport: u16, payload: &[u8], now: Instant) -> (Step, Vec<u8>) {
    assert_eq!(g.outbound(&tcp4(MAC, sport, dst, dport, 1000, 0, SYN, &[]), now), Step::Forward);
    let data = tcp4(MAC, sport, dst, dport, 1001, 5001, PA, payload);
    (g.outbound(&data, now), data)
}

fn checks(out: &[Out]) -> Vec<(GroupId, Option<String>)> {
    out.iter().filter_map(|o| if let Out::Check { group, host, .. } = o { Some((*group, host.clone())) } else { None }).collect()
}

fn request_for(out: &[Out], group: GroupId) -> RequestId {
    let ids: Vec<_> = out.iter().filter_map(|o| match o {
        Out::Check { group: id, request_id, .. } if *id == group => Some(*request_id),
        _ => None,
    }).collect();
    let [id] = ids.as_slice() else { panic!("expected one check for group {group}, got {out:?}") };
    *id
}

fn verify_checksums(p: &[u8]) {
    let q = parse_ip(p).expect("parses");
    match q.src {
        IpAddr::V4(_) => {
            assert_eq!(fold(sum16(&p[..20], 0)), 0, "IPv4 header checksum");
            let mut pseudo = p[12..20].to_vec();
            pseudo.extend_from_slice(&[0, 6, 0, (p.len() - 20) as u8]);
            assert_eq!(fold(sum16(&p[20..], sum16(&pseudo, 0))), 0, "TCP checksum");
        }
        IpAddr::V6(_) => {
            let mut pseudo = p[8..40].to_vec();
            pseudo.extend_from_slice(&[0, 0, 0, (p.len() - 40) as u8, 0, 0, 0, 6]);
            assert_eq!(fold(sum16(&p[40..], sum16(&pseudo, 0))), 0, "TCP checksum");
        }
    }
}

#[test]
fn unprotected_tls_passes_without_holding() {
    let mut g = gate();
    let now = Instant::now();
    let (step, _) = connect_and_send(&mut g, 40000, OTHER, &hello(Some("www.example.org"), &[b"h2"], false, 0), now);
    assert_eq!(step, Step::Forward);
    assert!(g.drain().is_empty());
    // Later packets take the fast path.
    assert_eq!(g.outbound(&tcp4(MAC, 40000, OTHER, 443, 1300, 5001, PA, b"more"), now), Step::Forward);
}

#[test]
fn protected_sni_is_held_until_the_check_passes() {
    let mut g = gate();
    let now = Instant::now();
    let (step, data) = connect_and_send(&mut g, 40001, SITE, &hello(Some("api.protected.example"), &[b"h2"], false, 0), now);
    assert_eq!(step, Step::Consumed);
    let out = g.drain();
    assert_eq!(checks(&out), vec![(1, Some("api.protected.example".into()))]);
    let [Out::Check { destination, .. }] = out.as_slice() else { panic!("{out:?}") };
    assert_eq!(*destination, SocketAddr::from((SITE, 443)));
    // More data while waiting stays held, in order.
    let more = tcp4(MAC, 40001, SITE, 443, 1001 + (data.len() as u32 - 40), 5001, PA, b"x");
    assert_eq!(g.outbound(&more, now), Step::Consumed);
    g.verdict(1, request_for(&out, 1), Verdict::AllowDirect, now);
    assert_eq!(g.drain(), vec![Out::ToTunnel(data), Out::ToTunnel(more)]);
    assert_eq!(g.outbound(&tcp4(MAC, 40001, SITE, 443, 2000, 5001, PA, b"y"), now), Step::Forward);
}

#[test]
fn failed_check_drops_and_resets_the_application() {
    let mut g = gate();
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    let (step, _) = connect_and_send(&mut g, 40002, SITE, &payload, now);
    assert_eq!(step, Step::Consumed);
    let request = request_for(&g.drain(), 1);
    g.verdict(1, request, Verdict::Block, now);
    let out = g.drain();
    assert_eq!(out.len(), 1);
    let Out::ToHost(rst) = &out[0] else { panic!("expected a RST, got {out:?}") };
    verify_checksums(rst);
    let p = parse_ip(rst).unwrap();
    assert_eq!((p.src, p.dst), (IpAddr::V4(SITE.into()), IpAddr::V4(MAC.into())));
    let L4::Tcp(t) = p.l4 else { panic!() };
    assert_eq!((t.sport, t.dport), (443, 40002));
    assert_eq!(t.flags, RST | ACK);
    assert_eq!(t.seq, 5001, "the client's acknowledged number");
    assert_eq!(t.ack, 1001 + payload.len() as u32);
    // Nothing of this connection reaches the tunnel afterwards.
    assert_eq!(g.outbound(&tcp4(MAC, 40002, SITE, 443, 1001, 5001, PA, &payload), now), Step::Consumed);
    assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));
}

#[test]
fn concurrent_connections_share_one_check() {
    let mut g = gate();
    let now = Instant::now();
    let (a, da) = connect_and_send(&mut g, 41000, SITE, &hello(Some("a.protected.example"), &[], false, 0), now);
    let (b, db) = connect_and_send(&mut g, 41001, SITE, &hello(Some("A.Protected.Example."), &[], false, 0), now);
    assert_eq!((a, b), (Step::Consumed, Step::Consumed));
    let request = request_for(&g.drain(), 1);
    g.verdict(1, request, Verdict::AllowDirect, now);
    let out = g.drain();
    assert_eq!(out.len(), 2);
    assert!(out.contains(&Out::ToTunnel(da)) && out.contains(&Out::ToTunnel(db)));
}

#[test]
fn a_verdict_younger_than_a_second_is_reused() {
    let mut g = gate();
    let t0 = Instant::now();
    connect_and_send(&mut g, 42000, SITE, &hello(Some("protected.example"), &[], false, 0), t0);
    let request = request_for(&g.drain(), 1);
    g.verdict(1, request, Verdict::AllowDirect, t0);
    g.drain();
    let (step, data) = connect_and_send(&mut g, 42001, SITE, &hello(Some("protected.example"), &[], false, 0), t0 + Duration::from_millis(500));
    assert_eq!(step, Step::Consumed);
    assert_eq!(g.drain(), vec![Out::ToTunnel(data)], "released at once, no new check");
    let (step, _) = connect_and_send(&mut g, 42002, SITE, &hello(Some("protected.example"), &[], false, 0), t0 + Duration::from_millis(1500));
    assert_eq!(step, Step::Consumed);
    assert_eq!(checks(&g.drain()).len(), 1, "stale verdict: check again");
}

#[test]
fn a_pass_only_releases_connections_to_the_same_host_ip_and_port() {
    let mut g = gate();
    let now = Instant::now();
    let protected = hello(Some("protected.example"), &[], false, 0);
    let other_name = hello(Some("other.protected.example"), &[], false, 0);
    let (_, first) = connect_and_send(&mut g, 42010, SITE, &protected, now);
    let id_first = request_for(&g.drain(), 1);
    let (_, other_ip) = connect_and_send(&mut g, 42011, OTHER, &protected, now);
    let id_ip = request_for(&g.drain(), 1);
    let (_, other_port) = connect_to_port(&mut g, 42012, SITE, 8443, &protected, now);
    let id_port = request_for(&g.drain(), 1);
    let (_, other_host) = connect_and_send(&mut g, 42013, SITE, &other_name, now);
    let id_host = request_for(&g.drain(), 1);
    assert!(id_first < id_ip && id_ip < id_port && id_port < id_host);

    g.verdict(1, id_first, Verdict::AllowDirect, now);
    assert_eq!(g.drain(), vec![Out::ToTunnel(first)]);
    for (id, packet) in [(id_port, other_port), (id_host, other_host), (id_ip, other_ip)] {
        g.verdict(1, id, Verdict::AllowDirect, now);
        assert_eq!(g.drain(), vec![Out::ToTunnel(packet)]);
    }
}

#[test]
fn a_cached_pass_does_not_admit_a_different_destination() {
    let mut g = gate();
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    connect_and_send(&mut g, 42020, SITE, &payload, now);
    let first = request_for(&g.drain(), 1);
    g.verdict(1, first, Verdict::AllowDirect, now);
    g.drain();

    connect_and_send(&mut g, 42021, OTHER, &payload, now);
    let out = g.drain();
    let [Out::Check { request_id, destination, .. }] = out.as_slice() else { panic!("{out:?}") };
    assert_ne!(*request_id, first);
    assert_eq!(*destination, SocketAddr::from((OTHER, 443)));
}

#[test]
fn failure_removes_the_groups_cached_passes_but_keeps_other_destinations_pending() {
    let mut g = gate();
    let t0 = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    let (_, established) = connect_and_send(&mut g, 42030, SITE, &payload, t0);
    let first = request_for(&g.drain(), 1);
    g.verdict(1, first, Verdict::AllowDirect, t0);
    assert_eq!(g.drain(), vec![Out::ToTunnel(established)]);
    connect_and_send(&mut g, 42031, OTHER, &payload, t0);
    let failed = request_for(&g.drain(), 1);
    let (_, independent) = connect_and_send(&mut g, 42032, RANGE_IP, &payload, t0);
    let other = request_for(&g.drain(), 1);

    g.verdict(1, failed, Verdict::Block, t0);
    assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));
    assert!(g.groups[&1].recent.values().all(|(ok, _)| !ok));
    g.verdict(1, other, Verdict::AllowDirect, t0);
    assert_eq!(g.drain(), vec![Out::ToTunnel(independent)]);

    connect_and_send(&mut g, 42033, OTHER, &payload, t0);
    assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]), "B's success leaves A's denial in effect");
    connect_and_send(&mut g, 42034, SITE, &payload, t0);
    let current = request_for(&g.drain(), 1);
    g.verdict(1, failed, Verdict::AllowDirect, t0);
    assert!(g.drain().is_empty());

    let established = tcp4(MAC, 42030, SITE, 443, 2000, 5001, PA, b"next");
    assert_eq!(g.outbound(&established, t0), Step::Forward);

    let retry_at = t0 + g.cfg.reuse;
    let (_, retry) = connect_and_send(&mut g, 42035, OTHER, &payload, retry_at);
    let output = g.drain();
    let [Out::Check { request_id, destination, .. }] = output.as_slice() else { panic!("{output:?}") };
    assert!(*request_id > current);
    assert_eq!(*destination, SocketAddr::from((OTHER, 443)));
    g.verdict(1, *request_id, Verdict::AllowDirect, retry_at);
    assert_eq!(g.drain(), vec![Out::ToTunnel(retry)]);
}

#[test]
fn a_recent_failure_resets_new_connections_at_once() {
    let mut g = gate();
    let t0 = Instant::now();
    connect_and_send(&mut g, 42100, SITE, &hello(Some("protected.example"), &[], false, 0), t0);
    let request = request_for(&g.drain(), 1);
    g.verdict(1, request, Verdict::Block, t0);
    g.drain();
    connect_and_send(&mut g, 42101, SITE, &hello(Some("protected.example"), &[], false, 0), t0 + Duration::from_millis(200));
    assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));
}

#[test]
fn earlier_dependent_results_cannot_release_packets_across_a_failure() {
    for local_deadline in [false, true] {
        let mut g = gate();
        let t0 = Instant::now();
        let payload = hello(Some("protected.example"), &[], false, 0);
        connect_and_send(&mut g, 42110, SITE, &payload, t0);
        let failed = request_for(&g.drain(), 1);

        let later = t0 + Duration::from_secs(1);
        let dependent = hello(Some("follow.protected.example"), &[], false, 0);
        connect_and_send(&mut g, 42111, OTHER, &dependent, later);
        let old_dependent = request_for(&g.drain(), 1);
        let (_, direct_packet) = connect_and_send(&mut g, 42112, OTHER, &payload, later);
        let direct = request_for(&g.drain(), 1);

        let now = if local_deadline {
            let deadline = t0 + g.cfg.check_timeout;
            // The dependent verdict was already on the wire at the deadline.
            g.verdict(1, old_dependent, Verdict::AllowDependent, deadline);
            assert!(matches!(
                g.drain().as_slice(),
                [Out::TimedOut { request_id, .. }, Out::ToHost(_), Out::ToHost(_)] if *request_id == failed
            ));
            deadline
        } else {
            g.verdict(1, failed, Verdict::Block, later);
            assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));
            g.verdict(1, old_dependent, Verdict::AllowDependent, later);
            assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));
            later
        };

        g.verdict(1, direct, Verdict::AllowDirect, now);
        assert_eq!(g.drain(), vec![Out::ToTunnel(direct_packet)]);
        let (_, retry) = connect_and_send(&mut g, 42113, OTHER, &dependent, now);
        let current = request_for(&g.drain(), 1);
        g.verdict(1, current, Verdict::AllowDependent, now);
        assert_eq!(g.drain(), vec![Out::ToTunnel(retry)]);
    }
}

#[test]
fn controller_group_block_discards_passes_and_pending_checks_even_after_a_deadline() {
    let mut g = gate();
    let t0 = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    connect_and_send(&mut g, 42120, SITE, &payload, t0);
    let expired = request_for(&g.drain(), 1);
    let later = t0 + Duration::from_secs(1);
    connect_and_send(&mut g, 42121, OTHER, &payload, later);
    let pending = request_for(&g.drain(), 1);
    let (_, outside) = connect_and_send(&mut g, 42122, SITE, &hello(Some("second.example"), &[], false, 0), later);
    let outside_id = request_for(&g.drain(), 2);

    let deadline = t0 + g.cfg.check_timeout;
    g.tick(deadline);
    assert!(matches!(
        g.drain().as_slice(),
        [Out::TimedOut { request_id, .. }, Out::ToHost(_)] if *request_id == expired
    ));
    let (_, already_released) = connect_to_port(&mut g, 42123, OTHER, 8443, &payload, deadline);
    let released_id = request_for(&g.drain(), 1);
    g.verdict(1, released_id, Verdict::AllowDirect, deadline);
    assert_eq!(g.drain(), vec![Out::ToTunnel(already_released)]);

    g.block_group(1);
    assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));
    g.verdict(1, pending, Verdict::AllowDirect, deadline);
    g.verdict(1, expired, Verdict::AllowDirect, deadline);
    assert!(g.drain().is_empty());
    g.verdict(2, outside_id, Verdict::AllowDirect, deadline);
    assert_eq!(g.drain(), vec![Out::ToTunnel(outside)]);

    let established = tcp4(MAC, 42123, OTHER, 8443, 2000, 5001, PA, b"next");
    assert_eq!(g.outbound(&established, deadline), Step::Forward);
    connect_to_port(&mut g, 42124, OTHER, 8443, &payload, deadline);
    let current = request_for(&g.drain(), 1);
    assert!(current > released_id);
    g.verdict(1, current, Verdict::Block, deadline);
    assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));
}

#[test]
fn hello_split_across_segments_waits_for_the_name() {
    let mut g = gate();
    let now = Instant::now();
    let rec = hello(Some("protected.example"), &[], false, 2500);
    let (first, second) = rec.split_at(1200);
    let (step, d1) = connect_and_send(&mut g, 43000, SITE, first, now);
    assert_eq!(step, Step::Consumed);
    assert!(g.drain().is_empty(), "no decision before the name arrives");
    // A retransmission of the first part is not held twice.
    assert_eq!(g.outbound(&d1, now), Step::Consumed);
    let d2 = tcp4(MAC, 43000, SITE, 443, 1001 + 1200, 5001, PA, second);
    assert_eq!(g.outbound(&d2, now), Step::Consumed);
    let out = g.drain();
    assert_eq!(checks(&out), vec![(1, Some("protected.example".into()))]);
    g.verdict(1, request_for(&out, 1), Verdict::AllowDirect, now);
    assert_eq!(g.drain(), vec![Out::ToTunnel(d1), Out::ToTunnel(d2)]);
}

#[test]
fn split_unprotected_hello_is_released_in_order() {
    let mut g = gate();
    let now = Instant::now();
    let rec = hello(Some("www.example.org"), &[], false, 2500);
    let (first, second) = rec.split_at(1200);
    let (_, d1) = connect_and_send(&mut g, 43100, OTHER, first, now);
    let d2 = tcp4(MAC, 43100, OTHER, 443, 1001 + 1200, 5001, PA, second);
    assert_eq!(g.outbound(&d2, now), Step::Consumed);
    assert_eq!(g.drain(), vec![Out::ToTunnel(d1), Out::ToTunnel(d2)]);
}

#[test]
fn plain_http_is_decided_by_host() {
    let mut g = gate();
    let now = Instant::now();
    let (step, _) = connect_and_send(&mut g, 44000, OTHER, b"GET / HTTP/1.1\r\nHost: Protected.Example:8080\r\n\r\n", now);
    assert_eq!(step, Step::Consumed);
    assert_eq!(checks(&g.drain()), vec![(1, Some("protected.example".into()))]);
    let (step, _) = connect_and_send(&mut g, 44001, OTHER, b"GET / HTTP/1.1\r\nHost: www.example.org\r\n\r\n", now);
    assert_eq!(step, Step::Forward);
}

#[test]
fn hard_coded_addresses_are_decided_by_name_then_by_range() {
    let mut g = gate();
    let now = Instant::now();
    // Another site on a shared address inside a protected range: its own name decides.
    let (step, _) = connect_and_send(&mut g, 45000, RANGE_IP, &hello(Some("www.example.org"), &[], false, 0), now);
    assert_eq!(step, Step::Forward);
    // A protected name on an address nobody resolved: still caught by name.
    let (step, _) = connect_and_send(&mut g, 45001, OTHER, &hello(Some("protected.example"), &[], false, 0), now);
    assert_eq!(step, Step::Consumed);
    g.drain();
    // No name at all: the protected range decides.
    let (step, _) = connect_and_send(&mut g, 45002, RANGE_IP, b"\x00\x01private-protocol", now);
    assert_eq!(step, Step::Consumed);
    assert_eq!(checks(&g.drain()), vec![(1, None)], "the address gets its own check");
    let (step, _) = connect_and_send(&mut g, 45003, OTHER, b"\x00\x01private-protocol", now);
    assert_eq!(step, Step::Forward);
}

#[test]
fn tunnel_dns_answers_teach_protected_addresses() {
    let mut g = gate();
    let now = Instant::now();
    g.inbound(&udp4([10, 0, 0, 53], 53, MAC, 5353, &dns_answer("b.protected.example", &[SITE])), now);
    g.inbound(&udp4([10, 0, 0, 53], 53, MAC, 5354, &dns_answer("www.example.org", &[OTHER])), now);
    let (step, _) = connect_and_send(&mut g, 46000, SITE, b"\x00\x01private-protocol", now);
    assert_eq!(step, Step::Consumed);
    assert_eq!(checks(&g.drain()), vec![(1, Some("b.protected.example".into()))]);
    let (step, _) = connect_and_send(&mut g, 46001, OTHER, b"\x00\x01private-protocol", now);
    assert_eq!(step, Step::Forward);
}

#[test]
fn ech_falls_back_to_the_address() {
    let mut g = gate();
    let now = Instant::now();
    g.inbound(&udp4([10, 0, 0, 53], 53, MAC, 5353, &dns_answer("protected.example", &[SITE])), now);
    let (step, _) = connect_and_send(&mut g, 47000, SITE, &hello(Some("public.cdn.example"), &[], true, 0), now);
    assert_eq!(step, Step::Consumed);
    assert_eq!(checks(&g.drain()), vec![(1, Some("protected.example".into()))]);
    let (step, _) = connect_and_send(&mut g, 47001, OTHER, &hello(Some("public.cdn.example"), &[], true, 0), now);
    assert_eq!(step, Step::Forward);
}

#[test]
fn own_probes_pass_by_their_alpn_marker() {
    let mut g = gate();
    let now = Instant::now();
    let (step, _) = connect_and_send(&mut g, 48000, SITE, &hello(Some("protected.example"), &[b"http/1.1", b"ac-probe-test"], false, 0), now);
    assert_eq!(step, Step::Forward);
    assert!(g.drain().is_empty());
    // Without the marker the same hello is held.
    let (step, _) = connect_and_send(&mut g, 48001, SITE, &hello(Some("protected.example"), &[b"http/1.1"], false, 0), now);
    assert_eq!(step, Step::Consumed);
}

#[test]
fn quic_is_dropped_and_other_udp_passes() {
    let mut g = gate();
    let now = Instant::now();
    assert_eq!(g.outbound(&udp4(MAC, 50000, OTHER, 443, b"quic"), now), Step::Consumed);
    assert_eq!(g.outbound(&udp4(MAC, 50001, [10, 0, 0, 53], 53, b"dns"), now), Step::Forward);
    // UDP to a protected range waits for the group like TCP.
    assert_eq!(g.outbound(&udp4(MAC, 50002, RANGE_IP, 3478, b"x"), now), Step::Consumed);
    let out = g.drain();
    let [Out::Check { destination, .. }] = out.as_slice() else { panic!("{out:?}") };
    assert_eq!(*destination, SocketAddr::from((RANGE_IP, 3478)));
    g.verdict(1, request_for(&out, 1), Verdict::AllowDirect, now);
    assert_eq!(g.drain().len(), 1);
    assert_eq!(g.outbound(&udp4(MAC, 50002, RANGE_IP, 3478, b"y"), now), Step::Forward);
}

#[test]
fn a_check_that_never_answers_blocks() {
    let mut g = gate();
    let t0 = Instant::now();
    connect_and_send(&mut g, 51000, SITE, &hello(Some("protected.example"), &[], false, 0), t0);
    let request = request_for(&g.drain(), 1);
    g.tick(t0 + Duration::from_millis(2900));
    assert!(g.drain().is_empty());
    g.tick(t0 + Duration::from_secs(3));
    assert!(matches!(
        g.drain().as_slice(),
        [Out::TimedOut { group: 1, request_id, .. }, Out::ToHost(_)] if *request_id == request
    ));
}

#[test]
fn a_verdict_at_its_deadline_cannot_release_packets_even_before_tick() {
    let mut g = gate();
    let t0 = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    connect_and_send(&mut g, 51010, SITE, &payload, t0);
    let first = request_for(&g.drain(), 1);
    let deadline = t0 + g.cfg.check_timeout;
    g.verdict(1, first, Verdict::AllowDirect, deadline);

    let retry_at = deadline + g.cfg.reuse;
    let (_, packet) = connect_and_send(&mut g, 51011, SITE, &payload, retry_at);
    let out = g.drain();
    let [Out::TimedOut { request_id: expired, .. }, Out::ToHost(_), Out::Check { request_id: retry, .. }] =
        out.as_slice() else { panic!("{out:?}") };
    assert_eq!(*expired, first);
    g.verdict(1, first, Verdict::AllowDirect, retry_at);
    assert!(g.drain().is_empty());
    g.verdict(1, *retry, Verdict::AllowDirect, retry_at);
    assert_eq!(g.drain(), vec![Out::ToTunnel(packet)]);
}

#[test]
fn an_unfinished_hello_is_decided_by_address_after_the_timeout() {
    let mut g = gate();
    let t0 = Instant::now();
    let rec = hello(Some("protected.example"), &[], false, 2500);
    connect_and_send(&mut g, 52000, RANGE_IP, &rec[..1000], t0);
    connect_and_send(&mut g, 52001, OTHER, &rec[..1000], t0);
    assert!(g.drain().is_empty());
    g.tick(t0 + Duration::from_secs(3));
    let out = g.drain();
    assert_eq!(checks(&out), vec![(1, None)], "the protected range is checked");
    assert_eq!(out.iter().filter(|o| matches!(o, Out::ToTunnel(_))).count(), 1, "the other one passes");
}

#[test]
fn mid_stream_packets_are_decided_by_address() {
    let mut g = gate();
    let now = Instant::now();
    assert_eq!(g.outbound(&tcp4(MAC, 53000, RANGE_IP, 443, 9000, 1, PA, b"data"), now), Step::Consumed);
    assert_eq!(checks(&g.drain()), vec![(1, None)]);
    assert_eq!(g.outbound(&tcp4(MAC, 53001, OTHER, 443, 9000, 1, PA, b"data"), now), Step::Forward);
    assert_eq!(g.outbound(&tcp4(MAC, 53002, OTHER, 443, 9000, 1, ACK, &[]), now), Step::Forward);
}

#[test]
fn fast_open_data_on_the_syn_is_held() {
    let mut g = gate();
    let now = Instant::now();
    let rec = hello(Some("protected.example"), &[], false, 0);
    let syn = tcp4(MAC, 54000, SITE, 443, 7000, 0, SYN, &rec);
    assert_eq!(g.outbound(&syn, now), Step::Consumed);
    let request = request_for(&g.drain(), 1);
    g.verdict(1, request, Verdict::Block, now);
    let out = g.drain();
    let [Out::ToHost(rst)] = out.as_slice() else { panic!("{out:?}") };
    verify_checksums(rst);
    let L4::Tcp(t) = parse_ip(rst).unwrap().l4 else { panic!() };
    assert_eq!((t.seq, t.ack), (0, 7001 + rec.len() as u32));
}

#[test]
fn ipv6_connections_are_gated_too() {
    let mut g = gate();
    let now = Instant::now();
    let (mac, site): (Ipv6Addr, Ipv6Addr) = ("2001:db8::2".parse().unwrap(), "2001:db8:1::10".parse().unwrap());
    assert_eq!(g.outbound(&tcp6(mac, 55000, site, 443, 1, 0, SYN, &[]), now), Step::Forward);
    let data = tcp6(mac, 55000, site, 443, 2, 77, PA, &hello(Some("protected.example"), &[], false, 0));
    assert_eq!(g.outbound(&data, now), Step::Consumed);
    let out = g.drain();
    let [Out::Check { destination, .. }] = out.as_slice() else { panic!("{out:?}") };
    assert_eq!(*destination, SocketAddr::new(IpAddr::V6(site), 443));
    g.verdict(1, request_for(&out, 1), Verdict::Block, now);
    let out = g.drain();
    let [Out::ToHost(rst)] = out.as_slice() else { panic!("{out:?}") };
    verify_checksums(rst);
    let p = parse_ip(rst).unwrap();
    assert_eq!((p.src, p.dst), (IpAddr::V6(site), IpAddr::V6(mac)));
}

#[test]
fn groups_are_independent() {
    let mut g = gate();
    let now = Instant::now();
    connect_and_send(&mut g, 56000, SITE, &hello(Some("protected.example"), &[], false, 0), now);
    let (_, d2) = connect_and_send(&mut g, 56001, OTHER, &hello(Some("second.example"), &[], false, 0), now);
    let out = g.drain();
    assert_eq!(checks(&out).len(), 2);
    g.verdict(1, request_for(&out, 1), Verdict::Block, now);
    assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));
    g.verdict(2, request_for(&out, 2), Verdict::AllowDirect, now);
    assert_eq!(g.drain(), vec![Out::ToTunnel(d2)]);
}

#[test]
fn invalidate_forces_a_fresh_check() {
    let mut g = gate();
    let t0 = Instant::now();
    connect_and_send(&mut g, 57000, SITE, &hello(Some("protected.example"), &[], false, 0), t0);
    let request = request_for(&g.drain(), 1);
    g.verdict(1, request, Verdict::AllowDirect, t0);
    g.drain();
    g.invalidate();
    connect_and_send(&mut g, 57001, SITE, &hello(Some("protected.example"), &[], false, 0), t0 + Duration::from_millis(100));
    assert_eq!(checks(&g.drain()).len(), 1);
}

#[test]
fn only_a_current_request_for_the_specified_group_can_release_packets() {
    let mut g = gate();
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    connect_and_send(&mut g, 57002, SITE, &payload, now);
    let old = request_for(&g.drain(), 1);
    g.invalidate();
    assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));
    let (_, packet) = connect_and_send(&mut g, 57003, SITE, &payload, now);
    let current = request_for(&g.drain(), 1);
    assert!(current > old);

    g.verdict(1, old, Verdict::AllowDirect, now);
    g.verdict(2, current, Verdict::AllowDirect, now);
    g.verdict(1, RequestId::new(current.get() + 1).unwrap(), Verdict::Block, now);
    assert!(g.drain().is_empty());
    g.verdict(1, current, Verdict::AllowDirect, now);
    assert_eq!(g.drain(), vec![Out::ToTunnel(packet)]);
    g.verdict(1, current, Verdict::Block, now);
    assert!(g.drain().is_empty());
}

#[test]
fn policy_refresh_keeps_the_existing_connection_and_rechecks_the_next_one() {
    let mut g = gate();
    let now = Instant::now();
    let initial = hello(Some("protected.example"), &[], false, 0);
    let (_, original) = connect_and_send(&mut g, 57010, SITE, &initial, now);
    let request = request_for(&g.drain(), 1);
    g.verdict(1, request, Verdict::AllowDirect, now);
    assert!(g.drain().iter().any(|o| matches!(o, Out::ToTunnel(p) if p == &original)));
    g.reconfigure(vec![], Box::new(Rules));
    let established = tcp4(MAC, 57010, SITE, 443, 1001 + initial.len() as u32, 5001, PA, b"next");
    assert_eq!(g.outbound(&established, now), Step::Forward);
    assert!(g.drain().is_empty());
    connect_and_send(&mut g, 57011, SITE, &initial, now);
    let request = request_for(&g.drain(), 1);
    g.verdict(1, request, Verdict::Block, now);
    let output = g.drain();
    assert!(!output.iter().any(|o| matches!(o, Out::ToTunnel(_))));
    assert!(output.iter().any(|o| matches!(o, Out::ToHost(_))));
}

#[test]
fn eviction_never_drops_held_connections() {
    let cfg = GateConfig { max_flows: 16, ..GateConfig::default() };
    let mut g = Gate::new(cfg, Box::new(Rules));
    let now = Instant::now();
    let (step, _) = connect_and_send(&mut g, 58000, SITE, &hello(Some("protected.example"), &[], false, 0), now);
    assert_eq!(step, Step::Consumed);
    let request = request_for(&g.drain(), 1);
    for i in 0..200u16 {
        connect_and_send(&mut g, 59000 + i, OTHER, &hello(Some("www.example.org"), &[], false, 0), now + Duration::from_millis(i as u64 + 1));
    }
    assert!(g.flow_count() <= 16);
    assert!(g.drain().is_empty());
    g.verdict(1, request, Verdict::AllowDirect, now);
    assert_eq!(g.drain().len(), 1, "the held connection survived eviction");
}

#[test]
fn pending_targets_and_held_packet_bytes_are_bounded() {
    let cfg = GateConfig { max_held_bytes: 256, ..GateConfig::default() };
    let mut g = Gate::new(cfg, Box::new(Rules));
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    for i in 0..MAX_PENDING_PER_GROUP {
        connect_and_send(&mut g, 59100 + i as u16, [198, 51, 100, i as u8 + 10], &payload, now);
    }
    let out = g.drain();
    let [Out::Check { request_id, .. }, ..] = out.as_slice() else { panic!("{out:?}") };
    assert_eq!(out.len(), MAX_PENDING_PER_GROUP);
    connect_and_send(&mut g, 59200, OTHER, &payload, now);
    assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));

    let ack = tcp4(MAC, 59100, SITE, 443, 1001 + payload.len() as u32, 5001, ACK, &[]);
    for _ in 0..32 {
        assert_eq!(g.outbound(&ack, now), Step::Consumed);
    }
    g.verdict(1, *request_id, Verdict::AllowDirect, now);
    let sent: usize = g.drain().iter().map(|out| match out {
        Out::ToTunnel(packet) => packet.len(),
        _ => panic!("{out:?}"),
    }).sum();
    assert!(sent <= 256);
}

#[test]
fn a_table_full_of_pending_flows_refuses_new_connections() {
    let cfg = GateConfig { max_flows: 2, ..GateConfig::default() };
    let mut g = Gate::new(cfg, Box::new(Rules));
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    let (_, a) = connect_and_send(&mut g, 59300, SITE, &payload, now);
    let (_, b) = connect_and_send(&mut g, 59301, SITE, &payload, now);
    let id = request_for(&g.drain(), 1);

    assert_eq!(g.outbound(&tcp4(MAC, 59302, SITE, 443, 1000, 0, SYN, &[]), now), Step::Consumed);
    assert_eq!(g.flow_count(), 2);
    assert!(matches!(g.drain().as_slice(), [Out::ToHost(_)]));
    g.verdict(1, id, Verdict::AllowDirect, now);
    assert_eq!(g.drain(), vec![Out::ToTunnel(a), Out::ToTunnel(b)]);
}

#[test]
fn idle_connections_are_forgotten() {
    let mut g = gate();
    let t0 = Instant::now();
    connect_and_send(&mut g, 60000, OTHER, &hello(Some("www.example.org"), &[], false, 0), t0);
    assert_eq!(g.flow_count(), 1);
    g.tick(t0 + Duration::from_secs(16 * 60));
    assert_eq!(g.flow_count(), 0);
}

#[test]
fn malformed_input_never_panics_and_passes() {
    let mut g = gate();
    let now = Instant::now();
    for junk in [&b""[..], &[0x45], &[0x60; 10], &[0x45, 0, 0, 10, 0, 0, 0, 0, 64, 6]] {
        assert_eq!(g.outbound(junk, now), Step::Forward);
        g.inbound(junk, now);
    }
    // Truncated or lying TLS lengths.
    let mut rec = hello(Some("protected.example"), &[], false, 0);
    rec[3] = 0xff;
    rec[4] = 0xff;
    let (_, _) = connect_and_send(&mut g, 61000, OTHER, &rec, now);
    for cut in 0..rec.len() {
        let _ = client_hello(&rec[..cut]);
        let _ = sniff(&rec[..cut]);
    }
    let _ = parse_dns_answer(&[0, 0, 0x80, 0, 0, 1, 0, 9, 0, 0, 0, 0, 0xc0, 12]);
}

#[test]
fn sniffers_read_names() {
    assert_eq!(
        client_hello(&hello(Some("Mixed.Case.Example."), &[b"h2"], false, 0)),
        Hello::Found { sni: Some("mixed.case.example".into()), alpn: vec![b"h2".to_vec()], ech: false }
    );
    assert_eq!(client_hello(&hello(None, &[], false, 0)), Hello::Found { sni: None, alpn: vec![], ech: false });
    assert_eq!(client_hello(b"\x16\x03\x01\x00"), Hello::Incomplete);
    assert_eq!(client_hello(b"\x17\x03\x03\x00\x10"), Hello::Other);
    assert_eq!(http_host(b"GE"), HttpHost::Incomplete);
    assert_eq!(http_host(b"SSH-2.0-x\r\n"), HttpHost::NotHttp);
    assert_eq!(http_host(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n"), HttpHost::Host(Some("2001:db8::1".into())));
    assert_eq!(http_host(b"GET / HTTP/1.0\r\n\r\n"), HttpHost::Host(None));
    assert_eq!(parse_dns_answer(&dns_answer("a.example", &[SITE, OTHER])), Some(("a.example".into(), vec![IpAddr::V4(SITE.into()), IpAddr::V4(OTHER.into())])));
}
