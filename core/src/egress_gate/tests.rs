use super::*;

// Documentation addresses only (RFC 5737 / RFC 3849) and example names.
const MAC: [u8; 4] = [10, 0, 0, 2];
const SITE: [u8; 4] = [198, 51, 100, 10];
const OTHER: [u8; 4] = [192, 0, 2, 50];
const PA: u8 = 0x18; // PSH|ACK

thread_local! {
    static CLOCK: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(Some(10_000)) };
}

fn sites() -> ProtectedSites {
    ProtectedSites::new(&[
        SiteGroup { id: 1, sites: vec!["protected.example".into()] },
        SiteGroup { id: 2, sites: vec!["*.second.example".into(), "".into()] },
    ])
}

fn gate_with(cfg: GateConfig) -> Gate {
    CLOCK.set(Some(10_000));
    let mut gate = Gate::new(GateConfig { probe_alpn: b"ac-probe-test".to_vec(), ..cfg }, sites());
    gate.clock = || CLOCK.get();
    gate
}

fn gate() -> Gate {
    gate_with(GateConfig::default())
}

fn allow() -> Verdict {
    Verdict::Allow { evidence_at_ms: CLOCK.get().unwrap() }
}

/// Everything the gate wants sent, committing checked releases at once.
fn drain(gate: &mut Gate) -> Vec<Out> {
    let mut output = Vec::new();
    loop {
        let actions = gate.drain();
        if actions.is_empty() {
            return output;
        }
        for action in actions {
            if let Out::SendChecked(id) = action {
                gate.send_checked(id, Instant::now(), |packets| {
                    output.extend(packets.iter().cloned().map(Out::ToTunnel));
                    true
                });
            } else {
                output.push(action);
            }
        }
    }
}

/// SYN then the first data packet; returns the step of the data packet.
fn connect_and_send(g: &mut Gate, sport: u16, dst: [u8; 4], payload: &[u8], now: Instant) -> (Step, Vec<u8>) {
    assert_eq!(g.outbound(&tcp4(MAC, sport, dst, 443, 1000, 0, SYN, &[]), now), Step::Forward);
    let data = tcp4(MAC, sport, dst, 443, 1001, 5001, PA, payload);
    (g.outbound(&data, now), data)
}

fn checks(out: &[Out]) -> Vec<(GroupId, String)> {
    out.iter().filter_map(|o| if let Out::Check { group, host, .. } = o { Some((*group, host.clone())) } else { None }).collect()
}

fn request_for(out: &[Out], group: GroupId) -> RequestId {
    let ids: Vec<_> = out.iter().filter_map(|o| match o {
        Out::Check { group: id, request_id, .. } if *id == group => Some(*request_id),
        _ => None,
    }).collect();
    let [id] = ids.as_slice() else { panic!("expected one check for rule {group}, got {out:?}") };
    *id
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
fn protected_sites_cover_their_subdomains_only() {
    let s = sites();
    assert_eq!(s.group_for("protected.example"), Some(1));
    assert_eq!(s.group_for("API.Protected.Example."), Some(1));
    assert_eq!(s.group_for("notprotected.example"), None);
    assert_eq!(s.group_for("second.example"), Some(2), "a leading *. is the site itself");
    assert_eq!(s.group_for("example"), None);
    assert!(ProtectedSites::new(&[SiteGroup { id: 3, sites: vec![" ".into()] }]).is_empty());
}

#[test]
fn other_sites_pass_at_their_first_packet() {
    let mut g = gate();
    let now = Instant::now();
    let (step, _) = connect_and_send(&mut g, 40000, OTHER, &hello(Some("www.example.org"), &[b"h2"], false, 0), now);
    assert_eq!(step, Step::Forward);
    assert!(drain(&mut g).is_empty());
    assert_eq!(g.outbound(&tcp4(MAC, 40000, OTHER, 443, 1300, 5001, PA, b"more"), now), Step::Forward);
}

#[test]
fn a_protected_name_is_held_until_its_exit_is_allowed() {
    let mut g = gate();
    let now = Instant::now();
    let (step, data) = connect_and_send(&mut g, 40001, SITE, &hello(Some("api.protected.example"), &[b"h2"], false, 0), now);
    assert_eq!(step, Step::Consumed);
    let out = drain(&mut g);
    assert_eq!(checks(&out), vec![(1, "api.protected.example".into())]);
    let [Out::Check { destination, .. }] = out.as_slice() else { panic!("{out:?}") };
    assert_eq!(*destination, SocketAddr::from((SITE, 443)));
    // More data while waiting stays held, in order.
    let more = tcp4(MAC, 40001, SITE, 443, 1001 + (data.len() as u32 - 40), 5001, PA, b"x");
    assert_eq!(g.outbound(&more, now), Step::Consumed);
    g.verdict(1, request_for(&out, 1), allow(), now);
    assert_eq!(drain(&mut g), vec![Out::ToTunnel(data), Out::ToTunnel(more)]);
    assert_eq!(g.outbound(&tcp4(MAC, 40001, SITE, 443, 2000, 5001, PA, b"y"), now), Step::Forward);
}

#[test]
fn a_wrong_exit_resets_the_application_and_is_counted() {
    let mut g = gate();
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    connect_and_send(&mut g, 40002, SITE, &payload, now);
    let request = request_for(&drain(&mut g), 1);
    g.verdict(1, request, Verdict::Block, now);
    let out = drain(&mut g);
    let [Out::ToHost(rst)] = out.as_slice() else { panic!("expected a RST, got {out:?}") };
    verify_checksums(rst);
    let p = parse_ip(rst).unwrap();
    assert_eq!((p.src, p.dst), (IpAddr::V4(SITE.into()), IpAddr::V4(MAC.into())));
    let L4::Tcp(t) = p.l4 else { panic!() };
    assert_eq!((t.sport, t.dport, t.flags), (443, 40002, RST | ACK));
    assert_eq!(t.seq, 5001, "the client's acknowledged number");
    assert_eq!(t.ack, 1001 + payload.len() as u32);
    // Nothing of this connection reaches the tunnel afterwards.
    assert_eq!(g.outbound(&tcp4(MAC, 40002, SITE, 443, 1001, 5001, PA, &payload), now), Step::Consumed);
    assert!(matches!(drain(&mut g).as_slice(), [Out::ToHost(_)]));
    let denied = g.take_denied_group().unwrap();
    assert_eq!((denied.group, denied.count, denied.last_host.as_deref()), (1, 1, Some("protected.example")));
    assert!(g.take_denied_group().is_none());
}

#[test]
fn an_unreadable_exit_lets_the_connection_through() {
    let mut g = gate();
    let now = Instant::now();
    let (_, data) = connect_and_send(&mut g, 40003, SITE, &hello(Some("protected.example"), &[], false, 0), now);
    let request = request_for(&drain(&mut g), 1);
    g.verdict(1, request, Verdict::Unverified, now);
    assert_eq!(drain(&mut g), vec![Out::ToTunnel(data)]);
    assert!(g.take_denied_group().is_none());
}

#[test]
fn connections_to_one_destination_share_a_check_and_a_recent_result() {
    let mut g = gate();
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    let (_, a) = connect_and_send(&mut g, 40010, SITE, &payload, now);
    let (_, b) = connect_and_send(&mut g, 40011, SITE, &payload, now);
    let out = drain(&mut g);
    assert_eq!(checks(&out).len(), 1);
    g.verdict(1, request_for(&out, 1), allow(), now);
    assert_eq!(drain(&mut g), vec![Out::ToTunnel(a), Out::ToTunnel(b)]);
    // Within a second the same target reuses it; another server is checked.
    let (_, c) = connect_and_send(&mut g, 40012, SITE, &payload, now + Duration::from_millis(500));
    assert_eq!(drain(&mut g), vec![Out::ToTunnel(c)]);
    connect_and_send(&mut g, 40013, OTHER, &payload, now);
    assert_eq!(checks(&drain(&mut g)), vec![(1, "protected.example".into())]);
    connect_and_send(&mut g, 40014, SITE, &payload, now + Duration::from_secs(2));
    assert_eq!(checks(&drain(&mut g)).len(), 1, "an older result is not reused");
}

#[test]
fn a_recent_wrong_exit_resets_new_connections_at_once() {
    let mut g = gate();
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    connect_and_send(&mut g, 40020, SITE, &payload, now);
    let request = request_for(&drain(&mut g), 1);
    g.verdict(1, request, Verdict::Block, now);
    drain(&mut g);
    connect_and_send(&mut g, 40021, SITE, &payload, now + Duration::from_millis(100));
    assert!(matches!(drain(&mut g).as_slice(), [Out::ToHost(_)]));
    assert_eq!(g.take_denied_group().unwrap().count, 2);
}

#[test]
fn evidence_must_still_be_fresh_when_the_first_packet_is_written() {
    let mut g = gate();
    let now = Instant::now();
    let (_, data) = connect_and_send(&mut g, 40030, SITE, &hello(Some("protected.example"), &[], false, 0), now);
    let first = request_for(&drain(&mut g), 1);
    g.verdict(1, first, allow(), now);
    let out = g.drain();
    let [Out::SendChecked(id)] = out.as_slice() else { panic!("{out:?}") };
    // The release waits behind a slow write; the observation ages past a second.
    CLOCK.set(Some(11_500));
    g.send_checked(*id, now, |_| panic!("stale evidence must not release packets"));
    let retry = request_for(&g.drain(), 1);
    assert_ne!(retry, first, "one fresh check instead");
    g.verdict(1, retry, allow(), now);
    assert_eq!(drain(&mut g), vec![Out::ToTunnel(data)]);
}

#[test]
fn a_late_or_invalid_allow_cannot_release() {
    let mut g = gate();
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    connect_and_send(&mut g, 40040, SITE, &payload, now);
    let request = request_for(&drain(&mut g), 1);
    g.verdict(1, request, Verdict::Allow { evidence_at_ms: 0 }, now);
    assert!(matches!(drain(&mut g).as_slice(), [Out::ToHost(_)]));

    connect_and_send(&mut g, 40041, OTHER, &payload, now);
    let request = request_for(&drain(&mut g), 1);
    g.verdict(2, request, allow(), now);
    assert!(drain(&mut g).is_empty(), "another rule's answer is ignored");
    g.verdict(1, request, Verdict::Allow { evidence_at_ms: 8_000 }, now);
    let retry = request_for(&drain(&mut g), 1);
    g.verdict(1, retry, Verdict::Allow { evidence_at_ms: 8_000 }, now);
    assert!(matches!(drain(&mut g).as_slice(), [Out::ToHost(_)]), "a second stale answer blocks");
}

#[test]
fn a_check_that_never_answers_blocks() {
    let mut g = gate();
    let now = Instant::now();
    connect_and_send(&mut g, 40050, SITE, &hello(Some("protected.example"), &[], false, 0), now);
    let request = request_for(&drain(&mut g), 1);
    g.tick(now + Duration::from_secs(3));
    assert!(matches!(drain(&mut g).as_slice(), [Out::ToHost(_)]));
    g.verdict(1, request, allow(), now + Duration::from_secs(3));
    assert!(drain(&mut g).is_empty());
}

#[test]
fn invalidation_and_new_sites_refuse_waiting_connections_and_recheck() {
    let mut g = gate();
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    connect_and_send(&mut g, 40060, SITE, &payload, now);
    let request = request_for(&drain(&mut g), 1);
    g.invalidate();
    assert!(matches!(drain(&mut g).as_slice(), [Out::ToHost(_)]));
    g.verdict(1, request, allow(), now);
    assert!(drain(&mut g).is_empty());
    assert!(g.take_denied_group().is_none(), "internal refusals are not protection denials");

    g.reconfigure(Vec::new(), ProtectedSites::new(&[SiteGroup { id: 3, sites: vec!["other.example".into()] }]));
    let (step, _) = connect_and_send(&mut g, 40061, SITE, &payload, now);
    assert_eq!(step, Step::Forward, "no longer protected");
}

#[test]
fn split_hellos_wait_for_the_name_and_unreadable_ones_pass_after_a_while() {
    let mut g = gate();
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 3000);
    let (step, first) = {
        assert_eq!(g.outbound(&tcp4(MAC, 40070, SITE, 443, 1000, 0, SYN, &[]), now), Step::Forward);
        let data = tcp4(MAC, 40070, SITE, 443, 1001, 5001, PA, &payload[..1400]);
        (g.outbound(&data, now), data)
    };
    assert_eq!(step, Step::Consumed);
    assert!(drain(&mut g).is_empty());
    let rest = tcp4(MAC, 40070, SITE, 443, 2401, 5001, PA, &payload[1400..]);
    assert_eq!(g.outbound(&rest, now), Step::Consumed);
    let request = request_for(&drain(&mut g), 1);
    g.verdict(1, request, allow(), now);
    assert_eq!(drain(&mut g), vec![Out::ToTunnel(first), Out::ToTunnel(rest)]);

    // A hello that never completes: no name to read, it passes (best effort).
    let (step, part) = {
        assert_eq!(g.outbound(&tcp4(MAC, 40071, SITE, 443, 1000, 0, SYN, &[]), now), Step::Forward);
        let data = tcp4(MAC, 40071, SITE, 443, 1001, 5001, PA, &payload[..1400]);
        (g.outbound(&data, now), data)
    };
    assert_eq!(step, Step::Consumed);
    g.tick(now + Duration::from_secs(3));
    assert_eq!(drain(&mut g), vec![Out::ToTunnel(part)]);
}

#[test]
fn http_is_decided_by_its_host_and_other_protocols_pass() {
    let mut g = gate();
    let now = Instant::now();
    let (step, _) = connect_and_send(&mut g, 40080, SITE, b"GET / HTTP/1.1\r\nHost: www.second.example:8080\r\n\r\n", now);
    assert_eq!(step, Step::Consumed);
    assert_eq!(checks(&drain(&mut g)), vec![(2, "www.second.example".into())]);
    let (step, _) = connect_and_send(&mut g, 40081, SITE, b"SSH-2.0-client\r\n", now);
    assert_eq!(step, Step::Forward);
    let (step, _) = connect_and_send(&mut g, 40082, SITE, &hello(None, &[], true, 0), now);
    assert_eq!(step, Step::Forward, "a hello without a name passes");
}

#[test]
fn own_probes_pass_by_their_alpn_marker() {
    let mut g = gate();
    let (step, _) = connect_and_send(&mut g, 40090, SITE, &hello(Some("protected.example"), &[b"http/1.1", b"ac-probe-test"], false, 0), Instant::now());
    assert_eq!(step, Step::Forward);
    assert!(drain(&mut g).is_empty());
}

#[test]
fn quic_is_dropped_only_while_a_site_is_protected() {
    let mut g = gate();
    let now = Instant::now();
    assert_eq!(g.outbound(&udp4(MAC, 50000, OTHER, 443, b"quic"), now), Step::Consumed);
    assert_eq!(g.outbound(&udp4(MAC, 50000, OTHER, 53, b"dns"), now), Step::Forward);
    let mut idle = Gate::new(GateConfig::default(), ProtectedSites::default());
    assert_eq!(idle.outbound(&udp4(MAC, 50000, OTHER, 443, b"quic"), now), Step::Forward);
    let (step, _) = connect_and_send(&mut idle, 50001, SITE, &hello(Some("protected.example"), &[], false, 0), now);
    assert_eq!(step, Step::Forward);
    assert_eq!(idle.flow_count(), 0, "nothing is tracked without protected sites");
}

#[test]
fn connections_older_than_the_gate_pass() {
    let mut g = gate();
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    assert_eq!(g.outbound(&tcp4(MAC, 40100, SITE, 443, 7000, 5001, PA, &payload), now), Step::Forward);
    assert_eq!(g.flow_count(), 0);
}

#[test]
fn fast_open_data_on_the_syn_is_held() {
    let mut g = gate();
    let now = Instant::now();
    let syn = tcp4(MAC, 40110, SITE, 443, 1000, 0, SYN, &hello(Some("protected.example"), &[], false, 0));
    assert_eq!(g.outbound(&syn, now), Step::Consumed);
    let request = request_for(&drain(&mut g), 1);
    g.verdict(1, request, allow(), now);
    assert_eq!(drain(&mut g), vec![Out::ToTunnel(syn)]);
}

#[test]
fn ipv6_connections_are_gated_too() {
    let mut g = gate();
    let now = Instant::now();
    let (mac, site): (Ipv6Addr, Ipv6Addr) = ("2001:db8::2".parse().unwrap(), "2001:db8::10".parse().unwrap());
    assert_eq!(g.outbound(&tcp6(mac, 40120, site, 443, 1000, 0, SYN, &[]), now), Step::Forward);
    let data = tcp6(mac, 40120, site, 443, 1001, 5001, PA, &hello(Some("protected.example"), &[], false, 0));
    assert_eq!(g.outbound(&data, now), Step::Consumed);
    let request = request_for(&drain(&mut g), 1);
    g.verdict(1, request, Verdict::Block, now);
    let out = drain(&mut g);
    let [Out::ToHost(rst)] = out.as_slice() else { panic!("{out:?}") };
    verify_checksums(rst);
}

#[test]
fn eviction_never_drops_held_connections_and_a_full_table_refuses() {
    let mut g = gate_with(GateConfig { max_flows: 16, ..GateConfig::default() });
    let now = Instant::now();
    let (_, held) = connect_and_send(&mut g, 40130, SITE, &hello(Some("protected.example"), &[], false, 0), now);
    let request = request_for(&drain(&mut g), 1);
    for i in 0..200u16 {
        connect_and_send(&mut g, 41000 + i, OTHER, &hello(Some("www.example.org"), &[], false, 0), now + Duration::from_millis(i as u64 + 1));
    }
    assert!(g.flow_count() <= 16);
    g.verdict(1, request, allow(), now);
    assert_eq!(drain(&mut g), vec![Out::ToTunnel(held)], "the held connection survived eviction");

    let mut full = gate_with(GateConfig { max_flows: 1, ..GateConfig::default() });
    connect_and_send(&mut full, 40131, SITE, &hello(Some("protected.example"), &[], false, 0), now);
    drain(&mut full);
    assert_eq!(full.outbound(&tcp4(MAC, 40132, SITE, 443, 1000, 0, SYN, &[]), now), Step::Consumed);
    assert!(matches!(drain(&mut full).as_slice(), [Out::ToHost(_)]));
}

#[test]
fn pending_checks_and_held_bytes_are_bounded() {
    let mut g = gate_with(GateConfig { max_held_bytes: 512, ..GateConfig::default() });
    let now = Instant::now();
    let payload = hello(Some("protected.example"), &[], false, 0);
    for i in 0..MAX_PENDING_PER_GROUP {
        connect_and_send(&mut g, 42000 + i as u16, [198, 51, 100, i as u8 + 10], &payload, now);
    }
    let out = drain(&mut g);
    assert_eq!(out.len(), MAX_PENDING_PER_GROUP);
    let Out::Check { request_id, destination, .. } = &out[0] else { panic!("{out:?}") };
    connect_and_send(&mut g, 42100, OTHER, &payload, now);
    assert!(matches!(drain(&mut g).as_slice(), [Out::ToHost(_)]));

    let IpAddr::V4(dst) = destination.ip() else { panic!() };
    let ack = tcp4(MAC, 42000, dst.octets(), 443, 1001 + payload.len() as u32, 5001, ACK, &[]);
    for _ in 0..32 {
        assert_eq!(g.outbound(&ack, now), Step::Consumed);
    }
    g.verdict(1, *request_id, allow(), now);
    let sent: usize = drain(&mut g).iter().map(|out| match out {
        Out::ToTunnel(packet) => packet.len(),
        _ => panic!("{out:?}"),
    }).sum();
    assert!(sent <= 512);
}

#[test]
fn denial_counts_keep_the_first_hosts_and_have_fixed_limits() {
    let mut g = gate();
    let now = Instant::now();
    for i in 0..(MAX_REPORTED_HOSTS as u16 + 2) {
        let host = format!("h{i}.protected.example");
        connect_and_send(&mut g, 43000 + i, SITE, &hello(Some(&host), &[], false, 0), now);
        let request = request_for(&drain(&mut g), 1);
        g.verdict(1, request, Verdict::Block, now);
        drain(&mut g);
    }
    let denied = g.take_denied_group().unwrap();
    assert_eq!(denied.count, MAX_REPORTED_HOSTS as u64 + 2);
    assert_eq!(denied.hosts.len(), MAX_REPORTED_HOSTS);
    assert!(denied.hosts_truncated);
    assert_eq!(denied.last_host, None, "the latest host is past the list");
}

#[test]
fn idle_connections_are_forgotten() {
    let mut g = gate();
    let t0 = Instant::now();
    connect_and_send(&mut g, 44000, OTHER, &hello(Some("www.example.org"), &[], false, 0), t0);
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
    }
    let mut rec = hello(Some("protected.example"), &[], false, 0);
    rec[3] = 0xff;
    rec[4] = 0xff;
    connect_and_send(&mut g, 45000, OTHER, &rec, now);
    for cut in 0..rec.len() {
        let _ = client_hello(&rec[..cut]);
        let _ = sniff(&rec[..cut]);
    }
}

#[test]
fn sniffers_read_names() {
    assert_eq!(
        client_hello(&hello(Some("Mixed.Case.Example."), &[b"h2"], true, 0)),
        Hello::Found { sni: Some("mixed.case.example".into()), alpn: vec![b"h2".to_vec()] }
    );
    assert_eq!(client_hello(&hello(None, &[], false, 0)), Hello::Found { sni: None, alpn: vec![] });
    assert_eq!(client_hello(b"\x16\x03\x01\x00"), Hello::Incomplete);
    assert_eq!(client_hello(b"\x17\x03\x03\x00\x10"), Hello::Other);
    assert_eq!(http_host(b"GE"), HttpHost::Incomplete);
    assert_eq!(http_host(b"SSH-2.0-x\r\n"), HttpHost::NotHttp);
    assert_eq!(http_host(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n"), HttpHost::Host(Some("2001:db8::1".into())));
    assert_eq!(http_host(b"GET / HTTP/1.0\r\n\r\n"), HttpHost::Host(None));
}
