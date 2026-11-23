use super::*;

const OWNER: &[u8] = &[0xc0, 12];

fn observed(qtype: u16, q: &[u8], a: &[u8]) -> Option<DeliveredDns> {
    delivered::extract(7, 101, 103, qtype, q, a, false)
}

fn value(value: &str, ttl: u32) -> DeliveredDnsValue {
    DeliveredDnsValue {
        value: value.into(),
        ttl,
    }
}

fn ech_list(names: &[&str]) -> Vec<u8> {
    let mut configs = Vec::new();
    for name in names {
        let mut body = vec![1, 0, 0x20, 0, 32]; // ID, X25519, public key length
        body.extend([3; 32]);
        body.extend([0, 4, 0, 1, 0, 1, 0, name.len() as u8]);
        body.extend(name.as_bytes());
        body.extend([0, 0]); // extensions
        configs.extend(param(0xfe0d, &body));
    }
    let mut list = (configs.len() as u16).to_be_bytes().to_vec();
    list.extend(configs);
    list
}

#[test]
fn address_rrsets_follow_only_a_bounded_cname_chain() {
    let q = query("WwW.Example", TYPE_A, 3);
    let alias = rr(OWNER, TYPE_CNAME, 51, &wire("target.example"));
    let target_offset = q.len() + 12;
    let target = [0xc0, target_offset as u8];
    let a = reply(
        &q,
        &[
            alias.clone(),
            rr(&target, TYPE_A, 3600, &[192, 0, 2, 3]),
            rr(&wire("unrelated.example"), TYPE_A, 1, &[192, 0, 2, 4]),
            rr(&target, TYPE_A, 20, &[192, 0, 2, 3]),
            rr(&target, TYPE_A, 30, &[192, 0, 2, 5]),
        ],
        &[],
        &[rr(&target, TYPE_A, 1, &[192, 0, 2, 9])],
    );
    assert_eq!(
        observed(TYPE_A, &q, &a).unwrap(),
        DeliveredDns {
            epoch: 7,
            started_at_ms: 101,
            observed_at_ms: 103,
            name: "www.example".into(),
            qtype: TYPE_A,
            incomplete: false,
            scope_known: false,
            kind: DeliveredDnsKind::Ipv4,
            values: vec![value("192.0.2.3", 20), value("192.0.2.5", 20)],
        }
    );
    for records in [
        vec![alias.clone()],
        vec![
            alias.clone(),
            rr(OWNER, TYPE_CNAME, 51, &wire("different.example")),
        ],
        vec![alias.clone(), rr(&target, TYPE_CNAME, 51, OWNER)],
        vec![alias.clone(), rr(OWNER, TYPE_A, 51, &[192, 0, 2, 4])],
        vec![alias.clone(), rr(&target, TYPE_A, 51, &[192, 0, 2])],
    ] {
        assert!(
            observed(TYPE_A, &q, &reply(&q, &records, &[], &[]))
                .unwrap()
                .incomplete
        );
    }

    let q = query("www.example", TYPE_AAAA, 4);
    let ip = "2001:db8::1"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets();
    let a = reply(&q, &[rr(OWNER, TYPE_AAAA, 7200, &ip)], &[], &[]);
    let evidence = observed(TYPE_AAAA, &q, &a).unwrap();
    assert_eq!(evidence.kind, DeliveredDnsKind::Ipv6);
    assert_eq!(evidence.values, [value("2001:db8::1", 300)]);
    for ttl in [0, 0x8000_0000] {
        let a = reply(&q, &[rr(OWNER, TYPE_AAAA, ttl, &ip)], &[], &[]);
        assert!(observed(TYPE_AAAA, &q, &a).unwrap().values.is_empty());
    }
    let a = reply(
        &q,
        &[
            rr(OWNER, TYPE_CNAME, 4, &wire("target.example")),
            rr(&wire("target.example"), TYPE_AAAA, 80, &ip),
        ],
        &[],
        &[],
    );
    assert_eq!(
        observed(TYPE_AAAA, &q, &a).unwrap().values,
        [value("2001:db8::1", 4)]
    );
}

#[test]
fn only_exact_complete_in_questions_can_replace_a_rrset() {
    let q = query("www.example", TYPE_A, 3);
    let a = answer(&q, [192, 0, 2, 3], false);
    assert!(observed(TYPE_A, &q, &a).is_some());
    for length in 0..a.len() {
        match observed(TYPE_A, &q, &a[..length]) {
            None => assert!(length < q.len()),
            Some(evidence) => assert!(evidence.incomplete && evidence.values.is_empty()),
        }
    }
    for answer in [
        answer(
            &query("different.example", TYPE_A, 3),
            [192, 0, 2, 3],
            false,
        ),
        answer(&query("www.example", TYPE_A, 4), [192, 0, 2, 3], false),
    ] {
        assert!(observed(TYPE_A, &q, &answer).is_none());
    }
    let oversized = reply(&q, &[], &[], &[rr(OWNER, 16, 60, &vec![0; 8192])]);
    for answer in [
        answer(&q, [192, 0, 2, 3], true),
        oversized,
        reply(&q, &[], &[], &[rr(&[0], 41, 0x0100_0000, &[])]),
        reply(
            &q,
            &[],
            &[rr(&wire("example"), TYPE_NS, 400, &wire("ns.example"))],
            &[],
        ),
        reply(
            &q,
            &vec![rr(OWNER, TYPE_A, 10, &[192, 0, 2, 3]); 65],
            &[],
            &[],
        ),
    ] {
        let event = observed(TYPE_A, &q, &answer).unwrap();
        assert!(event.incomplete && event.values.is_empty());
    }
    assert!(observed(TYPE_AAAA, &q, &a).is_none());
    let mut wrong_class = q.clone();
    *wrong_class.last_mut().unwrap() = 3;
    assert!(observed(TYPE_A, &wrong_class, &reply(&wrong_class, &[], &[], &[])).is_none());

    let nodata = reply(&q, &[], &[], &[]);
    assert!(observed(TYPE_A, &q, &nodata).unwrap().values.is_empty());
    let mut nxdomain = nodata.clone();
    nxdomain[3] |= 3;
    assert!(observed(TYPE_A, &q, &nxdomain).unwrap().values.is_empty());
    let bad_owner = rr(&[0xc0, 13], TYPE_A, 60, &[192, 0, 2, 3]);
    assert!(
        observed(TYPE_A, &q, &reply(&q, &[bad_owner], &[], &[]))
            .unwrap()
            .incomplete
    );
}

#[test]
fn only_unambiguous_resolver_errors_have_known_incomplete_scope() {
    let q = query("www.example", TYPE_A, 3);
    let ede = rr(&[0], 41, 0, &param(15, &[0, 23]));
    let alias = rr(OWNER, TYPE_CNAME, 50, &wire("alias.example"));
    for rcode in [2, 5] {
        for (mut a, expected) in [
            (reply(&q, &[], &[], &[]), true),
            (reply(&q, &[], &[], std::slice::from_ref(&ede)), true),
            (reply(&q, std::slice::from_ref(&alias), &[], &[]), false),
            (answer(&q, [192, 0, 2, 3], true), false),
        ] {
            a[3] |= rcode;
            let event = observed(TYPE_A, &q, &a).unwrap();
            assert!(event.incomplete && event.values.is_empty());
            assert_eq!(event.scope_known, expected);
        }
    }
}

#[test]
fn common_address_shape_agrees_with_expanded_owner() {
    let owner = wire("wWw.example");
    for (kind, ip) in [(TYPE_A, vec![192, 0, 2, 3]), (TYPE_AAAA, vec![1; 16])] {
        let q = query("WWW.example", kind, 7);
        for ttl in [0, 60, 300, 301, 0x8000_0000] {
            let compressed = reply(&q, &[rr(OWNER, kind, ttl, &ip)], &[], &[]);
            let expanded = reply(&q, &[rr(&owner, kind, ttl, &ip)], &[], &[]);
            assert_eq!(
                observed(kind, &q, &compressed),
                observed(kind, &q, &expanded)
            );
        }
    }
}

#[test]
fn ech_names_come_from_service_rrsets_with_effective_ttl() {
    for qtype in [TYPE_HTTPS, TYPE_SVCB] {
        let q = query("www.example", qtype, 5);
        let terminal = wire("edge.example");
        let params = [
            param(1, b"\x02h2"),
            param(5, &ech_list(&["Public.Example", "outer.example"])),
        ]
        .concat();
        let a = reply(
            &q,
            &[
                rr(OWNER, TYPE_CNAME, 50, &terminal),
                rr(&terminal, qtype, 900, &svcb_data(1, ".", &params)),
                rr(&terminal, qtype, 40, &svcb_data(2, ".", &[])),
            ],
            &[],
            &[rr(
                &terminal,
                qtype,
                1,
                &svcb_data(3, ".", &param(5, &ech_list(&["glue.example"]))),
            )],
        );
        let evidence = observed(qtype, &q, &a).unwrap();
        assert_eq!(evidence.kind, DeliveredDnsKind::Ech);
        assert_eq!(evidence.qtype, qtype);
        assert_eq!(
            evidence.values,
            [value("public.example", 40), value("outer.example", 40)]
        );
        let a = reply(
            &q,
            &[rr(OWNER, qtype, 60, &svcb_data(1, ".", &[]))],
            &[],
            &[],
        );
        assert!(observed(qtype, &q, &a).unwrap().values.is_empty());
    }
}

#[test]
fn unsupported_or_malformed_service_data_cannot_replace_ech_evidence() {
    let q = query("www.example", TYPE_HTTPS, 5);
    let good = param(5, &ech_list(&["outer.example"]));
    let mut unsupported = good.clone();
    unsupported[6] ^= 0x01; // unsupported config version
    let mut short = good.clone();
    short.pop();
    for data in [
        svcb_data(0, "alias.example", &[]),
        svcb_data(1, "different.example", &good),
        svcb_data(1, ".", &short),
        svcb_data(1, ".", &unsupported),
        svcb_data(1, ".", &param(5, &ech_list(&["bad_name.example"]))),
        svcb_data(1, ".", &param(5, &ech_list(&["192.0.2.1"]))),
        svcb_data(1, ".", &[good.clone(), good.clone()].concat()),
        svcb_data(1, ".", &[param(0, &[0, 1]), good].concat()),
    ] {
        let a = reply(&q, &[rr(OWNER, TYPE_HTTPS, 60, &data)], &[], &[]);
        let event = observed(TYPE_HTTPS, &q, &a).unwrap();
        assert!(event.incomplete && event.values.is_empty());
    }
}

#[test]
fn listeners_report_only_the_delivered_tunnel_rrsets() {
    use crate::egress_control::{GateGroup, ProtectedRoutes};
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let server = upstream.local_addr().unwrap().to_string();
    let responder = std::thread::spawn(move || {
        let mut buffer = [0; 512];
        for _ in 0..8 {
            let (size, peer) = upstream.recv_from(&mut buffer).unwrap();
            let q = &buffer[..size];
            let mut a = if question(q).unwrap().qtype == TYPE_A {
                egress_reply(q)
            } else {
                let params = if q[1] == 8 {
                    vec![0, 5, 0, 2, 0] // truncated SvcParam
                } else {
                    [
                        param(4, &[192, 0, 2, 55]),
                        param(5, &ech_list(&["outer.example"])),
                    ]
                    .concat()
                };
                reply(
                    q,
                    &[rr(OWNER, TYPE_HTTPS, 900, &svcb_data(1, ".", &params))],
                    &[],
                    &[],
                )
            };
            if q[1] == 5 {
                a[3] |= 0x20; // AD: bytes are preserved even on the protected site
            }
            upstream.send_to(&a, peer).unwrap();
        }
    });
    let port = free_port();
    let routes =
        serde_json::from_str::<Vec<GateGroup>>(r#"[{"id":1,"names":["protected.example"]}]"#)
            .unwrap();
    let direct = vec!["direct.example".into()];
    let (tx, rx) = mpsc::sync_channel(8);
    let fwd = Forwarder::with_dns_hooks(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
        53,
        Duration::from_millis(300),
        direct.clone(),
        Upstreams {
            tunnel: vec![server.clone()],
            local: vec![server],
            physical_if: None,
            tunnel_if: Some(loopback_interface().into()),
        },
        None,
        None,
        Some(Box::new(|_, _, _| vec![WRONG_EXIT.into()])),
        Some(Box::new(move |evidence| tx.try_send(evidence).unwrap())),
    );
    fwd.set_parsed_rules(
        SplitRules::new(&direct).with_protection(Some(Arc::new(ProtectedRoutes::new(&routes)))),
    );
    fwd.start().unwrap();
    let recv = || {
        let evidence = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(evidence.epoch, fwd.epoch());
        assert!(evidence.started_at_ms <= evidence.observed_at_ms);
        evidence
    };
    for id in [1, 2] {
        let q = query("Protected.Example", TYPE_A, id);
        let wire = if id == 1 {
            ask(&q, port).unwrap()
        } else {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            write_framed(&mut stream, &q).unwrap();
            read_framed(&mut stream).unwrap()
        };
        assert_eq!(
            ipv4_answers(&wire),
            [FIRST_ALTERNATIVE, SECOND_ALTERNATIVE].map(Ipv4Addr::from)
        );
        assert_eq!(
            recv().values,
            [value("203.0.113.9", 10), value("203.0.113.2", 10)]
        );
    }

    let protected = query("protected.example", TYPE_HTTPS, 3);
    assert_eq!(
        records(&ask(&protected, port).unwrap())[0].3,
        "prio=1 target="
    );
    let stripped = recv();
    assert!(stripped.values.is_empty() && !stripped.incomplete);
    let unprotected = query("www.example", TYPE_HTTPS, 4);
    let ordinary = ask(&unprotected, port).unwrap();
    assert_eq!(recv().values, [value("outer.example", 300)]);
    assert!(!records(&ordinary)[0].3.contains("4:"));
    let authenticated = query("protected.example", TYPE_HTTPS, 5);
    let mut expected = reply(
        &authenticated,
        &[rr(
            OWNER,
            TYPE_HTTPS,
            900,
            &svcb_data(
                1,
                ".",
                &[
                    param(4, &[192, 0, 2, 55]),
                    param(5, &ech_list(&["outer.example"])),
                ]
                .concat(),
            ),
        )],
        &[],
        &[],
    );
    expected[3] |= 0x20;
    assert_eq!(ask(&authenticated, port).unwrap(), expected);
    assert_eq!(recv().values, [value("outer.example", 300)]);

    assert!(ask(&query("direct.example", TYPE_A, 6), port).is_some());
    assert_eq!(
        ask(&query("www.example", TYPE_AAAA, 7), port).unwrap()[7],
        0
    );
    assert_eq!(
        ask(&query("www.example", TYPE_HTTPS, 8), port).unwrap()[7],
        0
    );
    let fallback = recv();
    assert!(fallback.incomplete && fallback.values.is_empty());
    assert!(fwd
        .inner()
        .resolve(&query("www.example", TYPE_A, 9))
        .is_some());
    responder.join().unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(75)).is_err());
}

#[test]
fn old_epoch_and_closed_listener_do_not_publish_evidence() {
    let (tx, rx) = mpsc::sync_channel(1);
    let fwd = Forwarder::with_dns_hooks(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        53,
        Duration::from_millis(200),
        vec![],
        Upstreams {
            tunnel: vec![],
            local: vec![],
            physical_if: None,
            tunnel_if: None,
        },
        None,
        None,
        None,
        Some(Box::new(move |evidence| tx.try_send(evidence).unwrap())),
    );
    let q = query("www.example", TYPE_A, 9);
    let resolved = |epoch| ResolvedAnswer {
        bytes: reply(&q, &[], &[], &[]),
        evidence: Some(Delivery {
            epoch,
            qtype: TYPE_A,
            synthesized: false,
        }),
    };
    fwd.start().unwrap();
    let session = fwd
        .listening
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .replies
        .clone();
    let old_epoch = fwd.epoch();
    fwd.set_rules(&[]);
    let started = evidence_clock_ms();
    fwd.inner
        .publish_delivered(&q, resolved(old_epoch), started, &session);
    assert!(rx.try_recv().is_err());
    session.close();
    assert!(!session.send(&q, "127.0.0.1:1".parse().unwrap()));
    fwd.inner
        .publish_delivered(&q, resolved(fwd.epoch()), started, &session);
    assert!(rx.try_recv().is_err());
}
