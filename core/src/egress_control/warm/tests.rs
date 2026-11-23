use super::*;
use crate::egress_control::{recheck::Failures, Group, Member, ProbeRequest, PRESET_TRACE};
use std::sync::mpsc::{channel, Receiver, Sender};

fn config() -> EgressConfig {
    EgressConfig {
        enabled: true,
        groups: vec![Group {
            id: 1,
            enabled: true,
            members: vec![
                Member {
                    pattern: "*.example".into(),
                    method: Some(PRESET_TRACE.into()),
                    probe_host: Some("a.example".into()),
                },
                Member {
                    pattern: "follow.test".into(),
                    ..Default::default()
                },
            ],
            expect: vec!["ZZ".into()],
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn scope() -> Scope {
    Scope {
        peer_id: 4,
        epoch: 9,
        interface: "utun42".into(),
    }
}

fn ip(last: u8) -> IpAddr {
    std::net::Ipv4Addr::new(192, 0, 2, last).into()
}

fn check(host: Option<&str>) -> CheckMsg {
    serde_json::from_value(serde_json::json!({
        "group": 1, "host": host, "hostConfirmed": host.is_some(), "ip": ip(1), "port": 443, "requestId": 1,
    }))
    .unwrap()
}

fn hint(last: u8) -> WarmMsg {
    WarmMsg {
        group: 1,
        host: "A.Example.".into(),
        ip: ip(last),
        port: NonZeroU16::new(443).unwrap(),
    }
}

fn reply() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\n\r\nloc=YY\nip=198.51.100.8\n".to_vec()
}

fn fixture_probe() -> ProbeHook {
    Arc::new(|request, peer| {
        *peer = request.connect_ip;
        Some(reply())
    })
}

fn held_probe() -> (ProbeHook, Receiver<ProbeRequest>, Sender<()>) {
    let (entered, requests) = channel();
    let (release, released) = channel();
    let released = Mutex::new(released);
    let hook: ProbeHook = Arc::new(move |request, peer| {
        entered.send(request.clone()).ok()?;
        released
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(3))
            .ok()?;
        *peer = request.connect_ip;
        Some(reply())
    });
    (hook, requests, release)
}

fn finished(attempt: &Attempt) {
    let state = attempt.state.lock().unwrap();
    let (state, _) = attempt
        .changed
        .wait_timeout_while(state, Duration::from_secs(3), |s| {
            matches!(s, State::Running | State::Retired)
        })
        .unwrap();
    assert!(matches!(*state, State::Finished(_)));
}

fn plan(config: &EgressConfig, check: &CheckMsg) -> Vec<Target> {
    Failures::default().plan(config, config.group(check.group).unwrap(), check)
}

#[test]
fn wire_contains_only_a_group_concrete_name_numerical_address_and_port() {
    #[derive(Deserialize)]
    struct Frame {
        warm: WarmMsg,
    }
    let frame: Frame = serde_json::from_str(
        r#"{"warm":{"group":1,"host":"a.example","ip":"2001:db8::1","port":443}}"#,
    )
    .unwrap();
    assert_eq!(frame.warm.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    for frame in [
        r#"{"warm":{"group":1,"ip":"192.0.2.1","port":443}}"#,
        r#"{"warm":{"group":1,"host":null,"ip":"192.0.2.1","port":443}}"#,
        r#"{"warm":{"group":1,"host":"a.example","ip":"not-an-address","port":443}}"#,
        r#"{"warm":{"group":1,"host":"a.example","ip":"192.0.2.1","port":0}}"#,
        r#"{"warm":{"group":1,"host":"a.example","ip":"192.0.2.1","port":443,"requestId":9}}"#,
        r#"{"warm":{"group":1,"host":"a.example","ip":"192.0.2.1","port":443,"verdict":true}}"#,
    ] {
        assert!(serde_json::from_str::<Frame>(frame).is_err(), "{frame}");
    }
}

#[test]
fn only_a_known_direct_method_at_the_flow_port_can_start() {
    let config = config();
    let (hook, _, _) = held_probe();
    let mut probes = WarmProbes::default();
    for msg in [
        WarmMsg {
            group: 5,
            ..hint(1)
        },
        WarmMsg {
            host: "unknown.test".into(),
            ..hint(1)
        },
        WarmMsg {
            host: "follow.test".into(),
            ..hint(1)
        },
        WarmMsg {
            host: "a.example\r\n".into(),
            ..hint(1)
        },
        WarmMsg {
            port: NonZeroU16::new(8443).unwrap(),
            ..hint(1)
        },
    ] {
        probes.start(&config, scope(), 0, msg, &hook, "marker");
    }
    probes.start(
        &config,
        Scope {
            interface: String::new(),
            ..scope()
        },
        0,
        hint(1),
        &hook,
        "marker",
    );
    probes.start(&config, scope(), 0, hint(1), &hook, "");
    let mut third_party = config.clone();
    let mut method = config.method(PRESET_TRACE).unwrap();
    method.url = "https://observer.example/geo".into();
    third_party.methods.push(method);
    probes.start(&third_party, scope(), 0, hint(1), &hook, "marker");
    assert!(probes.0.is_empty());
}

#[test]
fn ipv6_and_a_configured_https_port_are_preserved_in_the_probe() {
    let mut config = config();
    let mut method = config.method(PRESET_TRACE).unwrap();
    method.url = "https://{host}:8443/probe".into();
    config.methods.push(method);
    let ip = "2001:db8::2".parse().unwrap();
    let port = NonZeroU16::new(8443).unwrap();
    let (hook, requests, release) = held_probe();
    let mut probes = WarmProbes::default();
    probes.start(
        &config,
        scope(),
        0,
        WarmMsg {
            ip,
            port,
            ..hint(1)
        },
        &hook,
        "marker",
    );
    let request = requests.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(request.connect_ip, Some(ip));
    assert_eq!(request.port, port.get());
    assert!(request.request.contains("Host: a.example:8443\r\n"));
    let check = CheckMsg {
        ip,
        port,
        ..check(Some("a.example"))
    };
    let targets = plan(&config, &check);
    let warm = probes
        .for_check(&scope(), 0, &check, true, &targets)
        .unwrap();
    release.send(()).unwrap();
    assert_eq!(warm.wait().unwrap().observation.peer_address, Some(ip));
}

#[test]
fn named_check_can_join_a_pinned_probe_and_reuse_its_original_time() {
    let config = config();
    let (hook, requests, release) = held_probe();
    let mut probes = WarmProbes::default();
    probes.start(&config, scope(), 0, hint(1), &hook, "marker");
    let observed = requests.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(observed.connect_ip, Some(ip(1)));
    assert_eq!(observed.port, 443);
    assert_eq!(observed.host, "a.example");
    assert_eq!(observed.interface, "utun42");
    assert_eq!(observed.alpn, ["http/1.1", "marker"]);
    assert!((1..=1000).contains(&observed.timeout_ms));

    let check = check(Some("A.example."));
    let targets = plan(&config, &check);
    let candidate = probes
        .for_check(&scope(), 0, &check, true, &targets)
        .unwrap();
    release.send(()).unwrap();
    let first = candidate.wait().unwrap();
    let next = probes
        .for_check(&scope(), 0, &check, true, &targets)
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(first.evidence_at_ms, next.evidence_at_ms);
    assert_eq!(first.observation, next.observation);
    assert_eq!(first.observation.peer_address, Some(ip(1)));
    assert_eq!(first.observation.ip.as_deref(), Some("198.51.100.8"));
    assert!(candidate.is_current(&scope(), 0));
    assert!(!candidate.is_current(&scope(), 1));

    // The actual check evaluates the raw observation under the current policy.
    let mut failures = Failures::default();
    assert!(failures.observed_failures().is_empty());
    assert!(!failures.evaluate(
        config.group(1).unwrap(),
        0,
        &[(targets[0].clone(), first.observation)]
    ));
    assert_eq!(failures.observed_failures().len(), 1);
}

#[test]
fn missing_confirmation_dns_fallback_and_changed_identity_use_the_ordinary_check() {
    let config = config();
    let mut probes = WarmProbes::default();
    probes.start(&config, scope(), 2, hint(1), &fixture_probe(), "marker");
    finished(&probes.0[0]);
    let named = check(Some("a.example"));
    let targets = plan(&config, &named);
    assert!(probes
        .for_check(&scope(), 2, &named, true, &targets)
        .is_some());
    // These are identical parsed names but the gate supplied no SNI or Host proof.
    assert!(probes
        .for_check(&scope(), 2, &named, false, &targets)
        .is_none());
    let nameless = check(None);
    assert!(probes
        .for_check(&scope(), 2, &nameless, true, &plan(&config, &nameless))
        .is_none());
    for different in [
        check(Some("b.example")),
        check(Some("follow.test")),
        CheckMsg {
            ip: ip(2),
            ..check(Some("a.example"))
        },
        CheckMsg {
            port: NonZeroU16::new(8443).unwrap(),
            ..check(Some("a.example"))
        },
    ] {
        assert!(probes
            .for_check(&scope(), 2, &different, true, &plan(&config, &different))
            .is_none());
    }
    let wrong_group = CheckMsg {
        group: 2,
        ..check(Some("a.example"))
    };
    assert!(probes
        .for_check(&scope(), 2, &wrong_group, true, &targets)
        .is_none());
    let mut edited = config.clone();
    let mut method = config.method(PRESET_TRACE).unwrap();
    method.url = "https://{host}/different".into();
    edited.methods.push(method);
    assert!(probes
        .for_check(&scope(), 2, &named, true, &plan(&edited, &named))
        .is_none());
    for changed in [
        Scope {
            peer_id: 5,
            ..scope()
        },
        Scope {
            epoch: 10,
            ..scope()
        },
        Scope {
            interface: "utun7".into(),
            ..scope()
        },
    ] {
        assert!(probes
            .for_check(&changed, 2, &named, true, &targets)
            .is_none());
    }
    assert!(probes
        .for_check(&scope(), 3, &named, true, &targets)
        .is_none());
}

#[test]
fn unconfirmed_probe_evidence_falls_back() {
    let config = config();
    let check = check(Some("a.example"));
    let targets = plan(&config, &check);
    for (reported, answer) in [
        (None, Some(reply())),
        (Some(ip(2)), Some(reply())),
        (
            Some(ip(1)),
            Some(b"HTTP/1.1 200 OK\r\n\r\nunknown".to_vec()),
        ),
        (Some(ip(1)), None),
    ] {
        let hook: ProbeHook = Arc::new(move |_, peer| {
            *peer = reported;
            answer.clone()
        });
        let mut probes = WarmProbes::default();
        probes.start(&config, scope(), 0, hint(1), &hook, "marker");
        finished(&probes.0[0]);
        assert!(probes
            .for_check(&scope(), 0, &check, true, &targets)
            .is_none());
    }
}

#[test]
fn duplicate_addresses_and_retired_workers_keep_the_concurrency_bound() {
    let config = config();
    let (hook, requests, release) = held_probe();
    let mut probes = WarmProbes::default();
    probes.start(&config, scope(), 0, hint(1), &hook, "marker");
    probes.start(
        &config,
        scope(),
        0,
        WarmMsg {
            host: "b.example".into(),
            ..hint(1)
        },
        &hook,
        "marker",
    );
    assert_eq!(probes.0.len(), 1);
    probes.start(&config, scope(), 0, hint(2), &hook, "marker");
    probes.start(&config, scope(), 0, hint(3), &hook, "marker");
    assert_eq!(probes.0.len(), MAX_RUNNING);
    for _ in 0..MAX_RUNNING {
        requests.recv_timeout(Duration::from_secs(3)).unwrap();
    }
    let check = check(Some("a.example"));
    let candidate = probes
        .for_check(&scope(), 0, &check, true, &plan(&config, &check))
        .unwrap();
    assert!(
        candidate.wait().is_none(),
        "a busy probe must leave time for the real check"
    );
    probes.invalidate();
    assert!(candidate.wait().is_none());
    let next = Scope {
        epoch: 10,
        ..scope()
    };
    probes.start(&config, next.clone(), 0, hint(3), &hook, "marker");
    assert_eq!(probes.0.len(), MAX_RUNNING);
    for _ in 0..MAX_RUNNING {
        release.send(()).unwrap();
    }
    for attempt in &probes.0 {
        finished(attempt);
        assert!(matches!(
            *attempt.state.lock().unwrap(),
            State::Finished(None)
        ));
    }
    probes.start(&config, next, 0, hint(3), &fixture_probe(), "marker");
    finished(probes.0.last().unwrap());
    assert_eq!(probes.0.last().unwrap().target.ip, ip(3));
}

#[test]
fn ready_entries_are_bounded_expire_and_can_be_revoked() {
    let config = config();
    let mut probes = WarmProbes::default();
    let hook = fixture_probe();
    for last in 1..=MAX_ENTRIES as u8 {
        probes.start(&config, scope(), 0, hint(last), &hook, "marker");
        finished(probes.0.last().unwrap());
    }
    probes.start(&config, scope(), 0, hint(9), &hook, "marker");
    assert_eq!(probes.0.len(), MAX_ENTRIES);
    assert!(probes.0.iter().all(|attempt| attempt.target.ip != ip(9)));
    let check = check(Some("a.example"));
    let targets = plan(&config, &check);
    let ready = probes
        .for_check(&scope(), 0, &check, true, &targets)
        .unwrap();
    std::thread::sleep(
        ready
            .attempt
            .expires()
            .saturating_duration_since(Instant::now()),
    );
    assert!(!ready.is_current(&scope(), 0));
    assert!(ready.wait().is_none());
    assert!(probes
        .for_check(&scope(), 0, &check, true, &targets)
        .is_none());
    probes.start(&config, scope(), 0, hint(1), &hook, "marker");
    finished(probes.0.last().unwrap());
    let recent = probes
        .for_check(&scope(), 0, &check, true, &targets)
        .unwrap();
    assert!(recent.wait().is_some());
    probes.invalidate();
    assert!(!recent.is_current(&scope(), 0));
    assert!(recent.wait().is_none());
    assert!(probes.0.is_empty());
}
